"""Threat detection engine.

Hybrid model:
  * RandomForest classifier  -> Normal / Suspicious / Malicious
  * IsolationForest (trained on normal traffic only) -> anomaly score that can
    escalate an unusual "Normal" event to "Suspicious".

To plug in your own model, keep the `Detector.predict(feature_rows)` contract:
it receives a list of feature dicts (see ml/features.FEATURES) and returns a
list of {"label", "risk"} dicts.
"""
import json
import os
import threading
import time

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_recall_fscore_support, roc_auc_score)
from sklearn.model_selection import train_test_split

from .features import FEATURES, explain, featurize_batch
from .synth import generate_training_events

CLASSES = ["Normal", "Suspicious", "Malicious"]
MODEL_DIR = os.environ.get("MODEL_DIR", os.path.join(os.path.dirname(__file__), "..", "model_store"))
MODEL_PATH = os.path.join(MODEL_DIR, f"detector-skl{sklearn.__version__}.joblib")
ANOMALY_ESCALATE = 0.995   # more unusual than 99.5% of normal traffic


def _matrix(rows):
    return np.array([[r[f] for f in FEATURES] for r in rows], dtype=float)


def evaluate(y_true, y_pred, proba=None):
    """Evaluation metrics shown on the dashboards."""
    labels = [c for c in CLASSES if c in set(y_true) | set(y_pred)]
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=CLASSES, zero_division=0)
    out = {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "macro_f1": round(float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)), 4),
        "per_class": {c: {"precision": round(float(p[i]), 4), "recall": round(float(r[i]), 4),
                          "f1": round(float(f[i]), 4), "support": int(s[i])} for i, c in enumerate(CLASSES)},
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=CLASSES).tolist(),
        "labels": CLASSES,
        "samples": len(y_true),
    }
    # threat (= not Normal) detection view, the number most people care about
    yt = np.array([y != "Normal" for y in y_true])
    yp = np.array([y != "Normal" for y in y_pred])
    tp, fp, fn = int((yt & yp).sum()), int((~yt & yp).sum()), int((yt & ~yp).sum())
    out["threat_detection_rate"] = round(tp / (tp + fn), 4) if tp + fn else None
    out["false_alarm_rate"] = round(fp / int((~yt).sum()), 4) if (~yt).sum() else None
    if proba is not None and len(set(y_true)) > 1:
        try:
            out["roc_auc"] = round(float(roc_auc_score(yt, proba)), 4)
        except ValueError:
            pass
    return out


class Detector:
    def __init__(self, clf, iso, iso_ref, metrics):
        self.clf, self.iso, self.iso_ref, self.metrics = clf, iso, iso_ref, metrics

    # ------------------------------------------------------------------ train
    @classmethod
    def train(cls, seed=42):
        t0 = time.time()
        events, feats = featurize_batch(generate_training_events(seed))
        X, y = _matrix(feats), np.array([e["label"] for e in events])
        X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, random_state=seed, stratify=y)

        clf = RandomForestClassifier(n_estimators=150, max_depth=14, min_samples_leaf=2,
                                     class_weight="balanced", n_jobs=-1, random_state=seed)
        clf.fit(X_tr, y_tr)
        iso = IsolationForest(n_estimators=150, contamination="auto", random_state=seed)
        iso.fit(X_tr[y_tr == "Normal"])
        iso_ref = np.sort(iso.score_samples(X_tr[y_tr == "Normal"]))

        det = cls(clf, iso, iso_ref, {})
        preds = det._predict_matrix(X_te)
        det.metrics = evaluate(list(y_te), [p["label"] for p in preds], [p["risk"] / 100 for p in preds])
        det.metrics.update({"train_events": int(len(y_tr)), "test_events": int(len(y_te)),
                            "train_seconds": round(time.time() - t0, 1),
                            "trained_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())})
        return det

    # ---------------------------------------------------------------- predict
    def _predict_matrix(self, X):
        if len(X) == 0:
            return []
        proba = self.clf.predict_proba(X)
        idx = {c: list(self.clf.classes_).index(c) for c in CLASSES}
        # anomaly = share of normal training traffic that looks *more* normal
        anomaly = np.searchsorted(self.iso_ref, self.iso.score_samples(X)) / len(self.iso_ref)
        anomaly = 1.0 - anomaly
        out = []
        for i in range(len(X)):
            p = {c: proba[i, idx[c]] for c in CLASSES}
            label = max(p, key=p.get)
            if label == "Normal" and anomaly[i] >= ANOMALY_ESCALATE:
                label = "Suspicious"
            risk = 100 * (0.85 * (0.5 * p["Suspicious"] + p["Malicious"]) + 0.15 * anomaly[i])
            if label == "Suspicious":
                risk = max(risk, 40)
            elif label == "Malicious":
                risk = max(risk, 70)
            out.append({"label": label, "risk": round(float(min(risk, 100)), 1)})
        return out

    def predict(self, feature_rows):
        preds = self._predict_matrix(_matrix(feature_rows))
        for p, f in zip(preds, feature_rows):
            p["reason"] = explain(f, p["label"])
        return preds

    # ------------------------------------------------------------ persistence
    def save(self, path=MODEL_PATH):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({"clf": self.clf, "iso": self.iso, "iso_ref": self.iso_ref, "metrics": self.metrics}, path)

    @classmethod
    def load(cls, path=MODEL_PATH):
        d = joblib.load(path)
        return cls(d["clf"], d["iso"], d["iso_ref"], d["metrics"])


_detector = None
_lock = threading.Lock()


def get_detector():
    """Load the trained model from disk, training it on first use."""
    global _detector
    with _lock:
        if _detector is None:
            if os.path.exists(MODEL_PATH):
                _detector = Detector.load()
            else:
                _detector = Detector.train()
                _detector.save()
        return _detector


def analyze_events(events, detector=None):
    """Batch analysis: featurise, score and (if labels exist) evaluate."""
    det = detector or get_detector()
    events, feats = featurize_batch(events)
    preds = det.predict(feats)
    results = []
    for e, f, p in zip(events, feats, preds):
        results.append({**{k: e.get(k) for k in ("ts", "user", "ip", "action", "success", "path", "status")},
                        **p, "true_label": e.get("label")})
    evaluation = None
    labelled = [r for r in results if r["true_label"] in CLASSES]
    if labelled and len(labelled) >= 0.5 * len(results):
        evaluation = evaluate([r["true_label"] for r in labelled], [r["label"] for r in labelled],
                              [r["risk"] / 100 for r in labelled])
    return results, evaluation


if __name__ == "__main__":
    d = Detector.train()
    d.save()
    print(json.dumps(d.metrics, indent=2))
