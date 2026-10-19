"""Bridge between the cloud app and the AIML mini-project models (aiml/nids).

Three services, all backed by the AIML project's trained models:
  intrusion    Network Intrusion Detection  - Random Forest (normal vs attack)
  anomaly      Anomaly Detection            - Isolation Forest trained on normal traffic
  attack_type  Attack Type Classification   - Random Forest (DoS / Probe / R2L / U2R)

Training happens once (at `docker build`, or on first start) with
`python -m web.engine`; the app then only loads the saved models.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "aiml"))

from nids.config import MODELS_DIR, load_config  # noqa: E402
from nids.data import load_raw  # noqa: E402
from nids.detector import Detector, train_detector  # noqa: E402

BINARY_DIR = MODELS_DIR / "binary"
FAMILY_DIR = MODELS_DIR / "family"
CARD_FILE = MODELS_DIR / "model_card.json"
SERVICES = ("intrusion", "anomaly", "attack_type")
VERDICTS = ["Normal", "Suspicious", "Attack"]
FAMILIES = ["DoS", "Probe", "R2L", "U2R", "Other"]


class Engine:
    def __init__(self):
        self.cfg = load_config()
        self.binary = Detector.load(BINARY_DIR)
        self.family = Detector.load(FAMILY_DIR)
        self.card = json.loads(CARD_FILE.read_text())
        self.columns = [c for c in self.cfg.dataset.columns
                        if c not in (self.cfg.dataset.label_column, *self.cfg.dataset.drop_columns)]
        self.seen_labels = set(self.binary.metadata["seen_labels"])
        self.threshold = float(self.binary.anomaly.threshold_)

    # ------------------------------------------------------------- analyse
    def analyze(self, df: pd.DataFrame, services) -> pd.DataFrame:
        """Run the subscribed services on raw connection records.

        Returns one row per input with: verdict, prediction, confidence,
        anomaly_score, is_anomaly, family.
        """
        services = set(services)
        out = pd.DataFrame(index=df.index)
        res = self.binary.predict(df)          # classifier + anomaly in one pass
        attack = np.zeros(len(df), dtype=bool)
        if "intrusion" in services:
            out["prediction"] = res["prediction"].astype(str).to_numpy()
            out["confidence"] = res["confidence"].round(4).to_numpy()
            attack |= out["prediction"].to_numpy() != "normal"
        if "attack_type" in services:
            fam = self.family.predict(df)["prediction"].astype(str).to_numpy()
            out["family"] = np.where(fam == "normal", "", fam)
            if "intrusion" not in services:
                attack |= fam != "normal"
        anomaly = np.zeros(len(df), dtype=bool)
        if "anomaly" in services:
            out["anomaly_score"] = res["anomaly_score"].round(4).to_numpy()
            anomaly = res["is_anomaly"].to_numpy(dtype=bool)
            out["is_anomaly"] = anomaly
        if "family" in out:      # only name a family for traffic we actually flag
            out.loc[~attack, "family"] = ""
        out["verdict"] = np.where(attack, "Attack", np.where(anomaly, "Suspicious", "Normal"))
        return out

    # ------------------------------------------------------------ helpers
    def label_family(self, label: str) -> str:
        return self.cfg.dataset.category_of(label)

    def parse_upload(self, raw: bytes, max_rows: int = 100_000) -> pd.DataFrame:
        """NSL-KDD style logs: CSV/TXT with or without a header row, with or without labels."""
        import io
        text = raw.decode("utf-8", errors="replace")
        first = next((ln for ln in text.splitlines() if ln.strip()), "")
        header = any(c in first.split(",")[:5] for c in ("duration", "protocol_type", "service"))
        if header:
            df = pd.read_csv(io.StringIO(text), nrows=max_rows, low_memory=False)
            df.columns = [str(c).strip() for c in df.columns]
        else:
            df = pd.read_csv(io.StringIO(text), header=None, nrows=max_rows, low_memory=False)
            names = self.cfg.dataset.columns            # 41 features + label + difficulty
            if df.shape[1] > len(names) or df.shape[1] < len(self.columns):
                raise ValueError(f"Expected {len(self.columns)}-{len(names)} columns, found {df.shape[1]}.")
            df.columns = names[: df.shape[1]]
        missing = [c for c in ("protocol_type", "service", "flag", "src_bytes") if c not in df.columns]
        if missing:
            raise ValueError(f"Missing required columns: {', '.join(missing)}")
        return df.drop(columns=[c for c in self.cfg.dataset.drop_columns if c in df.columns])


# ---------------------------------------------------------------- evaluation
def binary_metrics(actual_attack, flagged) -> dict:
    actual_attack, flagged = np.asarray(actual_attack, bool), np.asarray(flagged, bool)
    cm = confusion_matrix(actual_attack, flagged, labels=[False, True])
    return {
        "accuracy": round(float(accuracy_score(actual_attack, flagged)), 4),
        "precision": round(float(precision_score(actual_attack, flagged, zero_division=0)), 4),
        "recall": round(float(recall_score(actual_attack, flagged, zero_division=0)), 4),
        "f1": round(float(f1_score(actual_attack, flagged, zero_division=0)), 4),
        "false_alarm_rate": round(float(cm[0, 1] / cm[0].sum()), 4) if cm[0].sum() else None,
        "confusion_matrix": cm.tolist(),
        "labels": ["Normal", "Attack"],
        "samples": int(len(actual_attack)),
    }


def evaluate(labels, results: pd.DataFrame, engine: Engine) -> dict | None:
    """Compare verdicts with ground-truth labels (if the logs carried them)."""
    labels = pd.Series(labels).astype(str).str.strip().reset_index(drop=True)
    known = labels.ne("") & labels.ne("nan") & labels.ne("None")
    if known.sum() < 10:
        return None
    labels, res = labels[known], results.reset_index(drop=True)[known.to_numpy()]
    normal = engine.cfg.dataset.normal_value
    actual = (labels != normal).to_numpy()
    unseen = (~labels.isin(engine.seen_labels) & (labels != normal)).to_numpy()
    out = {"hybrid": binary_metrics(actual, res["verdict"] != "Normal"), "approaches": {}}
    if "prediction" in res:
        out["approaches"]["Random Forest (intrusion)"] = res["prediction"].ne("normal").to_numpy()
    if "is_anomaly" in res:
        out["approaches"]["Isolation Forest (anomaly)"] = res["is_anomaly"].to_numpy(bool)
    out["approaches"]["Combined verdict"] = (res["verdict"] != "Normal").to_numpy()
    table = {}
    for name, flagged in out["approaches"].items():
        m = binary_metrics(actual, flagged)
        table[name] = {k: m[k] for k in ("accuracy", "precision", "recall", "f1", "false_alarm_rate")}
        table[name]["unseen_caught"] = round(float(flagged[unseen].mean()), 4) if unseen.any() else None
        table[name]["known_caught"] = (round(float(flagged[actual & ~unseen].mean()), 4)
                                       if (actual & ~unseen).any() else None)
    out["approaches"] = table
    out["unseen_attacks"] = int(unseen.sum())
    if "family" in res:
        true_fam = labels.map(lambda l: "normal" if l == normal else engine.label_family(l)).to_numpy()
        mask = true_fam != "normal"
        pred_fam = res["family"].replace("", "normal").to_numpy()
        if mask.any():
            fams = [f for f in FAMILIES if f in set(true_fam[mask]) | set(pred_fam[mask])] + ["normal"]
            out["family"] = {
                "accuracy": round(float((pred_fam[mask] == true_fam[mask]).mean()), 4),
                "labels": fams,                       # columns (predicted); rows are actual attacks only
                "row_labels": fams[:-1],
                "confusion_matrix": confusion_matrix(true_fam[mask], pred_fam[mask], labels=fams)[:-1].tolist(),
            }
    return out


# ---------------------------------------------------------------- loading
_engine = None
_lock = threading.Lock()


def get_engine() -> Engine:
    global _engine
    with _lock:
        if _engine is None:
            if not CARD_FILE.exists():
                train_all()
            _engine = Engine()
        return _engine


def train_all():
    """Train both AIML detectors on NSL-KDD and write a model card from KDDTest+."""
    t0 = time.time()
    cfg = load_config()
    binary, b_summary = train_detector(cfg, "Random Forest", target="binary")
    binary.save(BINARY_DIR)
    family, f_summary = train_detector(cfg, "Random Forest", target="category")
    family.save(FAMILY_DIR)
    CARD_FILE.write_text(json.dumps({"trained_at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())}))

    eng = Engine()
    test = load_raw(cfg.dataset, "test")
    labels = test[cfg.dataset.label_column]
    results = eng.analyze(test, SERVICES)
    card = {
        "dataset": cfg.dataset.name,
        "train_rows": binary.metadata["train_rows"],
        "test_rows": int(len(test)),
        "trained_at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "train_seconds": round(time.time() - t0, 1),
        "anomaly_threshold": eng.threshold,
        "evaluation": evaluate(labels, results, eng),
        "family_metrics": {k: round(float(v), 4) for k, v in f_summary["metrics"].items()},
        "versions": binary.metadata["versions"],
    }
    CARD_FILE.write_text(json.dumps(card, indent=2))
    return card


if __name__ == "__main__":
    print(json.dumps(train_all()["evaluation"]["approaches"], indent=2))
