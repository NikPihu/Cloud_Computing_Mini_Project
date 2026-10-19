"""The deployable detector.

One object holds everything needed to analyse new traffic:
    classifier      - trained Pipeline (preprocessing + model): normal or attack?
    anomaly         - Isolation Forest: does it look unusual?
    defaults/options/examples - what the GUI form needs

It is saved as ``models/detector.joblib`` plus a human-readable
``models/metadata.json``. A future cloud API only needs::

    detector = Detector.load()
    detector.predict(dataframe_of_connections)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.pipeline import Pipeline

from nids.anomaly import AnomalyDetector, train_anomaly_detector
from nids.config import MODELS_DIR, Config
from nids.data import load_raw
from nids.evaluation import compute_metrics, detection_summary, feature_importance, flagged_as_attack
from nids.preprocessing import NORMAL, PreparedData, prepare_data
from nids.training import train_models

DETECTOR_FILE = "detector.joblib"
METADATA_FILE = "metadata.json"

VERDICT_ATTACK = "Attack"
VERDICT_SUSPICIOUS = "Suspicious"
VERDICT_NORMAL = "Normal"


@dataclass
class Detector:
    classifier: Pipeline
    anomaly: AnomalyDetector
    model_name: str
    target: str
    feature_columns: list[str]
    input_features: list[str]          # fields shown in the GUI form
    defaults: dict                     # a typical normal connection
    options: dict[str, list[str]]      # choices for the text fields
    integer_columns: list[str]
    examples: pd.DataFrame             # a few real test rows, for GUI presets
    metadata: dict = field(default_factory=dict)

    # ------------------------------------------------------------------ build
    @classmethod
    def build(cls, classifier: Pipeline, model_name: str, anomaly: AnomalyDetector,
              data: PreparedData, cfg: Config, metrics: dict | None = None) -> "Detector":
        X, y = data.X_train, data.y_train
        normal_rows = X[(y == NORMAL).to_numpy()]
        cat_cols = data.categorical_columns
        defaults = {
            c: (str(normal_rows[c].mode().iloc[0]) if c in cat_cols else float(normal_rows[c].median()))
            for c in X.columns
        }
        integer_columns = [c for c in data.numeric_columns
                           if np.allclose(X[c].dropna() % 1, 0)]
        metadata = {
            "dataset": cfg.dataset.name,
            "config": str(cfg.source.name) if cfg.source else None,
            "target": data.target,
            "model": model_name,
            "trained_at": datetime.now().isoformat(timespec="seconds"),
            "train_rows": len(X),
            "features": len(X.columns),
            "classes": [str(c) for c in classifier.classes_],
            "label_column": cfg.dataset.label_column,
            "normal_value": str(cfg.dataset.normal_value),
            "seen_labels": sorted(data.attack_train.astype(str).unique().tolist()),
            "false_alarm_rate": anomaly.false_alarm_rate,
            "anomaly_threshold": anomaly.threshold_,
            "metrics": {k: round(float(v), 4) for k, v in (metrics or {}).items()},
            "versions": {"scikit-learn": sklearn.__version__, "pandas": pd.__version__,
                         "numpy": np.__version__},
        }
        return cls(
            classifier=classifier, anomaly=anomaly, model_name=model_name, target=data.target,
            feature_columns=list(X.columns),
            input_features=_choose_input_features(classifier, data, cfg.live_input_features),
            defaults=defaults,
            options={c: sorted(X[c].astype(str).unique().tolist()) for c in cat_cols},
            integer_columns=integer_columns,
            examples=_pick_examples(data, cfg),
            metadata=metadata,
        )

    # ---------------------------------------------------------------- predict
    def _align(self, df: pd.DataFrame) -> pd.DataFrame:
        """Put columns in training order; fill columns that are missing entirely
        with the typical-normal default."""
        df = df.rename(columns=lambda c: str(c).strip())
        X = df.reindex(columns=self.feature_columns)
        for col in self.feature_columns:
            if col not in df.columns:
                X[col] = self.defaults[col]
        for col in self.options:
            X[col] = X[col].astype(str)
        return X

    def _verdicts(self, prediction: np.ndarray, is_anomaly: np.ndarray) -> np.ndarray:
        return np.where(prediction != NORMAL, VERDICT_ATTACK,
                        np.where(is_anomaly, VERDICT_SUSPICIOUS, VERDICT_NORMAL))

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """One result row per input row."""
        X = self._align(df)
        proba = self.classifier.predict_proba(X)
        prediction = self.classifier.classes_[proba.argmax(axis=1)]
        score = self.anomaly.score(X)
        is_anomaly = score > self.anomaly.threshold_
        return pd.DataFrame({
            "prediction": prediction,
            "confidence": proba.max(axis=1),
            "anomaly_score": score,
            "is_anomaly": is_anomaly,
            "verdict": self._verdicts(prediction, is_anomaly),
        }, index=df.index)

    def analyze(self, row: dict) -> dict:
        """Same as predict, for one connection, but keeps every intermediate
        step so the GUI can show the processing as it happens."""
        X = self._align(pd.DataFrame([row]))
        prep = self.classifier.named_steps["prep"]
        encoded = pd.DataFrame(prep.transform(X), columns=prep.get_feature_names_out())
        proba = pd.Series(self.classifier.predict_proba(X)[0], index=self.classifier.classes_)
        score = float(self.anomaly.score(X)[0])
        prediction = str(proba.idxmax())
        is_anomaly = score > self.anomaly.threshold_
        return {
            "input": X,
            "encoded": encoded,
            "probabilities": proba,
            "prediction": prediction,
            "confidence": float(proba.max()),
            "anomaly_score": score,
            "threshold": self.anomaly.threshold_,
            "is_anomaly": bool(is_anomaly),
            "verdict": str(self._verdicts(np.array([prediction]), np.array([is_anomaly]))[0]),
        }

    # ------------------------------------------------------------ save / load
    def save(self, folder: Path = MODELS_DIR) -> Path:
        folder = Path(folder)
        folder.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, folder / DETECTOR_FILE, compress=3)
        (folder / METADATA_FILE).write_text(json.dumps(self.metadata, indent=2, default=str))
        return folder / DETECTOR_FILE

    @staticmethod
    def load(folder: Path = MODELS_DIR) -> "Detector":
        return joblib.load(Path(folder) / DETECTOR_FILE)

    @staticmethod
    def exists(folder: Path = MODELS_DIR) -> bool:
        return (Path(folder) / DETECTOR_FILE).exists()


def _choose_input_features(classifier: Pipeline, data: PreparedData, setting) -> list[str]:
    """Fields for the GUI form: the list from the config, or (auto) the text
    columns plus the most important numeric columns."""
    if isinstance(setting, list):
        return [c for c in setting if c in data.feature_columns]
    cats = data.categorical_columns[:3]
    importance = feature_importance(classifier, data.feature_columns)
    ranked = list(importance.index) if importance is not None else data.numeric_columns
    return cats + [c for c in ranked if c not in cats][: 12 - len(cats)]


def _pick_examples(data: PreparedData, cfg: Config, per_type: int = 1) -> pd.DataFrame:
    """A few real test connections: normal, the most common known attacks
    and the most common attacks that never appeared in training."""
    names = data.attack_test.astype(str)
    normal = str(cfg.dataset.normal_value)
    unseen = data.unseen_attacks
    counts = names.value_counts()
    known = [a for a in counts.index if a != normal and a not in unseen][:5]
    new = [a for a in counts.index if a in unseen][:3]

    rows, labels = [], []
    for name in [normal] + known + new:
        idx = names[names == name].sample(per_type, random_state=7).index
        rows.append(data.X_test.loc[idx])
        if name == normal:
            labels.append("Normal traffic")
        else:
            family = cfg.dataset.category_of(name) if cfg.dataset.attack_categories else "attack"
            note = " - never seen in training" if name in unseen else ""
            labels.append(f"{name} ({family}){note}")
    examples = pd.concat(rows)
    examples.index = labels
    examples["actual label"] = [names[i] for r in rows for i in r.index]
    return examples


def train_detector(cfg: Config, model_name: str = "Random Forest", target: str | None = None,
                   sample_fraction: float | None = None, on_progress=None) -> tuple[Detector, dict]:
    """Load data -> prepare -> train classifier + anomaly detector -> evaluate -> build.

    Used by notebook 06 and by the GUI's "quick train" button.
    Returns (detector, test-set summary).
    """
    say = on_progress or (lambda msg, p: None)
    say("Loading dataset…", 0.05)
    train_df, test_df = load_raw(cfg.dataset, "train"), load_raw(cfg.dataset, "test")
    say("Preprocessing…", 0.15)
    data = prepare_data(cfg, train_df, test_df, target=target, sample_fraction=sample_fraction)
    say(f"Training {model_name}…", 0.3)
    models, _ = train_models(data.X_train, data.y_train, [model_name])
    classifier = models[model_name]
    say("Training anomaly detector on normal traffic…", 0.6)
    anomaly = train_anomaly_detector(data.X_train, data.y_train,
                                     n_estimators=cfg.anomaly.n_estimators,
                                     false_alarm_rate=cfg.anomaly.false_alarm_rate)
    say("Evaluating on the test set…", 0.8)
    y_pred = classifier.predict(data.X_test)
    metrics = compute_metrics(data.y_test, y_pred)
    detector = Detector.build(classifier, model_name, anomaly, data, cfg, metrics)
    hybrid = flagged_as_attack(y_pred) | anomaly.predict(data.X_test)
    summary = {
        "metrics": metrics,
        "classifier": detection_summary(flagged_as_attack(y_pred), data.attack_test,
                                        cfg.dataset.normal_value, data.unseen_attacks),
        "hybrid": detection_summary(hybrid, data.attack_test,
                                    cfg.dataset.normal_value, data.unseen_attacks),
    }
    say("Done", 1.0)
    return detector, summary
