"""Performance evaluation.

Accuracy, precision, recall, F1, confusion matrix, ROC - plus the analysis
that matters most for intrusion detection: how many *unseen* attack types
each approach still catches.
"""
from __future__ import annotations

import time

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, auc, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_curve)
from sklearn.pipeline import Pipeline

from nids.preprocessing import ATTACK, NORMAL


def is_binary(y) -> bool:
    return set(pd.Series(y).unique()) <= {NORMAL, ATTACK}


def compute_metrics(y_true, y_pred) -> dict:
    """Binary: scores for the 'attack' class. Families: macro average."""
    kw = {"pos_label": ATTACK, "average": "binary"} if is_binary(y_true) else {"average": "macro"}
    return {
        "Accuracy": accuracy_score(y_true, y_pred),
        "Precision": precision_score(y_true, y_pred, zero_division=0, **kw),
        "Recall": recall_score(y_true, y_pred, zero_division=0, **kw),
        "F1": f1_score(y_true, y_pred, zero_division=0, **kw),
    }


def evaluate_models(models: dict[str, Pipeline], X: pd.DataFrame, y: pd.Series):
    """Returns (metrics table, predictions dict)."""
    rows, predictions = {}, {}
    for name, model in models.items():
        start = time.perf_counter()
        predictions[name] = model.predict(X)
        seconds = time.perf_counter() - start
        rows[name] = {**compute_metrics(y, predictions[name]), "Predict time (s)": seconds}
    return pd.DataFrame(rows).T, predictions


def confusion_table(y_true, y_pred) -> pd.DataFrame:
    """Confusion matrix as a labelled table (rows = actual, columns = predicted)."""
    labels = sorted(set(y_true) | set(y_pred), key=lambda c: (c != NORMAL, c))
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    return pd.DataFrame(cm, index=pd.Index(labels, name="Actual"),
                        columns=pd.Index(labels, name="Predicted"))


def roc_points(model: Pipeline, X: pd.DataFrame, y: pd.Series):
    """(false-positive rates, true-positive rates, AUC) for a binary model."""
    attack_col = list(model.classes_).index(ATTACK)
    scores = model.predict_proba(X)[:, attack_col]
    fpr, tpr, _ = roc_curve(y == ATTACK, scores)
    return fpr, tpr, auc(fpr, tpr)


def flagged_as_attack(y_pred) -> np.ndarray:
    """True wherever the model said anything other than 'normal'."""
    return np.asarray(y_pred) != NORMAL


def detection_summary(flagged, attack_names: pd.Series, normal_value: str,
                      unseen: set[str]) -> dict:
    """Detection rate on known vs unseen attack types, and false alarms on normal traffic."""
    flagged = np.asarray(flagged)
    names = attack_names.astype(str).to_numpy()
    normal = names == str(normal_value)
    unseen_mask = np.isin(names, list(unseen))
    known_mask = ~normal & ~unseen_mask
    rate = lambda mask: float(flagged[mask].mean()) if mask.any() else float("nan")
    return {
        "Known attacks detected": rate(known_mask),
        "Unseen attacks detected": rate(unseen_mask),
        "False alarms on normal": rate(normal),
    }


def detection_by_attack_type(flagged, attack_names: pd.Series, normal_value: str,
                             unseen: set[str]) -> pd.DataFrame:
    """One row per attack type: how many rows, how many detected, seen or unseen."""
    df = pd.DataFrame({"attack": attack_names.astype(str).to_numpy(),
                       "detected": np.asarray(flagged)})
    df = df[df["attack"] != str(normal_value)]
    table = df.groupby("attack")["detected"].agg(rows="size", detection_rate="mean")
    table["in training data"] = ~table.index.isin(list(unseen))
    return table.sort_values("rows", ascending=False)


def feature_importance(model: Pipeline, feature_columns: list[str]) -> pd.Series | None:
    """Importance per ORIGINAL column (one-hot columns are added back together).

    Only tree models have importances; returns None for the others.
    """
    estimator = model.named_steps["model"]
    if not hasattr(estimator, "feature_importances_"):
        return None
    names = model.named_steps["prep"].get_feature_names_out()
    raw = pd.Series(estimator.feature_importances_, index=names)
    # 'service_http' belongs to column 'service'; numeric columns map to themselves.
    owner = {}
    for name in names:
        prefixes = [c for c in feature_columns if name.startswith(f"{c}_")]
        owner[name] = name if name in feature_columns else max(prefixes, key=len, default=name)
    return raw.groupby(owner).sum().sort_values(ascending=False)
