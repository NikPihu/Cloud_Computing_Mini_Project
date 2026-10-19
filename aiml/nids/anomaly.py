"""Anomaly detection with an Isolation Forest.

Idea: learn what NORMAL traffic looks like, and flag anything that does not
fit. Because it never sees attack labels, it can flag attack types that did
not exist in the training data - something a supervised classifier cannot.

Isolation Forest in one sentence: it builds random trees that keep splitting
the data; unusual points get isolated after only a few splits, so a short
average path length means "anomaly".
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline

from nids.preprocessing import build_preprocessor


class AnomalyDetector:
    """Isolation Forest trained on normal traffic only.

    ``false_alarm_rate`` sets the alarm threshold: 0.05 means about 5% of
    normal training connections would be (wrongly) flagged. Changing it does
    not require retraining - see ``set_false_alarm_rate``.
    """

    def __init__(self, n_estimators: int = 200, false_alarm_rate: float = 0.05,
                 random_state: int = 42):
        self.n_estimators = n_estimators
        self.false_alarm_rate = false_alarm_rate
        self.random_state = random_state

    def fit(self, X_normal: pd.DataFrame) -> "AnomalyDetector":
        self.pipeline = Pipeline([
            ("prep", build_preprocessor(X_normal)),
            ("model", IsolationForest(n_estimators=self.n_estimators, n_jobs=-1,
                                      random_state=self.random_state)),
        ]).fit(X_normal)
        self.train_scores_ = self.score(X_normal)
        self.set_false_alarm_rate(self.false_alarm_rate)
        return self

    def score(self, X: pd.DataFrame) -> np.ndarray:
        """Anomaly score: higher = more unusual."""
        return -self.pipeline.score_samples(X)

    def set_false_alarm_rate(self, rate: float) -> None:
        self.false_alarm_rate = rate
        self.threshold_ = float(np.quantile(self.train_scores_, 1 - rate))

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """True = anomaly."""
        return self.score(X) > self.threshold_


def train_anomaly_detector(X_train: pd.DataFrame, y_train: pd.Series, normal_label: str = "normal",
                           n_estimators: int = 200, false_alarm_rate: float = 0.05) -> AnomalyDetector:
    """Fit on the rows whose target is normal - attacks are never shown to it."""
    X_normal = X_train[(y_train == normal_label).to_numpy()]
    return AnomalyDetector(n_estimators, false_alarm_rate).fit(X_normal)


def pca_projection(preprocessor, X: pd.DataFrame, n_components: int = 2):
    """Squash the encoded features into 2 dimensions for plotting (syllabus PR10).

    A few connections transfer millions of bytes; left as they are, they would
    decide the PCA directions on their own. A signed log, sign(x)*log(1+|x|),
    compresses those extremes first so the picture shows the bulk of the traffic.

    Returns (DataFrame with PC1/PC2, share of variance each component keeps).
    """
    encoded = preprocessor.transform(X)
    encoded = np.sign(encoded) * np.log1p(np.abs(encoded))
    pca = PCA(n_components=n_components, random_state=42)
    points = pca.fit_transform(encoded)
    columns = [f"PC{i + 1}" for i in range(n_components)]
    return pd.DataFrame(points, columns=columns, index=X.index), pca.explained_variance_ratio_
