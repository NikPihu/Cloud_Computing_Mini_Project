"""The machine-learning models we compare (syllabus PR7, PR8, PR11).

To try another model, add one line to MODEL_REGISTRY (and optionally a grid
to PARAM_GRIDS) - the notebooks and the GUI pick it up automatically.
"""
from __future__ import annotations

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier

from nids.preprocessing import build_preprocessor

RANDOM_STATE = 42

MODEL_REGISTRY = {
    "Logistic Regression": lambda: LogisticRegression(max_iter=1000),
    "Naive Bayes": lambda: GaussianNB(),
    "Decision Tree": lambda: DecisionTreeClassifier(random_state=RANDOM_STATE),
    "Random Forest": lambda: RandomForestClassifier(
        n_estimators=100, n_jobs=-1, random_state=RANDOM_STATE
    ),
}

MODEL_NOTES = {
    "Logistic Regression": "Linear baseline: draws one straight boundary between classes.",
    "Naive Bayes": "Probabilistic: assumes every feature is independent of the others.",
    "Decision Tree": "Learns if/else rules - easy to read, tends to overfit.",
    "Random Forest": "Many decision trees voting together - usually the most accurate.",
}

# Hyper-parameters tried by GridSearchCV. Names start with "model__" because
# the model sits inside a Pipeline step called "model".
PARAM_GRIDS = {
    "Logistic Regression": {"model__C": [0.1, 1.0, 10.0]},
    "Naive Bayes": {"model__var_smoothing": [1e-9, 1e-6, 1e-3]},
    "Decision Tree": {
        "model__max_depth": [10, 20, None],
        "model__min_samples_leaf": [1, 5, 10],
    },
    "Random Forest": {
        "model__n_estimators": [100, 200],
        "model__max_depth": [20, None],
        "model__min_samples_leaf": [1, 2],
    },
}


def make_pipeline(name: str, X: pd.DataFrame) -> Pipeline:
    """Preprocessing + model in one object.

    Fitting the pipeline fits the scaler/encoder on the training data only,
    and the saved pipeline accepts raw rows directly at prediction time.
    """
    return Pipeline([
        ("prep", build_preprocessor(X)),
        ("model", MODEL_REGISTRY[name]()),
    ])
