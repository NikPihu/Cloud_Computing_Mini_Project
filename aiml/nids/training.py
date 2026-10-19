"""Model development and optimisation (syllabus PR7, PR8, PR11).

Every long-running function accepts an optional ``on_progress(message, fraction)``
callback. The notebooks pass ``print``-style callbacks; the GUI passes one that
moves a progress bar. The training logic itself never knows which UI is used.
"""
from __future__ import annotations

import time
from typing import Callable

import pandas as pd
from sklearn.base import clone
from sklearn.metrics import f1_score, make_scorer
from sklearn.model_selection import GridSearchCV, StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline

from nids.models import PARAM_GRIDS, RANDOM_STATE, make_pipeline
from nids.preprocessing import ATTACK, NORMAL

Progress = Callable[[str, float], None] | None


def train_models(X: pd.DataFrame, y: pd.Series, names: list[str], on_progress: Progress = None):
    """Train each named model. Returns (models dict, training-seconds dict)."""
    models, times = {}, {}
    for i, name in enumerate(names):
        if on_progress:
            on_progress(f"Training {name} on {len(X):,} rows…", i / len(names))
        start = time.perf_counter()
        models[name] = make_pipeline(name, X).fit(X, y)
        times[name] = time.perf_counter() - start
    if on_progress:
        on_progress("All models trained", 1.0)
    return models, times


def _subsample(X: pd.DataFrame, y: pd.Series, n: int):
    if len(X) <= n:
        return X, y
    X_small, _, y_small, _ = train_test_split(
        X, y, train_size=n, stratify=y, random_state=RANDOM_STATE
    )
    return X_small, y_small


def scorer_for(y: pd.Series):
    """F1 of the 'attack' class for binary targets, macro-F1 for families."""
    if set(y.unique()) <= {NORMAL, ATTACK}:
        return make_scorer(f1_score, pos_label=ATTACK)
    return "f1_macro"


def cross_validate(pipeline: Pipeline, X: pd.DataFrame, y: pd.Series, folds: int = 3,
                   sample_size: int | None = 20000) -> pd.Series:
    """K-fold cross-validation F1 scores of an (unfitted copy of a) pipeline."""
    if sample_size:
        X, y = _subsample(X, y, sample_size)
    cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=RANDOM_STATE)
    scores = cross_val_score(clone(pipeline), X, y, cv=cv, scoring=scorer_for(y), n_jobs=-1)
    return pd.Series(scores, index=[f"fold {i + 1}" for i in range(folds)], name="F1")


def tune_model(name: str, X: pd.DataFrame, y: pd.Series, folds: int = 3,
               sample_size: int = 20000, on_progress: Progress = None):
    """Grid search over PARAM_GRIDS[name] with K-fold cross-validation.

    The search runs on a stratified sample (``sample_size`` rows) to keep it
    fast; the best settings are then re-trained on the full training set.
    Returns (best pipeline, best params, all results as a DataFrame).
    """
    grid = PARAM_GRIDS[name]
    X_small, y_small = _subsample(X, y, sample_size)
    n_candidates = 1
    for values in grid.values():
        n_candidates *= len(values)
    if on_progress:
        on_progress(f"Grid search: {n_candidates} settings × {folds} folds "
                    f"on {len(X_small):,} rows…", 0.05)

    search = GridSearchCV(
        make_pipeline(name, X_small), grid,
        cv=StratifiedKFold(n_splits=folds, shuffle=True, random_state=RANDOM_STATE),
        scoring=scorer_for(y), n_jobs=-1,
    )
    search.fit(X_small, y_small)

    if on_progress:
        on_progress(f"Re-training best {name} on all {len(X):,} rows…", 0.7)
    best = make_pipeline(name, X).set_params(**search.best_params_).fit(X, y)

    results = pd.DataFrame(search.cv_results_)
    params_cols = [c for c in results.columns if c.startswith("param_")]
    results = (results[params_cols + ["mean_test_score", "std_test_score", "rank_test_score"]]
               .rename(columns=lambda c: c.replace("param_model__", ""))
               .sort_values("rank_test_score"))
    if on_progress:
        on_progress("Tuning finished", 1.0)
    best_params = {k.replace("model__", ""): v for k, v in search.best_params_.items()}
    return best, best_params, results
