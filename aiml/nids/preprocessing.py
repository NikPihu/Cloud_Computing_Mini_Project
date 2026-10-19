"""Data preprocessing (syllabus PR5).

Steps, in order:
    1. clean          - fix infinite numbers, drop rows without a label, drop duplicates
    2. make_target    - turn raw labels ('neptune', 'smurf', ...) into the
                        prediction target ('normal' / 'attack', or a family like 'DoS')
    3. split          - use the separate test file, or split the train file
    4. build_preprocessor - missing values, encoding and scaling, packed into a
                        scikit-learn ColumnTransformer that is fitted on the
                        TRAINING data only (no information leaks from the test set)
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from nids.config import Config, DatasetConfig

NORMAL = "normal"
ATTACK = "attack"


@dataclass
class PreparedData:
    """Everything the modelling steps need, produced by ``prepare_data``."""

    X_train: pd.DataFrame
    X_test: pd.DataFrame
    y_train: pd.Series
    y_test: pd.Series
    attack_train: pd.Series  # original label names, e.g. 'neptune'
    attack_test: pd.Series
    target: str
    report: dict = field(default_factory=dict)

    @property
    def feature_columns(self) -> list[str]:
        return list(self.X_train.columns)

    @property
    def categorical_columns(self) -> list[str]:
        return text_columns(self.X_train)

    @property
    def numeric_columns(self) -> list[str]:
        return [c for c in self.X_train.columns if c not in self.categorical_columns]

    @property
    def unseen_attacks(self) -> set[str]:
        """Attack types in the test set that the models never saw in training."""
        seen = set(self.attack_train.unique())
        return set(self.attack_test[self.y_test != NORMAL].unique()) - seen


def text_columns(X: pd.DataFrame) -> list[str]:
    return list(X.select_dtypes(include=["object", "string", "category"]).columns)


# ----------------------------------------------------------------------------
# 1. Cleaning
# ----------------------------------------------------------------------------
def clean(df: pd.DataFrame, cfg: DatasetConfig, drop_duplicates: bool = True):
    """Return (cleaned DataFrame, report of what was changed)."""
    df = df.copy()
    label = cfg.label_column
    report = {"rows_before": len(df)}

    df[label] = df[label].astype(str).str.strip()

    numeric = df.select_dtypes(include="number").columns
    is_inf = np.isinf(df[numeric].to_numpy(dtype=float))
    report["infinite_replaced"] = int(is_inf.sum())
    df[numeric] = df[numeric].replace([np.inf, -np.inf], np.nan)

    no_label = df[label].isin(["", "nan", "None"])
    report["rows_without_label"] = int(no_label.sum())
    df = df[~no_label]

    report["duplicates_removed"] = 0
    if drop_duplicates:
        before = len(df)
        df = df.drop_duplicates()
        report["duplicates_removed"] = before - len(df)

    missing = df.isna().sum()
    report["missing_values"] = {c: int(n) for c, n in missing[missing > 0].items()}
    report["rows_after"] = len(df)
    return df.reset_index(drop=True), report


def constant_columns(X: pd.DataFrame) -> list[str]:
    """Columns with a single value carry no information (e.g. num_outbound_cmds)."""
    return [c for c in X.columns if X[c].nunique(dropna=False) <= 1]


# ----------------------------------------------------------------------------
# 2. Target
# ----------------------------------------------------------------------------
def make_target(raw_labels: pd.Series, cfg: DatasetConfig, target: str = "binary") -> pd.Series:
    """binary   -> 'normal' / 'attack'
    category -> 'normal' / attack family from the config (DoS, Probe, ...)
    """
    raw_labels = raw_labels.astype(str)
    is_normal = raw_labels == str(cfg.normal_value)
    if target == "binary":
        values = np.where(is_normal, NORMAL, ATTACK)
        return pd.Series(values, index=raw_labels.index, name="target")
    families = raw_labels.map(cfg.category_of) if cfg.attack_categories else raw_labels
    return families.where(~is_normal, NORMAL).rename("target")


# ----------------------------------------------------------------------------
# 3. Full preparation: clean -> target -> split -> sample
# ----------------------------------------------------------------------------
def prepare_data(
    cfg: Config,
    train_df: pd.DataFrame,
    test_df: pd.DataFrame | None = None,
    target: str | None = None,
    sample_fraction: float | None = None,
) -> PreparedData:
    ds, tr = cfg.dataset, cfg.training
    target = target or tr.target
    sample_fraction = tr.sample_fraction if sample_fraction is None else sample_fraction
    label = ds.label_column

    train_df, report = clean(train_df, ds)
    report = {"train_cleaning": report}

    if test_df is None:
        train_df, test_df = train_test_split(
            train_df,
            test_size=tr.test_size,
            stratify=make_target(train_df[label], ds, "binary"),
            random_state=tr.random_state,
        )
        report["split"] = f"no test file: train file split {1 - tr.test_size:.0%} / {tr.test_size:.0%}"
    else:
        test_df, test_report = clean(test_df, ds, drop_duplicates=False)
        report["test_cleaning"] = test_report
        report["split"] = "separate train and test files"

    if sample_fraction < 1.0:
        train_df, _ = train_test_split(
            train_df,
            train_size=sample_fraction,
            stratify=make_target(train_df[label], ds, "binary"),
            random_state=tr.random_state,
        )
        report["sampled_fraction"] = sample_fraction

    features = [c for c in train_df.columns if c != label]
    dropped = constant_columns(train_df[features])
    features = [c for c in features if c not in dropped]
    report["constant_columns_dropped"] = dropped

    X_train = train_df[features].reset_index(drop=True)
    X_test = test_df.reindex(columns=features).reset_index(drop=True)
    for col in text_columns(X_train):  # same dtype in both sets
        X_test[col] = X_test[col].astype(X_train[col].dtype)

    attack_train = train_df[label].reset_index(drop=True)
    attack_test = test_df[label].reset_index(drop=True)
    y_train = make_target(attack_train, ds, target)
    y_test = make_target(attack_test, ds, target)

    report["train_rows"] = len(X_train)
    report["test_rows"] = len(X_test)
    report["features"] = len(features)
    report["class_balance_train"] = y_train.value_counts().to_dict()

    return PreparedData(X_train, X_test, y_train, y_test, attack_train, attack_test, target, report)


# ----------------------------------------------------------------------------
# 4. Missing values + encoding + scaling
# ----------------------------------------------------------------------------
def build_preprocessor(X: pd.DataFrame) -> ColumnTransformer:
    """Numbers: fill missing with the median, then standard-scale.
    Text:    fill missing with the most frequent value, then one-hot encode.

    The column lists come from the data itself, so this works for any dataset.
    """
    cat_cols = text_columns(X)
    num_cols = [c for c in X.columns if c not in cat_cols]
    numeric = Pipeline([
        ("impute", SimpleImputer(strategy="median")),
        ("scale", StandardScaler()),
    ])
    categorical = Pipeline([
        ("impute", SimpleImputer(strategy="most_frequent")),
        ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
    ])
    return ColumnTransformer(
        [("num", numeric, num_cols), ("cat", categorical, cat_cols)],
        verbose_feature_names_out=False,
    )


def transformed_frame(preprocessor: ColumnTransformer, X: pd.DataFrame) -> pd.DataFrame:
    """Apply a fitted preprocessor and keep readable column names (for display)."""
    return pd.DataFrame(
        preprocessor.transform(X),
        columns=preprocessor.get_feature_names_out(),
        index=X.index,
    )
