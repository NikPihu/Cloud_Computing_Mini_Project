"""Dataset collection and loading.

Works for any CSV that a config describes: with or without a header row,
with one file (we split it later) or separate train/test files.
"""
from __future__ import annotations

import urllib.request
from pathlib import Path

import numpy as np
import pandas as pd

from nids.config import DatasetConfig


def download_dataset(cfg: DatasetConfig, force: bool = False) -> list[Path]:
    """Download the train/test files listed under ``download:`` in the config.

    Files that already exist are skipped unless ``force=True``.
    """
    saved = []
    for split, url in cfg.download.items():
        path = cfg.train_path if split == "train" else cfg.test_path
        if path is None or (path.exists() and not force):
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(url, path)
        saved.append(path)
    return saved


def load_raw(cfg: DatasetConfig, split: str = "train") -> pd.DataFrame | None:
    """Read the raw train or test file into a DataFrame.

    Returns ``None`` when the config has no file for that split
    (e.g. no separate test file).
    """
    path = cfg.train_path if split == "train" else cfg.test_path
    if path is None:
        return None
    if not path.exists():
        download_dataset(cfg)
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    if cfg.has_header:
        df = pd.read_csv(path, low_memory=False)
    else:
        df = pd.read_csv(path, header=None, names=cfg.columns, low_memory=False)

    df.columns = [str(c).strip() for c in df.columns]
    df = df.drop(columns=[c for c in cfg.drop_columns if c in df.columns])
    validate(df, cfg)
    return df


def validate(df: pd.DataFrame, cfg: DatasetConfig) -> None:
    """Fail early with a clear message if the file does not match the config."""
    if cfg.label_column not in df.columns:
        raise ValueError(
            f"Label column '{cfg.label_column}' not found. "
            f"Available columns: {list(df.columns)[:15]}..."
        )
    labels = df[cfg.label_column].astype(str).str.strip()
    if not (labels == str(cfg.normal_value)).any():
        raise ValueError(
            f"No rows have the normal value '{cfg.normal_value}' in "
            f"'{cfg.label_column}'. Example values: {labels.unique()[:10].tolist()}"
        )


def categorical_columns(df: pd.DataFrame, cfg: DatasetConfig) -> list[str]:
    """Text columns (excluding the label) - or the list given in the config."""
    if isinstance(cfg.categorical_columns, list):
        return [c for c in cfg.categorical_columns if c in df.columns]
    text = df.select_dtypes(include=["object", "string", "category"]).columns
    return [c for c in text if c != cfg.label_column]


def summarize(df: pd.DataFrame, cfg: DatasetConfig) -> dict:
    """Quick facts shown at the top of notebook 01 and the GUI Data page."""
    labels = df[cfg.label_column].astype(str)
    numeric = df.select_dtypes(include="number")
    return {
        "rows": len(df),
        "columns": df.shape[1] - 1,  # features only
        "categorical": len(categorical_columns(df, cfg)),
        "numeric": numeric.shape[1],
        "missing_values": int(df.isna().sum().sum()),
        "infinite_values": int(np.isinf(numeric.to_numpy(dtype=float)).sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "attack_share": float((labels != str(cfg.normal_value)).mean()),
        "label_types": int(labels.nunique()),
    }
