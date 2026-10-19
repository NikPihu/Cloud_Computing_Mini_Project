"""Project settings.

Reads a YAML file from ``config/`` and turns it into small, typed objects so
the rest of the code can write ``cfg.dataset.label_column`` instead of
digging through dictionaries. All paths are resolved relative to the project
root, so the code works no matter which folder you start it from (notebooks/,
the project root, or a cloud server).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
MODELS_DIR = PROJECT_ROOT / "models"
FIGURES_DIR = PROJECT_ROOT / "reports" / "figures"
SAMPLE_DIR = PROJECT_ROOT / "data" / "sample"
UPLOAD_DIR = PROJECT_ROOT / "data" / "uploads"
DEFAULT_CONFIG = CONFIG_DIR / "nsl_kdd.yaml"


def resolve_path(path: str | Path | None) -> Path | None:
    """Turn a path from the YAML file into an absolute path."""
    if path is None:
        return None
    path = Path(path)
    return path if path.is_absolute() else PROJECT_ROOT / path


@dataclass
class DatasetConfig:
    name: str
    train_path: Path
    label_column: str
    normal_value: str
    test_path: Path | None = None
    has_header: bool = True
    columns: list[str] | None = None
    drop_columns: list[str] = field(default_factory=list)
    categorical_columns: list[str] | str = "auto"
    attack_categories: dict[str, list[str]] = field(default_factory=dict)
    download: dict[str, str] = field(default_factory=dict)
    description: str = ""

    def category_of(self, attack_name: str) -> str:
        """Map a raw label (e.g. 'neptune') to its family (e.g. 'DoS')."""
        if attack_name == self.normal_value:
            return self.normal_value
        for category, members in self.attack_categories.items():
            if attack_name in members:
                return category
        return "Other"


@dataclass
class TrainingConfig:
    target: str = "binary"
    test_size: float = 0.2
    sample_fraction: float = 1.0
    random_state: int = 42
    models: list[str] = field(default_factory=lambda: ["Random Forest"])
    cv_folds: int = 3
    tuning_sample_size: int = 20000


@dataclass
class AnomalyConfig:
    n_estimators: int = 200
    false_alarm_rate: float = 0.05


@dataclass
class Config:
    dataset: DatasetConfig
    training: TrainingConfig = field(default_factory=TrainingConfig)
    anomaly: AnomalyConfig = field(default_factory=AnomalyConfig)
    live_input_features: list[str] | str = "auto"
    source: Path | None = None


def config_from_dict(raw: dict, source: Path | None = None) -> Config:
    """Build a Config from a plain dictionary (the parsed YAML)."""
    ds = dict(raw["dataset"])
    ds["train_path"] = resolve_path(ds["train_path"])
    ds["test_path"] = resolve_path(ds.get("test_path"))
    ds["drop_columns"] = ds.get("drop_columns") or []
    ds["attack_categories"] = ds.get("attack_categories") or {}
    ds["download"] = ds.get("download") or {}
    ds["description"] = (ds.get("description") or "").strip()
    return Config(
        dataset=DatasetConfig(**ds),
        training=TrainingConfig(**(raw.get("training") or {})),
        anomaly=AnomalyConfig(**(raw.get("anomaly") or {})),
        live_input_features=(raw.get("ui") or {}).get("live_input_features", "auto"),
        source=source,
    )


def load_config(path: str | Path | None = None) -> Config:
    """Load a YAML config.

    Priority: the ``path`` argument, then the ``NIDS_CONFIG`` environment
    variable (handy on a cloud server), then ``config/nsl_kdd.yaml``.
    """
    path = resolve_path(path or os.environ.get("NIDS_CONFIG") or DEFAULT_CONFIG)
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return config_from_dict(raw, source=path)


def list_configs() -> list[Path]:
    """All dataset configs available in ``config/``."""
    return sorted(CONFIG_DIR.glob("*.yaml"))
