"""Charts used by both the notebooks and the GUI.

Every function returns a matplotlib Figure, so a notebook simply displays
it and the GUI calls ``st.pyplot(fig)``. Colours follow one fixed rule:
the same class or model always gets the same colour on every chart.
"""
from __future__ import annotations

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.colors import LinearSegmentedColormap

from nids.config import FIGURES_DIR

# ---- palette ---------------------------------------------------------------
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100",
          "#e87ba4", "#008300", "#6250d6", "#e34948"]
STATUS = {"good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a", "critical": "#d03b3b"}

# Same entity -> same colour, on every chart.
CLASS_COLORS = {
    "normal": SERIES[0], "attack": SERIES[1],
    "DoS": SERIES[1], "Probe": SERIES[2], "R2L": SERIES[3], "U2R": SERIES[4], "Other": SERIES[6],
    "Known attack": SERIES[1], "Unseen attack": SERIES[2],
}
MODEL_COLORS = {
    "Logistic Regression": SERIES[0], "Naive Bayes": SERIES[1],
    "Decision Tree": SERIES[2], "Random Forest": SERIES[3],
    "Isolation Forest": SERIES[6], "Hybrid (RF + IF)": SERIES[4], "Hybrid": SERIES[4],
}
BLUES = LinearSegmentedColormap.from_list(
    "nids_blues", ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"])
BLUE_RED = LinearSegmentedColormap.from_list(
    "nids_diverging", ["#184f95", "#6da7ec", "#f0efec", "#ef8f8e", "#c0302f"])

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": AXIS, "axes.labelcolor": INK_SECONDARY, "axes.titlecolor": INK,
    "axes.titlesize": 12, "axes.titleweight": "bold", "axes.titlelocation": "left",
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "axes.axisbelow": True, "grid.color": GRID, "grid.linewidth": 0.8,
    "xtick.color": MUTED, "ytick.color": MUTED, "xtick.labelcolor": INK_SECONDARY,
    "ytick.labelcolor": INK_SECONDARY, "legend.frameon": False, "font.size": 10,
    "lines.linewidth": 2, "figure.dpi": 100,
})


def color_for(name: str, i: int = 0) -> str:
    return CLASS_COLORS.get(name) or MODEL_COLORS.get(name) or SERIES[i % len(SERIES)]


def _ink_on(fill: tuple) -> str:
    r, g, b = fill[:3]
    return INK if (0.299 * r + 0.587 * g + 0.114 * b) > 0.55 else "white"


def save_figure(fig, name: str) -> None:
    """Save a chart to reports/figures/ for the written report."""
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURES_DIR / f"{name}.png", dpi=150, bbox_inches="tight")


# ---- data exploration (PR5) -----------------------------------------------
def bar_counts(counts: pd.Series, title: str, xlabel: str = "Rows", log: bool = False):
    """Horizontal bars, largest on top, value at the tip of each bar."""
    counts = counts.sort_values()
    fig, ax = plt.subplots(figsize=(7, max(2.2, 0.32 * len(counts) + 1)))
    colors = [color_for(str(k)) if str(k) in CLASS_COLORS else SERIES[0] for k in counts.index]
    ax.barh(counts.index.astype(str), counts.values, color=colors, height=0.6)
    for y, v in enumerate(counts.values):
        ax.text(v, y, f" {v:,}", va="center", color=INK_SECONDARY, fontsize=9)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    if log:
        ax.set_xscale("log")
    ax.grid(axis="y", visible=False)
    ax.margins(x=0.15)
    fig.tight_layout()
    return fig


def _wide(values: pd.Series) -> bool:
    """True for columns like byte counts that span many orders of magnitude."""
    return values.max() > 100


def _display_values(values: pd.Series, log_values: bool) -> tuple[pd.Series, str]:
    if log_values and _wide(values):
        return np.log10(1 + values.clip(lower=0)), " (log10 of 1 + value)"
    return values, ""


def histograms(df: pd.DataFrame, columns: list[str], groups: pd.Series, bins: int = 30,
               log_values: bool = True, ncols: int = 3):
    """One small histogram per column, normal vs attack overlaid.

    Network features are very skewed (most connections send a few bytes, some
    send millions), so wide-range columns are shown as log10(1 + value) and
    the counts use a log scale.
    """
    nrows = int(np.ceil(len(columns) / ncols))
    fig, axes = plt.subplots(nrows, ncols, figsize=(4 * ncols, 2.8 * nrows), squeeze=False)
    groups = pd.Series(np.asarray(groups), index=df.index)
    for ax, col in zip(axes.flat, columns):
        values, note = _display_values(df[col], log_values)
        edges = np.histogram_bin_edges(values.dropna(), bins=bins)
        for i, g in enumerate(sorted(groups.unique(), key=lambda c: (c != "normal", c))):
            v = values[groups == g].dropna()
            ax.hist(v, bins=edges, histtype="stepfilled", alpha=0.18, color=color_for(g, i))
            ax.hist(v, bins=edges, histtype="step", linewidth=1.6, color=color_for(g, i), label=g)
        ax.set_title(col + note, fontsize=10)
        ax.set_yscale("log")
        ax.grid(axis="x", visible=False)
    for ax in list(axes.flat)[len(columns):]:
        ax.set_visible(False)
    axes.flat[0].legend(loc="upper right", fontsize=8)
    fig.suptitle("Feature distributions (count on a log scale)", x=0.01, ha="left", fontsize=11, color=INK)
    fig.tight_layout()
    return fig


def boxplots(df: pd.DataFrame, columns: list[str], groups: pd.Series, log_values: bool = True,
             ncols: int = 3):
    """Box plot per column, one box per class - shows spread and outliers."""
    nrows = int(np.ceil(len(columns) / ncols))
    fig, axes = plt.subplots(nrows, ncols, figsize=(4 * ncols, 2.8 * nrows), squeeze=False)
    groups = pd.Series(np.asarray(groups), index=df.index)
    order = sorted(groups.unique(), key=lambda c: (c != "normal", c))
    for ax, col in zip(axes.flat, columns):
        values, note = _display_values(df[col], log_values)
        data = [values[groups == g].dropna() for g in order]
        bp = ax.boxplot(data, vert=False, patch_artist=True, widths=0.5,
                        flierprops={"marker": "o", "markersize": 2, "alpha": 0.3,
                                    "markeredgecolor": MUTED},
                        medianprops={"color": INK, "linewidth": 1.5})
        for patch, g in zip(bp["boxes"], order):
            patch.set_facecolor(color_for(g))
            patch.set_alpha(0.6)
            patch.set_edgecolor(color_for(g))
        ax.set_yticks(range(1, len(order) + 1), order)
        ax.set_title(col + note, fontsize=10)
        ax.grid(axis="y", visible=False)
    for ax in list(axes.flat)[len(columns):]:
        ax.set_visible(False)
    fig.suptitle("Box plots: spread of each feature per class", x=0.01, ha="left", fontsize=11, color=INK)
    fig.tight_layout()
    return fig


def correlation_heatmap(df: pd.DataFrame, columns: list[str]):
    corr = df[columns].corr().fillna(0)
    size = 0.42 * len(columns) + 2
    fig, ax = plt.subplots(figsize=(size + 1, size))
    im = ax.imshow(corr.values, cmap=BLUE_RED, vmin=-1, vmax=1)
    ax.set_xticks(range(len(columns)), columns, rotation=90, fontsize=8)
    ax.set_yticks(range(len(columns)), columns, fontsize=8)
    ax.grid(False)
    fig.colorbar(im, ax=ax, shrink=0.7, label="Correlation")
    ax.set_title("Correlation between features")
    fig.tight_layout()
    return fig


# ---- evaluation ------------------------------------------------------------
def confusion_matrix_plot(cm: pd.DataFrame, title: str = "Confusion matrix", ax=None):
    own_fig = ax is None
    if own_fig:
        fig, ax = plt.subplots(figsize=(1.1 * len(cm) + 2.4, 1.0 * len(cm) + 1.6))
    share = cm.div(cm.sum(axis=1).replace(0, 1), axis=0)  # colour = share of the actual class
    ax.imshow(share.values, cmap=BLUES, vmin=0, vmax=1)
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            fill = BLUES(share.values[i, j])
            ax.text(j, i, f"{cm.values[i, j]:,}\n{share.values[i, j]:.0%}", ha="center",
                    va="center", fontsize=9, color=_ink_on(fill))
    ax.set_xticks(range(cm.shape[1]), cm.columns)
    ax.set_yticks(range(cm.shape[0]), cm.index)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.grid(False)
    ax.set_title(title, fontsize=11)
    if own_fig:
        fig.tight_layout()
        return fig
    return ax.figure


def confusion_grid(tables: dict[str, pd.DataFrame], ncols: int = 2):
    n = len(tables)
    k = len(next(iter(tables.values())))
    nrows = int(np.ceil(n / ncols))
    fig, axes = plt.subplots(nrows, ncols, figsize=(ncols * (1.1 * k + 2.6), nrows * (1.0 * k + 1.8)),
                             squeeze=False)
    for ax, (name, cm) in zip(axes.flat, tables.items()):
        confusion_matrix_plot(cm, name, ax=ax)
    for ax in list(axes.flat)[n:]:
        ax.set_visible(False)
    fig.tight_layout()
    return fig


def metrics_comparison(metrics: pd.DataFrame, columns=("Accuracy", "Precision", "Recall", "F1")):
    """Grouped horizontal bars: one group per metric, one bar per model."""
    columns = [c for c in columns if c in metrics.columns]
    models = list(metrics.index)
    fig, ax = plt.subplots(figsize=(8, 0.45 * len(models) * len(columns) + 1.2))
    height = 0.8 / len(models)
    for i, model in enumerate(models):
        ys = np.arange(len(columns)) + i * height
        vals = metrics.loc[model, columns].astype(float).values
        ax.barh(ys, vals, height=height * 0.85, color=color_for(model, i), label=model)
        for y, v in zip(ys, vals):
            ax.text(v, y, f" {v:.3f}", va="center", fontsize=8, color=INK_SECONDARY)
    ax.set_yticks(np.arange(len(columns)) + 0.4 - height / 2, columns)
    ax.invert_yaxis()
    ax.set_xlim(0, 1.12)
    ax.set_xlabel("Score (higher is better)")
    ax.grid(axis="y", visible=False)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=min(4, len(models)), fontsize=9)
    ax.set_title("Model comparison on the test set", pad=28)
    fig.tight_layout()
    return fig


def feature_importance_plot(importance: pd.Series, top_n: int = 15):
    top = importance.head(top_n).sort_values()
    fig, ax = plt.subplots(figsize=(7, 0.3 * len(top) + 1.2))
    ax.barh(top.index, top.values, color=SERIES[0], height=0.6)
    ax.set_title(f"Top {len(top)} most important features")
    ax.set_xlabel("Importance (share of the model's decisions)")
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    return fig


def roc_plot(curves: dict[str, tuple]):
    fig, ax = plt.subplots(figsize=(6, 5))
    for i, (name, (fpr, tpr, area)) in enumerate(curves.items()):
        ax.plot(fpr, tpr, color=color_for(name, i), label=f"{name} (AUC {area:.3f})")
    ax.plot([0, 1], [0, 1], color=AXIS, linewidth=1, label="Random guess")
    ax.set_xlabel("False positive rate (normal flagged as attack)")
    ax.set_ylabel("True positive rate (attacks caught)")
    ax.set_title("ROC curves")
    ax.legend(loc="lower right", fontsize=9)
    fig.tight_layout()
    return fig


def grouped_rates(table: pd.DataFrame, title: str, xlabel: str = "Share of rows",
                  fmt: str = "{:.1%}"):
    """Rows = approaches/models, columns = groups (e.g. known vs unseen attacks)."""
    groups = list(table.columns)
    fig, ax = plt.subplots(figsize=(8, 0.5 * len(table) * len(groups) + 1.4))
    height = 0.8 / len(table)
    for i, name in enumerate(table.index):
        ys = np.arange(len(groups)) + i * height
        vals = table.loc[name].astype(float).values
        ax.barh(ys, vals, height=height * 0.85, color=color_for(name, i), label=name)
        for y, v in zip(ys, vals):
            ax.text(v, y, " " + fmt.format(v), va="center", fontsize=8, color=INK_SECONDARY)
    ax.set_yticks(np.arange(len(groups)) + 0.4 - height / 2, groups)
    ax.invert_yaxis()
    ax.set_xlim(0, 1.15)
    ax.set_xlabel(xlabel)
    ax.grid(axis="y", visible=False)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=min(3, len(table)), fontsize=9)
    ax.set_title(title, pad=28)
    fig.tight_layout()
    return fig


def before_after(before: dict, after: dict, title: str = "Before vs after tuning"):
    table = pd.DataFrame({"Before tuning": before, "After tuning": after}).T
    table.index.name = None
    return grouped_rates(table, title, xlabel="Score", fmt="{:.4f}")


# ---- anomaly detection -----------------------------------------------------
def score_histogram(scores: np.ndarray, groups: pd.Series, threshold: float, bins: int = 60):
    fig, ax = plt.subplots(figsize=(8, 3.6))
    edges = np.histogram_bin_edges(scores, bins=bins)
    groups = np.asarray(groups)
    for i, g in enumerate(sorted(pd.unique(groups), key=lambda c: (c != "normal", c))):
        v = scores[groups == g]
        ax.hist(v, bins=edges, histtype="stepfilled", alpha=0.15, color=color_for(g, i))
        ax.hist(v, bins=edges, histtype="step", linewidth=1.6, color=color_for(g, i), label=f"{g} ({len(v):,})")
    ax.axvline(threshold, color=INK, linewidth=1.2)
    ax.text(threshold, ax.get_ylim()[1] * 0.95, "  alarm threshold", color=INK, fontsize=9, va="top")
    ax.set_xlabel("Anomaly score (higher = more unusual)")
    ax.set_ylabel("Connections")
    ax.set_title("Anomaly scores on the test set")
    ax.grid(axis="x", visible=False)
    ax.legend(fontsize=9)
    fig.tight_layout()
    return fig


def pca_scatter(points: pd.DataFrame, groups: pd.Series, variance=None, max_points: int = 4000):
    """2-D picture of the traffic. At most three groups (colour-blind safe)."""
    df = points.assign(group=np.asarray(groups))
    if len(df) > max_points:
        df = df.sample(max_points, random_state=0)
    fig, ax = plt.subplots(figsize=(7, 5))
    for i, g in enumerate(sorted(df["group"].unique(), key=lambda c: (c != "normal", c))):
        part = df[df["group"] == g]
        ax.scatter(part["PC1"], part["PC2"], s=14, color=color_for(g, i), alpha=0.6,
                   edgecolors=SURFACE, linewidths=0.6, label=f"{g} ({len(part):,})")
    # A handful of extreme connections would squash everything else into a
    # corner, so the view is zoomed to the central 98% of points.
    for axis, col in (("x", "PC1"), ("y", "PC2")):
        lo, hi = np.percentile(df[col], [1, 99])
        pad = (hi - lo) * 0.08
        getattr(ax, f"set_{axis}lim")(lo - pad, hi + pad)
    if variance is not None:
        ax.set_xlabel(f"PC1 ({variance[0]:.0%} of variance)")
        ax.set_ylabel(f"PC2 ({variance[1]:.0%} of variance)")
    ax.set_title("Traffic projected to 2-D with PCA (zoomed to 98% of points)")
    ax.legend(fontsize=9, markerscale=1.5)
    fig.tight_layout()
    return fig
