"""Turns analysed records into the numbers and series the dashboards draw."""
from collections import Counter, defaultdict

VERDICTS = ["Normal", "Suspicious", "Attack"]


def _bucket_size(span):
    for size in (5, 10, 30, 60, 300, 600, 1800, 3600, 3 * 3600, 6 * 3600, 86400):
        if span / size <= 60:
            return size
    return 7 * 86400


def summarize(rows, threshold=None, by_time=True, recent=50):
    total = len(rows)
    counts = Counter(r["verdict"] for r in rows)
    flagged = [r for r in rows if r["verdict"] != "Normal"]

    # activity over time (live) or over the file in order (batch)
    timeline = {"labels": [], "series": {v: [] for v in VERDICTS}, "mode": "time" if by_time else "order",
                "bucket": 0}
    if rows:
        buckets = defaultdict(Counter)
        if by_time:
            t0, t1 = min(r["ts"] for r in rows), max(r["ts"] for r in rows)
            size = _bucket_size(max(t1 - t0, 1))
            start = int(t0 // size * size)
            n = int((t1 - start) // size) + 1
            for r in rows:
                buckets[int((r["ts"] - start) // size)][r["verdict"]] += 1
            timeline["labels"] = [start + i * size for i in range(n)]
        else:
            size = max(1, -(-total // 50))
            n = -(-total // size)
            for i, r in enumerate(rows):
                buckets[i // size][r["verdict"]] += 1
            timeline["labels"] = [f"{i * size + 1:,}-{min((i + 1) * size, total):,}" for i in range(n)]
        timeline["bucket"] = size
        for v in VERDICTS:
            timeline["series"][v] = [buckets[i][v] for i in range(n)]

    def by_field(field, top=10):
        acc = defaultdict(Counter)
        for r in rows:
            if r.get(field):
                acc[r[field]][r["verdict"]] += 1
        ranked = sorted(acc.items(), key=lambda kv: (kv[1]["Attack"] + kv[1]["Suspicious"], sum(kv[1].values())),
                        reverse=True)[:top]
        return [{"name": k, **{v: c[v] for v in VERDICTS}} for k, c in ranked]

    scores = [r["anomaly_score"] for r in rows if r.get("anomaly_score") is not None]
    hist = None
    if scores:
        lo, hi = min(scores), max(scores)
        if threshold is not None:
            lo, hi = min(lo, threshold), max(hi, threshold)
        width = (hi - lo) / 20 or 1
        bins = [0] * 20
        for s in scores:
            bins[min(int((s - lo) / width), 19)] += 1
        hist = {"edges": [round(lo + i * width, 3) for i in range(21)], "counts": bins, "threshold": threshold}

    return {
        "kpis": {
            "total": total, "normal": counts["Normal"], "suspicious": counts["Suspicious"],
            "attack": counts["Attack"],
            "threat_pct": round(100 * len(flagged) / total, 1) if total else 0,
            "sources": len({r["src_ip"] for r in rows if r.get("src_ip")}),
            "services_hit": len({r["service"] for r in flagged if r.get("service")}),
            "avg_confidence": round(100 * sum(r["confidence"] for r in rows if r.get("confidence") is not None)
                                    / max(1, sum(1 for r in rows if r.get("confidence") is not None)), 1),
        },
        "distribution": {v: counts[v] for v in VERDICTS},
        "timeline": timeline,
        "families": Counter(r["family"] for r in flagged if r.get("family")).most_common(),
        "services": by_field("service"),
        "protocols": by_field("protocol", 5),
        "sources": by_field("src_ip"),
        "anomaly_hist": hist,
        "recent_flagged": [
            {k: r.get(k) for k in ("ts", "src_ip", "protocol", "service", "flag", "verdict", "family",
                                   "confidence", "anomaly_score", "label")}
            for r in (sorted(flagged, key=lambda r: -r["ts"]) if by_time else flagged)[:recent]
        ],
    }
