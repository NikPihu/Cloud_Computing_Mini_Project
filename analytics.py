"""Aggregates scored events into the numbers and series the dashboards draw."""
import time
from collections import Counter, defaultdict

LABELS = ["Normal", "Suspicious", "Malicious"]


def _bucket_size(span):
    for size in (10, 30, 60, 300, 600, 1800, 3600, 3 * 3600, 6 * 3600, 86400):
        if span / size <= 48:
            return size
    return 7 * 86400


def summarize(rows, recent=40):
    """rows: dicts with ts, ip, user, label, risk, reason (+ optional action/path)."""
    total = len(rows)
    counts = Counter(r["label"] for r in rows)
    flagged = [r for r in rows if r["label"] != "Normal"]

    timeline = {"labels": [], "series": {l: [] for l in LABELS}, "bucket_seconds": 0}
    if rows:
        t0, t1 = min(r["ts"] for r in rows), max(r["ts"] for r in rows)
        size = _bucket_size(max(t1 - t0, 1))
        start = int(t0 // size * size)
        n = int((t1 - start) // size) + 1
        buckets = defaultdict(Counter)
        for r in rows:
            buckets[int((r["ts"] - start) // size)][r["label"]] += 1
        timeline["bucket_seconds"] = size
        timeline["labels"] = [start + i * size for i in range(n)]
        for l in LABELS:
            timeline["series"][l] = [buckets[i][l] for i in range(n)]

    per_ip = defaultdict(Counter)
    for r in flagged:
        per_ip[r["ip"]][r["label"]] += 1
    top_ips = sorted(per_ip.items(), key=lambda kv: (kv[1]["Malicious"], kv[1]["Suspicious"]), reverse=True)[:10]

    hist = [0] * 10
    for r in rows:
        hist[min(int((r["risk"] or 0) // 10), 9)] += 1

    return {
        "kpis": {
            "total": total,
            "normal": counts["Normal"],
            "suspicious": counts["Suspicious"],
            "malicious": counts["Malicious"],
            "threat_pct": round(100 * len(flagged) / total, 1) if total else 0,
            "unique_ips": len({r["ip"] for r in rows}),
            "unique_users": len({r["user"] for r in rows if r.get("user")}),
            "flagged_ips": len(per_ip),
            "avg_risk": round(sum(r["risk"] or 0 for r in rows) / total, 1) if total else 0,
        },
        "distribution": {l: counts[l] for l in LABELS},
        "timeline": timeline,
        "top_ips": [{"ip": ip, "Suspicious": c["Suspicious"], "Malicious": c["Malicious"]} for ip, c in top_ips],
        "reasons": Counter(r["reason"] for r in flagged if r.get("reason")).most_common(8),
        "risk_hist": hist,
        "recent_flagged": [
            {k: r.get(k) for k in ("ts", "ip", "user", "action", "label", "risk", "reason")}
            for r in sorted(flagged, key=lambda r: (-r["ts"], -(r["risk"] or 0)))[:recent]
        ],
        "generated_at": time.time(),
    }
