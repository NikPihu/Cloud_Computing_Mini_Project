"""Generate the labelled sample CSV offered for upload / URL import demos."""
import csv
import datetime as dt
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ml.synth import generate_training_events  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "static", "samples", "sample_login_events.csv")

events = sorted(generate_training_events(seed=2024, days=1, scale=0.12), key=lambda e: e["ts"])
shift = dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc).timestamp() - events[0]["ts"] // 86400 * 86400
with open(OUT, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["timestamp", "ip", "user", "action", "success", "user_agent", "path", "status", "invalid_user", "label"])
    for e in events:
        ts = dt.datetime.fromtimestamp(e["ts"] + shift, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        w.writerow([ts, e["ip"], e["user"] or "", e["action"], int(e["success"]), e["user_agent"] or "",
                    e["path"] or "", e["status"] or "", int(e["invalid_user"]), e["label"]])
print(f"wrote {len(events)} events to {OUT}")
