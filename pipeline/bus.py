"""Real-time log pipeline: producer -> queue -> stream-processing worker -> storage/sinks.

Producers (the web store, the attack simulator) call `bus.publish(event)`.
A background consumer drains the queue in micro-batches, computes features
with sliding windows, scores them with the detector and persists the results.

This is the in-process equivalent of Kinesis/SQS/Pub-Sub + a Lambda consumer;
the interface (publish / consume) is what you would keep when swapping the
`queue.Queue` for a managed queue.
"""
import logging
import queue
import threading
import time
from collections import deque

import storage
from ml.engine import get_detector
from ml.features import FeatureState

from .sinks import emit_detection, send_alert

log = logging.getLogger("shopsecure.pipeline")


class EventBus:
    def __init__(self, tz_offset_hours=5.5, alert_lookup=None, max_queue=20000, batch_size=256):
        self.q = queue.Queue(maxsize=max_queue)
        self.state = FeatureState(tz_offset_hours)
        self.alert_lookup = alert_lookup or (lambda tenant: None)
        self.batch_size = batch_size
        self._thread = None
        self._throughput = deque()            # (time, n) for the last 60 s
        self.stats = {"published": 0, "processed": 0, "flagged": 0, "dropped": 0,
                      "avg_latency_ms": 0.0, "started_at": None}

    # ---------------------------------------------------------- producer API
    def publish(self, event):
        event.setdefault("ts", time.time())
        event["_enqueued"] = time.time()
        try:
            self.q.put_nowait(event)
            self.stats["published"] += 1
        except queue.Full:
            self.stats["dropped"] += 1

    def publish_many(self, events):
        for e in events:
            self.publish(e)

    # ---------------------------------------------------------- consumer
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._warm_up()
        self.stats["started_at"] = time.time()
        self._thread = threading.Thread(target=self._run, name="log-pipeline", daemon=True)
        self._thread.start()
        log.info("pipeline worker started")

    def _warm_up(self, limit=5000):
        """Rebuild sliding windows and known devices from recent history after a restart."""
        rows = storage.query("SELECT * FROM (SELECT * FROM events ORDER BY ts DESC LIMIT ?) ORDER BY ts", (limit,))
        for r in rows:
            self.state.featurize({**r, "success": bool(r["success"])})

    def _run(self):
        while True:
            try:
                batch = [self.q.get(timeout=1.0)]
            except queue.Empty:
                continue
            while len(batch) < self.batch_size:
                try:
                    batch.append(self.q.get_nowait())
                except queue.Empty:
                    break
            try:
                self.process(batch)
            except Exception:  # keep the worker alive whatever happens
                log.exception("failed to process batch of %d events", len(batch))

    def process(self, batch):
        batch.sort(key=lambda e: e["ts"])
        feats = [self.state.featurize(e) for e in batch]
        preds = get_detector().predict(feats)
        now = time.time()
        rows = []
        for e, p in zip(batch, preds):
            latency = (now - e.get("_enqueued", now)) * 1000
            rows.append((e["ts"], e.get("tenant"), e.get("user"), e.get("ip"), e.get("action"),
                         int(bool(e.get("success", True))), e.get("path"), e.get("status"),
                         (e.get("user_agent") or "")[:300], e.get("source", "web"),
                         p["label"], p["risk"], p["reason"], round(latency, 2)))
            if p["label"] != "Normal":
                self.stats["flagged"] += 1
                record = {"ts": e["ts"], "tenant": e.get("tenant"), "user": e.get("user"), "ip": e.get("ip"),
                          "action": e.get("action"), "source": e.get("source", "web"), **p}
                emit_detection(record)
                if p["label"] == "Malicious":
                    send_alert(self.alert_lookup(e.get("tenant")), record)
            self.stats["avg_latency_ms"] = 0.9 * self.stats["avg_latency_ms"] + 0.1 * latency
        storage.insert_events(rows)
        self.stats["processed"] += len(batch)
        self._throughput.append((now, len(batch)))
        while self._throughput and self._throughput[0][0] < now - 60:
            self._throughput.popleft()

    # ---------------------------------------------------------- monitoring
    def health(self):
        now = time.time()
        recent = sum(n for t, n in self._throughput if t >= now - 60)
        return {**self.stats, "avg_latency_ms": round(self.stats["avg_latency_ms"], 2),
                "queue_depth": self.q.qsize(), "events_per_min": recent,
                "worker_alive": bool(self._thread and self._thread.is_alive()),
                "uptime_s": round(now - self.stats["started_at"]) if self.stats["started_at"] else 0}
