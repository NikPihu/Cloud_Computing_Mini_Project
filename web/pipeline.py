"""Streaming pipeline: log sources -> queue -> analysis worker -> storage + CloudWatch.

Two kinds of source deliver records one by one:
  pull  - we connect to a feed URL that streams newline-delimited JSON
          (e.g. the bundled log-streamer container, or a company log shipper)
  push  - the customer's agent POSTs records to /api/v1/ingest with an API key
"""
import json
import logging
import os
import queue
import threading
import time
from collections import defaultdict

import pandas as pd
import requests

import storage
from cloudwatch import log_event, metrics
from engine import get_engine

log = logging.getLogger("netguard.pipeline")
RETENTION_HOURS = float(os.environ.get("STREAM_RETENTION_HOURS", "24"))


def record_row(rec, res, user_id, source_id=None, ts=None):
    """Flatten an input record + its analysis result into a DB row."""
    return {
        "user_id": user_id, "source_id": source_id, "ts": ts or time.time(),
        "src_ip": rec.get("src_ip"), "protocol": rec.get("protocol_type"), "service": rec.get("service"),
        "flag": rec.get("flag"), "src_bytes": _num(rec.get("src_bytes")), "dst_bytes": _num(rec.get("dst_bytes")),
        "label": _label(rec.get("label")),
        "verdict": res["verdict"], "prediction": res.get("prediction"),
        "confidence": _num(res.get("confidence")), "anomaly_score": _num(res.get("anomaly_score")),
        "family": res.get("family") or None,
    }


def _label(v):
    if v is None or (isinstance(v, float) and v != v):    # missing / NaN
        return None
    v = str(v).strip()
    return v or None


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def emit_metrics(rows, source):
    counts = defaultdict(int)
    for r in rows:
        counts[r["verdict"]] += 1
        if r.get("family"):
            metrics.count("AttacksByType", AttackType=r["family"])
    metrics.count("RecordsAnalyzed", len(rows), Source=source)
    metrics.count("RecordsAnalyzed", len(rows))
    metrics.count("Attacks", counts["Attack"])
    metrics.count("Suspicious", counts["Suspicious"])
    metrics.count("NormalTraffic", counts["Normal"])


class Pipeline:
    def __init__(self, max_queue=50_000, batch_size=500):
        self.q = queue.Queue(maxsize=max_queue)
        self.batch_size = batch_size
        self.readers = {}                       # source_id -> threading.Event (stop flag)
        self.stats = {"received": 0, "processed": 0, "dropped": 0, "flagged": 0, "started_at": None}
        self._latency = 0.0

    # ------------------------------------------------------------- producers
    def submit(self, user_id, source_id, records):
        accepted = 0
        for rec in records:
            try:
                self.q.put_nowait((user_id, source_id, rec, time.time()))
                accepted += 1
            except queue.Full:
                self.stats["dropped"] += 1
        self.stats["received"] += accepted
        return accepted

    def connect(self, source):
        """Start reading a pull source in a background thread."""
        if source["id"] in self.readers:
            return
        stop = threading.Event()
        self.readers[source["id"]] = stop
        threading.Thread(target=self._read_feed, args=(source, stop), daemon=True,
                         name=f"feed-{source['id']}").start()

    def disconnect(self, source_id):
        stop = self.readers.pop(source_id, None)
        if stop:
            stop.set()

    def _read_feed(self, src, stop):
        backoff = 2
        while not stop.is_set():
            try:
                with requests.get(src["url"], stream=True, timeout=(5, 60)) as resp:
                    resp.raise_for_status()
                    storage.execute("UPDATE sources SET status='active', last_error=NULL WHERE id=?", (src["id"],))
                    log_event(log, logging.INFO, "feed connected", source_id=src["id"], url=src["url"])
                    backoff = 2
                    for line in resp.iter_lines():
                        if stop.is_set():
                            return
                        line = line.decode("utf-8", "replace").strip()
                        if line.startswith("data:"):          # Server-Sent Events framing
                            line = line[5:].strip()
                        if not line or line[0] not in "{[":
                            continue
                        try:
                            data = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        self.submit(src["user_id"], src["id"], data if isinstance(data, list) else [data])
            except Exception as exc:  # network errors, bad payloads: report and reconnect
                if stop.is_set():
                    return
                msg = f"{type(exc).__name__}: {str(exc)[:200]}"
                storage.execute("UPDATE sources SET status='error', last_error=? WHERE id=?", (msg, src["id"]))
                metrics.count("FeedErrors")
                log_event(log, logging.WARNING, "feed error, retrying", source_id=src["id"], error=msg)
            stop.wait(backoff)
            backoff = min(backoff * 2, 30)

    # -------------------------------------------------------------- consumer
    def start(self):
        if self.stats["started_at"]:
            return
        self.stats["started_at"] = time.time()
        metrics.gauges["QueueDepth"] = self.q.qsize
        metrics.gauges["ActiveStreams"] = lambda: len(self.readers)
        threading.Thread(target=self._work, name="analysis-worker", daemon=True).start()
        threading.Thread(target=self._housekeeping, name="housekeeping", daemon=True).start()
        for src in storage.query("SELECT * FROM sources WHERE kind='pull' AND status!='paused'"):
            self.connect(src)

    def _work(self):
        while True:
            try:
                batch = [self.q.get(timeout=1)]
            except queue.Empty:
                continue
            while len(batch) < self.batch_size:
                try:
                    batch.append(self.q.get_nowait())
                except queue.Empty:
                    break
            try:
                self.process(batch)
            except Exception:
                log.exception("failed to analyse a batch of %d records", len(batch))

    def process(self, batch):
        engine = get_engine()
        by_user = defaultdict(list)
        for item in batch:
            by_user[item[0]].append(item)
        for user_id, items in by_user.items():
            services = storage.subscriptions(user_id)
            if not services:
                self.stats["dropped"] += len(items)
                continue
            t0 = time.time()
            df = pd.DataFrame([it[2] for it in items])
            results = engine.analyze(df, services).to_dict("records")
            rows = []
            for (uid, sid, rec, enq), res in zip(items, results):
                rows.append(record_row(rec, res, uid, sid, _num(rec.get("ts")) or enq))
            storage.insert_records(rows)
            per_source = defaultdict(int)
            for r in rows:
                per_source[r["source_id"]] += 1
            for sid, n in per_source.items():
                storage.execute("UPDATE sources SET records=records+?, last_seen=? WHERE id=?", (n, time.time(), sid))
            latency = (time.time() - min(it[3] for it in items)) * 1000
            self._latency = 0.8 * self._latency + 0.2 * latency
            metrics.sample("ProcessingLatency", latency)
            emit_metrics(rows, "stream")
            for r in rows:
                if r["verdict"] != "Normal":
                    self.stats["flagged"] += 1
                    log_event(log, logging.WARNING if r["verdict"] == "Attack" else logging.INFO,
                              f"{r['verdict'].upper()} {r['protocol']}/{r['service']} from {r['src_ip'] or '-'}",
                              event="detection", user_id=uid, source_id=r["source_id"], verdict=r["verdict"],
                              attack_type=r["family"], src_ip=r["src_ip"], service=r["service"],
                              confidence=r["confidence"], anomaly_score=r["anomaly_score"],
                              actual_label=r["label"])
            self.stats["processed"] += len(rows)

    def _housekeeping(self):
        while True:
            time.sleep(600)
            cutoff = time.time() - RETENTION_HOURS * 3600
            storage.execute("DELETE FROM records WHERE analysis_id IS NULL AND ts < ?", (cutoff,))

    def health(self):
        return {**self.stats, "queue_depth": self.q.qsize(), "active_feeds": len(self.readers),
                "avg_latency_ms": round(self._latency, 1),
                "uptime_s": round(time.time() - self.stats["started_at"]) if self.stats["started_at"] else 0}


pipeline = Pipeline()
