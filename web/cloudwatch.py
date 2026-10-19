"""Amazon CloudWatch integration.

Logs:    everything is written as one JSON object per line on stdout. On EC2 the
         Docker `awslogs` log driver (docker-compose.aws.yml) ships stdout to
         CloudWatch Logs, where Logs Insights can query the JSON fields.
Metrics: counters are aggregated in memory and sent to CloudWatch with
         PutMetricData once a minute (namespace NetGuard by default). Credentials
         come from the EC2 instance role, so no keys are stored anywhere.
"""
import json
import logging
import os
import sys
import threading
import time
from collections import defaultdict

NAMESPACE = os.environ.get("CW_NAMESPACE", "NetGuard")
REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or ""
LOG_GROUP = os.environ.get("CW_LOG_GROUP", "/netguard/web")
DASHBOARD = os.environ.get("CW_DASHBOARD", "NetGuard")
FLUSH_SECONDS = int(os.environ.get("CW_FLUSH_SECONDS", "60"))


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
                   "level": record.levelname, "logger": record.name, "msg": record.getMessage()}
        payload.update(getattr(record, "data", {}))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging():
    root = logging.getLogger()
    if any(getattr(h, "_netguard", False) for h in root.handlers):
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler._netguard = True
    root.handlers = [handler]
    root.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def log_event(logger, level, msg, **data):
    logger.log(level, msg, extra={"data": data})


class Metrics:
    """Thread-safe metric buffer with a background flusher to CloudWatch."""

    def __init__(self):
        self._lock = threading.Lock()
        self._sums = defaultdict(float)          # (name, dims, unit) -> value
        self._samples = defaultdict(list)        # (name, dims, unit) -> values (latency etc.)
        self.gauges = {}                         # name -> callable returning a value
        self.totals = defaultdict(float)         # lifetime counters, shown in the app
        self.status = {"enabled": False, "last_flush": None, "last_error": None, "sent": 0}
        self._client = None
        self._log = logging.getLogger("netguard.cloudwatch")

    # --------------------------------------------------------------- record
    def count(self, name, value=1, unit="Count", **dims):
        key = (name, tuple(sorted(dims.items())), unit)
        with self._lock:
            self._sums[key] += value
            self.totals[name] += value

    def sample(self, name, value, unit="Milliseconds", **dims):
        key = (name, tuple(sorted(dims.items())), unit)
        with self._lock:
            self._samples[key].append(float(value))

    # ---------------------------------------------------------------- flush
    def start(self):
        mode = os.environ.get("CW_METRICS", "auto").lower()
        if mode in ("off", "0", "false") or (mode == "auto" and not REGION):
            self.status["last_error"] = "disabled (set AWS_REGION / CW_METRICS=on to publish)"
            return
        try:
            import boto3
            self._client = boto3.client("cloudwatch", region_name=REGION or None)
            self.status["enabled"] = True
        except Exception as exc:  # boto3 missing or no region
            self.status["last_error"] = f"{type(exc).__name__}: {exc}"
            return
        threading.Thread(target=self._loop, name="cloudwatch-metrics", daemon=True).start()
        self._log.info("publishing metrics to CloudWatch", extra={"data": {"namespace": NAMESPACE, "region": REGION}})

    def _loop(self):
        while True:
            time.sleep(FLUSH_SECONDS)
            try:
                self.flush()
            except Exception as exc:
                self.status["last_error"] = f"{type(exc).__name__}: {exc}"
                self._log.warning("CloudWatch PutMetricData failed: %s", exc)

    def _drain(self):
        with self._lock:
            sums, samples = self._sums, self._samples
            self._sums, self._samples = defaultdict(float), defaultdict(list)
        now = time.time()
        data = []
        for (name, dims, unit), value in sums.items():
            data.append({"MetricName": name, "Value": value, "Unit": unit, "Timestamp": now,
                         "Dimensions": [{"Name": k, "Value": str(v)} for k, v in dims]})
        for (name, dims, unit), values in samples.items():
            data.append({"MetricName": name, "Unit": unit, "Timestamp": now,
                         "StatisticValues": {"SampleCount": len(values), "Sum": sum(values),
                                             "Minimum": min(values), "Maximum": max(values)},
                         "Dimensions": [{"Name": k, "Value": str(v)} for k, v in dims]})
        for name, fn in self.gauges.items():
            try:
                data.append({"MetricName": name, "Value": float(fn()), "Unit": "Count", "Timestamp": now})
            except Exception:
                pass
        return data

    def flush(self):
        data = self._drain()
        if not self._client or not data:
            return
        for i in range(0, len(data), 500):          # API limit: 1000 values per call
            self._client.put_metric_data(Namespace=NAMESPACE, MetricData=data[i:i + 500])
        self.status.update(last_flush=time.time(), last_error=None, sent=self.status["sent"] + len(data))

    def console_links(self):
        if not REGION:
            return {}
        base = f"https://{REGION}.console.aws.amazon.com/cloudwatch/home?region={REGION}"
        group = LOG_GROUP.replace("/", "$252F")
        return {
            "dashboard": f"{base}#dashboards/dashboard/{DASHBOARD}",
            "metrics": f"{base}#metricsV2?graph=~()&namespace=~'{NAMESPACE}",
            "logs": f"{base}#logsV2:log-groups/log-group/{group}",
            "insights": f"{base}#logsV2:logs-insights",
            "alarms": f"{base}#alarmsV2:",
        }


metrics = Metrics()
