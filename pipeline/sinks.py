"""Where detection results go: structured cloud logs, a JSONL audit file, webhooks."""
import json
import logging
import os
import sys
import threading
import time

import requests

LOG_DIR = os.environ.get("LOG_DIR", os.path.join(os.path.dirname(__file__), "..", "logs"))
ALLOWED_WEBHOOKS = ("https://discord.com/api/webhooks/", "https://discordapp.com/api/webhooks/",
                    "https://hooks.slack.com/")


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
                   "level": record.levelname, "logger": record.name, "msg": record.getMessage()}
        payload.update(getattr(record, "data", {}))
        return json.dumps(payload)


def setup_logging():
    """JSON lines on stdout -> picked up by Render / Cloud Run / CloudWatch log viewers."""
    root = logging.getLogger()
    if any(getattr(h, "_shopsecure", False) for h in root.handlers):
        return
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(JsonFormatter())
    h._shopsecure = True
    root.addHandler(h)
    root.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


log = logging.getLogger("shopsecure.detections")
_file_lock = threading.Lock()
_last_alert = {}


def audit(record):
    """Append a flagged detection to logs/detections.jsonl (audit trail)."""
    os.makedirs(LOG_DIR, exist_ok=True)
    with _file_lock, open(os.path.join(LOG_DIR, "detections.jsonl"), "a") as f:
        f.write(json.dumps(record) + "\n")


def emit_detection(record):
    level = logging.WARNING if record["label"] == "Malicious" else logging.INFO
    log.log(level, "%s %s from %s (%s)", record["label"].upper(), record["action"], record["ip"],
            record["reason"], extra={"data": {"event": "detection", **record}})
    audit(record)


def valid_webhook(url):
    return bool(url) and url.startswith(ALLOWED_WEBHOOKS)


def send_alert(webhook_url, record, cooldown=300):
    """Post a Malicious detection to a Discord/Slack webhook (once per IP per cooldown)."""
    if not valid_webhook(webhook_url):
        return
    key = (webhook_url, record["ip"])
    if time.time() - _last_alert.get(key, 0) < cooldown:
        return
    _last_alert[key] = time.time()
    text = (f":rotating_light: ShopSecure alert: **{record['reason'] or 'Malicious activity'}** "
            f"from `{record['ip']}` against account `{record.get('tenant') or '-'}` "
            f"(risk {record['risk']:.0f}/100)")

    def _post():
        try:
            requests.post(webhook_url, json={"content": text, "text": text}, timeout=5)
        except requests.RequestException as exc:
            log.warning("webhook failed: %s", exc)

    threading.Thread(target=_post, daemon=True).start()
