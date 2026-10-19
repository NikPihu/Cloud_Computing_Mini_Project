"""Network log streamer - simulates a company's network sensor.

Replays real NSL-KDD connection records (KDDTest+, incl. attack types never seen
in training) ONE BY ONE, adding a timestamp and source IP, so the cloud app can be
fed exactly like it would be by a live log shipper.

  GET /stream?profile=mixed&rate=5     newline-delimited JSON, endless
  GET /sample?n=20&profile=attack      a JSON array (quick look)
  GET /health

Optional push mode (env PUSH_URL + PUSH_API_KEY): POST each record to the
NetGuard ingest API instead of waiting for the app to connect.
"""
import csv
import json
import os
import random
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DATA = os.environ.get("DATA_FILE", "/data/KDDTest+.txt")
COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty",
]
TEXT = {"protocol_type", "service", "flag", "label"}
# share of normal traffic between attack bursts, and how long bursts last
PROFILES = {"normal": (0.97, (3, 8)), "mixed": (0.80, (8, 25)), "attack": (0.40, (20, 60))}


def log(msg, **kw):
    print(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "msg": msg, **kw}), flush=True)


def load():
    normal, attacks = [], {}
    with open(DATA, newline="") as f:
        for row in csv.reader(f):
            if len(row) < 42:
                continue
            rec = {c: (v if c in TEXT else float(v)) for c, v in zip(COLUMNS, row) if c != "difficulty"}
            (normal if rec["label"] == "normal" else attacks.setdefault(rec["label"], [])).append(rec)
    log("dataset loaded", normal=len(normal), attack_types=len(attacks),
        attacks=sum(len(v) for v in attacks.values()))
    return normal, attacks


NORMAL, ATTACKS = load()
ATTACK_WEIGHTS = {k: len(v) ** 0.5 for k, v in ATTACKS.items()}     # rare attack types still show up


def office_ip(rng):
    return f"10.0.{rng.randint(1, 20)}.{rng.randint(2, 250)}"


def attacker_ip(rng):
    return f"{rng.choice([45, 103, 185, 193, 222])}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def generate(profile="mixed", seed=None):
    """Endless record generator: normal traffic with bursts of a single attack type from one attacker."""
    rng = random.Random(seed)
    share_normal, burst_len = PROFILES.get(profile, PROFILES["mixed"])
    while True:
        if rng.random() < share_normal:
            for _ in range(rng.randint(5, 20)):
                yield {**rng.choice(NORMAL), "src_ip": office_ip(rng)}
        else:
            kind = rng.choices(list(ATTACK_WEIGHTS), weights=list(ATTACK_WEIGHTS.values()))[0]
            ip = attacker_ip(rng)
            for _ in range(rng.randint(*burst_len)):
                yield {**rng.choice(ATTACKS[kind]), "src_ip": ip}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        profile = q.get("profile", "mixed")
        if url.path == "/health":
            return self._send(200, json.dumps({"status": "ok", "records": len(NORMAL) + sum(map(len, ATTACKS.values()))}))
        if url.path == "/sample":
            gen = generate(profile)
            n = min(int(q.get("n", 20)), 1000)
            return self._send(200, json.dumps([{**next(gen), "ts": time.time()} for _ in range(n)]))
        if url.path != "/stream":
            return self._send(404, json.dumps({"error": "not found"}))
        rate = min(max(float(q.get("rate", 5)), 0.2), 200)
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        client = self.client_address[0]
        log("client connected", client=client, profile=profile, rate=rate)
        sent = 0
        try:
            for rec in generate(profile):
                self.wfile.write((json.dumps({**rec, "ts": time.time()}) + "\n").encode())
                self.wfile.flush()
                sent += 1
                if sent % 500 == 0:
                    log("streaming", client=client, sent=sent)
                time.sleep(1 / rate)
        except (BrokenPipeError, ConnectionResetError):
            log("client disconnected", client=client, sent=sent)


def push_loop(url, key, rate, profile):
    """Push mode: deliver records to the ingest API one by one."""
    for rec in generate(profile):
        body = json.dumps({**rec, "ts": time.time()}).encode()
        req = urllib.request.Request(url, body, {"Content-Type": "application/json", "X-API-Key": key})
        try:
            urllib.request.urlopen(req, timeout=10).read()
        except Exception as exc:
            log("push failed", error=str(exc))
            time.sleep(5)
        time.sleep(1 / rate)


if __name__ == "__main__":
    if os.environ.get("PUSH_URL") and os.environ.get("PUSH_API_KEY"):
        threading.Thread(target=push_loop, daemon=True, args=(
            os.environ["PUSH_URL"], os.environ["PUSH_API_KEY"], float(os.environ.get("PUSH_RATE", "2")),
            os.environ.get("PUSH_PROFILE", "mixed"))).start()
        log("push mode on", url=os.environ["PUSH_URL"])
    port = int(os.environ.get("PORT", "9000"))
    log("log streamer listening", port=port)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
