"""Turns raw activity events into numeric features.

Every input source (the live store, uploaded files, public log URLs) is first
normalised into the same event dict:

    {ts, user, ip, action, success, user_agent, path, status, invalid_user}

`FeatureState` then walks the events in time order and keeps sliding windows
per IP / per user, so the exact same code path is used for batch files and
for the real-time pipeline.
"""
import datetime as dt
import math
import re
from collections import defaultdict, deque

FEATURES = [
    "hour_sin", "hour_cos", "is_night", "is_failure", "is_login",
    "ip_fail_10m", "user_fail_10m", "ip_users_10m", "ip_events_1m",
    "ip_fail_ratio", "new_ip_for_user", "new_device_for_user",
    "is_bot_ua", "is_crawler", "suspicious_path", "sensitive_action",
    "invalid_user", "is_anonymous",
]

BOT_UA = re.compile(
    r"curl|wget|python|requests|httpclient|go-http|java/|libwww|sqlmap|nikto|nmap|"
    r"masscan|zgrab|scrapy|hydra|medusa|nuclei|dirbuster|gobuster|okhttp|headless",
    re.I,
)
CRAWLER_UA = re.compile(r"googlebot|bingbot|yandex|baiduspider|duckduckbot|slurp|crawler|spider|bot\b", re.I)
SUSPICIOUS_PATH = re.compile(
    r"wp-admin|wp-login|xmlrpc|phpmyadmin|\.env|\.git|/etc/passwd|\.\./|cgi-bin|"
    r"union(\s|%20|\+)select|<script|%3cscript|/shell|\.php\?|/admin\.php|/boaform|/HNAP1",
    re.I,
)
SENSITIVE_ACTIONS = {"checkout", "change_password", "admin", "payment", "subscribe"}
LOGIN_ACTIONS = {"login", "ssh_login", "auth"}

WIN_10M = 600
WIN_1M = 60


class FeatureState:
    """Stateful, streaming feature extractor (sliding windows per IP/user)."""

    def __init__(self, tz_offset_hours=0.0):
        # Local-time offset used for hour-of-day features (live store: IST = 5.5)
        self.tz = dt.timezone(dt.timedelta(hours=tz_offset_hours))
        self.ip_events = defaultdict(deque)    # ip -> deque[(ts, failed, user)]
        self.user_fails = defaultdict(deque)   # user -> deque[ts]
        self.user_ips = defaultdict(set)       # user -> known IPs
        self.user_devices = defaultdict(set)   # user -> known user agents

    @staticmethod
    def _prune(dq, now, window, key=lambda x: x[0]):
        while dq and key(dq[0]) < now - window:
            dq.popleft()

    def remember(self, ev):
        """Learn a user's normal IP/device without scoring (history warm-up)."""
        user = ev.get("user")
        if user and ev.get("success", True) and ev.get("action") in LOGIN_ACTIONS | {"register"}:
            self.user_ips[user].add(ev.get("ip"))
            if ev.get("user_agent"):
                self.user_devices[user].add(ev["user_agent"])

    def featurize(self, ev):
        ts = float(ev["ts"])
        ip = ev.get("ip") or "0.0.0.0"
        user = ev.get("user") or None
        action = (ev.get("action") or "request").lower()
        ua = ev.get("user_agent")
        path = ev.get("path") or ""
        failed = not bool(ev.get("success", True))
        is_login = action in LOGIN_ACTIONS

        # --- update windows with this event -------------------------------
        dq = self.ip_events[ip]
        dq.append((ts, failed and is_login, user))
        self._prune(dq, ts, WIN_10M)
        if user and failed and is_login:
            uf = self.user_fails[user]
            uf.append(ts)
            self._prune(uf, ts, WIN_10M, key=lambda x: x)

        ip_fail = sum(1 for e in dq if e[1])
        ip_users = len({e[2] for e in dq if e[2]})
        ip_1m = sum(1 for e in dq if e[0] >= ts - WIN_1M)
        user_fail = len(self.user_fails[user]) if user else 0

        new_ip = new_dev = 0
        if user and is_login and not ev.get("invalid_user"):
            new_ip = int(bool(self.user_ips[user]) and ip not in self.user_ips[user])
            if ua:
                new_dev = int(bool(self.user_devices[user]) and ua not in self.user_devices[user])
            if not failed:  # successful login -> becomes a known IP/device
                self.remember(ev)
        elif action == "register":
            self.remember(ev)

        t = dt.datetime.fromtimestamp(ts, self.tz)
        hour = t.hour + t.minute / 60.0

        status = ev.get("status")
        is_fail = int(failed or (status is not None and int(status) >= 400))

        return {
            "hour_sin": math.sin(2 * math.pi * hour / 24),
            "hour_cos": math.cos(2 * math.pi * hour / 24),
            "is_night": int(hour < 5),
            "is_failure": is_fail,
            "is_login": int(is_login),
            "ip_fail_10m": ip_fail,
            "user_fail_10m": user_fail,
            "ip_users_10m": ip_users,
            "ip_events_1m": ip_1m,
            "ip_fail_ratio": ip_fail / (len(dq) + 1),
            "new_ip_for_user": new_ip,
            "new_device_for_user": new_dev,
            "is_bot_ua": int(ua is not None and (ua.strip() in ("", "-") or bool(BOT_UA.search(ua)))),
            "is_crawler": int(bool(ua) and bool(CRAWLER_UA.search(ua)) and not BOT_UA.search(ua)),
            "suspicious_path": int(bool(SUSPICIOUS_PATH.search(path))),
            "sensitive_action": int(action in SENSITIVE_ACTIONS),
            "invalid_user": int(bool(ev.get("invalid_user"))),
            "is_anonymous": int(user is None),
        }


def featurize_batch(events):
    """Featurise a list of events (sorted by time) with a fresh state."""
    state = FeatureState()
    events = sorted(events, key=lambda e: e["ts"])
    return events, [state.featurize(e) for e in events]


def explain(f, label):
    """Human-readable reason for a flagged event (shown to the user)."""
    if label == "Normal":
        return ""
    if f["ip_users_10m"] >= 5:
        return "Credential stuffing"
    if f["ip_fail_10m"] >= 8 or f["user_fail_10m"] >= 8:
        return "Brute-force login"
    if f["suspicious_path"] or f["is_bot_ua"]:
        return "Bot / vulnerability scan"
    if f["ip_events_1m"] >= 60:
        return "Request flooding"
    if f["ip_events_1m"] >= 25:
        return "High request rate"
    if f["invalid_user"]:
        return "Unknown username"
    if f["new_ip_for_user"] and f["new_device_for_user"]:
        return "New device & location"
    if f["user_fail_10m"] >= 2 or f["ip_fail_10m"] >= 2:
        return "Repeated failed logins"
    if f["is_night"] and f["is_login"]:
        return "Off-hours access"
    if f["new_ip_for_user"] or f["new_device_for_user"]:
        return "New device or location"
    return "Anomalous behaviour"
