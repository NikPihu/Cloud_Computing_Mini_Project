"""Parse uploaded / downloaded logs into the common event format.

Supported formats (auto-detected):
  * CSV with columns timestamp, ip [, user, action, success, user_agent, path, status, label]
  * Loghub structured CSV (Date, Day, Time, Content columns)
  * OpenSSH / Linux syslog auth logs  (sshd: Failed/Accepted/Invalid user ...)
  * Apache / Nginx access logs (Common & Combined Log Format)
"""
import csv
import datetime as dt
import gzip
import io
import re

MAX_EVENTS = 50_000
DEFAULT_YEAR = 2024   # syslog lines carry no year

SYSLOG_TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+(?P<msg>.*)$")
SSH_PATTERNS = [
    (re.compile(r"Failed (?:password|publickey|none) for invalid user (?P<user>\S*) from (?P<ip>[\d.:a-fA-F]+)"), "login", False, True),
    (re.compile(r"Failed (?:password|publickey|none) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"), "login", False, False),
    (re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[\d.:a-fA-F]+)"), "login", False, True),
    (re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"), "login", True, False),
    (re.compile(r"authentication failure;.*rhost=(?P<ip>\S+)(?:\s+user=(?P<user>\S+))?"), "login", False, False),
    (re.compile(r"Did not receive identification string from (?P<ip>[\d.:a-fA-F]+)"), "request", False, False),
    (re.compile(r"Received disconnect from (?P<ip>[\d.:a-fA-F]+)"), "request", True, False),
    (re.compile(r"session opened for user (?P<user>\S+)"), "login", True, False),
]
ACCESS_LOG = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>\S+)? ?(?P<path>[^"]*?)(?: HTTP/[\d.]+)?" '
    r'(?P<status>\d{3}) \S+(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)
LOGIN_PATH = re.compile(r"login|signin|auth|wp-login", re.I)


class ParseError(ValueError):
    pass


def _syslog_ts(mon, day, time_s, year=DEFAULT_YEAR):
    return dt.datetime.strptime(f"{year} {mon} {int(day):02d} {time_s}", "%Y %b %d %H:%M:%S") \
        .replace(tzinfo=dt.timezone.utc).timestamp()


def parse_syslog_line(line):
    m = SYSLOG_TS.match(line.strip())
    if not m:
        return None
    msg = m.group("msg")
    for rx, action, success, invalid in SSH_PATTERNS:
        hit = rx.search(msg)
        if hit:
            d = hit.groupdict()
            user = d.get("user") or None
            try:
                ts = _syslog_ts(m["mon"], m["day"], m["time"])
            except ValueError:
                return None
            return {"ts": ts, "ip": d.get("ip") or "local",
                    "user": user, "action": action, "success": success, "user_agent": None,
                    "path": None, "status": None, "invalid_user": invalid or user == "unknown"}
    return None


def parse_access_line(line):
    m = ACCESS_LOG.match(line.strip())
    if not m:
        return None
    try:
        ts = dt.datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        return None
    status, path, method = int(m["status"]), m["path"] or "/", (m["method"] or "GET").upper()
    is_login = method == "POST" and bool(LOGIN_PATH.search(path))
    user = m["user"] if m["user"] not in ("-", "") else None
    return {"ts": ts, "ip": m["ip"], "user": user, "action": "login" if is_login else "request",
            "success": status < 400, "user_agent": m["ua"] if m["ua"] is not None else "-",
            "path": path, "status": status, "invalid_user": False}


def _truthy(v):
    return str(v).strip().lower() in ("1", "true", "yes", "y", "success", "ok", "t")


def _parse_ts(v):
    v = str(v).strip()
    try:
        f = float(v)
        return f / 1000 if f > 1e12 else f
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S.%f",
                "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return dt.datetime.strptime(v, fmt).replace(tzinfo=dt.timezone.utc).timestamp()
        except ValueError:
            continue
    return dt.datetime.fromisoformat(v).timestamp()


def parse_csv(text):
    reader = csv.DictReader(io.StringIO(text))
    cols = {c.lower().strip(): c for c in (reader.fieldnames or [])}
    if {"date", "time", "content"} <= set(cols):        # Loghub structured CSV
        lines = (f"{r[cols['date']]} {r.get(cols.get('day', ''), '1')} {r[cols['time']]} host {r[cols['content']]}"
                 for r in reader)
        return [e for e in map(parse_syslog_line, lines) if e]
    ts_col = next((cols[c] for c in ("timestamp", "ts", "time", "datetime", "date") if c in cols), None)
    ip_col = next((cols[c] for c in ("ip", "ip_address", "src_ip", "source_ip", "client_ip") if c in cols), None)
    if not ts_col or not ip_col:
        raise ParseError("CSV needs at least a 'timestamp' and an 'ip' column.")
    pick = lambda *names: next((cols[n] for n in names if n in cols), None)
    c_user, c_act, c_succ = pick("user", "username", "user_id"), pick("action", "event", "event_type"), \
        pick("success", "login_successful", "successful", "outcome")
    c_ua, c_path, c_status = pick("user_agent", "useragent", "ua", "user_agent_string"), pick("path", "url", "endpoint"), \
        pick("status", "status_code", "http_status")
    c_label, c_inv = pick("label", "class", "y"), pick("invalid_user")
    events = []
    for r in reader:
        try:
            ts = _parse_ts(r[ts_col])
        except (ValueError, TypeError):
            continue
        try:
            status = int(float(r[c_status])) if c_status and r.get(c_status) not in (None, "") else None
        except ValueError:
            status = None
        success = _truthy(r[c_succ]) if c_succ and r.get(c_succ) not in (None, "") else (status is None or status < 400)
        ev = {"ts": ts, "ip": r[ip_col], "user": (r.get(c_user) or None) if c_user else None,
              "action": (r.get(c_act) or "login").lower() if c_act else "login", "success": success,
              "user_agent": r.get(c_ua) if c_ua else None, "path": r.get(c_path) if c_path else None,
              "status": status, "invalid_user": _truthy(r.get(c_inv)) if c_inv else False}
        if c_label and r.get(c_label):
            lab = r[c_label].strip().capitalize()
            ev["label"] = {"0": "Normal", "1": "Malicious", "Benign": "Normal", "Attack": "Malicious"}.get(lab, lab)
        events.append(ev)
        if len(events) >= MAX_EVENTS:
            break
    return events


def parse_bytes(raw, filename=""):
    """Detect the format and return (events, format_name)."""
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8", errors="replace")
    first = next((ln for ln in text.splitlines() if ln.strip()), "")
    if filename.lower().endswith(".csv") or ("," in first and ACCESS_LOG.match(first) is None
                                             and SYSLOG_TS.match(first) is None):
        events, fmt = parse_csv(text), "CSV"
    elif ACCESS_LOG.match(first):
        events, fmt = [e for e in map(parse_access_line, text.splitlines()[:MAX_EVENTS * 2]) if e], "Web access log"
    elif SYSLOG_TS.match(first):
        events, fmt = [e for e in map(parse_syslog_line, text.splitlines()) if e], "Linux / SSH auth log"
    else:
        raise ParseError("Unrecognised format. Upload a CSV, an SSH/Linux auth log or an Apache/Nginx access log.")
    if not events:
        raise ParseError(f"Detected {fmt}, but found no login/activity events in it.")
    return events[:MAX_EVENTS], fmt
