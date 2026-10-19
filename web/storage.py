"""SQLite persistence. The file lives on a Docker volume (/data) so it survives restarts."""
import json
import os
import secrets
import sqlite3
import threading
import time

DB_PATH = os.environ.get("DATABASE_PATH",
                         os.path.join(os.path.dirname(__file__), "..", "instance", "netguard.db"))
_write_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    full_name TEXT DEFAULT '',
    email TEXT DEFAULT '',
    company TEXT DEFAULT '',
    password_hash TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_login REAL
);
CREATE TABLE IF NOT EXISTS subscriptions (
    user_id INTEGER NOT NULL,
    service TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (user_id, service)
);
CREATE TABLE IF NOT EXISTS activity (
    user_id INTEGER, ts REAL, action TEXT, ip TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,              -- pull (we read a feed URL) | push (they POST to us)
    url TEXT,
    api_key TEXT UNIQUE,
    status TEXT NOT NULL DEFAULT 'active',
    last_error TEXT,
    records INTEGER NOT NULL DEFAULT 0,
    last_seen REAL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    n_records INTEGER,
    services TEXT,
    summary TEXT,
    evaluation TEXT,
    seconds REAL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    source_id INTEGER,
    analysis_id INTEGER,
    ts REAL,
    src_ip TEXT,
    protocol TEXT,
    service TEXT,
    flag TEXT,
    src_bytes REAL,
    dst_bytes REAL,
    label TEXT,
    verdict TEXT,
    prediction TEXT,
    confidence REAL,
    anomaly_score REAL,
    family TEXT
);
CREATE INDEX IF NOT EXISTS idx_records_live ON records(user_id, source_id, ts);
CREATE INDEX IF NOT EXISTS idx_records_analysis ON records(analysis_id);
"""

RECORD_COLS = ["user_id", "source_id", "analysis_id", "ts", "src_ip", "protocol", "service", "flag",
               "src_bytes", "dst_bytes", "label", "verdict", "prediction", "confidence",
               "anomaly_score", "family"]


def connect():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _write_lock, connect() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)


def query(sql, args=()):
    with connect() as c:
        return [dict(r) for r in c.execute(sql, args).fetchall()]


def query_one(sql, args=()):
    rows = query(sql, args)
    return rows[0] if rows else None


def execute(sql, args=()):
    with _write_lock, connect() as c:
        return c.execute(sql, args).lastrowid


def executemany(sql, rows):
    with _write_lock, connect() as c:
        c.executemany(sql, rows)


# --------------------------------------------------------------------- users
def create_user(username, password_hash, email="", full_name="", company=""):
    return execute("INSERT INTO users (username, password_hash, email, full_name, company, created_at) "
                   "VALUES (?,?,?,?,?,?)", (username, password_hash, email, full_name, company, time.time()))


def get_user(username=None, user_id=None):
    if user_id is not None:
        return query_one("SELECT * FROM users WHERE id=?", (user_id,))
    return query_one("SELECT * FROM users WHERE username=?", (username,))


def log_activity(user_id, action, ip, detail=""):
    execute("INSERT INTO activity VALUES (?,?,?,?,?)", (user_id, time.time(), action, ip, detail))


def subscriptions(user_id):
    return {r["service"] for r in query("SELECT service FROM subscriptions WHERE user_id=?", (user_id,))}


def subscribe(user_id, service):
    execute("INSERT OR IGNORE INTO subscriptions VALUES (?,?,?)", (user_id, service, time.time()))


def unsubscribe(user_id, service):
    execute("DELETE FROM subscriptions WHERE user_id=? AND service=?", (user_id, service))


def delete_user(user_id):
    with _write_lock, connect() as c:
        for table in ("records", "analyses", "sources", "subscriptions", "activity"):
            c.execute(f"DELETE FROM {table} WHERE user_id=?", (user_id,))
        c.execute("DELETE FROM users WHERE id=?", (user_id,))


# ------------------------------------------------------------------- sources
def create_source(user_id, name, kind, url=None):
    return execute("INSERT INTO sources (user_id, name, kind, url, api_key, created_at) VALUES (?,?,?,?,?,?)",
                   (user_id, name, kind, url, "ng_" + secrets.token_urlsafe(24), time.time()))


def insert_records(rows):
    executemany(f"INSERT INTO records ({','.join(RECORD_COLS)}) VALUES ({','.join('?' * len(RECORD_COLS))})",
                [tuple(r.get(c) for c in RECORD_COLS) for r in rows])


def save_analysis(user_id, name, services, rows, summary, evaluation, seconds):
    aid = execute("INSERT INTO analyses (user_id, name, n_records, services, summary, evaluation, seconds, "
                  "created_at) VALUES (?,?,?,?,?,?,?,?)",
                  (user_id, name, len(rows), json.dumps(sorted(services)), json.dumps(summary),
                   json.dumps(evaluation) if evaluation else None, seconds, time.time()))
    for r in rows:
        r["analysis_id"] = aid
    insert_records(rows)
    return aid
