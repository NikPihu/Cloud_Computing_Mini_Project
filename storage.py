"""SQLite persistence (swap DATABASE_PATH to a mounted disk in production)."""
import json
import os
import sqlite3
import threading
import time

DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "instance", "shopsecure.db"))
_write_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT,
    password_hash TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS subscriptions (
    user_id INTEGER NOT NULL,
    service TEXT NOT NULL,
    settings TEXT DEFAULT '{}',
    created_at REAL NOT NULL,
    PRIMARY KEY (user_id, service)
);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    items TEXT NOT NULL,
    total REAL NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    tenant TEXT,
    user TEXT,
    ip TEXT,
    action TEXT,
    success INTEGER,
    path TEXT,
    status INTEGER,
    user_agent TEXT,
    source TEXT,
    label TEXT,
    risk REAL,
    reason TEXT,
    latency_ms REAL
);
CREATE INDEX IF NOT EXISTS idx_events_tenant_ts ON events(tenant, ts);
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source TEXT,
    fmt TEXT,
    n_events INTEGER,
    summary TEXT,
    evaluation TEXT,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS analysis_rows (
    analysis_id INTEGER NOT NULL,
    ts REAL, ip TEXT, user TEXT, action TEXT, success INTEGER,
    path TEXT, status INTEGER, label TEXT, risk REAL, reason TEXT, true_label TEXT
);
CREATE INDEX IF NOT EXISTS idx_rows_analysis ON analysis_rows(analysis_id);
"""


def connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
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
        cur = c.execute(sql, args)
        return cur.lastrowid


def executemany(sql, rows):
    with _write_lock, connect() as c:
        c.executemany(sql, rows)


# ----------------------------------------------------------------- helpers
def create_user(username, email, password_hash):
    return execute("INSERT INTO users (username, email, password_hash, created_at) VALUES (?,?,?,?)",
                   (username, email, password_hash, time.time()))


def get_user(username=None, user_id=None):
    if user_id is not None:
        return query_one("SELECT * FROM users WHERE id=?", (user_id,))
    return query_one("SELECT * FROM users WHERE username=?", (username,))


def subscriptions(user_id):
    return {r["service"]: json.loads(r["settings"] or "{}")
            for r in query("SELECT service, settings FROM subscriptions WHERE user_id=?", (user_id,))}


def subscribe(user_id, service, settings=None):
    execute("INSERT OR REPLACE INTO subscriptions (user_id, service, settings, created_at) VALUES (?,?,?,?)",
            (user_id, service, json.dumps(settings or {}), time.time()))


def unsubscribe(user_id, service):
    execute("DELETE FROM subscriptions WHERE user_id=? AND service=?", (user_id, service))


def insert_events(rows):
    executemany("""INSERT INTO events (ts, tenant, user, ip, action, success, path, status, user_agent,
                   source, label, risk, reason, latency_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)


def save_analysis(user_id, name, source_type, source, fmt, results, summary, evaluation):
    aid = execute("""INSERT INTO analyses (user_id, name, source_type, source, fmt, n_events, summary,
                     evaluation, created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
                  (user_id, name, source_type, source, fmt, len(results), json.dumps(summary),
                   json.dumps(evaluation) if evaluation else None, time.time()))
    executemany("INSERT INTO analysis_rows VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                [(aid, r["ts"], r["ip"], r["user"], r["action"], int(bool(r["success"])), r["path"],
                  r["status"], r["label"], r["risk"], r["reason"], r.get("true_label")) for r in results])
    return aid
