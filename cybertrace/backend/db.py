"""SQLite persistence. Swap connect() for a PostgreSQL driver in production."""
import os
import sqlite3
import time

DB_PATH = os.getenv("CYBERTRACE_DB", "cybertrace.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id),
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS investigations (
    investigation_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id),
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    severity TEXT NOT NULL DEFAULT 'LOW',
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_json TEXT,
    timeline_json TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id),
    filename TEXT,
    file_type TEXT,
    size INTEGER,
    analysis_status TEXT,
    extracted_information TEXT,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS agent_executions (
    execution_id TEXT PRIMARY KEY,
    investigation_id TEXT,
    tool_name TEXT,
    input_summary TEXT,
    output TEXT,
    execution_status TEXT,
    timestamp REAL
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    investigation_id TEXT,
    category TEXT,
    severity TEXT,
    confidence REAL,
    evidence_reference TEXT,
    kind TEXT,
    description TEXT
);
CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    investigation_id TEXT,
    report_path TEXT,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS messages (
    message_id TEXT PRIMARY KEY,
    investigation_id TEXT,
    role TEXT,
    content TEXT,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS notes (
    note_id TEXT PRIMARY KEY,
    investigation_id TEXT,
    body TEXT,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    action TEXT,
    detail TEXT,
    created_at REAL
);
"""


def connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def run(sql, params=(), fetch=None):
    """Execute one statement. fetch: None | 'one' | 'all'."""
    conn = connect()
    try:
        cur = conn.execute(sql, params)
        conn.commit()
        if fetch == "one":
            row = cur.fetchone()
            return dict(row) if row else None
        if fetch == "all":
            return [dict(r) for r in cur.fetchall()]
        return cur.lastrowid
    finally:
        conn.close()


def init_db():
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def audit(user_id, action, detail=""):
    run(
        "INSERT INTO audit_log (user_id, action, detail, created_at) VALUES (?,?,?,?)",
        (user_id, action, str(detail)[:500], time.time()),
    )
