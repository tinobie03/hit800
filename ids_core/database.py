"""SQLite schema and connection helpers."""

import sqlite3
from pathlib import Path


def connect(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_schema(db_path: str) -> None:
    with connect(db_path) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                source_host TEXT,
                label TEXT,
                data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_host TEXT,
                source_ip TEXT,
                prediction TEXT,
                severity TEXT,
                attack_prob REAL,
                blocked INTEGER,
                indexed_at TEXT,
                raw_log TEXT,
                attack_type TEXT DEFAULT 'UNKNOWN',
                source_log_id INTEGER
            );
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                reason TEXT,
                blocked_at TEXT,
                active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS whitelist (
                ip TEXT PRIMARY KEY,
                reason TEXT,
                added_at TEXT,
                active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS service_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attack_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type TEXT,
                target_ip TEXT,
                source_ip TEXT,
                intensity TEXT,
                start_time TEXT,
                end_time TEXT,
                status TEXT DEFAULT 'running',
                no_block INTEGER DEFAULT 0
            );
            -- Second data source: host auth-log events (e.g. failed SSH logins)
            CREATE TABLE IF NOT EXISTS log_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                window_start TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                failed_logins INTEGER DEFAULT 0,
                distinct_users INTEGER DEFAULT 0,
                indexed_at TEXT
            );
            -- Fused multi-source correlation results
            CREATE TABLE IF NOT EXISTS correlated_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                network_score REAL DEFAULT 0,
                log_score REAL DEFAULT 0,
                fused_score REAL DEFAULT 0,
                correlated INTEGER DEFAULT 0,
                detail TEXT,
                window_start TEXT,
                indexed_at TEXT
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_log_events_ip ON log_events(source_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_log_events_indexed ON log_events(indexed_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_correlated_indexed ON correlated_alerts(indexed_at)")
        columns = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
        if "attack_type" not in columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN attack_type TEXT DEFAULT 'UNKNOWN'")
        if "source_log_id" not in columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN source_log_id INTEGER")
        run_columns = {row[1] for row in conn.execute("PRAGMA table_info(attack_runs)")}
        if "no_block" not in run_columns:
            conn.execute("ALTER TABLE attack_runs ADD COLUMN no_block INTEGER DEFAULT 0")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_source_log "
            "ON alerts(source_log_id) WHERE source_log_id IS NOT NULL"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_indexed_at ON alerts(indexed_at)")

