"""Auth-log collector — the second data source for multi-source correlation.

Tails the host auth log (e.g. /var/log/auth.log) read-only, extracts failed
SSH login attempts per source IP, aggregates them into fixed time windows, and
writes one row per IP/window into the `log_events` table. The correlation step
in the inference service then fuses these with the CNN's network anomalies.

Run:
  python -m inference.auth_log_collector

Requires the host auth log mounted read-only into the container, e.g.
  volumes:
    - /var/log/auth.log:/var/log/auth.log:ro
"""

from __future__ import annotations

import logging
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timezone

from ids_core.database import connect, init_schema

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = lambda: None

load_dotenv()
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("logs/auth_log_collector.log")],
)
log = logging.getLogger(__name__)

DB_PATH = os.getenv("DB_PATH", "data/ids.db")
AUTH_LOG_PATH = os.getenv("AUTH_LOG_PATH", "/var/log/auth.log")
FLUSH_INTERVAL = float(os.getenv("LOG_FLUSH_INTERVAL", "5"))

# "Failed password for [invalid user] <user> from <ip> port <n> ssh2"
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
# "Invalid user <user> from <ip>"
INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")

# Per-window aggregation: ip -> set of usernames tried (count via len + total).
_failed_counts: dict[str, int] = defaultdict(int)
_failed_users: dict[str, set] = defaultdict(set)


def parse_line(line: str) -> None:
    for pattern in (FAILED_RE, INVALID_RE):
        match = pattern.search(line)
        if match:
            ip = match.group("ip")
            _failed_counts[ip] += 1
            _failed_users[ip].add(match.group("user"))
            return


def flush() -> int:
    if not _failed_counts:
        return 0
    window_start = datetime.now(timezone.utc).isoformat()
    rows = [
        (window_start, ip, count, len(_failed_users[ip]), window_start)
        for ip, count in _failed_counts.items()
    ]
    with connect(DB_PATH) as conn:
        conn.executemany(
            """INSERT INTO log_events (window_start, source_ip, failed_logins, distinct_users, indexed_at)
               VALUES (?, ?, ?, ?, ?)""",
            rows,
        )
    written = len(rows)
    _failed_counts.clear()
    _failed_users.clear()
    log.info("Flushed %d auth-log IP windows", written)
    return written


def tail(path: str):
    """Yield new lines appended to `path`, tolerating rotation/truncation."""
    while not os.path.exists(path):
        log.warning("Auth log %s not found yet; waiting...", path)
        time.sleep(5)
    with open(path, "r", errors="ignore") as handle:
        handle.seek(0, os.SEEK_END)
        last_flush = time.time()
        while True:
            # Flush on a timer regardless of traffic, so a *sustained* brute
            # force still produces windows instead of buffering until it stops.
            if time.time() - last_flush >= FLUSH_INTERVAL:
                flush()
                last_flush = time.time()

            line = handle.readline()
            if line:
                yield line
            else:
                time.sleep(0.25)
                # Handle log rotation (file shrank / inode replaced).
                try:
                    if os.stat(path).st_size < handle.tell():
                        handle.seek(0)
                except FileNotFoundError:
                    time.sleep(2)


def run() -> None:
    init_schema(DB_PATH)
    log.info("Auth-log collector started; reading %s", AUTH_LOG_PATH)
    for line in tail(AUTH_LOG_PATH):
        parse_line(line)


if __name__ == "__main__":
    run()
