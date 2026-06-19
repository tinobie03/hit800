"""Seed critical infrastructure IPs into the whitelist on startup.

Runs once when the API starts to protect SSH, gateway, target, and management IPs
from auto-blocking during attack simulations.
"""

import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

DB_PATH = os.getenv("DB_PATH", "data/ids.db")

# Critical IPs that should never be auto-blocked
CRITICAL_IPS = {
    "127.0.0.1": "loopback",
    "172.20.10.1": "gateway",
    "172.20.10.2": "protected target",
    "172.20.10.3": "management interface",
}


def seed_whitelist():
    """Add critical IPs to whitelist if they don't exist."""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

    try:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        c = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()

        # Check if whitelist table exists
        c.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='whitelist'"
        )
        if not c.fetchone():
            log.warning("Whitelist table does not exist yet; skipping seed")
            conn.close()
            return

        seeded = 0
        for ip, reason in CRITICAL_IPS.items():
            c.execute("SELECT active FROM whitelist WHERE ip = ?", (ip,))
            existing = c.fetchone()

            if existing and existing[0] == 1:
                log.info(f"IP {ip} already whitelisted")
            else:
                c.execute(
                    "INSERT OR REPLACE INTO whitelist (ip, reason, added_at, active) VALUES (?, ?, ?, 1)",
                    (ip, reason, now),
                )
                seeded += 1
                log.info(f"Whitelisted {ip} ({reason})")

        conn.commit()
        conn.close()

        if seeded > 0:
            log.info(f"Seeded {seeded} critical IPs into whitelist")
    except Exception as e:
        log.warning(f"Failed to seed whitelist: {e}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    seed_whitelist()
