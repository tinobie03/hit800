import tempfile
import unittest
from pathlib import Path

from ids_core.database import connect, init_schema


class DatabaseTests(unittest.TestCase):
    def test_schema_and_alert_idempotency(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "ids.db")
            init_schema(path)
            with connect(path) as conn:
                tables = {row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )}
                self.assertTrue({"logs", "alerts", "blocked_ips", "whitelist", "service_state"} <= tables)
                values = ("now", "host", "1.2.3.4", "ATTACK", "HIGH", .9, 1, "now", "{}", "UNKNOWN", 7)
                sql = """INSERT OR IGNORE INTO alerts
                    (timestamp, source_host, source_ip, prediction, severity, attack_prob,
                     blocked, indexed_at, raw_log, attack_type, source_log_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
                conn.execute(sql, values)
                conn.execute(sql, values)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()

