import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ids_core.database import connect, init_schema
from inference import service


class InferenceStateTests(unittest.TestCase):
    def test_private_management_addresses_are_protected(self):
        self.assertTrue(service.is_protected("172.20.10.1"))
        self.assertTrue(service.is_protected("192.168.64.5"))
        self.assertFalse(service.is_protected("203.0.113.10"))

    def test_alert_and_cursor_commit_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            old_path = service.DB_PATH
            service.DB_PATH = str(Path(directory) / "ids.db")
            try:
                init_schema(service.DB_PATH)
                alert = {
                    "source_log_id": 12, "timestamp": "now", "source_host": "host",
                    "source_ip": "192.0.2.1", "prediction": "ATTACK", "severity": "HIGH",
                    "attack_prob": .9, "blocked": 1, "indexed_at": "now",
                    "raw_log": "{}", "attack_type": "UNKNOWN",
                }
                service.commit_batch([alert], 12)
                service.commit_batch([alert], 12)
                self.assertEqual(service.get_cursor(), 12)
                with connect(service.DB_PATH) as conn:
                    self.assertEqual(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 1)
            finally:
                service.DB_PATH = old_path

    def test_build_events_keeps_benign_and_attack_results(self):
        logs = [
            {"id": 1, "source_ip": "198.51.100.1", "data": {}},
            {"id": 2, "source_ip": "198.51.100.2", "data": {}},
        ]
        events = service.build_events(logs, [0, 1], [.12, .91], "SYN_FLOOD")
        self.assertEqual([event["prediction"] for event in events], ["BENIGN", "ATTACK"])
        self.assertEqual(events[0]["attack_type"], "NORMAL")
        self.assertEqual(events[1]["attack_type"], "SYN_FLOOD")

    def test_block_evidence_requires_repeated_alerts(self):
        with tempfile.TemporaryDirectory() as directory:
            old_path = service.DB_PATH
            old_min = service.BLOCK_MIN_ALERTS
            service.DB_PATH = str(Path(directory) / "ids.db")
            service.BLOCK_MIN_ALERTS = 3
            try:
                init_schema(service.DB_PATH)
                now = datetime.now(timezone.utc).isoformat()
                with connect(service.DB_PATH) as conn:
                    for source_log_id in (1, 2):
                        conn.execute(
                            """INSERT INTO alerts
                               (source_ip, prediction, attack_prob, indexed_at, source_log_id)
                               VALUES (?, 'ATTACK', .95, ?, ?)""",
                            ("198.51.100.8", now, source_log_id),
                        )
                self.assertFalse(service.has_block_evidence("198.51.100.8"))
                with connect(service.DB_PATH) as conn:
                    conn.execute(
                        """INSERT INTO alerts
                           (source_ip, prediction, attack_prob, indexed_at, source_log_id)
                           VALUES (?, 'ATTACK', .95, ?, 3)""",
                        ("198.51.100.8", now),
                    )
                self.assertTrue(service.has_block_evidence("198.51.100.8"))
            finally:
                service.DB_PATH = old_path
                service.BLOCK_MIN_ALERTS = old_min

    def test_active_attack_runs_are_scoped_to_source_ip(self):
        with tempfile.TemporaryDirectory() as directory:
            old_path = service.DB_PATH
            service.DB_PATH = str(Path(directory) / "ids.db")
            try:
                init_schema(service.DB_PATH)
                now = datetime.now(timezone.utc).isoformat()
                with connect(service.DB_PATH) as conn:
                    conn.execute(
                        """INSERT INTO attack_runs
                           (attack_type, target_ip, source_ip, start_time, status, no_block)
                           VALUES ('SYN_FLOOD', '192.0.2.2', '198.51.100.8', ?, 'running', 1)""",
                        (now,),
                    )
                runs = service.current_attack_runs()
                self.assertEqual(runs["198.51.100.8"], ("SYN_FLOOD", True))
                self.assertNotIn("198.51.100.9", runs)
            finally:
                service.DB_PATH = old_path


if __name__ == "__main__":
    unittest.main()
