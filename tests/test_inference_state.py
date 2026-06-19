import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
