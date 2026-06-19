import unittest

from ids_core.correlation import score_log_anomalies


class CorrelationTests(unittest.TestCase):
    def test_single_brute_force_source_can_trigger_cold_start(self):
        scores = score_log_anomalies([
            {"source_ip": "172.20.10.4", "failed_logins": 10, "distinct_users": 4},
        ])
        self.assertGreaterEqual(scores["172.20.10.4"], 0.5)

    def test_small_benign_auth_event_stays_below_threshold(self):
        scores = score_log_anomalies([
            {"source_ip": "172.20.10.4", "failed_logins": 1, "distinct_users": 1},
        ])
        self.assertLess(scores["172.20.10.4"], 0.5)


if __name__ == "__main__":
    unittest.main()
