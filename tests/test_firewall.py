import unittest
from unittest.mock import patch

from ids_core import firewall


class FirewallTests(unittest.TestCase):
    def test_rejects_invalid_ip(self):
        with self.assertRaises(ValueError):
            firewall.normalize_ip("not-an-ip")

    def test_block_requires_every_rule(self):
        # For each rule: the existence check misses, then insertion succeeds.
        with patch.object(firewall, "_run", side_effect=[False, True] * 2) as run:
            self.assertTrue(firewall.block_ip("192.0.2.9"))
            self.assertEqual(run.call_count, 4)

        def fail_output(args, **_kwargs):
            if args[0] == "-C":
                return False
            return not (args[0] == "-I" and args[1] == "FORWARD")

        with patch.object(firewall, "_run", side_effect=fail_output):
            self.assertFalse(firewall.block_ip("192.0.2.9"))


if __name__ == "__main__":
    unittest.main()
