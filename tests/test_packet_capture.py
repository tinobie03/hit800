import unittest

from scapy.all import IP, TCP

from inference import packet_capture
from ids_core.features import FEATURES


class FlowAggregationTests(unittest.TestCase):
    def setUp(self):
        packet_capture.flows.clear()

    def test_reverse_packets_form_one_bidirectional_flow(self):
        syn = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=12345, dport=443, flags="S", window=64240
        )
        syn_ack = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(
            sport=443, dport=12345, flags="SA", window=65535
        )
        packet_capture.consume_packet(syn, 1.0)
        packet_capture.consume_packet(syn_ack, 1.1)

        self.assertEqual(len(packet_capture.flows), 1)
        values = next(iter(packet_capture.flows.values())).features()
        self.assertEqual(list(values), FEATURES)
        self.assertEqual(values["Tot Fwd Pkts"], 1)
        self.assertEqual(values["Tot Bwd Pkts"], 1)
        self.assertEqual(values["SYN Flag Cnt"], 2)
        self.assertAlmostEqual(values["Flow Duration"], 100_000)
        self.assertGreater(values["Flow Pkts/s"], 0)

    def test_distinct_ports_form_distinct_flows(self):
        for port in (80, 443):
            packet_capture.consume_packet(
                IP(src="10.0.0.1", dst="10.0.0.2") /
                TCP(sport=12345, dport=port, flags="S"),
                1.0,
            )
        self.assertEqual(len(packet_capture.flows), 2)


if __name__ == "__main__":
    unittest.main()

