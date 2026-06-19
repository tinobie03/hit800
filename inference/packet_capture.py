#!/usr/bin/env python3
"""Capture bidirectional five-tuple flows and write 76-feature rows to SQLite."""

import logging
import math
import os
import statistics
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from scapy.all import ICMP, IP, TCP, UDP, sniff

from ids_core.database import connect, init_schema
from ids_core.features import FEATURES

try:
    from dotenv import load_dotenv
except ImportError:  # Environment variables still work without a .env loader.
    load_dotenv = lambda: None
load_dotenv()
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("logs/packet_capture.log")],
)
log = logging.getLogger(__name__)

DB_PATH = os.getenv("DB_PATH", "data/ids.db")
INTERFACE = os.getenv("CAPTURE_INTERFACE") or None
FLOW_WINDOW = float(os.getenv("FLOW_WINDOW", "5"))


def _stats(values: list[float]) -> tuple[float, float, float, float]:
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    return (
        statistics.fmean(values),
        statistics.pstdev(values) if len(values) > 1 else 0.0,
        max(values),
        min(values),
    )


def _iats(times: list[float]) -> list[float]:
    return [(b - a) * 1_000_000 for a, b in zip(times, times[1:])]


def _active_idle(times: list[float], idle_threshold: float = 1.0) -> tuple[list[float], list[float]]:
    """Return active-period durations and idle gaps in microseconds."""
    if not times:
        return [], []
    active, idle = [], []
    period_start = times[0]
    previous = times[0]
    for timestamp in times[1:]:
        gap = timestamp - previous
        if gap > idle_threshold:
            active.append((previous - period_start) * 1_000_000)
            idle.append(gap * 1_000_000)
            period_start = timestamp
        previous = timestamp
    active.append((previous - period_start) * 1_000_000)
    return active, idle


def packet_tuple(packet):
    ip = packet[IP]
    if TCP in packet:
        return 6, (ip.src, int(packet[TCP].sport)), (ip.dst, int(packet[TCP].dport))
    if UDP in packet:
        return 17, (ip.src, int(packet[UDP].sport)), (ip.dst, int(packet[UDP].dport))
    if ICMP in packet:
        return 1, (ip.src, 0), (ip.dst, 0)
    return int(ip.proto), (ip.src, 0), (ip.dst, 0)


def canonical_key(protocol: int, source: tuple, destination: tuple) -> tuple:
    low, high = sorted((source, destination))
    return protocol, low, high


@dataclass
class Direction:
    lengths: list[int] = field(default_factory=list)
    times: list[float] = field(default_factory=list)
    header_bytes: int = 0
    psh: int = 0
    urg: int = 0
    active_data: int = 0
    initial_window: int = 0
    segment_sizes: list[int] = field(default_factory=list)


@dataclass
class Flow:
    protocol: int
    forward_endpoint: tuple
    source_ip: str
    started: float
    last_seen: float
    forward: Direction = field(default_factory=Direction)
    backward: Direction = field(default_factory=Direction)
    all_lengths: list[int] = field(default_factory=list)
    all_times: list[float] = field(default_factory=list)
    flags: dict[str, int] = field(default_factory=lambda: {
        "FIN": 0, "SYN": 0, "RST": 0, "PSH": 0,
        "ACK": 0, "URG": 0, "CWE": 0, "ECE": 0,
    })

    def add(self, packet, source: tuple, timestamp: float) -> None:
        direction = self.forward if source == self.forward_endpoint else self.backward
        length = len(packet[IP])
        header_length = int(getattr(packet[IP], "ihl", 5) or 5) * 4
        payload_length = max(0, length - header_length)
        if TCP in packet:
            tcp = packet[TCP]
            tcp_header = int(tcp.dataofs or 5) * 4
            header_length += tcp_header
            payload_length = len(bytes(tcp.payload))
            if not direction.lengths:
                direction.initial_window = int(tcp.window)
            direction.segment_sizes.append(max(0, length - header_length))
            for name, marker in (
                ("FIN", "F"), ("SYN", "S"), ("RST", "R"), ("PSH", "P"),
                ("ACK", "A"), ("URG", "U"), ("ECE", "E"), ("CWE", "C"),
            ):
                if marker in str(tcp.flags):
                    self.flags[name] += 1
            direction.psh += int("P" in str(tcp.flags))
            direction.urg += int("U" in str(tcp.flags))
        else:
            direction.segment_sizes.append(payload_length)

        direction.lengths.append(length)
        direction.times.append(timestamp)
        direction.header_bytes += header_length
        direction.active_data += int(payload_length > 0)
        self.all_lengths.append(length)
        self.all_times.append(timestamp)
        self.last_seen = timestamp

    def features(self) -> dict[str, float]:
        fwd, bwd = self.forward, self.backward
        duration_us = max(0.0, (self.last_seen - self.started) * 1_000_000)
        duration_s = max(duration_us / 1_000_000, 1e-6)
        fmean, fstd, fmax, fmin = _stats(fwd.lengths)
        bmean, bstd, bmax, bmin = _stats(bwd.lengths)
        pmean, pstd, pmax, pmin = _stats(self.all_lengths)
        flow_iat = _iats(self.all_times)
        fwd_iat, bwd_iat = _iats(fwd.times), _iats(bwd.times)
        imean, istd, imax, imin = _stats(flow_iat)
        fimean, fistd, fimax, fimin = _stats(fwd_iat)
        bimean, bistd, bimax, bimin = _stats(bwd_iat)
        total_bytes = sum(self.all_lengths)
        total_packets = len(self.all_lengths)
        active, idle = _active_idle(self.all_times)
        amean, astd, amax, amin = _stats(active)
        idmean, idstd, idmax, idmin = _stats(idle)
        values = {
            "Flow Duration": duration_us,
            "Tot Fwd Pkts": len(fwd.lengths), "Tot Bwd Pkts": len(bwd.lengths),
            "TotLen Fwd Pkts": sum(fwd.lengths), "TotLen Bwd Pkts": sum(bwd.lengths),
            "Fwd Pkt Len Max": fmax, "Fwd Pkt Len Min": fmin,
            "Fwd Pkt Len Mean": fmean, "Fwd Pkt Len Std": fstd,
            "Bwd Pkt Len Max": bmax, "Bwd Pkt Len Min": bmin,
            "Bwd Pkt Len Mean": bmean, "Bwd Pkt Len Std": bstd,
            "Flow Byts/s": total_bytes / duration_s, "Flow Pkts/s": total_packets / duration_s,
            "Flow IAT Mean": imean, "Flow IAT Std": istd,
            "Flow IAT Max": imax, "Flow IAT Min": imin,
            "Fwd IAT Tot": sum(fwd_iat), "Fwd IAT Mean": fimean,
            "Fwd IAT Std": fistd, "Fwd IAT Max": fimax, "Fwd IAT Min": fimin,
            "Bwd IAT Tot": sum(bwd_iat), "Bwd IAT Mean": bimean,
            "Bwd IAT Std": bistd, "Bwd IAT Max": bimax, "Bwd IAT Min": bimin,
            "Fwd PSH Flags": fwd.psh, "Bwd PSH Flags": bwd.psh,
            "Fwd URG Flags": fwd.urg, "Bwd URG Flags": bwd.urg,
            "Fwd Header Len": fwd.header_bytes, "Bwd Header Len": bwd.header_bytes,
            "Fwd Pkts/s": len(fwd.lengths) / duration_s,
            "Bwd Pkts/s": len(bwd.lengths) / duration_s,
            "Pkt Len Min": pmin, "Pkt Len Max": pmax, "Pkt Len Mean": pmean,
            "Pkt Len Std": pstd, "Pkt Len Var": pstd ** 2,
            "FIN Flag Cnt": self.flags["FIN"], "SYN Flag Cnt": self.flags["SYN"],
            "RST Flag Cnt": self.flags["RST"], "PSH Flag Cnt": self.flags["PSH"],
            "ACK Flag Cnt": self.flags["ACK"], "URG Flag Cnt": self.flags["URG"],
            "CWE Flag Count": self.flags["CWE"], "ECE Flag Cnt": self.flags["ECE"],
            "Down/Up Ratio": len(bwd.lengths) / max(len(fwd.lengths), 1),
            "Pkt Size Avg": pmean, "Fwd Seg Size Avg": _stats(fwd.segment_sizes)[0],
            "Bwd Seg Size Avg": _stats(bwd.segment_sizes)[0],
            "Fwd Byts/b Avg": 0, "Fwd Pkts/b Avg": 0, "Fwd Blk Rate Avg": 0,
            "Bwd Byts/b Avg": 0, "Bwd Pkts/b Avg": 0, "Bwd Blk Rate Avg": 0,
            "Subflow Fwd Pkts": len(fwd.lengths), "Subflow Fwd Byts": sum(fwd.lengths),
            "Subflow Bwd Pkts": len(bwd.lengths), "Subflow Bwd Byts": sum(bwd.lengths),
            "Init Fwd Win Byts": fwd.initial_window, "Init Bwd Win Byts": bwd.initial_window,
            "Fwd Act Data Pkts": fwd.active_data,
            "Fwd Seg Size Min": min(fwd.segment_sizes) if fwd.segment_sizes else 0,
            "Active Mean": amean, "Active Std": astd, "Active Max": amax, "Active Min": amin,
            "Idle Mean": idmean, "Idle Std": idstd, "Idle Max": idmax, "Idle Min": idmin,
        }
        return {name: float(values[name]) if math.isfinite(float(values[name])) else 0.0 for name in FEATURES}


flows: dict[tuple, Flow] = {}
flow_lock = threading.Lock()


def consume_packet(packet, timestamp: float | None = None) -> None:
    if IP not in packet:
        return
    protocol, source, destination = packet_tuple(packet)
    key = canonical_key(protocol, source, destination)
    timestamp = float(packet.time if timestamp is None else timestamp)
    with flow_lock:
        flow = flows.get(key)
        if flow is None:
            flow = Flow(protocol, source, source[0], timestamp, timestamp)
            flows[key] = flow
        flow.add(packet, source, timestamp)


def packet_callback(packet) -> None:
    consume_packet(packet)


def flush_flows_to_db() -> int:
    with flow_lock:
        pending = list(flows.values())
        flows.clear()
    if not pending:
        return 0
    now = datetime.now(timezone.utc).isoformat()
    import json
    with connect(DB_PATH) as conn:
        conn.executemany(
            "INSERT INTO logs (timestamp, source_ip, source_host, label, data) VALUES (?, ?, ?, ?, ?)",
            [(now, flow.source_ip, flow.source_ip, "UNLABELLED", json.dumps(flow.features()))
             for flow in pending],
        )
    return len(pending)


def _flush_worker() -> None:
    while True:
        time.sleep(FLOW_WINDOW)
        count = flush_flows_to_db()
        if count:
            log.info("Flushed %d bidirectional flows", count)


def start_capture() -> None:
    init_schema(DB_PATH)
    threading.Thread(target=_flush_worker, daemon=True).start()
    log.info("Capturing IP traffic on %s with %.1fs windows", INTERFACE or "all interfaces", FLOW_WINDOW)
    try:
        sniff(prn=packet_callback, iface=INTERFACE, store=False, filter="ip")
    finally:
        flush_flows_to_db()


if __name__ == "__main__":
    start_capture()
