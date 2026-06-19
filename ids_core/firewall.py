"""Idempotent host firewall operations used by API and inference."""

import ipaddress
import logging
import subprocess

log = logging.getLogger(__name__)


def normalize_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


def _run(args: list[str], *, acceptable: tuple[int, ...] = (0,)) -> bool:
    try:
        result = subprocess.run(
            ["iptables", "-w", "5", *args], capture_output=True, text=True, timeout=10
        )
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        log.error("iptables unavailable: %s", exc)
        return False
    if result.returncode not in acceptable:
        log.warning("iptables %s failed: %s", " ".join(args), result.stderr.strip())
        return False
    return True


def _ensure_rule(chain: str, selector: str, ip: str) -> bool:
    rule = [chain, selector, ip, "-j", "DROP"]
    if _run(["-C", *rule]):
        return True
    return _run(["-I", *rule])


def block_ip(value: str) -> bool:
    ip = normalize_ip(value)
    # An IDS blocks traffic arriving from an attacker. Adding an OUTPUT rule can
    # sever SSH/API management replies and is unnecessary for source blocking.
    rules = [
        ("INPUT", "-s"),
        ("FORWARD", "-s"),
    ]
    for chain, selector in rules:
        if not _ensure_rule(chain, selector, ip):
            for rollback_chain, rollback_selector in rules:
                _delete_all(rollback_chain, rollback_selector, ip)
            return False
    return True


def _delete_all(chain: str, selector: str, ip: str) -> bool:
    rule = [chain, selector, ip, "-j", "DROP"]
    while _run(["-C", *rule]):
        if not _run(["-D", *rule]):
            return False
    return True


def unblock_ip(value: str) -> bool:
    ip = normalize_ip(value)
    # Also remove legacy destination rules created by releases before 2.1.
    return all([
        _delete_all("INPUT", "-s", ip),
        _delete_all("OUTPUT", "-d", ip),
        _delete_all("FORWARD", "-s", ip),
        _delete_all("FORWARD", "-d", ip),
    ])
