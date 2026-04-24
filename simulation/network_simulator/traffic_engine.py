"""
Traffic Engine - Generates baseline network flows and DNS/DHCP traffic.
Uses simulated Scapy-style packet metadata (no real packets sent).
"""
from __future__ import annotations
import random
from dataclasses import dataclass
from typing import Any


@dataclass
class NetworkFlowEvent:
    tick: int
    timestamp: float
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str  # "tcp", "udp", "icmp"
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    duration_ms: int
    flags: str | None = None  # TCP flags: "SYN", "SYN-ACK", "FIN", etc.
    flow_type: str = "normal"  # "normal", "dns", "dhcp", "service", "external"
    source_host: str | None = None
    dest_host: str | None = None
    details: dict[str, Any] | None = None


DNS_QUERIES = [
    "intranet.amcds-corp.sim", "mail.amcds-corp.sim", "portal.amcds-corp.sim",
    "ad.amcds-corp.sim", "fileserver.amcds-corp.sim", "vpn.amcds-corp.sim",
    "updates.microsoft.com", "github.com", "pypi.org", "npmjs.com",
]


class TrafficEngine:
    """Generates simulated network flow data mimicking real enterprise traffic patterns."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self._rng = random.Random(seed)
        self._flow_counter = 0

    def generate_service_flow(self, tick: int, timestamp: float,
                               src_ip: str, src_host: str,
                               dst_ip: str, dst_host: str,
                               dst_port: int) -> NetworkFlowEvent:
        self._flow_counter += 1
        return NetworkFlowEvent(
            tick=tick, timestamp=timestamp, source_ip=src_ip,
            source_port=self._rng.randint(49152, 65535),
            dest_ip=dst_ip, dest_port=dst_port, protocol="tcp",
            bytes_sent=self._rng.randint(100, 10000),
            bytes_received=self._rng.randint(100, 50000),
            packets_sent=self._rng.randint(5, 50),
            packets_received=self._rng.randint(5, 100),
            duration_ms=self._rng.randint(10, 5000),
            flags="SYN", flow_type="service",
            source_host=src_host, dest_host=dst_host,
        )

    def generate_dns_query(self, tick: int, timestamp: float,
                            src_ip: str, dns_server: str = "10.1.1.2") -> NetworkFlowEvent:
        domain = self._rng.choice(DNS_QUERIES)
        return NetworkFlowEvent(
            tick=tick, timestamp=timestamp, source_ip=src_ip,
            source_port=self._rng.randint(49152, 65535),
            dest_ip=dns_server, dest_port=53, protocol="udp",
            bytes_sent=self._rng.randint(40, 120),
            bytes_received=self._rng.randint(60, 300),
            packets_sent=1, packets_received=1,
            duration_ms=self._rng.randint(1, 50),
            flow_type="dns",
            details={"query": domain, "query_type": "A", "response_code": "NOERROR"},
        )

    def generate_external_flow(self, tick: int, timestamp: float,
                                src_ip: str, src_host: str) -> NetworkFlowEvent:
        ext_ip = f"203.0.113.{self._rng.randint(1, 254)}"
        return NetworkFlowEvent(
            tick=tick, timestamp=timestamp, source_ip=src_ip,
            source_port=self._rng.randint(49152, 65535),
            dest_ip=ext_ip, dest_port=self._rng.choice([80, 443]),
            protocol="tcp",
            bytes_sent=self._rng.randint(500, 50000),
            bytes_received=self._rng.randint(1000, 500000),
            packets_sent=self._rng.randint(10, 200),
            packets_received=self._rng.randint(10, 500),
            duration_ms=self._rng.randint(100, 30000),
            flow_type="external", source_host=src_host,
        )

    def generate_background_noise(self, tick: int, timestamp: float,
                                   host_ips: list[str], count: int = 5) -> list[NetworkFlowEvent]:
        """Generate background network noise for realism."""
        events = []
        for _ in range(count):
            src = self._rng.choice(host_ips)
            dst = self._rng.choice(host_ips)
            if src == dst:
                continue
            events.append(NetworkFlowEvent(
                tick=tick, timestamp=timestamp, source_ip=src,
                source_port=self._rng.randint(49152, 65535),
                dest_ip=dst, dest_port=self._rng.choice([445, 139, 389, 135, 3389, 22]),
                protocol="tcp",
                bytes_sent=self._rng.randint(50, 5000),
                bytes_received=self._rng.randint(50, 5000),
                packets_sent=self._rng.randint(1, 20),
                packets_received=self._rng.randint(1, 20),
                duration_ms=self._rng.randint(5, 1000),
                flow_type="normal",
            ))
        return events
