"""Ransomware Attack module."""
from __future__ import annotations
import random
from typing import Any


class RansomwareAttack:
    """T1486 - Data Encrypted for Impact: file encryption and propagation."""

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed + 5)

    def execute(self, tick: int, timestamp: float, state: dict[str, Any],
                params: dict[str, Any]) -> list[dict[str, Any]]:
        events = []
        compromised_hosts = params.get("compromised_hosts", [])
        if not compromised_hosts:
            hosts = list(state.get("hosts", {}).values())
            workstations = [h for h in hosts if h.get("host_type") == "workstation"]
            compromised_hosts = self._rng.sample(workstations, min(3, len(workstations)))

        for host in compromised_hosts:
            host_id = host.get("id", "unknown") if isinstance(host, dict) else host
            hostname = host.get("hostname", host_id) if isinstance(host, dict) else host_id
            ip = host.get("ip_address", "10.1.2.50") if isinstance(host, dict) else "10.1.2.50"

            # Shadow copy deletion
            events.append({
                "event_type": "process",
                "timestamp": timestamp,
                "host_id": host_id, "hostname": hostname,
                "pid": self._rng.randint(6000, 9000), "ppid": 1000,
                "process_name": "cmd.exe",
                "command_line": "vssadmin delete shadows /all /quiet",
                "user": "SYSTEM", "event_type_proc": "start",
                "attack_indicator": True, "mitre_technique": "T1490",
            })

            # File encryption
            for i in range(params.get("files_per_tick", 5)):
                events.append({
                    "event_type": "file",
                    "timestamp": timestamp + i * 0.05,
                    "user_id": "SYSTEM", "source_host": hostname,
                    "operation": "write",
                    "file_path": f"/shared/data/document_{self._rng.randint(1, 500)}.encrypted",
                    "file_name": f"document_{self._rng.randint(1, 500)}.encrypted",
                    "file_size": self._rng.randint(1024, 1048576),
                    "file_type": "encrypted",
                    "sensitivity": "internal",
                    "attack_indicator": True, "mitre_technique": "T1486",
                })

            # Propagation attempt to adjacent hosts
            if self._rng.random() < params.get("propagation_rate", 0.3):
                subnet = host.get("subnet_id", "subnet-001") if isinstance(host, dict) else "subnet-001"
                events.append({
                    "event_type": "network",
                    "timestamp": timestamp + 0.5,
                    "source_ip": ip, "source_host": hostname,
                    "dest_ip": f"10.1.{self._rng.randint(2, 5)}.{self._rng.randint(10, 200)}",
                    "dest_port": 445,
                    "protocol": "tcp",
                    "bytes_sent": self._rng.randint(50000, 500000),
                    "bytes_received": 0,
                    "packets_sent": self._rng.randint(10, 100),
                    "packets_received": 0,
                    "duration_ms": self._rng.randint(100, 5000),
                    "flow_type": "lateral",
                    "attack_indicator": True, "mitre_technique": "T1570",
                })
        return events
