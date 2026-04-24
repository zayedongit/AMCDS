"""Lateral Movement Attack module."""
from __future__ import annotations
import random
from typing import Any


class LateralMovementAttack:
    """T1021 - Remote Services: RDP/SMB movement with stolen credentials."""

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed + 6)

    def execute(self, tick: int, timestamp: float, state: dict[str, Any],
                params: dict[str, Any]) -> list[dict[str, Any]]:
        events = []
        compromised_user = params.get("compromised_user", "admin")
        source_host = params.get("source_host", {})
        target_hosts = params.get("target_hosts", [])

        if not target_hosts:
            hosts = list(state.get("hosts", {}).values())
            servers = [h for h in hosts if h.get("host_type") == "server"]
            target_hosts = self._rng.sample(servers, min(3, len(servers)))

        src_ip = source_host.get("ip_address", "10.1.2.50") if isinstance(source_host, dict) else "10.1.2.50"
        src_name = source_host.get("hostname", "compromised-ws") if isinstance(source_host, dict) else "compromised-ws"

        for target in target_hosts:
            dst_ip = target.get("ip_address", "10.1.1.10") if isinstance(target, dict) else "10.1.1.10"
            dst_name = target.get("hostname", "target-srv") if isinstance(target, dict) else "target-srv"

            # RDP/SMB connection attempt
            port = self._rng.choice([3389, 445, 22])
            events.append({
                "event_type": "network",
                "timestamp": timestamp,
                "source_ip": src_ip, "source_host": src_name,
                "source_port": self._rng.randint(49152, 65535),
                "dest_ip": dst_ip, "dest_host": dst_name,
                "dest_port": port,
                "protocol": "tcp",
                "bytes_sent": self._rng.randint(1000, 50000),
                "bytes_received": self._rng.randint(1000, 50000),
                "packets_sent": self._rng.randint(10, 200),
                "packets_received": self._rng.randint(10, 200),
                "duration_ms": self._rng.randint(1000, 30000),
                "flow_type": "lateral",
                "attack_indicator": True, "mitre_technique": "T1021.001",
            })

            # Authentication with stolen credentials
            events.append({
                "event_type": "auth",
                "timestamp": timestamp + 1,
                "user_id": compromised_user, "username": compromised_user,
                "source_ip": src_ip, "source_host": src_name,
                "target_service": dst_name,
                "auth_method": "password",
                "success": self._rng.random() < 0.7,
                "mfa_used": False,
                "attack_indicator": True, "mitre_technique": "T1078",
            })

            # If successful, run reconnaissance commands
            if self._rng.random() < 0.5:
                events.append({
                    "event_type": "process",
                    "timestamp": timestamp + 5,
                    "host_id": target.get("id", "unknown") if isinstance(target, dict) else "unknown",
                    "hostname": dst_name,
                    "pid": self._rng.randint(7000, 9999), "ppid": 1,
                    "process_name": "cmd.exe",
                    "command_line": f"net user /domain && net localgroup administrators",
                    "user": compromised_user, "event_type_proc": "start",
                    "attack_indicator": True, "mitre_technique": "T1087",
                })
        return events
