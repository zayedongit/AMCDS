"""HTTP Exploitation Attack module."""
from __future__ import annotations
import random
from typing import Any


class HttpAttack:
    """T1190 - Exploit Public-Facing Application: SQL injection, path traversal."""

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed + 4)

    def execute(self, tick: int, timestamp: float, state: dict[str, Any],
                params: dict[str, Any]) -> list[dict[str, Any]]:
        events = []
        attacker_ip = params.get("attacker_ip", "198.51.100.75")
        target_services = params.get("target_services", ["Web Server", "HR Portal"])

        sqli_payloads = [
            "/api/users?id=1' OR '1'='1",
            "/api/search?q=admin' UNION SELECT * FROM users--",
            "/login?username=admin'--&password=x",
            "/api/data?filter=1; DROP TABLE sessions--",
        ]

        traversal_payloads = [
            "/download?file=../../../etc/passwd",
            "/api/files?path=..\\..\\windows\\system32\\config\\sam",
            "/static/../../../etc/shadow",
        ]

        for _ in range(params.get("requests_per_tick", 2)):
            target_svc = self._rng.choice(target_services)
            is_sqli = self._rng.random() < 0.6

            if is_sqli:
                payload = self._rng.choice(sqli_payloads)
                technique = "T1190"
            else:
                payload = self._rng.choice(traversal_payloads)
                technique = "T1190"

            target_ip = "10.1.1.10"  # DMZ web server
            events.append({
                "event_type": "http",
                "timestamp": timestamp + self._rng.uniform(0, 0.1),
                "source_ip": attacker_ip,
                "source_host": "external",
                "dest_ip": target_ip,
                "dest_host": target_svc.lower().replace(" ", "-"),
                "method": "GET" if "?" in payload else "POST",
                "url": f"https://{target_svc.lower().replace(' ', '-')}.amcds-corp.sim{payload}",
                "status_code": self._rng.choice([200, 200, 403, 500]),
                "request_size": len(payload),
                "response_size": self._rng.randint(100, 10000),
                "response_time_ms": self._rng.randint(50, 5000),
                "user_agent": "sqlmap/1.7 (http://sqlmap.org)",
                "attack_indicator": True,
                "mitre_technique": technique,
            })
        return events
