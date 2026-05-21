"""Malicious Link Attack module."""
from __future__ import annotations
import random
from typing import Any


class MaliciousLinkAttack:
    """T1566.002 - Spearphishing Link: credential harvesting via malicious URLs."""

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed + 3)

    def execute(self, tick: int, timestamp: float, state: dict[str, Any],
                params: dict[str, Any]) -> list[dict[str, Any]]:
        events = []
        malicious_domains = ["secure-login-verify.com", "amcds-corp-portal.net", "account-update-now.org"]
        targets = params.get("targets", [])
        if not targets:
            users = list(state.get("users", {}).values())
            targets = self._rng.sample(users, min(5, len(users)))

        for target in targets:
            domain = self._rng.choice(malicious_domains)
            # Email with malicious link
            events.append({
                "event_type": "email",
                "timestamp": timestamp,
                "sender_id": "attacker",
                "sender_email": f"support@{domain}",
                "recipients": [target.get("email", "")],
                "subject": "Verify Your Account - Click Here",
                "body_length": 500,
                "has_attachment": False,
                "attack_indicator": True,
                "mitre_technique": "T1566.002",
            })

            # Simulate click-through
            if self._rng.random() < params.get("click_rate", 0.20):
                host = target.get("assigned_host_id", "unknown")
                events.append({
                    "event_type": "http",
                    "timestamp": timestamp + self._rng.uniform(60, 600),
                    "source_ip": state.get("hosts", {}).get(host, {}).get("ip_address", "10.1.2.50"),
                    "source_host": host,
                    "dest_ip": "198.51.100.100",
                    "dest_host": domain,
                    "method": "POST",
                    "url": f"https://{domain}/login?token=malicious",
                    "status_code": 200,
                    "request_size": 500,
                    "response_size": 2000,
                    "response_time_ms": 150,
                    "user_agent": "Mozilla/5.0 Chrome/120.0.0.0",
                    "user_id": target.get("id"),
                    "attack_indicator": True,
                    "mitre_technique": "T1566.002",
                })
        return events
