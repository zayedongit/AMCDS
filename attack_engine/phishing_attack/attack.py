"""Phishing Attack module."""
from __future__ import annotations
import random
from typing import Any


class PhishingAttack:
    """T1566.001 - Spearphishing Attachment: malicious emails to targeted users."""

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed + 2)

    def execute(self, tick: int, timestamp: float, state: dict[str, Any],
                params: dict[str, Any]) -> list[dict[str, Any]]:
        events = []
        targets = params.get("targets", [])
        sender = params.get("sender", "attacker@malicious-domain.com")

        if not targets:
            users = list(state.get("users", {}).values())
            targets = self._rng.sample(users, min(5, len(users)))

        subjects = [
            "URGENT: Verify Your Account Immediately",
            "Password Reset Required - Action Needed",
            "Security Alert: Suspicious Activity Detected",
            "Important: Update Your Payment Information",
            "IT Department: System Maintenance Notice",
        ]

        for target in targets:
            if self._rng.random() < params.get("send_rate", 0.5):
                email = target.get("email", f"{target.get('username', 'user')}@amcds-corp.sim")
                events.append({
                    "event_type": "email",
                    "timestamp": timestamp,
                    "sender_id": "attacker",
                    "sender_email": sender,
                    "recipients": [email],
                    "subject": self._rng.choice(subjects),
                    "body_length": self._rng.randint(200, 1000),
                    "has_attachment": True,
                    "attachment_name": self._rng.choice(["invoice.pdf.exe", "report.docm", "update.scr", "document.xlsm"]),
                    "attachment_size": self._rng.randint(50000, 500000),
                    "attack_indicator": True,
                    "mitre_technique": "T1566.001",
                })

                # Simulate user click probability
                click_prob = params.get("click_rate", 0.15)
                if self._rng.random() < click_prob:
                    events.append({
                        "event_type": "process",
                        "timestamp": timestamp + self._rng.uniform(30, 300),
                        "host_id": target.get("assigned_host_id", "unknown"),
                        "hostname": target.get("assigned_host_id", "unknown"),
                        "pid": self._rng.randint(5000, 9999),
                        "ppid": 1000,
                        "process_name": "malware_payload.exe",
                        "command_line": "C:\\Users\\user\\Downloads\\invoice.pdf.exe",
                        "user": target.get("username", "user"),
                        "event_type_proc": "start",
                        "attack_indicator": True,
                        "mitre_technique": "T1204.002",
                    })
        return events
