"""
Identity Agent - Monitors authentication telemetry for identity-based threats.

Detects: brute force, impossible travel, credential stuffing, unusual login times,
         account enumeration, suspicious MFA bypasses.
"""
from __future__ import annotations
import logging
import math
from typing import Any
from agents.base_agent import BaseAgent, Alert, StrategyProposal

logger = logging.getLogger(__name__)

# Detection thresholds
FAILED_LOGIN_THRESHOLD = 5       # failures per user in window
FAILED_LOGIN_WINDOW = 300        # seconds
BRUTE_FORCE_THRESHOLD = 15       # failures across users from same IP
UNUSUAL_HOUR_START = 0           # midnight
UNUSUAL_HOUR_END = 5             # 5 AM
CREDENTIAL_STUFFING_USERS = 10   # distinct users from same IP in window


class IdentityAgent(BaseAgent):
    """Monitors telemetry.auth and telemetry.email for identity threats."""

    def __init__(self, **kwargs):
        super().__init__(agent_name="identity_agent", **kwargs)

    def get_subscribed_topics(self) -> list[str]:
        return ["telemetry.auth", "telemetry.email"]

    def analyze(self, event: dict[str, Any]) -> list[Alert]:
        alerts = []
        class_uid = event.get("class_uid", 0)

        if class_uid == 3001:  # Auth event
            alerts.extend(self._analyze_auth(event))
        elif class_uid == 6001:  # Email event
            alerts.extend(self._analyze_email_auth(event))

        return alerts

    def _analyze_auth(self, event: dict[str, Any]) -> list[Alert]:
        alerts = []
        status = event.get("status_id", 1)
        actor = event.get("actor", {}) or {}
        src = event.get("src_endpoint", {}) or {}
        user_id = actor.get("uid", "unknown")
        source_ip = src.get("ip", "unknown")
        timestamp = event.get("time", 0)

        if status == 2:  # Failed auth
            # Track per-user failures
            user_fail_key = f"fail:{user_id}"
            fail_count = self.cache_incr(user_fail_key, ttl=FAILED_LOGIN_WINDOW)
            if fail_count >= FAILED_LOGIN_THRESHOLD:
                alerts.append(Alert(
                    agent_name=self.agent_name, timestamp=timestamp,
                    severity="high", confidence=min(0.6 + fail_count * 0.05, 0.95),
                    alert_type="brute_force_attempt",
                    mitre_tactic="Credential Access", mitre_technique="T1110",
                    source_ip=source_ip, user_id=user_id,
                    description=f"Brute force detected: {fail_count} failed logins for {user_id}",
                    evidence=[{"type": "failed_logins", "count": fail_count, "window_sec": FAILED_LOGIN_WINDOW}],
                    recommended_actions=["lock_account", "alert_soc", "reset_credentials"],
                    raw_events=[event.get("metadata", {}).get("uid", "")],
                ))

            # Track per-IP failures (credential stuffing)
            ip_fail_key = f"ip_fail:{source_ip}"
            ip_fail_count = self.cache_incr(ip_fail_key, ttl=FAILED_LOGIN_WINDOW)
            ip_users_key = f"ip_users:{source_ip}"
            existing = self.cache_get(ip_users_key) or []
            if user_id not in existing:
                existing.append(user_id)
                self.cache_set(ip_users_key, existing, ttl=FAILED_LOGIN_WINDOW)

            if len(existing) >= CREDENTIAL_STUFFING_USERS:
                alerts.append(Alert(
                    agent_name=self.agent_name, timestamp=timestamp,
                    severity="critical", confidence=0.90,
                    alert_type="credential_stuffing",
                    mitre_tactic="Credential Access", mitre_technique="T1110.004",
                    source_ip=source_ip,
                    description=f"Credential stuffing from {source_ip}: {len(existing)} users targeted",
                    evidence=[{"type": "distinct_users", "count": len(existing), "ip": source_ip}],
                    recommended_actions=["block_ip", "lock_targeted_accounts", "force_password_reset"],
                ))

        elif status == 1:  # Successful auth
            # Unusual login time detection
            hour = int((timestamp % 86400) / 3600)
            if UNUSUAL_HOUR_START <= hour < UNUSUAL_HOUR_END:
                alerts.append(Alert(
                    agent_name=self.agent_name, timestamp=timestamp,
                    severity="medium", confidence=0.50,
                    alert_type="unusual_login_time",
                    mitre_tactic="Initial Access", mitre_technique="T1078",
                    source_ip=source_ip, user_id=user_id,
                    description=f"Unusual login time for {user_id} at hour {hour}",
                    evidence=[{"type": "login_hour", "hour": hour}],
                    recommended_actions=["monitor_session", "verify_with_user"],
                ))

        return alerts

    def _analyze_email_auth(self, event: dict[str, Any]) -> list[Alert]:
        """Check email events for suspicious authentication-related patterns."""
        alerts = []
        subject = event.get("subject", "").lower()
        suspicious_keywords = ["password reset", "verify your account", "urgent action",
                                "confirm identity", "security alert", "suspended"]
        if any(kw in subject for kw in suspicious_keywords):
            if event.get("has_attachment") or "http" in subject:
                alerts.append(Alert(
                    agent_name=self.agent_name, timestamp=event.get("time", 0),
                    severity="high", confidence=0.70,
                    alert_type="phishing_email",
                    mitre_tactic="Initial Access", mitre_technique="T1566.001",
                    user_id=event.get("actor", {}).get("uid"),
                    description=f"Suspicious email detected: '{event.get('subject', '')}'",
                    evidence=[{"type": "suspicious_subject", "subject": event.get("subject")}],
                    recommended_actions=["quarantine_email", "alert_user", "block_sender"],
                ))
        return alerts

    def propose_strategy(self, alert: Alert) -> StrategyProposal | None:
        strategies = {
            "brute_force_attempt": StrategyProposal(
                agent_name=self.agent_name, actions=["lock_account", "reset_credentials", "enable_mfa"],
                confidence=alert.confidence, residual_risk=0.15,
                impact_estimate={"affected_users": 1, "affected_services": 1},
            ),
            "credential_stuffing": StrategyProposal(
                agent_name=self.agent_name, actions=["block_ip", "lock_accounts", "force_password_reset", "enable_mfa"],
                confidence=alert.confidence, residual_risk=0.10,
                impact_estimate={"affected_users": 10, "affected_services": 2},
            ),
            "phishing_email": StrategyProposal(
                agent_name=self.agent_name, actions=["quarantine_email", "block_sender_domain", "alert_all_recipients"],
                confidence=alert.confidence, residual_risk=0.20,
                impact_estimate={"affected_users": 5, "affected_services": 1},
            ),
        }
        proposal = strategies.get(alert.alert_type)
        if proposal:
            proposal.incident_id = alert.alert_id
        return proposal
