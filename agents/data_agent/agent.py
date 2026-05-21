"""
Data Sensitivity Agent - Monitors file access for data exfiltration and policy violations.

Detects: bulk data download, unauthorized sensitive file access, cross-department access.
"""
from __future__ import annotations
import logging
from typing import Any
from agents.base_agent import BaseAgent, Alert, StrategyProposal

logger = logging.getLogger(__name__)

BULK_DOWNLOAD_THRESHOLD = 8
BULK_DOWNLOAD_WINDOW = 120


class DataAgent(BaseAgent):
    def __init__(self, **kwargs):
        super().__init__(agent_name="data_agent", **kwargs)

    def get_subscribed_topics(self) -> list[str]:
        return ["telemetry.file"]

    def analyze(self, event: dict[str, Any]) -> list[Alert]:
        alerts = []
        operation = event.get("operation", "")
        sensitivity = event.get("sensitivity", "internal")
        actor = event.get("actor", {}) or {}
        user_id = actor.get("uid", "unknown")
        timestamp = event.get("time", 0)
        file_path = event.get("file_path", "")
        src = event.get("src_endpoint", {}) or {}
        hostname = src.get("hostname", "")

        # Bulk download detection
        if operation in ("download", "copy"):
            dl_key = f"downloads:{user_id}"
            count = self.cache_incr(dl_key, ttl=BULK_DOWNLOAD_WINDOW)
            if count >= BULK_DOWNLOAD_THRESHOLD:
                alerts.append(Alert(
                    agent_name=self.agent_name, timestamp=timestamp,
                    severity="high", confidence=0.75,
                    alert_type="bulk_data_download",
                    mitre_tactic="Collection", mitre_technique="T1005",
                    user_id=user_id, source_host=hostname,
                    description=f"Bulk download by {user_id}: {count} files in {BULK_DOWNLOAD_WINDOW}s",
                    evidence=[{"type": "download_count", "count": count}],
                    recommended_actions=["revoke_access", "investigate_user", "dlp_scan"],
                ))

        # Sensitive file access by unauthorized user
        if sensitivity in ("restricted", "confidential"):
            dept = event.get("unmapped", {}).get("department_match")
            # Cross-department access to restricted files
            if dept and user_id:
                access_key = f"sensitive:{user_id}:{sensitivity}"
                count = self.cache_incr(access_key, ttl=600)
                if count >= 3:
                    alerts.append(Alert(
                        agent_name=self.agent_name, timestamp=timestamp,
                        severity="high" if sensitivity == "restricted" else "medium",
                        confidence=0.70,
                        alert_type="unauthorized_sensitive_access",
                        mitre_tactic="Collection", mitre_technique="T1039",
                        user_id=user_id, source_host=hostname,
                        description=f"Repeated {sensitivity} file access by {user_id}: {file_path}",
                        evidence=[{"type": "sensitive_access", "sensitivity": sensitivity, "count": count}],
                        recommended_actions=["revoke_file_access", "alert_data_owner", "investigate"],
                    ))

        return alerts

    def propose_strategy(self, alert: Alert) -> StrategyProposal | None:
        strategies = {
            "bulk_data_download": StrategyProposal(
                agent_name=self.agent_name,
                actions=["revoke_file_access", "quarantine_downloads", "investigate_user"],
                confidence=alert.confidence, residual_risk=0.20,
                impact_estimate={"affected_users": 1, "data_at_risk_mb": 100},
            ),
            "unauthorized_sensitive_access": StrategyProposal(
                agent_name=self.agent_name,
                actions=["revoke_file_access", "encrypt_sensitive_files", "alert_dlp"],
                confidence=alert.confidence, residual_risk=0.15,
                impact_estimate={"affected_users": 1},
            ),
        }
        p = strategies.get(alert.alert_type)
        if p:
            p.incident_id = alert.alert_id
        return p
