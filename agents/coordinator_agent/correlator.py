"""
Incident Correlator - Groups classified alerts into incidents using temporal,
actor, and kill-chain proximity.
"""
from __future__ import annotations
import logging
import uuid
import time
from dataclasses import dataclass, field, asdict
from typing import Any

logger = logging.getLogger(__name__)

CORRELATION_WINDOW = 300  # seconds
MITRE_KILL_CHAIN_ORDER = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact",
]


@dataclass
class Incident:
    incident_id: str = ""
    alerts: list[dict[str, Any]] = field(default_factory=list)
    attack_class: str = "unknown"
    confidence: float = 0.0
    severity: str = "medium"
    first_seen: float = 0.0
    last_seen: float = 0.0
    affected_users: list[str] = field(default_factory=list)
    affected_hosts: list[str] = field(default_factory=list)
    affected_ips: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    kill_chain_phase: int = 0
    status: str = "open"  # "open", "investigating", "contained", "resolved"

    def __post_init__(self):
        if not self.incident_id:
            self.incident_id = f"inc-{uuid.uuid4().hex[:12]}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IncidentCorrelator:
    """Groups related classified alerts into incidents."""

    def __init__(self):
        self._active_incidents: list[Incident] = []

    def correlate(self, classified_alert: dict[str, Any]) -> Incident:
        """Correlate a classified alert into an existing or new incident."""
        timestamp = classified_alert.get("timestamp", time.time())

        # Find matching existing incident
        matched = self._find_matching_incident(classified_alert, timestamp)
        if matched:
            self._add_alert_to_incident(matched, classified_alert)
            return matched

        # Create new incident
        incident = self._create_incident(classified_alert)
        self._active_incidents.append(incident)
        return incident

    def _find_matching_incident(self, alert: dict[str, Any], timestamp: float) -> Incident | None:
        src_ip = alert.get("source_ip")
        user_id = alert.get("user_id")
        attack_class = alert.get("attack_class", "unknown")

        for inc in self._active_incidents:
            if inc.status in ("contained", "resolved"):
                continue
            if timestamp - inc.last_seen > CORRELATION_WINDOW:
                continue

            # Match by shared actor
            if src_ip and src_ip in inc.affected_ips:
                return inc
            if user_id and user_id in inc.affected_users:
                return inc
            # Match by attack class and temporal proximity
            if inc.attack_class == attack_class and timestamp - inc.last_seen < CORRELATION_WINDOW / 2:
                return inc

        return None

    def _add_alert_to_incident(self, incident: Incident, alert: dict[str, Any]) -> None:
        incident.alerts.append(alert)
        incident.last_seen = alert.get("timestamp", time.time())

        if alert.get("source_ip") and alert["source_ip"] not in incident.affected_ips:
            incident.affected_ips.append(alert["source_ip"])
        if alert.get("user_id") and alert["user_id"] not in incident.affected_users:
            incident.affected_users.append(alert["user_id"])
        if alert.get("source_host") and alert["source_host"] not in incident.affected_hosts:
            incident.affected_hosts.append(alert["source_host"])

        tactic = alert.get("mitre_tactic", "")
        if tactic and tactic not in incident.mitre_tactics:
            incident.mitre_tactics.append(tactic)
        technique = alert.get("mitre_technique", "")
        if technique and technique not in incident.mitre_techniques:
            incident.mitre_techniques.append(technique)

        # Recalculate confidence
        confidences = [a.get("confidence", 0.5) for a in incident.alerts]
        incident.confidence = round(1 - (1 - max(confidences)) * (0.9 ** (len(incident.alerts) - 1)), 3)

        # Update severity
        severities = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        max_sev = max(severities.get(a.get("severity", "medium"), 2) for a in incident.alerts)
        incident.severity = {1: "low", 2: "medium", 3: "high", 4: "critical"}.get(max_sev, "medium")

        # Update kill chain phase
        for tac in incident.mitre_tactics:
            if tac in MITRE_KILL_CHAIN_ORDER:
                phase = MITRE_KILL_CHAIN_ORDER.index(tac)
                incident.kill_chain_phase = max(incident.kill_chain_phase, phase)

    def _create_incident(self, alert: dict[str, Any]) -> Incident:
        ts = alert.get("timestamp", time.time())
        return Incident(
            alerts=[alert],
            attack_class=alert.get("attack_class", "unknown"),
            confidence=alert.get("confidence", 0.5),
            severity=alert.get("severity", "medium"),
            first_seen=ts, last_seen=ts,
            affected_users=[alert["user_id"]] if alert.get("user_id") else [],
            affected_hosts=[alert["source_host"]] if alert.get("source_host") else [],
            affected_ips=[alert["source_ip"]] if alert.get("source_ip") else [],
            mitre_tactics=[alert["mitre_tactic"]] if alert.get("mitre_tactic") else [],
            mitre_techniques=[alert["mitre_technique"]] if alert.get("mitre_technique") else [],
        )

    def get_active_incidents(self) -> list[Incident]:
        return [i for i in self._active_incidents if i.status in ("open", "investigating")]

    def get_all_incidents(self) -> list[Incident]:
        return list(self._active_incidents)

    def close_stale_incidents(self, max_age: float = 3600) -> list[str]:
        now = time.time()
        closed = []
        for inc in self._active_incidents:
            if inc.status == "open" and now - inc.last_seen > max_age:
                inc.status = "resolved"
                closed.append(inc.incident_id)
        return closed
