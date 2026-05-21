"""
Endpoint Agent - Monitors process and endpoint telemetry for threats.

Detects: suspicious processes, privilege escalation, ransomware encryption patterns,
         unauthorized remote access, malicious command execution.
"""
from __future__ import annotations
import logging
from typing import Any
from agents.base_agent import BaseAgent, Alert, StrategyProposal

logger = logging.getLogger(__name__)

SUSPICIOUS_PROCESSES = [
    "mimikatz", "psexec", "procdump", "lazagne", "bloodhound",
    "rubeus", "sharphound", "cobaltstrike", "meterpreter",
]

SUSPICIOUS_COMMANDS = [
    "net user /add", "net localgroup administrators",
    "reg add", "schtasks /create", "bitsadmin /transfer",
    "certutil -urlcache", "powershell -enc", "cmd.exe /c whoami",
    "wmic process call create", "vssadmin delete shadows",
]

RANSOMWARE_INDICATORS = [
    "vssadmin delete", "wbadmin delete", "bcdedit /set",
    "cipher /w:", "icacls", "attrib +h",
]


class EndpointAgent(BaseAgent):
    def __init__(self, **kwargs):
        super().__init__(agent_name="endpoint_agent", **kwargs)

    def get_subscribed_topics(self) -> list[str]:
        return ["telemetry.endpoint", "telemetry.process"]

    def analyze(self, event: dict[str, Any]) -> list[Alert]:
        alerts = []
        process_name = event.get("process_name", "").lower()
        command_line = event.get("command_line", "").lower()
        hostname = event.get("src_endpoint", {}).get("hostname", "") if event.get("src_endpoint") else ""
        timestamp = event.get("time", 0)

        # Suspicious process detection
        for susp in SUSPICIOUS_PROCESSES:
            if susp in process_name or susp in command_line:
                alerts.append(Alert(
                    agent_name=self.agent_name, timestamp=timestamp,
                    severity="critical", confidence=0.90,
                    alert_type="suspicious_process",
                    mitre_tactic="Execution", mitre_technique="T1059",
                    source_host=hostname,
                    description=f"Suspicious process detected: {process_name} on {hostname}",
                    evidence=[{"type": "process", "name": process_name, "cmd": command_line[:200]}],
                    recommended_actions=["kill_process", "isolate_host", "forensic_capture"],
                ))
                break

        # Suspicious command detection
        for cmd in SUSPICIOUS_COMMANDS:
            if cmd.lower() in command_line:
                alerts.append(Alert(
                    agent_name=self.agent_name, timestamp=timestamp,
                    severity="high", confidence=0.80,
                    alert_type="privilege_escalation",
                    mitre_tactic="Privilege Escalation", mitre_technique="T1078",
                    source_host=hostname,
                    description=f"Suspicious command: {command_line[:100]}",
                    evidence=[{"type": "command", "cmd": command_line[:200]}],
                    recommended_actions=["kill_process", "investigate_user", "isolate_host"],
                ))
                break

        # Ransomware pattern detection
        for indicator in RANSOMWARE_INDICATORS:
            if indicator.lower() in command_line:
                alerts.append(Alert(
                    agent_name=self.agent_name, timestamp=timestamp,
                    severity="critical", confidence=0.95,
                    alert_type="ransomware_activity",
                    mitre_tactic="Impact", mitre_technique="T1486",
                    source_host=hostname,
                    description=f"Ransomware indicator on {hostname}: {command_line[:100]}",
                    evidence=[{"type": "ransomware_cmd", "cmd": command_line[:200]}],
                    recommended_actions=["isolate_host", "kill_process", "snapshot_disk", "alert_ir"],
                ))
                break

        # Rapid file encryption tracking
        enc_key = f"file_encrypt:{hostname}"
        if "encrypt" in command_line or "cipher" in command_line:
            count = self.cache_incr(enc_key, ttl=60)
            if count >= 5:
                alerts.append(Alert(
                    agent_name=self.agent_name, timestamp=timestamp,
                    severity="critical", confidence=0.92,
                    alert_type="ransomware_encryption",
                    mitre_tactic="Impact", mitre_technique="T1486",
                    source_host=hostname,
                    description=f"Mass encryption on {hostname}: {count} encryption ops in 60s",
                    evidence=[{"type": "encryption_count", "count": count}],
                    recommended_actions=["isolate_host", "network_quarantine", "snapshot_disk"],
                ))

        return alerts

    def propose_strategy(self, alert: Alert) -> StrategyProposal | None:
        strategies = {
            "suspicious_process": StrategyProposal(
                agent_name=self.agent_name, actions=["kill_process", "isolate_host", "forensic_capture"],
                confidence=alert.confidence, residual_risk=0.15,
                impact_estimate={"affected_hosts": 1},
            ),
            "ransomware_activity": StrategyProposal(
                agent_name=self.agent_name, actions=["isolate_host", "isolate_subnet", "kill_all_suspicious", "snapshot_disk"],
                confidence=alert.confidence, residual_risk=0.05,
                impact_estimate={"affected_hosts": 5, "downtime_minutes": 30},
            ),
            "ransomware_encryption": StrategyProposal(
                agent_name=self.agent_name, actions=["network_quarantine", "isolate_host", "kill_all_suspicious", "restore_from_backup"],
                confidence=alert.confidence, residual_risk=0.05,
                impact_estimate={"affected_hosts": 10, "downtime_minutes": 60},
            ),
            "privilege_escalation": StrategyProposal(
                agent_name=self.agent_name, actions=["kill_process", "revoke_privileges", "investigate_user"],
                confidence=alert.confidence, residual_risk=0.20,
                impact_estimate={"affected_hosts": 1},
            ),
        }
        p = strategies.get(alert.alert_type)
        if p:
            p.incident_id = alert.alert_id
        return p
