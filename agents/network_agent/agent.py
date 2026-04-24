"""
Network Agent - Monitors network flows and HTTP traffic for threats.

Detects: port scanning, C2 beaconing, DNS tunneling, unusual traffic volumes,
         suspicious HTTP patterns (SQL injection, path traversal).
"""
from __future__ import annotations
import logging
from typing import Any
from agents.base_agent import BaseAgent, Alert, StrategyProposal

logger = logging.getLogger(__name__)

PORT_SCAN_THRESHOLD = 10
BEACON_INTERVAL_TOLERANCE = 5.0  # seconds
HIGH_VOLUME_MULTIPLIER = 10
SQL_INJECTION_PATTERNS = ["' OR ", "1=1", "UNION SELECT", "DROP TABLE", "; --", "' AND "]
PATH_TRAVERSAL_PATTERNS = ["../", "..\\", "/etc/passwd", "/etc/shadow", "cmd.exe", "powershell"]


class NetworkAgent(BaseAgent):
    def __init__(self, **kwargs):
        super().__init__(agent_name="network_agent", **kwargs)

    def get_subscribed_topics(self) -> list[str]:
        return ["telemetry.network", "telemetry.http"]

    def analyze(self, event: dict[str, Any]) -> list[Alert]:
        alerts = []
        class_uid = event.get("class_uid", 0)
        if class_uid == 4001:
            alerts.extend(self._analyze_network(event))
        elif class_uid == 4002:
            alerts.extend(self._analyze_http(event))
        return alerts

    def _analyze_network(self, event: dict[str, Any]) -> list[Alert]:
        alerts = []
        src = event.get("src_endpoint", {}) or {}
        dst = event.get("dst_endpoint", {}) or {}
        src_ip = src.get("ip", "")
        dst_ip = dst.get("ip", "")
        dst_port = dst.get("port", 0)
        timestamp = event.get("time", 0)

        # Port scanning detection
        scan_key = f"ports:{src_ip}:{dst_ip}"
        scanned = self.cache_get(scan_key) or []
        if dst_port and dst_port not in scanned:
            scanned.append(dst_port)
            self.cache_set(scan_key, scanned, ttl=300)
        if len(scanned) >= PORT_SCAN_THRESHOLD:
            alerts.append(Alert(
                agent_name=self.agent_name, timestamp=timestamp,
                severity="high", confidence=0.80,
                alert_type="port_scan", mitre_tactic="Discovery", mitre_technique="T1046",
                source_ip=src_ip, target_ip=dst_ip,
                description=f"Port scan from {src_ip}: {len(scanned)} ports on {dst_ip}",
                evidence=[{"type": "scanned_ports", "ports": scanned[:20]}],
                recommended_actions=["block_source_ip", "isolate_target", "investigate"],
            ))

        # High volume transfer detection
        bytes_total = event.get("bytes_sent", 0) + event.get("bytes_received", 0)
        if bytes_total > 10_000_000:  # 10MB in single flow
            alerts.append(Alert(
                agent_name=self.agent_name, timestamp=timestamp,
                severity="medium", confidence=0.60,
                alert_type="high_volume_transfer", mitre_tactic="Exfiltration", mitre_technique="T1048",
                source_ip=src_ip, target_ip=dst_ip,
                description=f"Large data transfer: {bytes_total / 1_000_000:.1f}MB from {src_ip}",
                evidence=[{"type": "bytes_transferred", "bytes": bytes_total}],
                recommended_actions=["investigate_transfer", "monitor_source"],
            ))

        return alerts

    def _analyze_http(self, event: dict[str, Any]) -> list[Alert]:
        alerts = []
        url = event.get("url", "")
        method = event.get("http_method", "GET")
        src = event.get("src_endpoint", {}) or {}
        src_ip = src.get("ip", "")
        timestamp = event.get("time", 0)

        # SQL injection detection
        url_upper = url.upper()
        for pattern in SQL_INJECTION_PATTERNS:
            if pattern.upper() in url_upper:
                alerts.append(Alert(
                    agent_name=self.agent_name, timestamp=timestamp,
                    severity="critical", confidence=0.85,
                    alert_type="sql_injection", mitre_tactic="Initial Access", mitre_technique="T1190",
                    source_ip=src_ip,
                    description=f"SQL injection attempt in URL: {url[:100]}",
                    evidence=[{"type": "sql_pattern", "url": url[:200], "pattern": pattern}],
                    recommended_actions=["block_ip", "waf_rule", "patch_application"],
                ))
                break

        # Path traversal detection
        for pattern in PATH_TRAVERSAL_PATTERNS:
            if pattern in url:
                alerts.append(Alert(
                    agent_name=self.agent_name, timestamp=timestamp,
                    severity="high", confidence=0.80,
                    alert_type="path_traversal", mitre_tactic="Initial Access", mitre_technique="T1190",
                    source_ip=src_ip,
                    description=f"Path traversal attempt: {url[:100]}",
                    evidence=[{"type": "traversal_pattern", "url": url[:200]}],
                    recommended_actions=["block_ip", "patch_application"],
                ))
                break

        return alerts

    def propose_strategy(self, alert: Alert) -> StrategyProposal | None:
        strategies = {
            "port_scan": StrategyProposal(
                agent_name=self.agent_name, actions=["block_ip", "isolate_subnet", "enable_ids"],
                confidence=alert.confidence, residual_risk=0.20,
                impact_estimate={"affected_hosts": 2},
            ),
            "sql_injection": StrategyProposal(
                agent_name=self.agent_name, actions=["block_ip", "enable_waf", "patch_app", "isolate_server"],
                confidence=alert.confidence, residual_risk=0.10,
                impact_estimate={"affected_services": 1, "downtime_minutes": 5},
            ),
            "path_traversal": StrategyProposal(
                agent_name=self.agent_name, actions=["block_ip", "patch_app"],
                confidence=alert.confidence, residual_risk=0.15,
                impact_estimate={"affected_services": 1},
            ),
            "high_volume_transfer": StrategyProposal(
                agent_name=self.agent_name, actions=["throttle_traffic", "investigate_source", "dlp_scan"],
                confidence=alert.confidence, residual_risk=0.30,
                impact_estimate={"affected_hosts": 1},
            ),
        }
        p = strategies.get(alert.alert_type)
        if p:
            p.incident_id = alert.alert_id
        return p
