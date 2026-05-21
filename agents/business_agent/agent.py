"""
Business Impact Agent - Calculates revenue, operational, and SLA impact of incidents.
Uses service dependency graph and OR-Tools for constraint optimization.
"""
from __future__ import annotations
import logging
from typing import Any
from agents.base_agent import BaseAgent, Alert, StrategyProposal

logger = logging.getLogger(__name__)


class BusinessImpactAgent(BaseAgent):
    """Assesses business impact of security incidents."""

    def __init__(self, service_registry: dict[str, Any] | None = None, **kwargs):
        super().__init__(agent_name="business_agent", **kwargs)
        self._service_registry = service_registry or {}
        self._dependency_graph: dict[str, list[str]] = {}

    def get_subscribed_topics(self) -> list[str]:
        return ["incidents.correlated"]

    def load_service_graph(self, services: dict[str, Any]) -> None:
        self._service_registry = services
        for svc_id, svc in services.items():
            self._dependency_graph[svc_id] = svc.get("dependencies", [])

    def analyze(self, event: dict[str, Any]) -> list[Alert]:
        """Analyze an incident for business impact and publish assessment."""
        affected_hosts = event.get("affected_hosts", [])
        affected_services = self._find_affected_services(affected_hosts)
        cascade = self._calculate_cascade(affected_services)
        impact = self._calculate_impact(affected_services, cascade)

        assessment = {
            "incident_id": event.get("incident_id"),
            "affected_services": affected_services,
            "cascade_services": cascade,
            "revenue_impact_per_minute": impact["revenue"],
            "operational_disruption_score": impact["disruption"],
            "sla_violation_probability": impact["sla_violation"],
            "total_affected_users": impact["users"],
            "recommended_priority": impact["priority"],
        }

        if self._producer:
            self._producer.produce("incidents.correlated", {
                **event, "business_impact": assessment,
            }, key=event.get("incident_id", ""))

        return []

    def _find_affected_services(self, hosts: list[str]) -> list[str]:
        affected = []
        for svc_id, svc in self._service_registry.items():
            host_ids = svc.get("host_ids", [])
            if any(h in hosts for h in host_ids):
                affected.append(svc_id)
        return affected

    def _calculate_cascade(self, affected_services: list[str]) -> list[str]:
        """Find services that depend on affected services (cascade failure)."""
        cascade = set()
        queue = list(affected_services)
        visited = set(affected_services)

        while queue:
            current = queue.pop(0)
            for svc_id, deps in self._dependency_graph.items():
                if current in deps and svc_id not in visited:
                    cascade.add(svc_id)
                    visited.add(svc_id)
                    queue.append(svc_id)

        return list(cascade)

    def _calculate_impact(self, affected: list[str], cascade: list[str]) -> dict[str, Any]:
        all_affected = set(affected + cascade)
        total_rpm = 0.0
        max_criticality = 0.0
        sla_violations = 0

        for svc_id in all_affected:
            svc = self._service_registry.get(svc_id, {})
            total_rpm += svc.get("revenue_per_minute", 0)
            crit = svc.get("criticality", 0.5)
            max_criticality = max(max_criticality, crit)
            if crit >= 0.9:
                sla_violations += 1

        disruption = min(max_criticality * len(all_affected) / 10, 1.0)
        sla_prob = min(sla_violations / max(len(all_affected), 1), 1.0)
        priority = "P1" if max_criticality >= 0.9 else ("P2" if max_criticality >= 0.7 else "P3")

        return {
            "revenue": round(total_rpm, 2),
            "disruption": round(disruption, 3),
            "sla_violation": round(sla_prob, 3),
            "users": len(all_affected) * 10,  # Estimate
            "priority": priority,
        }

    def propose_strategy(self, alert: Alert) -> StrategyProposal | None:
        return None  # Business agent doesn't propose strategies directly
