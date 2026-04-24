"""
Coordinator Agent - Master coordinator for incident response.
Consumes classified alerts and strategies, correlates incidents,
selects optimal containment strategies, and updates simulation state.
"""
from __future__ import annotations
import json
import logging
import time
from typing import Any
from agents.base_agent import BaseAgent, Alert, StrategyProposal
from agents.coordinator_agent.correlator import IncidentCorrelator
from agents.coordinator_agent.strategy_engine import StrategyEngine

logger = logging.getLogger(__name__)


class CoordinatorAgent(BaseAgent):
    """Master coordinator that ties incident correlation and strategy selection together."""

    def __init__(self, **kwargs):
        super().__init__(agent_name="coordinator_agent", **kwargs)
        self._correlator = IncidentCorrelator()
        self._strategy_engine = StrategyEngine()
        self._decisions: list[dict[str, Any]] = []

    def get_subscribed_topics(self) -> list[str]:
        return ["alerts.classified", "strategies.proposed"]

    def analyze(self, event: dict[str, Any]) -> list[Alert]:
        """Process classified alerts and strategy proposals."""
        # Determine event type based on content
        if "attack_class" in event:
            self._handle_classified_alert(event)
        elif "strategy_id" in event:
            self._handle_strategy_proposal(event)
        return []

    def _handle_classified_alert(self, alert: dict[str, Any]) -> None:
        """Correlate alert into an incident and publish."""
        incident = self._correlator.correlate(alert)

        if self._producer:
            self._producer.produce("incidents.correlated", incident.to_dict(), key=incident.incident_id)

        logger.info(
            "[Coordinator] Incident %s: class=%s, confidence=%.2f, alerts=%d, phase=%d",
            incident.incident_id, incident.attack_class,
            incident.confidence, len(incident.alerts), incident.kill_chain_phase,
        )

        # Auto-select strategy if enough proposals exist
        proposals = self._strategy_engine.get_proposals(incident.incident_id)
        if len(proposals) >= 2:
            self._select_and_execute(incident.incident_id, incident.to_dict())

    def _handle_strategy_proposal(self, proposal_data: dict[str, Any]) -> None:
        """Add strategy proposal from an agent."""
        proposal = StrategyProposal(
            strategy_id=proposal_data.get("strategy_id", ""),
            incident_id=proposal_data.get("incident_id", ""),
            agent_name=proposal_data.get("agent_name", ""),
            actions=proposal_data.get("actions", []),
            confidence=proposal_data.get("confidence", 0.5),
            residual_risk=proposal_data.get("residual_risk", 0.5),
            impact_estimate=proposal_data.get("impact_estimate", {}),
            constraints=proposal_data.get("constraints", []),
        )
        self._strategy_engine.add_proposal(proposal)

    def _select_and_execute(self, incident_id: str, incident_data: dict[str, Any]) -> None:
        """Select optimal strategy and simulate execution."""
        selected = self._strategy_engine.select_strategy(incident_id)
        if not selected:
            return

        decision = {
            "incident_id": incident_id,
            "selected_strategy": selected.to_dict(),
            "timestamp": time.time(),
            "rationale": f"Pareto-optimal selection: confidence={selected.confidence:.2f}, risk={selected.residual_risk:.2f}",
            "actions_taken": selected.actions,
        }
        self._decisions.append(decision)

        # Publish selected strategy
        if self._producer:
            self._producer.produce("strategies.selected", decision, key=incident_id)

        # Publish state update
        state_update = {
            "type": "containment_executed",
            "incident_id": incident_id,
            "actions": selected.actions,
            "timestamp": time.time(),
        }
        if self._producer:
            self._producer.produce("system.state", state_update, key="state")

        logger.info(
            "[Coordinator] Strategy selected for %s: %s (confidence=%.2f)",
            incident_id, selected.actions, selected.confidence,
        )

    def get_decisions(self) -> list[dict[str, Any]]:
        return list(self._decisions)

    def get_active_incidents(self):
        return self._correlator.get_active_incidents()

    def propose_strategy(self, alert: Alert) -> StrategyProposal | None:
        return None
