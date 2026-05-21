"""
Strategy Engine - Manages strategy proposals, Pareto filtering, and selection.
"""
from __future__ import annotations
import logging
from typing import Any
from agents.base_agent import StrategyProposal

logger = logging.getLogger(__name__)


class StrategyEngine:
    """Collects, filters, and selects optimal containment strategies."""

    def __init__(self):
        self._proposals: dict[str, list[StrategyProposal]] = {}  # incident_id -> proposals

    def add_proposal(self, proposal: StrategyProposal) -> None:
        self._proposals.setdefault(proposal.incident_id, []).append(proposal)

    def get_proposals(self, incident_id: str) -> list[StrategyProposal]:
        return self._proposals.get(incident_id, [])

    def pareto_filter(self, incident_id: str) -> list[StrategyProposal]:
        """Filter dominated strategies using Pareto optimality on confidence vs residual risk."""
        proposals = self.get_proposals(incident_id)
        if len(proposals) <= 1:
            return proposals

        non_dominated = []
        for p in proposals:
            dominated = False
            for other in proposals:
                if other is p:
                    continue
                # other dominates p if it has higher confidence AND lower residual risk
                if other.confidence >= p.confidence and other.residual_risk <= p.residual_risk:
                    if other.confidence > p.confidence or other.residual_risk < p.residual_risk:
                        dominated = True
                        break
            if not dominated:
                non_dominated.append(p)

        return non_dominated

    def select_strategy(self, incident_id: str, sla_constraints: dict[str, float] | None = None) -> StrategyProposal | None:
        """Select optimal strategy from Pareto-optimal set."""
        pareto_set = self.pareto_filter(incident_id)
        if not pareto_set:
            return None

        # Validate constraints
        if sla_constraints:
            pareto_set = [p for p in pareto_set if self._validate_constraints(p, sla_constraints)]

        if not pareto_set:
            # Relax constraints, pick highest confidence
            pareto_set = self.get_proposals(incident_id)

        # Score: maximize confidence, minimize residual risk, minimize impact
        def score(p: StrategyProposal) -> float:
            impact_size = sum(v if isinstance(v, (int, float)) else 0 for v in p.impact_estimate.values())
            return p.confidence * 0.5 - p.residual_risk * 0.3 - (impact_size / 100) * 0.2

        return max(pareto_set, key=score)

    def _validate_constraints(self, proposal: StrategyProposal, constraints: dict[str, float]) -> bool:
        for constraint in proposal.constraints:
            # Simple constraint parsing: "sla_service > 99.9"
            parts = constraint.replace(">", " > ").replace("<", " < ").split()
            if len(parts) >= 3:
                sla_name = parts[0]
                threshold = float(parts[-1])
                actual = constraints.get(sla_name, 100.0)
                if ">" in constraint and actual < threshold:
                    return False
        return True

    def clear_incident(self, incident_id: str) -> None:
        self._proposals.pop(incident_id, None)
