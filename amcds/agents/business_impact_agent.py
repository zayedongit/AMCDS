"""Business Impact Agent — the SLA enforcer.

This agent does NOT propose isolations aggressively. Instead, it has formal
veto authority: it computes the cost of every other agent's proposal and
vetoes hosts whose isolation would breach a gold-tier SLA without a critical
security justification.

Per the AMCDS abstract, this is the key innovation.
"""
from __future__ import annotations

from typing import Set

from .base_agent import BaseAgent, AgentProposal
from ..network.topology import NetworkTopology


class BusinessImpactAgent(BaseAgent):
    name = "BusinessImpact"

    def __init__(self, max_hourly_loss: float = 8_000_000) -> None:
        # Default: refuse to allow isolation that costs > ₹80 lakh/hour
        # unless infection is confirmed on that host.
        self.max_hourly_loss = max_hourly_loss

    def propose(self, topology: NetworkTopology, scenario: dict) -> AgentProposal:
        infected: Set[str] = set(scenario.get("infected_hosts", []))

        # The Business Impact Agent never proposes isolation on its own —
        # it just monitors and is ready to veto.
        return AgentProposal(
            agent_name=self.name,
            isolate=set(),
            reasoning=(
                "Business Impact Agent does not propose isolation; will "
                "veto SLA-breaching proposals during the negotiation phase. "
                f"Current max acceptable hourly loss: ₹{self.max_hourly_loss/1e5:.1f}L."
            ),
            confidence=1.0,
        )

    def critique(self, topology: NetworkTopology, scenario: dict,
                 joint_isolate: Set[str]) -> dict:
        infected: Set[str] = set(scenario.get("infected_hosts", []))

        # Find gold SLA breaches caused by this proposal.
        breaches = topology.sla_breaches(joint_isolate)
        # Compute total ₹/hour loss.
        loss = topology.revenue_impact_of_isolating(joint_isolate)

        vetoed: Set[str] = set()
        concerns_list = []

        if breaches:
            # Veto hosts that are gold-tier AND not confirmed infected.
            for sid in breaches:
                for h in topology.hosts_for_service(sid):
                    if h in joint_isolate and h not in infected:
                        # Only veto if we don't have hard evidence — gold SLAs
                        # are sacred unless the host itself is confirmed infected.
                        vetoed.add(h)
            if vetoed:
                concerns_list.append(
                    f"Gold-tier SLA breaches detected on services {sorted(breaches)}. "
                    f"Vetoing {len(vetoed)} non-infected gold-tier host(s) from isolation set."
                )

        if loss > self.max_hourly_loss:
            concerns_list.append(
                f"Total hourly cost ₹{loss/1e5:.1f}L exceeds budget "
                f"₹{self.max_hourly_loss/1e5:.1f}L."
            )

        satisfied = (not vetoed) and (loss <= self.max_hourly_loss)
        return {
            "satisfied": satisfied,
            "concerns": " ".join(concerns_list) if concerns_list else "Within business constraints.",
            "add": set(),
            "remove": vetoed,
        }
