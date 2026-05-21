"""Endpoint Agent — focuses on EDR-style host-level signals.

Heuristics:
- High suspicion_score (set by EDR / scenario) → isolate.
- Workstations with infected neighbors → quarantine workstation tier
  (workstations are cheap to isolate and frequently malware-bearing).
"""
from __future__ import annotations

from typing import Set

from .base_agent import BaseAgent, AgentProposal
from ..network.topology import NetworkTopology


class EndpointAgent(BaseAgent):
    name = "Endpoint"

    def __init__(self, suspicion_threshold: float = 0.6) -> None:
        self.suspicion_threshold = suspicion_threshold

    def propose(self, topology: NetworkTopology, scenario: dict) -> AgentProposal:
        infected: Set[str] = set(scenario.get("infected_hosts", []))
        host_suspicion = scenario.get("host_suspicion", {})  # {host_id: score}

        isolate: Set[str] = set(infected)

        # 1) Anyone with EDR-reported high suspicion score
        flagged_edr = set()
        for hid, score in host_suspicion.items():
            if score >= self.suspicion_threshold and hid in topology.hosts:
                flagged_edr.add(hid)
        isolate.update(flagged_edr)

        # 2) Quarantine the workstation tier — cheap and likely vector
        ws_with_infected_nbr = set()
        for hid, host in topology.hosts.items():
            if host.host_type != "workstation":
                continue
            if hid in infected:
                continue
            for nbr in topology.neighbors(hid):
                if nbr in infected:
                    ws_with_infected_nbr.add(hid)
                    break
        isolate.update(ws_with_infected_nbr)

        reasoning = (
            f"EDR flagged {len(flagged_edr)} host(s) above suspicion threshold "
            f"{self.suspicion_threshold:.2f}; "
            f"{len(ws_with_infected_nbr)} workstation(s) adjacent to infection — "
            f"recommend workstation-tier quarantine."
        )

        return AgentProposal(
            agent_name=self.name,
            isolate=isolate,
            reasoning=reasoning,
            confidence=0.7,
        )
