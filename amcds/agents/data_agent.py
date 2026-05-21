"""Data Agent — focuses on protecting PII / data exfiltration paths.

Heuristics:
- Any host with contains_pii=True that is reachable from an infected host
  is a candidate for isolation.
- If the attack type is `ransomware` or `data_exfiltration`, recommend
  isolating file servers and DB servers more aggressively.
"""
from __future__ import annotations

from typing import Set

from .base_agent import BaseAgent, AgentProposal
from ..network.topology import NetworkTopology


class DataAgent(BaseAgent):
    name = "Data"

    def propose(self, topology: NetworkTopology, scenario: dict) -> AgentProposal:
        infected: Set[str] = set(scenario.get("infected_hosts", []))
        attack_type = scenario.get("attack_type", "unknown")

        # All hosts reachable from infected ones (any number of hops),
        # treating no isolation yet.
        reachable = topology.reachable_from(infected, excluded=set())

        # PII / data hosts that are reachable from infection.
        pii_at_risk = {h for h in reachable
                       if topology.hosts[h].contains_pii and h not in infected}

        isolate: Set[str] = set(infected)
        if attack_type in ("ransomware", "data_exfiltration"):
            # Isolate file servers + non-gold db servers proactively.
            for hid, host in topology.hosts.items():
                if host.host_type == "file_server":
                    isolate.add(hid)
                if host.host_type == "db_server" and host.sla_tier != "gold":
                    isolate.add(hid)
        else:
            # Only isolate PII hosts that are within 2 hops of infection.
            two_hop = set(infected)
            frontier = set(infected)
            for _ in range(2):
                nxt = set()
                for h in frontier:
                    for nbr in topology.neighbors(h):
                        if nbr not in two_hop:
                            nxt.add(nbr)
                two_hop.update(nxt)
                frontier = nxt
            isolate.update(pii_at_risk & two_hop)

        reasoning = (
            f"{len(pii_at_risk)} PII-bearing host(s) reachable from infection. "
            f"Attack type='{attack_type}' → "
        )
        if attack_type in ("ransomware", "data_exfiltration"):
            reasoning += "isolating all file servers and non-critical DBs to stop exfil."
        else:
            reasoning += "isolating only PII hosts within 2 hops of infected."

        return AgentProposal(
            agent_name=self.name,
            isolate=isolate,
            reasoning=reasoning,
            confidence=0.75,
        )
