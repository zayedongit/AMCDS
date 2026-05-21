"""Identity Agent — focuses on credential misuse / privilege escalation paths.

Heuristics:
- Domain controllers (AD) seeing infected workstation auth attempts → high risk.
- Privilege escalation is fastest via DC compromise → recommend isolating
  any host that has a direct auth path to a confirmed infected host AND
  hosts contains_pii=True (likely target).
"""
from __future__ import annotations

from typing import Set

from .base_agent import BaseAgent, AgentProposal
from ..network.topology import NetworkTopology


class IdentityAgent(BaseAgent):
    name = "Identity"

    def propose(self, topology: NetworkTopology, scenario: dict) -> AgentProposal:
        infected: Set[str] = set(scenario.get("infected_hosts", []))
        attack_type = scenario.get("attack_type", "unknown")

        isolate: Set[str] = set()
        # Always recommend isolating infected hosts themselves.
        isolate.update(infected)

        # 1) Any host that is 1-hop from infected AND is a DC or PII store —
        #    these are next-target candidates for credential theft.
        at_risk = set()
        for h in infected:
            for nbr in topology.neighbors(h):
                host = topology.hosts[nbr]
                if host.host_type == "domain_controller" or host.contains_pii:
                    at_risk.add(nbr)

        # 2) Insider threats: also consider hosts the user has unusual auth to.
        if attack_type == "insider_threat":
            for h in infected:
                # the insider's machine reaches more PII-bearing hosts than usual
                for nbr in topology.neighbors(h):
                    if topology.hosts[nbr].contains_pii:
                        at_risk.add(nbr)

        # We don't ISOLATE DCs directly (that would break identity for the
        # whole org) — but we flag them as needing forced password rotation.
        # For isolate-set we restrict to non-DC at-risk hosts. DCs are added
        # to a 'monitor' note instead.
        dc_concerns = {h for h in at_risk if topology.hosts[h].host_type == "domain_controller"}
        isolate.update(at_risk - dc_concerns)

        reasoning = (
            f"Found {len(infected)} confirmed infected host(s). "
            f"{len(at_risk - dc_concerns)} adjacent PII-bearing or identity-critical hosts "
            f"are at risk of credential theft. "
            + (f"⚠ Domain controllers {sorted(dc_concerns)} adjacent — flagging for forced "
               "password rotation rather than isolation." if dc_concerns else "")
        )

        return AgentProposal(
            agent_name=self.name,
            isolate=isolate,
            reasoning=reasoning,
            confidence=0.8 if infected else 0.3,
        )
