"""Five-phase multi-agent negotiation protocol.

Phases (as described in the AMCDS abstract):
  1. PROPOSAL     — each specialist independently proposes an isolation set.
  2. CRITIQUE     — every other agent critiques the union proposal.
  3. COUNTER      — each agent updates its proposal in light of critiques.
  4. BUSINESS_VETO — the Business Impact Agent removes SLA-breaching hosts
                    that aren't backed by hard evidence.
  5. CONSENSUS    — the final joint set is fed to the optimizer (classical/quantum).

The whole protocol completes in well under 60 seconds locally.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Set

from ..agents.base_agent import BaseAgent, AgentProposal
from ..network.topology import NetworkTopology


@dataclass
class NegotiationLog:
    """Replayable record of one negotiation run."""
    phases: List[dict] = field(default_factory=list)
    final_isolate: Set[str] = field(default_factory=set)
    elapsed_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "phases": self.phases,
            "final_isolate": sorted(list(self.final_isolate)),
            "elapsed_seconds": self.elapsed_seconds,
        }


class NegotiationProtocol:
    def __init__(self, specialists: List[BaseAgent], business_agent: BaseAgent) -> None:
        self.specialists = specialists      # Identity, Network, Data, Endpoint
        self.business_agent = business_agent

    def run(self, topology: NetworkTopology, scenario: dict) -> NegotiationLog:
        log = NegotiationLog()
        t0 = time.time()

        # ---------------- Phase 1: PROPOSAL ----------------------
        proposals: Dict[str, AgentProposal] = {}
        for a in self.specialists:
            p = a.propose(topology, scenario)
            proposals[a.name] = p
        biz_proposal = self.business_agent.propose(topology, scenario)
        proposals[self.business_agent.name] = biz_proposal

        log.phases.append({
            "phase": "PROPOSAL",
            "proposals": {n: p.to_dict() for n, p in proposals.items()},
        })

        # Union as initial candidate.
        joint: Set[str] = set()
        for p in proposals.values():
            joint.update(p.isolate)

        # ---------------- Phase 2: CRITIQUE ----------------------
        critiques: Dict[str, dict] = {}
        for a in self.specialists:
            c = a.critique(topology, scenario, joint)
            critiques[a.name] = {
                "satisfied": c["satisfied"],
                "concerns": c["concerns"],
                "add": sorted(list(c["add"])),
                "remove": sorted(list(c["remove"])),
            }
        log.phases.append({
            "phase": "CRITIQUE",
            "joint_candidate": sorted(list(joint)),
            "critiques": critiques,
        })

        # ---------------- Phase 3: COUNTER -----------------------
        # Each agent gets to add/remove based on the critique round.
        for c in critiques.values():
            joint.update(c["add"])
            joint -= set(c["remove"])

        log.phases.append({
            "phase": "COUNTER",
            "joint_after_counter": sorted(list(joint)),
        })

        # ---------------- Phase 4: BUSINESS_VETO -----------------
        veto = self.business_agent.critique(topology, scenario, joint)
        joint.update(veto.get("add", set()))
        joint -= set(veto.get("remove", set()))

        log.phases.append({
            "phase": "BUSINESS_VETO",
            "satisfied": veto["satisfied"],
            "concerns": veto["concerns"],
            "vetoed_hosts": sorted(list(veto.get("remove", set()))),
            "joint_after_veto": sorted(list(joint)),
        })

        # ---------------- Phase 5: CONSENSUS ---------------------
        log.final_isolate = joint
        log.phases.append({
            "phase": "CONSENSUS",
            "final_isolate": sorted(list(joint)),
            "n_hosts": len(joint),
            "revenue_impact_per_hour": topology.revenue_impact_of_isolating(joint),
            "sla_breaches": topology.sla_breaches(joint),
        })

        log.elapsed_seconds = time.time() - t0
        return log
