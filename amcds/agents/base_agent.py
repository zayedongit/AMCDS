"""Base class shared by all specialist agents."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set

from ..network.topology import NetworkTopology


@dataclass
class AgentProposal:
    """A containment proposal from one agent.

    `isolate` is the set of host_ids that this agent wants to isolate.
    `reasoning` is a human-readable explanation (for explainability).
    `confidence` is in [0, 1].
    `vetoed_hosts` are hosts this agent explicitly refuses to isolate
    (the Business Impact Agent uses this).
    """
    agent_name: str
    isolate: Set[str] = field(default_factory=set)
    reasoning: str = ""
    confidence: float = 0.5
    vetoed_hosts: Set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "agent_name": self.agent_name,
            "isolate": sorted(list(self.isolate)),
            "reasoning": self.reasoning,
            "confidence": self.confidence,
            "vetoed_hosts": sorted(list(self.vetoed_hosts)),
        }


class BaseAgent:
    """Abstract specialist agent. Subclasses override propose()."""
    name = "base"

    def propose(self, topology: NetworkTopology, scenario: dict) -> AgentProposal:
        """Return an AgentProposal given the topology and current attack scenario.

        `scenario` is a dict like:
            {"infected_hosts": [...], "attack_type": "ransomware",
             "elapsed_minutes": 12, "ioc_evidence": {...}}
        """
        raise NotImplementedError

    def critique(self, topology: NetworkTopology, scenario: dict,
                 joint_isolate: Set[str]) -> dict:
        """Optional: look at a candidate joint isolation set and flag concerns.
        Returns {"satisfied": bool, "concerns": str, "add": set, "remove": set}.
        Default is satisfied with no edits.
        """
        return {"satisfied": True, "concerns": "", "add": set(), "remove": set()}
