"""Shared types and default behaviour for the five specialist agents.

Every agent implements three verbs, one per negotiation phase in which it acts:

``propose(ctx)``
    Independent recommendation. The agent sees only the shared
    :class:`NegotiationContext` — never ground truth.

``critique(ctx, proposals)``
    Reviews *every other agent's* proposal and records per-host **objections**
    (hosts it thinks should not be isolated), **endorsements** (hosts it agrees
    with) and **additions** (hosts it thinks everyone missed). This is what makes
    the critique phase load-bearing: in the original prototype no agent
    overrode it, so the phase was a no-op and proposals were merged by set union.

``counter(ctx, own, critiques)``
    Revises its own proposal in light of the objections raised against it. The
    default implementation drops a host when enough peers object *and* the agent
    itself has no hard evidence for it; specialists override this when their
    domain gives them a reason to hold their ground.

Conflict resolution proper happens in the consensus phase (see
:mod:`amcds.negotiation.protocol`), which weighs support against opposition
rather than taking a union.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

from ..evidence import ThreatAssessment
from ..network.topology import NetworkTopology


@dataclass
class NegotiationContext:
    """Everything the agents share during one negotiation.

    Deliberately contains no ground truth: ``assessment`` is the output of the
    detection pipeline, so an agent can only ever reason about *evidence*.
    """

    topology: NetworkTopology
    assessment: ThreatAssessment
    #: Hosts with hard evidence of infection — the anchor for every decision.
    confirmed: Set[str] = field(default_factory=set)
    #: Hosts that look bad but are not proven.
    suspected: Set[str] = field(default_factory=set)
    #: Blast-radius report computed from ``confirmed`` (see NetworkTopology).
    blast: dict = field(default_factory=dict)

    @classmethod
    def build(cls, topology: NetworkTopology,
              assessment: ThreatAssessment) -> "NegotiationContext":
        confirmed = assessment.confirmed_infected()
        return cls(
            topology=topology,
            assessment=assessment,
            confirmed=confirmed,
            suspected=assessment.suspected(),
            blast=topology.blast_radius(sorted(confirmed)) if confirmed else {},
        )

    # ------------------------------------------------------------- shortcuts
    @property
    def attack_type(self) -> str:
        return self.assessment.attack_type

    def risk(self, host_id: str) -> float:
        return self.assessment.risk_of(host_id)

    def has_hard_evidence(self, host_id: str) -> bool:
        a = self.assessment.hosts.get(host_id)
        return bool(a and a.has_hard_evidence())

    def confidence(self, host_id: str) -> float:
        a = self.assessment.hosts.get(host_id)
        return 0.0 if a is None else a.infection_confidence()


@dataclass
class AgentProposal:
    """One agent's recommended isolation set, with a reason per host."""

    agent_name: str
    isolate: Set[str] = field(default_factory=set)
    #: host_id -> why this agent wants it isolated. Drives the decision trace.
    justification: Dict[str, str] = field(default_factory=dict)
    reasoning: str = ""
    confidence: float = 0.5

    def why(self, host_id: str) -> str:
        return self.justification.get(host_id, "")

    def to_dict(self) -> dict:
        return {
            "agent_name": self.agent_name,
            "isolate": sorted(self.isolate),
            "justification": {h: self.justification.get(h, "")
                              for h in sorted(self.isolate)},
            "reasoning": self.reasoning,
            "confidence": round(self.confidence, 4),
        }


@dataclass
class Critique:
    """One agent's review of one other agent's proposal."""

    agent_name: str          # the critic
    target_agent: str        # whose proposal is being reviewed
    #: host_id -> why the critic objects to isolating it.
    objections: Dict[str, str] = field(default_factory=dict)
    #: host_id -> why the critic agrees it should be isolated.
    endorsements: Dict[str, str] = field(default_factory=dict)
    #: host_id -> why the critic thinks this host is missing from the proposal.
    additions: Dict[str, str] = field(default_factory=dict)
    summary: str = ""

    @property
    def satisfied(self) -> bool:
        return not self.objections and not self.additions

    def to_dict(self) -> dict:
        return {
            "agent_name": self.agent_name,
            "target_agent": self.target_agent,
            "satisfied": self.satisfied,
            "objections": {h: self.objections[h] for h in sorted(self.objections)},
            "endorsements": {h: self.endorsements[h] for h in sorted(self.endorsements)},
            "additions": {h: self.additions[h] for h in sorted(self.additions)},
            "summary": self.summary,
        }


@dataclass
class VetoDecision:
    """Formal veto issued by the agent holding veto authority."""

    agent_name: str
    #: host_id -> the rule that blocked it.
    vetoed: Dict[str, str] = field(default_factory=dict)
    #: host_id -> why a veto that would otherwise apply was overridden.
    overridden: Dict[str, str] = field(default_factory=dict)
    summary: str = ""
    #: Prepended to ``summary`` when a rule could not be applied at all.
    summary_prefix: str = ""

    def to_dict(self) -> dict:
        return {
            "agent_name": self.agent_name,
            "vetoed": {h: self.vetoed[h] for h in sorted(self.vetoed)},
            "overridden": {h: self.overridden[h] for h in sorted(self.overridden)},
            "n_vetoed": len(self.vetoed),
            "summary": self.summary,
        }


class BaseAgent:
    """Abstract specialist agent."""

    name = "base"
    #: Relative authority in the weighted consensus vote.
    weight: float = 1.0
    #: Only the Business Impact agent sets this.
    has_veto: bool = False

    # ------------------------------------------------------- phase 1: propose
    def propose(self, ctx: NegotiationContext) -> AgentProposal:
        raise NotImplementedError

    # ------------------------------------------------------ phase 2: critique
    def critique(self, ctx: NegotiationContext,
                 proposals: Dict[str, AgentProposal]) -> List[Critique]:
        """Review every peer proposal. Default: no objections."""
        return [Critique(agent_name=self.name, target_agent=other,
                         summary="no domain-specific objection")
                for other in sorted(proposals) if other != self.name]

    # ------------------------------------------------------- phase 3: counter
    def counter(self, ctx: NegotiationContext, own: AgentProposal,
                critiques: Sequence[Critique],
                min_objections: int = 2) -> AgentProposal:
        """Revise ``own`` given the critiques aimed at it.

        Default policy: concede a host when at least ``min_objections`` peers
        object to it and this agent has no hard evidence for that host. Hosts
        backed by hard evidence are never conceded — that is the whole point of
        having evidence.
        """
        objection_count: Dict[str, int] = {}
        objection_text: Dict[str, List[str]] = {}
        additions: Dict[str, str] = {}
        for c in critiques:
            for host, why in sorted(c.objections.items()):
                objection_count[host] = objection_count.get(host, 0) + 1
                objection_text.setdefault(host, []).append(f"{c.agent_name}: {why}")
            for host, why in sorted(c.additions.items()):
                additions.setdefault(host, f"{c.agent_name}: {why}")

        revised = set(own.isolate)
        conceded: List[str] = []
        for host in sorted(objection_count):
            if host not in revised:
                continue
            if ctx.has_hard_evidence(host):
                continue
            if objection_count[host] >= min_objections:
                revised.discard(host)
                conceded.append(host)

        justification = dict(own.justification)
        accepted: List[str] = []
        for host, why in sorted(additions.items()):
            if host in revised:
                continue
            if self._accepts_addition(ctx, host):
                revised.add(host)
                justification[host] = f"accepted peer addition — {why}"
                accepted.append(host)

        note = []
        if conceded:
            note.append(f"conceded {len(conceded)} host(s) after peer objections "
                        f"({', '.join(conceded[:4])}"
                        f"{'…' if len(conceded) > 4 else ''})")
        if accepted:
            note.append(f"accepted {len(accepted)} peer addition(s)")
        if not note:
            note.append("held position — no objection met the concession bar")

        return AgentProposal(
            agent_name=self.name,
            isolate=revised,
            justification={h: justification.get(h, own.why(h)) for h in revised},
            reasoning=f"{own.reasoning} COUNTER: " + "; ".join(note) + ".",
            confidence=own.confidence,
        )

    def _accepts_addition(self, ctx: NegotiationContext, host: str) -> bool:
        """Whether this agent will adopt a host a peer says it missed."""
        return ctx.has_hard_evidence(host)

    # ------------------------------------------------------------- utilities
    @staticmethod
    def _fmt(hosts: Sequence[str], limit: int = 4) -> str:
        hosts = sorted(hosts)
        if not hosts:
            return "none"
        head = ", ".join(hosts[:limit])
        return head + ("…" if len(hosts) > limit else "")
