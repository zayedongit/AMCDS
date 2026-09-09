"""The five-phase negotiation protocol.

    PROPOSE -> CRITIQUE -> COUNTER -> VETO -> CONSENSUS

Each phase does real work and each one can change the outcome:

**PROPOSE** — all five agents independently produce an isolation set with a
per-host justification. They disagree by construction: the Network agent reasons
from attack paths, the Data agent from where PII lives, the Endpoint agent from
per-machine behaviour, the Identity agent from credential exposure, and the
Business Impact agent from service continuity.

**CRITIQUE** — every agent reviews *every other agent's* proposal and records
per-host objections, endorsements and additions. This is an O(n²) exchange, not a
single review of a merged set, so an objection is always attributable to a
specific pair of agents.

**COUNTER** — each agent revises its own proposal against the objections raised
at it. Hosts backed by hard evidence are never conceded; hosts that two or more
peers object to and that the agent cannot evidence are dropped.

**VETO** — the Business Impact agent applies its formal veto (gold-tier SLA
without hard evidence) and its budget ceiling to the pooled candidate set. A veto
is absolute: the host is struck before the optimizer ever sees it.

**CONSENSUS** — conflicts are resolved by *weighted support*, not by union::

    support(h)    = sum of confidence x weight over agents proposing h
    opposition(h) = sum of confidence x weight over agents objecting to h
    keep(h)       iff support(h) / (support(h) + opposition(h)) >= threshold

A host that one agent wants and three object to loses. A host that everyone
wants sails through. Hosts with hard evidence are pinned in regardless, because
leaving a proven compromise online is not a decision the vote gets to make.

The whole run is recorded in a :class:`NegotiationLog` that is replayable and is
what the decision trace and the dashboard are built from.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Set

from ..config import CONSENSUS_SUPPORT_THRESHOLD
from ..agents.base_agent import (AgentProposal, BaseAgent, Critique,
                                 NegotiationContext, VetoDecision)


@dataclass
class HostVote:
    """The consensus arithmetic for one contested host."""

    host_id: str
    supporters: List[str] = field(default_factory=list)
    objectors: List[str] = field(default_factory=list)
    support: float = 0.0
    opposition: float = 0.0
    pinned: bool = False          # hard evidence — not subject to the vote
    kept: bool = False

    @property
    def support_ratio(self) -> float:
        total = self.support + self.opposition
        return 1.0 if total <= 0 else self.support / total

    @property
    def contested(self) -> bool:
        return bool(self.supporters) and bool(self.objectors)

    def to_dict(self) -> dict:
        return {
            "host_id": self.host_id,
            "supporters": sorted(self.supporters),
            "objectors": sorted(self.objectors),
            "support": round(self.support, 4),
            "opposition": round(self.opposition, 4),
            "support_ratio": round(self.support_ratio, 4),
            "contested": self.contested,
            "pinned_by_hard_evidence": self.pinned,
            "kept": self.kept,
        }


@dataclass
class NegotiationLog:
    """Replayable record of one negotiation run."""

    scenario_id: str = ""
    phases: List[dict] = field(default_factory=list)
    proposals: Dict[str, AgentProposal] = field(default_factory=dict)
    counters: Dict[str, AgentProposal] = field(default_factory=dict)
    critiques: List[Critique] = field(default_factory=list)
    veto: VetoDecision | None = None
    votes: Dict[str, HostVote] = field(default_factory=dict)
    final_isolate: Set[str] = field(default_factory=set)
    agreement: float = 0.0
    elapsed_seconds: float = 0.0

    def phase(self, name: str) -> dict:
        for p in self.phases:
            if p["phase"] == name:
                return p
        return {}

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "phases": self.phases,
            "final_isolate": sorted(self.final_isolate),
            "n_final": len(self.final_isolate),
            "agreement": round(self.agreement, 4),
            "elapsed_seconds": round(self.elapsed_seconds, 6),
            "votes": {h: self.votes[h].to_dict() for h in sorted(self.votes)},
        }


class NegotiationProtocol:
    """Runs the five phases over a set of agents."""

    def __init__(self, agents: Sequence[BaseAgent],
                 support_threshold: float = CONSENSUS_SUPPORT_THRESHOLD) -> None:
        if not agents:
            raise ValueError("negotiation needs at least one agent")
        self.agents = list(agents)
        self.support_threshold = support_threshold
        veto_holders = [a for a in self.agents if a.has_veto]
        if len(veto_holders) > 1:
            raise ValueError("exactly one agent may hold the formal veto, "
                             f"got {[a.name for a in veto_holders]}")
        self.veto_agent = veto_holders[0] if veto_holders else None

    # ------------------------------------------------------------------- run
    def run(self, ctx: NegotiationContext) -> NegotiationLog:
        log = NegotiationLog(scenario_id=ctx.assessment.scenario_id)
        t0 = time.perf_counter()

        proposals = self._phase_propose(ctx, log)
        critiques = self._phase_critique(ctx, log, proposals)
        counters = self._phase_counter(ctx, log, proposals, critiques)
        pooled, veto = self._phase_veto(ctx, log, counters)
        self._phase_consensus(ctx, log, counters, critiques, pooled, veto)

        log.elapsed_seconds = time.perf_counter() - t0
        return log

    # ------------------------------------------------------- phase 1: PROPOSE
    def _phase_propose(self, ctx: NegotiationContext,
                       log: NegotiationLog) -> Dict[str, AgentProposal]:
        proposals: Dict[str, AgentProposal] = {}
        for agent in self.agents:
            proposals[agent.name] = agent.propose(ctx)
        log.proposals = proposals

        sets = [frozenset(p.isolate) for p in proposals.values()]
        union: Set[str] = set().union(*sets) if sets else set()
        intersection: Set[str] = set(sets[0]).intersection(*sets) if sets else set()
        log.phases.append({
            "phase": "PROPOSE",
            "proposals": {n: p.to_dict() for n, p in sorted(proposals.items())},
            "union": sorted(union),
            "unanimous": sorted(intersection),
            "n_union": len(union),
            "n_unanimous": len(intersection),
            "initial_disagreement": len(union) - len(intersection),
        })
        return proposals

    # ------------------------------------------------------ phase 2: CRITIQUE
    def _phase_critique(self, ctx: NegotiationContext, log: NegotiationLog,
                        proposals: Dict[str, AgentProposal]) -> List[Critique]:
        critiques: List[Critique] = []
        for agent in self.agents:
            critiques.extend(agent.critique(ctx, proposals))
        log.critiques = critiques

        n_obj = sum(len(c.objections) for c in critiques)
        n_add = sum(len(c.additions) for c in critiques)
        contested = sorted({h for c in critiques for h in c.objections})
        log.phases.append({
            "phase": "CRITIQUE",
            "critiques": [c.to_dict() for c in critiques],
            "n_critiques": len(critiques),
            "n_objections": n_obj,
            "n_additions": n_add,
            "contested_hosts": contested,
            "unsatisfied_pairs": sorted(
                f"{c.agent_name}->{c.target_agent}" for c in critiques
                if not c.satisfied),
        })
        return critiques

    # ------------------------------------------------------- phase 3: COUNTER
    def _phase_counter(self, ctx: NegotiationContext, log: NegotiationLog,
                       proposals: Dict[str, AgentProposal],
                       critiques: List[Critique]) -> Dict[str, AgentProposal]:
        counters: Dict[str, AgentProposal] = {}
        moves: Dict[str, dict] = {}
        for agent in self.agents:
            aimed_at_me = [c for c in critiques if c.target_agent == agent.name]
            revised = agent.counter(ctx, proposals[agent.name], aimed_at_me)
            counters[agent.name] = revised
            before, after = proposals[agent.name].isolate, revised.isolate
            moves[agent.name] = {
                "conceded": sorted(before - after),
                "adopted": sorted(after - before),
                "n_before": len(before),
                "n_after": len(after),
            }
        log.counters = counters

        sets = [frozenset(p.isolate) for p in counters.values()]
        union: Set[str] = set().union(*sets) if sets else set()
        intersection: Set[str] = set(sets[0]).intersection(*sets) if sets else set()
        log.phases.append({
            "phase": "COUNTER",
            "counter_proposals": {n: p.to_dict() for n, p in sorted(counters.items())},
            "moves": moves,
            "union": sorted(union),
            "unanimous": sorted(intersection),
            "residual_disagreement": len(union) - len(intersection),
            "total_conceded": sum(len(m["conceded"]) for m in moves.values()),
            "total_adopted": sum(len(m["adopted"]) for m in moves.values()),
        })
        return counters

    # ---------------------------------------------------------- phase 4: VETO
    def _phase_veto(self, ctx: NegotiationContext, log: NegotiationLog,
                    counters: Dict[str, AgentProposal]):
        pooled: Set[str] = set()
        for p in counters.values():
            pooled |= p.isolate

        if self.veto_agent is None:
            veto = VetoDecision(agent_name="none", summary="no veto authority configured")
            surviving = pooled
        else:
            surviving, veto = self.veto_agent.apply_veto(ctx, pooled)
        log.veto = veto

        log.phases.append({
            "phase": "VETO",
            "veto_holder": veto.agent_name,
            "pooled_candidates": sorted(pooled),
            "decision": veto.to_dict(),
            "surviving": sorted(surviving),
            "n_vetoed": len(veto.vetoed),
            "n_overridden": len(veto.overridden),
        })
        return surviving, veto

    # ----------------------------------------------------- phase 5: CONSENSUS
    def _phase_consensus(self, ctx: NegotiationContext, log: NegotiationLog,
                         counters: Dict[str, AgentProposal],
                         critiques: List[Critique], surviving: Set[str],
                         veto: VetoDecision) -> None:
        by_name = {a.name: a for a in self.agents}
        votes: Dict[str, HostVote] = {}

        for host in sorted(surviving):
            v = HostVote(host_id=host, pinned=ctx.has_hard_evidence(host))
            for name, proposal in sorted(counters.items()):
                if host in proposal.isolate:
                    v.supporters.append(name)
                    v.support += proposal.confidence * by_name[name].weight
            for c in critiques:
                if host in c.objections and c.agent_name not in v.objectors:
                    # An agent that ultimately proposed the host itself is not
                    # counted as an objector — the counter phase resolved it.
                    if host in counters[c.agent_name].isolate:
                        continue
                    v.objectors.append(c.agent_name)
                    v.opposition += (counters[c.agent_name].confidence
                                     * by_name[c.agent_name].weight)
            v.kept = v.pinned or v.support_ratio >= self.support_threshold
            votes[host] = v

        final = {h for h, v in votes.items() if v.kept}
        log.votes = votes
        log.final_isolate = final

        contested = [v for v in votes.values() if v.contested]
        resolved_out = sorted(v.host_id for v in contested if not v.kept)
        resolved_in = sorted(v.host_id for v in contested if v.kept)
        log.agreement = self._agreement(counters)

        log.phases.append({
            "phase": "CONSENSUS",
            "support_threshold": self.support_threshold,
            "votes": {h: votes[h].to_dict() for h in sorted(votes)},
            "final_isolate": sorted(final),
            "n_final": len(final),
            "n_contested": len(contested),
            "contested_resolved_in": resolved_in,
            "contested_resolved_out": resolved_out,
            "pinned_by_hard_evidence": sorted(v.host_id for v in votes.values()
                                              if v.pinned),
            "agreement": round(log.agreement, 4),
            "revenue_impact_per_hour": ctx.topology.revenue_impact_of_isolating(final),
            "sla_breaches": ctx.topology.sla_breaches(final),
            "vetoed_before_vote": sorted(veto.vetoed),
        })

    @staticmethod
    def _agreement(counters: Dict[str, AgentProposal]) -> float:
        """Mean pairwise Jaccard similarity of the post-counter proposals.

        1.0 means the agents converged on identical plans; 0.0 means they never
        agreed on a single host. Reported so it is visible whether the protocol
        is doing anything or the agents happened to agree from the start.
        """
        names = sorted(counters)
        if len(names) < 2:
            return 1.0
        scores: List[float] = []
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                sa, sb = counters[a].isolate, counters[b].isolate
                union = sa | sb
                scores.append(1.0 if not union else len(sa & sb) / len(union))
        return sum(scores) / len(scores)
