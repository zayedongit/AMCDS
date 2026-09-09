"""Network Agent — lateral-movement containment.

Domain
------
Cutting the attacker's routes. It works from the trust-weighted attack surface
(``plausible_attack_surface``) rather than a hop count, and it explicitly
measures what an isolation *buys*: for every candidate host it asks NetworkX how
much of the reachable surface disappears if that host is cut.

That measurement is also its critique weapon. A host that is on nobody's attack
path and whose removal shrinks the surface by zero is, from this agent's point
of view, pure business cost for no containment value — so it objects. That is the
main counterweight to the Data and Endpoint agents, which tend to over-propose.
"""
from __future__ import annotations

from typing import Dict, List, Set

from ..config import MIN_PATH_TRUST
from .base_agent import AgentProposal, BaseAgent, Critique, NegotiationContext

#: Hosts reachable with at least this path trust are treated as genuinely
#: exposed and are candidates for pre-emptive isolation.
EXPOSURE_TRUST = 0.25


class NetworkAgent(BaseAgent):
    name = "Network"

    def __init__(self, exposure_trust: float = EXPOSURE_TRUST,
                 max_hops: int = 2) -> None:
        self.exposure_trust = exposure_trust
        self.max_hops = max_hops

    # ------------------------------------------------------------------ propose
    def propose(self, ctx: NegotiationContext) -> AgentProposal:
        t = ctx.topology
        isolate: Set[str] = set(ctx.confirmed)
        justification: Dict[str, str] = {
            h: "confirmed compromised — an active foothold on the network"
            for h in sorted(ctx.confirmed)
        }

        if not ctx.confirmed:
            return AgentProposal(
                agent_name=self.name, isolate=isolate, justification=justification,
                reasoning="no host has hard evidence; no containment cut proposed.",
                confidence=0.3)

        probs = t.attack_path_probabilities(sorted(ctx.confirmed))
        within = t.within_hops(sorted(ctx.confirmed), self.max_hops)
        centrality = t.centrality()

        # A host is worth cutting when the attacker can plausibly reach it AND
        # cutting it actually shrinks the reachable surface.
        exposed = sorted(h for h in within
                         if h not in ctx.confirmed
                         and probs.get(h, 0.0) >= self.exposure_trust)
        for h in exposed:
            value = t.containment_value([h], sorted(ctx.confirmed))
            protects = len(value["hosts_protected"])
            central = centrality.get(h, 0.0)
            if protects > 0 or central >= 0.05 or h in ctx.suspected:
                isolate.add(h)
                justification[h] = (
                    f"reachable at path trust {probs.get(h, 0.0):.2f}; cutting it "
                    f"protects {protects} downstream host(s), betweenness "
                    f"{central:.3f}")

        surface = t.plausible_attack_surface(sorted(ctx.confirmed), MIN_PATH_TRUST)
        value = t.containment_value(isolate, sorted(ctx.confirmed))
        reasoning = (
            f"Attacker on {len(ctx.confirmed)} confirmed host(s) can plausibly reach "
            f"{len(surface)} host(s) (path trust >= {MIN_PATH_TRUST}). Proposed cut of "
            f"{len(isolate)} host(s) shrinks that surface by "
            f"{value['reduction_pct']:.0f}% "
            f"({value['surface_before']} -> {value['surface_after']}).")

        return AgentProposal(
            agent_name=self.name, isolate=isolate, justification=justification,
            reasoning=reasoning,
            confidence=0.85 if ctx.confirmed else 0.4,
        )

    # ----------------------------------------------------------------- critique
    def critique(self, ctx: NegotiationContext,
                 proposals: Dict[str, AgentProposal]) -> List[Critique]:
        t = ctx.topology
        confirmed = sorted(ctx.confirmed)
        probs = t.attack_path_probabilities(confirmed) if confirmed else {}
        out: List[Critique] = []

        for other in sorted(proposals):
            if other == self.name:
                continue
            p = proposals[other]
            c = Critique(agent_name=self.name, target_agent=other)

            for h in sorted(p.isolate):
                if h in ctx.confirmed:
                    c.endorsements[h] = "confirmed foothold — cutting it is mandatory"
                    continue
                reach = probs.get(h, 0.0)
                if reach < MIN_PATH_TRUST:
                    c.objections[h] = (
                        f"the attacker cannot plausibly reach this host "
                        f"(best path trust {reach:.3f} < {MIN_PATH_TRUST}); "
                        f"isolating it buys no containment")
                    continue
                value = t.containment_value([h], confirmed)
                if not value["hosts_protected"] and reach < self.exposure_trust:
                    c.objections[h] = (
                        f"cutting it protects no downstream host and it is only "
                        f"weakly reachable (trust {reach:.2f})")
                else:
                    c.endorsements[h] = (
                        f"reachable at trust {reach:.2f}; cut protects "
                        f"{len(value['hosts_protected'])} host(s)")

            # Additions: high-value cut points the proposal missed.
            if confirmed:
                for h in sorted(set(probs) - p.isolate - set(confirmed)):
                    if probs[h] < 0.5:
                        continue
                    value = t.containment_value([h], confirmed)
                    if len(value["hosts_protected"]) >= 3:
                        c.additions[h] = (
                            f"choke point: reachable at trust {probs[h]:.2f} and "
                            f"cutting it shields "
                            f"{len(value['hosts_protected'])} host(s)")

            c.summary = ("no containment objection" if c.satisfied else
                         f"{len(c.objections)} host(s) with no containment value, "
                         f"{len(c.additions)} missed choke point(s)")
            out.append(c)
        return out

    def _accepts_addition(self, ctx: NegotiationContext, host: str) -> bool:
        if ctx.has_hard_evidence(host):
            return True
        probs = ctx.topology.attack_path_probabilities(sorted(ctx.confirmed))
        return probs.get(host, 0.0) >= self.exposure_trust
