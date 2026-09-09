"""Business Impact Agent — service continuity, and the holder of the veto.

This is the agent the whole design is built around, so its authority is stated
as an explicit, testable rule rather than a heuristic.

The veto rule
-------------
For a host ``h`` in the candidate isolation set::

    VETO(h)  iff  breaches_gold_sla(h)  AND  NOT has_hard_evidence(h)

where

* ``breaches_gold_sla(h)`` — isolating ``h`` takes at least one **gold**-tier
  business service offline, and
* ``has_hard_evidence(h)`` — see :meth:`amcds.evidence.HostAssessment.has_hard_evidence`:
  one high-fidelity detector, or several independent medium signals whose
  noisy-OR reaches the corroboration threshold.

A veto is **formal**: a vetoed host is removed from the candidate set before the
optimizer runs, so CP-SAT never gets the chance to put it back. No amount of
support from the other four agents overrides it. Hard evidence is the *only*
override, and when it fires it is recorded in ``overridden`` so the trace shows
the rule was evaluated and consciously waived.

The budget rule
---------------
Separately, the agent enforces a ceiling on total hourly revenue impact. If the
candidate set would cost more than ``max_hourly_loss`` per hour, hosts without
hard evidence are dropped in descending order of the marginal revenue they cost,
until the plan is inside budget or only hard-evidence hosts remain. In the
original prototype this budget was computed and then ignored; here it is
enforced and reported.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Set, Tuple

from ..config import DEFAULT_MAX_HOURLY_LOSS
from .base_agent import (AgentProposal, BaseAgent, Critique, NegotiationContext,
                         VetoDecision)


class BusinessImpactAgent(BaseAgent):
    name = "BusinessImpact"
    has_veto = True

    def __init__(self, max_hourly_loss: float = DEFAULT_MAX_HOURLY_LOSS) -> None:
        self.max_hourly_loss = float(max_hourly_loss)

    # ------------------------------------------------------------------ rules
    def breaches_gold_sla(self, ctx: NegotiationContext, host: str) -> List[str]:
        """Gold-tier services this single host would take offline."""
        return [s for s in ctx.topology.services_on_host(host)
                if ctx.topology.service_sla.get(s) == "gold"]

    def veto_applies(self, ctx: NegotiationContext, host: str) -> bool:
        """The formal veto predicate, exposed so tests can assert on it."""
        return bool(self.breaches_gold_sla(ctx, host)) and not ctx.has_hard_evidence(host)

    # ---------------------------------------------------------------- propose
    def propose(self, ctx: NegotiationContext) -> AgentProposal:
        """Proposes only what business continuity itself demands.

        It contributes the hosts that are both confirmed compromised *and* carry
        gold-tier services: leaving a proven-infected payments database online is
        the larger business risk. Everything else it leaves to the specialists
        and reviews at the veto phase.
        """
        t = ctx.topology
        isolate: Set[str] = set()
        justification: Dict[str, str] = {}
        for h in sorted(ctx.confirmed):
            gold = self.breaches_gold_sla(ctx, h)
            if gold:
                isolate.add(h)
                justification[h] = (
                    f"hard evidence on a gold-tier host carrying {sorted(gold)}; "
                    f"a confirmed compromise of a gold service is worse than its "
                    f"downtime")

        exposure = t.revenue_impact_of_isolating(sorted(ctx.confirmed | ctx.suspected))
        gold_hosts = sorted(t.gold_tier_hosts())
        at_risk_gold = [h for h in gold_hosts
                        if h in ctx.confirmed or h in ctx.suspected]
        reasoning = (
            f"Budget ceiling INR {self.max_hourly_loss/1e5:.1f}L/hour. "
            f"{len(gold_hosts)} host(s) carry gold-tier services; {len(at_risk_gold)} of "
            f"them are implicated. Isolating everything currently implicated would "
            f"cost INR {exposure/1e5:.1f}L/hour. This agent proposes only the "
            f"{len(isolate)} gold-tier host(s) with hard evidence and holds formal "
            f"veto over the rest.")

        return AgentProposal(
            agent_name=self.name, isolate=isolate, justification=justification,
            reasoning=reasoning, confidence=1.0,
        )

    # --------------------------------------------------------------- critique
    def critique(self, ctx: NegotiationContext,
                 proposals: Dict[str, AgentProposal]) -> List[Critique]:
        """Warns before it vetoes, so agents can revise in the counter phase."""
        t = ctx.topology
        out: List[Critique] = []
        for other in sorted(proposals):
            if other == self.name:
                continue
            p = proposals[other]
            c = Critique(agent_name=self.name, target_agent=other)

            for h in sorted(p.isolate):
                gold = self.breaches_gold_sla(ctx, h)
                if not gold:
                    continue
                if ctx.has_hard_evidence(h):
                    c.endorsements[h] = (
                        f"gold-tier host carrying {sorted(gold)}, but hard evidence "
                        f"justifies the SLA breach")
                else:
                    c.objections[h] = (
                        f"would breach gold-tier SLA on {sorted(gold)} "
                        f"(INR {sum(t.service_revenue[s] for s in gold)/1e5:.1f}L/hour) "
                        f"without hard evidence — this will be vetoed")

            cost = t.revenue_impact_of_isolating(p.isolate)
            if cost > self.max_hourly_loss:
                c.summary = (
                    f"plan costs INR {cost/1e5:.1f}L/hour, over the "
                    f"INR {self.max_hourly_loss/1e5:.1f}L ceiling; "
                    f"{len(c.objections)} gold-tier host(s) flagged for veto")
            else:
                c.summary = ("within business constraints" if c.satisfied else
                             f"{len(c.objections)} gold-tier host(s) flagged for veto "
                             f"(plan cost INR {cost/1e5:.1f}L/hour)")
            out.append(c)
        return out

    # ------------------------------------------------------------------- veto
    def apply_veto(self, ctx: NegotiationContext,
                   candidates: Iterable[str]) -> Tuple[Set[str], VetoDecision]:
        """Run the formal veto and the budget rule over the candidate set."""
        t = ctx.topology
        surviving = set(candidates)
        decision = VetoDecision(agent_name=self.name)

        # ---- Rule 1: gold-tier SLA without hard evidence --------------------
        for h in sorted(surviving):
            gold = self.breaches_gold_sla(ctx, h)
            if not gold:
                continue
            if ctx.has_hard_evidence(h):
                decision.overridden[h] = (
                    f"gold-tier SLA on {sorted(gold)} would be breached, but "
                    f"{ctx.assessment.hosts[h].why()} — veto waived")
                continue
            decision.vetoed[h] = (
                f"isolating it breaks gold-tier service(s) {sorted(gold)} "
                f"(INR {sum(t.service_revenue[s] for s in gold)/1e5:.1f}L/hour) and the "
                f"evidence is only {ctx.confidence(h):.2f} confidence "
                f"(risk {ctx.risk(h):.2f}) — below the hard-evidence bar")
        surviving -= set(decision.vetoed)

        # ---- Rule 2: hourly revenue ceiling ---------------------------------
        # The hosts with hard evidence are non-negotiable, so their cost is a
        # floor. If that floor already exceeds the ceiling the rule cannot be
        # satisfied at all, and dropping cheap hosts would be theatre: we record
        # the breach instead of pretending to act on it.
        forced = {h for h in surviving if ctx.has_hard_evidence(h)}
        floor = t.revenue_impact_of_isolating(forced)
        cost = t.revenue_impact_of_isolating(surviving)
        if cost > self.max_hourly_loss and floor > self.max_hourly_loss:
            decision.summary_prefix = (
                f"budget ceiling INR {self.max_hourly_loss/1e5:.1f}L/hour is "
                f"unattainable: hard-evidence hosts alone cost INR "
                f"{floor/1e5:.1f}L/hour. Ceiling waived. ")
        elif cost > self.max_hourly_loss:
            # Drop the most expensive non-evidenced hosts until inside budget.
            droppable = sorted(
                (h for h in surviving if not ctx.has_hard_evidence(h)),
                key=lambda h: (-self._marginal_cost(ctx, surviving, h), h))
            for h in droppable:
                if cost <= self.max_hourly_loss:
                    break
                marginal = self._marginal_cost(ctx, surviving, h)
                if marginal <= 0:
                    continue
                surviving.discard(h)
                cost = t.revenue_impact_of_isolating(surviving)
                decision.vetoed[h] = (
                    f"budget rule: plan exceeded the INR "
                    f"{self.max_hourly_loss/1e5:.1f}L/hour ceiling; this host adds "
                    f"INR {marginal/1e5:.1f}L/hour and has no hard evidence")

        final_cost = t.revenue_impact_of_isolating(surviving)
        breaches = t.sla_breaches(surviving)
        decision.summary = (
            getattr(decision, "summary_prefix", "") +
            f"vetoed {len(decision.vetoed)} host(s), waived {len(decision.overridden)} "
            f"veto(es) on hard evidence. Approved plan costs INR "
            f"{final_cost/1e5:.1f}L/hour with {len(breaches)} gold-tier breach(es)"
            + (f" ({sorted(breaches)}, all evidence-backed)" if breaches else "") + ".")
        return surviving, decision

    @staticmethod
    def _marginal_cost(ctx: NegotiationContext, plan: Set[str], host: str) -> float:
        """Revenue that comes back online if ``host`` is dropped from ``plan``."""
        t = ctx.topology
        with_host = t.revenue_impact_of_isolating(plan)
        without = t.revenue_impact_of_isolating(plan - {host})
        return with_host - without
