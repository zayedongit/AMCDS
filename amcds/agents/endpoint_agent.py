"""Endpoint Agent — host-level signals and the ML risk score.

Domain
------
What each individual machine is doing. This is the agent that consumes the ML
layer most directly: it reads the calibrated risk score produced by the
IsolationForest and the peer-group z-scores that explain it.

Position in the negotiation
---------------------------
It is the *evidence sceptic*. Its distinctive critique is aimed at proposals
built from topology alone: if a host has no detector alert and a risk score
below the suspicious threshold, then whatever the graph says, nothing on that
machine looks wrong and the Endpoint agent objects to isolating it. This is the
main mechanism by which the ML layer actually reduces unnecessary shutdowns —
it gives an agent a principled reason to say "no".

Running the pipeline with ``risk_score = None`` (the AMCDS_NO_ML ablation) blunts
exactly this objection, which is how the benchmark isolates the ML contribution.
"""
from __future__ import annotations

from typing import Dict, List, Set

from ..config import ML_STRONG_THRESHOLD, ML_SUSPICIOUS_THRESHOLD
from .base_agent import AgentProposal, BaseAgent, Critique, NegotiationContext


class EndpointAgent(BaseAgent):
    name = "Endpoint"

    def __init__(self, risk_threshold: float = ML_SUSPICIOUS_THRESHOLD,
                 strong_threshold: float = ML_STRONG_THRESHOLD) -> None:
        self.risk_threshold = risk_threshold
        self.strong_threshold = strong_threshold

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _n_alerts(ctx: NegotiationContext, host: str) -> int:
        a = ctx.assessment.hosts.get(host)
        if a is None:
            return 0
        return sum(1 for e in a.evidence if e.ev_type.value != "ml_anomaly")

    @staticmethod
    def _ml_available(ctx: NegotiationContext) -> bool:
        return any(a.risk_score is not None
                   for a in ctx.assessment.hosts.values())

    def _quiet(self, ctx: NegotiationContext, host: str) -> bool:
        """No detector alert and (if the ML layer is on) a low risk score."""
        if self._n_alerts(ctx, host) > 0:
            return False
        a = ctx.assessment.hosts.get(host)
        if a is None or a.risk_score is None:
            return True
        return a.risk_score < self.risk_threshold

    # ------------------------------------------------------------------ propose
    def propose(self, ctx: NegotiationContext) -> AgentProposal:
        isolate: Set[str] = set(ctx.confirmed)
        justification: Dict[str, str] = {}
        for h in sorted(ctx.confirmed):
            a = ctx.assessment.hosts[h]
            justification[h] = f"hard evidence on the endpoint — {a.why()}"

        n_ml_only = 0
        for h in ctx.topology.host_ids():
            if h in isolate:
                continue
            a = ctx.assessment.hosts.get(h)
            if a is None:
                continue
            risk = a.risk_score
            if risk is not None and risk >= self.strong_threshold:
                isolate.add(h)
                justification[h] = f"endpoint behaviour strongly anomalous — {a.why()}"
                n_ml_only += 1
            elif (risk is not None and risk >= self.risk_threshold
                  and self._n_alerts(ctx, h) >= 1):
                isolate.add(h)
                justification[h] = (
                    f"risk {risk:.2f} above the {self.risk_threshold:.2f} threshold "
                    f"and corroborated by {self._n_alerts(ctx, h)} detector alert(s)")
                n_ml_only += 1
            elif risk is None and a.infection_confidence() >= 0.5:
                isolate.add(h)
                justification[h] = (
                    f"detector alerts combine to {a.infection_confidence():.2f} "
                    f"confidence (no ML layer available)")

        ml_note = ("ML risk model active" if self._ml_available(ctx)
                   else "ML risk model DISABLED — signature alerts only")
        reasoning = (
            f"{ml_note}. {len(ctx.confirmed)} host(s) carry hard endpoint evidence; "
            f"{n_ml_only} further host(s) are behaviourally anomalous above the "
            f"{self.risk_threshold:.2f} risk threshold. Proposing "
            f"{len(isolate)} host(s).")

        return AgentProposal(
            agent_name=self.name, isolate=isolate, justification=justification,
            reasoning=reasoning,
            confidence=0.8 if ctx.confirmed else 0.4,
        )

    # ----------------------------------------------------------------- critique
    def critique(self, ctx: NegotiationContext,
                 proposals: Dict[str, AgentProposal]) -> List[Critique]:
        out: List[Critique] = []
        ml_on = self._ml_available(ctx)

        for other in sorted(proposals):
            if other == self.name:
                continue
            p = proposals[other]
            c = Critique(agent_name=self.name, target_agent=other)

            for h in sorted(p.isolate):
                a = ctx.assessment.hosts.get(h)
                if ctx.has_hard_evidence(h):
                    c.endorsements[h] = "hard endpoint evidence"
                    continue
                if self._quiet(ctx, h):
                    risk_txt = ("no ML score available" if a is None or a.risk_score is None
                                else f"risk {a.risk_score:.2f} < {self.risk_threshold:.2f}")
                    c.objections[h] = (
                        f"nothing on this endpoint looks wrong: zero detector alerts, "
                        f"{risk_txt}; isolating it is unnecessary downtime")
                elif a is not None and a.risk_score is not None:
                    c.endorsements[h] = (
                        f"behaviourally anomalous (risk {a.risk_score:.2f})")

            # Additions: hosts the model screams about that nobody proposed.
            if ml_on:
                for h in ctx.topology.host_ids():
                    if h in p.isolate:
                        continue
                    a = ctx.assessment.hosts.get(h)
                    if a is not None and a.risk_score is not None and \
                            a.risk_score >= self.strong_threshold:
                        c.additions[h] = (
                            f"risk {a.risk_score:.2f} is in the top "
                            f"{100*(1-self.strong_threshold):.0f}% most anomalous — "
                            f"{a.why()}")

            c.summary = ("no endpoint objection" if c.satisfied else
                         f"{len(c.objections)} host(s) with no endpoint indicator, "
                         f"{len(c.additions)} highly anomalous host(s) missed")
            out.append(c)
        return out

    def _accepts_addition(self, ctx: NegotiationContext, host: str) -> bool:
        if ctx.has_hard_evidence(host):
            return True
        return ctx.risk(host) >= self.risk_threshold
