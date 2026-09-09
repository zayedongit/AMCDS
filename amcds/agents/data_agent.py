"""Data Agent — protection of PII and prevention of exfiltration.

Domain
------
Where the regulated data lives and whether the attacker can get to it. It scores
each PII-bearing host by the probability the attacker can reach it, and it reads
``DATA_EXFIL_VOLUME`` evidence directly.

Position in the negotiation
---------------------------
It is the agent most willing to isolate pre-emptively, because a copy of a
customer database leaving the building cannot be undone. Its distinctive
critique is the opposite of that instinct though: it objects when a proposal
would isolate *every* replica of a PII store, because that converts a
confidentiality incident into an availability incident. That constraint is also
enforced as a hard constraint in the CP-SAT model.
"""
from __future__ import annotations

from typing import Dict, List, Set

from .base_agent import AgentProposal, BaseAgent, Critique, NegotiationContext

#: Path trust above which a PII store is considered genuinely at risk.
PII_REACH_TRUST = 0.10


class DataAgent(BaseAgent):
    name = "Data"

    def __init__(self, pii_reach_trust: float = PII_REACH_TRUST) -> None:
        self.pii_reach_trust = pii_reach_trust

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _exfil_signal(ctx: NegotiationContext, host: str) -> bool:
        a = ctx.assessment.hosts.get(host)
        return bool(a and any(e.ev_type.value == "data_exfil_volume"
                              for e in a.evidence))

    def _pii_hosts(self, ctx: NegotiationContext) -> List[str]:
        t = ctx.topology
        return [h for h in t.host_ids() if t.hosts[h].contains_pii]

    # ------------------------------------------------------------------ propose
    def propose(self, ctx: NegotiationContext) -> AgentProposal:
        t = ctx.topology
        isolate: Set[str] = set(ctx.confirmed)
        justification: Dict[str, str] = {
            h: ("confirmed compromised" +
                (" with outbound-volume anomaly — active exfiltration risk"
                 if self._exfil_signal(ctx, h) else ""))
            for h in sorted(ctx.confirmed)
        }

        probs = (t.attack_path_probabilities(sorted(ctx.confirmed))
                 if ctx.confirmed else {})
        pii = self._pii_hosts(ctx)
        at_risk: List[str] = []

        for h in pii:
            if h in isolate:
                continue
            reach = probs.get(h, 0.0)
            if reach < self.pii_reach_trust:
                continue
            at_risk.append(h)
            # Isolate a PII host pre-emptively only if it is itself suspicious,
            # or the attack is one that goes straight for data.
            data_attack = ctx.attack_type in ("ransomware", "insider_threat")
            if h in ctx.suspected or self._exfil_signal(ctx, h) or (
                    data_attack and reach >= 0.4):
                isolate.add(h)
                justification[h] = (
                    f"PII store reachable at path trust {reach:.2f}"
                    + (" with exfiltration indicators" if self._exfil_signal(ctx, h)
                       else f"; attack type '{ctx.attack_type}' targets data directly"))

        # Availability guard: never propose isolating every replica of a service.
        isolate = self._preserve_a_replica(ctx, isolate, justification)

        reasoning = (
            f"{len(pii)} PII-bearing host(s) in scope; {len(at_risk)} reachable from "
            f"the confirmed foothold (trust >= {self.pii_reach_trust:.2f}). "
            f"Proposing isolation of {len(isolate)} host(s) to stop exfiltration "
            f"while keeping at least one replica of every data service online.")

        return AgentProposal(
            agent_name=self.name, isolate=isolate, justification=justification,
            reasoning=reasoning,
            confidence=0.8 if ctx.confirmed else 0.35,
        )

    def _preserve_a_replica(self, ctx: NegotiationContext, isolate: Set[str],
                            justification: Dict[str, str]) -> Set[str]:
        """Drop the least-suspicious host of any service we would fully isolate."""
        t = ctx.topology
        out = set(isolate)
        for sid in sorted(t.service_deps):
            deps = sorted(t.service_deps[sid])
            if len(deps) < 2:
                continue
            if not set(deps).issubset(out):
                continue
            spare = [h for h in deps if not ctx.has_hard_evidence(h)]
            if not spare:
                continue   # everything is confirmed; availability is already lost
            keep = min(spare, key=lambda h: (ctx.confidence(h), ctx.risk(h), h))
            out.discard(keep)
            justification.pop(keep, None)
        return out

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

            # Objection 1: a proposal that takes out every replica of a service
            # turns a breach into an outage.
            for sid in sorted(t.service_deps):
                deps = sorted(t.service_deps[sid])
                if len(deps) < 2 or not set(deps).issubset(p.isolate):
                    continue
                spare = [h for h in deps if not ctx.has_hard_evidence(h)]
                if not spare:
                    continue
                keep = min(spare, key=lambda h: (ctx.confidence(h), ctx.risk(h), h))
                c.objections[keep] = (
                    f"isolating this would take every host of '{sid}' offline; "
                    f"keep one replica for availability (this is the least "
                    f"suspicious of the {len(deps)})")

            for h in sorted(p.isolate):
                if h in c.objections:
                    continue
                if t.hosts[h].contains_pii and probs.get(h, 0.0) >= self.pii_reach_trust:
                    c.endorsements[h] = (
                        f"PII store reachable at trust {probs.get(h, 0.0):.2f} — "
                        f"agree it should come offline")

            # Additions: reachable PII stores with exfil signals nobody proposed.
            for h in sorted(set(self._pii_hosts(ctx)) - p.isolate):
                if self._exfil_signal(ctx, h) and probs.get(h, 0.0) >= self.pii_reach_trust:
                    c.additions[h] = (
                        "PII store showing an outbound-volume anomaly while "
                        "reachable from the foothold")

            c.summary = ("no data-protection objection" if c.satisfied else
                         f"{len(c.objections)} availability risk(s), "
                         f"{len(c.additions)} unprotected PII store(s)")
            out.append(c)
        return out

    def _accepts_addition(self, ctx: NegotiationContext, host: str) -> bool:
        return (ctx.has_hard_evidence(host)
                or ctx.topology.hosts[host].contains_pii)
