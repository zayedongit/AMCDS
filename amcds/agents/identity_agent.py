"""Identity Agent — credential-theft and privilege-escalation paths.

Domain
------
Who can become domain admin, and how fast. It reasons over the *most probable
attack path* to each domain controller (Dijkstra on ``-log(trust)``), not over
raw adjacency, so a workstation that can only reach a DC through a hardened
Kerberos channel is treated very differently from one sitting next to a jump
host.

Position in the negotiation
---------------------------
It is the agent that pushes back hardest on isolating identity infrastructure:
quarantining a domain controller stops the attacker *and* stops every login in
the organisation, so its critique offers credential rotation as the alternative
containment action. This is a genuine, recurring source of disagreement with the
Network agent, which wants to cut high-centrality hosts.
"""
from __future__ import annotations

from typing import Dict, List, Sequence

from .base_agent import AgentProposal, BaseAgent, Critique, NegotiationContext

#: Path-trust above which a credential-theft pivot is considered realistic.
CREDENTIAL_PATH_TRUST = 0.20


class IdentityAgent(BaseAgent):
    name = "Identity"

    def __init__(self, path_trust_threshold: float = CREDENTIAL_PATH_TRUST) -> None:
        self.path_trust_threshold = path_trust_threshold

    # ------------------------------------------------------------------ helpers
    def _identity_assets(self, ctx: NegotiationContext) -> List[str]:
        t = ctx.topology
        return [h for h in t.host_ids()
                if t.hosts[h].host_type in ("domain_controller", "jump_host")]

    # ------------------------------------------------------------------ propose
    def propose(self, ctx: NegotiationContext) -> AgentProposal:
        t = ctx.topology
        isolate: set = set()
        justification: Dict[str, str] = {}

        for h in sorted(ctx.confirmed):
            isolate.add(h)
            justification[h] = ("confirmed compromised — every credential cached "
                                "here must be treated as stolen")

        # Suspected hosts matter to us only when they sit on a credible path to
        # identity infrastructure.
        assets = self._identity_assets(ctx)
        for h in sorted(ctx.suspected):
            best = 0.0
            best_asset = ""
            for asset in assets:
                if asset == h:
                    continue
                _, p = t.attack_path(h, asset)
                if p > best:
                    best, best_asset = p, asset
            cred_signal = self._has_credential_signal(ctx, h)
            if best >= self.path_trust_threshold and (cred_signal or best >= 0.4):
                isolate.add(h)
                justification[h] = (
                    f"suspected, and has a {best:.2f}-probability lateral path to "
                    f"{best_asset}"
                    + (" with credential-theft indicators" if cred_signal else ""))

        # We never propose isolating a domain controller: see critique().
        dcs = {h for h in isolate if t.hosts[h].host_type == "domain_controller"}
        for h in sorted(dcs):
            if not ctx.has_hard_evidence(h):
                isolate.discard(h)
                justification.pop(h, None)

        n_dc_at_risk = sum(1 for a in assets
                           if t.hosts[a].host_type == "domain_controller"
                           and any(t.attack_path(c, a)[1] >= self.path_trust_threshold
                                   for c in sorted(ctx.confirmed)))
        reasoning = (
            f"{len(ctx.confirmed)} host(s) with hard evidence hold cached credentials. "
            f"{n_dc_at_risk} domain controller(s) sit on a credible attack path "
            f"(trust >= {self.path_trust_threshold:.2f}). "
            f"Recommending isolation of {len(isolate)} host(s); domain controllers are "
            f"flagged for forced credential rotation rather than isolation.")

        return AgentProposal(
            agent_name=self.name, isolate=isolate, justification=justification,
            reasoning=reasoning,
            confidence=0.85 if ctx.confirmed else 0.35,
        )

    @staticmethod
    def _has_credential_signal(ctx: NegotiationContext, host: str) -> bool:
        a = ctx.assessment.hosts.get(host)
        if a is None:
            return False
        return any(e.ev_type.value in ("credential_dump", "auth_anomaly")
                   for e in a.evidence)

    # ----------------------------------------------------------------- critique
    def critique(self, ctx: NegotiationContext,
                 proposals: Dict[str, AgentProposal]) -> List[Critique]:
        t = ctx.topology
        out: List[Critique] = []
        for other in sorted(proposals):
            if other == self.name:
                continue
            p = proposals[other]
            c = Critique(agent_name=self.name, target_agent=other)

            for h in sorted(p.isolate):
                host = t.hosts[h]
                if host.host_type == "domain_controller" and not ctx.has_hard_evidence(h):
                    c.objections[h] = (
                        "isolating a domain controller halts authentication for the "
                        "whole estate; without hard evidence, force credential "
                        "rotation instead")
                elif host.host_type == "jump_host" and not ctx.has_hard_evidence(h):
                    c.objections[h] = (
                        "the jump host is how responders reach the app and identity "
                        "tiers; isolating it on suspicion blinds the response")
                elif ctx.has_hard_evidence(h):
                    c.endorsements[h] = "hard evidence — cached credentials are burned"

            # Additions: confirmed hosts with a strong path to identity assets
            # that this proposal skipped.
            for h in sorted(ctx.confirmed - p.isolate):
                c.additions[h] = ("hard evidence of compromise; leaving it online "
                                  "leaves stolen credentials in active use")

            n_obj, n_add = len(c.objections), len(c.additions)
            c.summary = (
                "no identity objection" if c.satisfied else
                f"{n_obj} identity objection(s), {n_add} missing confirmed host(s)")
            out.append(c)
        return out

    def _accepts_addition(self, ctx: NegotiationContext, host: str) -> bool:
        if ctx.has_hard_evidence(host):
            return True
        return self._has_credential_signal(ctx, host)
