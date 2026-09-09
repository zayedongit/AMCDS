"""Each specialist agent's propose / critique / counter behaviour."""
from __future__ import annotations

import pytest

from amcds.agents import (BusinessImpactAgent, DataAgent, EndpointAgent,
                          IdentityAgent, NegotiationContext, NetworkAgent,
                          default_agents)
from amcds.agents.base_agent import AgentProposal, Critique
from amcds.evidence import (EVIDENCE_FIDELITY, Evidence, EvidenceType,
                            HostAssessment, ThreatAssessment)


# --------------------------------------------------------------------- helpers
def make_ctx(topology, hard=(), risks=None, attack_type="ransomware",
             medium=()):
    """Build a context with exactly the evidence the test wants."""
    ta = ThreatAssessment("T", attack_type, 30)
    for h in topology.host_ids():
        ta.hosts[h] = HostAssessment(h, risk_score=(risks or {}).get(h))
    for h in hard:
        ta.hosts[h].add(Evidence(
            h, EvidenceType.EDR_MALICIOUS_PROCESS,
            EVIDENCE_FIDELITY[EvidenceType.EDR_MALICIOUS_PROCESS],
            detail="test fixture"))
    for h in medium:
        ta.hosts[h].add(Evidence(
            h, EvidenceType.AUTH_ANOMALY,
            EVIDENCE_FIDELITY[EvidenceType.AUTH_ANOMALY], detail="test fixture"))
    return NegotiationContext.build(topology, ta)


class TestRoster:
    def test_exactly_five_agents(self):
        assert len(default_agents()) == 5

    def test_names_are_unique(self):
        names = [a.name for a in default_agents()]
        assert len(set(names)) == 5

    def test_exactly_one_holds_the_veto(self):
        holders = [a.name for a in default_agents() if a.has_veto]
        assert holders == ["BusinessImpact"]

    def test_every_agent_proposes_and_critiques(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        proposals = {a.name: a.propose(ctx) for a in default_agents()}
        for a in default_agents():
            assert isinstance(proposals[a.name], AgentProposal)
            crits = a.critique(ctx, proposals)
            assert len(crits) == 4          # every peer, never itself
            assert all(c.target_agent != a.name for c in crits)
            assert all(isinstance(c, Critique) for c in crits)

    def test_no_agent_crashes_with_zero_evidence(self, topology):
        ctx = make_ctx(topology)
        for a in default_agents():
            p = a.propose(ctx)
            assert p.isolate == set() or ctx.confirmed


class TestContext:
    def test_confirmed_requires_hard_evidence(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"], medium=["ws-fin-02"])
        assert ctx.confirmed == {"ws-fin-01"}
        assert "ws-fin-02" not in ctx.confirmed

    def test_blast_radius_is_computed_from_confirmed_only(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        assert ctx.blast["sources"] == ["ws-fin-01"]

    def test_no_confirmed_means_no_blast(self, topology):
        assert make_ctx(topology).blast == {}


class TestIdentityAgent:
    def test_proposes_every_confirmed_host(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        assert "ws-fin-01" in IdentityAgent().propose(ctx).isolate

    def test_never_proposes_a_dc_without_hard_evidence(self, topology):
        ctx = make_ctx(topology, hard=["app-prod-01"],
                       risks={"dc-01": 0.99, "dc-02": 0.99})
        p = IdentityAgent().propose(ctx)
        assert "dc-01" not in p.isolate and "dc-02" not in p.isolate

    def test_proposes_a_dc_when_the_dc_itself_is_proven(self, topology):
        ctx = make_ctx(topology, hard=["dc-01"])
        assert "dc-01" in IdentityAgent().propose(ctx).isolate

    def test_objects_to_peers_isolating_a_dc_on_suspicion(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        peer = AgentProposal("Network", isolate={"dc-01"})
        c = IdentityAgent().critique(ctx, {"Network": peer})[0]
        assert "dc-01" in c.objections
        assert "authentication" in c.objections["dc-01"]

    def test_objects_to_isolating_the_jump_host_on_suspicion(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        peer = AgentProposal("Data", isolate={"jump-01"})
        c = IdentityAgent().critique(ctx, {"Data": peer})[0]
        assert "jump-01" in c.objections

    def test_does_not_object_to_a_dc_with_hard_evidence(self, topology):
        ctx = make_ctx(topology, hard=["dc-01"])
        peer = AgentProposal("Network", isolate={"dc-01"})
        c = IdentityAgent().critique(ctx, {"Network": peer})[0]
        assert "dc-01" not in c.objections
        assert "dc-01" in c.endorsements

    def test_flags_confirmed_hosts_a_peer_left_out(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01", "ws-fin-02"])
        peer = AgentProposal("Data", isolate={"ws-fin-01"})
        c = IdentityAgent().critique(ctx, {"Data": peer})[0]
        assert "ws-fin-02" in c.additions


class TestNetworkAgent:
    def test_objects_to_hosts_the_attacker_cannot_reach(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        # Isolating the source cuts everything, so nothing else is reachable.
        peer = AgentProposal("Data", isolate={"db-prod-04"})
        c = NetworkAgent().critique(ctx, {"Data": peer})[0]
        assert "db-prod-04" in c.objections
        assert "containment" in c.objections["db-prod-04"]

    def test_endorses_the_confirmed_foothold(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        peer = AgentProposal("Data", isolate={"ws-fin-01"})
        c = NetworkAgent().critique(ctx, {"Data": peer})[0]
        assert "ws-fin-01" in c.endorsements

    def test_reasoning_quantifies_the_surface_reduction(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        assert "%" in NetworkAgent().propose(ctx).reasoning

    def test_proposes_nothing_without_a_foothold(self, topology):
        assert NetworkAgent().propose(make_ctx(topology)).isolate == set()


class TestDataAgent:
    def test_never_proposes_isolating_every_replica(self, topology):
        ctx = make_ctx(topology, hard=["app-prod-01"],
                       risks={h: 0.99 for h in topology.host_ids()})
        p = DataAgent().propose(ctx)
        for sid, deps in topology.service_deps.items():
            if len(deps) >= 2 and not deps <= ctx.confirmed:
                assert not deps <= p.isolate, f"{sid} fully isolated"

    def test_objects_when_a_peer_would_down_every_replica(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        deps = sorted(topology.service_deps["customer_data"])
        peer = AgentProposal("Network", isolate=set(deps))
        c = DataAgent().critique(ctx, {"Network": peer})[0]
        assert any(h in deps for h in c.objections)
        assert "availability" in " ".join(c.objections.values())

    def test_no_availability_objection_when_all_replicas_are_proven(self, topology):
        deps = sorted(topology.service_deps["customer_data"])
        ctx = make_ctx(topology, hard=deps)
        peer = AgentProposal("Network", isolate=set(deps))
        c = DataAgent().critique(ctx, {"Network": peer})[0]
        assert not any(h in deps for h in c.objections)


class TestEndpointAgent:
    def test_isolates_hosts_the_model_screams_about(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"], risks={"ws-eng-04": 0.999})
        assert "ws-eng-04" in EndpointAgent().propose(ctx).isolate

    def test_ignores_hosts_below_the_threshold(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"], risks={"ws-eng-04": 0.2})
        assert "ws-eng-04" not in EndpointAgent().propose(ctx).isolate

    def test_objects_to_isolating_a_quiet_host(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"], risks={"ws-sls-03": 0.05})
        peer = AgentProposal("Network", isolate={"ws-sls-03"})
        c = EndpointAgent().critique(ctx, {"Network": peer})[0]
        assert "ws-sls-03" in c.objections
        assert "zero detector alerts" in c.objections["ws-sls-03"]

    def test_does_not_object_when_the_host_is_anomalous(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"], risks={"ws-sls-03": 0.97})
        peer = AgentProposal("Network", isolate={"ws-sls-03"})
        c = EndpointAgent().critique(ctx, {"Network": peer})[0]
        assert "ws-sls-03" not in c.objections

    def test_reasoning_states_whether_ml_is_on(self, topology):
        with_ml = make_ctx(topology, hard=["ws-fin-01"], risks={"ws-eng-01": 0.5})
        without = make_ctx(topology, hard=["ws-fin-01"])
        assert "ML risk model active" in EndpointAgent().propose(with_ml).reasoning
        assert "DISABLED" in EndpointAgent().propose(without).reasoning

    def test_without_ml_it_falls_back_to_alert_confidence(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"],
                       medium=["ws-eng-02", "ws-eng-02"])
        p = EndpointAgent().propose(ctx)
        assert "ws-fin-01" in p.isolate
