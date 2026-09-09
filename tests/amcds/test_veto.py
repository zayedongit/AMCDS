"""The formal Business Impact veto — the project's central claim.

    VETO(h)  iff  isolating h breaks a gold-tier SLA  AND  h has no hard evidence
"""
from __future__ import annotations

import pytest

from amcds.agents import BusinessImpactAgent
from amcds.agents.base_agent import AgentProposal
from tests.amcds.test_agents import make_ctx


def gold_host(topology):
    """A host that carries a gold service and is not the only one."""
    return sorted(topology.service_deps["payments"])[0]


class TestVetoPredicate:
    def test_gold_host_without_hard_evidence_is_vetoed(self, topology):
        h = gold_host(topology)
        ctx = make_ctx(topology, hard=["ws-fin-01"], risks={h: 0.99})
        assert BusinessImpactAgent().veto_applies(ctx, h) is True

    def test_gold_host_with_hard_evidence_is_not_vetoed(self, topology):
        h = gold_host(topology)
        ctx = make_ctx(topology, hard=["ws-fin-01", h])
        assert BusinessImpactAgent().veto_applies(ctx, h) is False

    def test_non_gold_host_is_never_vetoed_by_the_sla_rule(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        assert BusinessImpactAgent().veto_applies(ctx, "ws-sls-04") is False

    def test_breaches_gold_sla_lists_the_services(self, topology):
        h = gold_host(topology)
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        gold = BusinessImpactAgent().breaches_gold_sla(ctx, h)
        assert "payments" in gold
        assert all(topology.service_sla[s] == "gold" for s in gold)


class TestVetoApplication:
    def test_vetoed_host_is_removed_from_the_candidate_set(self, topology):
        h = gold_host(topology)
        ctx = make_ctx(topology, hard=["ws-fin-01"], risks={h: 0.99})
        surviving, decision = BusinessImpactAgent().apply_veto(ctx, {"ws-fin-01", h})
        assert h not in surviving
        assert h in decision.vetoed
        assert "ws-fin-01" in surviving

    def test_hard_evidence_overrides_and_the_override_is_recorded(self, topology):
        h = gold_host(topology)
        ctx = make_ctx(topology, hard=["ws-fin-01", h])
        surviving, decision = BusinessImpactAgent().apply_veto(ctx, {"ws-fin-01", h})
        assert h in surviving
        assert h in decision.overridden
        assert h not in decision.vetoed

    def test_veto_is_absolute_regardless_of_peer_support(self, topology):
        """No amount of agreement from the other agents unblocks a veto."""
        h = gold_host(topology)
        ctx = make_ctx(topology, hard=["ws-fin-01"], risks={h: 0.999})
        surviving, _ = BusinessImpactAgent().apply_veto(ctx, {h})
        assert h not in surviving

    def test_empty_candidate_set_is_handled(self, topology):
        ctx = make_ctx(topology)
        surviving, decision = BusinessImpactAgent().apply_veto(ctx, set())
        assert surviving == set()
        assert decision.vetoed == {}

    def test_veto_reason_names_the_service_and_the_evidence_gap(self, topology):
        h = gold_host(topology)
        ctx = make_ctx(topology, hard=["ws-fin-01"], risks={h: 0.5})
        _, decision = BusinessImpactAgent().apply_veto(ctx, {h})
        why = decision.vetoed[h]
        assert "gold-tier" in why and "payments" in why
        assert "hard-evidence bar" in why

    def test_summary_reports_the_approved_cost(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        _, decision = BusinessImpactAgent().apply_veto(ctx, {"ws-fin-01"})
        assert "L/hour" in decision.summary


class TestBudgetRule:
    def test_expensive_unevidenced_hosts_are_dropped_to_meet_the_ceiling(self, topology):
        agent = BusinessImpactAgent(max_hourly_loss=100_000)
        # A silver host: not protected by the SLA rule, so only the budget bites.
        ctx = make_ctx(topology, hard=["ws-fin-01"], risks={"web-01": 0.99})
        surviving, decision = agent.apply_veto(ctx, {"ws-fin-01", "web-01"})
        assert "web-01" not in surviving
        assert "budget rule" in decision.vetoed["web-01"]

    def test_budget_never_drops_a_hard_evidence_host(self, topology):
        agent = BusinessImpactAgent(max_hourly_loss=1.0)
        ctx = make_ctx(topology, hard=["web-01", "app-prod-01"])
        surviving, _ = agent.apply_veto(ctx, {"web-01", "app-prod-01"})
        assert {"web-01", "app-prod-01"} <= surviving

    def test_unattainable_ceiling_is_reported_not_faked(self, topology):
        """When proven hosts alone blow the budget, dropping cheap hosts would
        be theatre. The rule must say so instead."""
        agent = BusinessImpactAgent(max_hourly_loss=1.0)
        ctx = make_ctx(topology, hard=["db-prod-01"], risks={"ws-sls-01": 0.99})
        surviving, decision = agent.apply_veto(ctx, {"db-prod-01", "ws-sls-01"})
        assert "unattainable" in decision.summary
        assert "ws-sls-01" not in decision.vetoed

    def test_generous_budget_vetoes_nothing_on_cost(self, topology):
        agent = BusinessImpactAgent(max_hourly_loss=10 ** 12)
        ctx = make_ctx(topology, hard=["ws-fin-01"], risks={"web-01": 0.99})
        _, decision = agent.apply_veto(ctx, {"ws-fin-01", "web-01"})
        assert not any("budget" in v for v in decision.vetoed.values())


class TestVetoCritique:
    def test_warns_before_it_vetoes(self, topology):
        """The critique phase must surface the objection so agents can revise."""
        h = gold_host(topology)
        ctx = make_ctx(topology, hard=["ws-fin-01"], risks={h: 0.99})
        peer = AgentProposal("Network", isolate={h})
        c = BusinessImpactAgent().critique(ctx, {"Network": peer})[0]
        assert h in c.objections
        assert "will be vetoed" in c.objections[h]

    def test_endorses_an_evidence_backed_gold_isolation(self, topology):
        h = gold_host(topology)
        ctx = make_ctx(topology, hard=[h])
        peer = AgentProposal("Network", isolate={h})
        c = BusinessImpactAgent().critique(ctx, {"Network": peer})[0]
        assert h in c.endorsements
        assert h not in c.objections

    def test_flags_an_over_budget_plan(self, topology):
        agent = BusinessImpactAgent(max_hourly_loss=1.0)
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        peer = AgentProposal("Network", isolate={"db-prod-01"})
        c = agent.critique(ctx, {"Network": peer})[0]
        assert "ceiling" in c.summary


class TestVetoProposal:
    def test_proposes_gold_hosts_that_are_proven_compromised(self, topology):
        h = gold_host(topology)
        ctx = make_ctx(topology, hard=[h])
        assert h in BusinessImpactAgent().propose(ctx).isolate

    def test_does_not_propose_unproven_gold_hosts(self, topology):
        h = gold_host(topology)
        ctx = make_ctx(topology, hard=["ws-fin-01"], risks={h: 0.99})
        assert h not in BusinessImpactAgent().propose(ctx).isolate
