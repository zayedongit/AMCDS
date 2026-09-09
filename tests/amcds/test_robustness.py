"""Failure and robustness cases: malformed input, degenerate graphs, extremes."""
from __future__ import annotations

import random

import pytest

from amcds.agents import (BusinessImpactAgent, NegotiationContext,
                          default_agents)
from amcds.evidence import HostAssessment, ThreatAssessment
from amcds.negotiation import NegotiationProtocol
from amcds.network import HostNode, NetworkTopology
from amcds.optimization import CPSATSolver
from amcds.pipeline import AMCDSPipeline
from amcds.scenarios import ScenarioGenerator


def empty_ctx(topology):
    ta = ThreatAssessment("EMPTY", "ransomware", 0)
    for h in topology.host_ids():
        ta.hosts[h] = HostAssessment(h)
    return NegotiationContext.build(topology, ta)


class TestUnusualGraphs:
    def test_two_host_network(self):
        t = NetworkTopology()
        for h in ("a", "b"):
            t.add_host(HostNode(h, "workstation", 1, "bronze", 10.0))
        t.add_edge("a", "b", 0.9)
        t.add_service("s", ["a", "b"], 100.0, sla="bronze")
        t.finalize()
        assert t.blast_radius(["a"])["n_hosts_at_risk"] == 2
        assert CPSATSolver().solve(t, ["a", "b"], ["a"],
                                   reach={"a": 1.0})["isolate"] >= {"a"}

    def test_star_topology_hub_is_a_choke_point(self):
        t = NetworkTopology()
        t.add_host(HostNode("hub", "app_server", 4, "silver", 1000.0))
        for i in range(5):
            t.add_host(HostNode(f"leaf-{i}", "workstation", 1, "bronze", 10.0))
            t.add_edge("hub", f"leaf-{i}", 0.8)
        t.add_service("s", ["hub"], 100.0, sla="bronze")
        t.finalize()
        assert t.choke_points() == ["hub"]
        v = t.containment_value(["hub"], ["leaf-0"])
        assert v["surface_after"] <= 1

    def test_disconnected_graph_is_rejected_by_validation(self):
        t = NetworkTopology()
        for h in ("a", "b", "island"):
            t.add_host(HostNode(h, "workstation", 1, "bronze", 10.0))
        t.add_edge("a", "b", 0.5)
        with pytest.raises(ValueError):
            t.validate()

    def test_summary_handles_a_disconnected_graph(self):
        t = NetworkTopology()
        for h in ("a", "b", "c", "d"):
            t.add_host(HostNode(h, "workstation", 1, "bronze", 10.0))
        t.add_edge("a", "b", 0.5)
        t.add_edge("c", "d", 0.5)
        assert t.summary()["diameter"] is None

    def test_zero_trust_edge_is_clamped_not_infinite(self):
        t = NetworkTopology()
        for h in ("a", "b"):
            t.add_host(HostNode(h, "workstation", 1, "bronze", 10.0))
        t.add_edge("a", "b", 0.0)
        assert t.graph["a"]["b"]["trust"] > 0
        assert t.attack_path("a", "b")[1] > 0

    def test_trust_above_one_is_clamped(self):
        t = NetworkTopology()
        for h in ("a", "b"):
            t.add_host(HostNode(h, "workstation", 1, "bronze", 10.0))
        t.add_edge("a", "b", 99.0)
        assert t.graph["a"]["b"]["trust"] == 1.0


class TestWeakOrAbsentEvidence:
    def test_no_evidence_produces_no_isolation(self, topology):
        log = NegotiationProtocol(default_agents()).run(empty_ctx(topology))
        assert log.final_isolate == set()

    def test_suspicion_alone_never_breaches_a_gold_sla(self, topology, risk_model,
                                                       generator):
        """The core safety guarantee, checked across a whole suite."""
        p = AMCDSPipeline(topology, risk_model)
        for sc in generator.batch(n_each=4):
            d = p.run(sc)
            confirmed = d.assessment.confirmed_infected()
            for sid in d.solver_result["sla_breaches"]:
                assert topology.service_deps[sid] & d.isolate & confirmed

    def test_ml_only_evidence_cannot_confirm_a_host(self, topology, risk_model,
                                                    generator):
        p = AMCDSPipeline(topology, risk_model)
        d = p.run(generator.insider_threat("WEAK"))
        for host, a in d.assessment.hosts.items():
            only_ml = a.evidence and all(e.ev_type.value == "ml_anomaly"
                                         for e in a.evidence)
            if only_ml:
                assert not a.has_hard_evidence()


class TestExtremes:
    def test_entire_estate_compromised(self, topology, risk_model):
        gen = ScenarioGenerator(topology, seed=1)
        sc = gen.ransomware("EXTREME")
        sc.ground_truth_compromised = topology.host_ids()
        sc.telemetry = None  # force the no-ML path rather than a bogus score
        p = AMCDSPipeline(topology, risk_model, use_ml=False)
        d = p.run(sc)
        assert isinstance(d.isolate, set)

    def test_maximally_expensive_candidate_set(self, topology):
        gold = sorted(topology.gold_tier_hosts())
        r = CPSATSolver(max_hourly_loss=1.0).solve(
            topology, gold, [], reach={h: 1.0 for h in gold},
            risk_scores={h: 1.0 for h in gold})
        assert r["status"] in ("OPTIMAL", "FEASIBLE")
        # With no evidence and a tight budget, isolating nothing is optimal.
        assert r["business_cost_per_hour"] <= 1.0

    def test_equivalent_candidates_resolve_deterministically(self, topology):
        """Ties must break the same way every run, not by set iteration order."""
        twins = ["ws-sls-01", "ws-sls-02", "ws-sls-03"]
        kw = dict(reach={h: 0.5 for h in twins},
                  risk_scores={h: 0.5 for h in twins})
        plans = {frozenset(CPSATSolver().solve(topology, twins, [], **kw)["isolate"])
                 for _ in range(5)}
        assert len(plans) == 1

    def test_very_large_candidate_set_still_solves_fast(self, topology):
        cand = topology.host_ids()
        r = CPSATSolver().solve(topology, cand, ["ws-fin-01"],
                                reach={h: 0.5 for h in cand})
        assert r["runtime_seconds"] < 10.0
        assert r["status"] in ("OPTIMAL", "FEASIBLE")


class TestMalformedInput:
    def test_solver_rejects_unknown_hosts(self, topology):
        with pytest.raises(KeyError):
            CPSATSolver().solve(topology, ["not-a-host"], [])

    def test_hard_evidence_outside_the_candidate_set_is_ignored(self, topology):
        r = CPSATSolver().solve(topology, ["ws-fin-01"], ["ws-eng-05"],
                                reach={"ws-fin-01": 1.0})
        assert "ws-eng-05" not in r["isolate"]

    def test_veto_tolerates_hosts_with_no_assessment(self, topology):
        ta = ThreatAssessment("SPARSE", "ransomware", 5)
        ctx = NegotiationContext.build(topology, ta)
        surviving, decision = BusinessImpactAgent().apply_veto(ctx, {"db-prod-01"})
        assert "db-prod-01" in decision.vetoed
        assert surviving == set()

    def test_agents_tolerate_a_context_with_no_host_entries(self, topology):
        ta = ThreatAssessment("SPARSE", "ransomware", 5)
        ctx = NegotiationContext.build(topology, ta)
        for a in default_agents():
            assert a.propose(ctx).isolate == set()

    def test_negative_revenue_service_is_rejected_only_if_host_unknown(self, topology):
        t = NetworkTopology()
        t.add_host(HostNode("a", "workstation", 1, "bronze", 10.0))
        t.add_host(HostNode("b", "workstation", 1, "bronze", 10.0))
        t.add_edge("a", "b")
        t.add_service("s", ["a"], 0.0, sla="bronze")
        t.finalize()
        assert t.revenue_impact_of_isolating({"a"}) == 0.0
