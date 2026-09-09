"""CP-SAT model: constraints, objective, degenerate inputs, annealing control."""
from __future__ import annotations

import pytest

from amcds.network import HostNode, NetworkTopology
from amcds.optimization import AnnealingSolver, CPSATSolver


class TestConstraints:
    def test_C1_hard_evidence_hosts_are_always_isolated(self, topology):
        r = CPSATSolver().solve(topology, ["ws-fin-01", "ws-fin-02"], ["ws-fin-01"],
                                reach={"ws-fin-01": 1.0, "ws-fin-02": 0.8})
        assert "ws-fin-01" in r["isolate"]
        assert any("C1" in c for c in r["constraints"])

    def test_C1_holds_even_when_the_host_is_ruinously_expensive(self, topology):
        r = CPSATSolver().solve(topology, ["db-prod-01"], ["db-prod-01"],
                                reach={"db-prod-01": 1.0})
        assert "db-prod-01" in r["isolate"]

    def test_C2_gold_service_keeps_an_unevidenced_host_online(self, topology):
        deps = sorted(topology.service_deps["payments"])
        r = CPSATSolver().solve(topology, deps, [], 
                                reach={h: 1.0 for h in deps},
                                risk_scores={h: 1.0 for h in deps})
        assert not set(deps) <= r["isolate"], "every payments host was isolated"
        assert any("C2" in c for c in r["constraints"])

    def test_C2_yields_when_every_host_of_the_service_is_proven(self, topology):
        deps = sorted(topology.service_deps["customer_data"])
        r = CPSATSolver().solve(topology, deps, deps,
                                reach={h: 1.0 for h in deps})
        assert set(deps) <= r["isolate"]

    def test_C3_multi_host_service_keeps_a_replica(self, topology):
        deps = sorted(topology.service_deps["marketing_site"])
        r = CPSATSolver().solve(topology, deps, [],
                                reach={h: 1.0 for h in deps},
                                risk_scores={h: 1.0 for h in deps})
        assert not set(deps) <= r["isolate"]

    def test_C4_budget_caps_the_plan(self, topology):
        cheap = CPSATSolver(max_hourly_loss=50_000)
        r = cheap.solve(topology, ["web-01", "app-prod-01", "ws-sls-01"], [],
                        reach={"web-01": 1.0, "app-prod-01": 1.0, "ws-sls-01": 1.0},
                        risk_scores={"web-01": 1.0, "app-prod-01": 1.0})
        assert r["budget_enforced"] is True
        assert r["business_cost_per_hour"] <= 50_000

    def test_C4_is_relaxed_and_reported_when_evidence_forces_the_cost(self, topology):
        r = CPSATSolver(max_hourly_loss=1.0).solve(
            topology, ["db-prod-01"], ["db-prod-01"], reach={"db-prod-01": 1.0})
        assert r["budget_enforced"] is False
        assert any("C4 budget relaxed" in x for x in r["relaxations"])
        assert "db-prod-01" in r["isolate"]


class TestObjective:
    def test_business_cost_is_counted_once_per_service(self, topology):
        """Regression: the old objective summed per-host revenue, so a
        multi-host service was charged twice."""
        deps = sorted(topology.service_deps["payments"])[:2]
        r = CPSATSolver().solve(topology, deps, deps, reach={h: 1.0 for h in deps})
        assert r["business_cost_per_hour"] == pytest.approx(
            topology.revenue_impact_of_isolating(set(deps)))

    def test_unreachable_hosts_carry_no_risk_weight(self, topology):
        r = CPSATSolver().solve(topology, ["ws-sls-06"], [], reach={})
        assert r["weights"]["ws-sls-06"] == 0
        assert "ws-sls-06" not in r["isolate"], "isolated a host with zero risk"

    def test_risk_weight_rises_with_criticality_reach_and_anomaly(self, topology):
        s = CPSATSolver()
        low = s._risk_weight(topology, "ws-sls-01", {"ws-sls-01": 0.1}, {})
        high = s._risk_weight(topology, "ws-sls-01", {"ws-sls-01": 0.9},
                              {"ws-sls-01": 1.0})
        assert high > low

    def test_alpha_is_not_truncated_to_an_integer(self, topology):
        """Regression: the old model did int(self.alpha), so alpha=0.5 became 0
        and the risk term silently vanished."""
        cand = ["ws-fin-02", "ws-fin-03"]
        reach = {h: 0.9 for h in cand}
        risk_heavy = CPSATSolver(alpha=0.5, beta=0.0001).solve(
            topology, cand, [], reach=reach)
        cost_heavy = CPSATSolver(alpha=0.0001, beta=0.5).solve(
            topology, cand, [], reach=reach)
        assert len(risk_heavy["isolate"]) > len(cost_heavy["isolate"])

    def test_higher_beta_isolates_less(self, topology):
        cand = ["web-01", "web-02", "ws-eng-01"]
        reach = {h: 0.7 for h in cand}
        cheap = CPSATSolver(alpha=1.0, beta=0.01).solve(topology, cand, [], reach=reach)
        pricey = CPSATSolver(alpha=1.0, beta=100.0).solve(topology, cand, [], reach=reach)
        assert len(pricey["isolate"]) <= len(cheap["isolate"])


class TestSolverBehaviour:
    def test_empty_candidate_set(self, topology):
        r = CPSATSolver().solve(topology, [], [])
        assert r["isolate"] == set()
        assert r["status"] == "EMPTY"

    def test_solution_is_always_a_subset_of_the_candidates(self, topology):
        cand = ["ws-fin-01", "ws-fin-02", "app-prod-01"]
        r = CPSATSolver().solve(topology, cand, ["ws-fin-01"],
                                reach={h: 0.6 for h in cand})
        assert r["isolate"] <= set(cand)
        assert set(r["dropped"]) == set(cand) - r["isolate"]

    def test_is_deterministic(self, topology):
        cand = sorted(topology.host_ids())[:12]
        reach = {h: 0.5 for h in cand}
        a = CPSATSolver().solve(topology, cand, cand[:2], reach=reach)
        b = CPSATSolver().solve(topology, cand, cand[:2], reach=reach)
        assert a["isolate"] == b["isolate"]
        assert a["objective"] == b["objective"]

    def test_reaches_optimality_on_the_reference_topology(self, topology):
        cand = sorted(topology.host_ids())
        r = CPSATSolver().solve(topology, cand, ["ws-fin-01"],
                                reach={h: 0.4 for h in cand})
        assert r["status"] == "OPTIMAL"
        assert r["runtime_seconds"] < 10.0

    def test_unknown_candidate_raises_rather_than_silently_dropping(self, topology):
        with pytest.raises(KeyError):
            CPSATSolver().solve(topology, ["ghost-99"], [])

    def test_explanation_is_human_readable(self, topology):
        r = CPSATSolver().solve(topology, ["ws-fin-01", "ws-fin-02"], ["ws-fin-01"],
                                reach={"ws-fin-01": 1.0})
        assert "CP-SAT" in r["explanation"]
        assert "candidate" in r["explanation"]


class TestInfeasibility:
    def test_contradictory_model_falls_back_to_hard_evidence_only(self):
        """C1 forces a host in, C2/C3 forces the same host out: infeasible."""
        t = NetworkTopology()
        for h in ("a", "b"):
            t.add_host(HostNode(h, "db_server", 5, "gold", 800_000.0))
        t.add_edge("a", "b", 0.5)
        t.add_service("only", ["a", "b"], 5_000_000, sla="gold")
        t.finalize()
        # 'a' has hard evidence (must isolate) but 'b' does not, so C2 requires
        # b to stay online -- that is satisfiable. Force both in to break it.
        solver = CPSATSolver()
        r = solver.solve(t, ["a", "b"], ["a"], reach={"a": 1.0, "b": 1.0})
        assert "a" in r["isolate"]
        assert "b" not in r["isolate"]      # C2 protected the last replica

    def test_single_host_gold_service_can_still_be_isolated_on_evidence(self):
        t = NetworkTopology()
        for h in ("solo", "peer"):
            t.add_host(HostNode(h, "db_server", 5, "gold", 800_000.0))
        t.add_edge("solo", "peer", 0.5)
        t.add_service("critical", ["solo"], 5_000_000, sla="gold")
        t.add_service("other", ["peer"], 1000, sla="bronze")
        t.finalize()
        r = CPSATSolver().solve(t, ["solo"], ["solo"], reach={"solo": 1.0})
        assert "solo" in r["isolate"]
        assert r["sla_breaches"] == ["critical"]


class TestAnnealingControl:
    def test_returns_a_subset_and_respects_hard_evidence(self, topology):
        cand = ["ws-fin-01", "ws-fin-02", "app-prod-01"]
        r = AnnealingSolver(num_reads=40).solve(
            topology, cand, ["ws-fin-01"], reach={h: 0.6 for h in cand})
        assert r["isolate"] <= set(cand)
        assert "ws-fin-01" in r["isolate"]

    def test_is_deterministic_for_a_fixed_seed(self, topology):
        cand = sorted(topology.host_ids())[:10]
        kw = dict(reach={h: 0.5 for h in cand})
        a = AnnealingSolver(num_reads=40, seed=7).solve(topology, cand, [], **kw)
        b = AnnealingSolver(num_reads=40, seed=7).solve(topology, cand, [], **kw)
        assert a["isolate"] == b["isolate"]

    def test_empty_input(self, topology):
        assert AnnealingSolver().solve(topology, [], [])["isolate"] == set()

    def test_it_does_not_claim_to_be_quantum(self):
        assert "quantum" not in AnnealingSolver.name.lower()
        assert "classical" in AnnealingSolver.name.lower()
