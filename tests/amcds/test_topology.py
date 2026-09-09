"""Graph model: reachability, blast radius, service dependencies, validation."""
from __future__ import annotations

import networkx as nx
import pytest

from amcds.network import HostNode, NetworkTopology, build_segmented_enterprise


class TestStructure:
    def test_is_connected_and_segmented(self, topology):
        assert nx.is_connected(topology.graph)
        # Segmentation must actually raise the diameter: a flat network where
        # every workstation touches both DCs has diameter 2, which makes a
        # 3-hop blanket baseline isolate the entire estate.
        assert nx.diameter(topology.graph) >= 4

    def test_every_host_has_an_edge(self, topology):
        assert all(topology.graph.degree(h) > 0 for h in topology.host_ids())

    def test_deterministic_across_builds(self):
        a, b = build_segmented_enterprise(7), build_segmented_enterprise(7)
        assert a.to_json() == b.to_json()

    def test_different_seed_changes_wiring(self):
        a, b = build_segmented_enterprise(7), build_segmented_enterprise(99)
        assert a.to_json()["edges"] != b.to_json()["edges"]

    def test_host_ids_are_sorted(self, topology):
        assert topology.host_ids() == sorted(topology.host_ids())

    def test_edge_trust_becomes_log_weight(self, topology):
        for _, _, d in topology.graph.edges(data=True):
            assert 0 < d["trust"] <= 1.0
            assert d["weight"] == pytest.approx(-__import__("math").log(d["trust"]))


class TestValidation:
    def test_edge_to_unknown_host_rejected(self):
        t = NetworkTopology()
        t.add_host(HostNode("a", "workstation", 1, "bronze", 10.0))
        with pytest.raises(KeyError):
            t.add_edge("a", "ghost")

    def test_unknown_sla_tier_rejected(self, topology):
        t = build_segmented_enterprise()
        with pytest.raises(ValueError):
            t.add_service("bad", ["dc-01"], 1.0, sla="platinum")

    def test_service_on_unknown_host_rejected(self):
        t = NetworkTopology()
        t.add_host(HostNode("a", "workstation", 1, "bronze", 10.0))
        with pytest.raises(KeyError):
            t.add_service("s", ["a", "ghost"], 1.0)

    def test_orphan_host_fails_validation(self):
        t = NetworkTopology()
        t.add_host(HostNode("a", "workstation", 1, "bronze", 10.0))
        t.add_host(HostNode("b", "workstation", 1, "bronze", 10.0))
        t.add_edge("a", "b")
        t.add_host(HostNode("lonely", "workstation", 1, "bronze", 10.0))
        with pytest.raises(ValueError, match="no reachability edges"):
            t.validate()

    def test_empty_topology_fails_validation(self):
        with pytest.raises(ValueError, match="no hosts"):
            NetworkTopology().validate()


class TestServiceDependencies:
    def test_services_on_host_matches_deps(self, topology):
        for sid, deps in topology.service_deps.items():
            for h in deps:
                assert sid in topology.services_on_host(h)

    def test_service_is_down_if_any_dependency_isolated(self, topology):
        deps = sorted(topology.service_deps["payments"])
        assert "payments" in topology.downed_services({deps[0]})

    def test_revenue_counted_once_per_service_not_per_host(self, topology):
        deps = sorted(topology.service_deps["payments"])
        one = topology.revenue_impact_of_isolating({deps[0]})
        two = topology.revenue_impact_of_isolating({deps[0], deps[1]})
        # Both hosts belong to payments, so the second adds only whatever other
        # services it carries -- never a second copy of the payments revenue.
        assert two - one < topology.service_revenue["payments"]

    def test_sla_breaches_are_gold_only(self, topology):
        breaches = topology.sla_breaches(set(topology.host_ids()))
        assert breaches
        assert all(topology.service_sla[s] == "gold" for s in breaches)

    def test_gold_tier_hosts_carry_a_gold_service(self, topology):
        for h in topology.gold_tier_hosts():
            assert any(topology.service_sla[s] == "gold"
                       for s in topology.services_on_host(h))

    def test_host_sla_tier_is_the_strictest_service_it_carries(self, topology):
        rank = {"gold": 0, "silver": 1, "bronze": 2}
        for h in topology.host_ids():
            tiers = [topology.service_sla[s] for s in topology.services_on_host(h)]
            if tiers:
                assert topology.hosts[h].sla_tier == min(tiers, key=lambda t: rank[t])


class TestReachability:
    def test_reachable_from_shrinks_when_hosts_are_cut(self, topology):
        src = {"ws-fin-01"}
        full = topology.reachable_from(src)
        cut = topology.reachable_from(src, excluded=topology.neighbors("ws-fin-01"))
        assert len(cut) < len(full)

    def test_isolating_the_source_leaves_nothing_reachable(self, topology):
        assert topology.reachable_from({"ws-fin-01"}, excluded={"ws-fin-01"}) == set()

    def test_hop_distance_is_zero_at_source(self, topology):
        assert topology.hop_distances(["dc-01"])["dc-01"] == 0

    def test_within_hops_is_monotone(self, topology):
        src = ["ws-eng-01"]
        sizes = [len(topology.within_hops(src, k)) for k in range(1, 5)]
        assert sizes == sorted(sizes)

    def test_attack_path_probability_is_the_product_of_edge_trusts(self, topology):
        path, p = topology.attack_path("ws-fin-01", "db-prod-01")
        assert len(path) >= 2
        expected = 1.0
        for a, b in zip(path, path[1:]):
            expected *= topology.graph[a][b]["trust"]
        assert p == pytest.approx(expected)

    def test_most_probable_path_beats_an_arbitrary_path(self, topology):
        """Dijkstra on -log(trust) must find the maximum-product path."""
        _, best = topology.attack_path("ws-fin-01", "db-prod-01")
        for alt in nx.all_simple_paths(topology.graph, "ws-fin-01", "db-prod-01",
                                       cutoff=4):
            p = 1.0
            for a, b in zip(alt, alt[1:]):
                p *= topology.graph[a][b]["trust"]
            assert p <= best + 1e-9

    def test_no_path_returns_zero(self, topology):
        assert topology.attack_path("ws-fin-01", "does-not-exist") == ([], 0.0)

    def test_hardened_tiers_are_harder_to_reach(self, topology):
        probs = topology.attack_path_probabilities(["ws-fin-01"])
        # A departmental peer is far easier to reach than a production database.
        assert probs["ws-fin-02"] > probs["db-prod-01"]

    def test_plausible_surface_is_a_subset_of_reachable(self, topology):
        src = ["ws-fin-01"]
        assert topology.plausible_attack_surface(src) <= topology.reachable_from(src)


class TestBlastRadius:
    def test_reports_hosts_services_and_revenue(self, topology):
        b = topology.blast_radius(["ws-fin-01"], hops=2)
        assert b["n_hosts_at_risk"] == len(b["hosts_at_risk"])
        assert "ws-fin-01" in b["hosts_at_risk"]
        assert b["revenue_at_risk_per_hour"] == pytest.approx(
            sum(topology.service_revenue[s] for s in b["services_at_risk"]))
        assert set(b["gold_services_at_risk"]) <= set(b["services_at_risk"])

    def test_more_hops_never_shrinks_the_radius(self, topology):
        small = topology.blast_radius(["ws-eng-01"], hops=1)
        large = topology.blast_radius(["ws-eng-01"], hops=3)
        assert large["n_hosts_at_risk"] >= small["n_hosts_at_risk"]

    def test_empty_source_gives_empty_radius(self, topology):
        assert topology.blast_radius([])["n_hosts_at_risk"] == 0

    def test_containment_value_of_isolating_the_source_is_total(self, topology):
        v = topology.containment_value(["ws-fin-01"], ["ws-fin-01"])
        assert v["surface_after"] == 0
        assert v["reduction_pct"] == 100.0

    def test_containment_value_of_isolating_nothing_is_zero(self, topology):
        v = topology.containment_value([], ["ws-fin-01"])
        assert v["reduction_pct"] == 0.0

    def test_centrality_and_choke_points_are_computable(self, topology):
        c = topology.centrality()
        assert set(c) == set(topology.host_ids())
        assert isinstance(topology.choke_points(), list)
