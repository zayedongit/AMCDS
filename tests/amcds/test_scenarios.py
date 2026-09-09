"""Scenario generation, attack propagation, and detection sensors."""
from __future__ import annotations

import random

import pytest

from amcds.attack.propagation import PROFILES, PropagationModel
from amcds.detection import build_assessment, emit_alerts
from amcds.detection.sensors import dwell_factor
from amcds.scenarios import ATTACK_TYPES, ScenarioGenerator, derive_seed
from amcds.telemetry import TelemetryGenerator


class TestPropagation:
    def test_same_seed_gives_the_same_spread(self, topology):
        m = PropagationModel(topology)
        a = m.counterfactual_spread(["ws-fin-01"], "ransomware", 15, 42)
        b = m.counterfactual_spread(["ws-fin-01"], "ransomware", 15, 42)
        assert a.compromised == b.compromised
        assert a.pivots == b.pivots

    def test_different_seeds_generally_differ(self, topology):
        m = PropagationModel(topology)
        runs = {tuple(m.counterfactual_spread(["ws-fin-01"], "ransomware", 15, s
                                              ).compromised) for s in range(12)}
        assert len(runs) > 1

    def test_seeds_are_always_compromised(self, topology):
        r = PropagationModel(topology).counterfactual_spread(
            ["ws-fin-01", "ws-eng-01"], "ransomware", 15, 3)
        assert {"ws-fin-01", "ws-eng-01"} <= set(r.compromised)

    def test_blocking_the_seed_stops_everything(self, topology):
        r = PropagationModel(topology).counterfactual_spread(
            ["ws-fin-01"], "ransomware", 20, 3, isolate=["ws-fin-01"])
        assert r.compromised == []

    def test_isolation_reduces_the_spread(self, topology):
        m = PropagationModel(topology)
        free = m.counterfactual_spread(["ws-fin-01"], "ransomware", 20, 5)
        cut = m.counterfactual_spread(["ws-fin-01"], "ransomware", 20, 5,
                                      isolate=topology.neighbors("ws-fin-01"))
        assert len(cut.compromised) <= len(free.compromised)

    def test_longer_dwell_never_shrinks_the_spread(self, topology):
        m = PropagationModel(topology)
        sizes = [len(m.counterfactual_spread(["ws-fin-01"], "ransomware", d, 9
                                             ).compromised) for d in (4, 8, 20)]
        assert sizes == sorted(sizes)

    def test_ransomware_spreads_further_than_an_insider(self, topology):
        m = PropagationModel(topology)
        rw = sum(len(m.counterfactual_spread(["ws-fin-01"], "ransomware", 20, s
                                             ).compromised) for s in range(15))
        it = sum(len(m.counterfactual_spread(["ws-fin-01"], "insider_threat", 20, s
                                             ).compromised) for s in range(15))
        assert rw > it

    def test_spread_only_follows_graph_edges(self, topology):
        r = PropagationModel(topology).counterfactual_spread(
            ["ws-fin-01"], "ransomware", 20, 11)
        for src, dst, _ in r.pivots:
            assert topology.graph.has_edge(src, dst)

    def test_rounds_are_capped_by_the_profile(self, topology):
        m = PropagationModel(topology)
        for name, profile in PROFILES.items():
            assert m.rounds_for(name, 10_000) == profile.max_rounds
            assert m.rounds_for(name, 0) >= 1

    def test_unknown_attack_type_falls_back(self, topology):
        r = PropagationModel(topology).counterfactual_spread(
            ["ws-fin-01"], "not-a-real-attack", 20, 1)
        assert "ws-fin-01" in r.compromised


class TestSensors:
    def test_alerts_only_reference_known_hosts(self, topology):
        alerts = emit_alerts(topology.host_ids(), ["ws-fin-01"], "ransomware",
                             30, random.Random(1))
        assert all(a.host_id in topology.hosts for a in alerts)

    def test_compromised_hosts_alert_far_more_often(self, topology):
        bad = ["ws-fin-01", "ws-fin-02", "ws-fin-03"]
        hits = {h: 0 for h in topology.host_ids()}
        for s in range(40):
            for a in emit_alerts(topology.host_ids(), bad, "ransomware", 30,
                                 random.Random(s)):
                hits[a.host_id] += 1
        mean_bad = sum(hits[h] for h in bad) / len(bad)
        mean_ok = (sum(hits[h] for h in hits if h not in bad) /
                   (len(hits) - len(bad)))
        assert mean_bad > 3 * mean_ok

    def test_benign_hosts_do_produce_false_positives(self, topology):
        """False positives must exist, otherwise the veto has nothing to guard."""
        fp = 0
        for s in range(30):
            fp += sum(1 for a in emit_alerts(topology.host_ids(), [], "ransomware",
                                             30, random.Random(s)))
        assert fp > 0

    def test_insider_threat_evades_high_fidelity_sensors(self, topology):
        bad = ["ws-fin-01"]
        hard = 0
        for s in range(40):
            hard += sum(1 for a in emit_alerts(topology.host_ids(), bad,
                                               "insider_threat", 120,
                                               random.Random(s))
                        if a.host_id in bad and a.is_hard)
        assert hard <= 8, "insider threat should rarely trip a high-fidelity sensor"

    def test_dwell_factor_saturates(self):
        assert dwell_factor(0) == pytest.approx(0.5)
        assert dwell_factor(60) == pytest.approx(1.0)
        assert dwell_factor(10_000) == pytest.approx(1.0)

    def test_alerts_are_reproducible(self, topology):
        a = emit_alerts(topology.host_ids(), ["ws-fin-01"], "ransomware", 30,
                        random.Random(7))
        b = emit_alerts(topology.host_ids(), ["ws-fin-01"], "ransomware", 30,
                        random.Random(7))
        assert [x.to_dict() for x in a] == [x.to_dict() for x in b]


class TestTelemetry:
    def test_every_host_gets_a_window(self, topology):
        tel = TelemetryGenerator(topology).generate([], "ransomware", random.Random(1))
        assert set(tel) == set(topology.host_ids())

    def test_baseline_corpus_size(self, topology):
        corpus = TelemetryGenerator(topology).generate_baseline_corpus(5, seed=1)
        assert len(corpus) == 5 * len(topology.hosts)

    def test_baseline_corpus_is_reproducible(self, topology):
        g = TelemetryGenerator(topology)
        a = [r.to_dict() for r in g.generate_baseline_corpus(3, seed=9)]
        b = [r.to_dict() for r in g.generate_baseline_corpus(3, seed=9)]
        assert a == b

    def test_all_counters_are_non_negative(self, topology):
        tel = TelemetryGenerator(topology).generate(["ws-fin-01"], "ransomware",
                                                    random.Random(2))
        for rec in tel.values():
            assert all(v >= 0 for v in rec.feature_vector())

    def test_ratio_fields_stay_bounded(self, topology):
        tel = TelemetryGenerator(topology).generate(["ws-fin-01"], "lateral_movement",
                                                    random.Random(2))
        for rec in tel.values():
            assert 0.0 <= rec.failed_auth_ratio <= 1.0
            assert 0.0 <= rec.new_peer_ratio <= 1.0
            assert 0.0 <= rec.off_hours_activity_ratio <= 1.0
            assert 0.0 <= rec.beacon_regularity <= 1.0


class TestScenarioGenerator:
    def test_batch_size_and_composition(self, generator):
        batch = generator.batch(n_each=5)
        assert len(batch) == 15
        for t in ATTACK_TYPES:
            assert sum(1 for s in batch if s.attack_type == t) == 5

    def test_canonical_suite_is_45_scenarios(self, generator):
        assert len(generator.batch(n_each=15)) == 45

    def test_scenario_ids_are_unique(self, generator):
        ids = [s.scenario_id for s in generator.batch(n_each=15)]
        assert len(set(ids)) == len(ids)

    def test_a_scenario_is_independent_of_batch_size(self, topology):
        """Regression: order-dependent RNG made scenario N depend on N-1."""
        g = ScenarioGenerator(topology, seed=2024)
        small = {s.scenario_id: s for s in g.batch(n_each=2)}
        large = {s.scenario_id: s for s in g.batch(n_each=15)}
        for sid in small:
            assert (small[sid].ground_truth_compromised ==
                    large[sid].ground_truth_compromised)

    def test_regenerating_one_scenario_is_identical(self, topology):
        a = ScenarioGenerator(topology, seed=2024).generate("X-001", "ransomware")
        b = ScenarioGenerator(topology, seed=2024).generate("X-001", "ransomware")
        assert a.to_dict(include_telemetry=True) == b.to_dict(include_telemetry=True)
        assert [e.to_dict() for e in a.alerts] == [e.to_dict() for e in b.alerts]

    def test_different_master_seeds_differ(self, topology):
        a = ScenarioGenerator(topology, seed=1).batch(n_each=5)
        b = ScenarioGenerator(topology, seed=2).batch(n_each=5)
        assert ([s.ground_truth_compromised for s in a] !=
                [s.ground_truth_compromised for s in b])

    def test_derive_seed_is_stable_and_distinct(self):
        assert derive_seed(1, "A") == derive_seed(1, "A")
        assert derive_seed(1, "A") != derive_seed(1, "B")
        assert derive_seed(1, "A") != derive_seed(2, "A")

    def test_unknown_attack_type_rejected(self, generator):
        with pytest.raises(ValueError, match="unknown attack type"):
            generator.generate("X", "definitely-not-an-attack")

    def test_ground_truth_includes_the_seed_hosts(self, generator):
        for s in generator.batch(n_each=3):
            assert set(s.seed_hosts) <= set(s.ground_truth_compromised)

    def test_seed_hosts_match_the_attack_type(self, topology, generator):
        for s in generator.batch(n_each=5):
            for h in s.seed_hosts:
                kind = topology.hosts[h].host_type
                if s.attack_type == "ransomware":
                    assert kind == "workstation"
                elif s.attack_type == "lateral_movement":
                    assert kind in ("web_server", "app_server", "jump_host")


class TestAssessmentFusion:
    def test_no_ml_leaves_every_risk_score_none(self, topology, generator):
        sc = generator.ransomware("A-001")
        ta = build_assessment(topology, sc.scenario_id, sc.attack_type,
                              sc.elapsed_minutes, sc.alerts, risks=None)
        assert all(a.risk_score is None for a in ta.hosts.values())

    def test_every_host_appears_in_the_assessment(self, topology, generator):
        sc = generator.ransomware("A-002")
        ta = build_assessment(topology, sc.scenario_id, sc.attack_type,
                              sc.elapsed_minutes, sc.alerts)
        assert set(ta.hosts) == set(topology.host_ids())

    def test_alerts_are_attached_to_the_right_hosts(self, topology, generator):
        sc = generator.lateral_movement("A-003")
        ta = build_assessment(topology, sc.scenario_id, sc.attack_type,
                              sc.elapsed_minutes, sc.alerts)
        for ev in sc.alerts:
            assert ev in ta.hosts[ev.host_id].evidence
