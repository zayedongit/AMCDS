"""Benchmark metrics and the evaluation harness."""
from __future__ import annotations

import pytest

from amcds.evaluation import EvaluationHarness, aggregate, score
from amcds.evaluation.metrics import ScenarioResult
from amcds.attack.propagation import PropagationModel


class TestMetricDefinitions:
    def test_perfect_plan_scores_perfectly(self, topology, generator):
        sc = generator.ransomware("M-001")
        truth = set(sc.ground_truth_compromised)
        r = score(topology, PropagationModel(topology), sc, truth, "ORACLE", 0.0)
        assert r.unnecessary_shutdown == 0
        assert r.missed_threat == 0
        assert r.precision == 1.0 and r.recall == 1.0 and r.f1 == 1.0

    def test_empty_plan_misses_everything(self, topology, generator):
        sc = generator.ransomware("M-002")
        r = score(topology, PropagationModel(topology), sc, set(), "NONE", 0.0)
        assert r.unnecessary_shutdown == 0
        assert r.missed_threat == len(sc.ground_truth_compromised)
        assert r.recall == 0.0

    def test_isolating_everything_maximises_unnecessary_shutdown(self, topology,
                                                                 generator):
        sc = generator.ransomware("M-003")
        r = score(topology, PropagationModel(topology), sc,
                  set(topology.host_ids()), "ALL", 0.0)
        assert r.unnecessary_shutdown == (len(topology.hosts) -
                                          len(sc.ground_truth_compromised))
        assert r.recall == 1.0

    def test_unnecessary_plus_true_positive_equals_the_plan_size(self, topology,
                                                                 generator):
        sc = generator.lateral_movement("M-004")
        plan = set(sorted(topology.host_ids())[:10])
        r = score(topology, PropagationModel(topology), sc, plan, "X", 0.0)
        assert r.unnecessary_shutdown + r.true_positive == r.n_isolated

    def test_containing_everything_stops_the_spread(self, topology, generator):
        sc = generator.ransomware("M-005")
        r = score(topology, PropagationModel(topology), sc,
                  set(topology.host_ids()), "ALL", 0.0)
        assert r.post_containment_spread == 0
        assert r.contained is True

    def test_doing_nothing_lets_it_spread(self, topology, generator):
        """At least one scenario in the suite must show uncontained spread,
        otherwise the containment metric is measuring nothing."""
        prop = PropagationModel(topology)
        uncontained = sum(
            0 if score(topology, prop, sc, set(), "NONE", 0.0).contained else 1
            for sc in generator.batch(n_each=5))
        assert uncontained > 0

    def test_revenue_matches_the_topology_model(self, topology, generator):
        sc = generator.ransomware("M-006")
        plan = {"db-prod-01", "ws-fin-01"}
        r = score(topology, PropagationModel(topology), sc, plan, "X", 0.0)
        assert r.revenue_impact == topology.revenue_impact_of_isolating(plan)
        assert r.sla_breaches == topology.sla_breaches(plan)

    def test_metrics_are_deterministic(self, topology, generator):
        sc = generator.ransomware("M-007")
        prop = PropagationModel(topology)
        plan = {"ws-fin-01"}
        a = score(topology, prop, sc, plan, "X", 0.0)
        b = score(topology, prop, sc, plan, "X", 0.0)
        assert a.to_dict() == b.to_dict()


class TestAggregation:
    def _mk(self, **kw):
        base = dict(scenario_id="s", attack_type="ransomware", strategy="X",
                    n_ground_truth=4, n_isolated=4)
        base.update(kw)
        return ScenarioResult(**base)

    def test_empty_input(self):
        assert aggregate([]) == {}

    def test_means_and_totals(self):
        rs = [self._mk(unnecessary_shutdown=2), self._mk(unnecessary_shutdown=4)]
        agg = aggregate(rs)
        assert agg["n_scenarios"] == 2
        assert agg["avg_unnecessary_shutdown"] == 3.0
        assert agg["total_unnecessary_shutdown"] == 6

    def test_micro_average_is_not_the_mean_of_ratios(self):
        rs = [self._mk(true_positive=1, unnecessary_shutdown=0, missed_threat=0),
              self._mk(true_positive=1, unnecessary_shutdown=99, missed_threat=0)]
        agg = aggregate(rs)
        assert agg["micro_precision"] == pytest.approx(2 / 101)

    def test_containment_rate(self):
        rs = [self._mk(contained=True), self._mk(contained=False),
              self._mk(contained=True), self._mk(contained=True)]
        assert aggregate(rs)["containment_rate"] == 0.75


class TestHarness:
    @pytest.fixture(scope="class")
    @staticmethod
    def report(topology, risk_model, generator):
        return EvaluationHarness(topology, risk_model).run(
            generator.batch(n_each=2), verbose=False)

    def test_every_strategy_ran_on_every_scenario(self, report):
        n = report["config"]["n_scenarios"]
        for name, m in report["summary"].items():
            assert m["n_scenarios"] == n, name

    def test_all_six_strategies_present(self, report):
        expected = {"AGGRESSIVE_3HOP", "AGGRESSIVE_2HOP", "CONSERVATIVE",
                    "RISK_THRESHOLD", "AMCDS_NO_ML", "AMCDS"}
        assert expected <= set(report["summary"])

    def test_no_strategy_receives_ground_truth(self, topology, risk_model,
                                               generator):
        """The baselines must key on hard evidence, not on the true infected
        list. The original harness handed them ground truth."""
        h = EvaluationHarness(topology, risk_model)
        sc = generator.ransomware("FAIR")
        assert h._confirmed(sc) == h.pipeline_ml.assess(sc).confirmed_infected()
        assert h._conservative(sc) == h._confirmed(sc)
        # The 3-hop blanket keys on evidence, so it must be reachable-from-
        # evidence, not the true compromised set.
        assert h._hop_baseline(sc, 3) == topology.within_hops(
            sorted(h._confirmed(sc)), 3)

    def test_blanket_baselines_over_isolate(self, report):
        s = report["summary"]
        assert (s["AGGRESSIVE_3HOP"]["avg_unnecessary_shutdown"] >
                s["AMCDS"]["avg_unnecessary_shutdown"])
        assert (s["AGGRESSIVE_3HOP"]["avg_n_isolated"] >=
                s["AGGRESSIVE_2HOP"]["avg_n_isolated"])

    def test_conservative_misses_more_than_amcds(self, report):
        s = report["summary"]
        assert (s["CONSERVATIVE"]["avg_missed_threat"] >=
                s["AMCDS"]["avg_missed_threat"])

    def test_amcds_breaches_fewer_slas_than_the_blanket_baseline(self, report):
        s = report["summary"]
        assert (s["AMCDS"]["avg_n_sla_breaches"] <
                s["AGGRESSIVE_3HOP"]["avg_n_sla_breaches"])

    def test_headline_reductions_are_reported(self, report):
        assert report["headline"][
            "unnecessary_shutdown_reduction_vs_AGGRESSIVE_3HOP_pct"] is not None

    def test_per_attack_type_breakdown_exists(self, report):
        assert set(report["by_attack_type"]) == {"ransomware", "lateral_movement",
                                                 "insider_threat"}

    def test_config_records_the_setup(self, report):
        assert report["config"]["ml_enabled"] is True
        assert report["config"]["topology"]["n_hosts"] > 0

    def test_report_is_json_serialisable(self, report):
        import json
        assert json.loads(json.dumps(report, default=str))

    def test_harness_is_reproducible(self, topology, risk_model, generator):
        scs = generator.batch(n_each=2)
        a = EvaluationHarness(topology, risk_model).run(scs, verbose=False)
        b = EvaluationHarness(topology, risk_model).run(scs, verbose=False)
        assert ([r["isolated"] for r in a["results"]] ==
                [r["isolated"] for r in b["results"]])
