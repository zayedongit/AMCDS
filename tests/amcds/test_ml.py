"""Feature engineering, the risk model, and its evaluation metrics."""
from __future__ import annotations

import random

import numpy as np
import pandas as pd
import pytest

from amcds.config import ML_SUSPICIOUS_THRESHOLD
from amcds.detection.pipeline import ML_MAX_FIDELITY, ml_fidelity
from amcds.config import HARD_EVIDENCE_FIDELITY
from amcds.ml import evaluate_on_scenarios, evaluate_risk_scores
from amcds.ml.features import (MODEL_FEATURES, PeerGroupNormalizer,
                               build_raw_frame, graph_features,
                               top_contributing_features)
from amcds.ml.risk_model import HostRiskModel
from amcds.telemetry import TelemetryGenerator


class TestFeatures:
    def test_raw_frame_has_every_model_feature(self, topology):
        recs = TelemetryGenerator(topology).generate_baseline_corpus(2, seed=1)
        df = build_raw_frame(recs, topology)
        assert set(MODEL_FEATURES) <= set(df.columns)
        assert len(df) == 2 * len(topology.hosts)

    def test_derived_ratios_are_computed(self, topology):
        recs = TelemetryGenerator(topology).generate_baseline_corpus(1, seed=1)
        df = build_raw_frame(recs, topology)
        row = df.iloc[0]
        assert row["conn_per_peer"] == pytest.approx(
            row["outbound_connections"] / (row["distinct_peers"] + 1e-9), rel=1e-6)

    def test_graph_features_cover_every_host(self, topology):
        gf = graph_features(topology)
        assert sorted(gf["host_id"]) == topology.host_ids()
        assert (gf["degree"] > 0).all()

    def test_peer_group_normalisation_centres_each_host_type(self, topology):
        recs = TelemetryGenerator(topology).generate_baseline_corpus(40, seed=2)
        df = build_raw_frame(recs, topology)
        z = PeerGroupNormalizer().fit_transform(df)
        z["host_type"] = df["host_type"].values
        for _, group in z.groupby("host_type"):
            # Robust standardisation puts the per-type median at zero.
            assert abs(group["outbound_connections"].median()) < 0.2

    def test_normalisation_is_relative_to_the_peer_group(self, topology):
        """A busy workstation is anomalous; an equally busy web server is not."""
        recs = TelemetryGenerator(topology).generate_baseline_corpus(40, seed=3)
        df = build_raw_frame(recs, topology)
        norm = PeerGroupNormalizer().fit(df)
        probe = df[df["host_type"].isin(["workstation", "web_server"])].head(2).copy()
        probe = probe.reset_index(drop=True)
        probe.loc[:, "outbound_connections"] = 1400.0
        probe.loc[0, "host_type"] = "workstation"
        probe.loc[1, "host_type"] = "web_server"
        z = norm.transform(probe)
        assert z.loc[0, "outbound_connections"] > z.loc[1, "outbound_connections"]

    def test_transform_before_fit_raises(self):
        with pytest.raises(RuntimeError):
            PeerGroupNormalizer().transform(pd.DataFrame())

    def test_top_contributors_are_positive_and_ranked(self):
        row = pd.Series({"a": 4.0, "b": -9.0, "c": 1.0, "d": 7.0})
        top = top_contributing_features(row, k=3)
        assert [n for n, _ in top] == ["d", "a", "c"]
        assert all(v > 0 for _, v in top)

    def test_no_positive_deviation_gives_no_drivers(self):
        assert top_contributing_features(pd.Series({"a": -1.0})) == []


class TestRiskModel:
    def test_score_before_fit_raises(self, topology):
        with pytest.raises(RuntimeError):
            HostRiskModel().score({}, topology)

    def test_empty_baseline_rejected(self, topology):
        with pytest.raises(ValueError):
            HostRiskModel().fit([], topology)

    def test_scores_every_host_in_range(self, topology, risk_model):
        tel = TelemetryGenerator(topology).generate([], "ransomware", random.Random(1))
        risks = risk_model.score(tel, topology)
        assert set(risks) == set(topology.host_ids())
        assert all(0.0 <= r.risk_score <= 1.0 for r in risks.values())

    def test_scoring_is_deterministic(self, topology, risk_model):
        tel = TelemetryGenerator(topology).generate(
            ["ws-fin-01"], "ransomware", random.Random(4))
        a = risk_model.score(tel, topology)
        b = risk_model.score(tel, topology)
        assert {h: r.risk_score for h, r in a.items()} == \
               {h: r.risk_score for h, r in b.items()}

    def test_benign_scores_are_roughly_uniform(self, topology, risk_model):
        """Calibration claim: on clean traffic the score is the benign
        percentile, so a threshold equals the nominal false-positive rate."""
        gen = TelemetryGenerator(topology)
        scores = []
        for i in range(25):
            tel = gen.generate([], "ransomware", random.Random(500 + i))
            scores.extend(r.risk_score for r in risk_model.score(tel, topology).values())
        flagged = np.mean([s >= ML_SUSPICIOUS_THRESHOLD for s in scores])
        assert flagged == pytest.approx(1 - ML_SUSPICIOUS_THRESHOLD, abs=0.08)

    def test_compromised_hosts_score_higher_than_benign(self, topology, risk_model):
        gen = TelemetryGenerator(topology)
        bad = ["ws-fin-01", "ws-fin-02", "ws-fin-03"]
        hits, total = 0, 0
        for i in range(10):
            tel = gen.generate(bad, "lateral_movement", random.Random(800 + i))
            risks = risk_model.score(tel, topology)
            mean_bad = np.mean([risks[h].risk_score for h in bad])
            mean_ok = np.mean([risks[h].risk_score for h in topology.host_ids()
                               if h not in bad])
            hits += mean_bad > mean_ok
            total += 1
        assert hits >= total - 1

    def test_drivers_explain_the_score(self, topology, risk_model):
        gen = TelemetryGenerator(topology)
        tel = gen.generate(["ws-fin-01"], "ransomware", random.Random(11))
        risks = risk_model.score(tel, topology)
        top = max(risks.values(), key=lambda r: r.risk_score)
        assert top.drivers
        assert all(name in MODEL_FEATURES for name, _ in top.drivers)
        assert "risk" in top.explanation()

    def test_describe_reports_the_configuration(self, risk_model):
        d = risk_model.describe()
        assert d["model"] == "IsolationForest"
        assert d["n_features"] == len(MODEL_FEATURES)
        assert d["n_training_windows"] > 0


class TestMLFidelityCap:
    def test_ml_never_reaches_hard_evidence(self):
        assert ML_MAX_FIDELITY < HARD_EVIDENCE_FIDELITY
        assert ml_fidelity(1.0) < HARD_EVIDENCE_FIDELITY

    def test_below_threshold_emits_nothing(self):
        assert ml_fidelity(ML_SUSPICIOUS_THRESHOLD - 0.01) == 0.0

    def test_fidelity_increases_with_risk(self):
        assert ml_fidelity(0.99) > ml_fidelity(0.92)


class TestEvaluationMetrics:
    def test_perfect_ranking_scores_one(self):
        rep = evaluate_risk_scores([0, 0, 1, 1], [0.1, 0.2, 0.95, 0.99])
        assert rep.roc_auc == 1.0
        assert rep.recall == 1.0
        assert rep.precision == 1.0

    def test_single_class_is_rejected(self):
        with pytest.raises(ValueError):
            evaluate_risk_scores([0, 0, 0], [0.1, 0.2, 0.3])

    def test_mismatched_lengths_rejected(self):
        with pytest.raises(ValueError):
            evaluate_risk_scores([0, 1], [0.5])

    def test_base_rate_and_confusion_are_consistent(self):
        rep = evaluate_risk_scores([0, 1, 1, 0], [0.1, 0.95, 0.3, 0.2])
        assert rep.base_rate == pytest.approx(0.5)
        assert rep.tp + rep.fn == rep.n_positive
        assert rep.tn + rep.fp + rep.fn + rep.tp == rep.n_samples

    def test_pr_auc_beats_the_base_rate_on_real_scenarios(self, topology, risk_model,
                                                          scenarios):
        rep, per = evaluate_on_scenarios(risk_model, topology, scenarios)
        assert rep.pr_auc > rep.base_rate * 2
        assert rep.roc_auc > 0.75
        assert len(per) == len(scenarios)

    def test_recall_at_fpr_budgets_is_monotone(self, topology, risk_model, scenarios):
        rep, _ = evaluate_on_scenarios(risk_model, topology, scenarios)
        r = rep.recall_at_fpr
        assert r["0.01"] <= r["0.05"] <= r["0.10"]
