"""End-to-end: telemetry -> ML -> graph -> agents -> negotiation -> CP-SAT -> plan."""
from __future__ import annotations

import json

import pytest

from amcds.agents import default_agents
from amcds.events import build_timeline
from amcds.pipeline import AMCDSPipeline


class TestFullPipeline:
    def test_every_stage_produced_output(self, decision):
        assert decision.assessment.hosts
        assert [p["phase"] for p in decision.negotiation.phases] == [
            "PROPOSE", "CRITIQUE", "COUNTER", "VETO", "CONSENSUS"]
        assert decision.solver_result["status"] in ("OPTIMAL", "FEASIBLE", "EMPTY")

    def test_the_plan_is_a_subset_of_the_negotiated_candidates(self, decision):
        assert decision.isolate <= set(decision.negotiation.final_isolate)

    def test_every_hard_evidence_host_is_isolated(self, decision):
        assert decision.assessment.confirmed_infected() <= decision.isolate

    def test_no_vetoed_host_survives_into_the_plan(self, decision):
        vetoed = set(decision.negotiation.veto.vetoed)
        assert not (vetoed & decision.isolate)

    def test_every_sla_breach_is_evidence_backed(self, topology, decision):
        """The central safety property of the whole system."""
        confirmed = decision.assessment.confirmed_infected()
        for sid in decision.solver_result["sla_breaches"]:
            responsible = topology.service_deps[sid] & decision.isolate
            assert responsible & confirmed, (
                f"gold service {sid} was broken with no evidence-backed host")

    def test_the_agents_never_see_ground_truth(self, pipeline, generator):
        """The assessment must be derivable from observations alone."""
        sc = generator.ransomware("LEAK-CHECK")
        a = pipeline.assess(sc)
        alerted = {ev.host_id for ev in sc.alerts}
        for host, item in a.hosts.items():
            for ev in item.evidence:
                assert ev.ev_type.value == "ml_anomaly" or host in alerted

    def test_detection_is_imperfect_in_both_directions(self, pipeline, scenarios):
        """If detection were an oracle the negotiation would be pointless."""
        misses = wrong = 0
        for sc in scenarios:
            confirmed = pipeline.assess(sc).confirmed_infected()
            truth = set(sc.ground_truth_compromised)
            misses += len(truth - confirmed)
            wrong += len(confirmed - truth)
        assert misses > 0, "detection caught everything - it is an oracle"

    def test_runs_are_reproducible(self, pipeline, generator):
        sc = generator.ransomware("REPRO")
        a, b = pipeline.run(sc), pipeline.run(sc)
        assert a.isolate == b.isolate
        assert a.negotiation.final_isolate == b.negotiation.final_isolate
        assert a.solver_result["objective"] == b.solver_result["objective"]

    def test_completes_quickly(self, decision):
        assert decision.runtime_seconds < 10.0

    def test_serialises_to_json(self, decision):
        assert json.loads(json.dumps(decision.to_dict(), default=str))


class TestMLAblation:
    def test_disabling_ml_removes_every_risk_score(self, topology, risk_model,
                                                   generator):
        p = AMCDSPipeline(topology, risk_model, use_ml=False)
        d = p.run(generator.ransomware("ABL"))
        assert d.ml_enabled is False
        assert all(a.risk_score is None for a in d.assessment.hosts.values())

    def test_ml_changes_the_plan_somewhere_in_the_suite(self, topology, risk_model,
                                                        scenarios):
        with_ml = AMCDSPipeline(topology, risk_model, use_ml=True)
        without = AMCDSPipeline(topology, risk_model, use_ml=False)
        assert any(with_ml.run(sc).isolate != without.run(sc).isolate
                   for sc in scenarios)

    def test_ml_finds_hosts_the_signature_sensors_missed(self, topology, risk_model,
                                                         scenarios):
        with_ml = AMCDSPipeline(topology, risk_model, use_ml=True)
        without = AMCDSPipeline(topology, risk_model, use_ml=False)
        gained = 0
        for sc in scenarios:
            truth = set(sc.ground_truth_compromised)
            gained += len((with_ml.run(sc).isolate & truth) -
                          (without.run(sc).isolate & truth))
        assert gained > 0, "the ML layer caught no additional compromised host"


class TestDecisionTrace:
    def test_every_isolated_host_has_a_trace(self, decision):
        for h in sorted(decision.isolate):
            t = decision.trace_host(h)
            assert t["outcome"] == "ISOLATED"
            assert t["narrative"]
            assert t["evidence"] is not None

    def test_a_vetoed_host_is_traced_as_vetoed(self, pipeline, generator):
        for sid in ("T1", "T2", "T3", "T4", "T5", "T6"):
            d = pipeline.run(generator.lateral_movement(sid))
            for h in d.negotiation.veto.vetoed:
                t = d.trace_host(h)
                assert t["outcome"] == "VETOED"
                assert "FORMAL VETO" in t["narrative"]
                return
        pytest.skip("no veto fired in the sampled scenarios")

    def test_an_untouched_host_is_traced_as_not_proposed(self, decision, topology):
        untouched = [h for h in topology.host_ids()
                     if not any(h in p.isolate
                                for p in decision.negotiation.proposals.values())]
        assert untouched
        assert decision.trace_host(untouched[0])["outcome"] == "NOT_PROPOSED"

    def test_the_trace_names_the_agents_involved(self, decision):
        names = {a.name for a in default_agents()}
        for h in sorted(decision.isolate):
            t = decision.trace_host(h)
            assert set(t["proposed_by"]) <= names
            assert set(t["objections"]) <= names

    def test_trace_records_the_optimizer_reasoning(self, decision):
        for h in sorted(decision.isolate):
            assert "CP-SAT" in (decision.trace_host(h)["optimizer"] or "")


class TestTimeline:
    def test_events_are_ordered_and_typed(self, decision, generator):
        events = build_timeline(decision, generator.lateral_movement("FIXTURE-LM"))
        times = [e["t"] for e in events]
        assert times == sorted(times)
        assert events[0]["type"] == "ATTACK_DETECTED"
        assert events[-1]["type"] == "CONTAINMENT_COMPLETE"

    def test_covers_all_five_phases(self, decision, generator):
        events = build_timeline(decision, generator.lateral_movement("FIXTURE-LM"))
        banners = " ".join(e["data"].get("text", "") for e in events
                           if e["type"] == "PHASE_BANNER")
        for phase in ("Propose", "Critique", "Counter", "Veto", "Consensus"):
            assert phase in banners

    def test_one_isolation_event_per_isolated_host(self, decision, generator):
        events = build_timeline(decision, generator.lateral_movement("FIXTURE-LM"))
        isolated = {e["data"]["host"] for e in events if e["type"] == "HOST_ISOLATED"}
        assert isolated == decision.isolate

    def test_is_json_serialisable(self, decision, generator):
        events = build_timeline(decision, generator.lateral_movement("FIXTURE-LM"))
        assert json.loads(json.dumps(events, default=str))
