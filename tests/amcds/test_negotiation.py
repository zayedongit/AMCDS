"""The five phases, conflict resolution, and the guarantees each phase gives."""
from __future__ import annotations

import pytest

from amcds.agents import (BusinessImpactAgent, DataAgent, EndpointAgent,
                          IdentityAgent, NetworkAgent, default_agents)
from amcds.agents.base_agent import AgentProposal, BaseAgent, Critique
from amcds.negotiation import NegotiationProtocol
from tests.amcds.test_agents import make_ctx

PHASES = ["PROPOSE", "CRITIQUE", "COUNTER", "VETO", "CONSENSUS"]


class TestProtocolShape:
    def test_all_five_phases_run_in_order(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        log = NegotiationProtocol(default_agents()).run(ctx)
        assert [p["phase"] for p in log.phases] == PHASES

    def test_rejects_two_veto_holders(self):
        with pytest.raises(ValueError, match="formal veto"):
            NegotiationProtocol([BusinessImpactAgent(), BusinessImpactAgent()])

    def test_rejects_an_empty_roster(self):
        with pytest.raises(ValueError):
            NegotiationProtocol([])

    def test_runs_without_a_veto_holder(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        log = NegotiationProtocol([IdentityAgent(), NetworkAgent()]).run(ctx)
        assert log.veto.agent_name == "none"

    def test_log_is_json_serialisable(self, topology):
        import json
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        log = NegotiationProtocol(default_agents()).run(ctx)
        assert json.loads(json.dumps(log.to_dict(), default=str))

    def test_negotiation_is_fast(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01", "app-prod-01"])
        log = NegotiationProtocol(default_agents()).run(ctx)
        assert log.elapsed_seconds < 5.0


class TestCritiquePhaseIsLoadBearing:
    """Regression guard: this phase used to be a no-op."""

    def test_every_ordered_pair_is_reviewed(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        log = NegotiationProtocol(default_agents()).run(ctx)
        n = len(default_agents())
        assert len(log.critiques) == n * (n - 1)
        pairs = {(c.agent_name, c.target_agent) for c in log.critiques}
        assert len(pairs) == n * (n - 1)

    def test_a_nobody_agrees_scenario_produces_objections(self, topology):
        # One proven host plus a quiet, unreachable, gold-tier host is exactly
        # the shape that makes several agents object.
        ctx = make_ctx(topology, hard=["ws-fin-01"],
                       risks={"db-prod-02": 0.999, "dc-01": 0.999})
        log = NegotiationProtocol(default_agents()).run(ctx)
        assert log.phase("CRITIQUE")["n_objections"] > 0

    def test_objections_carry_a_reason(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"], risks={"dc-01": 0.999})
        log = NegotiationProtocol(default_agents()).run(ctx)
        for c in log.critiques:
            for why in c.objections.values():
                assert len(why) > 20


class TestCounterPhase:
    def test_agents_actually_revise_under_pressure(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"],
                       risks={"dc-01": 0.999, "jump-01": 0.999})
        log = NegotiationProtocol(default_agents()).run(ctx)
        counter = log.phase("COUNTER")
        assert counter["total_conceded"] + counter["total_adopted"] > 0

    def test_hard_evidence_hosts_are_never_conceded(self, topology):
        class Contrarian(BaseAgent):
            name = "Contrarian"

            def propose(self, ctx):
                return AgentProposal(self.name)

            def critique(self, ctx, proposals):
                return [Critique(self.name, other,
                                 objections={h: "I object to everything, at length."
                                             for h in proposals[other].isolate})
                        for other in proposals if other != self.name]

        agents = default_agents() + [Contrarian(), Contrarian.__class__(
            "C2", (Contrarian,), {"name": "Contrarian2"})()]
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        log = NegotiationProtocol(agents).run(ctx)
        for name, p in log.counters.items():
            if "ws-fin-01" in log.proposals[name].isolate:
                assert "ws-fin-01" in p.isolate, f"{name} conceded proven evidence"

    def test_counter_reasoning_records_what_happened(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"])
        log = NegotiationProtocol(default_agents()).run(ctx)
        assert all("COUNTER:" in p.reasoning for p in log.counters.values())


class TestConsensusResolvesConflict:
    """Regression guard: the outcome used to be a plain set union."""

    def test_result_is_not_the_union_when_agents_disagree(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"],
                       risks={"db-prod-02": 0.999, "dc-01": 0.999,
                              "db-prod-03": 0.999})
        log = NegotiationProtocol(default_agents()).run(ctx)
        union = set().union(*[p.isolate for p in log.proposals.values()])
        assert log.final_isolate != union
        assert log.final_isolate <= union

    def test_a_lone_supporter_against_the_field_loses(self, topology):
        class Zealot(BaseAgent):
            """Refuses to concede, so the conflict must be settled by the vote
            rather than by the counter phase."""

            name = "Zealot"

            def propose(self, ctx):
                return AgentProposal(self.name, isolate={"ws-sls-06"},
                                     justification={"ws-sls-06": "because"},
                                     confidence=0.5)

            def counter(self, ctx, own, critiques, min_objections=2):
                return own

        ctx = make_ctx(topology, hard=["ws-fin-01"], risks={"ws-sls-06": 0.01})
        log = NegotiationProtocol(default_agents() + [Zealot()]).run(ctx)
        vote = log.votes.get("ws-sls-06")
        assert vote is not None and vote.contested
        assert vote.support_ratio < 0.5
        assert "ws-sls-06" not in log.final_isolate

    def test_hard_evidence_hosts_are_pinned_past_the_vote(self, topology):
        ctx = make_ctx(topology, hard=["db-prod-01"])
        log = NegotiationProtocol(default_agents()).run(ctx)
        assert log.votes["db-prod-01"].pinned is True
        assert "db-prod-01" in log.final_isolate

    def test_support_ratio_arithmetic(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"], risks={"dc-01": 0.99})
        log = NegotiationProtocol(default_agents()).run(ctx)
        for v in log.votes.values():
            total = v.support + v.opposition
            if total > 0:
                assert v.support_ratio == pytest.approx(v.support / total)
            assert v.kept == (v.pinned or v.support_ratio >= 0.5)

    def test_agreement_is_one_when_all_agents_match(self, topology):
        class Clone(BaseAgent):
            def __init__(self, name):
                self.name = name

            def propose(self, ctx):
                return AgentProposal(self.name, isolate={"ws-fin-01"},
                                     confidence=0.9)

        log = NegotiationProtocol([Clone("A"), Clone("B"), Clone("C")]).run(
            make_ctx(topology, hard=["ws-fin-01"]))
        assert log.agreement == pytest.approx(1.0)

    def test_agreement_is_zero_when_no_host_is_shared(self, topology):
        class Picky(BaseAgent):
            def __init__(self, name, host):
                self.name, self.host = name, host

            def propose(self, ctx):
                return AgentProposal(self.name, isolate={self.host}, confidence=0.9)

        log = NegotiationProtocol([Picky("A", "ws-fin-01"),
                                   Picky("B", "ws-eng-01")]).run(make_ctx(topology))
        assert log.agreement == pytest.approx(0.0)

    def test_vetoed_hosts_never_reach_the_vote(self, topology):
        gold = sorted(topology.service_deps["payments"])[0]
        ctx = make_ctx(topology, hard=["ws-fin-01"], risks={gold: 0.999})
        log = NegotiationProtocol(default_agents()).run(ctx)
        if gold in log.veto.vetoed:
            assert gold not in log.votes
            assert gold not in log.final_isolate


class TestDegenerateInputs:
    def test_no_evidence_at_all_yields_no_plan(self, topology):
        log = NegotiationProtocol(default_agents()).run(make_ctx(topology))
        assert log.final_isolate == set()

    def test_everything_compromised_still_terminates(self, topology):
        ctx = make_ctx(topology, hard=topology.host_ids())
        log = NegotiationProtocol(default_agents()).run(ctx)
        assert log.final_isolate == set(topology.host_ids())

    def test_repeated_runs_are_identical(self, topology):
        ctx = make_ctx(topology, hard=["ws-fin-01"], risks={"dc-01": 0.9})
        a = NegotiationProtocol(default_agents()).run(ctx)
        b = NegotiationProtocol(default_agents()).run(ctx)
        assert a.final_isolate == b.final_isolate
        assert a.to_dict()["votes"] == b.to_dict()["votes"]
