"""End-to-end AMCDS pipeline and the explainable decision trace.

    telemetry ─> ML risk ─┐
                          ├─> ThreatAssessment ─> 5 agents ─> negotiation
    sensor alerts ────────┘                                        │
                                                                   v
                       final plan <── CP-SAT <── NetworkX graph analysis

``AMCDSPipeline.run`` returns a :class:`ContainmentDecision` that records every
input and every intermediate step, and :meth:`ContainmentDecision.trace_host`
answers, for any single host, the question an incident responder actually asks:
*why is this machine on (or off) the isolation list?*
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

from .agents import NegotiationContext, default_agents
from .agents.base_agent import BaseAgent
from .detection.pipeline import build_assessment
from .evidence import ThreatAssessment
from .ml.risk_model import HostRiskModel
from .negotiation.protocol import NegotiationLog, NegotiationProtocol
from .network.topology import NetworkTopology
from .optimization.cpsat_solver import CPSATSolver
from .scenarios.generator import AttackScenario


@dataclass
class ContainmentDecision:
    """The full, auditable outcome of one AMCDS run."""

    scenario_id: str
    attack_type: str
    assessment: ThreatAssessment
    negotiation: NegotiationLog
    solver_result: dict
    isolate: Set[str] = field(default_factory=set)
    blast_before: dict = field(default_factory=dict)
    blast_after: dict = field(default_factory=dict)
    containment: dict = field(default_factory=dict)
    ml_enabled: bool = True
    runtime_seconds: float = 0.0

    # ------------------------------------------------------------- explaining
    def trace_host(self, host_id: str) -> dict:
        """Everything that happened to one host, in decision order."""
        ha = self.assessment.hosts.get(host_id)
        neg = self.negotiation
        proposals = {n: p for n, p in neg.proposals.items() if host_id in p.isolate}
        counters = {n: p for n, p in neg.counters.items() if host_id in p.isolate}
        objections = {c.agent_name: c.objections[host_id] for c in neg.critiques
                      if host_id in c.objections}
        endorsements = {c.agent_name: c.endorsements[host_id] for c in neg.critiques
                        if host_id in c.endorsements}
        vote = neg.votes.get(host_id)
        veto = neg.veto

        if host_id in self.isolate:
            outcome = "ISOLATED"
        elif veto and host_id in veto.vetoed:
            outcome = "VETOED"
        elif host_id in neg.final_isolate:
            outcome = "DROPPED_BY_OPTIMIZER"
        elif proposals:
            outcome = "REJECTED_IN_CONSENSUS"
        else:
            outcome = "NOT_PROPOSED"

        return {
            "host_id": host_id,
            "outcome": outcome,
            "evidence": ha.to_dict() if ha else None,
            "risk_score": None if ha is None else ha.risk_score,
            "graph": self._graph_context(host_id),
            "proposed_by": {n: p.why(host_id) for n, p in sorted(proposals.items())},
            "after_counter": sorted(counters),
            "objections": {k: objections[k] for k in sorted(objections)},
            "endorsements": {k: endorsements[k] for k in sorted(endorsements)},
            "veto": (veto.vetoed.get(host_id) or veto.overridden.get(host_id)
                     if veto else None),
            "vote": vote.to_dict() if vote else None,
            "optimizer": self._optimizer_note(host_id),
            "narrative": self._narrative(host_id, outcome, proposals, objections,
                                         vote, veto),
        }

    def _graph_context(self, host_id: str) -> dict:
        return self.blast_before.get("_per_host", {}).get(host_id, {})

    def _optimizer_note(self, host_id: str) -> Optional[str]:
        r = self.solver_result
        if host_id not in r.get("weights", {}):
            return None
        w = r["weights"][host_id]
        if host_id in self.isolate:
            return (f"CP-SAT kept it: leaving it online carried {w} residual-risk "
                    f"units against its share of the business cost")
        return (f"CP-SAT dropped it: only {w} residual-risk units, not worth the "
                f"service downtime it would cause")

    def _narrative(self, host_id: str, outcome: str, proposals: dict,
                   objections: dict, vote, veto) -> str:
        ha = self.assessment.hosts.get(host_id)
        bits = [f"{host_id}: {ha.why() if ha else 'no assessment'}."]
        if proposals:
            bits.append(f"Proposed for isolation by {', '.join(sorted(proposals))}.")
        else:
            bits.append("No agent proposed isolating it.")
        if objections:
            bits.append(f"Objected to by {', '.join(sorted(objections))}.")
        if veto and host_id in veto.vetoed:
            bits.append(f"FORMAL VETO — {veto.vetoed[host_id]}.")
        elif veto and host_id in veto.overridden:
            bits.append(f"Veto waived — {veto.overridden[host_id]}.")
        if vote is not None and vote.contested:
            bits.append(
                f"Contested: support {vote.support:.2f} vs opposition "
                f"{vote.opposition:.2f} (ratio {vote.support_ratio:.2f}) -> "
                f"{'kept' if vote.kept else 'dropped'}.")
        note = self._optimizer_note(host_id)
        if note:
            bits.append(note + ".")
        bits.append(f"Outcome: {outcome}.")
        return " ".join(bits)

    def summary(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "attack_type": self.attack_type,
            "ml_enabled": self.ml_enabled,
            "confirmed_hosts": sorted(self.assessment.confirmed_infected()),
            "suspected_hosts": sorted(self.assessment.suspected()),
            "n_candidates": len(self.negotiation.final_isolate),
            "isolate": sorted(self.isolate),
            "n_isolated": len(self.isolate),
            "agreement": round(self.negotiation.agreement, 4),
            "n_vetoed": len(self.negotiation.veto.vetoed) if self.negotiation.veto else 0,
            "business_cost_per_hour": self.solver_result.get("business_cost_per_hour", 0.0),
            "sla_breaches": self.solver_result.get("sla_breaches", []),
            "solver_status": self.solver_result.get("status"),
            "objective": self.solver_result.get("objective"),
            "containment": self.containment,
            "runtime_seconds": round(self.runtime_seconds, 6),
        }

    def to_dict(self, include_traces: bool = True) -> dict:
        d = {
            "summary": self.summary(),
            "assessment": self.assessment.to_dict(),
            "negotiation": self.negotiation.to_dict(),
            "solver": {k: (sorted(v) if isinstance(v, set) else v)
                       for k, v in self.solver_result.items()},
            "blast_before": {k: v for k, v in self.blast_before.items()
                             if k != "_per_host"},
            "blast_after": {k: v for k, v in self.blast_after.items()
                            if k != "_per_host"},
        }
        if include_traces:
            interesting = sorted(
                set(self.isolate)
                | set(self.negotiation.final_isolate)
                | set(self.negotiation.veto.vetoed if self.negotiation.veto else []))
            d["traces"] = [self.trace_host(h) for h in interesting]
        return d


class AMCDSPipeline:
    """Wires detection, negotiation and optimization into one callable."""

    def __init__(self, topology: NetworkTopology,
                 risk_model: Optional[HostRiskModel] = None,
                 agents: Optional[Sequence[BaseAgent]] = None,
                 solver: Optional[CPSATSolver] = None,
                 use_ml: bool = True) -> None:
        self.topology = topology
        self.risk_model = risk_model
        self.agents = list(agents) if agents is not None else default_agents()
        self.protocol = NegotiationProtocol(self.agents)
        self.solver = solver or CPSATSolver()
        self.use_ml = use_ml and risk_model is not None

    # ------------------------------------------------------------------- run
    def assess(self, scenario: AttackScenario) -> ThreatAssessment:
        """Detection only: alerts (+ ML risk) -> ThreatAssessment."""
        risks = None
        if self.use_ml and self.risk_model is not None:
            risks = self.risk_model.score(scenario.telemetry, self.topology)
        return build_assessment(
            self.topology, scenario.scenario_id, scenario.attack_type,
            scenario.elapsed_minutes, scenario.alerts, risks,
            scenario.ioc_evidence)

    def run(self, scenario: AttackScenario) -> ContainmentDecision:
        t0 = time.perf_counter()
        assessment = self.assess(scenario)
        ctx = NegotiationContext.build(self.topology, assessment)
        log = self.protocol.run(ctx)

        confirmed = sorted(ctx.confirmed)
        reach = (self.topology.attack_path_probabilities(confirmed)
                 if confirmed else {})
        result = self.solver.solve(
            self.topology, log.final_isolate, confirmed,
            reach=reach, risk_scores=assessment.risk_scores())
        isolate = set(result["isolate"])

        blast_before = self.topology.blast_radius(confirmed) if confirmed else {}
        if blast_before:
            blast_before["_per_host"] = {
                h: {"reach_probability": round(reach.get(h, 0.0), 4),
                    "criticality": self.topology.hosts[h].criticality,
                    "services": self.topology.services_on_host(h),
                    "sla_tier": self.topology.hosts[h].sla_tier,
                    "zone": self.topology.hosts[h].zone}
                for h in self.topology.host_ids()}
        containment = (self.topology.containment_value(isolate, confirmed)
                       if confirmed else {})
        blast_after = (self.topology.blast_radius(
            sorted(set(confirmed) - isolate)) if set(confirmed) - isolate else {})

        return ContainmentDecision(
            scenario_id=scenario.scenario_id,
            attack_type=scenario.attack_type,
            assessment=assessment,
            negotiation=log,
            solver_result=result,
            isolate=isolate,
            blast_before=blast_before,
            blast_after=blast_after,
            containment=containment,
            ml_enabled=self.use_ml,
            runtime_seconds=time.perf_counter() - t0,
        )
