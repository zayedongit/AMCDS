"""Evaluation harness — compare AMCDS against two automated baselines.

Baselines
---------
AGGRESSIVE:    isolate every host within 3 hops of any infected host.
               (Standard SOAR playbook; security-first, ignores business cost.)
CONSERVATIVE:  isolate only confirmed infected hosts.
               (Wait-and-see; business-first, ignores risk.)
AMCDS:         5-agent negotiation + classical solver (or quantum on demand).

Metrics
-------
- residual_risk          : # hosts in ground_truth_spread NOT in isolated set
                           (lower is better)
- unnecessary_isolation  : # hosts isolated that were NOT in ground_truth_spread
                           (lower is better)
- revenue_impact         : ₹/hour of services taken down
- sla_breaches           : # gold-tier services broken
- response_time_seconds  : wall-clock for negotiation + solver
"""
from __future__ import annotations

import json
import os
import statistics
import time
from dataclasses import dataclass, field
from typing import Dict, List, Set

from ..agents import (
    BusinessImpactAgent,
    DataAgent,
    EndpointAgent,
    IdentityAgent,
    NetworkAgent,
)
from ..negotiation import NegotiationProtocol
from ..network.topology import NetworkTopology
from ..optimization import ClassicalSolver, QuantumSolver
from ..scenarios import AttackScenario


@dataclass
class ScenarioResult:
    scenario_id: str
    attack_type: str
    strategy: str
    isolated: List[str] = field(default_factory=list)
    residual_risk: int = 0
    unnecessary_isolation: int = 0
    revenue_impact: float = 0.0
    sla_breaches: List[str] = field(default_factory=list)
    response_time_seconds: float = 0.0

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _aggressive_baseline(topology: NetworkTopology,
                         scenario: AttackScenario) -> Set[str]:
    isolate = set(scenario.infected_hosts)
    frontier = set(scenario.infected_hosts)
    for _ in range(3):
        nxt = set()
        for h in frontier:
            for nbr in topology.neighbors(h):
                if nbr not in isolate:
                    nxt.add(nbr)
        isolate.update(nxt)
        frontier = nxt
    return isolate


def _conservative_baseline(topology: NetworkTopology,
                           scenario: AttackScenario) -> Set[str]:
    return set(scenario.infected_hosts)


def _amcds(topology: NetworkTopology, scenario: AttackScenario,
           use_quantum: bool = False) -> Set[str]:
    agents = [IdentityAgent(), NetworkAgent(),
              DataAgent(), EndpointAgent()]
    biz = BusinessImpactAgent()
    protocol = NegotiationProtocol(agents, biz)

    log = protocol.run(topology, scenario.to_dict())
    candidates = log.final_isolate

    solver = QuantumSolver() if use_quantum else ClassicalSolver()
    result = solver.solve(topology, candidates, set(scenario.infected_hosts))
    return result["isolate"]


def _metrics(topology: NetworkTopology, scenario: AttackScenario,
             isolated: Set[str], strategy: str,
             response_time: float) -> ScenarioResult:
    ground_truth = set(scenario.ground_truth_spread) | set(scenario.infected_hosts)
    residual = ground_truth - isolated
    unnecessary = isolated - ground_truth
    revenue = topology.revenue_impact_of_isolating(isolated)
    breaches = topology.sla_breaches(isolated)

    return ScenarioResult(
        scenario_id=scenario.scenario_id,
        attack_type=scenario.attack_type,
        strategy=strategy,
        isolated=sorted(isolated),
        residual_risk=len(residual),
        unnecessary_isolation=len(unnecessary),
        revenue_impact=revenue,
        sla_breaches=breaches,
        response_time_seconds=response_time,
    )


class EvaluationHarness:
    def __init__(self, topology: NetworkTopology) -> None:
        self.topology = topology

    def run(self, scenarios: List[AttackScenario], *,
            include_quantum: bool = False,
            quantum_sample: int = 10,
            verbose: bool = True) -> Dict:
        all_results: List[ScenarioResult] = []

        for i, sc in enumerate(scenarios):
            if verbose and i % 20 == 0:
                print(f"  scenario {i+1}/{len(scenarios)}  ({sc.scenario_id})")

            # AGGRESSIVE
            t0 = time.time()
            agg = _aggressive_baseline(self.topology, sc)
            all_results.append(_metrics(self.topology, sc, agg,
                                        "AGGRESSIVE", time.time() - t0))

            # CONSERVATIVE
            t0 = time.time()
            cons = _conservative_baseline(self.topology, sc)
            all_results.append(_metrics(self.topology, sc, cons,
                                        "CONSERVATIVE", time.time() - t0))

            # AMCDS (classical)
            t0 = time.time()
            amc = _amcds(self.topology, sc, use_quantum=False)
            all_results.append(_metrics(self.topology, sc, amc,
                                        "AMCDS_CLASSICAL", time.time() - t0))

            # AMCDS (quantum) — only on a sample to keep runtime reasonable
            if include_quantum and i < quantum_sample:
                t0 = time.time()
                amc_q = _amcds(self.topology, sc, use_quantum=True)
                all_results.append(_metrics(self.topology, sc, amc_q,
                                            "AMCDS_QUANTUM", time.time() - t0))

        return self._summarize(all_results)

    # ------------------------------------------------------- summary
    def _summarize(self, results: List[ScenarioResult]) -> Dict:
        by_strategy: Dict[str, List[ScenarioResult]] = {}
        for r in results:
            by_strategy.setdefault(r.strategy, []).append(r)

        summary = {}
        for strat, rs in by_strategy.items():
            summary[strat] = {
                "n_scenarios": len(rs),
                "avg_residual_risk": statistics.mean(r.residual_risk for r in rs),
                "avg_unnecessary_isolation": statistics.mean(r.unnecessary_isolation for r in rs),
                "avg_revenue_impact": statistics.mean(r.revenue_impact for r in rs),
                "avg_sla_breaches": statistics.mean(len(r.sla_breaches) for r in rs),
                "avg_response_time_seconds": statistics.mean(r.response_time_seconds for r in rs),
                "total_sla_breaches": sum(len(r.sla_breaches) for r in rs),
                "avg_isolated_hosts": statistics.mean(len(r.isolated) for r in rs),
            }

        # Headline: % reduction in unnecessary isolation vs AGGRESSIVE
        if "AGGRESSIVE" in summary and "AMCDS_CLASSICAL" in summary:
            agg = summary["AGGRESSIVE"]["avg_unnecessary_isolation"]
            amc = summary["AMCDS_CLASSICAL"]["avg_unnecessary_isolation"]
            if agg > 0:
                summary["_headline"] = {
                    "unnecessary_isolation_reduction_vs_aggressive_pct":
                        round((agg - amc) / agg * 100, 1),
                }

        return {
            "summary": summary,
            "results": [r.to_dict() for r in results],
        }

    @staticmethod
    def save(report: Dict, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(report, f, indent=2, default=str)
