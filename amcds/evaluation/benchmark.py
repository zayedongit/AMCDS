"""Reproducible benchmark: AMCDS against baselines and against itself.

Strategies compared
-------------------
``AGGRESSIVE_3HOP``   isolate every host within 3 network hops of any host with
                      hard evidence. The classic blanket SOAR playbook and the
                      baseline the headline reduction is measured against.
``AGGRESSIVE_2HOP``   the same idea with a tighter radius — a fairer, stronger
                      version of the blanket approach.
``CONSERVATIVE``      isolate only hosts with hard evidence. Business-first.
``RISK_THRESHOLD``    isolate every host whose ML risk score clears the
                      suspicious threshold. This is the **ML-only ablation**: no
                      agents, no negotiation, no optimizer. It answers "does the
                      multi-agent layer add anything over just running the model?"
``AMCDS_NO_ML``       the full pipeline with the risk model switched off, so the
                      agents see signature alerts only. The **agent-only ablation**.
``AMCDS``             the full pipeline.
``AMCDS_ANNEALING``   the full pipeline with the QUBO annealer replacing CP-SAT
                      (optional; measures what a metaheuristic costs).

Fairness
--------
Every strategy — baselines included — sees exactly the same observable inputs:
hosts with hard evidence and, where applicable, the ML risk scores. None of them
gets the ground-truth compromised set. The original harness handed the aggressive
baseline the true infected list, which made the comparison meaningless.
"""
from __future__ import annotations

import json
import os
import time
from typing import Callable, Dict, List, Optional, Sequence, Set

from ..attack.propagation import PropagationModel
from ..config import ML_SUSPICIOUS_THRESHOLD
from ..ml.risk_model import HostRiskModel
from ..network.topology import NetworkTopology
from ..optimization.annealing_solver import AnnealingSolver
from ..pipeline import AMCDSPipeline
from ..scenarios.generator import AttackScenario
from .metrics import ScenarioResult, aggregate, score

#: Order matters only for presentation.
BASELINE_STRATEGIES = ("AGGRESSIVE_3HOP", "AGGRESSIVE_2HOP", "CONSERVATIVE",
                       "RISK_THRESHOLD")
AMCDS_STRATEGIES = ("AMCDS_NO_ML", "AMCDS")


class EvaluationHarness:
    """Runs every strategy over every scenario and aggregates the results."""

    def __init__(self, topology: NetworkTopology,
                 risk_model: Optional[HostRiskModel] = None) -> None:
        self.topology = topology
        self.risk_model = risk_model
        self.propagation = PropagationModel(topology)
        self.pipeline_ml = AMCDSPipeline(topology, risk_model, use_ml=True)
        self.pipeline_no_ml = AMCDSPipeline(topology, risk_model, use_ml=False)
        # Detection is shared infrastructure, not part of any one strategy, so it
        # is computed once per scenario and cached. Otherwise every baseline
        # would be charged for re-running the risk model and the reported
        # runtimes would be meaningless.
        self._assessment_cache: Dict[str, object] = {}
        self._risk_cache: Dict[str, dict] = {}

    # ------------------------------------------------------------- baselines
    def _hop_baseline(self, scenario: AttackScenario, hops: int) -> Set[str]:
        confirmed = self._confirmed(scenario)
        if not confirmed:
            return set()
        return self.topology.within_hops(sorted(confirmed), hops)

    def _conservative(self, scenario: AttackScenario) -> Set[str]:
        return self._confirmed(scenario)

    def _risk_threshold(self, scenario: AttackScenario) -> Set[str]:
        confirmed = self._confirmed(scenario)
        if self.risk_model is None:
            return confirmed
        risks = self._risk_cache.get(scenario.scenario_id)
        if risks is None:
            risks = self.risk_model.score(scenario.telemetry, self.topology)
            self._risk_cache[scenario.scenario_id] = risks
        flagged = {h for h, r in risks.items()
                   if r.risk_score >= ML_SUSPICIOUS_THRESHOLD}
        return flagged | confirmed

    def _confirmed(self, scenario: AttackScenario) -> Set[str]:
        """Hosts with hard evidence — the only thing a baseline may key on."""
        assessment = self._assessment_cache.get(scenario.scenario_id)
        if assessment is None:
            assessment = self.pipeline_ml.assess(scenario)
            self._assessment_cache[scenario.scenario_id] = assessment
        return assessment.confirmed_infected()

    def prewarm(self, scenario: AttackScenario) -> None:
        """Populate the detection caches before any strategy is timed."""
        self._confirmed(scenario)
        self._risk_threshold(scenario)

    # ------------------------------------------------------------------- run
    def run(self, scenarios: Sequence[AttackScenario], *,
            include_annealing: bool = False,
            annealing_sample: int = 10,
            verbose: bool = True) -> Dict:
        results: List[ScenarioResult] = []
        traces: List[dict] = []

        strategies: Dict[str, Callable[[AttackScenario], Set[str]]] = {
            "AGGRESSIVE_3HOP": lambda sc: self._hop_baseline(sc, 3),
            "AGGRESSIVE_2HOP": lambda sc: self._hop_baseline(sc, 2),
            "CONSERVATIVE": self._conservative,
            "RISK_THRESHOLD": self._risk_threshold,
        }

        for i, sc in enumerate(scenarios):
            if verbose and (i % 10 == 0 or i == len(scenarios) - 1):
                print(f"    scenario {i+1}/{len(scenarios)}  {sc.scenario_id} "
                      f"({sc.attack_type})", flush=True)

            self.prewarm(sc)
            for name, fn in strategies.items():
                t0 = time.perf_counter()
                plan = fn(sc)
                results.append(score(self.topology, self.propagation, sc, plan,
                                     name, time.perf_counter() - t0))

            decision_no_ml = self.pipeline_no_ml.run(sc)
            results.append(score(self.topology, self.propagation, sc,
                                 decision_no_ml.isolate, "AMCDS_NO_ML",
                                 decision_no_ml.runtime_seconds))

            decision = self.pipeline_ml.run(sc)
            results.append(score(self.topology, self.propagation, sc,
                                 decision.isolate, "AMCDS",
                                 decision.runtime_seconds))
            traces.append(decision.summary())

            if include_annealing and i < annealing_sample:
                t0 = time.perf_counter()
                plan = self._annealing_plan(decision)
                results.append(score(self.topology, self.propagation, sc, plan,
                                     "AMCDS_ANNEALING", time.perf_counter() - t0))

        return self._report(results, traces, scenarios)

    def _annealing_plan(self, decision) -> Set[str]:
        confirmed = sorted(decision.assessment.confirmed_infected())
        reach = (self.topology.attack_path_probabilities(confirmed)
                 if confirmed else {})
        out = AnnealingSolver().solve(
            self.topology, decision.negotiation.final_isolate, confirmed,
            reach=reach, risk_scores=decision.assessment.risk_scores())
        return set(out["isolate"])

    # -------------------------------------------------------------- reporting
    def _report(self, results: Sequence[ScenarioResult], traces: List[dict],
                scenarios: Sequence[AttackScenario]) -> Dict:
        by_strategy: Dict[str, List[ScenarioResult]] = {}
        for r in results:
            by_strategy.setdefault(r.strategy, []).append(r)

        summary = {name: aggregate(rs) for name, rs in sorted(by_strategy.items())}

        # Per-attack-type breakdown for AMCDS, so a weak category cannot hide
        # inside the average.
        by_type: Dict[str, Dict[str, dict]] = {}
        for name, rs in sorted(by_strategy.items()):
            for attack_type in sorted({r.attack_type for r in rs}):
                subset = [r for r in rs if r.attack_type == attack_type]
                by_type.setdefault(attack_type, {})[name] = aggregate(subset)

        headline = {}
        for baseline in BASELINE_STRATEGIES:
            if baseline not in summary or "AMCDS" not in summary:
                continue
            b = summary[baseline]["avg_unnecessary_shutdown"]
            a = summary["AMCDS"]["avg_unnecessary_shutdown"]
            headline[f"unnecessary_shutdown_reduction_vs_{baseline}_pct"] = (
                round((b - a) / b * 100, 1) if b > 0 else None)
        if "AMCDS_NO_ML" in summary and "AMCDS" in summary:
            b = summary["AMCDS_NO_ML"]["avg_unnecessary_shutdown"]
            a = summary["AMCDS"]["avg_unnecessary_shutdown"]
            headline["unnecessary_shutdown_reduction_vs_AMCDS_NO_ML_pct"] = (
                round((b - a) / b * 100, 1) if b > 0 else None)

        return {
            "config": {
                "n_scenarios": len(scenarios),
                "scenarios_by_type": {
                    t: sum(1 for s in scenarios if s.attack_type == t)
                    for t in sorted({s.attack_type for s in scenarios})},
                "topology": self.topology.summary(),
                "ml_enabled": self.risk_model is not None,
                "risk_threshold": ML_SUSPICIOUS_THRESHOLD,
            },
            "summary": summary,
            "by_attack_type": by_type,
            "headline": headline,
            "amcds_decisions": traces,
            "results": [r.to_dict() for r in results],
        }

    # ------------------------------------------------------------------- io
    @staticmethod
    def save(report: Dict, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(report, f, indent=2, default=str)

    @staticmethod
    def print_summary(report: Dict) -> None:
        order = list(BASELINE_STRATEGIES) + list(AMCDS_STRATEGIES) + ["AMCDS_ANNEALING"]
        rows = [s for s in order if s in report["summary"]]
        header = (f"  {'strategy':<18}{'unnec':>7}{'missed':>8}{'isolated':>10}"
                  f"{'prec':>7}{'recall':>8}{'F1':>7}{'INR L/hr':>10}"
                  f"{'SLA':>6}{'contain':>9}{'ms':>8}")
        print(header)
        print("  " + "-" * (len(header) - 2))
        for s in rows:
            m = report["summary"][s]
            print(f"  {s:<18}"
                  f"{m['avg_unnecessary_shutdown']:>7.2f}"
                  f"{m['avg_missed_threat']:>8.2f}"
                  f"{m['avg_n_isolated']:>10.2f}"
                  f"{m['micro_precision']:>7.3f}"
                  f"{m['micro_recall']:>8.3f}"
                  f"{m['micro_f1']:>7.3f}"
                  f"{m['avg_revenue_impact']/1e5:>10.1f}"
                  f"{m['avg_n_sla_breaches']:>6.2f}"
                  f"{m['containment_rate']:>9.2f}"
                  f"{m['avg_runtime_seconds']*1000:>8.1f}")
        print()
        for k, v in sorted(report["headline"].items()):
            if v is not None:
                print(f"  {k}: {v}%")
