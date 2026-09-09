#!/usr/bin/env python3
"""AMCDS demo — runs the whole pipeline and writes the dashboard report.

    python run_demo.py                     # walkthrough + 45-scenario benchmark
    python run_demo.py --no-benchmark      # walkthrough only (fast)
    python run_demo.py --per-type 30       # 90-scenario benchmark

Writes ``results/demo_report.json``, which ``serve.py`` and the dashboard read.
Everything is seeded; see ``scripts/run_benchmark.py`` for the benchmark on its
own with the seeds printed.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from amcds.config import DEFAULT_BENCHMARK_SEED, DEFAULT_TOPOLOGY_SEED
from amcds.evaluation import EvaluationHarness
from amcds.events import build_timeline
from amcds.ml import evaluate_on_scenarios, train_default_model
from amcds.network import build_segmented_enterprise
from amcds.pipeline import AMCDSPipeline
from amcds.scenarios import ScenarioGenerator

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(HERE, "results")


def banner(text: str) -> None:
    line = "=" * 76
    print(f"\n{line}\n  {text}\n{line}")


def walkthrough(pipeline: AMCDSPipeline, scenario) -> dict:
    """Run one scenario end to end and print a readable narration."""
    print(f"\n--- {scenario.scenario_id} ({scenario.attack_type}, "
          f"{scenario.elapsed_minutes} min dwell) ---")
    print(f"  seeded on            {scenario.seed_hosts}")
    print(f"  ground truth spread  {len(scenario.ground_truth_compromised)} host(s) "
          f"[evaluation only — the agents never see this]")

    decision = pipeline.run(scenario)
    a = decision.assessment
    log = decision.negotiation

    print(f"  detection            {len(a.confirmed_infected())} confirmed "
          f"(hard evidence), {len(a.suspected())} suspected")
    propose = log.phase("PROPOSE")
    print(f"  PROPOSE              union {propose['n_union']}, unanimous "
          f"{propose['n_unanimous']} -> disagreement {propose['initial_disagreement']}")
    critique = log.phase("CRITIQUE")
    print(f"  CRITIQUE             {critique['n_objections']} objection(s), "
          f"{critique['n_additions']} addition(s) across "
          f"{critique['n_critiques']} peer reviews")
    counter = log.phase("COUNTER")
    print(f"  COUNTER              {counter['total_conceded']} conceded, "
          f"{counter['total_adopted']} adopted")
    veto = log.phase("VETO")
    print(f"  VETO                 {veto['n_vetoed']} vetoed, "
          f"{veto['n_overridden']} waived on hard evidence")
    for host, why in sorted((log.veto.vetoed if log.veto else {}).items()):
        print(f"      x {host}: {why}")
    consensus = log.phase("CONSENSUS")
    print(f"  CONSENSUS            {consensus['n_final']} candidate(s); "
          f"{consensus['n_contested']} contested; agreement {log.agreement:.2f}")
    r = decision.solver_result
    print(f"  CP-SAT               {r['status']} in {r['runtime_seconds']*1000:.1f} ms "
          f"-> {len(decision.isolate)} host(s), INR "
          f"{r['business_cost_per_hour']/1e5:.1f}L/hour, "
          f"{len(r['sla_breaches'])} gold-SLA breach(es)")
    if decision.containment:
        print(f"  containment          attack surface "
              f"{decision.containment['surface_before']} -> "
              f"{decision.containment['surface_after']} "
              f"({decision.containment['reduction_pct']:.0f}% reduction)")

    timeline = build_timeline(decision, scenario)
    return {
        "scenario": scenario.to_dict(),
        "decision": decision.to_dict(include_traces=True),
        "timeline": timeline,
        "timeline_duration_ms": timeline[-1]["t"] if timeline else 0,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-type", type=int, default=15,
                    help="benchmark scenarios per attack type (default 15 -> 45)")
    ap.add_argument("--no-benchmark", action="store_true")
    ap.add_argument("--no-ml", action="store_true",
                    help="disable the risk model (agents see signature alerts only)")
    ap.add_argument("--topology-seed", type=int, default=DEFAULT_TOPOLOGY_SEED)
    ap.add_argument("--seed", type=int, default=DEFAULT_BENCHMARK_SEED)
    ap.add_argument("--ml-seed", type=int, default=1234)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    os.makedirs(RESULTS_DIR, exist_ok=True)
    out_path = args.out or os.path.join(RESULTS_DIR, "demo_report.json")

    banner("AMCDS — Autonomous Multi-Agent Cyber Defense System")
    topology = build_segmented_enterprise(seed=args.topology_seed)
    print(f"  topology  {json.dumps(topology.summary())}")

    risk_model = None
    if not args.no_ml:
        print("  training the host-risk model on attack-free telemetry…", flush=True)
        risk_model = train_default_model(topology, n_windows=60, seed=args.ml_seed)
        print(f"  risk model {json.dumps(risk_model.describe()['model'])} on "
              f"{risk_model.describe()['n_features']} features, "
              f"{risk_model.describe()['n_training_windows']} training windows")

    pipeline = AMCDSPipeline(topology, risk_model, use_ml=not args.no_ml)
    gen = ScenarioGenerator(topology, seed=args.seed)

    banner("WALKTHROUGH — one scenario per attack category")
    walk = [walkthrough(pipeline, gen.ransomware("DEMO-RW")),
            walkthrough(pipeline, gen.lateral_movement("DEMO-LM")),
            walkthrough(pipeline, gen.insider_threat("DEMO-IT"))]

    bench_report = None
    ml_report = None
    if not args.no_benchmark:
        scenarios = gen.batch(n_each=args.per_type)
        if risk_model is not None:
            banner("ML RISK MODEL — evaluated independently")
            ml_report, _ = evaluate_on_scenarios(risk_model, topology, scenarios)
            print(ml_report.pretty())

        banner(f"BENCHMARK — {len(scenarios)} scenarios, "
               f"{args.per_type} per attack type")
        harness = EvaluationHarness(topology, risk_model)
        bench_report = harness.run(scenarios, verbose=False)
        EvaluationHarness.print_summary(bench_report)

    report = {
        "topology": topology.to_json(),
        "walkthrough": walk,
        "benchmark": bench_report,
        "ml_metrics": ml_report.to_dict() if ml_report else None,
        "ml_model": risk_model.describe() if risk_model else None,
        "seeds": {"topology_seed": args.topology_seed, "scenario_seed": args.seed,
                  "ml_seed": args.ml_seed},
    }
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  wrote {out_path}")
    print("  run `python serve.py` to open the dashboard.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
