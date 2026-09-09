#!/usr/bin/env python3
"""Reproducible AMCDS benchmark.

    python scripts/run_benchmark.py                  # canonical 45 scenarios
    python scripts/run_benchmark.py --per-type 30    # 90 scenarios
    python scripts/run_benchmark.py --include-annealing

Everything is seeded. Re-running with the same flags reproduces the numbers
exactly, in any process, on any machine — the seeds are printed in the header
and written into the report.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from amcds.config import (DEFAULT_BENCHMARK_SEED, DEFAULT_TOPOLOGY_SEED,
                          ML_SUSPICIOUS_THRESHOLD)
from amcds.evaluation import EvaluationHarness
from amcds.ml import evaluate_on_scenarios, train_default_model
from amcds.network import build_segmented_enterprise
from amcds.scenarios import ScenarioGenerator

DEFAULT_ML_SEED = 1234
DEFAULT_ML_WINDOWS = 60


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--per-type", type=int, default=15,
                    help="scenarios per attack type (default 15 -> 45 total)")
    ap.add_argument("--topology-seed", type=int, default=DEFAULT_TOPOLOGY_SEED)
    ap.add_argument("--scenario-seed", type=int, default=DEFAULT_BENCHMARK_SEED)
    ap.add_argument("--ml-seed", type=int, default=DEFAULT_ML_SEED)
    ap.add_argument("--ml-windows", type=int, default=DEFAULT_ML_WINDOWS,
                    help="attack-free observation windows used to train the model")
    ap.add_argument("--no-ml", action="store_true",
                    help="skip the risk model entirely (agents see alerts only)")
    ap.add_argument("--include-annealing", action="store_true",
                    help="also run the QUBO annealing optimizer on a sample")
    ap.add_argument("--annealing-sample", type=int, default=10)
    ap.add_argument("--out", default="results/benchmark.json")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    print("=" * 78)
    print("  AMCDS benchmark")
    print("=" * 78)
    print(f"  topology seed  {args.topology_seed}")
    print(f"  scenario seed  {args.scenario_seed}")
    print(f"  ML seed        {args.ml_seed}  ({args.ml_windows} attack-free windows)")
    print(f"  scenarios      {args.per_type} per type -> {args.per_type * 3} total")
    print(f"  risk threshold {ML_SUSPICIOUS_THRESHOLD}")
    print()

    t_start = time.perf_counter()
    topology = build_segmented_enterprise(seed=args.topology_seed)
    print(f"  topology: {json.dumps(topology.summary())}")

    risk_model = None
    if not args.no_ml:
        print("  training host-risk model on attack-free telemetry…", flush=True)
        risk_model = train_default_model(topology, n_windows=args.ml_windows,
                                         seed=args.ml_seed)

    print("  generating scenarios…", flush=True)
    scenarios = ScenarioGenerator(topology, seed=args.scenario_seed).batch(
        n_each=args.per_type)

    ml_report = None
    if risk_model is not None:
        print("\n--- ML risk model, evaluated independently ---")
        ml_report, per_scenario = evaluate_on_scenarios(risk_model, topology, scenarios)
        print(ml_report.pretty())

    print("\n--- containment strategies ---", flush=True)
    harness = EvaluationHarness(topology, risk_model)
    report = harness.run(scenarios,
                         include_annealing=args.include_annealing,
                         annealing_sample=args.annealing_sample,
                         verbose=not args.quiet)
    print()
    EvaluationHarness.print_summary(report)

    report["seeds"] = {
        "topology_seed": args.topology_seed,
        "scenario_seed": args.scenario_seed,
        "ml_seed": args.ml_seed,
        "ml_windows": args.ml_windows,
    }
    if ml_report is not None:
        report["ml_model"] = {
            "describe": risk_model.describe(),
            "metrics": ml_report.to_dict(),
            "per_scenario": per_scenario,
        }
    report["wall_clock_seconds"] = round(time.perf_counter() - t_start, 3)

    EvaluationHarness.save(report, args.out)
    print(f"\n  wall clock: {report['wall_clock_seconds']}s")
    print(f"  wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
