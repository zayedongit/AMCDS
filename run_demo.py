"""AMCDS demo — one command runs the whole pipeline.

What this does:
  1. Builds a sample enterprise network (~30 hosts, 8 services).
  2. Generates one attack scenario per category (ransomware, lateral, insider).
  3. Runs the 5-agent negotiation protocol on each.
  4. Runs the classical (OR-Tools) and quantum-style (D-Wave neal) solvers.
  5. Runs a benchmark across 90 scenarios comparing AMCDS vs aggressive vs
     conservative baselines.
  6. Writes results/demo_report.json which the dashboard reads.

Usage
-----
    pip install -r requirements.txt
    python run_demo.py
    open dashboard/index.html
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from amcds.agents import (BusinessImpactAgent, DataAgent, EndpointAgent,
                          IdentityAgent, NetworkAgent)
from amcds.evaluation import EvaluationHarness
from amcds.events import build_timeline
from amcds.negotiation import NegotiationProtocol
from amcds.network.topology import build_sample_enterprise
from amcds.optimization import ClassicalSolver, QuantumSolver
from amcds.scenarios import ScenarioGenerator


HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(HERE, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)


def banner(s: str) -> None:
    line = "=" * 72
    print(f"\n{line}\n  {s}\n{line}")


def run_single_scenario(topology, scenario, run_quantum: bool = True) -> dict:
    agents = [IdentityAgent(), NetworkAgent(), DataAgent(), EndpointAgent()]
    biz = BusinessImpactAgent()
    protocol = NegotiationProtocol(agents, biz)

    print(f"\n--- Scenario {scenario.scenario_id} ({scenario.attack_type}) ---")
    print(f"  Infected hosts: {scenario.infected_hosts}")
    print(f"  Elapsed:        {scenario.elapsed_minutes} min")
    print(f"  Ground truth spread (if no isolation): "
          f"{len(scenario.ground_truth_spread)} hosts")

    log = protocol.run(topology, scenario.to_dict())
    print(f"  Negotiation:    {log.elapsed_seconds*1000:.0f} ms  →  "
          f"{len(log.final_isolate)} candidate hosts")

    # classical
    classical = ClassicalSolver().solve(topology, log.final_isolate,
                                        set(scenario.infected_hosts))
    print(f"  Classical solver: {classical['runtime_seconds']*1000:.0f} ms, "
          f"isolates {len(classical['isolate'])} hosts "
          f"(₹{topology.revenue_impact_of_isolating(classical['isolate'])/1e5:.1f}L/hr cost)")

    # quantum-style
    quantum = None
    if run_quantum:
        quantum = QuantumSolver().solve(topology, log.final_isolate,
                                        set(scenario.infected_hosts))
        print(f"  Quantum solver:   {quantum['runtime_seconds']*1000:.0f} ms, "
              f"isolates {len(quantum['isolate'])} hosts "
              f"(via {quantum['solver']})")

    classical_payload = {**classical,
                         "isolate": sorted(list(classical["isolate"]))}
    quantum_payload = (None if quantum is None else
                       {**quantum, "isolate": sorted(list(quantum["isolate"]))})

    # Build the cinematic event timeline the dashboard replays.
    timeline = build_timeline(
        scenario=scenario.to_dict(),
        negotiation_log=log.to_dict(),
        classical_result=classical_payload,
        quantum_result=quantum_payload,
    )

    return {
        "scenario": scenario.to_dict(),
        "negotiation": log.to_dict(),
        "classical": classical_payload,
        "quantum": quantum_payload,
        "timeline": timeline,
        "timeline_duration_ms": timeline[-1]["t"] if timeline else 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenarios-per-type", type=int, default=30,
                        help="benchmark scenarios per attack category (default 30 → 90 total)")
    parser.add_argument("--quantum-sample", type=int, default=5,
                        help="how many scenarios to also run on the quantum solver (default 5)")
    parser.add_argument("--no-benchmark", action="store_true",
                        help="skip the multi-scenario benchmark (faster demo)")
    parser.add_argument("--seed", type=int, default=11)
    args = parser.parse_args()

    banner("AMCDS — Autonomous Multi-Agent Cyber Defense System")
    print("  Building enterprise topology…")
    topology = build_sample_enterprise()
    print(f"  Topology: {topology.summary()}")

    gen = ScenarioGenerator(topology, seed=args.seed)

    # ------------------------------- Single-scenario walkthrough ----------
    banner("WALKTHROUGH — one scenario per attack category")
    walk = []
    walk.append(run_single_scenario(topology, gen.ransomware("DEMO-RW")))
    walk.append(run_single_scenario(topology, gen.lateral_movement("DEMO-LM")))
    walk.append(run_single_scenario(topology, gen.insider_threat("DEMO-IT")))

    # ------------------------------- Benchmark ----------------------------
    bench_report = None
    if not args.no_benchmark:
        banner(f"BENCHMARK — {args.scenarios_per_type*3} scenarios "
               f"(AMCDS vs aggressive vs conservative)")
        gen2 = ScenarioGenerator(topology, seed=args.seed + 1)
        scenarios = gen2.batch(n_each=args.scenarios_per_type)
        harness = EvaluationHarness(topology)
        bench_report = harness.run(scenarios,
                                   include_quantum=args.quantum_sample > 0,
                                   quantum_sample=args.quantum_sample)
        print("\n=== Summary ===")
        for strat, m in bench_report["summary"].items():
            if strat.startswith("_"):
                continue
            print(f"  {strat:<18}  "
                  f"unnecessary={m['avg_unnecessary_isolation']:.2f}  "
                  f"residual_risk={m['avg_residual_risk']:.2f}  "
                  f"₹/hr={m['avg_revenue_impact']/1e5:.1f}L  "
                  f"SLA-breach/run={m['avg_sla_breaches']:.2f}  "
                  f"time={m['avg_response_time_seconds']*1000:.0f}ms")
        head = bench_report["summary"].get("_headline")
        if head:
            print(f"\n  ➜ AMCDS reduces unnecessary isolation by "
                  f"{head['unnecessary_isolation_reduction_vs_aggressive_pct']}% "
                  f"vs aggressive baseline.")

    # ------------------------------- Write report -------------------------
    report = {
        "topology": topology.to_json(),
        "walkthrough": walk,
        "benchmark": bench_report,
    }
    out_path = os.path.join(RESULTS_DIR, "demo_report.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n📁 Wrote {out_path}")
    print(f"📊 Open dashboard/index.html in your browser to view the visual report.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
