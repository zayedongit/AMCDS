"""Containment optimizer — Google OR-Tools CP-SAT.

The negotiation produces a *set of defensible candidates*. It does not decide
which combination of them is best, because that is a constrained combinatorial
problem: isolating two hosts of the same service costs no more than isolating
one, gold-tier services must keep a replica online, and there is a hard ceiling
on hourly revenue loss. CP-SAT solves exactly that.

Decision variables
------------------
``x[h] in {0,1}``    isolate host ``h``  (one per negotiated candidate)
``d[s] in {0,1}``    service ``s`` is down (linked by ``d[s] = max_h x[h]`` over
                     the hosts ``s`` depends on)

The service indicators are what make the objective honest: business cost is
counted **once per downed service**, matching the evaluation metric exactly. The
original model summed per-host revenue, so it double-counted every multi-host
service and optimised a different quantity from the one it was scored on.

Objective
---------
    minimise   alpha * residual_risk  +  beta * business_cost

    business_cost  = sum over services  revenue_per_hour[s] * d[s]
    residual_risk  = sum over candidates  risk_weight[h] * (1 - x[h])

    risk_weight[h] = criticality[h] * reach[h] * (1 + risk_score[h]) * RISK_UNIT

``reach[h]`` is the most-probable-path trust from the confirmed foothold to
``h`` (Dijkstra over ``-log(trust)``), so leaving a critical, easily reached,
behaviourally anomalous host online is expensive, and leaving an unreachable
one online is nearly free. Both terms are scaled to integers because CP-SAT is
an integer solver; ``OBJECTIVE_SCALE`` and ``RISK_UNIT`` are chosen so the two
components land in the same order of magnitude and neither silently dominates.

Hard constraints
----------------
C1  Hard evidence      every host with hard evidence of infection is isolated.
C2  Gold-tier SLA      for every gold service not entirely hard-evidenced, at
                       least one of its non-evidenced hosts stays online.
C3  Service availability  for every multi-host service, at least one host stays
                       online unless every host of it is hard-evidenced.
C4  Budget             total business cost stays under the hourly ceiling, when
                       a plan satisfying C1-C3 can do so.

C4 is dropped and reported (rather than returning INFEASIBLE) when C1 alone
already blows the budget — a confirmed compromise of the payments database costs
what it costs. Every relaxation is recorded in the result.
"""
from __future__ import annotations

import time
from typing import Dict, Iterable, List, Optional, Sequence, Set

from ortools.sat.python import cp_model

from ..config import (CPSAT_MAX_SECONDS, DEFAULT_ALPHA, DEFAULT_BETA,
                      DEFAULT_MAX_HOURLY_LOSS, OBJECTIVE_SCALE)
from ..network.topology import NetworkTopology

#: Scales a (criticality x reach x risk) product into the same integer range as
#: revenue/OBJECTIVE_SCALE. Revenue is up to 5e6 INR -> 5,000 units; a maximally
#: critical, fully reachable, maximally anomalous host scores 5*1*2*500 = 5,000.
RISK_UNIT = 500


class CPSATSolver:
    """Solves the containment problem over the negotiated candidate set."""

    name = "OR-Tools CP-SAT"

    def __init__(self, alpha: float = DEFAULT_ALPHA, beta: float = DEFAULT_BETA,
                 max_hourly_loss: float = DEFAULT_MAX_HOURLY_LOSS,
                 max_seconds: float = CPSAT_MAX_SECONDS) -> None:
        self.alpha = float(alpha)
        self.beta = float(beta)
        self.max_hourly_loss = float(max_hourly_loss)
        self.max_seconds = float(max_seconds)
        self.last_runtime: float = 0.0

    # ------------------------------------------------------------------ solve
    def solve(self, topology: NetworkTopology, candidates: Iterable[str],
              hard_evidence: Iterable[str],
              reach: Optional[Dict[str, float]] = None,
              risk_scores: Optional[Dict[str, float]] = None) -> Dict:
        t0 = time.perf_counter()
        cand = sorted(set(candidates))
        hard = sorted(set(hard_evidence) & set(cand))
        reach = reach or {}
        risk_scores = risk_scores or {}

        if not cand:
            self.last_runtime = time.perf_counter() - t0
            return self._empty_result("no candidates from negotiation")

        unknown = [h for h in cand if h not in topology.hosts]
        if unknown:
            raise KeyError(f"candidate hosts not in the topology: {unknown}")

        model = cp_model.CpModel()
        x = {h: model.NewBoolVar(f"x[{h}]") for h in cand}

        # ---- service-down indicators ------------------------------------
        touched = sorted({s for h in cand for s in topology.services_on_host(h)})
        d: Dict[str, cp_model.IntVar] = {}
        for sid in touched:
            deps = sorted(topology.service_deps[sid] & set(cand))
            if not deps:
                continue
            d[sid] = model.NewBoolVar(f"down[{sid}]")
            # d[s] = 1 iff any dependency is isolated
            model.AddMaxEquality(d[sid], [x[h] for h in deps])

        constraints: List[str] = []
        relaxations: List[str] = []

        # ---- C1: hard evidence must be isolated --------------------------
        for h in hard:
            model.Add(x[h] == 1)
        if hard:
            constraints.append(
                f"C1 hard-evidence: {len(hard)} host(s) forced to isolate ({', '.join(hard[:5])}"
                f"{'…' if len(hard) > 5 else ''})")

        # ---- C2: gold-tier SLA protection --------------------------------
        n_gold_guarded = 0
        for sid in sorted(topology.service_deps):
            if topology.service_sla.get(sid) != "gold":
                continue
            deps = sorted(topology.service_deps[sid])
            spare = [h for h in deps if h not in hard]
            if not spare:
                continue                      # entire service is proven compromised
            spare_candidates = [h for h in spare if h in x]
            if len(spare_candidates) < len(spare):
                continue                      # a spare host is not even a candidate
            model.Add(sum(1 - x[h] for h in spare_candidates) >= 1)
            n_gold_guarded += 1
        if n_gold_guarded:
            constraints.append(
                f"C2 gold-SLA: {n_gold_guarded} gold service(s) must keep one "
                f"non-evidenced host online")

        # ---- C3: availability of multi-host services ---------------------
        n_avail = 0
        for sid in sorted(topology.service_deps):
            deps = sorted(topology.service_deps[sid])
            if len(deps) < 2:
                continue
            spare = [h for h in deps if h not in hard]
            if not spare:
                continue
            spare_candidates = [h for h in spare if h in x]
            if len(spare_candidates) < len(spare):
                continue
            model.Add(sum(1 - x[h] for h in spare_candidates) >= 1)
            n_avail += 1
        if n_avail:
            constraints.append(
                f"C3 availability: {n_avail} multi-host service(s) keep a replica online")

        # ---- objective terms ---------------------------------------------
        cost_terms = [int(round(topology.service_revenue[s] / OBJECTIVE_SCALE)) * d[s]
                      for s in sorted(d)]
        risk_terms = []
        weights: Dict[str, int] = {}
        for h in cand:
            w = self._risk_weight(topology, h, reach, risk_scores)
            weights[h] = w
            if w > 0:
                risk_terms.append(w * (1 - x[h]))

        # ---- C4: hourly budget ceiling -----------------------------------
        budget_units = int(round(self.max_hourly_loss / OBJECTIVE_SCALE))
        floor_cost = self._forced_cost(topology, hard)
        budget_applied = False
        if cost_terms:
            if floor_cost <= self.max_hourly_loss:
                model.Add(sum(cost_terms) <= budget_units)
                budget_applied = True
                constraints.append(
                    f"C4 budget: business cost <= INR "
                    f"{self.max_hourly_loss/1e5:.1f}L/hour")
            else:
                relaxations.append(
                    f"C4 budget relaxed: hard-evidence hosts alone already cost INR "
                    f"{floor_cost/1e5:.1f}L/hour, above the "
                    f"INR {self.max_hourly_loss/1e5:.1f}L ceiling")

        alpha_i = int(round(self.alpha * 100))
        beta_i = int(round(self.beta * 100))
        model.Minimize(alpha_i * sum(risk_terms) + beta_i * sum(cost_terms))

        solver = cp_model.CpSolver()
        solver.parameters.max_time_in_seconds = self.max_seconds
        solver.parameters.num_workers = 1          # determinism
        solver.parameters.random_seed = 42
        status = solver.Solve(model)
        status_name = solver.StatusName(status)
        runtime = time.perf_counter() - t0
        self.last_runtime = runtime

        if status in (cp_model.OPTIMAL, cp_model.FEASIBLE):
            isolate = {h for h in cand if solver.Value(x[h]) == 1}
            objective = solver.ObjectiveValue()
            dropped = sorted(set(cand) - isolate)
        else:
            # No feasible plan: fall back to the hard-evidence hosts only, which
            # is always safe and always satisfies C1.
            isolate = set(hard)
            objective = None
            dropped = sorted(set(cand) - isolate)
            relaxations.append(
                f"solver returned {status_name}; fell back to isolating only the "
                f"{len(hard)} hard-evidence host(s)")

        cost = topology.revenue_impact_of_isolating(isolate)
        residual = sum(weights[h] for h in cand if h not in isolate)

        return {
            "isolate": isolate,
            "dropped": dropped,
            "n_candidates": len(cand),
            "n_isolated": len(isolate),
            "objective": objective,
            "status": status_name,
            "runtime_seconds": runtime,
            "solver": self.name,
            "business_cost_per_hour": cost,
            "residual_risk_units": residual,
            "sla_breaches": topology.sla_breaches(isolate),
            "downed_services": topology.downed_services(isolate),
            "constraints": constraints,
            "relaxations": relaxations,
            "budget_enforced": budget_applied,
            "weights": {h: weights[h] for h in cand},
            "explanation": self._explain(cand, isolate, dropped, cost, residual,
                                         status_name, constraints, relaxations),
        }

    # -------------------------------------------------------------- helpers
    @staticmethod
    def _risk_weight(topology: NetworkTopology, host: str,
                     reach: Dict[str, float], risk_scores: Dict[str, float]) -> int:
        """Cost of leaving ``host`` online, as an integer objective weight."""
        h = topology.hosts[host]
        r = max(0.0, min(1.0, reach.get(host, 0.0)))
        anomaly = 1.0 + max(0.0, min(1.0, risk_scores.get(host, 0.0)))
        return int(round(h.criticality * r * anomaly * RISK_UNIT))

    @staticmethod
    def _forced_cost(topology: NetworkTopology, hard: Sequence[str]) -> float:
        return topology.revenue_impact_of_isolating(hard)

    def _empty_result(self, why: str) -> Dict:
        return {
            "isolate": set(), "dropped": [], "n_candidates": 0, "n_isolated": 0,
            "objective": 0.0, "status": "EMPTY", "runtime_seconds": self.last_runtime,
            "solver": self.name, "business_cost_per_hour": 0.0,
            "residual_risk_units": 0, "sla_breaches": [], "downed_services": [],
            "constraints": [], "relaxations": [], "budget_enforced": False,
            "weights": {}, "explanation": why,
        }

    @staticmethod
    def _explain(cand: Sequence[str], isolate: Set[str], dropped: Sequence[str],
                 cost: float, residual: int, status: str,
                 constraints: Sequence[str], relaxations: Sequence[str]) -> str:
        parts = [
            f"CP-SAT {status}: isolated {len(isolate)} of {len(cand)} negotiated "
            f"candidate(s) at INR {cost/1e5:.1f}L/hour with {residual} residual-risk "
            f"units left on the table."
        ]
        if dropped:
            parts.append(
                f"Dropped {len(dropped)} candidate(s) whose business cost exceeded "
                f"the risk they removed: {', '.join(sorted(dropped)[:6])}"
                f"{'…' if len(dropped) > 6 else ''}.")
        if constraints:
            parts.append("Active constraints: " + "; ".join(constraints) + ".")
        if relaxations:
            parts.append("Relaxations: " + "; ".join(relaxations) + ".")
        return " ".join(parts)


#: Backwards-compatible alias for the original class name.
ClassicalSolver = CPSATSolver
