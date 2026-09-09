"""Alternative optimizer: the same problem as a QUBO, solved by annealing.

**Naming honesty.** An earlier version of this file called itself a "quantum
solver". It is not. It builds a QUBO — the input format an Ising-model annealer
expects — and solves it with D-Wave's ``neal``, a *classical* simulated
annealer running on the CPU. Nothing quantum executes. The QUBO form is
portable to quantum annealing hardware, and that is the honest claim: the
formulation is annealer-ready, the execution is classical.

**Why keep it at all.** It is a genuinely useful control. CP-SAT returns a
provably optimal solution to a model with hard constraints; the annealer returns
a good solution to a model where those constraints are *penalty terms*. Running
both on the same scenario shows what a metaheuristic costs you in solution
quality and constraint satisfaction, which is a real experimental result rather
than a marketing line.

QUBO formulation
----------------
For each candidate host ``i`` with binary variable ``x_i``:

    Q[i,i] += beta * revenue_i / OBJECTIVE_SCALE       cost of isolating
    Q[i,i] -= alpha * risk_weight_i                    benefit of isolating
    Q[i,i] -= LAMBDA_EVIDENCE      if i has hard evidence  (drives x_i -> 1)
    Q[i,j] += LAMBDA_SLA / n       for pairs within a gold service
                                   (discourages isolating all replicas)

Note the asymmetry with CP-SAT: here the SLA rule is a *soft penalty* that a bad
enough risk term can outweigh, whereas CP-SAT enforces it as a hard constraint.
That difference is the point of the comparison.
"""
from __future__ import annotations

import time
from typing import Dict, Iterable, Optional, Set

from ..config import DEFAULT_ALPHA, DEFAULT_BETA, OBJECTIVE_SCALE
from ..network.topology import NetworkTopology
from .cpsat_solver import RISK_UNIT, CPSATSolver

try:  # pragma: no cover - exercised only when the optional dep is installed
    import dimod
    import neal
    HAS_NEAL = True
except Exception:  # pragma: no cover
    HAS_NEAL = False

LAMBDA_EVIDENCE = 100_000.0   # penalty weight forcing hard-evidence isolation
LAMBDA_SLA = 50_000.0         # penalty weight discouraging full-service outage


class AnnealingSolver:
    """QUBO + simulated annealing. Optional; falls back to a greedy heuristic."""

    name = "QUBO / simulated annealing (classical)"

    def __init__(self, alpha: float = DEFAULT_ALPHA, beta: float = DEFAULT_BETA,
                 num_reads: int = 200, seed: int = 42) -> None:
        self.alpha = float(alpha)
        self.beta = float(beta)
        self.num_reads = num_reads
        self.seed = seed
        self.last_runtime: float = 0.0

    # ------------------------------------------------------------------ QUBO
    def build_qubo(self, topology: NetworkTopology, candidates,
                   hard_evidence: Set[str], reach: Dict[str, float],
                   risk_scores: Dict[str, float]):
        Q: Dict[tuple, float] = {}
        idx = {h: i for i, h in enumerate(candidates)}

        for h in candidates:
            i = idx[h]
            host = topology.hosts[h]
            diag = self.beta * host.revenue_per_hour / OBJECTIVE_SCALE
            diag -= self.alpha * CPSATSolver._risk_weight(
                topology, h, reach, risk_scores) / float(RISK_UNIT) * RISK_UNIT / 100.0
            if h in hard_evidence:
                diag -= LAMBDA_EVIDENCE
            Q[(i, i)] = Q.get((i, i), 0.0) + diag

        for sid in sorted(topology.service_deps):
            if topology.service_sla.get(sid) != "gold":
                continue
            members = sorted(h for h in topology.service_deps[sid]
                             if h in idx and h not in hard_evidence)
            if len(members) < 2:
                continue
            penalty = LAMBDA_SLA / len(members)
            for a in range(len(members)):
                for b in range(a + 1, len(members)):
                    i, j = idx[members[a]], idx[members[b]]
                    Q[(i, j)] = Q.get((i, j), 0.0) + penalty
        return Q, idx

    # ----------------------------------------------------------------- solve
    def solve(self, topology: NetworkTopology, candidates: Iterable[str],
              hard_evidence: Iterable[str],
              reach: Optional[Dict[str, float]] = None,
              risk_scores: Optional[Dict[str, float]] = None) -> Dict:
        t0 = time.perf_counter()
        cand = sorted(set(candidates))
        hard = set(hard_evidence) & set(cand)
        reach = reach or {}
        risk_scores = risk_scores or {}

        if not cand:
            self.last_runtime = time.perf_counter() - t0
            return {"isolate": set(), "objective": 0.0, "status": "EMPTY",
                    "runtime_seconds": self.last_runtime, "solver": self.name,
                    "backend": "none", "num_reads": self.num_reads,
                    "business_cost_per_hour": 0.0, "sla_breaches": [],
                    "explanation": "no candidates from negotiation"}

        Q, idx = self.build_qubo(topology, cand, hard, reach, risk_scores)

        if HAS_NEAL:
            bqm = dimod.BinaryQuadraticModel.from_qubo(Q)
            sampler = neal.SimulatedAnnealingSampler()
            sampleset = sampler.sample(bqm, num_reads=self.num_reads, seed=self.seed)
            best = sampleset.first
            isolate = {h for h in cand if best.sample.get(idx[h], 0) == 1}
            energy = float(best.energy)
            backend = "D-Wave neal (classical simulated annealing)"
        else:
            isolate = {h for h in cand if Q.get((idx[h], idx[h]), 0.0) < 0}
            energy = float(sum(Q.get((idx[h], idx[h]), 0.0) for h in sorted(isolate)))
            backend = "greedy diagonal fallback (neal not installed)"

        # The evidence term is a soft penalty; enforce it exactly for safety.
        isolate |= hard

        runtime = time.perf_counter() - t0
        self.last_runtime = runtime
        breaches = topology.sla_breaches(isolate)
        return {
            "isolate": isolate,
            "objective": energy,
            "status": "HEURISTIC",
            "runtime_seconds": runtime,
            "solver": self.name,
            "backend": backend,
            "num_reads": self.num_reads,
            "n_candidates": len(cand),
            "n_isolated": len(isolate),
            "business_cost_per_hour": topology.revenue_impact_of_isolating(isolate),
            "sla_breaches": breaches,
            "explanation": (
                f"Annealed a {len(cand)}-variable QUBO with {self.num_reads} reads on "
                f"{backend}; isolated {len(isolate)} host(s). SLA protection is a soft "
                f"penalty here, so {len(breaches)} gold-tier breach(es) were accepted "
                f"where CP-SAT would have forbidden them."),
        }


#: Deprecated alias. Retained so older scripts keep importing, but the class is
#: not quantum and never was; prefer :class:`AnnealingSolver`.
QuantumSolver = AnnealingSolver
