"""Quantum-style containment optimizer using D-Wave's simulated annealer.

This solves the same problem as ClassicalSolver, but formulated as a QUBO
(Quadratic Unconstrained Binary Optimization) — the form a real D-Wave
quantum annealer expects. We run it on D-Wave's free `neal` simulated
annealer (CPU), so no API key or cloud account is needed for the demo.

If a D-Wave Leap API token is available in env (`DWAVE_API_TOKEN`),
this same QUBO can be submitted to a real QPU without code changes —
the swap is one import.

QUBO formulation
----------------
For each candidate host i we have a binary variable x_i.
We construct Q such that minimizing  x^T Q x  encodes:
    + β · revenue_per_hour_i      on diagonal Q[i,i]    (cost of isolation)
    – α · criticality_i · 100     on diagonal Q[i,i]    (risk reduction)
                                       for i in risk_zone   (cap as benefit)
    + LAMBDA_INFECT · (1 - x_i)   penalty for not isolating infected i
        → represented as: Q[i,i] -= LAMBDA_INFECT  (so x_i=1 is rewarded)
    + LAMBDA_SLA · soft penalty if all hosts of a gold service get isolated
        → pairwise terms encouraging at least one to stay online
"""
from __future__ import annotations

import os
import time
from typing import Dict, Set

import numpy as np

try:
    import neal  # D-Wave's free local simulated annealer
    import dimod
    HAS_NEAL = True
except Exception:  # pragma: no cover
    HAS_NEAL = False

from ..network.topology import NetworkTopology


LAMBDA_INFECT = 100000.0   # huge reward for isolating infected
LAMBDA_SLA = 50000.0       # penalty per gold service fully taken down


class QuantumSolver:
    """Solver that uses simulated annealing on a QUBO formulation.

    Falls back to a greedy heuristic if D-Wave neal is unavailable.
    """
    def __init__(self, alpha: float = 1.0, beta: float = 1.0,
                 num_reads: int = 200, seed: int = 42) -> None:
        self.alpha = alpha
        self.beta = beta
        self.num_reads = num_reads
        self.seed = seed
        self.last_runtime: float = 0.0

    def _build_qubo(self, topology: NetworkTopology, candidates,
                    infected: Set[str]):
        """Build the QUBO matrix as a dict {(i, j): coeff}."""
        Q: Dict[tuple, float] = {}
        idx = {h: i for i, h in enumerate(candidates)}

        # risk zone (within 2 hops of infected)
        risk_zone: Set[str] = set(infected)
        frontier = set(infected)
        for _ in range(2):
            nxt = set()
            for h in frontier:
                for nbr in topology.neighbors(h):
                    if nbr not in risk_zone:
                        nxt.add(nbr)
            risk_zone.update(nxt)
            frontier = nxt

        # diagonal terms
        for h in candidates:
            i = idx[h]
            host = topology.hosts[h]
            # cost: penalize isolation (x_i = 1)
            diag = self.beta * host.revenue_per_hour / 1000.0
            # risk reduction benefit if h is in risk_zone (reward isolation)
            if h in risk_zone:
                diag -= self.alpha * host.criticality * 100.0
            # infected: huge reward for isolation
            if h in infected:
                diag -= LAMBDA_INFECT
            Q[(i, i)] = Q.get((i, i), 0.0) + diag

        # SLA pairwise penalty: for each gold service, if all candidate hosts
        # of that service are isolated, add a penalty (encoded as quadratic
        # repulsion between them).
        for sid, sla in topology.service_sla.items():
            if sla != "gold":
                continue
            hosts = list(topology.service_deps[sid])
            cand_hosts = [h for h in hosts if h in idx and h not in infected]
            if len(cand_hosts) < 2:
                continue
            # pairwise: + LAMBDA_SLA * x_i * x_j for i != j among cand_hosts
            n = len(cand_hosts)
            penalty = LAMBDA_SLA / n  # spread across pairs
            for a in range(n):
                for b in range(a + 1, n):
                    i, j = idx[cand_hosts[a]], idx[cand_hosts[b]]
                    Q[(i, j)] = Q.get((i, j), 0.0) + penalty

        return Q, idx, risk_zone

    def solve(self, topology: NetworkTopology, candidate_set: Set[str],
              infected: Set[str]) -> Dict:
        t0 = time.time()
        candidates = sorted(candidate_set)

        if not candidates:
            self.last_runtime = time.time() - t0
            return {
                "isolate": set(),
                "objective": 0.0,
                "runtime_seconds": self.last_runtime,
                "solver": "D-Wave neal (simulated annealer)",
                "num_reads": self.num_reads,
            }

        Q, idx, _ = self._build_qubo(topology, candidates, infected)

        if HAS_NEAL:
            bqm = dimod.BinaryQuadraticModel.from_qubo(Q)
            sampler = neal.SimulatedAnnealingSampler()
            sampleset = sampler.sample(bqm, num_reads=self.num_reads,
                                       seed=self.seed)
            best = sampleset.first
            sample = best.sample
            energy = best.energy
            isolate = {h for h in candidates if sample.get(idx[h], 0) == 1}
            backend = "D-Wave neal (simulated annealer)"
        else:
            # Fallback greedy: isolate if diag coefficient < 0
            isolate = set()
            for h in candidates:
                if Q.get((idx[h], idx[h]), 0.0) < 0:
                    isolate.add(h)
            energy = sum(Q.get((idx[h], idx[h]), 0.0) for h in isolate)
            backend = "Greedy fallback (neal not installed)"

        # Hard-enforce infected hosts (annealer is soft constraint)
        isolate.update(infected & set(candidates))

        runtime = time.time() - t0
        self.last_runtime = runtime
        return {
            "isolate": isolate,
            "objective": float(energy),
            "runtime_seconds": runtime,
            "solver": backend,
            "num_reads": self.num_reads,
        }
