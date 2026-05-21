"""Classical containment optimizer using Google OR-Tools CP-SAT.

Formulation
-----------
Decision variable x_i ∈ {0,1} for each host i in the candidate set
(produced by negotiation). x_i = 1 means "isolate host i".

Minimize:
    α · residual_risk(x) + β · business_cost(x)

where
    residual_risk(x) = Σ over non-isolated hosts reachable from infected:
                       criticality_i · (1 - x_i)
    business_cost(x) = Σ_i revenue_per_hour_i · x_i

Hard constraints:
    - Every confirmed infected host MUST be isolated  (x_i = 1)
    - No gold-tier SLA service can have ALL its hosts isolated
      (we encode: at least one host of each gold service stays online,
      unless the only hosts of that service are themselves infected)
"""
from __future__ import annotations

import time
from typing import Dict, Set

from ortools.sat.python import cp_model

from ..network.topology import NetworkTopology


class ClassicalSolver:
    def __init__(self, alpha: float = 1.0, beta: float = 1.0) -> None:
        self.alpha = alpha  # weight on residual risk
        self.beta = beta    # weight on business cost
        self.last_runtime: float = 0.0

    def solve(self, topology: NetworkTopology, candidate_set: Set[str],
              infected: Set[str]) -> Dict:
        t0 = time.time()
        model = cp_model.CpModel()

        candidates = sorted(candidate_set)
        x = {h: model.NewBoolVar(f"x_{h}") for h in candidates}

        # ---- hard: infected hosts MUST be isolated --------------------
        for h in infected:
            if h in x:
                model.Add(x[h] == 1)

        # ---- hard: keep at least one host of each gold service alive,
        #              unless ALL its hosts are confirmed infected
        for sid, sla in topology.service_sla.items():
            if sla != "gold":
                continue
            service_hosts = topology.service_deps[sid]
            if service_hosts.issubset(infected):
                continue  # entire service is already compromised
            # at least one non-infected host in service_hosts must NOT be isolated
            non_infected = [h for h in service_hosts if h not in infected]
            terms = [(1 - x[h]) for h in non_infected if h in x]
            non_candidate = [h for h in non_infected if h not in x]
            # if some are not even candidates, they're trivially online → satisfied
            if non_candidate:
                continue
            if terms:
                model.Add(sum(terms) >= 1)

        # ---- objective ----------------------------------------------
        # business cost component
        cost_terms = []
        for h in candidates:
            host = topology.hosts[h]
            # scale revenue down so it doesn't dominate
            cost_terms.append(int(host.revenue_per_hour / 1000) * x[h])

        # residual-risk component: sum of criticality of NON-isolated candidate
        # hosts that are reachable from infected (proxy — full reachability is
        # nonlinear, so we approximate as "criticality * (1 - x_i)" for any
        # candidate within 2 hops of infected)
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
        risk_terms = []
        for h in candidates:
            if h in risk_zone:
                crit = topology.hosts[h].criticality
                # penalty if NOT isolated
                risk_terms.append(crit * 100 * (1 - x[h]))

        model.Minimize(int(self.alpha) * sum(risk_terms) +
                       int(self.beta) * sum(cost_terms))

        solver = cp_model.CpSolver()
        solver.parameters.max_time_in_seconds = 10
        status = solver.Solve(model)
        runtime = time.time() - t0
        self.last_runtime = runtime

        if status in (cp_model.OPTIMAL, cp_model.FEASIBLE):
            isolate = {h for h in candidates if solver.Value(x[h]) == 1}
        else:
            # Fallback: keep the candidate set as-is
            isolate = set(candidate_set)

        return {
            "isolate": isolate,
            "objective": solver.ObjectiveValue() if status in (cp_model.OPTIMAL, cp_model.FEASIBLE) else None,
            "status": solver.StatusName(status),
            "runtime_seconds": runtime,
            "solver": "OR-Tools CP-SAT (classical)",
        }
