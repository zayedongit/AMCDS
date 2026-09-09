"""Precise definitions of every metric the benchmark reports.

Notation for one scenario
-------------------------
``G``      ground-truth compromised set at detection time (from the propagation
           model, never visible to any strategy)
``I``      the isolation set the strategy chose
``S``      the seed hosts where the attack started

Detection-quality metrics (all defined over hosts)
--------------------------------------------------
``unnecessary_shutdown``   ``|I \\ G|``   hosts taken offline that were never
                                        compromised. This is the headline metric
                                        and the one the resume claim refers to.
``missed_threat``          ``|G \\ I|``   compromised hosts left online.
``precision``              ``|I ∩ G| / |I|``   share of shutdowns that were justified
``recall``                 ``|I ∩ G| / |G|``   share of compromised hosts caught
``f1``                     harmonic mean of the two

Business metrics
----------------
``services_disrupted``     count of business services with a dependency in ``I``
``revenue_impact``         INR/hour of those services
``sla_breaches``           gold-tier services among them

Containment metrics (forward-looking, counterfactual)
-----------------------------------------------------
Isolation happens *after* ``G`` is already compromised, so containment is
measured over a look-ahead window starting at detection:

    future = propagate(from = G \\ I, blocked = I, for LOOKAHEAD_MINUTES)
    post_containment_spread = |future \\ G|
    contained = (post_containment_spread == 0)

The same look-ahead run with ``I = {}`` gives ``no_action_spread``, so
``spread_prevented = no_action_spread - post_containment_spread``. Every
counterfactual re-seeds its RNG from the scenario's ``propagation_seed``, so the
only difference between two strategies' containment numbers is their isolation
set.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Set

from ..attack.propagation import PropagationModel
from ..network.topology import NetworkTopology

#: How far ahead containment effectiveness is measured, in simulated minutes.
LOOKAHEAD_MINUTES = 60


@dataclass
class ScenarioResult:
    """All metrics for one (scenario, strategy) pair."""

    scenario_id: str
    attack_type: str
    strategy: str
    n_ground_truth: int
    n_isolated: int
    isolated: List[str] = field(default_factory=list)

    unnecessary_shutdown: int = 0
    missed_threat: int = 0
    true_positive: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0

    services_disrupted: int = 0
    revenue_impact: float = 0.0
    sla_breaches: List[str] = field(default_factory=list)
    n_sla_breaches: int = 0

    post_containment_spread: int = 0
    no_action_spread: int = 0
    spread_prevented: int = 0
    contained: bool = False

    runtime_seconds: float = 0.0

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        for k in ("precision", "recall", "f1", "revenue_impact", "runtime_seconds"):
            d[k] = round(float(d[k]), 6)
        return d


def score(topology: NetworkTopology, propagation: PropagationModel,
          scenario, isolated: Set[str], strategy: str,
          runtime_seconds: float) -> ScenarioResult:
    """Compute every metric for one strategy's plan on one scenario."""
    truth: Set[str] = set(scenario.ground_truth_compromised)
    iso = set(isolated)

    tp = len(iso & truth)
    unnecessary = len(iso - truth)
    missed = len(truth - iso)
    precision = tp / len(iso) if iso else 0.0
    recall = tp / len(truth) if truth else 1.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)

    downed = topology.downed_services(iso)
    breaches = topology.sla_breaches(iso)

    # --- forward-looking containment counterfactuals ----------------------
    still_active = sorted(truth - iso)
    future = propagation.counterfactual_spread(
        still_active, scenario.attack_type, LOOKAHEAD_MINUTES,
        scenario.propagation_seed, isolate=sorted(iso)) if still_active else None
    post_spread = len(set(future.compromised) - truth) if future else 0

    no_action = propagation.counterfactual_spread(
        sorted(truth), scenario.attack_type, LOOKAHEAD_MINUTES,
        scenario.propagation_seed) if truth else None
    no_action_spread = len(set(no_action.compromised) - truth) if no_action else 0

    return ScenarioResult(
        scenario_id=scenario.scenario_id,
        attack_type=scenario.attack_type,
        strategy=strategy,
        n_ground_truth=len(truth),
        n_isolated=len(iso),
        isolated=sorted(iso),
        unnecessary_shutdown=unnecessary,
        missed_threat=missed,
        true_positive=tp,
        precision=precision, recall=recall, f1=f1,
        services_disrupted=len(downed),
        revenue_impact=topology.revenue_impact_of_isolating(iso),
        sla_breaches=breaches,
        n_sla_breaches=len(breaches),
        post_containment_spread=post_spread,
        no_action_spread=no_action_spread,
        spread_prevented=max(0, no_action_spread - post_spread),
        contained=(post_spread == 0),
        runtime_seconds=runtime_seconds,
    )


#: Fields aggregated as a mean across scenarios.
MEAN_FIELDS = (
    "unnecessary_shutdown", "missed_threat", "n_isolated", "precision", "recall",
    "f1", "services_disrupted", "revenue_impact", "n_sla_breaches",
    "post_containment_spread", "spread_prevented", "runtime_seconds",
)


def aggregate(results: Sequence[ScenarioResult]) -> Dict[str, float]:
    """Mean of each metric plus the totals that only make sense summed."""
    n = len(results)
    if n == 0:
        return {}
    out: Dict[str, float] = {"n_scenarios": n}
    for field_name in MEAN_FIELDS:
        out[f"avg_{field_name}"] = sum(
            float(getattr(r, field_name)) for r in results) / n
    out["total_unnecessary_shutdown"] = sum(r.unnecessary_shutdown for r in results)
    out["total_missed_threat"] = sum(r.missed_threat for r in results)
    out["total_sla_breaches"] = sum(r.n_sla_breaches for r in results)
    out["containment_rate"] = sum(1 for r in results if r.contained) / n
    # Micro-averaged precision/recall over all hosts, not the mean of ratios.
    tp = sum(r.true_positive for r in results)
    fp = sum(r.unnecessary_shutdown for r in results)
    fn = sum(r.missed_threat for r in results)
    out["micro_precision"] = tp / (tp + fp) if (tp + fp) else 0.0
    out["micro_recall"] = tp / (tp + fn) if (tp + fn) else 0.0
    out["micro_f1"] = (2 * out["micro_precision"] * out["micro_recall"] /
                       (out["micro_precision"] + out["micro_recall"])
                       if (out["micro_precision"] + out["micro_recall"]) else 0.0)
    return out
