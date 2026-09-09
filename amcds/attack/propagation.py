"""Attack propagation simulator over the trust-weighted reachability graph.

This produces the *ground truth* used by the evaluation harness: "which hosts
would the attacker actually own if we did nothing?". It is deliberately separate
from the defence pipeline — no agent, detector or solver ever calls it.

Model
-----
Discrete rounds. In each round every already-compromised host attempts to pivot
to each of its not-yet-compromised neighbours. The per-attempt success
probability is

    p = edge_trust * profile_aggression * (1 - target_hardening)

Rounds are derived from how long the attack has been running, so a 15-minute
ransomware detonation spreads further than a 5-minute one. Every random draw is
taken in a **sorted** order from a seeded ``random.Random``, so a given
(seed, scenario) pair reproduces byte-for-byte.

Attack profiles
---------------
``ransomware``       fast, indiscriminate, prefers file shares.
``lateral_movement`` slower, deliberate, prefers servers and credential stores.
``insider_threat``   barely propagates; the actor *uses* legitimate access to
                     reach PII rather than exploiting hosts.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Set

from ..network.topology import NetworkTopology


@dataclass(frozen=True)
class AttackProfile:
    """Per-attack-type propagation behaviour."""

    name: str
    aggression: float           # global multiplier on pivot probability
    minutes_per_round: float    # how fast the actor moves
    max_rounds: int
    #: Multiplier applied when the target host type is one this actor favours.
    preferred_types: Sequence[str] = ()
    preference_bonus: float = 1.0
    #: Multiplier applied to hosts holding PII.
    pii_bonus: float = 1.0


PROFILES: Dict[str, AttackProfile] = {
    "ransomware": AttackProfile(
        name="ransomware", aggression=0.95, minutes_per_round=4.0, max_rounds=5,
        preferred_types=("workstation", "file_server"), preference_bonus=1.25),
    "lateral_movement": AttackProfile(
        name="lateral_movement", aggression=0.70, minutes_per_round=25.0,
        max_rounds=4, preferred_types=("app_server", "db_server",
                                       "domain_controller", "jump_host"),
        preference_bonus=1.4),
    "insider_threat": AttackProfile(
        name="insider_threat", aggression=0.22, minutes_per_round=90.0,
        max_rounds=2, preferred_types=("file_server", "db_server"),
        preference_bonus=1.5, pii_bonus=2.0),
}


@dataclass
class PropagationResult:
    """Outcome of one propagation simulation."""

    seeds: List[str]
    compromised: List[str]
    #: host_id -> round index at which it fell (0 for the seeds).
    compromised_at_round: Dict[str, int] = field(default_factory=dict)
    #: Ordered (src, dst, round) pivots that actually succeeded.
    pivots: List[tuple] = field(default_factory=list)
    rounds_run: int = 0

    def to_dict(self) -> dict:
        return {
            "seeds": list(self.seeds),
            "compromised": list(self.compromised),
            "n_compromised": len(self.compromised),
            "rounds_run": self.rounds_run,
            "compromised_at_round": dict(self.compromised_at_round),
            "pivots": [{"src": s, "dst": d, "round": r} for s, d, r in self.pivots],
        }


class PropagationModel:
    """Simulates lateral movement so the harness has a defensible ground truth."""

    def __init__(self, topology: NetworkTopology) -> None:
        self.topology = topology

    def rounds_for(self, attack_type: str, elapsed_minutes: float) -> int:
        profile = PROFILES.get(attack_type, PROFILES["lateral_movement"])
        n = int(elapsed_minutes // profile.minutes_per_round)
        return max(1, min(profile.max_rounds, n))

    def simulate(self, seeds: Sequence[str], attack_type: str,
                 elapsed_minutes: float, rng: random.Random,
                 blocked: Sequence[str] = ()) -> PropagationResult:
        """Run the propagation. ``blocked`` hosts are already isolated.

        Passing an isolation set as ``blocked`` and re-running with the *same*
        ``rng`` state is how the harness measures counterfactual containment.
        """
        profile = PROFILES.get(attack_type, PROFILES["lateral_movement"])
        blocked_set = set(blocked)
        compromised: Set[str] = {s for s in seeds if s not in blocked_set}
        at_round = {h: 0 for h in sorted(compromised)}
        pivots: List[tuple] = []
        rounds = self.rounds_for(attack_type, elapsed_minutes)

        for r in range(1, rounds + 1):
            newly: Set[str] = set()
            # sorted() everywhere: set iteration order is not stable across runs
            for src in sorted(compromised):
                for dst in self.topology.neighbors(src):
                    if dst in compromised or dst in newly or dst in blocked_set:
                        continue
                    p = self._pivot_probability(src, dst, profile)
                    if rng.random() < p:
                        newly.add(dst)
                        pivots.append((src, dst, r))
            if not newly:
                break
            for h in sorted(newly):
                at_round[h] = r
            compromised |= newly

        return PropagationResult(
            seeds=sorted(seeds),
            compromised=sorted(compromised),
            compromised_at_round=at_round,
            pivots=pivots,
            rounds_run=rounds,
        )

    def _pivot_probability(self, src: str, dst: str,
                           profile: AttackProfile) -> float:
        edge = self.topology.graph[src][dst]
        target = self.topology.hosts[dst]
        p = edge["trust"] * profile.aggression * (1.0 - target.hardening)
        if target.host_type in profile.preferred_types:
            p *= profile.preference_bonus
        if target.contains_pii:
            p *= profile.pii_bonus
        return max(0.0, min(0.99, p))

    # ------------------------------------------------------------ evaluation
    def counterfactual_spread(self, seeds: Sequence[str], attack_type: str,
                              elapsed_minutes: float, seed: int,
                              isolate: Sequence[str] = ()) -> PropagationResult:
        """Re-run propagation from a *fresh* RNG with ``isolate`` blocked.

        Because the RNG is re-seeded identically, the only difference between
        the no-action run and the containment run is the isolation set, so the
        comparison measures containment and nothing else.
        """
        return self.simulate(seeds, attack_type, elapsed_minutes,
                             random.Random(seed), blocked=isolate)
