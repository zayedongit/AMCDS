"""Attack scenario generator.

Generates realistic attack scenarios across three categories from the abstract:
  - ransomware
  - lateral_movement
  - insider_threat

Each scenario specifies:
  - infected_hosts          : seed of confirmed-compromised hosts
  - attack_type             : one of the three categories
  - elapsed_minutes         : how long since initial compromise
  - host_suspicion          : EDR-like per-host suspicion scores (0..1)
  - ioc_evidence            : indicators of compromise (URLs, hashes, etc.)
  - ground_truth_spread     : hosts that WOULD become infected if nothing
                              is isolated (used for evaluation only).
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Set

from ..network.topology import NetworkTopology


SAMPLE_MAL_URLS = [
    "http://secure-login.paypal-update.com/login.php?session=abcdef",
    "http://192.168.1.1/upload.php?x=cmd.exe",
    "http://free-credits.xyz/win-now",
    "https://drive-download-googl.com/file/d/abcd1234",
    "http://0x7f000001/admin/shell.sh",
    "http://download-update-microsoft.tk/setup.exe",
]

SAMPLE_BENIGN_URLS = [
    "https://www.google.com",
    "https://github.com/zayedongit/AMCDS",
    "https://en.wikipedia.org/wiki/Cybersecurity",
    "https://docs.python.org/3/",
]


@dataclass
class AttackScenario:
    scenario_id: str
    attack_type: str  # 'ransomware' | 'lateral_movement' | 'insider_threat'
    infected_hosts: List[str] = field(default_factory=list)
    elapsed_minutes: int = 5
    host_suspicion: Dict[str, float] = field(default_factory=dict)
    ioc_evidence: Dict[str, list] = field(default_factory=dict)
    ground_truth_spread: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "attack_type": self.attack_type,
            "infected_hosts": list(self.infected_hosts),
            "elapsed_minutes": self.elapsed_minutes,
            "host_suspicion": dict(self.host_suspicion),
            "ioc_evidence": dict(self.ioc_evidence),
            "ground_truth_spread": list(self.ground_truth_spread),
        }


class ScenarioGenerator:
    def __init__(self, topology: NetworkTopology, seed: int = 11) -> None:
        self.topology = topology
        self.rng = random.Random(seed)

    # ----------------------------------------------------------- helpers
    def _simulate_spread(self, start: Set[str], hops: int) -> List[str]:
        """Forward BFS for `hops` steps — what the attack would reach
        if we did nothing. Used as ground truth."""
        spread = set(start)
        frontier = set(start)
        for _ in range(hops):
            nxt = set()
            for h in frontier:
                for nbr in self.topology.neighbors(h):
                    if nbr not in spread:
                        # DCs and DBs resist a bit
                        host = self.topology.hosts[nbr]
                        prob = 0.95 if host.host_type == "workstation" else \
                               0.6  if host.host_type == "app_server" else \
                               0.4
                        if self.rng.random() < prob:
                            nxt.add(nbr)
            spread.update(nxt)
            frontier = nxt
        return sorted(spread)

    def _random_suspicion(self, infected: Set[str]) -> Dict[str, float]:
        """Plausible EDR readouts: infected → high, neighbors → moderate,
        rest → low noise."""
        suspicion: Dict[str, float] = {}
        for hid in self.topology.hosts:
            base = self.rng.uniform(0.0, 0.2)  # background noise
            suspicion[hid] = base
        for h in infected:
            suspicion[h] = self.rng.uniform(0.75, 0.98)
            for nbr in self.topology.neighbors(h):
                suspicion[nbr] = max(suspicion[nbr], self.rng.uniform(0.45, 0.75))
        return suspicion

    # ----------------------------------------------------------- generators
    def ransomware(self, sid: str = "RW") -> AttackScenario:
        # Start on a workstation, spread aggressively.
        ws_pool = [h for h, host in self.topology.hosts.items()
                   if host.host_type == "workstation"]
        seed = self.rng.sample(ws_pool, k=self.rng.randint(1, 2))
        infected = set(seed)

        # 5-15 minutes since detection
        elapsed = self.rng.randint(5, 15)
        spread = self._simulate_spread(infected, hops=3)

        return AttackScenario(
            scenario_id=sid,
            attack_type="ransomware",
            infected_hosts=sorted(infected),
            elapsed_minutes=elapsed,
            host_suspicion=self._random_suspicion(infected),
            ioc_evidence={
                "urls": self.rng.sample(SAMPLE_MAL_URLS, k=2) +
                        self.rng.sample(SAMPLE_BENIGN_URLS, k=1),
                "hashes": [f"sha256:{self.rng.getrandbits(64):016x}"],
            },
            ground_truth_spread=spread,
        )

    def lateral_movement(self, sid: str = "LM") -> AttackScenario:
        # Start on a web server or app server; targeted, slower.
        pool = [h for h, host in self.topology.hosts.items()
                if host.host_type in ("web_server", "app_server")]
        seed = self.rng.sample(pool, k=1)
        infected = set(seed)
        elapsed = self.rng.randint(20, 90)
        spread = self._simulate_spread(infected, hops=2)
        return AttackScenario(
            scenario_id=sid,
            attack_type="lateral_movement",
            infected_hosts=sorted(infected),
            elapsed_minutes=elapsed,
            host_suspicion=self._random_suspicion(infected),
            ioc_evidence={
                "urls": [self.rng.choice(SAMPLE_MAL_URLS)],
                "auth_anomalies": [{"src": s, "auth_failures": self.rng.randint(20, 100)}
                                   for s in seed],
            },
            ground_truth_spread=spread,
        )

    def insider_threat(self, sid: str = "IT") -> AttackScenario:
        # Start on a workstation owned by a privileged user; PII focus.
        pool = [h for h, host in self.topology.hosts.items()
                if host.host_type == "workstation"]
        seed = self.rng.sample(pool, k=1)
        infected = set(seed)
        elapsed = self.rng.randint(60, 240)
        # Insider isn't really "spreading" — they're accessing PII directly.
        spread = []
        for h in seed:
            for nbr in self.topology.neighbors(h):
                if self.topology.hosts[nbr].contains_pii:
                    spread.append(nbr)
        return AttackScenario(
            scenario_id=sid,
            attack_type="insider_threat",
            infected_hosts=sorted(infected),
            elapsed_minutes=elapsed,
            host_suspicion=self._random_suspicion(infected),
            ioc_evidence={
                "urls": [],
                "data_access_anomalies": [{"src": s, "abnormal_pii_reads": self.rng.randint(50, 500)}
                                          for s in seed],
            },
            ground_truth_spread=sorted(set(spread)),
        )

    # ----------------------------------------------------------- batch
    def batch(self, n_each: int = 35) -> List[AttackScenario]:
        out: List[AttackScenario] = []
        for i in range(n_each):
            out.append(self.ransomware(sid=f"RW-{i:03d}"))
        for i in range(n_each):
            out.append(self.lateral_movement(sid=f"LM-{i:03d}"))
        for i in range(n_each):
            out.append(self.insider_threat(sid=f"IT-{i:03d}"))
        return out
