"""Reproducible attack-scenario generator.

One scenario bundles three things that must stay consistent with each other:

1. **Ground truth** — where the attack started and, via
   :class:`~amcds.attack.propagation.PropagationModel`, which hosts it actually
   reaches if nobody intervenes. Used *only* by the evaluation harness.
2. **Observations** — sensor alerts and behavioural telemetry. This is all the
   defence pipeline is allowed to see.
3. **Metadata** — attack type, dwell time, scenario id.

Reproducibility
---------------
Every scenario derives its own ``random.Random`` from
``hash_seed(master_seed, scenario_id)``, so scenario ``RW-007`` is identical
whether you generate 10 scenarios or 1,000, and regenerating one scenario does
not shift any other. All iteration is over sorted sequences — the original
generator iterated over ``set`` objects, which under Python's randomised string
hashing made the whole benchmark irreproducible between processes.
"""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from ..attack.propagation import PROFILES, PropagationModel
from ..detection.sensors import emit_alerts
from ..evidence import Evidence
from ..network.topology import NetworkTopology
from ..telemetry.generator import HostTelemetry, TelemetryGenerator

ATTACK_TYPES = ("ransomware", "lateral_movement", "insider_threat")

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


def derive_seed(master_seed: int, key: str) -> int:
    """Stable per-scenario seed. Independent of generation order."""
    digest = hashlib.sha256(f"{master_seed}:{key}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


@dataclass
class AttackScenario:
    """One fully specified, reproducible incident."""

    scenario_id: str
    attack_type: str
    seed_hosts: List[str]                       # where the attack started
    elapsed_minutes: int
    #: Ground truth: every host the attack owns after ``elapsed_minutes``.
    ground_truth_compromised: List[str] = field(default_factory=list)
    #: Observable sensor alerts.
    alerts: List[Evidence] = field(default_factory=list)
    #: Observable behavioural telemetry, host_id -> window.
    telemetry: Dict[str, HostTelemetry] = field(default_factory=dict)
    ioc_evidence: Dict[str, list] = field(default_factory=dict)
    #: Seed used for the propagation RNG, so counterfactuals can be replayed.
    propagation_seed: int = 0
    #: Diagnostic record of how the attack actually spread.
    propagation: dict = field(default_factory=dict)

    # ------------------------------------------------------------- accessors
    @property
    def infected_hosts(self) -> List[str]:
        """Backwards-compatible alias for the ground-truth compromised set."""
        return list(self.ground_truth_compromised)

    def to_dict(self, include_telemetry: bool = False) -> dict:
        d = {
            "scenario_id": self.scenario_id,
            "attack_type": self.attack_type,
            "seed_hosts": list(self.seed_hosts),
            "elapsed_minutes": self.elapsed_minutes,
            "ground_truth_compromised": list(self.ground_truth_compromised),
            "n_compromised": len(self.ground_truth_compromised),
            "n_alerts": len(self.alerts),
            "ioc_evidence": dict(self.ioc_evidence),
            "propagation_seed": self.propagation_seed,
        }
        if include_telemetry:
            d["telemetry"] = {h: t.to_dict() for h, t in sorted(self.telemetry.items())}
        return d


class ScenarioGenerator:
    """Builds reproducible scenarios on a fixed topology."""

    def __init__(self, topology: NetworkTopology, seed: int = 11) -> None:
        self.topology = topology
        self.seed = seed
        self.propagation = PropagationModel(topology)
        self.telemetry_gen = TelemetryGenerator(topology)

    # ---------------------------------------------------------------- pools
    def _pool(self, attack_type: str) -> List[str]:
        t = self.topology
        if attack_type == "ransomware":
            pool = [h for h in t.host_ids() if t.hosts[h].host_type == "workstation"]
        elif attack_type == "lateral_movement":
            pool = [h for h in t.host_ids()
                    if t.hosts[h].host_type in ("web_server", "app_server", "jump_host")]
        else:  # insider_threat
            pool = [h for h in t.host_ids()
                    if t.hosts[h].host_type in ("workstation", "jump_host")]
        if not pool:
            raise ValueError(f"no candidate seed hosts for attack type {attack_type!r}")
        return pool

    def _dwell(self, attack_type: str, rng: random.Random) -> int:
        if attack_type == "ransomware":
            return rng.randint(5, 20)
        if attack_type == "lateral_movement":
            return rng.randint(25, 120)
        return rng.randint(60, 300)

    def _n_seeds(self, attack_type: str, rng: random.Random) -> int:
        return 2 if (attack_type == "ransomware" and rng.random() < 0.35) else 1

    def _iocs(self, attack_type: str, rng: random.Random) -> Dict[str, list]:
        if attack_type == "insider_threat":
            return {"urls": [], "notes": ["no external C2 observed"]}
        k = 2 if attack_type == "ransomware" else 1
        return {
            "urls": sorted(rng.sample(SAMPLE_MAL_URLS, k=k)) +
                    sorted(rng.sample(SAMPLE_BENIGN_URLS, k=1)),
            "hashes": [f"sha256:{rng.getrandbits(64):016x}"],
        }

    # ------------------------------------------------------------- generation
    def generate(self, scenario_id: str, attack_type: str) -> AttackScenario:
        """Build one scenario. Deterministic in (master seed, scenario_id)."""
        if attack_type not in PROFILES:
            raise ValueError(f"unknown attack type {attack_type!r}; "
                             f"expected one of {sorted(PROFILES)}")
        base = derive_seed(self.seed, scenario_id)
        rng = random.Random(base)

        pool = self._pool(attack_type)
        seed_hosts = sorted(rng.sample(pool, k=min(self._n_seeds(attack_type, rng),
                                                   len(pool))))
        elapsed = self._dwell(attack_type, rng)

        prop_seed = (base ^ 0x5EED) % (2 ** 32)
        result = self.propagation.counterfactual_spread(
            seed_hosts, attack_type, elapsed, prop_seed)

        alerts = emit_alerts(self.topology.host_ids(), result.compromised,
                             attack_type, elapsed, rng)
        telemetry = self.telemetry_gen.generate(result.compromised, attack_type, rng)

        return AttackScenario(
            scenario_id=scenario_id,
            attack_type=attack_type,
            seed_hosts=seed_hosts,
            elapsed_minutes=elapsed,
            ground_truth_compromised=list(result.compromised),
            alerts=alerts,
            telemetry=telemetry,
            ioc_evidence=self._iocs(attack_type, rng),
            propagation_seed=prop_seed,
            propagation=result.to_dict(),
        )

    # -------------------------------------------------------- convenience API
    def ransomware(self, sid: str = "RW") -> AttackScenario:
        return self.generate(sid, "ransomware")

    def lateral_movement(self, sid: str = "LM") -> AttackScenario:
        return self.generate(sid, "lateral_movement")

    def insider_threat(self, sid: str = "IT") -> AttackScenario:
        return self.generate(sid, "insider_threat")

    def batch(self, n_each: int = 15) -> List[AttackScenario]:
        """``n_each`` scenarios per attack type, in a stable order.

        The default of 15 gives the canonical 45-scenario benchmark suite.
        """
        prefixes = {"ransomware": "RW", "lateral_movement": "LM",
                    "insider_threat": "IT"}
        out: List[AttackScenario] = []
        for attack_type in ATTACK_TYPES:
            for i in range(n_each):
                out.append(self.generate(f"{prefixes[attack_type]}-{i:03d}",
                                         attack_type))
        return out
