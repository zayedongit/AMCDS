"""Behavioural telemetry generator.

Each host emits a fixed set of counters aggregated over one observation window
(30 minutes by default). These counters are the *raw material* for the ML layer;
no ground-truth label ever appears in them.

Why generate rather than use a public dataset
---------------------------------------------
The anomaly model has to score hosts *in this specific topology*, using
graph-derived features (centrality, zone diversity, neighbour context) that only
exist for this network. No public NIDS dataset carries that join key. The
generator is therefore part of the experiment design, and the honest framing is:
the ML result measures whether the feature set and model can separate
compromised from benign hosts **under this generative model**, not on real
enterprise traffic. That limitation is stated in the docs.

What keeps the task non-trivial
-------------------------------
* Every host has a *persistent* benign profile drawn from a heavy-tailed
  lognormal, so some benign hosts are legitimately noisy (backup windows, admin
  workstations, busy app servers) and produce genuine false positives.
* Compromised hosts are perturbed by attack-specific multipliers that overlap
  the benign tail rather than sitting cleanly outside it.
* A fraction of compromised hosts (``stealth_rate``) barely deviate at all,
  producing genuine false negatives.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Sequence

from ..network.topology import NetworkTopology

#: Ordered feature names. The order is fixed so the model's feature matrix and
#: any saved artefact stay aligned.
TELEMETRY_FIELDS: List[str] = [
    "outbound_connections",
    "distinct_peers",
    "new_peer_ratio",
    "failed_auth_count",
    "failed_auth_ratio",
    "distinct_dest_ports",
    "bytes_out_mb",
    "bytes_in_mb",
    "off_hours_activity_ratio",
    "admin_process_launches",
    "file_ops_per_min",
    "peer_zone_diversity",
    "beacon_regularity",
]


@dataclass
class HostTelemetry:
    """One observation window of behaviour for one host."""

    host_id: str
    host_type: str
    zone: str
    outbound_connections: float = 0.0
    distinct_peers: float = 0.0
    new_peer_ratio: float = 0.0
    failed_auth_count: float = 0.0
    failed_auth_ratio: float = 0.0
    distinct_dest_ports: float = 0.0
    bytes_out_mb: float = 0.0
    bytes_in_mb: float = 0.0
    off_hours_activity_ratio: float = 0.0
    admin_process_launches: float = 0.0
    file_ops_per_min: float = 0.0
    peer_zone_diversity: float = 0.0
    beacon_regularity: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)

    def feature_vector(self) -> List[float]:
        d = asdict(self)
        return [float(d[f]) for f in TELEMETRY_FIELDS]


@dataclass(frozen=True)
class Baseline:
    """Median benign values for a host type. Spread comes from the lognormal."""

    outbound_connections: float
    distinct_peers: float
    failed_auth_count: float
    distinct_dest_ports: float
    bytes_out_mb: float
    bytes_in_mb: float
    admin_process_launches: float
    file_ops_per_min: float
    off_hours: float
    #: Multiplicative spread (sigma of the underlying lognormal).
    sigma: float = 0.45


BASELINE_BY_HOST_TYPE: Dict[str, Baseline] = {
    "workstation":        Baseline(70, 6, 1.2, 8, 22, 180, 0.4, 9, 0.06),
    "file_server":        Baseline(220, 20, 0.8, 5, 240, 300, 0.6, 140, 0.10),
    "app_server":         Baseline(900, 12, 0.6, 9, 700, 800, 1.1, 25, 0.30),
    "db_server":          Baseline(500, 8, 0.5, 4, 900, 400, 0.9, 60, 0.32),
    "web_server":         Baseline(1500, 10, 1.5, 6, 1100, 950, 0.7, 12, 0.38),
    "domain_controller":  Baseline(1800, 30, 9.0, 7, 300, 350, 1.4, 18, 0.34),
    "jump_host":          Baseline(160, 14, 2.0, 12, 90, 110, 6.0, 8, 0.22),
}

_DEFAULT_BASELINE = BASELINE_BY_HOST_TYPE["workstation"]


@dataclass(frozen=True)
class AttackSignature:
    """Multipliers applied to a compromised host's benign counters."""

    outbound_connections: float = 1.0
    distinct_peers: float = 1.0
    new_peer_ratio: float = 0.0        # absolute, not a multiplier
    failed_auth_count: float = 1.0
    distinct_dest_ports: float = 1.0
    bytes_out_mb: float = 1.0
    admin_process_launches: float = 1.0
    file_ops_per_min: float = 1.0
    off_hours_bonus: float = 0.0       # absolute additive
    peer_zone_bonus: float = 0.0       # absolute additive
    beacon_regularity: float = 0.0     # absolute target


ATTACK_SIGNATURES: Dict[str, AttackSignature] = {
    # Mass file encryption + share enumeration; loud on the file/IO axis.
    "ransomware": AttackSignature(
        outbound_connections=2.1, distinct_peers=3.0, new_peer_ratio=0.55,
        failed_auth_count=2.5, distinct_dest_ports=1.8, bytes_out_mb=1.6,
        admin_process_launches=4.0, file_ops_per_min=7.5,
        off_hours_bonus=0.20, peer_zone_bonus=1.0, beacon_regularity=0.45),
    # Credential reuse and scanning; loud on auth + peer novelty + beaconing.
    "lateral_movement": AttackSignature(
        outbound_connections=1.8, distinct_peers=3.6, new_peer_ratio=0.7,
        failed_auth_count=7.0, distinct_dest_ports=3.2, bytes_out_mb=1.2,
        admin_process_launches=5.5, file_ops_per_min=1.3,
        off_hours_bonus=0.28, peer_zone_bonus=1.6, beacon_regularity=0.72),
    # Legitimate credentials, abnormal data volume; quiet on auth.
    "insider_threat": AttackSignature(
        outbound_connections=1.25, distinct_peers=1.6, new_peer_ratio=0.30,
        failed_auth_count=1.1, distinct_dest_ports=1.2, bytes_out_mb=9.0,
        admin_process_launches=1.4, file_ops_per_min=4.5,
        off_hours_bonus=0.35, peer_zone_bonus=0.6, beacon_regularity=0.10),
}


class TelemetryGenerator:
    """Emits one observation window of telemetry for every host."""

    #: Share of compromised hosts that stay near their benign profile. These are
    #: the model's unavoidable false negatives and they are intentional.
    STEALTH_RATE = 0.18
    #: Share of benign hosts that have an unusually busy window (backup job,
    #: admin session, batch load). These drive genuine false positives.
    NOISY_BENIGN_RATE = 0.10

    def __init__(self, topology: NetworkTopology) -> None:
        self.topology = topology

    # -------------------------------------------------------------- sampling
    @staticmethod
    def _lognormal(rng: random.Random, median: float, sigma: float) -> float:
        """Heavy-tailed draw whose median is exactly ``median``."""
        if median <= 0:
            return 0.0
        return float(median * math.exp(rng.gauss(0.0, sigma)))

    def _benign(self, host_id: str, rng: random.Random,
                noisy: bool) -> HostTelemetry:
        host = self.topology.hosts[host_id]
        b = BASELINE_BY_HOST_TYPE.get(host.host_type, _DEFAULT_BASELINE)
        sigma = b.sigma * (2.0 if noisy else 1.0)
        boost = 2.6 if noisy else 1.0

        n_peers = max(1.0, self._lognormal(rng, b.distinct_peers * boost, sigma))
        n_peers = min(n_peers, float(max(1, self.topology.graph.degree(host_id) * 3)))
        succ_auth = max(1.0, self._lognormal(rng, b.outbound_connections * 0.2, sigma))
        failed = self._lognormal(rng, b.failed_auth_count * boost, sigma)

        return HostTelemetry(
            host_id=host_id,
            host_type=host.host_type,
            zone=host.zone,
            outbound_connections=self._lognormal(rng, b.outbound_connections * boost, sigma),
            distinct_peers=n_peers,
            new_peer_ratio=min(1.0, abs(rng.gauss(0.05, 0.05)) * (2.5 if noisy else 1.0)),
            failed_auth_count=failed,
            failed_auth_ratio=min(1.0, failed / (failed + succ_auth)),
            distinct_dest_ports=max(1.0, self._lognormal(rng, b.distinct_dest_ports * boost, sigma)),
            bytes_out_mb=self._lognormal(rng, b.bytes_out_mb * boost, sigma),
            bytes_in_mb=self._lognormal(rng, b.bytes_in_mb, sigma),
            off_hours_activity_ratio=min(1.0, abs(rng.gauss(b.off_hours, 0.06))
                                         * (2.0 if noisy else 1.0)),
            admin_process_launches=self._lognormal(rng, b.admin_process_launches * boost, sigma),
            file_ops_per_min=self._lognormal(rng, b.file_ops_per_min * boost, sigma),
            peer_zone_diversity=float(min(5, max(1, round(rng.gauss(1.5, 0.7))))),
            beacon_regularity=min(1.0, abs(rng.gauss(0.12, 0.10))),
        )

    def _apply_attack(self, tel: HostTelemetry, attack_type: str,
                      rng: random.Random, stealthy: bool) -> HostTelemetry:
        sig = ATTACK_SIGNATURES.get(attack_type, ATTACK_SIGNATURES["lateral_movement"])
        # A stealthy actor expresses only a fraction of the signature.
        k = 0.15 if stealthy else 1.0
        # Per-host jitter so compromised hosts are not identical.
        j = lambda: 1.0 + rng.gauss(0.0, 0.18)

        def blend(mult: float) -> float:
            return 1.0 + (mult - 1.0) * k * max(0.2, j())

        tel.outbound_connections *= blend(sig.outbound_connections)
        tel.distinct_peers *= blend(sig.distinct_peers)
        tel.failed_auth_count *= blend(sig.failed_auth_count)
        tel.distinct_dest_ports *= blend(sig.distinct_dest_ports)
        tel.bytes_out_mb *= blend(sig.bytes_out_mb)
        tel.admin_process_launches *= blend(sig.admin_process_launches)
        tel.file_ops_per_min *= blend(sig.file_ops_per_min)

        tel.new_peer_ratio = min(1.0, tel.new_peer_ratio + sig.new_peer_ratio * k * abs(j()))
        tel.off_hours_activity_ratio = min(
            1.0, tel.off_hours_activity_ratio + sig.off_hours_bonus * k * abs(j()))
        tel.peer_zone_diversity = min(
            5.0, tel.peer_zone_diversity + sig.peer_zone_bonus * k)
        tel.beacon_regularity = min(
            1.0, max(tel.beacon_regularity, sig.beacon_regularity * k * abs(j())))

        succ = max(1.0, tel.outbound_connections * 0.2)
        tel.failed_auth_ratio = min(1.0, tel.failed_auth_count /
                                    (tel.failed_auth_count + succ))
        return tel

    # ------------------------------------------------------------------- API
    def generate(self, compromised: Sequence[str], attack_type: str,
                 rng: random.Random) -> Dict[str, HostTelemetry]:
        """One observation window for every host in the topology."""
        compromised_set = set(compromised)
        out: Dict[str, HostTelemetry] = {}
        for host_id in self.topology.host_ids():   # sorted -> reproducible
            noisy = (host_id not in compromised_set
                     and rng.random() < self.NOISY_BENIGN_RATE)
            tel = self._benign(host_id, rng, noisy)
            if host_id in compromised_set:
                stealthy = rng.random() < self.STEALTH_RATE
                tel = self._apply_attack(tel, attack_type, rng, stealthy)
            out[host_id] = tel
        return out

    def generate_baseline_corpus(self, n_windows: int, seed: int
                                 ) -> List[HostTelemetry]:
        """Attack-free windows used to *train* the unsupervised risk model.

        The model never sees an attack during training — it only learns what
        normal looks like — which is what makes IsolationForest the right tool
        and keeps the evaluation honest.
        """
        rng = random.Random(seed)
        corpus: List[HostTelemetry] = []
        for _ in range(n_windows):
            for host_id in self.topology.host_ids():
                noisy = rng.random() < self.NOISY_BENIGN_RATE
                corpus.append(self._benign(host_id, rng, noisy))
        return corpus
