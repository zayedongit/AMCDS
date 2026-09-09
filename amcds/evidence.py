"""Evidence model — what the system actually *knows* about a host.

Motivation
----------
The original prototype asked "is this host in ``scenario['infected_hosts']``?".
That is ground truth, which a real defender never has. Every downstream claim
built on it (especially the Business Impact agent's "hard evidence of infection"
veto override) was therefore untestable.

This module replaces that oracle with an explicit evidence ledger:

* :class:`Evidence` — one observation about one host, with a *fidelity* saying
  how trustworthy that class of observation is.
* :class:`HostAssessment` — everything known about a single host: its evidence
  items, the ML risk score, and the derived booleans the agents reason over.
* :class:`ThreatAssessment` — the per-scenario collection handed to the agents.

The key predicate is :meth:`HostAssessment.has_hard_evidence`:

    A host has HARD evidence of infection when either

      (a) at least one HIGH-fidelity signal was observed
          (fidelity >= ``HARD_EVIDENCE_FIDELITY``), or
      (b) at least ``CORROBORATION_MIN_SIGNALS`` *independent* medium-fidelity
          signals combine (noisy-OR) to a confidence of at least
          ``CORROBORATION_CONFIDENCE``.

"Independent" means distinct :class:`EvidenceType` values — three copies of the
same failed-login alert do not corroborate each other.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional, Set

from .config import (
    CORROBORATION_CONFIDENCE,
    CORROBORATION_MIN_SIGNALS,
    HARD_EVIDENCE_FIDELITY,
    ML_STRONG_THRESHOLD,
    ML_SUSPICIOUS_THRESHOLD,
    WEAK_EVIDENCE_FIDELITY,
)


class EvidenceType(str, Enum):
    """Classes of observation, ordered roughly by how hard they are to fake.

    Fidelity values are properties of the *detector*, not of one alert: an EDR
    that reports ``vssadmin delete shadows`` is almost never wrong, whereas a
    burst of failed logins has many benign explanations.
    """

    # --- high fidelity: a defender would act on any one of these alone -------
    RANSOMWARE_CANARY = "ransomware_canary"
    EDR_MALICIOUS_PROCESS = "edr_malicious_process"
    CREDENTIAL_DUMP = "credential_dump"
    C2_BEACON = "c2_beacon"

    # --- medium fidelity: suggestive, needs corroboration -------------------
    AUTH_ANOMALY = "auth_anomaly"
    LATERAL_CONNECTION = "lateral_connection"
    DATA_EXFIL_VOLUME = "data_exfil_volume"
    ML_ANOMALY = "ml_anomaly"

    # --- low fidelity: context only -----------------------------------------
    MALICIOUS_URL_CONTACT = "malicious_url_contact"
    PEER_REPUTATION = "peer_reputation"


#: Detector fidelity per evidence class. Single source of truth.
EVIDENCE_FIDELITY: Dict[EvidenceType, float] = {
    EvidenceType.RANSOMWARE_CANARY: 0.97,
    EvidenceType.EDR_MALICIOUS_PROCESS: 0.94,
    EvidenceType.CREDENTIAL_DUMP: 0.92,
    EvidenceType.C2_BEACON: 0.88,
    EvidenceType.AUTH_ANOMALY: 0.55,
    EvidenceType.LATERAL_CONNECTION: 0.60,
    EvidenceType.DATA_EXFIL_VOLUME: 0.58,
    EvidenceType.ML_ANOMALY: 0.50,          # overridden per-instance by the model
    EvidenceType.MALICIOUS_URL_CONTACT: 0.35,
    EvidenceType.PEER_REPUTATION: 0.20,
}


def is_high_fidelity(ev_type: EvidenceType) -> bool:
    return EVIDENCE_FIDELITY[ev_type] >= HARD_EVIDENCE_FIDELITY


@dataclass(frozen=True)
class Evidence:
    """A single observation about a single host."""

    host_id: str
    ev_type: EvidenceType
    fidelity: float
    detail: str = ""
    #: Detector-reported strength of this specific alert in [0, 1]. Used to
    #: scale the fidelity (a marginal alert from a good detector is worth less
    #: than a screaming one).
    strength: float = 1.0

    @property
    def confidence(self) -> float:
        """Effective confidence this single item lends to "host is infected"."""
        return max(0.0, min(1.0, self.fidelity * self.strength))

    @property
    def is_hard(self) -> bool:
        return self.confidence >= HARD_EVIDENCE_FIDELITY

    def to_dict(self) -> dict:
        return {
            "host_id": self.host_id,
            "type": self.ev_type.value,
            "fidelity": round(self.fidelity, 4),
            "strength": round(self.strength, 4),
            "confidence": round(self.confidence, 4),
            "is_hard": self.is_hard,
            "detail": self.detail,
        }


def noisy_or(confidences: Iterable[float]) -> float:
    """Combine independent probabilistic signals: 1 - prod(1 - p_i).

    This is the standard "at least one of these is a true positive" combination
    and is why two 0.6 signals (0.84) still fall short of one 0.94 signal.
    """
    acc = 1.0
    for c in confidences:
        acc *= (1.0 - max(0.0, min(1.0, c)))
    return 1.0 - acc


@dataclass
class HostAssessment:
    """Everything the detection layer knows about one host."""

    host_id: str
    evidence: List[Evidence] = field(default_factory=list)
    #: Calibrated anomaly risk from the ML layer, in [0, 1]. ``None`` when the
    #: ML layer is disabled (used by the AMCDS_NO_ML ablation).
    risk_score: Optional[float] = None

    # ---------------------------------------------------------------- adders
    def add(self, ev: Evidence) -> None:
        self.evidence.append(ev)

    # ------------------------------------------------------------ predicates
    def hard_items(self) -> List[Evidence]:
        return [e for e in self.evidence if e.is_hard]

    def corroborating_items(self) -> List[Evidence]:
        """Best independent medium-strength item per evidence type."""
        best: Dict[EvidenceType, Evidence] = {}
        for e in self.evidence:
            if e.confidence < WEAK_EVIDENCE_FIDELITY:
                continue
            cur = best.get(e.ev_type)
            if cur is None or e.confidence > cur.confidence:
                best[e.ev_type] = e
        return sorted(best.values(), key=lambda e: (-e.confidence, e.ev_type.value))

    def has_hard_evidence(self) -> bool:
        """The predicate the Business Impact agent's veto override depends on.

        True when a single high-fidelity detector fired, or when enough
        *independent* medium signals corroborate each other.
        """
        if self.hard_items():
            return True
        items = self.corroborating_items()
        if len(items) < CORROBORATION_MIN_SIGNALS:
            return False
        return noisy_or(e.confidence for e in items) >= CORROBORATION_CONFIDENCE

    def infection_confidence(self) -> float:
        """Overall probability-like confidence that this host is compromised."""
        items = self.corroborating_items()
        if not items:
            return 0.0
        return noisy_or(e.confidence for e in items)

    def is_suspicious(self) -> bool:
        """Weaker predicate: something is off, but not provable."""
        if self.has_hard_evidence():
            return True
        if self.risk_score is not None and self.risk_score >= ML_SUSPICIOUS_THRESHOLD:
            return True
        return self.infection_confidence() >= 0.5

    def ml_is_strong(self) -> bool:
        return self.risk_score is not None and self.risk_score >= ML_STRONG_THRESHOLD

    def why(self) -> str:
        """One-line human explanation used in decision traces."""
        hard = self.hard_items()
        if hard:
            top = max(hard, key=lambda e: e.confidence)
            return (f"hard evidence: {top.ev_type.value} "
                    f"(confidence {top.confidence:.2f}) — {top.detail}")
        items = self.corroborating_items()
        if items:
            names = ", ".join(f"{e.ev_type.value}@{e.confidence:.2f}" for e in items)
            verdict = "corroborated" if self.has_hard_evidence() else "not corroborated"
            return (f"{len(items)} independent signal(s) [{names}] -> "
                    f"combined {self.infection_confidence():.2f} ({verdict})")
        if self.risk_score is not None:
            return f"no detector alerts; ML risk score {self.risk_score:.2f}"
        return "no evidence"

    def to_dict(self) -> dict:
        return {
            "host_id": self.host_id,
            "risk_score": None if self.risk_score is None else round(self.risk_score, 4),
            "infection_confidence": round(self.infection_confidence(), 4),
            "has_hard_evidence": self.has_hard_evidence(),
            "is_suspicious": self.is_suspicious(),
            "evidence": [e.to_dict() for e in self.evidence],
            "why": self.why(),
        }


@dataclass
class ThreatAssessment:
    """Per-scenario detection output handed to the five agents.

    This is the *only* channel through which the agents learn about the attack.
    They never see ``scenario.infected_hosts`` (ground truth) directly.
    """

    scenario_id: str
    attack_type: str
    elapsed_minutes: int
    hosts: Dict[str, HostAssessment] = field(default_factory=dict)
    #: Free-form IOCs (URLs, hashes) that are not host-attributable.
    ioc_evidence: Dict[str, list] = field(default_factory=dict)

    # ---------------------------------------------------------------- access
    def get(self, host_id: str) -> HostAssessment:
        if host_id not in self.hosts:
            self.hosts[host_id] = HostAssessment(host_id=host_id)
        return self.hosts[host_id]

    def confirmed_infected(self) -> Set[str]:
        """Hosts with hard evidence — what the system treats as *known* bad."""
        return {h for h, a in self.hosts.items() if a.has_hard_evidence()}

    def suspected(self) -> Set[str]:
        """Hosts that look bad but are not proven."""
        return {h for h, a in self.hosts.items()
                if a.is_suspicious() and not a.has_hard_evidence()}

    def risk_scores(self) -> Dict[str, float]:
        return {h: (a.risk_score or 0.0) for h, a in self.hosts.items()}

    def risk_of(self, host_id: str) -> float:
        a = self.hosts.get(host_id)
        return 0.0 if a is None or a.risk_score is None else a.risk_score

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "attack_type": self.attack_type,
            "elapsed_minutes": self.elapsed_minutes,
            "confirmed_infected": sorted(self.confirmed_infected()),
            "suspected": sorted(self.suspected()),
            "hosts": {h: self.hosts[h].to_dict() for h in sorted(self.hosts)},
            "ioc_evidence": dict(self.ioc_evidence),
        }
