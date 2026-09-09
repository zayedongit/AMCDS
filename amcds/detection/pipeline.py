"""Defence-side detection pipeline: telemetry + alerts -> ThreatAssessment.

    sensor alerts ─┐
                   ├─> fuse ─> ThreatAssessment ─> the five agents
    telemetry ─> ML risk score ─┘

The ML score enters the evidence ledger as an ``ML_ANOMALY`` item whose fidelity
is derived from the calibrated risk. It is deliberately capped below
``HARD_EVIDENCE_FIDELITY``: an anomaly detector alone must never be enough to
override a gold-tier SLA. It can, however, act as one of several independent
signals that together corroborate.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from ..config import HARD_EVIDENCE_FIDELITY, ML_SUSPICIOUS_THRESHOLD
from ..evidence import Evidence, EvidenceType, HostAssessment, ThreatAssessment
from ..network.topology import NetworkTopology

#: The most fidelity an ML anomaly may ever claim. Strictly below the
#: hard-evidence bar so the model can corroborate but never confirm alone.
ML_MAX_FIDELITY = 0.75
ML_MIN_FIDELITY = 0.40


def ml_fidelity(risk_score: float) -> float:
    """Map a calibrated risk in [threshold, 1] onto [ML_MIN, ML_MAX] fidelity."""
    lo = ML_SUSPICIOUS_THRESHOLD
    if risk_score < lo:
        return 0.0
    frac = (risk_score - lo) / max(1e-9, 1.0 - lo)
    fid = ML_MIN_FIDELITY + frac * (ML_MAX_FIDELITY - ML_MIN_FIDELITY)
    return float(min(ML_MAX_FIDELITY, fid))


def build_assessment(topology: NetworkTopology, scenario_id: str,
                     attack_type: str, elapsed_minutes: int,
                     alerts: Sequence[Evidence],
                     risks: Optional[Dict[str, "object"]] = None,
                     ioc_evidence: Optional[dict] = None) -> ThreatAssessment:
    """Fuse sensor alerts and (optionally) ML risk into one assessment.

    Passing ``risks=None`` produces the *no-ML ablation* used by the benchmark:
    the agents then see only signature-sensor alerts.
    """
    ta = ThreatAssessment(
        scenario_id=scenario_id,
        attack_type=attack_type,
        elapsed_minutes=elapsed_minutes,
        ioc_evidence=dict(ioc_evidence or {}),
    )
    for host_id in topology.host_ids():
        ta.hosts[host_id] = HostAssessment(host_id=host_id)

    for ev in alerts:
        ta.get(ev.host_id).add(ev)

    if risks:
        for host_id in topology.host_ids():
            hr = risks.get(host_id)
            if hr is None:
                continue
            assessment = ta.get(host_id)
            assessment.risk_score = float(hr.risk_score)
            fid = ml_fidelity(assessment.risk_score)
            if fid <= 0.0:
                continue
            assert fid < HARD_EVIDENCE_FIDELITY, "ML must never be hard evidence"
            assessment.add(Evidence(
                host_id=host_id,
                ev_type=EvidenceType.ML_ANOMALY,
                fidelity=fid,
                detail=getattr(hr, "explanation", lambda: "")(),
                strength=1.0,
            ))
    return ta
