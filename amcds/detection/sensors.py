"""Simulated security sensors — the *environment*, not the defence.

These functions are the only place ground truth is read. They model imperfect
detection tooling: an EDR that catches most but not all ransomware, an auth
monitor that alarms on plenty of benign activity, and an insider-threat blind
spot (an insider using legitimate credentials trips almost no high-fidelity
sensor at all).

The defence pipeline downstream sees only the emitted :class:`Evidence` items
and the behavioural telemetry — never the compromised list.

Detection rates were chosen so that:

* ransomware is mostly caught by high-fidelity sensors (canary files, EDR),
* lateral movement is caught about half the time and otherwise looks like noisy
  authentication,
* insider threat is essentially invisible to signature sensors, which is what
  creates real work for the ML layer and for the agents.
"""
from __future__ import annotations

import random
from typing import Dict, List, Sequence, Tuple

from ..evidence import EVIDENCE_FIDELITY, Evidence, EvidenceType

HIGH_FIDELITY = (
    EvidenceType.RANSOMWARE_CANARY,
    EvidenceType.EDR_MALICIOUS_PROCESS,
    EvidenceType.CREDENTIAL_DUMP,
    EvidenceType.C2_BEACON,
)
MEDIUM_FIDELITY = (
    EvidenceType.AUTH_ANOMALY,
    EvidenceType.LATERAL_CONNECTION,
    EvidenceType.DATA_EXFIL_VOLUME,
)

#: P(sensor fires | host is genuinely compromised), per attack type.
TRUE_POSITIVE_RATES: Dict[str, Dict[EvidenceType, float]] = {
    "ransomware": {
        EvidenceType.RANSOMWARE_CANARY: 0.55,
        EvidenceType.EDR_MALICIOUS_PROCESS: 0.45,
        EvidenceType.C2_BEACON: 0.20,
        EvidenceType.CREDENTIAL_DUMP: 0.05,
        EvidenceType.AUTH_ANOMALY: 0.35,
        EvidenceType.LATERAL_CONNECTION: 0.65,
        EvidenceType.DATA_EXFIL_VOLUME: 0.30,
    },
    "lateral_movement": {
        EvidenceType.RANSOMWARE_CANARY: 0.00,
        EvidenceType.EDR_MALICIOUS_PROCESS: 0.30,
        EvidenceType.C2_BEACON: 0.35,
        EvidenceType.CREDENTIAL_DUMP: 0.30,
        EvidenceType.AUTH_ANOMALY: 0.75,
        EvidenceType.LATERAL_CONNECTION: 0.70,
        EvidenceType.DATA_EXFIL_VOLUME: 0.20,
    },
    "insider_threat": {
        EvidenceType.RANSOMWARE_CANARY: 0.00,
        EvidenceType.EDR_MALICIOUS_PROCESS: 0.03,
        EvidenceType.C2_BEACON: 0.02,
        EvidenceType.CREDENTIAL_DUMP: 0.04,
        EvidenceType.AUTH_ANOMALY: 0.10,
        EvidenceType.LATERAL_CONNECTION: 0.15,
        EvidenceType.DATA_EXFIL_VOLUME: 0.70,
    },
}

#: P(sensor fires | host is benign). Non-zero on purpose: false positives are
#: what make the Business Impact veto necessary in the first place.
FALSE_POSITIVE_RATES: Dict[EvidenceType, float] = {
    EvidenceType.RANSOMWARE_CANARY: 0.002,
    EvidenceType.EDR_MALICIOUS_PROCESS: 0.006,
    EvidenceType.CREDENTIAL_DUMP: 0.004,
    EvidenceType.C2_BEACON: 0.008,
    EvidenceType.AUTH_ANOMALY: 0.10,
    EvidenceType.LATERAL_CONNECTION: 0.08,
    EvidenceType.DATA_EXFIL_VOLUME: 0.06,
}

_DETAIL = {
    EvidenceType.RANSOMWARE_CANARY: "canary files modified in bulk",
    EvidenceType.EDR_MALICIOUS_PROCESS: "EDR blocked 'vssadmin delete shadows /all'",
    EvidenceType.CREDENTIAL_DUMP: "LSASS memory read by non-system process",
    EvidenceType.C2_BEACON: "periodic beacon to a low-reputation host",
    EvidenceType.AUTH_ANOMALY: "burst of failed authentications",
    EvidenceType.LATERAL_CONNECTION: "connections to hosts never contacted before",
    EvidenceType.DATA_EXFIL_VOLUME: "outbound volume far above this host's norm",
}


def dwell_factor(elapsed_minutes: float) -> float:
    """More dwell time means more chances for a sensor to fire.

    Saturates at 1.0 after roughly an hour, floors at 0.5 so a freshly detected
    incident still produces some alerts.
    """
    return float(min(1.0, 0.5 + 0.5 * (elapsed_minutes / 60.0)))


def emit_alerts(host_ids: Sequence[str], compromised: Sequence[str],
                attack_type: str, elapsed_minutes: float,
                rng: random.Random) -> List[Evidence]:
    """Run every sensor against every host and return the alerts that fired."""
    compromised_set = set(compromised)
    tpr = TRUE_POSITIVE_RATES.get(attack_type,
                                  TRUE_POSITIVE_RATES["lateral_movement"])
    factor = dwell_factor(elapsed_minutes)
    alerts: List[Evidence] = []

    for host_id in sorted(host_ids):          # sorted -> reproducible
        is_bad = host_id in compromised_set
        for ev_type in HIGH_FIDELITY + MEDIUM_FIDELITY:
            p = (tpr.get(ev_type, 0.0) * factor if is_bad
                 else FALSE_POSITIVE_RATES.get(ev_type, 0.0))
            if p <= 0.0 or rng.random() >= p:
                continue
            # Alert strength varies; a marginal alert is worth less than a
            # screaming one even from a high-fidelity sensor.
            strength = min(1.0, max(0.5, rng.gauss(0.9 if is_bad else 0.7, 0.12)))
            alerts.append(Evidence(
                host_id=host_id,
                ev_type=ev_type,
                fidelity=EVIDENCE_FIDELITY[ev_type],
                detail=_DETAIL[ev_type],
                strength=strength,
            ))
    return alerts
