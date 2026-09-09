"""The evidence ledger and the hard-evidence predicate the veto depends on."""
from __future__ import annotations

import pytest

from amcds.config import (CORROBORATION_CONFIDENCE, CORROBORATION_MIN_SIGNALS,
                          HARD_EVIDENCE_FIDELITY)
from amcds.evidence import (EVIDENCE_FIDELITY, Evidence, EvidenceType,
                            HostAssessment, ThreatAssessment, noisy_or)


def ev(host, ev_type, strength=1.0):
    return Evidence(host, ev_type, EVIDENCE_FIDELITY[ev_type], strength=strength)


class TestNoisyOr:
    def test_empty_is_zero(self):
        assert noisy_or([]) == 0.0

    def test_single_value_passes_through(self):
        assert noisy_or([0.6]) == pytest.approx(0.6)

    def test_combination_exceeds_each_but_stays_below_one(self):
        c = noisy_or([0.6, 0.6])
        assert 0.6 < c < 1.0
        assert c == pytest.approx(0.84)

    def test_saturates_at_one(self):
        assert noisy_or([1.0, 0.5]) == pytest.approx(1.0)


class TestHardEvidence:
    def test_no_evidence_is_not_hard(self):
        assert HostAssessment("h").has_hard_evidence() is False

    def test_one_high_fidelity_signal_is_hard(self):
        a = HostAssessment("h")
        a.add(ev("h", EvidenceType.RANSOMWARE_CANARY))
        assert a.has_hard_evidence() is True

    def test_one_medium_signal_is_not_hard(self):
        a = HostAssessment("h")
        a.add(ev("h", EvidenceType.AUTH_ANOMALY))
        assert a.has_hard_evidence() is False

    def test_two_medium_signals_are_not_enough(self):
        a = HostAssessment("h")
        a.add(ev("h", EvidenceType.AUTH_ANOMALY))
        a.add(ev("h", EvidenceType.LATERAL_CONNECTION))
        assert a.infection_confidence() < CORROBORATION_CONFIDENCE
        assert a.has_hard_evidence() is False

    def test_three_independent_medium_signals_corroborate(self):
        a = HostAssessment("h")
        for t in (EvidenceType.AUTH_ANOMALY, EvidenceType.LATERAL_CONNECTION,
                  EvidenceType.DATA_EXFIL_VOLUME):
            a.add(ev("h", t))
        assert a.infection_confidence() >= CORROBORATION_CONFIDENCE
        assert a.has_hard_evidence() is True

    def test_repeating_the_same_signal_does_not_corroborate(self):
        """Ten copies of one alert are one piece of evidence, not ten."""
        a = HostAssessment("h")
        for _ in range(10):
            a.add(ev("h", EvidenceType.AUTH_ANOMALY))
        assert len(a.corroborating_items()) == 1
        assert a.has_hard_evidence() is False

    def test_weak_alert_from_a_strong_sensor_is_not_hard(self):
        a = HostAssessment("h")
        a.add(ev("h", EvidenceType.RANSOMWARE_CANARY, strength=0.5))
        assert a.evidence[0].confidence < HARD_EVIDENCE_FIDELITY
        assert a.has_hard_evidence() is False

    def test_low_fidelity_noise_is_excluded_from_corroboration(self):
        a = HostAssessment("h")
        for t in (EvidenceType.PEER_REPUTATION, EvidenceType.MALICIOUS_URL_CONTACT):
            a.add(ev("h", t))
        assert all(e.ev_type != EvidenceType.PEER_REPUTATION
                   for e in a.corroborating_items())

    def test_corroboration_needs_the_configured_minimum(self):
        a = HostAssessment("h")
        a.add(ev("h", EvidenceType.LATERAL_CONNECTION))
        assert len(a.corroborating_items()) < CORROBORATION_MIN_SIGNALS
        assert a.has_hard_evidence() is False


class TestSuspicion:
    def test_high_ml_risk_alone_is_suspicious_but_never_hard(self):
        a = HostAssessment("h", risk_score=0.995)
        assert a.is_suspicious() is True
        assert a.has_hard_evidence() is False

    def test_low_risk_and_no_alerts_is_not_suspicious(self):
        assert HostAssessment("h", risk_score=0.1).is_suspicious() is False

    def test_why_is_always_a_non_empty_explanation(self):
        assert HostAssessment("h").why()
        a = HostAssessment("h", risk_score=0.4)
        assert "0.40" in a.why()
        a.add(ev("h", EvidenceType.C2_BEACON))
        assert "c2_beacon" in a.why()


class TestThreatAssessment:
    def test_confirmed_and_suspected_are_disjoint(self):
        ta = ThreatAssessment("S", "ransomware", 10)
        ta.get("bad").add(ev("bad", EvidenceType.RANSOMWARE_CANARY))
        ta.get("odd").risk_score = 0.99
        ta.get("fine").risk_score = 0.05
        assert ta.confirmed_infected() == {"bad"}
        assert ta.suspected() == {"odd"}
        assert not (ta.confirmed_infected() & ta.suspected())

    def test_get_creates_missing_hosts(self):
        ta = ThreatAssessment("S", "ransomware", 10)
        assert ta.get("new").host_id == "new"
        assert "new" in ta.hosts

    def test_risk_of_unknown_host_is_zero(self):
        assert ThreatAssessment("S", "ransomware", 10).risk_of("ghost") == 0.0

    def test_serialisation_is_sorted_and_complete(self):
        ta = ThreatAssessment("S", "ransomware", 10)
        for h in ("z", "a", "m"):
            ta.get(h)
        d = ta.to_dict()
        assert list(d["hosts"]) == ["a", "m", "z"]
        assert d["scenario_id"] == "S"
