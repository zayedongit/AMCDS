"""Host risk model: unsupervised anomaly detection with a calibrated score.

Design decisions and why
------------------------
**IsolationForest, not a classifier.** In a real SOC you do not have labelled
"this host was compromised" data for your own network. You do have plenty of
quiet days. So the model is fitted on an attack-free baseline corpus only and
never sees a labelled attack. Evaluation against ground truth is therefore a
genuine held-out test rather than a fit statistic.

**Calibration.** ``IsolationForest.score_samples`` returns an unbounded, model
specific number that is meaningless to an agent or an analyst. We convert it to
an empirical percentile against the benign score distribution:

    risk(x) = P_benign( score <= score(x) )

so ``risk = 0.97`` reads as "only 3% of normal windows looked at least this
unusual". That is a statement a student can defend in an interview and a number
the Business Impact agent can put a threshold on.

**Interpretability.** Alongside the score the model returns the peer-group
z-scores that drove it, so every risk value comes with "because
``failed_auth_count`` was +6.4 sigma and ``distinct_peers`` +4.1 sigma for a
workstation".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from ..config import (ISOLATION_FOREST_CONTAMINATION,
                      ISOLATION_FOREST_ESTIMATORS)
from ..network.topology import NetworkTopology
from ..telemetry.generator import HostTelemetry
from .features import (MODEL_FEATURES, PeerGroupNormalizer, build_raw_frame,
                       top_contributing_features)


@dataclass
class HostRisk:
    """Per-host output of the risk model."""

    host_id: str
    risk_score: float                       # calibrated, in [0, 1]
    raw_score: float                        # IsolationForest score_samples
    drivers: List[tuple] = field(default_factory=list)   # [(feature, z), ...]

    def explanation(self) -> str:
        if not self.drivers:
            return (f"risk {self.risk_score:.2f}: behaviour within the normal "
                    f"range for this host's peer group")
        parts = ", ".join(f"{name} +{z:.1f}σ" for name, z in self.drivers)
        return f"risk {self.risk_score:.2f} driven by {parts} vs peer-group baseline"

    def to_dict(self) -> dict:
        return {
            "host_id": self.host_id,
            "risk_score": round(self.risk_score, 4),
            "raw_score": round(self.raw_score, 6),
            "drivers": [[n, z] for n, z in self.drivers],
            "explanation": self.explanation(),
        }


class HostRiskModel:
    """IsolationForest over peer-group-normalised behavioural features."""

    def __init__(self, contamination: float = ISOLATION_FOREST_CONTAMINATION,
                 n_estimators: int = ISOLATION_FOREST_ESTIMATORS,
                 random_state: int = 42) -> None:
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.normalizer = PeerGroupNormalizer()
        self.forest: Optional[IsolationForest] = None
        self._benign_scores: Optional[np.ndarray] = None
        self.n_train_windows: int = 0

    # ------------------------------------------------------------------ fit
    def fit(self, baseline: Sequence[HostTelemetry],
            topology: NetworkTopology) -> "HostRiskModel":
        """Fit on attack-free telemetry only."""
        if not baseline:
            raise ValueError("baseline corpus is empty")
        raw = build_raw_frame(list(baseline), topology)
        z = self.normalizer.fit_transform(raw)
        self.forest = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=1,
        ).fit(z[MODEL_FEATURES].values)
        # Empirical benign score distribution -> the calibration curve.
        self._benign_scores = np.sort(
            self.forest.score_samples(z[MODEL_FEATURES].values))
        self.n_train_windows = len(baseline)
        return self

    @property
    def is_fitted(self) -> bool:
        return self.forest is not None and self._benign_scores is not None

    # -------------------------------------------------------------- scoring
    def _calibrate(self, raw_scores: np.ndarray) -> np.ndarray:
        """Empirical CDF of the benign scores; lower raw score => higher risk."""
        assert self._benign_scores is not None
        # searchsorted gives how many benign windows scored <= this value.
        idx = np.searchsorted(self._benign_scores, raw_scores, side="right")
        share_more_anomalous = idx / float(len(self._benign_scores))
        return np.clip(1.0 - share_more_anomalous, 0.0, 1.0)

    def score(self, telemetry: Dict[str, HostTelemetry],
              topology: NetworkTopology) -> Dict[str, HostRisk]:
        """Score one incident window. Returns host_id -> :class:`HostRisk`."""
        if not self.is_fitted:
            raise RuntimeError("HostRiskModel.score called before fit")
        records = [telemetry[h] for h in sorted(telemetry)]
        raw = build_raw_frame(records, topology)
        z = self.normalizer.transform(raw)
        assert self.forest is not None
        raw_scores = self.forest.score_samples(z[MODEL_FEATURES].values)
        risks = self._calibrate(raw_scores)

        out: Dict[str, HostRisk] = {}
        for i, host_id in enumerate(raw["host_id"].tolist()):
            out[host_id] = HostRisk(
                host_id=host_id,
                risk_score=float(risks[i]),
                raw_score=float(raw_scores[i]),
                drivers=top_contributing_features(z.iloc[i], k=3),
            )
        return out

    # ------------------------------------------------------------- metadata
    def describe(self) -> dict:
        return {
            "model": "IsolationForest",
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "random_state": self.random_state,
            "n_features": len(MODEL_FEATURES),
            "features": list(MODEL_FEATURES),
            "n_training_windows": self.n_train_windows,
            "normalisation": "robust z-score within host type (peer-group baselining)",
            "calibration": "empirical CDF against the benign score distribution",
        }


def train_default_model(topology: NetworkTopology, *, n_windows: int = 60,
                        seed: int = 1234) -> HostRiskModel:
    """Convenience: build a baseline corpus and fit the model on it.

    ``n_windows`` attack-free observation windows x ``len(hosts)`` hosts gives
    the training corpus size (60 x 38 = 2,280 rows for the reference topology).
    """
    from ..telemetry.generator import TelemetryGenerator
    corpus = TelemetryGenerator(topology).generate_baseline_corpus(n_windows, seed)
    return HostRiskModel().fit(corpus, topology)
