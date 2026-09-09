"""Standalone evaluation of the host-risk model.

Host compromise is an imbalanced problem — typically 15-25% of hosts in an
incident window, and far fewer across a whole estate — so accuracy is reported
but explicitly flagged as misleading. The headline metrics are:

* **PR-AUC (average precision)** — the right summary for imbalanced ranking,
  compared against the base rate (a random ranker achieves PR-AUC = base rate).
* **ROC-AUC** — threshold-free separability.
* **Precision / recall / F1 at the operating threshold** actually used by the
  agents (``ML_SUSPICIOUS_THRESHOLD``).
* **Recall at fixed false-positive budgets** — "if the SOC will tolerate 5% of
  clean hosts being flagged, what share of compromised hosts do we catch?"

The model is fitted on attack-free telemetry only, so every scenario in this
evaluation is genuinely held out.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

import numpy as np
from sklearn.metrics import (average_precision_score, confusion_matrix,
                             precision_recall_fscore_support, roc_auc_score)

from ..config import ML_STRONG_THRESHOLD, ML_SUSPICIOUS_THRESHOLD


@dataclass
class RiskModelReport:
    n_samples: int
    n_positive: int
    base_rate: float
    roc_auc: float
    pr_auc: float
    threshold: float
    precision: float
    recall: float
    f1: float
    accuracy: float
    tn: int
    fp: int
    fn: int
    tp: int
    recall_at_fpr: Dict[str, float]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        return {k: (round(v, 4) if isinstance(v, float) else v) for k, v in d.items()}

    def pretty(self) -> str:
        lines = [
            f"  samples                {self.n_samples}  "
            f"(positives {self.n_positive}, base rate {self.base_rate:.3f})",
            f"  ROC-AUC                {self.roc_auc:.3f}",
            f"  PR-AUC (avg precision) {self.pr_auc:.3f}   "
            f"(random baseline = base rate {self.base_rate:.3f})",
            f"  @ threshold {self.threshold:.2f}:  precision {self.precision:.3f}  "
            f"recall {self.recall:.3f}  F1 {self.f1:.3f}",
            f"  confusion              TN={self.tn} FP={self.fp} "
            f"FN={self.fn} TP={self.tp}",
            f"  accuracy               {self.accuracy:.3f}   "
            f"(misleading at this base rate; reported for completeness)",
        ]
        for k, v in sorted(self.recall_at_fpr.items()):
            lines.append(f"  recall @ FPR<={k}      {v:.3f}")
        return "\n".join(lines)


def _recall_at_fpr(y_true: np.ndarray, scores: np.ndarray,
                   budgets: Sequence[float]) -> Dict[str, float]:
    """Highest recall achievable while keeping FPR under each budget."""
    neg = scores[y_true == 0]
    pos = scores[y_true == 1]
    out: Dict[str, float] = {}
    if len(neg) == 0 or len(pos) == 0:
        return {f"{b:.2f}": 0.0 for b in budgets}
    for b in budgets:
        # Threshold that lets through at most b of the negatives.
        thr = float(np.quantile(neg, 1.0 - b))
        out[f"{b:.2f}"] = float((pos >= thr).mean())
    return out


def evaluate_risk_scores(y_true: Sequence[int], risk_scores: Sequence[float],
                         threshold: float = ML_SUSPICIOUS_THRESHOLD
                         ) -> RiskModelReport:
    """Compute the full report from paired labels and calibrated risk scores."""
    y = np.asarray(list(y_true), dtype=int)
    s = np.asarray(list(risk_scores), dtype=float)
    if len(y) != len(s):
        raise ValueError("labels and scores have different lengths")
    if y.sum() == 0 or y.sum() == len(y):
        raise ValueError("evaluation needs both compromised and benign hosts")

    pred = (s >= threshold).astype(int)
    p, r, f1, _ = precision_recall_fscore_support(
        y, pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()

    return RiskModelReport(
        n_samples=int(len(y)),
        n_positive=int(y.sum()),
        base_rate=float(y.mean()),
        roc_auc=float(roc_auc_score(y, s)),
        pr_auc=float(average_precision_score(y, s)),
        threshold=float(threshold),
        precision=float(p), recall=float(r), f1=float(f1),
        accuracy=float((pred == y).mean()),
        tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp),
        recall_at_fpr=_recall_at_fpr(y, s, (0.01, 0.05, 0.10)),
    )


def evaluate_on_scenarios(model, topology, scenarios: Sequence,
                          threshold: float = ML_SUSPICIOUS_THRESHOLD
                          ) -> Tuple[RiskModelReport, List[dict]]:
    """Score every host of every scenario and evaluate against ground truth.

    ``scenarios`` are :class:`~amcds.scenarios.generator.AttackScenario` objects;
    their ``ground_truth_compromised`` list is the label and is never visible to
    the model.
    """
    y_true: List[int] = []
    scores: List[float] = []
    per_scenario: List[dict] = []

    for sc in scenarios:
        truth = set(sc.ground_truth_compromised)
        risks = model.score(sc.telemetry, topology)
        s_y, s_s = [], []
        for host_id in topology.host_ids():
            s_y.append(1 if host_id in truth else 0)
            s_s.append(risks[host_id].risk_score)
        y_true.extend(s_y)
        scores.extend(s_s)
        flagged = {h for h in topology.host_ids()
                   if risks[h].risk_score >= threshold}
        per_scenario.append({
            "scenario_id": sc.scenario_id,
            "attack_type": sc.attack_type,
            "n_compromised": len(truth),
            "n_flagged": len(flagged),
            "tp": len(flagged & truth),
            "fp": len(flagged - truth),
            "fn": len(truth - flagged),
        })

    return evaluate_risk_scores(y_true, scores, threshold), per_scenario
