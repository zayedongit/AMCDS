"""Central configuration constants for AMCDS.

Every tunable threshold used by the detection, negotiation and optimization
layers lives here so that (a) nothing is a magic number buried in a module and
(b) an experiment can change one value and re-run the whole pipeline.
"""
from __future__ import annotations

# --------------------------------------------------------------- determinism
DEFAULT_TOPOLOGY_SEED = 7
DEFAULT_SCENARIO_SEED = 11
DEFAULT_BENCHMARK_SEED = 2024

# ------------------------------------------------------------------ evidence
# An evidence item counts as HIGH fidelity when its fidelity is at least this.
HARD_EVIDENCE_FIDELITY = 0.85
# ...or when several independent MEDIUM signals combine above this confidence.
CORROBORATION_CONFIDENCE = 0.90
# Minimum number of independent medium signals required to corroborate.
CORROBORATION_MIN_SIGNALS = 2
# Below this fidelity a signal is "weak" and never contributes to corroboration.
WEAK_EVIDENCE_FIDELITY = 0.25

# ---------------------------------------------------------------- ML / risk
# Contamination hint for IsolationForest (expected share of anomalous hosts).
ISOLATION_FOREST_CONTAMINATION = 0.12
ISOLATION_FOREST_ESTIMATORS = 300
# The calibrated risk score is the empirical benign percentile, so a benign host
# is uniform on [0, 1] and a threshold IS the nominal false-positive rate:
# 0.90 => ~10% of normal hosts flagged, 0.98 => ~2%.
ML_SUSPICIOUS_THRESHOLD = 0.90
# At/above this the model is confident enough to act as one corroborating signal
# (never hard evidence on its own).
ML_STRONG_THRESHOLD = 0.98

# --------------------------------------------------------------- propagation
# Lateral movement is modelled as a walk over trust-weighted edges. A path is
# considered a plausible attack path when the product of its edge trusts is at
# least this value.
MIN_PATH_TRUST = 0.05
# Hop budget used by hop-based (unweighted) blast-radius queries.
DEFAULT_BLAST_RADIUS_HOPS = 2

# -------------------------------------------------------------- negotiation
# A contested host (some agents want it isolated, at least one objects) is kept
# when its weighted support ratio reaches this value.
CONSENSUS_SUPPORT_THRESHOLD = 0.50

# ------------------------------------------------------------- business rules
# Default ceiling on hourly revenue the Business Impact agent will authorise
# without hard evidence (INR per hour).
DEFAULT_MAX_HOURLY_LOSS = 8_000_000.0

# ------------------------------------------------------------- optimization
CPSAT_MAX_SECONDS = 10.0
# Objective weights: alpha on residual risk, beta on business cost.
DEFAULT_ALPHA = 1.0
DEFAULT_BETA = 1.0
# Internal integer scaling (CP-SAT is an integer solver).
OBJECTIVE_SCALE = 1000
