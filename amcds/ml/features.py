"""Feature engineering for the host-risk model.

Two ideas do the real work here.

**Peer-group baselining.** A web server making 1,500 outbound connections is
normal; a workstation making 1,500 is not. Every raw counter is therefore turned
into a *robust z-score within its host type*:

    z = (x - median_type(x)) / (1.4826 * MAD_type(x))

Medians and MADs come from the attack-free baseline corpus only, so no
information about the incident leaks into the normalisation. The MAD scaling
constant 1.4826 makes the result comparable to a standard deviation for normally
distributed data. This is what real UEBA products call peer-group analytics.

**Behavioural ratios.** A few features only make sense as ratios and are
computed before normalisation:

* ``peer_saturation``  distinct peers / graph degree — >1 means the host talked
  to more hosts than its normal reachability set, i.e. scanning.
* ``bytes_out_per_peer`` — bulk transfer concentrated on few peers = exfil.
* ``conn_per_peer`` — many connections to few peers = beaconing/brute force.

Graph-derived features (centrality, zone-boundary degree, criticality) are
deliberately **not** fed to the anomaly model — they are static per host, so the
model would just learn to flag rare host types. They are exposed separately for
the agents and for the interpretable risk blend.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Sequence

import numpy as np
import pandas as pd

from ..network.topology import NetworkTopology
from ..telemetry.generator import TELEMETRY_FIELDS, HostTelemetry

#: Ratio features derived before normalisation.
DERIVED_FIELDS: List[str] = [
    "peer_saturation",
    "bytes_out_per_peer",
    "conn_per_peer",
]

#: Everything the anomaly model sees, in a fixed order.
MODEL_FEATURES: List[str] = TELEMETRY_FIELDS + DERIVED_FIELDS

#: Graph context exposed to agents and explanations (not model inputs).
GRAPH_FEATURES: List[str] = [
    "degree",
    "betweenness",
    "trust_weighted_degree",
    "zone_boundary_edges",
    "criticality",
    "n_services",
]

_EPS = 1e-9
_MAD_SCALE = 1.4826


def telemetry_frame(records: Iterable[HostTelemetry]) -> pd.DataFrame:
    """Raw telemetry records -> tidy DataFrame with the derived ratios added."""
    rows = [r.to_dict() for r in records]
    if not rows:
        return pd.DataFrame(columns=["host_id", "host_type", "zone"] + MODEL_FEATURES)
    df = pd.DataFrame(rows)
    df["peer_saturation"] = df["distinct_peers"] / (df["_degree"] if "_degree" in df
                                                    else 1.0)
    return df


def build_raw_frame(records: Sequence[HostTelemetry],
                    topology: NetworkTopology) -> pd.DataFrame:
    """Telemetry -> DataFrame of ``MODEL_FEATURES`` plus identity columns."""
    rows = [r.to_dict() for r in records]
    df = pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=["host_id", "host_type", "zone"] + TELEMETRY_FIELDS)

    degree = df["host_id"].map(lambda h: max(1, topology.graph.degree(h)))
    df["peer_saturation"] = df["distinct_peers"] / (degree + _EPS)
    df["bytes_out_per_peer"] = df["bytes_out_mb"] / (df["distinct_peers"] + _EPS)
    df["conn_per_peer"] = df["outbound_connections"] / (df["distinct_peers"] + _EPS)
    return df


def graph_features(topology: NetworkTopology) -> pd.DataFrame:
    """Static per-host structural features from the NetworkX graph."""
    centrality = topology.centrality()
    rows = []
    for h in topology.host_ids():
        host = topology.hosts[h]
        nbrs = topology.neighbors(h)
        rows.append({
            "host_id": h,
            "degree": len(nbrs),
            "betweenness": round(centrality.get(h, 0.0), 6),
            "trust_weighted_degree": round(
                sum(topology.graph[h][n]["trust"] for n in nbrs), 4),
            "zone_boundary_edges": sum(
                1 for n in nbrs if topology.hosts[n].zone != host.zone),
            "criticality": host.criticality,
            "n_services": len(topology.services_on_host(h)),
        })
    return pd.DataFrame(rows)


class PeerGroupNormalizer:
    """Robust per-host-type standardisation fitted on attack-free telemetry."""

    def __init__(self) -> None:
        self.median_: Dict[str, pd.Series] = {}
        self.scale_: Dict[str, pd.Series] = {}
        self.global_median_: pd.Series | None = None
        self.global_scale_: pd.Series | None = None
        self.features_: List[str] = list(MODEL_FEATURES)

    def fit(self, df: pd.DataFrame) -> "PeerGroupNormalizer":
        feats = df[self.features_].astype(float)
        self.global_median_ = feats.median()
        self.global_scale_ = self._mad(feats)
        for host_type, group in df.groupby("host_type", sort=True):
            g = group[self.features_].astype(float)
            self.median_[host_type] = g.median()
            self.scale_[host_type] = self._mad(g)
        return self

    @staticmethod
    def _mad(frame: pd.DataFrame) -> pd.Series:
        med = frame.median()
        mad = (frame - med).abs().median() * _MAD_SCALE
        # Fall back to std, then to 1.0, for constant columns.
        std = frame.std(ddof=0)
        mad = mad.where(mad > _EPS, std)
        return mad.where(mad > _EPS, 1.0)

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        if self.global_median_ is None:
            raise RuntimeError("PeerGroupNormalizer.transform before fit")
        out = pd.DataFrame(index=df.index, columns=self.features_, dtype=float)
        for host_type, group in df.groupby("host_type", sort=True):
            med = self.median_.get(host_type, self.global_median_)
            scale = self.scale_.get(host_type, self.global_scale_)
            z = (group[self.features_].astype(float) - med) / scale
            out.loc[group.index, self.features_] = z.values
        # Clip absurd tails so a single outlier cannot dominate the forest.
        return out.clip(-12.0, 12.0).fillna(0.0)

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        return self.fit(df).transform(df)


def top_contributing_features(z_row: pd.Series, k: int = 3) -> List[tuple]:
    """The ``k`` features that make this host look most abnormal.

    Only positive deviations count: "fewer connections than my peer group" is
    not evidence of compromise, "far more" is.
    """
    positives = z_row[z_row > 0].sort_values(ascending=False)
    return [(str(name), round(float(val), 2)) for name, val in positives.head(k).items()]
