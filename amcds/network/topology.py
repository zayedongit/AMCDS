"""Enterprise infrastructure model backed by NetworkX.

Three graphs are maintained, and each one answers a different question:

``self.graph`` (``nx.Graph``)
    Host-to-host *reachability*. An edge means host A can open a connection to
    host B. Every edge carries a ``trust`` weight in (0, 1] which is the modelled
    probability that an attacker sitting on A can pivot to B in one step. A
    workstation-to-workstation SMB path is cheap (0.85); a workstation-to-domain
    controller path is only an authentication channel and is hardened (0.10).

``self.dep_graph`` (``nx.DiGraph``)
    Business *service dependency*: an edge ``service -> host`` means the service
    is unavailable if that host goes offline. Kept as a bipartite DiGraph so
    NetworkX ancestor/descendant queries answer "what breaks if I isolate X".

``self.zones``
    Coarse network segments (dmz / corp / app / data / identity) used for
    segmentation-aware reasoning and for laying the dashboard out.

All query methods are deterministic: every iteration is over a sorted sequence,
never over a raw ``set`` (Python randomises string hashing per process, which is
what made the original benchmark irreproducible).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import networkx as nx

from ..config import DEFAULT_BLAST_RADIUS_HOPS, MIN_PATH_TRUST

SLA_TIERS = ("gold", "silver", "bronze")


@dataclass
class HostNode:
    """A single host/server in the enterprise network."""

    host_id: str
    host_type: str          # workstation | app_server | db_server | domain_controller | web_server | file_server | jump_host
    criticality: int        # 1 (low) .. 5 (critical)
    sla_tier: str           # gold | silver | bronze — the strictest tier of any service it carries
    revenue_per_hour: float # INR/hour attributable to this host alone
    zone: str = "corp"
    services: List[str] = field(default_factory=list)
    contains_pii: bool = False
    #: Hardening in [0, 1]: how much this host resists being pivoted *into*.
    hardening: float = 0.0

    def to_dict(self) -> dict:
        return {
            "host_id": self.host_id,
            "host_type": self.host_type,
            "criticality": self.criticality,
            "sla_tier": self.sla_tier,
            "revenue_per_hour": self.revenue_per_hour,
            "zone": self.zone,
            "services": list(self.services),
            "contains_pii": self.contains_pii,
            "hardening": self.hardening,
        }


class NetworkTopology:
    """Enterprise network model with service-dependency awareness."""

    def __init__(self) -> None:
        self.graph: nx.Graph = nx.Graph()
        self.dep_graph: nx.DiGraph = nx.DiGraph()
        self.hosts: Dict[str, HostNode] = {}
        self.service_deps: Dict[str, Set[str]] = {}
        self.service_revenue: Dict[str, float] = {}
        self.service_sla: Dict[str, str] = {}
        self._centrality_cache: Optional[Dict[str, float]] = None

    # ------------------------------------------------------------------ build
    def add_host(self, host: HostNode) -> None:
        self.hosts[host.host_id] = host
        self.graph.add_node(host.host_id, **host.to_dict())
        self.dep_graph.add_node(host.host_id, kind="host")
        self._centrality_cache = None

    def add_edge(self, a: str, b: str, trust: float = 0.5) -> None:
        """Add a reachability edge. ``trust`` is the one-hop pivot probability."""
        if a not in self.hosts or b not in self.hosts:
            raise KeyError(f"add_edge on unknown host(s): {a!r}, {b!r}")
        trust = float(max(1e-6, min(1.0, trust)))
        # -log(trust) turns "most probable path" into "shortest path", so we can
        # use Dijkstra for attack-path search.
        self.graph.add_edge(a, b, trust=trust, weight=-math.log(trust))
        self._centrality_cache = None

    def add_service(self, service_id: str, depends_on: Sequence[str],
                    revenue_per_hour: float, sla: str = "silver") -> None:
        if sla not in SLA_TIERS:
            raise ValueError(f"unknown SLA tier {sla!r}; expected one of {SLA_TIERS}")
        missing = [h for h in depends_on if h not in self.hosts]
        if missing:
            raise KeyError(f"service {service_id!r} depends on unknown hosts {missing}")
        self.service_deps[service_id] = set(depends_on)
        self.service_revenue[service_id] = float(revenue_per_hour)
        self.service_sla[service_id] = sla
        self.dep_graph.add_node(service_id, kind="service", sla=sla,
                                revenue_per_hour=float(revenue_per_hour))
        for h in depends_on:
            self.dep_graph.add_edge(service_id, h)
            if service_id not in self.hosts[h].services:
                self.hosts[h].services.append(service_id)

    def finalize(self) -> "NetworkTopology":
        """Derive per-host SLA tier from the services it carries and validate."""
        rank = {"gold": 0, "silver": 1, "bronze": 2}
        for hid, host in self.hosts.items():
            tiers = [self.service_sla[s] for s in self.services_on_host(hid)]
            if tiers:
                host.sla_tier = min(tiers, key=lambda t: rank[t])
            self.graph.nodes[hid]["sla_tier"] = host.sla_tier
            self.graph.nodes[hid]["services"] = sorted(self.services_on_host(hid))
        self.validate()
        return self

    def validate(self) -> None:
        """Fail loudly on structurally invalid topologies."""
        if not self.hosts:
            raise ValueError("topology has no hosts")
        orphans = [h for h in self.hosts if self.graph.degree(h) == 0]
        if orphans:
            raise ValueError(f"hosts with no reachability edges: {sorted(orphans)}")
        for sid, deps in self.service_deps.items():
            if not deps:
                raise ValueError(f"service {sid!r} has no host dependencies")

    # ---------------------------------------------------------- basic queries
    def host_ids(self) -> List[str]:
        return sorted(self.hosts)

    def neighbors(self, host_id: str) -> List[str]:
        return sorted(self.graph.neighbors(host_id))

    def hosts_for_service(self, service_id: str) -> Set[str]:
        return set(self.service_deps.get(service_id, set()))

    def services_on_host(self, host_id: str) -> List[str]:
        """Services broken by taking this host offline (DiGraph predecessors)."""
        if host_id not in self.dep_graph:
            return []
        return sorted(self.dep_graph.predecessors(host_id))

    def gold_tier_hosts(self) -> Set[str]:
        return {h for sid, sla in self.service_sla.items() if sla == "gold"
                for h in self.service_deps[sid]}

    def zone_of(self, host_id: str) -> str:
        return self.hosts[host_id].zone

    # ------------------------------------------------------ business impact
    def downed_services(self, host_ids: Iterable[str]) -> List[str]:
        """Services with at least one dependency in ``host_ids``.

        A service is modelled as unavailable if *any* host it depends on is
        offline (series reliability). This is the pessimistic reading and is the
        one the Business Impact agent uses.
        """
        offline = set(host_ids)
        return sorted(sid for sid, deps in self.service_deps.items() if deps & offline)

    def revenue_impact_of_isolating(self, host_ids: Iterable[str]) -> float:
        """Total INR/hour lost when ``host_ids`` are isolated.

        Service revenue is counted once per downed service (not per host), so
        isolating two hosts of the same service costs the same as isolating one.
        """
        return sum(self.service_revenue[s] for s in self.downed_services(host_ids))

    def sla_breaches(self, host_ids: Iterable[str]) -> List[str]:
        """Gold-tier services taken down by isolating ``host_ids``."""
        return [s for s in self.downed_services(host_ids)
                if self.service_sla.get(s) == "gold"]

    # ------------------------------------------------- reachability (NetworkX)
    def reachable_from(self, sources: Iterable[str],
                       excluded: Iterable[str] = ()) -> Set[str]:
        """Hosts reachable from ``sources`` once ``excluded`` hosts are cut off.

        Implemented as a NetworkX connected-component query on the subgraph with
        the isolated hosts removed — this is exactly "what can the attacker still
        touch after we pull these plugs".
        """
        excluded = set(excluded)
        live_sources = sorted(set(sources) - excluded)
        if not live_sources:
            return set()
        sub = self.graph.subgraph([n for n in self.graph.nodes if n not in excluded])
        out: Set[str] = set()
        for s in live_sources:
            if s in sub:
                out |= nx.node_connected_component(sub, s)
        return out

    def hop_distances(self, sources: Iterable[str],
                      max_hops: Optional[int] = None) -> Dict[str, int]:
        """Unweighted hop distance from the nearest source (multi-source BFS)."""
        sources = sorted(set(sources))
        if not sources:
            return {}
        dist: Dict[str, int] = {}
        for s in sources:
            if s not in self.graph:
                continue
            lengths = nx.single_source_shortest_path_length(
                self.graph, s, cutoff=max_hops)
            for node, d in lengths.items():
                if node not in dist or d < dist[node]:
                    dist[node] = d
        return dist

    def within_hops(self, sources: Iterable[str], hops: int) -> Set[str]:
        """All hosts within ``hops`` edges of any source (inclusive)."""
        return set(self.hop_distances(sources, max_hops=hops))

    def attack_path_probabilities(self, sources: Iterable[str]) -> Dict[str, float]:
        """Most-probable-path pivot probability from ``sources`` to every host.

        Uses Dijkstra over ``weight = -log(trust)``: minimising the summed weight
        maximises the product of edge trusts, so the returned value is the
        probability of the single most likely lateral-movement path.
        """
        sources = sorted(set(s for s in sources if s in self.graph))
        if not sources:
            return {}
        best: Dict[str, float] = {}
        for s in sources:
            lengths = nx.single_source_dijkstra_path_length(
                self.graph, s, weight="weight")
            for node, w in lengths.items():
                p = math.exp(-w)
                if p > best.get(node, 0.0):
                    best[node] = p
        return best

    def plausible_attack_surface(self, sources: Iterable[str],
                                 min_trust: float = MIN_PATH_TRUST) -> Set[str]:
        """Hosts an attacker on ``sources`` can plausibly reach.

        "Plausibly" = there exists a path whose cumulative trust product is at
        least ``min_trust``. This is far tighter than raw adjacency and is why
        the aggressive hop-based baseline over-isolates.
        """
        return {h for h, p in self.attack_path_probabilities(sources).items()
                if p >= min_trust}

    def attack_path(self, source: str, target: str) -> Tuple[List[str], float]:
        """The single most probable lateral-movement path and its probability."""
        if source not in self.graph or target not in self.graph:
            return [], 0.0
        try:
            path = nx.dijkstra_path(self.graph, source, target, weight="weight")
        except nx.NetworkXNoPath:
            return [], 0.0
        p = 1.0
        for a, b in zip(path, path[1:]):
            p *= self.graph[a][b]["trust"]
        return path, p

    def choke_points(self) -> List[str]:
        """Articulation points: hosts whose loss disconnects the network.

        Useful context for the Network agent — isolating a choke point buys a
        lot of containment but also severs everything behind it.
        """
        return sorted(nx.articulation_points(self.graph))

    def centrality(self) -> Dict[str, float]:
        """Betweenness centrality — how much lateral traffic flows through a host."""
        if self._centrality_cache is None:
            self._centrality_cache = nx.betweenness_centrality(
                self.graph, weight="weight", normalized=True)
        return dict(self._centrality_cache)

    # ------------------------------------------------------------ blast radius
    def blast_radius(self, sources: Iterable[str],
                     hops: int = DEFAULT_BLAST_RADIUS_HOPS,
                     use_trust: bool = True,
                     min_trust: float = MIN_PATH_TRUST) -> dict:
        """Quantify what an infection at ``sources`` threatens.

        Returns hosts at risk, the business services those hosts carry, the
        INR/hour those services represent, and the gold-tier services among them.
        This is the "what could happen if we do nothing" number; the same call
        with the isolation set as ``sources`` answers "what happens if we isolate".
        """
        sources = sorted(set(sources))
        hop_hosts = self.within_hops(sources, hops)
        if use_trust:
            hosts_at_risk = hop_hosts & self.plausible_attack_surface(sources, min_trust)
            hosts_at_risk |= set(sources)
        else:
            hosts_at_risk = hop_hosts
        services = self.downed_services(hosts_at_risk)
        return {
            "sources": sources,
            "hops": hops,
            "hosts_at_risk": sorted(hosts_at_risk),
            "n_hosts_at_risk": len(hosts_at_risk),
            "services_at_risk": services,
            "gold_services_at_risk": [s for s in services
                                      if self.service_sla.get(s) == "gold"],
            "revenue_at_risk_per_hour": sum(self.service_revenue[s] for s in services),
            "pii_hosts_at_risk": sorted(h for h in hosts_at_risk
                                        if self.hosts[h].contains_pii),
        }

    def containment_value(self, isolate: Iterable[str], sources: Iterable[str]) -> dict:
        """How much attack surface isolating ``isolate`` actually removes."""
        isolate = set(isolate)
        before = self.plausible_attack_surface(sources)
        after = self._surface_after_isolation(sources, isolate)
        return {
            "surface_before": len(before),
            "surface_after": len(after),
            "hosts_protected": sorted(before - after - isolate),
            "reduction_pct": (0.0 if not before else
                              round(100.0 * (len(before) - len(after)) / len(before), 2)),
        }

    def _surface_after_isolation(self, sources: Iterable[str],
                                 isolate: Set[str]) -> Set[str]:
        live_sources = sorted(set(sources) - isolate)
        if not live_sources:
            return set()
        keep = [n for n in self.graph.nodes if n not in isolate]
        sub = self.graph.subgraph(keep)
        best: Dict[str, float] = {}
        for s in live_sources:
            if s not in sub:
                continue
            for node, w in nx.single_source_dijkstra_path_length(
                    sub, s, weight="weight").items():
                p = math.exp(-w)
                if p > best.get(node, 0.0):
                    best[node] = p
        return {h for h, p in best.items() if p >= MIN_PATH_TRUST}

    # ------------------------------------------------------------ serialisation
    def summary(self) -> dict:
        return {
            "n_hosts": len(self.hosts),
            "n_edges": self.graph.number_of_edges(),
            "n_services": len(self.service_deps),
            "n_zones": len({h.zone for h in self.hosts.values()}),
            "gold_services": sorted(s for s, sla in self.service_sla.items()
                                    if sla == "gold"),
            "diameter": (nx.diameter(self.graph)
                         if nx.is_connected(self.graph) else None),
            "avg_degree": round(2 * self.graph.number_of_edges() / len(self.hosts), 2),
        }

    def to_json(self) -> dict:
        return {
            "hosts": {h: self.hosts[h].to_dict() for h in self.host_ids()},
            "edges": [{"a": a, "b": b, "trust": round(d.get("trust", 1.0), 4)}
                      for a, b, d in sorted(self.graph.edges(data=True),
                                            key=lambda e: (e[0], e[1]))],
            "services": {sid: {
                "depends_on": sorted(self.service_deps[sid]),
                "revenue_per_hour": self.service_revenue[sid],
                "sla": self.service_sla[sid],
            } for sid in sorted(self.service_deps)},
            "zones": sorted({h.zone for h in self.hosts.values()}),
        }
