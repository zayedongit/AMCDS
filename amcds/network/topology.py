"""Enterprise network topology model.

Represents an enterprise network as a graph where:
  - Nodes are hosts/servers/services (with attributes: criticality, sla_tier,
    revenue_per_hour, host_type, infected, contains_pii, etc.)
  - Edges are network reachability paths between hosts.
  - A separate service-dependency map captures which business services depend
    on which hosts (e.g. "payments" depends on db-prod-01, app-prod-02).

This is shared state for all five agents.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

import networkx as nx


@dataclass
class HostNode:
    """A single host/server/service in the enterprise network."""
    host_id: str
    host_type: str              # 'workstation', 'app_server', 'db_server', 'domain_controller', 'web_server'
    criticality: int            # 1=low ... 5=critical
    sla_tier: str               # 'gold' (no isolation without business approval), 'silver', 'bronze'
    revenue_per_hour: float     # ₹ per hour lost if this host is isolated
    services: List[str] = field(default_factory=list)   # business services that run on this host
    contains_pii: bool = False
    infected: bool = False
    suspicion_score: float = 0.0   # 0..1, updated by agents

    def to_dict(self) -> dict:
        return {
            "host_id": self.host_id,
            "host_type": self.host_type,
            "criticality": self.criticality,
            "sla_tier": self.sla_tier,
            "revenue_per_hour": self.revenue_per_hour,
            "services": list(self.services),
            "contains_pii": self.contains_pii,
            "infected": self.infected,
            "suspicion_score": self.suspicion_score,
        }


class NetworkTopology:
    """Enterprise network model with service-dependency awareness."""

    def __init__(self) -> None:
        self.graph: nx.Graph = nx.Graph()
        self.hosts: Dict[str, HostNode] = {}
        # service_id -> set of host_ids the service depends on
        self.service_deps: Dict[str, Set[str]] = {}
        # service_id -> revenue per hour if service is down (₹)
        self.service_revenue: Dict[str, float] = {}
        # service_id -> sla tier ('gold', 'silver', 'bronze')
        self.service_sla: Dict[str, str] = {}

    # ------------------------------------------------------------------ build
    def add_host(self, host: HostNode) -> None:
        self.hosts[host.host_id] = host
        self.graph.add_node(host.host_id, **host.to_dict())

    def add_edge(self, a: str, b: str, trust: float = 1.0) -> None:
        self.graph.add_edge(a, b, trust=trust)

    def add_service(self, service_id: str, depends_on: List[str],
                    revenue_per_hour: float, sla: str = "silver") -> None:
        self.service_deps[service_id] = set(depends_on)
        self.service_revenue[service_id] = revenue_per_hour
        self.service_sla[service_id] = sla

    # --------------------------------------------------------- query helpers
    def neighbors(self, host_id: str) -> List[str]:
        return list(self.graph.neighbors(host_id))

    def hosts_for_service(self, service_id: str) -> Set[str]:
        return self.service_deps.get(service_id, set())

    def services_on_host(self, host_id: str) -> List[str]:
        return [s for s, hosts in self.service_deps.items() if host_id in hosts]

    def gold_tier_hosts(self) -> Set[str]:
        """Hosts running at least one gold-SLA service."""
        gold: Set[str] = set()
        for sid, sla in self.service_sla.items():
            if sla == "gold":
                gold.update(self.service_deps.get(sid, set()))
        return gold

    def revenue_impact_of_isolating(self, host_ids: Set[str]) -> float:
        """Total ₹/hour lost if `host_ids` are isolated.

        A service is down if ANY host it depends on is isolated.
        """
        downed_services = []
        for sid, deps in self.service_deps.items():
            if deps & host_ids:
                downed_services.append(sid)
        return sum(self.service_revenue[s] for s in downed_services)

    def sla_breaches(self, host_ids: Set[str]) -> List[str]:
        """Gold-tier services that would be taken down by isolating `host_ids`."""
        breached = []
        for sid, deps in self.service_deps.items():
            if self.service_sla.get(sid) == "gold" and (deps & host_ids):
                breached.append(sid)
        return breached

    def reachable_from(self, source_ids: Set[str], excluded: Set[str]) -> Set[str]:
        """BFS from source_ids skipping any host in `excluded` (the isolated set)."""
        reachable: Set[str] = set()
        frontier = set(source_ids) - excluded
        while frontier:
            nxt = set()
            for h in frontier:
                if h in excluded:
                    continue
                reachable.add(h)
                for nbr in self.graph.neighbors(h):
                    if nbr not in excluded and nbr not in reachable:
                        nxt.add(nbr)
            frontier = nxt
        return reachable

    def summary(self) -> dict:
        return {
            "n_hosts": len(self.hosts),
            "n_edges": self.graph.number_of_edges(),
            "n_services": len(self.service_deps),
            "gold_services": [s for s, sla in self.service_sla.items() if sla == "gold"],
        }

    def to_json(self) -> dict:
        return {
            "hosts": {h: self.hosts[h].to_dict() for h in self.hosts},
            "edges": [{"a": a, "b": b, "trust": d.get("trust", 1.0)}
                      for a, b, d in self.graph.edges(data=True)],
            "services": {sid: {
                "depends_on": sorted(list(self.service_deps[sid])),
                "revenue_per_hour": self.service_revenue[sid],
                "sla": self.service_sla[sid],
            } for sid in self.service_deps},
        }


# ----------------------------------------------------------------- factory ---
def build_sample_enterprise(seed: int = 7) -> NetworkTopology:
    """Build a representative mid-size enterprise (~30 hosts, ~10 services).

    Resembles a 3-tier architecture: workstations -> app servers -> db servers,
    plus identity (AD), web edge, and a few critical financial hosts.
    """
    rng = random.Random(seed)
    t = NetworkTopology()

    # --- domain controllers (criticality 5)
    for i in range(1, 3):
        t.add_host(HostNode(
            host_id=f"dc-{i:02d}", host_type="domain_controller",
            criticality=5, sla_tier="gold", revenue_per_hour=500_000,
            services=["identity"], contains_pii=True,
        ))

    # --- db servers
    for i in range(1, 4):
        t.add_host(HostNode(
            host_id=f"db-prod-{i:02d}", host_type="db_server",
            criticality=5, sla_tier="gold", revenue_per_hour=800_000,
            services=["payments", "customer_data"], contains_pii=True,
        ))

    # --- app servers
    for i in range(1, 6):
        t.add_host(HostNode(
            host_id=f"app-prod-{i:02d}", host_type="app_server",
            criticality=4, sla_tier="silver", revenue_per_hour=300_000,
            services=["payments", "ecommerce", "reporting"],
        ))

    # --- web/edge
    for i in range(1, 4):
        t.add_host(HostNode(
            host_id=f"web-{i:02d}", host_type="web_server",
            criticality=3, sla_tier="silver", revenue_per_hour=150_000,
            services=["ecommerce", "marketing_site"],
        ))

    # --- file / backup
    for i in range(1, 3):
        t.add_host(HostNode(
            host_id=f"file-{i:02d}", host_type="file_server",
            criticality=3, sla_tier="silver", revenue_per_hour=80_000,
            services=["shared_drive"], contains_pii=True,
        ))

    # --- workstations (less critical)
    for i in range(1, 13):
        t.add_host(HostNode(
            host_id=f"ws-{i:02d}", host_type="workstation",
            criticality=2, sla_tier="bronze", revenue_per_hour=10_000,
            services=["internal_email"],
        ))

    # --- edges: workstations connect to AD + apps + a couple of file servers
    for i in range(1, 13):
        ws = f"ws-{i:02d}"
        t.add_edge(ws, "dc-01")
        t.add_edge(ws, "dc-02")
        # each workstation talks to 1–2 app servers
        for app_idx in rng.sample(range(1, 6), 2):
            t.add_edge(ws, f"app-prod-{app_idx:02d}")
        t.add_edge(ws, f"file-{rng.choice([1, 2]):02d}")

    # apps talk to DBs
    for i in range(1, 6):
        app = f"app-prod-{i:02d}"
        # each app uses 1–2 DBs
        for db_idx in rng.sample(range(1, 4), 2):
            t.add_edge(app, f"db-prod-{db_idx:02d}")
        # apps authenticate against DCs
        t.add_edge(app, "dc-01")
        t.add_edge(app, "dc-02")

    # web -> apps
    for i in range(1, 4):
        web = f"web-{i:02d}"
        for app_idx in rng.sample(range(1, 6), 2):
            t.add_edge(web, f"app-prod-{app_idx:02d}")

    # DCs talk to each other
    t.add_edge("dc-01", "dc-02")

    # ---- services (business view)
    t.add_service("identity",
                  depends_on=["dc-01", "dc-02"],
                  revenue_per_hour=2_000_000, sla="gold")
    t.add_service("payments",
                  depends_on=["db-prod-01", "db-prod-02", "app-prod-01", "app-prod-02"],
                  revenue_per_hour=5_000_000, sla="gold")
    t.add_service("customer_data",
                  depends_on=["db-prod-01", "db-prod-03"],
                  revenue_per_hour=1_500_000, sla="gold")
    t.add_service("ecommerce",
                  depends_on=["web-01", "web-02", "web-03", "app-prod-03", "app-prod-04"],
                  revenue_per_hour=3_000_000, sla="silver")
    t.add_service("reporting",
                  depends_on=["app-prod-05"],
                  revenue_per_hour=200_000, sla="bronze")
    t.add_service("marketing_site",
                  depends_on=["web-01", "web-02", "web-03"],
                  revenue_per_hour=50_000, sla="bronze")
    t.add_service("shared_drive",
                  depends_on=["file-01", "file-02"],
                  revenue_per_hour=80_000, sla="silver")
    t.add_service("internal_email",
                  depends_on=[f"ws-{i:02d}" for i in range(1, 13)],
                  revenue_per_hour=20_000, sla="bronze")

    return t


if __name__ == "__main__":
    import json
    t = build_sample_enterprise()
    print(json.dumps(t.summary(), indent=2))
