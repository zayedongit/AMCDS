"""
Enterprise Topology Generator

Generates a deterministic enterprise network topology with subnets, hosts,
and inter-host connectivity using NetworkX.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import random
from dataclasses import dataclass, field, asdict
from typing import Any

import networkx as nx


@dataclass
class Subnet:
    id: str
    name: str
    cidr: str
    vlan_id: int
    gateway: str
    dns_server: str
    department: str
    security_zone: str
    hosts: list[str] = field(default_factory=list)

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(self.cidr)


@dataclass
class Host:
    id: str
    hostname: str
    ip_address: str
    mac_address: str
    subnet_id: str
    os_type: str
    host_type: str
    department: str
    services: list[str] = field(default_factory=list)
    is_critical: bool = False
    open_ports: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EnterpriseTopology:
    ZONE_CONFIG = {
        "dmz": {"cidr_base": "10.1.1.0/24", "department": "IT", "host_ratio": 0.05},
        "internal_1": {"cidr_base": "10.1.2.0/24", "department": "Engineering", "host_ratio": 0.30},
        "internal_2": {"cidr_base": "10.1.3.0/24", "department": "Finance", "host_ratio": 0.25},
        "internal_3": {"cidr_base": "10.1.4.0/24", "department": "HR", "host_ratio": 0.20},
        "restricted": {"cidr_base": "10.1.5.0/24", "department": "Executive", "host_ratio": 0.20},
    }

    OS_DISTRIBUTION = {
        "workstation": [("windows_10", 0.70), ("linux_ws", 0.20), ("macos", 0.10)],
        "server": [("windows_server", 0.40), ("linux_server", 0.60)],
    }

    def __init__(self, seed: int = 42, num_subnets: int = 5, num_hosts: int = 100, num_services: int = 10):
        self.seed = seed
        self.num_subnets = num_subnets
        self.num_hosts = num_hosts
        self.num_services = num_services
        self._rng = random.Random(seed)
        self.graph = nx.Graph()
        self.subnets: dict[str, Subnet] = {}
        self.hosts: dict[str, Host] = {}

    def generate(self) -> "EnterpriseTopology":
        self._rng = random.Random(self.seed)
        self.graph = nx.Graph()
        self.subnets.clear()
        self.hosts.clear()
        self._generate_subnets()
        self._generate_hosts()
        self._generate_connectivity()
        return self

    def _generate_subnets(self) -> None:
        zone_keys = list(self.ZONE_CONFIG.keys())[: self.num_subnets]
        for i, zone_key in enumerate(zone_keys):
            cfg = self.ZONE_CONFIG[zone_key]
            subnet_id = f"subnet-{i+1:03d}"
            security_zone = "dmz" if "dmz" in zone_key else ("restricted" if "restricted" in zone_key else "internal")
            subnet = Subnet(
                id=subnet_id, name=f"{cfg['department']} Network", cidr=cfg["cidr_base"],
                vlan_id=100 + i, gateway=str(ipaddress.IPv4Network(cfg["cidr_base"]).network_address + 1),
                dns_server="10.1.1.2", department=cfg["department"], security_zone=security_zone,
            )
            self.subnets[subnet_id] = subnet
            self.graph.add_node(subnet_id, node_type="subnet", label=subnet.name, cidr=subnet.cidr, zone=security_zone)
        self.graph.add_node("core-router", node_type="router", label="Core Router")
        for subnet_id in self.subnets:
            self.graph.add_edge("core-router", subnet_id, link_type="trunk")

    def _generate_hosts(self) -> None:
        zone_keys = list(self.ZONE_CONFIG.keys())[: self.num_subnets]
        ratios = [self.ZONE_CONFIG[k]["host_ratio"] for k in zone_keys]
        total_ratio = sum(ratios)
        ratios = [r / total_ratio for r in ratios]
        subnet_ids = list(self.subnets.keys())
        host_counts = self._distribute_counts(self.num_hosts, ratios)
        host_index = 0
        for subnet_idx, (subnet_id, count) in enumerate(zip(subnet_ids, host_counts)):
            subnet = self.subnets[subnet_id]
            available_ips = list(subnet.network.hosts())[9:]
            for j in range(count):
                host_index += 1
                ip = str(available_ips[j % len(available_ips)])
                is_server = j < int(count * 0.15) or subnet.security_zone == "dmz"
                host_type = "server" if is_server else "workstation"
                os_choices = self.OS_DISTRIBUTION[host_type]
                os_type = self._rng.choices([c[0] for c in os_choices], weights=[c[1] for c in os_choices], k=1)[0]
                prefix = "srv" if is_server else "ws"
                hostname = f"{prefix}-{subnet.department.lower()[:3]}-{j+1:03d}"
                host = Host(
                    id=f"host-{host_index:04d}", hostname=hostname, ip_address=ip,
                    mac_address=self._generate_mac(host_index), subnet_id=subnet_id,
                    os_type=os_type, host_type=host_type, department=subnet.department,
                    is_critical=is_server and self._rng.random() < 0.3,
                    open_ports=self._generate_ports(host_type, os_type),
                )
                self.hosts[host.id] = host
                subnet.hosts.append(host.id)
                self.graph.add_node(host.id, node_type=host_type, label=hostname, ip=ip, subnet=subnet_id)
                self.graph.add_edge(subnet_id, host.id, link_type="access")

    def _generate_connectivity(self) -> None:
        servers = [h for h in self.hosts.values() if h.host_type == "server"]
        workstations = [h for h in self.hosts.values() if h.host_type == "workstation"]
        for ws in workstations:
            n = self._rng.randint(1, min(3, len(servers)))
            for srv in self._rng.sample(servers, n):
                self.graph.add_edge(ws.id, srv.id, link_type="service", protocol=self._rng.choice(["tcp", "https", "smb"]))
        for i, s1 in enumerate(servers):
            for s2 in servers[i+1:]:
                if self._rng.random() < 0.25:
                    self.graph.add_edge(s1.id, s2.id, link_type="dependency", protocol=self._rng.choice(["tcp", "grpc", "https"]))

    def _distribute_counts(self, total: int, ratios: list[float]) -> list[int]:
        counts = [int(total * r) for r in ratios]
        remainder = total - sum(counts)
        for i in range(remainder):
            counts[i % len(counts)] += 1
        return counts

    def _generate_mac(self, index: int) -> str:
        mac_bytes = hashlib.md5(f"amcds-mac-{self.seed}-{index}".encode()).hexdigest()[:12]
        return ":".join(mac_bytes[i:i+2] for i in range(0, 12, 2))

    def _generate_ports(self, host_type: str, os_type: str) -> list[int]:
        base = [22] if "linux" in os_type else [135, 139, 445, 3389]
        if host_type == "server":
            extra = self._rng.sample([80, 443, 8080, 8443, 3306, 5432, 27017, 6379, 25, 143, 993, 53], k=self._rng.randint(2, 5))
            return sorted(set(base + extra))
        return sorted(base)

    def get_host_by_ip(self, ip: str) -> Host | None:
        for host in self.hosts.values():
            if host.ip_address == ip:
                return host
        return None

    def get_hosts_in_subnet(self, subnet_id: str) -> list[Host]:
        subnet = self.subnets.get(subnet_id)
        if not subnet:
            return []
        return [self.hosts[hid] for hid in subnet.hosts if hid in self.hosts]

    def get_servers(self) -> list[Host]:
        return [h for h in self.hosts.values() if h.host_type == "server"]

    def get_workstations(self) -> list[Host]:
        return [h for h in self.hosts.values() if h.host_type == "workstation"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "subnets": {k: asdict(v) for k, v in self.subnets.items()},
            "hosts": {k: v.to_dict() for k, v in self.hosts.items()},
            "edges": [{"source": u, "target": v, **d} for u, v, d in self.graph.edges(data=True)],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def get_networkx_graph(self) -> nx.Graph:
        return self.graph
