"""
Service Registry - Defines enterprise services and their dependencies.
"""
from __future__ import annotations
import random
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class ServiceDefinition:
    id: str
    name: str
    service_type: str
    host_ids: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    protocol: str = "tcp"
    criticality: float = 0.5  # 0.0 = low, 1.0 = critical
    dependencies: list[str] = field(default_factory=list)
    sla_target: float = 99.9
    revenue_per_minute: float = 0.0
    department_owner: str = "IT"
    is_public_facing: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Template service definitions for 10 enterprise services
SERVICE_TEMPLATES = [
    {"name": "Active Directory", "service_type": "identity", "ports": [389, 636, 88], "criticality": 1.0, "sla": 99.99, "rpm": 500.0, "dept": "IT"},
    {"name": "Email Server", "service_type": "email", "ports": [25, 143, 993, 587], "criticality": 0.9, "sla": 99.9, "rpm": 100.0, "dept": "IT"},
    {"name": "Web Server", "service_type": "web", "ports": [80, 443], "criticality": 0.8, "sla": 99.9, "rpm": 200.0, "dept": "IT", "public": True},
    {"name": "File Server", "service_type": "storage", "ports": [445, 139], "criticality": 0.7, "sla": 99.5, "rpm": 50.0, "dept": "IT"},
    {"name": "Database Server", "service_type": "database", "ports": [5432, 3306], "criticality": 0.95, "sla": 99.99, "rpm": 400.0, "dept": "Engineering"},
    {"name": "DNS Server", "service_type": "network", "ports": [53], "criticality": 1.0, "sla": 99.99, "rpm": 300.0, "dept": "IT"},
    {"name": "VPN Gateway", "service_type": "network", "ports": [1194, 443], "criticality": 0.8, "sla": 99.5, "rpm": 80.0, "dept": "IT", "public": True},
    {"name": "HR Portal", "service_type": "web_app", "ports": [8080], "criticality": 0.5, "sla": 99.0, "rpm": 20.0, "dept": "HR"},
    {"name": "Finance App", "service_type": "web_app", "ports": [8443], "criticality": 0.85, "sla": 99.9, "rpm": 350.0, "dept": "Finance"},
    {"name": "Monitoring", "service_type": "monitoring", "ports": [9090, 3000], "criticality": 0.7, "sla": 99.5, "rpm": 10.0, "dept": "IT"},
]

# Service dependency graph (index-based)
DEPENDENCY_MAP = {
    1: [0, 5],       # Email depends on AD, DNS
    2: [5, 4],       # Web depends on DNS, DB
    3: [0],          # File depends on AD
    4: [5],          # DB depends on DNS
    6: [0, 5],       # VPN depends on AD, DNS
    7: [0, 4, 2],    # HR Portal depends on AD, DB, Web
    8: [0, 4],       # Finance depends on AD, DB
    9: [5],          # Monitoring depends on DNS
}


class ServiceRegistry:
    """Manages enterprise service definitions and dependencies."""

    def __init__(self, seed: int = 42, num_services: int = 10):
        self.seed = seed
        self.num_services = min(num_services, len(SERVICE_TEMPLATES))
        self._rng = random.Random(seed)
        self.services: dict[str, ServiceDefinition] = {}

    def generate(self, server_host_ids: list[str] | None = None) -> dict[str, ServiceDefinition]:
        self._rng = random.Random(self.seed)
        self.services.clear()
        hosts = list(server_host_ids) if server_host_ids else [f"srv-{i:03d}" for i in range(20)]

        for i in range(self.num_services):
            tmpl = SERVICE_TEMPLATES[i]
            svc_id = f"svc-{i+1:03d}"
            num_hosts = 2 if tmpl["criticality"] >= 0.9 else 1
            assigned_hosts = [hosts[idx % len(hosts)] for idx in range(i * 2, i * 2 + num_hosts)]
            deps = [f"svc-{d+1:03d}" for d in DEPENDENCY_MAP.get(i, [])]

            svc = ServiceDefinition(
                id=svc_id, name=tmpl["name"], service_type=tmpl["service_type"],
                host_ids=assigned_hosts, ports=tmpl["ports"], protocol="tcp",
                criticality=tmpl["criticality"], dependencies=deps,
                sla_target=tmpl["sla"], revenue_per_minute=tmpl["rpm"],
                department_owner=tmpl["dept"], is_public_facing=tmpl.get("public", False),
            )
            self.services[svc_id] = svc

        return self.services

    def get_service(self, svc_id: str) -> ServiceDefinition | None:
        return self.services.get(svc_id)

    def get_by_type(self, svc_type: str) -> list[ServiceDefinition]:
        return [s for s in self.services.values() if s.service_type == svc_type]

    def get_critical_services(self, threshold: float = 0.8) -> list[ServiceDefinition]:
        return [s for s in self.services.values() if s.criticality >= threshold]

    def get_dependency_chain(self, svc_id: str) -> list[str]:
        visited, stack = set(), [svc_id]
        chain = []
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            chain.append(current)
            svc = self.services.get(current)
            if svc:
                stack.extend(svc.dependencies)
        return chain

    def to_dict(self) -> dict[str, Any]:
        return {k: v.to_dict() for k, v in self.services.items()}
