"""Deterministic builders for the enterprise reference topology.

The reference network is a *segmented* three-tier enterprise, which matters:
the original flat topology put every workstation one hop from both domain
controllers, so the graph diameter was 2 and a "3-hop blanket" baseline
isolated literally every host. That made the headline comparison meaningless.

Segmentation model
------------------
    corp (3 departments x 6 workstations + a dept file server)
      |  low-trust auth channel
    identity (2 domain controllers)  <-- also reached from app tier
      |
    app (6 application servers)  <--  dmz (3 web servers + reverse proxy)
      |
    data (4 database servers)

Trust weights encode how easy a pivot is, not merely whether traffic is allowed:

    ws  <-> ws      0.85   flat departmental subnet, SMB/RPC
    ws   -> file    0.65   file share
    ws   -> dc      0.10   Kerberos/LDAP only, hardened
    app  -> db      0.45   service account with a scoped grant
    app  -> dc      0.20   machine auth
    web  -> app     0.55   application protocol through the DMZ boundary
    jump -> *       0.35   administrative jump host
"""
from __future__ import annotations

import random
from typing import List

from ..config import DEFAULT_TOPOLOGY_SEED
from .topology import HostNode, NetworkTopology

# Edge trust constants (documented above).
TRUST_WS_WS = 0.85
TRUST_WS_FILE = 0.65
TRUST_WS_DC = 0.10
TRUST_WS_JUMP = 0.30
TRUST_APP_DB = 0.45
TRUST_APP_DC = 0.20
TRUST_APP_APP = 0.50
TRUST_WEB_APP = 0.55
TRUST_WEB_WEB = 0.60
TRUST_PROXY_WEB = 0.55
TRUST_DB_DB = 0.40
TRUST_DC_DC = 0.30
TRUST_JUMP_APP = 0.35
TRUST_JUMP_DC = 0.25
TRUST_FILE_FILE = 0.50

DEPARTMENTS = ("fin", "eng", "sls")
WS_PER_DEPARTMENT = 6


def build_segmented_enterprise(seed: int = DEFAULT_TOPOLOGY_SEED) -> NetworkTopology:
    """Build the 30-host segmented reference enterprise.

    Deterministic for a given ``seed``: the only randomness is which app servers
    a department and each web server talk to, and it is drawn from sorted lists.
    """
    rng = random.Random(seed)
    t = NetworkTopology()

    # ---------------------------------------------------------------- identity
    for i in (1, 2):
        t.add_host(HostNode(f"dc-{i:02d}", "domain_controller", criticality=5,
                            sla_tier="gold", revenue_per_hour=500_000,
                            zone="identity", contains_pii=True, hardening=0.8))

    # -------------------------------------------------------------------- data
    for i in range(1, 5):
        t.add_host(HostNode(f"db-prod-{i:02d}", "db_server", criticality=5,
                            sla_tier="gold", revenue_per_hour=800_000,
                            zone="data", contains_pii=True, hardening=0.7))

    # --------------------------------------------------------------------- app
    for i in range(1, 7):
        t.add_host(HostNode(f"app-prod-{i:02d}", "app_server", criticality=4,
                            sla_tier="silver", revenue_per_hour=300_000,
                            zone="app", hardening=0.4))

    # --------------------------------------------------------------------- dmz
    t.add_host(HostNode("proxy-01", "web_server", criticality=3,
                        sla_tier="silver", revenue_per_hour=100_000,
                        zone="dmz", hardening=0.5))
    for i in range(1, 4):
        t.add_host(HostNode(f"web-{i:02d}", "web_server", criticality=3,
                            sla_tier="silver", revenue_per_hour=150_000,
                            zone="dmz", hardening=0.3))

    # -------------------------------------------------------- corp: jump host
    t.add_host(HostNode("jump-01", "jump_host", criticality=4,
                        sla_tier="bronze", revenue_per_hour=30_000,
                        zone="corp", hardening=0.6))

    # ------------------------------------------------ corp: departments + files
    for dept in DEPARTMENTS:
        t.add_host(HostNode(f"file-{dept}-01", "file_server", criticality=3,
                            sla_tier="silver", revenue_per_hour=80_000,
                            zone="corp", contains_pii=True, hardening=0.3))
        for i in range(1, WS_PER_DEPARTMENT + 1):
            t.add_host(HostNode(f"ws-{dept}-{i:02d}", "workstation", criticality=2,
                                sla_tier="bronze", revenue_per_hour=10_000,
                                zone="corp", hardening=0.1))

    # ------------------------------------------------------------------- edges
    t.add_edge("dc-01", "dc-02", TRUST_DC_DC)

    # database replication ring
    dbs = [f"db-prod-{i:02d}" for i in range(1, 5)]
    for a, b in zip(dbs, dbs[1:] + dbs[:1]):
        t.add_edge(a, b, TRUST_DB_DB)

    apps = [f"app-prod-{i:02d}" for i in range(1, 7)]
    for idx, app in enumerate(apps):
        # each app server is granted access to exactly two databases
        for db_idx in sorted(rng.sample(range(1, 5), 2)):
            t.add_edge(app, f"db-prod-{db_idx:02d}", TRUST_APP_DB)
        # machine authentication against one DC (site affinity, not both)
        t.add_edge(app, f"dc-{(idx % 2) + 1:02d}", TRUST_APP_DC)
    # app tier is partially meshed (shared middleware bus)
    for a, b in zip(apps, apps[1:]):
        t.add_edge(a, b, TRUST_APP_APP)

    webs = [f"web-{i:02d}" for i in range(1, 4)]
    for web in webs:
        t.add_edge("proxy-01", web, TRUST_PROXY_WEB)
        for app_idx in sorted(rng.sample(range(1, 7), 2)):
            t.add_edge(web, f"app-prod-{app_idx:02d}", TRUST_WEB_APP)
    for a, b in zip(webs, webs[1:]):
        t.add_edge(a, b, TRUST_WEB_WEB)

    # jump host bridges corp -> app/identity for administrators
    t.add_edge("jump-01", "dc-01", TRUST_JUMP_DC)
    for app_idx in (1, 4):
        t.add_edge("jump-01", f"app-prod-{app_idx:02d}", TRUST_JUMP_APP)

    files = [f"file-{d}-01" for d in DEPARTMENTS]
    for a, b in zip(files, files[1:]):
        t.add_edge(a, b, TRUST_FILE_FILE)

    for dept_idx, dept in enumerate(DEPARTMENTS):
        members = [f"ws-{dept}-{i:02d}" for i in range(1, WS_PER_DEPARTMENT + 1)]
        # flat departmental subnet: a ring plus one chord => realistic SMB mesh
        for a, b in zip(members, members[1:] + members[:1]):
            t.add_edge(a, b, TRUST_WS_WS)
        t.add_edge(members[0], members[len(members) // 2], TRUST_WS_WS)
        file_srv = f"file-{dept}-01"
        for ws in members:
            t.add_edge(ws, file_srv, TRUST_WS_FILE)
            # each department authenticates against one site DC only
            t.add_edge(ws, f"dc-{(dept_idx % 2) + 1:02d}", TRUST_WS_DC)
        # the department lead's workstation can reach the jump host
        t.add_edge(members[0], "jump-01", TRUST_WS_JUMP)

    # ---------------------------------------------------------------- services
    t.add_service("identity", ["dc-01", "dc-02"], 2_000_000, sla="gold")
    t.add_service("payments", ["db-prod-01", "db-prod-02",
                               "app-prod-01", "app-prod-02"], 5_000_000, sla="gold")
    t.add_service("customer_data", ["db-prod-01", "db-prod-03"], 1_500_000, sla="gold")
    t.add_service("core_banking", ["db-prod-04", "app-prod-03"], 2_500_000, sla="gold")
    t.add_service("ecommerce", ["web-01", "web-02", "proxy-01",
                                "app-prod-04"], 3_000_000, sla="silver")
    t.add_service("partner_api", ["web-03", "app-prod-05"], 900_000, sla="silver")
    t.add_service("reporting", ["app-prod-06"], 200_000, sla="bronze")
    t.add_service("marketing_site", ["web-01", "web-02", "web-03"], 50_000, sla="bronze")
    for dept in DEPARTMENTS:
        t.add_service(f"shared_drive_{dept}", [f"file-{dept}-01"], 80_000, sla="silver")
    t.add_service("internal_email",
                  [f"ws-{d}-{i:02d}" for d in DEPARTMENTS
                   for i in range(1, WS_PER_DEPARTMENT + 1)],
                  20_000, sla="bronze")
    t.add_service("admin_access", ["jump-01"], 30_000, sla="bronze")

    return t.finalize()


#: Backwards-compatible alias used by the original demo scripts.
build_sample_enterprise = build_segmented_enterprise


def workstations(t: NetworkTopology) -> List[str]:
    return [h for h in t.host_ids() if t.hosts[h].host_type == "workstation"]


def servers(t: NetworkTopology) -> List[str]:
    return [h for h in t.host_ids() if t.hosts[h].host_type != "workstation"]
