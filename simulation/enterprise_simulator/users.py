"""
User Generator - Creates simulated enterprise users with behavior profiles.
"""
from __future__ import annotations
import random
from dataclasses import dataclass, field, asdict
from typing import Any
from faker import Faker


@dataclass
class UserProfile:
    id: str
    username: str
    full_name: str
    email: str
    department: str
    role: str  # "admin", "standard", "privileged", "service-account"
    title: str
    manager_id: str | None
    assigned_host_id: str | None = None
    behavior_profile: str = "normal"  # "early_bird", "night_owl", "heavy_email", "normal", "remote"
    risk_score: float = 0.0
    is_active: bool = True
    groups: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


DEPARTMENTS = ["IT", "Engineering", "Finance", "HR", "Executive", "Operations"]
ROLE_DISTRIBUTION = [("standard", 0.60), ("privileged", 0.20), ("admin", 0.12), ("service-account", 0.08)]
BEHAVIOR_PROFILES = ["normal", "early_bird", "night_owl", "heavy_email", "remote"]
TITLES_BY_DEPT = {
    "IT": ["Systems Admin", "Network Engineer", "Help Desk Analyst", "Security Analyst", "DevOps Engineer"],
    "Engineering": ["Software Engineer", "QA Engineer", "Tech Lead", "Architect", "Data Engineer"],
    "Finance": ["Financial Analyst", "Accountant", "Controller", "Auditor", "Treasurer"],
    "HR": ["HR Specialist", "Recruiter", "Benefits Admin", "Training Coordinator", "HR Manager"],
    "Executive": ["CEO", "CTO", "CFO", "VP Engineering", "VP Operations"],
    "Operations": ["Ops Manager", "Facilities Coord", "Supply Chain Analyst", "Logistics Mgr", "Procurement"],
}


class UserGenerator:
    """Generates deterministic simulated enterprise users."""

    def __init__(self, seed: int = 42, num_users: int = 100):
        self.seed = seed
        self.num_users = num_users
        self._rng = random.Random(seed)
        self._faker = Faker()
        Faker.seed(seed)
        self.users: dict[str, UserProfile] = {}

    def generate(self, host_ids: list[str] | None = None) -> dict[str, UserProfile]:
        self._rng = random.Random(self.seed)
        Faker.seed(self.seed)
        self._faker = Faker()
        self.users.clear()

        dept_counts = self._distribute_by_dept()
        host_pool = list(host_ids) if host_ids else []
        self._rng.shuffle(host_pool)
        host_idx = 0

        user_index = 0
        managers: dict[str, str] = {}

        for dept, count in dept_counts.items():
            for j in range(count):
                user_index += 1
                uid = f"u-{user_index:04d}"
                first = self._faker.first_name()
                last = self._faker.last_name()
                username = f"{first[0].lower()}{last.lower()}"[:12]
                role = self._rng.choices([r[0] for r in ROLE_DISTRIBUTION], weights=[r[1] for r in ROLE_DISTRIBUTION], k=1)[0]
                titles = TITLES_BY_DEPT.get(dept, ["Staff"])
                title = self._rng.choice(titles)
                manager_id = managers.get(dept)
                behavior = self._rng.choice(BEHAVIOR_PROFILES)
                assigned_host = host_pool[host_idx % len(host_pool)] if host_pool else None
                host_idx += 1

                user = UserProfile(
                    id=uid, username=username, full_name=f"{first} {last}",
                    email=f"{username}@amcds-corp.sim", department=dept, role=role,
                    title=title, manager_id=manager_id, assigned_host_id=assigned_host,
                    behavior_profile=behavior, risk_score=round(self._rng.uniform(0.0, 0.3), 3),
                    groups=self._assign_groups(dept, role),
                )
                self.users[uid] = user
                if j == 0:
                    managers[dept] = uid

        return self.users

    def _distribute_by_dept(self) -> dict[str, int]:
        weights = {"IT": 0.15, "Engineering": 0.30, "Finance": 0.15, "HR": 0.10, "Executive": 0.05, "Operations": 0.25}
        counts: dict[str, int] = {}
        remaining = self.num_users
        depts = list(weights.keys())
        for i, dept in enumerate(depts):
            if i == len(depts) - 1:
                counts[dept] = remaining
            else:
                c = int(self.num_users * weights[dept])
                counts[dept] = c
                remaining -= c
        return counts

    def _assign_groups(self, dept: str, role: str) -> list[str]:
        groups = [f"dept-{dept.lower()}", "all-employees"]
        if role == "admin":
            groups.append("domain-admins")
        if role == "privileged":
            groups.append("privileged-users")
        if dept in ("IT", "Engineering"):
            groups.append("tech-staff")
        if dept == "Executive":
            groups.append("executive-team")
        return groups

    def get_user(self, uid: str) -> UserProfile | None:
        return self.users.get(uid)

    def get_users_by_department(self, dept: str) -> list[UserProfile]:
        return [u for u in self.users.values() if u.department == dept]

    def get_admins(self) -> list[UserProfile]:
        return [u for u in self.users.values() if u.role == "admin"]

    def to_dict(self) -> dict[str, Any]:
        return {uid: u.to_dict() for uid, u in self.users.items()}
