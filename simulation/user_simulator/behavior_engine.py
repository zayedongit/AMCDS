"""
User Behavior Engine - Drives per-user activity simulation with time-of-day
weighted probabilities and configurable behavior profiles.
"""
from __future__ import annotations
import math
import random
from dataclasses import dataclass
from typing import Any


@dataclass
class ActivityEvent:
    """Raw activity event before telemetry normalization."""
    tick: int
    timestamp: float
    user_id: str
    activity_type: str  # "login", "logout", "email_send", "email_read", "file_access", "web_browse", "internal_comm"
    source_host: str
    target: str | None = None
    details: dict[str, Any] | None = None
    success: bool = True


# Activity weights by behavior profile and hour-of-day bucket
# Buckets: night(0-6), morning(6-9), work_am(9-12), work_pm(12-17), evening(17-21), late(21-24)
PROFILE_WEIGHTS = {
    "normal": {
        "activity_level": {"night": 0.02, "morning": 0.15, "work_am": 0.30, "work_pm": 0.30, "evening": 0.10, "late": 0.03},
        "email_weight": 0.25, "file_weight": 0.20, "web_weight": 0.25, "comm_weight": 0.15, "login_weight": 0.15,
    },
    "early_bird": {
        "activity_level": {"night": 0.05, "morning": 0.35, "work_am": 0.30, "work_pm": 0.15, "evening": 0.05, "late": 0.01},
        "email_weight": 0.30, "file_weight": 0.20, "web_weight": 0.20, "comm_weight": 0.15, "login_weight": 0.15,
    },
    "night_owl": {
        "activity_level": {"night": 0.15, "morning": 0.05, "work_am": 0.15, "work_pm": 0.25, "evening": 0.25, "late": 0.20},
        "email_weight": 0.20, "file_weight": 0.15, "web_weight": 0.30, "comm_weight": 0.20, "login_weight": 0.15,
    },
    "heavy_email": {
        "activity_level": {"night": 0.01, "morning": 0.15, "work_am": 0.30, "work_pm": 0.30, "evening": 0.10, "late": 0.02},
        "email_weight": 0.45, "file_weight": 0.10, "web_weight": 0.15, "comm_weight": 0.20, "login_weight": 0.10,
    },
    "remote": {
        "activity_level": {"night": 0.05, "morning": 0.10, "work_am": 0.25, "work_pm": 0.25, "evening": 0.20, "late": 0.10},
        "email_weight": 0.25, "file_weight": 0.20, "web_weight": 0.25, "comm_weight": 0.15, "login_weight": 0.15,
    },
}

HOUR_BUCKETS = {
    "night": range(0, 6), "morning": range(6, 9), "work_am": range(9, 12),
    "work_pm": range(12, 17), "evening": range(17, 21), "late": range(21, 24),
}


class UserBehaviorEngine:
    """Drives per-user activity simulation with realistic patterns."""

    def __init__(self, seed: int = 42, tick_interval_ms: int = 100):
        self.seed = seed
        self.tick_interval_ms = tick_interval_ms
        self._rng = random.Random(seed)
        self._user_states: dict[str, dict] = {}  # tracks logged-in state per user

    def initialize_users(self, users: list[dict[str, Any]]) -> None:
        """Initialize user states from user profile dicts."""
        for u in users:
            self._user_states[u["id"]] = {
                "profile": u.get("behavior_profile", "normal"),
                "host": u.get("assigned_host_id"),
                "department": u.get("department", "IT"),
                "role": u.get("role", "standard"),
                "logged_in": False,
                "session_start": 0,
                "last_activity": 0,
            }

    def generate_tick_events(self, tick: int, base_timestamp: float) -> list[ActivityEvent]:
        """Generate all user activity events for a single simulation tick."""
        events = []
        sim_time = base_timestamp + (tick * self.tick_interval_ms / 1000.0)
        hour = int((sim_time % 86400) / 3600)  # Hour of simulated day
        bucket = self._get_hour_bucket(hour)

        for user_id, state in self._user_states.items():
            profile_cfg = PROFILE_WEIGHTS.get(state["profile"], PROFILE_WEIGHTS["normal"])
            activity_prob = profile_cfg["activity_level"].get(bucket, 0.1)

            # Scale probability to tick interval (base is per-second, tick is 100ms)
            tick_prob = activity_prob * (self.tick_interval_ms / 1000.0) * 0.05

            if self._rng.random() > tick_prob:
                continue

            # Handle login/logout state
            if not state["logged_in"]:
                if self._rng.random() < profile_cfg["login_weight"]:
                    events.append(ActivityEvent(
                        tick=tick, timestamp=sim_time, user_id=user_id,
                        activity_type="login", source_host=state["host"] or "unknown",
                        details={"method": "password", "mfa": self._rng.random() < 0.3},
                    ))
                    state["logged_in"] = True
                    state["session_start"] = sim_time
                continue

            # User is logged in — generate activities
            activity = self._pick_activity(profile_cfg)
            host = state["host"] or "unknown"

            if activity == "logout":
                session_len = sim_time - state["session_start"]
                if session_len > 300:  # Min 5 min session
                    events.append(ActivityEvent(
                        tick=tick, timestamp=sim_time, user_id=user_id,
                        activity_type="logout", source_host=host,
                        details={"session_duration": session_len},
                    ))
                    state["logged_in"] = False
            elif activity == "email_send":
                events.append(self._gen_email_send(tick, sim_time, user_id, host))
            elif activity == "email_read":
                events.append(ActivityEvent(
                    tick=tick, timestamp=sim_time, user_id=user_id,
                    activity_type="email_read", source_host=host,
                    details={"mailbox": "inbox", "count": self._rng.randint(1, 5)},
                ))
            elif activity == "file_access":
                events.append(self._gen_file_access(tick, sim_time, user_id, host, state["department"]))
            elif activity == "web_browse":
                events.append(self._gen_web_browse(tick, sim_time, user_id, host))
            elif activity == "internal_comm":
                events.append(ActivityEvent(
                    tick=tick, timestamp=sim_time, user_id=user_id,
                    activity_type="internal_comm", source_host=host,
                    details={"channel": self._rng.choice(["slack", "teams", "chat"]), "message_count": self._rng.randint(1, 3)},
                ))

            state["last_activity"] = sim_time

        return events

    def _pick_activity(self, profile_cfg: dict) -> str:
        activities = ["email_send", "email_read", "file_access", "web_browse", "internal_comm", "logout"]
        weights = [
            profile_cfg["email_weight"] * 0.5,
            profile_cfg["email_weight"] * 0.5,
            profile_cfg["file_weight"],
            profile_cfg["web_weight"],
            profile_cfg["comm_weight"],
            0.05,  # Small logout chance each tick
        ]
        return self._rng.choices(activities, weights=weights, k=1)[0]

    def _gen_email_send(self, tick: int, ts: float, uid: str, host: str) -> ActivityEvent:
        other_users = [u for u in self._user_states if u != uid]
        recipient = self._rng.choice(other_users) if other_users else "external@example.com"
        return ActivityEvent(
            tick=tick, timestamp=ts, user_id=uid, activity_type="email_send", source_host=host,
            target=recipient, details={"subject_length": self._rng.randint(3, 15), "has_attachment": self._rng.random() < 0.15, "recipient_type": "internal"},
        )

    def _gen_file_access(self, tick: int, ts: float, uid: str, host: str, dept: str) -> ActivityEvent:
        file_paths = {
            "IT": ["/shared/it/configs/", "/shared/it/scripts/", "/shared/it/docs/"],
            "Engineering": ["/shared/eng/src/", "/shared/eng/docs/", "/shared/eng/data/"],
            "Finance": ["/shared/finance/reports/", "/shared/finance/budgets/"],
            "HR": ["/shared/hr/personnel/", "/shared/hr/policies/"],
            "Executive": ["/shared/exec/strategy/", "/shared/exec/board/"],
            "Operations": ["/shared/ops/procedures/", "/shared/ops/inventory/"],
        }
        paths = file_paths.get(dept, ["/shared/general/"])
        return ActivityEvent(
            tick=tick, timestamp=ts, user_id=uid, activity_type="file_access", source_host=host,
            target=self._rng.choice(paths) + f"file_{self._rng.randint(1,100)}.{'xlsx' if dept == 'Finance' else 'docx'}",
            details={"operation": self._rng.choice(["read", "read", "read", "write", "download"]), "size_bytes": self._rng.randint(1024, 5242880)},
        )

    def _gen_web_browse(self, tick: int, ts: float, uid: str, host: str) -> ActivityEvent:
        sites = ["intranet.amcds-corp.sim", "portal.amcds-corp.sim", "wiki.amcds-corp.sim",
                 "news.example.com", "docs.example.com", "stackoverflow.com", "github.com"]
        return ActivityEvent(
            tick=tick, timestamp=ts, user_id=uid, activity_type="web_browse", source_host=host,
            target=f"https://{self._rng.choice(sites)}/{self._rng.choice(['page', 'article', 'doc'])}/{self._rng.randint(1, 500)}",
            details={"method": "GET", "status_code": 200, "response_time_ms": self._rng.randint(50, 2000)},
        )

    def _get_hour_bucket(self, hour: int) -> str:
        for bucket, hours in HOUR_BUCKETS.items():
            if hour in hours:
                return bucket
        return "night"

    def get_active_users(self) -> list[str]:
        return [uid for uid, s in self._user_states.items() if s["logged_in"]]
