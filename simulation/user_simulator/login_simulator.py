"""
Login Simulator - Generates authentication telemetry events.
"""
from __future__ import annotations
import random
from dataclasses import dataclass
from typing import Any


@dataclass
class AuthEvent:
    tick: int
    timestamp: float
    user_id: str
    username: str
    source_ip: str
    source_host: str
    target_service: str
    auth_method: str  # "password", "mfa", "sso", "certificate"
    success: bool
    failure_reason: str | None = None
    mfa_used: bool = False
    session_id: str | None = None
    details: dict[str, Any] | None = None


class LoginSimulator:
    """Generates realistic authentication events including failures and MFA."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self._rng = random.Random(seed)
        self._session_counter = 0

    def simulate_login(self, tick: int, timestamp: float, user_id: str, username: str,
                       source_ip: str, source_host: str, role: str = "standard") -> AuthEvent:
        """Simulate a normal login attempt."""
        # Normal users occasionally mistype passwords
        fail_chance = 0.03 if role != "service-account" else 0.001
        success = self._rng.random() > fail_chance
        mfa = role in ("admin", "privileged") or self._rng.random() < 0.2
        auth_method = "mfa" if mfa else "password"

        self._session_counter += 1
        session_id = f"sess-{self._session_counter:08d}" if success else None

        return AuthEvent(
            tick=tick, timestamp=timestamp, user_id=user_id, username=username,
            source_ip=source_ip, source_host=source_host, target_service="Active Directory",
            auth_method=auth_method, success=success,
            failure_reason="invalid_password" if not success else None,
            mfa_used=mfa, session_id=session_id,
            details={"role": role, "login_type": "interactive"},
        )

    def simulate_logout(self, tick: int, timestamp: float, user_id: str, username: str,
                        source_ip: str, source_host: str, session_duration: float) -> AuthEvent:
        return AuthEvent(
            tick=tick, timestamp=timestamp, user_id=user_id, username=username,
            source_ip=source_ip, source_host=source_host, target_service="Active Directory",
            auth_method="session_end", success=True,
            details={"session_duration_seconds": session_duration, "logout_type": "user_initiated"},
        )

    def simulate_service_auth(self, tick: int, timestamp: float, service_account: str,
                              source_ip: str, target_service: str) -> AuthEvent:
        self._session_counter += 1
        return AuthEvent(
            tick=tick, timestamp=timestamp, user_id=service_account, username=service_account,
            source_ip=source_ip, source_host="service", target_service=target_service,
            auth_method="certificate", success=True, session_id=f"svc-{self._session_counter:08d}",
            details={"login_type": "service"},
        )
