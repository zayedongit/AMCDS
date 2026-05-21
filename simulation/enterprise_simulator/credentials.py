"""
Credential Vault - Manages simulated credentials and their compromise state.
"""
from __future__ import annotations
import hashlib
import random
import secrets
from dataclasses import dataclass, field, asdict
from typing import Any
from datetime import datetime, timedelta


@dataclass
class Credential:
    user_id: str
    username: str
    password_hash: str
    credential_type: str  # "password", "api_key", "session_token", "certificate"
    created_at: float = 0.0
    expires_at: float = 0.0
    is_compromised: bool = False
    compromised_at: float | None = None
    compromised_by: str | None = None
    last_used: float = 0.0
    failed_attempts: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CredentialVault:
    """Manages the lifecycle of simulated credentials."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self._rng = random.Random(seed)
        self.credentials: dict[str, list[Credential]] = {}  # user_id -> list of creds
        self._password_cache: dict[str, str] = {}  # user_id -> plaintext (for attack sim)

    def generate_for_users(self, user_ids: list[tuple[str, str]], base_time: float = 1700000000.0) -> None:
        """Generate credentials for a list of (user_id, username) tuples."""
        self._rng = random.Random(self.seed)
        self.credentials.clear()
        self._password_cache.clear()

        for user_id, username in user_ids:
            creds = []
            # Primary password
            password = self._generate_password(user_id)
            self._password_cache[user_id] = password
            creds.append(Credential(
                user_id=user_id, username=username,
                password_hash=self._hash_password(password),
                credential_type="password",
                created_at=base_time - self._rng.uniform(0, 90 * 86400),
                expires_at=base_time + self._rng.uniform(30 * 86400, 180 * 86400),
            ))
            # API key for some users
            if self._rng.random() < 0.3:
                creds.append(Credential(
                    user_id=user_id, username=username,
                    password_hash=self._generate_api_key(user_id),
                    credential_type="api_key",
                    created_at=base_time - self._rng.uniform(0, 30 * 86400),
                    expires_at=base_time + 365 * 86400,
                ))
            self.credentials[user_id] = creds

    def verify_password(self, user_id: str, password: str) -> bool:
        cached = self._password_cache.get(user_id)
        return cached == password if cached else False

    def mark_compromised(self, user_id: str, attacker_id: str, timestamp: float) -> bool:
        creds = self.credentials.get(user_id, [])
        for cred in creds:
            if cred.credential_type == "password" and not cred.is_compromised:
                cred.is_compromised = True
                cred.compromised_at = timestamp
                cred.compromised_by = attacker_id
                return True
        return False

    def reset_credential(self, user_id: str, timestamp: float) -> None:
        creds = self.credentials.get(user_id, [])
        for cred in creds:
            if cred.credential_type == "password":
                new_pw = self._generate_password(user_id + str(timestamp))
                self._password_cache[user_id] = new_pw
                cred.password_hash = self._hash_password(new_pw)
                cred.is_compromised = False
                cred.compromised_at = None
                cred.compromised_by = None
                cred.created_at = timestamp
                cred.expires_at = timestamp + 90 * 86400

    def record_failed_attempt(self, user_id: str) -> int:
        creds = self.credentials.get(user_id, [])
        for cred in creds:
            if cred.credential_type == "password":
                cred.failed_attempts += 1
                return cred.failed_attempts
        return 0

    def get_compromised_users(self) -> list[str]:
        result = []
        for uid, creds in self.credentials.items():
            if any(c.is_compromised for c in creds):
                result.append(uid)
        return result

    def get_password_for_attack(self, user_id: str) -> str | None:
        return self._password_cache.get(user_id)

    def _generate_password(self, salt: str) -> str:
        h = hashlib.sha256(f"amcds-pw-{self.seed}-{salt}".encode()).hexdigest()
        return f"P@ss{h[:12]}"

    def _hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def _generate_api_key(self, salt: str) -> str:
        h = hashlib.sha256(f"amcds-apikey-{self.seed}-{salt}".encode()).hexdigest()
        return f"ak_{h[:32]}"

    def to_dict(self) -> dict[str, Any]:
        return {uid: [c.to_dict() for c in creds] for uid, creds in self.credentials.items()}
