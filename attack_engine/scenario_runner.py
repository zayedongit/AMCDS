"""
Attack Scenario Runner - Loads and executes attack scenarios from YAML config.
Deterministic execution tied to simulation ticks.
"""
from __future__ import annotations
import logging
import random
import yaml
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class AttackScenarioRunner:
    """Loads and orchestrates attack scenarios from YAML configuration."""

    def __init__(self, seed: int = 42, config_dir: str = "configs/attack_scenarios"):
        self.seed = seed
        self.config_dir = Path(config_dir)
        self._rng = random.Random(seed)
        self._scenarios: list[dict[str, Any]] = []
        self._active_attacks: list[dict[str, Any]] = []
        self._attack_modules: dict[str, Any] = {}

    def load_scenario(self, scenario_name: str) -> None:
        """Load a scenario YAML file."""
        path = self.config_dir / f"{scenario_name}.yaml"
        if not path.exists():
            logger.warning("Scenario file not found: %s", path)
            return

        with open(path) as f:
            config = yaml.safe_load(f)

        self._scenarios = config.get("attack_chains", [])
        logger.info("Loaded scenario '%s' with %d attack chains", scenario_name, len(self._scenarios))

    def initialize_modules(self) -> None:
        """Initialize available attack modules."""
        from attack_engine.credential_attack.attack import CredentialAttack
        from attack_engine.phishing_attack.attack import PhishingAttack
        from attack_engine.malicious_link_attack.attack import MaliciousLinkAttack
        from attack_engine.http_attack.attack import HttpAttack
        from attack_engine.ransomware_attack.attack import RansomwareAttack
        from attack_engine.lateral_movement.attack import LateralMovementAttack

        self._attack_modules = {
            "credential_stuffing": CredentialAttack(seed=self.seed),
            "phishing": PhishingAttack(seed=self.seed),
            "malicious_link": MaliciousLinkAttack(seed=self.seed),
            "http_exploit": HttpAttack(seed=self.seed),
            "ransomware": RansomwareAttack(seed=self.seed),
            "lateral_movement": LateralMovementAttack(seed=self.seed),
        }

    def execute_tick(self, tick: int, timestamp: float, enterprise_state: dict[str, Any]) -> list[dict[str, Any]]:
        """Execute all scheduled attacks for this tick, return generated events."""
        events = []
        for chain in self._scenarios:
            chain_events = self._execute_chain_tick(chain, tick, timestamp, enterprise_state)
            events.extend(chain_events)
        return events

    def _execute_chain_tick(self, chain: dict[str, Any], tick: int, timestamp: float,
                             state: dict[str, Any]) -> list[dict[str, Any]]:
        events = []
        phases = chain.get("phases", [])

        for phase in phases:
            start_tick = phase.get("start_tick", 0)
            end_tick = phase.get("end_tick", start_tick + 100)
            attack_type = phase.get("type", "")

            if start_tick <= tick <= end_tick:
                module = self._attack_modules.get(attack_type)
                if module:
                    phase_events = module.execute(tick, timestamp, state, phase.get("params", {}))
                    events.extend(phase_events)

        return events

    def get_active_scenarios(self) -> list[dict[str, Any]]:
        return list(self._scenarios)
