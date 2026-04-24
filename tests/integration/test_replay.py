"""Integration test: Deterministic replay produces identical results."""
import pytest
from simulation.enterprise_simulator.topology import EnterpriseTopology
from simulation.enterprise_simulator.users import UserGenerator
from simulation.user_simulator.behavior_engine import UserBehaviorEngine


class TestDeterministicReplay:
    def test_topology_replay(self):
        """Same seed produces identical topology across runs."""
        results = []
        for _ in range(3):
            t = EnterpriseTopology(seed=42, num_hosts=50, num_subnets=5).generate()
            data = t.to_dict()
            results.append(data)
        assert results[0] == results[1] == results[2]

    def test_user_replay(self):
        """Same seed produces identical users across runs."""
        results = []
        for _ in range(3):
            gen = UserGenerator(seed=42, num_users=20)
            users = gen.generate()
            results.append(list(users.keys()))
        assert results[0] == results[1] == results[2]

    def test_behavior_replay(self):
        """Same seed produces identical behavior events."""
        events_runs = []
        for _ in range(2):
            engine = UserBehaviorEngine(seed=42, tick_interval_ms=100)
            engine.initialize_users([
                {"id": f"u-{i}", "behavior_profile": "normal", "assigned_host_id": f"h-{i}", "department": "IT", "role": "standard"}
                for i in range(5)
            ])
            events = []
            for tick in range(100):
                tick_events = engine.generate_tick_events(tick, 1700000000.0)
                events.extend([(e.tick, e.user_id, e.activity_type) for e in tick_events])
            events_runs.append(events)
        assert events_runs[0] == events_runs[1]
