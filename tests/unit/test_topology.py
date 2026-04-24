"""Tests for Enterprise Topology Generator."""
import pytest
from simulation.enterprise_simulator.topology import EnterpriseTopology


class TestEnterpriseTopology:
    def test_deterministic_generation(self):
        """Same seed produces identical topology."""
        t1 = EnterpriseTopology(seed=42, num_hosts=50).generate()
        t2 = EnterpriseTopology(seed=42, num_hosts=50).generate()
        assert len(t1.hosts) == len(t2.hosts)
        assert list(t1.hosts.keys()) == list(t2.hosts.keys())
        for hid in t1.hosts:
            assert t1.hosts[hid].ip_address == t2.hosts[hid].ip_address
            assert t1.hosts[hid].mac_address == t2.hosts[hid].mac_address

    def test_host_count(self):
        t = EnterpriseTopology(seed=1, num_hosts=100).generate()
        assert len(t.hosts) == 100

    def test_subnet_count(self):
        t = EnterpriseTopology(seed=1, num_subnets=5).generate()
        assert len(t.subnets) == 5

    def test_hosts_distributed_across_subnets(self):
        t = EnterpriseTopology(seed=1, num_hosts=100, num_subnets=5).generate()
        total_hosts_in_subnets = sum(len(s.hosts) for s in t.subnets.values())
        assert total_hosts_in_subnets == 100

    def test_servers_exist(self):
        t = EnterpriseTopology(seed=1, num_hosts=100).generate()
        assert len(t.get_servers()) > 0

    def test_workstations_exist(self):
        t = EnterpriseTopology(seed=1, num_hosts=100).generate()
        assert len(t.get_workstations()) > 0

    def test_graph_connectivity(self):
        t = EnterpriseTopology(seed=1, num_hosts=50).generate()
        assert t.graph.number_of_edges() > 0

    def test_serialization(self):
        t = EnterpriseTopology(seed=42, num_hosts=10).generate()
        data = t.to_dict()
        assert "subnets" in data
        assert "hosts" in data
        assert "edges" in data

    def test_different_seeds_different_topology(self):
        t1 = EnterpriseTopology(seed=1, num_hosts=50).generate()
        t2 = EnterpriseTopology(seed=999, num_hosts=50).generate()
        # MACs should differ
        h1_macs = [h.mac_address for h in t1.hosts.values()]
        h2_macs = [h.mac_address for h in t2.hosts.values()]
        assert h1_macs != h2_macs
