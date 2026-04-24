"""Tests for Agent Detection Logic."""
import pytest
from agents.identity_agent.agent import IdentityAgent
from agents.network_agent.agent import NetworkAgent
from agents.endpoint_agent.agent import EndpointAgent


class TestIdentityAgent:
    def test_unusual_login_detection(self):
        agent = IdentityAgent()
        event = {
            "class_uid": 3001, "status_id": 1, "time": 7200.0,  # 2 AM
            "actor": {"uid": "u-001"}, "src_endpoint": {"ip": "10.1.2.50"},
        }
        alerts = agent.analyze(event)
        assert any(a.alert_type == "unusual_login_time" for a in alerts)


class TestNetworkAgent:
    def test_sql_injection_detection(self):
        agent = NetworkAgent()
        event = {
            "class_uid": 4002,
            "url": "/api/users?id=1' OR '1'='1",
            "http_method": "GET",
            "src_endpoint": {"ip": "198.51.100.1"},
            "time": 1700000000,
        }
        alerts = agent.analyze(event)
        assert any(a.alert_type == "sql_injection" for a in alerts)

    def test_path_traversal_detection(self):
        agent = NetworkAgent()
        event = {
            "class_uid": 4002,
            "url": "/download?file=../../../etc/passwd",
            "src_endpoint": {"ip": "198.51.100.1"},
            "time": 1700000000,
        }
        alerts = agent.analyze(event)
        assert any(a.alert_type == "path_traversal" for a in alerts)


class TestEndpointAgent:
    def test_ransomware_detection(self):
        agent = EndpointAgent()
        event = {
            "class_uid": 1007,
            "process_name": "cmd.exe",
            "command_line": "vssadmin delete shadows /all /quiet",
            "src_endpoint": {"hostname": "ws-001"},
            "time": 1700000000,
        }
        alerts = agent.analyze(event)
        assert any(a.alert_type == "ransomware_activity" for a in alerts)

    def test_suspicious_process_detection(self):
        agent = EndpointAgent()
        event = {
            "class_uid": 1007,
            "process_name": "mimikatz.exe",
            "command_line": "mimikatz.exe privilege::debug",
            "src_endpoint": {"hostname": "ws-002"},
            "time": 1700000000,
        }
        alerts = agent.analyze(event)
        assert any(a.alert_type == "suspicious_process" for a in alerts)
