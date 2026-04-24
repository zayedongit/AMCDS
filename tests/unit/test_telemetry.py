"""Tests for Telemetry Schema and Normalizer."""
import pytest
from simulation.telemetry_engine.schema import (
    AuthTelemetry, NetworkTelemetry, HttpTelemetry,
    FileTelemetry, ProcessTelemetry, EmailTelemetry, Severity,
)
from simulation.telemetry_engine.normalizer import TelemetryNormalizer


class TestTelemetrySchema:
    def test_auth_event_creation(self):
        evt = AuthTelemetry(message="Test login", auth_method="password")
        assert evt.class_uid == 3001
        assert evt.auth_method == "password"

    def test_network_event_creation(self):
        evt = NetworkTelemetry(protocol="tcp", bytes_sent=1000)
        assert evt.class_uid == 4001
        assert evt.bytes_sent == 1000

    def test_http_event_creation(self):
        evt = HttpTelemetry(http_method="GET", url="https://test.com", status_code=200)
        assert evt.class_uid == 4002

    def test_file_event_creation(self):
        evt = FileTelemetry(operation="read", file_path="/test/file.txt")
        assert evt.class_uid == 1001

    def test_event_serialization(self):
        evt = AuthTelemetry(message="Test")
        d = evt.to_kafka_dict()
        assert "metadata" in d
        assert "severity_id" in d
        assert "_sim" in d


class TestNormalizer:
    def setup_method(self):
        self.normalizer = TelemetryNormalizer(seed=42, scenario="test")

    def test_normalize_auth_success(self):
        raw = {"timestamp": 1700000000, "username": "jsmith", "user_id": "u-001",
               "source_ip": "10.1.2.50", "source_host": "ws-001", "success": True,
               "auth_method": "password"}
        evt = self.normalizer.normalize_auth_event(raw, tick=100)
        assert evt.severity_id == Severity.INFO
        assert evt.status_id == 1

    def test_normalize_auth_failure(self):
        raw = {"timestamp": 1700000000, "username": "jsmith", "user_id": "u-001",
               "source_ip": "10.1.2.50", "source_host": "ws-001", "success": False,
               "failure_reason": "invalid_password"}
        evt = self.normalizer.normalize_auth_event(raw, tick=100)
        assert evt.severity_id == Severity.MEDIUM
        assert evt.status_id == 2

    def test_normalize_network(self):
        raw = {"timestamp": 1700000000, "source_ip": "10.1.2.50", "dest_ip": "10.1.1.10",
               "dest_port": 443, "protocol": "tcp", "bytes_sent": 5000, "bytes_received": 10000}
        evt = self.normalizer.normalize_network_event(raw, tick=100)
        assert evt.bytes_sent == 5000
