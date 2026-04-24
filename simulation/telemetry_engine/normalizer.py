"""
Telemetry Normalizer - Converts raw simulator events into OCSF-style schema.
"""
from __future__ import annotations
from typing import Any

from simulation.telemetry_engine.schema import (
    AuthTelemetry, NetworkTelemetry, HttpTelemetry, FileTelemetry,
    ProcessTelemetry, EmailTelemetry, TelemetryEvent,
    Endpoint, UserInfo, Metadata, SimMeta, Severity,
)


class TelemetryNormalizer:
    """Converts raw simulation events to normalized OCSF telemetry."""

    def __init__(self, seed: int = 42, scenario: str = "baseline"):
        self.seed = seed
        self.scenario = scenario

    def normalize_auth_event(self, raw: dict[str, Any], tick: int) -> AuthTelemetry:
        return AuthTelemetry(
            time=raw.get("timestamp", 0),
            severity_id=Severity.INFO if raw.get("success", True) else Severity.MEDIUM,
            activity_id=1 if raw.get("success") else 2,
            actor=UserInfo(name=raw.get("username"), uid=raw.get("user_id")),
            src_endpoint=Endpoint(ip=raw.get("source_ip"), hostname=raw.get("source_host")),
            dst_endpoint=Endpoint(hostname=raw.get("target_service", "Active Directory")),
            status_id=1 if raw.get("success", True) else 2,
            message=f"Auth {'success' if raw.get('success') else 'failure'} for {raw.get('username')}",
            auth_method=raw.get("auth_method", "password"),
            session_id=raw.get("session_id"),
            mfa_used=raw.get("mfa_used", False),
            failure_reason=raw.get("failure_reason"),
            _sim=SimMeta(seed=self.seed, tick=tick, scenario=self.scenario),
        )

    def normalize_network_event(self, raw: dict[str, Any], tick: int) -> NetworkTelemetry:
        return NetworkTelemetry(
            time=raw.get("timestamp", 0),
            severity_id=Severity.INFO,
            src_endpoint=Endpoint(ip=raw.get("source_ip"), hostname=raw.get("source_host")),
            dst_endpoint=Endpoint(ip=raw.get("dest_ip"), hostname=raw.get("dest_host"), port=raw.get("dest_port")),
            message=f"Network flow {raw.get('source_ip')}:{raw.get('source_port')} -> {raw.get('dest_ip')}:{raw.get('dest_port')}",
            protocol=raw.get("protocol", "tcp"),
            bytes_sent=raw.get("bytes_sent", 0),
            bytes_received=raw.get("bytes_received", 0),
            packets_sent=raw.get("packets_sent", 0),
            packets_received=raw.get("packets_received", 0),
            duration_ms=raw.get("duration_ms", 0),
            flow_type=raw.get("flow_type", "normal"),
            _sim=SimMeta(seed=self.seed, tick=tick, scenario=self.scenario),
        )

    def normalize_http_event(self, raw: dict[str, Any], tick: int) -> HttpTelemetry:
        status = raw.get("status_code", 200)
        sev = Severity.INFO if status < 400 else (Severity.MEDIUM if status < 500 else Severity.HIGH)
        return HttpTelemetry(
            time=raw.get("timestamp", 0),
            severity_id=sev,
            actor=UserInfo(uid=raw.get("user_id")) if raw.get("user_id") else None,
            src_endpoint=Endpoint(ip=raw.get("source_ip"), hostname=raw.get("source_host")),
            dst_endpoint=Endpoint(ip=raw.get("dest_ip"), hostname=raw.get("dest_host")),
            message=f"{raw.get('method', 'GET')} {raw.get('url', '')} -> {status}",
            http_method=raw.get("method", "GET"),
            url=raw.get("url", ""),
            status_code=status,
            request_size=raw.get("request_size", 0),
            response_size=raw.get("response_size", 0),
            response_time_ms=raw.get("response_time_ms", 0),
            user_agent=raw.get("user_agent", ""),
            _sim=SimMeta(seed=self.seed, tick=tick, scenario=self.scenario),
        )

    def normalize_file_event(self, raw: dict[str, Any], tick: int) -> FileTelemetry:
        sev = Severity.INFO
        if raw.get("sensitivity") in ("confidential", "restricted"):
            sev = Severity.LOW if raw.get("operation") == "read" else Severity.MEDIUM
        return FileTelemetry(
            time=raw.get("timestamp", 0),
            severity_id=sev,
            actor=UserInfo(uid=raw.get("user_id")),
            src_endpoint=Endpoint(hostname=raw.get("source_host")),
            message=f"File {raw.get('operation', 'read')}: {raw.get('file_path', '')}",
            operation=raw.get("operation", "read"),
            file_path=raw.get("file_path", ""),
            file_name=raw.get("file_name", ""),
            file_size=raw.get("file_size", 0),
            file_type=raw.get("file_type", ""),
            sensitivity=raw.get("sensitivity", "internal"),
            _sim=SimMeta(seed=self.seed, tick=tick, scenario=self.scenario),
        )

    def normalize_process_event(self, raw: dict[str, Any], tick: int) -> ProcessTelemetry:
        return ProcessTelemetry(
            time=raw.get("timestamp", 0),
            severity_id=Severity.INFO,
            src_endpoint=Endpoint(hostname=raw.get("hostname")),
            message=f"Process {raw.get('event_type', 'start')}: {raw.get('process_name', '')}",
            pid=raw.get("pid", 0),
            ppid=raw.get("ppid", 0),
            process_name=raw.get("process_name", ""),
            command_line=raw.get("command_line", ""),
            process_user=raw.get("user", ""),
            event_type=raw.get("event_type", "start"),
            cpu_percent=raw.get("cpu_percent", 0.0),
            memory_mb=raw.get("memory_mb", 0.0),
            _sim=SimMeta(seed=self.seed, tick=tick, scenario=self.scenario),
        )

    def normalize_email_event(self, raw: dict[str, Any], tick: int) -> EmailTelemetry:
        return EmailTelemetry(
            time=raw.get("timestamp", 0),
            severity_id=Severity.INFO,
            actor=UserInfo(uid=raw.get("sender_id")),
            message=f"Email {raw.get('event_type', 'send')}: {raw.get('subject', '')}",
            email_event_type=raw.get("event_type", "send"),
            sender_email=raw.get("sender_email", ""),
            recipients=raw.get("recipients", []),
            subject=raw.get("subject", ""),
            body_length=raw.get("body_length", 0),
            has_attachment=raw.get("has_attachment", False),
            attachment_name=raw.get("attachment_name"),
            attachment_size=raw.get("attachment_size", 0),
            _sim=SimMeta(seed=self.seed, tick=tick, scenario=self.scenario),
        )
