"""
OCSF-Style Telemetry Event Schema using Pydantic models.

All telemetry events conform to a common base schema with category-specific
extensions. The `_sim` field carries simulation replay metadata.
"""
from __future__ import annotations
from enum import IntEnum
from typing import Any, Optional
import uuid
import time
from pydantic import BaseModel, Field


class Severity(IntEnum):
    UNKNOWN = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class CategoryUID(IntEnum):
    SYSTEM = 1
    FINDINGS = 2
    IAM = 3
    NETWORK = 4
    DISCOVERY = 5
    APPLICATION = 6


class ProductInfo(BaseModel):
    name: str = "AMCDS"
    vendor: str = "Simulated"
    version: str = "1.0.0"


class Metadata(BaseModel):
    version: str = "1.0.0"
    product: ProductInfo = Field(default_factory=ProductInfo)
    logged_time: float = Field(default_factory=time.time)
    uid: str = Field(default_factory=lambda: str(uuid.uuid4()))


class Endpoint(BaseModel):
    ip: str | None = None
    hostname: str | None = None
    port: int | None = None
    mac: str | None = None
    os_type: str | None = None


class UserInfo(BaseModel):
    name: str | None = None
    uid: str | None = None
    email: str | None = None
    department: str | None = None
    role: str | None = None
    groups: list[str] = Field(default_factory=list)


class SimMeta(BaseModel):
    """Simulation metadata for deterministic replay."""
    seed: int = 42
    tick: int = 0
    scenario: str = "baseline"


class TelemetryEvent(BaseModel):
    """Base OCSF-style telemetry event."""
    metadata: Metadata = Field(default_factory=Metadata)
    severity_id: int = Severity.INFO
    category_uid: int = CategoryUID.SYSTEM
    class_uid: int = 0
    type_uid: int = 0
    time: float = Field(default_factory=time.time)
    activity_id: int = 0
    actor: UserInfo | None = None
    src_endpoint: Endpoint | None = None
    dst_endpoint: Endpoint | None = None
    status_id: int = 1  # 1=success, 2=failure
    message: str = ""
    raw_data: str | None = None
    unmapped: dict[str, Any] = Field(default_factory=dict)
    _sim: SimMeta = SimMeta()

    class Config:
        use_enum_values = True

    def to_kafka_dict(self) -> dict[str, Any]:
        d = self.model_dump()
        d["_sim"] = self._sim.model_dump() if hasattr(self._sim, 'model_dump') else {"seed": 42, "tick": 0, "scenario": "baseline"}
        return d


# ===== Category-Specific Event Types =====

class AuthTelemetry(TelemetryEvent):
    """IAM Authentication event (OCSF class_uid 3001)."""
    category_uid: int = CategoryUID.IAM
    class_uid: int = 3001
    auth_method: str = "password"
    session_id: str | None = None
    mfa_used: bool = False
    failure_reason: str | None = None


class NetworkTelemetry(TelemetryEvent):
    """Network Activity event (OCSF class_uid 4001)."""
    category_uid: int = CategoryUID.NETWORK
    class_uid: int = 4001
    protocol: str = "tcp"
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    duration_ms: int = 0
    flow_type: str = "normal"


class HttpTelemetry(TelemetryEvent):
    """HTTP Activity event (OCSF class_uid 4002)."""
    category_uid: int = CategoryUID.NETWORK
    class_uid: int = 4002
    http_method: str = "GET"
    url: str = ""
    status_code: int = 200
    request_size: int = 0
    response_size: int = 0
    response_time_ms: int = 0
    user_agent: str = ""


class FileTelemetry(TelemetryEvent):
    """File Activity event (OCSF class_uid 1001)."""
    category_uid: int = CategoryUID.SYSTEM
    class_uid: int = 1001
    operation: str = "read"
    file_path: str = ""
    file_name: str = ""
    file_size: int = 0
    file_type: str = ""
    sensitivity: str = "internal"


class ProcessTelemetry(TelemetryEvent):
    """Process Activity event (OCSF class_uid 1007)."""
    category_uid: int = CategoryUID.SYSTEM
    class_uid: int = 1007
    pid: int = 0
    ppid: int = 0
    process_name: str = ""
    command_line: str = ""
    process_user: str = ""
    event_type: str = "start"
    cpu_percent: float = 0.0
    memory_mb: float = 0.0


class EmailTelemetry(TelemetryEvent):
    """Email Activity event (OCSF class_uid 6001)."""
    category_uid: int = CategoryUID.APPLICATION
    class_uid: int = 6001
    email_event_type: str = "send"
    sender_email: str = ""
    recipients: list[str] = Field(default_factory=list)
    subject: str = ""
    body_length: int = 0
    has_attachment: bool = False
    attachment_name: str | None = None
    attachment_size: int = 0
