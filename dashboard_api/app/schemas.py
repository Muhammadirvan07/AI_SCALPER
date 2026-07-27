from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ApiSchema(BaseModel):
    model_config = ConfigDict(extra="ignore")


class HealthResponse(ApiSchema):
    status: str
    uptime_seconds: float
    root_path: str
    root_path_valid: bool
    watcher_running: bool
    websocket_clients: int
    latest_snapshot_time: datetime | None
    snapshot_version: int
    stale: bool
    source_availability: dict[str, str] = Field(default_factory=dict)
    source_contract_compliance_percent: float = 0
    latency_target_ms: dict[str, float] = Field(default_factory=dict)
    slo_target_percent: float = 99.5


class WebSocketEvent(ApiSchema):
    type: str
    version: int
    timestamp: datetime
    payload: Any = None
