from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, SerializeAsAny


class SchemaModel(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class Freshness(SchemaModel):
    source_updated_at: datetime | None = None
    server_timestamp: datetime
    age_seconds: float | None = None
    stale: bool = True
    source_available: bool = False


class ApiMeta(Freshness):
    source: str | None = None
    request_id: str | None = None
    data_status: str = "unavailable"
    warnings: list[str] = Field(default_factory=list)


class ApiError(SchemaModel):
    code: str
    message: str
    details: Any = None


class ErrorMeta(SchemaModel):
    timestamp: datetime
    request_id: str | None = None


class SuccessResponse[T](SchemaModel):
    success: bool = True
    data: T
    meta: SerializeAsAny[ApiMeta]


class ErrorResponse(SchemaModel):
    success: bool = False
    error: ApiError
    meta: ErrorMeta


class Page[T](SchemaModel):
    items: list[T]
    total: int
    limit: int
    offset: int
