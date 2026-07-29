from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field, HttpUrl, field_validator

from app.schemas.common import SchemaModel


class EconomicEventStatus(StrEnum):
    SCHEDULED = "SCHEDULED"
    COUNTDOWN = "COUNTDOWN"
    AWAITING_RELEASE = "AWAITING_RELEASE"
    RELEASED = "RELEASED"
    REVISED = "REVISED"
    DELAYED = "DELAYED"
    RESCHEDULED = "RESCHEDULED"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"


class EconomicSourceType(StrEnum):
    OFFICIAL = "OFFICIAL"
    MANUAL = "MANUAL"
    LOCAL_FILE = "LOCAL_FILE"
    MODEL_ESTIMATE = "MODEL_ESTIMATE"
    UNKNOWN = "UNKNOWN"


class EconomicEventCategory(StrEnum):
    INTEREST_RATE = "INTEREST_RATE"
    CENTRAL_BANK = "CENTRAL_BANK"
    INFLATION = "INFLATION"
    CPI = "CPI"
    PPI = "PPI"
    EMPLOYMENT = "EMPLOYMENT"
    NFP = "NFP"
    UNEMPLOYMENT = "UNEMPLOYMENT"
    JOLTS = "JOLTS"
    GDP = "GDP"
    RETAIL_SALES = "RETAIL_SALES"
    PMI = "PMI"
    CONSUMER_CONFIDENCE = "CONSUMER_CONFIDENCE"
    INDUSTRIAL_PRODUCTION = "INDUSTRIAL_PRODUCTION"
    HOUSING = "HOUSING"
    TRADE_BALANCE = "TRADE_BALANCE"
    ENERGY = "ENERGY"
    INVENTORIES = "INVENTORIES"
    SPEECH = "SPEECH"
    MEETING_MINUTES = "MEETING_MINUTES"
    FINANCIAL_STABILITY = "FINANCIAL_STABILITY"
    REGULATION = "REGULATION"
    OTHER = "OTHER"


class EconomicImpact(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class SurpriseLabel(StrEnum):
    ABOVE_FORECAST = "ABOVE_FORECAST"
    BELOW_FORECAST = "BELOW_FORECAST"
    INLINE = "INLINE"
    NO_FORECAST = "NO_FORECAST"


class CalendarGuardState(StrEnum):
    NORMAL = "NORMAL"
    CAUTION = "CAUTION"
    HIGH_RISK = "HIGH_RISK"
    BLOCK_PREVIEW = "BLOCK_PREVIEW"
    POST_RELEASE_VOLATILITY = "POST_RELEASE_VOLATILITY"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class ScheduleHistoryEntry(SchemaModel):
    changed_at: datetime
    previous_scheduled_at: datetime
    scheduled_at: datetime
    reason: str


class EconomicCalendarEvent(SchemaModel):
    id: str
    provider: str
    source: str
    source_type: EconomicSourceType = EconomicSourceType.UNKNOWN
    source_url: HttpUrl | None = None
    event_name: str
    short_name: str | None = None
    description: str | None = None
    country: str | None = None
    country_code: str | None = None
    currency: str | None = None
    category: EconomicEventCategory = EconomicEventCategory.OTHER
    impact: EconomicImpact = EconomicImpact.UNKNOWN
    impact_score: float = Field(default=0, ge=0, le=1)
    impact_reasons: list[str] = Field(default_factory=list)
    scheduled_at: datetime
    original_scheduled_at: datetime | None = None
    actual: str | float | int | None = None
    actual_raw: str | float | int | None = None
    forecast: str | float | int | None = None
    forecast_source: str | None = None
    forecast_source_type: EconomicSourceType | None = None
    previous: str | float | int | None = None
    revised_previous: str | float | int | None = None
    revision_source: str | None = None
    revised_at: datetime | None = None
    unit: str | None = None
    frequency: str | None = None
    reference_period: str | None = None
    status: EconomicEventStatus = EconomicEventStatus.UNKNOWN
    affected_symbols: list[str] = Field(default_factory=list)
    symbols: list[str] = Field(default_factory=list)
    is_high_impact: bool = False
    is_live: bool = False
    is_released: bool = False
    is_revised: bool = False
    verified: bool = False
    verified_at: datetime | None = None
    last_checked_at: datetime | None = None
    released_at: datetime | None = None
    updated_at: datetime
    stale: bool = True
    stale_reason: str | None = None
    surprise: float | None = None
    surprise_percent: float | None = None
    surprise_label: SurpriseLabel = SurpriseLabel.NO_FORECAST
    schedule_history: list[ScheduleHistoryEntry] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("currency")
    @classmethod
    def _uppercase_currency(cls, value: str | None) -> str | None:
        return value.strip().upper() if value and value.strip() else None

    @field_validator("affected_symbols", "symbols")
    @classmethod
    def _uppercase_symbols(cls, value: list[str]) -> list[str]:
        return sorted({item.strip().upper() for item in value if item.strip()})


class EconomicCalendarPage(SchemaModel):
    items: list[EconomicCalendarEvent]
    total: int
    limit: int
    offset: int
    counts: dict[str, int] = Field(default_factory=dict)
    next_critical_event: EconomicCalendarEvent | None = None


class EconomicCalendarSourceStatus(SchemaModel):
    name: str
    display_name: str
    enabled: bool
    configured: bool
    healthy: bool
    status: str
    official_domain: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    last_fetch_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None
    last_status_code: int | None = None
    latency_ms: float | None = None
    event_count: int = 0
    failure_count: int = 0
    rate_limited: bool = False
    cooldown_until: datetime | None = None
    next_retry_at: datetime | None = None
    stale: bool = True
    last_known_good_available: bool = False
    verified_at: datetime | None = None


class EconomicCalendarRuntimeStatus(SchemaModel):
    enabled: bool
    state: str
    scheduler_running: bool
    scheduler_mode: str
    active_interval_seconds: float
    last_sync_at: datetime | None = None
    last_success_at: datetime | None = None
    next_sync_at: datetime | None = None
    event_count: int
    today_count: int
    upcoming_count: int
    high_impact_count: int
    live_count: int
    source_count: int
    healthy_source_count: int
    partial: bool
    timezone: str
    engine_integration_enabled: bool = False
    read_only: bool = True
    live_allowed: bool = False
    effective_max_lot: float = Field(default=0.01, le=0.01)
    warnings: list[str] = Field(default_factory=list)


class EconomicCalendarHealth(SchemaModel):
    status: str
    service: str
    scheduler: str
    cache: str
    repository: str
    sources: list[EconomicCalendarSourceStatus]
    last_success_at: datetime | None = None
    stale: bool
    read_only: bool = True
    live_allowed: bool = False
    effective_max_lot: float = Field(default=0.01, le=0.01)


class EconomicCalendarGuardPreview(SchemaModel):
    symbol: str
    state: CalendarGuardState
    event_id: str | None = None
    event_name: str | None = None
    event_impact: EconomicImpact | None = None
    event_scheduled_at: datetime | None = None
    minutes_to_event: float | None = None
    reasons: list[str] = Field(default_factory=list)
    read_only: bool = True
    engine_integration_enabled: bool = False
    diagnostic_only: bool = True
    execution_guard_enabled: bool = False
    affects_execution: bool = False
    creates_orders: bool = False


class EconomicCalendarDiagnosticEvent(SchemaModel):
    id: str
    event_name: str
    currency: str | None = None
    impact: EconomicImpact
    scheduled_at: datetime
    actual: str | float | int | None = None
    forecast: str | float | int | None = None
    previous: str | float | int | None = None
    unit: str | None = None
    status: EconomicEventStatus
    source: str
    source_url: HttpUrl | None = None
    verified: bool
    released_at: datetime | None = None


class EconomicCalendarDiagnosticContext(SchemaModel):
    symbol: str
    status: CalendarGuardState
    currency_exposure: list[str] = Field(default_factory=list)
    next_event: EconomicCalendarDiagnosticEvent | None = None
    minutes_to_event: float | None = None
    minutes_since_event: float | None = None
    event_impact: EconomicImpact | None = None
    event_status: EconomicEventStatus | None = None
    guard_preview: CalendarGuardState
    affected_symbols: list[str] = Field(default_factory=list)
    source: str | None = None
    verified: bool = False
    data_freshness: str = "UNAVAILABLE"
    reasons: list[str] = Field(default_factory=list)
    diagnostic_only: bool = True
    execution_guard_enabled: bool = False
    affects_execution: bool = False
    updated_at: datetime


class EconomicCalendarReleaseAuditRecord(SchemaModel):
    id: str
    event_id: str
    event_name: str
    scheduler_mode: str
    checked_at: datetime
    source: str
    http_status: int | None = None
    source_updated: datetime | None = None
    actual_found: bool
    actual_value: str | float | int | None = None
    status_before: EconomicEventStatus
    status_after: EconomicEventStatus
    latency_ms: float | None = Field(default=None, ge=0)
    error: str | None = None


class EconomicCalendarAuditPage(SchemaModel):
    items: list[EconomicCalendarReleaseAuditRecord]
    total: int
    limit: int
    offset: int


class EconomicCalendarReleaseLatency(SchemaModel):
    event_id: str
    scheduled_at: datetime
    first_check_at: datetime | None = None
    source_published_at: datetime | None = None
    backend_updated_at: datetime | None = None
    websocket_broadcast_at: datetime | None = None
    scheduled_to_first_check_ms: float | None = None
    scheduled_to_source_publish_ms: float | None = None
    scheduled_to_backend_update_ms: float | None = None
    scheduled_to_websocket_broadcast_ms: float | None = None
    scheduled_to_frontend_render_ms: float | None = None


class EconomicCalendarMetrics(SchemaModel):
    economic_calendar_sync_total: int = 0
    economic_calendar_sync_failure_total: int = 0
    economic_calendar_release_detected_total: int = 0
    economic_calendar_release_latency_ms: float | None = None
    economic_calendar_websocket_broadcast_total: int = 0
    economic_calendar_diagnostic_context_total: int = 0
    economic_calendar_guard_preview_changes_total: int = 0
    economic_calendar_mutation_block_total: int = 0
    release_detection_latency_ms: float | None = None
    websocket_delivery_latency_ms: float | None = None
    frontend_render_latency_ms: float | None = None
    latest_release: EconomicCalendarReleaseLatency | None = None
    audit_record_count: int = 0
    diagnostic_only: bool = True
    execution_guard_enabled: bool = False
    live_allowed: bool = False
    effective_max_lot: float = Field(default=0.01, le=0.01)
