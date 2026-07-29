from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from .common import SchemaModel
from .economic_calendar import EconomicCalendarDiagnosticContext


class DiagnosticsData(SchemaModel):
    final_decision: str = "UNKNOWN"
    selected_strategy: str | None = None
    strategy_score: float | None = None
    confidence: float | None = None
    score_components: dict[str, Any] = Field(default_factory=dict)
    score_boost: dict[str, Any] = Field(default_factory=dict)
    missing_components: list[str] = Field(default_factory=list)
    positive_reasons: list[str] = Field(default_factory=list)
    negative_reasons: list[str] = Field(default_factory=list)
    blocking_reasons: list[str] = Field(default_factory=list)
    market_regime: str | None = None
    volatility_state: str | None = None
    session_status: str | None = None
    pair_rotation_status: str | None = None
    quality_guard_status: str | None = None
    strategy_guard_status: str | None = None
    post_loss_cooldown: str | None = None
    recovery_lane: str | None = None
    readiness_score: float | None = None
    current_recommendation: str | None = None
    source: str
    updated_at: datetime | None = None
    economic_calendar: EconomicCalendarDiagnosticContext | None = None
