from __future__ import annotations

from pydantic import Field

from .common import SchemaModel


class QualityData(SchemaModel):
    current_phase: str | None = None
    quality_status: str = "UNKNOWN"
    readiness_status: str = "UNKNOWN"
    readiness_score: float | None = None
    closed_samples: int | None = None
    required_samples: int | None = None
    progress_percent: float | None = None
    win_rate_requirement: float | None = None
    profit_factor_requirement: float | None = None
    expectancy_requirement: float | None = None
    drawdown_requirement: float | None = None
    current_blockers: list[str] = Field(default_factory=list)
    missing_tests: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    safe_to_observe: bool = True
    safe_to_demo_auto_order: bool = False
    safe_to_live_trade: bool = False
