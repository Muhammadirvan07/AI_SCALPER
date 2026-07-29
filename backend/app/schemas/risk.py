from __future__ import annotations

from pydantic import Field

from .common import SchemaModel


class RiskData(SchemaModel):
    account_balance: float | None = None
    base_risk_percent: float | None = None
    adaptive_risk_percent: float | None = None
    risk_profile: str = "CONSERVATIVE_PAPER"
    calculated_lot: float | None = None
    engine_max_lot: float | None = None
    backend_safety_max_lot: float = 0.01
    effective_max_lot: float = 0.01
    guard_applied: bool = False
    stop_distance: float | None = None
    target_distance: float | None = None
    risk_reward_ratio: float | None = None
    daily_drawdown: float | None = None
    maximum_drawdown: float | None = None
    consecutive_losses: int = 0
    cooldown_status: str = "UNKNOWN"
    recovery_status: str = "UNKNOWN"
    live_allowed: bool = False
    live_execution_status: str = "LIVE EXECUTION LOCKED"
    risk_guard_status: str = "LOCKED"
    warnings: list[str] = Field(default_factory=list)
