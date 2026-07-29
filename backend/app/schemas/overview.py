from __future__ import annotations

from datetime import datetime

from .common import SchemaModel


class OverviewKpis(SchemaModel):
    account_balance: float | None = None
    equity: float | None = None
    net_profit: float | None = None
    win_rate: float | None = None
    profit_factor: float | None = None
    expectancy: float | None = None
    maximum_drawdown: float | None = None
    maximum_drawdown_percent: float | None = None
    closed_orders: int | None = None
    open_positions: int | None = None
    readiness_score: float | None = None


class OverviewStatus(SchemaModel):
    current_phase: str | None = None
    quality_status: str = "UNKNOWN"
    active_pair: str | None = None
    active_strategy: str | None = None
    market_session: str | None = None
    market_regime: str | None = None
    current_mode: str = "DRY_RUN"
    live_allowed: bool = False
    system_summary: str
    last_update: datetime | None = None


class OverviewData(SchemaModel):
    kpis: OverviewKpis
    status: OverviewStatus
