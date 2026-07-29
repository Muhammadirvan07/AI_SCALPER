from __future__ import annotations

from datetime import datetime

from pydantic import Field

from .common import SchemaModel


class PerformancePoint(SchemaModel):
    index: int
    timestamp: datetime | None = None
    balance: float
    equity: float
    cumulative_pnl: float
    period_pnl: float
    drawdown: float
    drawdown_percent: float
    order_id: str | None = None


class PerformanceData(SchemaModel):
    total_orders: int = 0
    closed_orders: int = 0
    open_orders: int = 0
    wins: int = 0
    losses: int = 0
    breakeven: int = 0
    timeouts: int = 0
    win_rate: float | None = None
    gross_profit: float = 0
    gross_loss: float = 0
    net_profit: float = 0
    profit_factor: float | None = None
    average_win: float | None = None
    average_loss: float | None = None
    expectancy: float | None = None
    maximum_drawdown: float = 0
    maximum_drawdown_percent: float = 0
    consecutive_wins: int = 0
    consecutive_losses: int = 0
    starting_balance: float = 0
    ending_balance: float = 0
    curve: list[PerformancePoint] = Field(default_factory=list)
