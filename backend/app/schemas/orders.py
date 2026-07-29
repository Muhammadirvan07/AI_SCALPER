from __future__ import annotations

from datetime import datetime

from .common import SchemaModel


class PaperOrder(SchemaModel):
    order_id: str
    signal_id: str | None = None
    symbol: str | None = None
    side: str | None = None
    strategy: str | None = None
    entry: float | None = None
    exit: float | None = None
    stop_loss: float | None = None
    take_profit: float | None = None
    lot: float | None = None
    open_time: datetime | None = None
    close_time: datetime | None = None
    duration_seconds: float | None = None
    pnl: float | None = None
    pnl_percent: float | None = None
    r_multiple: float | None = None
    exit_reason: str | None = None
    result: str | None = None
    status: str = "UNKNOWN"
    mode: str = "PAPER"
    source: str | None = None
