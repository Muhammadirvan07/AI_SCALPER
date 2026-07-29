from __future__ import annotations

from datetime import datetime

from pydantic import Field

from .common import SchemaModel


class Candle(SchemaModel):
    timestamp: datetime
    open: float
    high: float
    low: float
    close: float
    volume: float = 0
    spread: float | None = None


class CandleSeries(SchemaModel):
    symbol: str
    requested_timeframe: str
    actual_timeframe: str
    derived: bool = False
    candles: list[Candle] = Field(default_factory=list)
    resolution_warning: str | None = None


class Quote(SchemaModel):
    symbol: str
    bid: float | None = None
    ask: float | None = None
    last: float | None = None
    spread: float | None = None
    change: float | None = None
    change_percent: float | None = None
    timestamp: datetime | None = None
    source_kind: str = "historical_close"


class MarketIndicators(SchemaModel):
    symbol: str
    timeframe: str
    ema20: float | None = None
    ema50: float | None = None
    atr14: float | None = None
    adx14: float | None = None
    volatility: float | None = None
    trend: str = "UNKNOWN"
    market_regime: str = "UNKNOWN"


class WatchlistItem(SchemaModel):
    symbol: str
    bid: float | None = None
    ask: float | None = None
    last_price: float | None = None
    spread: float | None = None
    change: float | None = None
    change_percent: float | None = None
    trend: str = "UNKNOWN"
    volatility: float | None = None
    atr: float | None = None
    adx: float | None = None
    strategy: str | None = None
    strategy_score: float | None = None
    signal: str | None = None
    quality_status: str = "UNKNOWN"
    blocked: bool = False
    last_update: datetime | None = None
    stale: bool = True
