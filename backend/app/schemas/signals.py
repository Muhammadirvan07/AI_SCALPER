from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import Field

from .common import SchemaModel


class SignalStatus(StrEnum):
    WAIT = "WAIT"
    APPROVED = "APPROVED"
    PAPER_OPEN = "PAPER_OPEN"
    CLOSED = "CLOSED"
    BLOCKED = "BLOCKED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    SKIPPED = "SKIPPED"
    UNKNOWN = "UNKNOWN"


class TradingSignal(SchemaModel):
    signal_id: str
    timestamp: datetime | None = None
    symbol: str | None = None
    side: str | None = None
    strategy: str | None = None
    original_score: float | None = None
    adaptive_score: float | None = None
    confidence: float | None = None
    entry: float | None = None
    stop_loss: float | None = None
    take_profit: float | None = None
    risk_reward_ratio: float | None = None
    calculated_lot: float | None = None
    risk_percent: float | None = None
    status: SignalStatus = SignalStatus.UNKNOWN
    reason: str | None = None
    blocking_reasons: list[str] = Field(default_factory=list)
    quality_guard: str | None = None
    pair_guard: str | None = None
    session_guard: str | None = None
    expiry: datetime | None = None
    source: str
    mode: str = "PAPER"
