from __future__ import annotations

from app.adapters.bridge_adapter import BridgeAdapter
from app.adapters.order_adapter import OrderAdapter
from app.adapters.signal_adapter import SignalAdapter
from app.schemas.signals import SignalStatus
from app.utils.datetime import parse_datetime


def test_signal_adapter_normalizes_aliases_and_values() -> None:
    signal = SignalAdapter().normalize(
        {
            "id": "s-1",
            "time": "2026-07-29T14:00:00Z",
            "pair": "eurusd",
            "direction": "buy",
            "strategy": "breakout",
            "score": "4",
            "adaptive_score": "5",
            "entry_price": "1.1",
            "stop_loss": "1.09",
            "take_profit": "1.12",
            "status": "ready",
            "lot": "0.01",
        },
        source="test",
    )
    assert signal.symbol == "EURUSD"
    assert signal.side == "BUY"
    assert signal.status is SignalStatus.APPROVED
    assert signal.risk_reward_ratio == 2
    assert signal.adaptive_score == 5


def test_signal_adapter_handles_missing_unknown_and_invalid_numbers() -> None:
    signal = SignalAdapter().normalize(
        {"symbol": "xauusd", "status": "new-format", "score": "NaN", "reason": "unclassified"}, source="test"
    )
    assert signal.signal_id.startswith("signal-")
    assert signal.status is SignalStatus.UNKNOWN
    assert signal.original_score is None
    assert signal.side is None


def test_signal_source_combines_common_collections_without_duplicates() -> None:
    rows = SignalAdapter().normalize_source(
        {
            "generated_at": "2026-07-29T00:00:00Z",
            "signals": [{"id": "same", "symbol": "eurusd"}],
            "all_decisions": [{"id": "same", "symbol": "EURUSD"}],
        },
        source="test",
    )
    assert len(rows) == 1


def test_order_adapter_normalizes_paper_order() -> None:
    order = OrderAdapter().normalize(
        {
            "paper_order_id": "o-1",
            "created_at": "2026-07-29T00:00:00Z",
            "closed_at": "2026-07-29T00:05:00Z",
            "pair": "eurusd",
            "type": "sell",
            "entry": "1.1",
            "close_price": "1.09",
            "risk_usd": "0.25",
            "profit_usd": "0.5",
            "status": "PAPER_WIN",
            "result": "WIN",
        }
    )
    assert order.symbol == "EURUSD"
    assert order.side == "SELL"
    assert order.status == "CLOSED"
    assert order.duration_seconds == 300
    assert order.r_multiple == 2


def test_timestamp_adapter_is_timezone_aware_and_safe() -> None:
    assert parse_datetime("2026-07-29T14:00:00").tzinfo is not None
    assert parse_datetime("not-a-date") is None
    assert parse_datetime(None) is None


def test_bridge_adapter_always_applies_hard_safety_cap() -> None:
    result = BridgeAdapter().safety({"live_allowed": True, "max_allowed_lot": 0.1}, 0.01)
    assert result["live_allowed"] is False
    assert result["effective_max_lot"] == 0.01
    assert result["guard_applied"] is True
