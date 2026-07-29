from __future__ import annotations

import math

import pytest

from app.utils.calculations import performance_metrics


def test_performance_metrics_and_drawdown() -> None:
    data = performance_metrics(
        [
            {"status": "CLOSED", "pnl": 1},
            {"status": "CLOSED", "pnl": -0.5},
            {"status": "CLOSED", "pnl": 0},
            {"status": "PAPER_OPEN", "pnl": None},
        ],
        starting_balance=50,
    )
    assert data["wins"] == 1
    assert data["losses"] == 1
    assert data["breakeven"] == 1
    assert data["open_orders"] == 1
    assert data["win_rate"] == pytest.approx(100 / 3)
    assert data["profit_factor"] == 2
    assert data["expectancy"] == 0.5 / 3
    assert data["maximum_drawdown"] == 0.5
    assert data["ending_balance"] == 50.5


def test_performance_metrics_never_divide_by_zero() -> None:
    empty = performance_metrics([])
    assert empty["win_rate"] is None
    assert empty["profit_factor"] is None
    assert empty["expectancy"] is None
    only_win = performance_metrics([{"status": "CLOSED", "pnl": 1}])
    assert math.isinf(only_win["profit_factor"])


def test_consecutive_streaks() -> None:
    data = performance_metrics(
        [
            {"status": "CLOSED", "pnl": 1},
            {"status": "CLOSED", "pnl": 1},
            {"status": "CLOSED", "pnl": -1},
            {"status": "CLOSED", "pnl": -1},
            {"status": "CLOSED", "pnl": -1},
        ]
    )
    assert data["consecutive_wins"] == 2
    assert data["consecutive_losses"] == 3
