from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .serialization import safe_float


def performance_metrics(orders: Iterable[dict[str, Any]], starting_balance: float = 0.0) -> dict[str, Any]:
    rows = list(orders)
    closed = [row for row in rows if str(row.get("status", "")).upper() not in {"OPEN", "PAPER_OPEN", "PENDING"}]
    pnls = [value for row in closed if (value := safe_float(row.get("pnl"))) is not None]
    wins = [value for value in pnls if value > 0]
    losses = [value for value in pnls if value < 0]
    breakeven = sum(1 for value in pnls if value == 0)
    timeout = sum(1 for row in closed if "TIMEOUT" in str(row.get("result") or row.get("exit_reason") or "").upper())
    gross_profit = sum(wins)
    gross_loss = abs(sum(losses))
    net_profit = sum(pnls)
    total_resolved = len(pnls)
    win_rate = len(wins) / total_resolved * 100 if total_resolved else None
    profit_factor = gross_profit / gross_loss if gross_loss else (None if gross_profit == 0 else float("inf"))
    average_win = gross_profit / len(wins) if wins else None
    average_loss = -gross_loss / len(losses) if losses else None
    expectancy = net_profit / total_resolved if total_resolved else None
    equity = starting_balance
    peak = starting_balance
    max_drawdown = 0.0
    max_drawdown_percent = 0.0
    curve: list[dict[str, Any]] = []
    streak_win = streak_loss = max_wins = max_losses = 0
    cumulative = 0.0
    for index, row in enumerate(closed, start=1):
        pnl = safe_float(row.get("pnl")) or 0.0
        cumulative += pnl
        equity += pnl
        peak = max(peak, equity)
        drawdown = peak - equity
        drawdown_pct = drawdown / peak * 100 if peak else 0.0
        max_drawdown = max(max_drawdown, drawdown)
        max_drawdown_percent = max(max_drawdown_percent, drawdown_pct)
        if pnl > 0:
            streak_win += 1
            streak_loss = 0
        elif pnl < 0:
            streak_loss += 1
            streak_win = 0
        else:
            streak_win = streak_loss = 0
        max_wins = max(max_wins, streak_win)
        max_losses = max(max_losses, streak_loss)
        curve.append(
            {
                "index": index,
                "timestamp": row.get("close_time") or row.get("open_time"),
                "balance": round(equity, 8),
                "equity": round(equity, 8),
                "cumulative_pnl": round(cumulative, 8),
                "period_pnl": pnl,
                "drawdown": round(drawdown, 8),
                "drawdown_percent": round(drawdown_pct, 8),
                "order_id": row.get("order_id"),
            }
        )
    return {
        "total_orders": len(rows),
        "closed_orders": len(closed),
        "open_orders": len(rows) - len(closed),
        "wins": len(wins),
        "losses": len(losses),
        "breakeven": breakeven,
        "timeouts": timeout,
        "win_rate": win_rate,
        "gross_profit": gross_profit,
        "gross_loss": gross_loss,
        "net_profit": net_profit,
        "profit_factor": profit_factor,
        "average_win": average_win,
        "average_loss": average_loss,
        "expectancy": expectancy,
        "maximum_drawdown": max_drawdown,
        "maximum_drawdown_percent": max_drawdown_percent,
        "consecutive_wins": max_wins,
        "consecutive_losses": max_losses,
        "starting_balance": starting_balance,
        "ending_balance": equity,
        "curve": curve,
    }
