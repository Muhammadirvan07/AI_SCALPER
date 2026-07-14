"""
Phase5K Zero-Volume Feed Diagnostic (read-only)

Purpose:
    Dump a single JSON snapshot showing, per symbol, the full Phase5J -> Phase5K
    -> Phase5F -> Phase5H chain status. This exists purely to make it fast to
    answer "why is EURUSD stuck" without opening a Python REPL each time.

Safety:
    - Read-only. Does not create orders, does not touch the MT5 bridge/outbox.
    - Does not modify live_allowed, max_lot, safe_to_demo_auto_order.
    - Does not modify Phase4R lock, GBPUSD block, or BTCUSD shadow status.
    - Writes only to phase5k_zero_volume_diagnostic.json.
"""

import json
from datetime import datetime

import decision_engine as de
from strategy.strategy_selector import select_best_strategy
from active_pair_filter import load_symbol_data

DIAGNOSTIC_OUTPUT = "phase5k_zero_volume_diagnostic.json"
SYMBOLS = ["EURUSD", "GBPUSD", "BTCUSD"]


def diagnose_symbol(symbol):
    df = load_symbol_data(symbol)
    if df is None:
        return {"symbol": symbol, "status": "NO_DATA"}

    strategy_result = select_best_strategy(df, symbol=symbol)

    phase5j_allowed, phase5j_guard = de.evaluate_phase5j_market_session_guard(symbol)
    phase5k_allowed, phase5k_guard = de.evaluate_phase5k_market_reopen_warmup_guard(
        symbol, phase5j_guard
    )

    phase5f_allowed, phase5f_guard = de.evaluate_phase5f_adaptive_strategy_selection_guard(
        symbol,
        strategy_result["strategy"],
        strategy_result["score"],
        strategy_result["volatility_percent"],
        de.load_phase4_quality_rules(),
    )

    phase5h_explain = de.build_phase5h_strategy_score_explainability(
        symbol,
        strategy_result["strategy"],
        strategy_result["score"],
        strategy_result["reasons"],
        strategy_result["volatility_percent"],
    )

    return {
        "symbol": symbol,
        "strategy": strategy_result["strategy"],
        "signal": strategy_result["signal"],
        "score": strategy_result["score"],
        "reasons": strategy_result["reasons"],
        "phase5j": {
            "allowed": phase5j_allowed,
            "status": phase5j_guard.get("status"),
        },
        "phase5k": {
            "allowed": phase5k_allowed,
            "status": phase5k_guard.get("status"),
            "active_candles": phase5k_guard.get("active_candles"),
            "min_active_candles": phase5k_guard.get("min_active_candles"),
            "zero_volume_ratio": phase5k_guard.get("zero_volume_ratio"),
            "zero_volume_feed": phase5k_guard.get("zero_volume_feed"),
            "price_only_feed_allowed": phase5k_guard.get("price_only_feed_allowed"),
        },
        "phase5f": {
            "allowed": phase5f_allowed,
            "status": phase5f_guard.get("status"),
            "required_score": phase5f_guard.get("required_score"),
            "reason": phase5f_guard.get("reason"),
        },
        "phase5h": {
            "status": phase5h_explain.get("status"),
            "score_gap": phase5h_explain.get("score_gap"),
            "present_components": phase5h_explain.get("present_components"),
            "missing_components": phase5h_explain.get("missing_components"),
            "positive_matches": phase5h_explain.get("positive_matches"),
        },
    }


def main():
    snapshot = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "read_only": True,
        "creates_order": False,
        "symbols": [diagnose_symbol(symbol) for symbol in SYMBOLS],
    }

    with open(DIAGNOSTIC_OUTPUT, "w") as f:
        json.dump(snapshot, f, indent=2, default=str)

    for item in snapshot["symbols"]:
        if item.get("status") == "NO_DATA":
            print(f"{item['symbol']}: NO_DATA")
            continue
        print(
            f"{item['symbol']}: strategy={item['strategy']} score={item['score']} | "
            f"Phase5J={item['phase5j']['status']} | "
            f"Phase5K={item['phase5k']['status']} "
            f"(active={item['phase5k']['active_candles']}/{item['phase5k']['min_active_candles']}, "
            f"zero_vol_feed={item['phase5k']['zero_volume_feed']}) | "
            f"Phase5F={item['phase5f']['status']} (need>={item['phase5f']['required_score']}) | "
            f"missing={item['phase5h']['missing_components']}"
        )

    print(f"\nSaved diagnostic snapshot to: {DIAGNOSTIC_OUTPUT}")


if __name__ == "__main__":
    main()
