import json
import os
import subprocess
import sys
import time
from datetime import datetime

from active_pair_filter import scan_active_pairs
from decision_engine import (
    build_trade_decision,
    build_mt5_order_payload,
    get_mt5_symbol,
)

TRADE_SIGNAL_OUTPUT = "trade_signals.json"
MT5_SIGNAL_OUTPUT = "mt5_trade_signals.json"
MT5_BRIDGE_SCRIPT = "mt5_bridge_reader.py"
ACTIVE_PAIRS_FILE = "active_pairs.json"
DATA_DIR = "data"
RUN_MT5_BRIDGE_AFTER_DECISION = True
MAX_SIGNAL_AGE_SECONDS = 10
LIVE_DATA_MAX_AGE_SECONDS = 60
REQUIRE_FRESH_CSV_DATA = True
LIVE_ENGINE_ENABLED = False


def load_active_pairs_for_freshness_check():
    if not os.path.exists(ACTIVE_PAIRS_FILE):
        return []

    with open(ACTIVE_PAIRS_FILE, "r") as file:
        payload = json.load(file)

    return payload.get("active_pairs", [])


def get_csv_file_age_seconds(symbol):
    csv_path = os.path.join(DATA_DIR, f"{symbol.lower()}.csv")

    if not os.path.exists(csv_path):
        return None

    modified_at = os.path.getmtime(csv_path)
    return time.time() - modified_at


def validate_live_csv_freshness():
    active_pairs = load_active_pairs_for_freshness_check()

    if not active_pairs:
        return False, ["No active pairs found in active_pairs.json."]

    problems = []

    for symbol in active_pairs:
        age_seconds = get_csv_file_age_seconds(symbol)

        if age_seconds is None:
            problems.append(f"{symbol.upper()} CSV file is missing.")
            continue

        if age_seconds > LIVE_DATA_MAX_AGE_SECONDS:
            problems.append(
                f"{symbol.upper()} CSV is stale: {age_seconds:.1f}s old "
                f"(max allowed: {LIVE_DATA_MAX_AGE_SECONDS}s)."
            )

    return len(problems) == 0, problems


def is_data_fresh_enough(trade_plan):
    generated_at = datetime.now()

    return {
        "is_fresh": True,
        "checked_at": generated_at.isoformat(timespec="seconds"),
        "max_signal_age_seconds": MAX_SIGNAL_AGE_SECONDS,
        "note": "Fast mode uses the latest CSV snapshot from data/. For true live execution, replace CSV data with MT5 tick/bid-ask feed.",
    }


def generate_live_trade_plan():
    active_results = scan_active_pairs()
    trade_plan = []

    for item in active_results:
        trade_decision = build_trade_decision(item)
        trade_decision["engine_mode"] = "LIVE_FAST_MODE"
        trade_decision["decision_created_at"] = datetime.now().isoformat(timespec="seconds")
        trade_plan.append(trade_decision)

    return trade_plan


def save_live_trade_signals(trade_plan):
    ready_trades = [
        item for item in trade_plan
        if item["status"] == "READY_TO_TRADE"
    ]

    mt5_orders = []

    for item in ready_trades:
        mt5_payload = build_mt5_order_payload(item)

        if mt5_payload is not None:
            mt5_payload["engine_mode"] = "LIVE_FAST_MODE"
            mt5_payload["fast_mode_warning"] = (
                "This signal was generated without running data collection or backtest. "
                "It uses the latest available active_pairs.json and CSV market snapshot."
            )
            mt5_orders.append(mt5_payload)

    freshness = is_data_fresh_enough(trade_plan)

    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "engine_mode": "LIVE_FAST_MODE",
        "ready_trade_count": len(ready_trades),
        "freshness": freshness,
        "signals": ready_trades,
        "all_decisions": trade_plan,
    }

    mt5_payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "engine_mode": "LIVE_FAST_MODE",
        "order_count": len(mt5_orders),
        "freshness": freshness,
        "orders": mt5_orders,
    }

    with open(TRADE_SIGNAL_OUTPUT, "w") as file:
        json.dump(payload, file, indent=4)

    with open(MT5_SIGNAL_OUTPUT, "w") as file:
        json.dump(mt5_payload, file, indent=4)

    print(f"\nSaved live trade signals to: {TRADE_SIGNAL_OUTPUT}")
    print(f"Saved live MT5-ready signals to: {MT5_SIGNAL_OUTPUT}")


def run_mt5_bridge_reader():
    if not RUN_MT5_BRIDGE_AFTER_DECISION:
        print("\nMT5 bridge auto-run is OFF.")
        return True

    print("\nRunning MT5 bridge reader after live decision engine...")

    result = subprocess.run(
        [sys.executable, MT5_BRIDGE_SCRIPT],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print("❌ Failed to run MT5 bridge reader.")
        print(result.stderr)
        return False

    print("✅ MT5 bridge reader finished successfully.")

    if result.stdout:
        print(result.stdout)

    return True


def print_live_trade_plan(trade_plan, elapsed_seconds):
    print("\n=== LIVE FAST DECISION ENGINE ===")
    print(f"Execution time: {elapsed_seconds:.2f} seconds")
    print("Mode: Fast decision only. Data collection and backtest are skipped.")
    print(
        f"{'PAIR':<8} "
        f"{'STATUS':>15} "
        f"{'ACTION':>8} "
        f"{'STRATEGY':>18} "
        f"{'SCORE':>7} "
        f"{'LOT':>7} "
        f"{'ENTRY':>12} "
        f"{'SL':>12} "
        f"{'TP':>12} "
        f"{'STOP':>8} "
        f"{'VOL%':>8}"
    )
    print("-" * 130)

    for item in trade_plan:
        if item["status"] != "READY_TO_TRADE":
            print(
                f"{item['symbol']:<8} "
                f"{item['status']:>15} "
                f"{'-':>8} "
                f"{item.get('selected_strategy', 'UNKNOWN'):>18} "
                f"{item.get('strategy_score', 0):>7} "
                f"{'-':>7} "
                f"{'-':>12} "
                f"{'-':>12} "
                f"{'-':>12} "
                f"{'-':>8} "
                f"{item['volatility_percent']:>7.4f}%"
            )
            print(f"  Reason: {item['reason']}")
            continue

        print(
            f"{item['symbol']:<8} "
            f"{item['status']:>15} "
            f"{item['action']:>8} "
            f"{item.get('selected_strategy', 'UNKNOWN'):>18} "
            f"{item.get('strategy_score', 0):>7} "
            f"{item['lot_size']:>7.2f} "
            f"{item['entry_price']:>12.5f} "
            f"{item['stop_loss']:>12.5f} "
            f"{item['take_profit']:>12.5f} "
            f"{item['stop_pips']:>8.1f} "
            f"{item['volatility_percent']:>7.4f}%"
        )
        print(f"  Reason: {item['reason']}")

    ready_trades = [
        item for item in trade_plan
        if item["status"] == "READY_TO_TRADE"
    ]

    print("\n=== LIVE READY TRADE SUMMARY ===")

    if not ready_trades:
        print("No live trade is ready right now.")
        return

    for item in ready_trades:
        print(
            f"✅ {item['symbol']} {item['action']} | "
            f"Strategy: {item.get('selected_strategy', 'UNKNOWN')} | "
            f"Score: {item.get('strategy_score', 0)} | "
            f"MT5: {get_mt5_symbol(item['symbol'])} | "
            f"Lot: {item['lot_size']:.2f} | "
            f"Entry: {item['entry_price']:.5f} | "
            f"SL: {item['stop_loss']:.5f} | "
            f"TP: {item['take_profit']:.5f} | "
            f"Risk: ${item['risk_amount']:.2f}"
        )


def main():
    if not LIVE_ENGINE_ENABLED:
        print("\n=== LIVE FAST DECISION ENGINE ===")
        print("Live engine is hard-locked. Use decision_engine.py for paper-only evaluation.")
        print("No signal file was modified and no MT5 bridge was started.")
        return

    started_at = time.time()

    if REQUIRE_FRESH_CSV_DATA:
        is_fresh, freshness_problems = validate_live_csv_freshness()

        if not is_fresh:
            print("\n=== LIVE FAST DECISION ENGINE ===")
            print("❌ Live decision stopped because market CSV data is not fresh enough.")
            print("\nProblems:")

            for problem in freshness_problems:
                print(f"- {problem}")

            print("\nRun this first to refresh data and active pairs:")
            print("python decision_engine.py")
            return

    trade_plan = generate_live_trade_plan()
    elapsed_seconds = time.time() - started_at

    print_live_trade_plan(trade_plan, elapsed_seconds)
    save_live_trade_signals(trade_plan)

    bridge_ran = run_mt5_bridge_reader()

    if not bridge_ran:
        print("Live decision engine finished, but MT5 bridge reader failed.")


if __name__ == "__main__":
    main()
