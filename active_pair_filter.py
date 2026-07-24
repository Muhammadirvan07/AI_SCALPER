import json
import os

import pandas as pd

from strategy.strategy_selector import select_best_strategy
from agents.volatility_agent import get_atr
from agents.market_status import classify_market
from agents.supervisor_agent import SupervisorAgent
from execution_policy import is_execution_symbol_allowed

ACTIVE_PAIRS_FILE = "active_pairs.json"
DATA_DIR = "data"

DEFAULT_ACTIVE_PAIRS = [
    "eurusd",
]
SHADOW_SCAN_PAIRS = ["btcusd"]


def normalize_active_pairs(active_pairs):
    symbols = [
        str(symbol).lower()
        for symbol in active_pairs
        if str(symbol).strip()
    ]

    shadow_only = set(SHADOW_SCAN_PAIRS)
    return [
        symbol
        for symbol in dict.fromkeys(symbols)
        if symbol not in shadow_only
    ]


def get_scan_pairs():
    return list(dict.fromkeys(load_active_pairs() + SHADOW_SCAN_PAIRS))


def load_active_pairs():
    if not os.path.exists(ACTIVE_PAIRS_FILE):
        return normalize_active_pairs(DEFAULT_ACTIVE_PAIRS)

    try:
        with open(ACTIVE_PAIRS_FILE, "r") as file:
            payload = json.load(file)
    except (OSError, json.JSONDecodeError):
        return normalize_active_pairs(DEFAULT_ACTIVE_PAIRS)

    if isinstance(payload, dict):
        active_pairs = payload.get("active_pairs", [])
    elif isinstance(payload, list):
        active_pairs = payload
    else:
        return normalize_active_pairs(DEFAULT_ACTIVE_PAIRS)

    if not active_pairs:
        return normalize_active_pairs(DEFAULT_ACTIVE_PAIRS)

    return normalize_active_pairs(active_pairs)


def is_active_pair(symbol):
    active_pairs = load_active_pairs()
    return symbol.lower() in active_pairs


def load_symbol_data(symbol):
    symbol = str(symbol or "").strip()
    path_candidates = [
        f"{DATA_DIR}/{symbol}.csv",
        f"{DATA_DIR}/{symbol.lower()}.csv",
        f"{DATA_DIR}/{symbol.upper()}.csv",
    ]

    for data_path in path_candidates:
        if not os.path.exists(data_path):
            continue

        df = pd.read_csv(data_path)

        if len(df) < 250:
            return None

        return df

    return None


def analyze_active_pair(symbol):
    df = load_symbol_data(symbol)

    if df is None:
        return {
            "symbol": symbol.upper(),
            "status": "NO_DATA",
            "signal": "WAIT",
            "decision": "WAIT",
            "selected_strategy": "NO_DATA",
            "strategy_score": 0,
            "strategy_score_components": {},
            "strategy_regime": "NO_DATA",
            "strategy_reasons": ["no data available"],
        }

    supervisor = SupervisorAgent()

    strategy_result = select_best_strategy(df, symbol=symbol)
    signal = strategy_result["signal"]
    selected_strategy = strategy_result["strategy"]
    strategy_score = strategy_result["score"]
    strategy_score_components = strategy_result.get("score_components", {})
    strategy_regime = strategy_result["market_regime"]
    strategy_reasons = strategy_result["reasons"]

    atr = get_atr(df)
    price = df["Close"].iloc[-1]
    volatility_percent = (atr / price) * 100
    market_status = classify_market(atr, price, symbol=symbol)

    decision = supervisor.make_decision(
        signal,
        market_status,
    )

    return {
        "symbol": symbol.upper(),
        "scan_scope": (
            "EXECUTION_CANDIDATE"
            if is_execution_symbol_allowed(symbol)
            else "SHADOW_ONLY"
        ),
        "price": price,
        "atr": atr,
        "volatility_percent": volatility_percent,
        "market_status": market_status,
        "signal": signal,
        "decision": decision,
        "selected_strategy": selected_strategy,
        "strategy_score": strategy_score,
        "strategy_score_components": strategy_score_components,
        "strategy_regime": strategy_regime,
        "strategy_reasons": strategy_reasons,
    }


def scan_active_pairs():
    active_pairs = get_scan_pairs()
    results = []

    for symbol in active_pairs:
        result = analyze_active_pair(symbol)
        results.append(result)

    return results


def print_active_pair_scan(results):
    print("\n=== AI ACTIVE PAIR SCANNER ===")
    print(
        f"{'PAIR':<8} "
        f"{'PRICE':>12} "
        f"{'VOL%':>8} "
        f"{'MARKET':>8} "
        f"{'STRATEGY':>18} "
        f"{'SCORE':>7} "
        f"{'SIGNAL':>8} "
        f"{'DECISION':>9}"
    )
    print("-" * 100)

    for item in results:
        if item.get("status") == "NO_DATA":
            print(
                f"{item['symbol']:<8} "
                f"{'-':>12} "
                f"{'-':>8} "
                f"{'NO_DATA':>8} "
                f"{item['selected_strategy']:>18} "
                f"{item['strategy_score']:>7} "
                f"{item['signal']:>8} "
                f"{item['decision']:>9}"
            )
            continue

        print(
            f"{item['symbol']:<8} "
            f"{item['price']:>12.5f} "
            f"{item['volatility_percent']:>7.4f}% "
            f"{item['market_status']:>8} "
            f"{item['selected_strategy']:>18} "
            f"{item['strategy_score']:>7} "
            f"{item['signal']:>8} "
            f"{item['decision']:>9}"
        )


def get_tradeable_pairs():
    results = scan_active_pairs()

    tradeable_pairs = [
        item for item in results
        if item.get("decision") in ["BUY", "SELL"]
        and is_execution_symbol_allowed(item.get("symbol"))
    ]

    return tradeable_pairs


def main():
    active_pairs = load_active_pairs()

    print("\n=== AI ACTIVE PAIR FILTER ===")
    print(f"ACTIVE_PAIRS = {active_pairs}")
    print(f"SHADOW_SCAN_PAIRS = {SHADOW_SCAN_PAIRS}")
    print("\nOnly execution-approved active pairs may become trade candidates.")

    results = scan_active_pairs()
    print_active_pair_scan(results)

    tradeable_pairs = get_tradeable_pairs()

    print("\n=== TRADEABLE PAIRS NOW ===")

    if not tradeable_pairs:
        print("No active pair has a valid BUY/SELL decision right now.")
        return

    for item in tradeable_pairs:
        print(
            f"✅ {item['symbol']} | "
            f"Decision: {item['decision']} | "
            f"Strategy: {item['selected_strategy']} | "
            f"Score: {item['strategy_score']} | "
            f"Regime: {item['strategy_regime']} | "
            f"Market: {item['market_status']} | "
            f"Volatility: {item['volatility_percent']:.4f}%"
        )

        if item.get("strategy_reasons"):
            print(f"   Reasons: {item['strategy_reasons']}")


if __name__ == "__main__":
    main()
