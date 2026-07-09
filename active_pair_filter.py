import json
import os

import pandas as pd

from strategy.strategy_selector import select_best_strategy
from agents.volatility_agent import get_atr
from agents.market_status import classify_market
from agents.supervisor_agent import SupervisorAgent

ACTIVE_PAIRS_FILE = "active_pairs.json"
DATA_DIR = "data"

DEFAULT_ACTIVE_PAIRS = [
    "gbpusd",
    "eurusd",
    "btcusd",
]


def normalize_active_pairs(active_pairs):
    symbols = [
        str(symbol).lower()
        for symbol in active_pairs
        if str(symbol).strip()
    ]

    if "btcusd" not in symbols:
        symbols.append("btcusd")

    return list(dict.fromkeys(symbols))


def load_active_pairs():
    if not os.path.exists(ACTIVE_PAIRS_FILE):
        return normalize_active_pairs(DEFAULT_ACTIVE_PAIRS)

    with open(ACTIVE_PAIRS_FILE, "r") as file:
        payload = json.load(file)

    active_pairs = payload.get("active_pairs", [])

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
            "strategy_regime": "NO_DATA",
            "strategy_reasons": ["no data available"],
        }

    supervisor = SupervisorAgent()

    strategy_result = select_best_strategy(df)
    signal = strategy_result["signal"]
    selected_strategy = strategy_result["strategy"]
    strategy_score = strategy_result["score"]
    strategy_regime = strategy_result["market_regime"]
    strategy_reasons = strategy_result["reasons"]

    atr = get_atr(df)
    price = df["Close"].iloc[-1]
    volatility_percent = (atr / price) * 100
    market_status = classify_market(atr, price)

    decision = supervisor.make_decision(
        signal,
        market_status,
    )

    return {
        "symbol": symbol.upper(),
        "price": price,
        "atr": atr,
        "volatility_percent": volatility_percent,
        "market_status": market_status,
        "signal": signal,
        "decision": decision,
        "selected_strategy": selected_strategy,
        "strategy_score": strategy_score,
        "strategy_regime": strategy_regime,
        "strategy_reasons": strategy_reasons,
    }


def scan_active_pairs():
    active_pairs = load_active_pairs()
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
    ]

    return tradeable_pairs


def main():
    active_pairs = load_active_pairs()

    print("\n=== AI ACTIVE PAIR FILTER ===")
    print(f"ACTIVE_PAIRS = {active_pairs}")
    print("\nAI should only focus on these pairs until the next backtest refresh.")

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