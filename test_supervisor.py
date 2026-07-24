from pathlib import Path

import pandas as pd

from strategy.trend_analyzer import analyze_trend
from agents.volatility_agent import get_atr
from agents.market_status import classify_market
from agents.risk_manager import RiskManager
from agents.supervisor_agent import SupervisorAgent


DEFAULT_DATA_PATH = Path("data/btcusd.csv")


def build_supervisor_report(data_path=DEFAULT_DATA_PATH):
    df = pd.read_csv(data_path)
    signal = analyze_trend(df, symbol="BTCUSD")
    atr = get_atr(df)
    price = df["Close"].iloc[-1]
    market_status = classify_market(atr, price, symbol="BTCUSD")
    risk = RiskManager().calculate_trade_parameters(
        balance=50,
        risk_percent=1,
        atr=atr,
    )
    decision = SupervisorAgent().make_decision(signal, market_status)
    return {
        "signal": signal,
        "atr": atr,
        "market_status": market_status,
        "risk": risk,
        "decision": decision,
    }


def main():
    try:
        report = build_supervisor_report()
    except FileNotFoundError as exc:
        raise SystemExit(
            "Runtime cache data/btcusd.csv is unavailable. "
            "Run the data collector before this diagnostic."
        ) from exc

    print("\n=== AI SCALPER REPORT ===")
    print(f"Signal: {report['signal']}")
    print(
        f"ATR: {report['atr']:.2f} | "
        f"Market: {report['market_status']}"
    )
    print(f"Risk Amount: ${report['risk']['risk_amount']}")
    print(f"SL: {report['risk']['stop_loss']}")
    print(f"TP: {report['risk']['take_profit']}")
    print(f"\nDecision: {report['decision']}")


if __name__ == "__main__":
    main()
