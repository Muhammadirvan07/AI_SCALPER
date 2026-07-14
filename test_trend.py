import os
import pandas as pd

from strategy.trend_analyzer import analyze_trend

SYMBOLS = [
    "eurusd",
    "gbpusd",
    "usdjpy",
    "usdchf",
    "audusd",
    "nzdusd",
    "usdcad",
    "eurjpy",
    "gbpjpy",
    "eurgbp",
    "audjpy",
    "cadjpy",
    "chfjpy",
    "xauusd",
    "btcusd",
]


def test_latest_trend(symbol):
    data_path = f"data/{symbol}.csv"

    if not os.path.exists(data_path):
        return "NO_DATA"

    df = pd.read_csv(data_path)

    if len(df) < 250:
        return "NOT_ENOUGH_DATA"

    return analyze_trend(df, symbol=symbol)


def main():
    print("\n=== LATEST TREND SIGNAL CHECK ===")

    for symbol in SYMBOLS:
        signal = test_latest_trend(symbol)
        print(f"{symbol.upper():<8}: {signal}")


if __name__ == "__main__":
    main()
