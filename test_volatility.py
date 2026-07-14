import os
import pandas as pd

from agents.volatility_agent import get_atr
from agents.market_status import classify_market

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


def test_volatility(symbol):
    data_path = f"data/{symbol}.csv"

    if not os.path.exists(data_path):
        return {
            "symbol": symbol.upper(),
            "status": "NO_DATA",
        }

    df = pd.read_csv(data_path)

    if len(df) < 250:
        return {
            "symbol": symbol.upper(),
            "status": "NOT_ENOUGH_DATA",
        }

    atr = get_atr(df)
    price = df["Close"].iloc[-1]
    volatility_percent = (atr / price) * 100
    market_status = classify_market(atr, price, symbol=symbol)

    return {
        "symbol": symbol.upper(),
        "price": price,
        "atr": atr,
        "volatility_percent": volatility_percent,
        "status": market_status,
    }


def main():
    print("\n=== MULTI PAIR VOLATILITY CHECK ===")
    print(
        f"{'PAIR':<8} "
        f"{'PRICE':>12} "
        f"{'ATR':>12} "
        f"{'VOL%':>8} "
        f"{'STATUS':>8}"
    )
    print("-" * 56)

    for symbol in SYMBOLS:
        result = test_volatility(symbol)

        if result["status"] in ["NO_DATA", "NOT_ENOUGH_DATA"]:
            print(
                f"{result['symbol']:<8} "
                f"{'-':>12} "
                f"{'-':>12} "
                f"{'-':>8} "
                f"{result['status']:>8}"
            )
            continue

        print(
            f"{result['symbol']:<8} "
            f"{result['price']:>12.5f} "
            f"{result['atr']:>12.5f} "
            f"{result['volatility_percent']:>7.4f}% "
            f"{result['status']:>8}"
        )


if __name__ == "__main__":
    main()
