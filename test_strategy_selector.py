import pandas as pd

from strategy.strategy_selector import select_best_strategy, evaluate_strategies

SYMBOLS = [
    "eurusd",
    "gbpusd",
    "audusd",
    "gbpjpy",
    "xauusd",
    "btcusd",
]


def test_symbol(symbol):
    data_path = f"data/{symbol}.csv"
    df = pd.read_csv(data_path)

    result = select_best_strategy(df)
    all_strategies, context = evaluate_strategies(df)

    print(f"\n=== {symbol.upper()} ===")
    print(f"Market Regime     : {result['market_regime']}")
    print(f"Volatility %      : {result['volatility_percent']:.4f}")
    print(f"Selected Strategy : {result['strategy']}")
    print(f"Signal            : {result['signal']}")
    print(f"Score             : {result['score']}")
    print(f"Reasons           : {result['reasons']}")

    print("\nStrategy Scores:")
    for item in all_strategies:
        print(
            f"- {item['strategy']:<18} "
            f"Signal: {item['signal']:<8} "
            f"Score: {item['score']}"
        )


def main():
    for symbol in SYMBOLS:
        try:
            test_symbol(symbol)
        except FileNotFoundError:
            print(f"{symbol.upper()} data not found.")


if __name__ == "__main__":
    main()