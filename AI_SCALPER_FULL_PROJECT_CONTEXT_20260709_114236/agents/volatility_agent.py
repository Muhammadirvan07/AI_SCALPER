from ta.volatility import AverageTrueRange

def get_atr(df):

    atr = AverageTrueRange(
        high=df["High"],
        low=df["Low"],
        close=df["Close"],
        window=14
    )

    return atr.average_true_range().iloc[-1]
