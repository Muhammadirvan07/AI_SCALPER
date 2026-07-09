def classify_market(atr, price):
    volatility_percent = (atr / price) * 100

    if volatility_percent > 0.35:
        return "HIGH"
    elif volatility_percent > 0.08:
        return "NORMAL"
    return "LOW"