from strategy.strategy_profiles import get_strategy_profile


def classify_market(atr, price, symbol="UNKNOWN"):
    if price is None or float(price) <= 0 or atr is None or float(atr) < 0:
        return "HIGH"

    volatility_percent = (float(atr) / float(price)) * 100.0
    asset_class = get_strategy_profile(symbol).asset_class

    if asset_class == "FOREX":
        high_threshold, normal_threshold = 0.05, 0.006
    elif asset_class == "CRYPTO":
        high_threshold, normal_threshold = 0.50, 0.03
    else:
        high_threshold, normal_threshold = 0.35, 0.05

    if volatility_percent > high_threshold:
        return "HIGH"
    if volatility_percent > normal_threshold:
        return "NORMAL"
    return "LOW"
