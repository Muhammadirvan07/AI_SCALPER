from ta.trend import EMAIndicator, ADXIndicator
from ta.momentum import RSIIndicator

from strategy.trend_analyzer import analyze_trend

MIN_STRATEGY_SCORE = 2


def get_market_context(df):
    close = df["Close"]
    high = df["High"]
    low = df["Low"]

    current_price = close.iloc[-1]

    ema20 = EMAIndicator(close=close, window=20).ema_indicator()
    ema50 = EMAIndicator(close=close, window=50).ema_indicator()
    ema200 = EMAIndicator(close=close, window=200).ema_indicator()

    adx = ADXIndicator(
        high=high,
        low=low,
        close=close,
        window=14,
    ).adx()

    rsi = RSIIndicator(close=close, window=14).rsi()

    ema20_now = ema20.iloc[-1]
    ema50_now = ema50.iloc[-1]
    ema200_now = ema200.iloc[-1]
    adx_now = adx.iloc[-1]
    rsi_now = rsi.iloc[-1]

    recent_high = high.tail(20).max()
    recent_low = low.tail(20).min()
    volatility_percent = ((recent_high - recent_low) / current_price) * 100

    ema_trend_up = ema20_now > ema50_now > ema200_now
    ema_trend_down = ema20_now < ema50_now < ema200_now

    if adx_now >= 22 and (ema_trend_up or ema_trend_down):
        market_regime = "TRENDING"
    elif adx_now < 18:
        market_regime = "RANGING"
    else:
        market_regime = "TRANSITION"

    return {
        "price": current_price,
        "ema20": ema20_now,
        "ema50": ema50_now,
        "ema200": ema200_now,
        "adx": adx_now,
        "rsi": rsi_now,
        "recent_high": recent_high,
        "recent_low": recent_low,
        "volatility_percent": volatility_percent,
        "ema_trend_up": ema_trend_up,
        "ema_trend_down": ema_trend_down,
        "market_regime": market_regime,
    }


def trend_following_strategy(df, context):
    signal = analyze_trend(df)
    score = 0
    reasons = []

    if signal in ["BUY", "SELL"]:
        score += 2
        reasons.append("trend analyzer gives valid direction")

    if context["market_regime"] == "TRENDING":
        score += 2
        reasons.append("market is trending")

    if context["adx"] >= 22:
        score += 1
        reasons.append("ADX confirms trend strength")

    return {
        "strategy": "TREND_FOLLOWING",
        "signal": signal,
        "score": score,
        "reasons": reasons,
    }


def breakout_strategy(df, context):
    close = df["Close"]
    high = df["High"]
    low = df["Low"]

    current_close = close.iloc[-1]
    breakout_high = high.iloc[-21:-1].max()
    breakout_low = low.iloc[-21:-1].min()

    signal = "SIDEWAYS"
    score = 0
    reasons = []

    if current_close > breakout_high:
        signal = "BUY"
        score += 2
        reasons.append("price breaks previous 20-candle high")

    elif current_close < breakout_low:
        signal = "SELL"
        score += 2
        reasons.append("price breaks previous 20-candle low")

    if context["market_regime"] in ["TRENDING", "TRANSITION"]:
        score += 1
        reasons.append("market regime supports breakout")

    if context["adx"] >= 18:
        score += 1
        reasons.append("ADX supports breakout")

    return {
        "strategy": "BREAKOUT",
        "signal": signal,
        "score": score,
        "reasons": reasons,
    }


def mean_reversion_strategy(df, context):
    signal = "SIDEWAYS"
    score = 0
    reasons = []

    if context["rsi"] <= 30:
        signal = "BUY"
        score += 2
        reasons.append("RSI oversold")

    elif context["rsi"] >= 70:
        signal = "SELL"
        score += 2
        reasons.append("RSI overbought")

    if context["market_regime"] == "RANGING":
        score += 2
        reasons.append("market is ranging")

    if context["adx"] < 18:
        score += 1
        reasons.append("weak ADX supports range strategy")

    return {
        "strategy": "MEAN_REVERSION",
        "signal": signal,
        "score": score,
        "reasons": reasons,
    }


def momentum_pullback_strategy(df, context):
    price = context["price"]
    ema20 = context["ema20"]
    ema50 = context["ema50"]
    rsi = context["rsi"]

    distance_to_ema20_percent = abs(price - ema20) / price * 100

    signal = "SIDEWAYS"
    score = 0
    reasons = []

    if ema20 > ema50 and price >= ema20 and 45 <= rsi <= 65:
        signal = "BUY"
        score += 2
        reasons.append("bullish pullback near EMA20")

    elif ema20 < ema50 and price <= ema20 and 35 <= rsi <= 55:
        signal = "SELL"
        score += 2
        reasons.append("bearish pullback near EMA20")

    if distance_to_ema20_percent <= 0.05:
        score += 1
        reasons.append("price is close to EMA20")

    if context["market_regime"] in ["TRENDING", "TRANSITION"]:
        score += 1
        reasons.append("market supports pullback continuation")

    return {
        "strategy": "MOMENTUM_PULLBACK",
        "signal": signal,
        "score": score,
        "reasons": reasons,
    }


def evaluate_strategies(df):
    context = get_market_context(df)

    strategy_results = [
        trend_following_strategy(df, context),
        breakout_strategy(df, context),
        mean_reversion_strategy(df, context),
        momentum_pullback_strategy(df, context),
    ]

    return strategy_results, context


def select_best_strategy(df):
    strategy_results, context = evaluate_strategies(df)

    valid_results = [
        item for item in strategy_results
        if item["signal"] in ["BUY", "SELL"]
    ]

    if not valid_results:
        return {
            "signal": "SIDEWAYS",
            "strategy": "NO_STRATEGY",
            "score": 0,
            "market_regime": context["market_regime"],
            "volatility_percent": context["volatility_percent"],
            "all_strategies": strategy_results,
            "reasons": ["no strategy produced BUY/SELL"],
        }

    best_result = sorted(
        valid_results,
        key=lambda item: item["score"],
        reverse=True,
    )[0]

    if best_result["score"] < MIN_STRATEGY_SCORE:
        return {
            "signal": "SIDEWAYS",
            "strategy": "LOW_SCORE",
            "score": best_result["score"],
            "market_regime": context["market_regime"],
            "volatility_percent": context["volatility_percent"],
            "all_strategies": strategy_results,
            "reasons": ["best strategy score below threshold"],
        }

    return {
        "signal": best_result["signal"],
        "strategy": best_result["strategy"],
        "score": best_result["score"],
        "market_regime": context["market_regime"],
        "volatility_percent": context["volatility_percent"],
        "all_strategies": strategy_results,
        "reasons": best_result["reasons"],
    }