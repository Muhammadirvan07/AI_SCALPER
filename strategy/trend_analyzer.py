from ta.trend import EMAIndicator, ADXIndicator
from ta.momentum import RSIIndicator

DEBUG_TREND = False


def get_instrument_settings(current_price):
    # Forex pairs move much smaller in percent than XAUUSD/BTCUSD on M1 data.
    if current_price < 300:
        return {
            "instrument_type": "FOREX",
            "high_vol_threshold": 0.05,
            "normal_vol_threshold": 0.006,
            "min_volatility_percent": 0.003,
            "min_ema_distance_percent": 0.004,
            "min_price_momentum_percent": 0.004,
            "min_trend_score": 3,
            "require_ema200_slope": False,
        }

    if current_price < 10000:
        return {
            "instrument_type": "XAUUSD",
            "high_vol_threshold": 0.35,
            "normal_vol_threshold": 0.05,
            "min_volatility_percent": 0.05,
            "min_ema_distance_percent": 0.10,
            "min_price_momentum_percent": 0.05,
            "min_trend_score": 4,
            "require_ema200_slope": True,
        }

    return {
        "instrument_type": "BTCUSD",
        "high_vol_threshold": 0.50,
        "normal_vol_threshold": 0.03,
        "min_volatility_percent": 0.03,
        "min_ema_distance_percent": 0.10,
        "min_price_momentum_percent": 0.03,
        "min_trend_score": 4,
        "require_ema200_slope": True,
    }


def analyze_trend(df):
    # Butuh data cukup untuk EMA200 dan slope
    if len(df) < 250:
        return "SIDEWAYS"

    ema20 = EMAIndicator(
        close=df["Close"],
        window=20
    ).ema_indicator()

    ema50 = EMAIndicator(
        close=df["Close"],
        window=50
    ).ema_indicator()

    ema200 = EMAIndicator(
        close=df["Close"],
        window=200
    ).ema_indicator()

    adx = ADXIndicator(
        high=df["High"],
        low=df["Low"],
        close=df["Close"],
        window=14
    ).adx()

    rsi = RSIIndicator(
        close=df["Close"],
        window=14
    ).rsi()

    last_ema20 = ema20.iloc[-1]
    last_ema50 = ema50.iloc[-1]
    last_ema200 = ema200.iloc[-1]

    current_adx = adx.iloc[-1]
    current_rsi = rsi.iloc[-1]

    current_price = df["Close"].iloc[-1]

    settings = get_instrument_settings(current_price)

    instrument_type = settings["instrument_type"]
    high_vol_threshold = settings["high_vol_threshold"]
    normal_vol_threshold = settings["normal_vol_threshold"]
    min_volatility_percent = settings["min_volatility_percent"]
    min_ema_distance_percent = settings["min_ema_distance_percent"]
    min_price_momentum_percent = settings["min_price_momentum_percent"]
    min_trend_score = settings["min_trend_score"]
    require_ema200_slope = settings["require_ema200_slope"]

    # Volatility regime detection
    recent_high = df["High"].tail(20).max()
    recent_low = df["Low"].tail(20).min()
    volatility_percent = ((recent_high - recent_low) / current_price) * 100

    if volatility_percent > high_vol_threshold:
        adx_threshold = 18 if instrument_type == "FOREX" else 20
        rsi_buy_threshold = 52
        rsi_sell_threshold = 48
        market_regime = "HIGH_VOL"
    elif volatility_percent > normal_vol_threshold:
        adx_threshold = 14 if instrument_type == "FOREX" else 18
        rsi_buy_threshold = 53 if instrument_type == "FOREX" else 55
        rsi_sell_threshold = 47 if instrument_type == "FOREX" else 45
        market_regime = "NORMAL_VOL"
    else:
        # LOW_VOL market requires stronger confirmation.
        adx_threshold = 18 if instrument_type == "FOREX" else 22
        rsi_buy_threshold = 56 if instrument_type == "FOREX" else 60
        rsi_sell_threshold = 44 if instrument_type == "FOREX" else 40
        market_regime = "LOW_VOL"

    ema200_slope_up = ema200.iloc[-1] > ema200.iloc[-20]
    ema200_slope_down = ema200.iloc[-1] < ema200.iloc[-20]

    buy_slope_ok = ema200_slope_up or not require_ema200_slope
    sell_slope_ok = ema200_slope_down or not require_ema200_slope

    # Short-term momentum confirmation
    ema20_rising = ema20.iloc[-1] > ema20.iloc[-5]
    ema20_falling = ema20.iloc[-1] < ema20.iloc[-5]

    # Trend score helps avoid weak EMA alignments
    trend_score = 0

    if last_ema20 > last_ema50:
        trend_score += 1
    if last_ema50 > last_ema200:
        trend_score += 1
    if ema200_slope_up:
        trend_score += 1
    if current_rsi > 55:
        trend_score += 1

    bear_score = 0

    if last_ema20 < last_ema50:
        bear_score += 1
    if last_ema50 < last_ema200:
        bear_score += 1
    if ema200_slope_down:
        bear_score += 1
    if current_rsi < 45:
        bear_score += 1

    # Forex fallback score: M1 forex often trends with EMA20/EMA50 momentum
    # before EMA50 fully separates from EMA200.
    forex_buy_score = 0
    forex_sell_score = 0

    if last_ema20 > last_ema50:
        forex_buy_score += 1
    if current_price > last_ema200:
        forex_buy_score += 1
    if ema20_rising:
        forex_buy_score += 1
    if current_rsi > rsi_buy_threshold:
        forex_buy_score += 1
    if current_adx > adx_threshold:
        forex_buy_score += 1

    if last_ema20 < last_ema50:
        forex_sell_score += 1
    if current_price < last_ema200:
        forex_sell_score += 1
    if ema20_falling:
        forex_sell_score += 1
    if current_rsi < rsi_sell_threshold:
        forex_sell_score += 1
    if current_adx > adx_threshold:
        forex_sell_score += 1

    # Measure trend strength
    ema_distance_percent = (
        abs(last_ema20 - last_ema200) / current_price
    ) * 100

    # Price momentum over the last 10 candles
    price_10_candles_ago = df["Close"].iloc[-10]
    price_change_percent = (
        abs(current_price - price_10_candles_ago)
        / price_10_candles_ago
    ) * 100

    if DEBUG_TREND:
        print("\n=== TREND DEBUG ===")
        print("EMA20:", round(last_ema20, 2))
        print("EMA50:", round(last_ema50, 2))
        print("EMA200:", round(last_ema200, 2))
        print("ADX:", round(current_adx, 2))
        print("RSI:", round(current_rsi, 2))
        print("Volatility %:", round(volatility_percent, 2))
        print("Market Regime:", market_regime)
        print("Instrument Type:", instrument_type)
        print("ADX Threshold:", adx_threshold)
        print("Min Trend Score:", min_trend_score)
        print("Require EMA200 Slope:", require_ema200_slope)
        print("EMA Distance %:", round(ema_distance_percent, 3))
        print("Price Momentum %:", round(price_change_percent, 3))
        print("Bull Score:", trend_score)
        print("Bear Score:", bear_score)
        print("Forex Buy Score:", forex_buy_score)
        print("Forex Sell Score:", forex_sell_score)
        print("Slope Up:", ema200_slope_up)
        print("Slope Down:", ema200_slope_down)

    if (
        instrument_type == "FOREX"
        and forex_buy_score >= 4
        and ema_distance_percent > min_ema_distance_percent
        and price_change_percent > min_price_momentum_percent
    ):
        return "BUY"

    if (
        instrument_type == "FOREX"
        and forex_sell_score >= 4
        and ema_distance_percent > min_ema_distance_percent
        and price_change_percent > min_price_momentum_percent
    ):
        return "SELL"

    if (
        last_ema20 > last_ema50 > last_ema200
        and current_adx > adx_threshold
        and current_rsi > rsi_buy_threshold
        and buy_slope_ok
        and ema20_rising
        and ema_distance_percent > min_ema_distance_percent
        and price_change_percent > min_price_momentum_percent
        and trend_score >= min_trend_score
    ):
        return "BUY"

    elif (
        last_ema20 < last_ema50 < last_ema200
        and current_adx > adx_threshold
        and current_rsi < rsi_sell_threshold
        and sell_slope_ok
        and ema20_falling
        and ema_distance_percent > min_ema_distance_percent
        and price_change_percent > min_price_momentum_percent
        and bear_score >= min_trend_score
    ):
        return "SELL"

    # Avoid trading extremely quiet markets.
    if volatility_percent < min_volatility_percent:
        return "SIDEWAYS"

    # Reject weak momentum environments
    if price_change_percent < min_price_momentum_percent:
        return "SIDEWAYS"

    return "SIDEWAYS"


if __name__ == "__main__":
    print("trend_analyzer.py is a module.")
    print("Run from the project root with:")
    print("python test_trend.py")