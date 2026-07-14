"""Regime-aware strategy selection for AI_SCALPER.

The selector intentionally prefers no trade over a weak setup.  It evaluates
TREND_FOLLOWING for diagnostics, but never selects it because Phase 5F keeps
that strategy force-blocked.
"""

from __future__ import annotations

import math

import pandas as pd
from ta.momentum import RSIIndicator
from ta.trend import ADXIndicator, EMAIndicator
from ta.volatility import AverageTrueRange, BollingerBands

from market_regime_filter import (
    REGIME_BREAKOUT,
    REGIME_RANGE,
    REGIME_TREND,
    detect_market_regime,
)
from market_data_quality import keep_completed_candles
from strategy.strategy_profiles import get_strategy_profile, normalize_symbol
from strategy.trend_analyzer import analyze_trend


MIN_REQUIRED_ROWS = 250
FORCE_BLOCKED_STRATEGIES = frozenset({"TREND_FOLLOWING"})


def _normalize_ohlc(df: pd.DataFrame) -> pd.DataFrame:
    if not isinstance(df, pd.DataFrame):
        raise TypeError("strategy input must be a pandas DataFrame")

    df, _ = keep_completed_candles(df)
    required = ("Open", "High", "Low", "Close")
    missing = [column for column in required if column not in df.columns]
    if missing:
        raise ValueError(f"missing OHLC columns: {missing}")

    data = df.loc[:, required].copy()
    for column in required:
        data[column] = pd.to_numeric(data[column], errors="coerce")

    data = data.replace([float("inf"), float("-inf")], pd.NA).dropna()
    if len(data) < MIN_REQUIRED_ROWS:
        raise ValueError(
            f"not enough clean candles: {len(data)}/{MIN_REQUIRED_ROWS}"
        )
    if (data[["Open", "High", "Low", "Close"]] <= 0).any().any():
        raise ValueError("OHLC values must be positive")
    if ((data["High"] < data[["Open", "Close"]].max(axis=1)) | (
        data["Low"] > data[["Open", "Close"]].min(axis=1)
    )).any():
        raise ValueError("invalid OHLC price ordering")

    return data.reset_index(drop=True)


def get_market_context(df: pd.DataFrame, symbol: str = "UNKNOWN") -> dict:
    data = _normalize_ohlc(df)
    symbol = normalize_symbol(symbol)
    profile = get_strategy_profile(symbol)

    close = data["Close"]
    high = data["High"]
    low = data["Low"]
    open_price = data["Open"]

    ema20 = EMAIndicator(close=close, window=20).ema_indicator()
    ema50 = EMAIndicator(close=close, window=50).ema_indicator()
    ema200 = EMAIndicator(close=close, window=200).ema_indicator()
    adx = ADXIndicator(high=high, low=low, close=close, window=14).adx()
    rsi = RSIIndicator(close=close, window=14).rsi()
    atr = AverageTrueRange(high=high, low=low, close=close, window=14).average_true_range()
    bollinger = BollingerBands(close=close, window=20, window_dev=2)

    current_price = float(close.iloc[-1])
    current_atr = float(atr.iloc[-1])
    atr_median = float(atr.tail(100).median())
    atr_ratio = current_atr / atr_median if atr_median > 0 else 0.0

    candle_range = float(high.iloc[-1] - low.iloc[-1])
    candle_body = abs(float(close.iloc[-1] - open_price.iloc[-1]))
    candle_body_ratio = candle_body / candle_range if candle_range > 0 else 0.0

    regime_result = detect_market_regime(data, symbol=symbol)
    recent_high = float(high.iloc[-21:-1].max())
    recent_low = float(low.iloc[-21:-1].min())
    volatility_percent = (
        (float(high.tail(20).max()) - float(low.tail(20).min()))
        / current_price
        * 100.0
    )

    values = {
        "price": current_price,
        "open": float(open_price.iloc[-1]),
        "high": float(high.iloc[-1]),
        "low": float(low.iloc[-1]),
        "ema20": float(ema20.iloc[-1]),
        "ema50": float(ema50.iloc[-1]),
        "ema200": float(ema200.iloc[-1]),
        "ema50_slope": float(ema50.iloc[-1] - ema50.iloc[-6]),
        "adx": float(adx.iloc[-1]),
        "rsi": float(rsi.iloc[-1]),
        "atr": current_atr,
        "atr_ratio": float(atr_ratio),
        "bollinger_upper": float(bollinger.bollinger_hband().iloc[-1]),
        "bollinger_lower": float(bollinger.bollinger_lband().iloc[-1]),
        "recent_high": recent_high,
        "recent_low": recent_low,
        "candle_body_ratio": float(candle_body_ratio),
        "volatility_percent": float(volatility_percent),
        "ema_trend_up": bool(ema20.iloc[-1] > ema50.iloc[-1] > ema200.iloc[-1]),
        "ema_trend_down": bool(ema20.iloc[-1] < ema50.iloc[-1] < ema200.iloc[-1]),
        "market_regime": str(regime_result.get("regime", "NO_TRADE")),
        "regime_confidence": int(regime_result.get("confidence", 0) or 0),
        "regime_trade_allowed": bool(regime_result.get("trade_allowed", False)),
        "regime_reason": str(regime_result.get("reason", "")),
        "symbol": symbol,
        "asset_class": profile.asset_class,
    }

    numeric_keys = (
        "price",
        "ema20",
        "ema50",
        "ema200",
        "adx",
        "rsi",
        "atr",
        "atr_ratio",
    )
    if not all(math.isfinite(values[key]) for key in numeric_keys):
        raise ValueError("latest strategy indicators are not finite")

    return values


def _result(
    strategy: str,
    signal: str,
    score: int,
    reasons: list[str],
    eligible: bool,
) -> dict:
    return {
        "strategy": strategy,
        "signal": signal,
        "score": int(score),
        "reasons": reasons,
        "eligible": bool(eligible),
    }


def trend_following_strategy(
    df: pd.DataFrame,
    context: dict,
    symbol: str = "UNKNOWN",
) -> dict:
    signal = analyze_trend(df, symbol=symbol)
    reasons = ["diagnostic only; TREND_FOLLOWING remains force-blocked"]
    score = 0

    if signal in {"BUY", "SELL"}:
        score += 2
        reasons.append("trend analyzer produced a direction")
    if context["market_regime"] == REGIME_TREND:
        score += 2
        reasons.append("market regime is TREND")
    if context["adx"] >= 22:
        score += 1
        reasons.append("ADX confirms trend strength")

    return _result("TREND_FOLLOWING", signal, score, reasons, False)


def breakout_strategy(df: pd.DataFrame, context: dict, profile) -> dict:
    reasons: list[str] = []
    eligible = "BREAKOUT" in profile.allowed_strategies
    supported_regime = (
        context["regime_trade_allowed"]
        and context["market_regime"] in {REGIME_BREAKOUT, REGIME_TREND}
    )
    atr_quality = 0.70 <= context["atr_ratio"] <= profile.max_atr_ratio
    body_quality = context["candle_body_ratio"] >= 0.45
    adx_quality = context["adx"] >= profile.min_breakout_adx
    buffer_distance = profile.breakout_buffer_atr * context["atr"]

    buy_breakout = (
        context["price"] > context["recent_high"] + buffer_distance
        and context["price"] > context["ema50"]
        and context["price"] > context["open"]
    )
    sell_breakout = (
        context["price"] < context["recent_low"] - buffer_distance
        and context["price"] < context["ema50"]
        and context["price"] < context["open"]
    )

    signal = "SIDEWAYS"
    if eligible and supported_regime and atr_quality and body_quality and adx_quality:
        if buy_breakout:
            signal = "BUY"
        elif sell_breakout:
            signal = "SELL"

    if signal == "SIDEWAYS":
        if not eligible:
            reasons.append("BREAKOUT is disabled for this symbol profile")
        if not supported_regime:
            reasons.append("regime does not support breakout")
        if not atr_quality:
            reasons.append("ATR regime is too quiet or too extended")
        if not body_quality:
            reasons.append("breakout candle body is weak")
        if not adx_quality:
            reasons.append("ADX is below breakout threshold")
        if not buy_breakout and not sell_breakout:
            reasons.append("no buffered Donchian break")
        return _result("BREAKOUT", signal, 0, reasons, eligible)

    score = 2
    reasons.append("buffered 20-candle breakout confirmed")
    score += 1
    reasons.append(f"{context['market_regime']} regime supports breakout")
    score += 1
    reasons.append("ATR regime is stable")
    if context["adx"] >= profile.min_breakout_adx + 4:
        score += 1
        reasons.append("ADX has strong confirmation")
    if context["candle_body_ratio"] >= 0.60:
        score += 1
        reasons.append("breakout candle closes with a strong body")

    return _result("BREAKOUT", signal, score, reasons, eligible)


def mean_reversion_strategy(df: pd.DataFrame, context: dict, profile) -> dict:
    reasons: list[str] = []
    eligible = "MEAN_REVERSION" in profile.allowed_strategies
    range_regime = (
        context["regime_trade_allowed"]
        and context["market_regime"] == REGIME_RANGE
        and context["adx"] <= profile.max_mean_reversion_adx
    )
    tolerance = context["atr"] * 0.10
    buy_setup = (
        context["rsi"] <= 30
        and context["price"] <= context["bollinger_lower"] + tolerance
    )
    sell_setup = (
        context["rsi"] >= 70
        and context["price"] >= context["bollinger_upper"] - tolerance
    )

    signal = "SIDEWAYS"
    if eligible and range_regime:
        if buy_setup:
            signal = "BUY"
        elif sell_setup:
            signal = "SELL"

    if signal == "SIDEWAYS":
        if not eligible:
            reasons.append("MEAN_REVERSION is disabled for this symbol profile")
        if not range_regime:
            reasons.append("mean reversion requires a confirmed RANGE regime")
        if not buy_setup and not sell_setup:
            reasons.append("RSI and Bollinger extreme are not aligned")
        return _result("MEAN_REVERSION", signal, 0, reasons, eligible)

    reasons.extend(
        [
            "RSI extreme confirmed",
            "price reached the Bollinger edge",
            "low-ADX RANGE regime confirmed",
        ]
    )
    return _result("MEAN_REVERSION", signal, 6, reasons, eligible)


def momentum_pullback_strategy(df: pd.DataFrame, context: dict, profile) -> dict:
    reasons: list[str] = []
    eligible = "MOMENTUM_PULLBACK" in profile.allowed_strategies
    trend_regime = (
        context["regime_trade_allowed"]
        and context["market_regime"] == REGIME_TREND
    )
    atr_quality = 0.70 <= context["atr_ratio"] <= profile.max_atr_ratio
    adx_quality = context["adx"] >= profile.min_momentum_adx
    touch_distance = profile.pullback_touch_atr * context["atr"]

    buy_setup = (
        context["ema20"] > context["ema50"]
        and context["ema50_slope"] > 0
        and context["low"] <= context["ema20"] + touch_distance
        and context["price"] > context["ema20"]
        and context["price"] > context["open"]
        and 48 <= context["rsi"] <= 68
    )
    sell_setup = (
        context["ema20"] < context["ema50"]
        and context["ema50_slope"] < 0
        and context["high"] >= context["ema20"] - touch_distance
        and context["price"] < context["ema20"]
        and context["price"] < context["open"]
        and 32 <= context["rsi"] <= 52
    )

    signal = "SIDEWAYS"
    if eligible and trend_regime and atr_quality and adx_quality:
        if buy_setup:
            signal = "BUY"
        elif sell_setup:
            signal = "SELL"

    if signal == "SIDEWAYS":
        if not eligible:
            reasons.append("MOMENTUM_PULLBACK is disabled for this symbol profile")
        if not trend_regime:
            reasons.append("pullback requires a confirmed TREND regime")
        if not atr_quality:
            reasons.append("ATR regime is too quiet or too extended")
        if not adx_quality:
            reasons.append("ADX is below momentum threshold")
        if not buy_setup and not sell_setup:
            reasons.append("EMA touch/rejection and RSI are not aligned")
        return _result("MOMENTUM_PULLBACK", signal, 0, reasons, eligible)

    score = 5
    reasons.extend(
        [
            "EMA20 pullback rejection confirmed",
            "EMA50 slope confirms direction",
            "TREND regime and ADX confirm continuation",
            "ATR regime is stable",
        ]
    )
    if context["candle_body_ratio"] >= 0.55:
        score += 1
        reasons.append("rejection candle body is strong")

    return _result("MOMENTUM_PULLBACK", signal, score, reasons, eligible)


def evaluate_strategies(
    df: pd.DataFrame,
    symbol: str = "UNKNOWN",
) -> tuple[list[dict], dict]:
    symbol = normalize_symbol(symbol)
    context = get_market_context(df, symbol=symbol)
    profile = get_strategy_profile(symbol)

    strategy_results = [
        trend_following_strategy(df, context, symbol=symbol),
        breakout_strategy(df, context, profile),
        mean_reversion_strategy(df, context, profile),
        momentum_pullback_strategy(df, context, profile),
    ]

    return strategy_results, context


def _no_strategy_result(reason: str, context: dict | None = None) -> dict:
    context = context or {}
    return {
        "signal": "SIDEWAYS",
        "strategy": "NO_STRATEGY",
        "score": 0,
        "market_regime": context.get("market_regime", "NO_TRADE"),
        "volatility_percent": context.get("volatility_percent", 0.0),
        "all_strategies": context.get("all_strategies", []),
        "reasons": [reason],
    }


def select_best_strategy(df: pd.DataFrame, symbol: str = "UNKNOWN") -> dict:
    symbol = normalize_symbol(symbol)
    profile = get_strategy_profile(symbol)

    try:
        strategy_results, context = evaluate_strategies(df, symbol=symbol)
    except (TypeError, ValueError, KeyError, IndexError) as exc:
        return _no_strategy_result(f"strategy input rejected: {exc}")

    valid_results = [
        item
        for item in strategy_results
        if item["signal"] in {"BUY", "SELL"}
        and item.get("eligible", False)
        and item["strategy"] not in FORCE_BLOCKED_STRATEGIES
        and item["strategy"] in profile.allowed_strategies
    ]

    if not valid_results:
        context["all_strategies"] = strategy_results
        return _no_strategy_result(
            "no allowed strategy passed direction, regime, and quality filters",
            context,
        )

    priority = {
        "BREAKOUT": 1,
        "MEAN_REVERSION": 1,
        "MOMENTUM_PULLBACK": 1,
    }
    priority[profile.preferred_strategy] = 2
    best_result = max(
        valid_results,
        key=lambda item: (
            int(item["score"]),
            priority.get(item["strategy"], 0),
            int(context.get("regime_confidence", 0)),
        ),
    )

    if best_result["score"] < profile.min_strategy_score:
        return {
            "signal": "SIDEWAYS",
            "strategy": "LOW_SCORE",
            "score": best_result["score"],
            "market_regime": context["market_regime"],
            "volatility_percent": context["volatility_percent"],
            "all_strategies": strategy_results,
            "reasons": [
                f"best strategy score {best_result['score']} below "
                f"{symbol} minimum {profile.min_strategy_score}"
            ],
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
