"""
market_regime_filter.py

Phase 4C - Winrate Refinement Engine

Purpose:
- Detect market regime before AI_SCALPER allows a trade.
- Reduce weak entries in choppy/sideways/low-volatility markets.
- Improve winrate without loosening risk or live guard.

Regime labels:
- TREND
- RANGE
- BREAKOUT
- CHOPPY
- LOW_VOLATILITY
- VOLATILITY_SPIKE
- NO_TRADE

This module uses only pandas/numpy, no TA-Lib required.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, Tuple

import numpy as np
import pandas as pd

from market_data_quality import keep_completed_candles


# ============================================================
# CONFIG
# ============================================================

REGIME_TREND = "TREND"
REGIME_RANGE = "RANGE"
REGIME_BREAKOUT = "BREAKOUT"
REGIME_CHOPPY = "CHOPPY"
REGIME_LOW_VOLATILITY = "LOW_VOLATILITY"
REGIME_VOLATILITY_SPIKE = "VOLATILITY_SPIKE"
REGIME_NO_TRADE = "NO_TRADE"

DEFAULT_ATR_PERIOD = 14
DEFAULT_ADX_PERIOD = 14
DEFAULT_EMA_FAST = 20
DEFAULT_EMA_SLOW = 50
DEFAULT_BB_PERIOD = 20
DEFAULT_BB_STD = 2.0

MIN_ROWS_REQUIRED = 80

# Regime thresholds.
ADX_CHOPPY_MAX = 18.0
ADX_TREND_MIN = 22.0
ADX_STRONG_TREND_MIN = 28.0

EMA_DISTANCE_TREND_MIN_PERCENT = 0.025
EMA_SLOPE_MIN_PERCENT = 0.003

ATR_LOW_VOL_RATIO = 0.70
ATR_SPIKE_RATIO = 2.20

BB_BREAKOUT_QUANTILE = 0.75
BB_CHOPPY_RATIO = 0.80

CANDLE_BODY_MIN_RATIO = 0.30
CANDLE_WICK_SPIKE_MAX_RATIO = 3.0


# Strategy compatibility.
STRATEGY_ALLOWED_REGIMES = {
    "BREAKOUT": {REGIME_BREAKOUT, REGIME_TREND},
    "MEAN_REVERSION": {REGIME_RANGE},
    "MOMENTUM_PULLBACK": {REGIME_TREND},
    "TREND_FOLLOWING": set(),  # still blocked by Phase 4B
    "NO_STRATEGY": set(),
    "UNKNOWN": set(),
}


@dataclass
class RegimeResult:
    symbol: str
    regime: str
    trade_allowed: bool
    confidence: int
    reason: str

    adx: float
    atr: float
    atr_median: float
    atr_ratio: float
    ema_fast: float
    ema_slow: float
    ema_distance_percent: float
    ema_slope_percent: float
    bb_width_percent: float
    bb_width_median: float
    candle_body_ratio: float
    wick_body_ratio: float

    flags: Dict[str, bool]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================
# DATA NORMALIZATION
# ============================================================

def normalize_ohlcv(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize expected columns:
    Datetime, Open, High, Low, Close, Volume

    Supports common lowercase/uppercase variants.
    """
    if df is None or df.empty:
        return pd.DataFrame()

    data = df.copy()

    rename_map = {}
    for col in data.columns:
        lower = str(col).strip().lower()
        if lower in {"datetime", "date", "time", "timestamp"}:
            rename_map[col] = "Datetime"
        elif lower == "open":
            rename_map[col] = "Open"
        elif lower == "high":
            rename_map[col] = "High"
        elif lower == "low":
            rename_map[col] = "Low"
        elif lower == "close":
            rename_map[col] = "Close"
        elif lower in {"volume", "tick_volume", "tickvolume"}:
            rename_map[col] = "Volume"

    data = data.rename(columns=rename_map)

    required = ["Open", "High", "Low", "Close"]
    missing = [col for col in required if col not in data.columns]
    if missing:
        raise ValueError(f"Missing required OHLC columns: {missing}")

    if "Datetime" in data.columns:
        data["Datetime"] = pd.to_datetime(data["Datetime"], errors="coerce", utc=True)
        data = data.dropna(subset=["Datetime"]).sort_values("Datetime")

    for col in required:
        data[col] = pd.to_numeric(data[col], errors="coerce")

    if "Volume" not in data.columns:
        data["Volume"] = 0

    data["Volume"] = pd.to_numeric(data["Volume"], errors="coerce").fillna(0)
    data = data.dropna(subset=required)

    return data.reset_index(drop=True)


# ============================================================
# INDICATORS
# ============================================================

def calculate_atr(df: pd.DataFrame, period: int = DEFAULT_ATR_PERIOD) -> pd.Series:
    high = df["High"]
    low = df["Low"]
    close = df["Close"]

    prev_close = close.shift(1)

    tr = pd.concat(
        [
            high - low,
            (high - prev_close).abs(),
            (low - prev_close).abs(),
        ],
        axis=1,
    ).max(axis=1)

    return tr.rolling(period).mean()


def calculate_adx(df: pd.DataFrame, period: int = DEFAULT_ADX_PERIOD) -> pd.Series:
    high = df["High"]
    low = df["Low"]
    close = df["Close"]

    plus_dm = high.diff()
    minus_dm = -low.diff()

    plus_dm = plus_dm.where((plus_dm > minus_dm) & (plus_dm > 0), 0.0)
    minus_dm = minus_dm.where((minus_dm > plus_dm) & (minus_dm > 0), 0.0)

    prev_close = close.shift(1)
    tr = pd.concat(
        [
            high - low,
            (high - prev_close).abs(),
            (low - prev_close).abs(),
        ],
        axis=1,
    ).max(axis=1)

    atr = tr.rolling(period).mean()

    plus_di = 100 * (plus_dm.rolling(period).mean() / atr.replace(0, np.nan))
    minus_di = 100 * (minus_dm.rolling(period).mean() / atr.replace(0, np.nan))

    dx = 100 * (plus_di - minus_di).abs() / (plus_di + minus_di).replace(0, np.nan)
    adx = dx.rolling(period).mean()

    return adx.fillna(0)


def calculate_bollinger_width(
    df: pd.DataFrame,
    period: int = DEFAULT_BB_PERIOD,
    std_mult: float = DEFAULT_BB_STD,
) -> pd.Series:
    close = df["Close"]
    ma = close.rolling(period).mean()
    std = close.rolling(period).std()

    upper = ma + std_mult * std
    lower = ma - std_mult * std

    width = (upper - lower) / close.replace(0, np.nan) * 100
    return width.fillna(0)


def calculate_ema(series: pd.Series, period: int) -> pd.Series:
    return series.ewm(span=period, adjust=False).mean()


def calculate_candle_quality(df: pd.DataFrame) -> Tuple[float, float]:
    # Incomplete candles are removed before this function is called, so start
    # with the latest completed bar and only walk backward across doji bars.
    if df is None or df.empty:
        return 0.0, 999.0

    lookback = min(6, len(df))

    selected = None
    for i in range(1, lookback + 1):
        candle = df.iloc[-i]

        candle_range = abs(float(candle["High"]) - float(candle["Low"]))
        body = abs(float(candle["Close"]) - float(candle["Open"]))

        if candle_range > 0:
            body_ratio = body / candle_range
            if body_ratio >= 0.10:
                selected = candle
                break

    # Fallback: use the latest completed candle if recent bars are flat/doji.
    if selected is None:
        selected = df.iloc[-1]

    candle_range = abs(float(selected["High"]) - float(selected["Low"]))
    body = abs(float(selected["Close"]) - float(selected["Open"]))

    if candle_range <= 0:
        body_ratio = 0.0
    else:
        body_ratio = body / candle_range

    if body <= 0:
        wick_body_ratio = CANDLE_WICK_SPIKE_MAX_RATIO
    else:
        upper_wick = float(selected["High"]) - max(float(selected["Open"]), float(selected["Close"]))
        lower_wick = min(float(selected["Open"]), float(selected["Close"])) - float(selected["Low"])
        wick_body_ratio = max(abs(upper_wick), abs(lower_wick)) / body

    return float(body_ratio), float(wick_body_ratio)


# ============================================================
# REGIME DETECTION
# ============================================================

def detect_market_regime(
    df: pd.DataFrame,
    symbol: str = "UNKNOWN",
    min_rows: int = MIN_ROWS_REQUIRED,
) -> Dict[str, Any]:
    """
    Main regime detector.

    Returns dict with:
    - regime
    - trade_allowed
    - confidence
    - reason
    - indicator values
    - flags
    """
    symbol = str(symbol or "UNKNOWN").upper()

    try:
        data = normalize_ohlcv(df)
        data, _ = keep_completed_candles(data)
    except Exception as exc:
        return RegimeResult(
            symbol=symbol,
            regime=REGIME_NO_TRADE,
            trade_allowed=False,
            confidence=0,
            reason=f"Invalid OHLC data: {exc}",
            adx=0.0,
            atr=0.0,
            atr_median=0.0,
            atr_ratio=0.0,
            ema_fast=0.0,
            ema_slow=0.0,
            ema_distance_percent=0.0,
            ema_slope_percent=0.0,
            bb_width_percent=0.0,
            bb_width_median=0.0,
            candle_body_ratio=0.0,
            wick_body_ratio=0.0,
            flags={},
        ).to_dict()

    if len(data) < min_rows:
        return RegimeResult(
            symbol=symbol,
            regime=REGIME_NO_TRADE,
            trade_allowed=False,
            confidence=0,
            reason=f"Not enough candles for regime detection: {len(data)}/{min_rows}",
            adx=0.0,
            atr=0.0,
            atr_median=0.0,
            atr_ratio=0.0,
            ema_fast=0.0,
            ema_slow=0.0,
            ema_distance_percent=0.0,
            ema_slope_percent=0.0,
            bb_width_percent=0.0,
            bb_width_median=0.0,
            candle_body_ratio=0.0,
            wick_body_ratio=0.0,
            flags={},
        ).to_dict()

    close = data["Close"]

    atr_series = calculate_atr(data)
    adx_series = calculate_adx(data)
    bb_width_series = calculate_bollinger_width(data)

    ema_fast_series = calculate_ema(close, DEFAULT_EMA_FAST)
    ema_slow_series = calculate_ema(close, DEFAULT_EMA_SLOW)

    last_close = float(close.iloc[-1])
    atr_now = float(atr_series.iloc[-1]) if not pd.isna(atr_series.iloc[-1]) else 0.0
    atr_median = float(atr_series.rolling(200, min_periods=30).median().iloc[-1])
    if pd.isna(atr_median) or atr_median <= 0:
        atr_median = float(atr_series.dropna().median()) if not atr_series.dropna().empty else 0.0

    atr_ratio = atr_now / atr_median if atr_median > 0 else 0.0

    adx_now = float(adx_series.iloc[-1]) if not pd.isna(adx_series.iloc[-1]) else 0.0

    ema_fast = float(ema_fast_series.iloc[-1])
    ema_slow = float(ema_slow_series.iloc[-1])
    ema_distance_percent = abs(ema_fast - ema_slow) / last_close * 100 if last_close > 0 else 0.0

    ema_fast_prev = float(ema_fast_series.iloc[-6]) if len(ema_fast_series) >= 6 else ema_fast
    ema_slope_percent = abs(ema_fast - ema_fast_prev) / last_close * 100 if last_close > 0 else 0.0

    bb_width_now = float(bb_width_series.iloc[-1]) if not pd.isna(bb_width_series.iloc[-1]) else 0.0
    bb_width_median = float(bb_width_series.rolling(200, min_periods=30).median().iloc[-1])
    if pd.isna(bb_width_median) or bb_width_median <= 0:
        bb_width_median = float(bb_width_series.dropna().median()) if not bb_width_series.dropna().empty else 0.0

    bb_width_q75 = float(bb_width_series.rolling(200, min_periods=30).quantile(BB_BREAKOUT_QUANTILE).iloc[-1])
    if pd.isna(bb_width_q75) or bb_width_q75 <= 0:
        bb_width_q75 = float(bb_width_series.dropna().quantile(BB_BREAKOUT_QUANTILE)) if not bb_width_series.dropna().empty else 0.0

    candle_body_ratio, wick_body_ratio = calculate_candle_quality(data)

    flags = {
        "is_low_volatility": atr_ratio > 0 and atr_ratio < ATR_LOW_VOL_RATIO,
        "is_volatility_spike": atr_ratio > ATR_SPIKE_RATIO,
        "is_choppy_adx": adx_now < ADX_CHOPPY_MAX,
        "is_trending_adx": adx_now >= ADX_TREND_MIN,
        "is_strong_trend_adx": adx_now >= ADX_STRONG_TREND_MIN,
        "is_ema_separated": ema_distance_percent >= EMA_DISTANCE_TREND_MIN_PERCENT,
        "is_ema_sloping": ema_slope_percent >= EMA_SLOPE_MIN_PERCENT,
        "is_bb_expanding": bb_width_q75 > 0 and bb_width_now >= bb_width_q75,
        "is_bb_compressed": bb_width_median > 0 and bb_width_now < bb_width_median * BB_CHOPPY_RATIO,
        "is_weak_candle": candle_body_ratio < CANDLE_BODY_MIN_RATIO,
        "is_wick_spike": wick_body_ratio > CANDLE_WICK_SPIKE_MAX_RATIO,
    }

    confidence = 0
    reasons = []

    # Hard no-trade conditions first.
    if flags["is_volatility_spike"] and flags["is_wick_spike"]:
        regime = REGIME_VOLATILITY_SPIKE
        trade_allowed = False
        confidence = 1
        reasons.append(
            f"Volatility spike detected: ATR ratio {atr_ratio:.2f}, wick/body {wick_body_ratio:.2f}."
        )

    elif flags["is_low_volatility"]:
        regime = REGIME_LOW_VOLATILITY
        trade_allowed = False
        confidence = 1
        reasons.append(f"Low volatility: ATR ratio {atr_ratio:.2f} below {ATR_LOW_VOL_RATIO:.2f}.")

    elif flags["is_choppy_adx"] and flags["is_bb_compressed"]:
        regime = REGIME_CHOPPY
        trade_allowed = False
        confidence = 2
        reasons.append(
            f"Choppy market: ADX {adx_now:.2f} below {ADX_CHOPPY_MAX}, BB width compressed."
        )

    elif flags["is_trending_adx"] and flags["is_ema_separated"] and flags["is_ema_sloping"]:
        regime = REGIME_TREND
        trade_allowed = True
        confidence = 4
        reasons.append(
            f"Trend regime: ADX {adx_now:.2f}, EMA distance {ema_distance_percent:.4f}%, slope {ema_slope_percent:.4f}%."
        )
        if flags["is_strong_trend_adx"]:
            confidence += 1
            reasons.append("Strong trend ADX boost.")

    elif flags["is_bb_expanding"] and adx_now >= ADX_CHOPPY_MAX:
        regime = REGIME_BREAKOUT
        trade_allowed = True
        confidence = 4
        reasons.append(
            f"Breakout regime: BB width {bb_width_now:.4f}% above q75 {bb_width_q75:.4f}%."
        )

    elif adx_now < ADX_TREND_MIN and not flags["is_bb_expanding"]:
        regime = REGIME_RANGE
        trade_allowed = True
        confidence = 3
        reasons.append(f"Range regime: ADX {adx_now:.2f}, no BB expansion.")

    else:
        regime = REGIME_NO_TRADE
        trade_allowed = False
        confidence = 1
        reasons.append("No clear regime alignment.")

    # Candle quality penalty.
    if flags["is_weak_candle"] and regime in {REGIME_TREND, REGIME_BREAKOUT}:
        confidence = max(1, confidence - 1)
        reasons.append(f"Weak candle body ratio {candle_body_ratio:.2f}; confidence reduced.")

    if flags["is_wick_spike"] and regime in {REGIME_TREND, REGIME_BREAKOUT}:
        confidence = max(1, confidence - 1)
        reasons.append(f"Large wick/body ratio {wick_body_ratio:.2f}; confidence reduced.")

    reason = " | ".join(reasons)

    return RegimeResult(
        symbol=symbol,
        regime=regime,
        trade_allowed=trade_allowed,
        confidence=int(confidence),
        reason=reason,
        adx=round(adx_now, 4),
        atr=round(atr_now, 8),
        atr_median=round(atr_median, 8),
        atr_ratio=round(atr_ratio, 4),
        ema_fast=round(ema_fast, 8),
        ema_slow=round(ema_slow, 8),
        ema_distance_percent=round(ema_distance_percent, 6),
        ema_slope_percent=round(ema_slope_percent, 6),
        bb_width_percent=round(bb_width_now, 6),
        bb_width_median=round(bb_width_median, 6),
        candle_body_ratio=round(candle_body_ratio, 4),
        wick_body_ratio=round(wick_body_ratio, 4),
        flags=flags,
    ).to_dict()


# ============================================================
# STRATEGY COMPATIBILITY GUARD
# ============================================================

def evaluate_strategy_regime_compatibility(
    strategy: str,
    regime_result: Dict[str, Any],
) -> Tuple[bool, Dict[str, Any]]:
    strategy = str(strategy or "UNKNOWN").upper()
    regime = str(regime_result.get("regime", REGIME_NO_TRADE)).upper()

    allowed_regimes = STRATEGY_ALLOWED_REGIMES.get(strategy, set())

    if not regime_result.get("trade_allowed", False):
        return False, {
            "status": "BLOCKED_BY_REGIME",
            "strategy": strategy,
            "regime": regime,
            "allowed_regimes": sorted(allowed_regimes),
            "reason": f"Market regime {regime} is not tradeable: {regime_result.get('reason', '')}",
        }

    if regime not in allowed_regimes:
        return False, {
            "status": "STRATEGY_REGIME_MISMATCH",
            "strategy": strategy,
            "regime": regime,
            "allowed_regimes": sorted(allowed_regimes),
            "reason": (
                f"Strategy {strategy} is not compatible with market regime {regime}. "
                f"Allowed regimes: {sorted(allowed_regimes)}."
            ),
        }

    return True, {
        "status": "PASSED",
        "strategy": strategy,
        "regime": regime,
        "allowed_regimes": sorted(allowed_regimes),
        "reason": f"Strategy {strategy} is compatible with market regime {regime}.",
    }


def build_regime_guard(
    df: pd.DataFrame,
    symbol: str,
    strategy: str,
) -> Dict[str, Any]:
    regime_result = detect_market_regime(df, symbol=symbol)
    compatible, compatibility = evaluate_strategy_regime_compatibility(strategy, regime_result)

    return {
        "enabled": True,
        "passed": bool(compatible),
        "symbol": str(symbol or "UNKNOWN").upper(),
        "strategy": str(strategy or "UNKNOWN").upper(),
        "regime": regime_result.get("regime", REGIME_NO_TRADE),
        "confidence": regime_result.get("confidence", 0),
        "trade_allowed": regime_result.get("trade_allowed", False),
        "regime_result": regime_result,
        "compatibility": compatibility,
        "reason": compatibility.get("reason", regime_result.get("reason", "")),
    }


# ============================================================
# FILE TEST / CLI
# ============================================================

def load_symbol_data(symbol: str, data_dir: str = "data") -> Optional[pd.DataFrame]:
    symbol = str(symbol or "").lower()
    candidates = [
        f"{data_dir}/{symbol}.csv",
        f"{data_dir}/{symbol.upper()}.csv",
        f"{data_dir}/{symbol.lower()}=x.csv",
    ]

    for path in candidates:
        try:
            df = pd.read_csv(path)
            if not df.empty:
                return df
        except FileNotFoundError:
            continue
        except Exception as exc:
            print(f"Failed reading {path}: {exc}")

    return None


def main() -> None:
    symbols = ["EURUSD", "GBPUSD", "NZDUSD", "BTCUSD", "XAUUSD"]

    print("=" * 72)
    print("AI_SCALPER MARKET REGIME FILTER TEST")
    print("=" * 72)

    for symbol in symbols:
        df = load_symbol_data(symbol)
        if df is None or df.empty:
            print(f"{symbol:<8} | NO_DATA")
            continue

        result = detect_market_regime(df, symbol=symbol)
        print(
            f"{symbol:<8} | "
            f"Regime: {result['regime']:<16} | "
            f"Allowed: {str(result['trade_allowed']):<5} | "
            f"Conf: {result['confidence']} | "
            f"ADX: {result['adx']} | "
            f"ATR ratio: {result['atr_ratio']} | "
            f"Reason: {result['reason']}"
        )


if __name__ == "__main__":
    main()
