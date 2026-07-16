"""Cost-aware chronological validation for AI_SCALPER strategies.

This validator is deliberately stricter than the legacy next-candle proxy:
signals enter on the next candle open, positions cannot overlap, ambiguous
SL/TP candles resolve to the stop, and estimated round-trip costs are deducted.
Without an externally archived immutable snapshot contract, the final 20
percent is a moving diagnostic tail only and cannot satisfy any readiness gate.
A genuinely future broker-grade holdout is still required.

The report is diagnostic only and can never unlock live trading.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import pandas as pd
from ta.momentum import RSIIndicator
from ta.trend import ADXIndicator, EMAIndicator
from ta.volatility import AverageTrueRange, BollingerBands

from data_source_policy import YFINANCE_TICKERS, get_data_source_metadata
from live_runtime.contracts import DecisionSnapshot
from live_runtime.decision_core import (
    DecisionProvenance,
    FirstEligibleQuote,
    build_decision_snapshot,
    evaluate_decision_core,
)
from market_data_quality import keep_completed_candles
from strategy.strategy_profiles import get_strategy_profile, normalize_symbol


WARMUP_BARS = 250
MIN_DEVELOPMENT_TRADES_LIVE_REVIEW = 60
MIN_ROLLING_TRADES_LIVE_REVIEW = 15
MIN_PROFITABLE_SEGMENTS_LIVE_REVIEW = 2
MIN_DEVELOPMENT_PROFIT_FACTOR_LIVE_REVIEW = 1.20
MIN_ROLLING_PROFIT_FACTOR_LIVE_REVIEW = 1.15
MAX_DRAWDOWN_PERCENT_LIVE_REVIEW = 8.0
VALIDATION_SCHEMA_VERSION = "2.2"
STRATEGY_RULE_CONTRACT_VERSION = (
    "2026-07-15-structured-score-bounded-pullback-direction-choppy-v2"
)
INDICATOR_CONTRACT_VERSION = (
    "ta-atr-adx-bollinger-latest-finalized-candle-choppy-v2"
)
REPLAY_EXECUTION_CONTRACT_VERSION = "next-open-stop-first-cost-aware-v1"

MIN_DEVELOPMENT_TRADES_WATCH = 30
MIN_ROLLING_TRADES_WATCH = 8
MIN_DEVELOPMENT_PROFIT_FACTOR_WATCH = 1.10
MIN_ROLLING_PROFIT_FACTOR_WATCH = 1.05
ROLLING_TEST_BARS = 256
ROLLING_MIN_INITIAL_TRAIN_BARS = 768
ROLLING_MAX_FOLDS = 5
UNFROZEN_TAIL_ROLE = "DYNAMIC_TAIL_DIAGNOSTIC_NOT_FROZEN_NOT_GATE_EVIDENCE"
CALLER_PREFIX_MATCHED_TAIL_ROLE = (
    "CALLER_PREFIX_MATCHED_TAIL_REPORT_ONLY_NOT_TRUSTED_ARCHIVE"
)
VALIDATION_SNAPSHOT_CONTRACT_VERSION = "EXTERNAL_IMMUTABLE_ARCHIVE_REQUIRED_V1"


def normalize_ohlcv(df: pd.DataFrame) -> pd.DataFrame:
    if not isinstance(df, pd.DataFrame):
        raise TypeError("replay input must be a pandas DataFrame")

    df, _ = keep_completed_candles(df)
    required = ("Open", "High", "Low", "Close")
    missing = [column for column in required if column not in df.columns]
    if missing:
        raise ValueError(f"missing OHLC columns: {missing}")

    columns = []
    if "Datetime" in df.columns:
        columns.append("Datetime")
    columns.extend(required)
    if "Volume" in df.columns:
        columns.append("Volume")

    data = df.loc[:, columns].copy()
    if "Datetime" in data.columns:
        data["Datetime"] = pd.to_datetime(
            data["Datetime"],
            errors="coerce",
            utc=True,
        )
        data = data.dropna(subset=["Datetime"])
        if not data["Datetime"].is_monotonic_increasing:
            raise ValueError("Datetime must be chronological")
        if data["Datetime"].duplicated().any():
            raise ValueError("Datetime must not contain duplicate candles")
    for column in required:
        data[column] = pd.to_numeric(data[column], errors="coerce")
    if "Volume" in data.columns:
        data["Volume"] = pd.to_numeric(data["Volume"], errors="coerce")
    data = data.replace([float("inf"), float("-inf")], pd.NA)
    data = data.dropna(subset=list(required)).reset_index(drop=True)

    if len(data) < WARMUP_BARS + 10:
        raise ValueError(f"not enough clean candles: {len(data)}/{WARMUP_BARS + 10}")
    if (data.loc[:, required] <= 0).any().any():
        raise ValueError("OHLC values must be positive")
    if ((data["High"] < data[["Open", "Close"]].max(axis=1)) | (
        data["Low"] > data[["Open", "Close"]].min(axis=1)
    )).any():
        raise ValueError("invalid OHLC price ordering")

    return data


def add_indicators(df: pd.DataFrame) -> pd.DataFrame:
    data = normalize_ohlcv(df)
    close = data["Close"]
    high = data["High"]
    low = data["Low"]

    data["ema20"] = EMAIndicator(close=close, window=20).ema_indicator()
    data["ema50"] = EMAIndicator(close=close, window=50).ema_indicator()
    data["ema200"] = EMAIndicator(close=close, window=200).ema_indicator()
    data["adx"] = ADXIndicator(high=high, low=low, close=close, window=14).adx()
    data["rsi"] = RSIIndicator(close=close, window=14).rsi()
    data["atr"] = AverageTrueRange(
        high=high,
        low=low,
        close=close,
        window=14,
    ).average_true_range()

    bollinger = BollingerBands(close=close, window=20, window_dev=2)
    data["bb_upper"] = bollinger.bollinger_hband()
    data["bb_lower"] = bollinger.bollinger_lband()
    data["bb_width_percent"] = (
        (data["bb_upper"] - data["bb_lower"]) / close * 100.0
    )
    data["bb_width_median"] = data["bb_width_percent"].rolling(
        200,
        min_periods=30,
    ).median()
    data["bb_width_q75"] = data["bb_width_percent"].rolling(
        200,
        min_periods=30,
    ).quantile(0.75)

    data["atr_median"] = data["atr"].rolling(200, min_periods=30).median()
    data["atr_ratio"] = data["atr"] / data["atr_median"]
    data["ema_distance_percent"] = (
        (data["ema20"] - data["ema50"]).abs() / close * 100.0
    )
    data["ema_slope_percent"] = (
        (data["ema20"] - data["ema20"].shift(5)).abs() / close * 100.0
    )
    data["ema_slope_signed_percent"] = (
        (data["ema20"] - data["ema20"].shift(5)) / close * 100.0
    )
    data["ema50_slope"] = data["ema50"] - data["ema50"].shift(5)
    data["recent_high"] = high.shift(1).rolling(20).max()
    data["recent_low"] = low.shift(1).rolling(20).min()

    candle_range = (high - low).replace(0, np.nan)
    data["body_ratio"] = (close - data["Open"]).abs() / candle_range
    upper_wick = high - data[["Open", "Close"]].max(axis=1)
    lower_wick = data[["Open", "Close"]].min(axis=1) - low
    candle_body = (close - data["Open"]).abs().replace(0, np.nan)
    data["wick_body_ratio"] = pd.concat(
        [upper_wick.abs(), lower_wick.abs()], axis=1
    ).max(axis=1) / candle_body

    data["bb_expanding"] = data["bb_width_percent"] >= data["bb_width_q75"]
    data["low_volatility"] = data["atr_ratio"] < 0.70
    data["volatility_spike"] = (
        (data["atr_ratio"] > 2.20) & (data["wick_body_ratio"] > 3.0)
    )
    data["choppy_regime"] = (
        (data["adx"] < 18.0)
        & (data["bb_width_median"] > 0)
        & (data["bb_width_percent"] < data["bb_width_median"] * 0.80)
        & ~data["low_volatility"]
        & ~data["volatility_spike"]
    )
    up_direction = (
        (data["ema20"] > data["ema50"])
        & (data["ema_slope_signed_percent"] >= 0.003)
    )
    down_direction = (
        (data["ema20"] < data["ema50"])
        & (data["ema_slope_signed_percent"] <= -0.003)
    )
    data["regime_direction"] = np.select(
        [up_direction, down_direction],
        ["UP", "DOWN"],
        default="NEUTRAL",
    )
    weak_candle = data["body_ratio"] < 0.30
    wick_spike = data["wick_body_ratio"] > 3.0
    trend_confidence = (
        4
        + (data["adx"] >= 28.0).astype("int8")
        - weak_candle.astype("int8")
        - wick_spike.astype("int8")
    )
    breakout_confidence = (
        4 - weak_candle.astype("int8") - wick_spike.astype("int8")
    )
    trend_base = (
        (data["adx"] >= 22.0)
        & (data["ema_distance_percent"] >= 0.025)
        & (data["ema_slope_percent"] >= 0.003)
        & (data["regime_direction"] != "NEUTRAL")
        & ~data["low_volatility"]
        & ~data["volatility_spike"]
    )
    breakout_base = (
        data["bb_expanding"]
        & (data["adx"] >= 18.0)
        & ~data["low_volatility"]
        & ~data["volatility_spike"]
    )
    data["trend_regime"] = trend_base & (trend_confidence >= 3)
    data["breakout_regime"] = (
        ~trend_base & breakout_base & (breakout_confidence >= 3)
    )
    data["regime_confidence"] = np.select(
        [trend_base, breakout_base],
        [trend_confidence, breakout_confidence],
        default=0,
    )
    data["range_regime"] = (
        (data["adx"] < 22.0)
        & ~data["bb_expanding"]
        & ~data["choppy_regime"]
        & ~data["low_volatility"]
        & ~data["volatility_spike"]
    )

    return data


def generate_runtime_selector_signals(
    df: pd.DataFrame,
    symbol: str,
    start_index: int = WARMUP_BARS,
    end_index: int | None = None,
) -> pd.DataFrame:
    """Build an exact, deliberately slow selector oracle for parity audits.

    Each evaluated row calls the same ``evaluate_decision_core`` entry point
    used by the runtime snapshot builder on the candle prefix available at that
    moment.  This function is diagnostic-only and is not the default bulk
    replay path because its correctness-first implementation is O(n^2).
    """

    symbol = normalize_symbol(symbol)
    data = normalize_ohlcv(df)
    start = max(int(start_index), WARMUP_BARS)
    stop = len(data) if end_index is None else min(int(end_index), len(data))
    if stop < start:
        stop = start

    exact = pd.DataFrame(
        {
            "direction": pd.Series(0, index=data.index, dtype="int8"),
            "strategy": pd.Series(
                "NOT_EVALUATED",
                index=data.index,
                dtype="object",
            ),
            "score": pd.Series(0, index=data.index, dtype="int16"),
            "score_components": pd.Series(
                [None] * len(data),
                index=data.index,
                dtype="object",
            ),
        }
    )

    direction_map = {"BUY": 1, "SELL": -1}
    for index in range(start, stop):
        result = evaluate_decision_core(data.iloc[: index + 1], symbol=symbol)
        exact.at[index, "direction"] = direction_map.get(result.action, 0)
        exact.at[index, "strategy"] = result.strategy
        exact.at[index, "score"] = result.score
        exact.at[index, "score_components"] = result.score_components

    return exact


def build_replay_decision_snapshot(
    broker_bars: pd.DataFrame,
    symbol: str,
    signal_index: int,
    *,
    provenance: DecisionProvenance,
) -> DecisionSnapshot:
    """Adapt broker replay evidence to the shared pure decision core.

    The next bar must carry its first broker tick timestamp and bid/ask open.
    Legacy midpoint-only CSV data cannot mint a runtime-parity snapshot.
    """

    if not isinstance(broker_bars, pd.DataFrame):
        raise TypeError("broker_bars must be a pandas DataFrame")
    if type(signal_index) is not int:
        raise TypeError("signal_index must be an integer")
    if type(provenance) is not DecisionProvenance:
        raise TypeError("provenance must be DecisionProvenance")
    if signal_index < WARMUP_BARS - 1 or signal_index + 1 >= len(broker_bars):
        raise ValueError("signal_index lacks warmup or a next broker entry bar")
    required_entry_fields = {"bid_open", "ask_open", "first_time_msc"}
    if not required_entry_fields.issubset(broker_bars.columns):
        raise ValueError("broker replay requires first-tick bid/ask entry evidence")
    timestamp_columns = [
        column
        for column in ("Datetime", "open_time_utc")
        if column in broker_bars.columns
    ]
    if len(timestamp_columns) != 1:
        raise ValueError("broker replay requires one UTC bar timestamp column")

    entry_row = broker_bars.iloc[signal_index + 1]
    entry_bar_open = pd.Timestamp(entry_row[timestamp_columns[0]])
    if entry_bar_open.tzinfo is None or entry_bar_open.utcoffset() is None:
        raise ValueError("replay entry bar timestamp must be timezone-aware UTC")
    if entry_bar_open.utcoffset().total_seconds() != 0:
        raise ValueError("replay entry bar timestamp must use UTC")
    if entry_bar_open.to_pydatetime() != provenance.bar_closed_at:
        raise ValueError("replay entry bar does not follow the decision candle")

    try:
        first_time_msc = float(entry_row["first_time_msc"])
    except (TypeError, ValueError) as exc:
        raise ValueError("first_time_msc must be an integer timestamp") from exc
    if (
        not math.isfinite(first_time_msc)
        or first_time_msc < 0
        or not first_time_msc.is_integer()
    ):
        raise ValueError("first_time_msc must be a nonnegative integer timestamp")
    first_tick_at = pd.to_datetime(
        int(first_time_msc),
        unit="ms",
        utc=True,
    ).to_pydatetime()

    return build_decision_snapshot(
        broker_bars.iloc[: signal_index + 1].copy(),
        symbol=symbol,
        first_eligible_quote=FirstEligibleQuote(
            bid=entry_row["bid_open"],
            ask=entry_row["ask_open"],
            observed_at=first_tick_at,
        ),
        provenance=provenance,
    )


def compare_selector_signal_frames(
    exact: pd.DataFrame,
    proxy_by_strategy: dict[str, pd.Series],
    allowed_strategies: Iterable[str],
) -> dict:
    """Compare every evaluated runtime action with component replay signals."""

    required_columns = {"direction", "strategy"}
    if not isinstance(exact, pd.DataFrame) or not required_columns.issubset(exact):
        raise ValueError("exact selector frame must contain direction and strategy")

    evaluated = exact["strategy"].astype(str) != "NOT_EVALUATED"
    exact_direction = pd.to_numeric(exact["direction"], errors="coerce").fillna(0).astype("int8")
    exact_strategy = exact["strategy"].astype(str).str.upper()
    mismatch_rows = pd.Series(False, index=exact.index)
    component_reports: dict[str, dict] = {}
    coverage_gaps: list[str] = []

    for strategy in sorted(str(strategy).upper() for strategy in allowed_strategies):
        proxy = proxy_by_strategy.get(strategy)
        if proxy is None:
            proxy = pd.Series(0, index=exact.index, dtype="int8")
            coverage_gaps.append(f"missing proxy series for {strategy}")
        proxy = pd.to_numeric(proxy.reindex(exact.index), errors="coerce").fillna(0).astype("int8")
        expected = exact_direction.where(exact_strategy == strategy, 0).astype("int8")
        component_mismatch = evaluated & proxy.ne(expected)
        mismatch_rows |= component_mismatch

        proxy_signal = evaluated & proxy.ne(0)
        exact_signal = evaluated & expected.ne(0)
        true_positive = int((proxy_signal & proxy.eq(expected)).sum())
        false_positive = int((proxy_signal & proxy.ne(expected)).sum())
        false_negative = int((exact_signal & proxy.ne(expected)).sum())
        precision = (
            true_positive / (true_positive + false_positive)
            if true_positive + false_positive
            else None
        )
        recall = (
            true_positive / (true_positive + false_negative)
            if true_positive + false_negative
            else None
        )
        runtime_signal_rows = int(exact_signal.sum())
        if runtime_signal_rows == 0:
            coverage_gaps.append(f"no exact runtime signal coverage for {strategy}")

        component_reports[strategy] = {
            "runtime_signal_rows": runtime_signal_rows,
            "proxy_signal_rows": int(proxy_signal.sum()),
            "mismatch_rows": int(component_mismatch.sum()),
            "signal_precision": round(precision, 6) if precision is not None else None,
            "signal_recall": round(recall, 6) if recall is not None else None,
        }

    action_counts = {
        "BUY": int((evaluated & exact_direction.eq(1)).sum()),
        "SELL": int((evaluated & exact_direction.eq(-1)).sum()),
        "WAIT": int((evaluated & exact_direction.eq(0)).sum()),
    }
    for action, count in action_counts.items():
        if count == 0:
            coverage_gaps.append(f"no exact {action} action coverage")

    evaluated_rows = int(evaluated.sum())
    mismatch_count = int((evaluated & mismatch_rows).sum())
    agreement = (
        (evaluated_rows - mismatch_count) / evaluated_rows * 100.0
        if evaluated_rows
        else 0.0
    )
    if mismatch_count:
        status = "SELECTOR_SIGNAL_PARITY_MISMATCH"
    elif coverage_gaps:
        status = "SELECTOR_SIGNAL_COVERAGE_INSUFFICIENT"
    else:
        status = "SELECTOR_SIGNAL_PARITY_VERIFIED"

    return {
        "status": status,
        "evaluated_rows": evaluated_rows,
        "mismatch_rows": mismatch_count,
        "action_agreement_percent": round(agreement, 6),
        "exact_action_counts": action_counts,
        "component_reports": component_reports,
        "coverage_gaps": sorted(set(coverage_gaps)),
        "selector_signal_parity_verified": bool(
            evaluated_rows and mismatch_count == 0 and not coverage_gaps
        ),
        "runtime_parity_verified": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
    }


def measure_runtime_selector_parity(df: pd.DataFrame, symbol: str) -> dict:
    """Run the exact selector oracle against every vectorized component row."""

    symbol = normalize_symbol(symbol)
    profile = get_strategy_profile(symbol)
    indicator_data = add_indicators(df)
    exact = generate_runtime_selector_signals(df, symbol)
    proxy_selected = generate_proxy_selector_frame(indicator_data, symbol)
    proxy_by_strategy = {
        strategy: proxy_selected["direction"].where(
            proxy_selected["strategy"].eq(strategy),
            0,
        )
        for strategy in profile.allowed_strategies
    }
    report = compare_selector_signal_frames(
        exact,
        proxy_by_strategy,
        profile.allowed_strategies,
    )
    report.update(
        {
            "symbol": symbol,
            "selector_signal_engine": (
                "live_runtime.decision_core.evaluate_decision_core"
            ),
            "proxy_signal_engine": (
                "strategy.replay_validator.generate_proxy_selector_frame"
            ),
        }
    )
    return report


def generate_strategy_signals(
    data: pd.DataFrame,
    symbol: str,
    strategy: str,
) -> pd.Series:
    profile = get_strategy_profile(symbol)
    strategy = str(strategy or "").upper()
    signals = pd.Series(0, index=data.index, dtype="int8")

    atr_quality = data["atr_ratio"].between(0.70, profile.max_atr_ratio)

    if strategy == "BREAKOUT":
        buffer_distance = profile.breakout_buffer_atr * data["atr"]
        regime = data["trend_regime"] | data["breakout_regime"]
        quality = (
            regime
            & atr_quality
            & (data["adx"] >= profile.min_breakout_adx)
            & (data["body_ratio"] >= 0.45)
        )
        buy = (
            quality
            & (data["Close"] > data["recent_high"] + buffer_distance)
            & (data["Close"] > data["ema50"])
            & (data["Close"] > data["Open"])
        )
        sell = (
            quality
            & (data["Close"] < data["recent_low"] - buffer_distance)
            & (data["Close"] < data["ema50"])
            & (data["Close"] < data["Open"])
        )

        # Keep the vectorized replay aligned with the runtime selector's
        # symbol-specific score floor.  A base breakout scores 4; stronger ADX
        # and candle body add one point each in strategy_selector.py.
        breakout_score = (
            4
            + (data["adx"] >= profile.min_breakout_adx + 4).astype("int8")
            + (data["body_ratio"] >= 0.60).astype("int8")
        )
        score_ok = breakout_score >= profile.min_strategy_score
        buy &= score_ok
        sell &= score_ok

    elif strategy == "MEAN_REVERSION":
        tolerance = data["atr"] * 0.10
        choppy_regime = (
            data["choppy_regime"]
            if "choppy_regime" in data
            else pd.Series(False, index=data.index)
        )
        quality = (
            data["range_regime"]
            & ~choppy_regime.fillna(False)
            & (data["adx"] <= profile.max_mean_reversion_adx)
            & atr_quality
        )
        buy = (
            quality
            & (data["rsi"] <= 30)
            & (data["Close"] <= data["bb_lower"] + tolerance)
        )
        sell = (
            quality
            & (data["rsi"] >= 70)
            & (data["Close"] >= data["bb_upper"] - tolerance)
        )

    elif strategy == "MOMENTUM_PULLBACK":
        touch_distance = profile.pullback_touch_atr * data["atr"]
        quality = (
            data["trend_regime"]
            & atr_quality
            & (data["adx"] >= profile.min_momentum_adx)
        )
        momentum_score = (
            4
            + (data["adx"] >= profile.min_momentum_adx + 4).astype("int8")
            + (data["body_ratio"] >= 0.55).astype("int8")
        )
        score_ok = momentum_score >= profile.min_strategy_score
        buy = (
            quality
            & (data["ema20"] > data["ema50"])
            & (data["ema50"] > data["ema200"])
            & (data["ema50_slope"] > 0)
            & (data["regime_direction"] == "UP")
            & ((data["Low"] - data["ema20"]).abs() <= touch_distance)
            & (data["Close"] > data["ema20"])
            & (data["Close"] > data["Open"])
            & data["rsi"].between(48, 68)
            & score_ok
        )
        sell = (
            quality
            & (data["ema20"] < data["ema50"])
            & (data["ema50"] < data["ema200"])
            & (data["ema50_slope"] < 0)
            & (data["regime_direction"] == "DOWN")
            & ((data["High"] - data["ema20"]).abs() <= touch_distance)
            & (data["Close"] < data["ema20"])
            & (data["Close"] < data["Open"])
            & data["rsi"].between(32, 52)
            & score_ok
        )

    else:
        raise ValueError(f"unsupported strategy: {strategy}")

    signals.loc[buy.fillna(False)] = 1
    signals.loc[sell.fillna(False)] = -1
    return signals


def generate_proxy_selector_frame(
    data: pd.DataFrame,
    symbol: str,
    raw_signals_by_strategy: dict[str, pd.Series] | None = None,
) -> pd.DataFrame:
    """Apply the runtime selector's score and preference tie-break to proxies.

    Component signals may overlap on the same candle.  Comparing each raw
    component directly with the one strategy selected at runtime creates false
    parity mismatches, so this helper first resolves the same deterministic
    winner used by :func:`select_best_strategy`.
    """

    symbol = normalize_symbol(symbol)
    profile = get_strategy_profile(symbol)
    runtime_order = ("BREAKOUT", "MEAN_REVERSION", "MOMENTUM_PULLBACK")
    allowed_order = [
        strategy for strategy in runtime_order
        if strategy in profile.allowed_strategies
    ]
    raw_signals = (
        {
            strategy: raw_signals_by_strategy[strategy]
            for strategy in allowed_order
        }
        if raw_signals_by_strategy is not None
        else {
            strategy: generate_strategy_signals(data, symbol, strategy)
            for strategy in allowed_order
        }
    )
    strong_body_breakout = (data["body_ratio"] >= 0.60).astype("int16")
    strong_body_momentum = (data["body_ratio"] >= 0.55).astype("int16")
    scores = {
        "BREAKOUT": (
            4
            + (data["adx"] >= profile.min_breakout_adx + 4).astype("int16")
            + strong_body_breakout
        ),
        "MEAN_REVERSION": pd.Series(6, index=data.index, dtype="int16"),
        "MOMENTUM_PULLBACK": (
            4
            + (data["adx"] >= profile.min_momentum_adx + 4).astype("int16")
            + strong_body_momentum
        ),
    }
    confidence = pd.to_numeric(
        data.get("regime_confidence", pd.Series(0, index=data.index)),
        errors="coerce",
    ).fillna(0).astype("int16")
    priority = {strategy: 1 for strategy in runtime_order}
    priority[profile.preferred_strategy] = 2

    selected = pd.DataFrame(
        {
            "direction": pd.Series(0, index=data.index, dtype="int8"),
            "strategy": pd.Series("NO_STRATEGY", index=data.index, dtype="object"),
            "score": pd.Series(0, index=data.index, dtype="int16"),
        }
    )
    for index in data.index:
        candidates = [
            strategy
            for strategy in allowed_order
            if int(raw_signals[strategy].at[index]) in {-1, 1}
        ]
        if not candidates:
            continue
        best = max(
            candidates,
            key=lambda strategy: (
                int(scores[strategy].at[index]),
                priority.get(strategy, 0),
                int(confidence.at[index]),
            ),
        )
        selected.at[index, "direction"] = int(raw_signals[best].at[index])
        selected.at[index, "strategy"] = best
        selected.at[index, "score"] = int(scores[best].at[index])

    return selected


def make_purged_walk_forward_splits(
    total_rows: int,
    locked_end: int,
    max_holding_bars: int,
    test_bars: int = ROLLING_TEST_BARS,
    min_initial_train_bars: int = ROLLING_MIN_INITIAL_TRAIN_BARS,
    max_folds: int = ROLLING_MAX_FOLDS,
) -> list[dict]:
    """Create expanding, purged folds entirely inside development data."""

    total_rows = max(0, int(total_rows))
    locked_end = min(max(0, int(locked_end)), total_rows)
    max_holding_bars = max(1, int(max_holding_bars))
    test_bars = max(1, int(test_bars))
    min_initial_train_bars = max(WARMUP_BARS, int(min_initial_train_bars))
    max_folds = max(0, int(max_folds))
    purge_bars = max_holding_bars + 1  # signal bar plus full exit horizon

    first_test_start = min_initial_train_bars + purge_bars
    latest_test_start = locked_end - test_bars
    if max_folds == 0 or first_test_start > latest_test_start:
        return []

    starts = list(range(first_test_start, latest_test_start + 1, test_bars))
    starts = starts[-max_folds:]
    return [
        {
            "fold": fold,
            "train_start": 0,
            "train_end": test_start - purge_bars,
            "purge_start": test_start - purge_bars,
            "purge_end": test_start,
            "purge_bars": purge_bars,
            "test_start": test_start,
            "test_end": test_start + test_bars,
        }
        for fold, test_start in enumerate(starts, start=1)
    ]


def simulate_non_overlapping_trades(
    data: pd.DataFrame,
    signals: pd.Series,
    symbol: str,
    start_index: int,
    end_index: int,
) -> list[dict]:
    profile = get_strategy_profile(symbol)
    cost_percent = profile.estimated_round_trip_cost_bps / 100.0
    trades: list[dict] = []
    index = max(int(start_index), WARMUP_BARS)

    # Purge the right edge of every segment.  A signal is admitted only when
    # its full configured holding horizon is observable inside that segment;
    # otherwise segment-end truncation would create artificial TIMEOUT exits.
    final_signal_index = min(
        int(end_index) - profile.max_holding_bars - 1,
        len(data) - profile.max_holding_bars - 1,
    )

    signal_values = np.asarray(signals, dtype=np.int8)
    open_values = data["Open"].to_numpy(dtype=float, copy=False)
    high_values = data["High"].to_numpy(dtype=float, copy=False)
    low_values = data["Low"].to_numpy(dtype=float, copy=False)
    close_values = data["Close"].to_numpy(dtype=float, copy=False)
    atr_values = data["atr"].to_numpy(dtype=float, copy=False)

    while index <= final_signal_index:
        direction = int(signal_values[index])
        atr = float(atr_values[index])
        if direction not in {-1, 1} or not math.isfinite(atr) or atr <= 0:
            index += 1
            continue

        entry_index = index + 1
        entry_price = float(open_values[entry_index])
        stop_price = entry_price - direction * profile.stop_atr * atr
        target_price = entry_price + direction * profile.target_atr * atr
        last_exit_index = min(
            entry_index + profile.max_holding_bars - 1,
            int(end_index) - 1,
            len(data) - 1,
        )
        exit_price = float(close_values[last_exit_index])
        exit_index = last_exit_index
        exit_reason = "TIMEOUT"
        gap_through_stop = False

        for forward_index in range(entry_index, last_exit_index + 1):
            bar_open = float(open_values[forward_index])
            high = float(high_values[forward_index])
            low = float(low_values[forward_index])

            adverse_open_gap = (
                bar_open <= stop_price if direction == 1 else bar_open >= stop_price
            )
            favorable_open_gap = (
                bar_open >= target_price if direction == 1 else bar_open <= target_price
            )
            if adverse_open_gap:
                # A stop is a market order once triggered.  If price opens
                # beyond it, the conservative executable fill is the open,
                # not the now-unavailable stop level.
                exit_price = bar_open
                exit_index = forward_index
                exit_reason = "GAP_STOP"
                gap_through_stop = True
                break
            if favorable_open_gap:
                # Take-profit is treated as a resting limit; do not assume
                # positive slippage beyond the requested target.
                exit_price = target_price
                exit_index = forward_index
                exit_reason = "TARGET"
                break

            stop_hit = low <= stop_price if direction == 1 else high >= stop_price
            target_hit = high >= target_price if direction == 1 else low <= target_price

            # Conservative resolution when both levels are touched in one bar.
            if stop_hit:
                exit_price = stop_price
                exit_index = forward_index
                exit_reason = "STOP"
                break
            if target_hit:
                exit_price = target_price
                exit_index = forward_index
                exit_reason = "TARGET"
                break

        gross_return_percent = (
            direction * (exit_price - entry_price) / entry_price * 100.0
        )
        net_return_percent = gross_return_percent - cost_percent
        trades.append(
            {
                "signal_index": int(index),
                "entry_index": int(entry_index),
                "exit_index": int(exit_index),
                "direction": "BUY" if direction == 1 else "SELL",
                "entry_price": round(entry_price, 8),
                "exit_price": round(float(exit_price), 8),
                "exit_reason": exit_reason,
                "gap_through_stop": gap_through_stop,
                "gross_return_percent": round(gross_return_percent, 6),
                "cost_percent": round(cost_percent, 6),
                "net_return_percent": round(net_return_percent, 6),
            }
        )
        index = exit_index + 1

    return trades


def calculate_metrics(trades: list[dict]) -> dict:
    returns = np.asarray(
        [float(trade["net_return_percent"]) for trade in trades],
        dtype=float,
    )
    if returns.size == 0:
        return {
            "trades": 0,
            "wins": 0,
            "losses": 0,
            "winrate_percent": 0.0,
            "profit_factor": 0.0,
            "expectancy_percent": 0.0,
            "net_return_percent": 0.0,
            "max_drawdown_percent": 0.0,
            "profit_factor_defined": False,
        }

    wins = returns[returns > 0]
    losses = returns[returns <= 0]
    gross_profit = float(wins.sum()) if wins.size else 0.0
    gross_loss = float(abs(losses.sum())) if losses.size else 0.0
    profit_factor = gross_profit / gross_loss if gross_loss > 0 else None

    equity = np.cumprod(1.0 + returns / 100.0)
    peaks = np.maximum.accumulate(np.concatenate(([1.0], equity)))
    equity_with_start = np.concatenate(([1.0], equity))
    drawdown = (peaks - equity_with_start) / peaks * 100.0

    return {
        "trades": int(returns.size),
        "wins": int(wins.size),
        "losses": int(losses.size),
        "winrate_percent": round(float(wins.size / returns.size * 100.0), 4),
        "profit_factor": (
            round(float(profit_factor), 4) if profit_factor is not None else None
        ),
        "profit_factor_defined": profit_factor is not None,
        "expectancy_percent": round(float(returns.mean()), 6),
        "net_return_percent": round(float((equity[-1] - 1.0) * 100.0), 4),
        "max_drawdown_percent": round(float(drawdown.max()), 4),
    }


def _gate_requirements(
    development: dict,
    rolling: dict,
    positive_rolling_folds: int,
    source_aligned: bool,
    future_holdout_available: bool,
    future_holdout: dict | None = None,
) -> tuple[list[str], list[str]]:
    development_watch_failures: list[str] = []
    live_failures: list[str] = []

    development_profit_factor = float(development.get("profit_factor") or 0.0)
    rolling_profit_factor = float(rolling.get("profit_factor") or 0.0)
    future_holdout = future_holdout or {}
    future_profit_factor = float(future_holdout.get("profit_factor") or 0.0)

    watch_checks = (
        (
            development["trades"] >= MIN_DEVELOPMENT_TRADES_WATCH,
            "insufficient development WATCH-diagnostic trades",
        ),
        (
            rolling["trades"] >= MIN_ROLLING_TRADES_WATCH,
            "insufficient rolling WATCH-diagnostic trades",
        ),
        (
            development_profit_factor >= MIN_DEVELOPMENT_PROFIT_FACTOR_WATCH,
            "development WATCH-diagnostic PF below 1.10",
        ),
        (
            rolling_profit_factor >= MIN_ROLLING_PROFIT_FACTOR_WATCH,
            "rolling WATCH-diagnostic PF below 1.05",
        ),
        (
            development["expectancy_percent"] > 0,
            "development expectancy is not positive",
        ),
        (
            rolling["expectancy_percent"] > 0,
            "rolling expectancy is not positive",
        ),
        (
            positive_rolling_folds >= 2,
            "fewer than two positive rolling development folds",
        ),
    )
    development_watch_failures.extend(
        reason for passed, reason in watch_checks if not passed
    )

    live_checks = (
        (
            development["trades"] >= MIN_DEVELOPMENT_TRADES_LIVE_REVIEW,
            "insufficient development live-review trades",
        ),
        (
            rolling["trades"] >= MIN_ROLLING_TRADES_LIVE_REVIEW,
            "insufficient rolling live-review trades",
        ),
        (
            development_profit_factor
            >= MIN_DEVELOPMENT_PROFIT_FACTOR_LIVE_REVIEW,
            "development live-review PF below 1.20",
        ),
        (
            rolling_profit_factor >= MIN_ROLLING_PROFIT_FACTOR_LIVE_REVIEW,
            "rolling live-review PF below 1.15",
        ),
        (
            development["expectancy_percent"] > 0,
            "development expectancy is not positive",
        ),
        (
            rolling["expectancy_percent"] > 0,
            "rolling expectancy is not positive",
        ),
        (
            development["max_drawdown_percent"]
            <= MAX_DRAWDOWN_PERCENT_LIVE_REVIEW,
            "development drawdown exceeds live-review limit",
        ),
        (
            positive_rolling_folds >= MIN_PROFITABLE_SEGMENTS_LIVE_REVIEW,
            "rolling development stability failed",
        ),
        (source_aligned, "data source is not aligned with the target broker feed"),
        (
            future_holdout_available,
            "future broker-aligned holdout is unavailable",
        ),
        (
            int(future_holdout.get("trades", 0) or 0)
            >= MIN_ROLLING_TRADES_LIVE_REVIEW,
            "insufficient future holdout live-review trades",
        ),
        (
            future_profit_factor >= MIN_ROLLING_PROFIT_FACTOR_LIVE_REVIEW,
            "future holdout live-review PF below 1.15",
        ),
        (
            float(future_holdout.get("expectancy_percent", 0.0) or 0.0) > 0,
            "future holdout expectancy is not positive",
        ),
    )
    live_failures.extend(reason for passed, reason in live_checks if not passed)
    return development_watch_failures, live_failures


def _profile_fingerprint(profile: object) -> str:
    profile_payload = asdict(profile)
    profile_payload["allowed_strategies"] = sorted(
        profile_payload["allowed_strategies"]
    )
    payload = {
        "strategy_profile": profile_payload,
        "strategy_rule_contract_version": STRATEGY_RULE_CONTRACT_VERSION,
        "indicator_contract_version": INDICATOR_CONTRACT_VERSION,
        "replay_execution_contract_version": REPLAY_EXECUTION_CONTRACT_VERSION,
        "validation_snapshot_contract_version": (
            VALIDATION_SNAPSHOT_CONTRACT_VERSION
        ),
        "warmup_bars": WARMUP_BARS,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _data_fingerprint(data: pd.DataFrame) -> str:
    columns = [
        column
        for column in ("Datetime", "Open", "High", "Low", "Close", "Volume")
        if column in data
    ]
    fingerprint_data = data.loc[:, columns].copy()
    if "Datetime" in fingerprint_data:
        fingerprint_data["Datetime"] = pd.to_datetime(
            fingerprint_data["Datetime"],
            errors="coerce",
            utc=True,
        ).astype("int64")
    hashed = pd.util.hash_pandas_object(fingerprint_data, index=True)
    return hashlib.sha256(hashed.to_numpy().tobytes()).hexdigest()


def _resolve_validation_boundaries(
    data: pd.DataFrame,
    symbol: str,
    contract: dict | None = None,
) -> dict:
    """Resolve immutable development/legacy/future boundaries fail-closed."""

    symbol = normalize_symbol(symbol)
    fallback_development_end = int(len(data) * 0.80)
    fallback = {
        "contract_version": VALIDATION_SNAPSHOT_CONTRACT_VERSION,
        "contract_status": "FROZEN_SNAPSHOT_UNAVAILABLE",
        "contract_hash_verified": False,
        "trusted_archive_verified": False,
        "development_end_index": fallback_development_end,
        "seen_legacy_holdout_end_index": len(data),
        "future_holdout_start_index": len(data),
        "future_holdout_rows": 0,
        "development_end_at": None,
        "seen_legacy_holdout_end_at": None,
    }
    if not isinstance(contract, dict):
        fallback["contract_status"] = "FROZEN_SNAPSHOT_CONTRACT_MISSING"
        return fallback
    if "Datetime" not in data:
        fallback["contract_status"] = "FROZEN_SNAPSHOT_TIMESTAMP_UNAVAILABLE"
        return fallback

    try:
        development_end_at = pd.Timestamp(contract["development_end_at"])
        legacy_end_at = pd.Timestamp(contract["seen_legacy_holdout_end_at"])
        if development_end_at.tzinfo is None:
            development_end_at = development_end_at.tz_localize("UTC")
        else:
            development_end_at = development_end_at.tz_convert("UTC")
        if legacy_end_at.tzinfo is None:
            legacy_end_at = legacy_end_at.tz_localize("UTC")
        else:
            legacy_end_at = legacy_end_at.tz_convert("UTC")
        expected_rows = int(contract["snapshot_clean_rows"])
        expected_hash = str(contract["snapshot_data_sha256"])
    except (KeyError, TypeError, ValueError):
        fallback["contract_status"] = "FROZEN_SNAPSHOT_CONTRACT_INVALID"
        return fallback

    timestamps = pd.to_datetime(data["Datetime"], errors="coerce", utc=True)
    development_end = int((timestamps <= development_end_at).sum())
    legacy_end = int((timestamps <= legacy_end_at).sum())
    if (
        development_end < WARMUP_BARS
        or legacy_end < development_end
        or legacy_end > len(data)
    ):
        fallback["contract_status"] = "FROZEN_SNAPSHOT_BOUNDARY_INVALID"
        return fallback

    frozen_prefix = data.iloc[:legacy_end]
    actual_hash = _data_fingerprint(frozen_prefix)
    hash_verified = legacy_end == expected_rows and actual_hash == expected_hash
    return {
        "contract_version": VALIDATION_SNAPSHOT_CONTRACT_VERSION,
        "contract_status": (
            "CALLER_PREFIX_INTEGRITY_MATCHED"
            if hash_verified
            else "CALLER_PREFIX_INTEGRITY_MISMATCH"
        ),
        "contract_hash_verified": hash_verified,
        "trusted_archive_verified": False,
        "expected_snapshot_clean_rows": expected_rows,
        "actual_snapshot_clean_rows": legacy_end,
        "expected_snapshot_data_sha256": expected_hash,
        "actual_snapshot_data_sha256": actual_hash,
        "development_end_index": development_end,
        "seen_legacy_holdout_end_index": legacy_end,
        "future_holdout_start_index": legacy_end,
        "future_holdout_rows": max(0, len(data) - legacy_end),
        "development_end_at": development_end_at.isoformat(),
        "seen_legacy_holdout_end_at": legacy_end_at.isoformat(),
    }


def _prefixed_component_failures(
    strategy_reports: list[dict],
    failure_key: str,
) -> list[str]:
    failures: list[str] = []
    for report in strategy_reports:
        strategy = str(report.get("strategy", "UNKNOWN"))
        raw_failures = report.get(failure_key, [])
        if not isinstance(raw_failures, list):
            raw_failures = ["invalid component failure evidence"]
        failures.extend(f"{strategy}: {reason}" for reason in raw_failures)
    return failures


def validate_symbol_dataframe(
    symbol: str,
    df: pd.DataFrame,
    source_metadata: dict | None = None,
    verify_selector_parity: bool = False,
    validation_contract: dict | None = None,
) -> dict:
    symbol = normalize_symbol(symbol)
    profile = get_strategy_profile(symbol)
    source_metadata = source_metadata or get_data_source_metadata(symbol)
    data = add_indicators(df)
    validation_boundaries = _resolve_validation_boundaries(
        data,
        symbol,
        contract=validation_contract,
    )
    frozen_snapshot_verified = bool(
        validation_boundaries.get("contract_hash_verified", False)
    )
    holdout_evidence_role = (
        CALLER_PREFIX_MATCHED_TAIL_ROLE
        if frozen_snapshot_verified
        else UNFROZEN_TAIL_ROLE
    )
    validation_end = int(validation_boundaries["development_end_index"])
    legacy_holdout_end = int(
        validation_boundaries["seen_legacy_holdout_end_index"]
    )
    future_holdout_start = int(
        validation_boundaries["future_holdout_start_index"]
    )
    train_end = int(validation_end * 0.75)
    segments = (
        ("TRAIN", 0, train_end),
        ("VALIDATION", train_end, validation_end),
        ("HOLDOUT", validation_end, legacy_holdout_end),
        ("FUTURE_HOLDOUT", future_holdout_start, len(data)),
    )
    rolling_splits = make_purged_walk_forward_splits(
        total_rows=len(data),
        locked_end=validation_end,
        max_holding_bars=profile.max_holding_bars,
    )
    segment_roles = {
        "TRAIN": "DEVELOPMENT_V1_TRAIN",
        "VALIDATION": "DEVELOPMENT_V1_VALIDATION",
        "HOLDOUT": holdout_evidence_role,
        "FUTURE_HOLDOUT": "FUTURE_HOLDOUT_V1_BROKER_ALIGNMENT_REQUIRED",
    }

    standalone_signals_by_strategy = {
        strategy: generate_strategy_signals(data, symbol, strategy)
        for strategy in profile.allowed_strategies
    }
    proxy_selected = generate_proxy_selector_frame(
        data,
        symbol,
        raw_signals_by_strategy=standalone_signals_by_strategy,
    )
    runtime_selected_signals_by_strategy = {
        strategy: proxy_selected["direction"].where(
            proxy_selected["strategy"].eq(strategy),
            0,
        ).astype("int8")
        for strategy in profile.allowed_strategies
    }

    strategy_reports = []
    for strategy in sorted(profile.allowed_strategies):
        standalone_signals = standalone_signals_by_strategy[strategy]
        signals = runtime_selected_signals_by_strategy[strategy]
        segment_reports = []
        for segment_name, start_index, end_index in segments:
            segment_trades = simulate_non_overlapping_trades(
                data,
                signals,
                symbol,
                start_index,
                end_index,
            )
            segment_reports.append(
                {
                    "segment": segment_name,
                    "evidence_role": segment_roles[segment_name],
                    "start_index": int(start_index),
                    "end_index": int(end_index),
                    "metrics": calculate_metrics(segment_trades),
                }
            )

        all_trades = simulate_non_overlapping_trades(
            data,
            signals,
            symbol,
            0,
            legacy_holdout_end,
        )
        overall = calculate_metrics(all_trades)
        standalone_component_overall = calculate_metrics(
            simulate_non_overlapping_trades(
                data,
                standalone_signals,
                symbol,
                0,
                legacy_holdout_end,
            )
        )
        development_trades = simulate_non_overlapping_trades(
            data,
            signals,
            symbol,
            0,
            validation_end,
        )
        development_metrics = calculate_metrics(development_trades)
        rolling_fold_reports = []
        rolling_pooled_trades: list[dict] = []
        for split in rolling_splits:
            fold_trades = simulate_non_overlapping_trades(
                data,
                signals,
                symbol,
                split["test_start"],
                split["test_end"],
            )
            rolling_pooled_trades.extend(fold_trades)
            rolling_fold_reports.append(
                {
                    **split,
                    "metrics": calculate_metrics(fold_trades),
                }
            )
        rolling_pooled_metrics = calculate_metrics(rolling_pooled_trades)
        positive_rolling_folds = sum(
            fold["metrics"]["expectancy_percent"] > 0
            for fold in rolling_fold_reports
        )
        future_holdout_metrics = next(
            report["metrics"]
            for report in segment_reports
            if report["segment"] == "FUTURE_HOLDOUT"
        )
        profitable_segments = sum(
            1
            for report in segment_reports
            if report["segment"] != "FUTURE_HOLDOUT"
            if report["metrics"]["expectancy_percent"] > 0
            and float(report["metrics"].get("profit_factor") or 0.0) > 1.0
        )
        source_aligned = bool(
            source_metadata.get("source_aligned_for_live_validation", False)
        )
        # No trusted content-addressed broker archive/forward contract is wired
        # yet.  Never infer admissible future evidence from caller-provided
        # metadata or the collector's overwrite-prone rolling Yahoo CSV.
        future_holdout_available = False
        development_watch_failures, live_failures = _gate_requirements(
            development_metrics,
            rolling_pooled_metrics,
            positive_rolling_folds=positive_rolling_folds,
            source_aligned=source_aligned,
            future_holdout_available=future_holdout_available,
            future_holdout=future_holdout_metrics,
        )
        if not frozen_snapshot_verified:
            development_watch_failures.append(
                "caller prefix integrity contract is not matched"
            )
        # ``watch_ready`` is consumed downstream by decision diagnostics, so it
        # remains authoritative and fail-closed until genuinely future,
        # broker-aligned confirmation exists.  Development evidence is exposed
        # separately and cannot silently activate the draft path.
        watch_failures = list(development_watch_failures)
        if not future_holdout_available:
            watch_failures.append(
                "future broker-aligned holdout is unavailable"
            )
        else:
            future_profit_factor = float(
                future_holdout_metrics.get("profit_factor") or 0.0
            )
            future_watch_checks = (
                (
                    future_holdout_metrics["trades"]
                    >= MIN_ROLLING_TRADES_WATCH,
                    "insufficient future holdout WATCH trades",
                ),
                (
                    future_profit_factor
                    >= MIN_ROLLING_PROFIT_FACTOR_WATCH,
                    "future holdout WATCH PF below 1.05",
                ),
                (
                    future_holdout_metrics["expectancy_percent"] > 0,
                    "future holdout expectancy is not positive",
                ),
            )
            watch_failures.extend(
                reason for passed, reason in future_watch_checks if not passed
            )
        strategy_reports.append(
            {
                "strategy": strategy,
                "metrics_signal_engine": (
                    "RUNTIME_SELECTED_PROXY_WITH_PROFILE_TIE_BREAK"
                ),
                "runtime_selected_proxy_signal_rows": int(
                    signals.iloc[WARMUP_BARS:legacy_holdout_end].ne(0).sum()
                ),
                "standalone_component_signal_rows": int(
                    standalone_signals.iloc[
                        WARMUP_BARS:legacy_holdout_end
                    ].ne(0).sum()
                ),
                "standalone_component_overall": standalone_component_overall,
                "standalone_component_evidence_role": (
                    "RESEARCH_DIAGNOSTIC_NOT_SYSTEM_PERFORMANCE"
                ),
                "overall": overall,
                "overall_evidence_role": (
                    "FULL_SNAPSHOT_DESCRIPTIVE_INCLUDES_SEEN_LEGACY_"
                    "HOLDOUT_REPORT_ONLY"
                ),
                "segments": segment_reports,
                "profitable_segments": profitable_segments,
                "development_metrics": development_metrics,
                "development_rolling_diagnostic": {
                    "evidence_role": "DEVELOPMENT_V1_ONLY_NOT_FINAL_CONFIRMATION",
                    "folds": rolling_fold_reports,
                    "pooled_metrics": rolling_pooled_metrics,
                    "positive_expectancy_folds": positive_rolling_folds,
                    "used_for_promotion": False,
                },
                "development_watch_diagnostic_passed": not development_watch_failures,
                "development_watch_failures": development_watch_failures,
                "future_holdout_available": future_holdout_available,
                "future_holdout_metrics": future_holdout_metrics,
                "watch_ready": not watch_failures,
                "watch_failures": watch_failures,
                "live_review_ready": not live_failures,
                "live_review_failures": live_failures,
            }
        )

    # The strategy is pre-registered in the symbol profile.  Never rank or
    # select candidates with legacy HOLDOUT metrics: those results have already
    # been seen and must remain report-only rather than becoming tuning input.
    strategy_reports.sort(
        key=lambda report: (
            report["strategy"] != profile.preferred_strategy,
            report["strategy"],
        )
    )
    selected_report = next(
        (
            report
            for report in strategy_reports
            if report["strategy"] == profile.preferred_strategy
        ),
        strategy_reports[0] if strategy_reports else None,
    )
    component_watch_failures = _prefixed_component_failures(
        strategy_reports,
        "watch_failures",
    )
    component_development_watch_failures = _prefixed_component_failures(
        strategy_reports,
        "development_watch_failures",
    )
    component_live_failures = _prefixed_component_failures(
        strategy_reports,
        "live_review_failures",
    )
    watch_ready = bool(strategy_reports) and not component_watch_failures
    development_watch_diagnostic_passed = (
        bool(strategy_reports) and not component_development_watch_failures
    )
    live_review_ready = bool(strategy_reports) and not component_live_failures
    selector_signal_parity = (
        measure_runtime_selector_parity(df, symbol)
        if verify_selector_parity
        else {
            "status": "SELECTOR_SIGNAL_PARITY_NOT_RUN",
            "reason": (
                "Exact prefix-by-prefix selector audit is opt-in because the "
                "correctness oracle is O(n^2)."
            ),
            "selector_signal_parity_verified": False,
            "runtime_parity_verified": False,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
        }
    )

    return {
        "schema_version": VALIDATION_SCHEMA_VERSION,
        "symbol": symbol,
        "status": (
            "DEVELOPMENT_WATCH_DIAGNOSTIC_PASSED_FUTURE_HOLDOUT_REQUIRED"
            if development_watch_diagnostic_passed
            else "VALIDATION_HOLD"
        ),
        "rows": int(len(df)),
        "clean_rows": int(len(data)),
        "timeframe_assumption": "15m",
        "data_source": source_metadata,
        "asset_class": profile.asset_class,
        "allowed_strategies": sorted(profile.allowed_strategies),
        "preferred_strategy": profile.preferred_strategy,
        "selection_policy": "PRE_REGISTERED_PROFILE_PREFERENCE_NO_HOLDOUT_SELECTION",
        "holdout_used_for_selection": False,
        "development_end_index": validation_end,
        "seen_legacy_holdout_end_index": legacy_holdout_end,
        "future_holdout_start_index": future_holdout_start,
        "validation_snapshot_contract": validation_boundaries,
        "holdout_evidence_role": holdout_evidence_role,
        "future_holdout_required": True,
        "future_holdout_available": future_holdout_available,
        "future_holdout_acceptance_policy": (
            "DISABLED_UNTIL_CONTENT_ADDRESSED_BROKER_ARCHIVE_AND_"
            "PREREGISTERED_CONFIG_CONTRACT"
        ),
        "future_holdout_minimum_source": "BROKER_ALIGNED_FINALIZED_BID_ASK_CANDLES",
        "development_rolling_config": {
            "test_bars": ROLLING_TEST_BARS,
            "min_initial_train_bars": ROLLING_MIN_INITIAL_TRAIN_BARS,
            "max_folds": ROLLING_MAX_FOLDS,
            "purge_bars": profile.max_holding_bars + 1,
            "fold_count": len(rolling_splits),
            "used_for_promotion": False,
        },
        "config_sha256": _profile_fingerprint(profile),
        "strategy_rule_contract_version": STRATEGY_RULE_CONTRACT_VERSION,
        "indicator_contract_version": INDICATOR_CONTRACT_VERSION,
        "replay_execution_contract_version": REPLAY_EXECUTION_CONTRACT_VERSION,
        "validation_snapshot_contract_version": (
            VALIDATION_SNAPSHOT_CONTRACT_VERSION
        ),
        "data_sha256": _data_fingerprint(data),
        "estimated_round_trip_cost_bps": profile.estimated_round_trip_cost_bps,
        "entry_model": "signal close then next candle open",
        "position_model": "single non-overlapping position per strategy",
        "ambiguous_bar_policy": "stop first",
        "stop_atr": profile.stop_atr,
        "target_atr": profile.target_atr,
        "max_holding_bars": profile.max_holding_bars,
        "purged_segment_boundary_bars": profile.max_holding_bars + 1,
        "right_censored_trades_included": False,
        # Kept for backward-compatible diagnostic consumers.  This now means
        # the frozen/pre-registered strategy, not a holdout-ranked winner.
        "best_strategy": selected_report["strategy"] if selected_report else None,
        "selected_strategy": selected_report["strategy"] if selected_report else None,
        "strategy_reports": strategy_reports,
        "component_gate_policy": "ALL_RUNTIME_ALLOWED_COMPONENTS_MUST_PASS",
        "development_watch_diagnostic_passed": (
            development_watch_diagnostic_passed
        ),
        "component_development_watch_failures": (
            component_development_watch_failures
        ),
        "component_watch_failures": component_watch_failures,
        "component_live_review_failures": component_live_failures,
        "watch_ready": watch_ready,
        "live_review_ready": live_review_ready,
        "selector_signal_parity": selector_signal_parity,
        "selector_signal_parity_verified": bool(
            selector_signal_parity.get("selector_signal_parity_verified", False)
        ),
        "runtime_parity_verified": False,
        "promotion_eligible": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "max_lot": 0.01,
        "notes": (
            (
                "Exact selector-signal parity was verified for the evaluated "
                "snapshot, but Decision Engine, fill, exit, broker, and cost "
                "parity remain unverified. "
            )
            if selector_signal_parity.get("selector_signal_parity_verified", False)
            else (
                "Selector-signal parity is unverified or failed for this report. "
            )
        )
        + (
            "No immutable archived snapshot contract is verified; the dynamic "
            "tail is diagnostic-only and cannot satisfy readiness. "
            if not frozen_snapshot_verified
            else (
                "Caller prefix integrity matched, but trusted archive "
                "provenance is not established. "
            )
        )
        + (
            "Promotion remains ineligible; execution_policy and Phase4R are "
            "authoritative and locked."
        ),
    }


def validate_symbol_file(
    symbol: str,
    data_dir: str | Path = "data",
    verify_selector_parity: bool = False,
) -> dict:
    symbol = normalize_symbol(symbol)
    path = Path(data_dir) / f"{symbol.lower()}.csv"
    if not path.exists():
        return {
            "symbol": symbol,
            "status": "DATA_FILE_MISSING",
            "source_csv": str(path),
            "watch_ready": False,
            "live_review_ready": False,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "max_lot": 0.01,
        }

    try:
        dataframe = pd.read_csv(path)
        report = validate_symbol_dataframe(
            symbol,
            dataframe,
            verify_selector_parity=verify_selector_parity,
        )
    except (OSError, ValueError, TypeError, KeyError, IndexError) as exc:
        return {
            "symbol": symbol,
            "status": "VALIDATION_ERROR",
            "source_csv": str(path),
            "reason": str(exc),
            "watch_ready": False,
            "live_review_ready": False,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "max_lot": 0.01,
        }

    report["source_csv"] = str(path)
    report["source_csv_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    report["source_csv_size_bytes"] = path.stat().st_size
    if "Datetime" in dataframe.columns:
        timestamps = pd.to_datetime(dataframe["Datetime"], errors="coerce", utc=True).dropna()
        if not timestamps.empty:
            report["data_start_at"] = timestamps.min().isoformat()
            report["data_end_at"] = timestamps.max().isoformat()
    return report


def build_validation_report(
    symbols: Iterable[str],
    data_dir: str | Path = "data",
    verify_selector_parity: bool = False,
) -> dict:
    normalized_symbols = list(
        dict.fromkeys(normalize_symbol(symbol) for symbol in symbols if symbol)
    )
    reports = [
        validate_symbol_file(
            symbol,
            data_dir=data_dir,
            verify_selector_parity=verify_selector_parity,
        )
        for symbol in normalized_symbols
    ]
    return {
        "schema_version": VALIDATION_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "COST_AWARE_CHRONOLOGICAL_WALK_FORWARD",
        "selection_policy": "PRE_REGISTERED_PROFILE_PREFERENCE_NO_HOLDOUT_SELECTION",
        "holdout_used_for_selection": False,
        "runtime_parity_verified": False,
        "selector_signal_parity_requested": bool(verify_selector_parity),
        "selector_signal_parity_verified": bool(reports) and all(
            report.get("selector_signal_parity_verified", False)
            for report in reports
        ),
        "promotion_eligible": False,
        "status": "STRATEGY_VALIDATION_COMPLETE",
        "symbols": normalized_symbols,
        "watch_ready_symbols": [
            report["symbol"] for report in reports if report.get("watch_ready")
        ],
        "live_review_ready_symbols": [
            report["symbol"]
            for report in reports
            if report.get("live_review_ready")
        ],
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "max_lot": 0.01,
        "symbol_reports": reports,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run cost-aware chronological strategy validation"
    )
    parser.add_argument(
        "--symbols",
        nargs="*",
        default=list(YFINANCE_TICKERS),
        help="Symbols to validate; defaults to every configured symbol",
    )
    parser.add_argument("--data-dir", default="data")
    parser.add_argument("--output", default="strategy_walk_forward_report.json")
    parser.add_argument(
        "--verify-selector-parity",
        action="store_true",
        help=(
            "Run the exact O(n^2) prefix selector oracle; diagnostic-only and "
            "never sufficient for live/runtime parity."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = build_validation_report(
        args.symbols,
        data_dir=args.data_dir,
        verify_selector_parity=args.verify_selector_parity,
    )
    output_path = Path(args.output)
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print(f"Saved cost-aware validation report: {output_path}")
    for item in report["symbol_reports"]:
        print(
            f"{item['symbol']:<8} {item['status']:<24} "
            f"best={item.get('best_strategy') or '-':<18} "
            f"watch={item.get('watch_ready', False)} "
            f"live_review={item.get('live_review_ready', False)}"
        )


if __name__ == "__main__":
    main()
