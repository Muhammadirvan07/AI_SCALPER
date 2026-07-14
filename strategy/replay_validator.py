"""Cost-aware chronological validation for AI_SCALPER strategies.

This validator is deliberately stricter than the legacy next-candle proxy:
signals enter on the next candle open, positions cannot overlap, ambiguous
SL/TP candles resolve to the stop, estimated round-trip costs are deducted,
and the final 20 percent of data is reported as untouched holdout.

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
from market_data_quality import keep_completed_candles
from strategy.strategy_profiles import get_strategy_profile, normalize_symbol


WARMUP_BARS = 250
MIN_TOTAL_TRADES_LIVE_REVIEW = 60
MIN_HOLDOUT_TRADES_LIVE_REVIEW = 15
MIN_PROFITABLE_SEGMENTS_LIVE_REVIEW = 2
MIN_OVERALL_PROFIT_FACTOR_LIVE_REVIEW = 1.20
MIN_HOLDOUT_PROFIT_FACTOR_LIVE_REVIEW = 1.15
MAX_DRAWDOWN_PERCENT_LIVE_REVIEW = 8.0
VALIDATION_SCHEMA_VERSION = "2.0"

MIN_TOTAL_TRADES_WATCH = 30
MIN_HOLDOUT_TRADES_WATCH = 8
MIN_OVERALL_PROFIT_FACTOR_WATCH = 1.10
MIN_HOLDOUT_PROFIT_FACTOR_WATCH = 1.05


def normalize_ohlcv(df: pd.DataFrame) -> pd.DataFrame:
    if not isinstance(df, pd.DataFrame):
        raise TypeError("replay input must be a pandas DataFrame")

    df, _ = keep_completed_candles(df)
    required = ("Open", "High", "Low", "Close")
    missing = [column for column in required if column not in df.columns]
    if missing:
        raise ValueError(f"missing OHLC columns: {missing}")

    columns = list(required)
    if "Volume" in df.columns:
        columns.append("Volume")

    data = df.loc[:, columns].copy()
    for column in columns:
        data[column] = pd.to_numeric(data[column], errors="coerce")
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
        (data["atr_ratio"] > 2.20) & (data["wick_body_ratio"] > 4.0)
    )
    data["trend_regime"] = (
        (data["adx"] >= 22.0)
        & (data["ema_distance_percent"] >= 0.025)
        & (data["ema_slope_percent"] >= 0.003)
        & ~data["low_volatility"]
        & ~data["volatility_spike"]
    )
    data["breakout_regime"] = (
        data["bb_expanding"]
        & (data["adx"] >= 18.0)
        & ~data["low_volatility"]
        & ~data["volatility_spike"]
    )
    data["range_regime"] = (
        (data["adx"] < 22.0)
        & ~data["bb_expanding"]
        & ~data["low_volatility"]
        & ~data["volatility_spike"]
    )

    return data


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
        quality = (
            data["range_regime"]
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
        buy = (
            quality
            & (data["ema20"] > data["ema50"])
            & (data["ema50_slope"] > 0)
            & (data["Low"] <= data["ema20"] + touch_distance)
            & (data["Close"] > data["ema20"])
            & (data["Close"] > data["Open"])
            & data["rsi"].between(48, 68)
        )
        sell = (
            quality
            & (data["ema20"] < data["ema50"])
            & (data["ema50_slope"] < 0)
            & (data["High"] >= data["ema20"] - touch_distance)
            & (data["Close"] < data["ema20"])
            & (data["Close"] < data["Open"])
            & data["rsi"].between(32, 52)
        )

    else:
        raise ValueError(f"unsupported strategy: {strategy}")

    signals.loc[buy.fillna(False)] = 1
    signals.loc[sell.fillna(False)] = -1
    return signals


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
    overall: dict,
    holdout: dict,
    profitable_segments: int,
    source_aligned: bool,
) -> tuple[list[str], list[str]]:
    watch_failures: list[str] = []
    live_failures: list[str] = []

    overall_profit_factor = float(overall.get("profit_factor") or 0.0)
    holdout_profit_factor = float(holdout.get("profit_factor") or 0.0)

    watch_checks = (
        (overall["trades"] >= MIN_TOTAL_TRADES_WATCH, "insufficient total WATCH trades"),
        (holdout["trades"] >= MIN_HOLDOUT_TRADES_WATCH, "insufficient holdout WATCH trades"),
        (overall_profit_factor >= MIN_OVERALL_PROFIT_FACTOR_WATCH, "overall WATCH PF below 1.10"),
        (holdout_profit_factor >= MIN_HOLDOUT_PROFIT_FACTOR_WATCH, "holdout WATCH PF below 1.05"),
        (overall["expectancy_percent"] > 0, "overall expectancy is not positive"),
        (profitable_segments >= 2, "fewer than two profitable chronological segments"),
    )
    watch_failures.extend(reason for passed, reason in watch_checks if not passed)

    live_checks = (
        (overall["trades"] >= MIN_TOTAL_TRADES_LIVE_REVIEW, "insufficient total live-review trades"),
        (holdout["trades"] >= MIN_HOLDOUT_TRADES_LIVE_REVIEW, "insufficient holdout live-review trades"),
        (overall_profit_factor >= MIN_OVERALL_PROFIT_FACTOR_LIVE_REVIEW, "overall live-review PF below 1.20"),
        (holdout_profit_factor >= MIN_HOLDOUT_PROFIT_FACTOR_LIVE_REVIEW, "holdout live-review PF below 1.15"),
        (overall["expectancy_percent"] > 0, "overall expectancy is not positive"),
        (overall["max_drawdown_percent"] <= MAX_DRAWDOWN_PERCENT_LIVE_REVIEW, "drawdown exceeds live-review limit"),
        (
            profitable_segments >= MIN_PROFITABLE_SEGMENTS_LIVE_REVIEW,
            "chronological segment stability failed",
        ),
        (source_aligned, "data source is not aligned with the target broker feed"),
    )
    live_failures.extend(reason for passed, reason in live_checks if not passed)
    return watch_failures, live_failures


def _profile_fingerprint(profile: object) -> str:
    payload = asdict(profile)
    payload["allowed_strategies"] = sorted(payload["allowed_strategies"])
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _data_fingerprint(data: pd.DataFrame) -> str:
    columns = [column for column in ("Open", "High", "Low", "Close", "Volume") if column in data]
    hashed = pd.util.hash_pandas_object(data.loc[:, columns], index=True)
    return hashlib.sha256(hashed.to_numpy().tobytes()).hexdigest()


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
) -> dict:
    symbol = normalize_symbol(symbol)
    profile = get_strategy_profile(symbol)
    source_metadata = source_metadata or get_data_source_metadata(symbol)
    data = add_indicators(df)
    train_end = int(len(data) * 0.60)
    validation_end = int(len(data) * 0.80)
    segments = (
        ("TRAIN", 0, train_end),
        ("VALIDATION", train_end, validation_end),
        ("HOLDOUT", validation_end, len(data)),
    )

    strategy_reports = []
    for strategy in sorted(profile.allowed_strategies):
        signals = generate_strategy_signals(data, symbol, strategy)
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
            len(data),
        )
        overall = calculate_metrics(all_trades)
        holdout = next(
            report["metrics"]
            for report in segment_reports
            if report["segment"] == "HOLDOUT"
        )
        profitable_segments = sum(
            1
            for report in segment_reports
            if report["metrics"]["expectancy_percent"] > 0
            and float(report["metrics"].get("profit_factor") or 0.0) > 1.0
        )
        source_aligned = bool(
            source_metadata.get("source_aligned_for_live_validation", False)
        )
        watch_failures, live_failures = _gate_requirements(
            overall,
            holdout,
            profitable_segments,
            source_aligned,
        )
        strategy_reports.append(
            {
                "strategy": strategy,
                "overall": overall,
                "segments": segment_reports,
                "profitable_segments": profitable_segments,
                "watch_ready": not watch_failures,
                "watch_failures": watch_failures,
                "live_review_ready": not live_failures,
                "live_review_failures": live_failures,
            }
        )

    # The strategy is pre-registered in the symbol profile.  Never rank or
    # select candidates with HOLDOUT metrics: doing so would turn the stated
    # untouched test set into training data and inflate reported performance.
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
    component_live_failures = _prefixed_component_failures(
        strategy_reports,
        "live_review_failures",
    )
    watch_ready = bool(strategy_reports) and not component_watch_failures
    live_review_ready = bool(strategy_reports) and not component_live_failures

    return {
        "schema_version": VALIDATION_SCHEMA_VERSION,
        "symbol": symbol,
        "status": (
            "WATCH_VALIDATION_PASSED"
            if watch_ready
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
        "config_sha256": _profile_fingerprint(profile),
        "data_sha256": _data_fingerprint(data),
        "estimated_round_trip_cost_bps": profile.estimated_round_trip_cost_bps,
        "entry_model": "signal close then next candle open",
        "position_model": "single non-overlapping position per strategy",
        "ambiguous_bar_policy": "stop first",
        "stop_atr": profile.stop_atr,
        "target_atr": profile.target_atr,
        "max_holding_bars": profile.max_holding_bars,
        "purged_segment_boundary_bars": profile.max_holding_bars,
        "right_censored_trades_included": False,
        # Kept for backward-compatible diagnostic consumers.  This now means
        # the frozen/pre-registered strategy, not a holdout-ranked winner.
        "best_strategy": selected_report["strategy"] if selected_report else None,
        "selected_strategy": selected_report["strategy"] if selected_report else None,
        "strategy_reports": strategy_reports,
        "component_gate_policy": "ALL_RUNTIME_ALLOWED_COMPONENTS_MUST_PASS",
        "component_watch_failures": component_watch_failures,
        "component_live_review_failures": component_live_failures,
        "watch_ready": watch_ready,
        "live_review_ready": live_review_ready,
        "runtime_parity_verified": False,
        "promotion_eligible": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "max_lot": 0.01,
        "notes": (
            "Strategy signals remain a vectorized component proxy, not exact "
            "runtime-selector parity. Promotion is ineligible until parity is "
            "verified. execution_policy and Phase4R remain authoritative and locked."
        ),
    }


def validate_symbol_file(symbol: str, data_dir: str | Path = "data") -> dict:
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
        report = validate_symbol_dataframe(symbol, dataframe)
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
) -> dict:
    normalized_symbols = list(
        dict.fromkeys(normalize_symbol(symbol) for symbol in symbols if symbol)
    )
    reports = [validate_symbol_file(symbol, data_dir=data_dir) for symbol in normalized_symbols]
    return {
        "schema_version": VALIDATION_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "COST_AWARE_CHRONOLOGICAL_WALK_FORWARD",
        "selection_policy": "PRE_REGISTERED_PROFILE_PREFERENCE_NO_HOLDOUT_SELECTION",
        "holdout_used_for_selection": False,
        "runtime_parity_verified": False,
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
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = build_validation_report(args.symbols, data_dir=args.data_dir)
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
