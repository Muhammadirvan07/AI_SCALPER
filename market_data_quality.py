"""Shared market-data quality guards for decision and validation paths."""

from __future__ import annotations

import re
from datetime import timedelta

import pandas as pd


DEFAULT_TIMEFRAME = "15min"
TIMESTAMP_COLUMNS = ("Datetime", "datetime", "Timestamp", "timestamp", "Date", "date")


def _parse_timeframe(value: str) -> timedelta:
    match = re.fullmatch(
        r"\s*(\d+(?:\.\d+)?)\s*(s|sec|m|min|h|hr|d|day)\s*",
        str(value).lower(),
    )
    if not match:
        raise ValueError(f"unsupported timeframe: {value}")

    amount = float(match.group(1))
    unit = match.group(2)
    if amount <= 0:
        raise ValueError("timeframe must be positive")
    if unit in {"s", "sec"}:
        return timedelta(seconds=amount)
    if unit in {"m", "min"}:
        return timedelta(minutes=amount)
    if unit in {"h", "hr"}:
        return timedelta(hours=amount)
    return timedelta(days=amount)


def _utc_timestamp(value=None) -> pd.Timestamp:
    timestamp = pd.Timestamp.now(tz="UTC") if value is None else pd.Timestamp(value)
    if timestamp.tzinfo is None:
        return timestamp.tz_localize("UTC")
    return timestamp.tz_convert("UTC")


def _extract_timestamps(df: pd.DataFrame) -> pd.Series | pd.DatetimeIndex | None:
    if isinstance(df.index, pd.DatetimeIndex):
        return pd.to_datetime(df.index, errors="coerce", utc=True)

    for column in TIMESTAMP_COLUMNS:
        if column in df.columns:
            return pd.to_datetime(df[column], errors="coerce", utc=True)

    return None


def keep_completed_candles(
    df: pd.DataFrame,
    timeframe: str = DEFAULT_TIMEFRAME,
    now=None,
    finalization_lag: str = "0min",
) -> tuple[pd.DataFrame, bool]:
    """Drop a latest candle that is not safely finalized yet.

    ``finalization_lag`` lets provider-backed collectors wait beyond the
    nominal close.  Some vendors revise the just-closed bar for several
    minutes; backtests and decisions must not ingest that moving target.

    Timestamp-free frames are returned unchanged because their completion
    state cannot be proven. Callers that require broker-grade evidence must
    enforce timestamp provenance separately.
    """

    if not isinstance(df, pd.DataFrame):
        raise TypeError("market data must be a pandas DataFrame")
    if df.empty:
        return df.copy(), False

    timestamps = _extract_timestamps(df)
    if timestamps is None:
        return df.copy(), False
    if bool(pd.isna(timestamps).any()):
        raise ValueError("market data contains invalid timestamps")
    if bool(timestamps.duplicated().any()):
        raise ValueError("market data contains duplicate timestamps")
    if not timestamps.is_monotonic_increasing:
        raise ValueError("market data timestamps are not increasing")

    interval = _parse_timeframe(timeframe)
    lag = _parse_timeframe(finalization_lag) if finalization_lag != "0min" else timedelta(0)

    evaluation_time = _utc_timestamp(now)
    completion_times = pd.DatetimeIndex(timestamps) + pd.Timedelta(interval + lag)
    safe_mask = completion_times <= evaluation_time
    safe_positions = [position for position, is_safe in enumerate(safe_mask) if is_safe]
    dropped = len(safe_positions) != len(df)
    if dropped:
        return df.iloc[safe_positions].copy(), True

    return df.copy(), False
