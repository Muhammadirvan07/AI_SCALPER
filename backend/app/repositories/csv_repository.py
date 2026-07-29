from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

import pandas as pd

from app.core.config import Settings
from app.core.exceptions import FileTooLargeError, MarketDataUnavailableError
from app.schemas.market import Candle, CandleSeries

from .file_registry import FileRegistry


@dataclass(slots=True)
class CsvResult:
    series: CandleSeries
    path: Path
    source_updated_at: datetime | None
    received_at: datetime
    size_bytes: int
    stale: bool = False
    from_last_known_good: bool = False
    error: str | None = None


@dataclass(slots=True)
class _CsvCache:
    signature: tuple[int, int]
    frame: pd.DataFrame


class CsvRepository:
    _RULES: ClassVar[dict[str, str]] = {"M30": "30min", "H1": "1h", "H4": "4h", "D1": "1D"}

    def __init__(self, registry: FileRegistry, settings: Settings) -> None:
        self.registry = registry
        self.settings = settings
        self._cache: dict[str, _CsvCache] = {}
        self._last_good: dict[str, _CsvCache] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def read_candles(self, symbol: str, timeframe: str, limit: int) -> CsvResult:
        path = self.registry.csv_path(symbol)
        lock = self._locks.setdefault(symbol, asyncio.Lock())
        async with lock:
            error: str | None
            try:
                frame = await asyncio.to_thread(self._frame, symbol, path)
            except (OSError, ValueError, pd.errors.ParserError) as exc:
                cached = self._last_good.get(symbol)
                if not cached:
                    raise MarketDataUnavailableError(f"Market data unavailable for {symbol}", details=str(exc)) from exc
                frame = cached.frame.copy(deep=True)
                fallback = True
                error = str(exc)
            else:
                fallback = False
                error = None
            source_frame = frame
            actual = "M15"
            derived = False
            warning = None
            if timeframe in self._RULES:
                source_frame = self._resample(frame, self._RULES[timeframe])
                actual, derived = timeframe, True
            elif timeframe in {"M1", "M5"}:
                warning = (
                    f"Source only provides M15 candles; {timeframe} cannot be reconstructed without fabricating data."
                )
            source_frame = source_frame.tail(limit)
            candles = [
                Candle(
                    timestamp=pd.Timestamp(str(index)).to_pydatetime(),
                    open=float(row.Open),
                    high=float(row.High),
                    low=float(row.Low),
                    close=float(row.Close),
                    volume=float(row.Volume),
                )
                for index, row in source_frame.iterrows()
            ]
            latest = candles[-1].timestamp if candles else None
            now = datetime.now(UTC)
            stale = latest is None or (now - latest).total_seconds() > 10
            stat = await asyncio.to_thread(path.stat)
            return CsvResult(
                CandleSeries(
                    symbol=symbol,
                    requested_timeframe=timeframe,
                    actual_timeframe=actual,
                    derived=derived,
                    candles=candles,
                    resolution_warning=warning,
                ),
                path,
                latest,
                now,
                stat.st_size,
                stale,
                fallback,
                error,
            )

    def _frame(self, symbol: str, path: Path) -> pd.DataFrame:
        stat_before = path.stat()
        if stat_before.st_size > self.settings.max_csv_bytes:
            raise FileTooLargeError(f"{path.name} exceeds maximum size")
        signature = (stat_before.st_mtime_ns, stat_before.st_size)
        cached = self._cache.get(symbol)
        if cached and cached.signature == signature:
            return cached.frame.copy(deep=True)
        frame = pd.read_csv(path)
        lookup = {str(column).lower(): column for column in frame.columns}
        time_col = next((lookup[key] for key in ("datetime", "timestamp", "time") if key in lookup), None)
        required = {name: lookup.get(name.lower()) for name in ("Open", "High", "Low", "Close")}
        if time_col is None or any(value is None for value in required.values()):
            raise ValueError("CSV must contain timestamp and OHLC columns")
        frame[time_col] = pd.to_datetime(frame[time_col], utc=True, errors="coerce", format="mixed")
        frame = frame.dropna(subset=[time_col]).set_index(time_col).sort_index()
        renamed = {required[name]: name for name in required}
        volume_col = lookup.get("volume") or lookup.get("tick_volume")
        if volume_col:
            renamed[volume_col] = "Volume"
        frame = frame.rename(columns=renamed)
        if "Volume" not in frame:
            frame["Volume"] = 0.0
        frame = (
            frame[["Open", "High", "Low", "Close", "Volume"]]
            .apply(pd.to_numeric, errors="coerce")
            .dropna(subset=["Open", "High", "Low", "Close"])
        )
        stat_after = path.stat()
        if signature != (stat_after.st_mtime_ns, stat_after.st_size):
            raise RuntimeError("CSV changed while being read")
        if frame.empty:
            raise ValueError("CSV contains no valid candles")
        cached_frame = _CsvCache(signature, frame.copy(deep=True))
        self._cache[symbol] = cached_frame
        self._last_good[symbol] = cached_frame
        return frame

    @staticmethod
    def _resample(frame: pd.DataFrame, rule: str) -> pd.DataFrame:
        return (
            frame.resample(rule)
            .agg({"Open": "first", "High": "max", "Low": "min", "Close": "last", "Volume": "sum"})
            .dropna(subset=["Open", "High", "Low", "Close"])
        )

    async def invalidate(self, symbol: str | None = None) -> None:
        if symbol is None:
            self._cache.clear()
        else:
            self._cache.pop(symbol, None)
