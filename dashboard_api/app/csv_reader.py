from __future__ import annotations

import asyncio
import csv
import io
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .models import Candle, MarketSeries, SourceMeta

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class CsvReadResult:
    key: str
    market: MarketSeries
    meta: SourceMeta


@dataclass(slots=True)
class _CsvCache:
    signature: tuple[int, int]
    market: MarketSeries


def _parse_datetime(value: str) -> datetime:
    normalized = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _infer_timeframe(candles: list[Candle]) -> str | None:
    if len(candles) < 2:
        return None
    minutes = round(
        (candles[-1].timestamp - candles[-2].timestamp).total_seconds() / 60
    )
    if minutes <= 0:
        return None
    return f"M{minutes}" if minutes < 60 else f"H{max(1, minutes // 60)}"


def _tail_lines(path: Path, line_count: int) -> tuple[str, list[str], tuple[int, int]]:
    before = path.stat()
    with path.open("rb") as handle:
        header = handle.readline().decode("utf-8-sig").strip()
        handle.seek(0, 2)
        end = handle.tell()
        buffer = bytearray()
        cursor = end
        while cursor > 0 and buffer.count(b"\n") <= line_count + 1:
            chunk_size = min(8192, cursor)
            cursor -= chunk_size
            handle.seek(cursor)
            buffer[:0] = handle.read(chunk_size)
        lines = buffer.decode("utf-8-sig").splitlines()
    after = path.stat()
    if (
        before.st_mtime_ns != after.st_mtime_ns
        or before.st_size != after.st_size
    ):
        raise RuntimeError("CSV berubah saat dibaca")
    data_lines = [line for line in lines if line.strip()]
    if data_lines and data_lines[0].strip() == header:
        data_lines = data_lines[1:]
    return header, data_lines[-line_count:], (after.st_mtime_ns, after.st_size)


class CsvReader:
    def __init__(self, *, stale_after_seconds: float, candle_limit: int) -> None:
        self.stale_after_seconds = stale_after_seconds
        self.candle_limit = candle_limit
        self._cache: dict[Path, _CsvCache] = {}

    @staticmethod
    def _asset_price_change(candles: list[Candle]) -> float | None:
        if len(candles) < 2 or candles[-2].close == 0:
            return None
        return ((candles[-1].close / candles[-2].close) - 1) * 100

    @staticmethod
    def _volatility(candles: list[Candle]) -> float | None:
        sample = candles[-20:]
        if not sample or sample[-1].close == 0:
            return None
        average_range = sum(candle.high - candle.low for candle in sample) / len(sample)
        return (average_range / sample[-1].close) * 100

    def _read_sync(self, key: str, path: Path) -> tuple[MarketSeries, tuple[int, int]]:
        header, lines, signature = _tail_lines(path, self.candle_limit)
        if not header:
            raise ValueError("header CSV kosong")
        fieldnames = next(csv.reader([header]))
        lookup = {name.strip().lower(): name for name in fieldnames}
        time_key = next(
            (lookup[name] for name in ("time", "timestamp", "datetime") if name in lookup),
            None,
        )
        required = {
            field: lookup.get(field)
            for field in ("open", "high", "low", "close")
        }
        if time_key is None or any(value is None for value in required.values()):
            raise ValueError("kolom waktu/OHLC tidak lengkap")
        volume_key = lookup.get("volume") or lookup.get("tick_volume")
        candles: list[Candle] = []
        reader = csv.DictReader(io.StringIO("\n".join([header, *lines])))
        for row in reader:
            try:
                candles.append(
                    Candle(
                        timestamp=_parse_datetime(row[time_key]),
                        open=float(row[required["open"]]),
                        high=float(row[required["high"]]),
                        low=float(row[required["low"]]),
                        close=float(row[required["close"]]),
                        volume=float(row.get(volume_key, 0) or 0) if volume_key else 0,
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        if not candles:
            raise ValueError("CSV tidak memiliki candle valid")
        now = datetime.now(UTC)
        latest = candles[-1].timestamp
        age = max(0.0, (now - latest).total_seconds())
        stale = age > self.stale_after_seconds
        market = MarketSeries(
            symbol=key.split(":", 1)[-1],
            timeframe=_infer_timeframe(candles),
            candles=candles,
            latest_price=candles[-1].close,
            price_change_percent=self._asset_price_change(candles),
            volatility_percent=self._volatility(candles),
            source_timestamp=latest,
            received_at=now,
            age_seconds=age,
            stale=stale,
            status="stale" if stale else "fresh",
            source_path=str(path),
        )
        return market, signature

    async def read(self, key: str, path: Path | None) -> CsvReadResult:
        now = datetime.now(UTC)
        if path is None:
            market = MarketSeries(
                symbol=key.split(":", 1)[-1],
                received_at=now,
                status="unavailable",
                stale=True,
            )
            return CsvReadResult(
                key=key,
                market=market,
                meta=SourceMeta(
                    key=key,
                    status="unavailable",
                    received_at=now,
                    stale=True,
                    error="CSV belum ditemukan",
                ),
            )
        try:
            stat = await asyncio.to_thread(path.stat)
            signature = (stat.st_mtime_ns, stat.st_size)
            cached = self._cache.get(path)
            if cached and cached.signature == signature:
                market = cached.market.model_copy(
                    update={
                        "received_at": now,
                        "age_seconds": max(
                            0.0,
                            (now - cached.market.source_timestamp).total_seconds(),
                        )
                        if cached.market.source_timestamp
                        else None,
                    }
                )
                stale = (
                    market.age_seconds is None
                    or market.age_seconds > self.stale_after_seconds
                )
                market = market.model_copy(
                    update={
                        "stale": stale,
                        "status": "stale" if stale else "fresh",
                    }
                )
            else:
                market, signature = await asyncio.to_thread(
                    self._read_sync,
                    key,
                    path,
                )
                self._cache[path] = _CsvCache(signature=signature, market=market)
            meta = SourceMeta(
                key=key,
                path=str(path),
                status=market.status,
                source_timestamp=market.source_timestamp,
                received_at=now,
                age_seconds=market.age_seconds,
                stale=market.stale,
                size_bytes=stat.st_size,
            )
            return CsvReadResult(key=key, market=market, meta=meta)
        except (OSError, RuntimeError, ValueError) as exc:
            logger.warning("%s: %s", path, exc)
            cached = self._cache.get(path)
            if cached:
                market = cached.market.model_copy(
                    update={
                        "received_at": now,
                        "stale": True,
                        "status": "partial",
                    }
                )
                return CsvReadResult(
                    key=key,
                    market=market,
                    meta=SourceMeta(
                        key=key,
                        path=str(path),
                        status="partial",
                        source_timestamp=market.source_timestamp,
                        received_at=now,
                        age_seconds=market.age_seconds,
                        stale=True,
                        from_last_known_good=True,
                        error=str(exc),
                    ),
                )
            market = MarketSeries(
                symbol=key.split(":", 1)[-1],
                received_at=now,
                stale=True,
                status="invalid",
                source_path=str(path),
            )
            return CsvReadResult(
                key=key,
                market=market,
                meta=SourceMeta(
                    key=key,
                    path=str(path),
                    status="invalid",
                    received_at=now,
                    stale=True,
                    error=str(exc),
                ),
            )
