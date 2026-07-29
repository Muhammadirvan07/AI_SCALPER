from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.cache import AsyncTTLCache
from app.core.exceptions import DataSourceUnavailableError, FileTooLargeError, InvalidDataFormatError
from app.repositories.csv_repository import CsvRepository
from app.repositories.file_registry import FileRegistry
from app.repositories.json_repository import JsonRepository


@pytest.mark.asyncio
async def test_json_repository_valid_and_cached(settings) -> None:
    repository = JsonRepository(FileRegistry(settings), settings)
    first = await repository.read("paper_orders")
    second = await repository.read("paper_orders")
    assert first.value[0]["paper_order_id"] == "ORDER-1"
    assert first.value is not second.value
    first.value.clear()
    assert len(second.value) == 3


@pytest.mark.asyncio
async def test_json_repository_missing_empty_invalid_and_too_large(settings, engine_root: Path) -> None:
    repository = JsonRepository(FileRegistry(settings), settings)
    (engine_root / "active_pairs.json").unlink()
    with pytest.raises(DataSourceUnavailableError):
        await repository.read("active_pairs")
    (engine_root / "active_pairs.json").write_text("", encoding="utf-8")
    with pytest.raises(InvalidDataFormatError):
        await repository.read("active_pairs")
    (engine_root / "active_pairs.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(InvalidDataFormatError):
        await repository.read("active_pairs")
    (engine_root / "active_pairs.json").write_text(
        json.dumps({"data": "x" * settings.max_json_bytes}), encoding="utf-8"
    )
    with pytest.raises(FileTooLargeError):
        await repository.read("active_pairs")


@pytest.mark.asyncio
async def test_json_repository_last_known_good_after_temporary_corruption(settings, engine_root: Path) -> None:
    repository = JsonRepository(FileRegistry(settings), settings)
    first = await repository.read("active_pairs")
    (engine_root / "active_pairs.json").write_text("{temporarily invalid", encoding="utf-8")
    await repository.invalidate("active_pairs")
    fallback = await repository.read("active_pairs")
    assert fallback.value == first.value
    assert fallback.from_last_known_good is True
    assert fallback.stale is True


@pytest.mark.asyncio
async def test_json_repository_retries_unstable_read(monkeypatch, settings) -> None:
    repository = JsonRepository(FileRegistry(settings), settings)
    original = repository._read_sync
    calls = 0

    def unstable(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("changed while being read")
        return original(*args, **kwargs)

    monkeypatch.setattr(repository, "_read_sync", unstable)
    result = await repository.read("active_pairs")
    assert result.value["active_pairs"] == ["EURUSD"]
    assert calls == 2


def test_file_registry_prevents_path_traversal(settings) -> None:
    registry = FileRegistry(settings)
    with pytest.raises(ValueError):
        registry.csv_path("../../etc/passwd")
    assert registry.symbols() == ["EURUSD", "GBPUSD"]


@pytest.mark.asyncio
async def test_csv_repository_reads_resamples_and_reports_resolution(settings) -> None:
    repository = CsvRepository(FileRegistry(settings), settings)
    m15 = await repository.read_candles("EURUSD", "M15", 10)
    h1 = await repository.read_candles("EURUSD", "H1", 10)
    m1 = await repository.read_candles("EURUSD", "M1", 10)
    assert len(m15.series.candles) == 10
    assert h1.series.derived is True
    assert h1.series.actual_timeframe == "H1"
    assert m1.series.actual_timeframe == "M15"
    assert m1.series.resolution_warning


@pytest.mark.asyncio
async def test_csv_last_known_good_survives_watcher_invalidation(settings, engine_root: Path) -> None:
    repository = CsvRepository(FileRegistry(settings), settings)
    first = await repository.read_candles("EURUSD", "M15", 2)
    (engine_root / "data" / "eurusd.csv").write_text("broken", encoding="utf-8")
    await repository.invalidate("EURUSD")
    fallback = await repository.read_candles("EURUSD", "M15", 2)
    assert fallback.from_last_known_good is True
    assert fallback.series.candles == first.series.candles


@pytest.mark.asyncio
async def test_async_ttl_cache_deep_copy_and_invalidation() -> None:
    cache = AsyncTTLCache()
    calls = 0

    async def loader():
        nonlocal calls
        calls += 1
        return {"items": [1]}

    first = await cache.get_or_load("one", 30, loader)
    first["items"].append(2)
    second = await cache.get_or_load("one", 30, loader)
    assert second == {"items": [1]}
    assert calls == 1
    await cache.invalidate("one")
    await cache.get_or_load("one", 30, loader)
    assert calls == 2
