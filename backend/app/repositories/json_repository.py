from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.config import Settings
from app.core.exceptions import DataSourceUnavailableError, FileTooLargeError, InvalidDataFormatError
from app.utils.datetime import parse_datetime

from .file_registry import FileRegistry

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class RepositoryResult:
    key: str
    value: Any
    path: Path
    source_updated_at: datetime | None
    received_at: datetime
    size_bytes: int
    stale: bool = False
    from_last_known_good: bool = False
    error: str | None = None


@dataclass(slots=True)
class _CachedValue:
    signature: tuple[int, int]
    value: Any
    source_updated_at: datetime | None
    size_bytes: int


class JsonRepository:
    def __init__(self, registry: FileRegistry, settings: Settings) -> None:
        self.registry = registry
        self.settings = settings
        self._cache: dict[str, _CachedValue] = {}
        self._last_good: dict[str, _CachedValue] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self.last_successful_read: datetime | None = None
        self.error_count = 0

    async def read(self, key: str, validator: Callable[[Any], bool] | None = None) -> RepositoryResult:
        path = self.registry.json_path(key)
        if path is None:
            raise DataSourceUnavailableError(f"Unknown data source: {key}")
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            for attempt in range(self.settings.file_read_retries):
                try:
                    result = await asyncio.to_thread(self._read_sync, key, path, validator)
                    self.last_successful_read = result.received_at
                    return result
                except (json.JSONDecodeError, UnicodeDecodeError, RuntimeError, OSError) as exc:
                    if attempt + 1 < self.settings.file_read_retries:
                        await asyncio.sleep(self.settings.file_read_retry_delay_seconds * (attempt + 1))
                        continue
                    return self._fallback_or_raise(key, path, exc)
                except (FileTooLargeError, InvalidDataFormatError):
                    raise
        raise DataSourceUnavailableError(f"Unable to read {path.name}")

    def _read_sync(self, key: str, path: Path, validator: Callable[[Any], bool] | None) -> RepositoryResult:
        before = path.stat()
        if before.st_size == 0:
            raise InvalidDataFormatError(f"{path.name} is empty")
        if before.st_size > self.settings.max_json_bytes:
            raise FileTooLargeError(f"{path.name} exceeds maximum size", details={"size": before.st_size})
        signature = (before.st_mtime_ns, before.st_size)
        cached = self._cache.get(key)
        if cached and cached.signature == signature:
            return RepositoryResult(
                key, deepcopy(cached.value), path, cached.source_updated_at, datetime.now(UTC), cached.size_bytes
            )
        with path.open("r", encoding="utf-8-sig") as handle:
            value = json.load(handle)
        after = path.stat()
        if signature != (after.st_mtime_ns, after.st_size):
            raise RuntimeError("source changed while being read")
        if validator and not validator(value):
            raise InvalidDataFormatError(f"{path.name} failed validation")
        source_time = self._source_timestamp(value) or datetime.fromtimestamp(after.st_mtime, UTC)
        cached_value = _CachedValue(signature, deepcopy(value), source_time, after.st_size)
        self._cache[key] = cached_value
        self._last_good[key] = cached_value
        return RepositoryResult(key, deepcopy(value), path, source_time, datetime.now(UTC), after.st_size)

    def _fallback_or_raise(self, key: str, path: Path, exc: Exception) -> RepositoryResult:
        self.error_count += 1
        logger.warning(
            "JSON read failed", extra={"event": "json.read_failed", "source": key, "error_type": type(exc).__name__}
        )
        cached = self._last_good.get(key)
        if cached:
            return RepositoryResult(
                key,
                deepcopy(cached.value),
                path,
                cached.source_updated_at,
                datetime.now(UTC),
                cached.size_bytes,
                True,
                True,
                str(exc),
            )
        if isinstance(exc, FileNotFoundError):
            raise DataSourceUnavailableError(f"{path.name} is unavailable") from exc
        raise InvalidDataFormatError(f"{path.name} is temporarily invalid", details=str(exc)) from exc

    @staticmethod
    def _source_timestamp(value: Any) -> datetime | None:
        if not isinstance(value, dict):
            return None
        for key in ("generated_at", "updated_at", "last_updated", "timestamp", "created_at"):
            if parsed := parse_datetime(value.get(key)):
                return parsed
        return None

    async def invalidate(self, key: str | None = None) -> None:
        if key is None:
            self._cache.clear()
        else:
            self._cache.pop(key, None)
