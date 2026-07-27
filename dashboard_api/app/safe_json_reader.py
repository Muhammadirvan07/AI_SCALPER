from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import SourceMeta, SourceState

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class JsonReadResult:
    key: str
    value: Any
    meta: SourceMeta


@dataclass(slots=True)
class _KnownGood:
    value: Any
    source_timestamp: datetime
    size_bytes: int


class SafeJsonReader:
    def __init__(
        self,
        *,
        stale_after_seconds: float,
        max_bytes: int,
        retries: int = 3,
        retry_delay_seconds: float = 0.06,
    ) -> None:
        self.stale_after_seconds = stale_after_seconds
        self.max_bytes = max_bytes
        self.retries = max(1, retries)
        self.retry_delay_seconds = retry_delay_seconds
        self._last_known_good: dict[Path, _KnownGood] = {}
        self._last_logged_error: dict[Path, str] = {}

    @staticmethod
    def _now() -> datetime:
        return datetime.now(UTC)

    def _meta(
        self,
        *,
        key: str,
        path: Path | None,
        status: SourceState,
        source_timestamp: datetime | None,
        size_bytes: int | None,
        from_last_known_good: bool = False,
        error: str | None = None,
    ) -> SourceMeta:
        now = self._now()
        age = (
            max(0.0, (now - source_timestamp).total_seconds())
            if source_timestamp
            else None
        )
        stale = age is None or age > self.stale_after_seconds
        resolved_status: SourceState = "stale" if status == "fresh" and stale else status
        return SourceMeta(
            key=key,
            path=str(path) if path else None,
            status=resolved_status,
            source_timestamp=source_timestamp,
            received_at=now,
            age_seconds=age,
            stale=stale,
            size_bytes=size_bytes,
            from_last_known_good=from_last_known_good,
            error=error,
        )

    def _fallback(
        self,
        key: str,
        path: Path | None,
        *,
        status: SourceState,
        error: str,
    ) -> JsonReadResult:
        known = self._last_known_good.get(path) if path else None
        if known:
            meta = self._meta(
                key=key,
                path=path,
                status="partial" if status == "invalid" else "stale",
                source_timestamp=known.source_timestamp,
                size_bytes=known.size_bytes,
                from_last_known_good=True,
                error=error,
            )
            return JsonReadResult(key=key, value=known.value, meta=meta)
        return JsonReadResult(
            key=key,
            value=None,
            meta=self._meta(
                key=key,
                path=path,
                status=status,
                source_timestamp=None,
                size_bytes=None,
                error=error,
            ),
        )

    def _log_once(self, path: Path, message: str) -> None:
        if self._last_logged_error.get(path) == message:
            return
        self._last_logged_error[path] = message
        logger.warning("%s: %s", path, message)

    @staticmethod
    def _read_once(path: Path, max_bytes: int) -> tuple[Any, datetime, int]:
        before = path.stat()
        if before.st_size == 0:
            raise ValueError("file kosong")
        if before.st_size > max_bytes:
            raise ValueError(
                f"ukuran {before.st_size} byte melebihi batas {max_bytes} byte"
            )
        with path.open("r", encoding="utf-8") as handle:
            raw = handle.read(max_bytes + 1)
        after = path.stat()
        if (
            before.st_mtime_ns != after.st_mtime_ns
            or before.st_size != after.st_size
        ):
            raise RuntimeError("file berubah saat dibaca")
        value = json.loads(raw)
        source_timestamp = datetime.fromtimestamp(after.st_mtime, tz=UTC)
        return value, source_timestamp, after.st_size

    async def read(self, key: str, path: Path | None) -> JsonReadResult:
        if path is None:
            return self._fallback(
                key,
                None,
                status="unavailable",
                error="file belum ditemukan",
            )

        for attempt in range(self.retries):
            try:
                value, source_timestamp, size_bytes = await asyncio.to_thread(
                    self._read_once,
                    path,
                    self.max_bytes,
                )
                self._last_known_good[path] = _KnownGood(
                    value=value,
                    source_timestamp=source_timestamp,
                    size_bytes=size_bytes,
                )
                if path in self._last_logged_error:
                    logger.info("Sumber pulih: %s", path)
                    self._last_logged_error.pop(path, None)
                return JsonReadResult(
                    key=key,
                    value=value,
                    meta=self._meta(
                        key=key,
                        path=path,
                        status="fresh",
                        source_timestamp=source_timestamp,
                        size_bytes=size_bytes,
                    ),
                )
            except FileNotFoundError:
                return self._fallback(
                    key,
                    path,
                    status="unavailable",
                    error="file berpindah atau tidak tersedia",
                )
            except PermissionError:
                message = "izin baca ditolak"
                self._log_once(path, message)
                return self._fallback(
                    key,
                    path,
                    status="unavailable",
                    error=message,
                )
            except (json.JSONDecodeError, UnicodeDecodeError, RuntimeError) as exc:
                message = f"pembacaan belum stabil: {exc}"
                if attempt + 1 < self.retries:
                    await asyncio.sleep(self.retry_delay_seconds * (attempt + 1))
                    continue
                self._log_once(path, message)
                return self._fallback(
                    key,
                    path,
                    status="invalid",
                    error=message,
                )
            except (OSError, ValueError) as exc:
                message = str(exc)
                self._log_once(path, message)
                return self._fallback(
                    key,
                    path,
                    status="invalid",
                    error=message,
                )

        return self._fallback(
            key,
            path,
            status="invalid",
            error="gagal membaca file",
        )
