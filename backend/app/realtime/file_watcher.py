from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import Settings
from app.repositories.file_registry import FileRegistry

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class FileWatcherState:
    running: bool = False
    last_scan: datetime | None = None
    last_event: datetime | None = None
    last_error: str | None = None


class AsyncFileWatcher:
    def __init__(
        self, settings: Settings, registry: FileRegistry, on_change: Callable[[str, Path], Awaitable[None]]
    ) -> None:
        self.settings = settings
        self.registry = registry
        self.on_change = on_change
        self.state = FileWatcherState()
        self._task: asyncio.Task[None] | None = None
        self._signatures: dict[str, tuple[int, int] | None] = {}

    async def start(self) -> None:
        self._signatures = await asyncio.to_thread(self._scan)
        self.state.running = True
        self._task = asyncio.create_task(self._loop(), name="file-watcher")
        logger.info("File watcher started", extra={"event": "file_watcher.started", "sources": len(self._signatures)})

    async def stop(self) -> None:
        self.state.running = False
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)

    async def scan_now(self) -> None:
        await self._check_changes(force=True)

    def _scan(self) -> dict[str, tuple[int, int] | None]:
        result: dict[str, tuple[int, int] | None] = {}
        for key, path in self.registry.watched_paths().items():
            try:
                stat = path.stat()
                result[key] = (stat.st_mtime_ns, stat.st_size)
            except OSError:
                result[key] = None
        return result

    async def _loop(self) -> None:
        try:
            while self.state.running:
                await asyncio.sleep(self.settings.file_watch_interval_seconds)
                await self._check_changes()
        except asyncio.CancelledError:
            return

    async def _check_changes(self, force: bool = False) -> None:
        try:
            current = await asyncio.to_thread(self._scan)
            self.state.last_scan = datetime.now(UTC)
            changed = [key for key, signature in current.items() if force or self._signatures.get(key) != signature]
            self._signatures = current
            for key in changed:
                path = self.registry.watched_paths().get(key)
                if path is None:
                    continue
                if not force and self.settings.file_watch_debounce_seconds:
                    await asyncio.sleep(self.settings.file_watch_debounce_seconds)
                    stable = await asyncio.to_thread(self._stable_signature, path)
                    if stable != current.get(key):
                        continue
                await self.on_change(key, path)
                self.state.last_event = datetime.now(UTC)
                logger.info("File updated", extra={"event": "file.updated", "source": key})
            self.state.last_error = None
        except (OSError, RuntimeError) as exc:
            self.state.last_error = str(exc)
            logger.warning(
                "File watcher scan failed",
                extra={"event": "file_watcher.scan_failed", "error_type": type(exc).__name__},
            )

    @staticmethod
    def _stable_signature(path: Path) -> tuple[int, int] | None:
        try:
            stat = path.stat()
            return stat.st_mtime_ns, stat.st_size
        except OSError:
            return None
