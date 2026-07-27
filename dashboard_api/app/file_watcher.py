from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

from .config import Settings
from .file_registry import FileRegistry
from .models import DashboardSnapshot
from .snapshot_builder import SnapshotBuilder

logger = logging.getLogger(__name__)
Signature = tuple[int, int] | None


class AsyncFileWatcher:
    def __init__(
        self,
        *,
        settings: Settings,
        registry: FileRegistry,
        builder: SnapshotBuilder,
        on_snapshot: Callable[
            [DashboardSnapshot, DashboardSnapshot | None],
            Awaitable[None],
        ],
    ) -> None:
        self.settings = settings
        self.registry = registry
        self.builder = builder
        self.on_snapshot = on_snapshot
        self._signatures: dict[str, Signature] = {}
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._last_discovery = 0.0

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    @staticmethod
    def _signature(path: Path | None) -> Signature:
        if path is None:
            return None
        try:
            stat = path.stat()
            return stat.st_mtime_ns, stat.st_size
        except OSError:
            return None

    def capture_signatures(self) -> None:
        self._signatures = {
            key: self._signature(source.path)
            for key, source in self.registry.all_sources().items()
        }

    def _freshness_transition_due(self) -> bool:
        return self.builder.source_freshness_transition_due()

    def _remote_news_due(self) -> bool:
        return self.builder.news_provider.due()

    async def _poll_once(self) -> None:
        now = time.monotonic()
        registry_changed = False
        if now - self._last_discovery >= self.settings.discovery_refresh_seconds:
            registry_changed = await asyncio.to_thread(self.registry.refresh)
            self._last_discovery = now
        current = {
            key: self._signature(source.path)
            for key, source in self.registry.all_sources().items()
        }
        changed = {
            key
            for key in set(self._signatures) | set(current)
            if self._signatures.get(key) != current.get(key)
        }
        if registry_changed:
            changed.update(set(current) - set(self._signatures))
        if self._remote_news_due():
            changed.add("news_remote")
        if not changed and not self._freshness_transition_due():
            return
        if self.settings.debounce_ms:
            await asyncio.sleep(self.settings.debounce_ms / 1000)
            current = {
                key: self._signature(source.path)
                for key, source in self.registry.all_sources().items()
            }
            changed.update(
                key
                for key in set(self._signatures) | set(current)
                if self._signatures.get(key) != current.get(key)
            )
        self._signatures = current
        previous = self.builder.latest_snapshot
        snapshot, meaningful = await self.builder.rebuild(
            changed,
            watcher_running=True,
        )
        if meaningful:
            await self.on_snapshot(snapshot, previous)

    async def _run(self) -> None:
        logger.info(
            "File watcher aktif: interval=%.2fs debounce=%dms",
            self.settings.watch_interval_seconds,
            self.settings.debounce_ms,
        )
        try:
            while not self._stop.is_set():
                try:
                    await self._poll_once()
                except Exception:
                    logger.exception("File watcher gagal memproses satu siklus")
                try:
                    await asyncio.wait_for(
                        self._stop.wait(),
                        timeout=self.settings.watch_interval_seconds,
                    )
                except TimeoutError:
                    continue
        finally:
            logger.info("File watcher berhenti")

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self.capture_signatures()
        self._task = asyncio.create_task(self._run(), name="dashboard-file-watcher")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            await self._task
            self._task = None
