from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from app.core.cache import AsyncTTLCache
from app.core.config import Settings

from .news_service import NewsService

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class NewsSchedulerState:
    running: bool = False
    initial_refresh_complete: bool = False
    last_run_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None
    consecutive_failures: int = 0


class NewsScheduler:
    def __init__(self, settings: Settings, service: NewsService, cache: AsyncTTLCache | None = None) -> None:
        self.settings = settings
        self.service = service
        self.cache = cache
        self.state = NewsSchedulerState()
        self._task: asyncio.Task[None] | None = None
        self._refresh_lock = asyncio.Lock()

    async def start(self) -> None:
        if self.state.running:
            return
        self.state.running = True
        self.service.scheduler_running = True
        self._task = asyncio.create_task(self._run(), name="news-intelligence-scheduler")
        logger.info("News scheduler started", extra={"event": "news.scheduler_started"})

    async def stop(self) -> None:
        self.state.running = False
        self.service.scheduler_running = False
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        self._task = None

    async def refresh_now(self, *, force: bool = True, provider_names: list[str] | None = None) -> dict[str, int]:
        if self._refresh_lock.locked():
            return {
                "articles": len(self.service.articles_copy()),
                "created": 0,
                "calendar": len(self.service.calendar.events_copy()),
            }
        async with self._refresh_lock:
            self.state.last_run_at = datetime.now(UTC)
            try:
                async with asyncio.timeout(
                    self.settings.news_request_timeout_seconds * max(1, len(self.service.providers.providers)) + 5
                ):
                    result = await self.service.refresh(force=force, provider_names=provider_names)
                if self.cache:
                    await self.cache.invalidate("news:")
                self.state.last_success_at = datetime.now(UTC)
                self.state.last_error = None
                self.state.consecutive_failures = 0
                return result
            except (TimeoutError, OSError, RuntimeError) as exc:
                self.state.last_error = f"{type(exc).__name__}: {exc}"
                self.state.consecutive_failures += 1
                logger.warning(
                    "News refresh failed", extra={"event": "news.refresh_failed", "error_type": type(exc).__name__}
                )
                return {
                    "articles": len(self.service.articles_copy()),
                    "created": 0,
                    "calendar": len(self.service.calendar.events_copy()),
                }
            finally:
                self.state.initial_refresh_complete = True

    async def _run(self) -> None:
        try:
            while self.state.running:
                await self.refresh_now(force=False)
                base = self.settings.news_global_refresh_interval_seconds
                backoff = min(base * 4, base * (2 ** min(self.state.consecutive_failures, 3)))
                jitter = min(5.0, backoff * (0.025 if self.state.consecutive_failures % 2 else 0.05))
                await asyncio.sleep(backoff + jitter)
        except asyncio.CancelledError:
            return
