from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from time import monotonic

from pydantic import ValidationError

from app.core.config import Settings
from app.providers.economic_calendar.base import EconomicCalendarCollection
from app.providers.economic_calendar.registry import EconomicCalendarProviderRegistry
from app.schemas.economic_calendar import EconomicCalendarEvent

logger = logging.getLogger(__name__)


class EconomicCalendarRepository:
    """Async-safe source repository with last-known-good and optional atomic persistence."""

    def __init__(self, settings: Settings, providers: EconomicCalendarProviderRegistry) -> None:
        self.settings = settings
        self.providers = providers
        self.last_error: str | None = None
        self.last_collection = EconomicCalendarCollection()
        self.last_release_checks: dict[str, dict[str, object]] = {}
        self._persist_lock = asyncio.Lock()
        self._persist_path = settings.economic_calendar_cache_path

    @property
    def configured(self) -> bool:
        return self.providers.configured

    async def fetch(
        self,
        *,
        start_time: datetime,
        end_time: datetime,
        currencies: list[str] | None = None,
        provider_names: list[str] | None = None,
        force: bool = False,
    ) -> list[tuple[str, dict]]:
        self.last_collection = await self.providers.collect(
            start_time=start_time,
            end_time=end_time,
            currencies=currencies,
            provider_names=provider_names,
            force=force,
        )
        failures = self.last_collection.providers_failed + self.last_collection.providers_rate_limited
        self.last_error = (
            f"Calendar sources unavailable: {', '.join(failures)}"
            if failures and not self.last_collection.items
            else None
        )
        return [(provider, dict(row)) for provider, row in self.last_collection.items]

    async def fetch_release(self, event: EconomicCalendarEvent) -> dict | None:
        checked_at = datetime.now(UTC)
        started = monotonic()
        raw = event.model_dump(mode="python")
        release = await self.providers.fetch_release(event.provider, raw)
        status = self.providers.status(event.provider)
        self.last_release_checks[event.id] = {
            "checked_at": checked_at,
            "http_status": status.last_status_code if status else None,
            "latency_ms": (monotonic() - started) * 1000,
            "error": status.last_error if status and not status.healthy else None,
            # Fetch/update time must never be presented as official publication time.
            "source_updated": (release or {}).get("source_published_at"),
        }
        return release

    async def load(self) -> list[EconomicCalendarEvent]:
        path = self._persist_path
        if path is None or not path.is_file():
            return []
        try:
            size = await asyncio.to_thread(lambda: path.stat().st_size)
            if size > self.settings.economic_calendar_max_response_bytes:
                raise ValueError("Economic calendar cache exceeds the configured size limit")
            payload = json.loads(await asyncio.to_thread(path.read_text, encoding="utf-8"))
            rows = payload.get("events", []) if isinstance(payload, dict) else []
            if not isinstance(rows, list):
                raise ValueError("Economic calendar cache events must be an array")
            return [EconomicCalendarEvent.model_validate(item) for item in rows]
        except (OSError, ValueError, json.JSONDecodeError, ValidationError) as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "Economic calendar cache load failed",
                extra={"event": "calendar.cache_load_failed", "error_type": type(exc).__name__},
            )
            return []

    async def persist(self, events: list[EconomicCalendarEvent]) -> None:
        if self._persist_path is None:
            return
        async with self._persist_lock:
            payload = {
                "generated_at": datetime.now(UTC).isoformat(),
                "source": "AI_SCALPER Economic Calendar cache",
                "events": [event.model_dump(mode="json") for event in events],
            }
            encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            if len(encoded.encode("utf-8")) > self.settings.economic_calendar_max_response_bytes:
                return
            path = self._persist_path
            temp = path.with_suffix(f"{path.suffix}.tmp")
            await asyncio.to_thread(path.parent.mkdir, parents=True, exist_ok=True)
            await asyncio.to_thread(temp.write_text, encoded, encoding="utf-8")
            await asyncio.to_thread(temp.replace, path)
