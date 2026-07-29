from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.adapters.economic_calendar_adapter import EconomicCalendarAdapter
from app.core.config import Settings
from app.core.exceptions import InvalidDataFormatError, ResourceNotFoundError
from app.realtime.event_bus import EventBus
from app.realtime.events import InternalEvent
from app.repositories.economic_calendar_repository import EconomicCalendarRepository
from app.schemas.common import ApiMeta
from app.schemas.economic_calendar import (
    EconomicCalendarEvent,
    EconomicCalendarHealth,
    EconomicCalendarPage,
    EconomicCalendarRuntimeStatus,
    EconomicEventStatus,
    EconomicImpact,
    ScheduleHistoryEntry,
)
from app.utils.datetime import parse_datetime

from .base import ServicePayload
from .economic_calendar_guard_service import EconomicCalendarGuardService
from .economic_calendar_observability import EconomicCalendarObservability

logger = logging.getLogger(__name__)


class EconomicCalendarService:
    def __init__(
        self,
        settings: Settings,
        repository: EconomicCalendarRepository,
        adapter: EconomicCalendarAdapter,
        known_symbols,
        event_bus: EventBus | None = None,
        guard: EconomicCalendarGuardService | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings
        self.repository = repository
        self.adapter = adapter
        self.known_symbols = known_symbols
        self.event_bus = event_bus
        self.guard = guard or EconomicCalendarGuardService()
        self._clock = clock or (lambda: datetime.now(UTC))
        self.observability = EconomicCalendarObservability()
        self._events: dict[str, EconomicCalendarEvent] = {}
        self._lock = asyncio.Lock()
        self._initialized = False
        self.last_refresh_at: datetime | None = None
        self.last_success_at: datetime | None = None
        self.last_schedule_sync_at: datetime | None = None
        self.invalid_count = 0
        self.scheduler_running = False
        self.scheduler_mode = "NORMAL"
        self.active_interval_seconds = settings.economic_calendar_sync_interval_seconds
        self.next_sync_at: datetime | None = None

    async def initialize(self) -> None:
        cached = await self.repository.load()
        if not cached:
            return
        async with self._lock:
            self._events = {event.id: event for event in cached}
            self.last_success_at = max((event.updated_at for event in cached), default=None)
            self._initialized = True
        logger.info(
            "Economic calendar last-known-good cache loaded",
            extra={"event": "calendar.cache_loaded", "event_count": len(cached)},
        )

    async def refresh(
        self,
        *,
        force: bool = False,
        provider_names: list[str] | None = None,
        schedule: bool = True,
        releases: bool = True,
        now: datetime | None = None,
    ) -> tuple[list[EconomicCalendarEvent], list[EconomicCalendarEvent]]:
        if not self.settings.economic_calendar_enabled:
            self.last_refresh_at = datetime.now(UTC)
            return self.events_copy(), []
        now = (now or datetime.now(UTC)).astimezone(UTC)
        async with self._lock:
            created: list[EconomicCalendarEvent] = []
            updated: list[EconomicCalendarEvent] = []
            rescheduled: list[EconomicCalendarEvent] = []
            cancelled: list[EconomicCalendarEvent] = []
            schedule_due = schedule and (
                force
                or self.last_schedule_sync_at is None
                or now - self.last_schedule_sync_at >= timedelta(seconds=self.active_interval_seconds)
            )
            if schedule_due:
                raw_rows = await self.repository.fetch(
                    start_time=now - timedelta(days=1),
                    end_time=now + timedelta(days=self.settings.economic_calendar_retention_days),
                    provider_names=provider_names,
                    force=force,
                )
                normalized: list[EconomicCalendarEvent] = []
                symbols = self.known_symbols()
                for provider, raw in raw_rows:
                    try:
                        normalized.append(self.adapter.normalize(raw, provider=provider, known_symbols=symbols))
                    except InvalidDataFormatError:
                        self.invalid_count += 1
                created, updated, rescheduled, cancelled = self._reconcile(
                    normalized,
                    succeeded=set(self.repository.last_collection.providers_succeeded),
                    now=now,
                )
                self.last_schedule_sync_at = now
                if self.repository.last_collection.providers_succeeded:
                    self.last_success_at = now
            if releases:
                release_updates = await self._refresh_releases_locked(now)
                updated.extend(release_updates)
                if release_updates:
                    self.last_success_at = now
            self.last_refresh_at = now
            await self.repository.persist(list(self._events.values()))
            snapshot = self.events_copy(now=now)
        await self._publish_changes(created, updated, rescheduled, cancelled, startup=not self._initialized)
        self._initialized = True
        return snapshot, created

    def _reconcile(
        self,
        incoming: list[EconomicCalendarEvent],
        *,
        succeeded: set[str],
        now: datetime,
    ) -> tuple[
        list[EconomicCalendarEvent],
        list[EconomicCalendarEvent],
        list[EconomicCalendarEvent],
        list[EconomicCalendarEvent],
    ]:
        created: list[EconomicCalendarEvent] = []
        updated: list[EconomicCalendarEvent] = []
        rescheduled: list[EconomicCalendarEvent] = []
        cancelled: list[EconomicCalendarEvent] = []
        seen: set[str] = set()
        for candidate in incoming:
            seen.add(candidate.id)
            previous = self._events.get(candidate.id)
            if previous is None:
                self._events[candidate.id] = candidate
                created.append(candidate)
                continue
            changes: dict = {
                "metadata": {**previous.metadata, **candidate.metadata, "pending_verification": False},
                "actual": candidate.actual if candidate.actual is not None else previous.actual,
                "actual_raw": candidate.actual_raw if candidate.actual_raw is not None else previous.actual_raw,
                "previous": candidate.previous if candidate.previous is not None else previous.previous,
                "revised_previous": (
                    candidate.revised_previous if candidate.revised_previous is not None else previous.revised_previous
                ),
                "revision_source": candidate.revision_source or previous.revision_source,
                "revised_at": candidate.revised_at or previous.revised_at,
                "released_at": candidate.released_at or previous.released_at,
                "schedule_history": list(previous.schedule_history),
            }
            if candidate.scheduled_at != previous.scheduled_at:
                changes.update(
                    {
                        "status": EconomicEventStatus.RESCHEDULED,
                        "original_scheduled_at": previous.original_scheduled_at or previous.scheduled_at,
                        "schedule_history": [
                            *previous.schedule_history,
                            ScheduleHistoryEntry(
                                changed_at=now,
                                previous_scheduled_at=previous.scheduled_at,
                                scheduled_at=candidate.scheduled_at,
                                reason="Official source schedule changed.",
                            ),
                        ],
                    }
                )
            merged = candidate.model_copy(update=changes)
            if merged.actual is not None:
                merged = merged.model_copy(
                    update={
                        "status": (
                            EconomicEventStatus.REVISED
                            if previous.actual is not None and merged.actual != previous.actual
                            else EconomicEventStatus.RELEASED
                        ),
                        "is_released": True,
                        "is_revised": previous.actual is not None and merged.actual != previous.actual,
                    }
                )
            if merged != previous:
                self._events[merged.id] = merged
                if merged.status == EconomicEventStatus.RESCHEDULED:
                    rescheduled.append(merged)
                elif merged.status == EconomicEventStatus.CANCELLED:
                    cancelled.append(merged)
                else:
                    updated.append(merged)
        for event_id, event in list(self._events.items()):
            if event.provider in succeeded and event_id not in seen:
                metadata = {**event.metadata, "pending_verification": True, "missing_since": now.isoformat()}
                self._events[event_id] = event.model_copy(update={"metadata": metadata, "stale": True})
            if event.scheduled_at < now - timedelta(days=self.settings.economic_calendar_retention_days):
                del self._events[event_id]
        return created, updated, rescheduled, cancelled

    async def _refresh_releases_locked(self, now: datetime) -> list[EconomicCalendarEvent]:
        candidates = []
        for event in self._events.values():
            if event.status == EconomicEventStatus.CANCELLED:
                continue
            awaiting_actual = event.actual is None and (
                event.scheduled_at - timedelta(minutes=1) <= now <= event.scheduled_at + timedelta(hours=24)
            )
            checking_revision = event.actual is not None and (
                event.scheduled_at
                <= now
                <= event.scheduled_at + timedelta(minutes=self.settings.economic_calendar_post_release_window_minutes)
            )
            if awaiting_actual or checking_revision:
                candidates.append(event)
        if not candidates:
            return []
        semaphore = asyncio.Semaphore(self.settings.economic_calendar_max_parallel_requests)

        async def check(event: EconomicCalendarEvent) -> tuple[EconomicCalendarEvent, dict | None]:
            async with semaphore:
                return event, await self.repository.fetch_release(event)

        results = await asyncio.gather(*(check(event) for event in candidates))
        updated: list[EconomicCalendarEvent] = []
        symbols = self.known_symbols()
        for previous, release in results:
            runtime_before = self._with_runtime_state(previous, now).status
            checks = getattr(self.repository, "last_release_checks", {})
            check_meta = checks.get(previous.id, {}) if isinstance(checks, dict) else {}
            checked_at = check_meta.get("checked_at")
            checked = checked_at if isinstance(checked_at, datetime) else now
            source_updated = parse_datetime(check_meta.get("source_updated"))
            latency = check_meta.get("latency_ms")
            latency_ms = float(latency) if isinstance(latency, int | float) else None
            http_status = check_meta.get("http_status")
            status_code = int(http_status) if isinstance(http_status, int) else None
            error = str(check_meta["error"])[:500] if check_meta.get("error") else None
            if release is None or release.get("actual") is None:
                runtime_after = self._with_runtime_state(previous, now).status
                self.observability.record_check(
                    previous,
                    scheduler_mode=self.scheduler_mode,
                    checked_at=checked,
                    http_status=status_code,
                    source_updated=source_updated,
                    actual_found=False,
                    actual_value=None,
                    status_before=runtime_before,
                    status_after=runtime_after,
                    latency_ms=latency_ms,
                    error=error,
                )
                continue
            if not self._release_unit_is_valid(previous, release):
                self.observability.record_check(
                    previous,
                    scheduler_mode=self.scheduler_mode,
                    checked_at=checked,
                    http_status=status_code,
                    source_updated=source_updated,
                    actual_found=False,
                    actual_value=None,
                    status_before=runtime_before,
                    status_after=runtime_before,
                    latency_ms=latency_ms,
                    error="Official release unit did not match the event category.",
                )
                continue
            raw = previous.model_dump(mode="python")
            raw.update(release)
            raw["id"] = previous.id.removeprefix(f"{previous.provider}:")
            value_changed = previous.actual is not None and release.get("actual") != previous.actual
            revision_changed = (
                release.get("revised_previous") is not None
                and release.get("revised_previous") != previous.revised_previous
            )
            source_published = parse_datetime(release.get("source_published_at"))
            if previous.actual is not None and not value_changed and not revision_changed:
                self.observability.record_check(
                    previous,
                    scheduler_mode=self.scheduler_mode,
                    checked_at=checked,
                    http_status=status_code,
                    source_updated=source_published,
                    actual_found=True,
                    actual_value=previous.actual,
                    status_before=runtime_before,
                    status_after=runtime_before,
                    latency_ms=latency_ms,
                    error=None,
                )
                continue
            raw["status"] = "REVISED" if previous.actual is not None else "RELEASED"
            # Fetch time is not publication time; only source metadata may set released_at.
            raw["released_at"] = release.get("released_at") or source_published
            raw["last_checked_at"] = checked
            raw["updated_at"] = now
            if raw["status"] == "REVISED":
                raw["revision_source"] = release.get("source_url") or previous.source
                raw["revised_at"] = source_published or now
            normalized = self.adapter.normalize(raw, provider=previous.provider, known_symbols=symbols)
            normalized = normalized.model_copy(
                update={
                    "schedule_history": previous.schedule_history,
                    "original_scheduled_at": previous.original_scheduled_at,
                    "metadata": {**previous.metadata, **normalized.metadata},
                }
            )
            self._events[normalized.id] = normalized
            updated.append(normalized)
            self.observability.record_check(
                previous,
                scheduler_mode=self.scheduler_mode,
                checked_at=checked,
                http_status=status_code,
                source_updated=source_published,
                actual_found=True,
                actual_value=normalized.actual,
                status_before=runtime_before,
                status_after=normalized.status,
                latency_ms=latency_ms,
                error=error,
            )
            if previous.actual is None:
                self.observability.record_release(normalized, backend_updated_at=now)
        return updated

    @staticmethod
    def _release_unit_is_valid(event: EconomicCalendarEvent, release: dict) -> bool:
        if event.provider != "bea" or event.category.value != "GDP" or release.get("actual") is None:
            return True
        unit = str(release.get("unit") or "").strip().upper()
        return unit in {"%", "% SAAR"}

    async def upsert_stream(self, provider: str, raw: dict) -> tuple[EconomicCalendarEvent, bool]:
        event = self.adapter.normalize(raw, provider=provider, known_symbols=self.known_symbols())
        async with self._lock:
            previous = self._events.get(event.id)
            created = previous is None
            self._events[event.id] = event
            self.last_refresh_at = datetime.now(UTC)
            self.last_success_at = self.last_refresh_at
        await self._publish_changes([event] if created else [], [] if created else [event], [], [], startup=False)
        return event, created

    def events_copy(self, *, now: datetime | None = None) -> list[EconomicCalendarEvent]:
        current = now or datetime.now(UTC)
        rows = [self._with_runtime_state(event, current) for event in self._events.values()]
        return sorted(rows, key=lambda item: item.scheduled_at)

    def _with_runtime_state(self, event: EconomicCalendarEvent, now: datetime) -> EconomicCalendarEvent:
        status = event.status
        is_live = False
        if event.actual is not None:
            status = EconomicEventStatus.REVISED if event.is_revised else EconomicEventStatus.RELEASED
            detected_at = event.released_at or event.updated_at
            is_live = timedelta(0) <= now - detected_at <= timedelta(minutes=15)
        elif status not in {EconomicEventStatus.CANCELLED, EconomicEventStatus.RESCHEDULED}:
            delta = (event.scheduled_at - now).total_seconds()
            precision = event.metadata.get("schedule_precision", "DATETIME")
            if (
                precision == "DATETIME"
                and 0 <= delta <= self.settings.economic_calendar_pre_release_window_minutes * 60
            ):
                status = EconomicEventStatus.COUNTDOWN
                is_live = delta <= self.settings.economic_calendar_release_window_minutes * 60
            elif precision == "DATETIME" and -86400 <= delta < 0:
                status = EconomicEventStatus.AWAITING_RELEASE
                is_live = True
            elif precision == "DATETIME" and delta < -86400:
                status = EconomicEventStatus.DELAYED
        checked = event.last_checked_at or event.updated_at
        age = max(0.0, (now - checked).total_seconds())
        stale = event.stale or age > max(3600, self.active_interval_seconds * 3)
        reason = event.stale_reason
        if stale and not reason:
            reason = "Official source has not been checked inside the active freshness window."
        return event.model_copy(update={"status": status, "is_live": is_live, "stale": stale, "stale_reason": reason})

    def query(
        self,
        *,
        currency: str | None = None,
        country: str | None = None,
        symbol: str | None = None,
        impact: object | None = None,
        category: object | None = None,
        status: object | None = None,
        source: str | None = None,
        released: bool | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
        sort: str = "scheduled_at",
    ) -> ServicePayload:
        rows = self.events_copy()
        if currency:
            rows = [item for item in rows if item.currency == currency.upper()]
        if country:
            rows = [item for item in rows if (item.country or "").lower() == country.lower()]
        if symbol:
            rows = [item for item in rows if symbol.upper() in item.affected_symbols]
        if impact:
            value = str(getattr(impact, "value", impact)).upper()
            rows = [item for item in rows if item.impact.value == value]
        if category:
            value = str(getattr(category, "value", category)).upper()
            rows = [item for item in rows if item.category.value == value]
        if status:
            value = str(getattr(status, "value", status)).upper()
            rows = [item for item in rows if item.status.value == value]
        if source:
            rows = [item for item in rows if item.provider == source.lower()]
        if released is not None:
            rows = [item for item in rows if item.is_released is released]
        if start_time:
            rows = [item for item in rows if item.scheduled_at >= start_time]
        if end_time:
            rows = [item for item in rows if item.scheduled_at <= end_time]
        reverse = sort in {"-scheduled_at", "impact", "-updated_at"}
        if sort.lstrip("-") == "impact":
            rows.sort(key=lambda item: (item.impact_score, item.scheduled_at.timestamp()), reverse=reverse)
        elif sort.lstrip("-") == "updated_at":
            rows.sort(key=lambda item: item.updated_at, reverse=reverse)
        else:
            rows.sort(key=lambda item: item.scheduled_at, reverse=reverse)
        counts = {
            "critical": sum(item.impact == EconomicImpact.CRITICAL for item in rows),
            "high": sum(item.impact == EconomicImpact.HIGH for item in rows),
            "released": sum(item.is_released for item in rows),
            "live": sum(item.is_live for item in rows),
            "currencies": len({item.currency for item in rows if item.currency}),
        }
        next_critical = next(
            (
                item
                for item in sorted(rows, key=lambda row: row.scheduled_at)
                if item.scheduled_at >= datetime.now(UTC)
                and item.impact == EconomicImpact.CRITICAL
                and item.status != EconomicEventStatus.CANCELLED
            ),
            None,
        )
        return ServicePayload(
            EconomicCalendarPage(
                items=rows[offset : offset + limit],
                total=len(rows),
                limit=limit,
                offset=offset,
                counts=counts,
                next_critical_event=next_critical,
            ),
            self.meta(),
        )

    def query_date(self, value: date, timezone_name: str = "UTC", **kwargs) -> ServicePayload:
        try:
            zone = ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError as exc:
            raise InvalidDataFormatError(f"Unknown timezone {timezone_name!r}") from exc
        start = datetime.combine(value, time.min, zone).astimezone(UTC)
        end = datetime.combine(value + timedelta(days=1), time.min, zone).astimezone(UTC)
        return self.query(start_time=start, end_time=end, **kwargs)

    def detail(self, event_id: str) -> ServicePayload:
        item = next((event for event in self.events_copy() if event.id == event_id), None)
        if item is None:
            raise ResourceNotFoundError(f"Economic calendar event {event_id!r} was not found")
        return ServicePayload(item, self.meta())

    def sources(self) -> ServicePayload:
        return ServicePayload(self.repository.providers.statuses(), self.meta())

    def guard_preview(self, symbol: str) -> ServicePayload:
        preview = self.guard.preview(
            symbol,
            self.events_copy(),
            enabled=self.settings.economic_calendar_guard_preview_enabled,
        )
        return ServicePayload(preview, self.meta())

    def audit(self, event_id: str, *, limit: int = 100, offset: int = 0) -> ServicePayload:
        # Resolve the event first so unknown identifiers retain normal 404 semantics.
        self.detail(event_id)
        return ServicePayload(self.observability.audit(event_id, limit=limit, offset=offset), self.meta())

    def metrics(self) -> ServicePayload:
        return ServicePayload(self.observability.metrics(), self.meta())

    def record_scheduler_phase(
        self,
        events: list[EconomicCalendarEvent],
        *,
        mode: str,
        checked_at: datetime,
        previous_statuses: dict[str, EconomicEventStatus] | None = None,
    ) -> None:
        candidates = [
            event
            for event in events
            if event.impact in {EconomicImpact.HIGH, EconomicImpact.CRITICAL}
            and event.status != EconomicEventStatus.CANCELLED
            and event.metadata.get("schedule_precision", "DATETIME") == "DATETIME"
        ]
        if not candidates:
            return
        selected = min(candidates, key=lambda item: abs((item.scheduled_at - checked_at).total_seconds()))
        before = (previous_statuses or {}).get(selected.id, selected.status)
        self.observability.record_check(
            selected,
            scheduler_mode=mode,
            checked_at=checked_at,
            http_status=None,
            source_updated=None,
            actual_found=selected.actual is not None,
            actual_value=selected.actual,
            status_before=before,
            status_after=selected.status,
            latency_ms=None,
            error=None,
        )

    def runtime_status(self) -> ServicePayload:
        now = self._clock().astimezone(UTC)
        events = self.events_copy(now=now)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        statuses = self.repository.providers.statuses()
        warnings = [status.last_error for status in statuses if status.last_error]
        data = EconomicCalendarRuntimeStatus(
            enabled=self.settings.economic_calendar_enabled,
            state=self.meta().data_status,
            scheduler_running=self.scheduler_running,
            scheduler_mode=self.scheduler_mode,
            active_interval_seconds=self.active_interval_seconds,
            last_sync_at=self.last_schedule_sync_at,
            last_success_at=self.last_success_at,
            next_sync_at=self.next_sync_at,
            event_count=len(events),
            today_count=sum(today_start <= event.scheduled_at < today_start + timedelta(days=1) for event in events),
            upcoming_count=sum(
                event.scheduled_at >= now and event.status != EconomicEventStatus.CANCELLED for event in events
            ),
            high_impact_count=sum(event.impact in {EconomicImpact.HIGH, EconomicImpact.CRITICAL} for event in events),
            live_count=sum(event.is_live for event in events),
            source_count=len(statuses),
            healthy_source_count=sum(status.healthy for status in statuses),
            partial=any(status.status in {"degraded", "error", "rate_limited"} for status in statuses)
            and any(status.healthy for status in statuses),
            timezone=self.settings.economic_calendar_default_timezone,
            warnings=[item for item in warnings if item],
        )
        return ServicePayload(data, self.meta())

    def health(self) -> ServicePayload:
        statuses = self.repository.providers.statuses()
        healthy_count = sum(status.healthy for status in statuses)
        state = (
            "disabled"
            if not self.settings.economic_calendar_enabled
            else "unconfigured"
            if not self.repository.configured
            else "healthy"
            if healthy_count == len([status for status in statuses if status.configured]) and healthy_count
            else "degraded"
            if healthy_count
            else "offline"
        )
        data = EconomicCalendarHealth(
            status=state,
            service="healthy" if self.last_success_at else state,
            scheduler="healthy" if self.scheduler_running else "offline",
            cache="healthy" if self._events else "empty",
            repository="healthy" if self.repository.configured else "unconfigured",
            sources=statuses,
            last_success_at=self.last_success_at,
            stale=self.meta().stale,
        )
        return ServicePayload(data, self.meta())

    def meta(self) -> ApiMeta:
        now = datetime.now(UTC)
        configured = self.repository.configured and self.settings.economic_calendar_enabled
        age = (now - self.last_success_at).total_seconds() if self.last_success_at else None
        threshold = max(3600.0, self.active_interval_seconds * 3)
        stale = age is None or age > threshold
        statuses = self.repository.providers.statuses()
        healthy = any(status.healthy for status in statuses)
        partial = healthy and any(status.status in {"degraded", "error", "rate_limited"} for status in statuses)
        state = (
            "disabled"
            if not self.settings.economic_calendar_enabled
            else "unconfigured"
            if not configured
            else "partial"
            if partial
            else "stale"
            if stale
            else "live"
        )
        warnings = [status.last_error for status in statuses if status.last_error]
        if self.invalid_count:
            warnings.append(f"{self.invalid_count} invalid economic-calendar rows were rejected.")
        return ApiMeta(
            source="economic_calendar_service",
            source_updated_at=self.last_success_at,
            server_timestamp=now,
            age_seconds=age,
            stale=stale,
            source_available=configured and (healthy or bool(self._events)),
            data_status=state,
            warnings=[item for item in warnings if item],
        )

    def set_scheduler_state(
        self,
        *,
        running: bool,
        mode: str,
        interval_seconds: float,
        next_sync_at: datetime | None,
    ) -> None:
        self.scheduler_running = running
        self.scheduler_mode = mode
        self.active_interval_seconds = interval_seconds
        self.next_sync_at = next_sync_at

    async def _publish_changes(
        self,
        created: list[EconomicCalendarEvent],
        updated: list[EconomicCalendarEvent],
        rescheduled: list[EconomicCalendarEvent],
        cancelled: list[EconomicCalendarEvent],
        *,
        startup: bool,
    ) -> None:
        if self.event_bus is None:
            return
        if not startup:
            for event in created:
                await self._publish_event("calendar.event.created", event)
        for event in updated:
            event_type = (
                "calendar.event.revised"
                if event.status == EconomicEventStatus.REVISED
                else "calendar.event.released"
                if event.actual is not None
                else "calendar.event.updated"
            )
            await self._publish_event(event_type, event)
        for event in rescheduled:
            await self._publish_event("calendar.event.rescheduled", event)
            await self._publish_event("calendar.schedule.changed", event)
        for event in cancelled:
            await self._publish_event("calendar.event.cancelled", event)

    async def _publish_event(self, event_type: str, event: EconomicCalendarEvent) -> None:
        if self.event_bus is None:
            return
        now = self._clock().astimezone(UTC)
        payload = event.model_dump(mode="json")
        channels = ["economic-calendar"]
        if event.is_live:
            channels.append("economic-calendar:live")
        if event.impact in {EconomicImpact.HIGH, EconomicImpact.CRITICAL}:
            channels.append("economic-calendar:high-impact")
        if event.currency:
            channels.append(f"economic-calendar:currency:{event.currency}")
        channels.extend(f"economic-calendar:symbol:{symbol}" for symbol in event.affected_symbols)
        self.observability.increment("economic_calendar_websocket_broadcast_total")
        if event_type in {"calendar.event.released", "calendar.event.revised"}:
            self.observability.record_broadcast(event, broadcast_at=now)
        for channel in channels:
            await self.event_bus.publish(
                InternalEvent(event_type, channel, now, payload, f"{event_type}:{event.id}:{channel}")
            )
