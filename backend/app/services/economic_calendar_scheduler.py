from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.core.config import Settings
from app.realtime.event_bus import EventBus
from app.realtime.events import InternalEvent
from app.schemas.economic_calendar import EconomicCalendarEvent, EconomicEventStatus, EconomicImpact

from .economic_calendar_service import EconomicCalendarService

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class EconomicCalendarSchedulerState:
    running: bool = False
    mode: str = "NORMAL"
    active_interval_seconds: float = 900
    last_run_at: datetime | None = None
    last_success_at: datetime | None = None
    next_run_at: datetime | None = None
    last_error: str | None = None
    consecutive_failures: int = 0


class EconomicCalendarScheduler:
    def __init__(self, settings: Settings, service: EconomicCalendarService, event_bus: EventBus) -> None:
        self.settings = settings
        self.service = service
        self.event_bus = event_bus
        self.state = EconomicCalendarSchedulerState(
            active_interval_seconds=settings.economic_calendar_sync_interval_seconds
        )
        self._task: asyncio.Task[None] | None = None
        self._refresh_lock = asyncio.Lock()
        self._runtime_statuses: dict[str, EconomicEventStatus] = {}
        self._guard_states: dict[str, str] = {}

    async def start(self) -> None:
        if self.state.running:
            return
        self.state.running = True
        self._task = asyncio.create_task(self._run(), name="economic-calendar-scheduler")
        self._sync_service_state()
        logger.info("Economic calendar scheduler started", extra={"event": "calendar.scheduler_started"})

    async def stop(self) -> None:
        self.state.running = False
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        self._task = None
        self._sync_service_state()

    async def refresh_now(self, *, force: bool = True) -> dict[str, object]:
        if self._refresh_lock.locked():
            return {"status": "already_running", "event_count": len(self.service.events_copy())}
        async with self._refresh_lock:
            self.state.last_run_at = datetime.now(UTC)
            try:
                async with asyncio.timeout(
                    self.settings.economic_calendar_request_timeout_seconds
                    * max(1, self.settings.economic_calendar_max_parallel_requests)
                    + 10
                ):
                    events, created = await self.service.refresh(force=force, schedule=True, releases=True)
                mode, interval = self.interval_for(events, datetime.now(UTC))
                self.state.mode = mode
                self.state.active_interval_seconds = interval
                self.state.last_success_at = datetime.now(UTC)
                self.state.next_run_at = self.state.last_success_at + timedelta(seconds=interval)
                self.state.last_error = None
                self.state.consecutive_failures = 0
                self._sync_service_state()
                previous_statuses = dict(self._runtime_statuses)
                self.service.observability.increment("economic_calendar_sync_total")
                self.service.record_scheduler_phase(
                    events,
                    mode=mode,
                    checked_at=self.state.last_success_at,
                    previous_statuses=previous_statuses,
                )
                await self._publish_runtime_transitions(events)
                self.service.observability.increment("economic_calendar_websocket_broadcast_total")
                await self.event_bus.publish(
                    InternalEvent(
                        "calendar.sync.completed",
                        "economic-calendar",
                        datetime.now(UTC),
                        {
                            "event_count": len(events),
                            "created_count": len(created),
                            "mode": mode,
                            "active_interval_seconds": interval,
                            "last_sync_at": self.state.last_success_at,
                            "next_sync_at": self.state.next_run_at,
                        },
                    )
                )
                for source in self.service.repository.providers.statuses():
                    self.service.observability.increment("economic_calendar_websocket_broadcast_total")
                    await self.event_bus.publish(
                        InternalEvent(
                            "calendar.source.status.updated",
                            "economic-calendar",
                            datetime.now(UTC),
                            source.model_dump(mode="json"),
                            source.name,
                        )
                    )
                return {
                    "status": "completed",
                    "event_count": len(events),
                    "created_count": len(created),
                    "mode": mode,
                    "active_interval_seconds": interval,
                }
            except (TimeoutError, OSError, RuntimeError) as exc:
                self.state.last_error = f"{type(exc).__name__}: {exc}"
                self.state.consecutive_failures += 1
                self.service.observability.increment("economic_calendar_sync_failure_total")
                base = self.settings.economic_calendar_sync_interval_seconds
                interval = min(3600.0, base * 2 ** min(self.state.consecutive_failures, 3))
                self.state.mode = "BACKOFF"
                self.state.active_interval_seconds = interval
                self.state.next_run_at = datetime.now(UTC) + timedelta(seconds=interval)
                self._sync_service_state()
                logger.warning(
                    "Economic calendar sync failed",
                    extra={"event": "calendar.sync_failed", "error_type": type(exc).__name__},
                )
                await self.event_bus.publish(
                    InternalEvent(
                        "calendar.sync.failed",
                        "economic-calendar",
                        datetime.now(UTC),
                        {"error_type": type(exc).__name__, "next_sync_at": self.state.next_run_at},
                    )
                )
                return {"status": "failed", "error_type": type(exc).__name__}

    async def _publish_runtime_transitions(self, events: list[EconomicCalendarEvent]) -> None:
        current_statuses = {event.id: event.status for event in events}
        for event in events:
            previous = self._runtime_statuses.get(event.id)
            event_type = (
                "calendar.event.countdown"
                if previous is not None and event.status == EconomicEventStatus.COUNTDOWN and previous != event.status
                else "calendar.event.awaiting-release"
                if previous is not None
                and event.status == EconomicEventStatus.AWAITING_RELEASE
                and previous != event.status
                else None
            )
            if event_type:
                self.service.observability.increment("economic_calendar_websocket_broadcast_total")
                await self.event_bus.publish(
                    InternalEvent(
                        event_type,
                        "economic-calendar:live",
                        datetime.now(UTC),
                        event.model_dump(mode="json"),
                        f"{event_type}:{event.id}:{event.status}",
                    )
                )
        self._runtime_statuses = current_statuses
        for symbol in self.service.known_symbols():
            preview = self.service.guard.preview(
                symbol,
                events,
                enabled=self.settings.economic_calendar_guard_preview_enabled,
            )
            signature = f"{preview.state}:{preview.event_id}:{preview.minutes_to_event}"
            # Publish on semantic window changes, not on every countdown tick.
            semantic = f"{preview.state}:{preview.event_id}"
            if self._guard_states.get(symbol) not in {None, semantic}:
                self.service.observability.increment("economic_calendar_guard_preview_changes_total")
                self.service.observability.increment("economic_calendar_websocket_broadcast_total")
                await self.event_bus.publish(
                    InternalEvent(
                        "calendar.guard-preview.updated",
                        f"economic-calendar:symbol:{symbol}",
                        datetime.now(UTC),
                        preview.model_dump(mode="json"),
                        f"calendar.guard:{symbol}:{signature}",
                    )
                )
            self._guard_states[symbol] = semantic

    def interval_for(
        self,
        events: list[EconomicCalendarEvent],
        now: datetime,
    ) -> tuple[str, float]:
        choices: list[tuple[float, int, str]] = []
        for event in events:
            if (
                event.impact not in {EconomicImpact.HIGH, EconomicImpact.CRITICAL}
                or event.status == EconomicEventStatus.CANCELLED
                or event.metadata.get("schedule_precision", "DATETIME") != "DATETIME"
            ):
                continue
            minutes = (event.scheduled_at - now).total_seconds() / 60
            if event.actual is not None:
                detected_at = event.released_at or event.updated_at
                post_age = (now - detected_at).total_seconds() / 60
                if 0 <= post_age <= self.settings.economic_calendar_post_release_window_minutes:
                    choices.append((self.settings.economic_calendar_post_release_interval_seconds, 3, "POST_RELEASE"))
                continue
            if -24 * 60 <= minutes <= self.settings.economic_calendar_release_window_minutes:
                choices.append((self.settings.economic_calendar_release_interval_seconds, 0, "RELEASE"))
            elif minutes <= self.settings.economic_calendar_pre_release_window_minutes:
                choices.append((self.settings.economic_calendar_pre_release_interval_seconds, 1, "PRE_RELEASE"))
            elif minutes <= self.settings.economic_calendar_watch_window_minutes:
                choices.append((self.settings.economic_calendar_watch_interval_seconds, 2, "WATCH"))
        if not choices:
            return "NORMAL", self.settings.economic_calendar_sync_interval_seconds
        interval, _, mode = min(choices, key=lambda item: (item[0], item[1]))
        return mode, interval

    async def _run(self) -> None:
        try:
            while self.state.running:
                await self.refresh_now(force=False)
                interval = self.state.active_interval_seconds
                jitter = random.uniform(0, min(5.0, interval * 0.03))
                await asyncio.sleep(interval + jitter)
        except asyncio.CancelledError:
            return

    def _sync_service_state(self) -> None:
        self.service.set_scheduler_state(
            running=self.state.running,
            mode=self.state.mode,
            interval_seconds=self.state.active_interval_seconds,
            next_sync_at=self.state.next_run_at,
        )
