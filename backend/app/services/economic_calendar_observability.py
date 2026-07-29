from __future__ import annotations

import hashlib
from collections import deque
from datetime import UTC, datetime

from app.schemas.economic_calendar import (
    EconomicCalendarAuditPage,
    EconomicCalendarEvent,
    EconomicCalendarMetrics,
    EconomicCalendarReleaseAuditRecord,
    EconomicCalendarReleaseLatency,
    EconomicEventStatus,
)


def _elapsed_ms(start: datetime, end: datetime | None) -> float | None:
    if end is None:
        return None
    return round((end - start).total_seconds() * 1000, 3)


class EconomicCalendarObservability:
    """Bounded, read-only runtime telemetry for calendar release validation."""

    def __init__(self, *, max_audit_records: int = 2_000) -> None:
        self._audit: deque[EconomicCalendarReleaseAuditRecord] = deque(maxlen=max_audit_records)
        self._latencies: dict[str, EconomicCalendarReleaseLatency] = {}
        self._counters = {
            "economic_calendar_sync_total": 0,
            "economic_calendar_sync_failure_total": 0,
            "economic_calendar_release_detected_total": 0,
            "economic_calendar_websocket_broadcast_total": 0,
            "economic_calendar_diagnostic_context_total": 0,
            "economic_calendar_guard_preview_changes_total": 0,
            "economic_calendar_mutation_block_total": 0,
        }

    def increment(self, name: str, amount: int = 1) -> None:
        if name in self._counters:
            self._counters[name] += max(0, amount)

    def record_check(
        self,
        event: EconomicCalendarEvent,
        *,
        scheduler_mode: str,
        checked_at: datetime,
        http_status: int | None,
        source_updated: datetime | None,
        actual_found: bool,
        actual_value: str | float | int | None,
        status_before: EconomicEventStatus,
        status_after: EconomicEventStatus,
        latency_ms: float | None,
        error: str | None,
    ) -> EconomicCalendarReleaseAuditRecord:
        checked = checked_at.astimezone(UTC)
        digest = hashlib.sha256(
            f"{event.id}|{checked.isoformat()}|{scheduler_mode}|{status_after}|{len(self._audit)}".encode()
        ).hexdigest()[:20]
        record = EconomicCalendarReleaseAuditRecord(
            id=digest,
            event_id=event.id,
            event_name=event.event_name,
            scheduler_mode=scheduler_mode,
            checked_at=checked,
            source=event.source,
            http_status=http_status,
            source_updated=source_updated,
            actual_found=actual_found,
            actual_value=actual_value,
            status_before=status_before,
            status_after=status_after,
            latency_ms=round(latency_ms, 3) if latency_ms is not None else None,
            error=error,
        )
        self._audit.append(record)
        latency = self._latencies.get(event.id) or EconomicCalendarReleaseLatency(
            event_id=event.id,
            scheduled_at=event.scheduled_at,
        )
        if checked >= event.scheduled_at and latency.first_check_at is None:
            latency = latency.model_copy(
                update={
                    "first_check_at": checked,
                    "scheduled_to_first_check_ms": _elapsed_ms(event.scheduled_at, checked),
                }
            )
        if source_updated is not None and latency.source_published_at is None:
            latency = latency.model_copy(
                update={
                    "source_published_at": source_updated,
                    "scheduled_to_source_publish_ms": _elapsed_ms(event.scheduled_at, source_updated),
                }
            )
        if actual_found and latency.backend_updated_at is None:
            latency = latency.model_copy(
                update={
                    "backend_updated_at": checked,
                    "scheduled_to_backend_update_ms": _elapsed_ms(event.scheduled_at, checked),
                }
            )
        self._latencies[event.id] = latency
        return record

    def record_release(self, event: EconomicCalendarEvent, *, backend_updated_at: datetime) -> None:
        latency = self._latencies.get(event.id) or EconomicCalendarReleaseLatency(
            event_id=event.id,
            scheduled_at=event.scheduled_at,
        )
        self._latencies[event.id] = latency.model_copy(
            update={
                "backend_updated_at": backend_updated_at,
                "scheduled_to_backend_update_ms": _elapsed_ms(event.scheduled_at, backend_updated_at),
            }
        )
        self.increment("economic_calendar_release_detected_total")

    def record_broadcast(self, event: EconomicCalendarEvent, *, broadcast_at: datetime) -> None:
        latency = self._latencies.get(event.id) or EconomicCalendarReleaseLatency(
            event_id=event.id,
            scheduled_at=event.scheduled_at,
        )
        if latency.websocket_broadcast_at is None:
            self._latencies[event.id] = latency.model_copy(
                update={
                    "websocket_broadcast_at": broadcast_at,
                    "scheduled_to_websocket_broadcast_ms": _elapsed_ms(event.scheduled_at, broadcast_at),
                }
            )

    def audit(self, event_id: str, *, limit: int, offset: int) -> EconomicCalendarAuditPage:
        rows = [item for item in reversed(self._audit) if item.event_id == event_id]
        return EconomicCalendarAuditPage(
            items=rows[offset : offset + limit],
            total=len(rows),
            limit=limit,
            offset=offset,
        )

    def metrics(self) -> EconomicCalendarMetrics:
        latest = max(
            self._latencies.values(),
            key=lambda item: item.backend_updated_at or item.first_check_at or item.scheduled_at,
            default=None,
        )
        release_latency = latest.scheduled_to_backend_update_ms if latest else None
        websocket_latency = (
            _elapsed_ms(latest.backend_updated_at, latest.websocket_broadcast_at)
            if latest and latest.backend_updated_at
            else None
        )
        return EconomicCalendarMetrics(
            **self._counters,
            economic_calendar_release_latency_ms=release_latency,
            release_detection_latency_ms=release_latency,
            websocket_delivery_latency_ms=websocket_latency,
            frontend_render_latency_ms=None,
            latest_release=latest,
            audit_record_count=len(self._audit),
        )
