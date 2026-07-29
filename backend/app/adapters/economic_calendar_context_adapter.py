from __future__ import annotations

import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from app.adapters.news_adapter import CURRENCIES, symbol_components
from app.core.config import Settings
from app.core.exceptions import SafetyLockError
from app.schemas.economic_calendar import (
    EconomicCalendarDiagnosticContext,
    EconomicCalendarDiagnosticEvent,
)

if TYPE_CHECKING:
    from app.services.economic_calendar_service import EconomicCalendarService

logger = logging.getLogger(__name__)

PROTECTED_EXECUTION_FIELDS = frozenset(
    {
        "final_decision",
        "signal_status",
        "live_allowed",
        "effective_max_lot",
        "calculated_lot",
        "risk_percent",
        "stop_loss",
        "take_profit",
        "strategy_score",
        "execution_allowed",
    }
)


class EconomicCalendarContextAdapter:
    """Builds explanatory context without access to execution services or state."""

    def __init__(self, settings: Settings, calendar: EconomicCalendarService) -> None:
        self.settings = settings
        self.calendar = calendar

    PROTECTED_FIELDS = PROTECTED_EXECUTION_FIELDS

    async def build_context(
        self,
        *,
        symbol: str,
        now: datetime,
    ) -> EconomicCalendarDiagnosticContext:
        normalized = symbol.strip().upper()
        current = now.astimezone(UTC)
        _, components = symbol_components(normalized)
        exposures = sorted(component for component in components if component in CURRENCIES)
        all_events = self.calendar.events_copy(now=current)
        events = [event for event in all_events if normalized in event.affected_symbols]
        preview = self.calendar.guard.preview(
            normalized,
            all_events,
            now=current,
            enabled=self.settings.economic_calendar_diagnostics_enabled
            and self.settings.economic_calendar_guard_preview_enabled,
        )
        selected = next((event for event in events if event.id == preview.event_id), None)
        if selected is None:
            future = [event for event in events if event.scheduled_at >= current and event.status.value != "CANCELLED"]
            selected = min(future, key=lambda event: event.scheduled_at, default=None)
        minutes_to = None
        minutes_since = None
        if selected is not None:
            delta = (selected.scheduled_at - current).total_seconds() / 60
            if delta >= 0:
                minutes_to = round(delta, 2)
            else:
                minutes_since = round(abs(delta), 2)
        calendar_meta = self.calendar.meta()
        freshness = (
            "UNAVAILABLE"
            if selected is None and not calendar_meta.source_available
            else "STALE"
            if selected is None and calendar_meta.stale
            else "LIVE"
            if selected is None
            else "STALE"
            if selected is not None and selected.stale
            else "UNVERIFIED"
            if selected is not None and not selected.verified
            else "LIVE"
        )
        context = EconomicCalendarDiagnosticContext(
            symbol=normalized,
            status=preview.state,
            currency_exposure=exposures,
            next_event=(
                EconomicCalendarDiagnosticEvent(
                    id=selected.id,
                    event_name=selected.event_name,
                    currency=selected.currency,
                    impact=selected.impact,
                    scheduled_at=selected.scheduled_at,
                    actual=selected.actual,
                    forecast=selected.forecast,
                    previous=selected.previous,
                    unit=selected.unit,
                    status=selected.status,
                    source=selected.source,
                    source_url=selected.source_url,
                    verified=selected.verified,
                    released_at=selected.released_at,
                )
                if selected
                else None
            ),
            minutes_to_event=minutes_to,
            minutes_since_event=minutes_since,
            event_impact=selected.impact if selected else None,
            event_status=selected.status if selected else None,
            guard_preview=preview.state,
            affected_symbols=selected.affected_symbols if selected else [],
            source=selected.source if selected else None,
            verified=selected.verified if selected else False,
            data_freshness=freshness,
            reasons=preview.reasons,
            updated_at=current,
        )
        self.assert_context_safe(context.model_dump(mode="python"))
        self.calendar.observability.increment("economic_calendar_diagnostic_context_total")
        return context

    def assert_context_safe(self, payload: Mapping[str, object]) -> None:
        forbidden = sorted(PROTECTED_EXECUTION_FIELDS.intersection(payload))
        unsafe_flags = (
            not bool(payload.get("diagnostic_only", False))
            or bool(payload.get("execution_guard_enabled", False))
            or bool(payload.get("affects_execution", False))
        )
        if forbidden or unsafe_flags or self.settings.economic_calendar_execution_guard_enabled:
            self.calendar.observability.increment("economic_calendar_mutation_block_total")
            logger.error(
                "Calendar execution mutation blocked",
                extra={
                    "event": "calendar_execution_mutation_blocked",
                    "component": "economic_calendar_diagnostics",
                    "forbidden_fields": forbidden,
                },
            )
            raise SafetyLockError(
                "Economic Calendar is diagnostic-only and cannot modify execution state.",
                details={"forbidden_fields": forbidden},
            )

    def assert_execution_unchanged(
        self,
        before: Mapping[str, object],
        after: Mapping[str, object],
    ) -> None:
        changed = sorted(field for field in PROTECTED_EXECUTION_FIELDS if before.get(field) != after.get(field))
        if changed:
            self.calendar.observability.increment("economic_calendar_mutation_block_total")
            logger.error(
                "Calendar execution mutation blocked",
                extra={
                    "event": "calendar_execution_mutation_blocked",
                    "component": "economic_calendar_diagnostics",
                    "forbidden_fields": changed,
                },
            )
            raise SafetyLockError(
                "Economic Calendar attempted to mutate protected execution state.",
                details={"forbidden_fields": changed},
            )
