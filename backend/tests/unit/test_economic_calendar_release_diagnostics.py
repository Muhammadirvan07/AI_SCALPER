from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from app.adapters.economic_calendar_adapter import EconomicCalendarAdapter
from app.adapters.economic_calendar_context_adapter import EconomicCalendarContextAdapter
from app.core.config import Settings
from app.core.exceptions import SafetyLockError
from app.providers.economic_calendar.base import EconomicCalendarCollection
from app.providers.economic_calendar.bea import BeaCalendarProvider
from app.realtime.event_bus import EventBus
from app.schemas.economic_calendar import CalendarGuardState, EconomicEventStatus
from app.services.economic_calendar_scheduler import EconomicCalendarScheduler
from app.services.economic_calendar_service import EconomicCalendarService

RELEASE_AT = datetime(2026, 7, 30, 12, 30, tzinfo=UTC)


def _external(settings: Settings) -> Settings:
    values = settings.model_dump()
    values.update(
        app_env="development",
        trusted_hosts="localhost,127.0.0.1",
        websocket_heartbeat_seconds=2,
        economic_calendar_external_requests_enabled=True,
        economic_calendar_diagnostics_enabled=True,
        economic_calendar_engine_integration_enabled=False,
        economic_calendar_execution_guard_enabled=False,
    )
    return Settings(**values)


def _raw_event(when: datetime) -> dict:
    return {
        "id": "gdp-advance-estimate-q2-2026",
        "event_name": "GDP (Advance Estimate), Q2 2026",
        "short_name": "GDP Advance Estimate",
        "currency": "USD",
        "country": "United States",
        "category": "GDP",
        "impact": "HIGH",
        "scheduled_at": when,
        "reference_period": "2nd Quarter 2026",
        "source": "Bureau of Economic Analysis",
        "source_type": "OFFICIAL",
        "source_url": "https://www.bea.gov/news/schedule",
        "verified": True,
        "verified_at": datetime(2026, 7, 29, tzinfo=UTC),
        "last_checked_at": when - timedelta(minutes=40),
        "updated_at": when - timedelta(minutes=40),
        "forecast": None,
        "metadata": {"schedule_precision": "DATETIME"},
    }


@pytest.mark.asyncio
async def test_bea_official_shape_release_fixture_is_matched_without_production_dummy(
    settings: Settings,
) -> None:
    release_html = (
        Path(__file__)
        .parents[1]
        .joinpath("fixtures", "bea_gdp_release_q2_2026_simulation.html")
        .read_text(encoding="utf-8")
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/news/current-releases":
            return httpx.Response(
                200,
                text=(
                    '<a href="https://www.bea.gov/news/2026/gdp-advance-estimate-q2-2026.htm">'
                    "GDP (Advance Estimate), Second Quarter 2026</a>"
                ),
                headers={"content-type": "text/html"},
            )
        return httpx.Response(200, text=release_html, headers={"content-type": "text/html"})

    provider = BeaCalendarProvider(
        _external(settings),
        transport=httpx.MockTransport(handler),
        now_provider=lambda: RELEASE_AT + timedelta(seconds=8),
    )
    release = await provider.fetch_release(event=_raw_event(RELEASE_AT))
    assert release is not None
    assert release["actual"] == 7.654
    assert release["unit"] == "% SAAR"
    assert release["source_published_at"] == RELEASE_AT + timedelta(seconds=3)
    assert release["reference_period"] == "2nd Quarter 2026"
    wrong_period = {**_raw_event(RELEASE_AT), "reference_period": "3rd Quarter 2026"}
    assert await provider.fetch_release(event=wrong_period) is None


class _Statuses:
    def statuses(self):
        return []


class _ReleaseRepository:
    configured = True

    def __init__(self) -> None:
        self.rows = [_raw_event(RELEASE_AT)]
        self.release: dict | None = None
        self.providers = _Statuses()
        self.last_collection = EconomicCalendarCollection()
        self.last_release_checks: dict[str, dict[str, object]] = {}

    async def fetch(self, **kwargs):
        self.last_collection = EconomicCalendarCollection()
        self.last_collection.providers_succeeded = ["bea"]
        self.last_collection.items = [("bea", dict(row)) for row in self.rows]
        return list(self.last_collection.items)

    async def fetch_release(self, event):
        self.last_release_checks[event.id] = {
            "checked_at": self.checked_at,
            "http_status": 200,
            "latency_ms": 8.5,
            "error": None,
            "source_updated": (self.release or {}).get("source_published_at"),
        }
        return dict(self.release) if self.release else None

    async def persist(self, events):
        return None

    checked_at = RELEASE_AT


def _service(settings: Settings, repository: _ReleaseRepository, bus: EventBus) -> EconomicCalendarService:
    return EconomicCalendarService(
        settings,
        repository,  # type: ignore[arg-type]
        EconomicCalendarAdapter(),
        lambda: ["EURUSD", "USDJPY", "XAUUSD", "BTCUSD"],
        bus,
        clock=lambda: repository.checked_at + timedelta(milliseconds=25),
    )


@pytest.mark.asyncio
async def test_gdp_release_lifecycle_audit_metrics_revision_and_duplicate_suppression(
    settings: Settings,
) -> None:
    repository = _ReleaseRepository()
    bus = EventBus()
    service = _service(settings, repository, bus)
    scheduler = EconomicCalendarScheduler(settings, service, bus)
    await service.refresh(force=True, releases=False, now=RELEASE_AT - timedelta(minutes=61))
    event = service.events_copy(now=RELEASE_AT - timedelta(minutes=61))[0]

    assert scheduler.interval_for([event], RELEASE_AT - timedelta(minutes=61))[0] == "NORMAL"
    assert scheduler.interval_for([event], RELEASE_AT - timedelta(minutes=30))[0] == "WATCH"
    assert scheduler.interval_for([event], RELEASE_AT - timedelta(minutes=5))[0] == "PRE_RELEASE"
    assert scheduler.interval_for([event], RELEASE_AT - timedelta(seconds=30))[0] == "RELEASE"
    assert service.events_copy(now=RELEASE_AT + timedelta(seconds=1))[0].status == EconomicEventStatus.AWAITING_RELEASE

    repository.checked_at = RELEASE_AT + timedelta(seconds=2)
    service.set_scheduler_state(running=True, mode="RELEASE", interval_seconds=10, next_sync_at=None)
    await service.refresh(schedule=False, now=repository.checked_at)
    awaiting = service.events_copy(now=repository.checked_at)[0]
    assert awaiting.status == EconomicEventStatus.AWAITING_RELEASE and awaiting.actual is None

    repository.release = {
        "actual": 7.654,
        "actual_raw": "TEST FIXTURE ONLY",
        "unit": "% SAAR",
        "source_published_at": RELEASE_AT + timedelta(seconds=3),
        "source_url": "https://www.bea.gov/news/2026/gdp-advance-estimate-q2-2026.htm",
        "verified": True,
    }
    repository.checked_at = RELEASE_AT + timedelta(seconds=8)
    await service.refresh(schedule=False, now=repository.checked_at)
    released = service.events_copy(now=repository.checked_at)[0]
    assert released.status == EconomicEventStatus.RELEASED
    assert (
        released.actual == 7.654
        and released.forecast is None
        and released.released_at == RELEASE_AT + timedelta(seconds=3)
    )
    assert scheduler.interval_for([released], repository.checked_at)[0] == "POST_RELEASE"
    assert scheduler.interval_for([released], RELEASE_AT + timedelta(minutes=11))[0] == "NORMAL"

    first = await bus.next()
    assert first.event_type == "calendar.event.released"
    assert first.data["actual"] == 7.654
    before_queue = bus.queue.qsize()
    await service.refresh(schedule=False, now=RELEASE_AT + timedelta(seconds=9))
    assert bus.queue.qsize() == before_queue

    repository.release = {
        **repository.release,
        "revised_previous": 2.2,
        "source_published_at": RELEASE_AT + timedelta(seconds=40),
    }
    repository.checked_at = RELEASE_AT + timedelta(seconds=45)
    await service.refresh(schedule=False, now=repository.checked_at)
    revised = service.events_copy(now=repository.checked_at)[0]
    assert revised.status == EconomicEventStatus.REVISED
    assert revised.revised_previous == 2.2
    assert revised.revision_source and revised.revised_at is not None

    audit = service.audit(revised.id, limit=100, offset=0).data
    assert audit.total >= 4
    assert any(item.status_after == EconomicEventStatus.AWAITING_RELEASE for item in audit.items)
    assert any(item.actual_found and item.status_after == EconomicEventStatus.RELEASED for item in audit.items)
    metrics = service.metrics().data
    assert metrics.economic_calendar_release_detected_total == 1
    assert metrics.release_detection_latency_ms == 8_000
    assert metrics.latest_release is not None
    assert metrics.latest_release.scheduled_to_source_publish_ms == 3_000
    assert metrics.latest_release.scheduled_to_websocket_broadcast_ms == 8_025
    assert metrics.websocket_delivery_latency_ms == 25
    assert metrics.frontend_render_latency_ms is None


@pytest.mark.asyncio
async def test_diagnostic_context_rules_symbol_exposure_and_mutation_lock(settings: Settings) -> None:
    repository = _ReleaseRepository()
    service = _service(settings, repository, EventBus())
    await service.refresh(force=True, releases=False, now=RELEASE_AT - timedelta(minutes=30))
    adapter = EconomicCalendarContextAdapter(settings, service)
    eur = await adapter.build_context(symbol="EURUSD", now=RELEASE_AT - timedelta(minutes=30))
    gold = await adapter.build_context(symbol="XAUUSD", now=RELEASE_AT - timedelta(minutes=5))
    assert eur.status == CalendarGuardState.CAUTION
    assert eur.currency_exposure == ["EUR", "USD"]
    assert eur.next_event and eur.next_event.forecast is None and eur.diagnostic_only
    assert eur.execution_guard_enabled is False and eur.affects_execution is False
    assert gold.status == CalendarGuardState.HIGH_RISK and gold.currency_exposure == ["USD"]
    assert "XAUUSD" in gold.affected_symbols

    event = service.events_copy(now=RELEASE_AT)[0]
    event.stale = True
    service._events[event.id] = event
    stale = await adapter.build_context(symbol="EURUSD", now=RELEASE_AT)
    assert stale.status == CalendarGuardState.INSUFFICIENT_DATA

    protected = {
        "final_decision": "WAIT",
        "signal_status": "WAIT",
        "live_allowed": False,
        "effective_max_lot": 0.01,
        "calculated_lot": 0.01,
        "risk_percent": 0.5,
        "stop_loss": 1.0,
        "take_profit": 2.0,
        "strategy_score": 4,
        "execution_allowed": False,
    }
    adapter.assert_execution_unchanged(protected, dict(protected))
    with pytest.raises(SafetyLockError):
        adapter.assert_execution_unchanged(protected, {**protected, "calculated_lot": 0.1})
    with pytest.raises(SafetyLockError):
        adapter.assert_context_safe({"diagnostic_only": True, "final_decision": "BUY"})
    assert service.metrics().data.economic_calendar_mutation_block_total == 2


@pytest.mark.parametrize(
    ("offset", "expected"),
    [
        (-61, CalendarGuardState.NORMAL),
        (-30, CalendarGuardState.CAUTION),
        (-5, CalendarGuardState.HIGH_RISK),
        (-0.5, CalendarGuardState.BLOCK_PREVIEW),
        (3, CalendarGuardState.BLOCK_PREVIEW),
        (10, CalendarGuardState.POST_RELEASE_VOLATILITY),
        (16, CalendarGuardState.NORMAL),
    ],
)
def test_guard_preview_observation_boundaries(
    settings: Settings,
    offset: float,
    expected: CalendarGuardState,
) -> None:
    repository = _ReleaseRepository()
    service = _service(settings, repository, EventBus())
    event = EconomicCalendarAdapter().normalize(
        _raw_event(RELEASE_AT),
        provider="bea",
        known_symbols=["EURUSD", "XAUUSD"],
    )
    preview = service.guard.preview("EURUSD", [event], now=RELEASE_AT + timedelta(minutes=offset))
    assert preview.state == expected
    assert preview.read_only is True
    assert preview.execution_guard_enabled is False
    assert preview.affects_execution is False
