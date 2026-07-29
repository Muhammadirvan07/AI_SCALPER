from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.adapters.economic_calendar_adapter import EconomicCalendarAdapter
from app.core.config import Settings
from app.providers.economic_calendar.base import EconomicCalendarCollection
from app.providers.economic_calendar.bea import BeaCalendarProvider
from app.providers.economic_calendar.bls import BlsCalendarProvider
from app.providers.economic_calendar.ecb import EcbCalendarProvider
from app.providers.economic_calendar.federal_reserve import FederalReserveCalendarProvider
from app.providers.economic_calendar.http_client import OfficialSourceHttpClient
from app.providers.news.base import ProviderFetchError, ProviderRateLimitError
from app.realtime.event_bus import EventBus
from app.schemas.economic_calendar import CalendarGuardState, EconomicEventCategory, EconomicEventStatus
from app.services.economic_calendar_guard_service import (
    EconomicCalendarGuardService,
    classify_category,
    classify_impact,
)
from app.services.economic_calendar_scheduler import EconomicCalendarScheduler
from app.services.economic_calendar_service import EconomicCalendarService


def external_settings(settings: Settings, **updates: object) -> Settings:
    values = settings.model_dump()
    values.update(
        app_env="development",
        trusted_hosts="localhost,127.0.0.1",
        websocket_heartbeat_seconds=2,
        economic_calendar_external_requests_enabled=True,
    )
    values.update(updates)
    return Settings(**values)


def response_transport(content: str, content_type: str = "text/html") -> httpx.MockTransport:
    return httpx.MockTransport(
        lambda request: httpx.Response(200, text=content, headers={"content-type": content_type})
    )


@pytest.mark.asyncio
async def test_bea_bls_federal_reserve_and_ecb_official_schedule_parsers(settings: Settings) -> None:
    configured = external_settings(settings)
    bea_html = """
      <table id="release-schedule-table"><tr><th>2026 Release Schedule</th></tr>
      <tr><td class="scheduled-date">August 12 8:30 AM</td>
      <td class="release-title">Gross Domestic Product, 2nd Quarter 2026</td></tr></table>
    """
    bea = BeaCalendarProvider(configured, transport=response_transport(bea_html))
    rows = await bea.fetch_schedule(
        start_time=datetime(2026, 8, 1, tzinfo=UTC), end_time=datetime(2026, 8, 31, tzinfo=UTC)
    )
    assert len(rows) == 1 and rows[0]["currency"] == "USD"
    assert rows[0]["forecast"] is None and rows[0]["source_type"] == "OFFICIAL"

    ics = """BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:cpi-2026\r\nDTSTART;TZID=America/New_York:20260812T083000\r\nSUMMARY:Consumer Price Index\r\nURL:https://www.bls.gov/news.release/cpi.htm\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"""
    bls = BlsCalendarProvider(configured, transport=response_transport(ics, "text/calendar"))
    rows = await bls.fetch_schedule(
        start_time=datetime(2026, 8, 1, tzinfo=UTC), end_time=datetime(2026, 8, 31, tzinfo=UTC)
    )
    assert rows[0]["event_name"] == "Consumer Price Index"
    assert rows[0]["scheduled_at"].tzinfo is not None

    fed_html = """
      <h3>2026 FOMC Meetings</h3>
      <div class="fomc-meeting__month"><strong>July</strong></div>
      <div class="fomc-meeting__date">28-29</div>
      <a href="/newsevents/pressreleases/monetary20260729a.htm">Statement</a>
      <h3>2025 FOMC Meetings</h3>
    """
    fed = FederalReserveCalendarProvider(configured, transport=response_transport(fed_html))
    rows = await fed.fetch_schedule(
        start_time=datetime(2026, 7, 1, tzinfo=UTC), end_time=datetime(2026, 7, 31, tzinfo=UTC)
    )
    assert rows[0]["category"] == "INTEREST_RATE"
    assert rows[0]["metadata"]["schedule_precision"] == "DATE"

    ecb_html = """
      <h1>Weekly schedule</h1><p>Wednesday, 29 July 2026</p>
      <p>Event: ECB Governing Council monetary policy meeting</p><p>Time: 14:00 CEST</p>
    """
    ecb = EcbCalendarProvider(configured, transport=response_transport(ecb_html))
    rows = await ecb.fetch_schedule(
        start_time=datetime(2026, 7, 28, tzinfo=UTC), end_time=datetime(2026, 7, 30, tzinfo=UTC)
    )
    assert len(rows) == 1 and rows[0]["currency"] == "EUR"


@pytest.mark.asyncio
async def test_official_http_client_security_rate_limit_and_redirect(settings: Settings) -> None:
    client = OfficialSourceHttpClient(
        base_url="https://www.bea.gov",
        allowed_hosts={"www.bea.gov"},
        timeout_seconds=1,
        max_response_bytes=128,
        user_agent="AI_SCALPER test",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(429, headers={"retry-after": "90", "content-type": "text/html"})
        ),
    )
    with pytest.raises(ProviderRateLimitError) as error:
        await client.get("/news/schedule", accept="text/html")
    assert error.value.retry_after_seconds == 90
    redirect = OfficialSourceHttpClient(
        base_url="https://www.bea.gov",
        allowed_hosts={"www.bea.gov"},
        timeout_seconds=1,
        max_response_bytes=128,
        user_agent="AI_SCALPER test",
        transport=httpx.MockTransport(lambda request: httpx.Response(302, headers={"location": "https://evil.test"})),
    )
    with pytest.raises(ProviderFetchError):
        await redirect.get("/news/schedule", accept="text/html")
    with pytest.raises(ProviderFetchError):
        await client.get("https://evil.test/private", accept="text/html")


@pytest.mark.asyncio
async def test_official_actual_parsers_do_not_invent_forecast(settings: Settings) -> None:
    configured = external_settings(settings)
    gdp = BeaCalendarProvider._extract_actual(
        "Gross Domestic Product",
        "Real gross domestic product (GDP) increased at an annual rate of 2.6 percent in the second quarter.",
    )
    assert gdp == {
        "actual": 2.6,
        "actual_raw": "Real gross domestic product (GDP) increased at an annual rate of 2.6 percent",
        "previous": None,
        "unit": "% SAAR",
    }
    statement = "The Committee decided to maintain the target range for the federal funds rate at 4.25 to 4.50 percent."
    fed = FederalReserveCalendarProvider(configured, transport=response_transport(statement))
    release = await fed.fetch_release(
        event={
            "scheduled_at": datetime.now(UTC) - timedelta(minutes=1),
            "metadata": {
                "statement_url": "https://www.federalreserve.gov/newsevents/pressreleases/monetary20260729a.htm"
            },
        }
    )
    assert release is not None and release["actual"] == "4.25-4.50"
    assert "forecast" not in release


@pytest.mark.parametrize(
    ("name", "category", "impact"),
    [
        ("Federal Open Market Committee Rate Decision", EconomicEventCategory.INTEREST_RATE, "CRITICAL"),
        ("US Consumer Price Index CPI", EconomicEventCategory.CPI, "CRITICAL"),
        ("US Non-Farm Payrolls", EconomicEventCategory.NFP, "CRITICAL"),
        ("Gross Domestic Product", EconomicEventCategory.GDP, "HIGH"),
        ("Routine central bank speech", EconomicEventCategory.SPEECH, "MEDIUM"),
        ("Regional secondary survey", EconomicEventCategory.OTHER, "LOW"),
    ],
)
def test_deterministic_category_and_impact_rules(name: str, category: EconomicEventCategory, impact: str) -> None:
    normalized = classify_category(name)
    assert normalized == category
    _, result, reasons = classify_impact(name, normalized, currency="USD")
    assert result.value == impact and reasons


class _Providers:
    def statuses(self):
        return []


class _Repository:
    configured = True

    def __init__(self, rows: list[dict]) -> None:
        self.rows = rows
        self.release: dict | None = None
        self.providers = _Providers()
        self.last_collection = EconomicCalendarCollection()

    async def fetch(self, **kwargs):
        self.last_collection = EconomicCalendarCollection()
        self.last_collection.providers_succeeded = ["fixture"]
        self.last_collection.items = [("fixture", dict(row)) for row in self.rows]
        return list(self.last_collection.items)

    async def fetch_release(self, event):
        return dict(self.release) if self.release else None

    async def persist(self, events):
        return None


def raw_event(when: datetime, **updates: object) -> dict:
    row = {
        "id": "release-one",
        "event_name": "US Gross Domestic Product",
        "currency": "USD",
        "scheduled_at": when,
        "source": "Official Fixture",
        "source_type": "OFFICIAL",
        "verified": True,
        "metadata": {"schedule_precision": "DATETIME"},
    }
    row.update(updates)
    return row


@pytest.mark.asyncio
async def test_reconciliation_reschedule_release_null_forecast_and_safety(settings: Settings) -> None:
    now = datetime.now(UTC)
    repository = _Repository([raw_event(now + timedelta(minutes=30))])
    service = EconomicCalendarService(
        settings, repository, EconomicCalendarAdapter(), lambda: ["EURUSD", "USDJPY", "XAUUSD"], EventBus()
    )
    await service.refresh(force=True)
    repository.rows = [raw_event(now + timedelta(minutes=45))]
    await service.refresh(force=True, releases=False)
    event = service.events_copy()[0]
    assert event.status == EconomicEventStatus.RESCHEDULED
    assert event.original_scheduled_at is not None and len(event.schedule_history) == 1
    assert event.forecast is None and event.affected_symbols == ["EURUSD", "USDJPY", "XAUUSD"]

    repository.rows = [raw_event(now - timedelta(seconds=10))]
    repository.release = {"actual": 2.4, "unit": "%", "released_at": None, "verified": True}
    await service.refresh(force=True)
    released = service.events_copy()[0]
    assert released.actual == 2.4 and released.forecast is None
    assert released.released_at is None
    preview = service.guard_preview("EURUSD").data
    assert preview.read_only is True and preview.creates_orders is False
    status = service.runtime_status().data
    assert status.live_allowed is False and status.effective_max_lot <= 0.01


def test_surprise_zero_forecast_and_guard_boundaries(settings: Settings) -> None:
    now = datetime.now(UTC)
    adapter = EconomicCalendarAdapter()
    event = adapter.normalize(
        raw_event(now + timedelta(minutes=5), actual=2, forecast=0, impact="HIGH"),
        provider="fixture",
        known_symbols=["EURUSD"],
    )
    assert event.surprise == 2 and event.surprise_percent is None
    guard = EconomicCalendarGuardService()
    assert guard.preview("EURUSD", [event], now=now).state == CalendarGuardState.HIGH_RISK
    caution = adapter.normalize(
        raw_event(now + timedelta(minutes=30), impact="HIGH"), provider="fixture", known_symbols=["EURUSD"]
    )
    assert guard.preview("EURUSD", [caution], now=now).state == CalendarGuardState.CAUTION
    block = adapter.normalize(
        raw_event(now + timedelta(seconds=30), impact="HIGH"), provider="fixture", known_symbols=["EURUSD"]
    )
    assert guard.preview("EURUSD", [block], now=now).state == CalendarGuardState.BLOCK_PREVIEW


def test_adaptive_polling_modes(settings: Settings) -> None:
    service = EconomicCalendarService(
        settings, _Repository([]), EconomicCalendarAdapter(), lambda: ["EURUSD"], EventBus()
    )
    scheduler = EconomicCalendarScheduler(settings, service, EventBus())
    now = datetime.now(UTC)
    adapter = EconomicCalendarAdapter()

    def event(minutes: float):
        return adapter.normalize(
            raw_event(now + timedelta(minutes=minutes), impact="HIGH"),
            provider="fixture",
            known_symbols=["EURUSD"],
        )

    assert scheduler.interval_for([], now)[0] == "NORMAL"
    assert scheduler.interval_for([event(30)], now) == ("WATCH", settings.economic_calendar_watch_interval_seconds)
    assert scheduler.interval_for([event(5)], now) == (
        "PRE_RELEASE",
        settings.economic_calendar_pre_release_interval_seconds,
    )
    assert scheduler.interval_for([event(0.5)], now) == (
        "RELEASE",
        settings.economic_calendar_release_interval_seconds,
    )
    assert scheduler.interval_for([event(-5)], now) == (
        "RELEASE",
        settings.economic_calendar_release_interval_seconds,
    )
    released = event(-5).model_copy(
        update={"actual": 2.4, "is_released": True, "status": EconomicEventStatus.RELEASED, "updated_at": now}
    )
    assert scheduler.interval_for([released], now) == (
        "POST_RELEASE",
        settings.economic_calendar_post_release_interval_seconds,
    )
