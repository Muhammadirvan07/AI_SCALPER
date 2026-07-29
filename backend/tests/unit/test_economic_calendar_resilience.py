from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import ClassVar

import httpx
import pytest

from app.adapters.economic_calendar_adapter import EconomicCalendarAdapter
from app.core.config import Settings
from app.providers.economic_calendar.bea import BeaCalendarProvider
from app.providers.economic_calendar.bls import BlsCalendarProvider, _parse_ics_datetime, _unfold_ics
from app.providers.economic_calendar.ecb import EcbCalendarProvider
from app.providers.economic_calendar.federal_reserve import FederalReserveCalendarProvider
from app.providers.economic_calendar.file_provider import FileEconomicCalendarProvider
from app.providers.economic_calendar.http_client import OfficialHttpStatusError, OfficialSourceHttpClient
from app.providers.economic_calendar.parsing import html_to_text, normalized_key, slug, token_similarity
from app.providers.economic_calendar.registry import EconomicCalendarProviderRegistry, _Runtime
from app.providers.news.base import ProviderFetchError, ProviderRateLimitError
from app.realtime.event_bus import EventBus
from app.repositories.economic_calendar_repository import EconomicCalendarRepository
from app.schemas.economic_calendar import EconomicCalendarSourceStatus, EconomicEventStatus
from app.services.economic_calendar_scheduler import EconomicCalendarScheduler
from app.services.economic_calendar_service import EconomicCalendarService


def configured(settings: Settings, **updates: object) -> Settings:
    values = settings.model_dump()
    values.update(economic_calendar_external_requests_enabled=True, websocket_heartbeat_seconds=2)
    values.update(updates)
    return Settings(**values)


def transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def response(text: str, content_type: str = "text/html", status: int = 200) -> httpx.MockTransport:
    return transport(lambda request: httpx.Response(status, text=text, headers={"content-type": content_type}))


def raw_event(when: datetime) -> dict:
    return {
        "id": "official-gdp",
        "provider": "file",
        "source": "Official fixture",
        "source_type": "LOCAL_FILE",
        "event_name": "Gross Domestic Product",
        "currency": "USD",
        "scheduled_at": when.isoformat(),
        "forecast": None,
        "verified": False,
        "updated_at": when.isoformat(),
    }


class _EmptyRegistry:
    configured = False

    def statuses(self):
        return []


@pytest.mark.asyncio
async def test_atomic_calendar_cache_roundtrip_and_invalid_fallback(settings: Settings, tmp_path) -> None:
    cache_path = tmp_path / "calendar-cache.json"
    configured_settings = configured(settings, economic_calendar_cache_path=cache_path)
    repository = EconomicCalendarRepository(configured_settings, _EmptyRegistry())  # type: ignore[arg-type]
    event = EconomicCalendarAdapter().normalize(
        raw_event(datetime.now(UTC) + timedelta(hours=2)), provider="file", known_symbols=["EURUSD"]
    )
    await repository.persist([event])
    assert cache_path.is_file() and not cache_path.with_suffix(".json.tmp").exists()
    loaded = await repository.load()
    assert [item.id for item in loaded] == [event.id]
    service = EconomicCalendarService(
        configured_settings,
        repository,
        EconomicCalendarAdapter(),
        lambda: ["EURUSD"],
        EventBus(),
    )
    await service.initialize()
    assert service.events_copy()[0].id == event.id and service.last_success_at == event.updated_at

    cache_path.write_text("{invalid", encoding="utf-8")
    assert await repository.load() == []
    assert repository.last_error and "JSONDecodeError" in repository.last_error

    cache_path.write_text("x" * (configured_settings.economic_calendar_max_response_bytes + 1), encoding="utf-8")
    assert await repository.load() == []
    assert "size limit" in (repository.last_error or "")


@pytest.mark.asyncio
async def test_local_file_provider_validation_filter_and_health(settings: Settings, tmp_path) -> None:
    path = tmp_path / "calendar.json"
    when = datetime.now(UTC) + timedelta(days=1)
    path.write_text(json.dumps({"events": [raw_event(when), {**raw_event(when), "id": "eur", "currency": "EUR"}]}))
    provider = FileEconomicCalendarProvider(configured(settings, economic_calendar_file_path=path))
    rows = await provider.fetch_schedule(start_time=when, end_time=when, currencies=["eur"])
    assert len(rows) == 1 and rows[0]["currency"] == "EUR"
    assert rows[0]["source_type"] == "LOCAL_FILE" and rows[0]["verified"] is False
    assert (await provider.health_check())["healthy"] is True
    assert await provider.fetch_release(event=rows[0]) is None

    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(ProviderFetchError, match="unavailable or invalid"):
        await provider.fetch_schedule(start_time=when, end_time=when)
    path.write_text(json.dumps({"events": ["invalid"]}), encoding="utf-8")
    with pytest.raises(ProviderFetchError, match="events array"):
        await provider.fetch_schedule(start_time=when, end_time=when)

    disabled = FileEconomicCalendarProvider(configured(settings, economic_calendar_file_path=None))
    assert await disabled.fetch_schedule(start_time=when, end_time=when) == []
    assert (await disabled.health_check())["configured"] is False


@pytest.mark.asyncio
async def test_official_http_client_all_security_and_failure_branches() -> None:
    kwargs = dict(
        base_url="https://www.bea.gov",
        allowed_hosts={"www.bea.gov"},
        timeout_seconds=1,
        max_response_bytes=32,
        user_agent="AI_SCALPER test",
    )
    with pytest.raises(ValueError, match="allowlisted HTTPS"):
        OfficialSourceHttpClient(**{**kwargs, "base_url": "http://www.bea.gov"})
    with pytest.raises(ValueError, match="private address"):
        OfficialSourceHttpClient(**{**kwargs, "base_url": "https://127.0.0.1", "allowed_hosts": {"127.0.0.1"}})

    client = OfficialSourceHttpClient(**kwargs, transport=response("ok"))
    for unsafe in ("https://www.bea.gov/news", "//evil.test", "/../secret"):
        with pytest.raises(ProviderFetchError, match="path is not allowed"):
            await client.get(unsafe, accept="text/html")

    with pytest.raises(OfficialHttpStatusError) as status_error:
        await OfficialSourceHttpClient(**kwargs, transport=response("no", status=503)).get("/news", accept="text/html")
    assert status_error.value.status_code == 503

    declared = transport(
        lambda request: httpx.Response(
            200, content=b"tiny", headers={"content-length": "99", "content-type": "text/html"}
        )
    )
    with pytest.raises(ProviderFetchError, match="size limit"):
        await OfficialSourceHttpClient(**kwargs, transport=declared).get("/news", accept="text/html")
    body = transport(lambda request: httpx.Response(200, content=b"x" * 33, headers={"content-type": "text/html"}))
    with pytest.raises(ProviderFetchError, match="size limit"):
        await OfficialSourceHttpClient(**kwargs, transport=body).get("/news", accept="text/html")

    def timeout(request):
        raise httpx.ReadTimeout("late", request=request)

    with pytest.raises(ProviderFetchError, match="timed out"):
        await OfficialSourceHttpClient(**kwargs, transport=transport(timeout)).get("/news", accept="text/html")


def test_official_parsing_helpers_cover_sanitization_and_edge_cases() -> None:
    assert normalized_key("U.S. CPI — July") == "u s cpi july"
    assert html_to_text("<b>GDP</b><script>bad()</script><style>x</style> rises") == "GDP\nrises"
    assert slug("!!!") == "event"
    assert token_similarity("", "GDP") == 0
    assert token_similarity("US Gross Domestic Product", "Gross Domestic Product release") > 0.5
    assert _unfold_ics("A:one\r\n continued\r\nB:two") == ["A:onecontinued", "B:two"]
    assert _parse_ics_datetime("DTSTART", "20260812T123000Z") == datetime(2026, 8, 12, 12, 30, tzinfo=UTC)
    assert _parse_ics_datetime("DTSTART;TZID=Invalid/Zone", "20260812T083000") is None
    assert _parse_ics_datetime("DTSTART", "invalid") is None


@pytest.mark.asyncio
async def test_provider_parse_errors_currency_filters_and_health(settings: Settings) -> None:
    cfg = configured(settings)
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = datetime(2026, 12, 31, tzinfo=UTC)
    providers = [
        BeaCalendarProvider(cfg, transport=response("<html>none</html>")),
        FederalReserveCalendarProvider(cfg, transport=response("<html>none</html>")),
        EcbCalendarProvider(cfg, transport=response("<html>none</html>")),
        BlsCalendarProvider(cfg, transport=response("not calendar", "text/calendar")),
    ]
    for provider in providers:
        with pytest.raises(ProviderFetchError):
            await provider.fetch_schedule(start_time=start, end_time=end)
        health = await provider.health_check()
        assert health["healthy"] is False and health["error"]

    assert await providers[0].fetch_schedule(start_time=start, end_time=end, currencies=["EUR"]) == []
    assert await providers[2].fetch_schedule(start_time=start, end_time=end, currencies=["USD"]) == []
    assert await BlsCalendarProvider(cfg, transport=response("x", "application/json")).fetch_release(event={}) is None


@pytest.mark.asyncio
async def test_bea_release_matching_and_actual_variants(settings: Settings) -> None:
    cfg = configured(settings)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/news/current-releases":
            return httpx.Response(
                200,
                text='<a href="https://www.bea.gov/news/2026/gdp-second-quarter.htm">Gross Domestic Product, Second Quarter</a>',
                headers={"content-type": "text/html"},
            )
        return httpx.Response(
            200,
            text=(
                "Real gross domestic product (GDP) decreased at an annual rate of 1.2 percent in the second quarter. "
                "In the first quarter, real GDP increased 2.4 percent."
            ),
            headers={"content-type": "text/html"},
        )

    provider = BeaCalendarProvider(cfg, transport=transport(handler))
    release = await provider.fetch_release(
        event={"event_name": "Gross Domestic Product", "scheduled_at": datetime.now(UTC) - timedelta(minutes=1)}
    )
    assert release and release["actual"] == -1.2 and release["source_url"].endswith("gdp-second-quarter.htm")
    assert (
        BeaCalendarProvider._extract_actual(
            "Personal Income", "Personal income decreased $4.0 billion (0.3 percent at a monthly rate)"
        )["actual"]
        == -0.3
    )
    assert (
        BeaCalendarProvider._extract_actual("International Trade", "The goods and services deficit was $71.5 billion")[
            "actual"
        ]
        == -71.5
    )
    assert BeaCalendarProvider._extract_actual("Unknown", "nothing") is None


class _FakeProvider:
    name = "fake"
    display_name = "Official Fake"
    enabled = True
    configured = True
    official_domain = "example.gov"
    capabilities: ClassVar[list[str]] = ["official_schedule", "official_actuals"]

    def __init__(self) -> None:
        self.mode = "success"
        self.release_mode = "success"

    async def fetch_schedule(self, **kwargs):
        if self.mode == "rate":
            raise ProviderRateLimitError("quota", retry_after_seconds=600)
        if self.mode == "fail":
            raise ProviderFetchError("offline")
        return [raw_event(datetime.now(UTC) + timedelta(hours=1))]

    async def fetch_release(self, **kwargs):
        if self.release_mode == "rate":
            raise ProviderRateLimitError("release quota", retry_after_seconds=600)
        if self.release_mode == "fail":
            raise ProviderFetchError("release offline")
        return {"actual": 1.2}

    async def health_check(self):
        return {"healthy": True}


def fake_runtime(provider: _FakeProvider) -> _Runtime:
    return _Runtime(
        provider=provider,
        status=EconomicCalendarSourceStatus(
            name=provider.name,
            display_name=provider.display_name,
            enabled=True,
            configured=True,
            healthy=False,
            status="unknown",
            official_domain=provider.official_domain,
            capabilities=provider.capabilities,
        ),
    )


@pytest.mark.asyncio
async def test_provider_registry_partial_lkg_cooldown_and_release_failures(settings: Settings) -> None:
    cfg = configured(
        settings,
        economic_calendar_provider_failure_threshold=1,
        economic_calendar_provider_cooldown_seconds=300,
    )
    registry = EconomicCalendarProviderRegistry(cfg)
    provider = _FakeProvider()
    registry._runtimes = {provider.name: fake_runtime(provider)}
    start = datetime.now(UTC)
    end = start + timedelta(days=1)

    success = await registry.collect(start_time=start, end_time=end)
    assert success.providers_succeeded == ["fake"] and len(success.items) == 1
    assert registry.configured and registry.provider_names == {"fake"}
    assert registry.status("fake").last_known_good_available is True
    assert registry.status("missing") is None

    provider.mode = "rate"
    limited = await registry.collect(start_time=start, end_time=end, force=True)
    assert limited.providers_rate_limited == ["fake"] and limited.partial is True
    assert limited.items and registry.status("fake").last_status_code == 429
    cached = await registry.collect(start_time=start, end_time=end)
    assert cached.providers_rate_limited == ["fake"] and cached.items

    runtime = registry._runtimes["fake"]
    runtime.status = runtime.status.model_copy(update={"cooldown_until": None, "rate_limited": False})
    provider.mode = "fail"
    failed = await registry.collect(start_time=start, end_time=end, force=True)
    assert failed.providers_failed == ["fake"] and failed.items and failed.partial
    assert registry.status("fake").status == "degraded"

    runtime.status = runtime.status.model_copy(update={"cooldown_until": None})
    provider.release_mode = "rate"
    assert await registry.fetch_release("fake", {}) is None
    assert registry.status("fake").rate_limited is True
    runtime.status = runtime.status.model_copy(update={"cooldown_until": None})
    provider.release_mode = "fail"
    assert await registry.fetch_release("fake", {}) is None
    assert registry.status("fake").failure_count >= 1
    assert await registry.fetch_release("unknown", {}) is None


@pytest.mark.asyncio
async def test_scheduler_failure_backoff_lifecycle_and_event(settings: Settings, monkeypatch) -> None:
    cfg = configured(settings)
    repository = EconomicCalendarRepository(cfg, _EmptyRegistry())  # type: ignore[arg-type]
    service = EconomicCalendarService(cfg, repository, EconomicCalendarAdapter(), lambda: [], EventBus())

    async def fail_refresh(**kwargs):
        raise RuntimeError("official sources unavailable")

    monkeypatch.setattr(service, "refresh", fail_refresh)
    bus = EventBus()
    scheduler = EconomicCalendarScheduler(cfg, service, bus)
    result = await scheduler.refresh_now()
    assert result == {"status": "failed", "error_type": "RuntimeError"}
    assert scheduler.state.mode == "BACKOFF" and scheduler.state.next_run_at is not None
    assert (await bus.next()).event_type == "calendar.sync.failed"

    await scheduler.start()
    await scheduler.start()
    await asyncio.sleep(0)
    await scheduler.stop()
    assert scheduler.state.running is False and service.scheduler_running is False


def test_date_only_schedule_never_becomes_fake_delayed_release(settings: Settings) -> None:
    repository = EconomicCalendarRepository(settings, _EmptyRegistry())  # type: ignore[arg-type]
    service = EconomicCalendarService(settings, repository, EconomicCalendarAdapter(), lambda: ["EURUSD"])
    event = EconomicCalendarAdapter().normalize(
        {
            **raw_event(datetime.now(UTC) - timedelta(hours=8)),
            "metadata": {"schedule_precision": "DATE"},
        },
        provider="federal_reserve",
        known_symbols=["EURUSD"],
    )
    service._events[event.id] = event
    assert service.events_copy()[0].status == EconomicEventStatus.SCHEDULED
