from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic

import httpx
import pytest

from app.adapters.economic_calendar_adapter import EconomicCalendarAdapter
from app.core.config import Settings
from app.providers.news.alpha_vantage import AlphaVantageNewsProvider
from app.providers.news.base import (
    ProviderAuthenticationError,
    ProviderEntitlementError,
    ProviderFetchError,
    ProviderRateLimitError,
)
from app.providers.news.finnhub import FinnhubNewsProvider
from app.providers.news.gdelt import GdeltNewsProvider
from app.providers.news.http_client import SafeProviderHttpClient
from app.providers.news.official_rss import OfficialRssNewsProvider
from app.providers.news.resilience import ProviderRateLimiter
from app.providers.news.trading_economics import TradingEconomicsCalendarProvider
from app.realtime.event_bus import EventBus
from app.schemas.news import ProviderSentiment, SentimentLabel, SentimentResult
from app.services.economic_calendar_service import EconomicCalendarService
from app.services.sentiment_service import SentimentService
from app.services.trading_economics_stream import TradingEconomicsStream


def configured(settings: Settings, **updates) -> Settings:
    values = settings.model_dump()
    values["websocket_heartbeat_seconds"] = 2
    values.update(
        news_external_requests_enabled=True,
        alpha_vantage_enabled=False,
        finnhub_enabled=False,
        trading_economics_enabled=False,
        gdelt_enabled=False,
        official_rss_enabled=False,
    )
    values.update(updates)
    return Settings(**values)


def json_transport(payload, *, status: int = 200, headers: dict[str, str] | None = None):
    return httpx.MockTransport(
        lambda request: httpx.Response(
            status,
            headers=headers or {"content-type": "application/json"},
            json=payload,
        )
    )


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (401, ProviderAuthenticationError),
        (403, ProviderEntitlementError),
        (429, ProviderRateLimitError),
        (302, ProviderFetchError),
        (500, ProviderFetchError),
    ],
)
@pytest.mark.asyncio
async def test_safe_http_client_maps_provider_statuses(status, error) -> None:
    client = SafeProviderHttpClient(
        base_url="https://api.gdeltproject.org",
        allowed_hosts={"api.gdeltproject.org"},
        timeout_seconds=1,
        max_response_bytes=4096,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(status, headers={"content-type": "application/json"})
        ),
    )
    with pytest.raises(error):
        await client.get_json("/safe", params={})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("headers", "content"),
    [
        ({"content-type": "text/html"}, b"<html/>"),
        ({"content-type": "application/json", "content-length": "9999"}, b"{}"),
        ({"content-type": "application/json"}, b"x" * 5000),
        ({"content-type": "application/json"}, b"not-json"),
    ],
)
async def test_safe_http_client_rejects_invalid_or_oversized_content(headers, content) -> None:
    client = SafeProviderHttpClient(
        base_url="https://api.gdeltproject.org",
        allowed_hosts={"api.gdeltproject.org"},
        timeout_seconds=1,
        max_response_bytes=4096,
        transport=httpx.MockTransport(lambda request: httpx.Response(200, headers=headers, content=content)),
    )
    with pytest.raises(ProviderFetchError):
        await client.get_json("/safe", params={})


@pytest.mark.asyncio
async def test_safe_http_client_timeout_path_and_url_validation() -> None:
    def timeout(request):
        raise httpx.ReadTimeout("timeout", request=request)

    client = SafeProviderHttpClient(
        base_url="https://api.gdeltproject.org",
        allowed_hosts={"api.gdeltproject.org"},
        timeout_seconds=1,
        max_response_bytes=4096,
        transport=httpx.MockTransport(timeout),
    )
    with pytest.raises(ProviderFetchError):
        await client.get_json("/safe", params={})
    with pytest.raises(ProviderFetchError):
        await client.get_json("https://untrusted.example", params={})
    with pytest.raises(ValueError):
        SafeProviderHttpClient(
            base_url="http://127.0.0.1",
            allowed_hosts={"127.0.0.1"},
            timeout_seconds=1,
            max_response_bytes=4096,
        )


@pytest.mark.asyncio
async def test_alpha_vantage_error_contracts_and_sentiment_opt_out(settings) -> None:
    base = configured(settings, alpha_vantage_enabled=True, alpha_vantage_api_key="secret")
    for payload, error in [
        ([], ProviderFetchError),
        ({"Information": "invalid api key"}, ProviderAuthenticationError),
        ({"Information": "maintenance"}, ProviderFetchError),
        ({"Error Message": "bad query"}, ProviderFetchError),
        ({"items": []}, ProviderFetchError),
    ]:
        with pytest.raises(error):
            await AlphaVantageNewsProvider(base, transport=json_transport(payload)).fetch_news(limit=1)
    opt_out = configured(
        settings,
        alpha_vantage_enabled=True,
        alpha_vantage_api_key="secret",
        alpha_vantage_use_provider_sentiment=False,
    )
    rows = await AlphaVantageNewsProvider(
        opt_out,
        transport=json_transport(
            {
                "feed": [
                    {
                        "title": "A",
                        "url": "https://trusted.example/a",
                        "overall_sentiment_score": 0.5,
                        "ticker_sentiment": [],
                    }
                ]
            }
        ),
    ).fetch_news(limit=1)
    assert "overall_sentiment_score" not in rows[0]


@pytest.mark.asyncio
async def test_finnhub_errors_and_optional_calendar_capability(settings) -> None:
    base = configured(settings, finnhub_enabled=True, finnhub_api_key="secret")
    provider = FinnhubNewsProvider(base, transport=json_transport({"error": "API key invalid"}))
    with pytest.raises(ProviderAuthenticationError):
        await provider.fetch_news(limit=1)
    provider = FinnhubNewsProvider(base, transport=json_transport({"error": "Rate limit exceeded"}))
    with pytest.raises(ProviderRateLimitError):
        await provider.fetch_news(limit=1)
    provider = FinnhubNewsProvider(base, transport=json_transport({"error": "Premium access required"}))
    with pytest.raises(ProviderEntitlementError):
        await provider.fetch_news(limit=1)
    provider = FinnhubNewsProvider(base, transport=json_transport({"unexpected": []}))
    with pytest.raises(ProviderFetchError):
        await provider.fetch_news(limit=1)

    calendar_settings = configured(
        settings,
        finnhub_enabled=True,
        finnhub_api_key="secret",
        finnhub_economic_calendar_enabled=True,
    )
    calendar = FinnhubNewsProvider(
        calendar_settings,
        transport=json_transport({"economicCalendar": [{"event": "CPI", "time": "2026-07-29"}]}),
    )
    assert len(await calendar.fetch_calendar(limit=1)) == 1
    assert calendar.capabilities["economic_calendar"] is True
    unavailable = FinnhubNewsProvider(calendar_settings, transport=json_transport({"items": []}))
    with pytest.raises(ProviderEntitlementError):
        await unavailable.fetch_calendar(limit=1)
    assert unavailable.capabilities["economic_calendar"] is False


@pytest.mark.asyncio
async def test_gdelt_and_trading_economics_error_contracts(settings) -> None:
    gdelt = configured(settings, gdelt_enabled=True)
    with pytest.raises(ProviderRateLimitError):
        await GdeltNewsProvider(gdelt, transport=json_transport({"error": "too many requests"})).fetch_news(limit=1)
    with pytest.raises(ProviderFetchError):
        await GdeltNewsProvider(gdelt, transport=json_transport({"error": "bad request"})).fetch_news(limit=1)
    with pytest.raises(ProviderFetchError):
        await GdeltNewsProvider(gdelt, transport=json_transport([])).fetch_news(limit=1)

    te = configured(
        settings,
        trading_economics_enabled=True,
        trading_economics_api_key="client",
        trading_economics_api_secret="secret",
    )
    with pytest.raises(ProviderRateLimitError):
        await TradingEconomicsCalendarProvider(te, transport=json_transport({"Message": "quota limit"})).fetch_calendar(
            limit=1
        )
    with pytest.raises(ProviderAuthenticationError):
        await TradingEconomicsCalendarProvider(
            te, transport=json_transport({"Message": "authentication failed"})
        ).fetch_calendar(limit=1)
    with pytest.raises(ProviderFetchError):
        await TradingEconomicsCalendarProvider(te, transport=json_transport({"Message": "bad"})).fetch_calendar(limit=1)
    with pytest.raises(ProviderFetchError):
        await TradingEconomicsCalendarProvider(te, transport=json_transport({})).fetch_calendar(limit=1)


@pytest.mark.asyncio
async def test_official_rss_invalid_config_and_feed_fallback(settings, engine_root: Path) -> None:
    invalid = configured(settings, official_rss_enabled=True, official_rss_feeds_config=engine_root / "missing.json")
    provider = OfficialRssNewsProvider(invalid)
    assert provider.configured is False and provider.configuration_error

    config = engine_root / "feeds.json"
    config.write_text(
        json.dumps(
            {
                "feeds": [
                    {
                        "id": "one",
                        "name": "One",
                        "url": "https://www.federalreserve.gov/one.xml",
                        "official_domain": "federalreserve.gov",
                        "verified": True,
                        "enabled": True,
                    },
                    {
                        "id": "two",
                        "name": "Two",
                        "url": "https://www.ecb.europa.eu/two.xml",
                        "official_domain": "ecb.europa.eu",
                        "verified": True,
                        "enabled": True,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    atom = b"""<feed xmlns='http://www.w3.org/2005/Atom'><entry><id>x</id><title>ECB statement</title><link href='https://www.ecb.europa.eu/press/x.html'/><updated>2026-07-29T12:00:00Z</updated><summary>Update</summary></entry></feed>"""

    def handler(request: httpx.Request) -> httpx.Response:
        if "federalreserve" in request.url.host:
            return httpx.Response(500, headers={"content-type": "text/xml"})
        return httpx.Response(200, headers={"content-type": "application/atom+xml"}, content=atom)

    active = configured(settings, official_rss_enabled=True, official_rss_feeds_config=config)
    provider = OfficialRssNewsProvider(active, transport=httpx.MockTransport(handler))
    rows = await provider.fetch_news(limit=10)
    assert rows[0]["title"] == "ECB statement"
    assert (await provider.health_check())["feed_count"] == 2


@pytest.mark.asyncio
async def test_official_rss_304_uses_conditional_cache(settings, engine_root: Path) -> None:
    config = engine_root / "conditional-feeds.json"
    config.write_text(
        json.dumps(
            {
                "feeds": [
                    {
                        "id": "fed",
                        "name": "Federal Reserve",
                        "url": "https://www.federalreserve.gov/feed.xml",
                        "official_domain": "federalreserve.gov",
                        "verified": True,
                        "enabled": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    xml = b"<rss><channel><item><guid>1</guid><title>Policy statement</title><link>https://www.federalreserve.gov/a</link><pubDate>Wed, 29 Jul 2026 12:00:00 GMT</pubDate></item></channel></rss>"
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                200,
                headers={
                    "content-type": "application/rss+xml",
                    "etag": '"v1"',
                    "last-modified": "Wed, 29 Jul 2026 12:00:00 GMT",
                },
                content=xml,
            )
        assert request.headers["if-none-match"] == '"v1"'
        assert request.headers["if-modified-since"] == "Wed, 29 Jul 2026 12:00:00 GMT"
        return httpx.Response(304)

    active = configured(settings, official_rss_enabled=True, official_rss_feeds_config=config)
    provider = OfficialRssNewsProvider(active, transport=httpx.MockTransport(handler))
    first = await provider.fetch_news(limit=10)
    second = await provider.fetch_news(limit=10)
    assert second == first and calls == 2
    health = await provider.health_check()
    assert health["feeds"]["fed"]["last_status_code"] == 304
    assert health["feeds"]["fed"]["cached_item_count"] == 1


@pytest.mark.asyncio
async def test_gdelt_identical_query_uses_cache_and_retry_after_is_recorded(settings) -> None:
    active = configured(settings, gdelt_enabled=True, gdelt_refresh_interval_seconds=900)
    calls = 0

    def success_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "articles": [
                    {
                        "title": "Central bank update",
                        "url": "https://trusted.example/gdelt",
                        "seendate": "20260729T120000Z",
                        "language": "English",
                    }
                ]
            },
        )

    provider = GdeltNewsProvider(active, transport=httpx.MockTransport(success_handler))
    first = await provider.fetch_news(limit=1)
    second = await provider.fetch_news(limit=1)
    assert first == second and calls == 1
    assert provider.requests_sent == 1 and provider.requests_skipped_from_cache == 1

    limited = GdeltNewsProvider(
        configured(settings, gdelt_enabled=True, gdelt_jitter_seconds=0),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                429,
                headers={"content-type": "application/json", "retry-after": "700"},
            )
        ),
    )
    with pytest.raises(ProviderRateLimitError) as caught:
        await limited.fetch_news(limit=1)
    assert caught.value.retry_after_seconds == 700
    assert limited.rate_limit_count == 1
    assert limited.last_status_code == 429
    assert limited.last_retry_after_seconds == 700


@pytest.mark.asyncio
async def test_rate_limiter_known_quota_path(monkeypatch) -> None:
    limiter = ProviderRateLimiter(1)
    limiter._timestamps.append(monotonic())

    async def no_wait(delay: float) -> None:
        assert delay > 0

    monkeypatch.setattr("app.providers.news.resilience.asyncio.sleep", no_wait)
    async with limiter:
        assert limiter._lock.locked()
    limiter._timestamps.clear()
    limiter._timestamps.append(monotonic() - 61)
    async with limiter:
        assert len(limiter._timestamps) == 1


class _CalendarRepository:
    configured = True
    last_error = None


@pytest.mark.asyncio
async def test_calendar_stream_upsert_and_sentiment_ensemble(settings, monkeypatch) -> None:
    calendar = EconomicCalendarService(
        settings,
        _CalendarRepository(),  # type: ignore[arg-type]
        EconomicCalendarAdapter(),
        lambda: ["EURUSD", "USDJPY"],
    )
    raw = {
        "id": "cpi",
        "event_name": "US CPI",
        "currency": "USD",
        "scheduled_at": datetime.now(UTC).isoformat(),
        "impact": "HIGH",
    }
    first, created = await calendar.upsert_stream("trading_economics", raw)
    second, created_again = await calendar.upsert_stream("trading_economics", {**raw, "actual": "2.8%"})
    assert created is True and created_again is False
    assert first.id == second.id and second.actual == "2.8%"

    ensemble_settings = configured(settings, news_finbert_enabled=True)
    sentiment = SentimentService(ensemble_settings)
    monkeypatch.setattr(
        sentiment.finbert,
        "analyze",
        lambda text: SentimentResult(
            label=SentimentLabel.BULLISH,
            score=0.6,
            confidence=0.8,
            analyzer="finbert",
        ),
    )
    result = sentiment.analyze(
        "Markets rally strongly",
        None,
        ProviderSentiment(
            provider="alpha_vantage",
            raw_score=0.3,
            normalized_score=0.3,
            normalized_confidence=0.7,
        ),
    )
    assert result.analyzer == "ensemble" and result.score is not None and result.score > 0


class _StreamCalendar:
    async def upsert_stream(self, provider: str, raw: dict):
        event = type("Event", (), {"id": f"{provider}:event"})()
        return event, True


class _FakeWebSocket:
    def __init__(self) -> None:
        self.sent: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return None

    async def send(self, message: str) -> None:
        self.sent.append(message)

    def __aiter__(self):
        values = iter(
            [
                json.dumps(
                    {
                        "topic": "calendar",
                        "calendarId": "event",
                        "event": "CPI",
                        "date": "2026-07-29T12:00:00Z",
                        "importance": 3,
                    }
                )
            ]
        )

        async def next_value():
            try:
                return next(values)
            except StopIteration as exc:
                raise StopAsyncIteration from exc

        return type("Iterator", (), {"__aiter__": lambda self: self, "__anext__": lambda self: next_value()})()


@pytest.mark.asyncio
async def test_trading_economics_managed_stream_consume_and_state(settings, monkeypatch) -> None:
    stream_settings = configured(
        settings,
        trading_economics_enabled=True,
        trading_economics_streaming_enabled=True,
        trading_economics_api_key="client",
        trading_economics_api_secret="secret",
    )
    bus = EventBus()
    websocket = _FakeWebSocket()
    monkeypatch.setattr("websockets.asyncio.client.connect", lambda *args, **kwargs: websocket)
    stream = TradingEconomicsStream(stream_settings, _StreamCalendar(), bus)  # type: ignore[arg-type]
    await stream._consume()
    received = await bus.next()
    assert websocket.sent and received.event_type == "news.calendar.created"
    assert stream.component()["status"] == "healthy"
    await stream.stop()
    stream.state.running = True
    stream.state.connected = False
    assert stream.component()["status"] == "degraded"
