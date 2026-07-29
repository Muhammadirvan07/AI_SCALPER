from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from app.adapters.alpha_vantage_news_adapter import AlphaVantageNewsAdapter
from app.adapters.file_news_adapter import FileNewsAdapter
from app.adapters.finnhub_news_adapter import FinnhubNewsAdapter
from app.adapters.gdelt_news_adapter import GdeltNewsAdapter
from app.adapters.official_rss_adapter import OfficialRssAdapter
from app.adapters.trading_economics_calendar_adapter import TradingEconomicsCalendarAdapter
from app.core.config import Settings
from app.providers.news.alpha_vantage import AlphaVantageNewsProvider
from app.providers.news.base import NewsQuery, ProviderCircuitOpenError, ProviderFetchError, ProviderRateLimitError
from app.providers.news.finnhub import FinnhubNewsProvider
from app.providers.news.gdelt import GdeltNewsProvider
from app.providers.news.official_rss import OfficialRssNewsProvider
from app.providers.news.orchestrator import NewsProviderOrchestrator
from app.providers.news.resilience import ProviderCircuitBreaker
from app.providers.news.trading_economics import TradingEconomicsCalendarProvider
from app.schemas.news import CircuitState


def provider_settings(settings: Settings, **updates) -> Settings:
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


@pytest.mark.asyncio
async def test_alpha_vantage_provider_and_adapter_normalize_tickers_and_sentiment(settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["function"] == "NEWS_SENTIMENT"
        assert "FOREX:EUR" in request.url.params["tickers"]
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "feed": [
                    {
                        "title": "ECB supports euro",
                        "summary": "EUR outlook improves",
                        "url": "https://trusted.example/alpha",
                        "time_published": "20260729T120000",
                        "source": "Trusted Wire",
                        "authors": ["Reporter"],
                        "topics": [{"topic": "economy_monetary"}],
                        "overall_sentiment_score": "0.31",
                        "overall_sentiment_label": "Somewhat-Bullish",
                        "ticker_sentiment": [{"ticker": "FOREX:EUR", "relevance_score": "0.8"}],
                    }
                ]
            },
        )

    configured = provider_settings(settings, alpha_vantage_enabled=True, alpha_vantage_api_key="secret")
    provider = AlphaVantageNewsProvider(configured, transport=httpx.MockTransport(handler))
    rows = await provider.fetch_news(symbols=["EURUSD"], limit=10)
    normalized = AlphaVantageNewsAdapter().normalize(rows[0], known_symbols=["EURUSD", "EURJPY", "XAUUSD"])
    assert normalized["symbols"] == ["EURJPY", "EURUSD"]
    assert normalized["provider_sentiment"]["raw_label"] == "Somewhat-Bullish"
    assert normalized["provider_sentiment"]["normalized_score"] == 0.31
    assert normalized["published_at"] == "2026-07-29T12:00:00+00:00"


@pytest.mark.asyncio
async def test_alpha_vantage_rate_limit_is_not_an_empty_success(settings) -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"Note": "API call frequency rate limit reached"},
        )
    )
    configured = provider_settings(settings, alpha_vantage_enabled=True, alpha_vantage_api_key="secret")
    with pytest.raises(ProviderRateLimitError):
        await AlphaVantageNewsProvider(configured, transport=transport).fetch_news(limit=10)


@pytest.mark.asyncio
async def test_finnhub_provider_reports_capability_after_safe_probe(settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/news")
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[
                {
                    "id": 7,
                    "headline": "Dollar rises",
                    "summary": "FX markets move",
                    "url": "https://trusted.example/finnhub",
                    "datetime": 1785326400,
                    "category": "forex",
                    "related": "EURUSD",
                    "source": "Wire",
                }
            ],
        )

    configured = provider_settings(settings, finnhub_enabled=True, finnhub_api_key="secret")
    provider = FinnhubNewsProvider(configured, transport=httpx.MockTransport(handler))
    rows = await provider.fetch_news(categories=["FOREX"], limit=10)
    normalized = FinnhubNewsAdapter().normalize(rows[0], known_symbols=["EURUSD"])
    assert provider.capabilities["forex_news"] is True
    assert normalized["symbols"] == ["EURUSD"]
    assert normalized["category"] == "FOREX"


@pytest.mark.asyncio
async def test_gdelt_uses_trusted_query_template_and_language_allowlist(settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        query = request.url.params["query"]
        assert "raw frontend query" not in query
        assert len(query) <= 400
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "articles": [
                    {
                        "title": "Global sanctions escalate",
                        "url": "https://trusted.example/gdelt",
                        "seendate": "20260729T120000Z",
                        "domain": "trusted.example",
                        "language": "English",
                        "sourcecountry": "United States",
                    },
                    {
                        "title": "Unsupported language",
                        "url": "https://trusted.example/other",
                        "language": "French",
                    },
                ]
            },
        )

    configured = provider_settings(settings, gdelt_enabled=True)
    provider = GdeltNewsProvider(configured, transport=httpx.MockTransport(handler))
    rows = await provider.fetch_news(categories=["GEOPOLITICS"], limit=10)
    normalized = GdeltNewsAdapter().normalize(rows[0], known_symbols=[])
    assert len(rows) == 1
    assert normalized["language"] == "en"
    assert normalized["category"] == "GEOPOLITICS"


@pytest.mark.asyncio
async def test_trading_economics_provider_and_adapter_preserve_calendar_fields(settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/calendar"
        assert "secret" in request.url.params["c"]
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[
                {
                    "CalendarId": "87220",
                    "Date": "2026-07-29T13:30:00",
                    "Country": "United States",
                    "Category": "Non Farm Payrolls",
                    "Event": "Nonfarm Payrolls",
                    "Reference": "Jul/26",
                    "Source": "BLS",
                    "Actual": "178K",
                    "Previous": "142K",
                    "Revised": "141K",
                    "Forecast": "175K",
                    "Importance": 3,
                    "Currency": "$",
                    "Unit": "K",
                    "LastUpdate": "2026-07-29T13:31:00",
                }
            ],
        )

    configured = provider_settings(
        settings,
        trading_economics_enabled=True,
        trading_economics_api_key="client",
        trading_economics_api_secret="secret",
    )
    provider = TradingEconomicsCalendarProvider(configured, transport=httpx.MockTransport(handler))
    rows = await provider.fetch_calendar(limit=10)
    normalized = TradingEconomicsCalendarAdapter().normalize(rows[0], known_symbols=[])
    assert normalized["currency"] == "USD"
    assert normalized["impact"] == "HIGH"
    assert normalized["revised_previous"] == "141K"
    assert normalized["reference_period"] == "Jul/26"


@pytest.mark.asyncio
async def test_official_rss_only_reads_trusted_configured_feeds(settings, engine_root: Path) -> None:
    config = engine_root / "official_feeds.json"
    config.write_text(
        json.dumps(
            {
                "feeds": [
                    {
                        "id": "fed",
                        "name": "Federal Reserve",
                        "url": "https://www.federalreserve.gov/feeds/press_monetary.xml",
                        "official_domain": "federalreserve.gov",
                        "verified": True,
                        "currencies": ["USD"],
                        "countries": ["US"],
                        "categories": ["CENTRAL_BANK"],
                        "enabled": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    xml = b"""<rss><channel><item><guid>fed-1</guid><title>Federal Reserve statement</title><link>https://www.federalreserve.gov/newsevents/test.htm</link><description>Policy update</description><pubDate>Wed, 29 Jul 2026 12:00:00 GMT</pubDate></item></channel></rss>"""
    configured = provider_settings(
        settings,
        official_rss_enabled=True,
        official_rss_feeds_config=config,
    )
    provider = OfficialRssNewsProvider(
        configured,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, headers={"content-type": "text/xml"}, content=xml)
        ),
    )
    rows = await provider.fetch_news(limit=10)
    normalized = OfficialRssAdapter().normalize(rows[0], known_symbols=["EURUSD"])
    assert provider.configured is True
    assert normalized["currencies"] == ["USD"]
    assert normalized["category"] == "CENTRAL_BANK"


class _FakeProvider:
    def __init__(self, name: str, *, fail: bool = False) -> None:
        self.name = name
        self.enabled = True
        self.configured = True
        self.capabilities: dict[str, bool | None] = {"financial_news": True}
        self.fail = fail

    async def fetch_news(self, **kwargs) -> list[dict]:
        del kwargs
        if self.fail:
            raise ProviderFetchError("provider offline")
        return [{"title": "Canonical story", "url": f"https://{self.name}.example/story"}]

    async def health_check(self) -> dict:
        return {}


@pytest.mark.asyncio
async def test_orchestrator_partial_success_does_not_fail_domain(settings) -> None:
    orchestrator = NewsProviderOrchestrator(settings, lambda: ["EURUSD"])
    orchestrator.register_news(
        _FakeProvider("primary", fail=True), FileNewsAdapter(), priority=1, max_requests_per_minute=None
    )
    orchestrator.register_news(_FakeProvider("fallback"), FileNewsAdapter(), priority=2, max_requests_per_minute=None)
    result = await orchestrator.collect(NewsQuery(limit=10), force=True)
    assert result.partial is True
    assert result.providers_failed == ["primary"]
    assert result.providers_succeeded == ["fallback"]
    assert len(result.items) == 1


def test_provider_circuit_breaker_closed_open_half_open_and_force_safety() -> None:
    breaker = ProviderCircuitBreaker(failure_threshold=2, cooldown_seconds=60)
    breaker.failure()
    assert breaker.state == CircuitState.CLOSED
    breaker.failure()
    assert breaker.state == CircuitState.OPEN
    with pytest.raises(ProviderCircuitOpenError):
        breaker.allow_request(force=True)
    breaker.cooldown_until = datetime.now(UTC) - timedelta(seconds=1)
    breaker.allow_request()
    assert breaker.state == CircuitState.HALF_OPEN
    breaker.success()
    assert breaker.state == CircuitState.CLOSED and breaker.failure_count == 0
    breaker.open_for(120)
    assert breaker.state == CircuitState.OPEN and breaker.cooldown_until is not None
