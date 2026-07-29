from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.adapters.economic_calendar_adapter import EconomicCalendarAdapter
from app.adapters.news_adapter import NewsAdapter
from app.core.config import Settings
from app.core.exceptions import InvalidDataFormatError
from app.providers.news.base import ProviderFetchError, ProviderRateLimitError
from app.providers.news.rss_provider import RSSNewsProvider
from app.schemas.news import ImpactLevel, NewsCategory, SentimentLabel
from app.services.news_deduplication import NewsDeduplicator
from app.services.news_scoring import impact_level, score_impact
from app.services.sentiment_service import BaselineSentimentAnalyzer, label_for_score


def article(adapter: NewsAdapter, **overrides):
    raw = {
        "title": "ECB signals stronger euro as inflation cools",
        "summary": "European Central Bank outlook supports EURUSD gains.",
        "url": "https://news.example/article?utm_source=test",
        "published_at": datetime.now(UTC).isoformat(),
        **overrides,
    }
    return adapter.normalize(
        raw, provider="fixture", known_symbols=["EURUSD", "XAUUSD", "BTCUSD"], fetched_at=datetime.now(UTC)
    )


def test_news_adapter_normalizes_optional_fields_symbols_and_url() -> None:
    result = article(NewsAdapter(), author=None, image_url=None, category="central-bank")
    assert result.author is None
    assert result.image_url is None
    assert result.category == NewsCategory.CENTRAL_BANK
    assert result.symbols == ["EURUSD"]
    assert result.currencies == ["EUR"]
    assert "utm_source" not in str(result.url)
    assert result.raw_provider_id is None


def test_news_adapter_handles_invalid_date_unknown_category_and_rejects_url() -> None:
    result = article(NewsAdapter(), published_at="not-a-date", category="new-provider-category")
    assert result.published_at is None
    assert result.category in {NewsCategory.CENTRAL_BANK, NewsCategory.INFLATION}
    with pytest.raises(InvalidDataFormatError):
        article(NewsAdapter(), url="file:///etc/passwd")


@pytest.mark.parametrize(
    ("title", "expected"),
    [
        ("Dollar rallies sharply after strong jobs beat", SentimentLabel.VERY_BULLISH),
        ("Euro plunges as recession crisis deepens", SentimentLabel.VERY_BEARISH),
        ("Central bank publishes meeting schedule", SentimentLabel.NEUTRAL),
    ],
)
def test_baseline_sentiment_boundaries(title: str, expected: SentimentLabel) -> None:
    result = BaselineSentimentAnalyzer().analyze(title, None)
    assert result.label == expected
    assert result.analyzer == "baseline"
    assert -1 <= (result.score or 0) <= 1


def test_baseline_sentiment_negation_and_conflicting_text() -> None:
    analyzer = BaselineSentimentAnalyzer()
    negated = analyzer.analyze("Outlook is not weak", None)
    conflicting = analyzer.analyze("Stocks rally", "Markets plunge amid recession crisis")
    assert (negated.score or 0) > 0
    assert conflicting.score is not None
    assert label_for_score(-0.60) == SentimentLabel.VERY_BEARISH
    assert label_for_score(0.60) == SentimentLabel.VERY_BULLISH


def test_impact_scoring_is_explainable_and_bounded() -> None:
    adapter = NewsAdapter()
    high = article(adapter, title="Federal Reserve emergency rate decision", is_breaking=True)
    low = article(adapter, title="Weekly technical market analysis", summary="Neutral outlook")
    high_score, high_level = score_impact(high)
    low_score, low_level = score_impact(low)
    assert high_score >= 0.75 and high_level == ImpactLevel.CRITICAL
    assert low_score < high_score
    assert low_level in {ImpactLevel.LOW, ImpactLevel.MEDIUM}
    assert impact_level(0.24) == ImpactLevel.LOW
    assert impact_level(0.25) == ImpactLevel.MEDIUM
    assert impact_level(0.50) == ImpactLevel.HIGH
    assert impact_level(0.75) == ImpactLevel.CRITICAL


def test_deduplication_same_url_similar_story_and_distinct_story() -> None:
    adapter = NewsAdapter()
    published = datetime.now(UTC).isoformat()
    first = article(
        adapter,
        title="ECB signals rate cut after inflation cools",
        url="https://one.example/story",
        published_at=published,
    )
    same_url = article(
        adapter, title="ECB confirms monetary update", url="https://one.example/story", published_at=published
    )
    similar = article(
        adapter,
        title="ECB signals a rate cut after inflation cools",
        url="https://two.example/story",
        published_at=published,
    )
    distinct = article(
        adapter, title="Bitcoin network upgrade completes", url="https://three.example/story", published_at=published
    )
    marked = NewsDeduplicator().mark([first, same_url, similar, distinct])
    assert sum(item.is_duplicate for item in marked) == 2
    assert sum(not item.is_duplicate for item in marked) == 2
    assert all(item.duplicate_group_id for item in marked if item.is_duplicate)


def test_generic_relevance_for_metal_crypto_and_central_bank() -> None:
    adapter = NewsAdapter()
    gold = article(adapter, title="Gold XAUUSD rallies as dollar weakens", url="https://news.example/gold")
    crypto = article(adapter, title="Bitcoin BTCUSD gains after regulation update", url="https://news.example/btc")
    assert "XAUUSD" in gold.symbols
    assert "BTCUSD" in crypto.symbols
    assert any(match.breakdown["direct_symbol"] > 0 for match in gold.relevance)


def test_economic_calendar_adapter_preserves_null_values() -> None:
    event = EconomicCalendarAdapter().normalize(
        {
            "title": "US CPI",
            "currency": "usd",
            "scheduled_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "impact": "HIGH",
            "actual": None,
            "forecast": None,
            "previous": None,
        },
        provider="fixture",
        known_symbols=["EURUSD", "USDJPY", "XAUUSD"],
    )
    assert event.actual is None and event.forecast is None and event.previous is None
    assert event.impact == ImpactLevel.HIGH
    assert set(event.symbols) == {"EURUSD", "USDJPY", "XAUUSD"}


def rss_settings(settings: Settings, **overrides) -> Settings:
    values = settings.model_dump()
    values["websocket_heartbeat_seconds"] = 2
    configured = {
        "news_provider_mode": "rss",
        "news_rss_feeds": "https://news.example/feed.xml",
        "news_allowed_hosts": "news.example",
        "news_external_requests_enabled": True,
    }
    configured.update(overrides)
    values.update(configured)
    result = Settings(**values)
    result.websocket_heartbeat_seconds = 0.05
    return result


@pytest.mark.asyncio
async def test_rss_provider_success_and_rfc_timestamp(settings) -> None:
    xml = b"""<?xml version='1.0'?><rss><channel><title>Trusted Feed</title><item><guid>a1</guid><title>Gold rallies</title><link>https://news.example/a1</link><description>Dollar weakens</description><pubDate>Wed, 29 Jul 2026 01:00:00 GMT</pubDate></item></channel></rss>"""
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, headers={"content-type": "application/rss+xml"}, content=xml)
    )
    rows = await RSSNewsProvider(rss_settings(settings), transport=transport).fetch_latest(limit=10)
    normalized = NewsAdapter().normalize(
        rows[0], provider="rss", known_symbols=["XAUUSD"], fetched_at=datetime.now(UTC)
    )
    assert rows[0]["source"] == "Trusted Feed"
    assert normalized.published_at == datetime(2026, 7, 29, 1, tzinfo=UTC)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "headers", "content", "error"),
    [
        (429, {"content-type": "application/rss+xml"}, b"", ProviderRateLimitError),
        (200, {"content-type": "text/html"}, b"<html></html>", ProviderFetchError),
        (200, {"content-type": "application/rss+xml", "content-length": "9999999"}, b"x", ProviderFetchError),
        (200, {"content-type": "application/rss+xml"}, b"not-xml", ProviderFetchError),
    ],
)
async def test_rss_provider_rejects_unsafe_or_invalid_responses(settings, status, headers, content, error) -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(status, headers=headers, content=content))
    provider = RSSNewsProvider(rss_settings(settings, news_max_response_bytes=4096), transport=transport)
    with pytest.raises(error):
        await provider.fetch_latest(limit=10)


@pytest.mark.asyncio
async def test_rss_provider_timeout_and_external_disabled(settings) -> None:
    def timeout(request):
        raise httpx.ReadTimeout("timeout", request=request)

    provider = RSSNewsProvider(rss_settings(settings), transport=httpx.MockTransport(timeout))
    with pytest.raises(ProviderFetchError):
        await provider.fetch_latest(limit=10)
    disabled = RSSNewsProvider(rss_settings(settings, news_external_requests_enabled=False))
    assert await disabled.fetch_latest(limit=10) == []


def test_rss_provider_rejects_private_and_non_allowlisted_hosts(settings) -> None:
    private = rss_settings(settings, news_rss_feeds="http://127.0.0.1/feed", news_allowed_hosts="127.0.0.1")
    provider = RSSNewsProvider(private)
    assert provider.configuration_error == "Private RSS addresses are not allowed"
    mismatch = rss_settings(settings, news_allowed_hosts="other.example")
    provider = RSSNewsProvider(mismatch)
    assert "not allowlisted" in (provider.configuration_error or "")
