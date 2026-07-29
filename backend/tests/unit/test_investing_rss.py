from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from app.adapters.investing_rss_adapter import InvestingRssAdapter
from app.adapters.news_adapter import NewsAdapter
from app.core.config import Settings
from app.providers.news.base import ProviderFetchError
from app.providers.news.investing_rss import InvestingRssNewsProvider
from app.schemas.news import NewsCategory
from app.services.news_deduplication import NewsDeduplicator

RSS = b"""<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"><channel><title>Forex</title><item>
<guid>story-1</guid><title>Dollar falls as Fed signals slower rate path</title>
<description><![CDATA[<p>Euro gains.</p><script>alert(1)</script>]]></description>
<pubDate>2026-07-29 04:00:00</pubDate><author>Reuters</author>
<link>https://www.investing.com/news/forex-news/dollar-falls?utm_source=rss&amp;ref=test</link>
</item></channel></rss>"""

ATOM = b"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>Crypto</title><entry>
<id>atom-1</id><title>Bitcoin rises after institutional demand improves</title>
<summary>Crypto markets gain.</summary><updated>2026-07-29T04:30:00Z</updated>
<author><name>Investing.com</name></author>
<link href="https://www.investing.com/news/cryptocurrency-news/bitcoin-rises" />
</entry></feed>"""


def make_settings(tmp_path: Path, feeds: list[dict], **overrides) -> Settings:
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    config = tmp_path / "investing_rss_feeds.json"
    config.write_text(json.dumps({"provider": "investing_rss", "feeds": feeds}), encoding="utf-8")
    values = {
        "app_env": "test",
        "ai_scalper_root": tmp_path,
        "data_directory": tmp_path / "data",
        "news_external_requests_enabled": True,
        "investing_rss_enabled": True,
        "investing_rss_feeds_config": config,
        "investing_rss_failure_threshold": 1,
        "alpha_vantage_enabled": False,
        "finnhub_enabled": False,
        "gdelt_enabled": False,
        "official_rss_enabled": False,
    }
    values.update(overrides)
    return Settings(**values)


def feed(feed_id: str = "forex", *, url: str = "https://www.investing.com/rss/news_1.rss", **values) -> dict:
    result = {
        "id": feed_id,
        "name": f"Investing.com {feed_id}",
        "url": url,
        "categories": ["FOREX"],
        "topics": [],
        "enabled": True,
        "verified": True,
        "official_domain": "investing.com",
        "verified_at": "2026-07-29T00:00:00Z",
    }
    result.update(values)
    return result


@pytest.mark.asyncio
async def test_valid_rss_headers_sanitization_and_conditional_304(tmp_path: Path) -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 2:
            assert request.headers["if-none-match"] == 'W/"rss"'
            assert request.headers["if-modified-since"] == "Wed, 29 Jul 2026 04:00:00 GMT"
            return httpx.Response(304)
        assert request.headers["user-agent"] == "AI_SCALPER-NewsIntelligence/1.0"
        assert "application/rss+xml" in request.headers["accept"]
        assert "cookie" not in request.headers
        return httpx.Response(
            200,
            content=RSS,
            headers={
                "content-type": "application/rss+xml; charset=utf-8",
                "etag": 'W/"rss"',
                "last-modified": "Wed, 29 Jul 2026 04:00:00 GMT",
            },
        )

    provider = InvestingRssNewsProvider(make_settings(tmp_path, [feed()]), transport=httpx.MockTransport(handler))
    first = await provider.fetch_news(limit=20)
    second = await provider.fetch_news(limit=20)
    assert first == second
    assert first[0]["summary"] == "Euro gains."
    assert provider.requests_sent == 2
    assert provider.requests_skipped_from_cache == 1
    assert provider.feed_cache["forex"].last_status_code == 304


@pytest.mark.asyncio
async def test_atom_multiple_feeds_and_partial_failure(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("missing.rss"):
            return httpx.Response(404, headers={"content-type": "text/xml"})
        return httpx.Response(200, content=ATOM, headers={"content-type": "application/atom+xml"})

    feeds = [
        feed("crypto", url="https://www.investing.com/rss/crypto.rss", categories=["CRYPTO"]),
        feed("missing", url="https://www.investing.com/rss/missing.rss"),
    ]
    provider = InvestingRssNewsProvider(make_settings(tmp_path, feeds), transport=httpx.MockTransport(handler))
    rows = await provider.fetch_news(limit=20)
    assert rows[0]["id"] == "atom-1"
    assert rows[0]["author"] == "Investing.com"
    assert provider.healthy_feed_count == 1
    assert provider.failed_feed_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(404, headers={"content-type": "text/xml"}), "HTTP 404"),
        (httpx.Response(200, text="not xml", headers={"content-type": "text/html"}), "content type"),
        (httpx.Response(200, text="<rss>", headers={"content-type": "text/xml"}), "invalid XML"),
        (httpx.Response(302, headers={"location": "https://evil.example/rss"}), "redirects are disabled"),
    ],
)
async def test_invalid_provider_responses_are_rejected(tmp_path: Path, response: httpx.Response, message: str) -> None:
    provider = InvestingRssNewsProvider(
        make_settings(tmp_path, [feed()]),
        transport=httpx.MockTransport(lambda _: response),
    )
    with pytest.raises(ProviderFetchError, match=message):
        await provider.fetch_news(limit=10)
    assert provider.feed_cache["forex"].circuit_state == "OPEN"


@pytest.mark.asyncio
async def test_rate_limit_timeout_oversize_and_last_known_good(tmp_path: Path) -> None:
    responses: list[object] = [
        httpx.Response(200, content=RSS, headers={"content-type": "application/rss+xml"}),
        httpx.Response(429, headers={"retry-after": "120", "content-type": "text/xml"}),
    ]

    def handler(_: httpx.Request) -> httpx.Response:
        response = responses.pop(0)
        assert isinstance(response, httpx.Response)
        return response

    provider = InvestingRssNewsProvider(make_settings(tmp_path, [feed()]), transport=httpx.MockTransport(handler))
    good = await provider.fetch_news(limit=10)
    cached = await provider.fetch_news(limit=10)
    assert cached == good
    assert provider.rate_limit_count == 1
    assert provider.last_retry_after_seconds == 120
    assert provider.last_known_good_available is True

    oversized = InvestingRssNewsProvider(
        make_settings(tmp_path / "large", [feed()], investing_rss_max_response_bytes=4096),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, content=b"x" * 4097, headers={"content-type": "text/xml"})
        ),
    )
    with pytest.raises(ProviderFetchError, match="size limit"):
        await oversized.fetch_news(limit=10)

    def timeout(_: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    timed_out = InvestingRssNewsProvider(
        make_settings(tmp_path / "timeout", [feed()]), transport=httpx.MockTransport(timeout)
    )
    with pytest.raises(ProviderFetchError, match="timed out"):
        await timed_out.fetch_news(limit=10)
    assert timed_out.requests_sent == 0


@pytest.mark.asyncio
async def test_xxe_and_private_or_unofficial_config_are_rejected(tmp_path: Path) -> None:
    xxe = b'<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><rss />'
    provider = InvestingRssNewsProvider(
        make_settings(tmp_path, [feed()]),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, content=xxe, headers={"content-type": "application/xml"})
        ),
    )
    with pytest.raises(ProviderFetchError, match="declarations"):
        await provider.fetch_news(limit=10)

    invalid = InvestingRssNewsProvider(make_settings(tmp_path / "invalid", [feed(url="https://evil.example/rss.xml")]))
    assert invalid.configured is False
    assert "invalid" in (invalid.configuration_error or "").lower()


def test_adapter_category_url_sanitization_and_missing_fields() -> None:
    adapter = InvestingRssAdapter()
    row = adapter.normalize(
        {
            "id": "one",
            "title": "Gold rises while oil supply faces disruption",
            "description": "<style>bad</style><p>Safe summary</p><img src=x onerror=alert(1)>",
            "url": "/news/commodities-news/gold-rises?utm_source=rss&ref=feed&article=1",
            "categories": ["COMMODITIES", "COMMODITIES"],
            "topics": ["COMMODITIES", "COMMODITIES"],
        },
        known_symbols=["XAUUSD"],
    )
    assert row["source"] == "Investing.com"
    assert row["summary"] == "Safe summary"
    assert row["url"] == "https://www.investing.com/news/commodities-news/gold-rises?article=1"
    assert row["category"] == NewsCategory.GOLD
    assert row["author"] is None
    assert row["image_url"] is None
    assert row["topics"] == ["COMMODITIES", "GOLD"]
    assert adapter.normalize({"title": "Forex", "url": "https://evil.example/a"}, known_symbols=[])["url"] is None


def test_adapter_category_variants_and_provider_helpers() -> None:
    adapter = InvestingRssAdapter()
    for category, expected in (
        ("CRYPTO", NewsCategory.CRYPTO),
        ("EQUITIES", NewsCategory.EQUITIES),
        ("INTEREST_RATE", NewsCategory.CENTRAL_BANK),
        ("COMMODITIES", NewsCategory.COMMODITIES),
    ):
        row = adapter.normalize(
            {"title": "Market update", "url": "/news/update", "categories": [category]},
            known_symbols=[],
        )
        assert row["category"] == expected

    assert adapter.normalize({"title": "No link"}, known_symbols=[])["url"] is None
    assert InvestingRssNewsProvider._retry_after(None) is None
    assert InvestingRssNewsProvider._retry_after("invalid") is None
    future = (datetime.now(UTC) + timedelta(seconds=90)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    retry_after = InvestingRssNewsProvider._retry_after(future)
    assert retry_after is not None and 0 < retry_after <= 90
    assert InvestingRssNewsProvider._plain_text(None, maximum=10) is None
    with pytest.raises(ValueError, match="private address"):
        InvestingRssNewsProvider._validate_url("https://127.0.0.1/rss", official_domain="127.0.0.1")


def test_adapter_invalid_date_becomes_unknown_and_cross_feed_deduplicates() -> None:
    raw = InvestingRssAdapter().normalize(
        {
            "id": "same-guid",
            "title": "Euro rises as ECB reviews rates",
            "url": "https://www.investing.com/news/forex-news/euro-rises?utm_source=all",
            "published_at": "invalid",
            "categories": ["FOREX"],
        },
        known_symbols=["EURUSD"],
    )
    generic = NewsAdapter()
    first = generic.normalize(raw, provider="investing_rss", known_symbols=["EURUSD"], fetched_at=datetime.now(UTC))
    second_raw = dict(raw, category="GENERAL", summary="Short", id="other-guid")
    second = generic.normalize(
        second_raw,
        provider="investing_rss",
        known_symbols=["EURUSD"],
        fetched_at=datetime.now(UTC),
    )
    marked = NewsDeduplicator().mark([second, first])
    canonical = next(item for item in marked if not item.is_duplicate)
    duplicate = next(item for item in marked if item.is_duplicate)
    assert first.published_at is None
    assert canonical.category == NewsCategory.FOREX
    assert duplicate.canonical_article_id == canonical.id


@pytest.mark.asyncio
async def test_provider_health_and_disabled_configuration(tmp_path: Path) -> None:
    disabled = InvestingRssNewsProvider(make_settings(tmp_path, [feed()], investing_rss_enabled=False))
    assert disabled.enabled is False
    assert disabled.configured is False
    assert await disabled.fetch_news(limit=10) == []

    provider = InvestingRssNewsProvider(
        make_settings(tmp_path / "active", [feed()]),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, content=RSS, headers={"content-type": "application/rss+xml"})
        ),
    )
    await provider.fetch_news(limit=10)
    health = await provider.health_check()
    assert health["feed_count"] == 1
    assert health["healthy_feed_count"] == 1
    assert health["feeds"]["forex"]["cached_item_count"] == 1
