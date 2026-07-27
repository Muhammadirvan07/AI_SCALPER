from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime

import httpx

from dashboard_api.app.file_registry import FileRegistry
from dashboard_api.app.snapshot_builder import SnapshotBuilder
from dashboard_api.app.news_provider import RemoteNewsProvider


def test_news_is_normalized_without_enabling_execution(test_settings) -> None:
    registry = FileRegistry(test_settings)
    registry.refresh()
    builder = SnapshotBuilder(test_settings, registry)
    snapshot, _ = asyncio.run(
        builder.rebuild(watcher_running=False, force=True)
    )

    event = snapshot.news.events[0]
    impact = snapshot.news.pair_impacts[0]
    assert event.title == "Uji kalender EUR"
    assert event.surprise == "ABOVE"
    assert impact.symbol == "EURUSD"
    assert all(item.pair_status != "OBSERVE" for item in snapshot.news.pair_impacts)
    assert impact.decision != "PAPER_READY"
    assert snapshot.safety.live_allowed is False
    assert snapshot.safety.live_trading == "LOCKED"


def test_legacy_sources_are_reported_not_rewritten(test_settings) -> None:
    registry = FileRegistry(test_settings)
    registry.refresh()
    builder = SnapshotBuilder(test_settings, registry)
    snapshot, _ = asyncio.run(
        builder.rebuild(watcher_running=False, force=True)
    )

    assert snapshot.source_contracts["market_news"].status == "COMPLIANT"
    assert snapshot.source_contracts["paper_orders"].status == "LEGACY"
    assert "schema_version" in snapshot.source_contracts["paper_orders"].missing_fields


def test_remote_news_timestamp_requires_provider_metadata() -> None:
    parsed = RemoteNewsProvider._source_timestamp(
        {"updated_at": "2026-07-25T00:05:00Z"}
    )
    assert parsed == datetime(2026, 7, 25, 0, 5, tzinfo=UTC)
    assert RemoteNewsProvider._source_timestamp([{"event": "legacy"}]) is None


def test_remote_weekly_calendar_array_uses_last_modified_metadata(
    test_settings,
) -> None:
    settings = replace(
        test_settings,
        news_api_url="https://calendar.test/weekly.json",
        news_provider_name="PROVIDER UJI",
        news_stale_after_seconds=7200,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        return httpx.Response(
            200,
            headers={"Last-Modified": "Sun, 26 Jul 2026 11:42:17 GMT"},
            json=[
                {
                    "title": "Keputusan Suku Bunga",
                    "country": "USD",
                    "date": "2026-07-29T14:00:00-04:00",
                    "impact": "High",
                    "forecast": "3.75%",
                    "previous": "3.75%",
                }
            ],
        )

    provider = RemoteNewsProvider(
        settings,
        transport=httpx.MockTransport(handler),
        now=lambda: datetime(2026, 7, 26, 12, 0, tzinfo=UTC),
    )
    value, meta = asyncio.run(provider.read())

    assert value["provider"] == "PROVIDER UJI"
    assert value["events"][0]["country"] == "USD"
    assert value["updated_at"] == "2026-07-26T11:42:17+00:00"
    assert meta.source_timestamp == datetime(2026, 7, 26, 11, 42, 17, tzinfo=UTC)
    assert meta.status == "fresh"


def test_configured_remote_error_is_exposed_in_news_state(test_settings) -> None:
    settings = replace(
        test_settings,
        news_api_url="https://calendar.test/weekly.json",
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    registry = FileRegistry(settings)
    registry.refresh()
    builder = SnapshotBuilder(settings, registry)
    builder.news_provider = RemoteNewsProvider(
        settings,
        transport=httpx.MockTransport(handler),
    )

    snapshot, _ = asyncio.run(builder.rebuild(watcher_running=False, force=True))

    assert snapshot.news.provider == "news_remote"
    assert snapshot.news.source_status == "unavailable"
    assert "News provider gagal" in snapshot.news.note
