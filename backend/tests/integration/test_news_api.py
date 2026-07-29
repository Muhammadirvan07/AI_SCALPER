from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


def news_settings(base: Settings, engine_root, *, enabled: bool = True) -> Settings:
    values = base.model_dump()
    values["websocket_heartbeat_seconds"] = 2
    values.update(
        news_enabled=enabled,
        news_provider_mode="file",
        news_archive_path=engine_root / "news_intelligence_snapshot.json",
        economic_calendar_path=engine_root / "economic_calendar_snapshot.json",
        news_refresh_interval_seconds=60,
    )
    result = Settings(**values)
    result.websocket_heartbeat_seconds = 0.05
    return result


def write_sources(engine_root, *, second: bool = False) -> None:
    now = datetime.now(UTC)
    items = [
        {
            "id": "story-1",
            "title": "ECB signals rate cut as inflation cools",
            "summary": "Euro outlook improves and EURUSD gains.",
            "url": "https://trusted.example/story-1",
            "published_at": now.isoformat(),
            "language": "en",
        }
    ]
    if second:
        items.append(
            {
                "id": "story-2",
                "title": "Gold rallies sharply as dollar weakens",
                "summary": "XAUUSD reaches a record high.",
                "url": "https://trusted.example/story-2",
                "published_at": now.isoformat(),
                "language": "en",
                "is_breaking": True,
            }
        )
    engine_root.joinpath("news_intelligence_snapshot.json").write_text(json.dumps({"items": items}), encoding="utf-8")
    engine_root.joinpath("economic_calendar_snapshot.json").write_text(
        json.dumps(
            {
                "provider": "trusted-fixture",
                "events": [
                    {
                        "id": "cpi-1",
                        "event_name": "US CPI",
                        "currency": "USD",
                        "country": "US",
                        "impact": "HIGH",
                        "scheduled_at": (now + timedelta(hours=1)).isoformat(),
                        "actual": None,
                        "forecast": "2.8%",
                        "previous": "3.0%",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_news_rest_endpoints_provider_state_and_safety(settings, engine_root) -> None:
    write_sources(engine_root)
    app = create_app(news_settings(settings, engine_root))
    with TestClient(app) as client:
        time.sleep(0.05)
        client.portal.call(app.state.container.news_scheduler.refresh_now)
        paths = [
            "/api/v1/news",
            "/api/v1/news/latest",
            "/api/v1/news/breaking",
            "/api/v1/news/symbols/EURUSD",
            "/api/v1/news/symbols/EURUSD/sentiment",
            "/api/v1/news/symbols/EURUSD/summary",
            "/api/v1/news/sentiment",
            "/api/v1/news/sentiment/overview",
            "/api/v1/news/sentiment/timeline",
            "/api/v1/news/sentiment/distribution",
            "/api/v1/news/calendar",
            "/api/v1/news/calendar/today",
            "/api/v1/news/calendar/upcoming",
            "/api/v1/news/calendar/high-impact",
            "/api/v1/news/providers",
            "/api/v1/news/providers/file",
            "/api/v1/news/health",
            "/api/v1/news/status",
            "/api/v1/news/guard-preview/EURUSD",
        ]
        for path in paths:
            response = client.get(path)
            assert response.status_code == 200, (path, response.text)
            body = response.json()
            assert body["success"] is True
            assert "stale" in body["meta"]
        latest = client.get("/api/v1/news/latest").json()
        assert latest["data"]["total"] == 1
        item = latest["data"]["items"][0]
        assert item["symbols"] == ["EURUSD"]
        assert item["sentiment"]["analyzer"] == "baseline"
        assert item["url"] == "https://trusted.example/story-1"
        filtered = client.get(
            "/api/v1/news",
            params={
                "symbol": "EURUSD",
                "currency": "EUR",
                "category": "CENTRAL_BANK",
                "sentiment": "NEUTRAL",
                "impact": "HIGH",
                "provider": "file",
                "topic": "central_bank",
                "language": "en",
                "start_time": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
                "end_time": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
                "search": "ECB",
                "include_duplicates": True,
            },
        )
        assert filtered.status_code == 200
        assert client.get(f"/api/v1/news/{item['id']}").status_code == 200
        assert client.get("/api/v1/news/not-found").status_code == 404
        provider = client.get("/api/v1/news/providers/file").json()["data"]
        assert provider["capability_details"]["financial_news"] is True
        assert provider["circuit_state"] == "CLOSED"
        status = client.get("/api/v1/news/status").json()["data"]
        assert status["state"] == "live"
        assert status["live_allowed"] is False
        assert status["effective_max_lot"] == 0.01
        preview = client.get("/api/v1/news/guard-preview/EURUSD").json()["data"]
        assert preview["read_only"] is True and preview["creates_orders"] is False


def test_news_disabled_and_invalid_filters(settings, engine_root) -> None:
    app = create_app(news_settings(settings, engine_root, enabled=False))
    with TestClient(app) as client:
        response = client.get("/api/v1/news/latest")
        assert response.status_code == 200
        assert response.json()["meta"]["data_status"] == "disabled"
        assert client.get("/api/v1/news?search=" + "x" * 201).status_code == 422
        assert client.get("/api/v1/news?impact=IMPOSSIBLE").status_code == 422
        assert client.get("/api/v1/news?topic=raw%20frontend%20query").status_code == 422
        assert client.post("/api/v1/news/fetch", json={"url": "http://127.0.0.1/private"}).status_code in {404, 405}


def test_news_websocket_channels_and_duplicate_suppression(settings, engine_root) -> None:
    write_sources(engine_root)
    app = create_app(news_settings(settings, engine_root))
    with TestClient(app) as client:
        time.sleep(0.05)
        with client.websocket_connect("/api/v1/ws", headers={"origin": "http://localhost:5173"}) as websocket:
            websocket.receive_json()
            websocket.send_json(
                {
                    "action": "subscribe",
                    "channels": ["news", "news:breaking", "news:sentiment", "news:calendar", "news:symbol:EURUSD"],
                }
            )
            subscribed = websocket.receive_json()
            assert "news:symbol:EURUSD" in subscribed["data"]["subscribed"]
            write_sources(engine_root, second=True)
            client.portal.call(app.state.container.news_scheduler.refresh_now)
            found = []
            for _ in range(20):
                event = websocket.receive_json()
                if event["type"].startswith("news."):
                    found.append(event["type"])
                if "news.breaking.created" in found and "news.sentiment.updated" in found:
                    break
            assert "news.article.created" in found
            assert "news.breaking.created" in found
            assert "news.sentiment.updated" in found
            client.portal.call(app.state.container.news_scheduler.refresh_now)


def test_news_does_not_expose_order_or_safety_mutation(settings, engine_root) -> None:
    app = create_app(news_settings(settings, engine_root))
    with TestClient(app) as client:
        assert client.post("/api/v1/news/orders", json={"symbol": "EURUSD"}).status_code in {404, 405}
        assert client.post("/api/v1/news/safety", json={"live_allowed": True, "max_lot": 1}).status_code in {
            404,
            405,
        }
        assert client.post("/api/v1/commands/refresh-news", json={"command": "enable_live"}).status_code == 404
        assert (
            client.post(
                "/api/v1/commands/refresh-news",
                json={"command": "refresh_news", "providers": ["unknown_provider"], "force": True},
            ).status_code
            == 404
        )
        risk = client.get("/api/v1/risk").json()["data"]
        assert risk["live_allowed"] is False
        assert risk["effective_max_lot"] <= 0.01


def test_recent_articles_remain_canonical_and_latest_fallback_is_explicit(settings, engine_root) -> None:
    now = datetime.now(UTC)
    repeated = {
        "id": "official-release",
        "title": "Official policy release",
        "summary": "Verified official release outside the realtime window.",
        "url": "https://trusted.example/official-release",
        "published_at": (now - timedelta(hours=120)).isoformat(),
        "language": "en",
        "is_breaking": True,
    }
    historical = {
        "id": "historical-release",
        "title": "Older official policy release",
        "url": "https://trusted.example/historical-release",
        "published_at": (now - timedelta(hours=169)).isoformat(),
        "language": "en",
    }
    engine_root.joinpath("news_intelligence_snapshot.json").write_text(
        json.dumps({"items": [repeated, {**repeated, "id": "duplicate-release"}, historical]}),
        encoding="utf-8",
    )
    engine_root.joinpath("economic_calendar_snapshot.json").write_text('{"events": []}', encoding="utf-8")
    app = create_app(news_settings(settings, engine_root))
    with TestClient(app) as client:
        live = client.get("/api/v1/news/latest?freshness=live&fallback=none").json()
        assert live["data"]["total"] == 0
        assert live["data"]["recent_article_count"] == 1
        assert live["data"]["historical_article_count"] == 1

        fallback = client.get("/api/v1/news/latest?freshness=live&fallback=recent").json()
        assert fallback["data"]["total"] == 1
        assert fallback["data"]["fallback_applied"] is True
        assert fallback["data"]["effective_freshness"] == "recent"
        assert fallback["meta"]["fallback_applied"] is True
        article = fallback["data"]["items"][0]
        assert article["freshness_status"] == "RECENT"
        assert article["is_realtime"] is False
        assert article["is_recent"] is True
        assert article["is_breaking"] is False
        assert article["stale_reason"] == "Article is outside the realtime news window."

        recent = client.get("/api/v1/news?freshness=recent").json()
        assert recent["data"]["total"] == 1
        status = client.get("/api/v1/news/status").json()["data"]
        assert status["raw_article_count"] == 3
        assert status["canonical_article_count"] == 2
        assert status["realtime_article_count"] == 0
        assert status["recent_article_count"] == 1
        assert status["historical_article_count"] == 1
        assert status["live_allowed"] is False
        assert status["effective_max_lot"] == 0.01
