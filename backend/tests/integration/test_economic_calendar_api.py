from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


def calendar_settings(settings: Settings, engine_root, *, actual: float | None = None) -> Settings:
    path = engine_root / "data" / "economic_calendar.json"
    scheduled = datetime.now(UTC) + timedelta(minutes=30)
    path.write_text(
        json.dumps(
            {
                "events": [
                    {
                        "id": "official-cpi-one",
                        "event_name": "US Consumer Price Index",
                        "description": "Official integration fixture used only by tests.",
                        "country": "United States",
                        "country_code": "US",
                        "currency": "USD",
                        "category": "CPI",
                        "impact": "CRITICAL",
                        "scheduled_at": scheduled.isoformat(),
                        "actual": actual,
                        "forecast": None,
                        "previous": 3.0,
                        "unit": "%",
                        "source": "Trusted test file",
                        "source_type": "LOCAL_FILE",
                        "verified": False,
                        "metadata": {"schedule_precision": "DATETIME"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    values = settings.model_dump()
    values.update(
        websocket_heartbeat_seconds=2,
        economic_calendar_external_requests_enabled=False,
        economic_calendar_file_provider_enabled=True,
        economic_calendar_file_path=path,
        file_economic_calendar_path=path,
    )
    return Settings(**values)


def test_native_calendar_endpoints_filters_health_and_safety(settings, engine_root) -> None:
    app = create_app(calendar_settings(settings, engine_root))
    with TestClient(app) as client:
        client.portal.call(app.state.container.economic_calendar_scheduler.refresh_now)
        response = client.get("/api/v1/economic-calendar?currency=USD&impact=CRITICAL")
        assert response.status_code == 200
        payload = response.json()
        assert payload["success"] is True and payload["data"]["total"] == 1
        event = payload["data"]["items"][0]
        assert event["forecast"] is None and event["actual"] is None
        assert event["affected_symbols"] and event["impact"] == "CRITICAL"

        today = datetime.now(UTC).date().isoformat()
        assert client.get(f"/api/v1/economic-calendar/today?date={today}&timezone=UTC").status_code == 200
        assert client.get("/api/v1/economic-calendar/upcoming").json()["data"]["total"] == 1
        assert client.get("/api/v1/economic-calendar/high-impact").json()["data"]["total"] == 1
        assert client.get("/api/v1/economic-calendar/live").status_code == 200
        assert client.get("/api/v1/economic-calendar/symbols/EURUSD").json()["data"]["total"] == 1
        assert client.get("/api/v1/economic-calendar/currencies/USD").json()["data"]["total"] == 1
        assert client.get(f"/api/v1/economic-calendar/{event['id']}").json()["data"]["id"] == event["id"]

        sources = client.get("/api/v1/economic-calendar/sources").json()["data"]
        assert any(source["name"] == "file" and source["healthy"] for source in sources)
        status = client.get("/api/v1/economic-calendar/status").json()["data"]
        assert status["read_only"] is True and status["engine_integration_enabled"] is False
        assert status["live_allowed"] is False and status["effective_max_lot"] <= 0.01
        health = client.get("/api/v1/economic-calendar/health").json()["data"]
        assert health["read_only"] is True and health["live_allowed"] is False
        guard = client.get("/api/v1/economic-calendar/guard-preview/EURUSD").json()["data"]
        assert guard["state"] == "INSUFFICIENT_DATA" and guard["creates_orders"] is False
        assert guard["diagnostic_only"] is True and guard["affects_execution"] is False
        diagnostic = client.get("/api/v1/diagnostics/calendar/EURUSD").json()["data"]
        assert diagnostic["diagnostic_only"] is True
        assert diagnostic["execution_guard_enabled"] is False and diagnostic["affects_execution"] is False
        assert diagnostic["next_event"]["forecast"] is None
        assert client.get("/api/v1/diagnostics/calendar").status_code == 200
        full_diagnostics = client.get("/api/v1/diagnostics").json()["data"]
        assert full_diagnostics["economic_calendar"]["affects_execution"] is False
        metrics = client.get("/api/v1/economic-calendar/metrics").json()["data"]
        assert metrics["diagnostic_only"] is True and metrics["effective_max_lot"] <= 0.01
        audit = client.get(f"/api/v1/economic-calendar/{event['id']}/audit?limit=25").json()["data"]
        assert audit["limit"] == 25 and audit["total"] >= 1

        assert client.get("/api/v1/economic-calendar?impact=IMPOSSIBLE").status_code == 422
        assert client.post("/api/v1/economic-calendar/orders", json={"symbol": "EURUSD"}).status_code in {404, 405}
        assert (
            client.post(
                "/api/v1/commands/refresh-economic-calendar",
                json={"command": "refresh_economic_calendar", "providers": ["https://evil.test"]},
            ).status_code
            == 404
        )
        risk = client.get("/api/v1/risk").json()["data"]
        assert risk["live_allowed"] is False and risk["effective_max_lot"] <= 0.01
        assert app.state.container.settings.economic_calendar_engine_integration_enabled is False
        assert app.state.container.settings.economic_calendar_execution_guard_enabled is False


def test_native_calendar_websocket_release_update(settings, engine_root) -> None:
    configured = calendar_settings(settings, engine_root)
    app = create_app(configured)
    with TestClient(app) as client:
        client.portal.call(app.state.container.economic_calendar_scheduler.refresh_now)
        with client.websocket_connect("/api/v1/ws", headers={"origin": "http://localhost:5173"}) as websocket:
            assert websocket.receive_json()["type"] == "connection.ready"
            websocket.send_json({"action": "subscribe", "channels": ["economic-calendar"]})
            assert "economic-calendar" in websocket.receive_json()["data"]["subscribed"]
            calendar_settings(configured, engine_root, actual=3.1)
            time.sleep(0.11)
            client.portal.call(app.state.container.economic_calendar_scheduler.refresh_now)
            received = None
            for _ in range(30):
                event = websocket.receive_json()
                if event["type"] == "calendar.event.released":
                    received = event
                    break
            assert received is not None
            assert received["data"]["actual"] == 3.1
            assert received["data"]["forecast"] is None
            assert received["channel"] == "economic-calendar"
