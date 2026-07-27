from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from dashboard_api.app.main import create_app


def test_rest_health_and_snapshot(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        health = client.get("/api/health")
        snapshot = client.get("/api/v1/snapshot")
        news = client.get("/api/v1/news")
        readiness = client.get("/api/v1/decision-readiness")
        contracts = client.get("/api/v1/source-contracts")
        assert health.status_code == 200
        assert health.json()["watcher_running"] is True
        assert snapshot.status_code == 200
        assert snapshot.json()["safety"]["live_allowed"] is False
        assert snapshot.json()["summary"]["closed_orders"] == 1
        assert news.status_code == 200
        assert news.json()["news"]["events"][0]["id"] == "NEWS-EUR-1"
        assert readiness.json()["decision_readiness"]["decision_ready"] is False
        assert contracts.json()["schema_version"] == "1.1"


def test_websocket_initial_snapshot_and_heartbeat(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        with client.websocket_connect("/ws/v1/dashboard") as websocket:
            ready = websocket.receive_json()
            full = websocket.receive_json()
            heartbeat = websocket.receive_json()
            assert ready["type"] == "connection.ready"
            assert full["type"] == "snapshot.full"
            assert full["payload"]["safety"]["live_trading"] == "LOCKED"
            assert heartbeat["type"] == "heartbeat"


def test_websocket_broadcasts_file_update(
    test_settings,
    dashboard_root: Path,
) -> None:
    with TestClient(create_app(test_settings)) as client:
        with client.websocket_connect("/ws/v1/dashboard") as websocket:
            websocket.receive_json()
            initial = websocket.receive_json()
            original_version = initial["version"]
            path = dashboard_root / "trade_signals.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["generated_at"] = "2026-07-25T00:07:00Z"
            payload["all_decisions"][0]["strategy_score"] = 5
            path.write_text(json.dumps(payload), encoding="utf-8")
            for _ in range(10):
                event = websocket.receive_json()
                if event["type"] == "snapshot.updated":
                    assert event["version"] > original_version
                    assert event["payload"]["signals"][0]["score"] == 5
                    break
            else:
                raise AssertionError("snapshot.updated tidak diterima")
