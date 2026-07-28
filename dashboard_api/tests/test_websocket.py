from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from dashboard_api.app.main import create_app


ALLOWED_ORIGIN_HEADERS = {"origin": "http://localhost:5173"}


def test_rest_health_and_snapshot(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        health = client.get("/api/health")
        snapshot = client.get("/api/v1/snapshot")
        news = client.get("/api/v1/news")
        readiness = client.get("/api/v1/decision-readiness")
        contracts = client.get("/api/v1/source-contracts")
        progress = client.get("/api/v1/project-progress")
        brokers = client.get("/api/v1/broker-readiness")
        assert health.status_code == 200
        assert health.json()["watcher_running"] is True
        assert snapshot.status_code == 200
        assert snapshot.json()["safety"]["live_allowed"] is False
        assert snapshot.json()["summary"]["closed_orders"] == 1
        assert news.status_code == 200
        assert news.json()["news"]["events"][0]["id"] == "NEWS-EUR-1"
        assert readiness.json()["decision_readiness"]["decision_ready"] is False
        assert contracts.json()["schema_version"] == "1.2"
        assert progress.json()["project_progress"]["gates_total"] == 4
        assert len(brokers.json()["broker_readiness"]) == 2


def test_documentation_endpoints_are_allowlisted_and_read_only(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        listing = client.get("/api/v1/documentation")
        document = client.get("/api/v1/documentation/api-contract")
        missing = client.get("/api/v1/documentation/../../etc/passwd")
        openapi = client.get("/openapi.json").json()

        assert listing.status_code == 200
        assert len(listing.json()["documents"]) == 5
        assert document.status_code == 200
        assert document.text.startswith("# Kontrak uji")
        assert missing.status_code == 404
        for path_item in openapi["paths"].values():
            assert not {"post", "put", "patch", "delete"}.intersection(path_item)


def test_websocket_initial_snapshot_and_heartbeat(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        with client.websocket_connect(
            "/ws/v1/dashboard",
            headers=ALLOWED_ORIGIN_HEADERS,
        ) as websocket:
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
        with client.websocket_connect(
            "/ws/v1/dashboard",
            headers=ALLOWED_ORIGIN_HEADERS,
        ) as websocket:
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


@pytest.mark.parametrize(
    "headers",
    (
        {},
        {"origin": "https://attacker.example"},
        {"origin": "http://localhost.evil.example:5173"},
        {"origin": "null"},
    ),
)
def test_websocket_rejects_missing_or_untrusted_origin(
    test_settings,
    headers: dict[str, str],
) -> None:
    with TestClient(create_app(test_settings)) as client:
        with pytest.raises(WebSocketDisconnect) as raised:
            with client.websocket_connect(
                "/ws/v1/dashboard",
                headers=headers,
            ):
                pass
        assert raised.value.code == 1008
