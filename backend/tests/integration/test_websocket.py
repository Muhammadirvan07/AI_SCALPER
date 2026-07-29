from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from starlette.websockets import WebSocketDisconnect

from app.realtime.connection_manager import ConnectionManager


def _receive_event(
    websocket: Any,
    expected_type: str,
    *,
    max_messages: int = 10,
) -> dict[str, Any]:
    """Receive a target event while allowing protocol heartbeats to interleave."""
    for _ in range(max_messages):
        event = websocket.receive_json()
        if event["type"] == expected_type:
            return event
        assert event["type"] == "connection.heartbeat"
    raise AssertionError(f"WebSocket event {expected_type!r} was not received")


def test_websocket_connect_subscribe_unsubscribe_ping_and_invalid(client) -> None:
    with client.websocket_connect("/api/v1/ws", headers={"origin": "http://localhost:5173"}) as websocket:
        ready = websocket.receive_json()
        assert ready["type"] == "connection.ready"
        assert ready["sequence"] > 0
        websocket.send_json({"action": "subscribe", "channels": ["market:EURUSD", "signals"]})
        subscribed = websocket.receive_json()
        assert "market:EURUSD" in subscribed["data"]["subscribed"]
        websocket.send_json({"action": "unsubscribe", "channels": ["signals"]})
        unsubscribed = websocket.receive_json()
        assert "signals" not in unsubscribed["data"]["subscribed"]
        websocket.send_text("not-json")
        assert websocket.receive_json()["data"]["code"] == "INVALID_MESSAGE"
        websocket.send_json({"action": "ping", "channels": []})
        assert websocket.receive_json()["type"] == "connection.pong"


def test_websocket_heartbeat_and_cleanup(client, app) -> None:
    manager = app.state.container.connections
    with client.websocket_connect("/api/v1/ws", headers={"origin": "http://localhost:5173"}) as websocket:
        websocket.receive_json()
        heartbeat = websocket.receive_json()
        assert heartbeat["type"] == "connection.heartbeat"
        assert manager.state.connection_count == 1
    for _ in range(20):
        if manager.state.connection_count == 0:
            break
        __import__("time").sleep(0.01)
    assert manager.state.connection_count == 0


def test_multiple_clients_and_event_delivery(client, app) -> None:
    manager = app.state.container.connections
    with (
        client.websocket_connect("/api/v1/ws", headers={"origin": "http://localhost:5173"}) as first,
        client.websocket_connect("/api/v1/ws", headers={"origin": "http://localhost:5173"}) as second,
    ):
        first.receive_json()
        second.receive_json()
        asyncio.run(manager.broadcast("signal.created", "signals", {"signal_id": "one"}))
        assert _receive_event(first, "signal.created")["data"]["signal_id"] == "one"
        assert _receive_event(second, "signal.created")["data"]["signal_id"] == "one"


@pytest.mark.asyncio
async def test_event_deduplication(settings) -> None:
    manager = ConnectionManager(settings)
    assert await manager.broadcast("market.quote.updated", "market:EURUSD", {"last": 1.1}) is True
    assert await manager.broadcast("market.quote.updated", "market:EURUSD", {"last": 1.1}) is False
    assert await manager.broadcast("market.quote.updated", "market:EURUSD", {"last": 1.2}) is True


def test_websocket_rejects_untrusted_origin(client) -> None:
    with (
        pytest.raises(WebSocketDisconnect) as exc,
        client.websocket_connect("/api/v1/ws", headers={"origin": "https://evil.example"}),
    ):
        pass
    assert exc.value.code == 1008


def test_legacy_websocket_contract(client) -> None:
    with client.websocket_connect("/ws/v1/dashboard", headers={"origin": "http://localhost:5173"}) as websocket:
        assert websocket.receive_json()["type"] == "connection.ready"
        snapshot = websocket.receive_json()
        assert snapshot["type"] == "snapshot.full"
        assert snapshot["payload"]["safety"]["live_allowed"] is False


def test_file_change_is_broadcast_and_invalid_json_uses_last_known_good(client, app, engine_root) -> None:
    client.get("/api/v1/watchlist")
    source = engine_root / "active_pairs.json"
    with client.websocket_connect("/api/v1/ws", headers={"origin": "http://localhost:5173"}) as websocket:
        websocket.receive_json()
        source.write_text(
            json.dumps(
                {"generated_at": "2026-07-29T00:00:00Z", "active_pairs": ["EURUSD", "GBPUSD"], "live_allowed": False}
            ),
            encoding="utf-8",
        )
        received = None
        for _ in range(20):
            event = websocket.receive_json()
            if event["type"] == "system.updated":
                received = event
                break
        assert received is not None
        assert received["data"]["source"] == "active_pairs"
    source.write_text("{temporarily invalid", encoding="utf-8")
    __import__("time").sleep(0.2)
    response = client.get("/api/v1/watchlist")
    assert response.status_code == 200
    assert response.json()["success"] is True
