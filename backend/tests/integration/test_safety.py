from __future__ import annotations

import pytest

from app.core.config import Settings


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/commands",
        "/api/v1/commands/refresh",
        "/api/v1/commands/reload-data",
        "/api/v1/commands/recalculate-dashboard",
        "/api/v1/commands/refresh-news",
        "/api/v1/commands/refresh-economic-calendar",
    ],
)
def test_browser_command_endpoints_do_not_exist(client, path: str) -> None:
    assert client.post(path, json={"command": "refresh"}).status_code == 404


def test_cors_preflight_rejects_post(client) -> None:
    response = client.options(
        "/api/v1/overview",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert response.status_code == 400
    assert "POST" not in response.headers.get("access-control-allow-methods", "")


def test_live_order_endpoints_do_not_exist(client) -> None:
    assert client.post("/api/v1/orders/live", json={"symbol": "EURUSD"}).status_code == 405
    assert client.post("/api/v1/market-order", json={"symbol": "EURUSD"}).status_code == 404


def test_frontend_cannot_modify_safety_configuration(client) -> None:
    response = client.post("/api/v1/commands", json={"command": "max_lot", "value": 1})
    assert response.status_code == 404
    risk = client.get("/api/v1/risk/limits").json()["data"]
    assert risk["effective_max_lot"] <= 0.01
    assert risk["live_allowed"] is False


def test_openapi_exposes_no_live_execution_operation(client) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    read_only_live_views = {"/api/v1/health/live", "/api/v1/economic-calendar/live"}
    assert all(("live" not in path or path in read_only_live_views) and "market-order" not in path for path in paths)
    assert set(paths["/api/v1/economic-calendar/live"]) == {"get"}
    assert all(set(methods) <= {"get"} for methods in paths.values())


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"app_host": "0.0.0.0"}, "APP_HOST"),
        ({"app_host": "192.168.1.50"}, "APP_HOST"),
        ({"frontend_origins": "https://dashboard.example.com"}, "FRONTEND_ORIGINS"),
        ({"frontend_origins": "http://127.0.0.1:5173/path"}, "FRONTEND_ORIGINS"),
        ({"trusted_hosts": "*"}, "TRUSTED_HOSTS"),
        ({"trusted_hosts": "dashboard.example.com"}, "TRUSTED_HOSTS"),
    ],
)
def test_network_boundary_rejects_non_loopback_configuration(settings, override: dict[str, str], message: str) -> None:
    values = settings.model_dump()
    values["websocket_heartbeat_seconds"] = 2
    values.update(override)
    with pytest.raises(ValueError, match=message):
        Settings(**values)
