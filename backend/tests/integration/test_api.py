from __future__ import annotations

import time

import pytest


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/health",
        "/api/v1/health/ready",
        "/api/v1/health/live",
        "/api/v1/version",
        "/api/v1/overview",
        "/api/v1/overview/kpis",
        "/api/v1/overview/status",
        "/api/v1/performance",
        "/api/v1/performance/equity-curve",
        "/api/v1/performance/pnl",
        "/api/v1/performance/drawdown",
        "/api/v1/performance/statistics",
        "/api/v1/market/symbols",
        "/api/v1/market/EURUSD/quote",
        "/api/v1/market/EURUSD/candles?timeframe=M15&limit=10",
        "/api/v1/market/EURUSD/indicators",
        "/api/v1/market/EURUSD/status",
        "/api/v1/watchlist",
        "/api/v1/watchlist/EURUSD",
        "/api/v1/signals",
        "/api/v1/signals/latest",
        "/api/v1/orders",
        "/api/v1/orders/open",
        "/api/v1/orders/closed",
        "/api/v1/orders/ORDER-1",
        "/api/v1/diagnostics",
        "/api/v1/diagnostics/decision",
        "/api/v1/diagnostics/strategy",
        "/api/v1/diagnostics/guards",
        "/api/v1/diagnostics/health-snapshot",
        "/api/v1/risk",
        "/api/v1/risk/current",
        "/api/v1/risk/limits",
        "/api/v1/risk/status",
        "/api/v1/quality",
        "/api/v1/quality/readiness",
        "/api/v1/quality/progress",
        "/api/v1/quality/blockers",
        "/api/v1/system/status",
        "/api/v1/system/components",
        "/api/v1/system/files",
        "/api/v1/system/session",
        "/api/v1/logs",
        "/api/v1/logs/errors",
        "/api/v1/logs/recent",
        "/api/v1/activity",
        "/api/v1/snapshot",
        "/api/v1/documentation",
    ],
)
def test_get_endpoints_return_data(client, path: str) -> None:
    response = client.get(path, headers={"Origin": "http://localhost:5173"})
    if path.endswith("/health/ready"):
        deadline = time.monotonic() + 2
        while response.status_code == 503 and time.monotonic() < deadline:
            time.sleep(0.01)
            response = client.get(path, headers={"Origin": "http://localhost:5173"})
    assert response.status_code == 200, response.text
    body = response.json()
    if path.endswith("/snapshot"):
        assert body["safety"]["live_allowed"] is False
        assert body["safety"]["max_lot"] == 0.01
    else:
        assert body["success"] is True
        assert body["meta"]["server_timestamp"]
        assert "stale" in body["meta"]
        assert "source_available" in body["meta"]


def test_pagination_filter_not_found_and_validation(client) -> None:
    signals = client.get("/api/v1/signals?symbol=EURUSD&status=WAIT&limit=1&offset=0").json()
    assert signals["data"]["total"] >= 1
    orders = client.get("/api/v1/orders?side=BUY&limit=1").json()
    assert len(orders["data"]["items"]) == 1
    missing = client.get("/api/v1/orders/not-found")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "RESOURCE_NOT_FOUND"
    invalid = client.get("/api/v1/market/../../etc/passwd/candles")
    assert invalid.status_code in {404, 422}
    invalid_limit = client.get("/api/v1/market/EURUSD/candles?limit=99999")
    assert invalid_limit.status_code == 422
    assert invalid_limit.json()["success"] is False


def test_openapi_docs_and_request_id(client) -> None:
    response = client.get("/openapi.json", headers={"X-Request-ID": "test-request"})
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "test-request"
    schema = response.json()
    assert "/api/v1/overview" in schema["paths"]
    assert not any(path.startswith("/api/v1/commands") for path in schema["paths"])
    assert all(set(methods) <= {"get"} for methods in schema["paths"].values())
    docs = client.get("/docs")
    redoc = client.get("/redoc")
    assert docs.status_code == 200
    assert redoc.status_code == 200
    assert "default-src 'none'" in docs.headers["content-security-policy"]
    assert "https://cdn.jsdelivr.net" in docs.headers["content-security-policy"]
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert response.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=(), payment=()"


def test_cors_is_restricted(client) -> None:
    allowed = client.get("/api/v1/health", headers={"Origin": "http://localhost:5173"})
    denied = client.get("/api/v1/health", headers={"Origin": "https://evil.example"})
    preview = client.get("/api/v1/health", headers={"Origin": "http://127.0.0.1:4173"})
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-origin" not in denied.headers
    assert preview.headers["access-control-allow-origin"] == "http://127.0.0.1:4173"


def test_allowlisted_documentation_and_unknown_slug(client) -> None:
    for slug in ("architecture", "operator-runbook", "release-history", "safety-audit", "api-contract"):
        response = client.get(f"/api/v1/documentation/{slug}")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/markdown")
    missing = client.get("/api/v1/documentation/../../secret")
    assert missing.status_code == 404
