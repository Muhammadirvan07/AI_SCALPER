from __future__ import annotations

from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from dashboard_api.app.config import DashboardNetworkBoundaryError
from dashboard_api.app.main import create_app


@pytest.mark.parametrize(
    "host",
    (
        "0.0.0.0",
        "::",
        "192.168.1.10",
        "dashboard.example.com",
        " localhost",
    ),
)
def test_dashboard_rejects_non_loopback_bind_host(test_settings, host: str) -> None:
    with pytest.raises(
        DashboardNetworkBoundaryError,
        match="host must remain loopback-only",
    ):
        create_app(replace(test_settings, host=host))


@pytest.mark.parametrize(
    "origin",
    (
        "*",
        "https://dashboard.example.com",
        "http://localhost.evil.example:5173",
        "http://user:password@localhost:5173",
        "file://localhost/dashboard",
        "null",
    ),
)
def test_dashboard_rejects_non_loopback_cors_origin(
    test_settings,
    origin: str,
) -> None:
    with pytest.raises(DashboardNetworkBoundaryError, match="origin"):
        create_app(replace(test_settings, cors_origins=(origin,)))


def test_dashboard_rejects_duplicate_canonical_origins(test_settings) -> None:
    with pytest.raises(DashboardNetworkBoundaryError, match="duplicates"):
        create_app(
            replace(
                test_settings,
                cors_origins=(
                    "http://localhost:80",
                    "http://localhost",
                ),
            )
        )


def test_cors_uses_canonical_loopback_allowlist(test_settings) -> None:
    app = create_app(
        replace(
            test_settings,
            cors_origins=("HTTP://LOCALHOST:80/",),
        )
    )
    with TestClient(app) as client:
        response = client.options(
            "/api/v1/snapshot",
            headers={
                "origin": "http://localhost",
                "access-control-request-method": "GET",
            },
        )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost"
