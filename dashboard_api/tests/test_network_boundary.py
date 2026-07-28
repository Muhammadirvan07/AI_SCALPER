from __future__ import annotations

from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from dashboard_api.app.config import DashboardNetworkBoundaryError
from dashboard_api.app.main import create_app
from dashboard_api.app.security_headers import (
    HTML_CONTENT_SECURITY_POLICY,
    SECURITY_HEADERS,
)


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


@pytest.mark.parametrize(
    ("method", "path", "headers", "expected_status"),
    (
        ("GET", "/api/health", {}, 200),
        (
            "OPTIONS",
            "/api/v1/snapshot",
            {
                "origin": "http://localhost:5173",
                "access-control-request-method": "GET",
            },
            200,
        ),
        ("GET", "/api/not-found", {}, 404),
    ),
)
def test_security_headers_cover_api_and_cors_preflight(
    test_settings,
    method: str,
    path: str,
    headers: dict[str, str],
    expected_status: int,
) -> None:
    with TestClient(create_app(test_settings)) as client:
        response = client.request(method, path, headers=headers)

    assert response.status_code == expected_status
    for name, expected in SECURITY_HEADERS.items():
        assert response.headers[name] == expected
    assert "*" not in response.headers["content-security-policy"]


@pytest.mark.parametrize("path", ("/docs", "/redoc"))
def test_html_documentation_uses_narrow_compatible_csp(
    test_settings,
    path: str,
) -> None:
    with TestClient(create_app(test_settings)) as client:
        response = client.get(path)

    assert response.status_code == 200
    assert (
        response.headers["content-security-policy"]
        == HTML_CONTENT_SECURITY_POLICY
    )
    assert "https://cdn.jsdelivr.net" in HTML_CONTENT_SECURITY_POLICY
    assert "*" not in HTML_CONTENT_SECURITY_POLICY
