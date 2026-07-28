from __future__ import annotations

from types import MappingProxyType

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send


API_CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
        "object-src 'none'",
    )
)

HTML_CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'none'",
        "script-src 'self' https://cdn.jsdelivr.net",
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        "img-src 'self' data: https://fastapi.tiangolo.com",
        "connect-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
        "object-src 'none'",
    )
)

SECURITY_HEADERS = MappingProxyType(
    {
        "Cache-Control": "no-store",
        "Content-Security-Policy": API_CONTENT_SECURITY_POLICY,
        "Permissions-Policy": (
            "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
        ),
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }
)


class DashboardSecurityHeadersMiddleware:
    """Apply immutable browser-security headers to every HTTP response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers[name] = value
                if headers.get("content-type", "").lower().startswith("text/html"):
                    headers["Content-Security-Policy"] = (
                        HTML_CONTENT_SECURITY_POLICY
                    )
            await send(message)

        await self.app(scope, receive, send_with_security_headers)
