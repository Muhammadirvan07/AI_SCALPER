from __future__ import annotations

import re
import uuid
from collections.abc import Awaitable, Callable
from contextvars import ContextVar

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

request_id_context: ContextVar[str | None] = ContextVar("request_id", default=None)
SYMBOL_PATTERN = re.compile(r"^[A-Z0-9._-]{2,20}$")


def validate_symbol(value: str) -> str:
    normalized = value.strip().upper()
    if not SYMBOL_PATTERN.fullmatch(normalized) or ".." in normalized or "/" in normalized or "\\" in normalized:
        raise ValueError("Invalid market symbol")
    return normalized


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request_id = request.headers.get("X-Request-ID", "").strip()[:128] or str(uuid.uuid4())
        token = request_id_context.set(request_id)
        request.state.request_id = request_id
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Cache-Control"] = "no-store"
            response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
            content_type = response.headers.get("content-type", "").lower()
            if content_type.startswith("text/html"):
                response.headers["Content-Security-Policy"] = (
                    "default-src 'none'; "
                    "script-src 'self' https://cdn.jsdelivr.net; "
                    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                    "img-src 'self' data: https://fastapi.tiangolo.com; "
                    "font-src 'self' data:; connect-src 'self'; "
                    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
                )
            else:
                response.headers["Content-Security-Policy"] = (
                    "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
                )
            return response
        finally:
            request_id_context.reset(token)
