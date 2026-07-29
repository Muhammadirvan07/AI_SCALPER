from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.dependencies import AppContainer
from app.api.router import api_router
from app.core.config import Settings, get_settings
from app.core.constants import API_PREFIX
from app.core.exceptions import AppError
from app.core.logging import configure_logging
from app.core.security import RequestContextMiddleware
from app.schemas.websocket import SubscriptionMessage

logger = logging.getLogger(__name__)


def _error_response(request: Request, code: str, message: str, status_code: int, details=None) -> JSONResponse:
    # Validation contexts may contain exception instances.  Never let an error
    # response fail while serializing its own diagnostic details.
    safe_details = (
        json.loads(json.dumps(details, default=lambda value: str(value)[:500])) if details is not None else None
    )
    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "error": {"code": code, "message": message, "details": safe_details},
            "meta": {
                "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "request_id": getattr(request.state, "request_id", None),
            },
        },
    )


def create_app(settings_override: Settings | None = None) -> FastAPI:
    settings = settings_override or get_settings()
    configure_logging(settings.log_level)
    container = AppContainer.build(settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        logger.info(
            "Backend started",
            extra={
                "event": "backend.started",
                "mode": "DRY_RUN",
                "live_allowed": False,
                "max_lot": settings.max_allowed_lot,
            },
        )
        await container.legacy_snapshots.initialize()
        await container.economic_calendar.initialize()
        await container.connections.start()
        await container.broadcaster.start()
        await container.economic_calendar_scheduler.start()
        await container.news_scheduler.start()
        await container.trading_economics_stream.start()
        await container.watcher.start()
        await container.legacy_connections.start()
        try:
            yield
        finally:
            await container.watcher.stop()
            await container.news_scheduler.stop()
            await container.economic_calendar_scheduler.stop()
            await container.trading_economics_stream.stop()
            await container.broadcaster.stop()
            await container.connections.stop()
            await container.legacy_connections.stop()
            logger.info("Backend stopped", extra={"event": "backend.stopped"})

    app = FastAPI(
        title="AI_SCALPER Backend",
        version=settings.app_version,
        description=(
            "Production-oriented read-only REST and realtime gateway for the AI_SCALPER paper engine. "
            "News Intelligence normalizes configured metadata-only feeds and remains read-only. "
            "Browser-facing mutation endpoints are not published. Live execution is permanently locked "
            "and the effective lot cap is 0.01."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        openapi_tags=[
            {
                "name": "News",
                "description": "Metadata-only financial news normalized from configured providers. Full article content is never copied; links point to the original source. News is read-only and cannot create orders.",
            },
            {
                "name": "News Sentiment",
                "description": "Deterministic financial-lexicon sentiment with recency, relevance and impact-weighted aggregation. Missing values remain null; duplicate stories are counted once.",
            },
            {
                "name": "Economic Calendar",
                "description": "Native read-only calendar built from verified official schedules. Forecast remains null unless a trusted source supplies it; guard previews never alter execution.",
            },
        ],
        lifespan=lifespan,
        debug=settings.app_debug and settings.app_env != "production",
    )
    app.state.container = container
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "OPTIONS"],
        allow_headers=["Accept", "Content-Type", "X-Request-ID"],
    )
    app.add_middleware(RequestContextMiddleware)
    app.include_router(api_router, prefix=API_PREFIX)

    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError):
        logger.warning(
            "API error",
            extra={
                "event": "api.error",
                "request_id": getattr(request.state, "request_id", None),
                "error_type": type(exc).__name__,
                "error_code": exc.code,
            },
        )
        return _error_response(request, exc.code, exc.message, exc.status_code, exc.details)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        return _error_response(request, "VALIDATION_ERROR", "Request validation failed.", 422, exc.errors())

    @app.exception_handler(HTTPException)
    async def http_error_handler(request: Request, exc: HTTPException):
        code = "RESOURCE_NOT_FOUND" if exc.status_code == 404 else "HTTP_ERROR"
        return _error_response(request, code, str(exc.detail), exc.status_code)

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, exc: Exception):
        logger.exception(
            "Unhandled API error",
            extra={
                "event": "api.unhandled_error",
                "request_id": getattr(request.state, "request_id", None),
                "error_type": type(exc).__name__,
            },
        )
        message = (
            str(exc)
            if settings.app_debug and settings.app_env != "production"
            else "An internal server error occurred."
        )
        return _error_response(request, "INTERNAL_SERVER_ERROR", message, 500)

    def websocket_origin_allowed(websocket: WebSocket) -> bool:
        origin = (websocket.headers.get("origin") or "").rstrip("/")
        return origin in settings.cors_origins

    @app.websocket(f"{API_PREFIX}/ws")
    async def realtime_websocket(websocket: WebSocket) -> None:
        if not websocket_origin_allowed(websocket):
            await websocket.close(code=1008, reason="WebSocket origin not allowed")
            return
        client = await container.connections.connect(websocket)
        if client is None:
            return
        try:
            while True:
                raw = await websocket.receive_text()
                if len(raw.encode("utf-8")) > settings.websocket_max_message_bytes:
                    await container.connections.send_event(
                        client,
                        "error",
                        "connection",
                        {"code": "MESSAGE_TOO_LARGE", "message": "WebSocket message exceeds configured limit."},
                    )
                    await websocket.close(code=1009)
                    return
                try:
                    message = SubscriptionMessage.model_validate_json(raw)
                except (ValidationError, json.JSONDecodeError):
                    await container.connections.send_event(
                        client,
                        "error",
                        "connection",
                        {
                            "code": "INVALID_MESSAGE",
                            "message": "Use subscribe, unsubscribe, ping or pong with validated channels.",
                        },
                    )
                    continue
                if message.action == "subscribe":
                    await container.connections.subscribe(client, message.channels)
                elif message.action == "unsubscribe":
                    await container.connections.unsubscribe(client, message.channels)
                elif message.action == "ping":
                    await container.connections.send_event(client, "connection.pong", "connection", {})
        except WebSocketDisconnect:
            pass
        finally:
            await container.connections.disconnect(websocket)

    @app.websocket("/ws/v1/dashboard")
    async def legacy_websocket(websocket: WebSocket) -> None:
        if not websocket_origin_allowed(websocket):
            await websocket.close(code=1008, reason="WebSocket origin not allowed")
            return
        await container.legacy_connections.connect(websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            await container.legacy_connections.disconnect(websocket)

    @app.get("/api/health", include_in_schema=False)
    async def legacy_health():
        return container.system.health()

    return app


app = create_app()
