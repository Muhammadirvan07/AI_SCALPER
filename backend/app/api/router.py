from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from app.schemas.common import ErrorResponse, SuccessResponse

from .routes import (
    activity,
    compatibility,
    diagnostics,
    documentation,
    economic_calendar,
    health,
    logs,
    market,
    news,
    orders,
    overview,
    performance,
    quality,
    risk,
    signals,
    system,
    watchlist,
)

api_router = APIRouter()
standard_responses: dict[int | str, dict[str, Any]] = {
    200: {"model": SuccessResponse[Any], "description": "Successful response with freshness metadata."},
    400: {"model": ErrorResponse, "description": "Invalid request."},
    403: {"model": ErrorResponse, "description": "Safety lock or command policy rejection."},
    404: {"model": ErrorResponse, "description": "Resource not found."},
    409: {"model": ErrorResponse, "description": "Resource conflict or command already running."},
    422: {"model": ErrorResponse, "description": "Validation or source-format error."},
    429: {"model": ErrorResponse, "description": "Rate limit exceeded."},
    503: {"model": ErrorResponse, "description": "Engine data source unavailable."},
}
for route in (
    health.router,
    overview.router,
    performance.router,
    market.router,
    watchlist.router,
    signals.router,
    orders.router,
    diagnostics.router,
    risk.router,
    quality.router,
    system.router,
    logs.router,
    activity.router,
    economic_calendar.router,
    news.router,
):
    api_router.include_router(route, responses=standard_responses)
api_router.include_router(compatibility.router)
api_router.include_router(documentation.router)
