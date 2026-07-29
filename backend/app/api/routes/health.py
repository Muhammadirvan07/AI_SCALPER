from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Request, Response, status

from app.api.dependencies import Container
from app.api.responses import success
from app.schemas.common import ApiMeta
from app.services.base import ServicePayload

router = APIRouter(tags=["Health"])


@router.get("/health", summary="Complete backend and engine-source health")
async def health(request: Request, container: Container):
    return success(container.system.payload(container.system.health()), request)


@router.get("/health/ready", summary="Readiness probe")
async def ready(request: Request, response: Response, container: Container):
    data = container.system.health()
    news_initialization_complete = bool(
        not container.settings.news_enabled or container.news_scheduler.state.initial_refresh_complete
    )
    is_ready = bool(
        data["ai_scalper_root_available"]
        and data["data_directory_available"]
        and container.watcher.state.running
        and news_initialization_complete
    )
    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return success(
        container.system.payload(
            {"ready": is_ready, "news_initialization_complete": news_initialization_complete, **data}
        ),
        request,
    )


@router.get("/health/live", summary="Liveness probe")
async def live(request: Request):
    now = datetime.now(UTC)
    return success(
        ServicePayload(
            {"live": True, "status": "healthy"},
            ApiMeta(
                source="runtime",
                source_updated_at=now,
                server_timestamp=now,
                age_seconds=0,
                stale=False,
                source_available=True,
                data_status="live",
            ),
        ),
        request,
    )
