from __future__ import annotations

from fastapi import APIRouter, Request

from app.api.dependencies import Container, cached
from app.api.responses import success
from app.services.ai_advisory_status_service import build_ai_advisory_status

router = APIRouter(tags=["System"])


def _ai_advisory_status(container: Container):
    return build_ai_advisory_status(
        container.settings,
        news_meta=container.news.meta("latest"),
        calendar_meta=container.economic_calendar.meta(),
        calendar_sources=(
            container.economic_calendar.repository.providers.statuses()
        ),
    )


@router.get("/system/status", summary="Backend and engine component status")
async def system_status(request: Request, container: Container):
    async def load():
        data = container.system.health()
        data["ai_advisory"] = _ai_advisory_status(container)
        return container.system.payload(data)

    return success(await cached(container, "system:status", 1, load), request)


@router.get("/system/ai-advisory", summary="Effective read-only AI advisory and evidence status")
async def ai_advisory_status(request: Request, container: Container):
    return success(container.system.payload(_ai_advisory_status(container)), request)


@router.get("/system/components", summary="Per-component health and heartbeat")
async def components(request: Request, container: Container):
    async def load():
        return container.system.payload(list(container.system.components().values()))

    return success(await cached(container, "system:components", 1, load), request)


@router.get("/system/files", summary="Allowlisted source file status")
async def files(request: Request, container: Container):
    async def load():
        return container.system.files()

    return success(await cached(container, "system:files", 1, load), request)


@router.get("/system/session", summary="Paper forward-session tracker")
async def session(request: Request, container: Container):
    return success(
        await cached(container, "system:session", container.settings.dashboard_cache_seconds, container.system.session),
        request,
    )


@router.get("/version", summary="Backend and API build version")
async def version(request: Request, container: Container):
    return success(container.system.version(), request)
