from __future__ import annotations

from fastapi import APIRouter, Request

from app.api.dependencies import Container, cached
from app.api.responses import success

router = APIRouter(tags=["System"])


@router.get("/system/status", summary="Backend and engine component status")
async def system_status(request: Request, container: Container):
    async def load():
        return container.system.payload(container.system.health())

    return success(await cached(container, "system:status", 1, load), request)


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
