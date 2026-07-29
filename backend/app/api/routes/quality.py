from __future__ import annotations

from fastapi import APIRouter, Request

from app.api.dependencies import Container, cached
from app.api.responses import success

router = APIRouter(prefix="/quality", tags=["Quality and Readiness"])


@router.get("", summary="Complete quality and readiness state")
async def quality(request: Request, container: Container):
    return success(
        await cached(container, "quality", container.settings.dashboard_cache_seconds, container.quality.get), request
    )


@router.get("/readiness", summary="Readiness status and safe capabilities")
async def readiness(request: Request, container: Container):
    return success(
        await cached(
            container,
            "quality:readiness",
            container.settings.dashboard_cache_seconds,
            lambda: container.quality.section("readiness"),
        ),
        request,
    )


@router.get("/progress", summary="Closed-sample progress")
async def progress(request: Request, container: Container):
    return success(
        await cached(
            container,
            "quality:progress",
            container.settings.dashboard_cache_seconds,
            lambda: container.quality.section("progress"),
        ),
        request,
    )


@router.get("/blockers", summary="Quality blockers and recommendations")
async def blockers(request: Request, container: Container):
    return success(
        await cached(
            container,
            "quality:blockers",
            container.settings.dashboard_cache_seconds,
            lambda: container.quality.section("blockers"),
        ),
        request,
    )
