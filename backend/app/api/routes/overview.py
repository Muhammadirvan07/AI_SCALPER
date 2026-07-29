from __future__ import annotations

from fastapi import APIRouter, Request

from app.api.dependencies import Container, cached
from app.api.responses import success

router = APIRouter(prefix="/overview", tags=["Overview"])


@router.get("", summary="Dashboard command-center overview")
async def overview(request: Request, container: Container):
    payload = await cached(container, "overview", container.settings.dashboard_cache_seconds, container.overview.get)
    return success(payload, request)


@router.get("/kpis", summary="Primary trading KPIs")
async def kpis(request: Request, container: Container):
    payload = await cached(
        container, "overview:kpis", container.settings.dashboard_cache_seconds, container.overview.kpis
    )
    return success(payload, request)


@router.get("/status", summary="Current mode, quality and market status")
async def overview_status(request: Request, container: Container):
    payload = await cached(
        container, "overview:status", container.settings.dashboard_cache_seconds, container.overview.status
    )
    return success(payload, request)
