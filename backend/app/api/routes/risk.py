from __future__ import annotations

from fastapi import APIRouter, Request

from app.api.dependencies import Container, cached
from app.api.responses import success

router = APIRouter(prefix="/risk", tags=["Risk Management"])


@router.get("", summary="Complete paper-risk state with backend safety override")
async def risk(request: Request, container: Container):
    return success(
        await cached(container, "risk", container.settings.dashboard_cache_seconds, container.risk.get), request
    )


@router.get("/current", summary="Current calculated risk")
async def current_risk(request: Request, container: Container):
    return success(
        await cached(
            container,
            "risk:current",
            container.settings.dashboard_cache_seconds,
            lambda: container.risk.section("current"),
        ),
        request,
    )


@router.get("/limits", summary="Engine, backend and effective safety limits")
async def risk_limits(request: Request, container: Container):
    return success(
        await cached(
            container,
            "risk:limits",
            container.settings.dashboard_cache_seconds,
            lambda: container.risk.section("limits"),
        ),
        request,
    )


@router.get("/status", summary="Drawdown, cooldown and live lock state")
async def risk_status(request: Request, container: Container):
    return success(
        await cached(
            container,
            "risk:status",
            container.settings.dashboard_cache_seconds,
            lambda: container.risk.section("status"),
        ),
        request,
    )
