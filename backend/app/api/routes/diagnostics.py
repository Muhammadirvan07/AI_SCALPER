from __future__ import annotations

from fastapi import APIRouter, Request

from app.api.dependencies import Container, Symbol, cached
from app.api.responses import success

router = APIRouter(prefix="/diagnostics", tags=["AI Diagnostics"])


@router.get("", summary="Complete normalized AI decision diagnostics")
async def diagnostics(request: Request, container: Container):
    return success(
        await cached(container, "diagnostics", container.settings.dashboard_cache_seconds, container.diagnostics.get),
        request,
    )


@router.get("/decision", summary="Latest final decision")
async def decision(request: Request, container: Container):
    return success(
        await cached(
            container,
            "diagnostics:decision",
            container.settings.dashboard_cache_seconds,
            lambda: container.diagnostics.section("decision"),
        ),
        request,
    )


@router.get("/strategy", summary="Strategy score and explainability")
async def strategy(request: Request, container: Container):
    return success(
        await cached(
            container,
            "diagnostics:strategy",
            container.settings.dashboard_cache_seconds,
            lambda: container.diagnostics.section("strategy"),
        ),
        request,
    )


@router.get("/guards", summary="Decision guard state")
async def guards(request: Request, container: Container):
    return success(
        await cached(
            container,
            "diagnostics:guards",
            container.settings.dashboard_cache_seconds,
            lambda: container.diagnostics.section("guards"),
        ),
        request,
    )


@router.get("/health-snapshot", summary="Raw last-known decision health snapshot")
async def health_snapshot(request: Request, container: Container):
    return success(
        await cached(
            container,
            "diagnostics:health",
            container.settings.dashboard_cache_seconds,
            lambda: container.diagnostics.section("health-snapshot"),
        ),
        request,
    )


@router.get(
    "/calendar",
    summary="Read-only economic-calendar context for the current diagnostic symbol",
    description="Diagnostic context only. It cannot block, approve, modify, or execute a trade.",
)
async def calendar_context(request: Request, container: Container):
    return success(
        await cached(
            container,
            "diagnostics:calendar",
            container.settings.dashboard_cache_seconds,
            container.diagnostics.calendar,
        ),
        request,
    )


@router.get(
    "/calendar/{symbol}",
    summary="Read-only economic-calendar context for one symbol",
    description="Preview-only context; execution_guard_enabled and affects_execution are always false.",
)
async def calendar_context_for_symbol(request: Request, container: Container, symbol: Symbol):
    return success(
        await cached(
            container,
            f"diagnostics:calendar:{symbol}",
            container.settings.dashboard_cache_seconds,
            lambda: container.diagnostics.calendar(symbol),
        ),
        request,
    )
