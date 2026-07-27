from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from ..models import DashboardSnapshot

router = APIRouter(prefix="/api/v1", tags=["snapshot"])


def _snapshot(request: Request) -> DashboardSnapshot:
    snapshot = request.app.state.runtime.builder.latest_snapshot
    if snapshot is None:
        raise HTTPException(status_code=503, detail="Snapshot belum tersedia")
    return snapshot


@router.get("/snapshot", response_model=DashboardSnapshot)
async def get_snapshot(request: Request) -> DashboardSnapshot:
    return _snapshot(request)


@router.get("/summary")
async def get_summary(request: Request) -> dict[str, object]:
    snapshot = _snapshot(request)
    return {
        "summary": snapshot.summary,
        "readiness": snapshot.readiness,
        "generated_at": snapshot.generated_at,
        "version": snapshot.version,
    }

@router.get("/safety")
async def get_safety(request: Request) -> dict[str, object]:
    snapshot = _snapshot(request)
    return {
        "safety": snapshot.safety,
        "warnings": snapshot.safety.violations,
        "generated_at": snapshot.generated_at,
        "version": snapshot.version,
    }


@router.get("/performance")
async def get_performance(request: Request) -> dict[str, object]:
    snapshot = _snapshot(request)
    return {
        "performance": snapshot.performance,
        "generated_at": snapshot.generated_at,
        "version": snapshot.version,
    }


@router.get("/watchlist")
async def get_watchlist(request: Request) -> dict[str, object]:
    snapshot = _snapshot(request)
    return {
        "watchlist": snapshot.watchlist,
        "generated_at": snapshot.generated_at,
        "version": snapshot.version,
    }
