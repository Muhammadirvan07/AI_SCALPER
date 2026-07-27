from __future__ import annotations

from fastapi import APIRouter, Request

from .snapshot import _snapshot

router = APIRouter(prefix="/api/v1", tags=["system"])


@router.get("/decision-health")
async def get_decision_health(request: Request) -> dict[str, object]:
    snapshot = _snapshot(request)
    return {
        "decision_health": snapshot.decision_health,
        "version": snapshot.version,
    }


@router.get("/session")
async def get_session(request: Request) -> dict[str, object]:
    snapshot = _snapshot(request)
    return {"session": snapshot.session, "version": snapshot.version}


@router.get("/guards")
async def get_guards(request: Request) -> dict[str, object]:
    snapshot = _snapshot(request)
    return {"guards": snapshot.guards, "version": snapshot.version}


@router.get("/sources")
async def get_sources(request: Request) -> dict[str, object]:
    snapshot = _snapshot(request)
    return {
        "sources": snapshot.sources,
        "source_updated_at": snapshot.source_updated_at,
        "warnings": snapshot.warnings,
        "version": snapshot.version,
    }


@router.get("/news")
async def get_news(request: Request) -> dict[str, object]:
    snapshot = _snapshot(request)
    return {"news": snapshot.news, "version": snapshot.version}


@router.get("/decision-readiness")
async def get_decision_readiness(request: Request) -> dict[str, object]:
    snapshot = _snapshot(request)
    return {
        "decision_readiness": snapshot.decision_readiness,
        "version": snapshot.version,
    }


@router.get("/source-contracts")
async def get_source_contracts(request: Request) -> dict[str, object]:
    snapshot = _snapshot(request)
    return {
        "schema_version": snapshot.schema_version,
        "source_contracts": snapshot.source_contracts,
        "version": snapshot.version,
    }
