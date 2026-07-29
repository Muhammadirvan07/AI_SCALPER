from __future__ import annotations

from fastapi import APIRouter, Request

from app.api.dependencies import Container

router = APIRouter(tags=["Compatibility"])


@router.get("/snapshot", summary="Legacy Vite dashboard snapshot contract", deprecated=True)
async def snapshot(request: Request, container: Container):
    current = container.legacy_snapshots.latest or await container.legacy_snapshots.rebuild(force=True)
    return current
