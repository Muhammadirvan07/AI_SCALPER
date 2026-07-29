from __future__ import annotations

from fastapi import APIRouter, Query, Request

from app.api.dependencies import Container, cached
from app.api.responses import success

router = APIRouter(tags=["Recent Activity"])


@router.get("/activity", summary="Merged trading, system and command activity")
async def activity(request: Request, container: Container, limit: int = Query(50, ge=1, le=200)):
    return success(await cached(container, f"activity:{limit}", 2, lambda: container.activity.get(limit)), request)
