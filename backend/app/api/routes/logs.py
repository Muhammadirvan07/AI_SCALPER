from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Query, Request

from app.api.dependencies import Container
from app.api.responses import success

router = APIRouter(prefix="/logs", tags=["System Logs"])


async def _list(
    request: Request,
    container: Container,
    level: str | None,
    component: str | None,
    search: str | None,
    start_time: datetime | None,
    end_time: datetime | None,
    limit: int,
    offset: int,
):
    return success(
        await container.logs.list(
            level=level,
            component=component,
            search=search,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            offset=offset,
        ),
        request,
    )


@router.get("", summary="Paginated, redacted engine logs")
async def logs(
    request: Request,
    container: Container,
    level: str | None = None,
    component: str | None = None,
    search: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    return await _list(request, container, level, component, search, start_time, end_time, limit, offset)


@router.get("/errors", summary="Recent error and critical log entries")
async def errors(
    request: Request, container: Container, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)
):
    return await _list(request, container, "ERROR", None, None, None, None, limit, offset)


@router.get("/recent", summary="Most recent redacted log entries")
async def recent(request: Request, container: Container, limit: int = Query(50, ge=1, le=500)):
    return await _list(request, container, None, None, None, None, None, limit, 0)
