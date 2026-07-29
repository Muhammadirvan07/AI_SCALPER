from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Annotated, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Path, Query, Request

from app.api.dependencies import Container, PageLimit, PageOffset, Symbol
from app.api.responses import success
from app.schemas.economic_calendar import EconomicEventCategory, EconomicEventStatus, EconomicImpact

router = APIRouter(prefix="/economic-calendar", tags=["Economic Calendar"])
CalendarSort = Literal["scheduled_at", "-scheduled_at", "impact", "updated_at", "-updated_at"]
CalendarDate = Annotated[date | None, Query(alias="date")]


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@router.get("", summary="Query verified native economic-calendar events")
async def economic_calendar(
    request: Request,
    container: Container,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    date_value: CalendarDate = None,
    timezone: str = Query(default="UTC", min_length=1, max_length=64),
    currency: str | None = Query(default=None, min_length=3, max_length=8),
    country: str | None = Query(default=None, max_length=80),
    symbol: str | None = Query(default=None, min_length=3, max_length=20),
    category: EconomicEventCategory | None = None,
    impact: EconomicImpact | None = None,
    status: EconomicEventStatus | None = None,
    source: str | None = Query(default=None, pattern=r"^[a-z0-9_]+$", max_length=40),
    released: bool | None = None,
    limit: PageLimit = 100,
    offset: PageOffset = 0,
    sort: CalendarSort = "scheduled_at",
):
    payload = (
        container.economic_calendar.query_date(
            date_value,
            timezone,
            currency=currency,
            country=country,
            symbol=symbol,
            category=category,
            impact=impact,
            status=status,
            source=source,
            released=released,
            limit=limit,
            offset=offset,
            sort=sort,
        )
        if date_value
        else container.economic_calendar.query(
            start_time=_utc(start_time),
            end_time=_utc(end_time),
            currency=currency,
            country=country,
            symbol=symbol,
            category=category,
            impact=impact,
            status=status,
            source=source,
            released=released,
            limit=limit,
            offset=offset,
            sort=sort,
        )
    )
    return success(payload, request)


@router.get("/today", summary="Economic events for one local calendar day")
async def today(
    request: Request,
    container: Container,
    timezone: str = Query(default="UTC", min_length=1, max_length=64),
    date_value: CalendarDate = None,
    limit: PageLimit = 200,
    offset: PageOffset = 0,
):
    try:
        selected = date_value or datetime.now(ZoneInfo(timezone)).date()
    except ZoneInfoNotFoundError:
        selected = date_value or datetime.now(UTC).date()
    return success(container.economic_calendar.query_date(selected, timezone, limit=limit, offset=offset), request)


@router.get("/upcoming", summary="Upcoming verified economic events")
async def upcoming(
    request: Request,
    container: Container,
    hours: Annotated[int, Query(ge=1, le=24 * 366)] = 168,
    currency: str | None = Query(default=None, min_length=3, max_length=8),
    symbol: str | None = Query(default=None, min_length=3, max_length=20),
    limit: PageLimit = 200,
    offset: PageOffset = 0,
):
    now = datetime.now(UTC)
    return success(
        container.economic_calendar.query(
            start_time=now,
            end_time=now + timedelta(hours=hours),
            currency=currency,
            symbol=symbol,
            limit=limit,
            offset=offset,
        ),
        request,
    )


@router.get("/high-impact", summary="High and critical economic events")
async def high_impact(
    request: Request,
    container: Container,
    hours: Annotated[int, Query(ge=1, le=24 * 366)] = 168,
    limit: PageLimit = 200,
    offset: PageOffset = 0,
):
    now = datetime.now(UTC)
    payload = container.economic_calendar.query(
        start_time=now - timedelta(minutes=15),
        end_time=now + timedelta(hours=hours),
        limit=500,
        offset=0,
    )
    rows = [item for item in payload.data.items if item.impact in {EconomicImpact.HIGH, EconomicImpact.CRITICAL}]
    payload.data = payload.data.model_copy(
        update={"items": rows[offset : offset + limit], "total": len(rows), "limit": limit, "offset": offset}
    )
    return success(payload, request)


@router.get("/live", summary="Countdown, awaiting-release and newly released events")
async def live(request: Request, container: Container, limit: PageLimit = 100, offset: PageOffset = 0):
    now = datetime.now(UTC)
    payload = container.economic_calendar.query(
        start_time=now - timedelta(minutes=15),
        end_time=now + timedelta(minutes=10),
        limit=500,
        offset=0,
    )
    rows = [
        item
        for item in payload.data.items
        if item.is_live or item.status in {EconomicEventStatus.COUNTDOWN, EconomicEventStatus.AWAITING_RELEASE}
    ]
    payload.data = payload.data.model_copy(
        update={"items": rows[offset : offset + limit], "total": len(rows), "limit": limit, "offset": offset}
    )
    return success(payload, request)


@router.get("/symbols/{symbol}", summary="Economic events affecting one active symbol")
async def symbol_events(
    request: Request,
    container: Container,
    symbol: Symbol,
    hours: Annotated[int, Query(ge=1, le=24 * 366)] = 168,
    limit: PageLimit = 200,
    offset: PageOffset = 0,
):
    now = datetime.now(UTC)
    return success(
        container.economic_calendar.query(
            symbol=symbol,
            start_time=now - timedelta(hours=12),
            end_time=now + timedelta(hours=hours),
            limit=limit,
            offset=offset,
        ),
        request,
    )


@router.get("/currencies/{currency}", summary="Economic events for one currency")
async def currency_events(
    request: Request,
    container: Container,
    currency: Annotated[str, Path(min_length=3, max_length=8, pattern=r"^[A-Za-z]{3,8}$")],
    hours: Annotated[int, Query(ge=1, le=24 * 366)] = 168,
    limit: PageLimit = 200,
    offset: PageOffset = 0,
):
    now = datetime.now(UTC)
    return success(
        container.economic_calendar.query(
            currency=currency,
            start_time=now - timedelta(hours=12),
            end_time=now + timedelta(hours=hours),
            limit=limit,
            offset=offset,
        ),
        request,
    )


@router.get("/sources", summary="Official source health and freshness")
async def sources(request: Request, container: Container):
    return success(container.economic_calendar.sources(), request)


@router.get("/health", summary="Economic-calendar domain health")
async def health(request: Request, container: Container):
    return success(container.economic_calendar.health(), request)


@router.get("/status", summary="Economic-calendar scheduler and cache status")
async def status(request: Request, container: Container):
    return success(container.economic_calendar.runtime_status(), request)


@router.get("/guard-preview/{symbol}", summary="Read-only event-risk preview for a symbol")
async def guard_preview(request: Request, container: Container, symbol: Symbol):
    return success(container.economic_calendar.guard_preview(symbol), request)


@router.get("/metrics", summary="Read-only scheduler, release, WebSocket and diagnostics metrics")
async def metrics(request: Request, container: Container):
    return success(container.economic_calendar.metrics(), request)


@router.get("/{event_id}/audit", summary="Safe paginated release lifecycle audit metadata")
async def release_audit(
    request: Request,
    container: Container,
    event_id: Annotated[str, Path(min_length=1, max_length=180, pattern=r"^[A-Za-z0-9:_-]+$")],
    limit: PageLimit = 100,
    offset: PageOffset = 0,
):
    return success(container.economic_calendar.audit(event_id, limit=limit, offset=offset), request)


@router.get("/{event_id}", summary="Economic event detail and schedule history")
async def detail(
    request: Request,
    container: Container,
    event_id: Annotated[str, Path(min_length=1, max_length=180, pattern=r"^[A-Za-z0-9:_-]+$")],
):
    return success(container.economic_calendar.detail(event_id), request)
