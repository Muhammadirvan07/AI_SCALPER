from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Query, Request

from app.api.dependencies import Container, Symbol, cached
from app.api.responses import success

router = APIRouter(prefix="/orders", tags=["Paper Orders"])


@router.get("", summary="Read-only normalized paper orders")
async def orders(
    request: Request,
    container: Container,
    symbol: Symbol | None = None,
    status: str | None = None,
    side: str | None = Query(None, pattern="^(BUY|SELL)$"),
    strategy: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    normalized_strategy = strategy.upper() if strategy else None
    key = f"orders:{symbol or '*'}:{status or '*'}:{side or '*'}:{normalized_strategy or '*'}:{start_date}:{end_date}:{limit}:{offset}"
    payload = await cached(
        container,
        key,
        container.settings.dashboard_cache_seconds,
        lambda: container.orders.list(
            symbol=symbol,
            status=status,
            side=side,
            strategy=normalized_strategy,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            offset=offset,
        ),
    )
    return success(payload, request)


@router.get("/open", summary="Open paper orders")
async def open_orders(
    request: Request, container: Container, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)
):
    payload = await cached(
        container,
        f"orders:open:{limit}:{offset}",
        container.settings.dashboard_cache_seconds,
        lambda: container.orders.by_state("PAPER_OPEN", limit, offset),
    )
    return success(payload, request)


@router.get("/closed", summary="Closed paper orders")
async def closed_orders(
    request: Request, container: Container, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)
):
    payload = await cached(
        container,
        f"orders:closed:{limit}:{offset}",
        container.settings.dashboard_cache_seconds,
        lambda: container.orders.by_state("CLOSED", limit, offset),
    )
    return success(payload, request)


@router.get("/{order_id}", summary="Paper order by ID")
async def order(order_id: str, request: Request, container: Container):
    payload = await cached(
        container,
        f"orders:id:{order_id}",
        container.settings.dashboard_cache_seconds,
        lambda: container.orders.get(order_id),
    )
    return success(payload, request)
