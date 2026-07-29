from __future__ import annotations

from fastapi import APIRouter, Query, Request

from app.api.dependencies import Container, Symbol, cached
from app.api.responses import success

router = APIRouter(prefix="/signals", tags=["Trading Signals"])


@router.get("", summary="Normalized decision and trading signals")
async def signals(
    request: Request,
    container: Container,
    symbol: Symbol | None = None,
    side: str | None = Query(None, pattern="^(BUY|SELL)$"),
    strategy: str | None = None,
    status: str | None = Query(
        None, pattern="^(WAIT|APPROVED|PAPER_OPEN|CLOSED|BLOCKED|REJECTED|EXPIRED|SKIPPED|UNKNOWN)$"
    ),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    normalized_strategy = strategy.upper() if strategy else None
    key = f"signals:{symbol or '*'}:{side or '*'}:{normalized_strategy or '*'}:{status or '*'}:{limit}:{offset}"
    payload = await cached(
        container,
        key,
        container.settings.dashboard_cache_seconds,
        lambda: container.signals.list(
            symbol=symbol, side=side, strategy=normalized_strategy, status=status, limit=limit, offset=offset
        ),
    )
    return success(payload, request)


@router.get("/latest", summary="Latest normalized signal or decision")
async def latest_signal(request: Request, container: Container):
    return success(
        await cached(container, "signals:latest", container.settings.dashboard_cache_seconds, container.signals.latest),
        request,
    )


@router.get("/{signal_id}", summary="Signal by stable ID")
async def signal(signal_id: str, request: Request, container: Container):
    payload = await cached(
        container,
        f"signals:id:{signal_id}",
        container.settings.dashboard_cache_seconds,
        lambda: container.signals.get(signal_id),
    )
    return success(payload, request)
