from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Query, Request

from app.api.dependencies import Container, Symbol, cached
from app.api.responses import success

router = APIRouter(prefix="/market", tags=["Market"])
Timeframe = Literal["M1", "M5", "M15", "M30", "H1", "H4", "D1"]


@router.get("/symbols", summary="All symbols discovered from engine data")
async def symbols(request: Request, container: Container):
    return success(await cached(container, "market:symbols", 30, container.market.symbols), request)


@router.get("/{symbol}/quote", summary="Latest source quote without fabricated bid/ask")
async def quote(symbol: Symbol, request: Request, container: Container):
    payload = await cached(
        container,
        f"market:quote:{symbol}",
        container.settings.market_data_cache_seconds,
        lambda: container.market.quote(symbol),
    )
    return success(payload, request)


@router.get("/{symbol}/candles", summary="Historical OHLCV candles")
async def candles(
    symbol: Symbol,
    request: Request,
    container: Container,
    timeframe: Timeframe = "M15",
    limit: int = Query(100, ge=1, le=2000),
):
    safe_limit = min(limit, container.settings.max_candle_limit)
    payload = await cached(
        container,
        f"market:candles:{symbol}:{timeframe}:{safe_limit}",
        container.settings.market_data_cache_seconds,
        lambda: container.market.candles(symbol, timeframe, safe_limit),
    )
    return success(payload, request)


@router.get("/{symbol}/indicators", summary="Engine-compatible technical indicator fallback")
async def indicators(symbol: Symbol, request: Request, container: Container, timeframe: Timeframe = "M15"):
    payload = await cached(
        container,
        f"market:indicators:{symbol}:{timeframe}",
        container.settings.market_data_cache_seconds,
        lambda: container.market.indicators(symbol, timeframe),
    )
    return success(payload, request)


@router.get("/{symbol}/status", summary="Market freshness, trend and regime")
async def market_status(symbol: Symbol, request: Request, container: Container):
    payload = await cached(
        container,
        f"market:status:{symbol}",
        container.settings.market_data_cache_seconds,
        lambda: container.market.status(symbol),
    )
    return success(payload, request)
