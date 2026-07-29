from __future__ import annotations

from fastapi import APIRouter, Request

from app.api.dependencies import Container, Symbol, cached
from app.api.responses import success

router = APIRouter(prefix="/watchlist", tags=["Watchlist"])


@router.get("", summary="Watchlist assembled from active pairs and discovered data")
async def watchlist(request: Request, container: Container):
    payload = await cached(
        container, "watchlist", container.settings.market_data_cache_seconds, container.watchlist.get
    )
    return success(payload, request)


@router.get("/{symbol}", summary="Single watchlist symbol")
async def watchlist_symbol(symbol: Symbol, request: Request, container: Container):
    payload = await cached(
        container,
        f"watchlist:{symbol}",
        container.settings.market_data_cache_seconds,
        lambda: container.watchlist.get(symbol),
    )
    return success(payload, request)
