from __future__ import annotations

from fastapi import APIRouter, Query, Request

from .snapshot import _snapshot

router = APIRouter(prefix="/api/v1", tags=["signals"])


@router.get("/signals")
async def get_signals(
    request: Request,
    symbol: str | None = None,
    status: str | None = None,
    strategy: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, object]:
    snapshot = _snapshot(request)
    items = snapshot.signals
    if symbol:
        items = [item for item in items if item.symbol == symbol.upper()]
    if status:
        items = [
            item
            for item in items
            if (item.status or "").upper() == status.upper()
        ]
    if strategy:
        items = [
            item
            for item in items
            if (item.strategy or "").upper() == strategy.upper()
        ]
    return {
        "items": items[:limit],
        "count": min(len(items), limit),
        "total_matching": len(items),
        "version": snapshot.version,
    }
