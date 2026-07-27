from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from .snapshot import _snapshot

router = APIRouter(prefix="/api/v1", tags=["market"])


@router.get("/market/{symbol}")
async def get_market(
    request: Request,
    symbol: str,
    limit: int = Query(default=500, ge=1, le=5000),
    timeframe: str | None = None,
) -> dict[str, object]:
    snapshot = _snapshot(request)
    normalized_symbol = symbol.upper()
    market = snapshot.market.get(normalized_symbol)
    if market is None:
        raise HTTPException(status_code=404, detail="Data market tidak ditemukan")
    payload = market.model_dump(mode="json")
    payload["candles"] = payload["candles"][-limit:]
    payload["requested_timeframe"] = timeframe.upper() if timeframe else None
    payload["timeframe_available"] = (
        timeframe is None
        or market.timeframe is None
        or market.timeframe.upper() == timeframe.upper()
    )
    payload["version"] = snapshot.version
    return payload
