from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Query, Request

from app.api.dependencies import Container, Symbol, cached
from app.api.responses import success

router = APIRouter(prefix="/performance", tags=["Performance"])
RangeQuery = Literal["1d", "7d", "30d", "3m", "all"]
RangeParameter = Annotated[RangeQuery, Query(alias="range")]


async def _payload(
    container: Container, section: str | None, range_value: RangeQuery, symbol: Symbol | None, strategy: str | None
):
    normalized_strategy = strategy.strip().upper() if strategy else None
    key = f"performance:{section or 'all'}:{range_value}:{symbol or '*'}:{normalized_strategy or '*'}"

    async def load():
        return (
            await container.performance.section(section, range_value, symbol, normalized_strategy)
            if section
            else await container.performance.get(range_value, symbol, normalized_strategy)
        )

    return await cached(container, key, container.settings.dashboard_cache_seconds, load)


@router.get("", summary="Performance curves and statistics")
async def performance(
    request: Request,
    container: Container,
    range_value: RangeParameter = "all",
    symbol: Symbol | None = None,
    strategy: str | None = None,
):
    return success(await _payload(container, None, range_value, symbol, strategy), request)


@router.get("/equity-curve", summary="Equity and balance curve")
async def equity_curve(
    request: Request,
    container: Container,
    range_value: RangeParameter = "all",
    symbol: Symbol | None = None,
    strategy: str | None = None,
):
    return success(await _payload(container, "equity-curve", range_value, symbol, strategy), request)


@router.get("/pnl", summary="Period and cumulative PnL")
async def pnl(
    request: Request,
    container: Container,
    range_value: RangeParameter = "all",
    symbol: Symbol | None = None,
    strategy: str | None = None,
):
    return success(await _payload(container, "pnl", range_value, symbol, strategy), request)


@router.get("/drawdown", summary="Absolute and percentage drawdown")
async def drawdown(
    request: Request,
    container: Container,
    range_value: RangeParameter = "all",
    symbol: Symbol | None = None,
    strategy: str | None = None,
):
    return success(await _payload(container, "drawdown", range_value, symbol, strategy), request)


@router.get("/statistics", summary="Calculated performance statistics")
async def statistics(
    request: Request,
    container: Container,
    range_value: RangeParameter = "all",
    symbol: Symbol | None = None,
    strategy: str | None = None,
):
    return success(await _payload(container, "statistics", range_value, symbol, strategy), request)
