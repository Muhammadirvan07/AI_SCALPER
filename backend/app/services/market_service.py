from __future__ import annotations

from datetime import UTC, datetime

from app.adapters.market_adapter import MarketAdapter
from app.core.exceptions import ResourceNotFoundError
from app.repositories.csv_repository import CsvRepository
from app.repositories.file_registry import FileRegistry
from app.schemas.common import ApiMeta
from app.schemas.market import Quote

from .base import ServicePayload


class MarketService:
    def __init__(self, csv_repository: CsvRepository, registry: FileRegistry, adapter: MarketAdapter) -> None:
        self.csv = csv_repository
        self.registry = registry
        self.adapter = adapter

    async def symbols(self) -> ServicePayload:
        symbols = self.registry.symbols()
        now = datetime.now(UTC)
        return ServicePayload(
            symbols,
            ApiMeta(
                source="data/*.csv",
                source_updated_at=None,
                server_timestamp=now,
                age_seconds=None,
                stale=not bool(symbols),
                source_available=bool(symbols),
                data_status="historical" if symbols else "unavailable",
            ),
        )

    async def candles(self, symbol: str, timeframe: str, limit: int) -> ServicePayload:
        if symbol not in self.registry.symbols():
            raise ResourceNotFoundError(f"Unknown market symbol: {symbol}")
        result = await self.csv.read_candles(symbol, timeframe, limit)
        warnings = [result.series.resolution_warning] if result.series.resolution_warning else []
        age = (
            max(0.0, (result.received_at - result.source_updated_at).total_seconds())
            if result.source_updated_at
            else None
        )
        meta = ApiMeta(
            source=result.path.name,
            source_updated_at=result.source_updated_at,
            server_timestamp=result.received_at,
            age_seconds=age,
            stale=result.stale,
            source_available=bool(result.series.candles),
            data_status="stale" if result.stale else "live",
            warnings=warnings,
        )
        return ServicePayload(result.series, meta)

    async def quote(self, symbol: str) -> ServicePayload:
        payload = await self.candles(symbol, "M15", 2)
        candles = payload.data.candles
        last = candles[-1] if candles else None
        previous = candles[-2] if len(candles) > 1 else None
        change = last.close - previous.close if last and previous else None
        pct = change / previous.close * 100 if change is not None and previous and previous.close else None
        return ServicePayload(
            Quote(
                symbol=symbol,
                last=last.close if last else None,
                change=change,
                change_percent=pct,
                timestamp=last.timestamp if last else None,
            ),
            payload.meta,
        )

    async def indicators(self, symbol: str, timeframe: str) -> ServicePayload:
        payload = await self.candles(symbol, timeframe, 200)
        rows = [item.model_dump(mode="python") for item in payload.data.candles]
        return ServicePayload(self.adapter.indicators(symbol, payload.data.actual_timeframe, rows), payload.meta)

    async def status(self, symbol: str) -> ServicePayload:
        quote = await self.quote(symbol)
        indicators = await self.indicators(symbol, "M15")
        return ServicePayload(
            {
                "symbol": symbol,
                "market_status": "STALE" if quote.meta.stale else "ACTIVE",
                "quote_source": quote.data.source_kind,
                "trend": indicators.data.trend,
                "regime": indicators.data.market_regime,
                "stale": quote.meta.stale,
                "last_update": quote.data.timestamp,
            },
            quote.meta,
        )
