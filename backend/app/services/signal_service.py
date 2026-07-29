from __future__ import annotations

from datetime import UTC, datetime

from app.adapters.signal_adapter import SignalAdapter
from app.core.exceptions import DataSourceUnavailableError, ResourceNotFoundError
from app.repositories.json_repository import RepositoryResult
from app.schemas.common import Page
from app.schemas.signals import TradingSignal

from .base import BaseService, ServicePayload


class SignalService(BaseService):
    def __init__(self, json_repository, adapter: SignalAdapter) -> None:
        super().__init__(json_repository)
        self.adapter = adapter

    async def all_signals(self) -> tuple[list[TradingSignal], list[RepositoryResult | None], list[str]]:
        sources: list[RepositoryResult | None] = []
        warnings: list[str] = []
        signals: list[TradingSignal] = []
        for key, label in (
            ("trade_signals", "trade_signals.json"),
            ("mt5_trade_signals", "mt5_trade_signals.json"),
            ("bridge_rejections", "bridge_rejected_signals.json"),
        ):
            result, warning = await self.optional_source(key)
            sources.append(result)
            if warning:
                warnings.append(warning)
            if result:
                signals.extend(self.adapter.normalize_source(result.value, source=label))
        if not any(sources):
            raise DataSourceUnavailableError("Trading signal sources are unavailable")
        unique = {item.signal_id: item for item in signals}
        return list(unique.values()), sources, warnings

    async def list(
        self, *, symbol: str | None, side: str | None, strategy: str | None, status: str | None, limit: int, offset: int
    ) -> ServicePayload:
        rows, sources, warnings = await self.all_signals()
        filtered = [
            item
            for item in rows
            if (not symbol or item.symbol == symbol)
            and (not side or item.side == side)
            and (not strategy or item.strategy == strategy)
            and (not status or item.status.value == status)
        ]
        filtered.sort(key=lambda item: item.timestamp or datetime.min.replace(tzinfo=UTC), reverse=True)
        return ServicePayload(
            Page(items=filtered[offset : offset + limit], total=len(filtered), limit=limit, offset=offset),
            self.meta(
                sources,
                source="trade_signals.json,mt5_trade_signals.json,bridge_rejected_signals.json",
                threshold=300,
                warnings=warnings,
            ),
        )

    async def latest(self) -> ServicePayload:
        payload = await self.list(symbol=None, side=None, strategy=None, status=None, limit=1, offset=0)
        page = payload.data
        return ServicePayload(page.items[0] if page.items else None, payload.meta)

    async def get(self, signal_id: str) -> ServicePayload:
        rows, sources, warnings = await self.all_signals()
        item = next((row for row in rows if row.signal_id == signal_id), None)
        if item is None:
            raise ResourceNotFoundError(f"Signal {signal_id} was not found")
        return ServicePayload(item, self.meta(sources, source=item.source, threshold=300, warnings=warnings))
