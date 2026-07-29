from __future__ import annotations

import asyncio

from app.schemas.market import WatchlistItem
from app.utils.serialization import as_dict, as_list

from .base import BaseService, ServicePayload
from .market_service import MarketService
from .signal_service import SignalService


class WatchlistService(BaseService):
    def __init__(self, json_repository, market: MarketService, signals: SignalService) -> None:
        super().__init__(json_repository)
        self.market = market
        self.signals = signals

    async def get(self, symbol: str | None = None) -> ServicePayload:
        active, warning_active = await self.optional_source("active_pairs")
        replay, warning_replay = await self.optional_source("replay_candidates")
        quality, warning_quality = await self.optional_source("quality_rules")
        active_map, replay_map = as_dict(active.value if active else {}), as_dict(replay.value if replay else {})
        symbols = set(self.market.registry.symbols())
        for key in ("active_pairs", "main_active_pairs", "secondary_active_pairs", "exploration_active_pairs"):
            symbols.update(str(item).upper() for item in as_list(active_map.get(key)) if item)
        for key in ("approved_symbols", "watch_symbols", "blocked_symbols"):
            symbols.update(str(item).upper() for item in as_list(replay_map.get(key)) if item)
        if symbol:
            symbols = {symbol} if symbol in symbols else set()
        signal_rows, _, signal_warnings = await self.signals.all_signals()
        latest_signals = {}
        for item in signal_rows:
            if item.symbol and item.symbol not in latest_signals:
                latest_signals[item.symbol] = item
        rows: list[WatchlistItem] = []
        semaphore = asyncio.Semaphore(8)

        async def build(item_symbol: str) -> WatchlistItem | None:
            if item_symbol not in self.market.registry.symbols():
                return WatchlistItem(
                    symbol=item_symbol,
                    blocked=item_symbol in as_list(replay_map.get("blocked_symbols")),
                    quality_status=str(as_dict(quality.value if quality else {}).get("quality_status") or "UNKNOWN"),
                )
            async with semaphore:
                quote, indicators = await asyncio.gather(
                    self.market.quote(item_symbol), self.market.indicators(item_symbol, "M15")
                )
            signal = latest_signals.get(item_symbol)
            return WatchlistItem(
                symbol=item_symbol,
                last_price=quote.data.last,
                change=quote.data.change,
                change_percent=quote.data.change_percent,
                trend=indicators.data.trend,
                volatility=indicators.data.volatility,
                atr=indicators.data.atr14,
                adx=indicators.data.adx14,
                strategy=signal.strategy if signal else None,
                strategy_score=signal.adaptive_score or signal.original_score if signal else None,
                signal=signal.side or signal.status.value if signal else None,
                quality_status=str(as_dict(quality.value if quality else {}).get("quality_status") or "UNKNOWN"),
                blocked=item_symbol in as_list(replay_map.get("blocked_symbols")),
                last_update=quote.data.timestamp,
                stale=quote.meta.stale,
            )

        built = await asyncio.gather(*(build(item) for item in sorted(symbols)))
        rows = [item for item in built if item is not None]
        warnings = [item for item in (warning_active, warning_replay, warning_quality, *signal_warnings) if item]
        meta = self.meta(
            [active, replay, quality],
            source="active_pairs.json,paper_replay_candidates.json,data/*.csv",
            threshold=300,
            warnings=warnings,
        )
        meta.stale = all(item.stale for item in rows) if rows else True
        meta.data_status = "stale" if meta.stale else "live"
        return ServicePayload(rows[0] if symbol and rows else rows, meta)
