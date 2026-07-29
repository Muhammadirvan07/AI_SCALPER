from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from app.schemas.performance import PerformanceData
from app.utils.calculations import performance_metrics
from app.utils.serialization import as_dict, safe_float

from .base import ServicePayload
from .order_service import OrderService

Range = Literal["1d", "7d", "30d", "3m", "all"]


class PerformanceService:
    def __init__(self, orders: OrderService) -> None:
        self.orders = orders

    async def get(self, range_value: Range, symbol: str | None, strategy: str | None) -> ServicePayload:
        orders, source = await self.orders.all_orders()
        filtered = [
            row for row in orders if (not symbol or row.symbol == symbol) and (not strategy or row.strategy == strategy)
        ]
        if range_value != "all" and filtered:
            days = {"1d": 1, "7d": 7, "30d": 30, "3m": 90}[range_value]
            timestamps: list[datetime] = []
            for row in filtered:
                timestamp = row.close_time or row.open_time
                if timestamp is not None:
                    timestamps.append(timestamp)
            anchor = max(timestamps) if timestamps else datetime.now(UTC)
            cutoff = anchor - timedelta(days=days)
            filtered_rows = []
            for row in filtered:
                timestamp = row.close_time or row.open_time
                if timestamp is not None and timestamp >= cutoff:
                    filtered_rows.append(row)
            filtered = filtered_rows
        rows = [
            row.model_dump(mode="python")
            for row in sorted(
                filtered, key=lambda item: item.close_time or item.open_time or datetime.min.replace(tzinfo=UTC)
            )
        ]
        quality, quality_warning = await self.orders.optional_source("quality_report")
        quality_map = as_dict(quality.value if quality else {})
        drawdown = as_dict(quality_map.get("drawdown"))
        starting_balance = safe_float(drawdown.get("starting_balance")) or 0.0
        metrics = performance_metrics(rows, starting_balance=starting_balance)
        data = PerformanceData.model_validate(metrics)
        warnings = [quality_warning] if quality_warning else []
        meta = self.orders.meta(
            [source, quality], source="paper_orders.json,paper_quality_report.json", threshold=1800, warnings=warnings
        )
        meta.warnings.append(
            "Range filters anchor to the latest source record because this is an offline paper dataset."
        )
        return ServicePayload(data, meta)

    async def section(
        self, section: str, range_value: Range, symbol: str | None, strategy: str | None
    ) -> ServicePayload:
        payload = await self.get(range_value, symbol, strategy)
        data: PerformanceData = payload.data
        value: Any
        if section == "equity-curve":
            value = [
                {"timestamp": point.timestamp, "equity": point.equity, "balance": point.balance} for point in data.curve
            ]
        elif section == "pnl":
            value = [
                {"timestamp": point.timestamp, "period_pnl": point.period_pnl, "cumulative_pnl": point.cumulative_pnl}
                for point in data.curve
            ]
        elif section == "drawdown":
            value = [
                {"timestamp": point.timestamp, "drawdown": point.drawdown, "drawdown_percent": point.drawdown_percent}
                for point in data.curve
            ]
        else:
            value = data.model_dump(exclude={"curve"})
        return ServicePayload(value, payload.meta)
