from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.core.exceptions import AppError
from app.schemas.common import ApiMeta
from app.utils.serialization import stable_id

from .base import ServicePayload
from .order_service import OrderService
from .signal_service import SignalService


class ActivityService:
    def __init__(self, orders: OrderService, signals: SignalService) -> None:
        self.orders = orders
        self.signals = signals
        self._runtime_events: list[dict[str, Any]] = []

    def record(
        self,
        event_type: str,
        severity: str,
        component: str,
        title: str,
        message: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        now = datetime.now(UTC)
        self._runtime_events.insert(
            0,
            {
                "id": stable_id("event", now, event_type, message),
                "timestamp": now,
                "type": event_type,
                "severity": severity,
                "component": component,
                "title": title,
                "message": message,
                "metadata": metadata or {},
            },
        )
        del self._runtime_events[200:]

    async def get(self, limit: int) -> ServicePayload:
        rows = list(self._runtime_events)
        try:
            signals, _, warnings = await self.signals.all_signals()
            for signal_item in signals:
                rows.append(
                    {
                        "id": stable_id("event", signal_item.signal_id),
                        "timestamp": signal_item.timestamp,
                        "type": "signal.blocked" if signal_item.status.value == "BLOCKED" else "signal.generated",
                        "severity": "warning" if signal_item.status.value in {"BLOCKED", "REJECTED"} else "info",
                        "component": "decision_engine",
                        "title": "Signal blocked" if signal_item.status.value == "BLOCKED" else "Signal generated",
                        "message": signal_item.reason
                        or f"{signal_item.symbol or 'Unknown'} {signal_item.status.value}",
                        "metadata": {
                            "symbol": signal_item.symbol,
                            "strategy": signal_item.strategy,
                            "signal_id": signal_item.signal_id,
                        },
                    }
                )
        except AppError:
            warnings = ["Signal activity unavailable"]
        try:
            orders, _ = await self.orders.all_orders()
            for order_item in orders:
                rows.append(
                    {
                        "id": stable_id("event", order_item.order_id, order_item.status),
                        "timestamp": order_item.close_time or order_item.open_time,
                        "type": "order.closed" if order_item.status == "CLOSED" else "order.opened",
                        "severity": "success"
                        if (order_item.pnl or 0) > 0
                        else "warning"
                        if (order_item.pnl or 0) < 0
                        else "info",
                        "component": "paper_executor",
                        "title": "Paper order closed" if order_item.status == "CLOSED" else "Paper order opened",
                        "message": f"{order_item.symbol or 'Unknown'} {order_item.side or ''} {order_item.result or order_item.status}",
                        "metadata": {
                            "symbol": order_item.symbol,
                            "strategy": order_item.strategy,
                            "order_id": order_item.order_id,
                            "pnl": order_item.pnl,
                        },
                    }
                )
        except AppError:
            warnings.append("Order activity unavailable")
        rows = [row for row in rows if row.get("timestamp") is not None]
        rows.sort(key=lambda row: row["timestamp"], reverse=True)
        now = datetime.now(UTC)
        updated = rows[0]["timestamp"] if rows else None
        return ServicePayload(
            rows[:limit],
            ApiMeta(
                source="signals,orders,runtime",
                source_updated_at=updated,
                server_timestamp=now,
                age_seconds=(now - updated).total_seconds() if updated else None,
                stale=not bool(rows),
                source_available=bool(rows),
                data_status="historical" if rows else "unavailable",
                warnings=warnings,
            ),
        )
