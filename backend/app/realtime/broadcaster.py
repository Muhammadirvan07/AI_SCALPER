from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from .connection_manager import ConnectionManager
from .event_bus import EventBus
from .events import InternalEvent


class EventBroadcaster:
    def __init__(self, bus: EventBus, connections: ConnectionManager) -> None:
        self.bus = bus
        self.connections = connections
        self._task: asyncio.Task[None] | None = None
        self.running = False

    async def start(self) -> None:
        self.running = True
        self._task = asyncio.create_task(self._loop(), name="event-broadcaster")

    async def stop(self) -> None:
        self.running = False
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)

    async def _loop(self) -> None:
        try:
            while self.running:
                event = await self.bus.next()
                await self.connections.broadcast(event.event_type, event.channel, event.data)
                self.bus.queue.task_done()
        except asyncio.CancelledError:
            return


def events_for_source(key: str) -> list[InternalEvent]:
    now = datetime.now(UTC)
    payload = {"source": key, "changed_at": now}
    if key.startswith("market:"):
        symbol = key.split(":", 1)[1]
        return [InternalEvent("market.candle.updated", f"market:{symbol}", now, payload)]
    mapping = {
        "trade_signals": [("signal.updated", "signals"), ("overview.updated", "overview")],
        "mt5_trade_signals": [("signal.updated", "signals")],
        "paper_orders": [("order.updated", "orders"), ("kpi.updated", "overview")],
        "quality_rules": [("quality.updated", "quality")],
        "quality_report": [("quality.updated", "quality")],
        "bridge_status": [("risk.updated", "risk"), ("system.updated", "system")],
        "decision_health": [("overview.updated", "overview")],
    }
    return [
        InternalEvent(event_type, channel, now, payload)
        for event_type, channel in mapping.get(key, [("system.updated", "system")])
    ]
