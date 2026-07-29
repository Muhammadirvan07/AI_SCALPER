from __future__ import annotations

import asyncio

from .events import InternalEvent


class EventBus:
    def __init__(self, maxsize: int = 512) -> None:
        self.queue: asyncio.Queue[InternalEvent] = asyncio.Queue(maxsize=maxsize)
        self.dropped_events = 0

    async def publish(self, event: InternalEvent) -> None:
        if self.queue.full():
            try:
                self.queue.get_nowait()
                self.queue.task_done()
            except asyncio.QueueEmpty:
                pass
            self.dropped_events += 1
        await self.queue.put(event)

    async def next(self) -> InternalEvent:
        return await self.queue.get()
