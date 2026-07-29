from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from time import monotonic
from typing import Any


@dataclass(slots=True)
class CacheEntry:
    value: Any
    expires_at: float
    updated_at: datetime


class AsyncTTLCache:
    def __init__(self) -> None:
        self._items: dict[str, CacheEntry] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._guard = asyncio.Lock()

    async def get(self, key: str) -> Any | None:
        entry = self._items.get(key)
        if entry is None or entry.expires_at <= monotonic():
            return None
        return deepcopy(entry.value)

    async def set(self, key: str, value: Any, ttl: float) -> Any:
        self._items[key] = CacheEntry(deepcopy(value), monotonic() + ttl, datetime.now(UTC))
        return deepcopy(value)

    async def get_or_load(self, key: str, ttl: float, loader: Callable[[], Awaitable[Any]]) -> Any:
        cached = await self.get(key)
        if cached is not None:
            return cached
        async with self._guard:
            lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            cached = await self.get(key)
            if cached is not None:
                return cached
            return await self.set(key, await loader(), ttl)

    async def invalidate(self, prefix: str | None = None) -> None:
        if prefix is None:
            self._items.clear()
            return
        for key in [key for key in self._items if key.startswith(prefix)]:
            self._items.pop(key, None)

    @property
    def size(self) -> int:
        return len(self._items)
