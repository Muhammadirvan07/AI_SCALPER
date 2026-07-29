from __future__ import annotations

import asyncio
from collections import deque
from datetime import UTC, datetime, timedelta
from time import monotonic

from app.schemas.news import CircuitState

from .base import ProviderCircuitOpenError


class ProviderCircuitBreaker:
    def __init__(self, *, failure_threshold: int, cooldown_seconds: float) -> None:
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.cooldown_until: datetime | None = None
        self._probe_in_flight = False

    def allow_request(self, *, force: bool = False) -> None:
        del force  # Force refresh never bypasses provider safety.
        now = datetime.now(UTC)
        if self.state == CircuitState.OPEN:
            if self.cooldown_until and now >= self.cooldown_until and not self._probe_in_flight:
                self.state = CircuitState.HALF_OPEN
                self._probe_in_flight = True
                return
            raise ProviderCircuitOpenError("Provider circuit breaker is open")
        if self.state == CircuitState.HALF_OPEN and self._probe_in_flight:
            raise ProviderCircuitOpenError("Provider circuit breaker probe is already running")

    def success(self) -> None:
        self.failure_count = 0
        self.state = CircuitState.CLOSED
        self.cooldown_until = None
        self._probe_in_flight = False

    def failure(self) -> None:
        self.failure_count += 1
        self._probe_in_flight = False
        if self.state == CircuitState.HALF_OPEN or self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            self.cooldown_until = datetime.now(UTC) + timedelta(seconds=self.cooldown_seconds)

    def open_for(self, seconds: float) -> None:
        self.failure_count += 1
        self._probe_in_flight = False
        self.state = CircuitState.OPEN
        self.cooldown_until = datetime.now(UTC) + timedelta(seconds=max(self.cooldown_seconds, seconds))


class ProviderRateLimiter:
    """Per-provider limiter. Unknown quotas use serialized conservative mode."""

    def __init__(self, max_requests_per_minute: int | None) -> None:
        self.max_requests_per_minute = max_requests_per_minute
        self._lock = asyncio.Lock()
        self._timestamps: deque[float] = deque()

    async def __aenter__(self) -> ProviderRateLimiter:
        await self._lock.acquire()
        if self.max_requests_per_minute:
            now = monotonic()
            while self._timestamps and now - self._timestamps[0] >= 60:
                self._timestamps.popleft()
            if len(self._timestamps) >= self.max_requests_per_minute:
                delay = max(0.0, 60 - (now - self._timestamps[0]))
                await asyncio.sleep(delay)
            self._timestamps.append(monotonic())
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        self._lock.release()
