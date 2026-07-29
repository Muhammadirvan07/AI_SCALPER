from __future__ import annotations

from datetime import datetime
from typing import Protocol

from app.schemas.economic_calendar import EconomicCalendarSourceStatus


class EconomicCalendarProvider(Protocol):
    name: str
    display_name: str
    enabled: bool
    configured: bool
    official_domain: str | None
    capabilities: list[str]

    async def fetch_schedule(
        self,
        *,
        start_time: datetime,
        end_time: datetime,
        currencies: list[str] | None = None,
    ) -> list[dict]: ...

    async def fetch_release(self, *, event: dict) -> dict | None: ...

    async def health_check(self) -> dict: ...


class EconomicCalendarCollection:
    def __init__(self) -> None:
        self.items: list[tuple[str, dict]] = []
        self.providers_attempted: list[str] = []
        self.providers_succeeded: list[str] = []
        self.providers_failed: list[str] = []
        self.providers_rate_limited: list[str] = []
        self.providers_unconfigured: list[str] = []
        self.partial = False
        self.collected_at: datetime | None = None


ProviderStatuses = list[EconomicCalendarSourceStatus]
