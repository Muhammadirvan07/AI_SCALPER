from __future__ import annotations

from datetime import datetime
from typing import Any, ClassVar

from app.core.config import Settings
from app.core.exceptions import AppError
from app.repositories.json_repository import JsonRepository

from .base import ProviderFetchError


class FileNewsProvider:
    name = "file"
    CAPABILITIES: ClassVar[dict[str, bool | None]] = {
        "financial_news": True,
        "replay": True,
        "offline_snapshot": True,
    }

    def __init__(self, settings: Settings, repository: JsonRepository) -> None:
        self.settings = settings
        self.capabilities: dict[str, bool | None] = dict(self.CAPABILITIES)
        self.repository = repository
        self.enabled = settings.news_enabled and (
            settings.file_news_provider_enabled or "file" in settings.news_provider_modes
        )
        self.configured = bool(settings.file_news_path and settings.file_news_path.is_file())

    async def fetch_news(
        self,
        *,
        symbols: list[str] | None = None,
        currencies: list[str] | None = None,
        categories: list[str] | None = None,
        published_after: datetime | None = None,
        limit: int = 50,
    ) -> list[dict]:
        del symbols, currencies, categories, published_after
        if not self.enabled or not self.configured:
            return []
        try:
            result = await self.repository.read("news_archive")
        except AppError as exc:
            raise ProviderFetchError(exc.message) from exc
        rows = self._rows(result.value)
        return rows[:limit]

    async def fetch_latest(
        self, *, limit: int, symbols: list[str] | None = None, categories: list[str] | None = None
    ) -> list[dict]:
        return await self.fetch_news(limit=limit, symbols=symbols, categories=categories)

    async def health_check(self) -> dict:
        return {"configured": self.configured, "enabled": self.enabled, "capabilities": self.capabilities}

    @staticmethod
    def _rows(value: Any) -> list[dict]:
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if not isinstance(value, dict):
            raise ProviderFetchError("News archive must contain an object or array")
        for key in ("items", "articles", "news", "events", "calendar"):
            rows = value.get(key)
            if isinstance(rows, list):
                return [item for item in rows if isinstance(item, dict)]
        return []


class FileEconomicCalendarProvider:
    name = "file_calendar"
    CAPABILITIES: ClassVar[dict[str, bool | None]] = {
        "economic_calendar": True,
        "replay": True,
        "offline_snapshot": True,
    }

    def __init__(self, settings: Settings, repository: JsonRepository) -> None:
        self.settings = settings
        self.capabilities: dict[str, bool | None] = dict(self.CAPABILITIES)
        self.repository = repository
        self.enabled = (
            settings.news_enabled and settings.economic_calendar_enabled and settings.file_news_provider_enabled
        )
        self.configured = bool(settings.file_economic_calendar_path and settings.file_economic_calendar_path.is_file())

    async def fetch_calendar(
        self,
        *,
        currencies: list[str] | None = None,
        countries: list[str] | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        minimum_impact: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        del currencies, countries, start_time, end_time, minimum_impact
        if not self.enabled or not self.configured:
            return []
        try:
            result = await self.repository.read("economic_calendar")
        except AppError as exc:
            raise ProviderFetchError(exc.message) from exc
        return FileNewsProvider._rows(result.value)[:limit]

    async def health_check(self) -> dict:
        return {"configured": self.configured, "enabled": self.enabled, "capabilities": self.capabilities}
