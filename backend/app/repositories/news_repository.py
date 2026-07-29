from __future__ import annotations

from app.providers.news.base import ProviderCollectionResult
from app.providers.news.provider_registry import NewsProviderRegistry


class NewsRepository:
    """Provider-backed repository boundary with provider-level last-known-good handling."""

    def __init__(self, providers: NewsProviderRegistry) -> None:
        self.providers = providers
        self.last_collection = ProviderCollectionResult()

    async def fetch_latest(
        self, *, provider_names: list[str] | None = None, force: bool = False
    ) -> list[tuple[str, dict]]:
        self.last_collection = await self.providers.fetch_all(provider_names=provider_names, force=force)
        return self.last_collection.items
