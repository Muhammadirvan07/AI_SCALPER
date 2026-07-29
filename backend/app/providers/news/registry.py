from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from app.adapters.alpha_vantage_news_adapter import AlphaVantageNewsAdapter
from app.adapters.file_news_adapter import FileEconomicCalendarAdapter, FileNewsAdapter
from app.adapters.finnhub_news_adapter import FinnhubNewsAdapter
from app.adapters.gdelt_news_adapter import GdeltNewsAdapter
from app.adapters.investing_rss_adapter import InvestingRssAdapter
from app.adapters.official_rss_adapter import OfficialRssAdapter
from app.adapters.trading_economics_calendar_adapter import TradingEconomicsCalendarAdapter
from app.core.config import Settings
from app.repositories.json_repository import JsonRepository
from app.schemas.news import ProviderStatus

from .alpha_vantage import AlphaVantageNewsProvider
from .base import CalendarQuery, NewsQuery, ProviderCollectionResult
from .file_provider import FileEconomicCalendarProvider, FileNewsProvider
from .finnhub import FinnhubNewsProvider
from .gdelt import GdeltNewsProvider
from .investing_rss import InvestingRssNewsProvider
from .official_rss import OfficialRssNewsProvider
from .orchestrator import NewsProviderOrchestrator
from .trading_economics import TradingEconomicsCalendarProvider


class NewsProviderRegistry:
    def __init__(self, settings: Settings, repository: JsonRepository, known_symbols: Callable[[], list[str]]) -> None:
        self.settings = settings
        self.orchestrator = NewsProviderOrchestrator(settings, known_symbols)
        priority = {name: index for index, name in enumerate(settings.news_provider_priority, start=1)}
        investing = InvestingRssNewsProvider(settings)
        alpha = AlphaVantageNewsProvider(settings)
        finnhub = FinnhubNewsProvider(settings)
        gdelt = GdeltNewsProvider(settings)
        official = OfficialRssNewsProvider(settings)
        file_news = FileNewsProvider(settings, repository)
        trading_economics = TradingEconomicsCalendarProvider(settings)
        file_calendar = FileEconomicCalendarProvider(settings, repository)
        self.orchestrator.register_news(
            investing,
            InvestingRssAdapter(),
            priority=priority.get("investing_rss", 1),
            max_requests_per_minute=None,
        )
        self.orchestrator.register_news(
            alpha,
            AlphaVantageNewsAdapter(),
            priority=priority.get("alpha_vantage", 1),
            max_requests_per_minute=settings.alpha_vantage_max_requests_per_minute,
        )
        self.orchestrator.register_news(
            finnhub,
            FinnhubNewsAdapter(),
            priority=priority.get("finnhub", 2),
            max_requests_per_minute=settings.finnhub_max_requests_per_minute,
        )
        self.orchestrator.register_news(
            official,
            OfficialRssAdapter(),
            priority=priority.get("official_rss", 3),
            max_requests_per_minute=None,
        )
        self.orchestrator.register_news(
            gdelt,
            GdeltNewsAdapter(),
            priority=priority.get("gdelt", 4),
            max_requests_per_minute=settings.gdelt_max_requests_per_minute,
        )
        self.orchestrator.register_news(
            file_news,
            FileNewsAdapter(),
            priority=priority.get("file", 5),
            max_requests_per_minute=None,
        )
        self.orchestrator.register_calendar(
            trading_economics,
            TradingEconomicsCalendarAdapter(),
            priority=1,
            max_requests_per_minute=settings.trading_economics_max_requests_per_minute,
        )
        self.orchestrator.register_calendar(
            finnhub,
            _FinnhubCalendarAdapter(FinnhubNewsAdapter()),
            priority=2,
            max_requests_per_minute=settings.finnhub_max_requests_per_minute,
        )
        self.orchestrator.register_calendar(
            file_calendar,
            FileEconomicCalendarAdapter(),
            priority=3,
            max_requests_per_minute=None,
        )

    @property
    def providers(self) -> list:
        return [runtime.provider for runtime in self.orchestrator.runtimes.values()]

    async def fetch_all(
        self, *, provider_names: list[str] | None = None, force: bool = False
    ) -> ProviderCollectionResult:
        return await self.orchestrator.collect(
            NewsQuery(
                published_after=datetime.now(UTC) - timedelta(days=self.settings.news_historical_retention_days),
                limit=self.settings.news_max_articles_per_provider,
            ),
            provider_names=provider_names,
            force=force,
        )

    async def fetch_calendar(
        self, *, provider_names: list[str] | None = None, force: bool = False
    ) -> ProviderCollectionResult:
        return await self.orchestrator.collect_calendar(
            CalendarQuery(
                start_time=datetime.now(UTC) - timedelta(hours=12),
                end_time=datetime.now(UTC) + timedelta(days=7),
                limit=500,
            ),
            provider_names=provider_names,
            force=force,
        )

    def statuses(self) -> list[ProviderStatus]:
        return [status.model_copy(deep=True) for status in self.orchestrator.statuses.values()]

    def status(self, provider_name: str) -> ProviderStatus | None:
        status = self.orchestrator.statuses.get(provider_name.lower())
        return status.model_copy(deep=True) if status else None


class _FinnhubCalendarAdapter:
    def __init__(self, adapter: FinnhubNewsAdapter) -> None:
        self.adapter = adapter

    def normalize(self, raw: dict, *, known_symbols: list[str]) -> dict:
        return self.adapter.normalize_calendar(raw, known_symbols=known_symbols)
