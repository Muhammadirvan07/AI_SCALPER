from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from time import monotonic
from typing import Annotated, Any

from fastapi import Depends, Query, Request
from pydantic import AfterValidator

from app.adapters.bridge_adapter import BridgeAdapter
from app.adapters.dashboard_report_adapter import DashboardReportAdapter
from app.adapters.economic_calendar_adapter import EconomicCalendarAdapter
from app.adapters.economic_calendar_context_adapter import EconomicCalendarContextAdapter
from app.adapters.market_adapter import MarketAdapter
from app.adapters.news_adapter import NewsAdapter
from app.adapters.order_adapter import OrderAdapter
from app.adapters.signal_adapter import SignalAdapter
from app.core.cache import AsyncTTLCache
from app.core.config import Settings
from app.core.security import validate_symbol
from app.providers.economic_calendar.registry import EconomicCalendarProviderRegistry
from app.providers.news.provider_registry import NewsProviderRegistry
from app.realtime.broadcaster import EventBroadcaster, events_for_source
from app.realtime.connection_manager import ConnectionManager
from app.realtime.event_bus import EventBus
from app.realtime.file_watcher import AsyncFileWatcher
from app.repositories.csv_repository import CsvRepository
from app.repositories.economic_calendar_repository import EconomicCalendarRepository
from app.repositories.file_registry import FileRegistry
from app.repositories.json_repository import JsonRepository
from app.repositories.log_repository import LogRepository
from app.repositories.news_repository import NewsRepository
from app.services.activity_service import ActivityService
from app.services.compatibility_service import LegacyConnectionManager, LegacySnapshotService
from app.services.diagnostic_service import DiagnosticService
from app.services.economic_calendar_guard_service import EconomicCalendarGuardService
from app.services.economic_calendar_scheduler import EconomicCalendarScheduler
from app.services.economic_calendar_service import EconomicCalendarService
from app.services.log_service import LogService
from app.services.market_service import MarketService
from app.services.news_scheduler import NewsScheduler
from app.services.news_service import NewsService
from app.services.order_service import OrderService
from app.services.overview_service import OverviewService
from app.services.performance_service import PerformanceService
from app.services.quality_service import QualityService
from app.services.risk_service import RiskService
from app.services.sentiment_service import SentimentService
from app.services.signal_service import SignalService
from app.services.system_service import SystemService
from app.services.trading_economics_stream import TradingEconomicsStream
from app.services.watchlist_service import WatchlistService

Symbol = Annotated[str, AfterValidator(validate_symbol)]
PageLimit = Annotated[int, Query(ge=1, le=500)]
PageOffset = Annotated[int, Query(ge=0)]


@dataclass(slots=True)
class AppContainer:
    settings: Settings
    cache: AsyncTTLCache
    registry: FileRegistry
    json_repository: JsonRepository
    csv_repository: CsvRepository
    connections: ConnectionManager
    event_bus: EventBus
    broadcaster: EventBroadcaster
    watcher: AsyncFileWatcher
    orders: OrderService
    signals: SignalService
    performance: PerformanceService
    overview: OverviewService
    market: MarketService
    watchlist: WatchlistService
    diagnostics: DiagnosticService
    risk: RiskService
    quality: QualityService
    system: SystemService
    logs: LogService
    activity: ActivityService
    news: NewsService
    economic_calendar: EconomicCalendarService
    economic_calendar_scheduler: EconomicCalendarScheduler
    news_scheduler: NewsScheduler
    trading_economics_stream: TradingEconomicsStream
    legacy_snapshots: LegacySnapshotService
    legacy_connections: LegacyConnectionManager

    @classmethod
    def build(cls, settings: Settings) -> AppContainer:
        cache = AsyncTTLCache()
        registry = FileRegistry(settings)
        json_repository = JsonRepository(registry, settings)
        csv_repository = CsvRepository(registry, settings)
        connections = ConnectionManager(settings)
        bus = EventBus()
        broadcaster = EventBroadcaster(bus, connections)
        order_service = OrderService(json_repository, OrderAdapter())
        signal_service = SignalService(json_repository, SignalAdapter())
        performance = PerformanceService(order_service)
        overview = OverviewService(json_repository, performance, DashboardReportAdapter())
        market = MarketService(csv_repository, registry, MarketAdapter())
        watchlist = WatchlistService(json_repository, market, signal_service)
        risk = RiskService(json_repository, performance, BridgeAdapter(), settings)
        quality = QualityService(json_repository)
        activity = ActivityService(order_service, signal_service)
        provider_registry = NewsProviderRegistry(settings, json_repository, registry.symbols)
        calendar_provider_registry = EconomicCalendarProviderRegistry(settings)
        economic_calendar = EconomicCalendarService(
            settings,
            EconomicCalendarRepository(settings, calendar_provider_registry),
            EconomicCalendarAdapter(),
            registry.symbols,
            bus,
            EconomicCalendarGuardService(),
        )
        diagnostics = DiagnosticService(
            json_repository,
            EconomicCalendarContextAdapter(settings, economic_calendar)
            if settings.economic_calendar_diagnostics_enabled
            else None,
        )
        news = NewsService(
            settings,
            NewsRepository(provider_registry),
            provider_registry,
            NewsAdapter(),
            SentimentService(settings),
            economic_calendar,
            registry,
            bus,
        )
        news_scheduler = NewsScheduler(settings, news, cache)
        economic_calendar_scheduler = EconomicCalendarScheduler(settings, economic_calendar, bus)
        trading_economics_stream = TradingEconomicsStream(settings, economic_calendar, bus)
        legacy_snapshots = LegacySnapshotService(settings)

        container_ref: dict[str, Any] = {}

        async def on_change(key, path) -> None:
            if key.startswith("market:"):
                await csv_repository.invalidate(key.split(":", 1)[1])
            else:
                await json_repository.invalidate(key)
            await cache.invalidate()
            for event in events_for_source(key):
                await bus.publish(event)
            if key == "news_archive":
                scheduler = container_ref.get("news_scheduler")
                if scheduler:
                    await scheduler.refresh_now()
            if key == "economic_calendar":
                scheduler = container_ref.get("economic_calendar_scheduler")
                if scheduler:
                    await scheduler.refresh_now()
            activity.record(
                "data.refreshed", "info", "file_watcher", "Data refreshed", f"{path.name} was updated", {"source": key}
            )
            snapshot = await legacy_snapshots.rebuild(force=True)
            legacy = container_ref.get("legacy_connections")
            if legacy:
                await legacy.broadcast(snapshot)

        watcher = AsyncFileWatcher(settings, registry, on_change)
        legacy_connections = LegacyConnectionManager(settings.websocket_heartbeat_seconds, legacy_snapshots)
        container_ref["legacy_connections"] = legacy_connections
        container_ref["news_scheduler"] = news_scheduler
        container_ref["economic_calendar_scheduler"] = economic_calendar_scheduler

        def news_components() -> dict[str, dict[str, Any]]:
            rows = news.system_components()
            rows["trading_economics_stream"] = trading_economics_stream.component()
            calendar_status = economic_calendar.runtime_status().data
            rows["economic_calendar_service"] = {
                "name": "economic_calendar_service",
                "status": economic_calendar.meta().data_status,
                "last_heartbeat": economic_calendar.last_refresh_at,
                "last_successful_update": economic_calendar.last_success_at,
                "latest_error": economic_calendar.repository.last_error,
                "stale": economic_calendar.meta().stale,
                "source_file": None,
            }
            rows["economic_calendar_scheduler"] = {
                "name": "economic_calendar_scheduler",
                "status": "healthy" if economic_calendar_scheduler.state.running else "offline",
                "last_heartbeat": economic_calendar_scheduler.state.last_run_at,
                "last_successful_update": economic_calendar_scheduler.state.last_success_at,
                "latest_error": economic_calendar_scheduler.state.last_error,
                "stale": not economic_calendar_scheduler.state.running,
                "source_file": None,
                "mode": calendar_status.scheduler_mode,
            }
            for source in calendar_provider_registry.statuses():
                rows[f"economic_calendar_source:{source.name}"] = {
                    "name": f"economic_calendar_source:{source.name}",
                    "status": source.status,
                    "last_heartbeat": source.last_fetch_at,
                    "last_successful_update": source.last_success_at,
                    "latest_error": source.last_error,
                    "stale": source.stale,
                    "source_file": source.official_domain,
                }
            return rows

        system = SystemService(
            settings,
            registry,
            json_repository,
            monotonic(),
            watcher.state,
            connections.state,
            news_components,
        )
        logs = LogService(LogRepository(settings))

        return cls(
            settings,
            cache,
            registry,
            json_repository,
            csv_repository,
            connections,
            bus,
            broadcaster,
            watcher,
            order_service,
            signal_service,
            performance,
            overview,
            market,
            watchlist,
            diagnostics,
            risk,
            quality,
            system,
            logs,
            activity,
            news,
            economic_calendar,
            economic_calendar_scheduler,
            news_scheduler,
            trading_economics_stream,
            legacy_snapshots,
            legacy_connections,
        )


def get_container(request: Request) -> AppContainer:
    return request.app.state.container


Container = Annotated[AppContainer, Depends(get_container)]


async def cached(container: AppContainer, key: str, ttl: float, loader: Callable[[], Awaitable[Any]]) -> Any:
    return await container.cache.get_or_load(key, ttl, loader)
