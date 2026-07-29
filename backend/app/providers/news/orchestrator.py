from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from time import perf_counter
from typing import Any, cast

from app.core.config import Settings
from app.schemas.news import CircuitState, ProviderStatus, QuotaStatus

from .base import (
    CalendarProviderAdapter,
    CalendarQuery,
    EconomicCalendarProvider,
    NewsProvider,
    NewsProviderAdapter,
    NewsQuery,
    ProviderAuthenticationError,
    ProviderCircuitOpenError,
    ProviderCollectionResult,
    ProviderEntitlementError,
    ProviderFetchError,
    ProviderRateLimitError,
)
from .resilience import ProviderCircuitBreaker, ProviderRateLimiter

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ProviderRuntime:
    name: str
    provider: NewsProvider | EconomicCalendarProvider
    priority: int
    breaker: ProviderCircuitBreaker
    limiter: ProviderRateLimiter
    refresh_interval_seconds: float
    news_adapter: NewsProviderAdapter | None = None
    calendar_adapter: CalendarProviderAdapter | None = None


class NewsProviderOrchestrator:
    def __init__(self, settings: Settings, known_symbols: Callable[[], list[str]]) -> None:
        self.settings = settings
        self.known_symbols = known_symbols
        self.runtimes: dict[str, ProviderRuntime] = {}
        self.statuses: dict[str, ProviderStatus] = {}
        self.last_good_news: dict[str, list[dict[str, Any]]] = {}
        self.last_good_calendar: dict[str, list[dict[str, Any]]] = {}
        self.last_news_result = ProviderCollectionResult()
        self.last_calendar_result = ProviderCollectionResult()
        self._semaphore = asyncio.Semaphore(settings.news_max_parallel_provider_requests)

    def register_news(
        self,
        provider: NewsProvider,
        adapter: NewsProviderAdapter,
        *,
        priority: int,
        max_requests_per_minute: int | None,
    ) -> None:
        runtime = self._runtime(provider, priority, max_requests_per_minute)
        runtime.news_adapter = adapter

    def register_calendar(
        self,
        provider: EconomicCalendarProvider,
        adapter: CalendarProviderAdapter,
        *,
        priority: int,
        max_requests_per_minute: int | None,
    ) -> None:
        runtime = self._runtime(provider, priority, max_requests_per_minute)
        runtime.calendar_adapter = adapter

    def _runtime(
        self,
        provider: NewsProvider | EconomicCalendarProvider,
        priority: int,
        max_requests_per_minute: int | None,
    ) -> ProviderRuntime:
        runtime = self.runtimes.get(provider.name)
        if runtime is None:
            runtime = ProviderRuntime(
                name=provider.name,
                provider=provider,
                priority=priority,
                breaker=ProviderCircuitBreaker(
                    failure_threshold=self.settings.news_provider_failure_threshold,
                    cooldown_seconds=self.settings.news_provider_cooldown_seconds,
                ),
                limiter=ProviderRateLimiter(max_requests_per_minute),
                refresh_interval_seconds=self._refresh_interval(provider.name),
            )
            self.runtimes[provider.name] = runtime
        self.statuses[provider.name] = self._initial_status(runtime)
        return runtime

    def _refresh_interval(self, provider_name: str) -> float:
        return {
            "alpha_vantage": self.settings.alpha_vantage_refresh_interval_seconds,
            "finnhub": self.settings.finnhub_refresh_interval_seconds,
            "trading_economics": self.settings.trading_economics_refresh_interval_seconds,
            "gdelt": self.settings.gdelt_refresh_interval_seconds,
            "investing_rss": self.settings.investing_rss_refresh_interval_seconds,
            "official_rss": self.settings.official_rss_refresh_interval_seconds,
        }.get(provider_name, self.settings.news_global_refresh_interval_seconds)

    async def collect(
        self,
        request: NewsQuery,
        *,
        provider_names: list[str] | None = None,
        force: bool = False,
    ) -> ProviderCollectionResult:
        runtimes = self._ordered_news(request.categories, provider_names)
        results = await asyncio.gather(
            *(self._fetch_news(runtime, request, force=force) for runtime in runtimes), return_exceptions=False
        )
        collection = self._merge_results(results)
        self.last_news_result = collection
        return collection

    async def collect_calendar(
        self,
        request: CalendarQuery,
        *,
        provider_names: list[str] | None = None,
        force: bool = False,
    ) -> ProviderCollectionResult:
        runtimes = [
            runtime
            for runtime in sorted(self.runtimes.values(), key=lambda item: item.priority)
            if runtime.calendar_adapter is not None and (not provider_names or runtime.name in provider_names)
        ]
        results = await asyncio.gather(
            *(self._fetch_calendar(runtime, request, force=force) for runtime in runtimes), return_exceptions=False
        )
        collection = self._merge_results(results)
        self.last_calendar_result = collection
        return collection

    def _ordered_news(self, categories: list[str] | None, provider_names: list[str] | None) -> list[ProviderRuntime]:
        macro = bool(
            {item.upper() for item in categories or []}
            & {"GEOPOLITICS", "REGULATION", "ENERGY", "CENTRAL_BANK", "INTEREST_RATE"}
        )
        preferred = (
            ["investing_rss", "gdelt", "official_rss", "file", "alpha_vantage", "finnhub"]
            if macro
            else self.settings.news_provider_priority
        )
        order = {name: index for index, name in enumerate(preferred, start=1)}
        return sorted(
            [
                runtime
                for runtime in self.runtimes.values()
                if runtime.news_adapter is not None and (not provider_names or runtime.name in provider_names)
            ],
            key=lambda item: (order.get(item.name, 999), item.priority),
        )

    async def _fetch_news(
        self, runtime: ProviderRuntime, request: NewsQuery, *, force: bool
    ) -> tuple[str, list[tuple[str, dict]], str]:
        provider = runtime.provider
        if not provider.enabled or not provider.configured:
            self.statuses[runtime.name] = self._initial_status(runtime)
            return runtime.name, [], "unconfigured" if not provider.configured else "disabled"
        previous = self.statuses[runtime.name]
        if (
            not force
            and previous.last_fetch_at
            and (datetime.now(UTC) - previous.last_fetch_at).total_seconds() < runtime.refresh_interval_seconds
        ):
            cached = self.last_good_news.get(runtime.name, [])
            return runtime.name, [(runtime.name, item) for item in cached], "cached"
        started = perf_counter()
        now = datetime.now(UTC)
        self.statuses[runtime.name] = self.statuses[runtime.name].model_copy(update={"last_fetch_at": now})
        try:
            runtime.breaker.allow_request(force=force)
            news_provider = cast(NewsProvider, provider)
            adapter = cast(NewsProviderAdapter, runtime.news_adapter)
            async with self._semaphore, runtime.limiter:
                rows = await news_provider.fetch_news(
                    symbols=request.symbols,
                    currencies=request.currencies,
                    categories=request.categories,
                    published_after=request.published_after,
                    limit=request.limit,
                )
            normalized = [
                adapter.normalize(item, known_symbols=self.known_symbols()) for item in rows if isinstance(item, dict)
            ]
            runtime.breaker.success()
            self.last_good_news[runtime.name] = normalized
            self._success(runtime, len(normalized), started)
            return runtime.name, [(runtime.name, item) for item in normalized], "success"
        except ProviderCircuitOpenError as exc:
            return self._failure(runtime, exc, started, self.last_good_news, circuit_failure=False)
        except ProviderRateLimitError as exc:
            cooldown = exc.retry_after_seconds or (
                self.settings.gdelt_backoff_initial_seconds
                if runtime.name == "gdelt"
                else self.settings.news_provider_cooldown_seconds
            )
            runtime.breaker.open_for(cooldown)
            return self._failure(runtime, exc, started, self.last_good_news)
        except (ProviderFetchError, OSError, TimeoutError) as exc:
            runtime.breaker.failure()
            return self._failure(runtime, exc, started, self.last_good_news)

    async def _fetch_calendar(
        self, runtime: ProviderRuntime, request: CalendarQuery, *, force: bool
    ) -> tuple[str, list[tuple[str, dict]], str]:
        provider = runtime.provider
        if not provider.enabled or not provider.configured:
            self.statuses[runtime.name] = self._initial_status(runtime)
            return runtime.name, [], "unconfigured" if not provider.configured else "disabled"
        previous = self.statuses[runtime.name]
        if (
            not force
            and previous.last_fetch_at
            and (datetime.now(UTC) - previous.last_fetch_at).total_seconds() < runtime.refresh_interval_seconds
        ):
            cached = self.last_good_calendar.get(runtime.name, [])
            return runtime.name, [(runtime.name, item) for item in cached], "cached"
        started = perf_counter()
        now = datetime.now(UTC)
        self.statuses[runtime.name] = self.statuses[runtime.name].model_copy(update={"last_fetch_at": now})
        try:
            runtime.breaker.allow_request(force=force)
            calendar_provider = cast(EconomicCalendarProvider, provider)
            adapter = cast(CalendarProviderAdapter, runtime.calendar_adapter)
            async with self._semaphore, runtime.limiter:
                rows = await calendar_provider.fetch_calendar(
                    currencies=request.currencies,
                    countries=request.countries,
                    start_time=request.start_time,
                    end_time=request.end_time,
                    minimum_impact=request.minimum_impact,
                    limit=request.limit,
                )
            normalized = [
                adapter.normalize(item, known_symbols=self.known_symbols()) for item in rows if isinstance(item, dict)
            ]
            runtime.breaker.success()
            self.last_good_calendar[runtime.name] = normalized
            self._success(runtime, len(normalized), started)
            return runtime.name, [(runtime.name, item) for item in normalized], "success"
        except ProviderCircuitOpenError as exc:
            return self._failure(runtime, exc, started, self.last_good_calendar, circuit_failure=False)
        except (ProviderFetchError, OSError, TimeoutError) as exc:
            runtime.breaker.failure()
            return self._failure(runtime, exc, started, self.last_good_calendar)

    def _success(self, runtime: ProviderRuntime, count: int, started: float) -> None:
        previous = self.statuses[runtime.name]
        capabilities = dict(getattr(runtime.provider, "capabilities", {}))
        quota = (
            QuotaStatus.NOT_APPLICABLE
            if runtime.name in {"gdelt", "investing_rss", "official_rss", "file", "file_calendar"}
            else QuotaStatus.UNKNOWN
        )
        feed_count = getattr(runtime.provider, "feed_count", 0)
        healthy_feed_count = getattr(runtime.provider, "healthy_feed_count", 0)
        failed_feed_count = getattr(runtime.provider, "failed_feed_count", 0)
        provider_degraded = bool(feed_count and failed_feed_count)
        provider_rate_limited = bool(getattr(runtime.provider, "rate_limited", False))
        raw_circuit_state = getattr(runtime.provider, "circuit_state", CircuitState.CLOSED)
        provider_circuit_state = (
            raw_circuit_state
            if isinstance(raw_circuit_state, CircuitState)
            else CircuitState(str(raw_circuit_state).upper())
        )
        provider_cooldown_until = getattr(runtime.provider, "cooldown_until", None)
        provider_failure_count = getattr(runtime.provider, "failure_count", 0)
        self.statuses[runtime.name] = previous.model_copy(
            update={
                "healthy": not provider_degraded or healthy_feed_count > 0,
                "status": "degraded" if provider_degraded else "healthy",
                "last_success_at": datetime.now(UTC),
                "last_error": getattr(runtime.provider, "last_error", None),
                "article_count": count,
                "latency_ms": (perf_counter() - started) * 1000,
                "rate_limited": provider_rate_limited,
                "quota_status": QuotaStatus.EXHAUSTED if provider_rate_limited else quota,
                "failure_count": provider_failure_count,
                "cooldown_until": provider_cooldown_until,
                "circuit_state": provider_circuit_state,
                "authentication_failed": False,
                "entitlement_error": False,
                "stale": bool(feed_count and healthy_feed_count == 0),
                "last_status_code": getattr(runtime.provider, "last_status_code", 200),
                "requests_sent": getattr(runtime.provider, "requests_sent", previous.requests_sent),
                "requests_skipped_from_cache": getattr(
                    runtime.provider, "requests_skipped_from_cache", previous.requests_skipped_from_cache
                ),
                "rate_limit_count": getattr(runtime.provider, "rate_limit_count", previous.rate_limit_count),
                "last_retry_after_seconds": getattr(runtime.provider, "last_retry_after_seconds", None),
                "last_known_good_available": getattr(runtime.provider, "last_known_good_available", False),
                "capabilities": sorted(key for key, value in capabilities.items() if value is True),
                "capability_details": capabilities,
                "feed_count": feed_count,
                "healthy_feed_count": healthy_feed_count,
                "failed_feed_count": failed_feed_count,
            }
        )

    def _failure(
        self,
        runtime: ProviderRuntime,
        exc: Exception,
        started: float,
        last_good: dict[str, list[dict[str, Any]]],
        *,
        circuit_failure: bool = True,
    ) -> tuple[str, list[tuple[str, dict]], str]:
        del circuit_failure
        rate_limited = isinstance(exc, ProviderRateLimitError)
        authentication = isinstance(exc, ProviderAuthenticationError)
        entitlement = isinstance(exc, ProviderEntitlementError)
        circuit_open = isinstance(exc, ProviderCircuitOpenError)
        fallback = last_good.get(runtime.name, [])
        state = (
            "circuit_open"
            if circuit_open
            else "rate_limited"
            if rate_limited
            else "authentication_failed"
            if authentication
            else "entitlement_error"
            if entitlement
            else "error"
        )
        self.statuses[runtime.name] = self.statuses[runtime.name].model_copy(
            update={
                "healthy": False,
                "status": state,
                "last_error": str(exc),
                "article_count": len(fallback),
                "latency_ms": (perf_counter() - started) * 1000,
                "rate_limited": rate_limited,
                "quota_status": QuotaStatus.EXHAUSTED if rate_limited else QuotaStatus.UNKNOWN,
                "failure_count": runtime.breaker.failure_count,
                "cooldown_until": runtime.breaker.cooldown_until,
                "circuit_state": runtime.breaker.state,
                "authentication_failed": authentication,
                "entitlement_error": entitlement,
                "stale": True,
                "last_status_code": getattr(exc, "status_code", getattr(runtime.provider, "last_status_code", None)),
                "requests_sent": getattr(runtime.provider, "requests_sent", 0),
                "requests_skipped_from_cache": getattr(runtime.provider, "requests_skipped_from_cache", 0),
                "rate_limit_count": getattr(runtime.provider, "rate_limit_count", 0),
                "last_retry_after_seconds": getattr(
                    exc, "retry_after_seconds", getattr(runtime.provider, "last_retry_after_seconds", None)
                ),
                "last_known_good_available": getattr(runtime.provider, "last_known_good_available", bool(fallback)),
            }
        )
        logger.warning(
            "News provider fetch failed",
            extra={"event": "news.provider_failed", "component": runtime.name, "error_type": type(exc).__name__},
        )
        result_state = "rate_limited" if rate_limited else "failed"
        return runtime.name, [(runtime.name, item) for item in fallback], result_state

    @staticmethod
    def _merge_results(results: list[tuple[str, list[tuple[str, dict]], str]]) -> ProviderCollectionResult:
        attempted = [name for name, _, state in results if state not in {"unconfigured", "disabled"}]
        succeeded = [name for name, _, state in results if state == "success"]
        cached = [name for name, _, state in results if state == "cached"]
        failed = [name for name, _, state in results if state == "failed"]
        rate_limited = [name for name, _, state in results if state == "rate_limited"]
        unconfigured = [name for name, _, state in results if state == "unconfigured"]
        return ProviderCollectionResult(
            items=[row for _, rows, _ in results for row in rows],
            providers_attempted=attempted,
            providers_succeeded=succeeded,
            providers_failed=failed,
            providers_rate_limited=rate_limited,
            providers_unconfigured=unconfigured,
            partial=bool(succeeded and (failed or rate_limited)),
            stale=not (succeeded or cached),
            collected_at=datetime.now(UTC),
        )

    def _initial_status(self, runtime: ProviderRuntime) -> ProviderStatus:
        provider = runtime.provider
        configuration_error = getattr(provider, "configuration_error", None)
        state = (
            "unconfigured"
            if not provider.enabled and runtime.name in {"alpha_vantage", "finnhub", "trading_economics"}
            else "disabled"
            if not provider.enabled
            else "misconfigured"
            if not provider.configured and runtime.name in {"alpha_vantage", "finnhub", "trading_economics"}
            else "unconfigured"
            if not provider.configured
            else "error"
            if configuration_error
            else "unknown"
        )
        capabilities = dict(getattr(provider, "capabilities", {}))
        quota = (
            QuotaStatus.NOT_APPLICABLE
            if runtime.name in {"gdelt", "investing_rss", "official_rss", "file", "file_calendar"}
            else QuotaStatus.UNKNOWN
        )
        return ProviderStatus(
            name=runtime.name,
            enabled=provider.enabled,
            configured=provider.configured,
            healthy=False,
            status=state,
            capabilities=sorted(key for key, value in capabilities.items() if value is True),
            capability_details=capabilities,
            priority=runtime.priority,
            last_error=configuration_error,
            quota_status=quota,
            circuit_state=runtime.breaker.state,
            feed_count=getattr(provider, "feed_count", 0),
            healthy_feed_count=getattr(provider, "healthy_feed_count", 0),
            failed_feed_count=getattr(provider, "failed_feed_count", 0),
            stale=True,
        )
