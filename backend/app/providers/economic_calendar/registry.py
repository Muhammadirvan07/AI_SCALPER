from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from time import monotonic
from typing import cast

from app.core.config import Settings
from app.providers.news.base import ProviderFetchError, ProviderRateLimitError
from app.schemas.economic_calendar import EconomicCalendarSourceStatus

from .base import EconomicCalendarCollection, EconomicCalendarProvider
from .bea import BeaCalendarProvider
from .bls import BlsCalendarProvider
from .ecb import EcbCalendarProvider
from .federal_reserve import FederalReserveCalendarProvider
from .file_provider import FileEconomicCalendarProvider

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class _Runtime:
    provider: EconomicCalendarProvider
    status: EconomicCalendarSourceStatus
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    last_known_good: list[dict] = field(default_factory=list)


class EconomicCalendarProviderRegistry:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        providers: list[EconomicCalendarProvider] = [
            cast(EconomicCalendarProvider, BeaCalendarProvider(settings)),
            cast(EconomicCalendarProvider, FederalReserveCalendarProvider(settings)),
            cast(EconomicCalendarProvider, EcbCalendarProvider(settings)),
            cast(EconomicCalendarProvider, BlsCalendarProvider(settings)),
            cast(EconomicCalendarProvider, FileEconomicCalendarProvider(settings)),
        ]
        self._runtimes: dict[str, _Runtime] = {}
        for provider in providers:
            status = "disabled" if not provider.enabled else "unconfigured" if not provider.configured else "unknown"
            self._runtimes[provider.name] = _Runtime(
                provider=provider,
                status=EconomicCalendarSourceStatus(
                    name=provider.name,
                    display_name=provider.display_name,
                    enabled=provider.enabled,
                    configured=provider.configured,
                    healthy=False,
                    status=status,
                    official_domain=provider.official_domain,
                    capabilities=provider.capabilities,
                    verified_at=datetime(2026, 7, 29, tzinfo=UTC) if provider.official_domain else None,
                ),
            )
        self.last_collection = EconomicCalendarCollection()

    @property
    def configured(self) -> bool:
        return any(runtime.provider.enabled and runtime.provider.configured for runtime in self._runtimes.values())

    @property
    def provider_names(self) -> set[str]:
        return set(self._runtimes)

    def statuses(self) -> list[EconomicCalendarSourceStatus]:
        return [runtime.status.model_copy(deep=True) for runtime in self._runtimes.values()]

    def status(self, name: str) -> EconomicCalendarSourceStatus | None:
        runtime = self._runtimes.get(name.lower())
        return runtime.status.model_copy(deep=True) if runtime else None

    async def collect(
        self,
        *,
        start_time: datetime,
        end_time: datetime,
        currencies: list[str] | None = None,
        provider_names: list[str] | None = None,
        force: bool = False,
    ) -> EconomicCalendarCollection:
        result = EconomicCalendarCollection()
        selected = {item.lower() for item in provider_names or []}
        runtimes = [runtime for name, runtime in self._runtimes.items() if not selected or name in selected]
        semaphore = asyncio.Semaphore(self.settings.economic_calendar_max_parallel_requests)

        async def fetch(runtime: _Runtime) -> tuple[str, list[dict], str]:
            name = runtime.provider.name
            if not runtime.provider.enabled or not runtime.provider.configured:
                return name, [], "unconfigured"
            cooldown = runtime.status.cooldown_until
            if cooldown and datetime.now(UTC) < cooldown and not force:
                return name, list(runtime.last_known_good), "rate_limited" if runtime.status.rate_limited else "failed"
            async with semaphore, runtime.lock:
                runtime.status.last_fetch_at = datetime.now(UTC)
                started = monotonic()
                try:
                    async with asyncio.timeout(self.settings.economic_calendar_request_timeout_seconds + 1):
                        rows = await runtime.provider.fetch_schedule(
                            start_time=start_time,
                            end_time=end_time,
                            currencies=currencies,
                        )
                    runtime.last_known_good = [dict(item) for item in rows]
                    runtime.status = runtime.status.model_copy(
                        update={
                            "healthy": True,
                            "status": "healthy",
                            "last_success_at": datetime.now(UTC),
                            "last_error": None,
                            "last_status_code": 200,
                            "latency_ms": (monotonic() - started) * 1000,
                            "event_count": len(rows),
                            "failure_count": 0,
                            "rate_limited": False,
                            "cooldown_until": None,
                            "next_retry_at": None,
                            "stale": False,
                            "last_known_good_available": bool(rows),
                        }
                    )
                    return name, rows, "succeeded"
                except ProviderRateLimitError as exc:
                    retry_after = max(
                        self.settings.economic_calendar_provider_cooldown_seconds,
                        exc.retry_after_seconds or 0,
                    )
                    until = datetime.now(UTC) + timedelta(seconds=retry_after)
                    runtime.status = runtime.status.model_copy(
                        update={
                            "healthy": False,
                            "status": "rate_limited",
                            "last_error": str(exc),
                            "last_status_code": 429,
                            "latency_ms": (monotonic() - started) * 1000,
                            "failure_count": runtime.status.failure_count + 1,
                            "rate_limited": True,
                            "cooldown_until": until,
                            "next_retry_at": until,
                            "stale": True,
                            "last_known_good_available": bool(runtime.last_known_good),
                        }
                    )
                    logger.warning(
                        "Economic calendar source rate limited",
                        extra={"event": "calendar.source_rate_limited", "component": name},
                    )
                    return name, list(runtime.last_known_good), "rate_limited"
                except (ProviderFetchError, TimeoutError, OSError) as exc:
                    failures = runtime.status.failure_count + 1
                    cooldown = None
                    if failures >= self.settings.economic_calendar_provider_failure_threshold:
                        cooldown = datetime.now(UTC) + timedelta(
                            seconds=min(
                                self.settings.economic_calendar_provider_cooldown_seconds * 2 ** (failures - 1),
                                3600,
                            )
                        )
                    status_code = getattr(exc, "status_code", None)
                    runtime.status = runtime.status.model_copy(
                        update={
                            "healthy": False,
                            "status": "degraded" if runtime.last_known_good else "error",
                            "last_error": f"{type(exc).__name__}: {exc}",
                            "last_status_code": status_code,
                            "latency_ms": (monotonic() - started) * 1000,
                            "failure_count": failures,
                            "cooldown_until": cooldown,
                            "next_retry_at": cooldown,
                            "stale": True,
                            "last_known_good_available": bool(runtime.last_known_good),
                        }
                    )
                    logger.warning(
                        "Economic calendar source failed",
                        extra={
                            "event": "calendar.source_failed",
                            "component": name,
                            "error_type": type(exc).__name__,
                        },
                    )
                    return name, list(runtime.last_known_good), "failed"

        outcomes = await asyncio.gather(*(fetch(runtime) for runtime in runtimes))
        for name, rows, outcome in outcomes:
            if outcome != "unconfigured":
                result.providers_attempted.append(name)
            if outcome == "succeeded":
                result.providers_succeeded.append(name)
            elif outcome == "rate_limited":
                result.providers_rate_limited.append(name)
            elif outcome == "failed":
                result.providers_failed.append(name)
            else:
                result.providers_unconfigured.append(name)
            result.items.extend((name, row) for row in rows)
        result.partial = bool(result.items) and bool(result.providers_failed or result.providers_rate_limited)
        result.collected_at = datetime.now(UTC)
        self.last_collection = result
        return result

    async def fetch_release(self, provider_name: str, event: dict) -> dict | None:
        runtime = self._runtimes.get(provider_name)
        if runtime is None or not runtime.provider.enabled or not runtime.provider.configured:
            return None
        if runtime.status.cooldown_until and datetime.now(UTC) < runtime.status.cooldown_until:
            return None
        async with runtime.lock:
            checked_at = datetime.now(UTC)
            runtime.status.last_fetch_at = checked_at
            started = monotonic()
            try:
                async with asyncio.timeout(self.settings.economic_calendar_request_timeout_seconds + 1):
                    release = await runtime.provider.fetch_release(event=event)
                runtime.status = runtime.status.model_copy(
                    update={
                        "healthy": True,
                        "status": "healthy",
                        "last_success_at": datetime.now(UTC),
                        "last_error": None,
                        "last_status_code": 200,
                        "latency_ms": (monotonic() - started) * 1000,
                        "failure_count": 0,
                        "rate_limited": False,
                        "cooldown_until": None,
                        "next_retry_at": None,
                        "stale": False,
                    }
                )
                return release
            except ProviderRateLimitError as exc:
                retry_after = max(
                    self.settings.economic_calendar_provider_cooldown_seconds,
                    exc.retry_after_seconds or 0,
                )
                until = datetime.now(UTC) + timedelta(seconds=retry_after)
                runtime.status = runtime.status.model_copy(
                    update={
                        "healthy": False,
                        "status": "rate_limited",
                        "rate_limited": True,
                        "last_error": str(exc),
                        "last_status_code": 429,
                        "latency_ms": (monotonic() - started) * 1000,
                        "failure_count": runtime.status.failure_count + 1,
                        "cooldown_until": until,
                        "next_retry_at": until,
                        "stale": True,
                    }
                )
            except (ProviderFetchError, TimeoutError, OSError) as exc:
                failures = runtime.status.failure_count + 1
                cooldown = None
                if failures >= self.settings.economic_calendar_provider_failure_threshold:
                    cooldown = datetime.now(UTC) + timedelta(
                        seconds=min(
                            self.settings.economic_calendar_provider_cooldown_seconds * 2 ** (failures - 1),
                            3600,
                        )
                    )
                runtime.status = runtime.status.model_copy(
                    update={
                        "healthy": False,
                        "status": "degraded" if runtime.last_known_good else "error",
                        "last_error": f"{type(exc).__name__}: {exc}",
                        "last_status_code": getattr(exc, "status_code", None),
                        "latency_ms": (monotonic() - started) * 1000,
                        "failure_count": failures,
                        "cooldown_until": cooldown,
                        "next_retry_at": cooldown,
                        "stale": True,
                    }
                )
                logger.warning(
                    "Economic release check failed",
                    extra={
                        "event": "calendar.release_check_failed",
                        "component": provider_name,
                        "error_type": type(exc).__name__,
                    },
                )
        return None
