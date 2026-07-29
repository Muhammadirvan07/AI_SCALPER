from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol


class ProviderFetchError(RuntimeError):
    """A configured provider could not return a safe, valid response."""


class ProviderRateLimitError(ProviderFetchError):
    """The provider explicitly rate limited the backend."""

    def __init__(self, message: str, *, retry_after_seconds: float | None = None, status_code: int = 429) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds
        self.status_code = status_code


class ProviderAuthenticationError(ProviderFetchError):
    """Provider credentials were rejected."""


class ProviderEntitlementError(ProviderFetchError):
    """Credentials are valid but the requested capability is unavailable."""


class ProviderCircuitOpenError(ProviderFetchError):
    """The provider circuit breaker is cooling down."""


@dataclass(slots=True)
class NewsQuery:
    symbols: list[str] | None = None
    currencies: list[str] | None = None
    categories: list[str] | None = None
    published_after: datetime | None = None
    limit: int = 50


@dataclass(slots=True)
class CalendarQuery:
    currencies: list[str] | None = None
    countries: list[str] | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    minimum_impact: str | None = None
    limit: int = 100


@dataclass(slots=True)
class ProviderCollectionResult:
    items: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    providers_attempted: list[str] = field(default_factory=list)
    providers_succeeded: list[str] = field(default_factory=list)
    providers_failed: list[str] = field(default_factory=list)
    providers_rate_limited: list[str] = field(default_factory=list)
    providers_unconfigured: list[str] = field(default_factory=list)
    partial: bool = False
    stale: bool = True
    collected_at: datetime | None = None


class NewsProvider(Protocol):
    name: str
    enabled: bool
    configured: bool

    @property
    def capabilities(self) -> Mapping[str, bool | None]: ...

    async def fetch_news(
        self,
        *,
        symbols: list[str] | None = None,
        currencies: list[str] | None = None,
        categories: list[str] | None = None,
        published_after: datetime | None = None,
        limit: int = 50,
    ) -> list[dict]: ...

    async def health_check(self) -> dict: ...


class EconomicCalendarProvider(Protocol):
    name: str
    enabled: bool
    configured: bool

    @property
    def capabilities(self) -> Mapping[str, bool | None]: ...

    async def fetch_calendar(
        self,
        *,
        currencies: list[str] | None = None,
        countries: list[str] | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        minimum_impact: str | None = None,
        limit: int = 100,
    ) -> list[dict]: ...

    async def health_check(self) -> dict: ...


class NewsProviderAdapter(Protocol):
    def normalize(self, raw: dict, *, known_symbols: list[str]) -> dict: ...


class CalendarProviderAdapter(Protocol):
    def normalize(self, raw: dict, *, known_symbols: list[str]) -> dict: ...
