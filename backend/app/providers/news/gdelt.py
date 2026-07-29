from __future__ import annotations

import asyncio
import hashlib
import json
import random
from datetime import UTC, datetime, timedelta
from typing import ClassVar

import httpx

from app.core.config import Settings

from .base import ProviderFetchError, ProviderRateLimitError
from .http_client import SafeProviderHttpClient

ALLOWED_TOPICS = frozenset(
    {
        "central_bank",
        "interest_rate",
        "inflation",
        "employment",
        "gdp",
        "recession",
        "currency",
        "forex",
        "gold",
        "silver",
        "oil",
        "energy",
        "bitcoin",
        "cryptocurrency",
        "geopolitics",
        "sanctions",
        "war",
        "regulation",
        "trade",
    }
)
TOPIC_TERMS = {
    "central_bank": '"central bank"',
    "interest_rate": '"interest rate"',
    "inflation": "inflation",
    "employment": "employment",
    "gdp": '"gross domestic product"',
    "recession": "recession",
    "currency": "currency",
    "forex": "forex",
    "gold": "gold",
    "silver": "silver",
    "oil": "oil",
    "energy": "energy",
    "bitcoin": "bitcoin",
    "cryptocurrency": "cryptocurrency",
    "geopolitics": "geopolitics",
    "sanctions": "sanctions",
    "war": "war",
    "regulation": "regulation",
    "trade": '"trade dispute"',
}
CATEGORY_TOPICS = {
    "CENTRAL_BANK": "central_bank",
    "INTEREST_RATE": "interest_rate",
    "INFLATION": "inflation",
    "EMPLOYMENT": "employment",
    "GDP": "gdp",
    "FOREX": "forex",
    "GOLD": "gold",
    "SILVER": "silver",
    "CRYPTO": "cryptocurrency",
    "GEOPOLITICS": "geopolitics",
    "REGULATION": "regulation",
    "ENERGY": "energy",
}


class GdeltNewsProvider:
    name = "gdelt"
    CAPABILITIES: ClassVar[dict[str, bool | None]] = {
        "macro_news": True,
        "geopolitical_news": True,
        "multilingual_news": True,
        "breaking_news": True,
    }

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.capabilities: dict[str, bool | None] = dict(self.CAPABILITIES)
        self.enabled = settings.news_enabled and settings.news_external_requests_enabled and settings.gdelt_enabled
        self.configured = self.enabled
        self._query_cache: dict[str, tuple[datetime, list[dict]]] = {}
        self._query_locks: dict[str, asyncio.Lock] = {}
        self._last_request_at: datetime | None = None
        self._cooldown_until: datetime | None = None
        self.requests_sent = 0
        self.requests_skipped_from_cache = 0
        self.rate_limit_count = 0
        self.last_retry_after_seconds: float | None = None
        self.last_status_code: int | None = None
        self.client = SafeProviderHttpClient(
            base_url=settings.gdelt_base_url,
            allowed_hosts={"api.gdeltproject.org"},
            timeout_seconds=settings.gdelt_request_timeout_seconds,
            max_response_bytes=settings.news_max_response_bytes,
            transport=transport,
        )

    @staticmethod
    def _topics(categories: list[str] | None) -> list[str]:
        requested = [CATEGORY_TOPICS[item.upper()] for item in categories or [] if item.upper() in CATEGORY_TOPICS]
        return requested or [
            "central_bank",
            "interest_rate",
            "inflation",
            "geopolitics",
            "sanctions",
            "energy",
            "bitcoin",
        ]

    async def fetch_news(
        self,
        *,
        symbols: list[str] | None = None,
        currencies: list[str] | None = None,
        categories: list[str] | None = None,
        published_after: datetime | None = None,
        limit: int = 50,
    ) -> list[dict]:
        del symbols, currencies, published_after
        if not self.enabled:
            return []
        topics = [item for item in self._topics(categories) if item in ALLOWED_TOPICS]
        query = "(" + " OR ".join(TOPIC_TERMS[item] for item in topics) + ")"
        if len(query) > 400:
            raise ProviderFetchError("GDELT trusted query exceeds the configured length limit")
        params = {
            "query": query,
            "mode": "ArtList",
            "format": "json",
            "sort": "HybridRel",
            "maxrecords": min(limit, self.settings.gdelt_max_articles, 250),
            "timespan": f"{self.settings.gdelt_default_timespan_hours}h",
        }
        signature = self._signature(params)
        cached = self._cached(signature)
        if cached is not None:
            self.requests_skipped_from_cache += 1
            return cached[:limit]
        lock = self._query_locks.setdefault(signature, asyncio.Lock())
        async with lock:
            cached = self._cached(signature)
            if cached is not None:
                self.requests_skipped_from_cache += 1
                return cached[:limit]
            now = datetime.now(UTC)
            if self._cooldown_until and now < self._cooldown_until:
                fallback = self._last_known_good(signature)
                if fallback is not None:
                    self.requests_skipped_from_cache += 1
                    return fallback[:limit]
                raise ProviderRateLimitError(
                    "GDELT provider is cooling down after a rate limit",
                    retry_after_seconds=(self._cooldown_until - now).total_seconds(),
                )
            if self._last_request_at:
                elapsed = (now - self._last_request_at).total_seconds()
                if elapsed < self.settings.gdelt_min_request_interval_seconds:
                    fallback = self._last_known_good(signature)
                    if fallback is not None:
                        self.requests_skipped_from_cache += 1
                        return fallback[:limit]
                    await asyncio.sleep(self.settings.gdelt_min_request_interval_seconds - elapsed)
            self._last_request_at = datetime.now(UTC)
            self.requests_sent += 1
            try:
                payload = await self.client.get_json("/api/v2/doc/doc", params=params)
                self.last_status_code = 200
            except ProviderRateLimitError as exc:
                self.last_status_code = 429
                self.rate_limit_count += 1
                exponential = self.settings.gdelt_backoff_initial_seconds * (
                    self.settings.gdelt_backoff_multiplier ** max(0, self.rate_limit_count - 1)
                )
                cooldown = min(self.settings.gdelt_backoff_max_seconds, exponential)
                if exc.retry_after_seconds is not None:
                    cooldown = max(cooldown, exc.retry_after_seconds)
                cooldown = min(
                    self.settings.gdelt_backoff_max_seconds,
                    cooldown + random.uniform(0, self.settings.gdelt_jitter_seconds),
                )
                self.last_retry_after_seconds = round(cooldown, 3)
                self._cooldown_until = datetime.now(UTC) + timedelta(seconds=cooldown)
                raise ProviderRateLimitError(
                    "GDELT rate limited the request",
                    retry_after_seconds=cooldown,
                ) from exc
        if isinstance(payload, dict) and str(payload.get("error") or ""):
            message = str(payload["error"]).lower()
            if "rate" in message or "too many" in message:
                raise ProviderRateLimitError("GDELT rate limited the request")
            raise ProviderFetchError("GDELT returned an error response")
        if not isinstance(payload, dict) or not isinstance(payload.get("articles"), list):
            raise ProviderFetchError("GDELT response does not contain an articles array")
        rows = []
        for item in payload["articles"][:limit]:
            if isinstance(item, dict):
                language = str(item.get("language") or "").lower()
                language_alias = {"english": "en", "indonesian": "id", "japanese": "ja"}.get(language, language)
                if language_alias and language_alias not in self.settings.gdelt_languages:
                    continue
                item = dict(item)
                item["_query_topic"] = topics[0] if len(topics) == 1 else "general"
                rows.append(item)
        self._query_cache[signature] = (datetime.now(UTC), list(rows))
        self._cooldown_until = None
        self.rate_limit_count = 0
        self.last_retry_after_seconds = None
        return rows

    @staticmethod
    def _signature(params: dict[str, object]) -> str:
        normalized = {key: params[key] for key in ("query", "timespan", "maxrecords") if key in params}
        return hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def _cached(self, signature: str) -> list[dict] | None:
        cached = self._query_cache.get(signature)
        if cached is None:
            return None
        created_at, rows = cached
        if (datetime.now(UTC) - created_at).total_seconds() > self.settings.gdelt_refresh_interval_seconds:
            return None
        return list(rows)

    def _last_known_good(self, signature: str) -> list[dict] | None:
        cached = self._query_cache.get(signature)
        return list(cached[1]) if cached else None

    @property
    def last_known_good_available(self) -> bool:
        return bool(self._query_cache)

    async def health_check(self) -> dict:
        return {
            "configured": self.configured,
            "enabled": self.enabled,
            "capabilities": self.capabilities,
            "requests_sent": self.requests_sent,
            "requests_skipped_from_cache": self.requests_skipped_from_cache,
            "rate_limit_count": self.rate_limit_count,
            "last_retry_after_seconds": self.last_retry_after_seconds,
            "last_status_code": self.last_status_code,
            "cooldown_until": self._cooldown_until,
            "last_known_good_available": self.last_known_good_available,
        }
