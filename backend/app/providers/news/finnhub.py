from __future__ import annotations

from datetime import UTC, datetime

import httpx

from app.core.config import Settings

from .base import ProviderAuthenticationError, ProviderEntitlementError, ProviderFetchError, ProviderRateLimitError
from .http_client import SafeProviderHttpClient


class FinnhubNewsProvider:
    name = "finnhub"

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.enabled = settings.news_enabled and settings.news_external_requests_enabled and settings.finnhub_enabled
        self.configured = bool(settings.finnhub_api_key.strip())
        self.capabilities: dict[str, bool | None] = {
            "general_news": None,
            "company_news": None,
            "forex_news": None,
            "crypto_news": None,
            "economic_calendar": None if settings.finnhub_economic_calendar_enabled else False,
        }
        self.client = SafeProviderHttpClient(
            base_url=settings.finnhub_base_url,
            allowed_hosts={"finnhub.io", "api.finnhub.io"},
            timeout_seconds=settings.finnhub_request_timeout_seconds,
            max_response_bytes=settings.news_max_response_bytes,
            transport=transport,
        )

    @staticmethod
    def _category(categories: list[str] | None) -> str:
        values = {item.upper() for item in categories or []}
        return "forex" if "FOREX" in values else "crypto" if "CRYPTO" in values else "general"

    @staticmethod
    def _provider_error(payload: object) -> None:
        if not isinstance(payload, dict) or not payload.get("error"):
            return
        message = str(payload["error"]).lower()
        if "api key" in message or "authentication" in message:
            raise ProviderAuthenticationError("Finnhub API key was rejected")
        if "limit" in message or "quota" in message:
            raise ProviderRateLimitError("Finnhub rate limit reached")
        if "permission" in message or "access" in message or "premium" in message:
            raise ProviderEntitlementError("Finnhub endpoint is unavailable for the configured entitlement")
        raise ProviderFetchError("Finnhub returned an error response")

    async def fetch_news(
        self,
        *,
        symbols: list[str] | None = None,
        currencies: list[str] | None = None,
        categories: list[str] | None = None,
        published_after: datetime | None = None,
        limit: int = 50,
    ) -> list[dict]:
        del symbols, currencies
        if not self.enabled or not self.configured:
            return []
        category = self._category(categories)
        payload = await self.client.get_json(
            "/news", params={"category": category, "minId": 0, "token": self.settings.finnhub_api_key}
        )
        self._provider_error(payload)
        if not isinstance(payload, list):
            raise ProviderFetchError("Finnhub news response must be an array")
        self.capabilities[f"{category}_news"] = True
        rows = [item for item in payload if isinstance(item, dict)]
        if published_after:
            cutoff = int(published_after.astimezone(UTC).timestamp())
            rows = [
                item for item in rows if not isinstance(item.get("datetime"), int | float) or item["datetime"] >= cutoff
            ]
        return rows[: min(limit, self.settings.finnhub_max_articles)]

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
        del currencies, countries, minimum_impact
        if not self.enabled or not self.configured or not self.settings.finnhub_economic_calendar_enabled:
            return []
        start = (start_time or datetime.now(UTC)).date().isoformat()
        end = (end_time or datetime.now(UTC)).date().isoformat()
        payload = await self.client.get_json(
            "/calendar/economic", params={"from": start, "to": end, "token": self.settings.finnhub_api_key}
        )
        self._provider_error(payload)
        if not isinstance(payload, dict) or not isinstance(payload.get("economicCalendar"), list):
            self.capabilities["economic_calendar"] = False
            raise ProviderEntitlementError("Finnhub economic calendar is unavailable for this entitlement")
        self.capabilities["economic_calendar"] = True
        return [item for item in payload["economicCalendar"][:limit] if isinstance(item, dict)]

    async def health_check(self) -> dict:
        return {"configured": self.configured, "enabled": self.enabled, "capabilities": self.capabilities}
