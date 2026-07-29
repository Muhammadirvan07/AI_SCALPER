from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import ClassVar

import httpx

from app.core.config import Settings

from .base import ProviderAuthenticationError, ProviderFetchError, ProviderRateLimitError
from .http_client import SafeProviderHttpClient


class TradingEconomicsCalendarProvider:
    name = "trading_economics"
    CAPABILITIES: ClassVar[dict[str, bool | None]] = {
        "economic_calendar": True,
        "macroeconomic_releases": True,
        "streaming": False,
    }

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.capabilities: dict[str, bool | None] = dict(self.CAPABILITIES)
        self.enabled = (
            settings.news_enabled and settings.news_external_requests_enabled and settings.trading_economics_enabled
        )
        self.configured = bool(
            settings.trading_economics_api_key.strip() and settings.trading_economics_api_secret.strip()
        )
        self.capabilities["streaming"] = settings.trading_economics_streaming_enabled and self.configured
        self.client = SafeProviderHttpClient(
            base_url=settings.trading_economics_base_url,
            allowed_hosts={"api.tradingeconomics.com"},
            timeout_seconds=settings.trading_economics_request_timeout_seconds,
            max_response_bytes=settings.news_max_response_bytes,
            transport=transport,
        )

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
        del currencies
        if not self.enabled or not self.configured:
            return []
        start = (start_time or datetime.now(UTC) - timedelta(hours=12)).date().isoformat()
        end = (end_time or datetime.now(UTC) + timedelta(days=7)).date().isoformat()
        params: dict[str, str | int | bool] = {
            "c": f"{self.settings.trading_economics_api_key}:{self.settings.trading_economics_api_secret}",
            "d1": start,
            "d2": end,
            "f": "json",
            "values": "true",
        }
        if countries:
            params["country"] = ",".join(countries)
        if self.settings.trading_economics_high_impact_only or minimum_impact in {"HIGH", "CRITICAL"}:
            params["importance"] = 3
        payload = await self.client.get_json("/calendar", params=params)
        if isinstance(payload, dict) and payload.get("Message"):
            message = str(payload["Message"]).lower()
            if "limit" in message or "quota" in message:
                raise ProviderRateLimitError("Trading Economics quota reached")
            if "credential" in message or "authentication" in message:
                raise ProviderAuthenticationError("Trading Economics credentials were rejected")
            raise ProviderFetchError("Trading Economics returned an error response")
        if not isinstance(payload, list):
            raise ProviderFetchError("Trading Economics calendar response must be an array")
        return [item for item in payload[:limit] if isinstance(item, dict)]

    async def health_check(self) -> dict:
        return {"configured": self.configured, "enabled": self.enabled, "capabilities": self.capabilities}
