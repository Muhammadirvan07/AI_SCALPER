from __future__ import annotations

from datetime import UTC, datetime
from typing import ClassVar

import httpx

from app.adapters.news_adapter import CRYPTO_ASSETS, symbol_components
from app.core.config import Settings

from .base import ProviderAuthenticationError, ProviderFetchError, ProviderRateLimitError
from .http_client import SafeProviderHttpClient

TOPIC_MAP = {
    "CENTRAL_BANK": "economy_monetary",
    "INTEREST_RATE": "economy_monetary",
    "INFLATION": "economy_monetary",
    "EMPLOYMENT": "economy_macro",
    "GDP": "economy_macro",
    "ENERGY": "energy_transportation",
    "CRYPTO": "blockchain",
    "EQUITIES": "financial_markets",
    "FOREX": "financial_markets",
    "COMMODITIES": "financial_markets",
}


class AlphaVantageNewsProvider:
    name = "alpha_vantage"
    CAPABILITIES: ClassVar[dict[str, bool | None]] = {
        "financial_news": True,
        "forex_news": True,
        "crypto_news": True,
        "commodity_news": True,
        "provider_sentiment": True,
    }

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.capabilities: dict[str, bool | None] = dict(self.CAPABILITIES)
        self.enabled = (
            settings.news_enabled and settings.news_external_requests_enabled and settings.alpha_vantage_enabled
        )
        self.configured = bool(settings.alpha_vantage_api_key.strip())
        self.client = SafeProviderHttpClient(
            base_url=settings.alpha_vantage_base_url,
            allowed_hosts={"www.alphavantage.co", "alphavantage.co"},
            timeout_seconds=settings.alpha_vantage_request_timeout_seconds,
            max_response_bytes=settings.news_max_response_bytes,
            transport=transport,
        )

    @staticmethod
    def _tickers(symbols: list[str] | None, currencies: list[str] | None) -> list[str]:
        values: set[str] = {f"FOREX:{item.upper()}" for item in currencies or []}
        for symbol in symbols or []:
            normalized = symbol.upper()
            left = normalized[:3]
            _, components = symbol_components(normalized)
            values.update(f"FOREX:{currency}" for currency in components)
            if left in CRYPTO_ASSETS:
                values.add(f"CRYPTO:{left}")
        return sorted(values)

    async def fetch_news(
        self,
        *,
        symbols: list[str] | None = None,
        currencies: list[str] | None = None,
        categories: list[str] | None = None,
        published_after: datetime | None = None,
        limit: int = 50,
    ) -> list[dict]:
        if not self.enabled or not self.configured:
            return []
        params: dict[str, str | int] = {
            "function": "NEWS_SENTIMENT",
            "sort": "LATEST",
            "limit": min(limit, self.settings.alpha_vantage_max_articles),
            "apikey": self.settings.alpha_vantage_api_key,
        }
        tickers = self._tickers(symbols, currencies)
        topics = sorted({TOPIC_MAP[item.upper()] for item in categories or [] if item.upper() in TOPIC_MAP})
        if tickers:
            params["tickers"] = ",".join(tickers)
        if topics:
            params["topics"] = ",".join(topics)
        if published_after:
            params["time_from"] = published_after.astimezone(UTC).strftime("%Y%m%dT%H%M")
        payload = await self.client.get_json("/query", params=params)
        if not isinstance(payload, dict):
            raise ProviderFetchError("Alpha Vantage returned an invalid response")
        message = str(payload.get("Note") or payload.get("Information") or "")
        if message:
            if any(term in message.lower() for term in ("rate limit", "call frequency", "quota")):
                raise ProviderRateLimitError("Alpha Vantage quota or call frequency limit reached")
            if "api key" in message.lower():
                raise ProviderAuthenticationError("Alpha Vantage API key was rejected")
            raise ProviderFetchError("Alpha Vantage returned an informational error")
        if payload.get("Error Message"):
            raise ProviderFetchError("Alpha Vantage rejected the news query")
        feed = payload.get("feed")
        if not isinstance(feed, list):
            raise ProviderFetchError("Alpha Vantage response does not contain a feed array")
        rows = [dict(item) for item in feed[:limit] if isinstance(item, dict)]
        if not self.settings.alpha_vantage_use_provider_sentiment:
            for item in rows:
                item.pop("overall_sentiment_score", None)
                item.pop("overall_sentiment_label", None)
                item.pop("ticker_sentiment", None)
        return rows

    async def health_check(self) -> dict:
        return {"configured": self.configured, "enabled": self.enabled, "capabilities": self.capabilities}
