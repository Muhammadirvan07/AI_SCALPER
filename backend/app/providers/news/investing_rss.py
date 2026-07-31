from __future__ import annotations

import asyncio
import html
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar
from urllib.parse import urlparse

import httpx

from app.core.config import Settings

from .base import ProviderFetchError, ProviderRateLimitError
from .safe_xml import UnsafeXmlError, effective_xml_limit, parse_untrusted_xml

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

_BLOCK_TAG_RE = re.compile(
    r"<(script|style|iframe|form)\b[^>]*>.*?</\1\s*>",
    flags=re.IGNORECASE | re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")
_SPACE_RE = re.compile(r"\s+")
_ALLOWED_CONTENT_TYPES = {
    "application/rss+xml",
    "application/atom+xml",
    "application/xml",
    "text/xml",
}


@dataclass(slots=True)
class InvestingFeedState:
    etag: str | None = None
    last_modified: str | None = None
    last_fetch_at: datetime | None = None
    last_success_at: datetime | None = None
    last_status_code: int | None = None
    last_error: str | None = None
    cached_items: list[dict] = field(default_factory=list)
    failure_count: int = 0
    circuit_state: str = "CLOSED"
    cooldown_until: datetime | None = None


class InvestingRssNewsProvider:
    """Keyless, metadata-only client for Investing.com's published RSS catalog."""

    name = "investing_rss"
    OFFICIAL_DOMAIN = "investing.com"
    CAPABILITY_BY_CATEGORY: ClassVar[dict[str, str]] = {
        "GENERAL": "financial_news",
        "FOREX": "forex_news",
        "COMMODITIES": "commodities_news",
        "GOLD": "commodities_news",
        "SILVER": "commodities_news",
        "ENERGY": "commodities_news",
        "CRYPTO": "crypto_news",
        "CENTRAL_BANK": "central_bank_news",
        "INTEREST_RATE": "central_bank_news",
        "EQUITIES": "equities_news",
    }

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.transport = transport
        self.enabled = bool(
            settings.news_enabled and settings.news_external_requests_enabled and settings.investing_rss_enabled
        )
        self.configuration_error: str | None = None
        self.feeds = self._load_config(settings.investing_rss_feeds_config) if self.enabled else []
        self.configured = bool(self.feeds) and self.configuration_error is None
        capabilities = {
            self.CAPABILITY_BY_CATEGORY[category]
            for feed in self.feeds
            for category in feed.get("categories", [])
            if category in self.CAPABILITY_BY_CATEGORY
        }
        if any("ECONOMIC_INDICATORS" in feed.get("topics", []) for feed in self.feeds):
            capabilities.add("macroeconomic_news")
        self.capabilities: dict[str, bool | None] = {item: True for item in sorted(capabilities)}
        self.feed_cache: dict[str, InvestingFeedState] = {}
        self._feed_locks: dict[str, asyncio.Lock] = {}
        self.requests_sent = 0
        self.requests_skipped_from_cache = 0
        self.rate_limit_count = 0
        self.last_retry_after_seconds: float | None = None
        self.last_status_code: int | None = None
        self.feed_count = len(self.feeds)
        self.healthy_feed_count = 0
        self.failed_feed_count = 0
        self.raw_article_count = 0

    @property
    def last_known_good_available(self) -> bool:
        return any(state.cached_items for state in self.feed_cache.values())

    @property
    def circuit_state(self) -> str:
        states = {item.circuit_state for item in self.feed_cache.values()}
        if states == {"OPEN"} and states:
            return "OPEN"
        if "OPEN" in states:
            return "HALF_OPEN"
        return "CLOSED"

    @property
    def cooldown_until(self) -> datetime | None:
        values = [item.cooldown_until for item in self.feed_cache.values() if item.cooldown_until]
        return max(values) if values else None

    @property
    def failure_count(self) -> int:
        return sum(item.failure_count for item in self.feed_cache.values())

    @property
    def last_error(self) -> str | None:
        return next((item.last_error for item in self.feed_cache.values() if item.last_error), None)

    @property
    def rate_limited(self) -> bool:
        return any(item.last_status_code == 429 for item in self.feed_cache.values())

    def _load_config(self, path: Path) -> list[dict]:
        try:
            resolved = path.resolve(strict=True)
            allowed_roots = (self.settings.ai_scalper_root.resolve(), Path(__file__).resolve().parents[3])
            if not any(resolved.is_relative_to(root) for root in allowed_roots):
                raise ValueError("Investing RSS configuration must remain inside the project")
            payload = json.loads(resolved.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or payload.get("provider") != self.name:
                raise ValueError("Investing RSS configuration has an invalid provider")
            rows = payload.get("feeds")
            if not isinstance(rows, list):
                raise ValueError("Investing RSS configuration requires a feeds array")
            feeds: list[dict] = []
            for raw in rows:
                if not isinstance(raw, dict) or raw.get("enabled") is not True or raw.get("verified") is not True:
                    continue
                item = dict(raw)
                url = str(item.get("url") or "")
                official_domain = str(item.get("official_domain") or "").lower().strip(".")
                self._validate_url(url, official_domain=official_domain)
                if official_domain != self.OFFICIAL_DOMAIN:
                    raise ValueError("Investing RSS feed must declare investing.com as official_domain")
                feeds.append(item)
            return feeds
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            self.configuration_error = f"Investing RSS configuration invalid: {type(exc).__name__}"
            return []

    @classmethod
    def _validate_url(cls, url: str, *, official_domain: str | None = None) -> None:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().strip(".")
        domain = (official_domain or cls.OFFICIAL_DOMAIN).lower().strip(".")
        if parsed.scheme != "https" or not host or parsed.username or parsed.password:
            raise ValueError("Investing RSS URL must be HTTPS without credentials")
        if not (host == domain or host.endswith(f".{domain}")):
            raise ValueError("Investing RSS URL must use an allowlisted official domain")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return
        if not address.is_global:
            raise ValueError("Investing RSS URL cannot target a private address")

    async def fetch_news(
        self,
        *,
        symbols: list[str] | None = None,
        currencies: list[str] | None = None,
        categories: list[str] | None = None,
        published_after: datetime | None = None,
        limit: int = 50,
    ) -> list[dict]:
        # Relevance and freshness are applied only after cross-feed canonicalization.
        del symbols, currencies, published_after
        if not self.enabled or not self.configured:
            return []
        requested_categories = {item.upper() for item in categories or []}
        selected = [
            feed
            for feed in self.feeds
            if not requested_categories
            or requested_categories.intersection(
                {str(item).upper() for item in [*feed.get("categories", []), *feed.get("topics", [])]}
            )
        ]
        semaphore = asyncio.Semaphore(min(3, max(1, self.settings.news_max_parallel_provider_requests)))

        async def collect_feed(feed: dict) -> tuple[list[dict], Exception | None]:
            async with semaphore:
                try:
                    return await self._fetch_feed(feed), None
                except (ProviderFetchError, OSError, TimeoutError) as exc:
                    return [], exc

        results = await asyncio.gather(*(collect_feed(feed) for feed in selected))
        rows = [item for feed_rows, _ in results for item in feed_rows]
        failures = [error for _, error in results if error is not None]
        self.healthy_feed_count = sum(
            1
            for feed in selected
            if (state := self.feed_cache.get(str(feed["id"]))) is not None and state.last_error is None
        )
        self.failed_feed_count = len(selected) - self.healthy_feed_count
        max_items = min(self.settings.investing_rss_max_total_items, max(1, limit))
        self.raw_article_count = min(len(rows), max_items)
        if not rows and failures:
            rate_limited = next((item for item in failures if isinstance(item, ProviderRateLimitError)), None)
            raise rate_limited or failures[0]
        return rows[:max_items]

    async def _fetch_feed(self, feed: dict) -> list[dict]:
        feed_id = str(feed["id"])
        state = self.feed_cache.setdefault(feed_id, InvestingFeedState())
        lock = self._feed_locks.setdefault(feed_id, asyncio.Lock())
        now = datetime.now(UTC)
        if state.circuit_state == "OPEN" and state.cooldown_until and now < state.cooldown_until:
            if state.cached_items:
                self.requests_skipped_from_cache += 1
                return list(state.cached_items)
            raise ProviderFetchError(f"Investing RSS feed {feed_id} circuit is open")
        async with lock:
            try:
                payload, not_modified = await self._download(str(feed["url"]), state)
                if not_modified:
                    state.last_error = None
                    state.failure_count = 0
                    state.circuit_state = "CLOSED"
                    state.cooldown_until = None
                    return list(state.cached_items)
                parsed = self._parse(payload or b"", feed)
                state.cached_items = list(parsed[: self.settings.investing_rss_max_items_per_feed])
                state.last_success_at = datetime.now(UTC)
                state.last_error = None
                state.failure_count = 0
                state.circuit_state = "CLOSED"
                state.cooldown_until = None
                return list(state.cached_items)
            except ProviderFetchError as exc:
                state.last_error = str(exc)
                state.failure_count += 1
                if state.failure_count >= self.settings.investing_rss_failure_threshold:
                    state.circuit_state = "OPEN"
                    state.cooldown_until = datetime.now(UTC) + timedelta(
                        seconds=self.settings.investing_rss_cooldown_seconds
                    )
                if state.cached_items:
                    return list(state.cached_items)
                raise

    async def _download(self, url: str, state: InvestingFeedState) -> tuple[bytes | None, bool]:
        headers = {
            "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml",
            "User-Agent": self.settings.investing_rss_user_agent,
        }
        if self.settings.investing_rss_use_conditional_requests:
            if state.etag:
                headers["If-None-Match"] = state.etag
            if state.last_modified:
                headers["If-Modified-Since"] = state.last_modified
        for attempt in range(2):
            try:
                async with (
                    httpx.AsyncClient(
                        timeout=httpx.Timeout(self.settings.investing_rss_request_timeout_seconds),
                        follow_redirects=False,
                        max_redirects=0,
                        transport=self.transport,
                    ) as client,
                    client.stream("GET", url, headers=headers) as response,
                ):
                    self.requests_sent += 1
                    self.last_status_code = response.status_code
                    state.last_fetch_at = datetime.now(UTC)
                    state.last_status_code = response.status_code
                    if response.status_code == 304:
                        self.requests_skipped_from_cache += 1
                        state.last_success_at = state.last_fetch_at
                        return None, True
                    if response.status_code == 429:
                        retry_after = self._retry_after(response.headers.get("retry-after"))
                        self.rate_limit_count += 1
                        self.last_retry_after_seconds = retry_after
                        raise ProviderRateLimitError(
                            "Investing RSS rate limited the request",
                            retry_after_seconds=retry_after,
                        )
                    if 300 <= response.status_code < 400:
                        raise ProviderFetchError("Investing RSS redirects are disabled")
                    if response.status_code >= 500 and attempt == 0:
                        await asyncio.sleep(0.1)
                        continue
                    if response.status_code >= 400:
                        raise ProviderFetchError(f"Investing RSS returned HTTP {response.status_code}")
                    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                    if content_type not in _ALLOWED_CONTENT_TYPES:
                        raise ProviderFetchError("Investing RSS returned unsupported content type")
                    declared = response.headers.get("content-length")
                    xml_limit = effective_xml_limit(self.settings.investing_rss_max_response_bytes)
                    if declared:
                        try:
                            if int(declared) > xml_limit:
                                raise ProviderFetchError("Investing RSS response exceeds configured size limit")
                        except ValueError as exc:
                            raise ProviderFetchError("Investing RSS returned an invalid content length") from exc
                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > xml_limit:
                            raise ProviderFetchError("Investing RSS response exceeds configured size limit")
                        chunks.append(chunk)
                    state.etag = response.headers.get("etag") or state.etag
                    state.last_modified = response.headers.get("last-modified") or state.last_modified
                    return b"".join(chunks), False
            except ProviderFetchError:
                raise
            except httpx.TimeoutException as exc:
                if attempt == 0:
                    await asyncio.sleep(0.1)
                    continue
                raise ProviderFetchError("Investing RSS request timed out") from exc
            except httpx.HTTPError as exc:
                if attempt == 0:
                    await asyncio.sleep(0.1)
                    continue
                raise ProviderFetchError(f"Investing RSS request failed: {type(exc).__name__}") from exc
        raise ProviderFetchError("Investing RSS request failed")

    @staticmethod
    def _retry_after(value: str | None) -> float | None:
        if not value:
            return None
        try:
            return max(0.0, float(value))
        except ValueError:
            try:
                parsed = parsedate_to_datetime(value)
            except (TypeError, ValueError):
                return None
            aware = parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
            return max(0.0, (aware - datetime.now(UTC)).total_seconds())

    @staticmethod
    def _plain_text(value: str | None, *, maximum: int) -> str | None:
        if not value:
            return None
        decoded = html.unescape(value)
        decoded = _BLOCK_TAG_RE.sub(" ", decoded)
        decoded = _TAG_RE.sub(" ", decoded)
        cleaned = _SPACE_RE.sub(" ", decoded).strip()
        return cleaned[:maximum] or None

    @staticmethod
    def _local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1].lower()

    @classmethod
    def _child_text(cls, entry: Element, names: set[str]) -> str | None:
        for child in entry.iter():
            if child is entry or cls._local(child.tag) not in names:
                continue
            value = "".join(child.itertext())
            if cleaned := cls._plain_text(value, maximum=1000):
                return cleaned
        return None

    @classmethod
    def _link(cls, entry: Element) -> str | None:
        for child in entry.iter():
            if cls._local(child.tag) != "link":
                continue
            value = child.get("href") or child.text
            if value and value.strip():
                return value.strip()
        return None

    def _parse(self, payload: bytes, feed: dict) -> list[dict]:
        try:
            root = parse_untrusted_xml(
                payload,
                max_bytes=self.settings.investing_rss_max_response_bytes,
            )
        except UnsafeXmlError as exc:
            raise ProviderFetchError(f"Investing RSS returned invalid XML: {exc}") from exc
        entries = [item for item in root.iter() if self._local(item.tag) in {"item", "entry"}]
        rows: list[dict] = []
        for entry in entries:
            title = self._child_text(entry, {"title"})
            link = self._link(entry)
            if not title or not link:
                continue
            item_categories = [
                self._plain_text(child.get("term") or child.text, maximum=80)
                for child in entry.iter()
                if self._local(child.tag) == "category"
            ]
            categories = list(
                dict.fromkeys(
                    [
                        *(str(item).upper() for item in feed.get("categories", []) if item),
                        *(item.upper() for item in item_categories if item),
                    ]
                )
            )
            rows.append(
                {
                    "id": self._child_text(entry, {"guid", "id"}) or link,
                    "title": title,
                    "summary": self._child_text(entry, {"description", "summary"}),
                    "url": link,
                    "published_at": self._child_text(entry, {"pubdate", "published", "updated", "date"}),
                    "author": self._child_text(entry, {"author", "creator"}),
                    "source": "Investing.com",
                    "language": feed.get("language", "en"),
                    "countries": feed.get("countries", []),
                    "currencies": feed.get("currencies", []),
                    "symbols": feed.get("symbols", []),
                    "categories": categories,
                    "topics": list(dict.fromkeys([*feed.get("topics", []), *categories])),
                    "feed_id": feed.get("id"),
                    "feed_name": feed.get("name"),
                    "is_breaking_candidate": feed.get("id") == "investing_breaking",
                }
            )
        return rows

    async def health_check(self) -> dict:
        return {
            "configured": self.configured,
            "enabled": self.enabled,
            "capabilities": self.capabilities,
            "feed_count": self.feed_count,
            "healthy_feed_count": self.healthy_feed_count,
            "failed_feed_count": self.failed_feed_count,
            "configuration_error": self.configuration_error,
            "requests_sent": self.requests_sent,
            "requests_skipped_from_cache": self.requests_skipped_from_cache,
            "last_status_code": self.last_status_code,
            "last_known_good_available": self.last_known_good_available,
            "rate_limited": self.rate_limited,
            "circuit_state": self.circuit_state,
            "cooldown_until": self.cooldown_until,
            "feeds": {
                feed_id: {
                    "etag": item.etag,
                    "last_modified": item.last_modified,
                    "last_fetch_at": item.last_fetch_at,
                    "last_success_at": item.last_success_at,
                    "last_status_code": item.last_status_code,
                    "last_error": item.last_error,
                    "cached_item_count": len(item.cached_items),
                    "failure_count": item.failure_count,
                    "circuit_state": item.circuit_state,
                    "cooldown_until": item.cooldown_until,
                }
                for feed_id, item in self.feed_cache.items()
            },
        }
