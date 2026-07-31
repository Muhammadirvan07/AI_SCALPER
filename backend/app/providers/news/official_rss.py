from __future__ import annotations

import html
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar
from urllib.parse import urlparse

import httpx

from app.core.config import Settings

from .base import ProviderFetchError, ProviderRateLimitError
from .safe_xml import UnsafeXmlError, effective_xml_limit, parse_untrusted_xml

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

_TAG_RE = re.compile(r"<[^>]+>")


@dataclass(slots=True)
class FeedCacheEntry:
    etag: str | None = None
    last_modified: str | None = None
    last_fetch_at: datetime | None = None
    last_success_at: datetime | None = None
    last_status_code: int | None = None
    cached_items: list[dict] = field(default_factory=list)


class OfficialRssNewsProvider:
    name = "official_rss"
    CAPABILITIES: ClassVar[dict[str, bool | None]] = {
        "official_news": True,
        "central_bank_news": True,
        "government_releases": True,
    }

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.capabilities: dict[str, bool | None] = dict(self.CAPABILITIES)
        self.enabled = (
            settings.news_enabled and settings.news_external_requests_enabled and settings.official_rss_enabled
        )
        self.transport = transport
        self.configuration_error: str | None = None
        self.feed_cache: dict[str, FeedCacheEntry] = {}
        self.requests_sent = 0
        self.requests_skipped_from_cache = 0
        self.last_status_code: int | None = None
        self.feeds = self._load_config(settings.official_rss_feeds_config) if self.enabled else []
        self.configured = bool(self.feeds) and self.configuration_error is None

    def _load_config(self, path: Path) -> list[dict]:
        try:
            resolved = path.resolve(strict=True)
            allowed_roots = (self.settings.ai_scalper_root.resolve(), Path(__file__).resolve().parents[3])
            if not any(resolved.is_relative_to(root) for root in allowed_roots):
                raise ValueError("Official RSS configuration must remain inside the project")
            payload = json.loads(resolved.read_text(encoding="utf-8"))
            rows = payload.get("feeds") if isinstance(payload, dict) else None
            if not isinstance(rows, list):
                raise ValueError("Official RSS configuration requires a feeds array")
            feeds = [
                dict(item)
                for item in rows
                if isinstance(item, dict) and item.get("enabled") is True and item.get("verified") is True
            ]
            for item in feeds:
                url = str(item.get("url") or "")
                self._validate_url(url)
                official_domain = str(item.get("official_domain") or "").lower().strip(".")
                host = (urlparse(url).hostname or "").lower()
                if not official_domain or not (host == official_domain or host.endswith(f".{official_domain}")):
                    raise ValueError("Official RSS feed host does not match official_domain")
            return feeds
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            self.configuration_error = f"Official RSS configuration invalid: {type(exc).__name__}"
            return []

    @staticmethod
    def _validate_url(url: str) -> None:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not host or parsed.username or parsed.password:
            raise ValueError("Official RSS feed URL must be HTTPS")
        if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
            raise ValueError("Private RSS hosts are not allowed")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return
        if not address.is_global:
            raise ValueError("Private RSS addresses are not allowed")

    async def fetch_news(
        self,
        *,
        symbols: list[str] | None = None,
        currencies: list[str] | None = None,
        categories: list[str] | None = None,
        published_after=None,
        limit: int = 50,
    ) -> list[dict]:
        del symbols, currencies, published_after
        if not self.enabled or not self.configured:
            return []
        rows: list[dict] = []
        headers = {
            "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9",
            "User-Agent": "AI_SCALPER-NewsIntelligence/1.0 (read-only financial monitoring)",
        }
        failures: list[ProviderFetchError] = []
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.settings.official_rss_request_timeout_seconds),
            follow_redirects=False,
            transport=self.transport,
        ) as client:
            for feed in self.feeds:
                feed_categories = [str(item).upper() for item in feed.get("categories", [])]
                if categories and not set(item.upper() for item in categories).intersection(feed_categories):
                    continue
                try:
                    feed_id = str(feed["id"])
                    payload, not_modified = await self._download(client, str(feed["url"]), headers, feed_id)
                    if not_modified:
                        parsed = list(self.feed_cache[feed_id].cached_items)
                    else:
                        parsed = self._parse(payload or b"", feed)
                        cache = self.feed_cache.setdefault(feed_id, FeedCacheEntry())
                        cache.cached_items = list(parsed)
                        cache.last_success_at = datetime.now(UTC)
                except ProviderFetchError as exc:
                    failures.append(exc)
                    continue
                rows.extend(parsed[: self.settings.official_rss_max_items_per_feed])
                if len(rows) >= limit:
                    break
        if not rows and failures:
            raise failures[0]
        return rows[:limit]

    async def _download(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
        feed_id: str,
    ) -> tuple[bytes | None, bool]:
        cache = self.feed_cache.setdefault(feed_id, FeedCacheEntry())
        request_headers = dict(headers)
        if cache.etag:
            request_headers["If-None-Match"] = cache.etag
        if cache.last_modified:
            request_headers["If-Modified-Since"] = cache.last_modified
        try:
            async with client.stream("GET", url, headers=request_headers) as response:
                self.requests_sent += 1
                self.last_status_code = response.status_code
                cache.last_fetch_at = datetime.now(UTC)
                cache.last_status_code = response.status_code
                if response.status_code == 304:
                    self.requests_skipped_from_cache += 1
                    cache.last_success_at = cache.last_fetch_at
                    return None, True
                if response.status_code == 429:
                    raise ProviderRateLimitError("Official RSS source rate limited the request")
                if 300 <= response.status_code < 400:
                    raise ProviderFetchError("Official RSS redirects are disabled")
                if response.status_code >= 400:
                    raise ProviderFetchError(f"Official RSS source returned HTTP {response.status_code}")
                content_type = response.headers.get("content-type", "").lower()
                if content_type and not any(item in content_type for item in ("xml", "rss", "atom")):
                    raise ProviderFetchError("Official RSS source returned unsupported content type")
                xml_limit = effective_xml_limit(self.settings.news_max_response_bytes)
                declared = response.headers.get("content-length")
                if declared:
                    try:
                        if int(declared) > xml_limit:
                            raise ProviderFetchError("Official RSS response exceeds configured size limit")
                    except ValueError as exc:
                        raise ProviderFetchError("Official RSS returned an invalid content length") from exc
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > xml_limit:
                        raise ProviderFetchError("Official RSS response exceeds configured size limit")
                    chunks.append(chunk)
                cache.etag = response.headers.get("etag") or cache.etag
                cache.last_modified = response.headers.get("last-modified") or cache.last_modified
                return b"".join(chunks), False
        except ProviderFetchError:
            raise
        except httpx.TimeoutException as exc:
            raise ProviderFetchError("Official RSS request timed out") from exc
        except httpx.HTTPError as exc:
            raise ProviderFetchError(f"Official RSS request failed: {type(exc).__name__}") from exc

    @staticmethod
    def _text(element: Element | None) -> str | None:
        if element is None or element.text is None:
            return None
        value = html.unescape(_TAG_RE.sub(" ", element.text))
        return " ".join(value.split()) or None

    def _parse(self, payload: bytes, feed: dict) -> list[dict]:
        try:
            root = parse_untrusted_xml(payload, max_bytes=self.settings.news_max_response_bytes)
        except UnsafeXmlError as exc:
            raise ProviderFetchError(f"Official RSS source returned invalid XML: {exc}") from exc
        entries = root.findall("./channel/item") or root.findall("{*}entry")
        rows = []
        for entry in entries:
            link = self._text(entry.find("link"))
            if link is None:
                link_element = entry.find("{*}link")
                link = link_element.get("href") if link_element is not None else None
            title = self._text(entry.find("title")) or self._text(entry.find("{*}title"))
            if not title or not link:
                continue
            rows.append(
                {
                    "id": self._text(entry.find("guid")) or self._text(entry.find("{*}id")),
                    "title": title,
                    "summary": self._text(entry.find("description")) or self._text(entry.find("{*}summary")),
                    "url": link,
                    "published_at": self._text(entry.find("pubDate"))
                    or self._text(entry.find("{*}published"))
                    or self._text(entry.find("{*}updated")),
                    "author": self._text(entry.find("author")) or self._text(entry.find("{*}author/{*}name")),
                    "source": feed.get("name"),
                    "language": feed.get("language", "en"),
                    "countries": feed.get("countries", []),
                    "currencies": feed.get("currencies", []),
                    "categories": feed.get("categories", []),
                }
            )
        return rows

    async def health_check(self) -> dict:
        return {
            "configured": self.configured,
            "enabled": self.enabled,
            "capabilities": self.capabilities,
            "feed_count": len(self.feeds),
            "configuration_error": self.configuration_error,
            "requests_sent": self.requests_sent,
            "requests_skipped_from_cache": self.requests_skipped_from_cache,
            "last_status_code": self.last_status_code,
            "feeds": {
                feed_id: {
                    "etag": item.etag,
                    "last_modified": item.last_modified,
                    "last_fetch_at": item.last_fetch_at,
                    "last_success_at": item.last_success_at,
                    "last_status_code": item.last_status_code,
                    "cached_item_count": len(item.cached_items),
                }
                for feed_id, item in self.feed_cache.items()
            },
        }
