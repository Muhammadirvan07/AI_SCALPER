from __future__ import annotations

import html
import ipaddress
import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx

from app.core.config import Settings

from .base import ProviderFetchError, ProviderRateLimitError
from .safe_xml import UnsafeXmlError, effective_xml_limit, parse_untrusted_xml

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

_TAG_RE = re.compile(r"<[^>]+>")


class RSSNewsProvider:
    name = "rss"

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.feeds = settings.news_feed_urls
        self.enabled = (
            settings.news_enabled and settings.news_external_requests_enabled and "rss" in settings.news_provider_modes
        )
        self.configured = bool(self.feeds)
        self.transport = transport
        self.configuration_error: str | None = None
        for feed in self.feeds:
            try:
                self._validate_feed_url(feed)
            except ValueError as exc:
                self.configuration_error = str(exc)
                break

    async def fetch_latest(
        self,
        *,
        limit: int,
        symbols: list[str] | None = None,
        categories: list[str] | None = None,
    ) -> list[dict]:
        del symbols, categories
        if not self.enabled or not self.configured:
            return []
        if self.configuration_error:
            raise ProviderFetchError(self.configuration_error)
        rows: list[dict] = []
        timeout = httpx.Timeout(self.settings.news_request_timeout_seconds)
        headers = {
            "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9",
            "User-Agent": "AI_SCALPER-NewsIntelligence/1.0 (read-only financial monitoring)",
        }
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, transport=self.transport) as client:
            for feed in self.feeds:
                payload, content_type = await self._download(client, feed, headers)
                rows.extend(self._parse(payload, feed, content_type))
                if len(rows) >= limit:
                    break
        return rows[:limit]

    async def _download(self, client: httpx.AsyncClient, url: str, headers: dict[str, str]) -> tuple[bytes, str]:
        try:
            async with client.stream("GET", url, headers=headers) as response:
                if response.status_code == 429:
                    raise ProviderRateLimitError("RSS provider rate limited the request")
                if 300 <= response.status_code < 400:
                    raise ProviderFetchError("RSS redirects are disabled by policy")
                response.raise_for_status()
                content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
                if content_type and not any(token in content_type for token in ("xml", "rss", "atom")):
                    raise ProviderFetchError(f"Unsupported RSS content type: {content_type}")
                declared = response.headers.get("content-length")
                xml_limit = effective_xml_limit(self.settings.news_max_response_bytes)
                if declared:
                    try:
                        if int(declared) > xml_limit:
                            raise ProviderFetchError("RSS response exceeds configured size limit")
                    except ValueError as exc:
                        raise ProviderFetchError("RSS provider returned an invalid content length") from exc
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > xml_limit:
                        raise ProviderFetchError("RSS response exceeds configured size limit")
                    chunks.append(chunk)
                return b"".join(chunks), content_type
        except ProviderFetchError:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            raise ProviderFetchError(f"RSS request failed: {type(exc).__name__}") from exc

    def _validate_feed_url(self, url: str) -> None:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in {"https", "http"} or not host or parsed.username or parsed.password:
            raise ValueError("NEWS_RSS_FEEDS contains an invalid URL")
        if host not in self.settings.news_feed_hosts:
            raise ValueError(f"RSS host {host!r} is not allowlisted")
        if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
            raise ValueError("Private RSS hosts are not allowed")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return
        if not address.is_global:
            raise ValueError("Private RSS addresses are not allowed")

    @staticmethod
    def _text(element: Element | None) -> str | None:
        if element is None or element.text is None:
            return None
        value = html.unescape(_TAG_RE.sub(" ", element.text))
        cleaned = " ".join(value.split())
        return cleaned or None

    def _parse(self, payload: bytes, feed_url: str, content_type: str) -> list[dict]:
        del content_type
        try:
            root = parse_untrusted_xml(payload, max_bytes=self.settings.news_max_response_bytes)
        except UnsafeXmlError as exc:
            raise ProviderFetchError(f"RSS provider returned invalid XML: {exc}") from exc
        channel = root.find("channel")
        feed_title = self._text(channel.find("title")) if channel is not None else None
        entries = root.findall("./channel/item")
        if not entries:
            entries = root.findall("{*}entry")
        rows: list[dict] = []
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
                    "summary": (
                        self._text(entry.find("description"))
                        or self._text(entry.find("{*}summary"))
                        or self._text(entry.find("{*}content"))
                    ),
                    "url": link,
                    "published_at": (
                        self._text(entry.find("pubDate"))
                        or self._text(entry.find("{*}published"))
                        or self._text(entry.find("{*}updated"))
                    ),
                    "author": self._text(entry.find("author")) or self._text(entry.find("{*}author/{*}name")),
                    "source": feed_title or urlparse(feed_url).hostname,
                    "language": root.attrib.get("{http://www.w3.org/XML/1998/namespace}lang"),
                }
            )
        return rows
