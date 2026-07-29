from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from app.providers.news.base import ProviderFetchError, ProviderRateLimitError


@dataclass(slots=True)
class OfficialHttpResponse:
    status_code: int
    content: bytes
    content_type: str
    headers: Mapping[str, str]


class OfficialHttpStatusError(ProviderFetchError):
    def __init__(self, status_code: int) -> None:
        super().__init__(f"Official source returned HTTP {status_code}")
        self.status_code = status_code


class OfficialSourceHttpClient:
    """Small allowlisted HTTP client; it never accepts frontend-controlled URLs."""

    def __init__(
        self,
        *,
        base_url: str,
        allowed_hosts: set[str],
        timeout_seconds: float,
        max_response_bytes: int,
        user_agent: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        parsed = urlparse(base_url.rstrip("/"))
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or host not in allowed_hosts or parsed.username or parsed.password:
            raise ValueError("Official source base URL must be an allowlisted HTTPS endpoint")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            if not address.is_global:
                raise ValueError("Official source cannot target a private address")
        self.base_url = base_url.rstrip("/")
        self.allowed_hosts = allowed_hosts
        self.timeout = httpx.Timeout(timeout_seconds)
        self.max_response_bytes = max_response_bytes
        self.user_agent = user_agent
        self.transport = transport

    async def get(
        self,
        path: str,
        *,
        accept: str,
        headers: Mapping[str, str] | None = None,
    ) -> OfficialHttpResponse:
        if not path.startswith("/") or path.startswith("//") or ".." in path:
            raise ProviderFetchError("Official source path is not allowed")
        request_headers = {"Accept": accept, "User-Agent": self.user_agent, **dict(headers or {})}
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
                follow_redirects=False,
                transport=self.transport,
            ) as client:
                response = await client.get(path, headers=request_headers)
                if response.status_code == 429:
                    raw = response.headers.get("retry-after")
                    try:
                        retry_after = max(0.0, float(raw)) if raw else None
                    except ValueError:
                        retry_after = None
                    raise ProviderRateLimitError(
                        "Official source rate limit reached",
                        retry_after_seconds=retry_after,
                    )
                if 300 <= response.status_code < 400:
                    location = response.headers.get("location")
                    target = urlparse(urljoin(self.base_url, location or ""))
                    if target.scheme != "https" or (target.hostname or "").lower() not in self.allowed_hosts:
                        raise ProviderFetchError("Official source redirect escaped the host allowlist")
                    raise ProviderFetchError("Official source redirects are disabled")
                if response.status_code >= 400:
                    raise OfficialHttpStatusError(response.status_code)
                declared = response.headers.get("content-length")
                if declared:
                    try:
                        if int(declared) > self.max_response_bytes:
                            raise ProviderFetchError("Official source response exceeds the configured size limit")
                    except ValueError:
                        pass
                content = response.content
                if len(content) > self.max_response_bytes:
                    raise ProviderFetchError("Official source response exceeds the configured size limit")
                content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
                return OfficialHttpResponse(response.status_code, content, content_type, response.headers)
        except (ProviderFetchError, ProviderRateLimitError):
            raise
        except httpx.TimeoutException as exc:
            raise ProviderFetchError("Official source request timed out") from exc
        except httpx.HTTPError as exc:
            raise ProviderFetchError(f"Official source request failed: {type(exc).__name__}") from exc
