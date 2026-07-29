from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlparse

import httpx

from .base import (
    ProviderAuthenticationError,
    ProviderEntitlementError,
    ProviderFetchError,
    ProviderRateLimitError,
)


class SafeProviderHttpClient:
    def __init__(
        self,
        *,
        base_url: str,
        allowed_hosts: set[str],
        timeout_seconds: float,
        max_response_bytes: int,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        parsed = urlparse(base_url.rstrip("/"))
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or host not in allowed_hosts or parsed.username or parsed.password:
            raise ValueError("Provider base URL is not an allowlisted HTTPS endpoint")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            if not address.is_global:
                raise ValueError("Provider base URL cannot target a private address")
        self.base_url = base_url.rstrip("/")
        self.timeout = httpx.Timeout(timeout_seconds)
        self.max_response_bytes = max_response_bytes
        self.transport = transport

    async def get_json(self, path: str, *, params: dict[str, Any]) -> Any:
        if not path.startswith("/") or path.startswith("//") or ".." in path:
            raise ProviderFetchError("Provider path is not allowed")
        headers = {
            "Accept": "application/json",
            "User-Agent": "AI_SCALPER-NewsIntelligence/1.0 (read-only financial monitoring)",
        }
        try:
            async with (
                httpx.AsyncClient(
                    base_url=self.base_url,
                    timeout=self.timeout,
                    follow_redirects=False,
                    transport=self.transport,
                ) as client,
                client.stream("GET", path, params=params, headers=headers) as response,
            ):
                if response.status_code == 401:
                    raise ProviderAuthenticationError("Provider authentication failed")
                if response.status_code == 403:
                    raise ProviderEntitlementError("Provider entitlement denied")
                if response.status_code == 429:
                    retry_after: float | None = None
                    raw_retry_after = response.headers.get("retry-after")
                    if raw_retry_after:
                        try:
                            retry_after = max(0.0, float(raw_retry_after))
                        except ValueError:
                            retry_after = None
                    raise ProviderRateLimitError(
                        "Provider rate limit reached",
                        retry_after_seconds=retry_after,
                    )
                if 300 <= response.status_code < 400:
                    raise ProviderFetchError("Provider redirects are disabled")
                if response.status_code >= 400:
                    raise ProviderFetchError(f"Provider returned HTTP {response.status_code}")
                content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
                if content_type and "json" not in content_type:
                    raise ProviderFetchError(f"Provider returned unsupported content type {content_type}")
                declared = response.headers.get("content-length")
                if declared and int(declared) > self.max_response_bytes:
                    raise ProviderFetchError("Provider response exceeds configured size limit")
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > self.max_response_bytes:
                        raise ProviderFetchError("Provider response exceeds configured size limit")
                    chunks.append(chunk)
                try:
                    return httpx.Response(200, content=b"".join(chunks)).json()
                except ValueError as exc:
                    raise ProviderFetchError("Provider returned invalid JSON") from exc
        except ProviderFetchError:
            raise
        except httpx.TimeoutException as exc:
            raise ProviderFetchError("Provider request timed out") from exc
        except httpx.HTTPError as exc:
            raise ProviderFetchError(f"Provider request failed: {type(exc).__name__}") from exc
