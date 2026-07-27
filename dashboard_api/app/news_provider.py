from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from .config import Settings
from .models import SourceMeta

logger = logging.getLogger(__name__)


class RemoteNewsProvider:
    """Optional read-only HTTP news source with an in-memory last-known-good value."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings
        self.transport = transport
        self._now = now or (lambda: datetime.now(UTC))
        self.last_value: Any = None
        self.last_meta: SourceMeta | None = None
        self.last_fetch_monotonic = 0.0
        self._last_error: str | None = None

    @property
    def configured(self) -> bool:
        return bool(self.settings.news_api_url)

    def due(self) -> bool:
        return self.configured and (
            time.monotonic() - self.last_fetch_monotonic
            >= self.settings.news_poll_seconds
        )

    @staticmethod
    def _source_timestamp(value: Any) -> datetime | None:
        if not isinstance(value, Mapping):
            return None
        raw = next(
            (
                value.get(key)
                for key in ("updated_at", "generated_at", "last_updated", "timestamp")
                if value.get(key) is not None
            ),
            None,
        )
        if raw is None:
            return None
        try:
            parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            return None

    @staticmethod
    def _header_timestamp(headers: Mapping[str, str]) -> datetime | None:
        raw = headers.get("last-modified")
        if not raw:
            return None
        try:
            parsed = parsedate_to_datetime(raw)
            return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except (TypeError, ValueError, OverflowError):
            return None

    def _adapt_payload(
        self,
        value: Any,
        source_timestamp: datetime | None,
    ) -> Any:
        if isinstance(value, list):
            return {
                "schema_version": "external-calendar-1.0",
                "updated_at": (
                    source_timestamp.isoformat() if source_timestamp else None
                ),
                "provider": self.settings.news_provider_name,
                "events": value,
            }
        if isinstance(value, Mapping):
            adapted = dict(value)
            adapted.setdefault("provider", self.settings.news_provider_name)
            if source_timestamp and not any(
                adapted.get(key) is not None
                for key in ("updated_at", "generated_at", "last_updated", "timestamp")
            ):
                adapted["updated_at"] = source_timestamp.isoformat()
            return adapted
        return value

    async def read(self) -> tuple[Any, SourceMeta]:
        now = self._now()
        if not self.configured:
            return None, SourceMeta(
                key="news_remote",
                received_at=now,
                status="unavailable",
                error="AI_SCALPER_NEWS_API_URL belum dikonfigurasi.",
            )

        headers = {
            "Accept": "application/json",
            "User-Agent": "AI_SCALPER-Dashboard/1.0 (paper-monitoring)",
        }
        if self.settings.news_api_key:
            headers[self.settings.news_api_key_header] = self.settings.news_api_key
        self.last_fetch_monotonic = time.monotonic()
        try:
            async with httpx.AsyncClient(
                timeout=self.settings.news_timeout_seconds,
                follow_redirects=False,
                transport=self.transport,
            ) as client:
                response = await client.get(self.settings.news_api_url or "", headers=headers)
                response.raise_for_status()
                value = response.json()
            source_timestamp = (
                self._source_timestamp(value)
                or self._header_timestamp(response.headers)
            )
            value = self._adapt_payload(value, source_timestamp)
            age = (
                max(0.0, (now - source_timestamp).total_seconds())
                if source_timestamp
                else None
            )
            stale = bool(
                age is not None and age > self.settings.news_stale_after_seconds
            )
            self.last_value = value
            self.last_meta = SourceMeta(
                key="news_remote",
                path=self.settings.news_api_url,
                status=(
                    "partial"
                    if source_timestamp is None
                    else "stale"
                    if stale
                    else "fresh"
                ),
                source_timestamp=source_timestamp,
                received_at=now,
                age_seconds=age,
                stale=stale,
                size_bytes=len(response.content),
                error=(
                    "Provider tidak memberikan source timestamp."
                    if source_timestamp is None
                    else None
                ),
            )
            if self._last_error:
                logger.info("Sumber news remote pulih")
            self._last_error = None
            return value, self.last_meta
        except (httpx.HTTPError, ValueError) as exc:
            error = f"News provider gagal: {type(exc).__name__}"
            if error != self._last_error:
                logger.warning(error)
            self._last_error = error
            if self.last_value is not None and self.last_meta is not None:
                age = max(
                    0.0,
                    (now - (self.last_meta.source_timestamp or now)).total_seconds(),
                )
                return self.last_value, self.last_meta.model_copy(
                    update={
                        "received_at": now,
                        "age_seconds": age,
                        "stale": True,
                        "status": "partial",
                        "from_last_known_good": True,
                        "error": error,
                    }
                )
            return None, SourceMeta(
                key="news_remote",
                path=self.settings.news_api_url,
                status="unavailable",
                received_at=now,
                stale=True,
                error=error,
            )
