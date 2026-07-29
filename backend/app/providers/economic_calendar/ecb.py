from __future__ import annotations

import re
from datetime import UTC, datetime
from time import monotonic
from typing import ClassVar
from zoneinfo import ZoneInfo

import httpx

from app.core.config import Settings
from app.providers.news.base import ProviderFetchError

from .http_client import OfficialSourceHttpClient
from .parsing import html_to_text, slug


class EcbCalendarProvider:
    name = "ecb"
    display_name = "European Central Bank"
    official_domain: ClassVar[str | None] = "ecb.europa.eu"
    capabilities: ClassVar[list[str]] = ["official_schedule", "central_bank", "interest_rate", "speeches"]

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.enabled = settings.economic_calendar_enabled and settings.economic_calendar_ecb_enabled
        self.configured = self.enabled and settings.economic_calendar_external_requests_enabled
        self._client = OfficialSourceHttpClient(
            base_url="https://www.ecb.europa.eu",
            allowed_hosts={"www.ecb.europa.eu", "ecb.europa.eu"},
            timeout_seconds=settings.economic_calendar_request_timeout_seconds,
            max_response_bytes=settings.economic_calendar_max_response_bytes,
            user_agent=settings.economic_calendar_user_agent,
            transport=transport,
        )

    async def fetch_schedule(
        self,
        *,
        start_time: datetime,
        end_time: datetime,
        currencies: list[str] | None = None,
    ) -> list[dict]:
        if not self.configured or (currencies and "EUR" not in {item.upper() for item in currencies}):
            return []
        response = await self._client.get(
            "/press/calendars/weekly/html/index.en.html", accept="text/html,application/xhtml+xml"
        )
        if response.content_type and "html" not in response.content_type:
            raise ProviderFetchError("ECB weekly schedule returned an unsupported content type")
        text = html_to_text(response.content.decode("utf-8", errors="replace"))
        pattern = re.compile(
            r"(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday),\s*"
            r"(\d{1,2}\s+[A-Za-z]+\s+20\d{2})\s*\n(?:.*?\n){0,3}?Event:\s*([^\n]+)"
            r"(?:\s*\nTime:\s*(\d{1,2}:\d{2})\s*(?:CET|CEST))?",
            flags=re.IGNORECASE,
        )
        now = datetime.now(UTC)
        zone = ZoneInfo("Europe/Paris")
        rows: list[dict] = []
        for match in pattern.finditer(text):
            try:
                day = datetime.strptime(match.group(1), "%d %B %Y")
            except ValueError:
                continue
            precision = "DATE"
            if match.group(3):
                hour, minute = (int(value) for value in match.group(3).split(":"))
                day = day.replace(hour=hour, minute=minute)
                precision = "DATETIME"
            scheduled = day.replace(tzinfo=zone).astimezone(UTC)
            if not start_time <= scheduled <= end_time:
                continue
            name = match.group(2).strip()
            rows.append(
                {
                    "id": f"ecb-{scheduled.date().isoformat()}-{slug(name, maximum=72)}",
                    "event_name": name,
                    "country": "Eurozone",
                    "country_code": "EU",
                    "currency": "EUR",
                    "scheduled_at": scheduled,
                    "source": self.display_name,
                    "source_type": "OFFICIAL",
                    "source_url": "https://www.ecb.europa.eu/press/calendars/weekly/html/index.en.html",
                    "verified": True,
                    "verified_at": now,
                    "last_checked_at": now,
                    "updated_at": now,
                    "forecast": None,
                    "forecast_source": None,
                    "metadata": {"schedule_precision": precision, "source_timezone": "Europe/Paris"},
                }
            )
        if "Weekly schedule" not in text:
            raise ProviderFetchError("ECB weekly schedule could not be parsed")
        return rows

    async def fetch_release(self, *, event: dict) -> dict | None:
        return None

    async def health_check(self) -> dict:
        started = monotonic()
        try:
            now = datetime.now(UTC)
            rows = await self.fetch_schedule(
                start_time=now.replace(hour=0, minute=0, second=0, microsecond=0),
                end_time=now.replace(hour=0, minute=0, second=0, microsecond=0)
                + self.settings.economic_calendar_health_window,
            )
            return {"healthy": True, "event_count": len(rows), "latency_ms": (monotonic() - started) * 1000}
        except ProviderFetchError as exc:
            return {"healthy": False, "error": str(exc), "latency_ms": (monotonic() - started) * 1000}
