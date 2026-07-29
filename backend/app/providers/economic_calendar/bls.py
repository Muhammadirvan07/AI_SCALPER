from __future__ import annotations

from datetime import UTC, datetime
from time import monotonic
from typing import ClassVar
from zoneinfo import ZoneInfo

import httpx

from app.core.config import Settings
from app.providers.news.base import ProviderFetchError

from .http_client import OfficialSourceHttpClient
from .parsing import slug


def _unfold_ics(value: str) -> list[str]:
    lines: list[str] = []
    for line in value.replace("\r\n", "\n").split("\n"):
        if line.startswith((" ", "\t")) and lines:
            lines[-1] += line[1:]
        else:
            lines.append(line)
    return lines


def _parse_ics_datetime(key: str, value: str) -> datetime | None:
    zone = ZoneInfo("America/New_York")
    if "TZID=" in key:
        timezone = key.split("TZID=", 1)[1].split(";", 1)[0].split(":", 1)[0]
        try:
            zone = ZoneInfo(timezone)
        except (KeyError, ValueError):
            return None
    for pattern in ("%Y%m%dT%H%M%S", "%Y%m%dT%H%M", "%Y%m%d"):
        try:
            parsed = datetime.strptime(value.rstrip("Z"), pattern)
        except ValueError:
            continue
        if value.endswith("Z"):
            return parsed.replace(tzinfo=UTC)
        return parsed.replace(tzinfo=zone).astimezone(UTC)
    return None


class BlsCalendarProvider:
    name = "bls"
    display_name = "U.S. Bureau of Labor Statistics"
    official_domain: ClassVar[str | None] = "bls.gov"
    capabilities: ClassVar[list[str]] = ["official_schedule", "inflation", "employment", "official_actuals"]

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.enabled = settings.economic_calendar_enabled and settings.economic_calendar_bls_enabled
        self.configured = self.enabled and settings.economic_calendar_external_requests_enabled
        self._client = OfficialSourceHttpClient(
            base_url="https://www.bls.gov",
            allowed_hosts={"www.bls.gov", "bls.gov"},
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
        if not self.configured or (currencies and "USD" not in {item.upper() for item in currencies}):
            return []
        response = await self._client.get(
            "/schedule/news_release/bls.ics", accept="text/calendar,text/plain,application/octet-stream"
        )
        allowed = {"text/calendar", "text/plain", "application/octet-stream", ""}
        if response.content_type not in allowed:
            raise ProviderFetchError("BLS calendar returned an unsupported content type")
        events: list[dict[str, str]] = []
        current: dict[str, str] | None = None
        for line in _unfold_ics(response.content.decode("utf-8-sig", errors="replace")):
            if line == "BEGIN:VEVENT":
                current = {}
            elif line == "END:VEVENT" and current is not None:
                events.append(current)
                current = None
            elif current is not None and ":" in line:
                key, value = line.split(":", 1)
                current[key] = value.replace("\\,", ",").replace("\\n", " ")
        now = datetime.now(UTC)
        rows: list[dict] = []
        for item in events:
            dt_key = next((key for key in item if key.startswith("DTSTART")), None)
            scheduled = _parse_ics_datetime(dt_key or "", item.get(dt_key or "", ""))
            title = item.get("SUMMARY", "").strip()
            if scheduled is None or not title or not start_time <= scheduled <= end_time:
                continue
            rows.append(
                {
                    "id": item.get("UID") or f"bls-{slug(title, maximum=96)}",
                    "event_name": title,
                    "description": item.get("DESCRIPTION"),
                    "country": "United States",
                    "country_code": "US",
                    "currency": "USD",
                    "scheduled_at": scheduled,
                    "source": self.display_name,
                    "source_type": "OFFICIAL",
                    "source_url": item.get("URL") or "https://www.bls.gov/schedule/",
                    "verified": True,
                    "verified_at": now,
                    "last_checked_at": now,
                    "updated_at": now,
                    "forecast": None,
                    "forecast_source": None,
                    "metadata": {"schedule_precision": "DATETIME", "source_timezone": "America/New_York"},
                }
            )
        if events and not rows:
            return []
        if not events:
            raise ProviderFetchError("BLS iCalendar response did not contain events")
        return rows

    async def fetch_release(self, *, event: dict) -> dict | None:
        # BLS schedule and release pages remain authoritative; no value is inferred
        # until a dedicated series mapping can be verified for that event.
        return None

    async def health_check(self) -> dict:
        started = monotonic()
        try:
            now = datetime.now(UTC)
            rows = await self.fetch_schedule(start_time=now, end_time=now.replace(year=now.year + 1))
            return {"healthy": True, "event_count": len(rows), "latency_ms": (monotonic() - started) * 1000}
        except ProviderFetchError as exc:
            return {"healthy": False, "error": str(exc), "latency_ms": (monotonic() - started) * 1000}
