from __future__ import annotations

import re
from datetime import UTC, datetime
from time import monotonic
from typing import ClassVar

import httpx

from app.core.config import Settings
from app.providers.news.base import ProviderFetchError

from .http_client import OfficialSourceHttpClient
from .parsing import html_to_text

MONTHS = {
    "January": 1,
    "February": 2,
    "March": 3,
    "April": 4,
    "May": 5,
    "June": 6,
    "July": 7,
    "August": 8,
    "September": 9,
    "October": 10,
    "November": 11,
    "December": 12,
}


class FederalReserveCalendarProvider:
    name = "federal_reserve"
    display_name = "Federal Reserve"
    official_domain: ClassVar[str | None] = "federalreserve.gov"
    capabilities: ClassVar[list[str]] = ["official_schedule", "central_bank", "interest_rate", "official_actuals"]

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.enabled = settings.economic_calendar_enabled and settings.economic_calendar_federal_reserve_enabled
        self.configured = self.enabled and settings.economic_calendar_external_requests_enabled
        self._client = OfficialSourceHttpClient(
            base_url="https://www.federalreserve.gov",
            allowed_hosts={"www.federalreserve.gov", "federalreserve.gov"},
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
        response = await self._client.get("/monetarypolicy/fomccalendars.htm", accept="text/html,application/xhtml+xml")
        if response.content_type and "html" not in response.content_type:
            raise ProviderFetchError("Federal Reserve calendar returned an unsupported content type")
        html = response.content.decode("utf-8-sig", errors="replace")
        items: list[dict] = []
        now = datetime.now(UTC)
        for year in range(start_time.year, end_time.year + 1):
            marker = re.search(rf"{year}\s+FOMC\s+Meetings", html, flags=re.IGNORECASE)
            if marker is None:
                continue
            following_year = re.search(rf"{year - 1}\s+FOMC\s+Meetings", html[marker.end() :], re.I)
            end_index = marker.end() + following_year.start() if following_year else len(html)
            block = html[marker.end() : end_index]
            matches = list(
                re.finditer(
                    r"fomc-meeting__month[^>]*>\s*<strong>([^<]+)</strong>.*?"
                    r"fomc-meeting__date[^>]*>([^<]+)</div>",
                    block,
                    flags=re.IGNORECASE | re.DOTALL,
                )
            )
            for index, match in enumerate(matches):
                month_text = match.group(1).strip()
                date_text = match.group(2).strip()
                month_name = month_text.split("/", 1)[-1]
                month = MONTHS.get(month_name)
                day_numbers = [int(value) for value in re.findall(r"\d{1,2}", date_text)]
                if month is None or not day_numbers:
                    continue
                day = day_numbers[-1]
                try:
                    scheduled = datetime(year, month, day, tzinfo=UTC)
                except ValueError:
                    continue
                if not start_time <= scheduled <= end_time:
                    continue
                row_end = matches[index + 1].start() if index + 1 < len(matches) else len(block)
                row_html = block[match.start() : row_end]
                statement = re.search(r'href="([^\"]*pressreleases/monetary\d+[a-z]?\.htm)"', row_html, re.IGNORECASE)
                statement_url = None
                if statement:
                    statement_url = statement.group(1)
                    if statement_url.startswith("/"):
                        statement_url = f"https://www.federalreserve.gov{statement_url}"
                items.append(
                    {
                        "id": f"federal-reserve-{year}-{month:02d}",
                        "event_name": "Federal Open Market Committee Rate Decision",
                        "short_name": "FOMC Rate Decision",
                        "description": "Scheduled conclusion of the Federal Open Market Committee meeting.",
                        "country": "United States",
                        "country_code": "US",
                        "currency": "USD",
                        "category": "INTEREST_RATE",
                        "scheduled_at": scheduled,
                        "source": self.display_name,
                        "source_type": "OFFICIAL",
                        "source_url": "https://www.federalreserve.gov/monetarypolicy/fomccalendars.htm",
                        "verified": True,
                        "verified_at": now,
                        "last_checked_at": now,
                        "updated_at": now,
                        "forecast": None,
                        "forecast_source": None,
                        "metadata": {
                            "schedule_precision": "DATE",
                            "statement_url": statement_url,
                            "meeting_date_text": f"{month_text} {date_text}",
                            "summary_of_economic_projections": "*" in date_text,
                        },
                    }
                )
        if not items and start_time.year <= datetime.now(UTC).year <= end_time.year:
            raise ProviderFetchError("Federal Reserve FOMC schedule could not be parsed")
        return items

    async def fetch_release(self, *, event: dict) -> dict | None:
        metadata = event.get("metadata") or {}
        statement_url = metadata.get("statement_url")
        if not self.configured or not statement_url or datetime.now(UTC) < event["scheduled_at"]:
            return None
        prefix = "https://www.federalreserve.gov"
        if not str(statement_url).startswith(prefix):
            return None
        path = str(statement_url).removeprefix(prefix)
        response = await self._client.get(path, accept="text/html,application/xhtml+xml")
        text = " ".join(html_to_text(response.content.decode("utf-8-sig", errors="replace")).split())
        match = re.search(
            r"target range for the federal funds rate at (\d+(?:\.\d+)?) to (\d+(?:\.\d+)?) percent",
            text,
            flags=re.IGNORECASE,
        )
        if not match:
            return None
        actual = f"{match.group(1)}-{match.group(2)}"
        return {
            "actual": actual,
            "actual_raw": match.group(0),
            "unit": "% target range",
            "source_url": statement_url,
            "verified": True,
            "last_checked_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
            "metadata": {**metadata, "release_verified_from_statement": True},
        }

    async def health_check(self) -> dict:
        started = monotonic()
        try:
            now = datetime.now(UTC)
            rows = await self.fetch_schedule(start_time=now, end_time=now.replace(year=now.year + 1))
            return {"healthy": True, "event_count": len(rows), "latency_ms": (monotonic() - started) * 1000}
        except ProviderFetchError as exc:
            return {"healthy": False, "error": str(exc), "latency_ms": (monotonic() - started) * 1000}
