from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from html.parser import HTMLParser
from time import monotonic
from typing import ClassVar
from zoneinfo import ZoneInfo

import httpx

from app.core.config import Settings
from app.providers.news.base import ProviderFetchError
from app.utils.datetime import parse_datetime

from .http_client import OfficialSourceHttpClient
from .parsing import html_to_text, normalize_space, slug, token_similarity


class _BeaScheduleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_table = False
        self.in_row = False
        self.current_cell: str | None = None
        self.cell_parts: list[str] = []
        self.row: dict[str, str] = {}
        self.rows: list[dict[str, str]] = []
        self.year: int | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        classes = set((attributes.get("class") or "").split())
        if tag == "table" and attributes.get("id") == "release-schedule-table":
            self.in_table = True
        elif self.in_table and tag == "tr":
            self.in_row = True
            self.row = {}
        elif self.in_table and self.in_row and tag in {"td", "th"}:
            if "scheduled-date" in classes:
                self.current_cell = "scheduled"
            elif "release-title" in classes:
                self.current_cell = "title"
            elif tag == "th":
                self.current_cell = "heading"
            else:
                self.current_cell = "other"
            self.cell_parts = []

    def handle_endtag(self, tag: str) -> None:
        if self.in_table and self.in_row and tag in {"td", "th"} and self.current_cell:
            value = normalize_space(" ".join(self.cell_parts))
            if self.current_cell in {"scheduled", "title"}:
                self.row[self.current_cell] = value
            elif self.current_cell == "heading" and (match := re.search(r"\b(20\d{2})\b", value)):
                self.year = int(match.group(1))
            self.current_cell = None
            self.cell_parts = []
        elif self.in_table and tag == "tr":
            if self.row.get("scheduled") and self.row.get("title"):
                self.rows.append(dict(self.row))
            self.in_row = False
            self.row = {}
        elif tag == "table" and self.in_table:
            self.in_table = False

    def handle_data(self, data: str) -> None:
        if self.current_cell and (text := normalize_space(data)):
            self.cell_parts.append(text)


class BeaCalendarProvider:
    name = "bea"
    display_name = "U.S. Bureau of Economic Analysis"
    official_domain: ClassVar[str | None] = "bea.gov"
    capabilities: ClassVar[list[str]] = [
        "official_schedule",
        "gdp",
        "personal_income",
        "trade_balance",
        "official_actuals",
    ]

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        now_provider: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings
        self.enabled = settings.economic_calendar_enabled and settings.economic_calendar_bea_enabled
        self.configured = self.enabled and settings.economic_calendar_external_requests_enabled
        self._now = now_provider or (lambda: datetime.now(UTC))
        self._client = OfficialSourceHttpClient(
            base_url="https://www.bea.gov",
            allowed_hosts={"www.bea.gov", "bea.gov"},
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
        response = await self._client.get("/news/schedule", accept="text/html,application/xhtml+xml")
        if response.content_type and "html" not in response.content_type:
            raise ProviderFetchError("BEA schedule returned an unsupported content type")
        parser = _BeaScheduleParser()
        parser.feed(response.content.decode("utf-8", errors="replace"))
        if parser.year is None or not parser.rows:
            raise ProviderFetchError("BEA release schedule table could not be parsed")
        zone = ZoneInfo("America/New_York")
        now = self._now()
        items: list[dict] = []
        for row in parser.rows:
            match = re.fullmatch(r"([A-Za-z]+\s+\d{1,2})\s+(\d{1,2}:\d{2}\s+[AP]M)", row["scheduled"])
            if not match:
                continue
            try:
                local = datetime.strptime(
                    f"{match.group(1)} {parser.year} {match.group(2)}", "%B %d %Y %I:%M %p"
                ).replace(tzinfo=zone)
            except ValueError:
                continue
            scheduled = local.astimezone(UTC)
            if not start_time <= scheduled <= end_time:
                continue
            title = row["title"]
            reference = title.split(",", 1)[1].strip() if "," in title else None
            items.append(
                {
                    "id": f"bea-{slug(title, maximum=96)}",
                    "event_name": title,
                    "short_name": title.split(",", 1)[0],
                    "country": "United States",
                    "country_code": "US",
                    "currency": "USD",
                    "scheduled_at": scheduled,
                    "reference_period": reference,
                    "source": self.display_name,
                    "source_type": "OFFICIAL",
                    "source_url": "https://www.bea.gov/news/schedule",
                    "verified": True,
                    "verified_at": now,
                    "last_checked_at": now,
                    "updated_at": now,
                    "forecast": None,
                    "forecast_source": None,
                    "metadata": {"schedule_precision": "DATETIME", "source_timezone": "America/New_York"},
                }
            )
        return items

    async def fetch_release(self, *, event: dict) -> dict | None:
        if not self.configured or self._now() < event["scheduled_at"]:
            return None
        listing = await self._client.get("/news/current-releases", accept="text/html,application/xhtml+xml")
        html = listing.content.decode("utf-8", errors="replace")
        candidates = re.findall(
            r'<a[^>]+href="([^"?]+/news/20\d{2}/[^"?]+)"[^>]*>(.*?)</a>',
            html,
            flags=re.IGNORECASE | re.DOTALL,
        )
        best: tuple[float, str, str] | None = None
        for href, label_html in candidates:
            label = html_to_text(label_html)
            score = token_similarity(event["event_name"], label)
            if self._reference_matches(event.get("reference_period"), f"{label} {href}"):
                score += 0.3
            if best is None or score > best[0]:
                best = score, href, label
        if best is None or best[0] < 0.35:
            return None
        path = best[1]
        if path.startswith("https://www.bea.gov"):
            path = path.removeprefix("https://www.bea.gov")
        if not path.startswith("/"):
            return None
        response = await self._client.get(path, accept="text/html,application/xhtml+xml")
        release_html = response.content.decode("utf-8", errors="replace")
        text = normalize_space(html_to_text(release_html))
        if not self._reference_matches(event.get("reference_period"), text):
            return None
        source_published_at = self._source_published_at(release_html)
        scheduled = event.get("scheduled_at")
        if (
            source_published_at is not None
            and isinstance(scheduled, datetime)
            and abs((source_published_at.date() - scheduled.astimezone(UTC).date()).days) > 1
        ):
            return None
        result = self._extract_actual(event["event_name"], text)
        if result is None:
            return None
        return {
            **result,
            "source_url": f"https://www.bea.gov{path}",
            "last_checked_at": self._now(),
            "updated_at": self._now(),
            "source_published_at": source_published_at,
            "reference_period": event.get("reference_period"),
            "verified": True,
        }

    @staticmethod
    def _reference_matches(reference: object, text: str) -> bool:
        if not isinstance(reference, str) or not reference.strip():
            return True
        reference_text = reference.lower()
        haystack = text.lower()
        year = re.search(r"\b20\d{2}\b", reference_text)
        if year and year.group(0) not in haystack:
            return False
        quarter_aliases = (
            ("q1", "first quarter", "1st quarter"),
            ("q2", "second quarter", "2nd quarter"),
            ("q3", "third quarter", "3rd quarter"),
            ("q4", "fourth quarter", "4th quarter"),
        )
        for aliases in quarter_aliases:
            if any(alias in reference_text for alias in aliases):
                return any(alias in haystack for alias in aliases)
        return True

    @staticmethod
    def _source_published_at(html: str) -> datetime | None:
        patterns = (
            r'<meta[^>]+(?:property|name)=["\'](?:article:published_time|date|datePublished)["\'][^>]+content=["\']([^"\']+)',
            r'["\']datePublished["\']\s*:\s*["\']([^"\']+)',
            r'<time[^>]+datetime=["\']([^"\']+)',
        )
        for pattern in patterns:
            match = re.search(pattern, html, flags=re.IGNORECASE)
            parsed = parse_datetime(match.group(1)) if match else None
            if parsed is not None:
                return parsed
        return None

    @staticmethod
    def _extract_actual(event_name: str, text: str) -> dict | None:
        lowered = event_name.lower()
        if "gdp" in lowered or "gross domestic product" in lowered:
            match = re.search(
                r"real gross domestic product \(gdp\) (increased|decreased) at an annual rate of ([\d.]+) percent",
                text,
                flags=re.IGNORECASE,
            )
            if not match:
                return None
            value = float(match.group(2)) * (-1 if match.group(1).lower() == "decreased" else 1)
            previous_match = re.search(
                r"in the (?:first|second|third|fourth) quarter[^.]*? (increased|decreased) ([\d.]+) percent",
                text[match.end() : match.end() + 600],
                flags=re.IGNORECASE,
            )
            previous = None
            if previous_match:
                previous = float(previous_match.group(2)) * (
                    -1 if previous_match.group(1).lower() == "decreased" else 1
                )
            return {"actual": value, "actual_raw": match.group(0), "previous": previous, "unit": "% SAAR"}
        if "personal income" in lowered:
            match = re.search(
                r"personal income (increased|decreased) [^()]{0,120}\(([\d.]+) percent at a monthly rate\)",
                text,
                flags=re.IGNORECASE,
            )
            if match:
                value = float(match.group(2)) * (-1 if match.group(1).lower() == "decreased" else 1)
                return {"actual": value, "actual_raw": match.group(0), "unit": "% m/m"}
        if "trade" in lowered:
            match = re.search(r"(?:goods and services )?(deficit|surplus) was \$([\d.]+) billion", text, re.I)
            if match:
                value = float(match.group(2)) * (-1 if match.group(1).lower() == "deficit" else 1)
                return {"actual": value, "actual_raw": match.group(0), "unit": "USD bn"}
        return None

    async def health_check(self) -> dict:
        started = monotonic()
        try:
            rows = await self.fetch_schedule(
                start_time=self._now(),
                end_time=self._now().replace(year=self._now().year + 1),
            )
            return {"healthy": True, "event_count": len(rows), "latency_ms": (monotonic() - started) * 1000}
        except ProviderFetchError as exc:
            return {"healthy": False, "error": str(exc), "latency_ms": (monotonic() - started) * 1000}
