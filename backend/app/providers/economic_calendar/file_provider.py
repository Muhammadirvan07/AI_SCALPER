from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import ClassVar

from app.core.config import Settings
from app.providers.news.base import ProviderFetchError


class FileEconomicCalendarProvider:
    name = "file"
    display_name = "Trusted Local Calendar File"
    official_domain: ClassVar[str | None] = None
    capabilities: ClassVar[list[str]] = ["local_file", "replay", "offline_fallback"]

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.path: Path | None = settings.economic_calendar_file_path
        self.enabled = settings.economic_calendar_enabled and settings.economic_calendar_file_provider_enabled
        self.configured = bool(self.enabled and self.path and self.path.is_file())

    async def fetch_schedule(
        self,
        *,
        start_time: datetime,
        end_time: datetime,
        currencies: list[str] | None = None,
    ) -> list[dict]:
        if not self.configured or self.path is None:
            return []
        stat = await asyncio.to_thread(self.path.stat)
        if stat.st_size > self.settings.economic_calendar_max_response_bytes:
            raise ProviderFetchError("Local calendar file exceeds the configured size limit")
        try:
            payload = await asyncio.to_thread(self.path.read_text, encoding="utf-8")
            decoded = json.loads(payload)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ProviderFetchError("Local calendar file is unavailable or invalid") from exc
        rows = decoded.get("events") if isinstance(decoded, dict) else decoded
        if not isinstance(rows, list) or any(not isinstance(item, dict) for item in rows):
            raise ProviderFetchError("Local calendar file must contain an events array")
        selected = {item.upper() for item in currencies or []}
        result: list[dict] = []
        for row in rows:
            copied = dict(row)
            currency = str(copied.get("currency") or "").upper()
            if selected and currency not in selected:
                continue
            copied.setdefault("source_type", "LOCAL_FILE")
            copied.setdefault("verified", False)
            result.append(copied)
        return result

    async def fetch_release(self, *, event: dict) -> dict | None:
        return None

    async def health_check(self) -> dict:
        return {
            "healthy": self.configured,
            "configured": self.configured,
            "source_available": bool(self.path and self.path.is_file()),
        }
