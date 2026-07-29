from __future__ import annotations

from datetime import UTC, datetime


class FinnhubNewsAdapter:
    def normalize(self, raw: dict, *, known_symbols: list[str]) -> dict:
        related = str(raw.get("related") or "").upper()
        symbols = sorted(symbol for symbol in known_symbols if symbol in related)
        timestamp = raw.get("datetime")
        published = None
        if isinstance(timestamp, int | float):
            published = datetime.fromtimestamp(timestamp, tz=UTC).isoformat()
        category = str(raw.get("category") or "").upper()
        category = "CRYPTO" if category == "CRYPTO" else "FOREX" if category == "FOREX" else "GENERAL"
        return {
            "id": raw.get("id"),
            "title": raw.get("headline"),
            "summary": raw.get("summary"),
            "url": raw.get("url"),
            "image_url": raw.get("image"),
            "published_at": published,
            "source": raw.get("source"),
            "language": "en",
            "category": category,
            "symbols": symbols,
        }

    def normalize_calendar(self, raw: dict, *, known_symbols: list[str]) -> dict:
        del known_symbols
        return {
            "id": raw.get("id") or raw.get("eventId"),
            "event_name": raw.get("event") or raw.get("name"),
            "country": raw.get("country"),
            "currency": raw.get("currency"),
            "scheduled_at": raw.get("time") or raw.get("date"),
            "actual": raw.get("actual"),
            "forecast": raw.get("estimate") or raw.get("forecast"),
            "previous": raw.get("prev") or raw.get("previous"),
            "impact": raw.get("impact") or "UNKNOWN",
            "source_url": raw.get("url"),
        }
