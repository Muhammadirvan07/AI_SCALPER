from __future__ import annotations

from datetime import UTC, datetime
from typing import ClassVar


class GdeltNewsAdapter:
    LANGUAGE_CODES: ClassVar[dict[str, str]] = {
        "english": "en",
        "indonesian": "id",
        "japanese": "ja",
        "en": "en",
        "id": "id",
        "ja": "ja",
    }

    @staticmethod
    def _published(value: object) -> str | None:
        if not isinstance(value, str):
            return None
        for fmt in ("%Y%m%dT%H%M%SZ", "%Y%m%d%H%M%S"):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=UTC).isoformat()
            except ValueError:
                continue
        return value

    def normalize(self, raw: dict, *, known_symbols: list[str]) -> dict:
        del known_symbols
        topic = str(raw.get("_query_topic") or "general").lower()
        return {
            "id": raw.get("url"),
            "title": raw.get("title"),
            "summary": None,
            "url": raw.get("url"),
            "image_url": raw.get("socialimage"),
            "published_at": self._published(raw.get("seendate")),
            "source": raw.get("domain"),
            "language": self.LANGUAGE_CODES.get(
                str(raw.get("language") or "").lower(), str(raw.get("language") or "").lower()
            ),
            "countries": [raw.get("sourcecountry")] if raw.get("sourcecountry") else [],
            "topics": [topic],
            "category": topic.upper()
            if topic.upper()
            in {"INFLATION", "EMPLOYMENT", "GDP", "FOREX", "GOLD", "SILVER", "ENERGY", "GEOPOLITICS", "REGULATION"}
            else "CENTRAL_BANK"
            if topic in {"central_bank", "interest_rate"}
            else "CRYPTO"
            if topic in {"bitcoin", "cryptocurrency"}
            else "GENERAL",
            "is_breaking": bool(raw.get("_breaking")),
        }
