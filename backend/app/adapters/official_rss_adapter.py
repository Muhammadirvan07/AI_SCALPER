from __future__ import annotations


class OfficialRssAdapter:
    def normalize(self, raw: dict, *, known_symbols: list[str]) -> dict:
        del known_symbols
        return {
            "id": raw.get("id") or raw.get("guid"),
            "title": raw.get("title"),
            "summary": raw.get("summary") or raw.get("description"),
            "url": raw.get("url") or raw.get("link"),
            "published_at": raw.get("published_at"),
            "author": raw.get("author"),
            "source": raw.get("source"),
            "language": raw.get("language") or "en",
            "countries": raw.get("countries") or [],
            "currencies": raw.get("currencies") or [],
            "category": (raw.get("categories") or [None])[0],
            "topics": raw.get("categories") or [],
        }
