from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from app.adapters.news_adapter import classify_category, clean_text
from app.schemas.news import NewsCategory

_TRACKING_PARAMETERS = {"ref", "source", "feed", "campaign", "from", "utm_campaign", "utm_medium", "utm_source"}


class InvestingRssAdapter:
    """Maps provider RSS fields into the stable, provider-neutral news contract."""

    @staticmethod
    def _url(value: object) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return None
        absolute = urljoin("https://www.investing.com/", value.strip())
        parsed = urlparse(absolute)
        host = (parsed.hostname or "").lower().strip(".")
        if parsed.scheme != "https" or not (host == "investing.com" or host.endswith(".investing.com")):
            return None
        query = urlencode(
            [
                (key, item)
                for key, item in parse_qsl(parsed.query, keep_blank_values=True)
                if key.lower() not in _TRACKING_PARAMETERS
            ]
        )
        return urlunparse(("https", parsed.netloc.lower(), parsed.path or "/", "", query, ""))

    @staticmethod
    def _category(raw: dict, text: str) -> NewsCategory:
        values = {str(item).upper() for item in raw.get("categories", []) if item}
        if "CRYPTO" in values:
            return NewsCategory.CRYPTO
        if "FOREX" in values:
            return NewsCategory.FOREX
        if "EQUITIES" in values:
            return NewsCategory.EQUITIES
        if "CENTRAL_BANK" in values or "INTEREST_RATE" in values:
            return NewsCategory.CENTRAL_BANK
        if "COMMODITIES" in values:
            inferred = classify_category(text)
            return (
                inferred
                if inferred in {NewsCategory.GOLD, NewsCategory.SILVER, NewsCategory.ENERGY}
                else NewsCategory.COMMODITIES
            )
        return classify_category(text)

    def normalize(self, raw: dict, *, known_symbols: list[str]) -> dict:
        del known_symbols
        title = clean_text(raw.get("title"), maximum=300)
        summary = clean_text(raw.get("summary") or raw.get("description"), maximum=700)
        url = self._url(raw.get("url") or raw.get("link"))
        raw_id = raw.get("id") or raw.get("guid") or url
        feed_id = clean_text(raw.get("feed_id"), maximum=80)
        text = f"{title or ''} {summary or ''}"
        category = self._category(raw, text)
        topics = list(dict.fromkeys([*(str(item) for item in raw.get("topics", []) if item), category.value]))
        return {
            "id": f"{feed_id}:{raw_id}" if feed_id and raw_id else raw_id,
            "title": title,
            "summary": summary,
            "url": url,
            "image_url": None,
            "published_at": raw.get("published_at"),
            "author": clean_text(raw.get("author"), maximum=120),
            "source": "Investing.com",
            "language": raw.get("language") or "en",
            "countries": raw.get("countries") or [],
            "currencies": raw.get("currencies") or [],
            "symbols": raw.get("symbols") or [],
            "category": category.value,
            "topics": topics,
            "is_breaking": bool(raw.get("is_breaking_candidate")),
            "feed_id": raw.get("feed_id"),
            "feed_name": raw.get("feed_name"),
        }
