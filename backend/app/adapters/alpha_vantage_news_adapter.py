from __future__ import annotations

from datetime import UTC, datetime

from app.adapters.news_adapter import symbol_components

TOPIC_CATEGORY = {
    "economy_monetary": "INTEREST_RATE",
    "economy_macro": "GDP",
    "economy_fiscal": "GENERAL",
    "energy_transportation": "ENERGY",
    "blockchain": "CRYPTO",
    "financial_markets": "MARKET_ANALYSIS",
}


def _number(value: object) -> float | None:
    try:
        return float(str(value)) if value is not None else None
    except (TypeError, ValueError):
        return None


def _published(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    for fmt in ("%Y%m%dT%H%M%S", "%Y%m%dT%H%M"):
        try:
            return datetime.strptime(value.rstrip("Z"), fmt).replace(tzinfo=UTC).isoformat()
        except ValueError:
            continue
    return value


class AlphaVantageNewsAdapter:
    def normalize(self, raw: dict, *, known_symbols: list[str]) -> dict:
        symbols: set[str] = set()
        currencies: set[str] = set()
        ticker_value = raw.get("ticker_sentiment")
        ticker_rows: list[object] = ticker_value if isinstance(ticker_value, list) else []
        for item in ticker_rows:
            if not isinstance(item, dict):
                continue
            ticker = str(item.get("ticker") or "").upper()
            if ticker.startswith("FOREX:"):
                currencies.add(ticker.split(":", 1)[1])
            elif ticker.startswith("CRYPTO:"):
                asset = ticker.split(":", 1)[1]
                symbols.update(symbol for symbol in known_symbols if symbol.upper().startswith(asset))
            elif ticker in known_symbols:
                symbols.add(ticker)
        for symbol in known_symbols:
            _, components = symbol_components(symbol)
            if components & currencies:
                symbols.add(symbol)
        topic_value = raw.get("topics")
        topic_rows: list[object] = topic_value if isinstance(topic_value, list) else []
        topics = [str(item.get("topic")) for item in topic_rows if isinstance(item, dict) and item.get("topic")]
        raw_score = _number(raw.get("overall_sentiment_score"))
        raw_label = raw.get("overall_sentiment_label")
        provider_sentiment = (
            {
                "provider": "alpha_vantage",
                "raw_label": raw_label,
                "raw_score": raw_score,
                "normalized_score": max(-1.0, min(1.0, raw_score)) if raw_score is not None else None,
                "normalized_confidence": min(1.0, abs(raw_score) + 0.35) if raw_score is not None else None,
            }
            if raw_score is not None or raw_label is not None
            else None
        )
        category = next((TOPIC_CATEGORY[item] for item in topics if item in TOPIC_CATEGORY), None)
        author_value = raw.get("authors")
        authors: list[object] = author_value if isinstance(author_value, list) else []
        return {
            "id": raw.get("id") or raw.get("url"),
            "title": raw.get("title"),
            "summary": raw.get("summary"),
            "url": raw.get("url"),
            "image_url": raw.get("banner_image"),
            "author": ", ".join(str(item) for item in authors if item) or None,
            "published_at": _published(raw.get("time_published")),
            "source": raw.get("source"),
            "source_domain": raw.get("source_domain"),
            "language": "en",
            "topics": topics,
            "category": category,
            "symbols": sorted(symbols),
            "currencies": sorted(currencies),
            "provider_sentiment": provider_sentiment,
            "provider_metadata": {"ticker_sentiment": ticker_rows},
        }
