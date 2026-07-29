from __future__ import annotations

import hashlib
import html
import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse, urlunparse

from pydantic import ValidationError

from app.core.exceptions import InvalidDataFormatError
from app.schemas.news import (
    ImpactLevel,
    NewsArticle,
    NewsCategory,
    ProviderSentiment,
    RelevanceMatch,
    SentimentLabel,
    SentimentResult,
)
from app.utils.datetime import parse_datetime

_BLOCK_TAG_RE = re.compile(
    r"<(script|style|iframe|form)\b[^>]*>.*?</\1\s*>",
    flags=re.IGNORECASE | re.DOTALL,
)
_HTML_RE = re.compile(r"<[^>]+>")
_SPACE_RE = re.compile(r"\s+")
_SYMBOL_RE = re.compile(r"^[A-Z0-9]{3,16}$")

CURRENCIES = {
    "USD",
    "EUR",
    "GBP",
    "JPY",
    "AUD",
    "NZD",
    "CAD",
    "CHF",
    "CNY",
    "CNH",
    "HKD",
    "SGD",
    "NOK",
    "SEK",
    "DKK",
    "PLN",
    "CZK",
    "HUF",
    "TRY",
    "ZAR",
    "MXN",
    "BRL",
    "IDR",
    "INR",
}
CRYPTO_ASSETS = {"BTC", "ETH", "SOL", "XRP", "ADA", "DOGE", "BNB", "AVAX", "DOT", "LTC"}
METALS = {"XAU": "GOLD", "XAG": "SILVER", "XPT": "PLATINUM", "XPD": "PALLADIUM"}
TERM_CURRENCY = {
    "dollar": "USD",
    "greenback": "USD",
    "fed": "USD",
    "federal reserve": "USD",
    "euro": "EUR",
    "ecb": "EUR",
    "european central bank": "EUR",
    "sterling": "GBP",
    "pound": "GBP",
    "bank of england": "GBP",
    "boe": "GBP",
    "yen": "JPY",
    "bank of japan": "JPY",
    "boj": "JPY",
    "aussie": "AUD",
    "rba": "AUD",
    "kiwi": "NZD",
    "rbnz": "NZD",
    "loonie": "CAD",
    "bank of canada": "CAD",
    "boc": "CAD",
    "snb": "CHF",
    "yuan": "CNY",
}
CATEGORY_TERMS: list[tuple[NewsCategory, tuple[str, ...]]] = [
    (NewsCategory.CENTRAL_BANK, ("central bank", "federal reserve", "ecb", "boe", "boj", "rba", "snb")),
    (NewsCategory.INTEREST_RATE, ("interest rate", "rate decision", "rate hike", "rate cut", "monetary policy")),
    (NewsCategory.INFLATION, ("inflation", "consumer price", " cpi", "ppi", "price index")),
    (NewsCategory.EMPLOYMENT, ("employment", "unemployment", "nonfarm", " nfp", "payroll", "jobless")),
    (NewsCategory.GDP, ("gross domestic product", " gdp", "economic growth")),
    (NewsCategory.GOLD, ("gold", "xau")),
    (NewsCategory.SILVER, ("silver", "xag")),
    (NewsCategory.CRYPTO, ("crypto", "bitcoin", "ethereum", "blockchain", "btc", "eth")),
    (NewsCategory.ENERGY, ("oil", "brent", "wti", "natural gas", "opec", "energy")),
    (NewsCategory.GEOPOLITICS, ("war", "conflict", "sanction", "geopolit", "missile", "ceasefire")),
    (NewsCategory.REGULATION, ("regulation", "regulator", "sec ", "ban", "compliance")),
    (NewsCategory.EQUITIES, ("stocks", "equities", "shares", "s&p", "nasdaq", "dow jones")),
    (NewsCategory.FOREX, ("forex", "currency", "exchange rate", "fx market")),
    (NewsCategory.COMMODITIES, ("commodity", "commodities", "copper", "wheat")),
    (NewsCategory.MARKET_ANALYSIS, ("technical analysis", "market analysis", "outlook", "forecast")),
]


def clean_text(value: object, *, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    decoded = html.unescape(value)
    decoded = _BLOCK_TAG_RE.sub(" ", decoded)
    cleaned = _SPACE_RE.sub(" ", _HTML_RE.sub(" ", decoded)).strip()
    return cleaned[:maximum] or None


def canonical_url(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password:
        return None
    query = "&".join(part for part in parsed.query.split("&") if part and not part.lower().startswith("utm_"))
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", query, ""))


def classify_category(text: str, raw: object = None) -> NewsCategory:
    if isinstance(raw, str):
        normalized = raw.strip().upper().replace("-", "_").replace(" ", "_")
        try:
            return NewsCategory(normalized)
        except ValueError:
            pass
    lower = f" {text.lower()} "
    for category, terms in CATEGORY_TERMS:
        if any(term in lower for term in terms):
            return category
    return NewsCategory.GENERAL


def parse_news_datetime(value: object) -> datetime | None:
    parsed = parse_datetime(value)
    if parsed is not None or not isinstance(value, str):
        return parsed
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def symbol_components(symbol: str) -> tuple[set[str], set[str]]:
    normalized = re.sub(r"[^A-Z0-9]", "", symbol.upper())
    terms = {normalized}
    currencies: set[str] = set()
    if len(normalized) >= 6:
        left, right = normalized[:3], normalized[3:6]
        if left in CURRENCIES or left in CRYPTO_ASSETS or left in METALS:
            currencies.add(left)
        if right in CURRENCIES:
            currencies.add(right)
        if left in METALS:
            terms.add(METALS[left])
        if left in CRYPTO_ASSETS:
            terms.add("CRYPTO")
    return terms, currencies


class NewsAdapter:
    def normalize(self, raw: dict, *, provider: str, known_symbols: list[str], fetched_at: datetime) -> NewsArticle:
        title = clean_text(raw.get("title") or raw.get("headline") or raw.get("name"), maximum=300)
        url = canonical_url(raw.get("url") or raw.get("link") or raw.get("source_url"))
        if not title or not url:
            raise InvalidDataFormatError("News article requires a valid title and source URL")
        summary = clean_text(raw.get("summary") or raw.get("description") or raw.get("excerpt"), maximum=700)
        body = f"{title} {summary or ''}".lower()
        raw_symbols = raw.get("symbols") or raw.get("affected_symbols") or []
        if isinstance(raw_symbols, str):
            raw_symbols = [part.strip() for part in raw_symbols.split(",")]
        candidates = sorted({*known_symbols, *(str(item).upper() for item in raw_symbols if item)})
        relevance: list[RelevanceMatch] = []
        currencies = {str(item).upper() for item in (raw.get("currencies") or []) if item}
        for term, currency in TERM_CURRENCY.items():
            if term in body:
                currencies.add(currency)
        for symbol in candidates:
            if not _SYMBOL_RE.fullmatch(symbol):
                continue
            terms, components = symbol_components(symbol)
            direct = 1.0 if symbol.lower() in body else 0.0
            matched = sorted(term for term in terms if term.lower() in body)
            currency_matches = sorted(
                currency
                for currency in components
                if currency in currencies or re.search(rf"\b{re.escape(currency.lower())}\b", body)
            )
            score = min(1.0, direct * 0.55 + min(0.3, len(currency_matches) * 0.15) + min(0.15, len(matched) * 0.075))
            if score > 0:
                relevance.append(
                    RelevanceMatch(
                        symbol=symbol,
                        relevance_score=round(score, 4),
                        matched_terms=sorted({*matched, *currency_matches}),
                        breakdown={
                            "direct_symbol": direct * 0.55,
                            "currency": min(0.3, len(currency_matches) * 0.15),
                            "entity": min(0.15, len(matched) * 0.075),
                        },
                    )
                )
        source = clean_text(raw.get("source") or raw.get("publisher"), maximum=120)
        domain = urlparse(url).hostname
        published = parse_news_datetime(
            raw.get("published_at") or raw.get("published") or raw.get("pubDate") or raw.get("timestamp")
        )
        raw_id = clean_text(raw.get("id") or raw.get("guid") or raw.get("provider_id"), maximum=200)
        article_id = raw_id or hashlib.sha256(f"{provider}|{url}|{title.lower()}".encode()).hexdigest()[:24]
        language = str(raw.get("language") or "").strip().lower()
        raw_topics = raw.get("topics")
        raw_countries = raw.get("countries")
        topics: list[object] = list(raw_topics) if isinstance(raw_topics, list) else []
        countries: list[object] = list(raw_countries) if isinstance(raw_countries, list) else []
        image_url = canonical_url(raw.get("image_url") or raw.get("image"))
        category = classify_category(f"{title} {summary or ''}", raw.get("category"))
        provider_sentiment = None
        if isinstance(raw.get("provider_sentiment"), dict):
            try:
                provider_sentiment = ProviderSentiment.model_validate(raw["provider_sentiment"])
            except ValidationError:
                provider_sentiment = None
        try:
            return NewsArticle(
                id=f"{provider}:{article_id}",
                provider=provider,
                source=source,
                source_domain=domain,
                title=title,
                summary=summary,
                url=url,
                image_url=image_url,
                author=clean_text(raw.get("author"), maximum=120),
                published_at=published,
                fetched_at=fetched_at.astimezone(UTC),
                language=language,
                category=category,
                symbols=[match.symbol for match in relevance],
                currencies=sorted(currencies),
                countries=[str(item) for item in countries if item],
                topics=[str(item) for item in topics if item],
                sentiment=SentimentResult(label=SentimentLabel.UNKNOWN, analyzer="pending"),
                provider_sentiment=provider_sentiment,
                sentiment_score=None,
                impact=ImpactLevel.UNKNOWN,
                impact_score=None,
                relevance_score=max((match.relevance_score for match in relevance), default=0),
                relevance=relevance,
                is_breaking=bool(raw.get("is_breaking") or raw.get("breaking")),
                stale=False,
                raw_provider_id=raw_id,
            )
        except ValidationError as exc:
            raise InvalidDataFormatError("News article failed schema validation", details=exc.errors()) from exc
