from __future__ import annotations

from datetime import UTC, datetime

from app.schemas.news import ImpactLevel, NewsArticle, NewsCategory

IMPACT_BASE = {
    NewsCategory.CENTRAL_BANK: 0.60,
    NewsCategory.INTEREST_RATE: 0.68,
    NewsCategory.INFLATION: 0.55,
    NewsCategory.EMPLOYMENT: 0.55,
    NewsCategory.GDP: 0.48,
    NewsCategory.GEOPOLITICS: 0.55,
    NewsCategory.REGULATION: 0.42,
    NewsCategory.ENERGY: 0.40,
    NewsCategory.CRYPTO: 0.32,
    NewsCategory.GOLD: 0.30,
    NewsCategory.SILVER: 0.28,
    NewsCategory.FOREX: 0.30,
    NewsCategory.COMMODITIES: 0.28,
    NewsCategory.EQUITIES: 0.25,
    NewsCategory.MARKET_ANALYSIS: 0.14,
    NewsCategory.GENERAL: 0.10,
}
CRITICAL_TERMS = ("emergency rate", "unexpected rate", "war declared", "market crash", "capital controls")
HIGH_TERMS = ("rate decision", "interest rate", "cpi", "inflation", "nonfarm", "nfp", "gdp", "sanctions")


def impact_level(score: float) -> ImpactLevel:
    if score < 0.25:
        return ImpactLevel.LOW
    if score < 0.50:
        return ImpactLevel.MEDIUM
    if score < 0.75:
        return ImpactLevel.HIGH
    return ImpactLevel.CRITICAL


def score_impact_details(
    article: NewsArticle, provider_confidence: float = 0.8
) -> tuple[float, ImpactLevel, dict[str, float]]:
    text = f"{article.title} {article.summary or ''}".lower()
    base = IMPACT_BASE[article.category]
    keyword_floor = 0.0
    if any(term in text for term in CRITICAL_TERMS):
        keyword_floor = 0.75
    elif any(term in text for term in HIGH_TERMS):
        keyword_floor = 0.52
    breaking = 0.15 if article.is_breaking else 0.0
    direct_symbols = min(0.08, len(article.symbols) * 0.02)
    provider = max(0.0, min(1.0, provider_confidence)) * 0.05
    score = max(base, keyword_floor) + breaking + direct_symbols + provider
    score = round(min(1.0, score), 4)
    return (
        score,
        impact_level(score),
        {
            "category_base": round(base, 4),
            "keyword_floor": round(keyword_floor, 4),
            "breaking": round(breaking, 4),
            "direct_symbols": round(direct_symbols, 4),
            "provider_confidence": round(provider, 4),
        },
    )


def score_impact(article: NewsArticle, provider_confidence: float = 0.8) -> tuple[float, ImpactLevel]:
    score, level, _ = score_impact_details(article, provider_confidence)
    return score, level


def enrich_relevance(article: NewsArticle, provider_confidence: float = 0.8) -> NewsArticle:
    now = datetime.now(UTC)
    age_hours = max(0.0, (now - article.published_at).total_seconds() / 3600) if article.published_at else None
    recency = 0.10 * max(0.0, 1.0 - (age_hours or 72) / 72) if age_hours is not None else 0.0
    provider = max(0.0, min(1.0, provider_confidence)) * 0.05
    matches = []
    for match in article.relevance:
        breakdown = dict(match.breakdown)
        breakdown["recency"] = round(recency, 4)
        breakdown["provider_confidence"] = round(provider, 4)
        score = min(1.0, sum(breakdown.values()))
        matches.append(match.model_copy(update={"relevance_score": round(score, 4), "breakdown": breakdown}))
    return article.model_copy(
        update={
            "relevance": matches,
            "relevance_score": max((match.relevance_score for match in matches), default=0.0),
        }
    )
