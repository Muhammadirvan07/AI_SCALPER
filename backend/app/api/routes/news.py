from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Path, Query, Request

from app.api.dependencies import Container, PageLimit, PageOffset, Symbol, cached
from app.api.responses import success
from app.schemas.news import ImpactLevel, NewsCategory, SentimentLabel
from app.services.base import ServicePayload

router = APIRouter(prefix="/news")
SentimentRange = Literal["1h", "4h", "12h", "24h", "3d", "7d"]
NewsFreshnessQuery = Literal["live", "recent", "historical", "all"]
NewsFallbackQuery = Literal["none", "recent"]
GdeltTopic = Literal[
    "central_bank",
    "interest_rate",
    "inflation",
    "employment",
    "gdp",
    "recession",
    "currency",
    "forex",
    "gold",
    "silver",
    "oil",
    "energy",
    "bitcoin",
    "cryptocurrency",
    "geopolitics",
    "sanctions",
    "war",
    "regulation",
    "trade",
]


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@router.get("", tags=["News"], summary="Filtered canonical financial news")
async def news(
    request: Request,
    container: Container,
    symbol: str | None = None,
    currency: str | None = Query(default=None, min_length=3, max_length=8),
    category: NewsCategory | None = None,
    sentiment: SentimentLabel | None = None,
    impact: ImpactLevel | None = None,
    provider: str | None = Query(default=None, max_length=80),
    topic: GdeltTopic | None = None,
    language: str | None = Query(default=None, min_length=2, max_length=8),
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    search: str | None = Query(default=None, max_length=200),
    limit: PageLimit = 50,
    offset: PageOffset = 0,
    include_duplicates: bool = False,
    freshness: NewsFreshnessQuery = "all",
    fallback: NewsFallbackQuery = "none",
):
    payload = container.news.query(
        symbol=symbol,
        currency=currency,
        category=category,
        sentiment=sentiment,
        impact=impact,
        provider=provider,
        topic=topic,
        language=language,
        start_time=_utc(start_time),
        end_time=_utc(end_time),
        search=search,
        include_duplicates=include_duplicates,
        freshness=freshness,
        fallback=fallback,
        limit=limit,
        offset=offset,
    )
    return success(payload, request)


@router.get("/latest", tags=["News"], summary="Latest canonical financial news")
async def latest(
    request: Request,
    container: Container,
    limit: PageLimit = 50,
    offset: PageOffset = 0,
    freshness: NewsFreshnessQuery = "live",
    fallback: NewsFallbackQuery = "recent",
):
    payload = await cached(
        container,
        f"news:latest:{freshness}:{fallback}:{limit}:{offset}",
        container.settings.news_cache_ttl_seconds,
        lambda: _news_query(container, limit, offset, freshness, fallback),
    )
    return success(payload, request)


async def _news_query(
    container: Container,
    limit: int,
    offset: int,
    freshness: NewsFreshnessQuery,
    fallback: NewsFallbackQuery,
):
    return container.news.query(limit=limit, offset=offset, freshness=freshness, fallback=fallback)


@router.get("/breaking", tags=["News"], summary="Breaking news only")
async def breaking(request: Request, container: Container, limit: PageLimit = 50, offset: PageOffset = 0):
    return success(
        container.news.query(breaking_only=True, freshness="live", fallback="none", limit=limit, offset=offset),
        request,
    )


@router.get("/symbols/{symbol}", tags=["News"], summary="News relevant to a trading symbol")
async def symbol_news(
    request: Request,
    container: Container,
    symbol: Symbol,
    limit: PageLimit = 50,
    offset: PageOffset = 0,
    freshness: NewsFreshnessQuery = "live",
    fallback: NewsFallbackQuery = "recent",
):
    return success(
        container.news.query(
            symbol=symbol,
            freshness=freshness,
            fallback=fallback,
            limit=limit,
            offset=offset,
        ),
        request,
    )


@router.get("/symbols/{symbol}/sentiment", tags=["News Sentiment"], summary="Aggregated symbol sentiment")
async def symbol_sentiment(request: Request, container: Container, symbol: Symbol, range: SentimentRange = "24h"):
    return success(container.news.aggregate(symbol=symbol, range_name=range), request)


@router.get("/symbols/{symbol}/summary", tags=["News"], summary="Symbol news intelligence summary")
async def symbol_summary(request: Request, container: Container, symbol: Symbol, range: SentimentRange = "24h"):
    return success(container.news.symbol_summary(symbol, range), request)


def _sentiment_payload(container: Container, symbol, currency, category, range_name):
    return container.news.aggregate(symbol=symbol, currency=currency, category=category, range_name=range_name)


@router.get("/sentiment", tags=["News Sentiment"], summary="Aggregated financial-news sentiment")
@router.get("/sentiment/overview", tags=["News Sentiment"], summary="News sentiment overview")
async def sentiment_overview(
    request: Request,
    container: Container,
    symbol: str | None = None,
    currency: str | None = None,
    category: NewsCategory | None = None,
    range: SentimentRange = "24h",
):
    return success(_sentiment_payload(container, symbol, currency, category, range), request)


@router.get("/sentiment/timeline", tags=["News Sentiment"], summary="Bucketed sentiment timeline")
async def sentiment_timeline(
    request: Request,
    container: Container,
    symbol: str | None = None,
    currency: str | None = None,
    category: NewsCategory | None = None,
    range: SentimentRange = "24h",
):
    return success(
        container.news.timeline(symbol=symbol, currency=currency, category=category, range_name=range), request
    )


@router.get("/sentiment/distribution", tags=["News Sentiment"], summary="Bullish, bearish and neutral distribution")
async def sentiment_distribution(
    request: Request,
    container: Container,
    symbol: str | None = None,
    currency: str | None = None,
    category: NewsCategory | None = None,
    range: SentimentRange = "24h",
):
    return success(
        container.news.distribution(symbol=symbol, currency=currency, category=category, range_name=range), request
    )


def _calendar_query(container: Container, **kwargs):
    return container.economic_calendar.query(**kwargs)


@router.get("/calendar", tags=["Economic Calendar"], summary="Filtered economic calendar")
async def calendar(
    request: Request,
    container: Container,
    currency: str | None = Query(default=None, min_length=3, max_length=8),
    country: str | None = Query(default=None, max_length=80),
    symbol: str | None = None,
    impact: ImpactLevel | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: PageLimit = 100,
    offset: PageOffset = 0,
):
    return success(
        _calendar_query(
            container,
            currency=currency,
            country=country,
            symbol=symbol,
            impact=impact,
            start_time=_utc(start_time),
            end_time=_utc(end_time),
            limit=limit,
            offset=offset,
        ),
        request,
    )


@router.get("/calendar/today", tags=["Economic Calendar"], summary="Economic events for the current UTC day")
async def calendar_today(request: Request, container: Container, limit: PageLimit = 100, offset: PageOffset = 0):
    now = datetime.now(UTC)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return success(
        _calendar_query(container, start_time=start, end_time=start + timedelta(days=1), limit=limit, offset=offset),
        request,
    )


@router.get("/calendar/upcoming", tags=["Economic Calendar"], summary="Upcoming economic events")
async def calendar_upcoming(
    request: Request,
    container: Container,
    hours: Annotated[int, Query(ge=1, le=168)] = 24,
    limit: PageLimit = 100,
    offset: PageOffset = 0,
):
    now = datetime.now(UTC)
    return success(
        _calendar_query(container, start_time=now, end_time=now + timedelta(hours=hours), limit=limit, offset=offset),
        request,
    )


@router.get("/calendar/high-impact", tags=["Economic Calendar"], summary="High and critical impact events")
async def calendar_high_impact(request: Request, container: Container, limit: PageLimit = 100, offset: PageOffset = 0):
    payload = _calendar_query(container, limit=500, offset=0)
    rows = [item for item in payload.data.items if item.impact in {ImpactLevel.HIGH, ImpactLevel.CRITICAL}]
    payload.data = payload.data.model_copy(
        update={"items": rows[offset : offset + limit], "total": len(rows), "limit": limit, "offset": offset}
    )
    return success(payload, request)


@router.get("/calendar/{event_id}", tags=["Economic Calendar"], summary="Economic calendar event detail")
async def calendar_detail(request: Request, container: Container, event_id: str):
    return success(container.economic_calendar.detail(event_id), request)


@router.get("/providers", tags=["News"], summary="Configured news provider health and rate-limit state")
async def providers(request: Request, container: Container):
    return success(container.news.provider_statuses(), request)


@router.get("/providers/{provider_name}", tags=["News"], summary="One news provider capability and runtime state")
async def provider_detail(
    request: Request,
    container: Container,
    provider_name: Annotated[str, Path(min_length=1, max_length=40, pattern=r"^[a-z0-9_]+$")],
):
    return success(container.news.provider_status(provider_name), request)


@router.get("/health", tags=["News"], summary="News Intelligence domain health")
async def news_health(request: Request, container: Container):
    return success(container.news.health(), request)


@router.get("/status", tags=["News"], summary="News Intelligence runtime configuration and freshness")
async def news_status(request: Request, container: Container):
    return success(container.news.status(), request)


@router.get("/guard-preview", tags=["News"], summary="Read-only news guard preview for all known symbols")
async def guard_previews(request: Request, container: Container):
    rows = [container.news.guard_preview(symbol).data for symbol in container.registry.symbols()]
    return success(ServicePayload(rows, container.news.status().meta), request)


@router.get("/guard-preview/{symbol}", tags=["News"], summary="Read-only news guard preview for one symbol")
async def guard_preview(request: Request, container: Container, symbol: Symbol):
    return success(container.news.guard_preview(symbol), request)


@router.get("/{article_id}", tags=["News"], summary="Financial news article metadata and source link")
async def article_detail(request: Request, container: Container, article_id: str):
    return success(container.news.detail(article_id), request)
