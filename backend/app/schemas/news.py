from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field, HttpUrl, field_validator

from app.schemas.common import ApiMeta, SchemaModel


class SentimentLabel(StrEnum):
    VERY_BEARISH = "VERY_BEARISH"
    BEARISH = "BEARISH"
    NEUTRAL = "NEUTRAL"
    BULLISH = "BULLISH"
    VERY_BULLISH = "VERY_BULLISH"
    UNKNOWN = "UNKNOWN"


class ImpactLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class NewsCategory(StrEnum):
    CENTRAL_BANK = "CENTRAL_BANK"
    INTEREST_RATE = "INTEREST_RATE"
    INFLATION = "INFLATION"
    EMPLOYMENT = "EMPLOYMENT"
    GDP = "GDP"
    FOREX = "FOREX"
    COMMODITIES = "COMMODITIES"
    GOLD = "GOLD"
    SILVER = "SILVER"
    CRYPTO = "CRYPTO"
    EQUITIES = "EQUITIES"
    GEOPOLITICS = "GEOPOLITICS"
    REGULATION = "REGULATION"
    ENERGY = "ENERGY"
    MARKET_ANALYSIS = "MARKET_ANALYSIS"
    GENERAL = "GENERAL"


class CalendarStatus(StrEnum):
    SCHEDULED = "SCHEDULED"
    RELEASED = "RELEASED"
    REVISED = "REVISED"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"


class QuotaStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    LOW = "LOW"
    EXHAUSTED = "EXHAUSTED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class CircuitState(StrEnum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class NewsFreshnessStatus(StrEnum):
    REALTIME = "REALTIME"
    RECENT = "RECENT"
    HISTORICAL = "HISTORICAL"
    UNKNOWN = "UNKNOWN"


class SentimentResult(SchemaModel):
    label: SentimentLabel = SentimentLabel.UNKNOWN
    score: float | None = Field(default=None, ge=-1, le=1)
    confidence: float | None = Field(default=None, ge=0, le=1)
    analyzer: str
    positive_probability: float | None = Field(default=None, ge=0, le=1)
    neutral_probability: float | None = Field(default=None, ge=0, le=1)
    negative_probability: float | None = Field(default=None, ge=0, le=1)
    matched_terms: list[str] = Field(default_factory=list)


class ProviderSentiment(SchemaModel):
    provider: str
    raw_label: str | None = None
    raw_score: float | None = None
    normalized_score: float | None = Field(default=None, ge=-1, le=1)
    normalized_confidence: float | None = Field(default=None, ge=0, le=1)


class RelevanceMatch(SchemaModel):
    symbol: str
    relevance_score: float = Field(ge=0, le=1)
    matched_terms: list[str] = Field(default_factory=list)
    breakdown: dict[str, float] = Field(default_factory=dict)


class NewsArticle(SchemaModel):
    id: str
    provider: str
    source: str | None = None
    source_domain: str | None = None
    title: str
    summary: str | None = None
    url: HttpUrl
    image_url: HttpUrl | None = None
    author: str | None = None
    published_at: datetime | None = None
    fetched_at: datetime
    language: str
    category: NewsCategory = NewsCategory.GENERAL
    symbols: list[str] = Field(default_factory=list)
    currencies: list[str] = Field(default_factory=list)
    countries: list[str] = Field(default_factory=list)
    topics: list[str] = Field(default_factory=list)
    sentiment: SentimentResult
    provider_sentiment: ProviderSentiment | None = None
    sentiment_score: float | None = Field(default=None, ge=-1, le=1)
    sentiment_confidence: float | None = Field(default=None, ge=0, le=1)
    impact: ImpactLevel = ImpactLevel.UNKNOWN
    impact_score: float | None = Field(default=None, ge=0, le=1)
    impact_breakdown: dict[str, float] = Field(default_factory=dict)
    relevance_score: float = Field(default=0, ge=0, le=1)
    relevance: list[RelevanceMatch] = Field(default_factory=list)
    is_breaking: bool = False
    is_duplicate: bool = False
    duplicate_group_id: str | None = None
    canonical_article_id: str | None = None
    age_hours: float | None = Field(default=None, ge=0)
    freshness_status: NewsFreshnessStatus = NewsFreshnessStatus.UNKNOWN
    is_realtime: bool = False
    is_recent: bool = False
    is_historical: bool = False
    stale: bool = True
    stale_reason: str | None = None
    raw_provider_id: str | None = None

    @field_validator("symbols", "currencies")
    @classmethod
    def _uppercase(cls, value: list[str]) -> list[str]:
        return sorted({item.strip().upper() for item in value if item.strip()})


class EconomicCalendarEvent(SchemaModel):
    id: str
    provider: str
    event_name: str
    country: str | None = None
    currency: str | None = None
    category: NewsCategory = NewsCategory.GENERAL
    impact: ImpactLevel = ImpactLevel.UNKNOWN
    scheduled_at: datetime
    actual: str | float | int | None = None
    forecast: str | float | int | None = None
    previous: str | float | int | None = None
    revised_previous: str | float | int | None = None
    unit: str | None = None
    status: CalendarStatus = CalendarStatus.UNKNOWN
    symbols: list[str] = Field(default_factory=list)
    description: str | None = None
    source: str | None = None
    reference_period: str | None = None
    source_url: HttpUrl | None = None
    updated_at: datetime | None = None
    stale: bool = True


class ProviderStatus(SchemaModel):
    name: str
    enabled: bool
    configured: bool
    healthy: bool
    status: str
    capabilities: list[str] = Field(default_factory=list)
    capability_details: dict[str, bool | None] = Field(default_factory=dict)
    priority: int | None = None
    last_fetch_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None
    article_count: int = 0
    raw_count: int = 0
    canonical_count: int = 0
    latency_ms: float | None = None
    rate_limited: bool = False
    quota_status: QuotaStatus = QuotaStatus.UNKNOWN
    failure_count: int = 0
    cooldown_until: datetime | None = None
    circuit_state: CircuitState = CircuitState.CLOSED
    authentication_failed: bool = False
    entitlement_error: bool = False
    last_status_code: int | None = None
    requests_sent: int = 0
    requests_skipped_from_cache: int = 0
    rate_limit_count: int = 0
    last_retry_after_seconds: float | None = None
    last_known_good_available: bool = False
    feed_count: int = 0
    healthy_feed_count: int = 0
    failed_feed_count: int = 0
    raw_article_count: int = 0
    canonical_article_count: int = 0
    realtime_article_count: int = 0
    recent_article_count: int = 0
    stale: bool = True


class NewsListData(SchemaModel):
    items: list[NewsArticle]
    total: int
    limit: int
    offset: int
    requested_freshness: str = "all"
    effective_freshness: str = "all"
    fallback_applied: bool = False
    warning: str | None = None
    realtime_article_count: int = 0
    recent_article_count: int = 0
    historical_article_count: int = 0
    unknown_article_count: int = 0
    oldest_article_at: datetime | None = None
    latest_article_at: datetime | None = None
    freshness_threshold_hours: dict[str, int] = Field(default_factory=dict)


class NewsApiMeta(ApiMeta):
    realtime_article_count: int = 0
    recent_article_count: int = 0
    historical_article_count: int = 0
    unknown_article_count: int = 0
    oldest_article_at: datetime | None = None
    latest_article_at: datetime | None = None
    fallback_applied: bool = False
    requested_freshness: str | None = None
    effective_freshness: str | None = None
    freshness_threshold_hours: dict[str, int] = Field(default_factory=dict)


class CalendarListData(SchemaModel):
    items: list[EconomicCalendarEvent]
    total: int
    limit: int
    offset: int


class SentimentAggregate(SchemaModel):
    scope: str
    range: str
    article_count: int
    bullish_count: int
    bearish_count: int
    neutral_count: int
    weighted_sentiment_score: float | None = Field(default=None, ge=-1, le=1)
    average_impact_score: float | None = Field(default=None, ge=0, le=1)
    high_impact_count: int
    latest_article_at: datetime | None = None
    trend: str
    confidence: float | None = Field(default=None, ge=0, le=1)


class SentimentTimelinePoint(SchemaModel):
    timestamp: datetime
    score: float
    article_count: int


class NewsStatus(SchemaModel):
    enabled: bool
    state: str
    provider_mode: list[str]
    provider_count: int
    configured_provider_count: int
    article_count: int
    raw_article_count: int
    canonical_article_count: int
    realtime_article_count: int
    recent_article_count: int
    historical_article_count: int
    unknown_article_count: int
    calendar_event_count: int
    last_refresh_at: datetime | None = None
    last_success_at: datetime | None = None
    analyzer: str
    finbert_enabled: bool
    finbert_available: bool
    scheduler_running: bool
    external_requests_enabled: bool
    engine_integration_enabled: bool = False
    live_allowed: bool = False
    effective_max_lot: float = 0.01
    warnings: list[str] = Field(default_factory=list)
    providers_attempted: list[str] = Field(default_factory=list)
    providers_succeeded: list[str] = Field(default_factory=list)
    providers_failed: list[str] = Field(default_factory=list)
    providers_rate_limited: list[str] = Field(default_factory=list)
    providers_unconfigured: list[str] = Field(default_factory=list)
    providers: dict[str, ProviderStatus] = Field(default_factory=dict)
    partial: bool = False


class GuardPreview(SchemaModel):
    symbol: str
    high_impact_event_nearby: bool
    minutes_to_event: float | None = None
    aggregate_sentiment: SentimentLabel
    sentiment_confidence: float | None = None
    impact_score: float | None = None
    suggested_action: str
    reasons: list[str] = Field(default_factory=list)
    read_only: bool = True
    creates_orders: bool = False


NewsRaw = dict[str, Any]
