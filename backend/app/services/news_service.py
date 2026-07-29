from __future__ import annotations

import asyncio
import logging
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from app.adapters.news_adapter import NewsAdapter
from app.core.config import Settings
from app.core.exceptions import InvalidDataFormatError, ResourceNotFoundError
from app.providers.news.provider_registry import NewsProviderRegistry
from app.realtime.event_bus import EventBus
from app.realtime.events import InternalEvent
from app.repositories.file_registry import FileRegistry
from app.repositories.news_repository import NewsRepository
from app.schemas.news import (
    GuardPreview,
    ImpactLevel,
    NewsApiMeta,
    NewsArticle,
    NewsCategory,
    NewsFreshnessStatus,
    NewsListData,
    NewsStatus,
    ProviderStatus,
    SentimentAggregate,
    SentimentLabel,
    SentimentTimelinePoint,
)

from .base import ServicePayload
from .economic_calendar_service import EconomicCalendarService
from .news_deduplication import NewsDeduplicator
from .news_freshness import classify_news_freshness, freshness_update
from .news_scoring import enrich_relevance, score_impact_details
from .sentiment_service import SentimentService, label_for_score

logger = logging.getLogger(__name__)

RANGES = {"1h": 1, "4h": 4, "12h": 12, "24h": 24, "3d": 72, "7d": 168}


class NewsService:
    def __init__(
        self,
        settings: Settings,
        repository: NewsRepository,
        providers: NewsProviderRegistry,
        adapter: NewsAdapter,
        sentiment: SentimentService,
        calendar: EconomicCalendarService,
        registry: FileRegistry,
        event_bus: EventBus,
    ) -> None:
        self.settings = settings
        self.repository = repository
        self.providers = providers
        self.adapter = adapter
        self.sentiment = sentiment
        self.calendar = calendar
        self.registry = registry
        self.event_bus = event_bus
        self.deduplicator = NewsDeduplicator()
        self._articles: list[NewsArticle] = []
        self._lock = asyncio.Lock()
        self.last_refresh_at: datetime | None = None
        self.last_success_at: datetime | None = None
        self.invalid_count = 0
        self.scheduler_running = False
        self._initialized = False

    async def initialize(self) -> None:
        await self.refresh(force=True)

    async def refresh(self, *, force: bool = False, provider_names: list[str] | None = None) -> dict[str, int]:
        if not self.settings.news_enabled:
            self.last_refresh_at = datetime.now(UTC)
            return {"articles": 0, "created": 0, "calendar": 0}
        async with self._lock:
            before_provider = {item.name: item.model_dump(mode="json") for item in self.providers.statuses()}
            raw_rows = await self.repository.fetch_latest(provider_names=provider_names, force=force)
            now = datetime.now(UTC)
            normalized: list[NewsArticle] = []
            symbols = self.registry.symbols()
            for provider, raw in raw_rows:
                raw = dict(raw)
                raw.setdefault("language", self.settings.news_default_language)
                try:
                    article = self.adapter.normalize(raw, provider=provider, known_symbols=symbols, fetched_at=now)
                except InvalidDataFormatError:
                    self.invalid_count += 1
                    continue
                if article.language not in self.settings.allowed_news_languages:
                    continue
                normalized.append(article)
            if provider_names:
                selected = set(provider_names)
                normalized.extend(item for item in self._articles if item.provider not in selected)
            # Canonicalization and cross-provider deduplication intentionally happen
            # before presentation freshness is classified or filtered.
            marked = self.deduplicator.mark(normalized)
            enriched: list[NewsArticle] = []
            for article in marked:
                sentiment = self.sentiment.analyze(article.title, article.summary, article.provider_sentiment)
                scored = enrich_relevance(
                    article.model_copy(
                        update={
                            "sentiment": sentiment,
                            "sentiment_score": sentiment.score,
                            "sentiment_confidence": sentiment.confidence,
                        }
                    )
                )
                impact_score, impact, impact_breakdown = score_impact_details(scored)
                freshness = classify_news_freshness(
                    scored.published_at,
                    now=now,
                    realtime_max_age_hours=self.settings.news_realtime_max_age_hours,
                    recent_max_age_hours=self.settings.news_recent_max_age_hours,
                    clock_skew_tolerance_minutes=self.settings.news_clock_skew_tolerance_minutes,
                )
                if (
                    freshness.age_hours is not None
                    and freshness.age_hours > self.settings.news_historical_retention_days * 24
                ):
                    continue
                enriched.append(
                    scored.model_copy(
                        update={
                            "impact_score": impact_score,
                            "impact": impact,
                            "impact_breakdown": impact_breakdown,
                            "is_breaking": bool(scored.is_breaking and freshness.is_realtime),
                            **freshness_update(freshness),
                        }
                    )
                )
            old_by_id = {item.id: item for item in self._articles}
            self._articles = sorted(enriched, key=self._article_sort_key, reverse=True)[:1000]
            created = [item for item in self._articles if item.id not in old_by_id]
            updated = [item for item in self._articles if item.id in old_by_id and item != old_by_id[item.id]]
            freshness_changed = sum(
                item.id in old_by_id and item.freshness_status != old_by_id[item.id].freshness_status
                for item in self._articles
            )
            self.last_refresh_at = now
            if self.repository.last_collection.providers_succeeded:
                self.last_success_at = now
            # The native Economic Calendar has its own adaptive scheduler. News
            # refreshes must never trigger official-source polling.
            calendar_created: list = []
            await self._publish(
                created,
                updated,
                calendar_created,
                before_provider,
                startup=not self._initialized,
                freshness_changed=freshness_changed,
            )
            self._initialized = True
            logger.info(
                "News cache refreshed",
                extra={
                    "event": "news.cache_refreshed",
                    "component": "news_service",
                    "article_count": len(self._articles),
                },
            )
            return {
                "articles": len(self._articles),
                "created": len(created),
                "calendar": len(self.calendar.events_copy()),
            }

    @staticmethod
    def _article_sort_key(article: NewsArticle) -> tuple[bool, float, float, float]:
        now = datetime.now(UTC)
        published = article.published_at or article.fetched_at
        age_hours = max(0.0, (now - published).total_seconds() / 3600)
        recency_decay = max(0.05, 1.0 - age_hours / 168)
        decayed_impact = (article.impact_score or 0.0) * recency_decay
        return article.is_breaking, decayed_impact, article.relevance_score, published.timestamp()

    async def _publish(
        self,
        created: list[NewsArticle],
        updated: list[NewsArticle],
        calendar_created: list,
        before_provider: dict[str, dict],
        *,
        startup: bool,
        freshness_changed: int,
    ) -> None:
        now = datetime.now(UTC)
        canonical_created = [
            article
            for article in created
            if not article.is_duplicate and article.freshness_status == NewsFreshnessStatus.REALTIME and not startup
        ]
        canonical_updated = [article for article in updated if not article.is_duplicate]
        for article in canonical_created:
            payload = {
                "article_id": article.id,
                "symbols": article.symbols,
                "breaking": article.is_breaking,
                "freshness_status": article.freshness_status.value,
                "is_realtime": article.is_realtime,
            }
            await self.event_bus.publish(InternalEvent("news.article.created", "news", now, payload, article.id))
            if article.is_breaking:
                await self.event_bus.publish(
                    InternalEvent("news.breaking.created", "news:breaking", now, payload, article.id)
                )
            for symbol in article.symbols:
                await self.event_bus.publish(
                    InternalEvent(
                        "news.article.created", f"news:symbol:{symbol}", now, payload, f"{article.id}:{symbol}"
                    )
                )
        for article in canonical_updated:
            await self.event_bus.publish(
                InternalEvent("news.article.updated", "news", now, {"article_id": article.id}, article.id)
            )
        if canonical_created or canonical_updated:
            await self.event_bus.publish(
                InternalEvent(
                    "news.sentiment.updated",
                    "news:sentiment",
                    now,
                    {"changed": len(canonical_created) + len(canonical_updated)},
                )
            )
            for symbol in sorted(
                {symbol for article in canonical_created + canonical_updated for symbol in article.symbols}
            ):
                await self.event_bus.publish(
                    InternalEvent("news.symbol.sentiment.updated", f"news:symbol:{symbol}", now, {"symbol": symbol})
                )
        for event in calendar_created:
            await self.event_bus.publish(
                InternalEvent("news.calendar.created", "news:calendar", now, {"event_id": event.id}, event.id)
            )
        after_provider = {item.name: item.model_dump(mode="json") for item in self.providers.statuses()}
        if startup and self._articles:
            await self.event_bus.publish(
                InternalEvent(
                    "news.cache.loaded",
                    "news",
                    now,
                    {"canonical_count": sum(not item.is_duplicate for item in self._articles)},
                )
            )
        if freshness_changed:
            await self.event_bus.publish(
                InternalEvent(
                    "news.freshness.updated",
                    "news",
                    now,
                    {"changed": freshness_changed},
                )
            )
        if before_provider != after_provider:
            await self.event_bus.publish(
                InternalEvent("news.provider.status.updated", "news", now, {"providers": list(after_provider)})
            )
            for name, after in after_provider.items():
                before = before_provider.get(name, {})
                if before != after:
                    await self.event_bus.publish(
                        InternalEvent(
                            "news.provider.status.updated",
                            f"news:provider:{name}",
                            now,
                            {"provider": name, "status": after.get("status")},
                            f"{name}:{after.get('last_fetch_at')}",
                        )
                    )
                if after.get("rate_limited") and not before.get("rate_limited"):
                    await self.event_bus.publish(
                        InternalEvent("news.provider.rate_limited", "news", now, {"provider": name})
                    )
                if before.get("rate_limited") and not after.get("rate_limited"):
                    await self.event_bus.publish(
                        InternalEvent("news.provider.recovered", "news", now, {"provider": name})
                    )
                if after.get("status") in {"error", "degraded", "circuit_open"} and before.get("status") != after.get(
                    "status"
                ):
                    await self.event_bus.publish(
                        InternalEvent("news.provider.failed", f"news:provider:{name}", now, {"provider": name})
                    )

    def articles_copy(self) -> list[NewsArticle]:
        now = datetime.now(UTC)
        return [
            item.model_copy(
                update=freshness_update(
                    classify_news_freshness(
                        item.published_at,
                        now=now,
                        realtime_max_age_hours=self.settings.news_realtime_max_age_hours,
                        recent_max_age_hours=self.settings.news_recent_max_age_hours,
                        clock_skew_tolerance_minutes=self.settings.news_clock_skew_tolerance_minutes,
                    )
                )
            )
            for item in self._articles
        ]

    def query(
        self,
        *,
        symbol: str | None = None,
        currency: str | None = None,
        category: NewsCategory | None = None,
        sentiment: SentimentLabel | None = None,
        impact: ImpactLevel | None = None,
        provider: str | None = None,
        topic: str | None = None,
        language: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        search: str | None = None,
        include_duplicates: bool = False,
        breaking_only: bool = False,
        freshness: Literal["live", "recent", "historical", "all"] = "all",
        fallback: Literal["none", "recent"] = "none",
        limit: int = 50,
        offset: int = 0,
    ) -> ServicePayload:
        rows = self.articles_copy()
        if not include_duplicates:
            rows = [item for item in rows if not item.is_duplicate]
        if symbol:
            rows = [item for item in rows if symbol.upper() in item.symbols]
        if currency:
            rows = [item for item in rows if currency.upper() in item.currencies]
        if category:
            rows = [item for item in rows if item.category == category]
        if sentiment:
            rows = [item for item in rows if item.sentiment.label == sentiment]
        if impact:
            rows = [item for item in rows if item.impact == impact]
        if provider:
            rows = [item for item in rows if item.provider.lower() == provider.lower()]
        if topic:
            rows = [item for item in rows if topic.lower() in {value.lower() for value in item.topics}]
        if language:
            rows = [item for item in rows if item.language == language.lower()]
        if start_time:
            rows = [item for item in rows if item.published_at and item.published_at >= start_time]
        if end_time:
            rows = [item for item in rows if item.published_at and item.published_at <= end_time]
        if search:
            needle = search.casefold()
            rows = [item for item in rows if needle in f"{item.title} {item.summary or ''}".casefold()]
        if breaking_only:
            rows = [item for item in rows if item.is_breaking and item.is_realtime]
        counts = Counter(item.freshness_status for item in rows)
        published = [item.published_at for item in rows if item.published_at is not None]
        requested_freshness = freshness
        mapping = {
            "live": NewsFreshnessStatus.REALTIME,
            "recent": NewsFreshnessStatus.RECENT,
            "historical": NewsFreshnessStatus.HISTORICAL,
        }
        effective_freshness = freshness
        fallback_applied = False
        warning = None
        if freshness != "all":
            selected = [item for item in rows if item.freshness_status == mapping[freshness]]
            if freshness == "live" and not selected and fallback == "recent":
                selected = [item for item in rows if item.freshness_status == NewsFreshnessStatus.RECENT]
                if selected:
                    effective_freshness = "recent"
                    fallback_applied = True
                    warning = "No articles were published within the realtime window. Showing recent official releases."
            rows = selected
        thresholds = {
            "realtime": self.settings.news_realtime_max_age_hours,
            "recent": self.settings.news_recent_max_age_hours,
        }
        data = NewsListData(
            items=rows[offset : offset + limit],
            total=len(rows),
            limit=limit,
            offset=offset,
            requested_freshness=requested_freshness,
            effective_freshness=effective_freshness,
            fallback_applied=fallback_applied,
            warning=warning,
            realtime_article_count=counts[NewsFreshnessStatus.REALTIME],
            recent_article_count=counts[NewsFreshnessStatus.RECENT],
            historical_article_count=counts[NewsFreshnessStatus.HISTORICAL],
            unknown_article_count=counts[NewsFreshnessStatus.UNKNOWN],
            oldest_article_at=min(published, default=None),
            latest_article_at=max(published, default=None),
            freshness_threshold_hours=thresholds,
        )
        base_meta = self.meta("breaking" if breaking_only else "latest")
        meta = base_meta.model_copy(
            update={
                "fallback_applied": fallback_applied,
                "requested_freshness": requested_freshness,
                "effective_freshness": effective_freshness,
                "stale": bool(base_meta.stale or effective_freshness in {"recent", "historical"}),
                "warnings": [warning] if warning else [],
            }
        )
        return ServicePayload(
            data,
            meta,
        )

    def detail(self, article_id: str) -> ServicePayload:
        item = next((article for article in self.articles_copy() if article.id == article_id), None)
        if item is None:
            raise ResourceNotFoundError(f"News article {article_id!r} was not found")
        return ServicePayload(item, self.meta("latest"))

    def aggregate(
        self,
        *,
        symbol: str | None = None,
        currency: str | None = None,
        category: NewsCategory | None = None,
        provider: str | None = None,
        range_name: str = "24h",
    ) -> ServicePayload:
        hours = RANGES[range_name]
        now = datetime.now(UTC)
        start = now - timedelta(hours=hours)
        rows = [
            item
            for item in self.articles_copy()
            if not item.is_duplicate and item.published_at and item.published_at >= start
        ]
        if symbol:
            rows = [item for item in rows if symbol.upper() in item.symbols]
        if currency:
            rows = [item for item in rows if currency.upper() in item.currencies]
        if category:
            rows = [item for item in rows if item.category == category]
        if provider:
            rows = [item for item in rows if item.provider.lower() == provider.lower()]
        score, confidence = self._weighted_score(rows, now, hours)
        midpoint = now - timedelta(hours=hours / 2)
        recent_score, _ = self._weighted_score(
            [item for item in rows if item.published_at and item.published_at >= midpoint], now, max(1, hours / 2)
        )
        prior_score, _ = self._weighted_score(
            [item for item in rows if item.published_at and item.published_at < midpoint], midpoint, max(1, hours / 2)
        )
        trend = "INSUFFICIENT_DATA"
        if len(rows) >= 3 and recent_score is not None and prior_score is not None:
            delta = recent_score - prior_score
            trend = (
                "IMPROVING"
                if delta > 0.12
                else "WEAKENING"
                if delta < -0.12
                else "STABLE"
                if abs(delta) <= 0.05
                else "MIXED"
            )
        counter = Counter(item.sentiment.label for item in rows)
        impacts = [item.impact_score for item in rows if item.impact_score is not None]
        data = SentimentAggregate(
            scope=symbol or currency or (category.value if category else provider) or "all",
            range=range_name,
            article_count=len(rows),
            bullish_count=counter[SentimentLabel.BULLISH] + counter[SentimentLabel.VERY_BULLISH],
            bearish_count=counter[SentimentLabel.BEARISH] + counter[SentimentLabel.VERY_BEARISH],
            neutral_count=counter[SentimentLabel.NEUTRAL],
            weighted_sentiment_score=score,
            average_impact_score=round(sum(impacts) / len(impacts), 4) if impacts else None,
            high_impact_count=sum(item.impact in {ImpactLevel.HIGH, ImpactLevel.CRITICAL} for item in rows),
            latest_article_at=max((item.published_at for item in rows if item.published_at), default=None),
            trend=trend,
            confidence=confidence,
        )
        return ServicePayload(data, self.meta("sentiment"))

    @staticmethod
    def _weighted_score(
        rows: list[NewsArticle], reference: datetime, hours: float
    ) -> tuple[float | None, float | None]:
        weighted = 0.0
        total = 0.0
        confidences: list[float] = []
        for item in rows:
            if item.sentiment.score is None or item.published_at is None:
                continue
            age = max(0.0, (reference - item.published_at).total_seconds() / 3600)
            recency = max(0.05, 1 - age / max(1, hours))
            weight = recency * max(0.1, item.relevance_score) * max(0.1, item.impact_score or 0.1)
            weighted += item.sentiment.score * weight
            total += weight
            if item.sentiment.confidence is not None:
                confidences.append(item.sentiment.confidence)
        score = round(weighted / total, 4) if total else None
        confidence = (
            round(min(1.0, (sum(confidences) / len(confidences)) * min(1.0, len(rows) / 5)), 4) if confidences else None
        )
        return score, confidence

    def timeline(self, **filters: Any) -> ServicePayload:
        range_name = filters.pop("range_name", "24h")
        aggregate_payload = self.aggregate(range_name=range_name, **filters)
        hours = RANGES[range_name]
        now = datetime.now(UTC)
        rows = [
            item
            for item in self.articles_copy()
            if not item.is_duplicate and item.published_at and item.published_at >= now - timedelta(hours=hours)
        ]
        symbol = filters.get("symbol")
        currency = filters.get("currency")
        category = filters.get("category")
        if symbol:
            rows = [item for item in rows if symbol.upper() in item.symbols]
        if currency:
            rows = [item for item in rows if currency.upper() in item.currencies]
        if category:
            rows = [item for item in rows if item.category == category]
        buckets: dict[datetime, list[NewsArticle]] = {}
        bucket_hours = 1 if hours <= 24 else 6 if hours <= 72 else 24
        for item in rows:
            if item.published_at is None:
                continue
            stamp = item.published_at.replace(minute=0, second=0, microsecond=0)
            stamp = stamp.replace(hour=(stamp.hour // bucket_hours) * bucket_hours)
            buckets.setdefault(stamp, []).append(item)
        points = []
        for stamp, items in sorted(buckets.items()):
            score, _ = self._weighted_score(items, stamp + timedelta(hours=bucket_hours), bucket_hours)
            if score is not None:
                points.append(SentimentTimelinePoint(timestamp=stamp, score=score, article_count=len(items)))
        return ServicePayload(
            {"range": range_name, "items": points, "aggregate": aggregate_payload.data}, self.meta("sentiment")
        )

    def distribution(self, **filters: Any) -> ServicePayload:
        aggregate = self.aggregate(**filters)
        data = aggregate.data
        return ServicePayload(
            {
                "range": data.range,
                "total": data.article_count,
                "bullish": data.bullish_count,
                "bearish": data.bearish_count,
                "neutral": data.neutral_count,
            },
            aggregate.meta,
        )

    def symbol_summary(self, symbol: str, range_name: str = "24h") -> ServicePayload:
        news = self.query(symbol=symbol, freshness="live", fallback="recent", limit=5)
        sentiment = self.aggregate(symbol=symbol, range_name=range_name)
        upcoming = self.calendar.query(
            symbol=symbol, start_time=datetime.now(UTC), end_time=datetime.now(UTC) + timedelta(hours=24), limit=5
        )
        return ServicePayload(
            {
                "symbol": symbol,
                "latest": news.data.items,
                "sentiment": sentiment.data,
                "upcoming_events": upcoming.data.items,
            },
            self.meta("latest"),
        )

    def guard_preview(self, symbol: str) -> ServicePayload:
        now = datetime.now(UTC)
        upcoming = self.calendar.query(
            symbol=symbol, start_time=now, end_time=now + timedelta(hours=4), impact=ImpactLevel.HIGH, limit=1
        ).data.items
        aggregate = self.aggregate(symbol=symbol, range_name="24h").data
        event = upcoming[0] if upcoming else None
        minutes = max(0.0, (event.scheduled_at - now).total_seconds() / 60) if event else None
        reasons: list[str] = []
        action = "INSUFFICIENT_DATA" if aggregate.article_count == 0 and event is None else "ALLOW"
        if event:
            action = "BLOCK_PREVIEW" if minutes is not None and minutes <= 30 else "CAUTION"
            reasons.append(f"{event.impact.value} impact event {event.event_name} is scheduled nearby.")
        if aggregate.weighted_sentiment_score is not None and abs(aggregate.weighted_sentiment_score) >= 0.6:
            action = "CAUTION" if action == "ALLOW" else action
            reasons.append("Aggregate news sentiment is strongly directional.")
        label = (
            label_for_score(aggregate.weighted_sentiment_score or 0.0)
            if aggregate.article_count
            else SentimentLabel.UNKNOWN
        )
        return ServicePayload(
            GuardPreview(
                symbol=symbol,
                high_impact_event_nearby=event is not None,
                minutes_to_event=minutes,
                aggregate_sentiment=label,
                sentiment_confidence=aggregate.confidence,
                impact_score=event and (0.75 if event.impact == ImpactLevel.CRITICAL else 0.6),
                suggested_action=action,
                reasons=reasons,
            ),
            self.meta("latest"),
        )

    def provider_statuses(self) -> ServicePayload:
        return ServicePayload(self._provider_statuses_with_counts(), self.meta("providers"))

    def provider_status(self, provider_name: str) -> ServicePayload:
        item = next((status for status in self._provider_statuses_with_counts() if status.name == provider_name), None)
        if item is None:
            raise ResourceNotFoundError(f"News provider {provider_name!r} was not found")
        return ServicePayload(item, self.meta("providers"))

    def status(self) -> ServicePayload:
        statuses = self._news_statuses()
        collection = self.repository.last_collection
        configured = sum(item.configured and item.enabled for item in statuses)
        state = self._state(statuses)
        current_failed = {
            item.name
            for item in statuses
            if item.enabled and item.configured and not item.healthy and not item.rate_limited
        }
        current_rate_limited = {item.name for item in statuses if item.rate_limited}
        current_degraded = {item.name for item in statuses if item.status == "degraded"}
        partial = bool(collection.partial or current_failed or current_rate_limited or current_degraded)
        warnings = []
        if self.invalid_count:
            warnings.append(f"{self.invalid_count} invalid articles were rejected.")
        if self.sentiment.finbert.last_error:
            warnings.append(self.sentiment.finbert.last_error)
        if partial:
            warnings.append("News refresh completed with partial provider availability.")
        canonical = [item for item in self.articles_copy() if not item.is_duplicate]
        counts = Counter(item.freshness_status for item in canonical)
        data = NewsStatus(
            enabled=self.settings.news_enabled,
            state=state,
            provider_mode=self.settings.news_provider_priority,
            provider_count=len(statuses),
            configured_provider_count=configured,
            article_count=len(self._articles),
            raw_article_count=sum(item.raw_count or item.article_count for item in statuses),
            canonical_article_count=sum(not item.is_duplicate for item in self._articles),
            realtime_article_count=counts[NewsFreshnessStatus.REALTIME],
            recent_article_count=counts[NewsFreshnessStatus.RECENT],
            historical_article_count=counts[NewsFreshnessStatus.HISTORICAL],
            unknown_article_count=counts[NewsFreshnessStatus.UNKNOWN],
            calendar_event_count=len(self.calendar.events_copy()),
            last_refresh_at=self.last_refresh_at,
            last_success_at=self.last_success_at,
            analyzer=self.sentiment.analyzer_name if self.settings.news_sentiment_enabled else "disabled",
            finbert_enabled=self.settings.news_finbert_enabled,
            finbert_available=self.sentiment.finbert.available,
            scheduler_running=self.scheduler_running,
            external_requests_enabled=self.settings.news_external_requests_enabled,
            engine_integration_enabled=False,
            live_allowed=False,
            effective_max_lot=0.01,
            warnings=warnings,
            providers_attempted=collection.providers_attempted,
            providers_succeeded=collection.providers_succeeded,
            providers_failed=sorted(set(collection.providers_failed) | current_failed),
            providers_rate_limited=sorted(set(collection.providers_rate_limited) | current_rate_limited),
            providers_unconfigured=collection.providers_unconfigured,
            providers={item.name: item for item in statuses},
            partial=partial,
        )
        return ServicePayload(data, self.meta("providers"))

    def health(self) -> ServicePayload:
        status = self.status()
        return ServicePayload(
            {
                "status": status.data.state,
                "news_service": "healthy" if status.data.state == "live" else status.data.state,
                "news_scheduler": "healthy" if self.scheduler_running else "offline",
                "news_cache": "healthy" if self._articles else status.data.state,
                "sentiment_analyzer": "healthy" if self.settings.news_sentiment_enabled else "disabled",
                "economic_calendar": self.calendar.meta().data_status,
                "providers": [item.model_dump(mode="json") for item in self._provider_statuses_with_counts()],
                "live_allowed": False,
                "effective_max_lot": 0.01,
            },
            status.meta,
        )

    def system_components(self) -> dict[str, dict[str, Any]]:
        status = self.status().data
        base = {
            "last_heartbeat": self.last_refresh_at,
            "last_successful_update": self.last_success_at,
            "latest_error": "; ".join(status.warnings) or None,
            "stale": self.meta("providers").stale,
            "source_file": None,
        }
        rows = {
            "news_service": {"name": "news_service", "status": status.state, **base},
            "news_scheduler": {
                "name": "news_scheduler",
                "status": "healthy" if self.scheduler_running else "offline",
                **base,
            },
            "news_cache": {"name": "news_cache", "status": "healthy" if self._articles else status.state, **base},
            "sentiment_analyzer": {
                "name": "sentiment_analyzer",
                "status": "healthy" if self.settings.news_sentiment_enabled else "disabled",
                **base,
            },
            "economic_calendar": {"name": "economic_calendar", "status": self.calendar.meta().data_status, **base},
        }
        for provider in self.providers.statuses():
            rows[f"news_provider:{provider.name}"] = {
                "name": f"news_provider:{provider.name}",
                "status": provider.status,
                "last_heartbeat": provider.last_fetch_at,
                "last_successful_update": provider.last_success_at,
                "latest_error": provider.last_error,
                "stale": provider.stale,
                "source_file": self.settings.news_archive_path.name
                if provider.name == "file" and self.settings.news_archive_path
                else None,
            }
        return rows

    def meta(self, kind: str) -> NewsApiMeta:
        now = datetime.now(UTC)
        threshold: float = 600 if kind == "breaking" else 1800
        if kind == "providers":
            threshold = self.settings.news_global_refresh_interval_seconds * 2
        age = (now - self.last_success_at).total_seconds() if self.last_success_at else None
        statuses = self._news_statuses()
        available = any(item.healthy or item.article_count > 0 for item in statuses)
        stale = age is None or age > threshold or any(item.stale and item.article_count > 0 for item in statuses)
        state = self._state(statuses)
        warnings = []
        if state == "provider_unconfigured":
            warnings.append("News provider is not configured. Configure a trusted provider in the backend environment.")
        canonical = [item for item in self.articles_copy() if not item.is_duplicate]
        counts = Counter(item.freshness_status for item in canonical)
        published = [item.published_at for item in canonical if item.published_at]
        return NewsApiMeta(
            source="news_service",
            source_updated_at=self.last_success_at,
            server_timestamp=now,
            age_seconds=age,
            stale=stale,
            source_available=available,
            data_status=state,
            warnings=warnings,
            realtime_article_count=counts[NewsFreshnessStatus.REALTIME],
            recent_article_count=counts[NewsFreshnessStatus.RECENT],
            historical_article_count=counts[NewsFreshnessStatus.HISTORICAL],
            unknown_article_count=counts[NewsFreshnessStatus.UNKNOWN],
            oldest_article_at=min(published, default=None),
            latest_article_at=max(published, default=None),
            freshness_threshold_hours={
                "realtime": self.settings.news_realtime_max_age_hours,
                "recent": self.settings.news_recent_max_age_hours,
            },
        )

    def _state(self, statuses: list[ProviderStatus]) -> str:
        if not self.settings.news_enabled:
            return "disabled"
        if not any(item.enabled and item.configured for item in statuses):
            return "provider_unconfigured"
        if any(item.healthy for item in statuses):
            return "live"
        if any(item.rate_limited for item in statuses):
            return "rate_limited"
        if any(item.article_count > 0 for item in statuses):
            return "stale"
        return "error"

    def _news_statuses(self) -> list[ProviderStatus]:
        return [
            item
            for item in self._provider_statuses_with_counts()
            if any(
                key.endswith("news") or key in {"replay", "offline_snapshot"}
                for key, available in item.capability_details.items()
                if available is True
            )
        ]

    def _provider_statuses_with_counts(self) -> list[ProviderStatus]:
        articles = self.articles_copy()
        result = []
        for status in self.providers.statuses():
            provider_rows = [item for item in articles if item.provider == status.name]
            canonical_rows = [item for item in provider_rows if not item.is_duplicate]
            result.append(
                status.model_copy(
                    update={
                        "raw_count": status.article_count,
                        "canonical_count": len(canonical_rows),
                        "raw_article_count": status.article_count,
                        "canonical_article_count": len(canonical_rows),
                        "realtime_article_count": sum(
                            item.freshness_status == NewsFreshnessStatus.REALTIME for item in canonical_rows
                        ),
                        "recent_article_count": sum(
                            item.freshness_status == NewsFreshnessStatus.RECENT for item in canonical_rows
                        ),
                    }
                )
            )
        return result
