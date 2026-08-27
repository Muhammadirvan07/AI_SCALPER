from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.schemas.news import NewsFreshnessStatus


@dataclass(frozen=True, slots=True)
class NewsFreshness:
    age_hours: float | None
    status: NewsFreshnessStatus
    is_realtime: bool
    is_recent: bool
    is_historical: bool
    stale: bool
    stale_reason: str | None


def classify_news_freshness(
    published_at: datetime | None,
    *,
    now: datetime | None = None,
    realtime_max_age_hours: float = 0.5,
    recent_max_age_hours: int = 168,
    clock_skew_tolerance_minutes: int = 5,
) -> NewsFreshness:
    reference = (now or datetime.now(UTC)).astimezone(UTC)
    if published_at is None:
        return NewsFreshness(
            None, NewsFreshnessStatus.UNKNOWN, False, False, False, True, "Article timestamp is unavailable."
        )
    timestamp = published_at.replace(tzinfo=UTC) if published_at.tzinfo is None else published_at.astimezone(UTC)
    delta = reference - timestamp
    if delta < -timedelta(minutes=clock_skew_tolerance_minutes):
        return NewsFreshness(
            None,
            NewsFreshnessStatus.UNKNOWN,
            False,
            False,
            False,
            True,
            "Article timestamp is beyond the permitted clock-skew tolerance.",
        )
    age_hours = round(max(0.0, delta.total_seconds() / 3600), 4)
    if age_hours <= realtime_max_age_hours:
        return NewsFreshness(age_hours, NewsFreshnessStatus.REALTIME, True, False, False, False, None)
    if age_hours <= recent_max_age_hours:
        return NewsFreshness(
            age_hours,
            NewsFreshnessStatus.RECENT,
            False,
            True,
            False,
            True,
            "Article is outside the realtime news window.",
        )
    return NewsFreshness(
        age_hours,
        NewsFreshnessStatus.HISTORICAL,
        False,
        False,
        True,
        True,
        "Article is outside the recent news window.",
    )


def freshness_update(value: NewsFreshness) -> dict[str, object]:
    return {
        "age_hours": value.age_hours,
        "freshness_status": value.status,
        "is_realtime": value.is_realtime,
        "is_recent": value.is_recent,
        "is_historical": value.is_historical,
        "stale": value.stale,
        "stale_reason": value.stale_reason,
    }
