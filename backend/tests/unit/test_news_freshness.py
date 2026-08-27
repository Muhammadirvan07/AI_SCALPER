from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.core.config import Settings
from app.schemas.news import NewsFreshnessStatus, NewsListData
from app.services.news_freshness import classify_news_freshness

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("hours", "status"),
    [
        (0.25, NewsFreshnessStatus.REALTIME),
        (0.5, NewsFreshnessStatus.REALTIME),
        (0.51, NewsFreshnessStatus.RECENT),
        (73, NewsFreshnessStatus.RECENT),
        (167, NewsFreshnessStatus.RECENT),
        (169, NewsFreshnessStatus.HISTORICAL),
    ],
)
def test_freshness_boundaries(hours: float, status: NewsFreshnessStatus) -> None:
    result = classify_news_freshness(NOW - timedelta(hours=hours), now=NOW)
    assert result.status == status
    assert result.stale is (status != NewsFreshnessStatus.REALTIME)
    assert result.is_realtime is (status == NewsFreshnessStatus.REALTIME)
    assert result.is_recent is (status == NewsFreshnessStatus.RECENT)
    assert result.is_historical is (status == NewsFreshnessStatus.HISTORICAL)


def test_missing_timezone_and_clock_skew_are_handled_safely() -> None:
    missing = classify_news_freshness(None, now=NOW)
    assert missing.status == NewsFreshnessStatus.UNKNOWN and missing.age_hours is None and missing.stale

    aware = classify_news_freshness(NOW.astimezone(tz=UTC) - timedelta(hours=4), now=NOW)
    assert aware.age_hours == 4 and aware.status == NewsFreshnessStatus.RECENT

    tolerated = classify_news_freshness(NOW + timedelta(minutes=4), now=NOW, clock_skew_tolerance_minutes=5)
    assert tolerated.age_hours == 0 and tolerated.status == NewsFreshnessStatus.REALTIME

    invalid_future = classify_news_freshness(NOW + timedelta(minutes=6), now=NOW, clock_skew_tolerance_minutes=5)
    assert invalid_future.status == NewsFreshnessStatus.UNKNOWN and invalid_future.stale


def test_legacy_age_configuration_maps_to_realtime_threshold(settings) -> None:
    values = settings.model_dump()
    values["websocket_heartbeat_seconds"] = 2
    values["news_max_article_age_hours"] = 48
    legacy = Settings(**values)
    assert legacy.news_realtime_max_age_hours == 48
    assert legacy.news_recent_max_age_hours == 168

    values["news_max_article_age_hours"] = None
    values["news_realtime_max_age_hours"] = 72
    values["news_recent_max_age_hours"] = 24
    with pytest.raises(ValueError, match="NEWS_RECENT_MAX_AGE_HOURS"):
        Settings(**values)


def test_api_threshold_schema_accepts_fractional_hours_and_rejects_unsafe_values() -> None:
    valid = NewsListData(
        items=[],
        total=0,
        limit=1,
        offset=0,
        freshness_threshold_hours={"realtime": 0.5, "recent": 168.0},
    )
    assert valid.freshness_threshold_hours["realtime"] == 0.5

    for unsafe in (0.0, -0.5, float("inf"), float("nan")):
        with pytest.raises(ValueError):
            NewsListData(
                items=[],
                total=0,
                limit=1,
                offset=0,
                freshness_threshold_hours={"realtime": unsafe},
            )
