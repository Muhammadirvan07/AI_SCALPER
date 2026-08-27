from types import SimpleNamespace

from pydantic import SecretStr

from app.services.ai_advisory_status_service import build_ai_advisory_status


def meta(*, available: bool = True, stale: bool = False, articles: int = 1):
    return SimpleNamespace(
        source_available=available,
        stale=stale,
        data_status="live" if available else "unavailable",
        realtime_article_count=articles,
    )


def complete_calendar_sources():
    return [
        SimpleNamespace(
            name="trading_economics",
            enabled=True,
            configured=True,
            healthy=True,
            stale=False,
            status="healthy",
        )
    ]


def test_ai_status_is_explicitly_disabled_by_default(settings):
    status = build_ai_advisory_status(
        settings,
        news_meta=meta(),
        calendar_meta=meta(),
        calendar_sources=complete_calendar_sources(),
    )
    assert status["effective_mode"] == "DISABLED"
    assert status["blockers"] == []
    assert "OPENAI_DECISION_NOT_REQUESTED" in status["readiness_blockers"]
    assert "OPENAI_CREDENTIAL_UNAVAILABLE" in status["readiness_blockers"]
    assert "ECONOMIC_CALENDAR_CURRENCY_COVERAGE_INCOMPLETE" not in status[
        "readiness_blockers"
    ]
    assert status["live_allowed"] is False
    assert status["order_capability"] == "DISABLED"


def test_ai_status_reports_openai_only_with_credential_and_fresh_evidence(settings):
    configured = settings.model_copy(
        update={
            "openai_decision_enabled": True,
            "openai_api_key": SecretStr("test-secret"),
        }
    )
    status = build_ai_advisory_status(
        configured,
        news_meta=meta(),
        calendar_meta=meta(),
        calendar_sources=complete_calendar_sources(),
    )
    assert status["effective_mode"] == "OPENAI_ADVISORY"
    assert status["credential_configured"] is True
    assert "test-secret" not in str(status)


def test_ai_status_fallback_and_stale_evidence_are_distinct(settings):
    configured = settings.model_copy(
        update={"openai_decision_enabled": True}
    )
    fallback = build_ai_advisory_status(
        configured,
        news_meta=meta(),
        calendar_meta=meta(),
        calendar_sources=complete_calendar_sources(),
    )
    blocked = build_ai_advisory_status(
        configured,
        news_meta=meta(stale=True),
        calendar_meta=meta(),
        calendar_sources=complete_calendar_sources(),
    )
    assert fallback["effective_mode"] == "FALLBACK_DETERMINISTIC"
    assert blocked["effective_mode"] == "BLOCKED_EVIDENCE"
    assert "LIVE_NEWS_UNAVAILABLE_OR_STALE" in blocked["blockers"]


def test_ai_status_rejects_usd_eur_only_calendar_coverage(settings):
    configured = settings.model_copy(
        update={
            "openai_decision_enabled": True,
            "openai_api_key": SecretStr("test-secret"),
        }
    )
    official_sources = [
        SimpleNamespace(
            name=name,
            enabled=True,
            configured=True,
            healthy=True,
            stale=False,
            status="healthy",
        )
        for name in ("bea", "bls", "ecb", "federal_reserve")
    ]
    status = build_ai_advisory_status(
        configured,
        news_meta=meta(),
        calendar_meta=meta(),
        calendar_sources=official_sources,
    )
    assert status["effective_mode"] == "BLOCKED_EVIDENCE"
    assert status["economic_calendar_currency_coverage"]["missing"] == [
        "AUD",
        "JPY",
    ]
    assert (
        "ECONOMIC_CALENDAR_CURRENCY_COVERAGE_INCOMPLETE"
        in status["blockers"]
    )
