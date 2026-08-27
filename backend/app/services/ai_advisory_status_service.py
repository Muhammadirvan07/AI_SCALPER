from __future__ import annotations

from typing import Any

from app.core.config import Settings


REQUIRED_CALENDAR_CURRENCIES = frozenset({"AUD", "EUR", "JPY", "USD"})
PROVIDER_CURRENCY_COVERAGE = {
    "bea": frozenset({"USD"}),
    "bls": frozenset({"USD"}),
    "ecb": frozenset({"EUR"}),
    "federal_reserve": frozenset({"USD"}),
    "trading_economics": REQUIRED_CALENDAR_CURRENCIES,
}


def _value(source: Any, name: str, default: Any = None) -> Any:
    if isinstance(source, dict):
        return source.get(name, default)
    return getattr(source, name, default)


def build_ai_advisory_status(
    settings: Settings,
    *,
    news_meta: Any,
    calendar_meta: Any,
    calendar_sources: Any = None,
) -> dict[str, Any]:
    """Project effective advisory mode without granting execution authority."""

    news_ready = bool(
        _value(news_meta, "source_available", False)
        and not _value(news_meta, "stale", True)
        and str(_value(news_meta, "data_status", "")).lower() == "live"
        and int(_value(news_meta, "realtime_article_count", 0) or 0) > 0
    )
    calendar_source_ready = bool(
        _value(calendar_meta, "source_available", False)
        and not _value(calendar_meta, "stale", True)
        and str(_value(calendar_meta, "data_status", "")).lower() == "live"
    )
    source_rows = calendar_sources if isinstance(calendar_sources, (list, tuple)) else ()
    covered_currencies: set[str] = set()
    admitted_sources: list[str] = []
    for source in source_rows:
        name = str(_value(source, "name", "")).strip().lower()
        coverage = PROVIDER_CURRENCY_COVERAGE.get(name, frozenset())
        if (
            coverage
            and _value(source, "enabled", False) is True
            and _value(source, "configured", False) is True
            and _value(source, "healthy", False) is True
            and _value(source, "stale", False) is not True
            and str(_value(source, "status", "")).lower() == "healthy"
        ):
            covered_currencies.update(coverage)
            admitted_sources.append(name)
    missing_currencies = sorted(REQUIRED_CALENDAR_CURRENCIES - covered_currencies)
    calendar_ready = calendar_source_ready and not missing_currencies
    requested = settings.openai_decision_enabled
    credential_configured = bool(settings.openai_api_key.get_secret_value())
    evidence_blockers: list[str] = []
    if not news_ready:
        evidence_blockers.append("LIVE_NEWS_UNAVAILABLE_OR_STALE")
    if not calendar_source_ready:
        evidence_blockers.append("ECONOMIC_CALENDAR_UNAVAILABLE_OR_STALE")
    if missing_currencies:
        evidence_blockers.append("ECONOMIC_CALENDAR_CURRENCY_COVERAGE_INCOMPLETE")
    readiness_blockers = list(evidence_blockers)
    if not requested:
        readiness_blockers.append("OPENAI_DECISION_NOT_REQUESTED")
    if not credential_configured:
        readiness_blockers.append("OPENAI_CREDENTIAL_UNAVAILABLE")
    blockers = list(evidence_blockers) if requested else []

    if not requested:
        mode = "DISABLED"
    elif blockers:
        mode = "BLOCKED_EVIDENCE"
    elif credential_configured:
        mode = "OPENAI_ADVISORY"
    elif settings.openai_deterministic_fallback_enabled:
        mode = "FALLBACK_DETERMINISTIC"
        blockers.append("OPENAI_CREDENTIAL_UNAVAILABLE")
    else:
        mode = "BLOCKED_CONFIGURATION"
        blockers.append("OPENAI_CREDENTIAL_UNAVAILABLE")

    return {
        "requested": requested,
        "effective_mode": mode,
        "model": settings.openai_decision_model,
        "credential_configured": credential_configured,
        "deterministic_fallback_enabled": settings.openai_deterministic_fallback_enabled,
        "news_ready": news_ready,
        "economic_calendar_ready": calendar_ready,
        "economic_calendar_currency_coverage": {
            "required": sorted(REQUIRED_CALENDAR_CURRENCIES),
            "covered": sorted(covered_currencies),
            "missing": missing_currencies,
            "admitted_sources": sorted(admitted_sources),
        },
        "blockers": blockers,
        "readiness_blockers": readiness_blockers,
        "advisory_only": True,
        "execution_scope": "PAPER_ONLY",
        "live_allowed": False,
        "order_capability": "DISABLED",
    }
