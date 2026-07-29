from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.schemas.economic_calendar import (
    CalendarGuardState,
    EconomicCalendarEvent,
    EconomicCalendarGuardPreview,
    EconomicEventCategory,
    EconomicImpact,
)

CRITICAL_CATEGORIES = {
    EconomicEventCategory.INTEREST_RATE,
    EconomicEventCategory.CPI,
    EconomicEventCategory.NFP,
}
HIGH_CATEGORIES = {
    EconomicEventCategory.GDP,
    EconomicEventCategory.PPI,
    EconomicEventCategory.RETAIL_SALES,
    EconomicEventCategory.UNEMPLOYMENT,
    EconomicEventCategory.JOLTS,
    EconomicEventCategory.MEETING_MINUTES,
    EconomicEventCategory.PMI,
    EconomicEventCategory.INFLATION,
    EconomicEventCategory.EMPLOYMENT,
}
MEDIUM_CATEGORIES = {
    EconomicEventCategory.CONSUMER_CONFIDENCE,
    EconomicEventCategory.INDUSTRIAL_PRODUCTION,
    EconomicEventCategory.HOUSING,
    EconomicEventCategory.TRADE_BALANCE,
    EconomicEventCategory.SPEECH,
    EconomicEventCategory.ENERGY,
    EconomicEventCategory.INVENTORIES,
}


def classify_category(name: str, provider_category: object = None) -> EconomicEventCategory:
    explicit = str(provider_category or "").strip().upper()
    if explicit:
        try:
            return EconomicEventCategory(explicit)
        except ValueError:
            pass
    text = name.lower()
    rules: tuple[tuple[EconomicEventCategory, tuple[str, ...]], ...] = (
        (EconomicEventCategory.NFP, ("non-farm payroll", "nonfarm payroll", "employment situation")),
        (EconomicEventCategory.CPI, ("consumer price index", " cpi")),
        (EconomicEventCategory.PPI, ("producer price index", " ppi")),
        (EconomicEventCategory.INTEREST_RATE, ("rate decision", "monetary policy decision", "fomc")),
        (EconomicEventCategory.MEETING_MINUTES, ("meeting minutes", "monetary policy accounts", "minutes")),
        (EconomicEventCategory.JOLTS, ("job openings", "jolts")),
        (EconomicEventCategory.UNEMPLOYMENT, ("unemployment", "jobless claims")),
        (EconomicEventCategory.EMPLOYMENT, ("employment", "labor", "earnings", "payroll")),
        (EconomicEventCategory.GDP, ("gross domestic product", " gdp")),
        (EconomicEventCategory.RETAIL_SALES, ("retail sales",)),
        (EconomicEventCategory.PMI, ("pmi", "purchasing managers")),
        (EconomicEventCategory.CONSUMER_CONFIDENCE, ("consumer confidence", "confidence index")),
        (EconomicEventCategory.INDUSTRIAL_PRODUCTION, ("industrial production", "manufacturing production")),
        (EconomicEventCategory.HOUSING, ("housing", "home sales", "building permits")),
        (EconomicEventCategory.TRADE_BALANCE, ("trade balance", "international trade", "goods and services")),
        (EconomicEventCategory.INVENTORIES, ("inventories", "inventory")),
        (EconomicEventCategory.ENERGY, ("petroleum", "natural gas", "energy")),
        (EconomicEventCategory.SPEECH, ("speech", "remarks", "lecture", "testimony")),
        (EconomicEventCategory.FINANCIAL_STABILITY, ("financial stability",)),
        (EconomicEventCategory.REGULATION, ("regulation", "regulatory")),
        (EconomicEventCategory.INFLATION, ("inflation", "price index", "pce price")),
        (EconomicEventCategory.CENTRAL_BANK, ("central bank", "federal reserve", "ecb", "governing council")),
    )
    padded = f" {text}"
    for category, terms in rules:
        if any(term in padded for term in terms):
            return category
    return EconomicEventCategory.OTHER


def classify_impact(
    name: str,
    category: EconomicEventCategory,
    *,
    currency: str | None,
) -> tuple[float, EconomicImpact, list[str]]:
    text = name.lower()
    reasons: list[str] = []
    if category in CRITICAL_CATEGORIES:
        score = 0.9
        reasons.append("Historically high-volatility macro release")
        if category == EconomicEventCategory.INTEREST_RATE:
            reasons.append("Major central-bank decision")
        elif category == EconomicEventCategory.NFP:
            reasons.append("Major employment release")
        else:
            reasons.append("Headline consumer inflation release")
    elif category in HIGH_CATEGORIES:
        score = 0.7
        reasons.append("Primary macroeconomic indicator")
    elif category in MEDIUM_CATEGORIES:
        score = 0.43
        reasons.append("Secondary market-moving indicator")
    elif category == EconomicEventCategory.OTHER:
        score = 0.15
        reasons.append("No high-priority deterministic rule matched")
    else:
        score = 0.28
        reasons.append("Routine official economic release")
    if "emergency" in text:
        score = max(score, 0.96)
        reasons.append("Emergency announcement")
    if currency in {"USD", "EUR", "GBP", "JPY"} and score >= 0.43:
        score = min(1.0, score + 0.03)
        reasons.append(f"Direct {currency} market impact")
    impact = (
        EconomicImpact.CRITICAL
        if score >= 0.75
        else EconomicImpact.HIGH
        if score >= 0.5
        else EconomicImpact.MEDIUM
        if score >= 0.25
        else EconomicImpact.LOW
    )
    return round(score, 4), impact, reasons


class EconomicCalendarGuardService:
    def preview(
        self,
        symbol: str,
        events: list[EconomicCalendarEvent],
        *,
        now: datetime | None = None,
        enabled: bool = True,
    ) -> EconomicCalendarGuardPreview:
        normalized = symbol.upper()
        if not enabled:
            return EconomicCalendarGuardPreview(
                symbol=normalized,
                state=CalendarGuardState.INSUFFICIENT_DATA,
                reasons=["Guard preview is disabled by backend configuration."],
            )
        current = now or datetime.now(UTC)
        candidates = [
            event
            for event in events
            if normalized in event.affected_symbols
            and event.impact in {EconomicImpact.HIGH, EconomicImpact.CRITICAL}
            and event.status.value != "CANCELLED"
            and event.metadata.get("schedule_precision", "DATETIME") == "DATETIME"
            and current - timedelta(minutes=15) <= event.scheduled_at <= current + timedelta(minutes=60)
        ]
        if not candidates:
            return EconomicCalendarGuardPreview(
                symbol=normalized,
                state=CalendarGuardState.NORMAL if events else CalendarGuardState.INSUFFICIENT_DATA,
                reasons=[
                    "No verified high-impact event is inside the 60-minute monitoring window."
                    if events
                    else "No verified calendar events are available."
                ],
            )
        event = min(candidates, key=lambda item: abs((item.scheduled_at - current).total_seconds()))
        minutes = (event.scheduled_at - current).total_seconds() / 60
        if event.stale or not event.verified:
            state = CalendarGuardState.INSUFFICIENT_DATA
            reason = (
                "Calendar source data is stale."
                if event.stale
                else "The approaching event has not been verified by an official source."
            )
        elif -5 <= minutes <= 1:
            state = CalendarGuardState.BLOCK_PREVIEW
            reason = "Within the read-only one-minute pre-release to five-minute post-release window."
        elif -15 <= minutes < -5:
            state = CalendarGuardState.POST_RELEASE_VOLATILITY
            reason = "Inside the read-only post-release volatility window."
        elif 1 < minutes <= 10:
            state = CalendarGuardState.HIGH_RISK
            reason = "High-impact release is less than ten minutes away."
        elif 10 < minutes <= 60:
            state = CalendarGuardState.CAUTION
            reason = "High-impact release is inside the 60-minute watch window."
        else:
            state = CalendarGuardState.NORMAL
            reason = "No elevated preview window is active."
        return EconomicCalendarGuardPreview(
            symbol=normalized,
            state=state,
            event_id=event.id,
            event_name=event.event_name,
            event_impact=event.impact,
            event_scheduled_at=event.scheduled_at,
            minutes_to_event=round(minutes, 2),
            reasons=[
                reason,
                *([f"{normalized} has direct {event.currency} exposure."] if event.currency else []),
                "Preview only; execution gates are not modified.",
            ],
        )
