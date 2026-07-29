from __future__ import annotations

CURRENCY_ALIASES = {
    "$": "USD",
    "US$": "USD",
    "€": "EUR",
    "£": "GBP",
    "¥": "JPY",
    "C$": "CAD",
    "A$": "AUD",
    "NZ$": "NZD",
    "Fr": "CHF",
}


class TradingEconomicsCalendarAdapter:
    def normalize(self, raw: dict, *, known_symbols: list[str]) -> dict:
        del known_symbols
        importance_value = raw.get("Importance", raw.get("importance"))
        try:
            importance = int(str(importance_value)) if importance_value is not None else 0
        except (TypeError, ValueError):
            importance = 0
        impact = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}.get(importance, "UNKNOWN")
        actual = raw.get("Actual", raw.get("actual"))
        revised = raw.get("Revised", raw.get("revised"))
        return {
            "id": raw.get("CalendarId") or raw.get("CalendarID") or raw.get("calendarId"),
            "event_name": raw.get("Event") or raw.get("event") or raw.get("Category") or raw.get("category"),
            "country": raw.get("Country", raw.get("country")),
            "currency": CURRENCY_ALIASES.get(
                str(raw.get("Currency", raw.get("currency"))), raw.get("Currency", raw.get("currency"))
            ),
            "category": raw.get("Category", raw.get("category")),
            "impact": impact,
            "scheduled_at": raw.get("Date", raw.get("date")),
            "actual": actual,
            "forecast": raw.get("Forecast", raw.get("forecast")),
            "previous": raw.get("Previous", raw.get("previous")),
            "revised_previous": revised,
            "unit": raw.get("Unit", raw.get("unit")),
            "status": "REVISED"
            if actual is not None and revised is not None
            else "RELEASED"
            if actual is not None
            else "SCHEDULED",
            "description": raw.get("Category"),
            "source": raw.get("Source", raw.get("source")),
            "source_url": raw.get("SourceURL", raw.get("sourceURL")),
            "reference_period": raw.get("Reference")
            or raw.get("reference")
            or raw.get("ReferenceDate")
            or raw.get("referenceDate"),
            "updated_at": raw.get("LastUpdate", raw.get("lastUpdate")),
        }
