from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime

from app.adapters.news_adapter import canonical_url, clean_text, symbol_components
from app.core.exceptions import InvalidDataFormatError
from app.schemas.economic_calendar import (
    EconomicCalendarEvent,
    EconomicEventStatus,
    EconomicImpact,
    EconomicSourceType,
    SurpriseLabel,
)
from app.services.economic_calendar_guard_service import classify_category, classify_impact
from app.utils.datetime import parse_datetime


class EconomicCalendarAdapter:
    def normalize(self, raw: dict, *, provider: str, known_symbols: list[str]) -> EconomicCalendarEvent:
        name = clean_text(raw.get("event_name") or raw.get("title") or raw.get("name"), maximum=240)
        scheduled = parse_datetime(
            raw.get("scheduled_at") or raw.get("time") or raw.get("timestamp") or raw.get("date")
        )
        if not name or scheduled is None:
            raise InvalidDataFormatError("Calendar event requires event_name and scheduled_at")
        currency = str(raw.get("currency") or "").strip().upper() or None
        country = clean_text(raw.get("country") or raw.get("region"), maximum=100)
        country_code = clean_text(raw.get("country_code"), maximum=4)
        if not currency:
            currency = {
                "united states": "USD",
                "eurozone": "EUR",
                "united kingdom": "GBP",
                "japan": "JPY",
                "switzerland": "CHF",
                "canada": "CAD",
                "australia": "AUD",
                "new zealand": "NZD",
            }.get((country or "").lower())
        explicit = raw.get("affected_symbols") or raw.get("symbols") or []
        if isinstance(explicit, str):
            explicit = [item.strip() for item in explicit.split(",")]
        symbols = {str(item).upper() for item in explicit if item}
        if currency:
            for symbol in known_symbols:
                _, parts = symbol_components(symbol)
                if currency in parts:
                    symbols.add(symbol)
            if currency == "USD":
                for symbol in known_symbols:
                    if symbol.startswith(("XAU", "XAG", "BTC", "ETH")):
                        symbols.add(symbol)
        category = classify_category(name, raw.get("category"))
        impact_score, impact, impact_reasons = classify_impact(name, category, currency=currency)
        # Trusted adapters and local replay files may already provide a
        # normalized internal impact. Preserve that explicit classification;
        # raw provider-specific labels are normalized before reaching here.
        explicit_impact = str(raw.get("impact") or "").strip().upper()
        if explicit_impact:
            try:
                impact = EconomicImpact(explicit_impact)
            except ValueError:
                pass
            else:
                impact_score = {
                    EconomicImpact.CRITICAL: 0.9,
                    EconomicImpact.HIGH: 0.7,
                    EconomicImpact.MEDIUM: 0.4,
                    EconomicImpact.LOW: 0.15,
                    EconomicImpact.UNKNOWN: 0.0,
                }[impact]
                impact_reasons = ["Normalized impact supplied by the trusted source adapter."]
        status_raw = str(raw.get("status") or ("RELEASED" if raw.get("actual") is not None else "SCHEDULED")).upper()
        try:
            status = EconomicEventStatus(status_raw)
        except ValueError:
            status = EconomicEventStatus.UNKNOWN
        raw_id = raw.get("id") or raw.get("event_id")
        event_id = (
            str(raw_id)
            if raw_id
            else hashlib.sha256(f"{provider}|{name}|{raw.get('reference_period') or ''}".encode()).hexdigest()[:24]
        )
        actual = raw.get("actual")
        forecast = raw.get("forecast")
        actual_number = self._number(actual)
        forecast_number = self._number(forecast)
        surprise = (
            actual_number - forecast_number if actual_number is not None and forecast_number is not None else None
        )
        surprise_percent = (
            surprise / abs(forecast_number) * 100
            if surprise is not None and forecast_number is not None and forecast_number != 0
            else None
        )
        surprise_label = (
            SurpriseLabel.NO_FORECAST
            if surprise is None
            else SurpriseLabel.ABOVE_FORECAST
            if surprise > 0
            else SurpriseLabel.BELOW_FORECAST
            if surprise < 0
            else SurpriseLabel.INLINE
        )
        try:
            source_type = EconomicSourceType(str(raw.get("source_type") or "UNKNOWN").upper())
        except ValueError:
            source_type = EconomicSourceType.UNKNOWN
        raw_metadata = raw.get("metadata")
        metadata: dict = dict(raw_metadata) if isinstance(raw_metadata, dict) else {}
        now = datetime.now(UTC)
        return EconomicCalendarEvent(
            id=f"{provider}:{event_id}",
            provider=provider,
            source=clean_text(raw.get("source") or raw.get("provider_source"), maximum=120) or provider,
            source_type=source_type,
            source_url=canonical_url(raw.get("source_url") or raw.get("url")),
            event_name=name,
            short_name=clean_text(raw.get("short_name"), maximum=100),
            description=clean_text(raw.get("description") or raw.get("summary"), maximum=1000),
            country=country,
            country_code=country_code,
            currency=currency,
            category=category,
            impact=impact,
            impact_score=impact_score,
            impact_reasons=impact_reasons,
            scheduled_at=scheduled,
            original_scheduled_at=parse_datetime(raw.get("original_scheduled_at")),
            actual=actual,
            actual_raw=raw.get("actual_raw"),
            forecast=forecast,
            forecast_source=clean_text(raw.get("forecast_source"), maximum=120),
            forecast_source_type=self._source_type(raw.get("forecast_source_type")),
            previous=raw.get("previous"),
            revised_previous=raw.get("revised_previous") or raw.get("revised"),
            revision_source=clean_text(raw.get("revision_source"), maximum=160),
            revised_at=parse_datetime(raw.get("revised_at")),
            unit=clean_text(raw.get("unit"), maximum=30),
            frequency=clean_text(raw.get("frequency"), maximum=40),
            status=status,
            affected_symbols=sorted(symbols),
            symbols=sorted(symbols),
            is_high_impact=impact.value in {"HIGH", "CRITICAL"},
            is_released=actual is not None,
            is_revised=status == EconomicEventStatus.REVISED,
            verified=bool(raw.get("verified", source_type == EconomicSourceType.OFFICIAL)),
            verified_at=parse_datetime(raw.get("verified_at")),
            last_checked_at=parse_datetime(raw.get("last_checked_at")) or now,
            released_at=parse_datetime(raw.get("released_at")),
            reference_period=clean_text(raw.get("reference_period") or raw.get("reference"), maximum=80),
            updated_at=parse_datetime(raw.get("updated_at")) or now,
            stale=bool(raw.get("stale", False)),
            stale_reason=clean_text(raw.get("stale_reason"), maximum=240),
            surprise=round(surprise, 6) if surprise is not None else None,
            surprise_percent=round(surprise_percent, 4) if surprise_percent is not None else None,
            surprise_label=surprise_label,
            metadata=dict(metadata),
        )

    @staticmethod
    def _number(value: object) -> float | None:
        if isinstance(value, bool) or value is None:
            return None
        if isinstance(value, int | float):
            return float(value)
        text = re.sub(r"[^0-9+\-.]", "", str(value).replace(",", ""))
        try:
            return float(text)
        except ValueError:
            return None

    @staticmethod
    def _source_type(value: object) -> EconomicSourceType | None:
        if value in (None, ""):
            return None
        try:
            return EconomicSourceType(str(value).upper())
        except ValueError:
            return EconomicSourceType.UNKNOWN
