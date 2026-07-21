"""Fail-closed UTC session calendar builder for broker shadow evidence."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, Mapping
from zoneinfo import ZoneInfo

import pandas as pd

from validation_evidence import canonical_evidence_payload_sha256
from validation_evidence.secure_core import _normalize_session_calendar

from .benchmark import REQUIRED_SYMBOLS
from .contracts import require_utc
from .secure_files import write_json_exclusive


CALENDAR_BUNDLE_SCHEMA_VERSION = "broker-calendar-bundle-v1"
M15 = timedelta(minutes=15)
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_LOT = 0.01
CLOSURE_REASON_CODES = frozenset(
    {
        "WEEKEND",
        "HOLIDAY",
        "DAILY_BREAK",
        "PARTIAL_SESSION_CLOSE",
        "ROLLOVER",
        "BROKER_MAINTENANCE",
        "OTHER_SCHEDULED_CLOSURE",
    }
)


class SessionCalendarError(ValueError):
    pass


def _utc(value: object, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise SessionCalendarError(f"{field} must be ISO UTC") from exc
    require_utc(field, parsed)
    if parsed.second or parsed.microsecond or parsed.minute % 15:
        raise SessionCalendarError(f"{field} must align to M15")
    return parsed


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _scheduled_state(symbol: str, local: datetime) -> tuple[bool, str, str]:
    if local.weekday() >= 5:
        return False, "WEEKEND", "XM scheduled weekend closure"
    # XM's published symbol specification closes the final Friday session
    # before midnight.  A 23:45 M15 bucket therefore cannot be proven with a
    # right-boundary tick at 00:00 and must be excluded conservatively.
    if local.weekday() == 4 and local.hour == 23 and local.minute >= 45:
        return (
            False,
            "PARTIAL_SESSION_CLOSE",
            "XM scheduled Friday partial-session close",
        )
    # GOLD quotes stop shortly before midnight on ordinary trading days and
    # resume at 01:00 server time.  Close the final partial M15 bucket rather
    # than registering a bar the broker cannot finalize.
    if symbol == "XAUUSD" and (
        local.hour < 1 or (local.hour == 23 and local.minute >= 45)
    ):
        return False, "DAILY_BREAK", "XM GOLD scheduled daily break"
    return True, "", ""


def _local_minute(value: object, field: str, *, allow_2400: bool = False) -> int:
    text = str(value or "")
    if allow_2400 and text == "24:00":
        return 24 * 60
    parts = text.split(":")
    if (
        len(parts) != 2
        or not all(part.isdigit() for part in parts)
        or not 0 <= int(parts[0]) <= 23
        or int(parts[1]) not in {0, 15, 30, 45}
    ):
        raise SessionCalendarError(f"{field} must be an M15-aligned HH:MM value")
    return int(parts[0]) * 60 + int(parts[1])


def validate_weekly_m15_sessions(
    value: object,
    *,
    required_symbols: Iterable[str] = REQUIRED_SYMBOLS,
) -> dict[str, tuple[tuple[int, int, int], ...]]:
    """Validate an explicit broker-local weekly M15 eligibility schedule."""

    symbols = tuple(str(symbol).upper() for symbol in required_symbols)
    if (
        not symbols
        or len(set(symbols)) != len(symbols)
        or not set(symbols) <= set(REQUIRED_SYMBOLS)
    ):
        raise SessionCalendarError("required symbol subset is invalid")
    if not isinstance(value, Mapping) or set(value) != set(symbols):
        raise SessionCalendarError(
            "weekly_m15_sessions must exactly match the required symbols"
        )
    normalized: dict[str, tuple[tuple[int, int, int], ...]] = {}
    for symbol in sorted(symbols):
        raw_sessions = value[symbol]
        if (
            isinstance(raw_sessions, (str, bytes))
            or not isinstance(raw_sessions, Iterable)
        ):
            raise SessionCalendarError(f"weekly sessions are invalid: {symbol}")
        sessions: list[tuple[int, int, int]] = []
        for index, raw in enumerate(raw_sessions):
            if not isinstance(raw, Mapping) or set(raw) != {
                "weekday",
                "open_local",
                "close_local",
            }:
                raise SessionCalendarError(
                    f"weekly session fields are invalid: {symbol}:{index}"
                )
            weekday = raw["weekday"]
            if type(weekday) is not int or not 0 <= weekday <= 6:
                raise SessionCalendarError(
                    f"weekly session weekday is invalid: {symbol}:{index}"
                )
            opened = _local_minute(
                raw["open_local"],
                f"{symbol} open_local",
            )
            closed = _local_minute(
                raw["close_local"],
                f"{symbol} close_local",
                allow_2400=True,
            )
            if opened >= closed:
                raise SessionCalendarError(
                    f"weekly session must not cross midnight: {symbol}:{index}"
                )
            sessions.append((weekday, opened, closed))
        sessions.sort()
        for previous, current in zip(sessions, sessions[1:]):
            if previous[0] == current[0] and current[1] < previous[2]:
                raise SessionCalendarError(
                    f"weekly sessions overlap: {symbol}:{current[0]}"
                )
        if not sessions:
            raise SessionCalendarError(f"weekly sessions are empty: {symbol}")
        normalized[symbol] = tuple(sessions)
    return normalized


def _registered_closures(
    review: Mapping[str, object],
    *,
    required_symbols: Iterable[str] = REQUIRED_SYMBOLS,
) -> tuple[dict[str, object], ...]:
    symbols_allowed = set(str(symbol).upper() for symbol in required_symbols)
    raw_closures = review.get("registered_closures", [])
    if not isinstance(raw_closures, list):
        raise SessionCalendarError("registered_closures must be a list")
    closures: list[dict[str, object]] = []
    for index, raw in enumerate(raw_closures):
        if not isinstance(raw, Mapping) or set(raw) != {
            "symbols",
            "start_at_utc",
            "end_at_utc",
            "reason_code",
            "label",
        }:
            raise SessionCalendarError(
                f"registered closure fields are invalid: {index}"
            )
        symbols = raw["symbols"]
        if (
            not isinstance(symbols, list)
            or not symbols
            or not set(symbols) <= symbols_allowed
        ):
            raise SessionCalendarError(
                f"registered closure symbols are invalid: {index}"
            )
        start = _utc(raw["start_at_utc"], f"closure {index} start_at_utc")
        end = _utc(raw["end_at_utc"], f"closure {index} end_at_utc")
        if start >= end:
            raise SessionCalendarError(
                f"registered closure interval is invalid: {index}"
            )
        reason = str(raw["reason_code"] or "").strip().upper()
        label = str(raw["label"] or "").strip()
        if reason not in CLOSURE_REASON_CODES or not label:
            raise SessionCalendarError(
                f"registered closure reason is invalid: {index}"
            )
        closures.append(
            {
                "symbols": tuple(sorted(set(str(item) for item in symbols))),
                "start": start,
                "end": end,
                "reason": reason,
                "label": label,
            }
        )
    return tuple(closures)


def _explicit_scheduled_state(
    symbol: str,
    opened_at_utc: datetime,
    local: datetime,
    sessions: Mapping[str, tuple[tuple[int, int, int], ...]],
    closures: tuple[dict[str, object], ...],
) -> tuple[bool, str, str]:
    close_at_utc = opened_at_utc + M15
    for closure in closures:
        if symbol in closure["symbols"] and (
            opened_at_utc < closure["end"] and close_at_utc > closure["start"]
        ):
            return False, str(closure["reason"]), str(closure["label"])
    minute = local.hour * 60 + local.minute
    if any(
        weekday == local.weekday() and opened <= minute and minute + 15 <= closed
        for weekday, opened, closed in sessions[symbol]
    ):
        return True, "", ""
    return (
        False,
        "OTHER_SCHEDULED_CLOSURE",
        "Broker-attested weekly session closure",
    )


def _segments(
    symbol: str,
    start: datetime,
    end: datetime,
    timezone_name: str,
    *,
    explicit_sessions: Mapping[str, tuple[tuple[int, int, int], ...]] | None = None,
    registered_closures: tuple[dict[str, object], ...] = (),
):
    timezone = ZoneInfo(timezone_name)
    buckets: list[tuple[datetime, datetime, bool, str, str]] = []
    cursor = start
    while cursor < end:
        local = cursor.astimezone(timezone)
        if explicit_sessions is None:
            opened, reason, label = _scheduled_state(symbol, local)
        else:
            opened, reason, label = _explicit_scheduled_state(
                symbol,
                cursor,
                local,
                explicit_sessions,
                registered_closures,
            )
        buckets.append((cursor, cursor + M15, opened, reason, label))
        cursor += M15

    merged: list[list[object]] = []
    for opened_at, closed_at, opened, reason, label in buckets:
        key = (opened, reason, label)
        if merged and merged[-1][2] == key:
            merged[-1][1] = closed_at
        else:
            merged.append([opened_at, closed_at, key])
    intervals: list[dict[str, str]] = []
    closures: list[dict[str, str]] = []
    for opened_at, closed_at, state in merged:
        opened, reason, label = state
        if opened:
            intervals.append({"open_at_utc": _iso(opened_at), "close_at_utc": _iso(closed_at)})
        else:
            closures.append({
                "start_at_utc": _iso(opened_at),
                "end_at_utc": _iso(closed_at),
                "reason_code": reason,
                "label": label,
            })
    return intervals, closures


def build_calendar_bundle(plan: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(plan, Mapping):
        raise SessionCalendarError("calendar plan must be a mapping")
    start = _utc(plan.get("observation_start_at_utc"), "observation_start_at_utc")
    blind = _utc(plan.get("blind_until_utc"), "blind_until_utc")
    captured = _utc(plan.get("captured_at_utc"), "captured_at_utc")
    if not captured < start < blind:
        raise SessionCalendarError("calendar must be captured before a future window")
    symbols = plan.get("broker_symbols")
    if not isinstance(symbols, Mapping):
        raise SessionCalendarError("broker symbol map must be an object")
    required_symbols = tuple(
        symbol for symbol in REQUIRED_SYMBOLS if symbol in symbols
    )
    if (
        not required_symbols
        or set(symbols) != set(required_symbols)
        or any(not str(symbols[symbol] or "").strip() for symbol in required_symbols)
    ):
        raise SessionCalendarError("broker symbol map is outside the v1 lane allowlist")
    review = plan.get("special_hours_review")
    policy = plan.get("calendar_amendment_policy")
    amendment_enabled = bool(
        isinstance(policy, Mapping)
        and policy.get("mode") == "CLOSURE_ONLY_PROSPECTIVE_V1"
        and isinstance(policy.get("minimum_lead_seconds"), int)
        and not isinstance(policy.get("minimum_lead_seconds"), bool)
        and int(policy["minimum_lead_seconds"]) >= 900
        and int(policy["minimum_lead_seconds"]) % 900 == 0
        and policy.get("completeness_attestation_required") is True
        and policy.get("source_document_required") is True
    )
    if (
        not isinstance(review, Mapping)
        or type(review.get("attested")) is not bool
        or (review.get("attested") is not True and not amendment_enabled)
    ):
        raise SessionCalendarError("special-hours review must be explicitly attested")
    registered_closures = _registered_closures(
        review,
        required_symbols=required_symbols,
    )
    affected = review.get("affected_required_symbols")
    if not isinstance(affected, list) or set(affected) - set(required_symbols):
        raise SessionCalendarError("affected_required_symbols is invalid")
    closure_symbols = {
        symbol
        for closure in registered_closures
        for symbol in closure["symbols"]
    }
    if set(affected) != closure_symbols:
        raise SessionCalendarError(
            "special-hours changes require explicit closure intervals with an exact symbol match"
        )
    explicit_sessions = (
        validate_weekly_m15_sessions(
            plan.get("weekly_m15_sessions"),
            required_symbols=required_symbols,
        )
        if "weekly_m15_sessions" in plan
        else None
    )
    last_date = str(review.get("covered_through_server_date") or "")
    timezone_name = str(plan.get("server_timezone") or "")
    timezone = ZoneInfo(timezone_name)
    required_trading_dates = {
        cursor.astimezone(timezone).date().isoformat()
        for cursor in (start + index * M15 for index in range(int((blind - start) / M15)))
        if cursor.astimezone(timezone).weekday() < 5
    }
    if (
        not required_trading_dates
        or (
            review.get("attested") is True
            and max(required_trading_dates) > last_date
        )
    ):
        raise SessionCalendarError("special-hours review does not cover the trading window")

    calendars: dict[str, object] = {}
    hashes: dict[str, str] = {}
    receipt_hash = str(plan.get("discovery_receipt_sha256") or "")
    source_instance_id = str(plan.get("source_instance_id") or "").strip()
    if not source_instance_id:
        raise SessionCalendarError("one terminal cohort source_instance_id is required")
    for symbol in sorted(required_symbols):
        broker_symbol = str(symbols[symbol])
        broker_source = {
            "provider_kind": "BROKER_EXPORT",
            "broker_legal_name": str(plan.get("broker_legal_name")),
            "broker_server": str(plan.get("broker_server")),
            "environment": "DEMO",
            "broker_symbol": broker_symbol,
            "source_instance_id": source_instance_id,
        }
        intervals, closures = _segments(
            symbol,
            start,
            blind,
            timezone_name,
            explicit_sessions=explicit_sessions,
            registered_closures=registered_closures,
        )
        calendar = {
            "schema_version": "session-calendar-v1",
            "canonical_symbol": symbol,
            "timezone": "UTC",
            "observation_start_at_utc": _iso(start),
            "blind_until_utc": _iso(blind),
            "market_open_intervals": intervals,
            "closures": closures,
            "metadata": {
                **broker_source,
                "calendar_version": str(plan.get("calendar_version")),
                "captured_at_utc": _iso(captured),
            },
        }
        normalized = _normalize_session_calendar(
            symbol,
            calendar,
            observation=pd.Timestamp(start),
            blind=pd.Timestamp(blind),
            registered=pd.Timestamp(captured),
            broker_source=broker_source,
        )
        calendars[symbol] = normalized
        hashes[symbol] = canonical_evidence_payload_sha256(normalized)
    body = {
        "schema_version": CALENDAR_BUNDLE_SCHEMA_VERSION,
        "candidate_id": plan.get("candidate_id"),
        "plan_payload_sha256": plan.get("plan_payload_sha256"),
        "server_timezone": timezone_name,
        "discovery_receipt_sha256": receipt_hash,
        "special_hours_review": dict(review),
        **(
            {
                "prewindow_calendar_review_sha256": plan[
                    "prewindow_calendar_review"
                ]["review_artifact_sha256"]
            }
            if isinstance(plan.get("prewindow_calendar_review"), Mapping)
            else {}
        ),
        **(
            {"calendar_amendment_policy": dict(policy)}
            if amendment_enabled
            else {}
        ),
        "calendars": calendars,
        "session_calendar_sha256": hashes,
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "max_lot": MAX_LOT,
    }
    return {**body, "bundle_sha256": canonical_evidence_payload_sha256(body)}


def write_calendar_bundle_exclusive(path: str | Path, payload: Mapping[str, object]) -> Path:
    return write_json_exclusive(path, payload)


__all__ = [
    "CALENDAR_BUNDLE_SCHEMA_VERSION",
    "CLOSURE_REASON_CODES",
    "SessionCalendarError",
    "build_calendar_bundle",
    "validate_weekly_m15_sessions",
    "write_calendar_bundle_exclusive",
]
