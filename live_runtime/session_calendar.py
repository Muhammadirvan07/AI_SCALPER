"""Fail-closed UTC session calendar builder for broker shadow evidence."""

from __future__ import annotations

from datetime import datetime, timedelta
import json
import os
from pathlib import Path
from typing import Mapping
from zoneinfo import ZoneInfo

import pandas as pd

from validation_evidence import canonical_evidence_payload_sha256
from validation_evidence.secure_core import _normalize_session_calendar

from .benchmark import REQUIRED_SYMBOLS
from .contracts import require_utc


CALENDAR_BUNDLE_SCHEMA_VERSION = "broker-calendar-bundle-v1"
M15 = timedelta(minutes=15)
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_LOT = 0.01


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


def _segments(symbol: str, start: datetime, end: datetime, timezone_name: str):
    timezone = ZoneInfo(timezone_name)
    buckets: list[tuple[datetime, datetime, bool, str, str]] = []
    cursor = start
    while cursor < end:
        local = cursor.astimezone(timezone)
        opened, reason, label = _scheduled_state(symbol, local)
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
    review = plan.get("special_hours_review")
    if not isinstance(review, Mapping) or review.get("attested") is not True:
        raise SessionCalendarError("special-hours review must be explicitly attested")
    if review.get("affected_required_symbols") != []:
        raise SessionCalendarError("special-hours changes require explicit closure intervals")
    last_date = str(review.get("covered_through_server_date") or "")
    timezone_name = str(plan.get("server_timezone") or "")
    timezone = ZoneInfo(timezone_name)
    required_trading_dates = {
        cursor.astimezone(timezone).date().isoformat()
        for cursor in (start + index * M15 for index in range(int((blind - start) / M15)))
        if cursor.astimezone(timezone).weekday() < 5
    }
    if not required_trading_dates or max(required_trading_dates) > last_date:
        raise SessionCalendarError("special-hours review does not cover the trading window")

    symbols = plan.get("broker_symbols")
    if not isinstance(symbols, Mapping) or set(symbols) != set(REQUIRED_SYMBOLS):
        raise SessionCalendarError("broker symbol map must contain the four required symbols")
    calendars: dict[str, object] = {}
    hashes: dict[str, str] = {}
    receipt_hash = str(plan.get("discovery_receipt_sha256") or "")
    source_instance_id = str(plan.get("source_instance_id") or "").strip()
    if not source_instance_id:
        raise SessionCalendarError("one terminal cohort source_instance_id is required")
    for symbol in sorted(REQUIRED_SYMBOLS):
        broker_symbol = str(symbols[symbol])
        broker_source = {
            "provider_kind": "BROKER_EXPORT",
            "broker_legal_name": str(plan.get("broker_legal_name")),
            "broker_server": str(plan.get("broker_server")),
            "environment": "DEMO",
            "broker_symbol": broker_symbol,
            "source_instance_id": source_instance_id,
        }
        intervals, closures = _segments(symbol, start, blind, timezone_name)
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
        "calendars": calendars,
        "session_calendar_sha256": hashes,
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "max_lot": MAX_LOT,
    }
    return {**body, "bundle_sha256": canonical_evidence_payload_sha256(body)}


def write_calendar_bundle_exclusive(path: str | Path, payload: Mapping[str, object]) -> Path:
    destination = Path(path)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("calendar output already exists or is a symlink")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    return destination
