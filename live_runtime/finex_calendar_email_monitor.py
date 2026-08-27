"""Prospective, signed FINEX calendar-email monitoring checkpoints.

This module records byte-derived mailbox export evidence.  It deliberately
cannot establish final calendar completeness or authorize order submission;
an independent final review remains mandatory after the blind window.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
from typing import Callable, Iterable, Mapping

from .account_identity import AccountIdentityError, payload_hmac_sha256
from .contracts import canonical_sha256
from .secure_files import SecureFileError, write_json_exclusive


CONTRACT_SCHEMA = "finex-calendar-email-monitor-contract-v1"
CHECKPOINT_SCHEMA = "finex-calendar-email-checkpoint-v1"
REPORT_SCHEMA = "finex-calendar-email-monitor-report-v1"
KEY_NAME = "finex-calendar-email-monitor-v1"
SIGNATURE_DOMAIN = b"ai-scalper/finex-calendar-email-checkpoint/v1"
MAX_EXPORT_BYTES = 25 * 1024 * 1024
MAX_CLOCK_SKEW = timedelta(minutes=5)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_RESULTS = frozenset({"NO_RELEVANT_NOTICE", "NOTICE_CAPTURED"})
_CONTRACT_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "calendar_version",
        "monitoring_channel",
        "observation_start_at_utc",
        "blind_until_utc",
        "max_checkpoint_gap_hours",
        "max_checkpoint_recording_lag_hours",
        "accepted_export_suffixes",
        "required_query_scope",
        "final_independent_review_required",
        "execution_enabled",
        "live_allowed",
        "safe_to_demo_auto_order",
        "authorization_granted",
        "order_capability",
    }
)
_CHECKPOINT_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "calendar_version",
        "contract_sha256",
        "checkpoint_id",
        "coverage_start_at_utc",
        "coverage_end_at_utc",
        "observed_at_utc",
        "operator_id",
        "key_id",
        "mailbox_export_file_name",
        "mailbox_export_suffix",
        "mailbox_export_bytes",
        "mailbox_export_sha256",
        "query_scope",
        "complete_export_attested",
        "result",
        "notice_count",
        "final_independent_review_complete",
        "future_exception_completeness",
        "execution_enabled",
        "live_allowed",
        "safe_to_demo_auto_order",
        "authorization_granted",
        "order_capability",
        "signature_hmac_sha256",
    }
)


class FinexCalendarEmailMonitorError(ValueError):
    """Raised when monitoring evidence is incomplete or invalid."""


def _reject_constant(_: str) -> None:
    raise FinexCalendarEmailMonitorError("non-finite JSON is not allowed")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FinexCalendarEmailMonitorError("duplicate JSON key")
        result[key] = value
    return result


def load_json_object(path: str | Path) -> dict[str, object]:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise FinexCalendarEmailMonitorError("JSON input must be a regular file")
    try:
        with source.open("r", encoding="utf-8") as handle:
            value = json.load(
                handle,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
    except FinexCalendarEmailMonitorError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FinexCalendarEmailMonitorError("JSON input invalid") from exc
    if not isinstance(value, dict):
        raise FinexCalendarEmailMonitorError("JSON input must be an object")
    return value


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value or value != value.strip():
        raise FinexCalendarEmailMonitorError(f"{field} invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FinexCalendarEmailMonitorError(f"{field} invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise FinexCalendarEmailMonitorError(f"{field} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise FinexCalendarEmailMonitorError("trusted clock must be timezone-aware")
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _identifier(value: object, field: str) -> str:
    normalized = str(value or "").strip().lower()
    if _IDENTIFIER.fullmatch(normalized) is None:
        raise FinexCalendarEmailMonitorError(f"{field} invalid")
    return normalized


def validate_contract(contract: Mapping[str, object]) -> dict[str, object]:
    if set(contract) != set(_CONTRACT_FIELDS):
        raise FinexCalendarEmailMonitorError("monitoring contract fields invalid")
    start = _utc(contract.get("observation_start_at_utc"), "observation start")
    blind = _utc(contract.get("blind_until_utc"), "blind until")
    suffixes = contract.get("accepted_export_suffixes")
    if (
        contract.get("schema_version") != CONTRACT_SCHEMA
        or contract.get("candidate_id") != "finex"
        or contract.get("calendar_version") != "finex-window-01-v2"
        or contract.get("monitoring_channel") != "FINEX_REGISTERED_EMAIL"
        or not start < blind
        or contract.get("max_checkpoint_gap_hours") != 168
        or contract.get("max_checkpoint_recording_lag_hours") != 24
        or not isinstance(suffixes, list)
        or suffixes != sorted(set(suffixes))
        or any(
            not isinstance(item, str)
            or not item.startswith(".")
            or item != item.lower()
            for item in suffixes
        )
        or contract.get("required_query_scope")
        != "ALL_FINEX_TRADING_HOURS_HOLIDAY_AND_MARKET_CLOSURE_NOTICES"
        or contract.get("final_independent_review_required") is not True
        or contract.get("execution_enabled") is not False
        or contract.get("live_allowed") is not False
        or contract.get("safe_to_demo_auto_order") is not False
        or contract.get("authorization_granted") is not False
        or contract.get("order_capability") != "DISABLED"
    ):
        raise FinexCalendarEmailMonitorError("monitoring contract invalid")
    canonical_sha256(contract)
    return deepcopy(dict(contract))


def _stable_export(path: str | Path) -> tuple[str, str, int, bytes]:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise FinexCalendarEmailMonitorError("mailbox export must be a regular file")
    flags = os.O_RDONLY
    for name in ("O_BINARY", "O_CLOEXEC", "O_NOFOLLOW"):
        flags |= int(getattr(os, name, 0))
    try:
        descriptor = os.open(source, flags)
        try:
            before = os.fstat(descriptor)
            if before.st_size <= 0 or before.st_size > MAX_EXPORT_BYTES:
                raise FinexCalendarEmailMonitorError("mailbox export size invalid")
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    raise FinexCalendarEmailMonitorError("mailbox export truncated")
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except FinexCalendarEmailMonitorError:
        raise
    except OSError as exc:
        raise FinexCalendarEmailMonitorError("mailbox export read failed") from exc
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if identity_before != identity_after:
        raise FinexCalendarEmailMonitorError("mailbox export changed during read")
    payload = b"".join(chunks)
    return source.name, source.suffix.lower(), len(payload), payload


def _checkpoint_body(checkpoint: Mapping[str, object]) -> dict[str, object]:
    return {
        key: deepcopy(value)
        for key, value in checkpoint.items()
        if key != "signature_hmac_sha256"
    }


def create_checkpoint(
    contract: Mapping[str, object],
    *,
    mailbox_export_path: str | Path,
    coverage_start_at: datetime,
    coverage_end_at: datetime,
    result: str,
    notice_count: int,
    operator_id: str,
    signing_key: bytes,
    complete_export_attested: bool,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    validated = validate_contract(contract)
    start = _utc(validated["observation_start_at_utc"], "observation start")
    blind = _utc(validated["blind_until_utc"], "blind until")
    now = now_provider()
    if now.tzinfo is None or now.utcoffset() is None:
        raise FinexCalendarEmailMonitorError("trusted clock must be timezone-aware")
    now = now.astimezone(timezone.utc)
    if (
        coverage_start_at.tzinfo is None
        or coverage_end_at.tzinfo is None
        or coverage_start_at.utcoffset() is None
        or coverage_end_at.utcoffset() is None
    ):
        raise FinexCalendarEmailMonitorError("coverage timestamps must be aware")
    coverage_start = coverage_start_at.astimezone(timezone.utc)
    coverage_end = coverage_end_at.astimezone(timezone.utc)
    if (
        coverage_start < start
        or coverage_end > blind
        or not coverage_start < coverage_end
        or coverage_end > now + MAX_CLOCK_SKEW
        or now > coverage_end + timedelta(hours=24) + MAX_CLOCK_SKEW
        or coverage_end - coverage_start > timedelta(hours=168)
    ):
        raise FinexCalendarEmailMonitorError("checkpoint coverage invalid")
    normalized_result = str(result or "").strip().upper()
    if normalized_result not in _RESULTS or type(notice_count) is not int:
        raise FinexCalendarEmailMonitorError("checkpoint result invalid")
    if (
        (normalized_result == "NO_RELEVANT_NOTICE" and notice_count != 0)
        or (normalized_result == "NOTICE_CAPTURED" and notice_count <= 0)
        or not complete_export_attested
    ):
        raise FinexCalendarEmailMonitorError("checkpoint attestation incomplete")
    if not isinstance(signing_key, bytes) or len(signing_key) < 32:
        raise FinexCalendarEmailMonitorError("checkpoint signing key invalid")
    file_name, suffix, byte_count, payload = _stable_export(mailbox_export_path)
    if suffix not in validated["accepted_export_suffixes"]:
        raise FinexCalendarEmailMonitorError("mailbox export suffix not accepted")
    export_hash = hashlib.sha256(payload).hexdigest()
    observed = _utc_text(now)
    identity = _identifier(operator_id, "operator_id")
    checkpoint_claim = {
        "contract_sha256": canonical_sha256(validated),
        "coverage_start_at_utc": _utc_text(coverage_start),
        "coverage_end_at_utc": _utc_text(coverage_end),
        "mailbox_export_sha256": export_hash,
        "operator_id": identity,
    }
    body: dict[str, object] = {
        "schema_version": CHECKPOINT_SCHEMA,
        "candidate_id": "finex",
        "calendar_version": validated["calendar_version"],
        "contract_sha256": canonical_sha256(validated),
        "checkpoint_id": "finex-email-" + canonical_sha256(checkpoint_claim)[:32],
        "coverage_start_at_utc": _utc_text(coverage_start),
        "coverage_end_at_utc": _utc_text(coverage_end),
        "observed_at_utc": observed,
        "operator_id": identity,
        "key_id": KEY_NAME,
        "mailbox_export_file_name": file_name,
        "mailbox_export_suffix": suffix,
        "mailbox_export_bytes": byte_count,
        "mailbox_export_sha256": export_hash,
        "query_scope": validated["required_query_scope"],
        "complete_export_attested": True,
        "result": normalized_result,
        "notice_count": notice_count,
        "final_independent_review_complete": False,
        "future_exception_completeness": False,
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "authorization_granted": False,
        "order_capability": "DISABLED",
    }
    try:
        signature = payload_hmac_sha256(
            body,
            signing_key,
            domain=SIGNATURE_DOMAIN,
        )
    except AccountIdentityError as exc:
        raise FinexCalendarEmailMonitorError("checkpoint signing failed") from exc
    return {**body, "signature_hmac_sha256": signature}


def verify_checkpoint(
    contract: Mapping[str, object],
    checkpoint: Mapping[str, object],
    *,
    signing_key: bytes,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    validated = validate_contract(contract)
    if set(checkpoint) != set(_CHECKPOINT_FIELDS):
        raise FinexCalendarEmailMonitorError("checkpoint fields invalid")
    if not isinstance(signing_key, bytes) or len(signing_key) < 32:
        raise FinexCalendarEmailMonitorError("checkpoint signing key invalid")
    start = _utc(validated["observation_start_at_utc"], "observation start")
    blind = _utc(validated["blind_until_utc"], "blind until")
    coverage_start = _utc(checkpoint.get("coverage_start_at_utc"), "coverage start")
    coverage_end = _utc(checkpoint.get("coverage_end_at_utc"), "coverage end")
    observed = _utc(checkpoint.get("observed_at_utc"), "observed at")
    now = now_provider()
    if now.tzinfo is None or now.utcoffset() is None:
        raise FinexCalendarEmailMonitorError("trusted clock must be timezone-aware")
    now = now.astimezone(timezone.utc)
    result = checkpoint.get("result")
    notice_count = checkpoint.get("notice_count")
    if (
        checkpoint.get("schema_version") != CHECKPOINT_SCHEMA
        or checkpoint.get("candidate_id") != "finex"
        or checkpoint.get("calendar_version") != validated["calendar_version"]
        or checkpoint.get("contract_sha256") != canonical_sha256(validated)
        or checkpoint.get("key_id") != KEY_NAME
        or checkpoint.get("query_scope") != validated["required_query_scope"]
        or checkpoint.get("complete_export_attested") is not True
        or result not in _RESULTS
        or type(notice_count) is not int
        or (result == "NO_RELEVANT_NOTICE" and notice_count != 0)
        or (result == "NOTICE_CAPTURED" and notice_count <= 0)
        or coverage_start < start
        or coverage_end > blind
        or not coverage_start < coverage_end
        or coverage_end - coverage_start > timedelta(hours=168)
        or observed < coverage_end
        or observed > coverage_end + timedelta(hours=24) + MAX_CLOCK_SKEW
        or observed > now + MAX_CLOCK_SKEW
        or checkpoint.get("mailbox_export_suffix")
        not in validated["accepted_export_suffixes"]
        or type(checkpoint.get("mailbox_export_bytes")) is not int
        or int(checkpoint.get("mailbox_export_bytes", 0)) <= 0
        or int(checkpoint.get("mailbox_export_bytes", 0)) > MAX_EXPORT_BYTES
        or _SHA256.fullmatch(str(checkpoint.get("mailbox_export_sha256") or ""))
        is None
        or checkpoint.get("final_independent_review_complete") is not False
        or checkpoint.get("future_exception_completeness") is not False
        or checkpoint.get("execution_enabled") is not False
        or checkpoint.get("live_allowed") is not False
        or checkpoint.get("safe_to_demo_auto_order") is not False
        or checkpoint.get("authorization_granted") is not False
        or checkpoint.get("order_capability") != "DISABLED"
    ):
        raise FinexCalendarEmailMonitorError("checkpoint binding invalid")
    _identifier(checkpoint.get("operator_id"), "operator_id")
    claim = {
        "contract_sha256": checkpoint["contract_sha256"],
        "coverage_start_at_utc": checkpoint["coverage_start_at_utc"],
        "coverage_end_at_utc": checkpoint["coverage_end_at_utc"],
        "mailbox_export_sha256": checkpoint["mailbox_export_sha256"],
        "operator_id": checkpoint["operator_id"],
    }
    if checkpoint.get("checkpoint_id") != (
        "finex-email-" + canonical_sha256(claim)[:32]
    ):
        raise FinexCalendarEmailMonitorError("checkpoint id invalid")
    try:
        expected = payload_hmac_sha256(
            _checkpoint_body(checkpoint),
            signing_key,
            domain=SIGNATURE_DOMAIN,
        )
    except AccountIdentityError as exc:
        raise FinexCalendarEmailMonitorError("checkpoint verification failed") from exc
    if not hmac.compare_digest(
        str(checkpoint.get("signature_hmac_sha256") or ""), expected
    ):
        raise FinexCalendarEmailMonitorError("checkpoint signature invalid")
    return deepcopy(dict(checkpoint))


def assemble_monitor_report(
    contract: Mapping[str, object],
    checkpoints: Iterable[Mapping[str, object]],
    *,
    signing_key: bytes,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    validated = validate_contract(contract)
    now = now_provider()
    if now.tzinfo is None or now.utcoffset() is None:
        raise FinexCalendarEmailMonitorError("trusted clock must be timezone-aware")
    now = now.astimezone(timezone.utc)
    start = _utc(validated["observation_start_at_utc"], "observation start")
    blind = _utc(validated["blind_until_utc"], "blind until")
    verified = [
        verify_checkpoint(
            validated,
            checkpoint,
            signing_key=signing_key,
            now_provider=lambda: now,
        )
        for checkpoint in checkpoints
    ]
    if len({item["checkpoint_id"] for item in verified}) != len(verified):
        raise FinexCalendarEmailMonitorError("duplicate checkpoint id")
    verified.sort(key=lambda item: item["coverage_start_at_utc"])
    gaps: list[dict[str, str]] = []
    cursor = start
    for item in verified:
        item_start = _utc(item["coverage_start_at_utc"], "coverage start")
        item_end = _utc(item["coverage_end_at_utc"], "coverage end")
        if item_start > cursor:
            gaps.append(
                {
                    "gap_start_at_utc": _utc_text(cursor),
                    "gap_end_at_utc": _utc_text(item_start),
                }
            )
        if item_end > cursor:
            cursor = item_end
    coverage_end = min(cursor, blind)
    if now < start:
        status = "NOT_STARTED"
    elif gaps:
        status = "INCOMPLETE_GAPS"
    elif coverage_end < min(now, blind):
        status = "INCOMPLETE_TO_CURRENT_TIME"
    elif now < blind:
        status = "IN_PROGRESS"
    else:
        status = "PENDING_INDEPENDENT_FINAL_REVIEW"
    notices = sum(int(item["notice_count"]) for item in verified)
    body: dict[str, object] = {
        "schema_version": REPORT_SCHEMA,
        "candidate_id": "finex",
        "calendar_version": validated["calendar_version"],
        "contract_sha256": canonical_sha256(validated),
        "generated_at_utc": _utc_text(now),
        "status": status,
        "checkpoint_count": len(verified),
        "checkpoint_sha256": [canonical_sha256(item) for item in verified],
        "coverage_start_at_utc": _utc_text(start),
        "coverage_end_at_utc": _utc_text(coverage_end),
        "blind_until_utc": _utc_text(blind),
        "coverage_gaps": gaps,
        "notice_count": notices,
        "notice_review_required": notices > 0,
        "final_independent_review_required": True,
        "final_independent_review_complete": False,
        "future_exception_completeness": False,
        "registration_enabled": False,
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "authorization_granted": False,
        "order_capability": "DISABLED",
    }
    return {**body, "report_sha256": canonical_sha256(body)}


def write_artifact_exclusive(path: str | Path, payload: Mapping[str, object]) -> Path:
    try:
        return write_json_exclusive(path, payload)
    except FileExistsError:
        raise
    except (OSError, SecureFileError, TypeError, ValueError) as exc:
        raise FinexCalendarEmailMonitorError("artifact write failed") from exc
