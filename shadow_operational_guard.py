"""Stdlib-only operational safety controls for the XM read-only shadow runner."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import sqlite3
from typing import Mapping
import uuid


OPERATIONAL_EVENT_SCHEMA_VERSION = "xm-shadow-operational-event-v3"
LEGACY_OPERATIONAL_EVENT_SCHEMA_VERSIONS = frozenset(
    {
        "xm-shadow-operational-event-v1",
        "xm-shadow-operational-event-v2",
    }
)
OPERATIONAL_STATUS_SCHEMA_VERSION = "xm-shadow-operational-status-v2"
AUDIT_EXPORT_SCHEMA_VERSION = "xm-shadow-audit-export-v2"
AUDIT_EXPORT_MANIFEST_SCHEMA_VERSION = "xm-shadow-audit-export-manifest-v2"
RUNTIME_KEY = "xm-window-02-v3"
DEFAULT_MINIMUM_FREE_BYTES = 1_073_741_824
DEFAULT_HEARTBEAT_STALE_SECONDS = 180
_ZERO_HASH = "0" * 64
_ALLOWED_OUTCOMES = frozenset({"STARTED", "PASS", "HOLD", "BUSY"})
_ALLOWED_RUNTIME_STATES = frozenset({"RUNNING", "HEALTHY", "FAILED", "BUSY"})
_AUTHENTICATED = "HMAC_SHA256"
_UNAUTHENTICATED = "UNAUTHENTICATED"
_EVENT_HMAC_DOMAIN = b"AI_SCALPER_SHADOW_OPERATIONAL_EVENT_V1\0"
_STATUS_HMAC_DOMAIN = b"AI_SCALPER_SHADOW_RUNTIME_STATUS_V1\0"
_EXPORT_HMAC_DOMAIN = b"AI_SCALPER_SHADOW_AUDIT_EXPORT_V1\0"
_MANIFEST_HMAC_DOMAIN = b"AI_SCALPER_SHADOW_AUDIT_MANIFEST_V1\0"


class ShadowOperationalGuardError(RuntimeError):
    """Raised when a local operational safety control cannot be satisfied."""


class ShadowDiskSpaceHold(ShadowOperationalGuardError):
    """Raised before evidence mutation when free disk is below the hard floor."""


@dataclass(frozen=True)
class ShadowRuntimeStatus:
    reported_state: str
    recorded_state: str
    invocation_id: str | None
    stage: str | None
    heartbeat_at: datetime | None
    heartbeat_age_seconds: float | None
    last_success_at: datetime | None
    last_success_cycle_id: str | None
    failure_code: str | None
    stale: bool
    failed: bool
    head_event_sha256: str | None


@dataclass(frozen=True)
class ShadowAuditExportReceipt:
    export_path: Path
    manifest_path: Path
    export_sha256: str
    manifest_sha256: str
    operational_event_count: int
    operational_head_sha256: str
    authenticity: str
    signing_key_id: str | None


def _require_utc(name: str, value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ShadowOperationalGuardError(f"{name} must be timezone-aware UTC")
    normalized = value.astimezone(timezone.utc)
    if normalized.utcoffset() != timezone.utc.utcoffset(normalized):
        raise ShadowOperationalGuardError(f"{name} must normalize to UTC")
    return normalized


def _utc_text(value: datetime) -> str:
    return _require_utc("timestamp", value).isoformat().replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ShadowOperationalGuardError("stored timestamp is invalid") from exc
    return _require_utc("stored timestamp", parsed)


def _canonical_json(value: Mapping[str, object]) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _signing_key_id(signing_key: bytes) -> str:
    if not isinstance(signing_key, bytes) or len(signing_key) < 32:
        raise ShadowOperationalGuardError("operational signing key is invalid")
    return _sha256_bytes(signing_key)[:16]


def _hmac_bytes(signing_key: bytes, value: bytes) -> str:
    return hmac.new(signing_key, value, hashlib.sha256).hexdigest()


def _payload_hmac(
    payload: Mapping[str, object],
    *,
    signing_key: bytes,
    field: str,
    domain: bytes,
) -> str:
    unsigned = dict(payload)
    unsigned.pop(field, None)
    return _hmac_bytes(
        signing_key,
        domain + _canonical_json(unsigned).encode("utf-8"),
    )


def _is_sha256(value: object) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(
        character in "0123456789abcdef" for character in text
    )


def _verify_exported_event_chain(
    events: object,
    *,
    invocation_id: str,
    signing_key: bytes | None = None,
    expected_first_sequence: int | None = None,
    expected_initial_previous: str | None = None,
    initial_previous_signed_hmac: str | None = None,
    strict_authentication: bool = True,
) -> tuple[int, str, str | None]:
    event_count, head_hash, signed_head_hmac = _verify_event_chain_integrity(
        events,
        expected_first_sequence=expected_first_sequence,
        expected_initial_previous=expected_initial_previous,
        signing_key=signing_key,
        initial_previous_signed_hmac=initial_previous_signed_hmac,
        strict_authentication=strict_authentication,
    )
    assert isinstance(events, list)
    if (
        events[0].get("stage") != "INVOCATION"
        or events[0].get("outcome") != "STARTED"
        or events[0].get("invocation_id") != invocation_id
    ):
        raise ShadowOperationalGuardError(
            "audit export does not start at the primary invocation"
        )
    primary_terminal = False
    for item in events:
        if (
            item.get("invocation_id") == invocation_id
            and item.get("stage") == "INVOCATION_TERMINAL"
            and item.get("outcome") in {"PASS", "HOLD", "BUSY"}
        ):
            primary_terminal = True
    if not primary_terminal:
        raise ShadowOperationalGuardError(
            "audit export has no primary invocation terminal receipt"
        )
    return event_count, head_hash, signed_head_hmac


def _verify_event_chain_integrity(
    events: object,
    *,
    expected_first_sequence: int | None = None,
    expected_initial_previous: str | None = None,
    signing_key: bytes | None = None,
    initial_previous_signed_hmac: str | None = None,
    strict_authentication: bool = True,
) -> tuple[int, str, str | None]:
    if not isinstance(events, list) or not events:
        raise ShadowOperationalGuardError("audit export has no operational events")
    if (
        initial_previous_signed_hmac is not None
        and not _is_sha256(initial_previous_signed_hmac)
    ):
        raise ShadowOperationalGuardError(
            "operational signed predecessor anchor is invalid"
        )
    expected_key_id = (
        None if signing_key is None else _signing_key_id(signing_key)
    )
    previous_hash = None
    previous_sequence = None
    previous_signed_hmac = initial_previous_signed_hmac
    for index, item in enumerate(events):
        if not isinstance(item, dict):
            raise ShadowOperationalGuardError("audit export event is invalid")
        try:
            sequence = int(item["sequence"])
            payload_json = str(item["payload_json"])
            row_previous = str(item["previous_event_sha256"])
            event_hash = str(item["event_sha256"])
            payload = json.loads(payload_json)
        except (KeyError, TypeError, ValueError) as exc:
            raise ShadowOperationalGuardError(
                "audit export event fields are invalid"
            ) from exc
        if not isinstance(payload, dict) or _canonical_json(payload) != payload_json:
            raise ShadowOperationalGuardError(
                "audit export event payload is not canonical"
            )
        row_invocation = str(item.get("invocation_id") or "")
        if not row_invocation:
            raise ShadowOperationalGuardError(
                "audit export event invocation id is missing"
            )
        if (
            index == 0
            and expected_first_sequence is not None
            and sequence != expected_first_sequence
        ):
            raise ShadowOperationalGuardError(
                "audit export event chain does not start at genesis"
            )
        if (
            index == 0
            and expected_initial_previous is not None
            and row_previous != expected_initial_previous
        ):
            raise ShadowOperationalGuardError(
                "audit export event genesis anchor mismatch"
            )
        if previous_sequence is not None and sequence != previous_sequence + 1:
            raise ShadowOperationalGuardError(
                "audit export event sequence is discontinuous"
            )
        if previous_hash is not None and row_previous != previous_hash:
            raise ShadowOperationalGuardError(
                "audit export event chain is discontinuous"
            )
        if sequence <= 0 or not _is_sha256(row_previous) or not _is_sha256(
            event_hash
        ):
            raise ShadowOperationalGuardError(
                "audit export event chain fields are invalid"
            )
        observed_at = str(item.get("observed_at_utc") or "")
        _parse_utc(observed_at)
        stage = str(item.get("stage") or "")
        outcome = str(item.get("outcome") or "")
        reason_code = str(item.get("reason_code") or "")
        event_id = str(item.get("event_id") or "")
        if (
            not stage
            or stage != stage.upper()
            or outcome not in _ALLOWED_OUTCOMES
            or not reason_code
            or reason_code != reason_code.upper()
            or event_id != f"{row_invocation}-{sequence:012d}"
        ):
            raise ShadowOperationalGuardError(
                "audit export event identity fields are invalid"
            )
        expected_fields = {
            "sequence": sequence,
            "event_id": event_id,
            "invocation_id": row_invocation,
            "observed_at_utc": observed_at,
            "stage": stage,
            "outcome": outcome,
            "reason_code": reason_code,
            "previous_event_sha256": row_previous,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "order_capability": "DISABLED",
            "max_lot": 0.01,
        }
        schema_version = payload.get("schema_version")
        authenticity = str(
            item.get("authenticity") or _UNAUTHENTICATED
        )
        signing_key_id = item.get("signing_key_id")
        previous_event_hmac = item.get("previous_event_hmac_sha256")
        event_hmac = item.get("event_hmac_sha256")
        if schema_version == OPERATIONAL_EVENT_SCHEMA_VERSION:
            detail_type = payload.get("detail_type")
            metadata = payload.get("metadata")
            projection = payload.get("status_projection")
            if (
                detail_type is not None
                and (
                    not isinstance(detail_type, str)
                    or not detail_type.strip()
                )
            ):
                raise ShadowOperationalGuardError(
                    "operational event detail type is invalid"
                )
            if not isinstance(metadata, dict):
                raise ShadowOperationalGuardError(
                    "operational event metadata is invalid"
                )
            if not isinstance(projection, dict) or set(projection) != {
                "recorded_state",
                "last_success_at_utc",
                "last_success_cycle_id",
                "failure_code",
            }:
                raise ShadowOperationalGuardError(
                    "operational status projection is invalid"
                )
            if projection.get("recorded_state") not in _ALLOWED_RUNTIME_STATES:
                raise ShadowOperationalGuardError(
                    "operational projected runtime state is invalid"
                )
            success_at = projection.get("last_success_at_utc")
            success_cycle = projection.get("last_success_cycle_id")
            if (success_at is None) != (success_cycle is None):
                raise ShadowOperationalGuardError(
                    "operational success projection is incomplete"
                )
            if success_at is not None:
                _parse_utc(success_at)
                if not isinstance(success_cycle, str) or not success_cycle:
                    raise ShadowOperationalGuardError(
                        "operational success cycle is invalid"
                    )
            failure_code = projection.get("failure_code")
            if failure_code is not None and (
                not isinstance(failure_code, str)
                or not failure_code
                or failure_code != failure_code.upper()
            ):
                raise ShadowOperationalGuardError(
                    "operational failure projection is invalid"
                )
            expected_fields.update(
                {
                    "schema_version": OPERATIONAL_EVENT_SCHEMA_VERSION,
                    "detail_type": detail_type,
                    "metadata": metadata,
                    "authenticity": authenticity,
                    "signing_key_id": signing_key_id,
                    "previous_event_hmac_sha256": previous_event_hmac,
                    "status_projection": projection,
                }
            )
        elif schema_version in LEGACY_OPERATIONAL_EVENT_SCHEMA_VERSIONS:
            expected_fields["schema_version"] = schema_version
            if (
                authenticity != _UNAUTHENTICATED
                or signing_key_id is not None
                or previous_event_hmac is not None
                or event_hmac is not None
            ):
                raise ShadowOperationalGuardError(
                    "legacy operational event cannot claim authentication"
                )
        else:
            raise ShadowOperationalGuardError(
                "audit export event schema is invalid"
            )
        if any(payload.get(key) != value for key, value in expected_fields.items()):
            raise ShadowOperationalGuardError(
                "audit export event payload does not match its row"
            )
        expected_hash = _sha256_bytes(
            (row_previous + "\n" + payload_json).encode("utf-8")
        )
        if event_hash != expected_hash:
            raise ShadowOperationalGuardError(
                "audit export event hash mismatch"
            )
        if authenticity == _AUTHENTICATED:
            if (
                not isinstance(signing_key_id, str)
                or not signing_key_id
                or previous_event_hmac != previous_signed_hmac
                or not _is_sha256(event_hmac)
            ):
                raise ShadowOperationalGuardError(
                    "operational event HMAC fields are invalid"
                )
            if signing_key is None:
                if strict_authentication:
                    raise ShadowOperationalGuardError(
                        "operational signing key is required"
                    )
            elif signing_key_id != expected_key_id:
                raise ShadowOperationalGuardError(
                    "operational event signing key id mismatch"
                )
            else:
                expected_hmac = _hmac_bytes(
                    signing_key,
                    _EVENT_HMAC_DOMAIN
                    + (
                        (previous_signed_hmac or _ZERO_HASH)
                        + "\n"
                        + row_previous
                        + "\n"
                        + payload_json
                    ).encode("utf-8"),
                )
                if not hmac.compare_digest(str(event_hmac), expected_hmac):
                    raise ShadowOperationalGuardError(
                        "operational event HMAC mismatch"
                    )
            previous_signed_hmac = str(event_hmac)
        elif authenticity == _UNAUTHENTICATED:
            if (
                signing_key_id is not None
                or previous_event_hmac is not None
                or event_hmac is not None
            ):
                raise ShadowOperationalGuardError(
                    "unauthenticated operational event has HMAC fields"
                )
        else:
            raise ShadowOperationalGuardError(
                "operational event authenticity is invalid"
            )
        previous_hash = event_hash
        previous_sequence = sequence
    return len(events), str(previous_hash), previous_signed_hmac


def _projection_from_head_event(
    event: Mapping[str, object],
) -> dict[str, object]:
    try:
        payload = json.loads(str(event["payload_json"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ShadowOperationalGuardError(
            "operational head payload is invalid"
        ) from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != OPERATIONAL_EVENT_SCHEMA_VERSION
        or not isinstance(payload.get("status_projection"), dict)
    ):
        raise ShadowOperationalGuardError(
            "operational journal requires a fresh v3 status projection"
        )
    return dict(payload["status_projection"])


def _status_payload_from_head(
    event: Mapping[str, object],
) -> dict[str, object]:
    projection = _projection_from_head_event(event)
    return {
        "schema_version": OPERATIONAL_STATUS_SCHEMA_VERSION,
        "runtime_key": RUNTIME_KEY,
        "invocation_id": str(event["invocation_id"]),
        "recorded_state": projection["recorded_state"],
        "stage": str(event["stage"]),
        "heartbeat_at_utc": str(event["observed_at_utc"]),
        "last_success_at_utc": projection["last_success_at_utc"],
        "last_success_cycle_id": projection["last_success_cycle_id"],
        "failure_code": projection["failure_code"],
        "head_event_sequence": int(event["sequence"]),
        "head_event_sha256": str(event["event_sha256"]),
        "head_event_hmac_sha256": event.get("event_hmac_sha256"),
        "authenticity": str(event["authenticity"]),
        "signing_key_id": event.get("signing_key_id"),
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "order_capability": "DISABLED",
        "max_lot": 0.01,
    }


def _event_dicts_from_rows(
    event_rows: list[tuple[object, ...]],
) -> list[dict[str, object]]:
    return [
        {
            "sequence": int(row[0]),
            "event_id": str(row[1]),
            "invocation_id": str(row[2]),
            "observed_at_utc": str(row[3]),
            "stage": str(row[4]),
            "outcome": str(row[5]),
            "reason_code": str(row[6]),
            "payload_json": str(row[7]),
            "previous_event_sha256": str(row[8]),
            "event_sha256": str(row[9]),
            "authenticity": str(row[10]),
            "signing_key_id": row[11],
            "previous_event_hmac_sha256": row[12],
            "event_hmac_sha256": row[13],
        }
        for row in event_rows
    ]


def _next_status_projection(
    events: list[dict[str, object]],
    *,
    observed_at_utc: str,
    runtime_state: str | None,
    reason_code: str,
    last_success_cycle_id: str | None,
) -> dict[str, object]:
    if events:
        prior = _projection_from_head_event(events[-1])
        recorded_state = (
            str(prior["recorded_state"])
            if runtime_state is None
            else runtime_state
        )
        last_success_at = prior["last_success_at_utc"]
        success_cycle_id = prior["last_success_cycle_id"]
        failure_code = prior["failure_code"]
    else:
        recorded_state = runtime_state or "RUNNING"
        last_success_at = None
        success_cycle_id = None
        failure_code = None
    if last_success_cycle_id is not None:
        last_success_at = observed_at_utc
        success_cycle_id = str(last_success_cycle_id)
        failure_code = None
    elif recorded_state == "FAILED":
        failure_code = reason_code
    elif recorded_state in {"HEALTHY", "BUSY"}:
        failure_code = None
    return {
        "recorded_state": recorded_state,
        "last_success_at_utc": last_success_at,
        "last_success_cycle_id": success_cycle_id,
        "failure_code": failure_code,
    }


def _verify_status_row(
    status_row: tuple[object, ...] | None,
    events: list[dict[str, object]],
    *,
    signing_key: bytes | None,
    strict_authentication: bool,
) -> dict[str, object]:
    if status_row is None or not events:
        raise ShadowOperationalGuardError(
            "runtime status projection is missing"
        )
    expected = _status_payload_from_head(events[-1])
    try:
        (
            runtime_key,
            invocation_id,
            recorded_state,
            stage,
            heartbeat_at_utc,
            last_success_at_utc,
            last_success_cycle_id,
            failure_code,
            head_event_sequence,
            head_event_sha256,
            head_event_hmac_sha256,
            authenticity,
            signing_key_id,
            payload_json,
            payload_sha256,
            status_hmac_sha256,
        ) = status_row
    except (TypeError, ValueError) as exc:
        raise ShadowOperationalGuardError(
            "runtime status row is invalid"
        ) from exc
    row_fields = {
        "runtime_key": runtime_key,
        "invocation_id": invocation_id,
        "recorded_state": recorded_state,
        "stage": stage,
        "heartbeat_at_utc": heartbeat_at_utc,
        "last_success_at_utc": last_success_at_utc,
        "last_success_cycle_id": last_success_cycle_id,
        "failure_code": failure_code,
        "head_event_sequence": head_event_sequence,
        "head_event_sha256": head_event_sha256,
        "head_event_hmac_sha256": head_event_hmac_sha256,
        "authenticity": authenticity,
        "signing_key_id": signing_key_id,
    }
    if any(row_fields[key] != expected[key] for key in row_fields):
        raise ShadowOperationalGuardError(
            "runtime status projection integrity failed: "
            "does not derive from event head"
        )
    if (
        not isinstance(payload_json, str)
        or payload_json != _canonical_json(expected)
        or payload_sha256
        != _sha256_bytes(payload_json.encode("utf-8"))
    ):
        raise ShadowOperationalGuardError(
            "runtime status projection integrity failed"
        )
    if authenticity == _AUTHENTICATED:
        if (
            signing_key is None
            or signing_key_id != _signing_key_id(signing_key)
        ):
            if strict_authentication:
                raise ShadowOperationalGuardError(
                    "runtime status signing key is required"
                )
        else:
            expected_status_hmac = _hmac_bytes(
                signing_key,
                _STATUS_HMAC_DOMAIN + payload_json.encode("utf-8"),
            )
            if (
                not isinstance(status_hmac_sha256, str)
                or not hmac.compare_digest(
                    status_hmac_sha256,
                    expected_status_hmac,
                )
            ):
                raise ShadowOperationalGuardError(
                    "runtime status HMAC mismatch"
                )
        if not _is_sha256(status_hmac_sha256):
            raise ShadowOperationalGuardError(
                "runtime status HMAC is invalid"
            )
    elif authenticity == _UNAUTHENTICATED:
        if (
            signing_key_id is not None
            or head_event_hmac_sha256 is not None
            or status_hmac_sha256 is not None
        ):
            raise ShadowOperationalGuardError(
                "unauthenticated runtime status has HMAC fields"
            )
    else:
        raise ShadowOperationalGuardError(
            "runtime status authenticity is invalid"
        )
    return expected


def _verify_receipt_bindings(
    events: list[dict[str, object]],
    *,
    startup_guards: list[dict[str, object]],
    shadow_cycles: list[dict[str, object]],
) -> None:
    bindings: dict[tuple[str, str], dict[str, object]] = {}
    for event in events:
        try:
            payload = json.loads(str(event["payload_json"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise ShadowOperationalGuardError(
                "operational receipt binding payload is invalid"
            ) from exc
        metadata = payload.get("metadata")
        if not isinstance(metadata, dict):
            continue
        binding = metadata.get("receipt_binding")
        if binding is None:
            continue
        if not isinstance(binding, dict):
            raise ShadowOperationalGuardError(
                "operational receipt binding is invalid"
            )
        receipt_type = str(binding.get("receipt_type") or "")
        receipt_id = str(binding.get("receipt_id") or "")
        payload_sha256 = str(binding.get("payload_sha256") or "")
        if (
            receipt_type not in {"STARTUP_GUARD", "SHADOW_CYCLE"}
            or not receipt_id
            or not _is_sha256(payload_sha256)
        ):
            raise ShadowOperationalGuardError(
                "operational receipt binding fields are invalid"
            )
        key = (receipt_type, receipt_id)
        if key in bindings:
            raise ShadowOperationalGuardError(
                "operational receipt binding is duplicated"
            )
        bindings[key] = dict(binding)

    records_by_type = {
        "STARTUP_GUARD": startup_guards,
        "SHADOW_CYCLE": shadow_cycles,
    }
    identity_fields = {
        "STARTUP_GUARD": "startup_guard_id",
        "SHADOW_CYCLE": "cycle_id",
    }
    observed_bindings: set[tuple[str, str]] = set()
    for receipt_type, records in records_by_type.items():
        identity_field = identity_fields[receipt_type]
        for record in records:
            if not isinstance(record, dict):
                raise ShadowOperationalGuardError(
                    "audit export receipt record is invalid"
                )
            receipt_id = str(record.get(identity_field) or "")
            payload_json = str(record.get("payload_json") or "")
            payload_hash = str(record.get("payload_sha256") or "")
            if (
                not receipt_id
                or not _is_sha256(payload_hash)
                or _sha256_bytes(payload_json.encode("utf-8"))
                != payload_hash
            ):
                raise ShadowOperationalGuardError(
                    "audit export receipt hash is invalid"
                )
            try:
                receipt_payload = json.loads(payload_json)
            except (TypeError, ValueError) as exc:
                raise ShadowOperationalGuardError(
                    "audit export receipt payload is invalid"
                ) from exc
            if (
                not isinstance(receipt_payload, dict)
                or _canonical_json(receipt_payload) != payload_json
                or receipt_payload.get(identity_field) != receipt_id
                or receipt_payload.get("observed_at_utc")
                != record.get("observed_at_utc")
                or receipt_payload.get("status") != record.get("status")
                or receipt_payload.get("live_allowed") is not False
                or receipt_payload.get("safe_to_demo_auto_order") is not False
                or receipt_payload.get("max_lot") != 0.01
            ):
                raise ShadowOperationalGuardError(
                    "audit export receipt row does not match payload"
                )
            binding_key = (receipt_type, receipt_id)
            binding = bindings.get(binding_key)
            if (
                binding is None
                or binding.get("payload_sha256") != payload_hash
                or binding.get("status") != record.get("status")
            ):
                raise ShadowOperationalGuardError(
                    "audit export receipt is not bound to operational chain"
                )
            if receipt_type == "STARTUP_GUARD":
                dependency_receipt = receipt_payload.get(
                    "dependency_receipt"
                )
                environment_sha = (
                    dependency_receipt.get(
                        "installed_environment_sha256"
                    )
                    if isinstance(dependency_receipt, dict)
                    else None
                )
                if binding.get(
                    "installed_environment_sha256"
                ) != environment_sha:
                    raise ShadowOperationalGuardError(
                        "startup dependency receipt binding mismatch"
                    )
            observed_bindings.add(binding_key)
    if set(bindings) != observed_bindings:
        raise ShadowOperationalGuardError(
            "operational receipt binding has no exported receipt"
        )


def check_minimum_free_disk(
    path: str | Path,
    *,
    minimum_free_bytes: int = DEFAULT_MINIMUM_FREE_BYTES,
) -> dict[str, object]:
    """Return a receipt or raise before any broker evidence mutation."""

    if type(minimum_free_bytes) is not int or minimum_free_bytes < 0:
        raise ShadowOperationalGuardError("minimum free disk bytes is invalid")
    target = Path(path)
    probe = target
    while not probe.exists():
        parent = probe.parent
        if parent == probe:
            raise ShadowOperationalGuardError("disk probe has no existing ancestor")
        probe = parent
    try:
        usage = shutil.disk_usage(probe)
    except OSError as exc:
        raise ShadowOperationalGuardError("free disk measurement failed") from exc
    free_bytes = int(usage.free)
    required = minimum_free_bytes
    if free_bytes < required:
        raise ShadowDiskSpaceHold(
            f"free disk {free_bytes} is below required minimum {required}"
        )
    return {
        "probe_path": str(probe.resolve()),
        "free_bytes": free_bytes,
        "minimum_free_bytes": required,
        "status": "PASS",
    }


class ShadowOperationalStore:
    """Append-only operational receipts plus mutable heartbeat/status projection."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._signing_key: bytes | None = None
        self._signing_key_id: str | None = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(
            str(self.path),
            timeout=5.0,
            isolation_level=None,
        )
        self.connection.execute("PRAGMA busy_timeout=5000")
        journal_mode = self.connection.execute(
            "PRAGMA journal_mode=WAL"
        ).fetchone()
        if journal_mode is None or str(journal_mode[0]).lower() != "wal":
            self.connection.close()
            raise ShadowOperationalGuardError(
                "operational journal WAL mode is unavailable"
            )
        self.connection.execute("PRAGMA synchronous=FULL")
        synchronous = self.connection.execute("PRAGMA synchronous").fetchone()
        if synchronous is None or int(synchronous[0]) != 2:
            self.connection.close()
            raise ShadowOperationalGuardError(
                "operational journal FULL sync is unavailable"
            )
        self._initialize_schema()

    def _initialize_schema(self) -> None:
        self.connection.executescript(
            """CREATE TABLE IF NOT EXISTS shadow_operational_events (
                sequence INTEGER PRIMARY KEY,
                event_id TEXT NOT NULL UNIQUE,
                invocation_id TEXT NOT NULL,
                observed_at_utc TEXT NOT NULL,
                stage TEXT NOT NULL,
                outcome TEXT NOT NULL,
                reason_code TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_event_sha256 TEXT NOT NULL,
                event_sha256 TEXT NOT NULL UNIQUE,
                authenticity TEXT NOT NULL DEFAULT 'UNAUTHENTICATED',
                signing_key_id TEXT,
                previous_event_hmac_sha256 TEXT,
                event_hmac_sha256 TEXT
            );
            CREATE TRIGGER IF NOT EXISTS shadow_operational_events_no_update
            BEFORE UPDATE ON shadow_operational_events
            BEGIN
                SELECT RAISE(ABORT, 'shadow operational events are append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS shadow_operational_events_no_delete
            BEFORE DELETE ON shadow_operational_events
            BEGIN
                SELECT RAISE(ABORT, 'shadow operational events are append-only');
            END;
            CREATE TABLE IF NOT EXISTS shadow_runtime_status (
                runtime_key TEXT PRIMARY KEY,
                invocation_id TEXT NOT NULL,
                recorded_state TEXT NOT NULL,
                stage TEXT NOT NULL,
                heartbeat_at_utc TEXT NOT NULL,
                last_success_at_utc TEXT,
                last_success_cycle_id TEXT,
                failure_code TEXT,
                head_event_sequence INTEGER NOT NULL,
                head_event_sha256 TEXT NOT NULL,
                head_event_hmac_sha256 TEXT,
                authenticity TEXT NOT NULL,
                signing_key_id TEXT,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                status_hmac_sha256 TEXT
            );"""
        )
        columns = {
            str(row[1])
            for row in self.connection.execute(
                "PRAGMA table_info(shadow_operational_events)"
            ).fetchall()
        }
        for column, definition in (
            (
                "authenticity",
                "TEXT NOT NULL DEFAULT 'UNAUTHENTICATED'",
            ),
            ("signing_key_id", "TEXT"),
            ("previous_event_hmac_sha256", "TEXT"),
            ("event_hmac_sha256", "TEXT"),
        ):
            if column not in columns:
                self.connection.execute(
                    f"ALTER TABLE shadow_operational_events "
                    f"ADD COLUMN {column} {definition}"
                )
        status_columns = {
            str(row[1])
            for row in self.connection.execute(
                "PRAGMA table_info(shadow_runtime_status)"
            ).fetchall()
        }
        for column, definition in (
            ("head_event_sequence", "INTEGER NOT NULL DEFAULT 0"),
            ("head_event_hmac_sha256", "TEXT"),
            (
                "authenticity",
                "TEXT NOT NULL DEFAULT 'UNAUTHENTICATED'",
            ),
            ("signing_key_id", "TEXT"),
            ("status_hmac_sha256", "TEXT"),
        ):
            if column not in status_columns:
                self.connection.execute(
                    f"ALTER TABLE shadow_runtime_status "
                    f"ADD COLUMN {column} {definition}"
                )

    def close(self) -> None:
        self._signing_key = None
        self._signing_key_id = None
        self.connection.close()

    def install_signing_key(self, signing_key: bytes) -> str:
        """Install and verify the evidence HMAC key without persisting it."""

        normalized_key = bytes(signing_key)
        key_id = _signing_key_id(normalized_key)
        if self._signing_key is not None:
            if (
                self._signing_key_id != key_id
                or not hmac.compare_digest(self._signing_key, normalized_key)
            ):
                raise ShadowOperationalGuardError(
                    "operational signing key replacement is forbidden"
                )
            return key_id
        rows = self.connection.execute(
            """SELECT sequence, event_id, invocation_id, observed_at_utc,
                      stage, outcome, reason_code, payload_json,
                      previous_event_sha256, event_sha256, authenticity,
                      signing_key_id, previous_event_hmac_sha256,
                      event_hmac_sha256
               FROM shadow_operational_events ORDER BY sequence"""
        ).fetchall()
        if rows:
            events = _event_dicts_from_rows(rows)
            _verify_event_chain_integrity(
                events,
                expected_first_sequence=1,
                expected_initial_previous=_ZERO_HASH,
                signing_key=normalized_key,
            )
            status_row = self.connection.execute(
                """SELECT runtime_key, invocation_id, recorded_state, stage,
                          heartbeat_at_utc, last_success_at_utc,
                          last_success_cycle_id, failure_code,
                          head_event_sequence, head_event_sha256,
                          head_event_hmac_sha256, authenticity,
                          signing_key_id, payload_json, payload_sha256,
                          status_hmac_sha256
                   FROM shadow_runtime_status WHERE runtime_key=?""",
                (RUNTIME_KEY,),
            ).fetchone()
            _verify_status_row(
                status_row,
                events,
                signing_key=normalized_key,
                strict_authentication=True,
            )
        self._signing_key = normalized_key
        self._signing_key_id = key_id
        return key_id

    def has_authenticated_events(self) -> bool:
        row = self.connection.execute(
            """SELECT 1 FROM shadow_operational_events
               WHERE authenticity=? LIMIT 1""",
            (_AUTHENTICATED,),
        ).fetchone()
        return row is not None

    def _table_exists(self, name: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (str(name),),
        ).fetchone()
        return row is not None

    def begin_invocation(self, observed_at: datetime) -> str:
        normalized = _require_utc("observed_at", observed_at)
        invocation_id = (
            "xm-shadow-invocation-"
            + normalized.strftime("%Y%m%dT%H%M%S%fZ")
            + "-"
            + uuid.uuid4().hex[:12]
        )
        self.record_stage(
            invocation_id=invocation_id,
            observed_at=normalized,
            stage="INVOCATION",
            outcome="STARTED",
            reason_code="INVOCATION_STARTED",
            runtime_state="RUNNING",
        )
        return invocation_id

    def record_stage(
        self,
        *,
        invocation_id: str,
        observed_at: datetime,
        stage: str,
        outcome: str,
        reason_code: str,
        detail_type: str | None = None,
        metadata: Mapping[str, object] | None = None,
        runtime_state: str | None = None,
        last_success_cycle_id: str | None = None,
    ) -> str:
        normalized_at = _require_utc("observed_at", observed_at)
        normalized_invocation = str(invocation_id).strip()
        normalized_stage = str(stage).strip().upper()
        normalized_outcome = str(outcome).strip().upper()
        normalized_reason = str(reason_code).strip().upper()
        if not normalized_invocation:
            raise ShadowOperationalGuardError("invocation id is required")
        if not normalized_stage or not normalized_reason:
            raise ShadowOperationalGuardError("stage and reason code are required")
        if normalized_outcome not in _ALLOWED_OUTCOMES:
            raise ShadowOperationalGuardError("operational outcome is invalid")
        normalized_metadata = {} if metadata is None else dict(metadata)
        try:
            _canonical_json(normalized_metadata)
        except (TypeError, ValueError) as exc:
            raise ShadowOperationalGuardError(
                "operational metadata is not canonical JSON"
            ) from exc
        if runtime_state is None:
            runtime_state = {
                "STARTED": "RUNNING",
                "HOLD": "FAILED",
                "BUSY": "BUSY",
            }.get(normalized_outcome)
        if runtime_state is not None:
            runtime_state = str(runtime_state).strip().upper()
            if runtime_state not in _ALLOWED_RUNTIME_STATES:
                raise ShadowOperationalGuardError("runtime state is invalid")

        self.connection.execute("BEGIN IMMEDIATE")
        try:
            event_rows = self.connection.execute(
                """SELECT sequence, event_id, invocation_id, observed_at_utc,
                          stage, outcome, reason_code, payload_json,
                          previous_event_sha256, event_sha256, authenticity,
                          signing_key_id, previous_event_hmac_sha256,
                          event_hmac_sha256
                   FROM shadow_operational_events ORDER BY sequence"""
            ).fetchall()
            events = _event_dicts_from_rows(event_rows)
            previous_signed_hmac = None
            if events:
                if self._signing_key is None and any(
                    event["authenticity"] == _AUTHENTICATED
                    for event in events
                ):
                    raise ShadowOperationalGuardError(
                        "operational signing key must be installed before append"
                    )
                _, _, previous_signed_hmac = _verify_event_chain_integrity(
                    events,
                    expected_first_sequence=1,
                    expected_initial_previous=_ZERO_HASH,
                    signing_key=self._signing_key,
                    strict_authentication=self._signing_key is not None,
                )
            sequence = len(events) + 1
            previous_hash = (
                _ZERO_HASH
                if not events
                else str(events[-1]["event_sha256"])
            )
            authenticated = self._signing_key is not None
            authenticity = (
                _AUTHENTICATED if authenticated else _UNAUTHENTICATED
            )
            signing_key_id = self._signing_key_id if authenticated else None
            previous_event_hmac = (
                previous_signed_hmac if authenticated else None
            )
            event_id = (
                normalized_invocation
                + "-"
                + f"{sequence:012d}"
            )
            observed_at_utc = _utc_text(normalized_at)
            status_projection = _next_status_projection(
                events,
                observed_at_utc=observed_at_utc,
                runtime_state=runtime_state,
                reason_code=normalized_reason,
                last_success_cycle_id=last_success_cycle_id,
            )
            payload = {
                "schema_version": OPERATIONAL_EVENT_SCHEMA_VERSION,
                "sequence": sequence,
                "event_id": event_id,
                "invocation_id": normalized_invocation,
                "observed_at_utc": observed_at_utc,
                "stage": normalized_stage,
                "outcome": normalized_outcome,
                "reason_code": normalized_reason,
                "detail_type": (
                    None if detail_type is None else str(detail_type).strip()
                ),
                "metadata": normalized_metadata,
                "previous_event_sha256": previous_hash,
                "authenticity": authenticity,
                "signing_key_id": signing_key_id,
                "previous_event_hmac_sha256": previous_event_hmac,
                "status_projection": status_projection,
                "live_allowed": False,
                "safe_to_demo_auto_order": False,
                "order_capability": "DISABLED",
                "max_lot": 0.01,
            }
            payload_json = _canonical_json(payload)
            event_hash = _sha256_bytes(
                (previous_hash + "\n" + payload_json).encode("utf-8")
            )
            event_hmac = (
                None
                if self._signing_key is None
                else _hmac_bytes(
                    self._signing_key,
                    _EVENT_HMAC_DOMAIN
                    + (
                        (previous_event_hmac or _ZERO_HASH)
                        + "\n"
                        + previous_hash
                        + "\n"
                        + payload_json
                    ).encode("utf-8"),
                )
            )
            self.connection.execute(
                """INSERT INTO shadow_operational_events
                (sequence, event_id, invocation_id, observed_at_utc, stage,
                 outcome, reason_code, payload_json, previous_event_sha256,
                 event_sha256, authenticity, signing_key_id,
                 previous_event_hmac_sha256, event_hmac_sha256)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    sequence,
                    event_id,
                    normalized_invocation,
                    payload["observed_at_utc"],
                    normalized_stage,
                    normalized_outcome,
                    normalized_reason,
                    payload_json,
                    previous_hash,
                    event_hash,
                    authenticity,
                    signing_key_id,
                    previous_event_hmac,
                    event_hmac,
                ),
            )
            event = {
                "sequence": sequence,
                "event_id": event_id,
                "invocation_id": normalized_invocation,
                "observed_at_utc": observed_at_utc,
                "stage": normalized_stage,
                "outcome": normalized_outcome,
                "reason_code": normalized_reason,
                "payload_json": payload_json,
                "previous_event_sha256": previous_hash,
                "event_sha256": event_hash,
                "authenticity": authenticity,
                "signing_key_id": signing_key_id,
                "previous_event_hmac_sha256": previous_event_hmac,
                "event_hmac_sha256": event_hmac,
            }
            status_payload = _status_payload_from_head(event)
            status_json = _canonical_json(status_payload)
            status_hash = _sha256_bytes(status_json.encode("utf-8"))
            status_hmac = (
                None
                if self._signing_key is None
                else _hmac_bytes(
                    self._signing_key,
                    _STATUS_HMAC_DOMAIN + status_json.encode("utf-8"),
                )
            )
            self.connection.execute(
                """INSERT INTO shadow_runtime_status
                (runtime_key, invocation_id, recorded_state, stage,
                 heartbeat_at_utc, last_success_at_utc, last_success_cycle_id,
                 failure_code, head_event_sequence, head_event_sha256,
                 head_event_hmac_sha256, authenticity, signing_key_id,
                 payload_json, payload_sha256, status_hmac_sha256)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(runtime_key) DO UPDATE SET
                    invocation_id=excluded.invocation_id,
                    recorded_state=excluded.recorded_state,
                    stage=excluded.stage,
                    heartbeat_at_utc=excluded.heartbeat_at_utc,
                    last_success_at_utc=excluded.last_success_at_utc,
                    last_success_cycle_id=excluded.last_success_cycle_id,
                    failure_code=excluded.failure_code,
                    head_event_sequence=excluded.head_event_sequence,
                    head_event_sha256=excluded.head_event_sha256,
                    head_event_hmac_sha256=excluded.head_event_hmac_sha256,
                    authenticity=excluded.authenticity,
                    signing_key_id=excluded.signing_key_id,
                    payload_json=excluded.payload_json,
                    payload_sha256=excluded.payload_sha256,
                    status_hmac_sha256=excluded.status_hmac_sha256""",
                (
                    RUNTIME_KEY,
                    normalized_invocation,
                    status_projection["recorded_state"],
                    normalized_stage,
                    observed_at_utc,
                    status_projection["last_success_at_utc"],
                    status_projection["last_success_cycle_id"],
                    status_projection["failure_code"],
                    sequence,
                    event_hash,
                    event_hmac,
                    authenticity,
                    signing_key_id,
                    status_json,
                    status_hash,
                    status_hmac,
                ),
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return event_hash

    def finish_invocation(
        self,
        *,
        invocation_id: str,
        observed_at: datetime,
        outcome: str,
        reason_code: str,
        success_cycle_id: str | None = None,
        detail_type: str | None = None,
    ) -> str:
        normalized_outcome = str(outcome).strip().upper()
        runtime_state = {
            "PASS": "HEALTHY",
            "HOLD": "FAILED",
            "BUSY": "BUSY",
        }.get(normalized_outcome)
        if runtime_state is None:
            raise ShadowOperationalGuardError("terminal outcome is invalid")
        return self.record_stage(
            invocation_id=invocation_id,
            observed_at=observed_at,
            stage="INVOCATION_TERMINAL",
            outcome=normalized_outcome,
            reason_code=reason_code,
            detail_type=detail_type,
            runtime_state=runtime_state,
            last_success_cycle_id=(
                success_cycle_id if normalized_outcome == "PASS" else None
            ),
        )

    def read_status(
        self,
        *,
        observed_at: datetime,
        stale_after_seconds: int = DEFAULT_HEARTBEAT_STALE_SECONDS,
    ) -> ShadowRuntimeStatus:
        normalized_at = _require_utc("observed_at", observed_at)
        if type(stale_after_seconds) is not int or stale_after_seconds <= 0:
            raise ShadowOperationalGuardError("heartbeat stale threshold is invalid")
        event_rows = self.connection.execute(
            """SELECT sequence, event_id, invocation_id, observed_at_utc,
                      stage, outcome, reason_code, payload_json,
                      previous_event_sha256, event_sha256, authenticity,
                      signing_key_id, previous_event_hmac_sha256,
                      event_hmac_sha256
               FROM shadow_operational_events ORDER BY sequence"""
        ).fetchall()
        if not event_rows:
            return ShadowRuntimeStatus(
                reported_state="STALE",
                recorded_state="MISSING",
                invocation_id=None,
                stage=None,
                heartbeat_at=None,
                heartbeat_age_seconds=None,
                last_success_at=None,
                last_success_cycle_id=None,
                failure_code="HEARTBEAT_MISSING",
                stale=True,
                failed=True,
                head_event_sha256=None,
            )
        events = _event_dicts_from_rows(event_rows)
        _verify_event_chain_integrity(
            events,
            expected_first_sequence=1,
            expected_initial_previous=_ZERO_HASH,
            signing_key=self._signing_key,
            strict_authentication=True,
        )
        status_row = self.connection.execute(
            """SELECT runtime_key, invocation_id, recorded_state, stage,
                      heartbeat_at_utc, last_success_at_utc,
                      last_success_cycle_id, failure_code,
                      head_event_sequence, head_event_sha256,
                      head_event_hmac_sha256, authenticity, signing_key_id,
                      payload_json, payload_sha256, status_hmac_sha256
               FROM shadow_runtime_status WHERE runtime_key=?""",
            (RUNTIME_KEY,),
        ).fetchone()
        status = _verify_status_row(
            status_row,
            events,
            signing_key=self._signing_key,
            strict_authentication=True,
        )
        heartbeat_at = _parse_utc(status["heartbeat_at_utc"])
        heartbeat_age = (normalized_at - heartbeat_at).total_seconds()
        stale = heartbeat_age < -1.0 or heartbeat_age > stale_after_seconds
        recorded_state = str(status["recorded_state"])
        failed = recorded_state == "FAILED"
        return ShadowRuntimeStatus(
            reported_state="STALE" if stale else recorded_state,
            recorded_state=recorded_state,
            invocation_id=str(status["invocation_id"]),
            stage=str(status["stage"]),
            heartbeat_at=heartbeat_at,
            heartbeat_age_seconds=heartbeat_age,
            last_success_at=(
                None
                if status["last_success_at_utc"] is None
                else _parse_utc(status["last_success_at_utc"])
            ),
            last_success_cycle_id=(
                None
                if status["last_success_cycle_id"] is None
                else str(status["last_success_cycle_id"])
            ),
            failure_code=(
                None
                if status["failure_code"] is None
                else str(status["failure_code"])
            ),
            stale=stale,
            failed=failed,
            head_event_sha256=str(status["head_event_sha256"]),
        )

    def create_verified_audit_export(
        self,
        *,
        export_directory: str | Path,
        invocation_id: str,
        observed_at: datetime,
    ) -> ShadowAuditExportReceipt:
        """Export one invocation as a small append-only off-host audit bundle."""

        normalized_at = _require_utc("observed_at", observed_at)
        directory = Path(export_directory)
        if directory.is_symlink():
            raise ShadowOperationalGuardError(
                "audit export directory cannot be a symlink"
            )
        directory.mkdir(parents=True, exist_ok=True)
        if directory.is_symlink():
            raise ShadowOperationalGuardError(
                "audit export directory cannot be a symlink"
            )
        safe_invocation = str(invocation_id).strip()
        if not safe_invocation or any(
            token in safe_invocation for token in ("/", "\\", "..")
        ):
            raise ShadowOperationalGuardError(
                "audit export invocation id is invalid"
            )
        export_path = directory / f"{safe_invocation}.audit.json"
        manifest_path = directory / f"{safe_invocation}.manifest.json"
        if export_path.exists() or manifest_path.exists():
            raise ShadowOperationalGuardError(
                "audit export artifact already exists"
            )
        integrity = self.connection.execute("PRAGMA quick_check").fetchone()
        if integrity is None or integrity[0] != "ok":
            raise ShadowOperationalGuardError(
                "source journal integrity check failed"
            )
        self.connection.execute("BEGIN")
        try:
            first_sequence_row = self.connection.execute(
                """SELECT sequence FROM shadow_operational_events
                   WHERE invocation_id=?
                   ORDER BY sequence LIMIT 1""",
                (safe_invocation,),
            ).fetchone()
            if first_sequence_row is None:
                raise ShadowOperationalGuardError(
                    "audit export invocation has no operational events"
                )
            first_sequence = int(first_sequence_row[0])
            global_head_row = self.connection.execute(
                """SELECT sequence FROM shadow_operational_events
                   ORDER BY sequence DESC LIMIT 1"""
            ).fetchone()
            if global_head_row is None:
                raise ShadowOperationalGuardError(
                    "audit export has no global operational head"
                )
            global_head_sequence = int(global_head_row[0])
            event_rows = self.connection.execute(
                """SELECT sequence, event_id, invocation_id, observed_at_utc,
                          stage, outcome, reason_code, payload_json,
                          previous_event_sha256, event_sha256, authenticity,
                          signing_key_id, previous_event_hmac_sha256,
                          event_hmac_sha256
                   FROM shadow_operational_events
                   WHERE sequence BETWEEN ? AND ?
                   ORDER BY sequence""",
                (first_sequence, global_head_sequence),
            ).fetchall()
            source_event_rows = self.connection.execute(
                """SELECT sequence, event_id, invocation_id, observed_at_utc,
                          stage, outcome, reason_code, payload_json,
                          previous_event_sha256, event_sha256, authenticity,
                          signing_key_id, previous_event_hmac_sha256,
                          event_hmac_sha256
                   FROM shadow_operational_events
                   WHERE sequence <= ?
                   ORDER BY sequence""",
                (global_head_sequence,),
            ).fetchall()
            startup_candidates = (
                self.connection.execute(
                    """SELECT startup_guard_id, observed_at_utc, status,
                              payload_json, payload_sha256
                       FROM shadow_startup_guards
                       ORDER BY observed_at_utc, startup_guard_id"""
                ).fetchall()
                if self._table_exists("shadow_startup_guards")
                else []
            )
            cycle_candidates = (
                self.connection.execute(
                    """SELECT cycle_id, observed_at_utc, status, payload_json,
                              payload_sha256
                       FROM shadow_cycles
                       ORDER BY observed_at_utc, cycle_id"""
                ).fetchall()
                if self._table_exists("shadow_cycles")
                else []
            )
            status_row = self.connection.execute(
                """SELECT runtime_key, invocation_id, recorded_state, stage,
                          heartbeat_at_utc, last_success_at_utc,
                          last_success_cycle_id, failure_code,
                          head_event_sequence, head_event_sha256,
                          head_event_hmac_sha256, authenticity, signing_key_id,
                          payload_json, payload_sha256, status_hmac_sha256
                   FROM shadow_runtime_status WHERE runtime_key=?""",
                (RUNTIME_KEY,),
            ).fetchone()
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        source_events = _event_dicts_from_rows(source_event_rows)
        (
            source_event_count,
            source_head_hash,
            source_signed_head_hmac,
        ) = _verify_event_chain_integrity(
            source_events,
            expected_first_sequence=1,
            expected_initial_previous=_ZERO_HASH,
            signing_key=self._signing_key,
            strict_authentication=self._signing_key is not None,
        )
        if (
            source_event_count != global_head_sequence
            or source_events[-1]["sequence"] != global_head_sequence
        ):
            raise ShadowOperationalGuardError(
                "source operational event chain is incomplete"
            )
        events = _event_dicts_from_rows(event_rows)
        predecessor_sequence = int(events[0]["sequence"]) - 1
        predecessor_signed_hmac = next(
            (
                str(event["event_hmac_sha256"])
                for event in reversed(source_events[:predecessor_sequence])
                if event["authenticity"] == _AUTHENTICATED
            ),
            None,
        )
        (
            event_count,
            head_hash,
            signed_head_hmac,
        ) = _verify_exported_event_chain(
            events,
            invocation_id=safe_invocation,
            signing_key=self._signing_key,
            expected_first_sequence=predecessor_sequence + 1,
            expected_initial_previous=(
                _ZERO_HASH
                if predecessor_sequence == 0
                else str(
                    source_events[
                        predecessor_sequence - 1
                    ]["event_sha256"]
                )
            ),
            initial_previous_signed_hmac=predecessor_signed_hmac,
            strict_authentication=self._signing_key is not None,
        )
        if (
            head_hash != source_head_hash
            or signed_head_hmac != source_signed_head_hmac
        ):
            raise ShadowOperationalGuardError(
                "exported suffix does not reach verified source head"
            )
        predecessor_hash = str(events[0]["previous_event_sha256"])
        verified_predecessor_hash = (
            _ZERO_HASH
            if predecessor_sequence == 0
            else str(source_events[predecessor_sequence - 1]["event_sha256"])
        )
        if predecessor_hash != verified_predecessor_hash:
            raise ShadowOperationalGuardError(
                "exported suffix predecessor anchor mismatch"
            )
        event_times = [
            _parse_utc(event["observed_at_utc"])
            for event in events
        ]
        first_at = min(event_times)
        last_at = max(event_times)
        startup_records = [
            {
                "startup_guard_id": str(row[0]),
                "observed_at_utc": str(row[1]),
                "status": str(row[2]),
                "payload_json": str(row[3]),
                "payload_sha256": str(row[4]),
            }
            for row in startup_candidates
            if first_at <= _parse_utc(row[1]) <= last_at
        ]
        cycle_records = [
            {
                "cycle_id": str(row[0]),
                "observed_at_utc": str(row[1]),
                "status": str(row[2]),
                "payload_json": str(row[3]),
                "payload_sha256": str(row[4]),
            }
            for row in cycle_candidates
            if first_at <= _parse_utc(row[1]) <= last_at
        ]
        _verify_status_row(
            status_row,
            source_events,
            signing_key=self._signing_key,
            strict_authentication=self._signing_key is not None,
        )
        _verify_receipt_bindings(
            events,
            startup_guards=startup_records,
            shadow_cycles=cycle_records,
        )
        primary_terminal = next(
            (
                event
                for event in reversed(events)
                if event["invocation_id"] == safe_invocation
                and event["stage"] == "INVOCATION_TERMINAL"
            ),
            None,
        )
        if primary_terminal is None:
            raise ShadowOperationalGuardError(
                "audit export primary terminal is missing"
            )
        authenticated = self._signing_key is not None
        authenticity = (
            _AUTHENTICATED if authenticated else _UNAUTHENTICATED
        )
        if primary_terminal["outcome"] == "PASS" and not authenticated:
            raise ShadowOperationalGuardError(
                "PASS audit export requires operational signing key"
            )
        if (
            authenticated
            and primary_terminal["authenticity"] != _AUTHENTICATED
        ):
            raise ShadowOperationalGuardError(
                "authenticated audit export requires signed terminal receipt"
            )
        payload = {
            "schema_version": AUDIT_EXPORT_SCHEMA_VERSION,
            "created_at_utc": _utc_text(normalized_at),
            "runtime_key": RUNTIME_KEY,
            "invocation_id": safe_invocation,
            "source_journal_name": self.path.name,
            "source_sqlite_quick_check": "ok",
            "operational_events": events,
            "startup_guards": startup_records,
            "shadow_cycles": cycle_records,
            "runtime_status": {
                "runtime_key": str(status_row[0]),
                "invocation_id": str(status_row[1]),
                "recorded_state": str(status_row[2]),
                "stage": str(status_row[3]),
                "heartbeat_at_utc": str(status_row[4]),
                "last_success_at_utc": status_row[5],
                "last_success_cycle_id": status_row[6],
                "failure_code": status_row[7],
                "head_event_sequence": int(status_row[8]),
                "head_event_sha256": str(status_row[9]),
                "head_event_hmac_sha256": status_row[10],
                "authenticity": str(status_row[11]),
                "signing_key_id": status_row[12],
                "payload_json": str(status_row[13]),
                "payload_sha256": str(status_row[14]),
                "status_hmac_sha256": status_row[15],
            },
            "operational_event_count": event_count,
            "operational_head_sha256": head_hash,
            "operational_signed_head_hmac_sha256": signed_head_hmac,
            "source_operational_event_count": source_event_count,
            "source_operational_head_sha256": source_head_hash,
            "source_operational_signed_head_hmac_sha256": (
                source_signed_head_hmac
            ),
            "source_chain_verified_from_genesis": True,
            "export_predecessor_sequence": predecessor_sequence,
            "export_predecessor_event_sha256": predecessor_hash,
            "export_predecessor_signed_event_hmac_sha256": (
                predecessor_signed_hmac
            ),
            "authenticity": authenticity,
            "authenticated_evidence": authenticated,
            "signing_key_id": self._signing_key_id,
            "audit_export_hmac_sha256": None,
            "copy_instruction": "COPY_AUDIT_AND_MANIFEST_TO_OFF_HOST_WORM",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "order_capability": "DISABLED",
            "max_lot": 0.01,
        }
        if self._signing_key is not None:
            payload["audit_export_hmac_sha256"] = _payload_hmac(
                payload,
                signing_key=self._signing_key,
                field="audit_export_hmac_sha256",
                domain=_EXPORT_HMAC_DOMAIN,
            )
        export_bytes = (
            json.dumps(
                payload,
                ensure_ascii=True,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        export_descriptor = os.open(
            export_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        try:
            with os.fdopen(export_descriptor, "wb") as handle:
                handle.write(export_bytes)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                os.close(export_descriptor)
            except OSError:
                pass
            raise
        export_sha = _sha256_bytes(export_bytes)
        manifest_payload = {
            "schema_version": AUDIT_EXPORT_MANIFEST_SCHEMA_VERSION,
            "created_at_utc": _utc_text(normalized_at),
            "runtime_key": RUNTIME_KEY,
            "invocation_id": safe_invocation,
            "audit_export_file": export_path.name,
            "audit_export_bytes": len(export_bytes),
            "audit_export_sha256": export_sha,
            "operational_event_count": event_count,
            "operational_head_sha256": head_hash,
            "operational_signed_head_hmac_sha256": signed_head_hmac,
            "source_operational_event_count": source_event_count,
            "source_operational_head_sha256": source_head_hash,
            "source_operational_signed_head_hmac_sha256": (
                source_signed_head_hmac
            ),
            "source_chain_verified_from_genesis": True,
            "export_predecessor_sequence": predecessor_sequence,
            "export_predecessor_event_sha256": predecessor_hash,
            "export_predecessor_signed_event_hmac_sha256": (
                predecessor_signed_hmac
            ),
            "authenticity": authenticity,
            "authenticated_evidence": authenticated,
            "signing_key_id": self._signing_key_id,
            "audit_export_hmac_sha256": payload[
                "audit_export_hmac_sha256"
            ],
            "manifest_hmac_sha256": None,
            "copy_instruction": "COPY_AUDIT_AND_MANIFEST_TO_OFF_HOST_WORM",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "order_capability": "DISABLED",
            "max_lot": 0.01,
        }
        if self._signing_key is not None:
            manifest_payload["manifest_hmac_sha256"] = _payload_hmac(
                manifest_payload,
                signing_key=self._signing_key,
                field="manifest_hmac_sha256",
                domain=_MANIFEST_HMAC_DOMAIN,
            )
        manifest_hash = _sha256_bytes(
            _canonical_json(manifest_payload).encode("utf-8")
        )
        manifest = dict(manifest_payload, manifest_sha256=manifest_hash)
        manifest_bytes = (
            json.dumps(
                manifest,
                ensure_ascii=True,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        manifest_descriptor = os.open(
            manifest_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        try:
            with os.fdopen(manifest_descriptor, "wb") as handle:
                handle.write(manifest_bytes)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                os.close(manifest_descriptor)
            except OSError:
                pass
            raise
        os.chmod(export_path, 0o400)
        os.chmod(manifest_path, 0o400)
        return verify_audit_export_manifest(
            manifest_path,
            signing_key=self._signing_key,
        )


def verify_audit_export_manifest(
    path: str | Path,
    *,
    signing_key: bytes | None = None,
) -> ShadowAuditExportReceipt:
    manifest_path = Path(path)
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ShadowOperationalGuardError(
            "audit export manifest is unavailable"
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError) as exc:
        raise ShadowOperationalGuardError(
            "audit export manifest is unreadable"
        ) from exc
    if not isinstance(manifest, dict):
        raise ShadowOperationalGuardError("audit export manifest is invalid")
    if (
        manifest.get("schema_version")
        != AUDIT_EXPORT_MANIFEST_SCHEMA_VERSION
    ):
        raise ShadowOperationalGuardError(
            "audit export manifest schema is invalid"
        )
    if (
        manifest.get("runtime_key") != RUNTIME_KEY
        or manifest.get("live_allowed") is not False
        or manifest.get("safe_to_demo_auto_order") is not False
        or manifest.get("order_capability") != "DISABLED"
        or manifest.get("max_lot") != 0.01
    ):
        raise ShadowOperationalGuardError(
            "audit export manifest safety lock mismatch"
        )
    claimed_manifest_hash = str(manifest.get("manifest_sha256") or "")
    unsigned_manifest = dict(manifest)
    unsigned_manifest.pop("manifest_sha256", None)
    actual_manifest_hash = _sha256_bytes(
        _canonical_json(unsigned_manifest).encode("utf-8")
    )
    if claimed_manifest_hash != actual_manifest_hash:
        raise ShadowOperationalGuardError(
            "audit export manifest hash mismatch"
        )
    authenticity = str(manifest.get("authenticity") or "")
    authenticated = manifest.get("authenticated_evidence")
    signing_key_id = manifest.get("signing_key_id")
    if authenticity == _AUTHENTICATED:
        if authenticated is not True or signing_key is None:
            raise ShadowOperationalGuardError(
                "authenticated audit manifest requires signing key"
            )
        expected_key_id = _signing_key_id(signing_key)
        if signing_key_id != expected_key_id:
            raise ShadowOperationalGuardError(
                "audit manifest signing key id mismatch"
            )
        expected_manifest_hmac = _payload_hmac(
            unsigned_manifest,
            signing_key=signing_key,
            field="manifest_hmac_sha256",
            domain=_MANIFEST_HMAC_DOMAIN,
        )
        manifest_hmac = manifest.get("manifest_hmac_sha256")
        if (
            not isinstance(manifest_hmac, str)
            or not hmac.compare_digest(
                manifest_hmac,
                expected_manifest_hmac,
            )
        ):
            raise ShadowOperationalGuardError(
                "audit export manifest HMAC mismatch"
            )
    elif authenticity == _UNAUTHENTICATED:
        if (
            authenticated is not False
            or signing_key_id is not None
            or manifest.get("manifest_hmac_sha256") is not None
            or manifest.get("audit_export_hmac_sha256") is not None
        ):
            raise ShadowOperationalGuardError(
                "unauthenticated audit manifest has HMAC fields"
            )
    else:
        raise ShadowOperationalGuardError(
            "audit export manifest authenticity is invalid"
        )
    export_name = str(manifest.get("audit_export_file") or "")
    if not export_name or Path(export_name).name != export_name:
        raise ShadowOperationalGuardError("audit export file reference is unsafe")
    export_path = manifest_path.parent / export_name
    if export_path.is_symlink() or not export_path.is_file():
        raise ShadowOperationalGuardError("audit export file is unavailable")
    export_bytes = export_path.read_bytes()
    if len(export_bytes) != int(manifest.get("audit_export_bytes") or -1):
        raise ShadowOperationalGuardError("audit export size mismatch")
    export_hash = _sha256_bytes(export_bytes)
    if export_hash != manifest.get("audit_export_sha256"):
        raise ShadowOperationalGuardError("audit export hash mismatch")
    try:
        export = json.loads(export_bytes)
    except (TypeError, ValueError) as exc:
        raise ShadowOperationalGuardError("audit export is invalid JSON") from exc
    if not isinstance(export, dict):
        raise ShadowOperationalGuardError("audit export is invalid")
    if (
        export.get("schema_version") != AUDIT_EXPORT_SCHEMA_VERSION
        or export.get("runtime_key") != RUNTIME_KEY
        or export.get("live_allowed") is not False
        or export.get("safe_to_demo_auto_order") is not False
        or export.get("order_capability") != "DISABLED"
        or export.get("max_lot") != 0.01
    ):
        raise ShadowOperationalGuardError("audit export safety lock mismatch")
    invocation_id = str(export.get("invocation_id") or "")
    if not invocation_id or invocation_id != manifest.get("invocation_id"):
        raise ShadowOperationalGuardError(
            "audit export invocation binding mismatch"
        )
    if (
        export.get("authenticity") != authenticity
        or export.get("authenticated_evidence") is not authenticated
        or export.get("signing_key_id") != signing_key_id
        or export.get("audit_export_hmac_sha256")
        != manifest.get("audit_export_hmac_sha256")
    ):
        raise ShadowOperationalGuardError(
            "audit export authentication summary mismatch"
        )
    if authenticated:
        assert signing_key is not None
        expected_export_hmac = _payload_hmac(
            export,
            signing_key=signing_key,
            field="audit_export_hmac_sha256",
            domain=_EXPORT_HMAC_DOMAIN,
        )
        export_hmac = export.get("audit_export_hmac_sha256")
        if (
            not isinstance(export_hmac, str)
            or not hmac.compare_digest(export_hmac, expected_export_hmac)
        ):
            raise ShadowOperationalGuardError(
                "audit export HMAC mismatch"
            )
    predecessor_sequence = int(
        export.get("export_predecessor_sequence", -1)
    )
    predecessor_hash = str(
        export.get("export_predecessor_event_sha256") or ""
    )
    predecessor_signed_hmac = export.get(
        "export_predecessor_signed_event_hmac_sha256"
    )
    if (
        predecessor_sequence < 0
        or not _is_sha256(predecessor_hash)
        or (
            predecessor_signed_hmac is not None
            and not _is_sha256(predecessor_signed_hmac)
        )
        or manifest.get("export_predecessor_sequence")
        != predecessor_sequence
        or manifest.get("export_predecessor_event_sha256")
        != predecessor_hash
        or manifest.get(
            "export_predecessor_signed_event_hmac_sha256"
        )
        != predecessor_signed_hmac
        or (
            predecessor_sequence == 0
            and (
                predecessor_hash != _ZERO_HASH
                or predecessor_signed_hmac is not None
            )
        )
    ):
        raise ShadowOperationalGuardError(
            "audit export predecessor anchor is invalid"
        )
    (
        event_count,
        head_hash,
        signed_head_hmac,
    ) = _verify_exported_event_chain(
        export.get("operational_events"),
        invocation_id=invocation_id,
        signing_key=signing_key if authenticated else None,
        expected_first_sequence=predecessor_sequence + 1,
        expected_initial_previous=predecessor_hash,
        initial_previous_signed_hmac=predecessor_signed_hmac,
        strict_authentication=bool(authenticated),
    )
    if (
        event_count != int(export.get("operational_event_count") or -1)
        or event_count != int(manifest.get("operational_event_count") or -1)
        or head_hash != export.get("operational_head_sha256")
        or head_hash != manifest.get("operational_head_sha256")
        or signed_head_hmac
        != export.get("operational_signed_head_hmac_sha256")
        or signed_head_hmac
        != manifest.get("operational_signed_head_hmac_sha256")
    ):
        raise ShadowOperationalGuardError(
            "audit export operational summary mismatch"
        )
    first_event = export["operational_events"][0]
    last_event = export["operational_events"][-1]
    source_event_count = int(
        export.get("source_operational_event_count") or -1
    )
    if (
        export.get("source_chain_verified_from_genesis") is not True
        or manifest.get("source_chain_verified_from_genesis") is not True
        or source_event_count != int(last_event["sequence"])
        or export.get("source_operational_event_count") != source_event_count
        or manifest.get("source_operational_event_count") != source_event_count
        or export.get("source_operational_head_sha256") != head_hash
        or manifest.get("source_operational_head_sha256") != head_hash
        or export.get("source_operational_signed_head_hmac_sha256")
        != signed_head_hmac
        or manifest.get("source_operational_signed_head_hmac_sha256")
        != signed_head_hmac
        or int(first_event["sequence"]) != predecessor_sequence + 1
        or str(first_event["previous_event_sha256"]) != predecessor_hash
    ):
        raise ShadowOperationalGuardError(
            "audit export verified source anchor mismatch"
        )
    primary_terminal = next(
        (
            event
            for event in reversed(export["operational_events"])
            if event["invocation_id"] == invocation_id
            and event["stage"] == "INVOCATION_TERMINAL"
        ),
        None,
    )
    if primary_terminal is None:
        raise ShadowOperationalGuardError(
            "audit export primary terminal is missing"
        )
    if primary_terminal["outcome"] == "PASS" and (
        not authenticated
        or primary_terminal["authenticity"] != _AUTHENTICATED
    ):
        raise ShadowOperationalGuardError(
            "PASS audit export is not authenticated"
        )
    status = export.get("runtime_status")
    if not isinstance(status, dict):
        raise ShadowOperationalGuardError(
            "audit export runtime status is invalid"
        )
    status_row = (
        status.get("runtime_key"),
        status.get("invocation_id"),
        status.get("recorded_state"),
        status.get("stage"),
        status.get("heartbeat_at_utc"),
        status.get("last_success_at_utc"),
        status.get("last_success_cycle_id"),
        status.get("failure_code"),
        status.get("head_event_sequence"),
        status.get("head_event_sha256"),
        status.get("head_event_hmac_sha256"),
        status.get("authenticity"),
        status.get("signing_key_id"),
        status.get("payload_json"),
        status.get("payload_sha256"),
        status.get("status_hmac_sha256"),
    )
    _verify_status_row(
        status_row,
        export["operational_events"],
        signing_key=signing_key if authenticated else None,
        strict_authentication=bool(authenticated),
    )
    startup_guards = export.get("startup_guards")
    shadow_cycles = export.get("shadow_cycles")
    if not isinstance(startup_guards, list) or not isinstance(
        shadow_cycles,
        list,
    ):
        raise ShadowOperationalGuardError(
            "audit export receipt collections are invalid"
        )
    _verify_receipt_bindings(
        export["operational_events"],
        startup_guards=startup_guards,
        shadow_cycles=shadow_cycles,
    )
    return ShadowAuditExportReceipt(
        export_path=export_path,
        manifest_path=manifest_path,
        export_sha256=export_hash,
        manifest_sha256=actual_manifest_hash,
        operational_event_count=event_count,
        operational_head_sha256=head_hash,
        authenticity=authenticity,
        signing_key_id=(
            None if signing_key_id is None else str(signing_key_id)
        ),
    )


__all__ = [
    "AUDIT_EXPORT_MANIFEST_SCHEMA_VERSION",
    "AUDIT_EXPORT_SCHEMA_VERSION",
    "DEFAULT_HEARTBEAT_STALE_SECONDS",
    "DEFAULT_MINIMUM_FREE_BYTES",
    "RUNTIME_KEY",
    "ShadowAuditExportReceipt",
    "ShadowDiskSpaceHold",
    "ShadowOperationalGuardError",
    "ShadowOperationalStore",
    "ShadowRuntimeStatus",
    "check_minimum_free_disk",
    "verify_audit_export_manifest",
]
