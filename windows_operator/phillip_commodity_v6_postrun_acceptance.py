"""Build and verify one portable Phillip Commodity V6 post-run evidence bundle.

This tool never starts or changes a scheduled task and never imports an MT5 or
order module.  The Windows wrapper first runs the exact, hash-pinned V6.3
health checker.  This module then binds its transcript, the newest signed
checkpoint, the exact audit pair, the installation receipt, and the installed
task XML into one create-exclusive ZIP for independent custody.

The acceptance ZIP is transport evidence only.  A separate deterministic
custody request carries it to an independent WORM custodian.  Only an exact,
policy-pinned RSA receipt can produce a local custody assessment, and that
assessment still grants no execution or promotion authority.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import io
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import sys
from typing import BinaryIO, Iterable
import uuid
import xml.etree.ElementTree as ET
import zipfile


BRANCH = "agent/live-grade-phase3"
V63_REMEDIATION_COMMIT = "14762eac7e991fee8818ee20816709066f457f06"
V63_REMEDIATION_TREE = "727f5215b203796c584d7bf321edac2447e92a60"
WORKER_COMMIT = "290cc23d9d87f93e914612afdfecfc481d2c232f"
WORKER_TREE = "ef568ae39aa4c51d9afe738badbb86d2c45e9a58"
CONTRACT_ID = "phillip-commodity-window-01-diagnostic-v5"
PROOF_RECEIPT_SHA256 = (
    "29e14f81bbd87d460f171484d59a40e9"
    "bdd6ae00611c3453ade4aa6c846b3aec"
)
V63_TASK_CONTRACT_SHA256 = (
    "e40b315c5cae30b6708d04e39314fc13"
    "c4dbc9dffb18c2a37c4d2f6f959acbc6"
)
V63_EVIDENCE_VERIFIER_SHA256 = (
    "980712896acb613665e18f46d8cdc62e"
    "ac95bfc90ede222c318c374b0849606c"
)
V63_HEALTH_CHECKER_SHA256 = (
    "29b1cc9958d9f471a6664eea449f272c"
    "a539d750fa5778586303c7272990c1e5"
)
TASK_NAME = "AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow"
PRIOR_TASK_STATES = {
    "AI_SCALPER-PhillipCommodityV4-ReadOnlyShadow": "Disabled",
    "AI_SCALPER-PhillipCommodityV5-ReadOnlyShadow": "Disabled",
}
FIRST_SCHEDULED_START_UTC = datetime(2026, 7, 29, 21, 45, tzinfo=timezone.utc)
SCHEDULE_END_UTC = datetime(2026, 9, 21, 15, 16, tzinfo=timezone.utc)
FIRST_SCHEDULED_START_LOCAL = "2026-07-30T06:45:00+09:00"
SCHEDULE_END_LOCAL = "2026-09-22T00:16:00+09:00"
FIXED_ZIP_TIMESTAMP = (2026, 7, 30, 6, 45, 0)
FIXED_ZIP_MODE = stat.S_IFREG | 0o644
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_EXPANDED_BYTES = 48 * 1024 * 1024
MAX_CUSTODY_ARCHIVE_BYTES = 40 * 1024 * 1024
MAX_CUSTODY_MEMBER_BYTES = 32 * 1024 * 1024
MAX_CUSTODY_EXPANDED_BYTES = 40 * 1024 * 1024
MAX_CUSTODY_DOCUMENT_BYTES = 262_144
CHECKPOINT_SCHEMA = "phillip-commodity-v6-scheduler-evidence-checkpoint-v1"
TOOLKIT_SCHEMA = "phillip-commodity-v6-postrun-toolkit-v2"
BUNDLE_SCHEMA = "phillip-commodity-v6-postrun-acceptance-bundle-v3"
TASK_SCHEDULER_EVIDENCE_SCHEMA = (
    "phillip-commodity-v6-task-scheduler-trigger-evidence-v1"
)
CUSTODY_REQUEST_SCHEMA = "phillip-commodity-v6-worm-custody-request-v1"
CUSTODY_POLICY_SCHEMA = "phillip-commodity-v6-worm-custody-rsa-policy-v1"
CUSTODY_RECEIPT_SCHEMA = "phillip-commodity-v6-worm-custody-receipt-v1"
CUSTODY_ASSESSMENT_SCHEMA = (
    "phillip-commodity-v6-worm-custody-assessment-v1"
)
BUNDLE_MANIFEST = "PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE.json"
CUSTODY_REQUEST_MANIFEST = "PHILLIP_COMMODITY_V6_WORM_CUSTODY_REQUEST.json"
CUSTODY_ACCEPTANCE_MEMBER = "phillip-commodity-v6-postrun-acceptance.zip"
TOOLKIT_MANIFEST = "PHILLIP_COMMODITY_V6_POSTRUN_TOOLKIT.json"
TOOL_PATH = "phillip_commodity_v6_postrun_acceptance.py"
WRAPPER_PATH = "Invoke-PhillipCommodityV6PostRunAcceptance.ps1"
CUSTODY_REQUEST_WRAPPER_PATH = "New-PhillipCommodityV6CustodyRequest.ps1"
CUSTODY_RECEIPT_WRAPPER_PATH = "Test-PhillipCommodityV6CustodyReceipt.ps1"
TRIGGER_AUDIT_READINESS_WRAPPER_PATH = (
    "Test-PhillipCommodityV6TriggerAuditReadiness.ps1"
)
RUNBOOK_PATH = "PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE.md"
TOOLKIT_SOURCE_PATHS = (
    RUNBOOK_PATH,
    WRAPPER_PATH,
    CUSTODY_REQUEST_WRAPPER_PATH,
    CUSTODY_RECEIPT_WRAPPER_PATH,
    TRIGGER_AUDIT_READINESS_WRAPPER_PATH,
    TOOL_PATH,
)
TOOLKIT_PATHS = (*TOOLKIT_SOURCE_PATHS, TOOLKIT_MANIFEST)
EVIDENCE_PATHS = (
    "audit-export.json",
    "audit-manifest.json",
    "evidence-checkpoint.json",
    "health-transcript.txt",
    "installation-receipt.json",
    "installed-task.xml",
    "receipt-acl-evidence.json",
    "task-scheduler-events.json",
)
BUNDLE_PATHS = (*EVIDENCE_PATHS, BUNDLE_MANIFEST)
CUSTODY_REQUEST_PATHS = (CUSTODY_ACCEPTANCE_MEMBER, CUSTODY_REQUEST_MANIFEST)
SHA256_ZERO = "0" * 64
CUSTODY_SIGNATURE_ALGORITHM = "RSASSA-PKCS1-v1_5-SHA256"
CUSTODY_OBJECT_LOCK_MODE = "COMPLIANCE"
CUSTODY_MINIMUM_RETENTION_DAYS = 365
CUSTODY_RETENTION_FLOOR_UTC = SCHEDULE_END_UTC + timedelta(
    days=CUSTODY_MINIMUM_RETENTION_DAYS
)
CUSTODY_RECEIPT_DOMAIN = (
    b"AI_SCALPER:PHILLIP_COMMODITY_V6_WORM_CUSTODY_RECEIPT:v1\x00"
)
MINIMUM_RSA_BITS = 3072
MAXIMUM_RSA_BITS = 8192
RSA_PUBLIC_EXPONENT = 65537
_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_LOWER_HEX_RE = re.compile(r"^[0-9a-f]+$")
_EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
_EVENT_NAMESPACE_MAP = {"event": _EVENT_NAMESPACE}
TASK_SCHEDULER_EVENT_CHANNEL = (
    "Microsoft-Windows-TaskScheduler/Operational"
)
TASK_SCHEDULER_EVENT_PROVIDER = "Microsoft-Windows-TaskScheduler"
TASK_STARTED_EVENT_ID = 100
TASK_COMPLETED_EVENT_ID = 102
SCHEDULED_TRIGGER_EVENT_ID = 107
MANUAL_TRIGGER_EVENT_ID = 110
TASK_SCHEDULER_EVENT_IDS = (
    TASK_STARTED_EVENT_ID,
    TASK_COMPLETED_EVENT_ID,
    SCHEDULED_TRIGGER_EVENT_ID,
    MANUAL_TRIGGER_EVENT_ID,
)
TASK_SCHEDULER_QUERY_START_UTC = FIRST_SCHEDULED_START_UTC - timedelta(
    minutes=5
)
TASK_SCHEDULER_CAPTURE_MAXIMUM_DELAY = timedelta(minutes=30)
TASK_SCHEDULER_CORRELATION_TOLERANCE = timedelta(minutes=2)
MAX_TASK_SCHEDULER_EVENTS = 4096
MAX_TASK_SCHEDULER_EVENT_XML_BYTES = 512 * 1024
JST = timezone(timedelta(hours=9))
SCHEDULE_BOUNDARY_TOLERANCE = timedelta(minutes=5)
TASK_NEVER_RUN_CUTOFF_UTC = datetime(2000, 1, 1, tzinfo=timezone.utc)
TASK_RESULT_REQUEST_REFUSED = 0x800710E0
HEARTBEAT_MAXIMUM_AGE = timedelta(minutes=5)
HEARTBEAT_FUTURE_SKEW = timedelta(minutes=1)
RECEIPT_ACL_CAPTURE_MAXIMUM_DELAY = timedelta(minutes=30)
RECEIPT_ACL_SCHEMA = "phillip-commodity-v6-receipt-acl-evidence-v1"
AUTHORIZED_RECEIPT_WRITE_SIDS = (
    "S-1-5-18",  # LocalSystem
    "S-1-5-32-544",  # BUILTIN\\Administrators
)


class PostRunAcceptanceError(RuntimeError):
    """One post-run acceptance invariant failed closed."""


def _reject(code: str) -> None:
    raise PostRunAcceptanceError(code)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_git_oid(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _has_reparse_attribute(metadata: os.stat_result) -> bool:
    return bool(
        int(getattr(metadata, "st_file_attributes", 0))
        & FILE_ATTRIBUTE_REPARSE_POINT
    )


def _regular(path: Path, code: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PostRunAcceptanceError(code) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _has_reparse_attribute(metadata)
    ):
        _reject(code)
    return path.absolute()


def _directory(path: Path, code: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PostRunAcceptanceError(code) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _has_reparse_attribute(metadata)
    ):
        _reject(code)
    return path.absolute()


def _read_regular(path: Path, code: str, maximum: int = MAX_MEMBER_BYTES) -> bytes:
    safe = _regular(path, code)
    before = safe.lstat()
    if before.st_size <= 0 or before.st_size > maximum:
        _reject(code)
    try:
        with safe.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
            if (
                not stat.S_ISREG(opened.st_mode)
                or stat.S_ISLNK(opened.st_mode)
                or _has_reparse_attribute(opened)
                or any(
                    getattr(before, name) != getattr(opened, name)
                    for name in fields
                )
            ):
                _reject(code)
            value = handle.read(maximum + 1)
            after_handle = os.fstat(handle.fileno())
    except OSError as exc:
        raise PostRunAcceptanceError(code) from exc
    try:
        after_path = safe.lstat()
    except OSError as exc:
        raise PostRunAcceptanceError(code) from exc
    if (
        any(
            getattr(opened, name) != getattr(after_handle, name)
            or getattr(opened, name) != getattr(after_path, name)
            for name in fields
        )
        or len(value) != opened.st_size
        or len(value) > maximum
        or not stat.S_ISREG(after_path.st_mode)
        or stat.S_ISLNK(after_path.st_mode)
        or _has_reparse_attribute(after_handle)
        or _has_reparse_attribute(after_path)
    ):
        _reject(code)
    return value


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PostRunAcceptanceError("JSON_CANONICALIZATION_REJECTED") from exc


def _pretty_json(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PostRunAcceptanceError("JSON_SERIALIZATION_REJECTED") from exc


def _json_object(value: bytes, code: str) -> dict[str, object]:
    def reject_duplicates(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                _reject(code)
            result[key] = item
        return result

    try:
        parsed = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
        )
    except PostRunAcceptanceError:
        raise
    except (UnicodeDecodeError, ValueError) as exc:
        raise PostRunAcceptanceError(code) from exc
    if not isinstance(parsed, dict):
        _reject(code)
    return parsed


def _json_object_unique(value: bytes, code: str) -> dict[str, object]:
    return _json_object(value, code)


def _strict_canonical_json_object(value: bytes, kind: str) -> dict[str, object]:
    if not isinstance(value, bytes) or len(value) > MAX_CUSTODY_DOCUMENT_BYTES:
        _reject(f"{kind}_TOO_LARGE")
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PostRunAcceptanceError(f"{kind}_JSON_INVALID") from exc

    def reject_duplicates(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                _reject(f"{kind}_DUPLICATE_KEY")
            result[key] = item
        return result

    try:
        parsed = json.loads(text, object_pairs_hook=reject_duplicates)
    except PostRunAcceptanceError:
        raise
    except (TypeError, json.JSONDecodeError) as exc:
        raise PostRunAcceptanceError(f"{kind}_JSON_INVALID") from exc
    if not isinstance(parsed, dict) or _canonical_json(parsed) != value:
        _reject(f"{kind}_JSON_NOT_CANONICAL")
    return parsed


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        _reject(code)
    return value


def _nonzero_sha256(value: object, code: str) -> str:
    if not _is_sha256(value) or value == SHA256_ZERO:
        _reject(code)
    return str(value)


def custody_public_key_fingerprint_sha256(
    modulus_hex: str,
    exponent: int,
) -> str:
    return _sha256(
        _canonical_json(
            {"rsa_exponent": exponent, "rsa_modulus_hex": modulus_hex}
        )
    )


def _verify_rsa_pkcs1v15_sha256(
    *,
    modulus_hex: str,
    exponent: int,
    message: bytes,
    signature_hex: str,
) -> bool:
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    try:
        modulus = int(modulus_hex, 16)
        signature = bytes.fromhex(signature_hex)
    except (TypeError, ValueError):
        return False
    length = (modulus.bit_length() + 7) // 8
    if len(signature) != length:
        return False
    encoded_integer = int.from_bytes(signature, "big")
    if encoded_integer >= modulus:
        return False
    encoded = pow(encoded_integer, exponent, modulus).to_bytes(length, "big")
    digest_info = _SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
    padding_length = length - len(digest_info) - 3
    if padding_length < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    return hmac.compare_digest(encoded, expected)


def _parse_utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _reject(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PostRunAcceptanceError(code) from exc
    if parsed.utcoffset() != timedelta(0):
        _reject(code)
    return parsed.astimezone(timezone.utc)


def _parse_jst(value: object, code: str) -> datetime:
    if not isinstance(value, str):
        _reject(code)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise PostRunAcceptanceError(code) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(hours=9):
        _reject(code)
    return parsed.astimezone(JST)


def _is_scheduled_boundary(value: datetime) -> bool:
    local = value.astimezone(JST)
    expected = local.replace(hour=6, minute=45, second=0, microsecond=0)
    return (
        local.weekday() < 5
        and abs(local - expected) <= SCHEDULE_BOUNDARY_TOLERANCE
    )


def _latest_scheduled_boundary(observed_at: datetime) -> datetime | None:
    local = observed_at.astimezone(JST)
    candidate = local.replace(hour=6, minute=45, second=0, microsecond=0)
    if candidate > local:
        candidate -= timedelta(days=1)
    schedule_end_local = SCHEDULE_END_UTC.astimezone(JST)
    if candidate > schedule_end_local:
        candidate = schedule_end_local.replace(
            hour=6,
            minute=45,
            second=0,
            microsecond=0,
        )
        if candidate > schedule_end_local:
            candidate -= timedelta(days=1)
    while candidate.weekday() >= 5:
        candidate -= timedelta(days=1)
    candidate_utc = candidate.astimezone(timezone.utc)
    if candidate_utc < FIRST_SCHEDULED_START_UTC:
        return None
    return candidate_utc


def diagnose_trigger_readiness(
    *,
    observed_at_utc: str,
    last_run_at_utc: str,
    last_task_result: int,
    task_state: str,
    next_run_time_local: str,
    allow_start_on_demand: bool,
) -> dict[str, object]:
    """Classify scheduler observations without granting acceptance authority."""

    observed_at = _parse_utc(observed_at_utc, "OBSERVED_TIME_REJECTED")
    last_run_at = _parse_utc(last_run_at_utc, "LAST_RUN_TIME_REJECTED")
    next_run_at = _parse_jst(next_run_time_local, "NEXT_RUN_TIME_REJECTED")
    if (
        type(last_task_result) is not int
        or last_task_result < -(2**31)
        or last_task_result > 0xFFFFFFFF
        or task_state not in {"Ready", "Running"}
        or type(allow_start_on_demand) is not bool
        or last_run_at > observed_at
        or next_run_at.astimezone(timezone.utc) <= observed_at
    ):
        _reject("TRIGGER_READINESS_INPUT_INVALID")

    normalized_result = last_task_result & 0xFFFFFFFF
    result_hex = f"0x{normalized_result:08X}"
    latest_boundary = _latest_scheduled_boundary(observed_at)
    boundary_aligned = bool(
        latest_boundary is not None
        and abs(last_run_at - latest_boundary) <= SCHEDULE_BOUNDARY_TOLERANCE
    )

    if latest_boundary is None:
        boundary_status = "PRE_FIRST_BOUNDARY"
    elif boundary_aligned and task_state == "Running":
        boundary_status = "OBSERVED_RUNNING"
    elif boundary_aligned and normalized_result == 0:
        boundary_status = "OBSERVED_COMPLETED_ZERO"
    elif boundary_aligned:
        boundary_status = "OBSERVED_NONZERO"
    else:
        boundary_status = "NOT_OBSERVED"

    if last_run_at < TASK_NEVER_RUN_CUTOFF_UTC:
        last_run_classification = "NO_RECORDED_RUN"
    elif boundary_aligned and task_state == "Running":
        last_run_classification = "AUTOMATIC_RUN_ACTIVE"
    elif boundary_aligned and normalized_result == 0:
        last_run_classification = "AUTOMATIC_RUN_COMPLETED_PENDING_EVIDENCE"
    elif boundary_aligned:
        last_run_classification = "AUTOMATIC_RUN_NONZERO_REQUIRES_REVIEW"
    elif (
        normalized_result == TASK_RESULT_REQUEST_REFUSED
        and not allow_start_on_demand
    ):
        last_run_classification = (
            "NON_BOUNDARY_REQUEST_REFUSED_WITH_DEMAND_START_DISABLED"
        )
    else:
        last_run_classification = "NON_BOUNDARY_LAST_RUN_REQUIRES_REVIEW"

    if boundary_status in {"PRE_FIRST_BOUNDARY", "NOT_OBSERVED"}:
        trigger_evidence_collection = "PENDING_AUTOMATIC_RUN"
    elif boundary_status == "OBSERVED_RUNNING":
        trigger_evidence_collection = "PENDING_AUTOMATIC_COMPLETION"
    elif boundary_status == "OBSERVED_COMPLETED_ZERO":
        trigger_evidence_collection = (
            "PENDING_EVENT_CORRELATION_AND_ACCEPTANCE"
        )
    else:
        trigger_evidence_collection = "FORENSIC_REVIEW_REQUIRED"

    return {
        "status": "PHILLIP_COMMODITY_V6_TRIGGER_DIAGNOSTIC_READY",
        "observed_at_utc": _utc_text(observed_at),
        "latest_expected_boundary_utc": (
            _utc_text(latest_boundary) if latest_boundary is not None else None
        ),
        "latest_boundary_status": boundary_status,
        "latest_boundary_observed": boundary_aligned,
        "last_run_at_utc": _utc_text(last_run_at),
        "last_task_result": last_task_result,
        "last_task_result_uint32": normalized_result,
        "last_task_result_hex": result_hex,
        "last_run_classification": last_run_classification,
        "trigger_evidence_collection": trigger_evidence_collection,
        "task_state": task_state,
        "next_run_time_local": next_run_time_local,
        "allow_start_on_demand": allow_start_on_demand,
        "manual_start_provenance_observed": False,
        "event_provenance_inspected": False,
        "acceptance_ready": False,
        "order_capability": "DISABLED",
        "live_allowed": False,
        "task_scheduler_mutation": "NOT_PERFORMED",
        "broker_mutation": "NOT_PERFORMED",
    }


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_canonical_utc(value: object, code: str) -> datetime:
    parsed = _parse_utc(value, code)
    microseconds = parsed.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    if value not in {_utc_text(parsed), microseconds}:
        _reject(code)
    return parsed


def _valid_member_path(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        bool(value)
        and "\\" not in value
        and not value.startswith("/")
        and not value.endswith("/")
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
        and path.as_posix() == value
    )


def _member_row(path: str, value: bytes) -> dict[str, object]:
    return {"path": path, "size_bytes": len(value), "sha256": _sha256(value)}


def _rows_by_path(value: object, expected: Iterable[str]) -> dict[str, dict[str, object]]:
    expected_set = set(expected)
    if not isinstance(value, list) or len(value) != len(expected_set):
        _reject("MEMBER_INVENTORY_REJECTED")
    rows: dict[str, dict[str, object]] = {}
    folded: set[str] = set()
    for row in value:
        if not isinstance(row, dict) or set(row) != {"path", "size_bytes", "sha256"}:
            _reject("MEMBER_INVENTORY_REJECTED")
        path = row.get("path")
        size = row.get("size_bytes")
        digest = row.get("sha256")
        if (
            not isinstance(path, str)
            or path not in expected_set
            or path.casefold() in folded
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
            or size > MAX_MEMBER_BYTES
            or not _is_sha256(digest)
        ):
            _reject("MEMBER_INVENTORY_REJECTED")
        rows[path] = row
        folded.add(path.casefold())
    if set(rows) != expected_set:
        _reject("MEMBER_INVENTORY_REJECTED")
    return rows


def _validate_toolkit_manifest(
    manifest_bytes: bytes,
    *,
    source_commit: str | None = None,
    source_tree: str | None = None,
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    manifest = _json_object(manifest_bytes, "TOOLKIT_MANIFEST_INVALID")
    if set(manifest) != {
        "schema_version",
        "source",
        "installed_scheduler",
        "members",
        "safety",
    }:
        _reject("TOOLKIT_MANIFEST_INVALID")
    source = manifest.get("source")
    installed = manifest.get("installed_scheduler")
    safety = manifest.get("safety")
    if (
        not isinstance(source, dict)
        or set(source) != {"branch", "commit", "tree"}
        or source.get("branch") != BRANCH
        or not _is_git_oid(source.get("commit"))
        or not _is_git_oid(source.get("tree"))
        or (source_commit is not None and source.get("commit") != source_commit)
        or (source_tree is not None and source.get("tree") != source_tree)
        or not isinstance(installed, dict)
        or installed
        != {
            "remediation_source_commit": V63_REMEDIATION_COMMIT,
            "remediation_source_tree": V63_REMEDIATION_TREE,
            "health_checker_sha256": V63_HEALTH_CHECKER_SHA256,
            "task_contract_sha256": V63_TASK_CONTRACT_SHA256,
            "evidence_verifier_sha256": V63_EVIDENCE_VERIFIER_SHA256,
            "task_name": TASK_NAME,
            "contract_id": CONTRACT_ID,
            "first_scheduled_start_utc": _utc_text(FIRST_SCHEDULED_START_UTC),
            "schedule_end_utc": _utc_text(SCHEDULE_END_UTC),
        }
        or safety
        != {
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "task_scheduler_mutation": "NOT_PERFORMED",
            "broker_mutation": "NOT_PERFORMED",
            "offhost_custody_performed": False,
        }
        or manifest.get("schema_version") != TOOLKIT_SCHEMA
    ):
        _reject("TOOLKIT_MANIFEST_INVALID")
    rows = _rows_by_path(manifest.get("members"), TOOLKIT_SOURCE_PATHS)
    return manifest, rows


def validate_extracted_toolkit(
    manifest_path: Path,
    *,
    tool_path: Path,
) -> dict[str, object]:
    manifest_bytes = _read_regular(manifest_path, "TOOLKIT_MANIFEST_UNAVAILABLE")
    manifest, rows = _validate_toolkit_manifest(manifest_bytes)
    root = _directory(manifest_path.parent, "TOOLKIT_ROOT_INVALID")
    entries = list(root.iterdir())
    for path in entries:
        _regular(path, "TOOLKIT_EXTRACTED_INVENTORY_REJECTED")
    observed = {path.name for path in entries}
    if observed != set(TOOLKIT_PATHS):
        _reject("TOOLKIT_EXTRACTED_INVENTORY_REJECTED")
    for relative, row in rows.items():
        data = _read_regular(root / relative, "TOOLKIT_MEMBER_UNAVAILABLE")
        if len(data) != row["size_bytes"] or _sha256(data) != row["sha256"]:
            _reject("TOOLKIT_MEMBER_DRIFT")
    observed_tool = _regular(tool_path, "TOOLKIT_TOOL_UNAVAILABLE")
    expected_tool = _regular(root / TOOL_PATH, "TOOLKIT_TOOL_UNAVAILABLE")
    try:
        same_tool = os.path.samefile(observed_tool, expected_tool)
    except OSError as exc:
        raise PostRunAcceptanceError("TOOLKIT_TOOL_PATH_MISMATCH") from exc
    if not same_tool:
        _reject("TOOLKIT_TOOL_PATH_MISMATCH")
    source = manifest["source"]
    if not isinstance(source, dict):
        _reject("TOOLKIT_MANIFEST_INVALID")
    return {
        "manifest": manifest,
        "manifest_sha256": _sha256(manifest_bytes),
        "source_commit": source["commit"],
        "source_tree": source["tree"],
    }


INSTALLATION_KEYS = {
    "schema_version",
    "task_name",
    "installed_at_utc",
    "windows_sid",
    "remediation_source_commit",
    "remediation_source_tree",
    "worker_source_commit",
    "worker_source_tree",
    "worker_contract_id",
    "proof_receipt_path",
    "proof_receipt_sha256",
    "task_contract_sha256",
    "evidence_verifier_sha256",
    "contract_payload_sha256",
    "build_identity_sha256",
    "authenticated_audit_pairs",
    "authenticated_heartbeat_at_install_utc",
    "authenticated_source_event_count",
    "evidence_checkpoint_root",
    "initial_evidence_checkpoint_path",
    "initial_evidence_checkpoint_file_sha256",
    "initial_evidence_checkpoint_hmac_sha256",
    "task_definition_sha256",
    "registered_disabled_xml_sha256",
    "exported_task_xml_sha256",
    "command",
    "arguments",
    "working_directory",
    "frozen_runtime_repo",
    "frozen_runtime_worktree_lock",
    "start_boundary",
    "end_boundary",
    "worker_duration_seconds",
    "minimum_installation_lead_seconds",
    "verified_next_run_time",
    "preserved_tasks",
    "task_started_manually",
    "order_capability",
    "live_allowed",
    "safe_to_demo_auto_order",
    "broker_mutation",
}


CHECKPOINT_KEYS = {
    "schema_version",
    "candidate_id",
    "contract_id",
    "contract_payload_sha256",
    "build_identity_sha256",
    "proof_receipt_sha256",
    "runtime_key",
    "authenticity",
    "signing_key_id",
    "committed_manifest_count",
    "committed_manifest_names_sha256",
    "last_manifest_name",
    "last_manifest_file_sha256",
    "last_manifest_authenticated_sha256",
    "last_audit_name",
    "last_audit_sha256",
    "last_invocation_id",
    "source_operational_event_count",
    "source_operational_head_sha256",
    "source_operational_signed_head_hmac_sha256",
    "latest_heartbeat_at_utc",
    "predecessor_checkpoint_hmac_sha256",
    "source_chain_from_genesis",
    "order_capability",
    "live_allowed",
    "safe_to_demo_auto_order",
    "checkpoint_hmac_sha256",
}


def _validate_installation_receipt(receipt: dict[str, object]) -> None:
    required_strings = (
        "windows_sid",
        "proof_receipt_path",
        "evidence_checkpoint_root",
        "initial_evidence_checkpoint_path",
        "command",
        "arguments",
        "working_directory",
        "frozen_runtime_repo",
        "frozen_runtime_worktree_lock",
    )
    if any(
        not isinstance(receipt.get(field), str) or not receipt.get(field)
        for field in required_strings
    ):
        _reject("INSTALLATION_RECEIPT_REJECTED")
    windows_paths = (
        "proof_receipt_path",
        "evidence_checkpoint_root",
        "initial_evidence_checkpoint_path",
        "command",
        "working_directory",
        "frozen_runtime_repo",
        "frozen_runtime_worktree_lock",
    )
    if any(
        not PureWindowsPath(str(receipt[field])).is_absolute()
        or ".." in PureWindowsPath(str(receipt[field])).parts
        for field in windows_paths
    ):
        _reject("INSTALLATION_RECEIPT_REJECTED")
    checkpoint_root = PureWindowsPath(str(receipt["evidence_checkpoint_root"]))
    initial_checkpoint = PureWindowsPath(
        str(receipt["initial_evidence_checkpoint_path"])
    )
    if (
        set(receipt) != INSTALLATION_KEYS
        or receipt.get("schema_version")
        != "phillip-commodity-v6-scheduler-installation-receipt-v1"
        or receipt.get("task_name") != TASK_NAME
        or receipt.get("remediation_source_commit") != V63_REMEDIATION_COMMIT
        or receipt.get("remediation_source_tree") != V63_REMEDIATION_TREE
        or receipt.get("worker_source_commit") != WORKER_COMMIT
        or receipt.get("worker_source_tree") != WORKER_TREE
        or receipt.get("worker_contract_id") != CONTRACT_ID
        or receipt.get("proof_receipt_sha256") != PROOF_RECEIPT_SHA256
        or receipt.get("task_contract_sha256") != V63_TASK_CONTRACT_SHA256
        or receipt.get("evidence_verifier_sha256")
        != V63_EVIDENCE_VERIFIER_SHA256
        or receipt.get("start_boundary") != FIRST_SCHEDULED_START_LOCAL
        or receipt.get("end_boundary") != SCHEDULE_END_LOCAL
        or receipt.get("worker_duration_seconds") != 84300
        or receipt.get("minimum_installation_lead_seconds") != 900
        or receipt.get("verified_next_run_time") != "2026-07-30T06:45:00"
        or receipt.get("preserved_tasks") != list(PRIOR_TASK_STATES)
        or receipt.get("task_started_manually") is not False
        or receipt.get("order_capability") != "DISABLED"
        or receipt.get("live_allowed") is not False
        or receipt.get("safe_to_demo_auto_order") is not False
        or receipt.get("broker_mutation") != "NOT_PERFORMED"
        or not str(receipt["windows_sid"]).startswith("S-1-5-")
        or not _is_sha256(receipt.get("contract_payload_sha256"))
        or not _is_sha256(receipt.get("build_identity_sha256"))
        or not _is_sha256(receipt.get("initial_evidence_checkpoint_file_sha256"))
        or not _is_sha256(receipt.get("initial_evidence_checkpoint_hmac_sha256"))
        or not _is_sha256(receipt.get("task_definition_sha256"))
        or not _is_sha256(receipt.get("registered_disabled_xml_sha256"))
        or not _is_sha256(receipt.get("exported_task_xml_sha256"))
        or initial_checkpoint.parent != checkpoint_root
        or not initial_checkpoint.name.startswith("checkpoint-")
        or not initial_checkpoint.name.endswith(
            f"-{receipt['initial_evidence_checkpoint_hmac_sha256']}.json"
        )
        or not str(receipt["command"]).casefold().endswith("\\python.exe")
        or PureWindowsPath(str(receipt["working_directory"]))
        != PureWindowsPath(str(receipt["frozen_runtime_repo"]))
        or isinstance(receipt.get("authenticated_audit_pairs"), bool)
        or not isinstance(receipt.get("authenticated_audit_pairs"), int)
        or int(receipt["authenticated_audit_pairs"]) < 2
        or isinstance(receipt.get("authenticated_source_event_count"), bool)
        or not isinstance(receipt.get("authenticated_source_event_count"), int)
        or int(receipt["authenticated_source_event_count"]) < 1
    ):
        _reject("INSTALLATION_RECEIPT_REJECTED")
    _parse_utc(receipt.get("installed_at_utc"), "INSTALLATION_TIME_REJECTED")
    _parse_utc(
        receipt.get("authenticated_heartbeat_at_install_utc"),
        "INSTALLATION_HEARTBEAT_REJECTED",
    )


def _checkpoint_file_name(checkpoint: dict[str, object]) -> str:
    return (
        "checkpoint-"
        f"{int(checkpoint['source_operational_event_count']):020d}-"
        f"{checkpoint['checkpoint_hmac_sha256']}.json"
    )


def _validate_checkpoint(checkpoint: dict[str, object], receipt: dict[str, object]) -> None:
    predecessor = checkpoint.get("predecessor_checkpoint_hmac_sha256")
    invocation_id = checkpoint.get("last_invocation_id")
    if (
        set(checkpoint) != CHECKPOINT_KEYS
        or checkpoint.get("schema_version") != CHECKPOINT_SCHEMA
        or checkpoint.get("candidate_id") != "phillip-commodity"
        or checkpoint.get("contract_id") != CONTRACT_ID
        or checkpoint.get("contract_payload_sha256")
        != receipt.get("contract_payload_sha256")
        or checkpoint.get("build_identity_sha256")
        != receipt.get("build_identity_sha256")
        or checkpoint.get("proof_receipt_sha256") != PROOF_RECEIPT_SHA256
        or checkpoint.get("runtime_key")
        != "phillip-commodity-broker-shadow-v1"
        or checkpoint.get("authenticity") != "HMAC_SHA256"
        or not isinstance(checkpoint.get("signing_key_id"), str)
        or not checkpoint.get("signing_key_id")
        or checkpoint.get("source_chain_from_genesis") is not True
        or checkpoint.get("order_capability") != "DISABLED"
        or checkpoint.get("live_allowed") is not False
        or checkpoint.get("safe_to_demo_auto_order") is not False
        or isinstance(checkpoint.get("committed_manifest_count"), bool)
        or not isinstance(checkpoint.get("committed_manifest_count"), int)
        or int(checkpoint["committed_manifest_count"]) < 2
        or isinstance(checkpoint.get("source_operational_event_count"), bool)
        or not isinstance(checkpoint.get("source_operational_event_count"), int)
        or int(checkpoint["source_operational_event_count"]) < 1
        or not all(
            _is_sha256(checkpoint.get(field))
            for field in (
                "committed_manifest_names_sha256",
                "last_manifest_file_sha256",
                "last_manifest_authenticated_sha256",
                "last_audit_sha256",
                "source_operational_head_sha256",
                "source_operational_signed_head_hmac_sha256",
                "checkpoint_hmac_sha256",
            )
        )
        or (predecessor is not None and not _is_sha256(predecessor))
        or not isinstance(invocation_id, str)
        or not invocation_id
        or PurePosixPath(invocation_id).name != invocation_id
        or ".." in invocation_id
        or checkpoint.get("last_manifest_name")
        != f"{invocation_id}.manifest.json"
        or checkpoint.get("last_audit_name") != f"{invocation_id}.audit.json"
    ):
        _reject("CHECKPOINT_REJECTED")
    _parse_utc(checkpoint.get("latest_heartbeat_at_utc"), "CHECKPOINT_TIME_REJECTED")


def _manifest_authenticated_sha256(manifest: dict[str, object]) -> str:
    claimed = manifest.get("manifest_sha256")
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256", None)
    observed = _sha256(_canonical_json(unsigned))
    if claimed != observed:
        _reject("AUDIT_MANIFEST_AUTHENTICATED_HASH_REJECTED")
    return observed


def _validate_audit_pair(
    *,
    checkpoint: dict[str, object],
    audit_bytes: bytes,
    manifest_bytes: bytes,
) -> None:
    if (
        _sha256(audit_bytes) != checkpoint["last_audit_sha256"]
        or _sha256(manifest_bytes) != checkpoint["last_manifest_file_sha256"]
    ):
        _reject("AUDIT_PAIR_FILE_HASH_REJECTED")
    audit = _json_object(audit_bytes, "AUDIT_EXPORT_JSON_REJECTED")
    manifest = _json_object(manifest_bytes, "AUDIT_MANIFEST_JSON_REJECTED")
    runtime_status = audit.get("runtime_status")
    operational_events = audit.get("operational_events")
    terminal_events = (
        [
            event
            for event in operational_events
            if isinstance(event, dict)
            and event.get("invocation_id") == checkpoint["last_invocation_id"]
            and event.get("stage") == "INVOCATION_TERMINAL"
        ]
        if isinstance(operational_events, list)
        else []
    )
    if (
        _manifest_authenticated_sha256(manifest)
        != checkpoint["last_manifest_authenticated_sha256"]
        or manifest.get("invocation_id") != checkpoint["last_invocation_id"]
        or manifest.get("audit_export_file") != checkpoint["last_audit_name"]
        or manifest.get("authenticity") != "HMAC_SHA256"
        or manifest.get("signing_key_id") != checkpoint["signing_key_id"]
        or manifest.get("source_chain_verified_from_genesis") is not True
        or manifest.get("order_capability") != "DISABLED"
        or manifest.get("live_allowed") is not False
        or manifest.get("safe_to_demo_auto_order") is not False
        or manifest.get("max_lot") != 0.01
        or not isinstance(runtime_status, dict)
        or runtime_status.get("recorded_state") != "HEALTHY"
        or runtime_status.get("invocation_id") != checkpoint["last_invocation_id"]
        or runtime_status.get("failure_code") is not None
        or runtime_status.get("authenticity") != "HMAC_SHA256"
        or runtime_status.get("signing_key_id") != checkpoint["signing_key_id"]
        or runtime_status.get("heartbeat_at_utc")
        != checkpoint["latest_heartbeat_at_utc"]
        or audit.get("source_operational_event_count")
        != checkpoint["source_operational_event_count"]
        or audit.get("source_operational_head_sha256")
        != checkpoint["source_operational_head_sha256"]
        or audit.get("source_operational_signed_head_hmac_sha256")
        != checkpoint["source_operational_signed_head_hmac_sha256"]
        or audit.get("order_capability") != "DISABLED"
        or audit.get("live_allowed") is not False
        or audit.get("safe_to_demo_auto_order") is not False
        or audit.get("max_lot") != 0.01
        or len(terminal_events) != 1
        or terminal_events[0].get("outcome") != "PASS"
    ):
        _reject("AUDIT_PAIR_PROJECTION_REJECTED")


def _validate_receipt_acl_evidence(
    value: bytes,
    *,
    receipt_bytes: bytes,
    receipt: dict[str, object],
    observed_at: datetime,
    last_run_at: datetime,
) -> dict[str, object]:
    evidence = _json_object_unique(value, "RECEIPT_ACL_EVIDENCE_REJECTED")
    expected_sids = sorted(
        {*AUTHORIZED_RECEIPT_WRITE_SIDS, str(receipt["windows_sid"])}
    )
    captured_at = _parse_utc(
        evidence.get("captured_at_utc"),
        "RECEIPT_ACL_TIME_REJECTED",
    )
    receipt_path = evidence.get("receipt_path")
    if (
        set(evidence)
        != {
            "schema_version",
            "captured_at_utc",
            "receipt_path",
            "receipt_sha256",
            "owner_sid",
            "acl_protected",
            "authorized_write_sids",
            "unauthorized_write_sids",
            "acl_sddl_sha256",
            "collection",
        }
        or evidence.get("schema_version") != RECEIPT_ACL_SCHEMA
        or not isinstance(receipt_path, str)
        or not PureWindowsPath(receipt_path).is_absolute()
        or PureWindowsPath(receipt_path).name
        != f"{TASK_NAME}.installation-receipt.json"
        or ".." in PureWindowsPath(receipt_path).parts
        or evidence.get("receipt_sha256") != _sha256(receipt_bytes)
        or evidence.get("owner_sid") not in expected_sids
        or evidence.get("acl_protected") is not True
        or evidence.get("authorized_write_sids") != expected_sids
        or evidence.get("unauthorized_write_sids") != []
        or not _is_sha256(evidence.get("acl_sddl_sha256"))
        or evidence.get("collection")
        != {
            "api": "Get-Acl",
            "access_rules_translated_to_sid": True,
            "task_scheduler_mutation": "NOT_PERFORMED",
            "broker_mutation": "NOT_PERFORMED",
        }
        or captured_at < last_run_at
        or captured_at < observed_at - RECEIPT_ACL_CAPTURE_MAXIMUM_DELAY
        or captured_at > observed_at + RECEIPT_ACL_CAPTURE_MAXIMUM_DELAY
    ):
        _reject("RECEIPT_ACL_EVIDENCE_REJECTED")
    return {
        "receipt_sha256": evidence["receipt_sha256"],
        "owner_sid": evidence["owner_sid"],
        "acl_protected": True,
        "authorized_write_sids": expected_sids,
        "unauthorized_write_sids": [],
        "acl_sddl_sha256": evidence["acl_sddl_sha256"],
        "captured_at_utc": _utc_text(captured_at),
    }


def _validate_postrun_state(
    *,
    receipt: dict[str, object],
    checkpoint: dict[str, object],
    observed_at: datetime,
    task_state: str,
    last_run_at: datetime,
    last_task_result: int,
    next_run_local: str,
    v4_state: str,
    v5_state: str,
    health_transcript: bytes,
) -> None:
    initial_heartbeat = _parse_utc(
        receipt["authenticated_heartbeat_at_install_utc"],
        "INSTALLATION_HEARTBEAT_REJECTED",
    )
    latest_heartbeat = _parse_utc(
        checkpoint["latest_heartbeat_at_utc"],
        "CHECKPOINT_TIME_REJECTED",
    )
    next_run_at = _parse_jst(next_run_local, "NEXT_RUN_TIME_REJECTED")
    fields = _health_transcript_fields(health_transcript)
    transcript_heartbeat = _parse_utc(
        fields["AuthenticatedHeartbeatAtUtc"],
        "HEALTH_TRANSCRIPT_REJECTED",
    )
    transcript_observed = _parse_utc(
        fields["ObservedAtUtc"],
        "HEALTH_TRANSCRIPT_REJECTED",
    )
    checkpoint_name = PureWindowsPath(fields["EvidenceCheckpoint"]).name
    expected_checkpoint_path = PureWindowsPath(
        str(receipt["evidence_checkpoint_root"])
    ) / _checkpoint_file_name(checkpoint)
    if (
        observed_at < FIRST_SCHEDULED_START_UTC
        or observed_at >= SCHEDULE_END_UTC
        or last_run_at < FIRST_SCHEDULED_START_UTC
        or last_run_at > observed_at
        or not _is_scheduled_boundary(last_run_at)
        or next_run_at <= last_run_at.astimezone(JST)
        or next_run_at.astimezone(timezone.utc) >= SCHEDULE_END_UTC
        or latest_heartbeat < FIRST_SCHEDULED_START_UTC
        or latest_heartbeat <= initial_heartbeat
        or latest_heartbeat < last_run_at
        or observed_at - latest_heartbeat > HEARTBEAT_MAXIMUM_AGE
        or latest_heartbeat - observed_at > HEARTBEAT_FUTURE_SKEW
        or int(checkpoint["source_operational_event_count"])
        <= int(receipt["authenticated_source_event_count"])
        or int(checkpoint["committed_manifest_count"])
        <= int(receipt["authenticated_audit_pairs"])
        or checkpoint["checkpoint_hmac_sha256"]
        == receipt["initial_evidence_checkpoint_hmac_sha256"]
        or checkpoint["predecessor_checkpoint_hmac_sha256"] is None
        or task_state != "Ready"
        or last_task_result != 0
        or not isinstance(last_task_result, int)
        or isinstance(last_task_result, bool)
        or v4_state != "Disabled"
        or v5_state != "Disabled"
        or fields["Status"] != "PHILLIP_COMMODITY_V6_TASK_HEALTHY"
        or fields["TaskName"] != TASK_NAME
        or fields["TaskState"] != task_state
        or fields["LastTaskResult"] != str(last_task_result)
        or transcript_observed != observed_at
        or transcript_heartbeat != latest_heartbeat
        or fields["AuthenticatedSourceEventCount"]
        != str(checkpoint["source_operational_event_count"])
        or fields["AuditPairs"] != str(checkpoint["committed_manifest_count"])
        or checkpoint_name != _checkpoint_file_name(checkpoint)
        or PureWindowsPath(fields["EvidenceCheckpoint"])
        != expected_checkpoint_path
        or fields["RemediationSourceCommit"] != V63_REMEDIATION_COMMIT
        or fields["FrozenWorkerCommit"] != WORKER_COMMIT
        or fields["FrozenWorkerTree"] != WORKER_TREE
        or fields["Contract"] != CONTRACT_ID
        or fields["OrderCapability"] != "DISABLED"
        or fields["LiveAllowed"].casefold() != "false"
        or fields["TaskSchedulerMutation"] != "NOT_PERFORMED"
        or fields["BrokerMutation"] != "NOT_PERFORMED"
        or fields["HealthMutexAbandoned"].casefold() != "false"
    ):
        _reject("POSTRUN_ACCEPTANCE_STATE_REJECTED")


HEALTH_TRANSCRIPT_FIELDS = {
    "Status",
    "ObservedAtUtc",
    "TaskName",
    "TaskState",
    "LastTaskResult",
    "AuthenticatedHeartbeatAtUtc",
    "AuthenticatedSourceEventCount",
    "AuditPairs",
    "EvidenceCheckpoint",
    "HealthMutexAbandoned",
    "RemediationSourceCommit",
    "FrozenWorkerCommit",
    "FrozenWorkerTree",
    "Contract",
    "OrderCapability",
    "LiveAllowed",
    "TaskSchedulerMutation",
    "BrokerMutation",
}


def _health_transcript_fields(value: bytes) -> dict[str, str]:
    try:
        transcript = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PostRunAcceptanceError("HEALTH_TRANSCRIPT_REJECTED") from exc
    fields: dict[str, str] = {}
    for line in transcript.splitlines():
        if ":" not in line:
            continue
        label, field_value = line.split(":", 1)
        label = label.strip()
        if label not in HEALTH_TRANSCRIPT_FIELDS:
            continue
        if label in fields or not field_value.strip():
            _reject("HEALTH_TRANSCRIPT_REJECTED")
        fields[label] = field_value.strip()
    if set(fields) != HEALTH_TRANSCRIPT_FIELDS:
        _reject("HEALTH_TRANSCRIPT_REJECTED")
    return fields


def _normalized_instance_id(value: object) -> str:
    if not isinstance(value, str) or not value:
        _reject("TASK_SCHEDULER_EVENT_XML_REJECTED")
    try:
        parsed = uuid.UUID(value.strip("{}"))
    except (AttributeError, ValueError) as exc:
        raise PostRunAcceptanceError(
            "TASK_SCHEDULER_EVENT_XML_REJECTED"
        ) from exc
    if parsed.int == 0:
        _reject("TASK_SCHEDULER_EVENT_XML_REJECTED")
    return "{" + str(parsed) + "}"


def _exact_event_xml_child(parent: ET.Element, name: str) -> ET.Element:
    nodes = parent.findall(f"event:{name}", _EVENT_NAMESPACE_MAP)
    if len(nodes) != 1:
        _reject("TASK_SCHEDULER_EVENT_XML_REJECTED")
    return nodes[0]


def _parse_task_scheduler_event(
    row: object,
) -> dict[str, object]:
    if not isinstance(row, dict) or set(row) != {
        "event_id",
        "event_record_id",
        "time_created_utc",
        "raw_xml",
        "raw_xml_sha256",
    }:
        _reject("TASK_SCHEDULER_EVENT_ROW_REJECTED")
    event_id = row.get("event_id")
    record_id = row.get("event_record_id")
    raw_xml = row.get("raw_xml")
    if (
        isinstance(event_id, bool)
        or not isinstance(event_id, int)
        or event_id not in TASK_SCHEDULER_EVENT_IDS
        or isinstance(record_id, bool)
        or not isinstance(record_id, int)
        or record_id <= 0
        or not isinstance(raw_xml, str)
        or not raw_xml
        or len(raw_xml.encode("utf-8")) > MAX_TASK_SCHEDULER_EVENT_XML_BYTES
        or "<!DOCTYPE" in raw_xml.upper()
        or "<!ENTITY" in raw_xml.upper()
        or _sha256(raw_xml.encode("utf-8")) != row.get("raw_xml_sha256")
    ):
        _reject("TASK_SCHEDULER_EVENT_ROW_REJECTED")
    row_time = _parse_utc(
        row.get("time_created_utc"),
        "TASK_SCHEDULER_EVENT_TIME_REJECTED",
    )
    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as exc:
        raise PostRunAcceptanceError(
            "TASK_SCHEDULER_EVENT_XML_REJECTED"
        ) from exc
    if root.tag != f"{{{_EVENT_NAMESPACE}}}Event":
        _reject("TASK_SCHEDULER_EVENT_XML_REJECTED")
    systems = root.findall("event:System", _EVENT_NAMESPACE_MAP)
    event_data_nodes = root.findall("event:EventData", _EVENT_NAMESPACE_MAP)
    if len(systems) != 1 or len(event_data_nodes) != 1:
        _reject("TASK_SCHEDULER_EVENT_XML_REJECTED")
    system = systems[0]
    event_data = event_data_nodes[0]
    provider = _exact_event_xml_child(system, "Provider")
    event_id_node = _exact_event_xml_child(system, "EventID")
    record_id_node = _exact_event_xml_child(system, "EventRecordID")
    time_node = _exact_event_xml_child(system, "TimeCreated")
    channel_node = _exact_event_xml_child(system, "Channel")
    computer_node = _exact_event_xml_child(system, "Computer")
    try:
        xml_event_id = int(event_id_node.text or "")
        xml_record_id = int(record_id_node.text or "")
    except (AttributeError, TypeError, ValueError) as exc:
        raise PostRunAcceptanceError(
            "TASK_SCHEDULER_EVENT_XML_REJECTED"
        ) from exc
    if (
        provider.attrib.get("Name") != TASK_SCHEDULER_EVENT_PROVIDER
        or xml_event_id != event_id
        or xml_record_id != record_id
        or channel_node.text != TASK_SCHEDULER_EVENT_CHANNEL
        or not (computer_node.text or "").strip()
    ):
        _reject("TASK_SCHEDULER_EVENT_XML_REJECTED")
    xml_time = _parse_utc(
        time_node.attrib.get("SystemTime"),
        "TASK_SCHEDULER_EVENT_TIME_REJECTED",
    )
    if xml_time != row_time:
        _reject("TASK_SCHEDULER_EVENT_TIME_REJECTED")
    values: dict[str, str] = {}
    for node in event_data.findall("event:Data", _EVENT_NAMESPACE_MAP):
        name = node.attrib.get("Name")
        if (
            not isinstance(name, str)
            or not name
            or name in values
            or len(node) != 0
        ):
            _reject("TASK_SCHEDULER_EVENT_XML_REJECTED")
        values[name] = node.text or ""
    task_name = values.get("TaskName")
    instance_values = [
        values[name]
        for name in ("InstanceId", "TaskInstanceId")
        if values.get(name)
    ]
    if task_name != f"\\{TASK_NAME}" or len(instance_values) != 1:
        _reject("TASK_SCHEDULER_EVENT_XML_REJECTED")
    return {
        "event_id": event_id,
        "event_record_id": record_id,
        "time_created": row_time,
        "instance_id": _normalized_instance_id(instance_values[0]),
    }


def _validate_task_scheduler_evidence(
    value: bytes,
    *,
    observed_at: datetime,
    last_run_at: datetime,
    task_state: str,
) -> dict[str, object]:
    evidence = _json_object_unique(value, "TASK_SCHEDULER_EVIDENCE_REJECTED")
    if set(evidence) != {
        "schema_version",
        "captured_at_utc",
        "channel",
        "provider",
        "task_name",
        "query",
        "events",
        "collection",
    }:
        _reject("TASK_SCHEDULER_EVIDENCE_REJECTED")
    query = evidence.get("query")
    collection = evidence.get("collection")
    events = evidence.get("events")
    captured_at = _parse_utc(
        evidence.get("captured_at_utc"),
        "TASK_SCHEDULER_CAPTURE_TIME_REJECTED",
    )
    if (
        evidence.get("schema_version") != TASK_SCHEDULER_EVIDENCE_SCHEMA
        or evidence.get("channel") != TASK_SCHEDULER_EVENT_CHANNEL
        or evidence.get("provider") != TASK_SCHEDULER_EVENT_PROVIDER
        or evidence.get("task_name") != f"\\{TASK_NAME}"
        or not isinstance(query, dict)
        or query
        != {
            "event_ids": list(TASK_SCHEDULER_EVENT_IDS),
            "start_at_utc": _utc_text(TASK_SCHEDULER_QUERY_START_UTC),
            "end_at_utc": evidence.get("captured_at_utc"),
            "operational_log_enabled": True,
        }
        or collection
        != {
            "api": "Get-WinEvent",
            "event_messages_used_for_validation": False,
            "task_scheduler_mutation": "NOT_PERFORMED",
        }
        or captured_at < observed_at
        or captured_at - observed_at > TASK_SCHEDULER_CAPTURE_MAXIMUM_DELAY
        or not isinstance(events, list)
        or len(events) < 2
        or len(events) > MAX_TASK_SCHEDULER_EVENTS
    ):
        _reject("TASK_SCHEDULER_EVIDENCE_REJECTED")
    parsed = [_parse_task_scheduler_event(row) for row in events]
    record_ids = [int(row["event_record_id"]) for row in parsed]
    if record_ids != sorted(record_ids) or len(record_ids) != len(set(record_ids)):
        _reject("TASK_SCHEDULER_EVENT_ORDER_REJECTED")
    for row in parsed:
        event_time = row["time_created"]
        if (
            not isinstance(event_time, datetime)
            or event_time < TASK_SCHEDULER_QUERY_START_UTC
            or event_time > captured_at
        ):
            _reject("TASK_SCHEDULER_EVENT_TIME_REJECTED")
    starts = [
        row
        for row in parsed
        if row["event_id"] == TASK_STARTED_EVENT_ID
        and abs(row["time_created"] - last_run_at)
        <= TASK_SCHEDULER_CORRELATION_TOLERANCE
    ]
    if len(starts) != 1:
        _reject("TASK_SCHEDULER_START_EVENT_REJECTED")
    start = starts[0]
    instance_id = start["instance_id"]
    triggers = [
        row
        for row in parsed
        if row["event_id"] == SCHEDULED_TRIGGER_EVENT_ID
        and row["instance_id"] == instance_id
        and row["time_created"] <= start["time_created"]
        and start["time_created"] - row["time_created"]
        <= TASK_SCHEDULER_CORRELATION_TOLERANCE
    ]
    manual = [
        row
        for row in parsed
        if row["event_id"] == MANUAL_TRIGGER_EVENT_ID
        and (
            row["instance_id"] == instance_id
            or abs(row["time_created"] - last_run_at)
            <= TASK_SCHEDULER_CORRELATION_TOLERANCE
        )
    ]
    completions = [
        row
        for row in parsed
        if row["event_id"] == TASK_COMPLETED_EVENT_ID
        and row["instance_id"] == instance_id
    ]
    instance_events = [
        row for row in parsed if row["instance_id"] == instance_id
    ]
    if (
        len(triggers) != 1
        or manual
        or len(
            [row for row in instance_events if row["event_id"] == TASK_STARTED_EVENT_ID]
        )
        != 1
        or len(
            [
                row
                for row in instance_events
                if row["event_id"] == SCHEDULED_TRIGGER_EVENT_ID
            ]
        )
        != 1
        or len(completions) != 1
    ):
        _reject("TASK_SCHEDULER_TRIGGER_PROVENANCE_REJECTED")
    trigger = triggers[0]
    completion = completions[0]
    if (
        trigger["event_record_id"] >= start["event_record_id"]
        or task_state != "Ready"
        or completion["event_record_id"] <= start["event_record_id"]
        or completion["time_created"] < start["time_created"]
        or completion["time_created"] > observed_at
    ):
        _reject("TASK_SCHEDULER_TRIGGER_PROVENANCE_REJECTED")
    return {
        "source": TASK_SCHEDULER_EVENT_CHANNEL,
        "provider": TASK_SCHEDULER_EVENT_PROVIDER,
        "instance_id": instance_id,
        "scheduled_trigger_event_id": SCHEDULED_TRIGGER_EVENT_ID,
        "scheduled_trigger_record_id": trigger["event_record_id"],
        "scheduled_trigger_at_utc": _utc_text(trigger["time_created"]),
        "task_start_event_id": TASK_STARTED_EVENT_ID,
        "task_start_record_id": start["event_record_id"],
        "task_start_at_utc": _utc_text(start["time_created"]),
        "task_completion_event_id": TASK_COMPLETED_EVENT_ID,
        "task_completion_record_id": completion["event_record_id"],
        "task_completion_at_utc": _utc_text(completion["time_created"]),
        "manual_trigger_event_id": MANUAL_TRIGGER_EVENT_ID,
        "scheduled_trigger_observed": True,
        "manual_trigger_observed": False,
        "raw_event_xml_bound": True,
        "provenance_scope": "LOCAL_HOST_EVENT_LOG",
        "independent_attestation_performed": False,
    }


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, FIXED_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = FIXED_ZIP_MODE << 16
    info.create_system = 3
    return info


def _require_output_absent(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PostRunAcceptanceError("OUTPUT_PATH_REJECTED") from exc
    _reject("OUTPUT_ALREADY_EXISTS")


def _remove_created_output(
    path: Path,
    created_identity: tuple[int, int, int, int, int, int] | None,
) -> None:
    if created_identity is None:
        return
    try:
        observed = path.lstat()
    except OSError:
        return
    if (
        not stat.S_ISREG(observed.st_mode)
        or (
            observed.st_dev,
            observed.st_ino,
            observed.st_mode,
            observed.st_size,
            observed.st_mtime_ns,
            observed.st_ctime_ns,
        )
        != created_identity
    ):
        return
    try:
        path.unlink()
    except OSError:
        pass


def _write_archive(
    path: Path,
    members: dict[str, bytes],
    ordered_paths: tuple[str, ...],
) -> tuple[int, int]:
    if set(members) != set(ordered_paths) or len(ordered_paths) != len(
        set(ordered_paths)
    ):
        _reject("OUTPUT_INVENTORY_REJECTED")
    _require_output_absent(path)
    parent = path.parent
    if parent.exists():
        _directory(parent, "OUTPUT_PARENT_REJECTED")
    else:
        try:
            parent.mkdir(parents=True, exist_ok=False)
        except OSError as exc:
            raise PostRunAcceptanceError("OUTPUT_PARENT_REJECTED") from exc
        _directory(parent, "OUTPUT_PARENT_REJECTED")
    created_identity: tuple[int, int, int, int, int, int] | None = None
    try:
        with path.open("xb") as handle:
            created = os.fstat(handle.fileno())
            created_identity = (
                created.st_dev,
                created.st_ino,
                created.st_mode,
                created.st_size,
                created.st_mtime_ns,
                created.st_ctime_ns,
            )
            with zipfile.ZipFile(
                handle,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            ) as archive:
                for name in ordered_paths:
                    archive.writestr(_zip_info(name), members[name])
            handle.flush()
            os.fsync(handle.fileno())
            completed = os.fstat(handle.fileno())
            created_identity = (
                completed.st_dev,
                completed.st_ino,
                completed.st_mode,
                completed.st_size,
                completed.st_mtime_ns,
                completed.st_ctime_ns,
            )
    except Exception:
        _remove_created_output(path, created_identity)
        raise
    if created_identity is None:
        _reject("OUTPUT_ARCHIVE_UNAVAILABLE")
    return created_identity


def _evidence_set_sha256(rows: list[dict[str, object]]) -> str:
    return _sha256(_canonical_json(rows))


def collect_acceptance(
    *,
    toolkit_manifest: Path,
    installation_receipt: Path,
    checkpoint_root: Path,
    audit_root: Path,
    installed_task_xml: Path,
    receipt_acl_evidence: Path,
    health_transcript: Path,
    task_scheduler_events: Path,
    task_state: str,
    last_run_at_utc: str,
    last_task_result: int,
    next_run_time_local: str,
    v4_task_state: str,
    v5_task_state: str,
    observed_at_utc: str,
    output: Path,
    tool_path: Path | None = None,
) -> dict[str, object]:
    tool = Path(__file__).absolute() if tool_path is None else tool_path.absolute()
    toolkit = validate_extracted_toolkit(toolkit_manifest, tool_path=tool)
    receipt_bytes = _read_regular(
        installation_receipt,
        "INSTALLATION_RECEIPT_UNAVAILABLE",
    )
    receipt = _json_object(receipt_bytes, "INSTALLATION_RECEIPT_REJECTED")
    _validate_installation_receipt(receipt)
    checkpoints = []
    root = _directory(checkpoint_root, "CHECKPOINT_ROOT_REJECTED")
    for path in root.glob("checkpoint-*.json"):
        value = _json_object(
            _read_regular(path, "CHECKPOINT_UNAVAILABLE"),
            "CHECKPOINT_REJECTED",
        )
        _validate_checkpoint(value, receipt)
        if path.name != _checkpoint_file_name(value):
            _reject("CHECKPOINT_FILENAME_REJECTED")
        checkpoints.append((int(value["source_operational_event_count"]), path, value))
    if not checkpoints:
        _reject("CHECKPOINT_UNAVAILABLE")
    checkpoints.sort(key=lambda item: item[0])
    previous_hmac: str | None = None
    previous_count = 0
    initial_hmac = str(receipt["initial_evidence_checkpoint_hmac_sha256"])
    initial_name = PureWindowsPath(
        str(receipt["initial_evidence_checkpoint_path"])
    ).name
    initial_seen = False
    for count, _path, value in checkpoints:
        if count <= previous_count or value["predecessor_checkpoint_hmac_sha256"] != previous_hmac:
            _reject("CHECKPOINT_CHAIN_REJECTED")
        if value["checkpoint_hmac_sha256"] == initial_hmac:
            initial_seen = True
            if (
                _path.name != initial_name
                or _sha256(
                    _read_regular(_path, "INITIAL_CHECKPOINT_UNAVAILABLE")
                )
                != receipt["initial_evidence_checkpoint_file_sha256"]
            ):
                _reject("INITIAL_CHECKPOINT_HASH_REJECTED")
        previous_count = count
        previous_hmac = str(value["checkpoint_hmac_sha256"])
    if not initial_seen:
        _reject("INITIAL_CHECKPOINT_UNAVAILABLE")
    _count, checkpoint_path, checkpoint = checkpoints[-1]
    audit_dir = _directory(audit_root, "AUDIT_ROOT_REJECTED")
    audit_path = audit_dir / str(checkpoint["last_audit_name"])
    audit_manifest_path = audit_dir / str(checkpoint["last_manifest_name"])
    audit_bytes = _read_regular(audit_path, "AUDIT_EXPORT_UNAVAILABLE")
    audit_manifest_bytes = _read_regular(
        audit_manifest_path,
        "AUDIT_MANIFEST_UNAVAILABLE",
    )
    _validate_audit_pair(
        checkpoint=checkpoint,
        audit_bytes=audit_bytes,
        manifest_bytes=audit_manifest_bytes,
    )
    task_xml_bytes = _read_regular(installed_task_xml, "INSTALLED_TASK_XML_UNAVAILABLE")
    if _sha256(task_xml_bytes) != receipt["exported_task_xml_sha256"]:
        _reject("INSTALLED_TASK_XML_HASH_REJECTED")
    transcript_bytes = _read_regular(
        health_transcript,
        "HEALTH_TRANSCRIPT_UNAVAILABLE",
        maximum=2 * 1024 * 1024,
    )
    observed_at = _parse_utc(observed_at_utc, "OBSERVED_TIME_REJECTED")
    last_run_at = _parse_utc(last_run_at_utc, "LAST_RUN_TIME_REJECTED")
    receipt_acl_bytes = _read_regular(
        receipt_acl_evidence,
        "RECEIPT_ACL_EVIDENCE_UNAVAILABLE",
        maximum=MAX_CUSTODY_DOCUMENT_BYTES,
    )
    receipt_acl = _validate_receipt_acl_evidence(
        receipt_acl_bytes,
        receipt_bytes=receipt_bytes,
        receipt=receipt,
        observed_at=observed_at,
        last_run_at=last_run_at,
    )
    _validate_postrun_state(
        receipt=receipt,
        checkpoint=checkpoint,
        observed_at=observed_at,
        task_state=task_state,
        last_run_at=last_run_at,
        last_task_result=last_task_result,
        next_run_local=next_run_time_local,
        v4_state=v4_task_state,
        v5_state=v5_task_state,
        health_transcript=transcript_bytes,
    )
    scheduler_event_bytes = _read_regular(
        task_scheduler_events,
        "TASK_SCHEDULER_EVIDENCE_UNAVAILABLE",
        maximum=MAX_MEMBER_BYTES,
    )
    trigger_provenance = _validate_task_scheduler_evidence(
        scheduler_event_bytes,
        observed_at=observed_at,
        last_run_at=last_run_at,
        task_state=task_state,
    )
    checkpoint_bytes = _read_regular(checkpoint_path, "CHECKPOINT_UNAVAILABLE")
    evidence = {
        "audit-export.json": audit_bytes,
        "audit-manifest.json": audit_manifest_bytes,
        "evidence-checkpoint.json": checkpoint_bytes,
        "health-transcript.txt": transcript_bytes,
        "installation-receipt.json": receipt_bytes,
        "installed-task.xml": task_xml_bytes,
        "receipt-acl-evidence.json": receipt_acl_bytes,
        "task-scheduler-events.json": scheduler_event_bytes,
    }
    rows = [_member_row(path, evidence[path]) for path in sorted(evidence)]
    source_manifest = toolkit["manifest"]
    source = source_manifest["source"]
    if not isinstance(source, dict):
        _reject("TOOLKIT_MANIFEST_INVALID")
    bundle: dict[str, object] = {
        "schema_version": BUNDLE_SCHEMA,
        "status": "PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE_BUNDLED",
        "candidate_id": "phillip-commodity",
        "task_name": TASK_NAME,
        "toolkit": {
            "source_commit": source["commit"],
            "source_tree": source["tree"],
            "manifest_sha256": toolkit["manifest_sha256"],
        },
        "installed_scheduler": {
            "remediation_source_commit": V63_REMEDIATION_COMMIT,
            "remediation_source_tree": V63_REMEDIATION_TREE,
            "health_checker_sha256": V63_HEALTH_CHECKER_SHA256,
            "worker_source_commit": WORKER_COMMIT,
            "worker_source_tree": WORKER_TREE,
            "contract_id": CONTRACT_ID,
        },
        "scheduler_observation": {
            "observed_at_utc": _utc_text(observed_at),
            "task_state": task_state,
            "last_run_at_utc": _utc_text(last_run_at),
            "last_task_result": last_task_result,
            "process_exit_code": last_task_result,
            "process_completed": True,
            "next_run_time_local": next_run_time_local,
            "v4_task_state": v4_task_state,
            "v5_task_state": v5_task_state,
            "automatic_boundary_accepted": True,
            "scheduler_trigger_provenance_accepted": True,
            "manual_start_performed": False,
            "duplicate_run_observed": False,
            "stale_receipt_reuse_observed": False,
            "trigger_provenance": trigger_provenance,
        },
        "authenticated_evidence": {
            "signing_key_id": checkpoint["signing_key_id"],
            "checkpoint_hmac_sha256": checkpoint["checkpoint_hmac_sha256"],
            "checkpoint_predecessor_hmac_sha256": checkpoint[
                "predecessor_checkpoint_hmac_sha256"
            ],
            "source_operational_event_count": checkpoint[
                "source_operational_event_count"
            ],
            "committed_manifest_count": checkpoint["committed_manifest_count"],
            "latest_heartbeat_at_utc": checkpoint["latest_heartbeat_at_utc"],
            "last_invocation_id": checkpoint["last_invocation_id"],
            "last_audit_sha256": checkpoint["last_audit_sha256"],
            "last_manifest_file_sha256": checkpoint[
                "last_manifest_file_sha256"
            ],
            "receipt_acl": receipt_acl,
            "source_chain_from_genesis": True,
            "source_host_health_verifier_passed": True,
            "independent_hmac_reverification_performed": False,
        },
        "members": rows,
        "evidence_set_sha256": _evidence_set_sha256(rows),
        "external_custody": {
            "required": True,
            "performed": False,
            "worm_retention_verified": False,
            "acknowledgement_receipt_present": False,
            "copy_instruction": "COPY_ZIP_TO_INDEPENDENT_OFFHOST_WORM",
        },
        "safety": {
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "promotion_eligible": False,
            "task_scheduler_mutation": "NOT_PERFORMED",
            "broker_mutation": "NOT_PERFORMED",
            "max_lot": 0.01,
            "broker_order_count": 0,
            "broker_order_submission_performed": False,
        },
    }
    bundle["bundle_identity_sha256"] = _sha256(_canonical_json(bundle))
    evidence[BUNDLE_MANIFEST] = _pretty_json(bundle)
    output_path = output.absolute()
    created_identity: tuple[int, int, int, int, int, int] | None = None
    try:
        created_identity = _write_archive(
            output_path,
            evidence,
            (*sorted(EVIDENCE_PATHS), BUNDLE_MANIFEST),
        )
        archive_bytes = _read_regular(
            output_path,
            "OUTPUT_ARCHIVE_UNAVAILABLE",
            maximum=MAX_ARCHIVE_BYTES,
        )
        archive_sha = _sha256(archive_bytes)
        verified = verify_acceptance_archive(
            output_path,
            expected_archive_sha256=archive_sha,
            expected_toolkit_source_commit=str(source["commit"]),
            expected_toolkit_source_tree=str(source["tree"]),
        )
    except Exception:
        _remove_created_output(output_path, created_identity)
        raise
    return {
        "status": verified["status"],
        "archive": str(output_path),
        "archive_sha256": archive_sha,
        "bundle_identity_sha256": bundle["bundle_identity_sha256"],
        "checkpoint_hmac_sha256": checkpoint["checkpoint_hmac_sha256"],
        "latest_heartbeat_at_utc": checkpoint["latest_heartbeat_at_utc"],
        "source_event_count": checkpoint["source_operational_event_count"],
        "task_state": task_state,
        "last_task_result": last_task_result,
        "scheduler_instance_id": trigger_provenance["instance_id"],
        "scheduled_trigger_record_id": trigger_provenance[
            "scheduled_trigger_record_id"
        ],
        "task_start_record_id": trigger_provenance["task_start_record_id"],
        "task_completion_record_id": trigger_provenance[
            "task_completion_record_id"
        ],
        "process_exit_code": 0,
        "receipt_acl_validated": True,
        "broker_order_count": 0,
        "order_capability": "DISABLED",
        "live_allowed": False,
        "offhost_custody_performed": False,
    }


def _validate_eocd(
    handle: BinaryIO,
    expected_members: int,
    maximum_archive_bytes: int = MAX_ARCHIVE_BYTES,
) -> None:
    try:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        if size < 22 or size > maximum_archive_bytes:
            _reject("ARCHIVE_INVALID")
        handle.seek(-22, os.SEEK_END)
        eocd = handle.read(22)
        handle.seek(0)
    except OSError as exc:
        raise PostRunAcceptanceError("ARCHIVE_INVALID") from exc
    if (
        len(eocd) != 22
        or eocd[:4] != b"PK\x05\x06"
        or int.from_bytes(eocd[4:6], "little") != 0
        or int.from_bytes(eocd[6:8], "little") != 0
        or int.from_bytes(eocd[8:10], "little") != expected_members
        or int.from_bytes(eocd[10:12], "little") != expected_members
        or int.from_bytes(eocd[20:22], "little") != 0
    ):
        _reject("ARCHIVE_INVALID")
    central_size = int.from_bytes(eocd[12:16], "little")
    central_offset = int.from_bytes(eocd[16:20], "little")
    if (
        central_size in {0, 0xFFFFFFFF}
        or central_offset == 0xFFFFFFFF
        or central_offset + central_size != size - 22
    ):
        _reject("ARCHIVE_INVALID")


def _archive_members(
    archive: zipfile.ZipFile,
    expected: tuple[str, ...],
    *,
    maximum_member_bytes: int = MAX_MEMBER_BYTES,
    maximum_expanded_bytes: int = MAX_EXPANDED_BYTES,
) -> dict[str, zipfile.ZipInfo]:
    infos = archive.infolist()
    expected_order = tuple((*sorted(expected[:-1]), expected[-1]))
    if (
        tuple(info.filename for info in infos) != expected_order
        or archive.comment != b""
    ):
        _reject("ARCHIVE_INVENTORY_REJECTED")
    observed: dict[str, zipfile.ZipInfo] = {}
    folded: set[str] = set()
    total = 0
    offsets: set[int] = set()
    for info in infos:
        name = info.filename
        mode = (info.external_attr >> 16) & 0xFFFF
        if (
            not _valid_member_path(name)
            or name.casefold() in folded
            or info.is_dir()
            or info.compress_type != zipfile.ZIP_DEFLATED
            or info.flag_bits != 0
            or info.date_time != FIXED_ZIP_TIMESTAMP
            or info.create_system != 3
            or info.create_version != 20
            or info.extract_version != 20
            or mode != FIXED_ZIP_MODE
            or info.external_attr != FIXED_ZIP_MODE << 16
            or info.internal_attr != 0
            or info.volume != 0
            or info.extra != b""
            or info.comment != b""
            or info.file_size <= 0
            or info.file_size > maximum_member_bytes
            or info.compress_size <= 0
            or info.header_offset in offsets
        ):
            _reject("ARCHIVE_METADATA_REJECTED")
        observed[name] = info
        folded.add(name.casefold())
        offsets.add(info.header_offset)
        total += info.file_size
    if set(observed) != set(expected) or total > maximum_expanded_bytes:
        _reject("ARCHIVE_INVENTORY_REJECTED")
    return observed


def _read_archive_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    maximum_member_bytes: int = MAX_MEMBER_BYTES,
) -> bytes:
    try:
        with archive.open(info, "r") as member:
            value = member.read(maximum_member_bytes + 1)
            trailing = member.read(1)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise PostRunAcceptanceError("ARCHIVE_MEMBER_REJECTED") from exc
    if (
        trailing
        or len(value) != info.file_size
        or len(value) > maximum_member_bytes
    ):
        _reject("ARCHIVE_MEMBER_REJECTED")
    return value


def _open_verified_archive_bytes(
    value: bytes,
    *,
    expected_sha256: str,
    expected_paths: tuple[str, ...],
    maximum_archive_bytes: int = MAX_ARCHIVE_BYTES,
    maximum_member_bytes: int = MAX_MEMBER_BYTES,
    maximum_expanded_bytes: int = MAX_EXPANDED_BYTES,
) -> tuple[dict[str, bytes], str]:
    if not _is_sha256(expected_sha256):
        _reject("EXPECTED_ARCHIVE_SHA256_REJECTED")
    if not isinstance(value, bytes) or not value:
        _reject("ARCHIVE_UNAVAILABLE")
    observed_sha = _sha256(value)
    if observed_sha != expected_sha256:
        _reject("ARCHIVE_SHA256_MISMATCH")
    handle = io.BytesIO(value)
    try:
        _validate_eocd(
            handle,
            len(expected_paths),
            maximum_archive_bytes,
        )
        with zipfile.ZipFile(handle, "r") as archive:
            infos = _archive_members(
                archive,
                expected_paths,
                maximum_member_bytes=maximum_member_bytes,
                maximum_expanded_bytes=maximum_expanded_bytes,
            )
            members = {
                name: _read_archive_member(
                    archive,
                    infos[name],
                    maximum_member_bytes=maximum_member_bytes,
                )
                for name in expected_paths
            }
    except PostRunAcceptanceError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise PostRunAcceptanceError("ARCHIVE_INVALID") from exc
    return members, observed_sha


def _open_verified_archive(
    path: Path,
    *,
    expected_sha256: str,
    expected_paths: tuple[str, ...],
    maximum_archive_bytes: int = MAX_ARCHIVE_BYTES,
    maximum_member_bytes: int = MAX_MEMBER_BYTES,
    maximum_expanded_bytes: int = MAX_EXPANDED_BYTES,
) -> tuple[dict[str, bytes], str]:
    value = _read_regular(
        path,
        "ARCHIVE_UNAVAILABLE",
        maximum=maximum_archive_bytes,
    )
    return _open_verified_archive_bytes(
        value,
        expected_sha256=expected_sha256,
        expected_paths=expected_paths,
        maximum_archive_bytes=maximum_archive_bytes,
        maximum_member_bytes=maximum_member_bytes,
        maximum_expanded_bytes=maximum_expanded_bytes,
    )


def verify_toolkit_archive(
    archive: Path,
    *,
    expected_archive_sha256: str,
    expected_source_commit: str,
    expected_source_tree: str,
) -> dict[str, object]:
    if not _is_git_oid(expected_source_commit) or not _is_git_oid(expected_source_tree):
        _reject("EXPECTED_SOURCE_IDENTITY_REJECTED")
    members, archive_sha = _open_verified_archive(
        archive,
        expected_sha256=expected_archive_sha256,
        expected_paths=TOOLKIT_PATHS,
    )
    manifest, rows = _validate_toolkit_manifest(
        members[TOOLKIT_MANIFEST],
        source_commit=expected_source_commit,
        source_tree=expected_source_tree,
    )
    for path, row in rows.items():
        if len(members[path]) != row["size_bytes"] or _sha256(members[path]) != row["sha256"]:
            _reject("TOOLKIT_MEMBER_DRIFT")
    return {
        "schema_version": TOOLKIT_SCHEMA,
        "status": "PHILLIP_COMMODITY_V6_POSTRUN_TOOLKIT_VERIFIED",
        "archive_sha256": archive_sha,
        "source_commit": expected_source_commit,
        "source_tree": expected_source_tree,
        "member_count": len(members),
        "order_capability": "DISABLED",
        "live_allowed": False,
        "task_scheduler_mutation": "NOT_PERFORMED",
        "broker_mutation": "NOT_PERFORMED",
    }


def verify_acceptance_archive(
    archive: Path,
    *,
    expected_archive_sha256: str,
    expected_toolkit_source_commit: str,
    expected_toolkit_source_tree: str,
) -> dict[str, object]:
    if (
        not _is_git_oid(expected_toolkit_source_commit)
        or not _is_git_oid(expected_toolkit_source_tree)
    ):
        _reject("EXPECTED_SOURCE_IDENTITY_REJECTED")
    members, archive_sha = _open_verified_archive(
        archive,
        expected_sha256=expected_archive_sha256,
        expected_paths=BUNDLE_PATHS,
    )
    return _verify_acceptance_members(
        members,
        archive_sha=archive_sha,
        expected_toolkit_source_commit=expected_toolkit_source_commit,
        expected_toolkit_source_tree=expected_toolkit_source_tree,
    )


def _verify_acceptance_members(
    members: dict[str, bytes],
    *,
    archive_sha: str,
    expected_toolkit_source_commit: str,
    expected_toolkit_source_tree: str,
) -> dict[str, object]:
    if (
        set(members) != set(BUNDLE_PATHS)
        or not _is_sha256(archive_sha)
        or not _is_git_oid(expected_toolkit_source_commit)
        or not _is_git_oid(expected_toolkit_source_tree)
    ):
        _reject("BUNDLE_INPUT_REJECTED")
    bundle = _json_object(members[BUNDLE_MANIFEST], "BUNDLE_MANIFEST_REJECTED")
    identity = bundle.get("bundle_identity_sha256")
    unsigned = dict(bundle)
    unsigned.pop("bundle_identity_sha256", None)
    expected_keys = {
        "schema_version",
        "status",
        "candidate_id",
        "task_name",
        "toolkit",
        "installed_scheduler",
        "scheduler_observation",
        "authenticated_evidence",
        "members",
        "evidence_set_sha256",
        "external_custody",
        "safety",
        "bundle_identity_sha256",
    }
    toolkit = bundle.get("toolkit")
    installed = bundle.get("installed_scheduler")
    scheduler = bundle.get("scheduler_observation")
    authenticated = bundle.get("authenticated_evidence")
    custody = bundle.get("external_custody")
    safety = bundle.get("safety")
    if (
        set(bundle) != expected_keys
        or bundle.get("schema_version") != BUNDLE_SCHEMA
        or bundle.get("status")
        != "PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE_BUNDLED"
        or bundle.get("candidate_id") != "phillip-commodity"
        or bundle.get("task_name") != TASK_NAME
        or not _is_sha256(identity)
        or identity != _sha256(_canonical_json(unsigned))
        or not isinstance(toolkit, dict)
        or toolkit.get("source_commit") != expected_toolkit_source_commit
        or toolkit.get("source_tree") != expected_toolkit_source_tree
        or not _is_sha256(toolkit.get("manifest_sha256"))
        or installed
        != {
            "remediation_source_commit": V63_REMEDIATION_COMMIT,
            "remediation_source_tree": V63_REMEDIATION_TREE,
            "health_checker_sha256": V63_HEALTH_CHECKER_SHA256,
            "worker_source_commit": WORKER_COMMIT,
            "worker_source_tree": WORKER_TREE,
            "contract_id": CONTRACT_ID,
        }
        or not isinstance(scheduler, dict)
        or scheduler.get("automatic_boundary_accepted") is not True
        or scheduler.get("scheduler_trigger_provenance_accepted") is not True
        or scheduler.get("manual_start_performed") is not False
        or scheduler.get("duplicate_run_observed") is not False
        or scheduler.get("stale_receipt_reuse_observed") is not False
        or scheduler.get("v4_task_state") != "Disabled"
        or scheduler.get("v5_task_state") != "Disabled"
        or scheduler.get("task_state") != "Ready"
        or scheduler.get("last_task_result") != 0
        or scheduler.get("process_exit_code") != 0
        or scheduler.get("process_completed") is not True
        or not isinstance(authenticated, dict)
        or authenticated.get("source_chain_from_genesis") is not True
        or authenticated.get("source_host_health_verifier_passed") is not True
        or authenticated.get("independent_hmac_reverification_performed") is not False
        or not _is_sha256(authenticated.get("checkpoint_hmac_sha256"))
        or not _is_sha256(authenticated.get("checkpoint_predecessor_hmac_sha256"))
        or custody
        != {
            "required": True,
            "performed": False,
            "worm_retention_verified": False,
            "acknowledgement_receipt_present": False,
            "copy_instruction": "COPY_ZIP_TO_INDEPENDENT_OFFHOST_WORM",
        }
        or safety
        != {
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "promotion_eligible": False,
            "task_scheduler_mutation": "NOT_PERFORMED",
            "broker_mutation": "NOT_PERFORMED",
            "max_lot": 0.01,
            "broker_order_count": 0,
            "broker_order_submission_performed": False,
        }
    ):
        _reject("BUNDLE_MANIFEST_REJECTED")
    rows = _rows_by_path(bundle.get("members"), EVIDENCE_PATHS)
    if bundle.get("evidence_set_sha256") != _evidence_set_sha256(
        [rows[path] for path in sorted(rows)]
    ):
        _reject("EVIDENCE_SET_IDENTITY_REJECTED")
    for path, row in rows.items():
        if len(members[path]) != row["size_bytes"] or _sha256(members[path]) != row["sha256"]:
            _reject("BUNDLE_MEMBER_DRIFT")
    receipt = _json_object(
        members["installation-receipt.json"],
        "INSTALLATION_RECEIPT_REJECTED",
    )
    checkpoint = _json_object(
        members["evidence-checkpoint.json"],
        "CHECKPOINT_REJECTED",
    )
    _validate_installation_receipt(receipt)
    _validate_checkpoint(checkpoint, receipt)
    _validate_audit_pair(
        checkpoint=checkpoint,
        audit_bytes=members["audit-export.json"],
        manifest_bytes=members["audit-manifest.json"],
    )
    if _sha256(members["installed-task.xml"]) != receipt["exported_task_xml_sha256"]:
        _reject("INSTALLED_TASK_XML_HASH_REJECTED")
    observed_at = _parse_utc(scheduler.get("observed_at_utc"), "OBSERVED_TIME_REJECTED")
    last_run = _parse_utc(scheduler.get("last_run_at_utc"), "LAST_RUN_TIME_REJECTED")
    receipt_acl = _validate_receipt_acl_evidence(
        members["receipt-acl-evidence.json"],
        receipt_bytes=members["installation-receipt.json"],
        receipt=receipt,
        observed_at=observed_at,
        last_run_at=last_run,
    )
    _validate_postrun_state(
        receipt=receipt,
        checkpoint=checkpoint,
        observed_at=observed_at,
        task_state=str(scheduler.get("task_state")),
        last_run_at=last_run,
        last_task_result=scheduler.get("last_task_result"),
        next_run_local=str(scheduler.get("next_run_time_local") or ""),
        v4_state=str(scheduler.get("v4_task_state")),
        v5_state=str(scheduler.get("v5_task_state")),
        health_transcript=members["health-transcript.txt"],
    )
    trigger_provenance = _validate_task_scheduler_evidence(
        members["task-scheduler-events.json"],
        observed_at=observed_at,
        last_run_at=last_run,
        task_state=str(scheduler.get("task_state")),
    )
    if (
        scheduler.get("trigger_provenance") != trigger_provenance
        or authenticated.get("checkpoint_hmac_sha256")
        != checkpoint["checkpoint_hmac_sha256"]
        or authenticated.get("checkpoint_predecessor_hmac_sha256")
        != checkpoint["predecessor_checkpoint_hmac_sha256"]
        or authenticated.get("source_operational_event_count")
        != checkpoint["source_operational_event_count"]
        or authenticated.get("committed_manifest_count")
        != checkpoint["committed_manifest_count"]
        or authenticated.get("latest_heartbeat_at_utc")
        != checkpoint["latest_heartbeat_at_utc"]
        or authenticated.get("last_invocation_id") != checkpoint["last_invocation_id"]
        or authenticated.get("last_audit_sha256") != checkpoint["last_audit_sha256"]
        or authenticated.get("last_manifest_file_sha256")
        != checkpoint["last_manifest_file_sha256"]
        or authenticated.get("receipt_acl") != receipt_acl
    ):
        _reject("BUNDLE_EVIDENCE_PROJECTION_REJECTED")
    return {
        "schema_version": BUNDLE_SCHEMA,
        "status": "PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE_VERIFIED",
        "archive_sha256": archive_sha,
        "bundle_identity_sha256": identity,
        "toolkit_source_commit": expected_toolkit_source_commit,
        "toolkit_source_tree": expected_toolkit_source_tree,
        "checkpoint_hmac_sha256": checkpoint["checkpoint_hmac_sha256"],
        "latest_heartbeat_at_utc": checkpoint["latest_heartbeat_at_utc"],
        "source_event_count": checkpoint["source_operational_event_count"],
        "scheduler_instance_id": trigger_provenance["instance_id"],
        "scheduled_trigger_record_id": trigger_provenance[
            "scheduled_trigger_record_id"
        ],
        "task_start_record_id": trigger_provenance["task_start_record_id"],
        "task_completion_record_id": trigger_provenance[
            "task_completion_record_id"
        ],
        "process_exit_code": 0,
        "receipt_acl_validated": True,
        "broker_order_count": 0,
        "offhost_custody_performed": False,
        "order_capability": "DISABLED",
        "live_allowed": False,
        "promotion_eligible": False,
    }


def _custody_safety() -> dict[str, object]:
    return {
        "order_capability": "DISABLED",
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "promotion_eligible": False,
        "execution_authority_granted": False,
        "task_scheduler_mutation": "NOT_PERFORMED",
        "broker_mutation": "NOT_PERFORMED",
    }


def _write_document_exclusive(path: Path, value: bytes) -> None:
    if not value:
        _reject("OUTPUT_DOCUMENT_REJECTED")
    _require_output_absent(path)
    parent = path.parent
    if parent.exists():
        _directory(parent, "OUTPUT_PARENT_REJECTED")
    else:
        try:
            parent.mkdir(parents=True, exist_ok=False)
        except OSError as exc:
            raise PostRunAcceptanceError("OUTPUT_PARENT_REJECTED") from exc
        _directory(parent, "OUTPUT_PARENT_REJECTED")
    created_identity: tuple[int, int, int, int, int, int] | None = None
    try:
        with path.open("xb") as handle:
            created = os.fstat(handle.fileno())
            created_identity = (
                created.st_dev,
                created.st_ino,
                created.st_mode,
                created.st_size,
                created.st_mtime_ns,
                created.st_ctime_ns,
            )
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
            completed = os.fstat(handle.fileno())
            created_identity = (
                completed.st_dev,
                completed.st_ino,
                completed.st_mode,
                completed.st_size,
                completed.st_mtime_ns,
                completed.st_ctime_ns,
            )
    except Exception:
        _remove_created_output(path, created_identity)
        raise


def _validate_custody_request_manifest(
    manifest: dict[str, object],
) -> tuple[datetime, datetime, dict[str, object]]:
    expected_keys = {
        "schema_version",
        "status",
        "candidate_id",
        "requested_at_utc",
        "destination_id",
        "acceptance",
        "retention_requirements",
        "external_custody",
        "safety",
        "request_identity_sha256",
    }
    identity = manifest.get("request_identity_sha256")
    unsigned = dict(manifest)
    unsigned.pop("request_identity_sha256", None)
    acceptance = manifest.get("acceptance")
    retention = manifest.get("retention_requirements")
    if (
        set(manifest) != expected_keys
        or manifest.get("schema_version") != CUSTODY_REQUEST_SCHEMA
        or manifest.get("status")
        != "PHILLIP_COMMODITY_V6_WORM_CUSTODY_REQUESTED"
        or manifest.get("candidate_id") != "phillip-commodity"
        or not _is_sha256(identity)
        or identity != _sha256(_canonical_json(unsigned))
        or manifest.get("external_custody")
        != {
            "performed": False,
            "receipt_present": False,
            "worm_retention_attested": False,
        }
        or manifest.get("safety") != _custody_safety()
        or not isinstance(acceptance, dict)
        or set(acceptance)
        != {
            "archive_member",
            "archive_sha256",
            "archive_size_bytes",
            "bundle_identity_sha256",
            "toolkit_source_commit",
            "toolkit_source_tree",
            "checkpoint_hmac_sha256",
            "latest_heartbeat_at_utc",
            "source_event_count",
        }
        or acceptance.get("archive_member") != CUSTODY_ACCEPTANCE_MEMBER
        or not _is_sha256(acceptance.get("archive_sha256"))
        or not _is_sha256(acceptance.get("bundle_identity_sha256"))
        or not _is_git_oid(acceptance.get("toolkit_source_commit"))
        or not _is_git_oid(acceptance.get("toolkit_source_tree"))
        or not _is_sha256(acceptance.get("checkpoint_hmac_sha256"))
        or isinstance(acceptance.get("archive_size_bytes"), bool)
        or not isinstance(acceptance.get("archive_size_bytes"), int)
        or int(acceptance["archive_size_bytes"]) <= 0
        or int(acceptance["archive_size_bytes"]) > MAX_ARCHIVE_BYTES
        or isinstance(acceptance.get("source_event_count"), bool)
        or not isinstance(acceptance.get("source_event_count"), int)
        or int(acceptance["source_event_count"]) < 1
        or not isinstance(retention, dict)
        or retention
        != {
            "content_hash_verification_required": True,
            "minimum_retain_until_utc": retention.get(
                "minimum_retain_until_utc"
            ),
            "minimum_retention_days": CUSTODY_MINIMUM_RETENTION_DAYS,
            "object_lock_mode": CUSTODY_OBJECT_LOCK_MODE,
            "versioning_required": True,
            "worm_required": True,
        }
    ):
        _reject("CUSTODY_REQUEST_MANIFEST_REJECTED")
    _identifier(manifest.get("destination_id"), "CUSTODY_DESTINATION_REJECTED")
    requested = _parse_canonical_utc(
        manifest.get("requested_at_utc"),
        "CUSTODY_REQUEST_TIME_REJECTED",
    )
    heartbeat = _parse_canonical_utc(
        acceptance.get("latest_heartbeat_at_utc"),
        "CUSTODY_REQUEST_HEARTBEAT_REJECTED",
    )
    retain_until = _parse_canonical_utc(
        retention.get("minimum_retain_until_utc"),
        "CUSTODY_RETENTION_REJECTED",
    )
    if (
        requested < heartbeat
        or requested < FIRST_SCHEDULED_START_UTC
        or retain_until < CUSTODY_RETENTION_FLOOR_UTC
        or retain_until < requested + timedelta(
            days=CUSTODY_MINIMUM_RETENTION_DAYS
        )
    ):
        _reject("CUSTODY_RETENTION_REJECTED")
    return requested, retain_until, acceptance


def _load_verified_custody_request(
    archive: Path,
    *,
    expected_archive_sha256: str,
    expected_toolkit_source_commit: str,
    expected_toolkit_source_tree: str,
) -> tuple[dict[str, object], dict[str, object]]:
    if (
        not _is_git_oid(expected_toolkit_source_commit)
        or not _is_git_oid(expected_toolkit_source_tree)
    ):
        _reject("EXPECTED_SOURCE_IDENTITY_REJECTED")
    members, archive_sha = _open_verified_archive(
        archive,
        expected_sha256=expected_archive_sha256,
        expected_paths=CUSTODY_REQUEST_PATHS,
        maximum_archive_bytes=MAX_CUSTODY_ARCHIVE_BYTES,
        maximum_member_bytes=MAX_CUSTODY_MEMBER_BYTES,
        maximum_expanded_bytes=MAX_CUSTODY_EXPANDED_BYTES,
    )
    manifest = _strict_canonical_json_object(
        members[CUSTODY_REQUEST_MANIFEST],
        "CUSTODY_REQUEST",
    )
    _requested, retain_until, acceptance = _validate_custody_request_manifest(
        manifest
    )
    acceptance_bytes = members[CUSTODY_ACCEPTANCE_MEMBER]
    if (
        len(acceptance_bytes) != acceptance["archive_size_bytes"]
        or _sha256(acceptance_bytes) != acceptance["archive_sha256"]
        or acceptance["toolkit_source_commit"]
        != expected_toolkit_source_commit
        or acceptance["toolkit_source_tree"] != expected_toolkit_source_tree
    ):
        _reject("CUSTODY_REQUEST_ACCEPTANCE_BINDING_REJECTED")
    inner_members, inner_sha = _open_verified_archive_bytes(
        acceptance_bytes,
        expected_sha256=str(acceptance["archive_sha256"]),
        expected_paths=BUNDLE_PATHS,
    )
    inner = _verify_acceptance_members(
        inner_members,
        archive_sha=inner_sha,
        expected_toolkit_source_commit=expected_toolkit_source_commit,
        expected_toolkit_source_tree=expected_toolkit_source_tree,
    )
    if (
        inner["bundle_identity_sha256"]
        != acceptance["bundle_identity_sha256"]
        or inner["checkpoint_hmac_sha256"]
        != acceptance["checkpoint_hmac_sha256"]
        or inner["latest_heartbeat_at_utc"]
        != acceptance["latest_heartbeat_at_utc"]
        or inner["source_event_count"] != acceptance["source_event_count"]
        or inner["offhost_custody_performed"] is not False
    ):
        _reject("CUSTODY_REQUEST_ACCEPTANCE_PROJECTION_REJECTED")
    result = {
        "schema_version": CUSTODY_REQUEST_SCHEMA,
        "status": "PHILLIP_COMMODITY_V6_WORM_CUSTODY_REQUEST_VERIFIED",
        "archive_sha256": archive_sha,
        "request_identity_sha256": manifest["request_identity_sha256"],
        "acceptance_archive_sha256": acceptance["archive_sha256"],
        "acceptance_bundle_identity_sha256": acceptance[
            "bundle_identity_sha256"
        ],
        "destination_id": manifest["destination_id"],
        "minimum_retain_until_utc": _utc_text(retain_until),
        "offhost_custody_performed": False,
        "order_capability": "DISABLED",
        "live_allowed": False,
        "promotion_eligible": False,
    }
    return manifest, result


def verify_custody_request_archive(
    archive: Path,
    *,
    expected_archive_sha256: str,
    expected_toolkit_source_commit: str,
    expected_toolkit_source_tree: str,
) -> dict[str, object]:
    _manifest, result = _load_verified_custody_request(
        archive,
        expected_archive_sha256=expected_archive_sha256,
        expected_toolkit_source_commit=expected_toolkit_source_commit,
        expected_toolkit_source_tree=expected_toolkit_source_tree,
    )
    return result


def prepare_custody_request(
    *,
    acceptance_archive: Path,
    expected_acceptance_archive_sha256: str,
    expected_toolkit_source_commit: str,
    expected_toolkit_source_tree: str,
    destination_id: str,
    requested_at_utc: str,
    minimum_retain_until_utc: str,
    output: Path,
) -> dict[str, object]:
    destination = _identifier(
        destination_id,
        "CUSTODY_DESTINATION_REJECTED",
    )
    requested = _parse_canonical_utc(
        requested_at_utc,
        "CUSTODY_REQUEST_TIME_REJECTED",
    )
    retain_until = _parse_canonical_utc(
        minimum_retain_until_utc,
        "CUSTODY_RETENTION_REJECTED",
    )
    acceptance = verify_acceptance_archive(
        acceptance_archive,
        expected_archive_sha256=expected_acceptance_archive_sha256,
        expected_toolkit_source_commit=expected_toolkit_source_commit,
        expected_toolkit_source_tree=expected_toolkit_source_tree,
    )
    heartbeat = _parse_canonical_utc(
        acceptance["latest_heartbeat_at_utc"],
        "CUSTODY_REQUEST_HEARTBEAT_REJECTED",
    )
    if (
        requested < heartbeat
        or requested < FIRST_SCHEDULED_START_UTC
        or retain_until < CUSTODY_RETENTION_FLOOR_UTC
        or retain_until < requested + timedelta(
            days=CUSTODY_MINIMUM_RETENTION_DAYS
        )
    ):
        _reject("CUSTODY_RETENTION_REJECTED")
    acceptance_bytes = _read_regular(
        acceptance_archive,
        "ACCEPTANCE_ARCHIVE_UNAVAILABLE",
        maximum=MAX_ARCHIVE_BYTES,
    )
    manifest: dict[str, object] = {
        "schema_version": CUSTODY_REQUEST_SCHEMA,
        "status": "PHILLIP_COMMODITY_V6_WORM_CUSTODY_REQUESTED",
        "candidate_id": "phillip-commodity",
        "requested_at_utc": _utc_text(requested),
        "destination_id": destination,
        "acceptance": {
            "archive_member": CUSTODY_ACCEPTANCE_MEMBER,
            "archive_sha256": acceptance["archive_sha256"],
            "archive_size_bytes": len(acceptance_bytes),
            "bundle_identity_sha256": acceptance[
                "bundle_identity_sha256"
            ],
            "toolkit_source_commit": expected_toolkit_source_commit,
            "toolkit_source_tree": expected_toolkit_source_tree,
            "checkpoint_hmac_sha256": acceptance[
                "checkpoint_hmac_sha256"
            ],
            "latest_heartbeat_at_utc": acceptance[
                "latest_heartbeat_at_utc"
            ],
            "source_event_count": acceptance["source_event_count"],
        },
        "retention_requirements": {
            "content_hash_verification_required": True,
            "minimum_retain_until_utc": _utc_text(retain_until),
            "minimum_retention_days": CUSTODY_MINIMUM_RETENTION_DAYS,
            "object_lock_mode": CUSTODY_OBJECT_LOCK_MODE,
            "versioning_required": True,
            "worm_required": True,
        },
        "external_custody": {
            "performed": False,
            "receipt_present": False,
            "worm_retention_attested": False,
        },
        "safety": _custody_safety(),
    }
    manifest["request_identity_sha256"] = _sha256(_canonical_json(manifest))
    output_path = output.absolute()
    created_identity: tuple[int, int, int, int, int, int] | None = None
    try:
        created_identity = _write_archive(
            output_path,
            {
                CUSTODY_ACCEPTANCE_MEMBER: acceptance_bytes,
                CUSTODY_REQUEST_MANIFEST: _canonical_json(manifest),
            },
            CUSTODY_REQUEST_PATHS,
        )
        output_bytes = _read_regular(
            output_path,
            "CUSTODY_REQUEST_ARCHIVE_UNAVAILABLE",
            maximum=MAX_CUSTODY_ARCHIVE_BYTES,
        )
        archive_sha = _sha256(output_bytes)
        verified = verify_custody_request_archive(
            output_path,
            expected_archive_sha256=archive_sha,
            expected_toolkit_source_commit=expected_toolkit_source_commit,
            expected_toolkit_source_tree=expected_toolkit_source_tree,
        )
    except Exception:
        _remove_created_output(output_path, created_identity)
        raise
    return {
        **verified,
        "status": "PHILLIP_COMMODITY_V6_WORM_CUSTODY_REQUEST_READY",
        "archive": str(output_path),
        "archive_size_bytes": len(output_bytes),
    }


def _decode_custody_policy(
    policy_bytes: bytes,
    *,
    expected_policy_sha256: str,
) -> tuple[dict[str, object], str, datetime]:
    expected_sha = _nonzero_sha256(
        expected_policy_sha256,
        "CUSTODY_POLICY_PIN_REJECTED",
    )
    observed_sha = _sha256(policy_bytes)
    if observed_sha != expected_sha:
        _reject("CUSTODY_POLICY_PIN_MISMATCH")
    policy = _strict_canonical_json_object(policy_bytes, "CUSTODY_POLICY")
    if set(policy) != {
        "schema_version",
        "policy_id",
        "custodian_id",
        "custodian_key_id",
        "destination_id",
        "storage_provider_id",
        "minimum_retain_until_utc",
        "rsa_modulus_hex",
        "rsa_exponent",
        "public_key_fingerprint_sha256",
        "signature_algorithm",
        "safety",
    }:
        _reject("CUSTODY_POLICY_SCHEMA_REJECTED")
    for field in (
        "policy_id",
        "custodian_id",
        "custodian_key_id",
        "destination_id",
        "storage_provider_id",
    ):
        _identifier(policy.get(field), "CUSTODY_POLICY_SCHEMA_REJECTED")
    modulus_hex = policy.get("rsa_modulus_hex")
    exponent = policy.get("rsa_exponent")
    if (
        policy.get("schema_version") != CUSTODY_POLICY_SCHEMA
        or policy.get("signature_algorithm") != CUSTODY_SIGNATURE_ALGORITHM
        or policy.get("safety") != _custody_safety()
        or not isinstance(modulus_hex, str)
        or _LOWER_HEX_RE.fullmatch(modulus_hex) is None
        or not (
            MINIMUM_RSA_BITS // 4
            <= len(modulus_hex)
            <= MAXIMUM_RSA_BITS // 4
        )
        or len(modulus_hex) % 2
        or modulus_hex.startswith("00")
        or isinstance(exponent, bool)
        or exponent != RSA_PUBLIC_EXPONENT
    ):
        _reject("CUSTODY_POLICY_SCHEMA_REJECTED")
    modulus = int(modulus_hex, 16)
    if (
        not MINIMUM_RSA_BITS <= modulus.bit_length() <= MAXIMUM_RSA_BITS
        or modulus % 2 == 0
        or policy.get("public_key_fingerprint_sha256")
        != custody_public_key_fingerprint_sha256(modulus_hex, exponent)
    ):
        _reject("CUSTODY_POLICY_KEY_REJECTED")
    minimum_retain = _parse_canonical_utc(
        policy.get("minimum_retain_until_utc"),
        "CUSTODY_POLICY_RETENTION_REJECTED",
    )
    if minimum_retain < CUSTODY_RETENTION_FLOOR_UTC:
        _reject("CUSTODY_POLICY_RETENTION_REJECTED")
    return policy, observed_sha, minimum_retain


def verify_custody_receipt(
    *,
    custody_request_archive: Path,
    expected_custody_request_archive_sha256: str,
    expected_toolkit_source_commit: str,
    expected_toolkit_source_tree: str,
    policy_path: Path,
    expected_policy_sha256: str,
    receipt_path: Path,
    verified_at_utc: str,
    assessment_output: Path,
) -> dict[str, object]:
    request, request_result = _load_verified_custody_request(
        custody_request_archive,
        expected_archive_sha256=expected_custody_request_archive_sha256,
        expected_toolkit_source_commit=expected_toolkit_source_commit,
        expected_toolkit_source_tree=expected_toolkit_source_tree,
    )
    policy_bytes = _read_regular(
        policy_path,
        "CUSTODY_POLICY_UNAVAILABLE",
        maximum=MAX_CUSTODY_DOCUMENT_BYTES,
    )
    policy, policy_sha, policy_minimum_retain = _decode_custody_policy(
        policy_bytes,
        expected_policy_sha256=expected_policy_sha256,
    )
    receipt_bytes = _read_regular(
        receipt_path,
        "CUSTODY_RECEIPT_UNAVAILABLE",
        maximum=MAX_CUSTODY_DOCUMENT_BYTES,
    )
    receipt = _strict_canonical_json_object(receipt_bytes, "CUSTODY_RECEIPT")
    expected_receipt_keys = {
        "schema_version",
        "receipt_id",
        "request_identity_sha256",
        "custody_request_archive_sha256",
        "acceptance_archive_sha256",
        "acceptance_bundle_identity_sha256",
        "destination_id",
        "remote_object",
        "acknowledged_at_utc",
        "custodian_id",
        "custodian_key_id",
        "public_key_fingerprint_sha256",
        "trust_policy_sha256",
        "signature_algorithm",
        "external_custody",
        "safety",
        "signature_rsa_pkcs1v15_sha256_hex",
    }
    remote = receipt.get("remote_object")
    signature = receipt.get("signature_rsa_pkcs1v15_sha256_hex")
    if (
        set(receipt) != expected_receipt_keys
        or receipt.get("schema_version") != CUSTODY_RECEIPT_SCHEMA
        or receipt.get("signature_algorithm") != CUSTODY_SIGNATURE_ALGORITHM
        or receipt.get("safety") != _custody_safety()
        or receipt.get("external_custody")
        != {
            "custodian_attests_custody_performed": True,
            "custodian_attests_exact_bytes_verified": True,
            "custodian_attests_worm_retention_enabled": True,
        }
        or not isinstance(remote, dict)
        or set(remote)
        != {
            "storage_provider_id",
            "bucket_alias_sha256",
            "object_key_sha256",
            "object_version_id_sha256",
            "content_sha256",
            "size_bytes",
            "object_lock_mode",
            "retain_until_utc",
            "versioning_enabled",
            "worm_retention_enabled",
            "content_hash_verified",
        }
        or not isinstance(signature, str)
        or _LOWER_HEX_RE.fullmatch(signature) is None
        or len(signature) % 2
        or receipt.get("request_identity_sha256")
        != request_result["request_identity_sha256"]
        or receipt.get("custody_request_archive_sha256")
        != request_result["archive_sha256"]
        or receipt.get("acceptance_archive_sha256")
        != request_result["acceptance_archive_sha256"]
        or receipt.get("acceptance_bundle_identity_sha256")
        != request_result["acceptance_bundle_identity_sha256"]
        or receipt.get("destination_id") != request_result["destination_id"]
        or receipt.get("destination_id") != policy.get("destination_id")
        or remote.get("storage_provider_id")
        != policy.get("storage_provider_id")
        or receipt.get("custodian_id") != policy.get("custodian_id")
        or receipt.get("custodian_key_id") != policy.get("custodian_key_id")
        or receipt.get("public_key_fingerprint_sha256")
        != policy.get("public_key_fingerprint_sha256")
        or receipt.get("trust_policy_sha256") != policy_sha
        or remote.get("content_sha256")
        != request_result["acceptance_archive_sha256"]
        or remote.get("size_bytes")
        != request["acceptance"]["archive_size_bytes"]
        or remote.get("object_lock_mode") != CUSTODY_OBJECT_LOCK_MODE
        or remote.get("versioning_enabled") is not True
        or remote.get("worm_retention_enabled") is not True
        or remote.get("content_hash_verified") is not True
    ):
        _reject("CUSTODY_RECEIPT_BINDING_REJECTED")
    for field in ("receipt_id", "custodian_id", "custodian_key_id"):
        _identifier(receipt.get(field), "CUSTODY_RECEIPT_SCHEMA_REJECTED")
    _identifier(
        remote.get("storage_provider_id"),
        "CUSTODY_RECEIPT_SCHEMA_REJECTED",
    )
    for field in (
        "bucket_alias_sha256",
        "object_key_sha256",
        "object_version_id_sha256",
    ):
        _nonzero_sha256(
            remote.get(field),
            "CUSTODY_RECEIPT_SCHEMA_REJECTED",
        )
    if (
        isinstance(remote.get("size_bytes"), bool)
        or not isinstance(remote.get("size_bytes"), int)
        or int(remote["size_bytes"]) <= 0
    ):
        _reject("CUSTODY_RECEIPT_SCHEMA_REJECTED")
    requested = _parse_canonical_utc(
        request.get("requested_at_utc"),
        "CUSTODY_REQUEST_TIME_REJECTED",
    )
    request_minimum_retain = _parse_canonical_utc(
        request["retention_requirements"]["minimum_retain_until_utc"],
        "CUSTODY_RETENTION_REJECTED",
    )
    acknowledged = _parse_canonical_utc(
        receipt.get("acknowledged_at_utc"),
        "CUSTODY_RECEIPT_TIME_REJECTED",
    )
    retain_until = _parse_canonical_utc(
        remote.get("retain_until_utc"),
        "CUSTODY_RECEIPT_RETENTION_REJECTED",
    )
    verified_at = _parse_canonical_utc(
        verified_at_utc,
        "CUSTODY_VERIFICATION_TIME_REJECTED",
    )
    if (
        acknowledged < requested
        or acknowledged > verified_at
        or retain_until < request_minimum_retain
        or retain_until < policy_minimum_retain
        or retain_until <= verified_at
    ):
        _reject("CUSTODY_RECEIPT_TIME_REJECTED")
    unsigned_receipt = dict(receipt)
    unsigned_receipt.pop("signature_rsa_pkcs1v15_sha256_hex", None)
    if not _verify_rsa_pkcs1v15_sha256(
        modulus_hex=str(policy["rsa_modulus_hex"]),
        exponent=int(policy["rsa_exponent"]),
        message=CUSTODY_RECEIPT_DOMAIN + _canonical_json(unsigned_receipt),
        signature_hex=signature,
    ):
        _reject("CUSTODY_RECEIPT_SIGNATURE_REJECTED")
    receipt_sha = _sha256(receipt_bytes)
    assessment: dict[str, object] = {
        "schema_version": CUSTODY_ASSESSMENT_SCHEMA,
        "status": "PHILLIP_COMMODITY_V6_WORM_CUSTODY_ATTESTATION_VERIFIED",
        "candidate_id": "phillip-commodity",
        "verified_at_utc": _utc_text(verified_at),
        "toolkit": {
            "source_commit": expected_toolkit_source_commit,
            "source_tree": expected_toolkit_source_tree,
        },
        "custody_request": {
            "archive_sha256": request_result["archive_sha256"],
            "request_identity_sha256": request_result[
                "request_identity_sha256"
            ],
        },
        "acceptance": {
            "archive_sha256": request_result["acceptance_archive_sha256"],
            "bundle_identity_sha256": request_result[
                "acceptance_bundle_identity_sha256"
            ],
        },
        "custodian": {
            "policy_sha256": policy_sha,
            "policy_id": policy["policy_id"],
            "custodian_id": policy["custodian_id"],
            "custodian_key_id": policy["custodian_key_id"],
            "public_key_fingerprint_sha256": policy[
                "public_key_fingerprint_sha256"
            ],
            "receipt_sha256": receipt_sha,
            "receipt_id": receipt["receipt_id"],
        },
        "remote_object": remote,
        "external_custody": {
            "performed": True,
            "signed_custodian_attestation_accepted": True,
            "exact_acceptance_bytes_attested": True,
            "worm_retention_attestation_verified": True,
            "direct_storage_api_inspection_performed": False,
        },
        "safety": _custody_safety(),
    }
    assessment["assessment_identity_sha256"] = _sha256(
        _canonical_json(assessment)
    )
    output_path = assessment_output.absolute()
    assessment_bytes = _canonical_json(assessment)
    _write_document_exclusive(output_path, assessment_bytes)
    return {
        "schema_version": CUSTODY_ASSESSMENT_SCHEMA,
        "status": assessment["status"],
        "assessment": str(output_path),
        "assessment_sha256": _sha256(assessment_bytes),
        "assessment_identity_sha256": assessment[
            "assessment_identity_sha256"
        ],
        "custody_request_archive_sha256": request_result["archive_sha256"],
        "acceptance_archive_sha256": request_result[
            "acceptance_archive_sha256"
        ],
        "receipt_sha256": receipt_sha,
        "policy_sha256": policy_sha,
        "retain_until_utc": _utc_text(retain_until),
        "signed_custodian_attestation_accepted": True,
        "direct_storage_api_inspection_performed": False,
        "order_capability": "DISABLED",
        "live_allowed": False,
        "promotion_eligible": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    toolkit = subparsers.add_parser("verify-toolkit")
    toolkit.add_argument("--archive", type=Path, required=True)
    toolkit.add_argument("--expected-archive-sha256", required=True)
    toolkit.add_argument("--expected-source-commit", required=True)
    toolkit.add_argument("--expected-source-tree", required=True)
    diagnose = subparsers.add_parser("diagnose-readiness")
    diagnose.add_argument("--observed-at-utc", required=True)
    diagnose.add_argument("--last-run-at-utc", required=True)
    diagnose.add_argument("--last-task-result", type=int, required=True)
    diagnose.add_argument("--task-state", choices=("Ready", "Running"), required=True)
    diagnose.add_argument("--next-run-time-local", required=True)
    diagnose.add_argument(
        "--allow-start-on-demand",
        choices=("true", "false"),
        required=True,
    )
    collect = subparsers.add_parser("collect")
    collect.add_argument("--toolkit-manifest", type=Path, required=True)
    collect.add_argument("--installation-receipt", type=Path, required=True)
    collect.add_argument("--checkpoint-root", type=Path, required=True)
    collect.add_argument("--audit-root", type=Path, required=True)
    collect.add_argument("--installed-task-xml", type=Path, required=True)
    collect.add_argument("--receipt-acl-evidence", type=Path, required=True)
    collect.add_argument("--health-transcript", type=Path, required=True)
    collect.add_argument("--task-scheduler-events", type=Path, required=True)
    collect.add_argument("--task-state", required=True)
    collect.add_argument("--last-run-at-utc", required=True)
    collect.add_argument("--last-task-result", type=int, required=True)
    collect.add_argument("--next-run-time-local", required=True)
    collect.add_argument("--v4-task-state", required=True)
    collect.add_argument("--v5-task-state", required=True)
    collect.add_argument("--observed-at-utc", required=True)
    collect.add_argument("--output", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--archive", type=Path, required=True)
    verify.add_argument("--expected-archive-sha256", required=True)
    verify.add_argument("--expected-toolkit-source-commit", required=True)
    verify.add_argument("--expected-toolkit-source-tree", required=True)
    prepare_custody = subparsers.add_parser("prepare-custody")
    prepare_custody.add_argument("--acceptance-archive", type=Path, required=True)
    prepare_custody.add_argument(
        "--expected-acceptance-archive-sha256", required=True
    )
    prepare_custody.add_argument(
        "--expected-toolkit-source-commit", required=True
    )
    prepare_custody.add_argument(
        "--expected-toolkit-source-tree", required=True
    )
    prepare_custody.add_argument("--destination-id", required=True)
    prepare_custody.add_argument("--requested-at-utc", required=True)
    prepare_custody.add_argument("--minimum-retain-until-utc", required=True)
    prepare_custody.add_argument("--output", type=Path, required=True)
    verify_request = subparsers.add_parser("verify-custody-request")
    verify_request.add_argument("--archive", type=Path, required=True)
    verify_request.add_argument("--expected-archive-sha256", required=True)
    verify_request.add_argument(
        "--expected-toolkit-source-commit", required=True
    )
    verify_request.add_argument(
        "--expected-toolkit-source-tree", required=True
    )
    verify_receipt = subparsers.add_parser("verify-custody-receipt")
    verify_receipt.add_argument(
        "--custody-request-archive", type=Path, required=True
    )
    verify_receipt.add_argument(
        "--expected-custody-request-archive-sha256", required=True
    )
    verify_receipt.add_argument(
        "--expected-toolkit-source-commit", required=True
    )
    verify_receipt.add_argument(
        "--expected-toolkit-source-tree", required=True
    )
    verify_receipt.add_argument("--policy", type=Path, required=True)
    verify_receipt.add_argument("--expected-policy-sha256", required=True)
    verify_receipt.add_argument("--receipt", type=Path, required=True)
    verify_receipt.add_argument("--verified-at-utc", required=True)
    verify_receipt.add_argument("--assessment-output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "verify-toolkit":
            result = verify_toolkit_archive(
                args.archive,
                expected_archive_sha256=args.expected_archive_sha256,
                expected_source_commit=args.expected_source_commit,
                expected_source_tree=args.expected_source_tree,
            )
        elif args.command == "diagnose-readiness":
            result = diagnose_trigger_readiness(
                observed_at_utc=args.observed_at_utc,
                last_run_at_utc=args.last_run_at_utc,
                last_task_result=args.last_task_result,
                task_state=args.task_state,
                next_run_time_local=args.next_run_time_local,
                allow_start_on_demand=(
                    args.allow_start_on_demand == "true"
                ),
            )
        elif args.command == "collect":
            result = collect_acceptance(
                toolkit_manifest=args.toolkit_manifest,
                installation_receipt=args.installation_receipt,
                checkpoint_root=args.checkpoint_root,
                audit_root=args.audit_root,
                installed_task_xml=args.installed_task_xml,
                receipt_acl_evidence=args.receipt_acl_evidence,
                health_transcript=args.health_transcript,
                task_scheduler_events=args.task_scheduler_events,
                task_state=args.task_state,
                last_run_at_utc=args.last_run_at_utc,
                last_task_result=args.last_task_result,
                next_run_time_local=args.next_run_time_local,
                v4_task_state=args.v4_task_state,
                v5_task_state=args.v5_task_state,
                observed_at_utc=args.observed_at_utc,
                output=args.output,
            )
        elif args.command == "verify":
            result = verify_acceptance_archive(
                args.archive,
                expected_archive_sha256=args.expected_archive_sha256,
                expected_toolkit_source_commit=args.expected_toolkit_source_commit,
                expected_toolkit_source_tree=args.expected_toolkit_source_tree,
            )
        elif args.command == "prepare-custody":
            result = prepare_custody_request(
                acceptance_archive=args.acceptance_archive,
                expected_acceptance_archive_sha256=(
                    args.expected_acceptance_archive_sha256
                ),
                expected_toolkit_source_commit=(
                    args.expected_toolkit_source_commit
                ),
                expected_toolkit_source_tree=args.expected_toolkit_source_tree,
                destination_id=args.destination_id,
                requested_at_utc=args.requested_at_utc,
                minimum_retain_until_utc=args.minimum_retain_until_utc,
                output=args.output,
            )
        elif args.command == "verify-custody-request":
            result = verify_custody_request_archive(
                args.archive,
                expected_archive_sha256=args.expected_archive_sha256,
                expected_toolkit_source_commit=(
                    args.expected_toolkit_source_commit
                ),
                expected_toolkit_source_tree=args.expected_toolkit_source_tree,
            )
        else:
            result = verify_custody_receipt(
                custody_request_archive=args.custody_request_archive,
                expected_custody_request_archive_sha256=(
                    args.expected_custody_request_archive_sha256
                ),
                expected_toolkit_source_commit=(
                    args.expected_toolkit_source_commit
                ),
                expected_toolkit_source_tree=args.expected_toolkit_source_tree,
                policy_path=args.policy,
                expected_policy_sha256=args.expected_policy_sha256,
                receipt_path=args.receipt,
                verified_at_utc=args.verified_at_utc,
                assessment_output=args.assessment_output,
            )
    except (OSError, ValueError, PostRunAcceptanceError) as exc:
        print(f"PHILLIP_COMMODITY_V6_POSTRUN_REJECTED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
