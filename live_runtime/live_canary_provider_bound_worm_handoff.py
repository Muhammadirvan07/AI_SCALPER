"""Deterministic deny-only WORM handoff for provider-bound LIVE admission.

This module packages and verifies public evidence only. It never recreates a
runtime seal, contacts storage, consumes a CAS nonce, launches a process, or
authorizes broker mutation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
from typing import Mapping
import zipfile

import execution_policy

from .asymmetric_release_trust import (
    MAXIMUM_RSA_BITS,
    MINIMUM_RSA_BITS,
    SIGNATURE_ALGORITHM,
    rsa_public_key_fingerprint_sha256,
    verify_rsa_pkcs1v15_sha256,
)
from .contracts import canonical_json
from .windows_live_provider_conformance_acceptance import (
    WindowsLiveProviderAcceptancePolicy,
    WindowsLiveProviderConformanceAcceptanceError,
    decode_windows_live_provider_acceptance_policy,
)


REQUEST_SCHEMA = "live-canary-provider-bound-worm-request-v1"
ASSESSMENT_SCHEMA = "live-canary-provider-bound-worm-assessment-v1"
ADMISSION_SCHEMA = "live-canary-provider-bound-prebootstrap-admission-v1"
CUSTODY_POLICY_SCHEMA = "live-canary-portable-custody-policy-v1"
RECEIPT_SCHEMA = "live-canary-provider-bound-admission-worm-receipt-v2"
ADMISSION_STATUS = (
    "PROVIDER_BOUND_PREBOOTSTRAP_EVIDENCE_COMPLETE_"
    "CUSTODY_AND_CENTRAL_UNLOCK_REQUIRED"
)
RETENTION_MODE = "COMPLIANCE"
ORDER_CAPABILITY = "DISABLED"

ADMISSION_MEMBER = "provider-bound-admission.json"
CUSTODY_POLICY_MEMBER = "portable-custody-policy.json"
PROVIDER_POLICY_MEMBER = "provider-acceptance-policy.json"
REQUEST_MANIFEST_MEMBER = "LIVE_CANARY_PROVIDER_BOUND_WORM_REQUEST.json"
REQUEST_MEMBER_ORDER = (
    ADMISSION_MEMBER,
    CUSTODY_POLICY_MEMBER,
    PROVIDER_POLICY_MEMBER,
    REQUEST_MANIFEST_MEMBER,
)
SOURCE_MEMBER_ORDER = REQUEST_MEMBER_ORDER[:-1]

MAX_DOCUMENT_BYTES = 1_048_576
MAX_REQUEST_ARCHIVE_BYTES = 4_194_304
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
FIXED_ZIP_MODE = 0o100600
ZERO_SHA256 = "0" * 64
_RECEIPT_DOMAIN = (
    b"AI_SCALPER:LIVE_CANARY:PROVIDER_BOUND_ADMISSION_WORM:v2\x00"
)

_HEX = re.compile(r"^[0-9a-f]+$")
_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_CANONICAL_UTC = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
)
_REQUEST_NAME = re.compile(
    r"^live-canary-provider-bound-worm-request-"
    r"[a-z0-9][a-z0-9._-]{0,95}\.zip$"
)
_ASSESSMENT_NAME = re.compile(
    r"^live-canary-provider-bound-worm-assessment-"
    r"[a-z0-9][a-z0-9._-]{0,95}\.json$"
)

_ADMISSION_FIELDS = frozenset(
    {
        "activation_authorized",
        "activation_binding_sha256",
        "authorization_id",
        "authorization_sha256",
        "bootstrap_authorized",
        "broker_mutation_authorized",
        "candidate_sha256",
        "central_unlock_required",
        "checked_at",
        "credential_reference_count",
        "demo_source_bound_archive_sha256",
        "demo_source_bound_binding_identity_sha256",
        "demo_source_bound_verification_sha256",
        "execution_authorized",
        "installed_environment_sha256",
        "legacy_admission_sha256",
        "live_allowed",
        "live_binding_identity_sha256",
        "live_bound_archive_sha256",
        "live_commit_sha",
        "live_execution_release_identity_sha256",
        "live_execution_task_definition_sha256",
        "live_git_tree",
        "live_source_bound_verification_sha256",
        "max_concurrent_positions",
        "max_lot",
        "order_capability",
        "portable_custody_required",
        "process_launch_authorized",
        "promotion_eligible",
        "provider_acceptance_policy_sha256",
        "provider_acceptance_sha256",
        "provider_acceptance_valid_until_utc",
        "provider_accepted",
        "provider_binding_complete",
        "provider_conformance_review_sha256",
        "provider_count",
        "request_sha256",
        "safe_to_demo_auto_order",
        "schema_version",
        "status",
        "symbol",
        "target_host_identity_sha256",
        "trust_policy_sha256",
        "validation_sha256",
    }
)
_CUSTODY_POLICY_FIELDS = frozenset(
    {
        "bootstrap_authorized",
        "custody_issuer_id",
        "custody_key_id",
        "deployment_host_alias_sha256",
        "execution_authorized",
        "launcher_trust_policy_sha256",
        "live_allowed",
        "maximum_launch_ttl_seconds",
        "maximum_receipt_age_seconds",
        "minimum_retention_seconds",
        "order_capability",
        "policy_id",
        "process_launch_authorized",
        "public_key_fingerprint_sha256",
        "rsa_exponent",
        "rsa_modulus_hex",
        "schema_version",
        "service_account_alias_sha256",
        "signature_algorithm",
        "task_definition_sha256",
        "worm_repository_alias_sha256",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "authorization_sha256",
        "bootstrap_authorized",
        "broker_mutation_authorized",
        "candidate_sha256",
        "custody_issuer_id",
        "custody_key_id",
        "custody_policy_sha256",
        "demo_source_bound_verification_sha256",
        "execution_authorized",
        "installed_environment_sha256",
        "launcher_trust_policy_sha256",
        "legacy_admission_sha256",
        "live_allowed",
        "live_execution_release_identity_sha256",
        "live_execution_task_definition_sha256",
        "live_source_bound_verification_sha256",
        "object_key_sha256",
        "object_version_sha256",
        "order_capability",
        "process_launch_authorized",
        "provider_acceptance_policy_sha256",
        "provider_acceptance_sha256",
        "provider_acceptance_valid_until_utc",
        "provider_bound_admission_sha256",
        "provider_conformance_review_sha256",
        "public_key_fingerprint_sha256",
        "receipt_id",
        "retain_until_utc",
        "retention_mode",
        "schema_version",
        "service_account_alias_sha256",
        "signature_algorithm",
        "signature_rsa_pkcs1v15_sha256_hex",
        "stored_content_sha256",
        "stored_content_size_bytes",
        "target_host_identity_sha256",
        "uploaded_at_utc",
        "validation_sha256",
        "worm_repository_alias_sha256",
    }
)

REQUEST_SAFETY: dict[str, object] = {
    "runtime_admission_seal": False,
    "runtime_custody_seal": False,
    "live_allowed": False,
    "bootstrap_authorized": False,
    "process_launch_authorized": False,
    "execution_authorized": False,
    "activation_authorized": False,
    "broker_mutation_authorized": False,
    "promotion_eligible": False,
    "safe_to_demo_auto_order": False,
    "order_capability": ORDER_CAPABILITY,
}
REQUEST_EFFECTS: dict[str, object] = {
    "network_access": "NOT_PERFORMED",
    "credential_access": "NOT_PERFORMED",
    "private_key_access": "NOT_PERFORMED",
    "storage_api_inspection": "NOT_PERFORMED",
    "cas_reservation": "NOT_PERFORMED",
    "nonce_consumption": "NOT_PERFORMED",
    "central_policy_mutation": "NOT_PERFORMED",
    "process_launch": "NOT_PERFORMED",
    "task_scheduler_mutation": "NOT_PERFORMED",
    "mt5_initialization": "NOT_PERFORMED",
    "broker_mutation": "NOT_PERFORMED",
}


class LiveCanaryProviderBoundWormHandoffError(RuntimeError):
    """One public WORM handoff invariant failed with a stable reason."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: object) -> None:
        normalized = re.sub(
            r"[^A-Z0-9_]+",
            "_",
            str(reason_code or "").strip().upper(),
        ).strip("_")
        self.reason_code = (
            normalized or "LIVE_CANARY_PROVIDER_BOUND_WORM_HANDOFF_INVALID"
        )
        super().__init__(self.reason_code)


def _reject(reason_code: str) -> None:
    raise LiveCanaryProviderBoundWormHandoffError(reason_code)


def _sha256(data: bytes) -> str:
    if type(data) is not bytes:
        raise TypeError("hash input must be exact bytes")
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    try:
        return canonical_json(value).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LiveCanaryProviderBoundWormHandoffError(
            "HANDOFF_JSON_CANONICALIZATION_REJECTED"
        ) from exc


def _require_central_lock() -> None:
    if execution_policy.LIVE_ALLOWED is not False:
        _reject("CENTRAL_LIVE_LOCK_NOT_FALSE")
    allowed, reasons = execution_policy.execution_mode_policy_decision("LIVE")
    if allowed is not False or reasons != ("LIVE_MODE_LOCKED",):
        _reject("CENTRAL_LIVE_POLICY_DECISION_DRIFT")


def _identifier(value: object, reason: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        _reject(reason)
    return value


def _sha_pin(value: object, reason: str, *, allow_zero: bool = False) -> str:
    if type(value) is not str or _HEX_64.fullmatch(value) is None:
        _reject(reason)
    if not allow_zero and value == ZERO_SHA256:
        _reject(reason)
    return value


def _git_pin(value: object, reason: str) -> str:
    if (
        type(value) is not str
        or _HEX_40.fullmatch(value) is None
        or set(value) == {"0"}
    ):
        _reject(reason)
    return value


def _canonical_utc(value: object, reason: str) -> datetime:
    if type(value) is not str or _CANONICAL_UTC.fullmatch(value) is None:
        _reject(reason)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise LiveCanaryProviderBoundWormHandoffError(reason) from exc
    normalized = parsed.astimezone(timezone.utc)
    if (
        normalized.utcoffset() != timedelta(0)
        or normalized.isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        )
        != value
    ):
        _reject(reason)
    return normalized


def _strict_object(data: bytes, *, kind: str) -> dict[str, object]:
    if type(data) is not bytes or not data or len(data) > MAX_DOCUMENT_BYTES:
        _reject(f"{kind}_DOCUMENT_INVALID")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                _reject(f"{kind}_JSON_DUPLICATE_KEY")
            result[key] = value
        return result

    def nonfinite(_: str) -> object:
        _reject(f"{kind}_JSON_NONFINITE_VALUE")

    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=nonfinite,
        )
    except LiveCanaryProviderBoundWormHandoffError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LiveCanaryProviderBoundWormHandoffError(
            f"{kind}_JSON_INVALID"
        ) from exc
    if type(value) is not dict or _canonical_bytes(value) != data:
        _reject(f"{kind}_JSON_NOT_CANONICAL")
    return value


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return tuple(
        int(getattr(metadata, field, 0))
        for field in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    )


def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
    return _file_identity(left) == _file_identity(right)


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        int(getattr(left, field, 0)) == int(getattr(right, field, 0))
        for field in ("st_dev", "st_ino", "st_mode")
    )


def _read_regular(path: str | Path, *, maximum: int, reason: str) -> bytes:
    source = Path(path).expanduser().absolute()
    descriptor: int | None = None
    try:
        before = source.lstat()
        if source.resolve(strict=True) != source:
            _reject(reason)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or _is_reparse(before)
            or before.st_size <= 0
            or before.st_size > maximum
        ):
            _reject(reason)
        flags = (
            os.O_RDONLY
            | int(getattr(os, "O_BINARY", 0))
            | int(getattr(os, "O_CLOEXEC", 0))
            | int(getattr(os, "O_NOFOLLOW", 0))
        )
        descriptor = os.open(source, flags)
        opened_before = os.fstat(descriptor)
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1_048_576))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        opened_after = os.fstat(descriptor)
        os.close(descriptor)
        descriptor = None
        after = source.lstat()
    except LiveCanaryProviderBoundWormHandoffError:
        raise
    except OSError as exc:
        raise LiveCanaryProviderBoundWormHandoffError(reason) from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if (
        not _same_object(before, opened_before)
        or not _same_object(before, opened_after)
        or not _same_object(before, after)
        or len(data) != before.st_size
        or len(data) > maximum
    ):
        _reject(f"{reason}_CHANGED")
    return data


def _remove_owned_output(path: Path, created: os.stat_result | None) -> None:
    if created is None:
        return
    try:
        current = path.lstat()
    except OSError:
        return
    if (
        _same_inode(created, current)
        and stat.S_ISREG(current.st_mode)
        and not stat.S_ISLNK(current.st_mode)
        and not _is_reparse(current)
    ):
        try:
            path.unlink()
        except OSError:
            pass


def _validate_output(
    output: str | Path,
    *,
    pattern: re.Pattern[str],
    reason: str,
) -> tuple[Path, os.stat_result]:
    destination = Path(output).expanduser().absolute()
    if pattern.fullmatch(destination.name) is None:
        _reject(reason)
    parent = destination.parent
    try:
        parent_before = parent.lstat()
        if parent.resolve(strict=True) != parent:
            _reject(reason)
    except OSError as exc:
        raise LiveCanaryProviderBoundWormHandoffError(reason) from exc
    if (
        not stat.S_ISDIR(parent_before.st_mode)
        or stat.S_ISLNK(parent_before.st_mode)
        or _is_reparse(parent_before)
        or os.path.lexists(destination)
    ):
        _reject(reason)
    return destination, parent_before


def _publish_exclusive(
    output: str | Path,
    data: bytes,
    *,
    pattern: re.Pattern[str],
    destination_reason: str,
    publication_reason: str,
) -> Path:
    destination, parent_before = _validate_output(
        output,
        pattern=pattern,
        reason=destination_reason,
    )
    created: os.stat_result | None = None
    try:
        with destination.open("xb") as handle:
            created = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(created.st_mode)
                or stat.S_ISLNK(created.st_mode)
                or _is_reparse(created)
            ):
                _reject(publication_reason)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            written = os.fstat(handle.fileno())
        current = destination.lstat()
        parent_after = destination.parent.lstat()
        if (
            not _same_inode(created, written)
            or not _same_inode(created, current)
            or current.st_size != len(data)
            or _is_reparse(current)
            or not _same_inode(parent_before, parent_after)
            or _is_reparse(parent_after)
            or _read_regular(
                destination,
                maximum=max(len(data), 1),
                reason=publication_reason,
            )
            != data
        ):
            _reject(publication_reason)
        _require_central_lock()
    except LiveCanaryProviderBoundWormHandoffError:
        _remove_owned_output(destination, created)
        raise
    except (OSError, FileExistsError) as exc:
        _remove_owned_output(destination, created)
        raise LiveCanaryProviderBoundWormHandoffError(
            publication_reason
        ) from exc
    return destination


def _decode_admission(data: bytes) -> dict[str, object]:
    admission = _strict_object(data, kind="PROVIDER_BOUND_ADMISSION")
    if set(admission) != _ADMISSION_FIELDS:
        _reject("PROVIDER_BOUND_ADMISSION_SCHEMA_INVALID")
    for name in (
        "activation_binding_sha256",
        "authorization_sha256",
        "candidate_sha256",
        "demo_source_bound_archive_sha256",
        "demo_source_bound_binding_identity_sha256",
        "demo_source_bound_verification_sha256",
        "installed_environment_sha256",
        "legacy_admission_sha256",
        "live_binding_identity_sha256",
        "live_bound_archive_sha256",
        "live_execution_release_identity_sha256",
        "live_execution_task_definition_sha256",
        "live_source_bound_verification_sha256",
        "provider_acceptance_policy_sha256",
        "provider_acceptance_sha256",
        "provider_conformance_review_sha256",
        "request_sha256",
        "target_host_identity_sha256",
        "trust_policy_sha256",
        "validation_sha256",
    ):
        _sha_pin(admission.get(name), "PROVIDER_BOUND_ADMISSION_HASH_INVALID")
    _git_pin(
        admission.get("live_commit_sha"),
        "PROVIDER_BOUND_ADMISSION_GIT_INVALID",
    )
    _git_pin(
        admission.get("live_git_tree"),
        "PROVIDER_BOUND_ADMISSION_GIT_INVALID",
    )
    _identifier(
        admission.get("authorization_id"),
        "PROVIDER_BOUND_ADMISSION_IDENTIFIER_INVALID",
    )
    checked = _canonical_utc(
        admission.get("checked_at"),
        "PROVIDER_BOUND_ADMISSION_TIME_INVALID",
    )
    expires = _canonical_utc(
        admission.get("provider_acceptance_valid_until_utc"),
        "PROVIDER_BOUND_ADMISSION_TIME_INVALID",
    )
    if checked >= expires:
        _reject("PROVIDER_BOUND_ADMISSION_TIME_INVALID")
    expected = {
        "schema_version": ADMISSION_SCHEMA,
        "status": ADMISSION_STATUS,
        "provider_accepted": True,
        "provider_binding_complete": True,
        "portable_custody_required": True,
        "central_unlock_required": True,
        "bootstrap_authorized": False,
        "process_launch_authorized": False,
        "execution_authorized": False,
        "activation_authorized": False,
        "broker_mutation_authorized": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "promotion_eligible": False,
        "order_capability": ORDER_CAPABILITY,
        "symbol": "XAUUSD",
        "max_lot": 0.01,
        "max_concurrent_positions": 1,
        "provider_count": 68,
        "credential_reference_count": 12,
    }
    if any(admission.get(name) != value for name, value in expected.items()):
        _reject("PROVIDER_BOUND_ADMISSION_SAFETY_DRIFT")
    if type(admission.get("max_lot")) is bool:
        _reject("PROVIDER_BOUND_ADMISSION_SAFETY_DRIFT")
    return admission


def _decode_custody_policy(data: bytes) -> dict[str, object]:
    policy = _strict_object(data, kind="CUSTODY_POLICY")
    if set(policy) != _CUSTODY_POLICY_FIELDS:
        _reject("CUSTODY_POLICY_SCHEMA_INVALID")
    for name in (
        "worm_repository_alias_sha256",
        "deployment_host_alias_sha256",
        "service_account_alias_sha256",
        "task_definition_sha256",
        "launcher_trust_policy_sha256",
        "public_key_fingerprint_sha256",
    ):
        _sha_pin(policy.get(name), "CUSTODY_POLICY_HASH_INVALID")
    for name in ("policy_id", "custody_issuer_id", "custody_key_id"):
        _identifier(policy.get(name), "CUSTODY_POLICY_IDENTIFIER_INVALID")
    modulus_hex = policy.get("rsa_modulus_hex")
    exponent = policy.get("rsa_exponent")
    if (
        type(modulus_hex) is not str
        or _HEX.fullmatch(modulus_hex) is None
        or len(modulus_hex) % 2
        or modulus_hex.startswith("00")
        or type(exponent) is not int
        or type(exponent) is bool
        or exponent != 65_537
    ):
        _reject("CUSTODY_POLICY_RSA_INVALID")
    modulus = int(modulus_hex, 16)
    if (
        not MINIMUM_RSA_BITS <= modulus.bit_length() <= MAXIMUM_RSA_BITS
        or modulus % 2 == 0
        or rsa_public_key_fingerprint_sha256(modulus_hex, exponent)
        != policy["public_key_fingerprint_sha256"]
    ):
        _reject("CUSTODY_POLICY_RSA_INVALID")
    for name, minimum, maximum in (
        ("minimum_retention_seconds", 86_400, 315_360_000),
        ("maximum_receipt_age_seconds", 1, 300),
        ("maximum_launch_ttl_seconds", 1, 60),
    ):
        value = policy.get(name)
        if type(value) is not int or not minimum <= value <= maximum:
            _reject("CUSTODY_POLICY_LIMIT_INVALID")
    expected = {
        "schema_version": CUSTODY_POLICY_SCHEMA,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "live_allowed": False,
        "execution_authorized": False,
        "bootstrap_authorized": False,
        "process_launch_authorized": False,
        "order_capability": ORDER_CAPABILITY,
    }
    if any(policy.get(name) != value for name, value in expected.items()):
        _reject("CUSTODY_POLICY_SAFETY_DRIFT")
    deployment = (
        policy["worm_repository_alias_sha256"],
        policy["deployment_host_alias_sha256"],
        policy["service_account_alias_sha256"],
        policy["task_definition_sha256"],
    )
    if len(set(deployment)) != len(deployment):
        _reject("CUSTODY_POLICY_DEPLOYMENT_IDENTITY_REUSE")
    return policy


def _decode_provider_policy(
    data: bytes,
) -> tuple[dict[str, object], WindowsLiveProviderAcceptancePolicy]:
    raw = _strict_object(data, kind="PROVIDER_ACCEPTANCE_POLICY")
    try:
        policy = decode_windows_live_provider_acceptance_policy(data)
    except WindowsLiveProviderConformanceAcceptanceError as exc:
        raise LiveCanaryProviderBoundWormHandoffError(
            "PROVIDER_ACCEPTANCE_POLICY_INVALID"
        ) from exc
    if policy.canonical_json().encode("utf-8") != data:
        _reject("PROVIDER_ACCEPTANCE_POLICY_NOT_CANONICAL")
    return raw, policy


def _validate_source_closure(
    *,
    admission_data: bytes,
    custody_policy_data: bytes,
    provider_policy_data: bytes,
    expected_provider_bound_admission_sha256: str,
    expected_custody_policy_sha256: str,
    expected_provider_policy_sha256: str,
    expected_target_host_identity_sha256: str,
    expected_installed_environment_sha256: str,
    expected_live_execution_release_identity_sha256: str,
    expected_live_execution_task_definition_sha256: str,
    expected_launcher_trust_policy_sha256: str,
) -> tuple[
    dict[str, object],
    dict[str, object],
    WindowsLiveProviderAcceptancePolicy,
]:
    admission = _decode_admission(admission_data)
    custody = _decode_custody_policy(custody_policy_data)
    _, provider = _decode_provider_policy(provider_policy_data)
    pins = {
        "provider_bound_admission_sha256": _sha_pin(
            expected_provider_bound_admission_sha256,
            "ADMISSION_EXTERNAL_PIN_INVALID",
        ),
        "custody_policy_sha256": _sha_pin(
            expected_custody_policy_sha256,
            "CUSTODY_POLICY_EXTERNAL_PIN_INVALID",
        ),
        "provider_acceptance_policy_sha256": _sha_pin(
            expected_provider_policy_sha256,
            "PROVIDER_POLICY_EXTERNAL_PIN_INVALID",
        ),
        "target_host_identity_sha256": _sha_pin(
            expected_target_host_identity_sha256,
            "TARGET_HOST_EXTERNAL_PIN_INVALID",
        ),
        "installed_environment_sha256": _sha_pin(
            expected_installed_environment_sha256,
            "INSTALLED_ENVIRONMENT_EXTERNAL_PIN_INVALID",
        ),
        "live_execution_release_identity_sha256": _sha_pin(
            expected_live_execution_release_identity_sha256,
            "LIVE_RELEASE_EXTERNAL_PIN_INVALID",
        ),
        "live_execution_task_definition_sha256": _sha_pin(
            expected_live_execution_task_definition_sha256,
            "LIVE_TASK_EXTERNAL_PIN_INVALID",
        ),
        "launcher_trust_policy_sha256": _sha_pin(
            expected_launcher_trust_policy_sha256,
            "LAUNCHER_POLICY_EXTERNAL_PIN_INVALID",
        ),
    }
    observed = {
        "provider_bound_admission_sha256": _sha256(admission_data),
        "custody_policy_sha256": _sha256(custody_policy_data),
        "provider_acceptance_policy_sha256": _sha256(provider_policy_data),
        "target_host_identity_sha256": admission[
            "target_host_identity_sha256"
        ],
        "installed_environment_sha256": admission[
            "installed_environment_sha256"
        ],
        "live_execution_release_identity_sha256": admission[
            "live_execution_release_identity_sha256"
        ],
        "live_execution_task_definition_sha256": admission[
            "live_execution_task_definition_sha256"
        ],
        "launcher_trust_policy_sha256": custody[
            "launcher_trust_policy_sha256"
        ],
    }
    if observed != pins:
        _reject("HANDOFF_EXTERNAL_PIN_MISMATCH")
    provider_bindings = (
        (
            provider.content_sha256,
            admission["provider_acceptance_policy_sha256"],
        ),
        (
            provider.provider_conformance_review_sha256,
            admission["provider_conformance_review_sha256"],
        ),
        (
            provider.target_host_identity_sha256,
            admission["target_host_identity_sha256"],
        ),
        (
            provider.execution_release_identity_sha256,
            admission["live_execution_release_identity_sha256"],
        ),
        (
            provider.live_bound_archive_sha256,
            admission["live_bound_archive_sha256"],
        ),
        (
            provider.live_binding_identity_sha256,
            admission["live_binding_identity_sha256"],
        ),
        (
            provider.source_bound_archive_sha256,
            admission["demo_source_bound_archive_sha256"],
        ),
    )
    custody_bindings = (
        (
            custody["deployment_host_alias_sha256"],
            admission["target_host_identity_sha256"],
        ),
        (
            custody["task_definition_sha256"],
            admission["live_execution_task_definition_sha256"],
        ),
    )
    if any(left != right for left, right in provider_bindings):
        _reject("PROVIDER_POLICY_ADMISSION_BINDING_MISMATCH")
    if any(left != right for left, right in custody_bindings):
        _reject("CUSTODY_POLICY_ADMISSION_BINDING_MISMATCH")
    provider_ids = {
        provider.owner_authority_key_id,
        provider.runtime_authority_key_id,
    }
    provider_fingerprints = {
        provider.owner_public_key_fingerprint_sha256,
        provider.runtime_public_key_fingerprint_sha256,
    }
    if (
        custody["custody_key_id"] in provider_ids
        or custody["public_key_fingerprint_sha256"]
        in provider_fingerprints
    ):
        _reject("CUSTODY_PROVIDER_AUTHORITY_REUSE")
    return admission, custody, provider


def _member_records(members: Mapping[str, bytes]) -> list[dict[str, object]]:
    return [
        {
            "path": name,
            "sha256": _sha256(members[name]),
            "size_bytes": len(members[name]),
        }
        for name in SOURCE_MEMBER_ORDER
    ]


def _request_core(
    *,
    request_id: str,
    requested_at_utc: str,
    minimum_retain_until_utc: str,
    members: Mapping[str, bytes],
    admission: Mapping[str, object],
    custody: Mapping[str, object],
    provider: WindowsLiveProviderAcceptancePolicy,
) -> dict[str, object]:
    return {
        "schema_version": REQUEST_SCHEMA,
        "request_id": request_id,
        "requested_at_utc": requested_at_utc,
        "minimum_retain_until_utc": minimum_retain_until_utc,
        "provider_bound_admission_sha256": _sha256(
            members[ADMISSION_MEMBER]
        ),
        "custody_policy_sha256": _sha256(members[CUSTODY_POLICY_MEMBER]),
        "provider_acceptance_policy_sha256": _sha256(
            members[PROVIDER_POLICY_MEMBER]
        ),
        "legacy_admission_sha256": admission["legacy_admission_sha256"],
        "candidate_sha256": admission["candidate_sha256"],
        "demo_source_bound_verification_sha256": admission[
            "demo_source_bound_verification_sha256"
        ],
        "live_source_bound_verification_sha256": admission[
            "live_source_bound_verification_sha256"
        ],
        "provider_acceptance_sha256": admission[
            "provider_acceptance_sha256"
        ],
        "provider_conformance_review_sha256": admission[
            "provider_conformance_review_sha256"
        ],
        "target_host_identity_sha256": admission[
            "target_host_identity_sha256"
        ],
        "installed_environment_sha256": admission[
            "installed_environment_sha256"
        ],
        "live_execution_release_identity_sha256": admission[
            "live_execution_release_identity_sha256"
        ],
        "live_execution_task_definition_sha256": admission[
            "live_execution_task_definition_sha256"
        ],
        "authorization_sha256": admission["authorization_sha256"],
        "validation_sha256": admission["validation_sha256"],
        "provider_acceptance_valid_until_utc": admission[
            "provider_acceptance_valid_until_utc"
        ],
        "launcher_trust_policy_sha256": custody[
            "launcher_trust_policy_sha256"
        ],
        "service_account_alias_sha256": custody[
            "service_account_alias_sha256"
        ],
        "worm_repository_alias_sha256": custody[
            "worm_repository_alias_sha256"
        ],
        "custody_issuer_id": custody["custody_issuer_id"],
        "custody_key_id": custody["custody_key_id"],
        "custody_public_key_fingerprint_sha256": custody[
            "public_key_fingerprint_sha256"
        ],
        "provider_owner_authority_key_id": (
            provider.owner_authority_key_id
        ),
        "provider_owner_public_key_fingerprint_sha256": (
            provider.owner_public_key_fingerprint_sha256
        ),
        "provider_runtime_authority_key_id": (
            provider.runtime_authority_key_id
        ),
        "provider_runtime_public_key_fingerprint_sha256": (
            provider.runtime_public_key_fingerprint_sha256
        ),
        "members": _member_records(members),
        "retention_requirements": {
            "minimum_retention_seconds": custody[
                "minimum_retention_seconds"
            ],
            "minimum_retain_until_utc": minimum_retain_until_utc,
            "retention_mode": RETENTION_MODE,
            "versioned_object_required": True,
            "byte_identical_readback_required": True,
        },
        "safety": dict(REQUEST_SAFETY),
        "effects": dict(REQUEST_EFFECTS),
    }


def _validate_request_times(
    *,
    admission: Mapping[str, object],
    custody: Mapping[str, object],
    requested_at_utc: object,
    minimum_retain_until_utc: object,
) -> tuple[datetime, datetime]:
    checked = _canonical_utc(
        admission.get("checked_at"),
        "PROVIDER_BOUND_ADMISSION_TIME_INVALID",
    )
    provider_expiry = _canonical_utc(
        admission.get("provider_acceptance_valid_until_utc"),
        "PROVIDER_BOUND_ADMISSION_TIME_INVALID",
    )
    requested = _canonical_utc(requested_at_utc, "REQUEST_TIME_INVALID")
    retained = _canonical_utc(
        minimum_retain_until_utc,
        "REQUEST_RETENTION_INVALID",
    )
    if requested < checked or requested >= provider_expiry:
        _reject("REQUEST_TIME_INVALID")
    minimum_seconds = custody.get("minimum_retention_seconds")
    if type(minimum_seconds) is not int:
        _reject("REQUEST_RETENTION_INVALID")
    if retained < requested + timedelta(seconds=minimum_seconds):
        _reject("REQUEST_RETENTION_INVALID")
    return requested, retained


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, FIXED_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.create_version = 20
    info.extract_version = 20
    info.external_attr = FIXED_ZIP_MODE << 16
    return info


def _build_request_archive(members: Mapping[str, bytes]) -> bytes:
    destination = io.BytesIO()
    with zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_STORED,
    ) as archive:
        for name in REQUEST_MEMBER_ORDER:
            archive.writestr(_zip_info(name), members[name])
    data = destination.getvalue()
    if not data or len(data) > MAX_REQUEST_ARCHIVE_BYTES:
        _reject("REQUEST_ARCHIVE_SIZE_INVALID")
    return data


def _eocd_offset(data: bytes) -> int:
    if len(data) < 22:
        _reject("REQUEST_ARCHIVE_INVALID")
    offset = len(data) - 22
    eocd = data[offset:]
    expected_count = len(REQUEST_MEMBER_ORDER)
    if (
        eocd[:4] != b"PK\x05\x06"
        or int.from_bytes(eocd[4:6], "little") != 0
        or int.from_bytes(eocd[6:8], "little") != 0
        or int.from_bytes(eocd[8:10], "little") != expected_count
        or int.from_bytes(eocd[10:12], "little") != expected_count
        or int.from_bytes(eocd[20:22], "little") != 0
        or b"PK\x06\x06" in data
        or b"PK\x06\x07" in data
    ):
        _reject("REQUEST_ARCHIVE_INVALID")
    central_size = int.from_bytes(eocd[12:16], "little")
    central_offset = int.from_bytes(eocd[16:20], "little")
    if central_offset + central_size != offset:
        _reject("REQUEST_ARCHIVE_INVALID")
    return central_offset


def _strict_request_members(data: bytes) -> dict[str, bytes]:
    if type(data) is not bytes or not data or len(data) > MAX_REQUEST_ARCHIVE_BYTES:
        _reject("REQUEST_ARCHIVE_SIZE_INVALID")
    central_offset = _eocd_offset(data)
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            infos = archive.infolist()
            if (
                tuple(info.filename for info in infos)
                != REQUEST_MEMBER_ORDER
                or archive.comment != b""
                or archive.start_dir != central_offset
            ):
                _reject("REQUEST_ARCHIVE_INVALID")
            members: dict[str, bytes] = {}
            cursor = 0
            for info in infos:
                if (
                    info.header_offset != cursor
                    or info.date_time != FIXED_ZIP_TIMESTAMP
                    or info.create_system != 3
                    or info.create_version != 20
                    or info.extract_version != 20
                    or info.external_attr != FIXED_ZIP_MODE << 16
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.flag_bits != 0
                    or info.extra != b""
                    or info.comment != b""
                    or info.internal_attr != 0
                    or info.volume != 0
                    or info.is_dir()
                    or info.file_size <= 0
                    or info.file_size > MAX_DOCUMENT_BYTES
                    or cursor + 30 > central_offset
                ):
                    _reject("REQUEST_ARCHIVE_INVALID")
                local = data[cursor : cursor + 30]
                if local[:4] != b"PK\x03\x04":
                    _reject("REQUEST_ARCHIVE_INVALID")
                (
                    version,
                    flags,
                    method,
                    modified_time,
                    modified_date,
                    crc,
                    compressed_size,
                    file_size,
                    name_length,
                    extra_length,
                ) = struct.unpack("<HHHHHIIIHH", local[4:30])
                name_start = cursor + 30
                name_end = name_start + name_length
                data_start = name_end + extra_length
                data_end = data_start + compressed_size
                if (
                    version != 20
                    or flags != 0
                    or method != zipfile.ZIP_STORED
                    or modified_time != 0
                    or modified_date != 33
                    or crc != info.CRC
                    or compressed_size != info.compress_size
                    or file_size != info.file_size
                    or extra_length != 0
                    or data_end > central_offset
                    or data[name_start:name_end]
                    != info.filename.encode("ascii")
                ):
                    _reject("REQUEST_ARCHIVE_INVALID")
                member = archive.read(info)
                if (
                    len(member) != info.file_size
                    or data[data_start:data_end] != member
                ):
                    _reject("REQUEST_ARCHIVE_INVALID")
                members[info.filename] = member
                cursor = data_end
            if cursor != central_offset or archive.testzip() is not None:
                _reject("REQUEST_ARCHIVE_INVALID")
    except LiveCanaryProviderBoundWormHandoffError:
        raise
    except (OSError, UnicodeError, ValueError, zipfile.BadZipFile) as exc:
        raise LiveCanaryProviderBoundWormHandoffError(
            "REQUEST_ARCHIVE_INVALID"
        ) from exc
    return members


def _pin_arguments(
    *,
    expected_provider_bound_admission_sha256: str,
    expected_custody_policy_sha256: str,
    expected_provider_policy_sha256: str,
    expected_target_host_identity_sha256: str,
    expected_installed_environment_sha256: str,
    expected_live_execution_release_identity_sha256: str,
    expected_live_execution_task_definition_sha256: str,
    expected_launcher_trust_policy_sha256: str,
) -> dict[str, str]:
    return {
        "expected_provider_bound_admission_sha256": (
            expected_provider_bound_admission_sha256
        ),
        "expected_custody_policy_sha256": expected_custody_policy_sha256,
        "expected_provider_policy_sha256": expected_provider_policy_sha256,
        "expected_target_host_identity_sha256": (
            expected_target_host_identity_sha256
        ),
        "expected_installed_environment_sha256": (
            expected_installed_environment_sha256
        ),
        "expected_live_execution_release_identity_sha256": (
            expected_live_execution_release_identity_sha256
        ),
        "expected_live_execution_task_definition_sha256": (
            expected_live_execution_task_definition_sha256
        ),
        "expected_launcher_trust_policy_sha256": (
            expected_launcher_trust_policy_sha256
        ),
    }


def _verified_request(
    data: bytes,
    *,
    expected_request_archive_sha256: str,
    expected_provider_bound_admission_sha256: str,
    expected_custody_policy_sha256: str,
    expected_provider_policy_sha256: str,
    expected_target_host_identity_sha256: str,
    expected_installed_environment_sha256: str,
    expected_live_execution_release_identity_sha256: str,
    expected_live_execution_task_definition_sha256: str,
    expected_launcher_trust_policy_sha256: str,
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
    WindowsLiveProviderAcceptancePolicy,
    dict[str, bytes],
]:
    _require_central_lock()
    expected_archive = _sha_pin(
        expected_request_archive_sha256,
        "REQUEST_ARCHIVE_EXTERNAL_PIN_INVALID",
    )
    if _sha256(data) != expected_archive:
        _reject("REQUEST_ARCHIVE_EXTERNAL_PIN_MISMATCH")
    members = _strict_request_members(data)
    admission, custody, provider = _validate_source_closure(
        admission_data=members[ADMISSION_MEMBER],
        custody_policy_data=members[CUSTODY_POLICY_MEMBER],
        provider_policy_data=members[PROVIDER_POLICY_MEMBER],
        **_pin_arguments(
            expected_provider_bound_admission_sha256=(
                expected_provider_bound_admission_sha256
            ),
            expected_custody_policy_sha256=expected_custody_policy_sha256,
            expected_provider_policy_sha256=expected_provider_policy_sha256,
            expected_target_host_identity_sha256=(
                expected_target_host_identity_sha256
            ),
            expected_installed_environment_sha256=(
                expected_installed_environment_sha256
            ),
            expected_live_execution_release_identity_sha256=(
                expected_live_execution_release_identity_sha256
            ),
            expected_live_execution_task_definition_sha256=(
                expected_live_execution_task_definition_sha256
            ),
            expected_launcher_trust_policy_sha256=(
                expected_launcher_trust_policy_sha256
            ),
        ),
    )
    manifest = _strict_object(
        members[REQUEST_MANIFEST_MEMBER],
        kind="WORM_REQUEST_MANIFEST",
    )
    if "request_identity_sha256" not in manifest:
        _reject("WORM_REQUEST_MANIFEST_SCHEMA_INVALID")
    identity = _sha_pin(
        manifest.get("request_identity_sha256"),
        "WORM_REQUEST_IDENTITY_INVALID",
    )
    unsigned = dict(manifest)
    del unsigned["request_identity_sha256"]
    if _sha256(_canonical_bytes(unsigned)) != identity:
        _reject("WORM_REQUEST_IDENTITY_INVALID")
    request_id = _identifier(
        manifest.get("request_id"),
        "WORM_REQUEST_IDENTIFIER_INVALID",
    )
    _validate_request_times(
        admission=admission,
        custody=custody,
        requested_at_utc=manifest.get("requested_at_utc"),
        minimum_retain_until_utc=manifest.get(
            "minimum_retain_until_utc"
        ),
    )
    expected_core = _request_core(
        request_id=request_id,
        requested_at_utc=str(manifest["requested_at_utc"]),
        minimum_retain_until_utc=str(
            manifest["minimum_retain_until_utc"]
        ),
        members=members,
        admission=admission,
        custody=custody,
        provider=provider,
    )
    if unsigned != expected_core:
        _reject("WORM_REQUEST_MANIFEST_BINDING_MISMATCH")
    result = {
        "schema_version": REQUEST_SCHEMA,
        "status": "LIVE_CANARY_PROVIDER_BOUND_WORM_REQUEST_VERIFIED",
        "archive_sha256": expected_archive,
        "archive_size_bytes": len(data),
        "request_identity_sha256": identity,
        "request_id": request_id,
        "requested_at_utc": manifest["requested_at_utc"],
        "minimum_retain_until_utc": manifest[
            "minimum_retain_until_utc"
        ],
        "provider_bound_admission_sha256": _sha256(
            members[ADMISSION_MEMBER]
        ),
        "custody_policy_sha256": _sha256(
            members[CUSTODY_POLICY_MEMBER]
        ),
        "provider_acceptance_policy_sha256": _sha256(
            members[PROVIDER_POLICY_MEMBER]
        ),
        "target_host_identity_sha256": admission[
            "target_host_identity_sha256"
        ],
        "installed_environment_sha256": admission[
            "installed_environment_sha256"
        ],
        "live_execution_release_identity_sha256": admission[
            "live_execution_release_identity_sha256"
        ],
        "live_execution_task_definition_sha256": admission[
            "live_execution_task_definition_sha256"
        ],
        "launcher_trust_policy_sha256": custody[
            "launcher_trust_policy_sha256"
        ],
        "member_count": len(REQUEST_MEMBER_ORDER),
        "signed_receipt_accepted": False,
        "byte_identical_exported_readback_accepted": False,
        "direct_storage_api_inspection_performed": False,
        **REQUEST_SAFETY,
        "broker_mutation": "NOT_PERFORMED",
    }
    _require_central_lock()
    return result, manifest, admission, custody, provider, members


def verify_live_canary_provider_bound_worm_request_bytes(
    data: bytes,
    **pins: str,
) -> dict[str, object]:
    """Independently reconstruct one deterministic public request."""

    result, *_ = _verified_request(data, **pins)
    return result


def verify_live_canary_provider_bound_worm_request_path(
    request_archive: str | Path,
    **pins: str,
) -> dict[str, object]:
    data = _read_regular(
        request_archive,
        maximum=MAX_REQUEST_ARCHIVE_BYTES,
        reason="REQUEST_ARCHIVE_FILE_INVALID",
    )
    return verify_live_canary_provider_bound_worm_request_bytes(data, **pins)


def prepare_live_canary_provider_bound_worm_request(
    *,
    admission_path: str | Path,
    custody_policy_path: str | Path,
    provider_policy_path: str | Path,
    expected_provider_bound_admission_sha256: str,
    expected_custody_policy_sha256: str,
    expected_provider_policy_sha256: str,
    expected_target_host_identity_sha256: str,
    expected_installed_environment_sha256: str,
    expected_live_execution_release_identity_sha256: str,
    expected_live_execution_task_definition_sha256: str,
    expected_launcher_trust_policy_sha256: str,
    request_id: str,
    requested_at_utc: str,
    minimum_retain_until_utc: str,
    output: str | Path,
) -> dict[str, object]:
    """Create one exact four-member request without external effects."""

    _require_central_lock()
    source_members = {
        ADMISSION_MEMBER: _read_regular(
            admission_path,
            maximum=MAX_DOCUMENT_BYTES,
            reason="PROVIDER_BOUND_ADMISSION_FILE_INVALID",
        ),
        CUSTODY_POLICY_MEMBER: _read_regular(
            custody_policy_path,
            maximum=MAX_DOCUMENT_BYTES,
            reason="CUSTODY_POLICY_FILE_INVALID",
        ),
        PROVIDER_POLICY_MEMBER: _read_regular(
            provider_policy_path,
            maximum=MAX_DOCUMENT_BYTES,
            reason="PROVIDER_ACCEPTANCE_POLICY_FILE_INVALID",
        ),
    }
    pins = _pin_arguments(
        expected_provider_bound_admission_sha256=(
            expected_provider_bound_admission_sha256
        ),
        expected_custody_policy_sha256=expected_custody_policy_sha256,
        expected_provider_policy_sha256=expected_provider_policy_sha256,
        expected_target_host_identity_sha256=(
            expected_target_host_identity_sha256
        ),
        expected_installed_environment_sha256=(
            expected_installed_environment_sha256
        ),
        expected_live_execution_release_identity_sha256=(
            expected_live_execution_release_identity_sha256
        ),
        expected_live_execution_task_definition_sha256=(
            expected_live_execution_task_definition_sha256
        ),
        expected_launcher_trust_policy_sha256=(
            expected_launcher_trust_policy_sha256
        ),
    )
    admission, custody, provider = _validate_source_closure(
        admission_data=source_members[ADMISSION_MEMBER],
        custody_policy_data=source_members[CUSTODY_POLICY_MEMBER],
        provider_policy_data=source_members[PROVIDER_POLICY_MEMBER],
        **pins,
    )
    request = _identifier(request_id, "WORM_REQUEST_IDENTIFIER_INVALID")
    _validate_request_times(
        admission=admission,
        custody=custody,
        requested_at_utc=requested_at_utc,
        minimum_retain_until_utc=minimum_retain_until_utc,
    )
    core = _request_core(
        request_id=request,
        requested_at_utc=requested_at_utc,
        minimum_retain_until_utc=minimum_retain_until_utc,
        members=source_members,
        admission=admission,
        custody=custody,
        provider=provider,
    )
    manifest = {
        **core,
        "request_identity_sha256": _sha256(_canonical_bytes(core)),
    }
    all_members = {
        **source_members,
        REQUEST_MANIFEST_MEMBER: _canonical_bytes(manifest),
    }
    archive_data = _build_request_archive(all_members)
    archive_sha256 = _sha256(archive_data)
    verified = verify_live_canary_provider_bound_worm_request_bytes(
        archive_data,
        expected_request_archive_sha256=archive_sha256,
        **pins,
    )
    destination = _publish_exclusive(
        output,
        archive_data,
        pattern=_REQUEST_NAME,
        destination_reason="REQUEST_DESTINATION_INVALID",
        publication_reason="REQUEST_PUBLICATION_FAILED",
    )
    return {
        **verified,
        "status": "LIVE_CANARY_PROVIDER_BOUND_WORM_REQUEST_READY",
        "archive": str(destination),
    }


def _decode_receipt(data: bytes) -> dict[str, object]:
    receipt = _strict_object(data, kind="PROVIDER_BOUND_CUSTODY_RECEIPT")
    if set(receipt) != _RECEIPT_FIELDS:
        _reject("PROVIDER_BOUND_CUSTODY_RECEIPT_SCHEMA_INVALID")
    for name in (
        "custody_policy_sha256",
        "provider_bound_admission_sha256",
        "legacy_admission_sha256",
        "candidate_sha256",
        "demo_source_bound_verification_sha256",
        "live_source_bound_verification_sha256",
        "provider_acceptance_sha256",
        "provider_acceptance_policy_sha256",
        "provider_conformance_review_sha256",
        "target_host_identity_sha256",
        "launcher_trust_policy_sha256",
        "service_account_alias_sha256",
        "installed_environment_sha256",
        "live_execution_release_identity_sha256",
        "live_execution_task_definition_sha256",
        "authorization_sha256",
        "validation_sha256",
        "worm_repository_alias_sha256",
        "object_key_sha256",
        "object_version_sha256",
        "stored_content_sha256",
        "public_key_fingerprint_sha256",
    ):
        _sha_pin(receipt.get(name), "CUSTODY_RECEIPT_HASH_INVALID")
    for name in ("receipt_id", "custody_issuer_id", "custody_key_id"):
        _identifier(receipt.get(name), "CUSTODY_RECEIPT_IDENTIFIER_INVALID")
    size = receipt.get("stored_content_size_bytes")
    if type(size) is not int or not 1 <= size <= MAX_DOCUMENT_BYTES:
        _reject("CUSTODY_RECEIPT_CONTENT_SIZE_INVALID")
    _canonical_utc(
        receipt.get("provider_acceptance_valid_until_utc"),
        "CUSTODY_RECEIPT_TIME_INVALID",
    )
    uploaded = _canonical_utc(
        receipt.get("uploaded_at_utc"),
        "CUSTODY_RECEIPT_TIME_INVALID",
    )
    retained = _canonical_utc(
        receipt.get("retain_until_utc"),
        "CUSTODY_RECEIPT_TIME_INVALID",
    )
    signature = receipt.get("signature_rsa_pkcs1v15_sha256_hex")
    expected = {
        "schema_version": RECEIPT_SCHEMA,
        "retention_mode": RETENTION_MODE,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "live_allowed": False,
        "execution_authorized": False,
        "bootstrap_authorized": False,
        "process_launch_authorized": False,
        "broker_mutation_authorized": False,
        "order_capability": ORDER_CAPABILITY,
    }
    if (
        uploaded >= retained
        or type(signature) is not str
        or not signature
        or _HEX.fullmatch(signature) is None
        or len(signature) % 2
        or any(receipt.get(name) != value for name, value in expected.items())
    ):
        _reject("CUSTODY_RECEIPT_SCHEMA_INVALID")
    return receipt


def _receipt_signing_message(receipt: Mapping[str, object]) -> bytes:
    signing = dict(receipt)
    signature = signing.pop("signature_rsa_pkcs1v15_sha256_hex", None)
    if type(signature) is not str or not signature:
        _reject("CUSTODY_RECEIPT_SIGNATURE_INVALID")
    return _RECEIPT_DOMAIN + _canonical_bytes(signing)


def verify_live_canary_provider_bound_worm_receipt(
    *,
    request_archive: str | Path,
    expected_request_archive_sha256: str,
    receipt_path: str | Path,
    readback_path: str | Path,
    expected_readback_sha256: str,
    verified_at_utc: str,
    assessment_output: str | Path,
    expected_provider_bound_admission_sha256: str,
    expected_custody_policy_sha256: str,
    expected_provider_policy_sha256: str,
    expected_target_host_identity_sha256: str,
    expected_installed_environment_sha256: str,
    expected_live_execution_release_identity_sha256: str,
    expected_live_execution_task_definition_sha256: str,
    expected_launcher_trust_policy_sha256: str,
) -> dict[str, object]:
    """Verify one signed receipt plus exported readback, still deny-only."""

    _require_central_lock()
    request_data = _read_regular(
        request_archive,
        maximum=MAX_REQUEST_ARCHIVE_BYTES,
        reason="REQUEST_ARCHIVE_FILE_INVALID",
    )
    pins = _pin_arguments(
        expected_provider_bound_admission_sha256=(
            expected_provider_bound_admission_sha256
        ),
        expected_custody_policy_sha256=expected_custody_policy_sha256,
        expected_provider_policy_sha256=expected_provider_policy_sha256,
        expected_target_host_identity_sha256=(
            expected_target_host_identity_sha256
        ),
        expected_installed_environment_sha256=(
            expected_installed_environment_sha256
        ),
        expected_live_execution_release_identity_sha256=(
            expected_live_execution_release_identity_sha256
        ),
        expected_live_execution_task_definition_sha256=(
            expected_live_execution_task_definition_sha256
        ),
        expected_launcher_trust_policy_sha256=(
            expected_launcher_trust_policy_sha256
        ),
    )
    request, manifest, admission, custody, _provider, members = (
        _verified_request(
            request_data,
            expected_request_archive_sha256=(
                expected_request_archive_sha256
            ),
            **pins,
        )
    )
    receipt_data = _read_regular(
        receipt_path,
        maximum=MAX_DOCUMENT_BYTES,
        reason="CUSTODY_RECEIPT_FILE_INVALID",
    )
    receipt = _decode_receipt(receipt_data)
    readback = _read_regular(
        readback_path,
        maximum=MAX_DOCUMENT_BYTES,
        reason="WORM_READBACK_FILE_INVALID",
    )
    expected_readback = _sha_pin(
        expected_readback_sha256,
        "WORM_READBACK_EXTERNAL_PIN_INVALID",
    )
    if _sha256(readback) != expected_readback:
        _reject("WORM_READBACK_EXTERNAL_PIN_MISMATCH")
    expected_bindings = {
        "custody_policy_sha256": request["custody_policy_sha256"],
        "provider_bound_admission_sha256": request[
            "provider_bound_admission_sha256"
        ],
        "legacy_admission_sha256": admission["legacy_admission_sha256"],
        "candidate_sha256": admission["candidate_sha256"],
        "demo_source_bound_verification_sha256": admission[
            "demo_source_bound_verification_sha256"
        ],
        "live_source_bound_verification_sha256": admission[
            "live_source_bound_verification_sha256"
        ],
        "provider_acceptance_sha256": admission[
            "provider_acceptance_sha256"
        ],
        "provider_acceptance_policy_sha256": admission[
            "provider_acceptance_policy_sha256"
        ],
        "provider_conformance_review_sha256": admission[
            "provider_conformance_review_sha256"
        ],
        "target_host_identity_sha256": admission[
            "target_host_identity_sha256"
        ],
        "launcher_trust_policy_sha256": custody[
            "launcher_trust_policy_sha256"
        ],
        "service_account_alias_sha256": custody[
            "service_account_alias_sha256"
        ],
        "installed_environment_sha256": admission[
            "installed_environment_sha256"
        ],
        "live_execution_release_identity_sha256": admission[
            "live_execution_release_identity_sha256"
        ],
        "live_execution_task_definition_sha256": admission[
            "live_execution_task_definition_sha256"
        ],
        "authorization_sha256": admission["authorization_sha256"],
        "validation_sha256": admission["validation_sha256"],
        "provider_acceptance_valid_until_utc": admission[
            "provider_acceptance_valid_until_utc"
        ],
        "worm_repository_alias_sha256": custody[
            "worm_repository_alias_sha256"
        ],
        "custody_issuer_id": custody["custody_issuer_id"],
        "custody_key_id": custody["custody_key_id"],
        "public_key_fingerprint_sha256": custody[
            "public_key_fingerprint_sha256"
        ],
        "stored_content_sha256": request[
            "provider_bound_admission_sha256"
        ],
        "stored_content_size_bytes": len(members[ADMISSION_MEMBER]),
    }
    if any(
        receipt.get(name) != value
        for name, value in expected_bindings.items()
    ):
        _reject("CUSTODY_RECEIPT_BINDING_MISMATCH")
    if readback != members[ADMISSION_MEMBER]:
        _reject("WORM_READBACK_CONTENT_MISMATCH")
    if receipt["stored_content_sha256"] != expected_readback:
        _reject("WORM_READBACK_RECEIPT_BINDING_MISMATCH")
    if not verify_rsa_pkcs1v15_sha256(
        modulus_hex=str(custody["rsa_modulus_hex"]),
        exponent=int(custody["rsa_exponent"]),
        message=_receipt_signing_message(receipt),
        signature_hex=str(
            receipt["signature_rsa_pkcs1v15_sha256_hex"]
        ),
    ):
        _reject("CUSTODY_RECEIPT_SIGNATURE_INVALID")
    checked = _canonical_utc(verified_at_utc, "ASSESSMENT_TIME_INVALID")
    requested = _canonical_utc(
        manifest["requested_at_utc"],
        "REQUEST_TIME_INVALID",
    )
    minimum_retained = _canonical_utc(
        manifest["minimum_retain_until_utc"],
        "REQUEST_RETENTION_INVALID",
    )
    admission_checked = _canonical_utc(
        admission["checked_at"],
        "PROVIDER_BOUND_ADMISSION_TIME_INVALID",
    )
    provider_expiry = _canonical_utc(
        admission["provider_acceptance_valid_until_utc"],
        "PROVIDER_BOUND_ADMISSION_TIME_INVALID",
    )
    uploaded = _canonical_utc(
        receipt["uploaded_at_utc"],
        "CUSTODY_RECEIPT_TIME_INVALID",
    )
    retained = _canonical_utc(
        receipt["retain_until_utc"],
        "CUSTODY_RECEIPT_TIME_INVALID",
    )
    if (
        uploaded < admission_checked
        or uploaded < requested
        or uploaded > checked
        or checked - uploaded
        > timedelta(seconds=int(custody["maximum_receipt_age_seconds"]))
        or retained < minimum_retained
        or retained
        < uploaded
        + timedelta(seconds=int(custody["minimum_retention_seconds"]))
        or checked >= retained
        or checked >= provider_expiry
    ):
        _reject("CUSTODY_RECEIPT_TIME_OR_RETENTION_INVALID")
    core = {
        "schema_version": ASSESSMENT_SCHEMA,
        "status": "LIVE_CANARY_PROVIDER_BOUND_WORM_RECEIPT_VERIFIED",
        "verified_at_utc": verified_at_utc,
        "request_archive_sha256": request["archive_sha256"],
        "request_archive_size_bytes": request["archive_size_bytes"],
        "request_identity_sha256": request["request_identity_sha256"],
        "request_id": request["request_id"],
        "receipt_sha256": _sha256(receipt_data),
        "receipt_id": receipt["receipt_id"],
        "readback_sha256": expected_readback,
        "readback_size_bytes": len(readback),
        "provider_bound_admission_sha256": request[
            "provider_bound_admission_sha256"
        ],
        "custody_policy_sha256": request["custody_policy_sha256"],
        "provider_acceptance_policy_sha256": request[
            "provider_acceptance_policy_sha256"
        ],
        "target_host_identity_sha256": request[
            "target_host_identity_sha256"
        ],
        "installed_environment_sha256": request[
            "installed_environment_sha256"
        ],
        "live_execution_release_identity_sha256": request[
            "live_execution_release_identity_sha256"
        ],
        "live_execution_task_definition_sha256": request[
            "live_execution_task_definition_sha256"
        ],
        "launcher_trust_policy_sha256": request[
            "launcher_trust_policy_sha256"
        ],
        "worm_repository_alias_sha256": receipt[
            "worm_repository_alias_sha256"
        ],
        "object_key_sha256": receipt["object_key_sha256"],
        "object_version_sha256": receipt["object_version_sha256"],
        "uploaded_at_utc": receipt["uploaded_at_utc"],
        "retain_until_utc": receipt["retain_until_utc"],
        "provider_acceptance_valid_until_utc": receipt[
            "provider_acceptance_valid_until_utc"
        ],
        "signed_receipt_accepted": True,
        "byte_identical_exported_readback_accepted": True,
        "direct_storage_api_inspection_performed": False,
        "runtime_admission_seal": False,
        "runtime_custody_seal": False,
        "runtime_sealed_custody_emitted": False,
        "cas_reservation_performed": False,
        "nonce_consumed": False,
        "central_unlock_performed": False,
        "process_launch_performed": False,
        "bootstrap_authorized": False,
        "process_launch_authorized": False,
        "execution_authorized": False,
        "activation_authorized": False,
        "broker_mutation_authorized": False,
        "promotion_eligible": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
        "order_capability": ORDER_CAPABILITY,
        "effects": dict(REQUEST_EFFECTS),
    }
    assessment = {
        **core,
        "assessment_identity_sha256": _sha256(_canonical_bytes(core)),
    }
    destination = _publish_exclusive(
        assessment_output,
        _canonical_bytes(assessment),
        pattern=_ASSESSMENT_NAME,
        destination_reason="ASSESSMENT_DESTINATION_INVALID",
        publication_reason="ASSESSMENT_PUBLICATION_FAILED",
    )
    return {
        **assessment,
        "assessment": str(destination),
        "assessment_sha256": _sha256(_canonical_bytes(assessment)),
    }


__all__ = [
    "ADMISSION_MEMBER",
    "ASSESSMENT_SCHEMA",
    "CUSTODY_POLICY_MEMBER",
    "LiveCanaryProviderBoundWormHandoffError",
    "PROVIDER_POLICY_MEMBER",
    "REQUEST_MANIFEST_MEMBER",
    "REQUEST_MEMBER_ORDER",
    "REQUEST_SCHEMA",
    "prepare_live_canary_provider_bound_worm_request",
    "verify_live_canary_provider_bound_worm_receipt",
    "verify_live_canary_provider_bound_worm_request_bytes",
    "verify_live_canary_provider_bound_worm_request_path",
]
