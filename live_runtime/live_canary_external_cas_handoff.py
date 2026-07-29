"""Deterministic deny-only handoff for the external LIVE canary CAS ledger.

The module packages public proposal/policy bytes and verifies exported signed
evidence.  It does not call the external CAS provider, consume a runtime nonce,
recreate a verifier seal, launch a process, or authorize broker mutation.
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


REQUEST_SCHEMA = "live-canary-external-cas-request-v1"
ASSESSMENT_SCHEMA = "live-canary-external-cas-assessment-v1"
CUSTODY_POLICY_SCHEMA = "live-canary-portable-custody-policy-v1"
LAUNCH_PROPOSAL_SCHEMA = "live-canary-launch-reservation-proposal-v1"
LAUNCH_CHECKPOINT_SCHEMA = "live-canary-launch-reservation-checkpoint-v1"
LAUNCH_ACK_SCHEMA = "live-canary-launch-reservation-cas-ack-v1"
NONCE_READBACK_SCHEMA = "live-canary-external-cas-nonce-readback-v1"
ORDER_CAPABILITY = "DISABLED"
ZERO_SHA256 = "0" * 64

PROPOSAL_MEMBER = "launch-proposal.json"
CUSTODY_POLICY_MEMBER = "portable-custody-policy.json"
REQUEST_MANIFEST_MEMBER = "LIVE_CANARY_EXTERNAL_CAS_REQUEST.json"
REQUEST_MEMBER_ORDER = (
    PROPOSAL_MEMBER,
    CUSTODY_POLICY_MEMBER,
    REQUEST_MANIFEST_MEMBER,
)
SOURCE_MEMBER_ORDER = REQUEST_MEMBER_ORDER[:-1]

CHECKPOINT_MEMBER = "launch-checkpoint.json"
ACKNOWLEDGEMENT_MEMBER = "launch-acknowledgement.json"
HEAD_READBACK_MEMBER = "head-readback.json"
NONCE_READBACK_MEMBER = "nonce-readback-attestation.json"

MAX_DOCUMENT_BYTES = 1_048_576
MAX_REQUEST_ARCHIVE_BYTES = 4_194_304
MAXIMUM_LAUNCH_TTL_SECONDS = 60
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
FIXED_ZIP_MODE = 0o100600

CHECKPOINT_SIGNATURE_DOMAIN = (
    b"AI_SCALPER:LIVE_CANARY:LAUNCH_CHECKPOINT:v1\x00"
)
ACKNOWLEDGEMENT_SIGNATURE_DOMAIN = (
    b"AI_SCALPER:LIVE_CANARY:LAUNCH_CAS_ACK:v1\x00"
)
NONCE_READBACK_SIGNATURE_DOMAIN = (
    b"AI_SCALPER:LIVE_CANARY:EXTERNAL_CAS_NONCE_READBACK:v1\x00"
)

_HEX = re.compile(r"^[0-9a-f]+$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_CANONICAL_UTC = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
)
_REQUEST_NAME = re.compile(
    r"^live-canary-external-cas-request-"
    r"[a-z0-9][a-z0-9._-]{0,95}\.zip$"
)
_ASSESSMENT_NAME = re.compile(
    r"^live-canary-external-cas-assessment-"
    r"[a-z0-9][a-z0-9._-]{0,95}\.json$"
)

_PROPOSAL_FIELDS = frozenset(
    {
        "sequence",
        "predecessor_checkpoint_sha256",
        "custody_policy_sha256",
        "custody_verification_sha256",
        "admission_sha256",
        "candidate_sha256",
        "authorization_sha256",
        "validation_sha256",
        "launcher_trust_policy_sha256",
        "launcher_attestation_sha256",
        "launcher_nonce_sha256",
        "release_identity_sha256",
        "deployment_host_alias_sha256",
        "service_account_alias_sha256",
        "task_definition_sha256",
        "requested_at_utc",
        "expires_at_utc",
        "live_allowed",
        "execution_authorized",
        "bootstrap_authorized",
        "process_launch_authorized",
        "order_capability",
        "schema_version",
    }
)
_CUSTODY_POLICY_FIELDS = frozenset(
    {
        "policy_id",
        "custody_issuer_id",
        "custody_key_id",
        "rsa_modulus_hex",
        "rsa_exponent",
        "public_key_fingerprint_sha256",
        "worm_repository_alias_sha256",
        "deployment_host_alias_sha256",
        "service_account_alias_sha256",
        "task_definition_sha256",
        "launcher_trust_policy_sha256",
        "minimum_retention_seconds",
        "maximum_receipt_age_seconds",
        "maximum_launch_ttl_seconds",
        "live_allowed",
        "execution_authorized",
        "bootstrap_authorized",
        "process_launch_authorized",
        "order_capability",
        "signature_algorithm",
        "schema_version",
    }
)
_CHECKPOINT_FIELDS = frozenset(
    {
        "proposal",
        "proposal_sha256",
        "committed_at_utc",
        "custody_issuer_id",
        "custody_key_id",
        "public_key_fingerprint_sha256",
        "signature_rsa_pkcs1v15_sha256_hex",
        "live_allowed",
        "execution_authorized",
        "bootstrap_authorized",
        "process_launch_authorized",
        "order_capability",
        "signature_algorithm",
        "schema_version",
    }
)
_ACKNOWLEDGEMENT_FIELDS = frozenset(
    {
        "expected_predecessor_checkpoint_sha256",
        "written_checkpoint_sha256",
        "proposal_sha256",
        "launcher_nonce_sha256",
        "sequence",
        "acknowledged_at_utc",
        "custody_issuer_id",
        "custody_key_id",
        "public_key_fingerprint_sha256",
        "signature_rsa_pkcs1v15_sha256_hex",
        "live_allowed",
        "execution_authorized",
        "bootstrap_authorized",
        "process_launch_authorized",
        "order_capability",
        "signature_algorithm",
        "schema_version",
    }
)
_NONCE_READBACK_FIELDS = frozenset(
    {
        "schema_version",
        "request_identity_sha256",
        "proposal_sha256",
        "checkpoint_sha256",
        "acknowledgement_sha256",
        "expected_predecessor_checkpoint_sha256",
        "observed_head_sha256",
        "launcher_nonce_sha256",
        "sequence",
        "nonce_seen",
        "observed_at_utc",
        "custody_issuer_id",
        "custody_key_id",
        "public_key_fingerprint_sha256",
        "signature_algorithm",
        "signature_rsa_pkcs1v15_sha256_hex",
        "live_allowed",
        "execution_authorized",
        "bootstrap_authorized",
        "process_launch_authorized",
        "order_capability",
    }
)

REQUEST_SAFETY: dict[str, object] = {
    "runtime_admission_seal": False,
    "runtime_custody_seal": False,
    "runtime_launch_capability_emitted": False,
    "runtime_cas_callback_executed": False,
    "runtime_nonce_consumed_by_tool": False,
    "central_unlock_performed": False,
    "process_launch_performed": False,
    "live_allowed": False,
    "bootstrap_authorized": False,
    "process_launch_authorized": False,
    "execution_authorized": False,
    "broker_mutation_authorized": False,
    "promotion_eligible": False,
    "safe_to_demo_auto_order": False,
    "order_capability": ORDER_CAPABILITY,
}
REQUEST_EFFECTS: dict[str, object] = {
    "network_access": "NOT_PERFORMED",
    "credential_access": "NOT_PERFORMED",
    "private_key_access": "NOT_PERFORMED",
    "external_cas_api_call": "NOT_PERFORMED",
    "external_checkpoint_read": "NOT_PERFORMED",
    "external_nonce_read": "NOT_PERFORMED",
    "nonce_consumption": "NOT_PERFORMED",
    "central_policy_mutation": "NOT_PERFORMED",
    "process_launch": "NOT_PERFORMED",
    "task_scheduler_mutation": "NOT_PERFORMED",
    "mt5_initialization": "NOT_PERFORMED",
    "broker_mutation": "NOT_PERFORMED",
}


class LiveCanaryExternalCasHandoffError(RuntimeError):
    """One public CAS handoff invariant failed with a stable reason."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: object) -> None:
        normalized = re.sub(
            r"[^A-Z0-9_]+",
            "_",
            str(reason_code or "").strip().upper(),
        ).strip("_")
        self.reason_code = normalized or "LIVE_CANARY_EXTERNAL_CAS_HANDOFF_INVALID"
        super().__init__(self.reason_code)


def _reject(reason_code: str) -> None:
    raise LiveCanaryExternalCasHandoffError(reason_code)


def _sha256(data: bytes) -> str:
    if type(data) is not bytes:
        raise TypeError("hash input must be exact bytes")
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    try:
        return canonical_json(value).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LiveCanaryExternalCasHandoffError(
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


def _integer(
    value: object,
    reason: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if (
        type(value) is not int
        or type(value) is bool
        or not minimum <= value <= maximum
    ):
        _reject(reason)
    return value


def _signature(value: object, reason: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if (
        type(value) is not str
        or not value
        or _HEX.fullmatch(value) is None
        or len(value) % 2
    ):
        _reject(reason)
    return value


def _canonical_utc(value: object, reason: str) -> datetime:
    if type(value) is not str or _CANONICAL_UTC.fullmatch(value) is None:
        _reject(reason)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise LiveCanaryExternalCasHandoffError(reason) from exc
    normalized = parsed.astimezone(timezone.utc)
    if normalized.isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    ) != value:
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

    def nonfinite(_value: str) -> object:
        _reject(f"{kind}_JSON_NONFINITE_VALUE")

    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=nonfinite,
        )
    except LiveCanaryExternalCasHandoffError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LiveCanaryExternalCasHandoffError(
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
    except LiveCanaryExternalCasHandoffError:
        raise
    except OSError as exc:
        raise LiveCanaryExternalCasHandoffError(reason) from exc
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
        raise LiveCanaryExternalCasHandoffError(reason) from exc
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
    except LiveCanaryExternalCasHandoffError:
        _remove_owned_output(destination, created)
        raise
    except (OSError, FileExistsError) as exc:
        _remove_owned_output(destination, created)
        raise LiveCanaryExternalCasHandoffError(publication_reason) from exc
    return destination


def _validate_safety(
    raw: Mapping[str, object],
    *,
    schema: str,
    reason: str,
    signature: bool = False,
) -> None:
    expected: dict[str, object] = {
        "schema_version": schema,
        "live_allowed": False,
        "execution_authorized": False,
        "bootstrap_authorized": False,
        "process_launch_authorized": False,
        "order_capability": ORDER_CAPABILITY,
    }
    if signature:
        expected["signature_algorithm"] = SIGNATURE_ALGORITHM
    if any(raw.get(name) != value for name, value in expected.items()):
        _reject(reason)


def _validate_proposal(
    raw: object,
) -> tuple[dict[str, object], datetime, datetime]:
    if type(raw) is not dict or set(raw) != _PROPOSAL_FIELDS:
        _reject("LAUNCH_PROPOSAL_SCHEMA_INVALID")
    proposal = raw
    sequence = _integer(
        proposal.get("sequence"),
        "LAUNCH_PROPOSAL_SEQUENCE_INVALID",
        minimum=1,
        maximum=2**63 - 1,
    )
    predecessor = _sha_pin(
        proposal.get("predecessor_checkpoint_sha256"),
        "LAUNCH_PROPOSAL_PREDECESSOR_INVALID",
        allow_zero=True,
    )
    for name in (
        "custody_policy_sha256",
        "custody_verification_sha256",
        "admission_sha256",
        "candidate_sha256",
        "authorization_sha256",
        "validation_sha256",
        "launcher_trust_policy_sha256",
        "launcher_attestation_sha256",
        "launcher_nonce_sha256",
        "release_identity_sha256",
        "deployment_host_alias_sha256",
        "service_account_alias_sha256",
        "task_definition_sha256",
    ):
        _sha_pin(proposal.get(name), "LAUNCH_PROPOSAL_HASH_INVALID")
    requested = _canonical_utc(
        proposal.get("requested_at_utc"),
        "LAUNCH_PROPOSAL_TIME_INVALID",
    )
    expires = _canonical_utc(
        proposal.get("expires_at_utc"),
        "LAUNCH_PROPOSAL_TIME_INVALID",
    )
    if (
        requested >= expires
        or expires - requested
        > timedelta(seconds=MAXIMUM_LAUNCH_TTL_SECONDS)
        or (sequence == 1) != (predecessor == ZERO_SHA256)
    ):
        _reject("LAUNCH_PROPOSAL_WINDOW_OR_PREDECESSOR_INVALID")
    _validate_safety(
        proposal,
        schema=LAUNCH_PROPOSAL_SCHEMA,
        reason="LAUNCH_PROPOSAL_SAFETY_DRIFT",
    )
    return proposal, requested, expires


def _decode_proposal(data: bytes) -> tuple[dict[str, object], datetime, datetime]:
    raw = _strict_object(data, kind="LAUNCH_PROPOSAL")
    return _validate_proposal(raw)


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
        ("maximum_launch_ttl_seconds", 1, MAXIMUM_LAUNCH_TTL_SECONDS),
    ):
        _integer(
            policy.get(name),
            "CUSTODY_POLICY_LIMIT_INVALID",
            minimum=minimum,
            maximum=maximum,
        )
    _validate_safety(
        policy,
        schema=CUSTODY_POLICY_SCHEMA,
        reason="CUSTODY_POLICY_SAFETY_DRIFT",
        signature=True,
    )
    deployment = (
        policy["worm_repository_alias_sha256"],
        policy["deployment_host_alias_sha256"],
        policy["service_account_alias_sha256"],
        policy["task_definition_sha256"],
    )
    if len(set(deployment)) != len(deployment):
        _reject("CUSTODY_POLICY_DEPLOYMENT_IDENTITY_REUSE")
    return policy


def _pin_arguments(
    *,
    expected_proposal_sha256: str,
    expected_custody_policy_sha256: str,
    expected_predecessor_checkpoint_sha256: str,
    expected_launcher_nonce_sha256: str,
    expected_candidate_sha256: str,
    expected_admission_sha256: str,
    expected_custody_verification_sha256: str,
    expected_authorization_sha256: str,
    expected_validation_sha256: str,
    expected_launcher_trust_policy_sha256: str,
    expected_launcher_attestation_sha256: str,
    expected_release_identity_sha256: str,
    expected_deployment_host_alias_sha256: str,
    expected_service_account_alias_sha256: str,
    expected_task_definition_sha256: str,
) -> dict[str, str]:
    values = {
        "proposal_sha256": expected_proposal_sha256,
        "custody_policy_sha256": expected_custody_policy_sha256,
        "predecessor_checkpoint_sha256": (
            expected_predecessor_checkpoint_sha256
        ),
        "launcher_nonce_sha256": expected_launcher_nonce_sha256,
        "candidate_sha256": expected_candidate_sha256,
        "admission_sha256": expected_admission_sha256,
        "custody_verification_sha256": (
            expected_custody_verification_sha256
        ),
        "authorization_sha256": expected_authorization_sha256,
        "validation_sha256": expected_validation_sha256,
        "launcher_trust_policy_sha256": (
            expected_launcher_trust_policy_sha256
        ),
        "launcher_attestation_sha256": (
            expected_launcher_attestation_sha256
        ),
        "release_identity_sha256": expected_release_identity_sha256,
        "deployment_host_alias_sha256": (
            expected_deployment_host_alias_sha256
        ),
        "service_account_alias_sha256": (
            expected_service_account_alias_sha256
        ),
        "task_definition_sha256": expected_task_definition_sha256,
    }
    return {
        name: _sha_pin(
            value,
            "HANDOFF_EXTERNAL_PIN_INVALID",
            allow_zero=name == "predecessor_checkpoint_sha256",
        )
        for name, value in values.items()
    }


def _validate_source_closure(
    *,
    proposal_data: bytes,
    custody_policy_data: bytes,
    pins: Mapping[str, str],
) -> tuple[
    dict[str, object],
    dict[str, object],
    datetime,
    datetime,
]:
    proposal, requested, expires = _decode_proposal(proposal_data)
    policy = _decode_custody_policy(custody_policy_data)
    observed = {
        "proposal_sha256": _sha256(proposal_data),
        "custody_policy_sha256": _sha256(custody_policy_data),
        "predecessor_checkpoint_sha256": proposal[
            "predecessor_checkpoint_sha256"
        ],
        "launcher_nonce_sha256": proposal["launcher_nonce_sha256"],
        "candidate_sha256": proposal["candidate_sha256"],
        "admission_sha256": proposal["admission_sha256"],
        "custody_verification_sha256": proposal[
            "custody_verification_sha256"
        ],
        "authorization_sha256": proposal["authorization_sha256"],
        "validation_sha256": proposal["validation_sha256"],
        "launcher_trust_policy_sha256": proposal[
            "launcher_trust_policy_sha256"
        ],
        "launcher_attestation_sha256": proposal[
            "launcher_attestation_sha256"
        ],
        "release_identity_sha256": proposal["release_identity_sha256"],
        "deployment_host_alias_sha256": proposal[
            "deployment_host_alias_sha256"
        ],
        "service_account_alias_sha256": proposal[
            "service_account_alias_sha256"
        ],
        "task_definition_sha256": proposal["task_definition_sha256"],
    }
    if observed != dict(pins):
        _reject("HANDOFF_EXTERNAL_PIN_MISMATCH")
    bindings = (
        (
            proposal["custody_policy_sha256"],
            observed["custody_policy_sha256"],
        ),
        (
            proposal["deployment_host_alias_sha256"],
            policy["deployment_host_alias_sha256"],
        ),
        (
            proposal["service_account_alias_sha256"],
            policy["service_account_alias_sha256"],
        ),
        (
            proposal["task_definition_sha256"],
            policy["task_definition_sha256"],
        ),
        (
            proposal["launcher_trust_policy_sha256"],
            policy["launcher_trust_policy_sha256"],
        ),
    )
    if any(left != right for left, right in bindings):
        _reject("PROPOSAL_CUSTODY_POLICY_BINDING_MISMATCH")
    if expires - requested > timedelta(
        seconds=int(policy["maximum_launch_ttl_seconds"])
    ):
        _reject("PROPOSAL_CUSTODY_POLICY_TTL_MISMATCH")
    return proposal, policy, requested, expires


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
    members: Mapping[str, bytes],
    proposal: Mapping[str, object],
    policy: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema_version": REQUEST_SCHEMA,
        "request_id": request_id,
        "requested_at_utc": proposal["requested_at_utc"],
        "expires_at_utc": proposal["expires_at_utc"],
        "proposal_sha256": _sha256(members[PROPOSAL_MEMBER]),
        "custody_policy_sha256": _sha256(
            members[CUSTODY_POLICY_MEMBER]
        ),
        "sequence": proposal["sequence"],
        "predecessor_checkpoint_sha256": proposal[
            "predecessor_checkpoint_sha256"
        ],
        "launcher_nonce_sha256": proposal["launcher_nonce_sha256"],
        "candidate_sha256": proposal["candidate_sha256"],
        "admission_sha256": proposal["admission_sha256"],
        "custody_verification_sha256": proposal[
            "custody_verification_sha256"
        ],
        "authorization_sha256": proposal["authorization_sha256"],
        "validation_sha256": proposal["validation_sha256"],
        "launcher_trust_policy_sha256": proposal[
            "launcher_trust_policy_sha256"
        ],
        "launcher_attestation_sha256": proposal[
            "launcher_attestation_sha256"
        ],
        "release_identity_sha256": proposal["release_identity_sha256"],
        "deployment_host_alias_sha256": proposal[
            "deployment_host_alias_sha256"
        ],
        "service_account_alias_sha256": proposal[
            "service_account_alias_sha256"
        ],
        "task_definition_sha256": proposal["task_definition_sha256"],
        "custody_issuer_id": policy["custody_issuer_id"],
        "custody_key_id": policy["custody_key_id"],
        "custody_public_key_fingerprint_sha256": policy[
            "public_key_fingerprint_sha256"
        ],
        "members": _member_records(members),
        "response_requirements": {
            "checkpoint_member": CHECKPOINT_MEMBER,
            "checkpoint_schema": LAUNCH_CHECKPOINT_SCHEMA,
            "acknowledgement_member": ACKNOWLEDGEMENT_MEMBER,
            "acknowledgement_schema": LAUNCH_ACK_SCHEMA,
            "head_readback_member": HEAD_READBACK_MEMBER,
            "nonce_readback_member": NONCE_READBACK_MEMBER,
            "nonce_readback_schema": NONCE_READBACK_SCHEMA,
            "byte_identical_head_readback_required": True,
            "nonce_seen_required": True,
            "signature_algorithm": SIGNATURE_ALGORITHM,
        },
        "safety": dict(REQUEST_SAFETY),
        "effects": dict(REQUEST_EFFECTS),
    }


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
        allowZip64=False,
    ) as archive:
        for name in REQUEST_MEMBER_ORDER:
            archive.writestr(_zip_info(name), members[name])
    data = destination.getvalue()
    if not data or len(data) > MAX_REQUEST_ARCHIVE_BYTES:
        _reject("REQUEST_ARCHIVE_SIZE_INVALID")
    return data


def _strict_request_members(data: bytes) -> dict[str, bytes]:
    if (
        type(data) is not bytes
        or not data
        or len(data) > MAX_REQUEST_ARCHIVE_BYTES
    ):
        _reject("REQUEST_ARCHIVE_SIZE_INVALID")
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            infos = archive.infolist()
            if (
                tuple(info.filename for info in infos)
                != REQUEST_MEMBER_ORDER
                or archive.comment != b""
            ):
                _reject("REQUEST_ARCHIVE_INVALID")
            members: dict[str, bytes] = {}
            for info in infos:
                if (
                    info.date_time != FIXED_ZIP_TIMESTAMP
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
                    or info.compress_size != info.file_size
                ):
                    _reject("REQUEST_ARCHIVE_INVALID")
                payload = archive.read(info)
                if len(payload) != info.file_size:
                    _reject("REQUEST_ARCHIVE_INVALID")
                members[info.filename] = payload
    except LiveCanaryExternalCasHandoffError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, KeyError) as exc:
        raise LiveCanaryExternalCasHandoffError(
            "REQUEST_ARCHIVE_INVALID"
        ) from exc
    if _build_request_archive(members) != data:
        _reject("REQUEST_ARCHIVE_NOT_EXACT")
    return members


def _verified_request(
    data: bytes,
    *,
    expected_request_archive_sha256: str,
    expected_proposal_sha256: str,
    expected_custody_policy_sha256: str,
    expected_predecessor_checkpoint_sha256: str,
    expected_launcher_nonce_sha256: str,
    expected_candidate_sha256: str,
    expected_admission_sha256: str,
    expected_custody_verification_sha256: str,
    expected_authorization_sha256: str,
    expected_validation_sha256: str,
    expected_launcher_trust_policy_sha256: str,
    expected_launcher_attestation_sha256: str,
    expected_release_identity_sha256: str,
    expected_deployment_host_alias_sha256: str,
    expected_service_account_alias_sha256: str,
    expected_task_definition_sha256: str,
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, bytes],
    datetime,
    datetime,
]:
    _require_central_lock()
    expected_archive = _sha_pin(
        expected_request_archive_sha256,
        "REQUEST_ARCHIVE_EXTERNAL_PIN_INVALID",
    )
    if _sha256(data) != expected_archive:
        _reject("REQUEST_ARCHIVE_EXTERNAL_PIN_MISMATCH")
    pins = _pin_arguments(
        expected_proposal_sha256=expected_proposal_sha256,
        expected_custody_policy_sha256=expected_custody_policy_sha256,
        expected_predecessor_checkpoint_sha256=(
            expected_predecessor_checkpoint_sha256
        ),
        expected_launcher_nonce_sha256=expected_launcher_nonce_sha256,
        expected_candidate_sha256=expected_candidate_sha256,
        expected_admission_sha256=expected_admission_sha256,
        expected_custody_verification_sha256=(
            expected_custody_verification_sha256
        ),
        expected_authorization_sha256=expected_authorization_sha256,
        expected_validation_sha256=expected_validation_sha256,
        expected_launcher_trust_policy_sha256=(
            expected_launcher_trust_policy_sha256
        ),
        expected_launcher_attestation_sha256=(
            expected_launcher_attestation_sha256
        ),
        expected_release_identity_sha256=expected_release_identity_sha256,
        expected_deployment_host_alias_sha256=(
            expected_deployment_host_alias_sha256
        ),
        expected_service_account_alias_sha256=(
            expected_service_account_alias_sha256
        ),
        expected_task_definition_sha256=expected_task_definition_sha256,
    )
    members = _strict_request_members(data)
    proposal, policy, requested, expires = _validate_source_closure(
        proposal_data=members[PROPOSAL_MEMBER],
        custody_policy_data=members[CUSTODY_POLICY_MEMBER],
        pins=pins,
    )
    manifest = _strict_object(
        members[REQUEST_MANIFEST_MEMBER],
        kind="CAS_REQUEST_MANIFEST",
    )
    if "request_identity_sha256" not in manifest:
        _reject("CAS_REQUEST_MANIFEST_SCHEMA_INVALID")
    identity = _sha_pin(
        manifest.get("request_identity_sha256"),
        "CAS_REQUEST_IDENTITY_INVALID",
    )
    unsigned = dict(manifest)
    del unsigned["request_identity_sha256"]
    if _sha256(_canonical_bytes(unsigned)) != identity:
        _reject("CAS_REQUEST_IDENTITY_INVALID")
    request_id = _identifier(
        manifest.get("request_id"),
        "CAS_REQUEST_IDENTIFIER_INVALID",
    )
    expected_core = _request_core(
        request_id=request_id,
        members=members,
        proposal=proposal,
        policy=policy,
    )
    if unsigned != expected_core:
        _reject("CAS_REQUEST_MANIFEST_BINDING_MISMATCH")
    result: dict[str, object] = {
        "schema_version": REQUEST_SCHEMA,
        "status": "LIVE_CANARY_EXTERNAL_CAS_REQUEST_VERIFIED",
        "archive_sha256": expected_archive,
        "archive_size_bytes": len(data),
        "request_identity_sha256": identity,
        "request_id": request_id,
        "requested_at_utc": proposal["requested_at_utc"],
        "expires_at_utc": proposal["expires_at_utc"],
        "proposal_sha256": pins["proposal_sha256"],
        "custody_policy_sha256": pins["custody_policy_sha256"],
        "sequence": proposal["sequence"],
        **{
            name: pins[name]
            for name in pins
            if name not in {"proposal_sha256", "custody_policy_sha256"}
        },
        "member_count": len(REQUEST_MEMBER_ORDER),
        "signed_checkpoint_accepted": False,
        "signed_acknowledgement_accepted": False,
        "byte_identical_head_readback_accepted": False,
        "signed_nonce_readback_accepted": False,
        **REQUEST_SAFETY,
        "broker_mutation": "NOT_PERFORMED",
    }
    _require_central_lock()
    return result, manifest, proposal, policy, members, requested, expires


def verify_live_canary_external_cas_request_bytes(
    data: bytes,
    **pins: str,
) -> dict[str, object]:
    """Independently reconstruct one deterministic public CAS request."""

    result, *_ = _verified_request(data, **pins)
    return result


def verify_live_canary_external_cas_request_path(
    request_archive: str | Path,
    **pins: str,
) -> dict[str, object]:
    data = _read_regular(
        request_archive,
        maximum=MAX_REQUEST_ARCHIVE_BYTES,
        reason="REQUEST_ARCHIVE_FILE_INVALID",
    )
    return verify_live_canary_external_cas_request_bytes(data, **pins)


def prepare_live_canary_external_cas_request(
    *,
    proposal_path: str | Path,
    custody_policy_path: str | Path,
    request_id: str,
    output: str | Path,
    expected_proposal_sha256: str,
    expected_custody_policy_sha256: str,
    expected_predecessor_checkpoint_sha256: str,
    expected_launcher_nonce_sha256: str,
    expected_candidate_sha256: str,
    expected_admission_sha256: str,
    expected_custody_verification_sha256: str,
    expected_authorization_sha256: str,
    expected_validation_sha256: str,
    expected_launcher_trust_policy_sha256: str,
    expected_launcher_attestation_sha256: str,
    expected_release_identity_sha256: str,
    expected_deployment_host_alias_sha256: str,
    expected_service_account_alias_sha256: str,
    expected_task_definition_sha256: str,
) -> dict[str, object]:
    """Create one exact three-member request without external effects."""

    _require_central_lock()
    source_members = {
        PROPOSAL_MEMBER: _read_regular(
            proposal_path,
            maximum=MAX_DOCUMENT_BYTES,
            reason="LAUNCH_PROPOSAL_FILE_INVALID",
        ),
        CUSTODY_POLICY_MEMBER: _read_regular(
            custody_policy_path,
            maximum=MAX_DOCUMENT_BYTES,
            reason="CUSTODY_POLICY_FILE_INVALID",
        ),
    }
    pins = _pin_arguments(
        expected_proposal_sha256=expected_proposal_sha256,
        expected_custody_policy_sha256=expected_custody_policy_sha256,
        expected_predecessor_checkpoint_sha256=(
            expected_predecessor_checkpoint_sha256
        ),
        expected_launcher_nonce_sha256=expected_launcher_nonce_sha256,
        expected_candidate_sha256=expected_candidate_sha256,
        expected_admission_sha256=expected_admission_sha256,
        expected_custody_verification_sha256=(
            expected_custody_verification_sha256
        ),
        expected_authorization_sha256=expected_authorization_sha256,
        expected_validation_sha256=expected_validation_sha256,
        expected_launcher_trust_policy_sha256=(
            expected_launcher_trust_policy_sha256
        ),
        expected_launcher_attestation_sha256=(
            expected_launcher_attestation_sha256
        ),
        expected_release_identity_sha256=expected_release_identity_sha256,
        expected_deployment_host_alias_sha256=(
            expected_deployment_host_alias_sha256
        ),
        expected_service_account_alias_sha256=(
            expected_service_account_alias_sha256
        ),
        expected_task_definition_sha256=expected_task_definition_sha256,
    )
    proposal, policy, _requested, _expires = _validate_source_closure(
        proposal_data=source_members[PROPOSAL_MEMBER],
        custody_policy_data=source_members[CUSTODY_POLICY_MEMBER],
        pins=pins,
    )
    request = _identifier(request_id, "CAS_REQUEST_IDENTIFIER_INVALID")
    core = _request_core(
        request_id=request,
        members=source_members,
        proposal=proposal,
        policy=policy,
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
    verified = verify_live_canary_external_cas_request_bytes(
        archive_data,
        expected_request_archive_sha256=archive_sha256,
        expected_proposal_sha256=expected_proposal_sha256,
        expected_custody_policy_sha256=expected_custody_policy_sha256,
        expected_predecessor_checkpoint_sha256=(
            expected_predecessor_checkpoint_sha256
        ),
        expected_launcher_nonce_sha256=expected_launcher_nonce_sha256,
        expected_candidate_sha256=expected_candidate_sha256,
        expected_admission_sha256=expected_admission_sha256,
        expected_custody_verification_sha256=(
            expected_custody_verification_sha256
        ),
        expected_authorization_sha256=expected_authorization_sha256,
        expected_validation_sha256=expected_validation_sha256,
        expected_launcher_trust_policy_sha256=(
            expected_launcher_trust_policy_sha256
        ),
        expected_launcher_attestation_sha256=(
            expected_launcher_attestation_sha256
        ),
        expected_release_identity_sha256=expected_release_identity_sha256,
        expected_deployment_host_alias_sha256=(
            expected_deployment_host_alias_sha256
        ),
        expected_service_account_alias_sha256=(
            expected_service_account_alias_sha256
        ),
        expected_task_definition_sha256=expected_task_definition_sha256,
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
        "status": "LIVE_CANARY_EXTERNAL_CAS_REQUEST_READY",
        "archive": str(destination),
    }


def _authority_matches(
    value: Mapping[str, object],
    policy: Mapping[str, object],
) -> bool:
    return (
        value.get("custody_issuer_id") == policy.get("custody_issuer_id")
        and value.get("custody_key_id") == policy.get("custody_key_id")
        and value.get("public_key_fingerprint_sha256")
        == policy.get("public_key_fingerprint_sha256")
    )


def _signing_message(
    domain: bytes,
    payload: Mapping[str, object],
) -> bytes:
    signing = dict(payload)
    signature = signing.pop("signature_rsa_pkcs1v15_sha256_hex", None)
    if type(signature) is not str:
        _reject("SIGNED_DOCUMENT_SIGNATURE_FIELD_INVALID")
    return domain + _canonical_bytes(signing)


def _verify_signature(
    *,
    policy: Mapping[str, object],
    domain: bytes,
    payload: Mapping[str, object],
    reason: str,
) -> None:
    if not verify_rsa_pkcs1v15_sha256(
        modulus_hex=str(policy["rsa_modulus_hex"]),
        exponent=int(policy["rsa_exponent"]),
        message=_signing_message(domain, payload),
        signature_hex=str(payload["signature_rsa_pkcs1v15_sha256_hex"]),
    ):
        _reject(reason)


def _decode_checkpoint(
    data: bytes,
) -> tuple[dict[str, object], dict[str, object], datetime]:
    checkpoint = _strict_object(data, kind="LAUNCH_CHECKPOINT")
    if set(checkpoint) != _CHECKPOINT_FIELDS:
        _reject("LAUNCH_CHECKPOINT_SCHEMA_INVALID")
    proposal, _requested, expires = _validate_proposal(
        checkpoint.get("proposal")
    )
    proposal_sha256 = _sha_pin(
        checkpoint.get("proposal_sha256"),
        "LAUNCH_CHECKPOINT_HASH_INVALID",
    )
    if proposal_sha256 != _sha256(_canonical_bytes(proposal)):
        _reject("LAUNCH_CHECKPOINT_PROPOSAL_HASH_MISMATCH")
    committed = _canonical_utc(
        checkpoint.get("committed_at_utc"),
        "LAUNCH_CHECKPOINT_TIME_INVALID",
    )
    requested = _canonical_utc(
        proposal.get("requested_at_utc"),
        "LAUNCH_PROPOSAL_TIME_INVALID",
    )
    if not requested <= committed < expires:
        _reject("LAUNCH_CHECKPOINT_TIME_INVALID")
    for name in ("custody_issuer_id", "custody_key_id"):
        _identifier(
            checkpoint.get(name),
            "LAUNCH_CHECKPOINT_AUTHORITY_INVALID",
        )
    _sha_pin(
        checkpoint.get("public_key_fingerprint_sha256"),
        "LAUNCH_CHECKPOINT_AUTHORITY_INVALID",
    )
    _signature(
        checkpoint.get("signature_rsa_pkcs1v15_sha256_hex"),
        "LAUNCH_CHECKPOINT_SIGNATURE_INVALID",
    )
    _validate_safety(
        checkpoint,
        schema=LAUNCH_CHECKPOINT_SCHEMA,
        reason="LAUNCH_CHECKPOINT_SAFETY_DRIFT",
        signature=True,
    )
    return checkpoint, proposal, committed


def _decode_acknowledgement(
    data: bytes,
) -> tuple[dict[str, object], datetime]:
    acknowledgement = _strict_object(data, kind="LAUNCH_ACKNOWLEDGEMENT")
    if set(acknowledgement) != _ACKNOWLEDGEMENT_FIELDS:
        _reject("LAUNCH_ACKNOWLEDGEMENT_SCHEMA_INVALID")
    for name in (
        "written_checkpoint_sha256",
        "proposal_sha256",
        "launcher_nonce_sha256",
        "public_key_fingerprint_sha256",
    ):
        _sha_pin(
            acknowledgement.get(name),
            "LAUNCH_ACKNOWLEDGEMENT_HASH_INVALID",
        )
    _sha_pin(
        acknowledgement.get("expected_predecessor_checkpoint_sha256"),
        "LAUNCH_ACKNOWLEDGEMENT_PREDECESSOR_INVALID",
        allow_zero=True,
    )
    _integer(
        acknowledgement.get("sequence"),
        "LAUNCH_ACKNOWLEDGEMENT_SEQUENCE_INVALID",
        minimum=1,
        maximum=2**63 - 1,
    )
    acknowledged = _canonical_utc(
        acknowledgement.get("acknowledged_at_utc"),
        "LAUNCH_ACKNOWLEDGEMENT_TIME_INVALID",
    )
    for name in ("custody_issuer_id", "custody_key_id"):
        _identifier(
            acknowledgement.get(name),
            "LAUNCH_ACKNOWLEDGEMENT_AUTHORITY_INVALID",
        )
    _signature(
        acknowledgement.get("signature_rsa_pkcs1v15_sha256_hex"),
        "LAUNCH_ACKNOWLEDGEMENT_SIGNATURE_INVALID",
    )
    _validate_safety(
        acknowledgement,
        schema=LAUNCH_ACK_SCHEMA,
        reason="LAUNCH_ACKNOWLEDGEMENT_SAFETY_DRIFT",
        signature=True,
    )
    return acknowledgement, acknowledged


def _validate_nonce_readback_shape(
    raw: object,
    *,
    require_signature: bool,
    require_seen: bool,
) -> tuple[dict[str, object], datetime]:
    if type(raw) is not dict or set(raw) != _NONCE_READBACK_FIELDS:
        _reject("NONCE_READBACK_SCHEMA_INVALID")
    readback = raw
    for name in (
        "request_identity_sha256",
        "proposal_sha256",
        "checkpoint_sha256",
        "acknowledgement_sha256",
        "observed_head_sha256",
        "launcher_nonce_sha256",
        "public_key_fingerprint_sha256",
    ):
        _sha_pin(readback.get(name), "NONCE_READBACK_HASH_INVALID")
    _sha_pin(
        readback.get("expected_predecessor_checkpoint_sha256"),
        "NONCE_READBACK_PREDECESSOR_INVALID",
        allow_zero=True,
    )
    _integer(
        readback.get("sequence"),
        "NONCE_READBACK_SEQUENCE_INVALID",
        minimum=1,
        maximum=2**63 - 1,
    )
    seen = readback.get("nonce_seen")
    if type(seen) is not bool or (require_seen and seen is not True):
        _reject("NONCE_READBACK_SAFETY_DRIFT")
    observed = _canonical_utc(
        readback.get("observed_at_utc"),
        "NONCE_READBACK_TIME_INVALID",
    )
    for name in ("custody_issuer_id", "custody_key_id"):
        _identifier(
            readback.get(name),
            "NONCE_READBACK_AUTHORITY_INVALID",
        )
    _signature(
        readback.get("signature_rsa_pkcs1v15_sha256_hex"),
        "NONCE_READBACK_SIGNATURE_INVALID",
        allow_empty=not require_signature,
    )
    _validate_safety(
        readback,
        schema=NONCE_READBACK_SCHEMA,
        reason="NONCE_READBACK_SAFETY_DRIFT",
        signature=True,
    )
    return readback, observed


def _decode_nonce_readback(
    data: bytes,
) -> tuple[dict[str, object], datetime]:
    raw = _strict_object(data, kind="NONCE_READBACK")
    return _validate_nonce_readback_shape(
        raw,
        require_signature=True,
        require_seen=True,
    )


def external_cas_nonce_readback_signing_message(
    readback: Mapping[str, object],
) -> bytes:
    """Return the exact public message an external custodian must sign."""

    if not isinstance(readback, Mapping):
        _reject("NONCE_READBACK_SCHEMA_INVALID")
    normalized = dict(readback)
    _validate_nonce_readback_shape(
        normalized,
        require_signature=False,
        require_seen=False,
    )
    return _signing_message(NONCE_READBACK_SIGNATURE_DOMAIN, normalized)


def verify_live_canary_external_cas_response(
    *,
    request_archive: str | Path,
    expected_request_archive_sha256: str,
    checkpoint_path: str | Path,
    acknowledgement_path: str | Path,
    head_readback_path: str | Path,
    nonce_readback_path: str | Path,
    expected_head_readback_sha256: str,
    verified_at_utc: str,
    assessment_output: str | Path,
    expected_proposal_sha256: str,
    expected_custody_policy_sha256: str,
    expected_predecessor_checkpoint_sha256: str,
    expected_launcher_nonce_sha256: str,
    expected_candidate_sha256: str,
    expected_admission_sha256: str,
    expected_custody_verification_sha256: str,
    expected_authorization_sha256: str,
    expected_validation_sha256: str,
    expected_launcher_trust_policy_sha256: str,
    expected_launcher_attestation_sha256: str,
    expected_release_identity_sha256: str,
    expected_deployment_host_alias_sha256: str,
    expected_service_account_alias_sha256: str,
    expected_task_definition_sha256: str,
) -> dict[str, object]:
    """Verify exported signed CAS evidence and publish a deny-only assessment."""

    _require_central_lock()
    request_data = _read_regular(
        request_archive,
        maximum=MAX_REQUEST_ARCHIVE_BYTES,
        reason="REQUEST_ARCHIVE_FILE_INVALID",
    )
    request, manifest, proposal, policy, _members, requested, expires = (
        _verified_request(
            request_data,
            expected_request_archive_sha256=(
                expected_request_archive_sha256
            ),
            expected_proposal_sha256=expected_proposal_sha256,
            expected_custody_policy_sha256=(
                expected_custody_policy_sha256
            ),
            expected_predecessor_checkpoint_sha256=(
                expected_predecessor_checkpoint_sha256
            ),
            expected_launcher_nonce_sha256=(
                expected_launcher_nonce_sha256
            ),
            expected_candidate_sha256=expected_candidate_sha256,
            expected_admission_sha256=expected_admission_sha256,
            expected_custody_verification_sha256=(
                expected_custody_verification_sha256
            ),
            expected_authorization_sha256=expected_authorization_sha256,
            expected_validation_sha256=expected_validation_sha256,
            expected_launcher_trust_policy_sha256=(
                expected_launcher_trust_policy_sha256
            ),
            expected_launcher_attestation_sha256=(
                expected_launcher_attestation_sha256
            ),
            expected_release_identity_sha256=(
                expected_release_identity_sha256
            ),
            expected_deployment_host_alias_sha256=(
                expected_deployment_host_alias_sha256
            ),
            expected_service_account_alias_sha256=(
                expected_service_account_alias_sha256
            ),
            expected_task_definition_sha256=(
                expected_task_definition_sha256
            ),
        )
    )
    checkpoint_data = _read_regular(
        checkpoint_path,
        maximum=MAX_DOCUMENT_BYTES,
        reason="LAUNCH_CHECKPOINT_FILE_INVALID",
    )
    acknowledgement_data = _read_regular(
        acknowledgement_path,
        maximum=MAX_DOCUMENT_BYTES,
        reason="LAUNCH_ACKNOWLEDGEMENT_FILE_INVALID",
    )
    head_readback_data = _read_regular(
        head_readback_path,
        maximum=MAX_DOCUMENT_BYTES,
        reason="HEAD_READBACK_FILE_INVALID",
    )
    nonce_readback_data = _read_regular(
        nonce_readback_path,
        maximum=MAX_DOCUMENT_BYTES,
        reason="NONCE_READBACK_FILE_INVALID",
    )
    expected_head = _sha_pin(
        expected_head_readback_sha256,
        "HEAD_READBACK_EXTERNAL_PIN_INVALID",
    )
    if _sha256(head_readback_data) != expected_head:
        _reject("HEAD_READBACK_EXTERNAL_PIN_MISMATCH")

    checkpoint, checkpoint_proposal, committed = _decode_checkpoint(
        checkpoint_data
    )
    acknowledgement, acknowledged = _decode_acknowledgement(
        acknowledgement_data
    )
    nonce_readback, observed = _decode_nonce_readback(nonce_readback_data)
    proposal_sha256 = _sha256(_canonical_bytes(proposal))
    checkpoint_sha256 = _sha256(checkpoint_data)
    acknowledgement_sha256 = _sha256(acknowledgement_data)

    if checkpoint_proposal != proposal:
        _reject("LAUNCH_CHECKPOINT_PROPOSAL_MISMATCH")
    if not _authority_matches(checkpoint, policy):
        _reject("LAUNCH_CHECKPOINT_AUTHORITY_MISMATCH")
    if checkpoint_proposal.get("custody_policy_sha256") != request.get(
        "custody_policy_sha256"
    ):
        _reject("LAUNCH_CHECKPOINT_POLICY_MISMATCH")
    _verify_signature(
        policy=policy,
        domain=CHECKPOINT_SIGNATURE_DOMAIN,
        payload=checkpoint,
        reason="LAUNCH_CHECKPOINT_SIGNATURE_INVALID",
    )

    if not _authority_matches(acknowledgement, policy):
        _reject("LAUNCH_ACKNOWLEDGEMENT_AUTHORITY_MISMATCH")
    expected_ack = {
        "expected_predecessor_checkpoint_sha256": proposal[
            "predecessor_checkpoint_sha256"
        ],
        "written_checkpoint_sha256": checkpoint_sha256,
        "proposal_sha256": proposal_sha256,
        "launcher_nonce_sha256": proposal["launcher_nonce_sha256"],
        "sequence": proposal["sequence"],
    }
    if any(
        acknowledgement.get(name) != value
        for name, value in expected_ack.items()
    ):
        _reject("LAUNCH_ACKNOWLEDGEMENT_BINDING_MISMATCH")
    if not committed <= acknowledged < expires:
        _reject("LAUNCH_ACKNOWLEDGEMENT_TIME_INVALID")
    _verify_signature(
        policy=policy,
        domain=ACKNOWLEDGEMENT_SIGNATURE_DOMAIN,
        payload=acknowledgement,
        reason="LAUNCH_ACKNOWLEDGEMENT_SIGNATURE_INVALID",
    )

    if head_readback_data != checkpoint_data:
        _reject("HEAD_READBACK_CONTENT_MISMATCH")
    if expected_head != checkpoint_sha256:
        _reject("HEAD_READBACK_CHECKPOINT_BINDING_MISMATCH")

    if not _authority_matches(nonce_readback, policy):
        _reject("NONCE_READBACK_AUTHORITY_MISMATCH")
    expected_nonce = {
        "request_identity_sha256": manifest["request_identity_sha256"],
        "proposal_sha256": proposal_sha256,
        "checkpoint_sha256": checkpoint_sha256,
        "acknowledgement_sha256": acknowledgement_sha256,
        "expected_predecessor_checkpoint_sha256": proposal[
            "predecessor_checkpoint_sha256"
        ],
        "observed_head_sha256": checkpoint_sha256,
        "launcher_nonce_sha256": proposal["launcher_nonce_sha256"],
        "sequence": proposal["sequence"],
        "nonce_seen": True,
    }
    if any(
        nonce_readback.get(name) != value
        for name, value in expected_nonce.items()
    ):
        _reject("NONCE_READBACK_BINDING_MISMATCH")
    if not acknowledged <= observed < expires:
        _reject("NONCE_READBACK_TIME_INVALID")
    _verify_signature(
        policy=policy,
        domain=NONCE_READBACK_SIGNATURE_DOMAIN,
        payload=nonce_readback,
        reason="NONCE_READBACK_SIGNATURE_INVALID",
    )

    verified = _canonical_utc(
        verified_at_utc,
        "ASSESSMENT_TIME_INVALID",
    )
    if verified < observed or verified < requested or verified >= expires:
        _reject("ASSESSMENT_TIME_INVALID")
    _require_central_lock()
    core: dict[str, object] = {
        "schema_version": ASSESSMENT_SCHEMA,
        "status": "LIVE_CANARY_EXTERNAL_CAS_RESPONSE_VERIFIED",
        "verified_at_utc": verified_at_utc,
        "request_archive_sha256": request["archive_sha256"],
        "request_archive_size_bytes": request["archive_size_bytes"],
        "request_identity_sha256": request["request_identity_sha256"],
        "request_id": request["request_id"],
        "proposal_sha256": proposal_sha256,
        "custody_policy_sha256": request["custody_policy_sha256"],
        "checkpoint_sha256": checkpoint_sha256,
        "acknowledgement_sha256": acknowledgement_sha256,
        "head_readback_sha256": expected_head,
        "nonce_readback_sha256": _sha256(nonce_readback_data),
        "sequence": proposal["sequence"],
        "predecessor_checkpoint_sha256": proposal[
            "predecessor_checkpoint_sha256"
        ],
        "launcher_nonce_sha256": proposal["launcher_nonce_sha256"],
        "candidate_sha256": proposal["candidate_sha256"],
        "admission_sha256": proposal["admission_sha256"],
        "custody_verification_sha256": proposal[
            "custody_verification_sha256"
        ],
        "authorization_sha256": proposal["authorization_sha256"],
        "validation_sha256": proposal["validation_sha256"],
        "launcher_trust_policy_sha256": proposal[
            "launcher_trust_policy_sha256"
        ],
        "launcher_attestation_sha256": proposal[
            "launcher_attestation_sha256"
        ],
        "release_identity_sha256": proposal["release_identity_sha256"],
        "deployment_host_alias_sha256": proposal[
            "deployment_host_alias_sha256"
        ],
        "service_account_alias_sha256": proposal[
            "service_account_alias_sha256"
        ],
        "task_definition_sha256": proposal["task_definition_sha256"],
        "requested_at_utc": proposal["requested_at_utc"],
        "committed_at_utc": checkpoint["committed_at_utc"],
        "acknowledged_at_utc": acknowledgement["acknowledged_at_utc"],
        "nonce_observed_at_utc": nonce_readback["observed_at_utc"],
        "expires_at_utc": proposal["expires_at_utc"],
        "signed_checkpoint_accepted": True,
        "signed_acknowledgement_accepted": True,
        "byte_identical_head_readback_accepted": True,
        "signed_nonce_readback_accepted": True,
        "external_atomic_cas_claim_accepted": True,
        "external_nonce_seen_claim_accepted": True,
        **REQUEST_SAFETY,
        "effects": dict(REQUEST_EFFECTS),
        "broker_mutation": "NOT_PERFORMED",
    }
    assessment = {
        **core,
        "assessment_identity_sha256": _sha256(_canonical_bytes(core)),
    }
    assessment_data = _canonical_bytes(assessment)
    destination = _publish_exclusive(
        assessment_output,
        assessment_data,
        pattern=_ASSESSMENT_NAME,
        destination_reason="ASSESSMENT_DESTINATION_INVALID",
        publication_reason="ASSESSMENT_PUBLICATION_FAILED",
    )
    return {
        **assessment,
        "assessment": str(destination),
        "assessment_sha256": _sha256(assessment_data),
    }


__all__ = [
    "ACKNOWLEDGEMENT_MEMBER",
    "ASSESSMENT_SCHEMA",
    "CHECKPOINT_MEMBER",
    "CUSTODY_POLICY_MEMBER",
    "HEAD_READBACK_MEMBER",
    "LiveCanaryExternalCasHandoffError",
    "NONCE_READBACK_MEMBER",
    "NONCE_READBACK_SCHEMA",
    "PROPOSAL_MEMBER",
    "REQUEST_MANIFEST_MEMBER",
    "REQUEST_MEMBER_ORDER",
    "REQUEST_SCHEMA",
    "external_cas_nonce_readback_signing_message",
    "prepare_live_canary_external_cas_request",
    "verify_live_canary_external_cas_request_bytes",
    "verify_live_canary_external_cas_request_path",
    "verify_live_canary_external_cas_response",
]
