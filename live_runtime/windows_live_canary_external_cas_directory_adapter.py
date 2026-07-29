"""Synchronous signed directory adapter for LIVE-canary external CAS.

The adapter implements only the three callbacks consumed by
``consume_live_canary_launch_reservation``.  An independently operated service
owns the response directory, RSA private key, atomic checkpoint, and nonce
ledger.  This client never grants launch or order authority and is deliberately
unusable after the central LIVE unlock.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Callable, Mapping

import execution_policy

from .asymmetric_release_trust import (
    MINIMUM_RSA_BITS,
    SIGNATURE_ALGORITHM,
    rsa_public_key_fingerprint_sha256,
    verify_rsa_pkcs1v15_sha256,
)
from .contracts import canonical_json


CAS_REQUEST_SCHEMA = "windows-live-canary-directory-cas-request-v1"
CAS_RESPONSE_SCHEMA = "windows-live-canary-directory-cas-response-v1"
NONCE_QUERY_REQUEST_SCHEMA = "windows-live-canary-nonce-query-request-v1"
NONCE_QUERY_RESPONSE_SCHEMA = "windows-live-canary-nonce-query-response-v1"
NONCE_QUERY_RESPONSE_SIGNATURE_DOMAIN = (
    b"AI_SCALPER:WINDOWS:LIVE_CANARY:NONCE_QUERY_RESPONSE:v1\x00"
)
CUSTODY_POLICY_SCHEMA = "live-canary-portable-custody-policy-v1"
LAUNCH_PROPOSAL_SCHEMA = "live-canary-launch-reservation-proposal-v1"
LAUNCH_CHECKPOINT_SCHEMA = "live-canary-launch-reservation-checkpoint-v1"
LAUNCH_ACK_SCHEMA = "live-canary-launch-reservation-cas-ack-v1"
LAUNCH_CHECKPOINT_SIGNATURE_DOMAIN = (
    b"AI_SCALPER:LIVE_CANARY:LAUNCH_CHECKPOINT:v1\x00"
)
LAUNCH_ACKNOWLEDGEMENT_SIGNATURE_DOMAIN = (
    b"AI_SCALPER:LIVE_CANARY:LAUNCH_CAS_ACK:v1\x00"
)
ORDER_CAPABILITY = "DISABLED"
ZERO_SHA256 = "0" * 64
CURRENT_CHECKPOINT_NAME = "current.checkpoint.json"
MAXIMUM_PACKET_BYTES = 1_048_576
MAXIMUM_TIMEOUT_SECONDS = 2.0
POLL_INTERVAL_SECONDS = 0.005
MAXIMUM_RSA_BITS = 8192
MAXIMUM_LAUNCH_TTL_SECONDS = 60
MAXIMUM_RETENTION_SECONDS = 315_360_000

_HEX = re.compile(r"^[0-9a-f]+$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_CANONICAL_UTC = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
)

_CAS_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "request_id",
        "provider_id",
        "custody_policy_sha256",
        "worm_repository_alias_sha256",
        "expected_predecessor_checkpoint_sha256",
        "proposal_sha256",
        "proposal",
        "issued_at_utc",
        "expires_at_utc",
        "live_allowed",
        "execution_authorized",
        "bootstrap_authorized",
        "process_launch_authorized",
        "order_capability",
    }
)
_CAS_RESPONSE_FIELDS = frozenset(
    {
        "schema_version",
        "request_id",
        "request_sha256",
        "provider_id",
        "custody_policy_sha256",
        "worm_repository_alias_sha256",
        "checkpoint",
        "acknowledgement",
        "responded_at_utc",
    }
)
_NONCE_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "request_id",
        "provider_id",
        "custody_policy_sha256",
        "worm_repository_alias_sha256",
        "launcher_nonce_sha256",
        "expected_head_sha256",
        "query_nonce_sha256",
        "issued_at_utc",
        "expires_at_utc",
        "live_allowed",
        "execution_authorized",
        "bootstrap_authorized",
        "process_launch_authorized",
        "order_capability",
    }
)
_NONCE_RESPONSE_FIELDS = frozenset(
    {
        "schema_version",
        "request_id",
        "request_sha256",
        "provider_id",
        "custody_policy_sha256",
        "worm_repository_alias_sha256",
        "launcher_nonce_sha256",
        "expected_head_sha256",
        "observed_head_sha256",
        "query_nonce_sha256",
        "nonce_seen",
        "observed_at_utc",
        "expires_at_utc",
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
_LAUNCH_PROPOSAL_FIELDS = frozenset(
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
_LAUNCH_CHECKPOINT_FIELDS = frozenset(
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
_LAUNCH_ACK_FIELDS = frozenset(
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


@dataclass(frozen=True, slots=True)
class _PublicCustodyPolicy:
    content_sha256: str
    policy_id: str
    custody_issuer_id: str
    custody_key_id: str
    rsa_modulus_hex: str
    rsa_exponent: int
    public_key_fingerprint_sha256: str
    worm_repository_alias_sha256: str
    deployment_host_alias_sha256: str
    service_account_alias_sha256: str
    task_definition_sha256: str
    launcher_trust_policy_sha256: str
    minimum_retention_seconds: int
    maximum_receipt_age_seconds: int
    maximum_launch_ttl_seconds: int


@dataclass(frozen=True, slots=True)
class _LaunchProposal:
    canonical_payload: bytes
    content_sha256: str
    sequence: int
    predecessor_checkpoint_sha256: str
    custody_policy_sha256: str
    launcher_trust_policy_sha256: str
    launcher_nonce_sha256: str
    deployment_host_alias_sha256: str
    service_account_alias_sha256: str
    task_definition_sha256: str
    requested_at_utc: datetime
    expires_at_utc: datetime


@dataclass(frozen=True, slots=True)
class _LaunchCheckpoint:
    canonical_payload: bytes
    content_sha256: str
    proposal: _LaunchProposal
    committed_at_utc: datetime
    custody_issuer_id: str
    custody_key_id: str
    public_key_fingerprint_sha256: str
    signature_rsa_pkcs1v15_sha256_hex: str


@dataclass(frozen=True, slots=True)
class _LaunchAcknowledgement:
    canonical_payload: bytes
    content_sha256: str
    expected_predecessor_checkpoint_sha256: str
    written_checkpoint_sha256: str
    proposal_sha256: str
    launcher_nonce_sha256: str
    sequence: int
    acknowledged_at_utc: datetime
    custody_issuer_id: str
    custody_key_id: str
    public_key_fingerprint_sha256: str
    signature_rsa_pkcs1v15_sha256_hex: str


class WindowsLiveCanaryExternalCasDirectoryAdapterError(RuntimeError):
    """One adapter invariant failed without exposing provider content."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: object) -> None:
        normalized = re.sub(
            r"[^A-Z0-9_]+",
            "_",
            str(reason_code or "").strip().upper(),
        ).strip("_")
        self.reason_code = normalized or "LIVE_CANARY_DIRECTORY_CAS_INVALID"
        super().__init__(self.reason_code)


def _reject(reason_code: str) -> None:
    raise WindowsLiveCanaryExternalCasDirectoryAdapterError(reason_code)


def _sha256(data: bytes) -> str:
    if type(data) is not bytes:
        raise TypeError("hash input must be exact bytes")
    return hashlib.sha256(data).hexdigest()


def _sha_pin(
    value: object,
    reason_code: str,
    *,
    allow_zero: bool = False,
) -> str:
    if type(value) is not str or _HEX_64.fullmatch(value) is None:
        _reject(reason_code)
    if not allow_zero and value == ZERO_SHA256:
        _reject(reason_code)
    return value


def _identifier(value: object, reason_code: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        _reject(reason_code)
    return value


def _signature(
    value: object,
    *,
    allow_empty: bool,
    reason_code: str = "NONCE_RESPONSE_SIGNATURE_INVALID",
) -> str:
    if allow_empty and value == "":
        return ""
    if (
        type(value) is not str
        or not value
        or _HEX.fullmatch(value) is None
        or len(value) % 2
    ):
        _reject(reason_code)
    return value


def _integer(
    value: object,
    *,
    minimum: int,
    maximum: int,
    reason_code: str,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _reject(reason_code)
    return value


def _utc_text(value: datetime) -> str:
    if type(value) is not datetime or value.tzinfo is None:
        _reject("TRUSTED_CLOCK_VALUE_INVALID")
    try:
        offset = value.utcoffset()
        if offset is None or offset.total_seconds() != 0:
            _reject("TRUSTED_CLOCK_VALUE_INVALID")
        return value.astimezone(timezone.utc).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")
    except WindowsLiveCanaryExternalCasDirectoryAdapterError:
        raise
    except Exception:
        raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
            "TRUSTED_CLOCK_VALUE_INVALID"
        ) from None


def _parse_utc(value: object, reason_code: str) -> datetime:
    if type(value) is not str or _CANONICAL_UTC.fullmatch(value) is None:
        _reject(reason_code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
            reason_code
        ) from None
    if _utc_text(parsed) != value:
        _reject(reason_code)
    return parsed.astimezone(timezone.utc)


def _canonical_bytes(value: object) -> bytes:
    try:
        return canonical_json(value).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
            "DIRECTORY_CAS_JSON_INVALID"
        ) from None


def _strict_object(data: bytes, *, kind: str) -> dict[str, object]:
    if type(data) is not bytes or not data or len(data) > MAXIMUM_PACKET_BYTES:
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
    except WindowsLiveCanaryExternalCasDirectoryAdapterError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
            f"{kind}_JSON_INVALID"
        ) from None
    if type(value) is not dict:
        _reject(f"{kind}_JSON_NOT_CANONICAL")
    try:
        canonical = _canonical_bytes(value)
    except WindowsLiveCanaryExternalCasDirectoryAdapterError:
        raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
            f"{kind}_JSON_INVALID"
        ) from None
    if canonical != data:
        _reject(f"{kind}_JSON_NOT_CANONICAL")
    return value


def _decode_custody_policy(payload: object) -> _PublicCustodyPolicy:
    if type(payload) is not bytes:
        _reject("CUSTODY_POLICY_PAYLOAD_INVALID")
    value = _strict_object(payload, kind="CUSTODY_POLICY")
    if (
        set(value) != _CUSTODY_POLICY_FIELDS
        or value.get("schema_version") != CUSTODY_POLICY_SCHEMA
        or value.get("signature_algorithm") != SIGNATURE_ALGORITHM
    ):
        _reject("CUSTODY_POLICY_SCHEMA_INVALID")
    _require_locked_safety(value, reason_code="CUSTODY_POLICY_SAFETY_DRIFT")

    policy_id = _identifier(
        value.get("policy_id"),
        "CUSTODY_POLICY_ID_INVALID",
    )
    custody_issuer_id = _identifier(
        value.get("custody_issuer_id"),
        "CUSTODY_ISSUER_ID_INVALID",
    )
    custody_key_id = _identifier(
        value.get("custody_key_id"),
        "CUSTODY_KEY_ID_INVALID",
    )
    modulus_hex = value.get("rsa_modulus_hex")
    if (
        type(modulus_hex) is not str
        or _HEX.fullmatch(modulus_hex) is None
        or len(modulus_hex) % 2
        or modulus_hex.startswith("00")
        or len(modulus_hex) > MAXIMUM_RSA_BITS // 4
    ):
        _reject("CUSTODY_RSA_MODULUS_INVALID")
    modulus = int(modulus_hex, 16)
    if (
        not MINIMUM_RSA_BITS <= modulus.bit_length() <= MAXIMUM_RSA_BITS
        or modulus % 2 == 0
    ):
        _reject("CUSTODY_RSA_MODULUS_INVALID")
    exponent = _integer(
        value.get("rsa_exponent"),
        minimum=3,
        maximum=2**31 - 1,
        reason_code="CUSTODY_RSA_EXPONENT_INVALID",
    )
    if exponent != 65_537:
        _reject("CUSTODY_RSA_EXPONENT_INVALID")
    fingerprint = _sha_pin(
        value.get("public_key_fingerprint_sha256"),
        "CUSTODY_PUBLIC_KEY_FINGERPRINT_INVALID",
    )
    try:
        observed_fingerprint = rsa_public_key_fingerprint_sha256(
            modulus_hex,
            exponent,
        )
    except (TypeError, ValueError):
        raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
            "CUSTODY_PUBLIC_KEY_INVALID"
        ) from None
    if fingerprint != observed_fingerprint:
        _reject("CUSTODY_PUBLIC_KEY_FINGERPRINT_MISMATCH")

    hashes: dict[str, str] = {}
    for name in (
        "worm_repository_alias_sha256",
        "deployment_host_alias_sha256",
        "service_account_alias_sha256",
        "task_definition_sha256",
        "launcher_trust_policy_sha256",
    ):
        hashes[name] = _sha_pin(
            value.get(name),
            "CUSTODY_POLICY_DEPLOYMENT_HASH_INVALID",
        )
    if len(
        {
            hashes["worm_repository_alias_sha256"],
            hashes["deployment_host_alias_sha256"],
            hashes["service_account_alias_sha256"],
            hashes["task_definition_sha256"],
        }
    ) != 4:
        _reject("CUSTODY_POLICY_DEPLOYMENT_IDENTITY_REUSE")

    return _PublicCustodyPolicy(
        content_sha256=_sha256(payload),
        policy_id=policy_id,
        custody_issuer_id=custody_issuer_id,
        custody_key_id=custody_key_id,
        rsa_modulus_hex=modulus_hex,
        rsa_exponent=exponent,
        public_key_fingerprint_sha256=fingerprint,
        worm_repository_alias_sha256=hashes[
            "worm_repository_alias_sha256"
        ],
        deployment_host_alias_sha256=hashes[
            "deployment_host_alias_sha256"
        ],
        service_account_alias_sha256=hashes[
            "service_account_alias_sha256"
        ],
        task_definition_sha256=hashes["task_definition_sha256"],
        launcher_trust_policy_sha256=hashes[
            "launcher_trust_policy_sha256"
        ],
        minimum_retention_seconds=_integer(
            value.get("minimum_retention_seconds"),
            minimum=86_400,
            maximum=MAXIMUM_RETENTION_SECONDS,
            reason_code="CUSTODY_MINIMUM_RETENTION_SECONDS_INVALID",
        ),
        maximum_receipt_age_seconds=_integer(
            value.get("maximum_receipt_age_seconds"),
            minimum=1,
            maximum=300,
            reason_code="CUSTODY_MAXIMUM_RECEIPT_AGE_SECONDS_INVALID",
        ),
        maximum_launch_ttl_seconds=_integer(
            value.get("maximum_launch_ttl_seconds"),
            minimum=1,
            maximum=MAXIMUM_LAUNCH_TTL_SECONDS,
            reason_code="CUSTODY_MAXIMUM_LAUNCH_TTL_SECONDS_INVALID",
        ),
    )


def _decode_launch_proposal(payload: object) -> _LaunchProposal:
    if type(payload) is not bytes:
        _reject("LAUNCH_PROPOSAL_PAYLOAD_INVALID")
    value = _strict_object(payload, kind="LAUNCH_PROPOSAL")
    if (
        set(value) != _LAUNCH_PROPOSAL_FIELDS
        or value.get("schema_version") != LAUNCH_PROPOSAL_SCHEMA
    ):
        _reject("LAUNCH_PROPOSAL_SCHEMA_INVALID")
    _require_locked_safety(value, reason_code="LAUNCH_PROPOSAL_SAFETY_DRIFT")
    sequence = _integer(
        value.get("sequence"),
        minimum=1,
        maximum=2**63 - 1,
        reason_code="LAUNCH_PROPOSAL_SEQUENCE_INVALID",
    )
    predecessor = _sha_pin(
        value.get("predecessor_checkpoint_sha256"),
        "LAUNCH_PROPOSAL_PREDECESSOR_INVALID",
        allow_zero=True,
    )
    hashes: dict[str, str] = {}
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
        hashes[name] = _sha_pin(
            value.get(name),
            "LAUNCH_PROPOSAL_HASH_INVALID",
        )
    requested = _parse_utc(
        value.get("requested_at_utc"),
        "LAUNCH_PROPOSAL_TIME_INVALID",
    )
    expires = _parse_utc(
        value.get("expires_at_utc"),
        "LAUNCH_PROPOSAL_TIME_INVALID",
    )
    if (
        requested >= expires
        or expires - requested
        > timedelta(seconds=MAXIMUM_LAUNCH_TTL_SECONDS)
        or (sequence == 1) != (predecessor == ZERO_SHA256)
    ):
        _reject("LAUNCH_PROPOSAL_WINDOW_OR_PREDECESSOR_INVALID")
    return _LaunchProposal(
        canonical_payload=payload,
        content_sha256=_sha256(payload),
        sequence=sequence,
        predecessor_checkpoint_sha256=predecessor,
        custody_policy_sha256=hashes["custody_policy_sha256"],
        launcher_trust_policy_sha256=hashes[
            "launcher_trust_policy_sha256"
        ],
        launcher_nonce_sha256=hashes["launcher_nonce_sha256"],
        deployment_host_alias_sha256=hashes[
            "deployment_host_alias_sha256"
        ],
        service_account_alias_sha256=hashes[
            "service_account_alias_sha256"
        ],
        task_definition_sha256=hashes["task_definition_sha256"],
        requested_at_utc=requested,
        expires_at_utc=expires,
    )


def _decode_launch_checkpoint(payload: object) -> _LaunchCheckpoint:
    if type(payload) is not bytes:
        _reject("CHECKPOINT_DOCUMENT_INVALID")
    value = _strict_object(payload, kind="LAUNCH_CHECKPOINT")
    if (
        set(value) != _LAUNCH_CHECKPOINT_FIELDS
        or value.get("schema_version") != LAUNCH_CHECKPOINT_SCHEMA
        or value.get("signature_algorithm") != SIGNATURE_ALGORITHM
        or type(value.get("proposal")) is not dict
    ):
        _reject("CHECKPOINT_DOCUMENT_INVALID")
    _require_locked_safety(value, reason_code="CHECKPOINT_SAFETY_DRIFT")
    proposal_payload = _canonical_bytes(value["proposal"])
    proposal = _decode_launch_proposal(proposal_payload)
    proposal_sha256 = _sha_pin(
        value.get("proposal_sha256"),
        "CHECKPOINT_PROPOSAL_HASH_INVALID",
    )
    if proposal_sha256 != proposal.content_sha256:
        _reject("CHECKPOINT_PROPOSAL_HASH_MISMATCH")
    committed = _parse_utc(
        value.get("committed_at_utc"),
        "CHECKPOINT_TIME_INVALID",
    )
    if not proposal.requested_at_utc <= committed < proposal.expires_at_utc:
        _reject("CHECKPOINT_TIME_INVALID")
    return _LaunchCheckpoint(
        canonical_payload=payload,
        content_sha256=_sha256(payload),
        proposal=proposal,
        committed_at_utc=committed,
        custody_issuer_id=_identifier(
            value.get("custody_issuer_id"),
            "CHECKPOINT_AUTHORITY_INVALID",
        ),
        custody_key_id=_identifier(
            value.get("custody_key_id"),
            "CHECKPOINT_AUTHORITY_INVALID",
        ),
        public_key_fingerprint_sha256=_sha_pin(
            value.get("public_key_fingerprint_sha256"),
            "CHECKPOINT_AUTHORITY_INVALID",
        ),
        signature_rsa_pkcs1v15_sha256_hex=_signature(
            value.get("signature_rsa_pkcs1v15_sha256_hex"),
            allow_empty=False,
            reason_code="CHECKPOINT_SIGNATURE_INVALID",
        ),
    )


def _decode_launch_acknowledgement(
    payload: object,
) -> _LaunchAcknowledgement:
    if type(payload) is not bytes:
        _reject("ACKNOWLEDGEMENT_DOCUMENT_INVALID")
    value = _strict_object(payload, kind="LAUNCH_ACKNOWLEDGEMENT")
    if (
        set(value) != _LAUNCH_ACK_FIELDS
        or value.get("schema_version") != LAUNCH_ACK_SCHEMA
        or value.get("signature_algorithm") != SIGNATURE_ALGORITHM
    ):
        _reject("ACKNOWLEDGEMENT_DOCUMENT_INVALID")
    _require_locked_safety(
        value,
        reason_code="ACKNOWLEDGEMENT_SAFETY_DRIFT",
    )
    return _LaunchAcknowledgement(
        canonical_payload=payload,
        content_sha256=_sha256(payload),
        expected_predecessor_checkpoint_sha256=_sha_pin(
            value.get("expected_predecessor_checkpoint_sha256"),
            "ACKNOWLEDGEMENT_PREDECESSOR_INVALID",
            allow_zero=True,
        ),
        written_checkpoint_sha256=_sha_pin(
            value.get("written_checkpoint_sha256"),
            "ACKNOWLEDGEMENT_HASH_INVALID",
        ),
        proposal_sha256=_sha_pin(
            value.get("proposal_sha256"),
            "ACKNOWLEDGEMENT_HASH_INVALID",
        ),
        launcher_nonce_sha256=_sha_pin(
            value.get("launcher_nonce_sha256"),
            "ACKNOWLEDGEMENT_HASH_INVALID",
        ),
        sequence=_integer(
            value.get("sequence"),
            minimum=1,
            maximum=2**63 - 1,
            reason_code="ACKNOWLEDGEMENT_SEQUENCE_INVALID",
        ),
        acknowledged_at_utc=_parse_utc(
            value.get("acknowledged_at_utc"),
            "ACKNOWLEDGEMENT_TIME_INVALID",
        ),
        custody_issuer_id=_identifier(
            value.get("custody_issuer_id"),
            "ACKNOWLEDGEMENT_AUTHORITY_INVALID",
        ),
        custody_key_id=_identifier(
            value.get("custody_key_id"),
            "ACKNOWLEDGEMENT_AUTHORITY_INVALID",
        ),
        public_key_fingerprint_sha256=_sha_pin(
            value.get("public_key_fingerprint_sha256"),
            "ACKNOWLEDGEMENT_AUTHORITY_INVALID",
        ),
        signature_rsa_pkcs1v15_sha256_hex=_signature(
            value.get("signature_rsa_pkcs1v15_sha256_hex"),
            allow_empty=False,
            reason_code="ACKNOWLEDGEMENT_SIGNATURE_INVALID",
        ),
    )


def _document_signing_message(payload: bytes, *, domain: bytes) -> bytes:
    value = _strict_object(payload, kind="SIGNED_DOCUMENT")
    if "signature_rsa_pkcs1v15_sha256_hex" not in value:
        _reject("SIGNED_DOCUMENT_SIGNATURE_FIELD_MISSING")
    value.pop("signature_rsa_pkcs1v15_sha256_hex")
    return domain + _canonical_bytes(value)


def _require_locked_safety(
    value: Mapping[str, object],
    *,
    reason_code: str,
) -> None:
    expected = {
        "live_allowed": False,
        "execution_authorized": False,
        "bootstrap_authorized": False,
        "process_launch_authorized": False,
        "order_capability": ORDER_CAPABILITY,
    }
    if any(
        value.get(name) != expected_value
        for name, expected_value in expected.items()
    ):
        _reject(reason_code)


def _require_central_lock() -> None:
    if execution_policy.LIVE_ALLOWED is not False:
        _reject("CENTRAL_LIVE_LOCK_NOT_FALSE")
    allowed, reasons = execution_policy.execution_mode_policy_decision("LIVE")
    if allowed is not False or reasons != ("LIVE_MODE_LOCKED",):
        _reject("CENTRAL_LIVE_POLICY_DECISION_DRIFT")


def _nonce_response_values(
    response: Mapping[str, object],
    *,
    allow_empty_signature: bool,
) -> tuple[dict[str, object], datetime, datetime]:
    if not isinstance(response, Mapping):
        _reject("NONCE_RESPONSE_SCHEMA_INVALID")
    try:
        value = dict(response)
    except Exception:
        raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
            "NONCE_RESPONSE_SCHEMA_INVALID"
        ) from None
    if set(value) != _NONCE_RESPONSE_FIELDS:
        _reject("NONCE_RESPONSE_SCHEMA_INVALID")
    if value.get("schema_version") != NONCE_QUERY_RESPONSE_SCHEMA:
        _reject("NONCE_RESPONSE_SCHEMA_INVALID")
    for name in (
        "request_id",
        "request_sha256",
        "custody_policy_sha256",
        "worm_repository_alias_sha256",
        "launcher_nonce_sha256",
        "query_nonce_sha256",
        "public_key_fingerprint_sha256",
    ):
        _sha_pin(value.get(name), "NONCE_RESPONSE_HASH_INVALID")
    for name in ("expected_head_sha256", "observed_head_sha256"):
        _sha_pin(
            value.get(name),
            "NONCE_RESPONSE_HEAD_INVALID",
            allow_zero=True,
        )
    for name in ("provider_id", "custody_issuer_id", "custody_key_id"):
        _identifier(value.get(name), "NONCE_RESPONSE_IDENTITY_INVALID")
    if type(value.get("nonce_seen")) is not bool:
        _reject("NONCE_RESPONSE_STATE_INVALID")
    observed = _parse_utc(
        value.get("observed_at_utc"),
        "NONCE_RESPONSE_TIME_INVALID",
    )
    expires = _parse_utc(
        value.get("expires_at_utc"),
        "NONCE_RESPONSE_TIME_INVALID",
    )
    if observed >= expires:
        _reject("NONCE_RESPONSE_TIME_INVALID")
    if value.get("signature_algorithm") != SIGNATURE_ALGORITHM:
        _reject("NONCE_RESPONSE_SIGNATURE_ALGORITHM_INVALID")
    _signature(
        value.get("signature_rsa_pkcs1v15_sha256_hex"),
        allow_empty=allow_empty_signature,
    )
    _require_locked_safety(value, reason_code="NONCE_RESPONSE_SAFETY_DRIFT")
    return value, observed, expires


def live_canary_nonce_query_response_signing_message(
    response: Mapping[str, object],
) -> bytes:
    """Return the exact public RSA message for a nonce-query response."""

    value, _observed, _expires = _nonce_response_values(
        response,
        allow_empty_signature=True,
    )
    value.pop("signature_rsa_pkcs1v15_sha256_hex")
    return NONCE_QUERY_RESPONSE_SIGNATURE_DOMAIN + _canonical_bytes(value)


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return tuple(
        int(getattr(metadata, name, 0))
        for name in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_file_attributes",
        )
    )


def _directory_identity(path: Path, *, reason_code: str) -> tuple[int, ...]:
    if not path.is_absolute():
        _reject(reason_code)
    try:
        absolute = path.absolute()
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except Exception:
        raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
            reason_code
        ) from None
    if (
        resolved != absolute
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        _reject(reason_code)
    return tuple(
        int(getattr(metadata, name, 0))
        for name in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_file_attributes",
        )
    )


class WindowsLiveCanaryExternalCasDirectoryAdapter:
    """Three locked callbacks backed by an independent signed directory CAS."""

    __slots__ = (
        "_clock_provider",
        "_custody_policy",
        "_entropy_provider",
        "_last_clock",
        "_last_monotonic",
        "_lock",
        "_monotonic",
        "_provider_id",
        "_query_nonces",
        "_request_directory",
        "_request_directory_identity",
        "_response_directory",
        "_response_directory_identity",
        "_sleeper",
        "_timeout_seconds",
    )

    def __init__(
        self,
        *,
        provider_id: str,
        custody_policy_payload: bytes,
        expected_custody_policy_sha256: str,
        request_directory: str | Path,
        response_directory: str | Path,
        clock_provider: Callable[[], datetime],
        timeout_seconds: float,
        entropy_provider: Callable[[int], bytes] = os.urandom,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        _require_central_lock()
        provider = _identifier(provider_id, "PROVIDER_ID_INVALID")
        custody_policy = _decode_custody_policy(custody_policy_payload)
        expected_policy = _sha_pin(
            expected_custody_policy_sha256,
            "EXPECTED_CUSTODY_POLICY_SHA256_INVALID",
        )
        if custody_policy.content_sha256 != expected_policy:
            _reject("CUSTODY_POLICY_PIN_MISMATCH")
        for name, callback in (
            ("CLOCK_PROVIDER", clock_provider),
            ("ENTROPY_PROVIDER", entropy_provider),
            ("SLEEPER", sleeper),
            ("MONOTONIC_PROVIDER", monotonic),
        ):
            if not callable(callback):
                _reject(f"{name}_INVALID")
        if type(timeout_seconds) not in (int, float):
            _reject("RESPONSE_TIMEOUT_INVALID")
        try:
            timeout = float(timeout_seconds)
        except Exception:
            raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
                "RESPONSE_TIMEOUT_INVALID"
            ) from None
        if (
            not math.isfinite(timeout)
            or not 0.0 < timeout <= MAXIMUM_TIMEOUT_SECONDS
        ):
            _reject("RESPONSE_TIMEOUT_INVALID")

        try:
            request_root = Path(request_directory)
            responses = Path(response_directory)
        except Exception:
            raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
                "DIRECTORY_ARGUMENT_INVALID"
            ) from None
        request_identity = _directory_identity(
            request_root,
            reason_code="REQUEST_DIRECTORY_INVALID",
        )
        response_identity = _directory_identity(
            responses,
            reason_code="RESPONSE_DIRECTORY_INVALID",
        )
        if (
            os.path.normcase(str(request_root.absolute()))
            == os.path.normcase(str(responses.absolute()))
            or (
                request_identity[0:2] == response_identity[0:2]
                and request_identity[0:2] != (0, 0)
            )
        ):
            _reject("DIRECTORY_DOMAIN_COLLISION")
        _require_central_lock()

        self._provider_id = provider
        self._custody_policy = custody_policy
        self._request_directory = request_root.absolute()
        self._response_directory = responses.absolute()
        self._request_directory_identity = request_identity
        self._response_directory_identity = response_identity
        self._clock_provider = clock_provider
        self._entropy_provider = entropy_provider
        self._sleeper = sleeper
        self._monotonic = monotonic
        self._timeout_seconds = timeout
        self._last_clock: datetime | None = None
        self._last_monotonic: float | None = None
        self._query_nonces: set[str] = set()
        self._lock = threading.Lock()

    def _effect(
        self,
        callback: Callable[..., object],
        *,
        reason_code: str,
        args: tuple[object, ...] = (),
    ) -> object:
        _require_central_lock()
        try:
            result = callback(*args)
        except WindowsLiveCanaryExternalCasDirectoryAdapterError:
            _require_central_lock()
            raise
        except Exception:
            _require_central_lock()
            raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
                reason_code
            ) from None
        _require_central_lock()
        return result

    def _enter(self) -> None:
        _require_central_lock()
        if not self._lock.acquire(blocking=False):
            _reject("ADAPTER_BUSY")
        try:
            _require_central_lock()
        except Exception:
            self._lock.release()
            raise

    def _leave(self) -> None:
        self._lock.release()

    def _clock(self) -> datetime:
        observed = self._effect(
            self._clock_provider,
            reason_code="TRUSTED_CLOCK_UNAVAILABLE",
        )
        if type(observed) is not datetime:
            _reject("TRUSTED_CLOCK_VALUE_INVALID")
        current = _parse_utc(
            _utc_text(observed),
            "TRUSTED_CLOCK_VALUE_INVALID",
        )
        if self._last_clock is not None and current < self._last_clock:
            _reject("TRUSTED_CLOCK_REGRESSION")
        self._last_clock = current
        return current

    def _monotonic_now(self) -> float:
        observed = self._effect(
            self._monotonic,
            reason_code="MONOTONIC_CLOCK_UNAVAILABLE",
        )
        if isinstance(observed, bool):
            _reject("MONOTONIC_CLOCK_VALUE_INVALID")
        try:
            current = float(observed)
        except Exception:
            raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
                "MONOTONIC_CLOCK_VALUE_INVALID"
            ) from None
        if not math.isfinite(current):
            _reject("MONOTONIC_CLOCK_VALUE_INVALID")
        if (
            self._last_monotonic is not None
            and current < self._last_monotonic
        ):
            _reject("MONOTONIC_CLOCK_REGRESSION")
        self._last_monotonic = current
        return current

    def _sleep(self) -> None:
        self._effect(
            self._sleeper,
            reason_code="RESPONSE_WAIT_FAILED",
            args=(POLL_INTERVAL_SECONDS,),
        )

    def _check_root(self, *, request: bool) -> None:
        root = self._request_directory if request else self._response_directory
        expected = (
            self._request_directory_identity
            if request
            else self._response_directory_identity
        )
        reason = (
            "REQUEST_DIRECTORY_CHANGED"
            if request
            else "RESPONSE_DIRECTORY_CHANGED"
        )
        observed = self._effect(
            lambda: _directory_identity(root, reason_code=reason),
            reason_code=reason,
        )
        if observed != expected:
            _reject(reason)

    def _read_file(
        self,
        *,
        root: Path,
        name: str,
        missing_ok: bool,
    ) -> bytes | None:
        if (
            not name
            or "/" in name
            or "\\" in name
            or name in {".", ".."}
        ):
            _reject("RESPONSE_PATH_INVALID")
        self._check_root(request=root == self._request_directory)
        path = root / name
        if path.parent != root:
            _reject("RESPONSE_PATH_INVALID")
        _require_central_lock()
        try:
            first = path.lstat()
        except FileNotFoundError:
            _require_central_lock()
            if missing_ok:
                self._check_root(
                    request=root == self._request_directory
                )
                return None
            _reject("RESPONSE_FILE_MISSING")
        except OSError:
            _require_central_lock()
            raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
                "RESPONSE_PATH_INVALID"
            ) from None
        _require_central_lock()
        if (
            stat.S_ISLNK(first.st_mode)
            or not stat.S_ISREG(first.st_mode)
            or _is_reparse(first)
            or first.st_size <= 0
            or first.st_size > MAXIMUM_PACKET_BYTES
        ):
            _reject("RESPONSE_FILE_INVALID")

        flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
        flags |= int(getattr(os, "O_CLOEXEC", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        descriptor: int | None = None
        try:
            descriptor = self._effect(
                os.open,
                reason_code="RESPONSE_FILE_UNSTABLE",
                args=(path, flags),
            )
            if type(descriptor) is not int:
                _reject("RESPONSE_FILE_UNSTABLE")
            opened_before = self._effect(
                os.fstat,
                reason_code="RESPONSE_FILE_UNSTABLE",
                args=(descriptor,),
            )
            chunks: list[bytes] = []
            remaining = MAXIMUM_PACKET_BYTES + 1
            while remaining:
                chunk = self._effect(
                    os.read,
                    reason_code="RESPONSE_FILE_UNSTABLE",
                    args=(descriptor, min(remaining, 262_144)),
                )
                if type(chunk) is not bytes:
                    _reject("RESPONSE_FILE_UNSTABLE")
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            opened_after = self._effect(
                os.fstat,
                reason_code="RESPONSE_FILE_UNSTABLE",
                args=(descriptor,),
            )
            data = b"".join(chunks)
        finally:
            if descriptor is not None:
                self._effect(
                    os.close,
                    reason_code="RESPONSE_FILE_CLOSE_FAILED",
                    args=(descriptor,),
                )
        second = self._effect(
            path.lstat,
            reason_code="RESPONSE_FILE_UNSTABLE",
        )
        if (
            not isinstance(opened_before, os.stat_result)
            or not isinstance(opened_after, os.stat_result)
            or not isinstance(second, os.stat_result)
            or _metadata_identity(first) != _metadata_identity(opened_before)
            or _metadata_identity(first) != _metadata_identity(opened_after)
            or _metadata_identity(first) != _metadata_identity(second)
            or len(data) != first.st_size
            or len(data) > MAXIMUM_PACKET_BYTES
        ):
            _reject("RESPONSE_FILE_UNSTABLE")
        self._check_root(request=root == self._request_directory)
        return data

    def _sync_directory(self, root: Path) -> None:
        if os.name == "nt":
            _require_central_lock()
            return
        flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
        descriptor = self._effect(
            os.open,
            reason_code="REQUEST_DIRECTORY_SYNC_FAILED",
            args=(root, flags),
        )
        if type(descriptor) is not int:
            _reject("REQUEST_DIRECTORY_SYNC_FAILED")
        try:
            self._effect(
                os.fsync,
                reason_code="REQUEST_DIRECTORY_SYNC_FAILED",
                args=(descriptor,),
            )
        finally:
            self._effect(
                os.close,
                reason_code="REQUEST_DIRECTORY_SYNC_FAILED",
                args=(descriptor,),
            )

    def _write_request(
        self,
        *,
        name: str,
        payload: bytes,
        ambiguity_reason: str,
    ) -> None:
        if (
            type(payload) is not bytes
            or not payload
            or len(payload) > MAXIMUM_PACKET_BYTES
            or not name
            or "/" in name
            or "\\" in name
        ):
            _reject("REQUEST_DOCUMENT_INVALID")
        self._check_root(request=True)
        path = self._request_directory / name
        staging_name = f".{name}.pending"
        staging_path = self._request_directory / staging_name
        _require_central_lock()
        try:
            staging_path.lstat()
        except FileNotFoundError:
            _require_central_lock()
            self._check_root(request=True)
        except Exception:
            _require_central_lock()
            raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
                ambiguity_reason
            ) from None
        else:
            _require_central_lock()
            self._check_root(request=True)
            _reject(ambiguity_reason)
        existing = self._read_file(
            root=self._request_directory,
            name=name,
            missing_ok=True,
        )
        if existing is not None:
            if existing != payload:
                _reject("REQUEST_PUBLICATION_CONFLICT")
            return
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= int(getattr(os, "O_BINARY", 0))
        flags |= int(getattr(os, "O_CLOEXEC", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        descriptor: int | None = None
        try:
            _require_central_lock()
            try:
                descriptor = os.open(staging_path, flags, 0o600)
            except FileExistsError:
                _require_central_lock()
                _reject(ambiguity_reason)
            except Exception:
                _require_central_lock()
                raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
                    ambiguity_reason
                ) from None
            _require_central_lock()
            if type(descriptor) is not int:
                _reject(ambiguity_reason)
            offset = 0
            while offset < len(payload):
                written = self._effect(
                    os.write,
                    reason_code=ambiguity_reason,
                    args=(descriptor, payload[offset:]),
                )
                if type(written) is not int or written <= 0:
                    _reject(ambiguity_reason)
                offset += written
            self._effect(
                os.fsync,
                reason_code=ambiguity_reason,
                args=(descriptor,),
            )
        except WindowsLiveCanaryExternalCasDirectoryAdapterError:
            raise
        except Exception:
            raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
                ambiguity_reason
            ) from None
        finally:
            if descriptor is not None:
                self._effect(
                    os.close,
                    reason_code=ambiguity_reason,
                    args=(descriptor,),
                )
        staged = self._read_file(
            root=self._request_directory,
            name=staging_name,
            missing_ok=False,
        )
        if staged != payload:
            _reject(ambiguity_reason)

        final_won_race = False
        try:
            _require_central_lock()
            if os.name == "nt":
                os.rename(staging_path, path)
            else:
                os.link(staging_path, path, follow_symlinks=False)
        except FileExistsError:
            _require_central_lock()
            observed = self._read_file(
                root=self._request_directory,
                name=name,
                missing_ok=False,
            )
            if observed != payload:
                _reject("REQUEST_PUBLICATION_CONFLICT")
            final_won_race = True
        except Exception:
            _require_central_lock()
            raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
                ambiguity_reason
            ) from None
        _require_central_lock()
        self._sync_directory(self._request_directory)

        if os.name != "nt" or final_won_race:
            self._effect(
                os.unlink,
                reason_code=ambiguity_reason,
                args=(staging_path,),
            )
            self._sync_directory(self._request_directory)
        observed = self._read_file(
            root=self._request_directory,
            name=name,
            missing_ok=False,
        )
        if observed != payload:
            _reject(ambiguity_reason)

    def _verify_checkpoint(
        self,
        payload: bytes,
    ) -> _LaunchCheckpoint:
        try:
            checkpoint = _decode_launch_checkpoint(payload)
        except WindowsLiveCanaryExternalCasDirectoryAdapterError:
            raise
        except Exception:
            raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
                "CHECKPOINT_DOCUMENT_INVALID"
            ) from None
        policy = self._custody_policy
        if (
            checkpoint.custody_issuer_id != policy.custody_issuer_id
            or checkpoint.custody_key_id != policy.custody_key_id
            or checkpoint.public_key_fingerprint_sha256
            != policy.public_key_fingerprint_sha256
            or checkpoint.proposal.custody_policy_sha256
            != policy.content_sha256
        ):
            _reject("CHECKPOINT_AUTHORITY_MISMATCH")
        if len(checkpoint.signature_rsa_pkcs1v15_sha256_hex) != len(
            policy.rsa_modulus_hex
        ):
            _reject("CHECKPOINT_SIGNATURE_INVALID")
        if not verify_rsa_pkcs1v15_sha256(
            modulus_hex=policy.rsa_modulus_hex,
            exponent=policy.rsa_exponent,
            message=_document_signing_message(
                checkpoint.canonical_payload,
                domain=LAUNCH_CHECKPOINT_SIGNATURE_DOMAIN,
            ),
            signature_hex=checkpoint.signature_rsa_pkcs1v15_sha256_hex,
        ):
            _reject("CHECKPOINT_SIGNATURE_INVALID")
        return checkpoint

    def _verify_acknowledgement(
        self,
        payload: bytes,
    ) -> _LaunchAcknowledgement:
        try:
            acknowledgement = _decode_launch_acknowledgement(payload)
        except WindowsLiveCanaryExternalCasDirectoryAdapterError:
            raise
        except Exception:
            raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
                "ACKNOWLEDGEMENT_DOCUMENT_INVALID"
            ) from None
        policy = self._custody_policy
        if (
            acknowledgement.custody_issuer_id != policy.custody_issuer_id
            or acknowledgement.custody_key_id != policy.custody_key_id
            or acknowledgement.public_key_fingerprint_sha256
            != policy.public_key_fingerprint_sha256
        ):
            _reject("ACKNOWLEDGEMENT_AUTHORITY_MISMATCH")
        if len(
            acknowledgement.signature_rsa_pkcs1v15_sha256_hex
        ) != len(policy.rsa_modulus_hex):
            _reject("ACKNOWLEDGEMENT_SIGNATURE_INVALID")
        if not verify_rsa_pkcs1v15_sha256(
            modulus_hex=policy.rsa_modulus_hex,
            exponent=policy.rsa_exponent,
            message=_document_signing_message(
                acknowledgement.canonical_payload,
                domain=LAUNCH_ACKNOWLEDGEMENT_SIGNATURE_DOMAIN,
            ),
            signature_hex=acknowledgement.signature_rsa_pkcs1v15_sha256_hex,
        ):
            _reject("ACKNOWLEDGEMENT_SIGNATURE_INVALID")
        return acknowledgement

    def _read_head(self) -> tuple[bytes | None, str]:
        payload = self._read_file(
            root=self._response_directory,
            name=CURRENT_CHECKPOINT_NAME,
            missing_ok=True,
        )
        if payload is None:
            return None, ZERO_SHA256
        checkpoint = self._verify_checkpoint(payload)
        if _sha256(payload) != checkpoint.content_sha256:
            _reject("CHECKPOINT_CONTENT_HASH_MISMATCH")
        return payload, checkpoint.content_sha256

    def checkpoint_provider(self) -> bytes | None:
        """Return the exact signed current head or ``None`` at genesis."""

        self._enter()
        try:
            payload, _head_sha256 = self._read_head()
            _require_central_lock()
            return payload
        finally:
            self._leave()

    def _poll_response(
        self,
        *,
        name: str,
        expires_at_utc: datetime,
        timeout_reason: str,
    ) -> bytes:
        deadline = self._monotonic_now() + self._timeout_seconds
        while True:
            response = self._read_file(
                root=self._response_directory,
                name=name,
                missing_ok=True,
            )
            if response is not None:
                return response
            if (
                self._clock() >= expires_at_utc
                or self._monotonic_now() >= deadline
            ):
                _reject(timeout_reason)
            self._sleep()

    def _nonce_request(
        self,
        *,
        launcher_nonce_sha256: str,
        expected_head_sha256: str,
    ) -> tuple[dict[str, object], bytes, datetime]:
        entropy = self._effect(
            self._entropy_provider,
            reason_code="QUERY_ENTROPY_UNAVAILABLE",
            args=(32,),
        )
        if type(entropy) is not bytes or len(entropy) != 32:
            _reject("QUERY_ENTROPY_INVALID")
        query_nonce_sha256 = _sha256(entropy)
        if query_nonce_sha256 in self._query_nonces:
            _reject("QUERY_NONCE_REUSED")
        self._query_nonces.add(query_nonce_sha256)
        issued = self._clock()
        expires = issued + timedelta(seconds=self._timeout_seconds)
        identity = {
            "provider_id": self._provider_id,
            "custody_policy_sha256": self._custody_policy.content_sha256,
            "worm_repository_alias_sha256": (
                self._custody_policy.worm_repository_alias_sha256
            ),
            "launcher_nonce_sha256": launcher_nonce_sha256,
            "expected_head_sha256": expected_head_sha256,
            "query_nonce_sha256": query_nonce_sha256,
            "issued_at_utc": _utc_text(issued),
        }
        request_id = _sha256(_canonical_bytes(identity))
        request = {
            "schema_version": NONCE_QUERY_REQUEST_SCHEMA,
            "request_id": request_id,
            **identity,
            "expires_at_utc": _utc_text(expires),
            "live_allowed": False,
            "execution_authorized": False,
            "bootstrap_authorized": False,
            "process_launch_authorized": False,
            "order_capability": ORDER_CAPABILITY,
        }
        payload = _canonical_bytes(request)
        if set(request) != _NONCE_REQUEST_FIELDS:
            _reject("NONCE_QUERY_REQUEST_SCHEMA_INVALID")
        return request, payload, expires

    def _verify_nonce_response(
        self,
        *,
        request: Mapping[str, object],
        request_payload: bytes,
        response_payload: bytes,
    ) -> bool:
        raw = _strict_object(response_payload, kind="NONCE_RESPONSE")
        response, observed, expires = _nonce_response_values(
            raw,
            allow_empty_signature=False,
        )
        expected = (
            (response["request_id"], request["request_id"]),
            (response["request_sha256"], _sha256(request_payload)),
            (response["provider_id"], self._provider_id),
            (
                response["custody_policy_sha256"],
                self._custody_policy.content_sha256,
            ),
            (
                response["worm_repository_alias_sha256"],
                self._custody_policy.worm_repository_alias_sha256,
            ),
            (
                response["launcher_nonce_sha256"],
                request["launcher_nonce_sha256"],
            ),
            (
                response["expected_head_sha256"],
                request["expected_head_sha256"],
            ),
            (
                response["observed_head_sha256"],
                request["expected_head_sha256"],
            ),
            (
                response["query_nonce_sha256"],
                request["query_nonce_sha256"],
            ),
            (response["expires_at_utc"], request["expires_at_utc"]),
            (
                response["custody_issuer_id"],
                self._custody_policy.custody_issuer_id,
            ),
            (
                response["custody_key_id"],
                self._custody_policy.custody_key_id,
            ),
            (
                response["public_key_fingerprint_sha256"],
                self._custody_policy.public_key_fingerprint_sha256,
            ),
        )
        if any(left != right for left, right in expected):
            _reject("NONCE_RESPONSE_BINDING_MISMATCH")
        issued = _parse_utc(
            request["issued_at_utc"],
            "NONCE_QUERY_REQUEST_TIME_INVALID",
        )
        if observed < issued or observed >= expires:
            _reject("NONCE_RESPONSE_TIME_INVALID")
        current = self._clock()
        if current >= expires or observed > current + timedelta(seconds=1):
            _reject("NONCE_RESPONSE_NOT_CURRENT")
        if len(
            str(response["signature_rsa_pkcs1v15_sha256_hex"])
        ) != len(self._custody_policy.rsa_modulus_hex):
            _reject("NONCE_RESPONSE_SIGNATURE_INVALID")
        if not verify_rsa_pkcs1v15_sha256(
            modulus_hex=self._custody_policy.rsa_modulus_hex,
            exponent=self._custody_policy.rsa_exponent,
            message=live_canary_nonce_query_response_signing_message(
                response
            ),
            signature_hex=str(
                response["signature_rsa_pkcs1v15_sha256_hex"]
            ),
        ):
            _reject("NONCE_RESPONSE_SIGNATURE_INVALID")
        return bool(response["nonce_seen"])

    def nonce_seen_provider(self, launcher_nonce_sha256: str) -> bool:
        """Return one fresh signed external observation for a launcher nonce."""

        self._enter()
        try:
            nonce = _sha_pin(
                launcher_nonce_sha256,
                "LAUNCHER_NONCE_SHA256_INVALID",
            )
            _head_payload, head_sha256 = self._read_head()
            request, request_payload, expires = self._nonce_request(
                launcher_nonce_sha256=nonce,
                expected_head_sha256=head_sha256,
            )
            request_id = str(request["request_id"])
            self._write_request(
                name=f"{request_id}.nonce-request.json",
                payload=request_payload,
                ambiguity_reason="NONCE_QUERY_PUBLICATION_AMBIGUOUS",
            )
            response_payload = self._poll_response(
                name=f"{request_id}.nonce-response.json",
                expires_at_utc=expires,
                timeout_reason="NONCE_RESPONSE_TIMEOUT_AMBIGUOUS",
            )
            result = self._verify_nonce_response(
                request=request,
                request_payload=request_payload,
                response_payload=response_payload,
            )
            _require_central_lock()
            return result
        finally:
            self._leave()

    def _cas_request(
        self,
        *,
        expected_predecessor_checkpoint_sha256: str,
        proposal: _LaunchProposal,
    ) -> tuple[dict[str, object], bytes]:
        identity = {
            "provider_id": self._provider_id,
            "custody_policy_sha256": self._custody_policy.content_sha256,
            "worm_repository_alias_sha256": (
                self._custody_policy.worm_repository_alias_sha256
            ),
            "expected_predecessor_checkpoint_sha256": (
                expected_predecessor_checkpoint_sha256
            ),
            "proposal_sha256": proposal.content_sha256,
        }
        request_id = _sha256(_canonical_bytes(identity))
        request = {
            "schema_version": CAS_REQUEST_SCHEMA,
            "request_id": request_id,
            **identity,
            "proposal": _strict_object(
                proposal.canonical_payload,
                kind="LAUNCH_PROPOSAL",
            ),
            "issued_at_utc": _utc_text(proposal.requested_at_utc),
            "expires_at_utc": _utc_text(proposal.expires_at_utc),
            "live_allowed": False,
            "execution_authorized": False,
            "bootstrap_authorized": False,
            "process_launch_authorized": False,
            "order_capability": ORDER_CAPABILITY,
        }
        if set(request) != _CAS_REQUEST_FIELDS:
            _reject("CAS_REQUEST_SCHEMA_INVALID")
        return request, _canonical_bytes(request)

    def _verify_cas_response(
        self,
        *,
        request: Mapping[str, object],
        request_payload: bytes,
        proposal: _LaunchProposal,
        response_payload: bytes,
    ) -> tuple[bytes, bytes]:
        response = _strict_object(response_payload, kind="CAS_RESPONSE")
        if (
            set(response) != _CAS_RESPONSE_FIELDS
            or response.get("schema_version") != CAS_RESPONSE_SCHEMA
        ):
            _reject("CAS_RESPONSE_SCHEMA_INVALID")
        expected = (
            (response.get("request_id"), request["request_id"]),
            (response.get("request_sha256"), _sha256(request_payload)),
            (response.get("provider_id"), self._provider_id),
            (
                response.get("custody_policy_sha256"),
                self._custody_policy.content_sha256,
            ),
            (
                response.get("worm_repository_alias_sha256"),
                self._custody_policy.worm_repository_alias_sha256,
            ),
        )
        if any(left != right for left, right in expected):
            _reject("CAS_RESPONSE_BINDING_MISMATCH")
        if type(response.get("checkpoint")) is not dict or type(
            response.get("acknowledgement")
        ) is not dict:
            _reject("CAS_RESPONSE_SCHEMA_INVALID")
        checkpoint_payload = _canonical_bytes(response["checkpoint"])
        acknowledgement_payload = _canonical_bytes(
            response["acknowledgement"]
        )
        checkpoint = self._verify_checkpoint(checkpoint_payload)
        acknowledgement = self._verify_acknowledgement(
            acknowledgement_payload
        )
        if (
            checkpoint.proposal.canonical_payload
            != proposal.canonical_payload
        ):
            _reject("CAS_RESPONSE_PROPOSAL_MISMATCH")
        expected_ack = (
            (
                acknowledgement.expected_predecessor_checkpoint_sha256,
                request["expected_predecessor_checkpoint_sha256"],
            ),
            (
                acknowledgement.written_checkpoint_sha256,
                checkpoint.content_sha256,
            ),
            (acknowledgement.proposal_sha256, proposal.content_sha256),
            (
                acknowledgement.launcher_nonce_sha256,
                proposal.launcher_nonce_sha256,
            ),
            (acknowledgement.sequence, proposal.sequence),
        )
        if any(left != right for left, right in expected_ack):
            _reject("CAS_RESPONSE_ACKNOWLEDGEMENT_MISMATCH")
        responded = _parse_utc(
            response.get("responded_at_utc"),
            "CAS_RESPONSE_TIME_INVALID",
        )
        if not (
            proposal.requested_at_utc
            <= checkpoint.committed_at_utc
            <= acknowledgement.acknowledged_at_utc
            <= responded
            < proposal.expires_at_utc
        ):
            _reject("CAS_RESPONSE_TIME_INVALID")
        if self._clock() >= proposal.expires_at_utc:
            _reject("CAS_RESPONSE_EXPIRED")
        return checkpoint_payload, acknowledgement_payload

    def checkpoint_cas(
        self,
        expected_predecessor_checkpoint_sha256: str,
        proposal_payload: bytes,
    ) -> tuple[bytes, bytes]:
        """Publish one CAS request and return its exact signed pair."""

        self._enter()
        try:
            expected_predecessor = _sha_pin(
                expected_predecessor_checkpoint_sha256,
                "EXPECTED_PREDECESSOR_CHECKPOINT_SHA256_INVALID",
                allow_zero=True,
            )
            if type(proposal_payload) is not bytes:
                _reject("LAUNCH_PROPOSAL_PAYLOAD_INVALID")
            try:
                proposal = _decode_launch_proposal(proposal_payload)
            except WindowsLiveCanaryExternalCasDirectoryAdapterError:
                raise
            except Exception:
                raise WindowsLiveCanaryExternalCasDirectoryAdapterError(
                    "LAUNCH_PROPOSAL_DOCUMENT_INVALID"
                ) from None
            if (
                proposal.custody_policy_sha256
                != self._custody_policy.content_sha256
                or proposal.predecessor_checkpoint_sha256
                != expected_predecessor
                or proposal.launcher_trust_policy_sha256
                != self._custody_policy.launcher_trust_policy_sha256
                or proposal.deployment_host_alias_sha256
                != self._custody_policy.deployment_host_alias_sha256
                or proposal.service_account_alias_sha256
                != self._custody_policy.service_account_alias_sha256
                or proposal.task_definition_sha256
                != self._custody_policy.task_definition_sha256
                or proposal.expires_at_utc - proposal.requested_at_utc
                > timedelta(
                    seconds=self._custody_policy.maximum_launch_ttl_seconds
                )
            ):
                _reject("LAUNCH_PROPOSAL_BINDING_MISMATCH")
            _head_payload, observed_head = self._read_head()
            if observed_head != expected_predecessor:
                _reject("EXTERNAL_CHECKPOINT_PIN_MISMATCH")
            current = self._clock()
            if current < proposal.requested_at_utc - timedelta(seconds=1):
                _reject("LAUNCH_PROPOSAL_FROM_FUTURE")
            if current >= proposal.expires_at_utc:
                _reject("LAUNCH_PROPOSAL_EXPIRED")
            request, request_payload = self._cas_request(
                expected_predecessor_checkpoint_sha256=expected_predecessor,
                proposal=proposal,
            )
            request_id = str(request["request_id"])
            self._write_request(
                name=f"{request_id}.cas-request.json",
                payload=request_payload,
                ambiguity_reason="CAS_REQUEST_PUBLICATION_AMBIGUOUS",
            )
            response_payload = self._poll_response(
                name=f"{request_id}.cas-response.json",
                expires_at_utc=proposal.expires_at_utc,
                timeout_reason="CAS_RESPONSE_TIMEOUT_AMBIGUOUS",
            )
            result = self._verify_cas_response(
                request=request,
                request_payload=request_payload,
                proposal=proposal,
                response_payload=response_payload,
            )
            _require_central_lock()
            return result
        finally:
            self._leave()


__all__ = [
    "CAS_REQUEST_SCHEMA",
    "CAS_RESPONSE_SCHEMA",
    "CURRENT_CHECKPOINT_NAME",
    "MAXIMUM_PACKET_BYTES",
    "MAXIMUM_TIMEOUT_SECONDS",
    "NONCE_QUERY_REQUEST_SCHEMA",
    "NONCE_QUERY_RESPONSE_SCHEMA",
    "NONCE_QUERY_RESPONSE_SIGNATURE_DOMAIN",
    "ORDER_CAPABILITY",
    "POLL_INTERVAL_SECONDS",
    "WindowsLiveCanaryExternalCasDirectoryAdapter",
    "WindowsLiveCanaryExternalCasDirectoryAdapterError",
    "live_canary_nonce_query_response_signing_message",
]
