"""Strict one-use handoff consumer for a provider-bound LIVE session.

The module owns public verification only.  A distinct external replay service
must consume each signed handoff atomically before the existing sealed,
launch-only session can be reconstructed.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields as dataclass_fields
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import secrets
from typing import Any, Callable, cast

import execution_policy

from .asymmetric_release_trust import (
    MAXIMUM_RSA_BITS,
    MINIMUM_RSA_BITS,
    SIGNATURE_ALGORITHM,
    rsa_public_key_fingerprint_sha256,
    verify_rsa_pkcs1v15_sha256,
)
from .contracts import canonical_json
from .live_canary_provider_bound_runtime_session import (
    LiveCanaryProviderBoundRuntimeLaunchSession,
    PROVIDER_BOUND_RUNTIME_LAUNCH_SESSION_SCHEMA,
    is_live_canary_provider_bound_runtime_launch_session,
)
from .live_canary_runtime_authority import _SESSION_SEAL
from .live_canary_runtime_candidate import (
    LiveCanaryRuntimeCandidate,
    is_live_canary_runtime_candidate,
)


UTC = timezone.utc
HANDOFF_POLICY_SCHEMA = (
    "live-canary-provider-bound-runtime-session-handoff-policy-v1"
)
HANDOFF_DOCUMENT_SCHEMA = (
    "live-canary-provider-bound-runtime-session-handoff-v1"
)
REPLAY_REQUEST_SCHEMA = (
    "live-canary-provider-bound-runtime-session-consumption-request-v1"
)
REPLAY_RECEIPT_SCHEMA = (
    "live-canary-provider-bound-runtime-session-consumption-receipt-v1"
)
ORDER_CAPABILITY = "GATED_PRESENT"
MAXIMUM_DOCUMENT_BYTES = 1024 * 1024
MAXIMUM_HANDOFF_TTL_SECONDS = 60
MAXIMUM_REPLAY_REQUEST_TTL_SECONDS = 5

_HANDOFF_SIGNATURE_DOMAIN = (
    b"AI_SCALPER:LIVE_CANARY:PROVIDER_BOUND_RUNTIME_SESSION_HANDOFF:v1\x00"
)
_REPLAY_RECEIPT_SIGNATURE_DOMAIN = (
    b"AI_SCALPER:LIVE_CANARY:PROVIDER_BOUND_RUNTIME_SESSION_CONSUMPTION_"
    b"RECEIPT:v1\x00"
)
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_LOWER_HEX = re.compile(r"^[0-9a-f]+$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")

_POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "policy_id",
        "handoff_issuer_id",
        "handoff_key_id",
        "handoff_rsa_modulus_hex",
        "handoff_rsa_exponent",
        "handoff_public_key_fingerprint_sha256",
        "replay_issuer_id",
        "replay_key_id",
        "replay_rsa_modulus_hex",
        "replay_rsa_exponent",
        "replay_public_key_fingerprint_sha256",
        "replay_ledger_alias_sha256",
        "execution_release_identity_sha256",
        "target_host_identity_sha256",
        "installed_environment_sha256",
        "deployment_host_alias_sha256",
        "service_account_alias_sha256",
        "launcher_task_definition_sha256",
        "live_execution_task_definition_sha256",
        "reserved_authority_key_ids",
        "reserved_authority_fingerprints_sha256",
        "maximum_handoff_ttl_seconds",
        "maximum_replay_request_ttl_seconds",
        "signature_algorithm",
        "central_unlock_required",
        "session_reconstruction_authorized",
        "direct_execution_authorized",
        "broker_mutation_authorized",
        "order_capability",
    }
)
_HANDOFF_FIELDS = frozenset(
    {
        "schema_version",
        "handoff_id",
        "handoff_policy_sha256",
        "candidate_sha256",
        "session_sha256",
        "session",
        "handoff_nonce_sha256",
        "issued_at_utc",
        "not_before_utc",
        "expires_at_utc",
        "execution_release_identity_sha256",
        "target_host_identity_sha256",
        "installed_environment_sha256",
        "deployment_host_alias_sha256",
        "service_account_alias_sha256",
        "launcher_task_definition_sha256",
        "live_execution_task_definition_sha256",
        "handoff_issuer_id",
        "handoff_key_id",
        "handoff_public_key_fingerprint_sha256",
        "central_unlock_required",
        "session_reconstruction_authorized",
        "direct_execution_authorized",
        "broker_mutation_authorized",
        "order_capability",
        "signature_algorithm",
        "signature_rsa_pkcs1v15_sha256_hex",
    }
)
_REPLAY_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "handoff_id",
        "handoff_policy_sha256",
        "handoff_sha256",
        "candidate_sha256",
        "session_sha256",
        "handoff_nonce_sha256",
        "challenge_sha256",
        "replay_ledger_alias_sha256",
        "execution_release_identity_sha256",
        "target_host_identity_sha256",
        "installed_environment_sha256",
        "deployment_host_alias_sha256",
        "service_account_alias_sha256",
        "launcher_task_definition_sha256",
        "live_execution_task_definition_sha256",
        "requested_at_utc",
        "expires_at_utc",
        "central_unlock_required",
        "session_reconstruction_authorized",
        "direct_execution_authorized",
        "broker_mutation_authorized",
        "order_capability",
    }
)
_REPLAY_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "consumption_id",
        "consumption_sequence",
        "request_sha256",
        "handoff_id",
        "handoff_policy_sha256",
        "handoff_sha256",
        "candidate_sha256",
        "session_sha256",
        "handoff_nonce_sha256",
        "challenge_sha256",
        "replay_ledger_alias_sha256",
        "execution_release_identity_sha256",
        "target_host_identity_sha256",
        "installed_environment_sha256",
        "deployment_host_alias_sha256",
        "service_account_alias_sha256",
        "launcher_task_definition_sha256",
        "live_execution_task_definition_sha256",
        "consumed_at_utc",
        "expires_at_utc",
        "replay_issuer_id",
        "replay_key_id",
        "replay_public_key_fingerprint_sha256",
        "consumed_once",
        "central_unlock_required",
        "session_reconstruction_authorized",
        "direct_execution_authorized",
        "broker_mutation_authorized",
        "order_capability",
        "signature_algorithm",
        "signature_rsa_pkcs1v15_sha256_hex",
    }
)
_SESSION_FIELDS = frozenset(
    item.name
    for item in dataclass_fields(LiveCanaryProviderBoundRuntimeLaunchSession)
    if not item.name.startswith("_")
)
_SESSION_INIT_FIELDS = tuple(
    item.name
    for item in dataclass_fields(LiveCanaryProviderBoundRuntimeLaunchSession)
    if item.init and not item.name.startswith("_")
)
_SESSION_TIME_FIELDS = frozenset(
    {
        "activated_at_utc",
        "valid_until_utc",
        "provider_acceptance_valid_until_utc",
        "provider_bound_custody_valid_until_utc",
    }
)
_SESSION_FIXED_FIELDS: dict[str, object] = {
    "external_checkpoint_observations": 2,
    "external_nonce_observations": 2,
    "symbol": "XAUUSD",
    "max_lot": 0.01,
    "max_concurrent_positions": 1,
    "central_live_policy_enabled": True,
    "launch_reservation_consumed_once": True,
    "launch_capability_activation_consumed_once": True,
    "provider_bound_admission_verified": True,
    "provider_bound_custody_verified": True,
    "bootstrap_authorized": True,
    "process_launch_authorized": True,
    "live_allowed": True,
    "execution_authorized": False,
    "broker_mutation_authorized": False,
    "independent_per_order_authorization_required": True,
    "signed_promotion_evidence_required": True,
    "risk_and_news_guards_required": True,
    "durable_journal_lease_required": True,
    "final_mt5_submission_guard_required": True,
    "safe_to_demo_auto_order": False,
    "order_capability": ORDER_CAPABILITY,
    "schema_version": PROVIDER_BOUND_RUNTIME_LAUNCH_SESSION_SCHEMA,
}


class LiveCanaryProviderBoundRuntimeSessionHandoffError(RuntimeError):
    """A public handoff invariant failed with one stable reason code."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: object) -> None:
        normalized = re.sub(
            r"[^A-Z0-9_]+",
            "_",
            str(reason_code or "").strip().upper(),
        ).strip("_")
        self.reason_code = normalized or "RUNTIME_SESSION_HANDOFF_INVALID"
        super().__init__(self.reason_code)


def _reject(reason_code: str) -> None:
    raise LiveCanaryProviderBoundRuntimeSessionHandoffError(reason_code)


def _canonical_document(value: object) -> bytes:
    try:
        return canonical_json(value).encode("utf-8") + b"\n"
    except (RecursionError, TypeError, ValueError, UnicodeError) as exc:
        raise LiveCanaryProviderBoundRuntimeSessionHandoffError(
            "DOCUMENT_CANONICALIZATION_FAILED"
        ) from exc


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _reject("DOCUMENT_DUPLICATE_KEY")
        value[key] = item
    return value


def _reject_nonfinite(_value: str) -> None:
    _reject("DOCUMENT_NONFINITE_VALUE")


def _strict_document(
    payload: object,
    *,
    expected_fields: frozenset[str],
    kind: str,
) -> dict[str, Any]:
    if type(payload) is not bytes:
        _reject(f"{kind}_BYTES_INVALID")
    raw = cast(bytes, payload)
    if not raw or len(raw) > MAXIMUM_DOCUMENT_BYTES:
        _reject(f"{kind}_SIZE_INVALID")
    if not raw.endswith(b"\n") or b"\n" in raw[:-1] or b"\r" in raw:
        _reject(f"{kind}_TERMINATOR_INVALID")
    try:
        decoded = raw[:-1].decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_closed_object,
            parse_constant=_reject_nonfinite,
        )
    except LiveCanaryProviderBoundRuntimeSessionHandoffError:
        raise
    except (
        RecursionError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        raise LiveCanaryProviderBoundRuntimeSessionHandoffError(
            f"{kind}_JSON_INVALID"
        ) from exc
    if type(value) is not dict:
        _reject(f"{kind}_OBJECT_INVALID")
    result = cast(dict[str, Any], value)
    if frozenset(result) != expected_fields:
        _reject(f"{kind}_FIELDS_INVALID")
    if _canonical_document(result) != raw:
        _reject(f"{kind}_NONCANONICAL")
    return result


def _text(name: str, value: object) -> str:
    if type(value) is not str:
        _reject(f"{name}_INVALID")
    normalized = cast(str, value)
    if (
        not normalized
        or normalized != normalized.strip()
        or "\x00" in normalized
    ):
        _reject(f"{name}_INVALID")
    return normalized


def _identifier(name: str, value: object) -> str:
    normalized = _text(name, value)
    if _IDENTIFIER.fullmatch(normalized) is None:
        _reject(f"{name}_INVALID")
    return normalized


def _sha256(name: str, value: object) -> str:
    if (
        type(value) is not str
        or _HEX_64.fullmatch(cast(str, value)) is None
        or value == "0" * 64
    ):
        _reject(f"{name}_INVALID")
    return cast(str, value)


def _bounded_int(
    name: str,
    value: object,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int:
        _reject(f"{name}_INVALID")
    normalized = cast(int, value)
    if not minimum <= normalized <= maximum:
        _reject(f"{name}_INVALID")
    return normalized


def _canonical_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _utc(name: str, value: object) -> datetime:
    if type(value) is not str or not cast(str, value).endswith("Z"):
        _reject(f"{name}_INVALID")
    try:
        parsed = datetime.fromisoformat(cast(str, value)[:-1] + "+00:00")
    except (TypeError, ValueError) as exc:
        raise LiveCanaryProviderBoundRuntimeSessionHandoffError(
            f"{name}_INVALID"
        ) from exc
    if (
        type(parsed) is not datetime
        or parsed.tzinfo is None
        or parsed.utcoffset() != timedelta(0)
        or _canonical_utc(parsed) != value
    ):
        _reject(f"{name}_INVALID")
    return parsed


def _signature(name: str, value: object, *, allow_empty: bool) -> str:
    if allow_empty and value == "":
        return ""
    if (
        type(value) is not str
        or len(cast(str, value)) % 2 != 0
        or _LOWER_HEX.fullmatch(cast(str, value)) is None
    ):
        _reject(f"{name}_INVALID")
    return cast(str, value)


def _fixed_safety(value: dict[str, Any], *, kind: str) -> None:
    if (
        value.get("central_unlock_required") is not True
        or value.get("session_reconstruction_authorized") is not True
        or value.get("direct_execution_authorized") is not False
        or value.get("broker_mutation_authorized") is not False
        or value.get("order_capability") != ORDER_CAPABILITY
    ):
        _reject(f"{kind}_SAFETY_DRIFT")


def _require_central_live_policy() -> None:
    if execution_policy.LIVE_ALLOWED is not True:
        _reject("CENTRAL_LIVE_LOCK_NOT_ENABLED")
    if execution_policy.SAFE_TO_DEMO_AUTO_ORDER is not False:
        _reject("CENTRAL_EXECUTION_POLICY_MUTUAL_EXCLUSION_FAILED")
    allowed, reasons = execution_policy.execution_mode_policy_decision("LIVE")
    if allowed is not True or reasons != ():
        _reject("CENTRAL_LIVE_POLICY_DECISION_INVALID")


def _trusted_clock(clock_provider: Callable[[], datetime]) -> datetime:
    try:
        value = clock_provider()
    except Exception:
        raise LiveCanaryProviderBoundRuntimeSessionHandoffError(
            "TRUSTED_CLOCK_PROVIDER_FAILED"
        ) from None
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        _reject("TRUSTED_CLOCK_INVALID")
    return value


def _rsa_key(
    *,
    prefix: str,
    modulus_hex: object,
    exponent: object,
    fingerprint: object,
) -> tuple[str, int, str]:
    modulus = _text(f"{prefix}_RSA_MODULUS_HEX", modulus_hex)
    if (
        _LOWER_HEX.fullmatch(modulus) is None
        or len(modulus) % 2 != 0
        or modulus.startswith("00")
    ):
        _reject(f"{prefix}_RSA_MODULUS_INVALID")
    modulus_int = int(modulus, 16)
    if (
        not MINIMUM_RSA_BITS <= modulus_int.bit_length() <= MAXIMUM_RSA_BITS
        or modulus_int % 2 == 0
    ):
        _reject(f"{prefix}_RSA_MODULUS_INVALID")
    normalized_exponent = _bounded_int(
        f"{prefix}_RSA_EXPONENT",
        exponent,
        minimum=65537,
        maximum=65537,
    )
    normalized_fingerprint = _sha256(
        f"{prefix}_PUBLIC_KEY_FINGERPRINT_SHA256",
        fingerprint,
    )
    if normalized_fingerprint != rsa_public_key_fingerprint_sha256(
        modulus,
        normalized_exponent,
    ):
        _reject(f"{prefix}_PUBLIC_KEY_FINGERPRINT_MISMATCH")
    return modulus, normalized_exponent, normalized_fingerprint


def _sorted_identifiers(name: str, value: object) -> tuple[str, ...]:
    if type(value) is not list:
        _reject(f"{name}_INVALID")
    normalized = tuple(
        _identifier(name, item) for item in cast(list[object], value)
    )
    if not normalized or normalized != tuple(sorted(set(normalized))):
        _reject(f"{name}_INVALID")
    return normalized


def _sorted_hashes(name: str, value: object) -> tuple[str, ...]:
    if type(value) is not list:
        _reject(f"{name}_INVALID")
    normalized = tuple(_sha256(name, item) for item in cast(list[object], value))
    if not normalized or normalized != tuple(sorted(set(normalized))):
        _reject(f"{name}_INVALID")
    return normalized


@dataclass(frozen=True, slots=True)
class LiveCanaryProviderBoundRuntimeSessionHandoffPolicy:
    """Exact public handoff and replay authority policy."""

    policy_id: str
    handoff_issuer_id: str
    handoff_key_id: str
    handoff_rsa_modulus_hex: str
    handoff_rsa_exponent: int
    handoff_public_key_fingerprint_sha256: str
    replay_issuer_id: str
    replay_key_id: str
    replay_rsa_modulus_hex: str
    replay_rsa_exponent: int
    replay_public_key_fingerprint_sha256: str
    replay_ledger_alias_sha256: str
    execution_release_identity_sha256: str
    target_host_identity_sha256: str
    installed_environment_sha256: str
    deployment_host_alias_sha256: str
    service_account_alias_sha256: str
    launcher_task_definition_sha256: str
    live_execution_task_definition_sha256: str
    reserved_authority_key_ids: tuple[str, ...]
    reserved_authority_fingerprints_sha256: tuple[str, ...]
    maximum_handoff_ttl_seconds: int
    maximum_replay_request_ttl_seconds: int
    signature_algorithm: str
    central_unlock_required: bool
    session_reconstruction_authorized: bool
    direct_execution_authorized: bool
    broker_mutation_authorized: bool
    order_capability: str
    schema_version: str
    _document_sha256: str = field(repr=False, compare=False)

    @property
    def content_sha256(self) -> str:
        return self._document_sha256

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            item.name: (
                list(getattr(self, item.name))
                if item.name.startswith("reserved_authority_")
                else getattr(self, item.name)
            )
            for item in dataclass_fields(self)
            if not item.name.startswith("_")
        }


def decode_live_canary_provider_bound_runtime_session_handoff_policy(
    payload: bytes,
    *,
    expected_policy_sha256: str,
) -> LiveCanaryProviderBoundRuntimeSessionHandoffPolicy:
    """Decode one exact independently pinned public policy."""

    expected = _sha256("EXPECTED_POLICY_SHA256", expected_policy_sha256)
    policy = _strict_document(
        payload,
        expected_fields=_POLICY_FIELDS,
        kind="HANDOFF_POLICY",
    )
    observed = hashlib.sha256(payload).hexdigest()
    if observed != expected:
        _reject("HANDOFF_POLICY_PIN_MISMATCH")
    if policy.get("schema_version") != HANDOFF_POLICY_SCHEMA:
        _reject("HANDOFF_POLICY_SCHEMA_INVALID")
    policy_id = _identifier("POLICY_ID", policy.get("policy_id"))
    handoff_issuer_id = _identifier(
        "HANDOFF_ISSUER_ID", policy.get("handoff_issuer_id")
    )
    handoff_key_id = _identifier(
        "HANDOFF_KEY_ID", policy.get("handoff_key_id")
    )
    replay_issuer_id = _identifier(
        "REPLAY_ISSUER_ID", policy.get("replay_issuer_id")
    )
    replay_key_id = _identifier("REPLAY_KEY_ID", policy.get("replay_key_id"))
    if len({handoff_issuer_id, handoff_key_id, replay_issuer_id, replay_key_id}) != 4:
        _reject("HANDOFF_AUTHORITY_ID_REUSE")
    handoff_modulus, handoff_exponent, handoff_fingerprint = _rsa_key(
        prefix="HANDOFF",
        modulus_hex=policy.get("handoff_rsa_modulus_hex"),
        exponent=policy.get("handoff_rsa_exponent"),
        fingerprint=policy.get("handoff_public_key_fingerprint_sha256"),
    )
    replay_modulus, replay_exponent, replay_fingerprint = _rsa_key(
        prefix="REPLAY",
        modulus_hex=policy.get("replay_rsa_modulus_hex"),
        exponent=policy.get("replay_rsa_exponent"),
        fingerprint=policy.get("replay_public_key_fingerprint_sha256"),
    )
    if handoff_fingerprint == replay_fingerprint:
        _reject("HANDOFF_AUTHORITY_FINGERPRINT_REUSE")
    reserved_ids = _sorted_identifiers(
        "RESERVED_AUTHORITY_KEY_IDS",
        policy.get("reserved_authority_key_ids"),
    )
    reserved_fingerprints = _sorted_hashes(
        "RESERVED_AUTHORITY_FINGERPRINTS_SHA256",
        policy.get("reserved_authority_fingerprints_sha256"),
    )
    if (
        {handoff_issuer_id, handoff_key_id, replay_issuer_id, replay_key_id}
        & set(reserved_ids)
        or {handoff_fingerprint, replay_fingerprint}
        & set(reserved_fingerprints)
    ):
        _reject("HANDOFF_AUTHORITY_RESERVED_REUSE")
    hashes = {
        name: _sha256(name.upper(), policy.get(name))
        for name in (
            "replay_ledger_alias_sha256",
            "execution_release_identity_sha256",
            "target_host_identity_sha256",
            "installed_environment_sha256",
            "deployment_host_alias_sha256",
            "service_account_alias_sha256",
            "launcher_task_definition_sha256",
            "live_execution_task_definition_sha256",
        )
    }
    if policy.get("signature_algorithm") != SIGNATURE_ALGORITHM:
        _reject("HANDOFF_POLICY_SIGNATURE_ALGORITHM_INVALID")
    _fixed_safety(policy, kind="HANDOFF_POLICY")
    return LiveCanaryProviderBoundRuntimeSessionHandoffPolicy(
        policy_id=policy_id,
        handoff_issuer_id=handoff_issuer_id,
        handoff_key_id=handoff_key_id,
        handoff_rsa_modulus_hex=handoff_modulus,
        handoff_rsa_exponent=handoff_exponent,
        handoff_public_key_fingerprint_sha256=handoff_fingerprint,
        replay_issuer_id=replay_issuer_id,
        replay_key_id=replay_key_id,
        replay_rsa_modulus_hex=replay_modulus,
        replay_rsa_exponent=replay_exponent,
        replay_public_key_fingerprint_sha256=replay_fingerprint,
        reserved_authority_key_ids=reserved_ids,
        reserved_authority_fingerprints_sha256=reserved_fingerprints,
        maximum_handoff_ttl_seconds=_bounded_int(
            "MAXIMUM_HANDOFF_TTL_SECONDS",
            policy.get("maximum_handoff_ttl_seconds"),
            minimum=1,
            maximum=MAXIMUM_HANDOFF_TTL_SECONDS,
        ),
        maximum_replay_request_ttl_seconds=_bounded_int(
            "MAXIMUM_REPLAY_REQUEST_TTL_SECONDS",
            policy.get("maximum_replay_request_ttl_seconds"),
            minimum=1,
            maximum=MAXIMUM_REPLAY_REQUEST_TTL_SECONDS,
        ),
        signature_algorithm=SIGNATURE_ALGORITHM,
        central_unlock_required=True,
        session_reconstruction_authorized=True,
        direct_execution_authorized=False,
        broker_mutation_authorized=False,
        order_capability=ORDER_CAPABILITY,
        schema_version=HANDOFF_POLICY_SCHEMA,
        _document_sha256=observed,
        **hashes,
    )


def _signing_message(
    payload: bytes,
    *,
    fields: frozenset[str],
    kind: str,
    domain: bytes,
) -> bytes:
    value = _strict_document(payload, expected_fields=fields, kind=kind)
    _signature(
        "SIGNATURE_RSA_PKCS1V15_SHA256_HEX",
        value.get("signature_rsa_pkcs1v15_sha256_hex"),
        allow_empty=True,
    )
    unsigned = dict(value)
    unsigned.pop("signature_rsa_pkcs1v15_sha256_hex")
    return domain + canonical_json(unsigned).encode("utf-8")


def provider_bound_runtime_session_handoff_signing_message(
    handoff_payload: bytes,
) -> bytes:
    """Return the domain-separated message for one exact handoff."""

    return _signing_message(
        handoff_payload,
        fields=_HANDOFF_FIELDS,
        kind="HANDOFF_DOCUMENT",
        domain=_HANDOFF_SIGNATURE_DOMAIN,
    )


def provider_bound_runtime_session_consumption_receipt_signing_message(
    receipt_payload: bytes,
) -> bytes:
    """Return the domain-separated message for one exact replay receipt."""

    return _signing_message(
        receipt_payload,
        fields=_REPLAY_RECEIPT_FIELDS,
        kind="REPLAY_RECEIPT",
        domain=_REPLAY_RECEIPT_SIGNATURE_DOMAIN,
    )


def _validate_session_payload(
    payload: object,
    *,
    expected_session_sha256: str,
) -> tuple[dict[str, Any], dict[str, datetime]]:
    if type(payload) is not dict:
        _reject("RUNTIME_SESSION_PAYLOAD_INVALID")
    session = cast(dict[str, Any], payload)
    if frozenset(session) != _SESSION_FIELDS:
        _reject("RUNTIME_SESSION_FIELDS_INVALID")
    observed = hashlib.sha256(canonical_json(session).encode("utf-8")).hexdigest()
    if observed != expected_session_sha256:
        _reject("RUNTIME_SESSION_PIN_MISMATCH")
    times = {
        name: _utc(name.upper(), session.get(name))
        for name in _SESSION_TIME_FIELDS
    }
    if (
        times["activated_at_utc"] >= times["valid_until_utc"]
        or times["valid_until_utc"]
        > times["provider_acceptance_valid_until_utc"]
        or times["valid_until_utc"]
        > times["provider_bound_custody_valid_until_utc"]
    ):
        _reject("RUNTIME_SESSION_WINDOW_INVALID")
    _bounded_int(
        "RUNTIME_SESSION_SEQUENCE",
        session.get("sequence"),
        minimum=1,
        maximum=2**63 - 1,
    )
    for name in _SESSION_INIT_FIELDS:
        if name not in _SESSION_TIME_FIELDS and name != "sequence":
            _sha256(name.upper(), session.get(name))
    for name, expected in _SESSION_FIXED_FIELDS.items():
        value = session.get(name)
        if type(value) is not type(expected) or value != expected:
            _reject("RUNTIME_SESSION_SAFETY_DRIFT")
    return session, times


def _require_current(
    *,
    now: datetime,
    handoff_times: dict[str, datetime],
    session_times: dict[str, datetime],
) -> None:
    if (
        now < handoff_times["issued_at_utc"]
        or now < handoff_times["not_before_utc"]
        or now >= handoff_times["expires_at_utc"]
        or now < session_times["activated_at_utc"]
        or now >= session_times["valid_until_utc"]
        or now >= session_times["provider_acceptance_valid_until_utc"]
        or now >= session_times["provider_bound_custody_valid_until_utc"]
    ):
        _reject("RUNTIME_SESSION_HANDOFF_NOT_CURRENT")


def _candidate_unchanged(
    candidate: object,
    *,
    snapshot: dict[str, object],
    expected_sha256: str,
) -> bool:
    try:
        return (
            type(candidate) is LiveCanaryRuntimeCandidate
            and is_live_canary_runtime_candidate(candidate)
            and candidate.to_canonical_dict() == snapshot
            and candidate.content_sha256 == expected_sha256
        )
    except Exception:
        return False


def _expected_bindings(
    *,
    policy: LiveCanaryProviderBoundRuntimeSessionHandoffPolicy,
    expected_handoff_sha256: str,
    expected_candidate_sha256: str,
    expected_session_sha256: str,
    expected_handoff_nonce_sha256: str,
) -> dict[str, str]:
    return {
        "handoff_policy_sha256": policy.content_sha256,
        "handoff_sha256": expected_handoff_sha256,
        "candidate_sha256": expected_candidate_sha256,
        "session_sha256": expected_session_sha256,
        "handoff_nonce_sha256": expected_handoff_nonce_sha256,
        "replay_ledger_alias_sha256": policy.replay_ledger_alias_sha256,
        "execution_release_identity_sha256": (
            policy.execution_release_identity_sha256
        ),
        "target_host_identity_sha256": policy.target_host_identity_sha256,
        "installed_environment_sha256": policy.installed_environment_sha256,
        "deployment_host_alias_sha256": policy.deployment_host_alias_sha256,
        "service_account_alias_sha256": policy.service_account_alias_sha256,
        "launcher_task_definition_sha256": (
            policy.launcher_task_definition_sha256
        ),
        "live_execution_task_definition_sha256": (
            policy.live_execution_task_definition_sha256
        ),
    }


def _receipt_matches_request(
    *,
    receipt: dict[str, Any],
    request: dict[str, Any],
    request_payload: bytes,
    policy: LiveCanaryProviderBoundRuntimeSessionHandoffPolicy,
) -> tuple[datetime, datetime]:
    binding_names = (
        "handoff_id",
        "handoff_policy_sha256",
        "handoff_sha256",
        "candidate_sha256",
        "session_sha256",
        "handoff_nonce_sha256",
        "challenge_sha256",
        "replay_ledger_alias_sha256",
        "execution_release_identity_sha256",
        "target_host_identity_sha256",
        "installed_environment_sha256",
        "deployment_host_alias_sha256",
        "service_account_alias_sha256",
        "launcher_task_definition_sha256",
        "live_execution_task_definition_sha256",
        "expires_at_utc",
    )
    if any(receipt.get(name) != request.get(name) for name in binding_names):
        _reject("RECEIPT_BINDING_MISMATCH")
    if receipt.get("request_sha256") != hashlib.sha256(request_payload).hexdigest():
        _reject("RECEIPT_BINDING_MISMATCH")
    if (
        receipt.get("replay_issuer_id") != policy.replay_issuer_id
        or receipt.get("replay_key_id") != policy.replay_key_id
        or receipt.get("replay_public_key_fingerprint_sha256")
        != policy.replay_public_key_fingerprint_sha256
    ):
        _reject("RECEIPT_AUTHORITY_MISMATCH")
    _identifier("CONSUMPTION_ID", receipt.get("consumption_id"))
    _bounded_int(
        "CONSUMPTION_SEQUENCE",
        receipt.get("consumption_sequence"),
        minimum=1,
        maximum=2**63 - 1,
    )
    _sha256("REQUEST_SHA256", receipt.get("request_sha256"))
    _fixed_safety(receipt, kind="REPLAY_RECEIPT")
    if receipt.get("consumed_once") is not True:
        _reject("REPLAY_RECEIPT_NOT_CONSUMED_ONCE")
    if receipt.get("signature_algorithm") != SIGNATURE_ALGORITHM:
        _reject("REPLAY_RECEIPT_SIGNATURE_ALGORITHM_INVALID")
    consumed = _utc("CONSUMED_AT_UTC", receipt.get("consumed_at_utc"))
    expires = _utc("RECEIPT_EXPIRES_AT_UTC", receipt.get("expires_at_utc"))
    return consumed, expires


def load_live_canary_provider_bound_runtime_session_handoff(
    *,
    policy_payload: bytes,
    handoff_payload: bytes,
    candidate: LiveCanaryRuntimeCandidate,
    expected_policy_sha256: str,
    expected_handoff_sha256: str,
    expected_candidate_sha256: str,
    expected_session_sha256: str,
    expected_handoff_nonce_sha256: str,
    expected_execution_release_identity_sha256: str,
    expected_target_host_identity_sha256: str,
    expected_installed_environment_sha256: str,
    expected_deployment_host_alias_sha256: str,
    expected_service_account_alias_sha256: str,
    expected_launcher_task_definition_sha256: str,
    expected_live_execution_task_definition_sha256: str,
    external_replay_consumer: Callable[[bytes], bytes],
    clock_provider: Callable[[], datetime],
) -> LiveCanaryProviderBoundRuntimeLaunchSession:
    """Verify, consume externally once, and reconstruct one sealed session."""

    pins = {
        "expected_handoff_sha256": _sha256(
            "EXPECTED_HANDOFF_SHA256", expected_handoff_sha256
        ),
        "expected_candidate_sha256": _sha256(
            "EXPECTED_CANDIDATE_SHA256", expected_candidate_sha256
        ),
        "expected_session_sha256": _sha256(
            "EXPECTED_SESSION_SHA256", expected_session_sha256
        ),
        "expected_handoff_nonce_sha256": _sha256(
            "EXPECTED_HANDOFF_NONCE_SHA256", expected_handoff_nonce_sha256
        ),
        "expected_execution_release_identity_sha256": _sha256(
            "EXPECTED_EXECUTION_RELEASE_IDENTITY_SHA256",
            expected_execution_release_identity_sha256,
        ),
        "expected_target_host_identity_sha256": _sha256(
            "EXPECTED_TARGET_HOST_IDENTITY_SHA256",
            expected_target_host_identity_sha256,
        ),
        "expected_installed_environment_sha256": _sha256(
            "EXPECTED_INSTALLED_ENVIRONMENT_SHA256",
            expected_installed_environment_sha256,
        ),
        "expected_deployment_host_alias_sha256": _sha256(
            "EXPECTED_DEPLOYMENT_HOST_ALIAS_SHA256",
            expected_deployment_host_alias_sha256,
        ),
        "expected_service_account_alias_sha256": _sha256(
            "EXPECTED_SERVICE_ACCOUNT_ALIAS_SHA256",
            expected_service_account_alias_sha256,
        ),
        "expected_launcher_task_definition_sha256": _sha256(
            "EXPECTED_LAUNCHER_TASK_DEFINITION_SHA256",
            expected_launcher_task_definition_sha256,
        ),
        "expected_live_execution_task_definition_sha256": _sha256(
            "EXPECTED_LIVE_EXECUTION_TASK_DEFINITION_SHA256",
            expected_live_execution_task_definition_sha256,
        ),
    }
    policy = decode_live_canary_provider_bound_runtime_session_handoff_policy(
        policy_payload,
        expected_policy_sha256=expected_policy_sha256,
    )
    if not callable(external_replay_consumer):
        _reject("EXTERNAL_REPLAY_CONSUMER_INVALID")
    if not callable(clock_provider):
        _reject("TRUSTED_CLOCK_PROVIDER_INVALID")
    # No candidate, signed handoff, replay claim, or seal may become authority
    # while the single checked-in LIVE policy remains locked.
    _require_central_live_policy()
    if (
        type(candidate) is not LiveCanaryRuntimeCandidate
        or not is_live_canary_runtime_candidate(candidate)
    ):
        _reject("LIVE_CANARY_RUNTIME_CANDIDATE_NOT_EXACT")
    if candidate.content_sha256 != pins["expected_candidate_sha256"]:
        _reject("LIVE_CANARY_RUNTIME_CANDIDATE_PIN_MISMATCH")
    candidate_snapshot = candidate.to_canonical_dict()

    handoff = _strict_document(
        handoff_payload,
        expected_fields=_HANDOFF_FIELDS,
        kind="HANDOFF_DOCUMENT",
    )
    if hashlib.sha256(handoff_payload).hexdigest() != pins[
        "expected_handoff_sha256"
    ]:
        _reject("HANDOFF_DOCUMENT_PIN_MISMATCH")
    if handoff.get("schema_version") != HANDOFF_DOCUMENT_SCHEMA:
        _reject("HANDOFF_DOCUMENT_SCHEMA_INVALID")
    _identifier("HANDOFF_ID", handoff.get("handoff_id"))
    for name in (
        "handoff_policy_sha256",
        "candidate_sha256",
        "session_sha256",
        "handoff_nonce_sha256",
        "execution_release_identity_sha256",
        "target_host_identity_sha256",
        "installed_environment_sha256",
        "deployment_host_alias_sha256",
        "service_account_alias_sha256",
        "launcher_task_definition_sha256",
        "live_execution_task_definition_sha256",
        "handoff_public_key_fingerprint_sha256",
    ):
        _sha256(name.upper(), handoff.get(name))
    _fixed_safety(handoff, kind="HANDOFF_DOCUMENT")
    if handoff.get("signature_algorithm") != SIGNATURE_ALGORITHM:
        _reject("HANDOFF_SIGNATURE_ALGORITHM_INVALID")
    signature = _signature(
        "HANDOFF_SIGNATURE",
        handoff.get("signature_rsa_pkcs1v15_sha256_hex"),
        allow_empty=False,
    )
    session, session_times = _validate_session_payload(
        handoff.get("session"),
        expected_session_sha256=pins["expected_session_sha256"],
    )
    handoff_times = {
        name: _utc(name.upper(), handoff.get(name))
        for name in ("issued_at_utc", "not_before_utc", "expires_at_utc")
    }
    if (
        handoff_times["issued_at_utc"] > handoff_times["not_before_utc"]
        or handoff_times["not_before_utc"] >= handoff_times["expires_at_utc"]
        or handoff_times["issued_at_utc"]
        < session_times["activated_at_utc"]
        or handoff_times["not_before_utc"]
        < session_times["activated_at_utc"]
        or handoff_times["expires_at_utc"]
        - handoff_times["issued_at_utc"]
        > timedelta(seconds=policy.maximum_handoff_ttl_seconds)
        or handoff_times["expires_at_utc"] > session_times["valid_until_utc"]
        or handoff_times["expires_at_utc"]
        > session_times["provider_acceptance_valid_until_utc"]
        or handoff_times["expires_at_utc"]
        > session_times["provider_bound_custody_valid_until_utc"]
    ):
        _reject("RUNTIME_SESSION_HANDOFF_WINDOW_INVALID")

    external_bindings = {
        "execution_release_identity_sha256": pins[
            "expected_execution_release_identity_sha256"
        ],
        "target_host_identity_sha256": pins[
            "expected_target_host_identity_sha256"
        ],
        "installed_environment_sha256": pins[
            "expected_installed_environment_sha256"
        ],
        "deployment_host_alias_sha256": pins[
            "expected_deployment_host_alias_sha256"
        ],
        "service_account_alias_sha256": pins[
            "expected_service_account_alias_sha256"
        ],
        "launcher_task_definition_sha256": pins[
            "expected_launcher_task_definition_sha256"
        ],
        "live_execution_task_definition_sha256": pins[
            "expected_live_execution_task_definition_sha256"
        ],
    }
    handoff_bindings = {
        "handoff_policy_sha256": policy.content_sha256,
        "candidate_sha256": pins["expected_candidate_sha256"],
        "session_sha256": pins["expected_session_sha256"],
        "handoff_nonce_sha256": pins["expected_handoff_nonce_sha256"],
        **external_bindings,
    }
    if any(handoff.get(name) != value for name, value in handoff_bindings.items()):
        _reject("HANDOFF_BINDING_MISMATCH")
    if any(getattr(policy, name) != value for name, value in external_bindings.items()):
        _reject("HANDOFF_POLICY_BINDING_MISMATCH")
    session_bindings = {
        "candidate_sha256": pins["expected_candidate_sha256"],
        "release_manifest_sha256": pins[
            "expected_execution_release_identity_sha256"
        ],
        "target_host_identity_sha256": pins[
            "expected_target_host_identity_sha256"
        ],
        "installed_environment_sha256": pins[
            "expected_installed_environment_sha256"
        ],
        "deployment_host_alias_sha256": pins[
            "expected_deployment_host_alias_sha256"
        ],
        "service_account_alias_sha256": pins[
            "expected_service_account_alias_sha256"
        ],
        "task_definition_sha256": pins[
            "expected_launcher_task_definition_sha256"
        ],
        "live_execution_release_identity_sha256": pins[
            "expected_execution_release_identity_sha256"
        ],
        "live_execution_task_definition_sha256": pins[
            "expected_live_execution_task_definition_sha256"
        ],
    }
    if any(session.get(name) != value for name, value in session_bindings.items()):
        _reject("RUNTIME_SESSION_BINDING_MISMATCH")
    if (
        candidate.release_manifest_sha256
        != pins["expected_execution_release_identity_sha256"]
        or candidate.installed_environment_sha256
        != pins["expected_installed_environment_sha256"]
        or session.get("runtime_profile_sha256") != candidate.runtime_profile_sha256
        or session.get("live_stage_binding_sha256")
        != candidate.live_stage_binding_sha256
        or not candidate.runtime_key_ids.issubset(
            set(policy.reserved_authority_key_ids)
        )
        or not candidate.runtime_key_fingerprints.issubset(
            set(policy.reserved_authority_fingerprints_sha256)
        )
    ):
        _reject("RUNTIME_CANDIDATE_BINDING_MISMATCH")
    if (
        handoff.get("handoff_issuer_id") != policy.handoff_issuer_id
        or handoff.get("handoff_key_id") != policy.handoff_key_id
        or handoff.get("handoff_public_key_fingerprint_sha256")
        != policy.handoff_public_key_fingerprint_sha256
    ):
        _reject("HANDOFF_AUTHORITY_MISMATCH")

    _require_central_live_policy()
    started = _trusted_clock(clock_provider)
    _require_current(
        now=started,
        handoff_times=handoff_times,
        session_times=session_times,
    )
    if not _candidate_unchanged(
        candidate,
        snapshot=candidate_snapshot,
        expected_sha256=pins["expected_candidate_sha256"],
    ):
        _reject("RUNTIME_CANDIDATE_CHANGED_DURING_HANDOFF")
    _require_central_live_policy()
    message = provider_bound_runtime_session_handoff_signing_message(
        handoff_payload
    )
    if not verify_rsa_pkcs1v15_sha256(
        modulus_hex=policy.handoff_rsa_modulus_hex,
        exponent=policy.handoff_rsa_exponent,
        message=message,
        signature_hex=signature,
    ):
        _reject("HANDOFF_SIGNATURE_INVALID")
    _require_central_live_policy()

    before_replay = _trusted_clock(clock_provider)
    if before_replay < started:
        _reject("TRUSTED_CLOCK_REGRESSION")
    _require_current(
        now=before_replay,
        handoff_times=handoff_times,
        session_times=session_times,
    )
    if not _candidate_unchanged(
        candidate,
        snapshot=candidate_snapshot,
        expected_sha256=pins["expected_candidate_sha256"],
    ):
        _reject("RUNTIME_CANDIDATE_CHANGED_DURING_HANDOFF")
    try:
        challenge = secrets.token_bytes(32)
    except Exception:
        raise LiveCanaryProviderBoundRuntimeSessionHandoffError(
            "RANDOM_CHALLENGE_GENERATION_FAILED"
        ) from None
    if type(challenge) is not bytes or len(challenge) != 32:
        _reject("RANDOM_CHALLENGE_INVALID")
    request_expiry = min(
        before_replay
        + timedelta(seconds=policy.maximum_replay_request_ttl_seconds),
        handoff_times["expires_at_utc"],
        session_times["valid_until_utc"],
        session_times["provider_acceptance_valid_until_utc"],
        session_times["provider_bound_custody_valid_until_utc"],
    )
    if before_replay >= request_expiry:
        _reject("REPLAY_REQUEST_WINDOW_INVALID")
    bindings = _expected_bindings(
        policy=policy,
        expected_handoff_sha256=pins["expected_handoff_sha256"],
        expected_candidate_sha256=pins["expected_candidate_sha256"],
        expected_session_sha256=pins["expected_session_sha256"],
        expected_handoff_nonce_sha256=pins["expected_handoff_nonce_sha256"],
    )
    request: dict[str, Any] = {
        "schema_version": REPLAY_REQUEST_SCHEMA,
        "handoff_id": handoff["handoff_id"],
        **bindings,
        "challenge_sha256": hashlib.sha256(challenge).hexdigest(),
        "requested_at_utc": _canonical_utc(before_replay),
        "expires_at_utc": _canonical_utc(request_expiry),
        "central_unlock_required": True,
        "session_reconstruction_authorized": True,
        "direct_execution_authorized": False,
        "broker_mutation_authorized": False,
        "order_capability": ORDER_CAPABILITY,
    }
    if frozenset(request) != _REPLAY_REQUEST_FIELDS:
        _reject("REPLAY_REQUEST_FIELDS_INVALID")
    request_payload = _canonical_document(request)
    _require_central_live_policy()
    try:
        receipt_payload = external_replay_consumer(request_payload)
    except Exception:
        raise LiveCanaryProviderBoundRuntimeSessionHandoffError(
            "RUNTIME_SESSION_REPLAY_CONSUMPTION_FAILED"
        ) from None
    _require_central_live_policy()
    if not _candidate_unchanged(
        candidate,
        snapshot=candidate_snapshot,
        expected_sha256=pins["expected_candidate_sha256"],
    ):
        _reject("RUNTIME_CANDIDATE_CHANGED_DURING_REPLAY")
    if type(receipt_payload) is not bytes:
        _reject("REPLAY_RECEIPT_BYTES_INVALID")
    receipt = _strict_document(
        receipt_payload,
        expected_fields=_REPLAY_RECEIPT_FIELDS,
        kind="REPLAY_RECEIPT",
    )
    if receipt.get("schema_version") != REPLAY_RECEIPT_SCHEMA:
        _reject("REPLAY_RECEIPT_SCHEMA_INVALID")
    consumed_at, receipt_expiry = _receipt_matches_request(
        receipt=receipt,
        request=request,
        request_payload=request_payload,
        policy=policy,
    )
    receipt_signature = _signature(
        "REPLAY_RECEIPT_SIGNATURE",
        receipt.get("signature_rsa_pkcs1v15_sha256_hex"),
        allow_empty=False,
    )
    _require_central_live_policy()
    if not verify_rsa_pkcs1v15_sha256(
        modulus_hex=policy.replay_rsa_modulus_hex,
        exponent=policy.replay_rsa_exponent,
        message=(
            provider_bound_runtime_session_consumption_receipt_signing_message(
                receipt_payload
            )
        ),
        signature_hex=receipt_signature,
    ):
        _reject("REPLAY_RECEIPT_SIGNATURE_INVALID")
    _require_central_live_policy()

    completed = _trusted_clock(clock_provider)
    if (
        completed < before_replay
        or consumed_at < before_replay
        or consumed_at > completed
        or receipt_expiry != request_expiry
        or completed >= receipt_expiry
    ):
        _reject("REPLAY_RECEIPT_WINDOW_INVALID")
    _require_current(
        now=completed,
        handoff_times=handoff_times,
        session_times=session_times,
    )
    _require_central_live_policy()
    if not _candidate_unchanged(
        candidate,
        snapshot=candidate_snapshot,
        expected_sha256=pins["expected_candidate_sha256"],
    ):
        _reject("RUNTIME_CANDIDATE_CHANGED_DURING_REPLAY")

    constructor_values = {
        name: (
            session_times[name]
            if name in _SESSION_TIME_FIELDS
            else session[name]
        )
        for name in _SESSION_INIT_FIELDS
    }
    try:
        reconstructed = LiveCanaryProviderBoundRuntimeLaunchSession(
            **constructor_values,
            _seal=_SESSION_SEAL,
        )
    except Exception as exc:
        reason = getattr(exc, "reason_code", "RUNTIME_SESSION_RECONSTRUCTION_FAILED")
        raise LiveCanaryProviderBoundRuntimeSessionHandoffError(reason) from exc
    if (
        type(reconstructed) is not LiveCanaryProviderBoundRuntimeLaunchSession
        or not is_live_canary_provider_bound_runtime_launch_session(
            reconstructed
        )
        or reconstructed.to_canonical_dict() != session
        or reconstructed.content_sha256 != pins["expected_session_sha256"]
    ):
        _reject("RUNTIME_SESSION_RECONSTRUCTION_MISMATCH")
    reconstructed.assert_current(now=completed)
    _require_central_live_policy()
    return reconstructed


__all__ = [
    "HANDOFF_DOCUMENT_SCHEMA",
    "HANDOFF_POLICY_SCHEMA",
    "LiveCanaryProviderBoundRuntimeSessionHandoffError",
    "LiveCanaryProviderBoundRuntimeSessionHandoffPolicy",
    "MAXIMUM_DOCUMENT_BYTES",
    "ORDER_CAPABILITY",
    "REPLAY_RECEIPT_SCHEMA",
    "REPLAY_REQUEST_SCHEMA",
    "decode_live_canary_provider_bound_runtime_session_handoff_policy",
    "load_live_canary_provider_bound_runtime_session_handoff",
    "provider_bound_runtime_session_consumption_receipt_signing_message",
    "provider_bound_runtime_session_handoff_signing_message",
]
