"""Portable WORM custody and one-use live-canary launch reservation.

The module verifies public, signed canonical documents and delegates durable
object readback plus atomic compare-and-swap to narrow external callbacks.  A
successful result is only a short-lived prerequisite: every bootstrap,
process, execution, and broker authority remains disabled.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field, fields as dataclass_fields
from datetime import datetime, timedelta
import hashlib
import json
import re
from typing import Callable

import execution_policy

from .asymmetric_release_trust import (
    EXECUTION_RELEASE_PROFILE,
    MINIMUM_RSA_BITS,
    SIGNATURE_ALGORITHM,
    ExternalLauncherTrustPolicy,
    VerifiedExternalLauncherAttestation,
    is_verified_external_launcher_attestation,
    rsa_public_key_fingerprint_sha256,
    verify_rsa_pkcs1v15_sha256,
)
from .contracts import (
    CanonicalContract,
    canonical_json,
    canonicalize,
)
from .live_canary_activation import (
    LiveCanaryActivationAuthorization,
    LiveCanaryActivationValidation,
    LiveCanaryTrustPolicy,
)
from .live_canary_prebootstrap_admission import (
    LiveCanaryPrebootstrapAdmission,
    LiveCanaryRuntimeCandidate,
    is_live_canary_prebootstrap_admission,
)


CUSTODY_POLICY_SCHEMA = "live-canary-portable-custody-policy-v1"
ADMISSION_RECEIPT_SCHEMA = "live-canary-admission-worm-receipt-v1"
VERIFIED_CUSTODY_SCHEMA = "live-canary-verified-admission-custody-v1"
LAUNCH_PROPOSAL_SCHEMA = "live-canary-launch-reservation-proposal-v1"
LAUNCH_CHECKPOINT_SCHEMA = "live-canary-launch-reservation-checkpoint-v1"
LAUNCH_ACK_SCHEMA = "live-canary-launch-reservation-cas-ack-v1"
LAUNCH_CAPABILITY_SCHEMA = "live-canary-one-use-launch-capability-v1"

ORDER_CAPABILITY = "DISABLED"
RETENTION_MODE = "COMPLIANCE"
ZERO_SHA256 = "0" * 64
MAXIMUM_RSA_BITS = 8192
MAXIMUM_DOCUMENT_BYTES = 262_144
MAXIMUM_OBJECT_BYTES = 1_048_576
MAXIMUM_LAUNCH_TTL_SECONDS = 60
MAXIMUM_RETENTION_SECONDS = 315_360_000

_RECEIPT_DOMAIN = b"AI_SCALPER:LIVE_CANARY:ADMISSION_WORM:v1\x00"
_CHECKPOINT_DOMAIN = b"AI_SCALPER:LIVE_CANARY:LAUNCH_CHECKPOINT:v1\x00"
_ACK_DOMAIN = b"AI_SCALPER:LIVE_CANARY:LAUNCH_CAS_ACK:v1\x00"
_HEX = re.compile(r"^[0-9a-f]+$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_VERIFIED_CUSTODY_SEAL = object()
_CAPABILITY_SEAL = object()


class LiveCanaryPortableLaunchCustodyError(RuntimeError):
    """One portable custody invariant failed with a stable reason code."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: object) -> None:
        normalized = re.sub(
            r"[^A-Z0-9_]+",
            "_",
            str(reason_code or "").strip().upper(),
        ).strip("_")
        self.reason_code = normalized or "LIVE_CANARY_PORTABLE_CUSTODY_INVALID"
        super().__init__(self.reason_code)


def _reject(reason_code: str) -> None:
    raise LiveCanaryPortableLaunchCustodyError(reason_code)


def _text(name: str, value: object) -> str:
    if type(value) is not str:
        _reject(f"{name}_INVALID")
    normalized = value.strip()
    if not normalized or normalized != value or "\x00" in normalized:
        _reject(f"{name}_INVALID")
    return normalized


def _identifier(name: str, value: object) -> str:
    normalized = _text(name, value)
    if _IDENTIFIER.fullmatch(normalized) is None:
        _reject(f"{name}_INVALID")
    return normalized


def _sha256(name: str, value: object, *, allow_zero: bool = False) -> str:
    if type(value) is not str or _HEX_64.fullmatch(value) is None:
        _reject(f"{name}_INVALID")
    if not allow_zero and value == ZERO_SHA256:
        _reject(f"{name}_INVALID")
    return value


def _signature(value: object) -> str:
    if value == "":
        return ""
    normalized = _text("SIGNATURE_RSA_PKCS1V15_SHA256_HEX", value)
    if _HEX.fullmatch(normalized) is None or len(normalized) % 2:
        _reject("SIGNATURE_RSA_PKCS1V15_SHA256_HEX_INVALID")
    return normalized


def _integer(
    name: str,
    value: object,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _reject(f"{name}_INVALID")
    return value


def _utc(name: str, value: object) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset().total_seconds() != 0
    ):
        _reject(f"{name}_INVALID")
    return value


def _utc_text(value: datetime) -> str:
    return _utc("UTC_TIMESTAMP", value).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _parse_utc(name: str, value: object) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        _reject(f"{name}_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise LiveCanaryPortableLaunchCustodyError(
            f"{name}_INVALID"
        ) from exc
    result = _utc(name, parsed)
    if _utc_text(result) != value:
        _reject(f"{name}_NOT_CANONICAL")
    return result


def _strict_json(payload: object, *, kind: str) -> tuple[dict[str, object], str]:
    if type(payload) is not bytes:
        _reject(f"{kind}_PAYLOAD_TYPE_INVALID")
    if not payload or len(payload) > MAXIMUM_DOCUMENT_BYTES:
        _reject(f"{kind}_PAYLOAD_SIZE_INVALID")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LiveCanaryPortableLaunchCustodyError(
            f"{kind}_JSON_INVALID"
        ) from exc

    def reject_duplicates(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                _reject(f"{kind}_DUPLICATE_KEY")
            result[key] = value
        return result

    try:
        parsed = json.loads(text, object_pairs_hook=reject_duplicates)
    except LiveCanaryPortableLaunchCustodyError:
        raise
    except (TypeError, json.JSONDecodeError) as exc:
        raise LiveCanaryPortableLaunchCustodyError(
            f"{kind}_JSON_INVALID"
        ) from exc
    if type(parsed) is not dict or canonical_json(parsed) != text:
        _reject(f"{kind}_JSON_NOT_CANONICAL")
    return parsed, text


def _public_contract_dict(value: object) -> dict[str, object]:
    return {
        item.name: canonicalize(getattr(value, item.name))
        for item in dataclass_fields(value)
        if not item.name.startswith("_")
    }


def _constructor_values(model: type, raw: dict[str, object]) -> dict[str, object]:
    return {
        item.name: raw[item.name]
        for item in dataclass_fields(model)
        if item.init
    }


def _safety_is_locked(value: object) -> bool:
    return (
        getattr(value, "live_allowed", None) is False
        and getattr(value, "execution_authorized", None) is False
        and getattr(value, "bootstrap_authorized", None) is False
        and getattr(value, "process_launch_authorized", None) is False
        and getattr(value, "order_capability", None) == ORDER_CAPABILITY
    )


def _require_central_live_lock() -> None:
    if execution_policy.LIVE_ALLOWED is not False:
        _reject("CENTRAL_LIVE_LOCK_NOT_FALSE")
    allowed, reasons = execution_policy.execution_mode_policy_decision("LIVE")
    if allowed is not False or reasons != ("LIVE_MODE_LOCKED",):
        _reject("CENTRAL_LIVE_POLICY_DECISION_DRIFT")


@dataclass(frozen=True, slots=True)
class LiveCanaryPortableCustodyPolicy(CanonicalContract):
    """Public RSA and hashed deployment policy for WORM/CAS custody."""

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
    minimum_retention_seconds: int = 31_536_000
    maximum_receipt_age_seconds: int = 300
    maximum_launch_ttl_seconds: int = 30
    live_allowed: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    bootstrap_authorized: bool = field(default=False, init=False)
    process_launch_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    signature_algorithm: str = field(default=SIGNATURE_ALGORITHM, init=False)
    schema_version: str = field(default=CUSTODY_POLICY_SCHEMA, init=False)

    def __post_init__(self) -> None:
        for name in ("policy_id", "custody_issuer_id", "custody_key_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        modulus_hex = _text("RSA_MODULUS_HEX", self.rsa_modulus_hex)
        if (
            _HEX.fullmatch(modulus_hex) is None
            or len(modulus_hex) % 2
            or modulus_hex.startswith("00")
        ):
            _reject("RSA_MODULUS_HEX_INVALID")
        modulus = int(modulus_hex, 16)
        if (
            not MINIMUM_RSA_BITS <= modulus.bit_length() <= MAXIMUM_RSA_BITS
            or modulus % 2 == 0
        ):
            _reject("RSA_MODULUS_INVALID")
        object.__setattr__(self, "rsa_modulus_hex", modulus_hex)
        exponent = _integer(
            "RSA_EXPONENT",
            self.rsa_exponent,
            minimum=3,
            maximum=2**31 - 1,
        )
        if exponent != 65_537:
            _reject("RSA_EXPONENT_INVALID")
        object.__setattr__(self, "rsa_exponent", exponent)
        fingerprint = _sha256(
            "PUBLIC_KEY_FINGERPRINT_SHA256",
            self.public_key_fingerprint_sha256,
        )
        if fingerprint != rsa_public_key_fingerprint_sha256(
            modulus_hex,
            exponent,
        ):
            _reject("PUBLIC_KEY_FINGERPRINT_MISMATCH")
        object.__setattr__(
            self,
            "public_key_fingerprint_sha256",
            fingerprint,
        )
        deployment_hashes = (
            "worm_repository_alias_sha256",
            "deployment_host_alias_sha256",
            "service_account_alias_sha256",
            "task_definition_sha256",
            "launcher_trust_policy_sha256",
        )
        for name in deployment_hashes:
            object.__setattr__(self, name, _sha256(name, getattr(self, name)))
        if len(
            {
                self.worm_repository_alias_sha256,
                self.deployment_host_alias_sha256,
                self.service_account_alias_sha256,
                self.task_definition_sha256,
            }
        ) != 4:
            _reject("CUSTODY_DEPLOYMENT_IDENTITY_REUSE")
        object.__setattr__(
            self,
            "minimum_retention_seconds",
            _integer(
                "MINIMUM_RETENTION_SECONDS",
                self.minimum_retention_seconds,
                minimum=86_400,
                maximum=MAXIMUM_RETENTION_SECONDS,
            ),
        )
        object.__setattr__(
            self,
            "maximum_receipt_age_seconds",
            _integer(
                "MAXIMUM_RECEIPT_AGE_SECONDS",
                self.maximum_receipt_age_seconds,
                minimum=1,
                maximum=300,
            ),
        )
        object.__setattr__(
            self,
            "maximum_launch_ttl_seconds",
            _integer(
                "MAXIMUM_LAUNCH_TTL_SECONDS",
                self.maximum_launch_ttl_seconds,
                minimum=1,
                maximum=MAXIMUM_LAUNCH_TTL_SECONDS,
            ),
        )
        if (
            self.signature_algorithm != SIGNATURE_ALGORITHM
            or self.schema_version != CUSTODY_POLICY_SCHEMA
            or not _safety_is_locked(self)
        ):
            _reject("CUSTODY_POLICY_SAFETY_DRIFT")


@dataclass(frozen=True, slots=True)
class LiveCanaryAdmissionCustodyReceipt(CanonicalContract):
    """Externally RSA-signed claim for exact admission bytes in WORM."""

    receipt_id: str
    custody_policy_sha256: str
    admission_sha256: str
    candidate_sha256: str
    source_bound_verification_sha256: str
    authorization_sha256: str
    validation_sha256: str
    worm_repository_alias_sha256: str
    object_key_sha256: str
    object_version_sha256: str
    stored_content_sha256: str
    stored_content_size_bytes: int
    uploaded_at_utc: datetime
    retain_until_utc: datetime
    custody_issuer_id: str
    custody_key_id: str
    public_key_fingerprint_sha256: str
    signature_rsa_pkcs1v15_sha256_hex: str = ""
    retention_mode: str = field(default=RETENTION_MODE, init=False)
    live_allowed: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    bootstrap_authorized: bool = field(default=False, init=False)
    process_launch_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    signature_algorithm: str = field(default=SIGNATURE_ALGORITHM, init=False)
    schema_version: str = field(default=ADMISSION_RECEIPT_SCHEMA, init=False)

    def __post_init__(self) -> None:
        for name in ("receipt_id", "custody_issuer_id", "custody_key_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        for name in (
            "custody_policy_sha256",
            "admission_sha256",
            "candidate_sha256",
            "source_bound_verification_sha256",
            "authorization_sha256",
            "validation_sha256",
            "worm_repository_alias_sha256",
            "object_key_sha256",
            "object_version_sha256",
            "stored_content_sha256",
            "public_key_fingerprint_sha256",
        ):
            object.__setattr__(self, name, _sha256(name, getattr(self, name)))
        object.__setattr__(
            self,
            "stored_content_size_bytes",
            _integer(
                "STORED_CONTENT_SIZE_BYTES",
                self.stored_content_size_bytes,
                minimum=1,
                maximum=MAXIMUM_OBJECT_BYTES,
            ),
        )
        uploaded = _utc("UPLOADED_AT_UTC", self.uploaded_at_utc)
        retained = _utc("RETAIN_UNTIL_UTC", self.retain_until_utc)
        if uploaded >= retained:
            _reject("ADMISSION_CUSTODY_RETENTION_INVALID")
        object.__setattr__(
            self,
            "signature_rsa_pkcs1v15_sha256_hex",
            _signature(self.signature_rsa_pkcs1v15_sha256_hex),
        )
        if (
            self.retention_mode != RETENTION_MODE
            or self.signature_algorithm != SIGNATURE_ALGORITHM
            or self.schema_version != ADMISSION_RECEIPT_SCHEMA
            or not _safety_is_locked(self)
        ):
            _reject("ADMISSION_CUSTODY_RECEIPT_SAFETY_DRIFT")

    @property
    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_rsa_pkcs1v15_sha256_hex")
        return payload


@dataclass(frozen=True, slots=True)
class VerifiedLiveCanaryAdmissionCustody(CanonicalContract):
    """Sealed result of RSA, WORM readback, retention, and lineage checks."""

    checked_at_utc: datetime
    receipt_sha256: str
    custody_policy_sha256: str
    admission_sha256: str
    candidate_sha256: str
    source_bound_verification_sha256: str
    authorization_sha256: str
    validation_sha256: str
    worm_repository_alias_sha256: str
    object_key_sha256: str
    object_version_sha256: str
    stored_content_sha256: str
    stored_content_size_bytes: int
    retain_until_utc: datetime
    custody_verified: bool = field(default=True, init=False)
    live_allowed: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    bootstrap_authorized: bool = field(default=False, init=False)
    process_launch_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    schema_version: str = field(default=VERIFIED_CUSTODY_SCHEMA, init=False)
    _verification_seal: object = field(init=False, repr=False, compare=False)
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _VERIFIED_CUSTODY_SEAL:
            raise TypeError("verified admission custody requires its verifier")
        checked = _utc("CHECKED_AT_UTC", self.checked_at_utc)
        retained = _utc("RETAIN_UNTIL_UTC", self.retain_until_utc)
        if checked >= retained:
            _reject("VERIFIED_ADMISSION_CUSTODY_EXPIRED")
        for name in (
            "receipt_sha256",
            "custody_policy_sha256",
            "admission_sha256",
            "candidate_sha256",
            "source_bound_verification_sha256",
            "authorization_sha256",
            "validation_sha256",
            "worm_repository_alias_sha256",
            "object_key_sha256",
            "object_version_sha256",
            "stored_content_sha256",
        ):
            _sha256(name, getattr(self, name))
        _integer(
            "STORED_CONTENT_SIZE_BYTES",
            self.stored_content_size_bytes,
            minimum=1,
            maximum=MAXIMUM_OBJECT_BYTES,
        )
        if (
            self.custody_verified is not True
            or self.schema_version != VERIFIED_CUSTODY_SCHEMA
            or not _safety_is_locked(self)
        ):
            _reject("VERIFIED_ADMISSION_CUSTODY_SAFETY_DRIFT")
        object.__setattr__(
            self,
            "_verification_seal",
            _VERIFIED_CUSTODY_SEAL,
        )

    def to_canonical_dict(self) -> dict[str, object]:
        return _public_contract_dict(self)


def is_verified_live_canary_admission_custody(value: object) -> bool:
    """Return true only for custody sealed by this verifier module."""

    return (
        type(value) is VerifiedLiveCanaryAdmissionCustody
        and getattr(value, "_verification_seal", None)
        is _VERIFIED_CUSTODY_SEAL
    )


@dataclass(frozen=True, slots=True)
class LiveCanaryLaunchReservationProposal(CanonicalContract):
    """Canonical, non-secret input to one external atomic reservation."""

    sequence: int
    predecessor_checkpoint_sha256: str
    custody_policy_sha256: str
    custody_verification_sha256: str
    admission_sha256: str
    candidate_sha256: str
    authorization_sha256: str
    validation_sha256: str
    launcher_trust_policy_sha256: str
    launcher_attestation_sha256: str
    launcher_nonce_sha256: str
    release_identity_sha256: str
    deployment_host_alias_sha256: str
    service_account_alias_sha256: str
    task_definition_sha256: str
    requested_at_utc: datetime
    expires_at_utc: datetime
    live_allowed: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    bootstrap_authorized: bool = field(default=False, init=False)
    process_launch_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    schema_version: str = field(default=LAUNCH_PROPOSAL_SCHEMA, init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "sequence",
            _integer("SEQUENCE", self.sequence, minimum=1, maximum=2**63 - 1),
        )
        object.__setattr__(
            self,
            "predecessor_checkpoint_sha256",
            _sha256(
                "PREDECESSOR_CHECKPOINT_SHA256",
                self.predecessor_checkpoint_sha256,
                allow_zero=True,
            ),
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
            object.__setattr__(self, name, _sha256(name, getattr(self, name)))
        requested = _utc("REQUESTED_AT_UTC", self.requested_at_utc)
        expires = _utc("EXPIRES_AT_UTC", self.expires_at_utc)
        if (
            requested >= expires
            or expires - requested
            > timedelta(seconds=MAXIMUM_LAUNCH_TTL_SECONDS)
        ):
            _reject("LAUNCH_RESERVATION_WINDOW_INVALID")
        if (self.sequence == 1) != (
            self.predecessor_checkpoint_sha256 == ZERO_SHA256
        ):
            _reject("LAUNCH_RESERVATION_PREDECESSOR_INVALID")
        if self.schema_version != LAUNCH_PROPOSAL_SCHEMA or not _safety_is_locked(
            self
        ):
            _reject("LAUNCH_PROPOSAL_SAFETY_DRIFT")


@dataclass(frozen=True, slots=True)
class LiveCanaryLaunchReservationCheckpoint(CanonicalContract):
    """Externally signed new replay-ledger head."""

    proposal: LiveCanaryLaunchReservationProposal
    proposal_sha256: str
    committed_at_utc: datetime
    custody_issuer_id: str
    custody_key_id: str
    public_key_fingerprint_sha256: str
    signature_rsa_pkcs1v15_sha256_hex: str = ""
    live_allowed: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    bootstrap_authorized: bool = field(default=False, init=False)
    process_launch_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    signature_algorithm: str = field(default=SIGNATURE_ALGORITHM, init=False)
    schema_version: str = field(default=LAUNCH_CHECKPOINT_SCHEMA, init=False)

    def __post_init__(self) -> None:
        if type(self.proposal) is not LiveCanaryLaunchReservationProposal:
            _reject("LAUNCH_CHECKPOINT_PROPOSAL_TYPE_INVALID")
        proposal_sha = _sha256("PROPOSAL_SHA256", self.proposal_sha256)
        if proposal_sha != self.proposal.content_sha256:
            _reject("LAUNCH_CHECKPOINT_PROPOSAL_HASH_MISMATCH")
        committed = _utc("COMMITTED_AT_UTC", self.committed_at_utc)
        if not self.proposal.requested_at_utc <= committed < self.proposal.expires_at_utc:
            _reject("LAUNCH_CHECKPOINT_TIME_INVALID")
        for name in ("custody_issuer_id", "custody_key_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        object.__setattr__(
            self,
            "public_key_fingerprint_sha256",
            _sha256(
                "PUBLIC_KEY_FINGERPRINT_SHA256",
                self.public_key_fingerprint_sha256,
            ),
        )
        object.__setattr__(
            self,
            "signature_rsa_pkcs1v15_sha256_hex",
            _signature(self.signature_rsa_pkcs1v15_sha256_hex),
        )
        if (
            self.signature_algorithm != SIGNATURE_ALGORITHM
            or self.schema_version != LAUNCH_CHECKPOINT_SCHEMA
            or not _safety_is_locked(self)
        ):
            _reject("LAUNCH_CHECKPOINT_SAFETY_DRIFT")

    @property
    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_rsa_pkcs1v15_sha256_hex")
        return payload


@dataclass(frozen=True, slots=True)
class LiveCanaryLaunchReservationAcknowledgement(CanonicalContract):
    """Separately signed acknowledgement for the atomic CAS result."""

    expected_predecessor_checkpoint_sha256: str
    written_checkpoint_sha256: str
    proposal_sha256: str
    launcher_nonce_sha256: str
    sequence: int
    acknowledged_at_utc: datetime
    custody_issuer_id: str
    custody_key_id: str
    public_key_fingerprint_sha256: str
    signature_rsa_pkcs1v15_sha256_hex: str = ""
    live_allowed: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    bootstrap_authorized: bool = field(default=False, init=False)
    process_launch_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    signature_algorithm: str = field(default=SIGNATURE_ALGORITHM, init=False)
    schema_version: str = field(default=LAUNCH_ACK_SCHEMA, init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "expected_predecessor_checkpoint_sha256",
            _sha256(
                "EXPECTED_PREDECESSOR_CHECKPOINT_SHA256",
                self.expected_predecessor_checkpoint_sha256,
                allow_zero=True,
            ),
        )
        for name in (
            "written_checkpoint_sha256",
            "proposal_sha256",
            "launcher_nonce_sha256",
            "public_key_fingerprint_sha256",
        ):
            object.__setattr__(self, name, _sha256(name, getattr(self, name)))
        object.__setattr__(
            self,
            "sequence",
            _integer("SEQUENCE", self.sequence, minimum=1, maximum=2**63 - 1),
        )
        _utc("ACKNOWLEDGED_AT_UTC", self.acknowledged_at_utc)
        for name in ("custody_issuer_id", "custody_key_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        object.__setattr__(
            self,
            "signature_rsa_pkcs1v15_sha256_hex",
            _signature(self.signature_rsa_pkcs1v15_sha256_hex),
        )
        if (
            self.signature_algorithm != SIGNATURE_ALGORITHM
            or self.schema_version != LAUNCH_ACK_SCHEMA
            or not _safety_is_locked(self)
        ):
            _reject("LAUNCH_ACK_SAFETY_DRIFT")

    @property
    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_rsa_pkcs1v15_sha256_hex")
        return payload


@dataclass(frozen=True, slots=True)
class LiveCanaryOneUseLaunchCapability(CanonicalContract):
    """Sealed short-lived launch prerequisite with no effect authority."""

    checked_at_utc: datetime
    expires_at_utc: datetime
    sequence: int
    launch_nonce_sha256: str
    candidate_sha256: str
    admission_sha256: str
    custody_verification_sha256: str
    launcher_attestation_sha256: str
    proposal_sha256: str
    checkpoint_sha256: str
    acknowledgement_sha256: str
    launch_reservation_consumed_once: bool = field(default=True, init=False)
    launch_prerequisite_verified: bool = field(default=True, init=False)
    central_unlock_required: bool = field(default=True, init=False)
    live_allowed: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    bootstrap_authorized: bool = field(default=False, init=False)
    process_launch_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    schema_version: str = field(default=LAUNCH_CAPABILITY_SCHEMA, init=False)
    _capability_seal: object = field(init=False, repr=False, compare=False)
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _CAPABILITY_SEAL:
            raise TypeError("one-use launch capability requires its verifier")
        checked = _utc("CHECKED_AT_UTC", self.checked_at_utc)
        expires = _utc("EXPIRES_AT_UTC", self.expires_at_utc)
        if checked >= expires:
            _reject("ONE_USE_LAUNCH_CAPABILITY_EXPIRED")
        _integer("SEQUENCE", self.sequence, minimum=1, maximum=2**63 - 1)
        for name in (
            "launch_nonce_sha256",
            "candidate_sha256",
            "admission_sha256",
            "custody_verification_sha256",
            "launcher_attestation_sha256",
            "proposal_sha256",
            "checkpoint_sha256",
            "acknowledgement_sha256",
        ):
            _sha256(name, getattr(self, name))
        if (
            self.launch_reservation_consumed_once is not True
            or self.launch_prerequisite_verified is not True
            or self.central_unlock_required is not True
            or self.schema_version != LAUNCH_CAPABILITY_SCHEMA
            or not _safety_is_locked(self)
        ):
            _reject("ONE_USE_LAUNCH_CAPABILITY_SAFETY_DRIFT")
        object.__setattr__(self, "_capability_seal", _CAPABILITY_SEAL)

    def to_canonical_dict(self) -> dict[str, object]:
        return _public_contract_dict(self)


def is_live_canary_one_use_launch_capability(value: object) -> bool:
    """Return true only for a capability sealed by this verifier module."""

    return (
        type(value) is LiveCanaryOneUseLaunchCapability
        and getattr(value, "_capability_seal", None) is _CAPABILITY_SEAL
    )


def _signing_message(domain: bytes, payload: dict[str, object]) -> bytes:
    return domain + canonical_json(payload).encode("utf-8")


def admission_custody_signing_message(
    receipt: LiveCanaryAdmissionCustodyReceipt,
) -> bytes:
    if type(receipt) is not LiveCanaryAdmissionCustodyReceipt:
        raise TypeError("exact admission custody receipt required")
    return _signing_message(_RECEIPT_DOMAIN, receipt.signing_dict)


def launch_checkpoint_signing_message(
    checkpoint: LiveCanaryLaunchReservationCheckpoint,
) -> bytes:
    if type(checkpoint) is not LiveCanaryLaunchReservationCheckpoint:
        raise TypeError("exact launch checkpoint required")
    return _signing_message(_CHECKPOINT_DOMAIN, checkpoint.signing_dict)


def launch_acknowledgement_signing_message(
    acknowledgement: LiveCanaryLaunchReservationAcknowledgement,
) -> bytes:
    if type(acknowledgement) is not LiveCanaryLaunchReservationAcknowledgement:
        raise TypeError("exact launch acknowledgement required")
    return _signing_message(_ACK_DOMAIN, acknowledgement.signing_dict)


_RECEIPT_FIELDS = frozenset(
    item.name for item in dataclass_fields(LiveCanaryAdmissionCustodyReceipt)
)
_PROPOSAL_FIELDS = frozenset(
    item.name for item in dataclass_fields(LiveCanaryLaunchReservationProposal)
)
_CHECKPOINT_FIELDS = frozenset(
    item.name for item in dataclass_fields(LiveCanaryLaunchReservationCheckpoint)
)
_ACK_FIELDS = frozenset(
    item.name
    for item in dataclass_fields(LiveCanaryLaunchReservationAcknowledgement)
)


def decode_live_canary_admission_custody_receipt(
    payload: bytes,
) -> LiveCanaryAdmissionCustodyReceipt:
    raw, text = _strict_json(payload, kind="ADMISSION_CUSTODY_RECEIPT")
    if set(raw) != _RECEIPT_FIELDS:
        _reject("ADMISSION_CUSTODY_RECEIPT_SCHEMA_INVALID")
    values = _constructor_values(LiveCanaryAdmissionCustodyReceipt, raw)
    for name in ("uploaded_at_utc", "retain_until_utc"):
        values[name] = _parse_utc(name, values[name])
    try:
        receipt = LiveCanaryAdmissionCustodyReceipt(**values)
    except LiveCanaryPortableLaunchCustodyError:
        raise
    except (TypeError, ValueError, KeyError) as exc:
        raise LiveCanaryPortableLaunchCustodyError(
            "ADMISSION_CUSTODY_RECEIPT_SCHEMA_INVALID"
        ) from exc
    if (
        not receipt.signature_rsa_pkcs1v15_sha256_hex
        or receipt.canonical_json() != text
    ):
        _reject("ADMISSION_CUSTODY_RECEIPT_NOT_CANONICAL")
    return receipt


def _proposal_from_dict(raw: object) -> LiveCanaryLaunchReservationProposal:
    if type(raw) is not dict or set(raw) != _PROPOSAL_FIELDS:
        _reject("LAUNCH_PROPOSAL_SCHEMA_INVALID")
    values = _constructor_values(LiveCanaryLaunchReservationProposal, raw)
    for name in ("requested_at_utc", "expires_at_utc"):
        values[name] = _parse_utc(name, values[name])
    try:
        return LiveCanaryLaunchReservationProposal(**values)
    except LiveCanaryPortableLaunchCustodyError:
        raise
    except (TypeError, ValueError, KeyError) as exc:
        raise LiveCanaryPortableLaunchCustodyError(
            "LAUNCH_PROPOSAL_SCHEMA_INVALID"
        ) from exc


def decode_live_canary_launch_proposal(
    payload: bytes,
) -> LiveCanaryLaunchReservationProposal:
    raw, text = _strict_json(payload, kind="LAUNCH_PROPOSAL")
    proposal = _proposal_from_dict(raw)
    if proposal.canonical_json() != text:
        _reject("LAUNCH_PROPOSAL_NOT_CANONICAL")
    return proposal


def decode_live_canary_launch_checkpoint(
    payload: bytes,
) -> LiveCanaryLaunchReservationCheckpoint:
    raw, text = _strict_json(payload, kind="LAUNCH_CHECKPOINT")
    if set(raw) != _CHECKPOINT_FIELDS:
        _reject("LAUNCH_CHECKPOINT_SCHEMA_INVALID")
    values = _constructor_values(LiveCanaryLaunchReservationCheckpoint, raw)
    values["proposal"] = _proposal_from_dict(values["proposal"])
    values["committed_at_utc"] = _parse_utc(
        "committed_at_utc",
        values["committed_at_utc"],
    )
    try:
        checkpoint = LiveCanaryLaunchReservationCheckpoint(**values)
    except LiveCanaryPortableLaunchCustodyError:
        raise
    except (TypeError, ValueError, KeyError) as exc:
        raise LiveCanaryPortableLaunchCustodyError(
            "LAUNCH_CHECKPOINT_SCHEMA_INVALID"
        ) from exc
    if (
        not checkpoint.signature_rsa_pkcs1v15_sha256_hex
        or checkpoint.canonical_json() != text
    ):
        _reject("LAUNCH_CHECKPOINT_NOT_CANONICAL")
    return checkpoint


def decode_live_canary_launch_acknowledgement(
    payload: bytes,
) -> LiveCanaryLaunchReservationAcknowledgement:
    raw, text = _strict_json(payload, kind="LAUNCH_ACK")
    if set(raw) != _ACK_FIELDS:
        _reject("LAUNCH_ACK_SCHEMA_INVALID")
    values = _constructor_values(
        LiveCanaryLaunchReservationAcknowledgement,
        raw,
    )
    values["acknowledged_at_utc"] = _parse_utc(
        "acknowledged_at_utc",
        values["acknowledged_at_utc"],
    )
    try:
        acknowledgement = LiveCanaryLaunchReservationAcknowledgement(**values)
    except LiveCanaryPortableLaunchCustodyError:
        raise
    except (TypeError, ValueError, KeyError) as exc:
        raise LiveCanaryPortableLaunchCustodyError(
            "LAUNCH_ACK_SCHEMA_INVALID"
        ) from exc
    if (
        not acknowledgement.signature_rsa_pkcs1v15_sha256_hex
        or acknowledgement.canonical_json() != text
    ):
        _reject("LAUNCH_ACK_NOT_CANONICAL")
    return acknowledgement


def _verify_rsa_document(
    *,
    policy: LiveCanaryPortableCustodyPolicy,
    domain: bytes,
    signing_dict: dict[str, object],
    signature_hex: str,
    reason_code: str,
) -> None:
    if not verify_rsa_pkcs1v15_sha256(
        modulus_hex=policy.rsa_modulus_hex,
        exponent=policy.rsa_exponent,
        message=_signing_message(domain, signing_dict),
        signature_hex=signature_hex,
    ):
        _reject(reason_code)


def _clock(clock_provider: object, *, phase: str) -> datetime:
    if not callable(clock_provider):
        _reject("TRUSTED_CLOCK_PROVIDER_INVALID")
    try:
        observed = clock_provider()
    except Exception:
        raise LiveCanaryPortableLaunchCustodyError(
            f"TRUSTED_CLOCK_{phase}_UNAVAILABLE"
        ) from None
    return _utc("TRUSTED_CLOCK", observed)


def _call_provider(provider: object, *args: object, reason_code: str) -> object:
    if not callable(provider):
        _reject(f"{reason_code}_INVALID")
    try:
        return provider(*args)
    except Exception:
        raise LiveCanaryPortableLaunchCustodyError(reason_code) from None


def verify_live_canary_admission_custody(
    receipt_payload: bytes,
    *,
    policy: LiveCanaryPortableCustodyPolicy,
    expected_policy_sha256: str,
    admission: LiveCanaryPrebootstrapAdmission,
    object_readback_provider: Callable[[str, str, str], bytes],
    clock_provider: Callable[[], datetime],
) -> VerifiedLiveCanaryAdmissionCustody:
    """Verify exact signed WORM retention without granting launch authority."""

    _require_central_live_lock()
    if type(policy) is not LiveCanaryPortableCustodyPolicy:
        _reject("CUSTODY_POLICY_TYPE_INVALID")
    expected_policy = _sha256(
        "EXPECTED_CUSTODY_POLICY_SHA256",
        expected_policy_sha256,
    )
    if policy.content_sha256 != expected_policy:
        _reject("CUSTODY_POLICY_PIN_MISMATCH")
    if not is_live_canary_prebootstrap_admission(admission):
        _reject("PREBOOTSTRAP_ADMISSION_UNSEALED")

    started = _clock(clock_provider, phase="START")
    receipt = decode_live_canary_admission_custody_receipt(receipt_payload)
    expected = (
        (receipt.custody_policy_sha256, policy.content_sha256),
        (receipt.admission_sha256, admission.content_sha256),
        (receipt.candidate_sha256, admission.candidate_sha256),
        (
            receipt.source_bound_verification_sha256,
            admission.source_bound_verification_sha256,
        ),
        (receipt.authorization_sha256, admission.authorization_sha256),
        (receipt.validation_sha256, admission.validation_sha256),
        (
            receipt.worm_repository_alias_sha256,
            policy.worm_repository_alias_sha256,
        ),
        (receipt.custody_issuer_id, policy.custody_issuer_id),
        (receipt.custody_key_id, policy.custody_key_id),
        (
            receipt.public_key_fingerprint_sha256,
            policy.public_key_fingerprint_sha256,
        ),
    )
    if any(left != right for left, right in expected):
        _reject("ADMISSION_CUSTODY_RECEIPT_BINDING_MISMATCH")
    admission_bytes = admission.canonical_json().encode("utf-8")
    if (
        receipt.stored_content_sha256
        != hashlib.sha256(admission_bytes).hexdigest()
        or receipt.stored_content_size_bytes != len(admission_bytes)
    ):
        _reject("ADMISSION_CUSTODY_CONTENT_BINDING_MISMATCH")
    if (
        receipt.uploaded_at_utc < admission.checked_at
        or receipt.uploaded_at_utc > started
        or started - receipt.uploaded_at_utc
        > timedelta(seconds=policy.maximum_receipt_age_seconds)
        or receipt.retain_until_utc - receipt.uploaded_at_utc
        < timedelta(seconds=policy.minimum_retention_seconds)
        or started >= receipt.retain_until_utc
    ):
        _reject("ADMISSION_CUSTODY_TIME_OR_RETENTION_INVALID")
    _verify_rsa_document(
        policy=policy,
        domain=_RECEIPT_DOMAIN,
        signing_dict=receipt.signing_dict,
        signature_hex=receipt.signature_rsa_pkcs1v15_sha256_hex,
        reason_code="ADMISSION_CUSTODY_SIGNATURE_INVALID",
    )
    readback = _call_provider(
        object_readback_provider,
        receipt.worm_repository_alias_sha256,
        receipt.object_key_sha256,
        receipt.object_version_sha256,
        reason_code="ADMISSION_CUSTODY_READBACK_FAILED",
    )
    if type(readback) is not bytes or not readback or len(readback) > MAXIMUM_OBJECT_BYTES:
        _reject("ADMISSION_CUSTODY_READBACK_INVALID")
    if readback != admission_bytes:
        _reject("ADMISSION_CUSTODY_READBACK_MISMATCH")
    completed = _clock(clock_provider, phase="COMPLETION")
    if (
        completed < started
        or completed >= receipt.retain_until_utc
        or completed - receipt.uploaded_at_utc
        > timedelta(seconds=policy.maximum_receipt_age_seconds)
    ):
        _reject("ADMISSION_CUSTODY_CLOCK_WINDOW_INVALID")
    _require_central_live_lock()
    return VerifiedLiveCanaryAdmissionCustody(
        checked_at_utc=completed,
        receipt_sha256=receipt.content_sha256,
        custody_policy_sha256=policy.content_sha256,
        admission_sha256=admission.content_sha256,
        candidate_sha256=admission.candidate_sha256,
        source_bound_verification_sha256=(
            admission.source_bound_verification_sha256
        ),
        authorization_sha256=admission.authorization_sha256,
        validation_sha256=admission.validation_sha256,
        worm_repository_alias_sha256=receipt.worm_repository_alias_sha256,
        object_key_sha256=receipt.object_key_sha256,
        object_version_sha256=receipt.object_version_sha256,
        stored_content_sha256=receipt.stored_content_sha256,
        stored_content_size_bytes=receipt.stored_content_size_bytes,
        retain_until_utc=receipt.retain_until_utc,
        _seal=_VERIFIED_CUSTODY_SEAL,
    )


def _checkpoint_authority_matches(
    value: object,
    policy: LiveCanaryPortableCustodyPolicy,
) -> bool:
    return (
        getattr(value, "custody_issuer_id", None) == policy.custody_issuer_id
        and getattr(value, "custody_key_id", None) == policy.custody_key_id
        and getattr(value, "public_key_fingerprint_sha256", None)
        == policy.public_key_fingerprint_sha256
    )


def _verify_checkpoint(
    checkpoint: LiveCanaryLaunchReservationCheckpoint,
    policy: LiveCanaryPortableCustodyPolicy,
) -> None:
    if not _checkpoint_authority_matches(checkpoint, policy):
        _reject("LAUNCH_CHECKPOINT_AUTHORITY_MISMATCH")
    if checkpoint.proposal.custody_policy_sha256 != policy.content_sha256:
        _reject("LAUNCH_CHECKPOINT_POLICY_MISMATCH")
    _verify_rsa_document(
        policy=policy,
        domain=_CHECKPOINT_DOMAIN,
        signing_dict=checkpoint.signing_dict,
        signature_hex=checkpoint.signature_rsa_pkcs1v15_sha256_hex,
        reason_code="LAUNCH_CHECKPOINT_SIGNATURE_INVALID",
    )


def _require_launch_inputs(
    *,
    candidate: LiveCanaryRuntimeCandidate,
    admission: LiveCanaryPrebootstrapAdmission,
    custody_verification: VerifiedLiveCanaryAdmissionCustody,
    activation_trust_policy: LiveCanaryTrustPolicy,
    authorization: LiveCanaryActivationAuthorization,
    validation: LiveCanaryActivationValidation,
    custody_policy: LiveCanaryPortableCustodyPolicy,
    expected_custody_policy_sha256: str,
    launcher_policy: ExternalLauncherTrustPolicy,
    launcher_attestation: VerifiedExternalLauncherAttestation,
) -> None:
    if type(candidate) is not LiveCanaryRuntimeCandidate:
        _reject("LIVE_RUNTIME_CANDIDATE_TYPE_INVALID")
    if not is_live_canary_prebootstrap_admission(admission):
        _reject("PREBOOTSTRAP_ADMISSION_UNSEALED")
    if not is_verified_live_canary_admission_custody(custody_verification):
        _reject("ADMISSION_CUSTODY_VERIFICATION_UNSEALED")
    if type(activation_trust_policy) is not LiveCanaryTrustPolicy:
        _reject("ACTIVATION_TRUST_POLICY_TYPE_INVALID")
    if type(authorization) is not LiveCanaryActivationAuthorization:
        _reject("ACTIVATION_AUTHORIZATION_TYPE_INVALID")
    if type(validation) is not LiveCanaryActivationValidation:
        _reject("ACTIVATION_VALIDATION_TYPE_INVALID")
    if type(custody_policy) is not LiveCanaryPortableCustodyPolicy:
        _reject("CUSTODY_POLICY_TYPE_INVALID")
    expected_policy = _sha256(
        "EXPECTED_CUSTODY_POLICY_SHA256",
        expected_custody_policy_sha256,
    )
    if custody_policy.content_sha256 != expected_policy:
        _reject("CUSTODY_POLICY_PIN_MISMATCH")
    if type(launcher_policy) is not ExternalLauncherTrustPolicy:
        _reject("LAUNCHER_TRUST_POLICY_TYPE_INVALID")
    if not is_verified_external_launcher_attestation(launcher_attestation):
        _reject("EXTERNAL_LAUNCHER_ATTESTATION_UNSEALED")

    expected = (
        (admission.candidate_sha256, candidate.content_sha256),
        (admission.authorization_sha256, authorization.content_sha256),
        (admission.validation_sha256, validation.content_sha256),
        (
            admission.trust_policy_sha256,
            activation_trust_policy.policy_sha256,
        ),
        (custody_verification.admission_sha256, admission.content_sha256),
        (
            custody_verification.candidate_sha256,
            candidate.content_sha256,
        ),
        (
            custody_verification.authorization_sha256,
            authorization.content_sha256,
        ),
        (
            custody_verification.validation_sha256,
            validation.content_sha256,
        ),
        (
            custody_verification.custody_policy_sha256,
            custody_policy.content_sha256,
        ),
        (
            custody_policy.launcher_trust_policy_sha256,
            launcher_policy.content_sha256,
        ),
        (
            custody_policy.deployment_host_alias_sha256,
            launcher_policy.deployment_host_alias_sha256,
        ),
        (
            custody_policy.service_account_alias_sha256,
            launcher_policy.service_account_alias_sha256,
        ),
        (
            custody_policy.task_definition_sha256,
            launcher_policy.task_definition_sha256,
        ),
        (
            launcher_attestation.trust_policy_sha256,
            launcher_policy.content_sha256,
        ),
        (
            launcher_attestation.release_identity_sha256,
            candidate.release_manifest_sha256,
        ),
    )
    if any(left != right for left, right in expected):
        _reject("LIVE_CANARY_LAUNCH_INPUT_BINDING_MISMATCH")
    if launcher_policy.release_profile != EXECUTION_RELEASE_PROFILE:
        _reject("LIVE_CANARY_LAUNCHER_PROFILE_MISMATCH")

    runtime_ids = candidate.runtime_key_ids
    runtime_fingerprints = candidate.runtime_key_fingerprints
    activation_ids = activation_trust_policy.authority_key_ids
    activation_fingerprints = activation_trust_policy.authority_key_fingerprints
    custody_id = custody_policy.custody_key_id
    custody_fingerprint = custody_policy.public_key_fingerprint_sha256
    launcher_id = launcher_policy.issuer_key_id
    launcher_fingerprint = launcher_policy.public_key_fingerprint_sha256
    if (
        custody_id == launcher_id
        or custody_fingerprint == launcher_fingerprint
        or custody_id in runtime_ids
        or custody_id in activation_ids
        or launcher_id in runtime_ids
        or launcher_id in activation_ids
        or custody_fingerprint in runtime_fingerprints
        or custody_fingerprint in activation_fingerprints
        or launcher_fingerprint in runtime_fingerprints
        or launcher_fingerprint in activation_fingerprints
    ):
        _reject("LIVE_CANARY_LAUNCH_AUTHORITY_REUSE")


def consume_live_canary_launch_reservation(
    *,
    candidate: LiveCanaryRuntimeCandidate,
    admission: LiveCanaryPrebootstrapAdmission,
    custody_verification: VerifiedLiveCanaryAdmissionCustody,
    activation_trust_policy: LiveCanaryTrustPolicy,
    authorization: LiveCanaryActivationAuthorization,
    validation: LiveCanaryActivationValidation,
    custody_policy: LiveCanaryPortableCustodyPolicy,
    expected_custody_policy_sha256: str,
    launcher_policy: ExternalLauncherTrustPolicy,
    launcher_attestation: VerifiedExternalLauncherAttestation,
    expected_predecessor_checkpoint_sha256: str,
    external_checkpoint_provider: Callable[[], bytes | None],
    external_checkpoint_cas: Callable[[str, bytes], tuple[bytes, bytes]],
    external_nonce_seen_provider: Callable[[str], bool],
    clock_provider: Callable[[], datetime],
) -> LiveCanaryOneUseLaunchCapability:
    """Atomically reserve one signed launcher nonce while LIVE stays locked."""

    _require_central_live_lock()
    _require_launch_inputs(
        candidate=candidate,
        admission=admission,
        custody_verification=custody_verification,
        activation_trust_policy=activation_trust_policy,
        authorization=authorization,
        validation=validation,
        custody_policy=custody_policy,
        expected_custody_policy_sha256=expected_custody_policy_sha256,
        launcher_policy=launcher_policy,
        launcher_attestation=launcher_attestation,
    )
    for name, provider in (
        ("EXTERNAL_CHECKPOINT_PROVIDER", external_checkpoint_provider),
        ("EXTERNAL_CHECKPOINT_CAS", external_checkpoint_cas),
        ("EXTERNAL_NONCE_SEEN_PROVIDER", external_nonce_seen_provider),
    ):
        if not callable(provider):
            _reject(f"{name}_INVALID")
    pinned_predecessor = _sha256(
        "EXPECTED_PREDECESSOR_CHECKPOINT_SHA256",
        expected_predecessor_checkpoint_sha256,
        allow_zero=True,
    )

    started = _clock(clock_provider, phase="START")
    request = authorization.request
    if (
        started < admission.checked_at
        or started < custody_verification.checked_at_utc
        or started < validation.checked_at
        or started < request.issued_at
        or started >= request.expires_at
        or started >= custody_verification.retain_until_utc
    ):
        _reject("LIVE_CANARY_LAUNCH_TIME_INVALID")
    try:
        launcher_attestation.assert_current(
            now=started,
            expected_release_identity_sha256=candidate.release_manifest_sha256,
            expected_release_profile=EXECUTION_RELEASE_PROFILE,
        )
    except Exception:
        raise LiveCanaryPortableLaunchCustodyError(
            "EXTERNAL_LAUNCHER_ATTESTATION_NOT_CURRENT"
        ) from None
    nonce = launcher_attestation.nonce_sha256
    seen_before = _call_provider(
        external_nonce_seen_provider,
        nonce,
        reason_code="EXTERNAL_NONCE_PRECHECK_FAILED",
    )
    if type(seen_before) is not bool:
        _reject("EXTERNAL_NONCE_PRECHECK_INVALID")
    if seen_before:
        _reject("LIVE_CANARY_LAUNCH_NONCE_REPLAYED")

    current_payload = _call_provider(
        external_checkpoint_provider,
        reason_code="EXTERNAL_CHECKPOINT_READ_FAILED",
    )
    if current_payload is None:
        sequence = 1
        observed_predecessor = ZERO_SHA256
    else:
        if type(current_payload) is not bytes:
            _reject("EXTERNAL_CHECKPOINT_PAYLOAD_INVALID")
        current = decode_live_canary_launch_checkpoint(current_payload)
        _verify_checkpoint(current, custody_policy)
        if current.committed_at_utc > started:
            _reject("EXTERNAL_CHECKPOINT_FROM_FUTURE")
        current_expected = (
            (current.proposal.candidate_sha256, candidate.content_sha256),
            (
                current.proposal.launcher_trust_policy_sha256,
                launcher_policy.content_sha256,
            ),
            (
                current.proposal.release_identity_sha256,
                candidate.release_manifest_sha256,
            ),
            (
                current.proposal.deployment_host_alias_sha256,
                custody_policy.deployment_host_alias_sha256,
            ),
            (
                current.proposal.service_account_alias_sha256,
                custody_policy.service_account_alias_sha256,
            ),
            (
                current.proposal.task_definition_sha256,
                custody_policy.task_definition_sha256,
            ),
        )
        if any(left != right for left, right in current_expected):
            _reject("EXTERNAL_CHECKPOINT_LANE_BINDING_MISMATCH")
        sequence = current.proposal.sequence + 1
        if sequence > 2**63 - 1:
            _reject("EXTERNAL_CHECKPOINT_SEQUENCE_EXHAUSTED")
        observed_predecessor = current.content_sha256
        predecessor_nonce_seen = _call_provider(
            external_nonce_seen_provider,
            current.proposal.launcher_nonce_sha256,
            reason_code="EXTERNAL_PREDECESSOR_NONCE_READ_FAILED",
        )
        if predecessor_nonce_seen is not True:
            _reject("EXTERNAL_PREDECESSOR_NONCE_MISSING")
    if observed_predecessor != pinned_predecessor:
        _reject("EXTERNAL_CHECKPOINT_PIN_MISMATCH")
    predecessor = pinned_predecessor

    expires = min(
        started + timedelta(seconds=custody_policy.maximum_launch_ttl_seconds),
        request.expires_at,
        launcher_attestation.expires_at_utc,
        custody_verification.retain_until_utc,
    )
    if expires <= started:
        _reject("LIVE_CANARY_LAUNCH_WINDOW_EXHAUSTED")
    proposal = LiveCanaryLaunchReservationProposal(
        sequence=sequence,
        predecessor_checkpoint_sha256=predecessor,
        custody_policy_sha256=custody_policy.content_sha256,
        custody_verification_sha256=custody_verification.content_sha256,
        admission_sha256=admission.content_sha256,
        candidate_sha256=candidate.content_sha256,
        authorization_sha256=authorization.content_sha256,
        validation_sha256=validation.content_sha256,
        launcher_trust_policy_sha256=launcher_policy.content_sha256,
        launcher_attestation_sha256=launcher_attestation.content_sha256,
        launcher_nonce_sha256=nonce,
        release_identity_sha256=candidate.release_manifest_sha256,
        deployment_host_alias_sha256=(
            custody_policy.deployment_host_alias_sha256
        ),
        service_account_alias_sha256=(
            custody_policy.service_account_alias_sha256
        ),
        task_definition_sha256=custody_policy.task_definition_sha256,
        requested_at_utc=started,
        expires_at_utc=expires,
    )
    cas_result = _call_provider(
        external_checkpoint_cas,
        predecessor,
        proposal.canonical_json().encode("utf-8"),
        reason_code="EXTERNAL_CHECKPOINT_CAS_FAILED",
    )
    if type(cas_result) is not tuple or len(cas_result) != 2:
        _reject("EXTERNAL_CHECKPOINT_CAS_RESULT_INVALID")
    checkpoint_payload, acknowledgement_payload = cas_result
    if type(checkpoint_payload) is not bytes or type(acknowledgement_payload) is not bytes:
        _reject("EXTERNAL_CHECKPOINT_CAS_RESULT_INVALID")
    checkpoint = decode_live_canary_launch_checkpoint(checkpoint_payload)
    acknowledgement = decode_live_canary_launch_acknowledgement(
        acknowledgement_payload
    )
    _verify_checkpoint(checkpoint, custody_policy)
    if checkpoint.proposal != proposal:
        _reject("LAUNCH_CHECKPOINT_PROPOSAL_MISMATCH")
    if not _checkpoint_authority_matches(acknowledgement, custody_policy):
        _reject("LAUNCH_ACK_AUTHORITY_MISMATCH")
    expected_ack = (
        (
            acknowledgement.expected_predecessor_checkpoint_sha256,
            predecessor,
        ),
        (acknowledgement.written_checkpoint_sha256, checkpoint.content_sha256),
        (acknowledgement.proposal_sha256, proposal.content_sha256),
        (acknowledgement.launcher_nonce_sha256, nonce),
        (acknowledgement.sequence, sequence),
    )
    if any(left != right for left, right in expected_ack):
        _reject("LAUNCH_ACK_BINDING_MISMATCH")
    if not (
        checkpoint.committed_at_utc
        <= acknowledgement.acknowledged_at_utc
        < proposal.expires_at_utc
    ):
        _reject("LAUNCH_ACK_TIME_INVALID")
    _verify_rsa_document(
        policy=custody_policy,
        domain=_ACK_DOMAIN,
        signing_dict=acknowledgement.signing_dict,
        signature_hex=acknowledgement.signature_rsa_pkcs1v15_sha256_hex,
        reason_code="LAUNCH_ACK_SIGNATURE_INVALID",
    )

    completed = _clock(clock_provider, phase="COMPLETION")
    if (
        completed < started
        or completed < acknowledgement.acknowledged_at_utc
        or completed >= proposal.expires_at_utc
    ):
        _reject("LIVE_CANARY_LAUNCH_CLOCK_WINDOW_INVALID")
    readback_payload = _call_provider(
        external_checkpoint_provider,
        reason_code="EXTERNAL_CHECKPOINT_READBACK_FAILED",
    )
    if readback_payload != checkpoint_payload:
        _reject("EXTERNAL_CHECKPOINT_READBACK_MISMATCH")
    seen_after = _call_provider(
        external_nonce_seen_provider,
        nonce,
        reason_code="EXTERNAL_NONCE_READBACK_FAILED",
    )
    if seen_after is not True:
        _reject("EXTERNAL_NONCE_READBACK_MISMATCH")
    _require_central_live_lock()
    return LiveCanaryOneUseLaunchCapability(
        checked_at_utc=completed,
        expires_at_utc=proposal.expires_at_utc,
        sequence=sequence,
        launch_nonce_sha256=nonce,
        candidate_sha256=candidate.content_sha256,
        admission_sha256=admission.content_sha256,
        custody_verification_sha256=custody_verification.content_sha256,
        launcher_attestation_sha256=launcher_attestation.content_sha256,
        proposal_sha256=proposal.content_sha256,
        checkpoint_sha256=checkpoint.content_sha256,
        acknowledgement_sha256=acknowledgement.content_sha256,
        _seal=_CAPABILITY_SEAL,
    )


__all__ = [
    "ADMISSION_RECEIPT_SCHEMA",
    "CUSTODY_POLICY_SCHEMA",
    "LAUNCH_ACK_SCHEMA",
    "LAUNCH_CAPABILITY_SCHEMA",
    "LAUNCH_CHECKPOINT_SCHEMA",
    "LAUNCH_PROPOSAL_SCHEMA",
    "LiveCanaryAdmissionCustodyReceipt",
    "LiveCanaryLaunchReservationAcknowledgement",
    "LiveCanaryLaunchReservationCheckpoint",
    "LiveCanaryLaunchReservationProposal",
    "LiveCanaryOneUseLaunchCapability",
    "LiveCanaryPortableCustodyPolicy",
    "LiveCanaryPortableLaunchCustodyError",
    "VerifiedLiveCanaryAdmissionCustody",
    "admission_custody_signing_message",
    "consume_live_canary_launch_reservation",
    "decode_live_canary_admission_custody_receipt",
    "decode_live_canary_launch_acknowledgement",
    "decode_live_canary_launch_checkpoint",
    "decode_live_canary_launch_proposal",
    "is_live_canary_one_use_launch_capability",
    "is_verified_live_canary_admission_custody",
    "launch_acknowledgement_signing_message",
    "launch_checkpoint_signing_message",
    "verify_live_canary_admission_custody",
]
