"""WORM custody for an exact provider-bound LIVE canary admission."""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field, fields
from datetime import datetime, timedelta
import hashlib
import json
import re
from typing import Callable

import execution_policy

from .asymmetric_release_trust import (
    SIGNATURE_ALGORITHM,
    verify_rsa_pkcs1v15_sha256,
)
from .contracts import CanonicalContract, canonical_json, canonicalize
from .live_canary_portable_launch_custody import (
    LiveCanaryPortableCustodyPolicy,
)
from .live_canary_provider_bound_prebootstrap_admission import (
    LiveCanaryProviderBoundPrebootstrapAdmission,
    is_live_canary_provider_bound_prebootstrap_admission,
)
from .windows_live_provider_conformance_acceptance import (
    WindowsLiveProviderAcceptancePolicy,
)


PROVIDER_BOUND_ADMISSION_RECEIPT_SCHEMA = (
    "live-canary-provider-bound-admission-worm-receipt-v2"
)
VERIFIED_PROVIDER_BOUND_CUSTODY_SCHEMA = (
    "live-canary-verified-provider-bound-admission-custody-v2"
)
ORDER_CAPABILITY = "DISABLED"
RETENTION_MODE = "COMPLIANCE"
MAXIMUM_DOCUMENT_BYTES = 262_144
MAXIMUM_OBJECT_BYTES = 1_048_576

_RECEIPT_DOMAIN = (
    b"AI_SCALPER:LIVE_CANARY:PROVIDER_BOUND_ADMISSION_WORM:v2\x00"
)
_HEX = re.compile(r"^[0-9a-f]+$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_VERIFICATION_SEAL = object()


class LiveCanaryProviderBoundPortableCustodyError(RuntimeError):
    """One provider-bound custody invariant failed with a reason code."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: object) -> None:
        normalized = re.sub(
            r"[^A-Z0-9_]+",
            "_",
            str(reason_code or "").strip().upper(),
        ).strip("_")
        self.reason_code = (
            normalized or "LIVE_CANARY_PROVIDER_BOUND_CUSTODY_INVALID"
        )
        super().__init__(self.reason_code)


def _reject(reason_code: str) -> None:
    raise LiveCanaryProviderBoundPortableCustodyError(reason_code)


def _identifier(name: str, value: object) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        _reject(f"{name}_INVALID")
    return value


def _sha256(name: str, value: object) -> str:
    if (
        type(value) is not str
        or _HEX_64.fullmatch(value) is None
        or value == "0" * 64
    ):
        _reject(f"{name}_INVALID")
    return value


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
    except ValueError:
        raise LiveCanaryProviderBoundPortableCustodyError(
            f"{name}_INVALID"
        ) from None
    result = _utc(name, parsed)
    if _utc_text(result) != value:
        _reject(f"{name}_NOT_CANONICAL")
    return result


def _signature(value: object) -> str:
    if value == "":
        return ""
    if (
        type(value) is not str
        or _HEX.fullmatch(value) is None
        or len(value) % 2
    ):
        _reject("SIGNATURE_RSA_PKCS1V15_SHA256_HEX_INVALID")
    return value


def _public_contract_dict(value: object) -> dict[str, object]:
    return {
        item.name: canonicalize(getattr(value, item.name))
        for item in fields(value)
        if not item.name.startswith("_")
    }


def _safety_is_locked(value: object) -> bool:
    return (
        getattr(value, "live_allowed", None) is False
        and getattr(value, "execution_authorized", None) is False
        and getattr(value, "bootstrap_authorized", None) is False
        and getattr(value, "process_launch_authorized", None) is False
        and getattr(value, "broker_mutation_authorized", None) is False
        and getattr(value, "order_capability", None) == ORDER_CAPABILITY
    )


def _require_central_live_lock() -> None:
    if execution_policy.LIVE_ALLOWED is not False:
        _reject("CENTRAL_LIVE_LOCK_NOT_FALSE")
    allowed, reasons = execution_policy.execution_mode_policy_decision("LIVE")
    if allowed is not False or reasons != ("LIVE_MODE_LOCKED",):
        _reject("CENTRAL_LIVE_POLICY_DECISION_DRIFT")


def _clock(clock_provider: object, *, phase: str) -> datetime:
    if not callable(clock_provider):
        _reject("TRUSTED_CLOCK_PROVIDER_INVALID")
    try:
        value = clock_provider()
    except Exception:
        raise LiveCanaryProviderBoundPortableCustodyError(
            f"TRUSTED_CLOCK_{phase}_UNAVAILABLE"
        ) from None
    return _utc(f"TRUSTED_CLOCK_{phase}", value)


@dataclass(frozen=True, slots=True)
class LiveCanaryProviderBoundAdmissionCustodyReceipt(CanonicalContract):
    """Externally signed WORM claim for provider-bound admission bytes."""

    receipt_id: str
    custody_policy_sha256: str
    provider_bound_admission_sha256: str
    legacy_admission_sha256: str
    candidate_sha256: str
    demo_source_bound_verification_sha256: str
    live_source_bound_verification_sha256: str
    provider_acceptance_sha256: str
    provider_acceptance_policy_sha256: str
    provider_conformance_review_sha256: str
    target_host_identity_sha256: str
    launcher_trust_policy_sha256: str
    service_account_alias_sha256: str
    installed_environment_sha256: str
    live_execution_release_identity_sha256: str
    live_execution_task_definition_sha256: str
    authorization_sha256: str
    validation_sha256: str
    provider_acceptance_valid_until_utc: datetime
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
    broker_mutation_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    signature_algorithm: str = field(
        default=SIGNATURE_ALGORITHM,
        init=False,
    )
    schema_version: str = field(
        default=PROVIDER_BOUND_ADMISSION_RECEIPT_SCHEMA,
        init=False,
    )

    def __post_init__(self) -> None:
        for name in ("receipt_id", "custody_issuer_id", "custody_key_id"):
            _identifier(name, getattr(self, name))
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
            _sha256(name, getattr(self, name))
        _integer(
            "STORED_CONTENT_SIZE_BYTES",
            self.stored_content_size_bytes,
            minimum=1,
            maximum=MAXIMUM_OBJECT_BYTES,
        )
        provider_expiry = _utc(
            "PROVIDER_ACCEPTANCE_VALID_UNTIL_UTC",
            self.provider_acceptance_valid_until_utc,
        )
        uploaded = _utc("UPLOADED_AT_UTC", self.uploaded_at_utc)
        retained = _utc("RETAIN_UNTIL_UTC", self.retain_until_utc)
        if uploaded >= provider_expiry or uploaded >= retained:
            _reject("PROVIDER_BOUND_CUSTODY_RECEIPT_WINDOW_INVALID")
        object.__setattr__(
            self,
            "signature_rsa_pkcs1v15_sha256_hex",
            _signature(self.signature_rsa_pkcs1v15_sha256_hex),
        )
        if (
            self.retention_mode != RETENTION_MODE
            or self.signature_algorithm != SIGNATURE_ALGORITHM
            or self.schema_version != PROVIDER_BOUND_ADMISSION_RECEIPT_SCHEMA
            or not _safety_is_locked(self)
        ):
            _reject("PROVIDER_BOUND_CUSTODY_RECEIPT_SAFETY_DRIFT")

    @property
    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_rsa_pkcs1v15_sha256_hex")
        return payload


@dataclass(frozen=True, slots=True)
class VerifiedLiveCanaryProviderBoundAdmissionCustody(CanonicalContract):
    """Sealed provider-bound RSA/WORM verification with bounded lifetime."""

    checked_at_utc: datetime
    valid_until_utc: datetime
    receipt_sha256: str
    custody_policy_sha256: str
    provider_bound_admission_sha256: str
    legacy_admission_sha256: str
    candidate_sha256: str
    provider_acceptance_sha256: str
    provider_acceptance_policy_sha256: str
    provider_conformance_review_sha256: str
    target_host_identity_sha256: str
    launcher_trust_policy_sha256: str
    service_account_alias_sha256: str
    installed_environment_sha256: str
    live_execution_release_identity_sha256: str
    live_execution_task_definition_sha256: str
    authorization_sha256: str
    validation_sha256: str
    worm_repository_alias_sha256: str
    object_key_sha256: str
    object_version_sha256: str
    stored_content_sha256: str
    stored_content_size_bytes: int
    retain_until_utc: datetime
    provider_acceptance_valid_until_utc: datetime
    provider_bound_custody_verified: bool = field(default=True, init=False)
    central_unlock_required: bool = field(default=True, init=False)
    live_allowed: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    bootstrap_authorized: bool = field(default=False, init=False)
    process_launch_authorized: bool = field(default=False, init=False)
    broker_mutation_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    schema_version: str = field(
        default=VERIFIED_PROVIDER_BOUND_CUSTODY_SCHEMA,
        init=False,
    )
    _verification_seal: object = field(init=False, repr=False, compare=False)
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _VERIFICATION_SEAL:
            raise TypeError(
                "provider-bound admission custody requires its verifier"
            )
        checked = _utc("CHECKED_AT_UTC", self.checked_at_utc)
        valid_until = _utc("VALID_UNTIL_UTC", self.valid_until_utc)
        retained = _utc("RETAIN_UNTIL_UTC", self.retain_until_utc)
        provider_expiry = _utc(
            "PROVIDER_ACCEPTANCE_VALID_UNTIL_UTC",
            self.provider_acceptance_valid_until_utc,
        )
        if (
            checked >= valid_until
            or valid_until != min(retained, provider_expiry)
        ):
            _reject("VERIFIED_PROVIDER_BOUND_CUSTODY_WINDOW_INVALID")
        for name in (
            "receipt_sha256",
            "custody_policy_sha256",
            "provider_bound_admission_sha256",
            "legacy_admission_sha256",
            "candidate_sha256",
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
        ):
            _sha256(name, getattr(self, name))
        _integer(
            "STORED_CONTENT_SIZE_BYTES",
            self.stored_content_size_bytes,
            minimum=1,
            maximum=MAXIMUM_OBJECT_BYTES,
        )
        if (
            self.provider_bound_custody_verified is not True
            or self.central_unlock_required is not True
            or self.schema_version != VERIFIED_PROVIDER_BOUND_CUSTODY_SCHEMA
            or not _safety_is_locked(self)
        ):
            _reject("VERIFIED_PROVIDER_BOUND_CUSTODY_SAFETY_DRIFT")
        object.__setattr__(
            self,
            "_verification_seal",
            _VERIFICATION_SEAL,
        )

    def to_canonical_dict(self) -> dict[str, object]:
        return _public_contract_dict(self)


def is_verified_live_canary_provider_bound_admission_custody(
    value: object,
) -> bool:
    """Return true only for exact custody sealed by this module."""

    return (
        type(value) is VerifiedLiveCanaryProviderBoundAdmissionCustody
        and getattr(value, "_verification_seal", None) is _VERIFICATION_SEAL
    )


def provider_bound_admission_custody_signing_message(
    receipt: LiveCanaryProviderBoundAdmissionCustodyReceipt,
) -> bytes:
    """Return the public domain-separated message an external signer signs."""

    if type(receipt) is not LiveCanaryProviderBoundAdmissionCustodyReceipt:
        raise TypeError("exact provider-bound admission receipt required")
    return _RECEIPT_DOMAIN + canonical_json(receipt.signing_dict).encode(
        "utf-8"
    )


_RECEIPT_FIELDS = {
    item.name
    for item in fields(LiveCanaryProviderBoundAdmissionCustodyReceipt)
    if not item.name.startswith("_")
}


def decode_live_canary_provider_bound_admission_custody_receipt(
    payload: bytes,
) -> LiveCanaryProviderBoundAdmissionCustodyReceipt:
    """Decode strict canonical signed v2 receipt bytes."""

    if type(payload) is not bytes:
        _reject("PROVIDER_BOUND_CUSTODY_PAYLOAD_TYPE_INVALID")
    if not payload or len(payload) > MAXIMUM_DOCUMENT_BYTES:
        _reject("PROVIDER_BOUND_CUSTODY_PAYLOAD_SIZE_INVALID")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise LiveCanaryProviderBoundPortableCustodyError(
            "PROVIDER_BOUND_CUSTODY_JSON_INVALID"
        ) from None

    def reject_duplicates(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                _reject("PROVIDER_BOUND_CUSTODY_DUPLICATE_KEY")
            result[key] = value
        return result

    try:
        raw = json.loads(text, object_pairs_hook=reject_duplicates)
    except LiveCanaryProviderBoundPortableCustodyError:
        raise
    except (TypeError, json.JSONDecodeError):
        raise LiveCanaryProviderBoundPortableCustodyError(
            "PROVIDER_BOUND_CUSTODY_JSON_INVALID"
        ) from None
    if type(raw) is not dict or set(raw) != _RECEIPT_FIELDS:
        _reject("PROVIDER_BOUND_CUSTODY_RECEIPT_SCHEMA_INVALID")
    if canonical_json(raw) != text:
        _reject("PROVIDER_BOUND_CUSTODY_JSON_NOT_CANONICAL")
    values = {
        item.name: raw[item.name]
        for item in fields(LiveCanaryProviderBoundAdmissionCustodyReceipt)
        if item.init
    }
    for name in (
        "provider_acceptance_valid_until_utc",
        "uploaded_at_utc",
        "retain_until_utc",
    ):
        values[name] = _parse_utc(name, values[name])
    try:
        receipt = LiveCanaryProviderBoundAdmissionCustodyReceipt(**values)
    except LiveCanaryProviderBoundPortableCustodyError:
        raise
    except (TypeError, ValueError, KeyError):
        raise LiveCanaryProviderBoundPortableCustodyError(
            "PROVIDER_BOUND_CUSTODY_RECEIPT_SCHEMA_INVALID"
        ) from None
    if (
        not receipt.signature_rsa_pkcs1v15_sha256_hex
        or receipt.canonical_json() != text
    ):
        _reject("PROVIDER_BOUND_CUSTODY_RECEIPT_NOT_CANONICAL")
    return receipt


def _require_exact_policy_bindings(
    *,
    policy: LiveCanaryPortableCustodyPolicy,
    admission: LiveCanaryProviderBoundPrebootstrapAdmission,
    provider_policy: WindowsLiveProviderAcceptancePolicy,
) -> None:
    provider_ids = {
        provider_policy.owner_authority_key_id,
        provider_policy.runtime_authority_key_id,
    }
    provider_fingerprints = {
        provider_policy.owner_public_key_fingerprint_sha256,
        provider_policy.runtime_public_key_fingerprint_sha256,
    }
    if (
        policy.custody_key_id in provider_ids
        or policy.public_key_fingerprint_sha256 in provider_fingerprints
    ):
        _reject("CUSTODY_PROVIDER_AUTHORITY_REUSE")
    if (
        provider_policy.content_sha256
        != admission.provider_acceptance_policy_sha256
    ):
        _reject("PROVIDER_ACCEPTANCE_POLICY_BINDING_MISMATCH")
    if (
        policy.deployment_host_alias_sha256
        != admission.target_host_identity_sha256
        or policy.task_definition_sha256
        != admission.live_execution_task_definition_sha256
    ):
        _reject("CUSTODY_TARGET_BINDING_MISMATCH")


def verify_live_canary_provider_bound_admission_custody(
    receipt_payload: bytes,
    *,
    policy: LiveCanaryPortableCustodyPolicy,
    expected_policy_sha256: str,
    admission: LiveCanaryProviderBoundPrebootstrapAdmission,
    provider_acceptance_policy: WindowsLiveProviderAcceptancePolicy,
    object_readback_provider: Callable[[str, str, str], bytes],
    clock_provider: Callable[[], datetime],
) -> VerifiedLiveCanaryProviderBoundAdmissionCustody:
    """Verify exact provider-bound WORM custody without launch authority."""

    _require_central_live_lock()
    if type(policy) is not LiveCanaryPortableCustodyPolicy:
        _reject("CUSTODY_POLICY_TYPE_INVALID")
    if not is_live_canary_provider_bound_prebootstrap_admission(admission):
        _reject("PROVIDER_BOUND_ADMISSION_UNSEALED")
    if type(provider_acceptance_policy) is not WindowsLiveProviderAcceptancePolicy:
        _reject("PROVIDER_ACCEPTANCE_POLICY_TYPE_INVALID")
    expected_policy = _sha256(
        "EXPECTED_CUSTODY_POLICY_SHA256",
        expected_policy_sha256,
    )
    if policy.content_sha256 != expected_policy:
        _reject("CUSTODY_POLICY_PIN_MISMATCH")
    _require_exact_policy_bindings(
        policy=policy,
        admission=admission,
        provider_policy=provider_acceptance_policy,
    )
    if not callable(object_readback_provider):
        _reject("PROVIDER_BOUND_CUSTODY_READBACK_PROVIDER_INVALID")

    started = _clock(clock_provider, phase="START")
    receipt = decode_live_canary_provider_bound_admission_custody_receipt(
        receipt_payload
    )
    expected = (
        (receipt.custody_policy_sha256, policy.content_sha256),
        (
            receipt.provider_bound_admission_sha256,
            admission.content_sha256,
        ),
        (receipt.legacy_admission_sha256, admission.legacy_admission_sha256),
        (receipt.candidate_sha256, admission.candidate_sha256),
        (
            receipt.demo_source_bound_verification_sha256,
            admission.demo_source_bound_verification_sha256,
        ),
        (
            receipt.live_source_bound_verification_sha256,
            admission.live_source_bound_verification_sha256,
        ),
        (
            receipt.provider_acceptance_sha256,
            admission.provider_acceptance_sha256,
        ),
        (
            receipt.provider_acceptance_policy_sha256,
            admission.provider_acceptance_policy_sha256,
        ),
        (
            receipt.provider_conformance_review_sha256,
            admission.provider_conformance_review_sha256,
        ),
        (
            receipt.target_host_identity_sha256,
            admission.target_host_identity_sha256,
        ),
        (
            receipt.launcher_trust_policy_sha256,
            policy.launcher_trust_policy_sha256,
        ),
        (
            receipt.service_account_alias_sha256,
            policy.service_account_alias_sha256,
        ),
        (
            receipt.installed_environment_sha256,
            admission.installed_environment_sha256,
        ),
        (
            receipt.live_execution_release_identity_sha256,
            admission.live_execution_release_identity_sha256,
        ),
        (
            receipt.live_execution_task_definition_sha256,
            admission.live_execution_task_definition_sha256,
        ),
        (receipt.authorization_sha256, admission.authorization_sha256),
        (receipt.validation_sha256, admission.validation_sha256),
        (
            receipt.provider_acceptance_valid_until_utc,
            admission.provider_acceptance_valid_until_utc,
        ),
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
        _reject("PROVIDER_BOUND_CUSTODY_RECEIPT_BINDING_MISMATCH")
    admission_bytes = admission.canonical_json().encode("utf-8")
    if (
        receipt.stored_content_sha256
        != hashlib.sha256(admission_bytes).hexdigest()
        or receipt.stored_content_size_bytes != len(admission_bytes)
    ):
        _reject("PROVIDER_BOUND_CUSTODY_CONTENT_BINDING_MISMATCH")
    if (
        receipt.uploaded_at_utc < admission.checked_at
        or receipt.uploaded_at_utc > started
        or started - receipt.uploaded_at_utc
        > timedelta(seconds=policy.maximum_receipt_age_seconds)
        or receipt.retain_until_utc - receipt.uploaded_at_utc
        < timedelta(seconds=policy.minimum_retention_seconds)
        or started >= receipt.retain_until_utc
        or started >= admission.provider_acceptance_valid_until_utc
    ):
        _reject("PROVIDER_BOUND_CUSTODY_TIME_OR_RETENTION_INVALID")
    if not verify_rsa_pkcs1v15_sha256(
        modulus_hex=policy.rsa_modulus_hex,
        exponent=policy.rsa_exponent,
        message=provider_bound_admission_custody_signing_message(receipt),
        signature_hex=receipt.signature_rsa_pkcs1v15_sha256_hex,
    ):
        _reject("PROVIDER_BOUND_CUSTODY_SIGNATURE_INVALID")
    try:
        readback = object_readback_provider(
            receipt.worm_repository_alias_sha256,
            receipt.object_key_sha256,
            receipt.object_version_sha256,
        )
    except Exception:
        raise LiveCanaryProviderBoundPortableCustodyError(
            "PROVIDER_BOUND_CUSTODY_READBACK_FAILED"
        ) from None
    if (
        type(readback) is not bytes
        or not readback
        or len(readback) > MAXIMUM_OBJECT_BYTES
    ):
        _reject("PROVIDER_BOUND_CUSTODY_READBACK_INVALID")
    if readback != admission_bytes:
        _reject("PROVIDER_BOUND_CUSTODY_READBACK_MISMATCH")
    completed = _clock(clock_provider, phase="COMPLETION")
    valid_until = min(
        receipt.retain_until_utc,
        admission.provider_acceptance_valid_until_utc,
    )
    if (
        completed < started
        or completed >= valid_until
        or completed - receipt.uploaded_at_utc
        > timedelta(seconds=policy.maximum_receipt_age_seconds)
    ):
        _reject("PROVIDER_BOUND_CUSTODY_CLOCK_WINDOW_INVALID")
    _require_central_live_lock()
    return VerifiedLiveCanaryProviderBoundAdmissionCustody(
        checked_at_utc=completed,
        valid_until_utc=valid_until,
        receipt_sha256=receipt.content_sha256,
        custody_policy_sha256=policy.content_sha256,
        provider_bound_admission_sha256=admission.content_sha256,
        legacy_admission_sha256=admission.legacy_admission_sha256,
        candidate_sha256=admission.candidate_sha256,
        provider_acceptance_sha256=admission.provider_acceptance_sha256,
        provider_acceptance_policy_sha256=(
            admission.provider_acceptance_policy_sha256
        ),
        provider_conformance_review_sha256=(
            admission.provider_conformance_review_sha256
        ),
        target_host_identity_sha256=admission.target_host_identity_sha256,
        launcher_trust_policy_sha256=(
            policy.launcher_trust_policy_sha256
        ),
        service_account_alias_sha256=(
            policy.service_account_alias_sha256
        ),
        installed_environment_sha256=admission.installed_environment_sha256,
        live_execution_release_identity_sha256=(
            admission.live_execution_release_identity_sha256
        ),
        live_execution_task_definition_sha256=(
            admission.live_execution_task_definition_sha256
        ),
        authorization_sha256=admission.authorization_sha256,
        validation_sha256=admission.validation_sha256,
        worm_repository_alias_sha256=receipt.worm_repository_alias_sha256,
        object_key_sha256=receipt.object_key_sha256,
        object_version_sha256=receipt.object_version_sha256,
        stored_content_sha256=receipt.stored_content_sha256,
        stored_content_size_bytes=receipt.stored_content_size_bytes,
        retain_until_utc=receipt.retain_until_utc,
        provider_acceptance_valid_until_utc=(
            admission.provider_acceptance_valid_until_utc
        ),
        _seal=_VERIFICATION_SEAL,
    )


__all__ = [
    "LiveCanaryProviderBoundAdmissionCustodyReceipt",
    "LiveCanaryProviderBoundPortableCustodyError",
    "PROVIDER_BOUND_ADMISSION_RECEIPT_SCHEMA",
    "VERIFIED_PROVIDER_BOUND_CUSTODY_SCHEMA",
    "VerifiedLiveCanaryProviderBoundAdmissionCustody",
    "decode_live_canary_provider_bound_admission_custody_receipt",
    "is_verified_live_canary_provider_bound_admission_custody",
    "provider_bound_admission_custody_signing_message",
    "verify_live_canary_provider_bound_admission_custody",
]
