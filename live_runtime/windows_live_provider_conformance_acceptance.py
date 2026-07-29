"""Offline external acceptance for the exact Windows LIVE provider packet.

This module verifies public RSA signatures and immutable evidence bytes.  A
successful result accepts provider conformance only; it deliberately grants no
runtime, credential, broker, permit, scheduler, or order capability.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Callable, Mapping

from .asymmetric_release_trust import (
    rsa_public_key_fingerprint_sha256,
    verify_rsa_pkcs1v15_sha256,
)
from .contracts import (
    CanonicalContract,
    canonical_json,
    canonical_sha256,
    canonicalize,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from .windows_live_canary_execution_source_bound_candidate import (
    WindowsLiveCanaryExecutionSourceBoundCandidateVerification,
    is_windows_live_canary_execution_source_bound_candidate_verification,
)
from .windows_provider_conformance_review import (
    REVIEW_SCHEMA_VERSION_V4,
    WindowsThreeServiceProviderConformanceReview,
    is_windows_three_service_provider_conformance_review,
    live_execution_source_binding_from_verification,
)


POLICY_SCHEMA_VERSION = "windows-live-provider-acceptance-policy-v1"
OWNER_ACCEPTANCE_SCHEMA_VERSION = (
    "windows-live-provider-owner-acceptance-v1"
)
RUNTIME_ATTESTATION_SCHEMA_VERSION = (
    "windows-live-provider-runtime-attestation-v1"
)
ACCEPTANCE_SCHEMA_VERSION = (
    "windows-live-provider-conformance-acceptance-v1"
)
SIGNATURE_ALGORITHM = "RSASSA-PKCS1-v1_5-SHA256"
OWNER_ACCEPTANCE_DOMAIN = (
    b"AI_SCALPER:WINDOWS_LIVE_PROVIDER_OWNER_ACCEPTANCE:v1\x00"
)
RUNTIME_ATTESTATION_DOMAIN = (
    b"AI_SCALPER:WINDOWS_LIVE_PROVIDER_RUNTIME_ATTESTATION:v1\x00"
)
ACCEPTANCE_STATUS = (
    "LIVE_PROVIDER_CONFORMANCE_ACCEPTED_"
    "PREBOOTSTRAP_BINDING_REQUIRED"
)
ORDER_CAPABILITY = "DISABLED"
MAX_LOT = 0.01
PROVIDER_COUNT = 68
CREDENTIAL_REFERENCE_COUNT = 12
MINIMUM_RSA_BITS = 3072
MAXIMUM_RSA_BITS = 8192
MINIMUM_TTL_SECONDS = 60
MAXIMUM_TTL_SECONDS = 3600
MAXIMUM_PUBLIC_DOCUMENT_BYTES = 1_048_576
MAXIMUM_EVIDENCE_BYTES = 64 * 1024 * 1024

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_ACCEPTANCE_SEAL = object()


class WindowsLiveProviderConformanceAcceptanceError(RuntimeError):
    """One exact acceptance requirement failed with a stable reason."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: object) -> None:
        normalized = str(reason_code or "").strip().upper()
        if not normalized or re.fullmatch(r"[A-Z][A-Z0-9_]{2,127}", normalized) is None:
            normalized = "LIVE_PROVIDER_CONFORMANCE_ACCEPTANCE_INVALID"
        self.reason_code = normalized
        super().__init__(normalized)


def _reject(reason_code: str) -> None:
    raise WindowsLiveProviderConformanceAcceptanceError(reason_code)


def _identifier(name: str, value: object) -> str:
    normalized = require_text(name, value)
    if _ID_RE.fullmatch(normalized) is None:
        raise ValueError(f"{name} must be a canonical identifier")
    return normalized


def _nonzero_hash(name: str, value: object) -> str:
    normalized = require_hash(name, value)
    if normalized == "0" * 64:
        raise ValueError(f"{name} cannot be the zero hash")
    return normalized


def _exact_bool(name: str, value: object, expected: bool) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{name} must be bool")
    if value is not expected:
        raise ValueError(f"{name} must remain {expected}")
    return value


def _fixed_max_lot(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("max_lot must be numeric")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized != MAX_LOT:
        raise ValueError("max_lot must remain 0.01")
    return normalized


def _utc_text(value: datetime) -> str:
    return require_utc("UTC timestamp", value).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _utc_from_text(name: str, value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _reject(f"{name.upper()}_INVALID")
    try:
        parsed = require_utc(
            name,
            datetime.fromisoformat(value[:-1] + "+00:00"),
        )
    except (TypeError, ValueError) as exc:
        raise WindowsLiveProviderConformanceAcceptanceError(
            f"{name.upper()}_INVALID"
        ) from exc
    if _utc_text(parsed) != value:
        _reject(f"{name.upper()}_NOT_CANONICAL")
    return parsed


def _rsa_key(
    *,
    prefix: str,
    modulus_hex: object,
    exponent: object,
    fingerprint_sha256: object,
) -> tuple[str, int, str]:
    modulus = require_text(f"{prefix}_rsa_modulus_hex", modulus_hex)
    if (
        _HEX_RE.fullmatch(modulus) is None
        or len(modulus) % 2
        or modulus.startswith("00")
    ):
        raise ValueError(f"{prefix} RSA modulus is not canonical")
    modulus_integer = int(modulus, 16)
    if (
        not MINIMUM_RSA_BITS
        <= modulus_integer.bit_length()
        <= MAXIMUM_RSA_BITS
        or modulus_integer % 2 == 0
    ):
        raise ValueError(f"{prefix} RSA modulus size or parity is invalid")
    normalized_exponent = require_int(
        f"{prefix}_rsa_exponent",
        exponent,
        minimum=3,
    )
    if normalized_exponent != 65537:
        raise ValueError(f"{prefix} RSA exponent must be 65537")
    fingerprint = _nonzero_hash(
        f"{prefix}_public_key_fingerprint_sha256",
        fingerprint_sha256,
    )
    if fingerprint != rsa_public_key_fingerprint_sha256(
        modulus,
        normalized_exponent,
    ):
        raise ValueError(f"{prefix} RSA fingerprint mismatch")
    return modulus, normalized_exponent, fingerprint


def _signature_hex(value: object, *, modulus_hex: str) -> str:
    normalized = require_text(
        "signature_rsa_pkcs1v15_sha256_hex",
        value,
    )
    expected_length = ((int(modulus_hex, 16).bit_length() + 7) // 8) * 2
    if (
        _HEX_RE.fullmatch(normalized) is None
        or len(normalized) != expected_length
    ):
        raise ValueError("RSA signature must be exact lowercase hex")
    return normalized


@dataclass(frozen=True)
class WindowsLiveProviderAcceptancePolicy(CanonicalContract):
    policy_id: str
    provider_conformance_review_sha256: str
    live_bound_archive_sha256: str
    live_binding_identity_sha256: str
    source_bound_archive_sha256: str
    source_archive_sha256: str
    suite_identity_sha256: str
    decision_release_identity_sha256: str
    execution_release_identity_sha256: str
    status_monitor_release_identity_sha256: str
    target_host_identity_sha256: str
    owner_authority_id: str
    owner_authority_key_id: str
    owner_rsa_modulus_hex: str
    owner_rsa_exponent: int
    owner_public_key_fingerprint_sha256: str
    runtime_authority_id: str
    runtime_authority_key_id: str
    runtime_rsa_modulus_hex: str
    runtime_rsa_exponent: int
    runtime_public_key_fingerprint_sha256: str
    maximum_acceptance_ttl_seconds: int
    signature_algorithm: str = SIGNATURE_ALGORITHM
    schema_version: str = POLICY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "policy_id",
            "owner_authority_id",
            "owner_authority_key_id",
            "runtime_authority_id",
            "runtime_authority_key_id",
        ):
            object.__setattr__(
                self,
                name,
                _identifier(name, getattr(self, name)),
            )
        for item in fields(self):
            if item.name.endswith("_sha256") and item.name not in {
                "owner_public_key_fingerprint_sha256",
                "runtime_public_key_fingerprint_sha256",
            }:
                object.__setattr__(
                    self,
                    item.name,
                    _nonzero_hash(item.name, getattr(self, item.name)),
                )
        owner = _rsa_key(
            prefix="owner",
            modulus_hex=self.owner_rsa_modulus_hex,
            exponent=self.owner_rsa_exponent,
            fingerprint_sha256=(
                self.owner_public_key_fingerprint_sha256
            ),
        )
        runtime = _rsa_key(
            prefix="runtime",
            modulus_hex=self.runtime_rsa_modulus_hex,
            exponent=self.runtime_rsa_exponent,
            fingerprint_sha256=(
                self.runtime_public_key_fingerprint_sha256
            ),
        )
        object.__setattr__(self, "owner_rsa_modulus_hex", owner[0])
        object.__setattr__(self, "owner_rsa_exponent", owner[1])
        object.__setattr__(
            self,
            "owner_public_key_fingerprint_sha256",
            owner[2],
        )
        object.__setattr__(self, "runtime_rsa_modulus_hex", runtime[0])
        object.__setattr__(self, "runtime_rsa_exponent", runtime[1])
        object.__setattr__(
            self,
            "runtime_public_key_fingerprint_sha256",
            runtime[2],
        )
        if (
            self.owner_authority_id == self.runtime_authority_id
            or self.owner_authority_key_id
            == self.runtime_authority_key_id
            or owner[2] == runtime[2]
            or owner[0] == runtime[0]
        ):
            raise ValueError("owner and runtime authorities must be distinct")
        object.__setattr__(
            self,
            "maximum_acceptance_ttl_seconds",
            require_int(
                "maximum_acceptance_ttl_seconds",
                self.maximum_acceptance_ttl_seconds,
                minimum=MINIMUM_TTL_SECONDS,
                maximum=MAXIMUM_TTL_SECONDS,
            ),
        )
        if self.signature_algorithm != SIGNATURE_ALGORITHM:
            raise ValueError("signature algorithm is unsupported")
        if self.schema_version != POLICY_SCHEMA_VERSION:
            raise ValueError("policy schema is unsupported")


@dataclass(frozen=True)
class WindowsLiveProviderOwnerAcceptance(CanonicalContract):
    acceptance_id: str
    trust_policy_sha256: str
    provider_conformance_review_sha256: str
    provider_evidence_set_sha256: str
    decision_release_identity_sha256: str
    execution_release_identity_sha256: str
    status_monitor_release_identity_sha256: str
    target_host_identity_sha256: str
    provider_count: int
    source_evidence_sha256: str
    validation_receipt_sha256: str
    outcome: str
    observed_at_utc: datetime
    not_before_utc: datetime
    expires_at_utc: datetime
    authority_id: str
    authority_key_id: str
    public_key_fingerprint_sha256: str
    signature_rsa_pkcs1v15_sha256_hex: str
    activation_allowed: bool = False
    execution_enabled: bool = False
    live_allowed: bool = False
    order_capability: str = ORDER_CAPABILITY
    max_lot: float = MAX_LOT
    signature_algorithm: str = SIGNATURE_ALGORITHM
    schema_version: str = OWNER_ACCEPTANCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in ("acceptance_id", "authority_id", "authority_key_id"):
            object.__setattr__(
                self,
                name,
                _identifier(name, getattr(self, name)),
            )
        for item in fields(self):
            if item.name.endswith("_sha256"):
                object.__setattr__(
                    self,
                    item.name,
                    _nonzero_hash(item.name, getattr(self, item.name)),
                )
        object.__setattr__(
            self,
            "provider_count",
            require_int("provider_count", self.provider_count),
        )
        if self.provider_count != PROVIDER_COUNT:
            raise ValueError("provider_count must be 68")
        for name in ("observed_at_utc", "not_before_utc", "expires_at_utc"):
            object.__setattr__(
                self,
                name,
                require_utc(name, getattr(self, name)),
            )
        if self.outcome != "PASSED":
            raise ValueError("owner outcome must be PASSED")
        for name in ("activation_allowed", "execution_enabled", "live_allowed"):
            _exact_bool(name, getattr(self, name), False)
        if self.order_capability != ORDER_CAPABILITY:
            raise ValueError("order capability must remain disabled")
        object.__setattr__(self, "max_lot", _fixed_max_lot(self.max_lot))
        if self.signature_algorithm != SIGNATURE_ALGORITHM:
            raise ValueError("signature algorithm is unsupported")
        if self.schema_version != OWNER_ACCEPTANCE_SCHEMA_VERSION:
            raise ValueError("owner acceptance schema is unsupported")

    @property
    def signing_dict(self) -> dict[str, object]:
        result = self.to_canonical_dict()
        result.pop("signature_rsa_pkcs1v15_sha256_hex")
        return result


@dataclass(frozen=True)
class WindowsLiveProviderRuntimeAttestation(CanonicalContract):
    attestation_id: str
    trust_policy_sha256: str
    provider_conformance_review_sha256: str
    live_bound_archive_sha256: str
    live_binding_identity_sha256: str
    target_host_identity_sha256: str
    installed_environment_sha256: str
    runtime_evidence_sha256: str
    validation_receipt_sha256: str
    provider_count: int
    credential_reference_count: int
    runtime_mode: str
    outcome: str
    observed_at_utc: datetime
    not_before_utc: datetime
    expires_at_utc: datetime
    authority_id: str
    authority_key_id: str
    public_key_fingerprint_sha256: str
    signature_rsa_pkcs1v15_sha256_hex: str
    activation_allowed: bool = False
    execution_enabled: bool = False
    broker_mutation_performed: bool = False
    live_allowed: bool = False
    order_capability: str = ORDER_CAPABILITY
    max_lot: float = MAX_LOT
    signature_algorithm: str = SIGNATURE_ALGORITHM
    schema_version: str = RUNTIME_ATTESTATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in ("attestation_id", "authority_id", "authority_key_id"):
            object.__setattr__(
                self,
                name,
                _identifier(name, getattr(self, name)),
            )
        for item in fields(self):
            if item.name.endswith("_sha256"):
                object.__setattr__(
                    self,
                    item.name,
                    _nonzero_hash(item.name, getattr(self, item.name)),
                )
        object.__setattr__(
            self,
            "provider_count",
            require_int("provider_count", self.provider_count),
        )
        object.__setattr__(
            self,
            "credential_reference_count",
            require_int(
                "credential_reference_count",
                self.credential_reference_count,
            ),
        )
        if (
            self.provider_count != PROVIDER_COUNT
            or self.credential_reference_count
            != CREDENTIAL_REFERENCE_COUNT
        ):
            raise ValueError("runtime provider inventory is invalid")
        if self.runtime_mode != "LIVE" or self.outcome != "PASSED":
            raise ValueError("runtime mode or outcome is invalid")
        for name in ("observed_at_utc", "not_before_utc", "expires_at_utc"):
            object.__setattr__(
                self,
                name,
                require_utc(name, getattr(self, name)),
            )
        for name in (
            "activation_allowed",
            "execution_enabled",
            "broker_mutation_performed",
            "live_allowed",
        ):
            _exact_bool(name, getattr(self, name), False)
        if self.order_capability != ORDER_CAPABILITY:
            raise ValueError("order capability must remain disabled")
        object.__setattr__(self, "max_lot", _fixed_max_lot(self.max_lot))
        if self.signature_algorithm != SIGNATURE_ALGORITHM:
            raise ValueError("signature algorithm is unsupported")
        if self.schema_version != RUNTIME_ATTESTATION_SCHEMA_VERSION:
            raise ValueError("runtime attestation schema is unsupported")

    @property
    def signing_dict(self) -> dict[str, object]:
        result = self.to_canonical_dict()
        result.pop("signature_rsa_pkcs1v15_sha256_hex")
        return result


@dataclass(frozen=True)
class WindowsLiveProviderConformanceAcceptance:
    provider_conformance_review_sha256: str
    trust_policy_sha256: str
    owner_acceptance_sha256: str
    runtime_attestation_sha256: str
    owner_signature_sha256: str
    runtime_signature_sha256: str
    provider_evidence_set_sha256: str
    owner_validation_receipt_sha256: str
    runtime_evidence_sha256: str
    runtime_validation_receipt_sha256: str
    live_bound_archive_sha256: str
    live_binding_identity_sha256: str
    source_bound_archive_sha256: str
    source_archive_sha256: str
    suite_identity_sha256: str
    decision_release_identity_sha256: str
    execution_release_identity_sha256: str
    status_monitor_release_identity_sha256: str
    target_host_identity_sha256: str
    installed_environment_sha256: str
    provider_count: int
    credential_reference_count: int
    checked_at_utc: datetime
    status: str = ACCEPTANCE_STATUS
    provider_accepted: bool = True
    prebootstrap_binding_required: bool = True
    activation_allowed: bool = False
    execution_enabled: bool = False
    production_execution_ready: bool = False
    task_install_allowed: bool = False
    credential_access_performed: bool = False
    provider_imported: bool = False
    provider_materialized: bool = False
    broker_mutation_performed: bool = False
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    promotion_eligible: bool = False
    order_capability: str = ORDER_CAPABILITY
    max_lot: float = MAX_LOT
    schema_version: str = ACCEPTANCE_SCHEMA_VERSION
    _acceptance_seal: object = field(
        init=False,
        repr=False,
        compare=False,
    )
    _seal: object | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if self._seal is not _ACCEPTANCE_SEAL:
            raise TypeError("acceptance requires the sealed verifier")
        object.__setattr__(self, "_acceptance_seal", _ACCEPTANCE_SEAL)
        for item in fields(self):
            if item.name.endswith("_sha256"):
                _nonzero_hash(item.name, getattr(self, item.name))
        if (
            self.provider_count != PROVIDER_COUNT
            or self.credential_reference_count
            != CREDENTIAL_REFERENCE_COUNT
            or self.status != ACCEPTANCE_STATUS
            or self.order_capability != ORDER_CAPABILITY
            or self.schema_version != ACCEPTANCE_SCHEMA_VERSION
        ):
            raise ValueError("acceptance invariant drift")
        _exact_bool("provider_accepted", self.provider_accepted, True)
        _exact_bool(
            "prebootstrap_binding_required",
            self.prebootstrap_binding_required,
            True,
        )
        for name in (
            "activation_allowed",
            "execution_enabled",
            "production_execution_ready",
            "task_install_allowed",
            "credential_access_performed",
            "provider_imported",
            "provider_materialized",
            "broker_mutation_performed",
            "live_allowed",
            "safe_to_demo_auto_order",
            "promotion_eligible",
        ):
            _exact_bool(name, getattr(self, name), False)
        require_utc("checked_at_utc", self.checked_at_utc)
        object.__setattr__(self, "max_lot", _fixed_max_lot(self.max_lot))

    def _unsigned_canonical_dict(self) -> dict[str, object]:
        return {
            item.name: canonicalize(getattr(self, item.name))
            for item in fields(self)
            if not item.name.startswith("_")
        }

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self._unsigned_canonical_dict())

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            **self._unsigned_canonical_dict(),
            "content_sha256": self.content_sha256,
        }


def is_windows_live_provider_conformance_acceptance(
    value: object,
) -> bool:
    return (
        type(value) is WindowsLiveProviderConformanceAcceptance
        and getattr(value, "_acceptance_seal", None) is _ACCEPTANCE_SEAL
    )


def _service_release_identities(
    review: WindowsThreeServiceProviderConformanceReview,
) -> dict[str, str]:
    identities: dict[str, str] = {}
    try:
        for service in review.services:
            role = str(service["service_role"])
            identity = _nonzero_hash(
                f"{role.lower()}_release_identity_sha256",
                service["configured_release_identity_sha256"],
            )
            identities[role] = identity
    except (KeyError, TypeError, ValueError) as exc:
        raise WindowsLiveProviderConformanceAcceptanceError(
            "REVIEW_SERVICE_IDENTITIES_INVALID"
        ) from exc
    if set(identities) != {"DECISION", "EXECUTION", "STATUS_MONITOR"}:
        _reject("REVIEW_SERVICE_IDENTITIES_INVALID")
    if len(set(identities.values())) != 3:
        _reject("REVIEW_SERVICE_IDENTITIES_REUSED")
    return identities


def _latest_provider_observation(
    review: WindowsThreeServiceProviderConformanceReview,
) -> datetime:
    values: list[datetime] = []
    try:
        for service in review.services:
            evidence = service["provider_evidence"]
            if not isinstance(evidence, list):
                _reject("REVIEW_PROVIDER_EVIDENCE_INVALID")
            for item in evidence:
                if not isinstance(item, Mapping):
                    _reject("REVIEW_PROVIDER_EVIDENCE_INVALID")
                values.append(
                    _utc_from_text(
                        "provider_observed_at_utc",
                        item.get("observed_at_utc"),
                    )
                )
    except (KeyError, TypeError) as exc:
        raise WindowsLiveProviderConformanceAcceptanceError(
            "REVIEW_PROVIDER_EVIDENCE_INVALID"
        ) from exc
    if len(values) != PROVIDER_COUNT:
        _reject("REVIEW_PROVIDER_EVIDENCE_COUNT_INVALID")
    return max(values)


def _validate_exact_inputs(
    source_verification: object,
    conformance_review: object,
) -> tuple[
    WindowsLiveCanaryExecutionSourceBoundCandidateVerification,
    WindowsThreeServiceProviderConformanceReview,
]:
    if not is_windows_live_canary_execution_source_bound_candidate_verification(
        source_verification
    ):
        _reject("SEALED_LIVE_SOURCE_VERIFICATION_REQUIRED")
    if not is_windows_three_service_provider_conformance_review(
        conformance_review
    ):
        _reject("SEALED_PROVIDER_CONFORMANCE_REVIEW_REQUIRED")
    source = source_verification
    review = conformance_review
    if (
        review.schema_version != REVIEW_SCHEMA_VERSION_V4
        or review.provider_count != PROVIDER_COUNT
        or review.provider_accepted is not False
        or review.activation_allowed is not False
        or review.execution_enabled is not False
        or review.live_allowed is not False
        or review.safe_to_demo_auto_order is not False
        or review.promotion_eligible is not False
        or review.order_capability != ORDER_CAPABILITY
    ):
        _reject("PROVIDER_CONFORMANCE_REVIEW_V4_REQUIRED")
    expected_binding = live_execution_source_binding_from_verification(
        source
    )
    if dict(review.live_execution_source_binding or {}) != expected_binding:
        _reject("LIVE_SOURCE_REVIEW_BINDING_MISMATCH")
    return source, review


def _validate_policy_binding(
    *,
    source: WindowsLiveCanaryExecutionSourceBoundCandidateVerification,
    review: WindowsThreeServiceProviderConformanceReview,
    policy: WindowsLiveProviderAcceptancePolicy,
    expected_policy_sha256: str,
    expected_target_host_identity_sha256: str,
    identities: Mapping[str, str],
) -> None:
    try:
        policy_pin = _nonzero_hash(
            "expected_policy_sha256",
            expected_policy_sha256,
        )
        host_pin = _nonzero_hash(
            "expected_target_host_identity_sha256",
            expected_target_host_identity_sha256,
        )
    except (TypeError, ValueError) as exc:
        raise WindowsLiveProviderConformanceAcceptanceError(
            "EXTERNAL_ACCEPTANCE_PIN_INVALID"
        ) from exc
    if policy.content_sha256 != policy_pin:
        _reject("ACCEPTANCE_POLICY_PIN_MISMATCH")
    if policy.target_host_identity_sha256 != host_pin:
        _reject("TARGET_HOST_PIN_MISMATCH")
    expected = {
        "provider_conformance_review_sha256": review.content_sha256,
        "live_bound_archive_sha256": source.archive_sha256,
        "live_binding_identity_sha256": source.binding_identity_sha256,
        "source_bound_archive_sha256": source.source_bound_archive_sha256,
        "source_archive_sha256": source.source_archive_sha256,
        "suite_identity_sha256": source.suite_identity_sha256,
        "decision_release_identity_sha256": identities["DECISION"],
        "execution_release_identity_sha256": identities["EXECUTION"],
        "status_monitor_release_identity_sha256": identities[
            "STATUS_MONITOR"
        ],
    }
    if any(getattr(policy, key) != value for key, value in expected.items()):
        _reject("ACCEPTANCE_POLICY_BINDING_MISMATCH")
    if identities["EXECUTION"] != source.configured_release_identity_sha256:
        _reject("EXECUTION_RELEASE_SOURCE_BINDING_MISMATCH")


def _evidence_digest(name: str, value: object) -> str:
    if type(value) is not bytes:
        raise TypeError(f"{name} must be exact bytes")
    if not value or len(value) > MAXIMUM_EVIDENCE_BYTES:
        _reject(f"{name.upper()}_INVALID")
    return hashlib.sha256(value).hexdigest()


def _validate_interval(
    *,
    prefix: str,
    observed_at: datetime,
    not_before: datetime,
    expires_at: datetime,
    checked_at: datetime,
    maximum_ttl_seconds: int,
) -> None:
    if not (observed_at <= not_before < expires_at):
        _reject(f"{prefix}_TIME_ORDER_INVALID")
    lifetime = (expires_at - not_before).total_seconds()
    if lifetime <= 0 or lifetime > maximum_ttl_seconds:
        _reject(f"{prefix}_TTL_INVALID")
    if observed_at > checked_at:
        _reject(f"{prefix}_OBSERVATION_FROM_FUTURE")
    if checked_at < not_before:
        _reject(f"{prefix}_NOT_YET_VALID")
    if checked_at >= expires_at:
        _reject(f"{prefix}_EXPIRED")


def prepare_windows_live_provider_conformance_acceptance(
    *,
    source_verification: WindowsLiveCanaryExecutionSourceBoundCandidateVerification,
    conformance_review: WindowsThreeServiceProviderConformanceReview,
    trust_policy: WindowsLiveProviderAcceptancePolicy,
    owner_acceptance: WindowsLiveProviderOwnerAcceptance,
    runtime_attestation: WindowsLiveProviderRuntimeAttestation,
    owner_validation_receipt_bytes: bytes,
    runtime_evidence_bytes: bytes,
    runtime_validation_receipt_bytes: bytes,
    expected_policy_sha256: str,
    expected_target_host_identity_sha256: str,
    clock_provider: Callable[[], datetime],
) -> WindowsLiveProviderConformanceAcceptance:
    """Verify two external authorities and seal a non-executable result."""

    if not callable(clock_provider):
        raise TypeError("clock_provider must be callable")
    started_at = require_utc("trusted acceptance clock", clock_provider())
    source, review = _validate_exact_inputs(
        source_verification,
        conformance_review,
    )
    if type(trust_policy) is not WindowsLiveProviderAcceptancePolicy:
        _reject("ACCEPTANCE_POLICY_REQUIRED")
    if type(owner_acceptance) is not WindowsLiveProviderOwnerAcceptance:
        _reject("OWNER_ACCEPTANCE_REQUIRED")
    if type(runtime_attestation) is not WindowsLiveProviderRuntimeAttestation:
        _reject("RUNTIME_ATTESTATION_REQUIRED")

    identities = _service_release_identities(review)
    _validate_policy_binding(
        source=source,
        review=review,
        policy=trust_policy,
        expected_policy_sha256=expected_policy_sha256,
        expected_target_host_identity_sha256=(
            expected_target_host_identity_sha256
        ),
        identities=identities,
    )

    owner_receipt_sha256 = _evidence_digest(
        "owner_validation_receipt",
        owner_validation_receipt_bytes,
    )
    runtime_evidence_sha256 = _evidence_digest(
        "runtime_evidence",
        runtime_evidence_bytes,
    )
    runtime_receipt_sha256 = _evidence_digest(
        "runtime_validation_receipt",
        runtime_validation_receipt_bytes,
    )
    independent_hashes = {
        review.content_sha256,
        owner_receipt_sha256,
        runtime_evidence_sha256,
        runtime_receipt_sha256,
    }
    if len(independent_hashes) != 4:
        _reject("EXTERNAL_EVIDENCE_INDEPENDENCE_INVALID")

    owner_expected: Mapping[str, object] = {
        "trust_policy_sha256": trust_policy.content_sha256,
        "provider_conformance_review_sha256": review.content_sha256,
        "provider_evidence_set_sha256": (
            review.provider_evidence_set_sha256
        ),
        "decision_release_identity_sha256": identities["DECISION"],
        "execution_release_identity_sha256": identities["EXECUTION"],
        "status_monitor_release_identity_sha256": identities[
            "STATUS_MONITOR"
        ],
        "target_host_identity_sha256": (
            trust_policy.target_host_identity_sha256
        ),
        "provider_count": PROVIDER_COUNT,
        "source_evidence_sha256": review.content_sha256,
        "validation_receipt_sha256": owner_receipt_sha256,
        "authority_id": trust_policy.owner_authority_id,
        "authority_key_id": trust_policy.owner_authority_key_id,
        "public_key_fingerprint_sha256": (
            trust_policy.owner_public_key_fingerprint_sha256
        ),
    }
    if any(
        getattr(owner_acceptance, key) != value
        for key, value in owner_expected.items()
    ):
        _reject("OWNER_ACCEPTANCE_BINDING_MISMATCH")

    runtime_expected: Mapping[str, object] = {
        "trust_policy_sha256": trust_policy.content_sha256,
        "provider_conformance_review_sha256": review.content_sha256,
        "live_bound_archive_sha256": source.archive_sha256,
        "live_binding_identity_sha256": source.binding_identity_sha256,
        "target_host_identity_sha256": (
            trust_policy.target_host_identity_sha256
        ),
        "runtime_evidence_sha256": runtime_evidence_sha256,
        "validation_receipt_sha256": runtime_receipt_sha256,
        "provider_count": PROVIDER_COUNT,
        "credential_reference_count": CREDENTIAL_REFERENCE_COUNT,
        "runtime_mode": "LIVE",
        "authority_id": trust_policy.runtime_authority_id,
        "authority_key_id": trust_policy.runtime_authority_key_id,
        "public_key_fingerprint_sha256": (
            trust_policy.runtime_public_key_fingerprint_sha256
        ),
    }
    if any(
        getattr(runtime_attestation, key) != value
        for key, value in runtime_expected.items()
    ):
        _reject("RUNTIME_ATTESTATION_BINDING_MISMATCH")

    _validate_interval(
        prefix="OWNER_ACCEPTANCE",
        observed_at=owner_acceptance.observed_at_utc,
        not_before=owner_acceptance.not_before_utc,
        expires_at=owner_acceptance.expires_at_utc,
        checked_at=started_at,
        maximum_ttl_seconds=(
            trust_policy.maximum_acceptance_ttl_seconds
        ),
    )
    _validate_interval(
        prefix="RUNTIME_ATTESTATION",
        observed_at=runtime_attestation.observed_at_utc,
        not_before=runtime_attestation.not_before_utc,
        expires_at=runtime_attestation.expires_at_utc,
        checked_at=started_at,
        maximum_ttl_seconds=(
            trust_policy.maximum_acceptance_ttl_seconds
        ),
    )
    if runtime_attestation.observed_at_utc < _latest_provider_observation(
        review
    ):
        _reject("RUNTIME_OBSERVATION_PREDATES_PROVIDER_EVIDENCE")

    try:
        owner_signature = _signature_hex(
            owner_acceptance.signature_rsa_pkcs1v15_sha256_hex,
            modulus_hex=trust_policy.owner_rsa_modulus_hex,
        )
        runtime_signature = _signature_hex(
            runtime_attestation.signature_rsa_pkcs1v15_sha256_hex,
            modulus_hex=trust_policy.runtime_rsa_modulus_hex,
        )
    except (TypeError, ValueError) as exc:
        raise WindowsLiveProviderConformanceAcceptanceError(
            "ACCEPTANCE_SIGNATURE_ENCODING_INVALID"
        ) from exc
    owner_message = OWNER_ACCEPTANCE_DOMAIN + canonical_json(
        owner_acceptance.signing_dict
    ).encode("utf-8")
    if not verify_rsa_pkcs1v15_sha256(
        modulus_hex=trust_policy.owner_rsa_modulus_hex,
        exponent=trust_policy.owner_rsa_exponent,
        message=owner_message,
        signature_hex=owner_signature,
    ):
        _reject("OWNER_ACCEPTANCE_SIGNATURE_INVALID")
    runtime_message = RUNTIME_ATTESTATION_DOMAIN + canonical_json(
        runtime_attestation.signing_dict
    ).encode("utf-8")
    if not verify_rsa_pkcs1v15_sha256(
        modulus_hex=trust_policy.runtime_rsa_modulus_hex,
        exponent=trust_policy.runtime_rsa_exponent,
        message=runtime_message,
        signature_hex=runtime_signature,
    ):
        _reject("RUNTIME_ATTESTATION_SIGNATURE_INVALID")

    completed_at = require_utc(
        "trusted acceptance completion clock",
        clock_provider(),
    )
    if completed_at < started_at:
        _reject("TRUSTED_ACCEPTANCE_CLOCK_REGRESSION")
    for prefix, document in (
        ("OWNER_ACCEPTANCE", owner_acceptance),
        ("RUNTIME_ATTESTATION", runtime_attestation),
    ):
        if completed_at >= document.expires_at_utc:
            _reject(f"{prefix}_EXPIRED_DURING_VERIFICATION")

    result = WindowsLiveProviderConformanceAcceptance(
        provider_conformance_review_sha256=review.content_sha256,
        trust_policy_sha256=trust_policy.content_sha256,
        owner_acceptance_sha256=owner_acceptance.content_sha256,
        runtime_attestation_sha256=runtime_attestation.content_sha256,
        owner_signature_sha256=hashlib.sha256(
            bytes.fromhex(owner_signature)
        ).hexdigest(),
        runtime_signature_sha256=hashlib.sha256(
            bytes.fromhex(runtime_signature)
        ).hexdigest(),
        provider_evidence_set_sha256=review.provider_evidence_set_sha256,
        owner_validation_receipt_sha256=owner_receipt_sha256,
        runtime_evidence_sha256=runtime_evidence_sha256,
        runtime_validation_receipt_sha256=runtime_receipt_sha256,
        live_bound_archive_sha256=source.archive_sha256,
        live_binding_identity_sha256=source.binding_identity_sha256,
        source_bound_archive_sha256=source.source_bound_archive_sha256,
        source_archive_sha256=source.source_archive_sha256,
        suite_identity_sha256=source.suite_identity_sha256,
        decision_release_identity_sha256=identities["DECISION"],
        execution_release_identity_sha256=identities["EXECUTION"],
        status_monitor_release_identity_sha256=identities[
            "STATUS_MONITOR"
        ],
        target_host_identity_sha256=(
            trust_policy.target_host_identity_sha256
        ),
        installed_environment_sha256=(
            runtime_attestation.installed_environment_sha256
        ),
        provider_count=PROVIDER_COUNT,
        credential_reference_count=CREDENTIAL_REFERENCE_COUNT,
        checked_at_utc=completed_at,
        _seal=_ACCEPTANCE_SEAL,
    )
    if (
        len(canonical_json(result.to_canonical_dict()).encode("utf-8"))
        > MAXIMUM_PUBLIC_DOCUMENT_BYTES
    ):
        _reject("ACCEPTANCE_RESULT_TOO_LARGE")
    return result


def verify_windows_live_provider_conformance_acceptance(
    payload: Mapping[str, object],
    *,
    source_verification: WindowsLiveCanaryExecutionSourceBoundCandidateVerification,
    conformance_review: WindowsThreeServiceProviderConformanceReview,
    trust_policy: WindowsLiveProviderAcceptancePolicy,
    owner_acceptance: WindowsLiveProviderOwnerAcceptance,
    runtime_attestation: WindowsLiveProviderRuntimeAttestation,
    owner_validation_receipt_bytes: bytes,
    runtime_evidence_bytes: bytes,
    runtime_validation_receipt_bytes: bytes,
    expected_policy_sha256: str,
    expected_target_host_identity_sha256: str,
    clock_provider: Callable[[], datetime],
) -> WindowsLiveProviderConformanceAcceptance:
    """Reconstruct an assessment rather than trusting its outer hash."""

    if not isinstance(payload, Mapping):
        _reject("ACCEPTANCE_RESULT_SCHEMA_INVALID")
    expected = prepare_windows_live_provider_conformance_acceptance(
        source_verification=source_verification,
        conformance_review=conformance_review,
        trust_policy=trust_policy,
        owner_acceptance=owner_acceptance,
        runtime_attestation=runtime_attestation,
        owner_validation_receipt_bytes=owner_validation_receipt_bytes,
        runtime_evidence_bytes=runtime_evidence_bytes,
        runtime_validation_receipt_bytes=(
            runtime_validation_receipt_bytes
        ),
        expected_policy_sha256=expected_policy_sha256,
        expected_target_host_identity_sha256=(
            expected_target_host_identity_sha256
        ),
        clock_provider=clock_provider,
    )
    if dict(payload) != expected.to_canonical_dict():
        _reject("ACCEPTANCE_RESULT_RECONSTRUCTION_MISMATCH")
    return expected


def _reject_duplicates(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _reject("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> object:
    _reject(f"NONFINITE_JSON_NUMBER_{value}")


def _strict_json_object(
    value: str | bytes,
    *,
    kind: str,
) -> dict[str, object]:
    if isinstance(value, bytes):
        if not value or len(value) > MAXIMUM_PUBLIC_DOCUMENT_BYTES:
            _reject(f"{kind}_DOCUMENT_SIZE_INVALID")
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WindowsLiveProviderConformanceAcceptanceError(
                f"{kind}_JSON_INVALID"
            ) from exc
    elif isinstance(value, str):
        if (
            not value
            or len(value.encode("utf-8"))
            > MAXIMUM_PUBLIC_DOCUMENT_BYTES
        ):
            _reject(f"{kind}_DOCUMENT_SIZE_INVALID")
        text = value
    else:
        raise TypeError(f"{kind.lower()} must be UTF-8 JSON")
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_nonfinite,
        )
    except WindowsLiveProviderConformanceAcceptanceError:
        raise
    except json.JSONDecodeError as exc:
        raise WindowsLiveProviderConformanceAcceptanceError(
            f"{kind}_JSON_INVALID"
        ) from exc
    if not isinstance(document, dict):
        _reject(f"{kind}_OBJECT_REQUIRED")
    try:
        rendered = canonical_json(document)
    except (TypeError, ValueError) as exc:
        raise WindowsLiveProviderConformanceAcceptanceError(
            f"{kind}_JSON_INVALID"
        ) from exc
    if text not in {rendered, rendered + "\n"}:
        _reject(f"{kind}_JSON_NOT_CANONICAL")
    return document


_POLICY_FIELDS = frozenset(
    item.name
    for item in fields(WindowsLiveProviderAcceptancePolicy)
)
_OWNER_FIELDS = frozenset(
    item.name
    for item in fields(WindowsLiveProviderOwnerAcceptance)
)
_RUNTIME_FIELDS = frozenset(
    item.name
    for item in fields(WindowsLiveProviderRuntimeAttestation)
)


def decode_windows_live_provider_acceptance_policy(
    value: str | bytes,
) -> WindowsLiveProviderAcceptancePolicy:
    document = _strict_json_object(value, kind="ACCEPTANCE_POLICY")
    if set(document) != _POLICY_FIELDS:
        _reject("ACCEPTANCE_POLICY_SCHEMA_INVALID")
    try:
        return WindowsLiveProviderAcceptancePolicy(**document)
    except (TypeError, ValueError) as exc:
        raise WindowsLiveProviderConformanceAcceptanceError(
            "ACCEPTANCE_POLICY_INVALID"
        ) from exc


def decode_windows_live_provider_owner_acceptance(
    value: str | bytes,
) -> WindowsLiveProviderOwnerAcceptance:
    document = _strict_json_object(value, kind="OWNER_ACCEPTANCE")
    if set(document) != _OWNER_FIELDS:
        _reject("OWNER_ACCEPTANCE_SCHEMA_INVALID")
    values = dict(document)
    for name in ("observed_at_utc", "not_before_utc", "expires_at_utc"):
        values[name] = _utc_from_text(name, values[name])
    try:
        return WindowsLiveProviderOwnerAcceptance(**values)
    except (TypeError, ValueError) as exc:
        raise WindowsLiveProviderConformanceAcceptanceError(
            "OWNER_ACCEPTANCE_INVALID"
        ) from exc


def decode_windows_live_provider_runtime_attestation(
    value: str | bytes,
) -> WindowsLiveProviderRuntimeAttestation:
    document = _strict_json_object(value, kind="RUNTIME_ATTESTATION")
    if set(document) != _RUNTIME_FIELDS:
        _reject("RUNTIME_ATTESTATION_SCHEMA_INVALID")
    values = dict(document)
    for name in ("observed_at_utc", "not_before_utc", "expires_at_utc"):
        values[name] = _utc_from_text(name, values[name])
    try:
        return WindowsLiveProviderRuntimeAttestation(**values)
    except (TypeError, ValueError) as exc:
        raise WindowsLiveProviderConformanceAcceptanceError(
            "RUNTIME_ATTESTATION_INVALID"
        ) from exc


def _file_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _stable_read_file(
    path: str | Path,
    *,
    maximum_bytes: int,
    kind: str,
) -> bytes:
    source = Path(path).expanduser().absolute()
    descriptor: int | None = None
    try:
        if source.resolve(strict=True) != source:
            _reject(f"{kind}_FILE_INVALID")
        before = source.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or int(getattr(before, "st_file_attributes", 0)) & 0x400
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            _reject(f"{kind}_FILE_INVALID")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(source, flags)
        opened_before = os.fstat(descriptor)
        payload = os.read(descriptor, maximum_bytes + 1)
        opened_after = os.fstat(descriptor)
        os.close(descriptor)
        descriptor = None
        after = source.lstat()
    except WindowsLiveProviderConformanceAcceptanceError:
        raise
    except (OSError, RuntimeError) as exc:
        raise WindowsLiveProviderConformanceAcceptanceError(
            f"{kind}_FILE_UNAVAILABLE"
        ) from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    identity = _file_identity(before)
    if (
        _file_identity(opened_before) != identity
        or _file_identity(opened_after) != identity
        or _file_identity(after) != identity
        or len(payload) != before.st_size
        or len(payload) > maximum_bytes
    ):
        _reject(f"{kind}_FILE_UNSTABLE")
    return payload


def load_windows_live_provider_acceptance_policy(
    path: str | Path,
) -> WindowsLiveProviderAcceptancePolicy:
    return decode_windows_live_provider_acceptance_policy(
        _stable_read_file(
            path,
            maximum_bytes=MAXIMUM_PUBLIC_DOCUMENT_BYTES,
            kind="ACCEPTANCE_POLICY",
        )
    )


def load_windows_live_provider_owner_acceptance(
    path: str | Path,
) -> WindowsLiveProviderOwnerAcceptance:
    return decode_windows_live_provider_owner_acceptance(
        _stable_read_file(
            path,
            maximum_bytes=MAXIMUM_PUBLIC_DOCUMENT_BYTES,
            kind="OWNER_ACCEPTANCE",
        )
    )


def load_windows_live_provider_runtime_attestation(
    path: str | Path,
) -> WindowsLiveProviderRuntimeAttestation:
    return decode_windows_live_provider_runtime_attestation(
        _stable_read_file(
            path,
            maximum_bytes=MAXIMUM_PUBLIC_DOCUMENT_BYTES,
            kind="RUNTIME_ATTESTATION",
        )
    )


def _write_exclusive(path: str | Path, payload: Mapping[str, object]) -> Path:
    destination = Path(path).expanduser().absolute()
    data = (canonical_json(payload) + "\n").encode("utf-8")
    if len(data) > MAXIMUM_PUBLIC_DOCUMENT_BYTES:
        _reject("ACCEPTANCE_OUTPUT_TOO_LARGE")
    if destination.exists() or destination.is_symlink():
        _reject("ACCEPTANCE_OUTPUT_EXISTS")
    parent = destination.parent
    try:
        if parent.resolve(strict=True) != parent:
            _reject("ACCEPTANCE_OUTPUT_PARENT_INVALID")
        metadata = parent.lstat()
    except (OSError, RuntimeError) as exc:
        raise WindowsLiveProviderConformanceAcceptanceError(
            "ACCEPTANCE_OUTPUT_PARENT_INVALID"
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    ):
        _reject("ACCEPTANCE_OUTPUT_PARENT_INVALID")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    created_identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(destination, flags, 0o600)
        created = os.fstat(descriptor)
        if not stat.S_ISREG(created.st_mode):
            _reject("ACCEPTANCE_OUTPUT_INVALID")
        created_identity = (int(created.st_dev), int(created.st_ino))
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                _reject("ACCEPTANCE_OUTPUT_WRITE_FAILED")
            written += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
    except Exception:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if created_identity is not None:
            try:
                observed = destination.lstat()
                if (
                    stat.S_ISREG(observed.st_mode)
                    and (
                        int(observed.st_dev),
                        int(observed.st_ino),
                    )
                    == created_identity
                ):
                    destination.unlink()
            except OSError:
                pass
        raise
    return destination


def prepare_windows_live_provider_conformance_acceptance_file(
    *,
    source_verification: WindowsLiveCanaryExecutionSourceBoundCandidateVerification,
    conformance_review: WindowsThreeServiceProviderConformanceReview,
    trust_policy_path: str | Path,
    owner_acceptance_path: str | Path,
    runtime_attestation_path: str | Path,
    owner_validation_receipt_path: str | Path,
    runtime_evidence_path: str | Path,
    runtime_validation_receipt_path: str | Path,
    expected_policy_sha256: str,
    expected_target_host_identity_sha256: str,
    output_path: str | Path,
    clock_provider: Callable[[], datetime],
) -> WindowsLiveProviderConformanceAcceptance:
    """Stable-read all external files, then create one immutable result."""

    policy = load_windows_live_provider_acceptance_policy(trust_policy_path)
    owner = load_windows_live_provider_owner_acceptance(
        owner_acceptance_path
    )
    runtime = load_windows_live_provider_runtime_attestation(
        runtime_attestation_path
    )
    owner_receipt = _stable_read_file(
        owner_validation_receipt_path,
        maximum_bytes=MAXIMUM_EVIDENCE_BYTES,
        kind="OWNER_VALIDATION_RECEIPT",
    )
    runtime_evidence = _stable_read_file(
        runtime_evidence_path,
        maximum_bytes=MAXIMUM_EVIDENCE_BYTES,
        kind="RUNTIME_EVIDENCE",
    )
    runtime_receipt = _stable_read_file(
        runtime_validation_receipt_path,
        maximum_bytes=MAXIMUM_EVIDENCE_BYTES,
        kind="RUNTIME_VALIDATION_RECEIPT",
    )
    result = prepare_windows_live_provider_conformance_acceptance(
        source_verification=source_verification,
        conformance_review=conformance_review,
        trust_policy=policy,
        owner_acceptance=owner,
        runtime_attestation=runtime,
        owner_validation_receipt_bytes=owner_receipt,
        runtime_evidence_bytes=runtime_evidence,
        runtime_validation_receipt_bytes=runtime_receipt,
        expected_policy_sha256=expected_policy_sha256,
        expected_target_host_identity_sha256=(
            expected_target_host_identity_sha256
        ),
        clock_provider=clock_provider,
    )
    _write_exclusive(output_path, result.to_canonical_dict())
    return result


__all__ = [
    "ACCEPTANCE_SCHEMA_VERSION",
    "ACCEPTANCE_STATUS",
    "OWNER_ACCEPTANCE_DOMAIN",
    "OWNER_ACCEPTANCE_SCHEMA_VERSION",
    "POLICY_SCHEMA_VERSION",
    "RUNTIME_ATTESTATION_DOMAIN",
    "RUNTIME_ATTESTATION_SCHEMA_VERSION",
    "SIGNATURE_ALGORITHM",
    "WindowsLiveProviderAcceptancePolicy",
    "WindowsLiveProviderConformanceAcceptance",
    "WindowsLiveProviderConformanceAcceptanceError",
    "WindowsLiveProviderOwnerAcceptance",
    "WindowsLiveProviderRuntimeAttestation",
    "decode_windows_live_provider_acceptance_policy",
    "decode_windows_live_provider_owner_acceptance",
    "decode_windows_live_provider_runtime_attestation",
    "is_windows_live_provider_conformance_acceptance",
    "load_windows_live_provider_acceptance_policy",
    "load_windows_live_provider_owner_acceptance",
    "load_windows_live_provider_runtime_attestation",
    "prepare_windows_live_provider_conformance_acceptance",
    "prepare_windows_live_provider_conformance_acceptance_file",
    "verify_windows_live_provider_conformance_acceptance",
]
