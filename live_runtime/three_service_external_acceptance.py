"""Verify external acceptance evidence for the reviewed three-service plan.

This module is deliberately deny-only.  It authenticates public metadata and
returns a deterministic assessment, but it cannot issue evidence, activate a
runtime, materialize a provider, install a task, initialize a broker terminal,
or grant execution authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import math
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Callable, Mapping, Sequence

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
from .demo_soak_operations import (
    DemoSoakOperationsError,
    assert_no_embedded_secrets,
)
from .demo_soak_three_service_operations import (
    EXTERNAL_READINESS_BLOCKERS,
    WindowsThreeServiceDemoSoakOperationsPlan,
)
from .demo_soak_three_service_operations_artifacts import (
    ThreeServiceOperationsArtifactError,
    verify_windows_three_service_demo_soak_review_bundle,
)


POLICY_SCHEMA_VERSION = "windows-three-service-acceptance-rsa-policy-v1"
OBSERVATION_SCHEMA_VERSION = (
    "windows-three-service-acceptance-observation-v1"
)
OBSERVATIONS_SCHEMA_VERSION = (
    "windows-three-service-acceptance-observations-v1"
)
ASSESSMENT_SCHEMA_VERSION = (
    "windows-three-service-external-acceptance-assessment-v1"
)
SIGNATURE_ALGORITHM = "RSASSA-PKCS1-v1_5-SHA256"
ACCEPTANCE_OBSERVATION_DOMAIN = (
    b"AI_SCALPER:WINDOWS_THREE_SERVICE_ACCEPTANCE_OBSERVATION:v1\x00"
)

MAXIMUM_PUBLIC_DOCUMENT_BYTES = 1_048_576
MAXIMUM_REVIEW_BUNDLE_BYTES = 4_194_304
MINIMUM_RSA_BITS = 3072
MAXIMUM_RSA_BITS = 8192
ORDER_CAPABILITY = "DISABLED"
MAX_LOT = 0.01

GATE_OWNER_ROLES: Mapping[str, str] = MappingProxyType(
    {
        "EXTERNAL_DECISION_EXECUTION_IPC_CUSTODY_REQUIRED": (
            "IPC_CUSTODY_AUTHORITY"
        ),
        "EXTERNAL_DECISION_FACTORY_PROVIDER_CONFIGURATION_REQUIRED": (
            "DECISION_SERVICE_OWNER"
        ),
        "EXTERNAL_EXECUTION_FACTORY_PROVIDER_CONFIGURATION_REQUIRED": (
            "EXECUTION_SERVICE_OWNER"
        ),
        "EXTERNAL_LAUNCHER_ATTESTATIONS_REQUIRED": (
            "RELEASE_SECURITY_AUTHORITY"
        ),
        "EXTERNAL_MONITOR_OFFHOST_DELIVERY_ACCEPTANCE_REQUIRED": (
            "MONITOR_OPERATIONS_OWNER"
        ),
        "EXTERNAL_STATUS_MONITOR_CONFIGURED_RELEASE_ACCEPTANCE_REQUIRED": (
            "STATUS_MONITOR_SERVICE_OWNER"
        ),
        "EXTERNAL_THREE_SERVICE_TASK_INSTALLATION_AND_ACL_ATTESTATION_REQUIRED": (
            "WINDOWS_SECURITY_AUTHORITY"
        ),
        "MANUAL_DEMO_10_CONTROLLED_ORDERS_REQUIRED": (
            "MANUAL_DEMO_ACCEPTANCE_AUTHORITY"
        ),
        "WINDOWS_VPS_HARDENING_AND_FAILURE_DRILLS_REQUIRED": (
            "WINDOWS_OPERATIONS_AUTHORITY"
        ),
        "XAUUSD_MINIMUM_LOT_RISK_FEASIBILITY_REQUIRED": (
            "RISK_GOVERNOR_OWNER"
        ),
    }
)

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_ROLE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_OBSERVATION_ID_PREFIX = "acceptance-observation-"


class ThreeServiceAcceptanceError(RuntimeError):
    """An acceptance document or binding failed with a stable reason code."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = require_text(
            "reason_code",
            reason_code,
            upper=True,
        )
        super().__init__(self.reason_code)


def _identifier(name: str, value: object) -> str:
    normalized = require_text(name, value)
    if _ID_RE.fullmatch(normalized) is None:
        raise ValueError(f"{name} must be a canonical identifier")
    return normalized


def _role(name: str, value: object) -> str:
    normalized = require_text(name, value, upper=True)
    if _ROLE_RE.fullmatch(normalized) is None:
        raise ValueError(f"{name} must be a canonical owner role")
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
        raise ThreeServiceAcceptanceError(f"{name.upper()}_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        parsed = require_utc(name, parsed)
    except (TypeError, ValueError) as exc:
        raise ThreeServiceAcceptanceError(
            f"{name.upper()}_INVALID"
        ) from exc
    if _utc_text(parsed) != value:
        raise ThreeServiceAcceptanceError(
            f"{name.upper()}_NOT_CANONICAL_UTC"
        )
    return parsed


def _signature_hex(value: object) -> str:
    normalized = require_text(
        "signature_rsa_pkcs1v15_sha256_hex",
        value,
    )
    if (
        _HEX_RE.fullmatch(normalized) is None
        or len(normalized) % 2
        or not 768 <= len(normalized) <= 2048
    ):
        raise ValueError("RSA signature must be canonical lowercase hex")
    return normalized


def _owner_inventory(
    value: Mapping[str, str],
) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise TypeError("gate_owner_roles must be a mapping")
    normalized: dict[str, str] = {}
    for raw_gate, raw_owner in value.items():
        gate = require_text("gate_code", raw_gate, upper=True)
        owner = _role("owner_role", raw_owner)
        if gate in normalized:
            raise ValueError("gate_owner_roles contains a duplicate gate")
        normalized[gate] = owner
    if normalized != dict(GATE_OWNER_ROLES):
        raise ValueError("gate_owner_roles must match the canonical inventory")
    return MappingProxyType(dict(sorted(normalized.items())))


@dataclass(frozen=True)
class ThreeServiceAcceptanceTrustPolicy(CanonicalContract):
    """Pin one public acceptance authority to one exact reviewed topology."""

    policy_id: str
    plan_sha256: str
    review_bundle_sha256: str
    authority_id: str
    authority_key_id: str
    rsa_modulus_hex: str
    rsa_exponent: int
    public_key_fingerprint_sha256: str
    gate_owner_roles: Mapping[str, str]
    maximum_observation_ttl_seconds: int
    signature_algorithm: str = SIGNATURE_ALGORITHM
    schema_version: str = POLICY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in ("policy_id", "authority_id", "authority_key_id"):
            object.__setattr__(
                self,
                name,
                _identifier(name, getattr(self, name)),
            )
        for name in ("plan_sha256", "review_bundle_sha256"):
            object.__setattr__(
                self,
                name,
                _nonzero_hash(name, getattr(self, name)),
            )
        modulus_hex = require_text("rsa_modulus_hex", self.rsa_modulus_hex)
        if (
            _HEX_RE.fullmatch(modulus_hex) is None
            or len(modulus_hex) % 2
            or modulus_hex.startswith("00")
        ):
            raise ValueError("RSA modulus must be canonical lowercase hex")
        modulus = int(modulus_hex, 16)
        bits = modulus.bit_length()
        if (
            not MINIMUM_RSA_BITS <= bits <= MAXIMUM_RSA_BITS
            or modulus % 2 == 0
        ):
            raise ValueError("RSA modulus size or parity is invalid")
        object.__setattr__(self, "rsa_modulus_hex", modulus_hex)
        exponent = require_int("rsa_exponent", self.rsa_exponent, minimum=3)
        if exponent != 65537:
            raise ValueError("RSA public exponent must be 65537")
        object.__setattr__(self, "rsa_exponent", exponent)
        fingerprint = _nonzero_hash(
            "public_key_fingerprint_sha256",
            self.public_key_fingerprint_sha256,
        )
        if fingerprint != rsa_public_key_fingerprint_sha256(
            modulus_hex,
            exponent,
        ):
            raise ValueError("RSA public-key fingerprint mismatch")
        object.__setattr__(
            self,
            "public_key_fingerprint_sha256",
            fingerprint,
        )
        object.__setattr__(
            self,
            "gate_owner_roles",
            _owner_inventory(self.gate_owner_roles),
        )
        object.__setattr__(
            self,
            "maximum_observation_ttl_seconds",
            require_int(
                "maximum_observation_ttl_seconds",
                self.maximum_observation_ttl_seconds,
                minimum=60,
                maximum=86_400,
            ),
        )
        if self.signature_algorithm != SIGNATURE_ALGORITHM:
            raise ValueError("signature algorithm is unsupported")
        if self.schema_version != POLICY_SCHEMA_VERSION:
            raise ValueError("policy schema is unsupported")


_OBSERVATION_UNSIGNED_FIELDS = frozenset(
    {
        "trust_policy_sha256",
        "plan_sha256",
        "review_bundle_sha256",
        "decision_release_identity_sha256",
        "execution_release_identity_sha256",
        "status_monitor_release_identity_sha256",
        "gate_code",
        "owner_role",
        "source_evidence_sha256",
        "validation_receipt_sha256",
        "outcome",
        "observed_at_utc",
        "not_before_utc",
        "expires_at_utc",
        "authority_id",
        "authority_key_id",
        "public_key_fingerprint_sha256",
        "live_allowed",
        "safe_to_demo_auto_order",
        "activation_authorized",
        "execution_enabled",
        "promotion_eligible",
        "order_capability",
        "max_lot",
        "signature_algorithm",
        "schema_version",
    }
)


def derive_acceptance_observation_id(
    values: Mapping[str, object],
) -> str:
    """Derive the immutable identifier without relying on a caller claim."""

    if not isinstance(values, Mapping):
        raise TypeError("observation values must be a mapping")
    payload = {
        str(key): value
        for key, value in values.items()
        if key not in {
            "observation_id",
            "signature_rsa_pkcs1v15_sha256_hex",
        }
    }
    if set(payload) != _OBSERVATION_UNSIGNED_FIELDS:
        raise ValueError("observation identifier payload fields are invalid")
    return _OBSERVATION_ID_PREFIX + canonical_sha256(payload)


@dataclass(frozen=True)
class ThreeServiceAcceptanceObservation(CanonicalContract):
    """One externally authenticated result for one exact acceptance gate."""

    observation_id: str
    trust_policy_sha256: str
    plan_sha256: str
    review_bundle_sha256: str
    decision_release_identity_sha256: str
    execution_release_identity_sha256: str
    status_monitor_release_identity_sha256: str
    gate_code: str
    owner_role: str
    source_evidence_sha256: str
    validation_receipt_sha256: str
    outcome: str
    observed_at_utc: datetime
    not_before_utc: datetime
    expires_at_utc: datetime
    authority_id: str
    authority_key_id: str
    public_key_fingerprint_sha256: str
    live_allowed: bool
    safe_to_demo_auto_order: bool
    activation_authorized: bool
    execution_enabled: bool
    promotion_eligible: bool
    order_capability: str
    max_lot: float
    signature_algorithm: str
    schema_version: str
    signature_rsa_pkcs1v15_sha256_hex: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "observation_id",
            _identifier("observation_id", self.observation_id),
        )
        for name in (
            "trust_policy_sha256",
            "plan_sha256",
            "review_bundle_sha256",
            "decision_release_identity_sha256",
            "execution_release_identity_sha256",
            "status_monitor_release_identity_sha256",
            "source_evidence_sha256",
            "validation_receipt_sha256",
            "public_key_fingerprint_sha256",
        ):
            object.__setattr__(
                self,
                name,
                _nonzero_hash(name, getattr(self, name)),
            )
        if self.source_evidence_sha256 == self.validation_receipt_sha256:
            raise ValueError(
                "source evidence and validation receipt must be independent"
            )
        gate = require_text("gate_code", self.gate_code, upper=True)
        if gate not in EXTERNAL_READINESS_BLOCKERS:
            raise ValueError("gate_code is not a canonical external blocker")
        object.__setattr__(self, "gate_code", gate)
        object.__setattr__(
            self,
            "owner_role",
            _role("owner_role", self.owner_role),
        )
        outcome = require_text("outcome", self.outcome, upper=True)
        if outcome not in {"PASSED", "FAILED"}:
            raise ValueError("outcome must be PASSED or FAILED")
        object.__setattr__(self, "outcome", outcome)
        for name in ("authority_id", "authority_key_id"):
            object.__setattr__(
                self,
                name,
                _identifier(name, getattr(self, name)),
            )
        observed = require_utc("observed_at_utc", self.observed_at_utc)
        not_before = require_utc("not_before_utc", self.not_before_utc)
        expires = require_utc("expires_at_utc", self.expires_at_utc)
        if observed > not_before or not_before >= expires:
            raise ValueError("observation validity interval is invalid")
        for name in (
            "live_allowed",
            "safe_to_demo_auto_order",
            "activation_authorized",
            "execution_enabled",
            "promotion_eligible",
        ):
            _exact_bool(name, getattr(self, name), False)
        if self.order_capability != ORDER_CAPABILITY:
            raise ValueError("order_capability must remain DISABLED")
        object.__setattr__(self, "max_lot", _fixed_max_lot(self.max_lot))
        if self.signature_algorithm != SIGNATURE_ALGORITHM:
            raise ValueError("signature algorithm is unsupported")
        if self.schema_version != OBSERVATION_SCHEMA_VERSION:
            raise ValueError("observation schema is unsupported")
        object.__setattr__(
            self,
            "signature_rsa_pkcs1v15_sha256_hex",
            _signature_hex(self.signature_rsa_pkcs1v15_sha256_hex),
        )

    @property
    def identifier_payload(self) -> dict[str, object]:
        return {
            key: value
            for key, value in self.to_canonical_dict().items()
            if key
            not in {
                "observation_id",
                "signature_rsa_pkcs1v15_sha256_hex",
            }
        }

    @property
    def signing_dict(self) -> dict[str, object]:
        return {
            key: value
            for key, value in self.to_canonical_dict().items()
            if key != "signature_rsa_pkcs1v15_sha256_hex"
        }


@dataclass(frozen=True)
class ThreeServiceExternalAcceptanceAssessment(CanonicalContract):
    """Deterministic deny-only result of verifying the public dossier."""

    plan_sha256: str
    review_bundle_sha256: str
    trust_policy_sha256: str
    checked_at_utc: datetime
    accepted_gates: tuple[str, ...]
    pending_gates: tuple[str, ...]
    pending_reasons: Mapping[str, str]
    observation_sha256s: Mapping[str, str]
    external_acceptance_complete: bool
    status: str
    activation_review_required: bool = True
    activation_authorized: bool = False
    ready_for_demo_auto_soak: bool = False
    execution_enabled: bool = False
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    promotion_eligible: bool = False
    order_capability: str = ORDER_CAPABILITY
    max_lot: float = MAX_LOT
    schema_version: str = ASSESSMENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "plan_sha256",
            "review_bundle_sha256",
            "trust_policy_sha256",
        ):
            object.__setattr__(
                self,
                name,
                _nonzero_hash(name, getattr(self, name)),
            )
        require_utc("checked_at_utc", self.checked_at_utc)
        accepted = tuple(sorted(self.accepted_gates))
        pending = tuple(sorted(self.pending_gates))
        required = tuple(sorted(EXTERNAL_READINESS_BLOCKERS))
        if (
            len(accepted) != len(set(accepted))
            or len(pending) != len(set(pending))
            or set(accepted) & set(pending)
            or tuple(sorted(accepted + pending)) != required
        ):
            raise ValueError("assessment gate partition is invalid")
        object.__setattr__(self, "accepted_gates", accepted)
        object.__setattr__(self, "pending_gates", pending)
        reasons = {
            require_text("pending_gate", gate, upper=True): require_text(
                "pending_reason",
                reason,
                upper=True,
            )
            for gate, reason in self.pending_reasons.items()
        }
        if set(reasons) != set(pending):
            raise ValueError("pending reasons do not match pending gates")
        object.__setattr__(
            self,
            "pending_reasons",
            MappingProxyType(dict(sorted(reasons.items()))),
        )
        observed = {
            require_text("observed_gate", gate, upper=True): _nonzero_hash(
                "observation_sha256",
                digest,
            )
            for gate, digest in self.observation_sha256s.items()
        }
        if not set(observed).issubset(EXTERNAL_READINESS_BLOCKERS):
            raise ValueError("observation hashes include an unknown gate")
        object.__setattr__(
            self,
            "observation_sha256s",
            MappingProxyType(dict(sorted(observed.items()))),
        )
        complete = not pending
        if type(self.external_acceptance_complete) is not bool:
            raise TypeError("external_acceptance_complete must be bool")
        if self.external_acceptance_complete is not complete:
            raise ValueError("external acceptance completeness is inconsistent")
        expected_status = (
            "EXTERNAL_ACCEPTANCE_COMPLETE_ACTIVATION_REVIEW_REQUIRED"
            if complete
            else "BLOCKED_EXTERNAL_ACCEPTANCE"
        )
        if self.status != expected_status:
            raise ValueError("assessment status is inconsistent")
        _exact_bool(
            "activation_review_required",
            self.activation_review_required,
            True,
        )
        for name in (
            "activation_authorized",
            "ready_for_demo_auto_soak",
            "execution_enabled",
            "live_allowed",
            "safe_to_demo_auto_order",
            "promotion_eligible",
        ):
            _exact_bool(name, getattr(self, name), False)
        if self.order_capability != ORDER_CAPABILITY:
            raise ValueError("order_capability must remain DISABLED")
        object.__setattr__(self, "max_lot", _fixed_max_lot(self.max_lot))
        if self.schema_version != ASSESSMENT_SCHEMA_VERSION:
            raise ValueError("assessment schema is unsupported")


def _trusted_now(
    clock_provider: Callable[[], datetime],
) -> datetime:
    try:
        return require_utc("trusted acceptance clock", clock_provider())
    except Exception as exc:
        raise ThreeServiceAcceptanceError(
            "TRUSTED_CLOCK_PROVIDER_FAILED"
        ) from exc


def _verify_review_bundle(
    review_bundle: Mapping[str, object],
) -> WindowsThreeServiceDemoSoakOperationsPlan:
    if not isinstance(review_bundle, Mapping):
        raise ThreeServiceAcceptanceError(
            "THREE_SERVICE_REVIEW_BUNDLE_OBJECT_REQUIRED"
        )
    try:
        return verify_windows_three_service_demo_soak_review_bundle(
            review_bundle
        )
    except (
        ThreeServiceOperationsArtifactError,
        DemoSoakOperationsError,
        TypeError,
        ValueError,
    ) as exc:
        raise ThreeServiceAcceptanceError(
            "THREE_SERVICE_REVIEW_BUNDLE_INVALID"
        ) from exc


def _verify_observation_binding(
    observation: ThreeServiceAcceptanceObservation,
    *,
    trust_policy: ThreeServiceAcceptanceTrustPolicy,
    plan: WindowsThreeServiceDemoSoakOperationsPlan,
    review_bundle_sha256: str,
) -> None:
    try:
        expected_id = derive_acceptance_observation_id(
            observation.identifier_payload
        )
    except (TypeError, ValueError) as exc:
        raise ThreeServiceAcceptanceError(
            "ACCEPTANCE_OBSERVATION_ID_PAYLOAD_INVALID"
        ) from exc
    if observation.observation_id != expected_id:
        raise ThreeServiceAcceptanceError(
            "ACCEPTANCE_OBSERVATION_ID_MISMATCH"
        )
    expected = {
        "trust_policy_sha256": trust_policy.content_sha256,
        "plan_sha256": plan.plan_sha256,
        "review_bundle_sha256": review_bundle_sha256,
        "decision_release_identity_sha256": (
            plan.decision.configured_release_identity_sha256
        ),
        "execution_release_identity_sha256": (
            plan.execution.configured_release_identity_sha256
        ),
        "status_monitor_release_identity_sha256": (
            plan.status_monitor.configured_release_identity_sha256
        ),
        "authority_id": trust_policy.authority_id,
        "authority_key_id": trust_policy.authority_key_id,
        "public_key_fingerprint_sha256": (
            trust_policy.public_key_fingerprint_sha256
        ),
    }
    if any(
        getattr(observation, name) != value
        for name, value in expected.items()
    ):
        raise ThreeServiceAcceptanceError(
            "ACCEPTANCE_OBSERVATION_BINDING_MISMATCH"
        )
    expected_owner = trust_policy.gate_owner_roles.get(
        observation.gate_code
    )
    if observation.owner_role != expected_owner:
        raise ThreeServiceAcceptanceError(
            "ACCEPTANCE_OBSERVATION_OWNER_MISMATCH"
        )
    if (
        observation.expires_at_utc - observation.observed_at_utc
        > timedelta(
            seconds=trust_policy.maximum_observation_ttl_seconds
        )
    ):
        raise ThreeServiceAcceptanceError(
            "ACCEPTANCE_OBSERVATION_TTL_EXCEEDS_POLICY"
        )
    message = ACCEPTANCE_OBSERVATION_DOMAIN + canonical_json(
        observation.signing_dict
    ).encode("utf-8")
    if not verify_rsa_pkcs1v15_sha256(
        modulus_hex=trust_policy.rsa_modulus_hex,
        exponent=trust_policy.rsa_exponent,
        message=message,
        signature_hex=(
            observation.signature_rsa_pkcs1v15_sha256_hex
        ),
    ):
        raise ThreeServiceAcceptanceError(
            "ACCEPTANCE_OBSERVATION_SIGNATURE_INVALID"
        )


def assess_three_service_external_acceptance(
    *,
    review_bundle: Mapping[str, object],
    trust_policy: ThreeServiceAcceptanceTrustPolicy,
    observations: Sequence[ThreeServiceAcceptanceObservation],
    expected_policy_sha256: str,
    clock_provider: Callable[[], datetime],
) -> ThreeServiceExternalAcceptanceAssessment:
    """Authenticate the dossier while retaining every activation lock."""

    if type(trust_policy) is not ThreeServiceAcceptanceTrustPolicy:
        raise TypeError(
            "trust_policy must be exact "
            "ThreeServiceAcceptanceTrustPolicy"
        )
    if not callable(clock_provider):
        raise TypeError("clock_provider must be callable")
    try:
        pinned_policy = _nonzero_hash(
            "expected_policy_sha256",
            expected_policy_sha256,
        )
    except (TypeError, ValueError) as exc:
        raise ThreeServiceAcceptanceError(
            "EXPECTED_ACCEPTANCE_POLICY_HASH_INVALID"
        ) from exc
    if pinned_policy != trust_policy.content_sha256:
        raise ThreeServiceAcceptanceError(
            "ACCEPTANCE_POLICY_PIN_MISMATCH"
        )
    plan = _verify_review_bundle(review_bundle)
    try:
        review_hash = _nonzero_hash(
            "review_bundle_sha256",
            review_bundle["content_sha256"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ThreeServiceAcceptanceError(
            "THREE_SERVICE_REVIEW_BUNDLE_HASH_INVALID"
        ) from exc
    if (
        trust_policy.plan_sha256 != plan.plan_sha256
        or trust_policy.review_bundle_sha256 != review_hash
    ):
        raise ThreeServiceAcceptanceError(
            "ACCEPTANCE_POLICY_REVIEW_BINDING_MISMATCH"
        )
    if isinstance(observations, (str, bytes)) or not isinstance(
        observations,
        Sequence,
    ):
        raise TypeError("observations must be a sequence")

    started_at = _trusted_now(clock_provider)
    by_gate: dict[str, ThreeServiceAcceptanceObservation] = {}
    reasons: dict[str, str] = {}
    observation_hashes: dict[str, str] = {}
    candidates: set[str] = set()
    for observation in observations:
        if type(observation) is not ThreeServiceAcceptanceObservation:
            raise TypeError(
                "observations must contain exact "
                "ThreeServiceAcceptanceObservation values"
            )
        if observation.gate_code in by_gate:
            raise ThreeServiceAcceptanceError(
                "DUPLICATE_ACCEPTANCE_GATE"
            )
        by_gate[observation.gate_code] = observation
        _verify_observation_binding(
            observation,
            trust_policy=trust_policy,
            plan=plan,
            review_bundle_sha256=review_hash,
        )
        observation_hashes[observation.gate_code] = (
            observation.content_sha256
        )
        if observation.outcome != "PASSED":
            reasons[observation.gate_code] = "SIGNED_OUTCOME_FAILED"
        elif started_at < observation.observed_at_utc:
            reasons[observation.gate_code] = "OBSERVATION_FROM_FUTURE"
        elif started_at < observation.not_before_utc:
            reasons[observation.gate_code] = "NOT_YET_VALID"
        elif started_at >= observation.expires_at_utc:
            reasons[observation.gate_code] = "EXPIRED"
        else:
            candidates.add(observation.gate_code)

    completed_at = _trusted_now(clock_provider)
    if completed_at < started_at:
        raise ThreeServiceAcceptanceError("TRUSTED_CLOCK_REGRESSION")
    for gate in tuple(candidates):
        if completed_at >= by_gate[gate].expires_at_utc:
            candidates.remove(gate)
            reasons[gate] = "EXPIRED_DURING_VERIFICATION"

    for gate in EXTERNAL_READINESS_BLOCKERS:
        if gate not in by_gate:
            reasons[gate] = "MISSING"
    accepted = tuple(sorted(candidates))
    pending = tuple(
        sorted(set(EXTERNAL_READINESS_BLOCKERS) - set(accepted))
    )
    complete = not pending
    return ThreeServiceExternalAcceptanceAssessment(
        plan_sha256=plan.plan_sha256,
        review_bundle_sha256=review_hash,
        trust_policy_sha256=pinned_policy,
        checked_at_utc=started_at,
        accepted_gates=accepted,
        pending_gates=pending,
        pending_reasons={
            gate: reasons[gate]
            for gate in pending
        },
        observation_sha256s=observation_hashes,
        external_acceptance_complete=complete,
        status=(
            "EXTERNAL_ACCEPTANCE_COMPLETE_ACTIVATION_REVIEW_REQUIRED"
            if complete
            else "BLOCKED_EXTERNAL_ACCEPTANCE"
        ),
    )


def _reject_duplicates(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ThreeServiceAcceptanceError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> object:
    raise ThreeServiceAcceptanceError(
        f"NONFINITE_JSON_NUMBER_{value}"
    )


def _file_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def _read_public_json_object(
    path: str | Path,
    *,
    maximum_bytes: int,
    kind: str,
) -> dict[str, object]:
    source = Path(path)
    descriptor: int | None = None
    try:
        before = source.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or int(getattr(before, "st_file_attributes", 0)) & 0x400
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            raise ThreeServiceAcceptanceError(f"{kind}_FILE_INVALID")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(source, flags)
        opened_before = os.fstat(descriptor)
        payload = os.read(descriptor, maximum_bytes + 1)
        opened_after = os.fstat(descriptor)
        os.close(descriptor)
        descriptor = None
        after = source.lstat()
    except ThreeServiceAcceptanceError:
        raise
    except OSError as exc:
        raise ThreeServiceAcceptanceError(
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
        raise ThreeServiceAcceptanceError(
            f"{kind}_CHANGED_DURING_READ"
        )
    try:
        decoded = payload.decode("utf-8")
        document = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_nonfinite,
        )
    except ThreeServiceAcceptanceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ThreeServiceAcceptanceError(
            f"{kind}_JSON_INVALID"
        ) from exc
    if not isinstance(document, dict):
        raise ThreeServiceAcceptanceError(f"{kind}_OBJECT_REQUIRED")
    try:
        assert_no_embedded_secrets(document)
        canonicalize(document)
    except (DemoSoakOperationsError, TypeError, ValueError) as exc:
        raise ThreeServiceAcceptanceError(
            f"{kind}_PUBLIC_DOCUMENT_INVALID"
        ) from exc
    return document


_POLICY_FIELDS = frozenset(
    {
        "policy_id",
        "plan_sha256",
        "review_bundle_sha256",
        "authority_id",
        "authority_key_id",
        "rsa_modulus_hex",
        "rsa_exponent",
        "public_key_fingerprint_sha256",
        "gate_owner_roles",
        "maximum_observation_ttl_seconds",
        "signature_algorithm",
        "schema_version",
    }
)

_OBSERVATION_FIELDS = frozenset(
    _OBSERVATION_UNSIGNED_FIELDS
    | {
        "observation_id",
        "signature_rsa_pkcs1v15_sha256_hex",
    }
)


def load_three_service_review_bundle(
    path: str | Path,
) -> Mapping[str, object]:
    """Load and reconstruct one exact immutable v3 review bundle."""

    document = _read_public_json_object(
        path,
        maximum_bytes=MAXIMUM_REVIEW_BUNDLE_BYTES,
        kind="THREE_SERVICE_REVIEW_BUNDLE",
    )
    _verify_review_bundle(document)
    return document


def load_three_service_acceptance_policy(
    path: str | Path,
) -> ThreeServiceAcceptanceTrustPolicy:
    """Load one exact public trust policy with no issuer capability."""

    document = _read_public_json_object(
        path,
        maximum_bytes=MAXIMUM_PUBLIC_DOCUMENT_BYTES,
        kind="THREE_SERVICE_ACCEPTANCE_POLICY",
    )
    if set(document) != _POLICY_FIELDS:
        raise ThreeServiceAcceptanceError(
            "THREE_SERVICE_ACCEPTANCE_POLICY_SCHEMA_INVALID"
        )
    if not isinstance(document.get("gate_owner_roles"), dict):
        raise ThreeServiceAcceptanceError(
            "THREE_SERVICE_ACCEPTANCE_POLICY_OWNER_MAPPING_INVALID"
        )
    try:
        return ThreeServiceAcceptanceTrustPolicy(**document)
    except (TypeError, ValueError) as exc:
        raise ThreeServiceAcceptanceError(
            "THREE_SERVICE_ACCEPTANCE_POLICY_INVALID"
        ) from exc


def load_three_service_acceptance_observations(
    path: str | Path,
) -> tuple[ThreeServiceAcceptanceObservation, ...]:
    """Load the public signed observation collection without issuing it."""

    document = _read_public_json_object(
        path,
        maximum_bytes=MAXIMUM_PUBLIC_DOCUMENT_BYTES,
        kind="THREE_SERVICE_ACCEPTANCE_OBSERVATIONS",
    )
    if (
        set(document) != {"schema_version", "observations"}
        or document.get("schema_version") != OBSERVATIONS_SCHEMA_VERSION
        or not isinstance(document.get("observations"), list)
        or len(document["observations"]) > len(EXTERNAL_READINESS_BLOCKERS)
    ):
        raise ThreeServiceAcceptanceError(
            "THREE_SERVICE_ACCEPTANCE_OBSERVATIONS_SCHEMA_INVALID"
        )
    result: list[ThreeServiceAcceptanceObservation] = []
    gates: set[str] = set()
    for raw in document["observations"]:
        if not isinstance(raw, dict) or set(raw) != _OBSERVATION_FIELDS:
            raise ThreeServiceAcceptanceError(
                "THREE_SERVICE_ACCEPTANCE_OBSERVATION_SCHEMA_INVALID"
            )
        values = dict(raw)
        for name in (
            "observed_at_utc",
            "not_before_utc",
            "expires_at_utc",
        ):
            values[name] = _utc_from_text(name, values[name])
        try:
            observation = ThreeServiceAcceptanceObservation(**values)
            derived_id = derive_acceptance_observation_id(
                observation.identifier_payload
            )
        except (TypeError, ValueError) as exc:
            raise ThreeServiceAcceptanceError(
                "THREE_SERVICE_ACCEPTANCE_OBSERVATION_INVALID"
            ) from exc
        if observation.observation_id != derived_id:
            raise ThreeServiceAcceptanceError(
                "ACCEPTANCE_OBSERVATION_ID_MISMATCH"
            )
        if observation.gate_code in gates:
            raise ThreeServiceAcceptanceError(
                "DUPLICATE_ACCEPTANCE_GATE"
            )
        gates.add(observation.gate_code)
        result.append(observation)
    return tuple(result)


__all__ = [
    "ACCEPTANCE_OBSERVATION_DOMAIN",
    "ASSESSMENT_SCHEMA_VERSION",
    "GATE_OWNER_ROLES",
    "OBSERVATION_SCHEMA_VERSION",
    "OBSERVATIONS_SCHEMA_VERSION",
    "POLICY_SCHEMA_VERSION",
    "SIGNATURE_ALGORITHM",
    "ThreeServiceAcceptanceError",
    "ThreeServiceAcceptanceObservation",
    "ThreeServiceAcceptanceTrustPolicy",
    "ThreeServiceExternalAcceptanceAssessment",
    "assess_three_service_external_acceptance",
    "derive_acceptance_observation_id",
    "load_three_service_acceptance_observations",
    "load_three_service_acceptance_policy",
    "load_three_service_review_bundle",
]
