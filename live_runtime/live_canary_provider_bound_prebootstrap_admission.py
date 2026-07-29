"""Fresh provider-bound, deny-only admission for one XAUUSD LIVE canary."""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field, fields
from datetime import datetime
import math
import re
from typing import Callable

import execution_policy

from .contracts import CanonicalContract, canonical_sha256, canonicalize
from .live_canary_activation import (
    LIVE_CANARY_MAX_CONCURRENT_POSITIONS,
    LIVE_CANARY_MAX_LOT,
    LiveCanaryActivationAuthorization,
    LiveCanaryActivationValidation,
    LiveCanaryTrustPolicy,
)
from .live_canary_prebootstrap_admission import (
    LiveCanaryPrebootstrapAdmission,
    LiveCanaryRuntimeCandidate,
    is_live_canary_prebootstrap_admission,
)
from .windows_execution_source_bound_candidate import (
    WindowsExecutionSourceBoundCandidateVerification,
    is_windows_execution_source_bound_candidate_verification,
)
from .windows_live_canary_execution_source_bound_candidate import (
    WindowsLiveCanaryExecutionSourceBoundCandidateVerification,
    is_windows_live_canary_execution_source_bound_candidate_verification,
)
from .windows_live_provider_conformance_acceptance import (
    CREDENTIAL_REFERENCE_COUNT,
    PROVIDER_COUNT,
    WindowsLiveProviderAcceptancePolicy,
    WindowsLiveProviderConformanceAcceptanceError,
    WindowsLiveProviderOwnerAcceptance,
    WindowsLiveProviderRuntimeAttestation,
    is_windows_live_provider_conformance_acceptance,
    prepare_windows_live_provider_conformance_acceptance,
)
from .windows_provider_conformance_review import (
    WindowsThreeServiceProviderConformanceReview,
    live_execution_source_binding_from_verification,
)


ADMISSION_SCHEMA_VERSION = (
    "live-canary-provider-bound-prebootstrap-admission-v1"
)
ADMISSION_STATUS = (
    "PROVIDER_BOUND_PREBOOTSTRAP_EVIDENCE_COMPLETE_"
    "CUSTODY_AND_CENTRAL_UNLOCK_REQUIRED"
)
ORDER_CAPABILITY = "DISABLED"

_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_REPORT_SEAL = object()


class LiveCanaryProviderBoundPrebootstrapAdmissionError(RuntimeError):
    """One composition invariant failed with a stable public reason code."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: object) -> None:
        normalized = re.sub(
            r"[^A-Z0-9_]+",
            "_",
            str(reason_code or "").strip().upper(),
        ).strip("_")
        self.reason_code = (
            normalized
            or "LIVE_CANARY_PROVIDER_BOUND_PREBOOTSTRAP_INVALID"
        )
        super().__init__(self.reason_code)


def _reject(reason_code: str) -> None:
    raise LiveCanaryProviderBoundPrebootstrapAdmissionError(reason_code)


def _sha256(name: str, value: object) -> str:
    if (
        type(value) is not str
        or _HEX_64.fullmatch(value) is None
        or value == "0" * 64
    ):
        _reject(f"{name}_INVALID")
    return value


def _git_sha(name: str, value: object) -> str:
    if (
        type(value) is not str
        or _HEX_40.fullmatch(value) is None
        or value == "0" * 40
    ):
        _reject(f"{name}_INVALID")
    return value


def _identifier(name: str, value: object) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
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


def _fixed_float(name: str, value: object, expected: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _reject(f"{name}_INVALID")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized != expected:
        _reject(f"{name}_INVALID")
    return normalized


def _clock(
    clock_provider: Callable[[], datetime],
    *,
    phase: str,
) -> datetime:
    if not callable(clock_provider):
        _reject("TRUSTED_CLOCK_PROVIDER_INVALID")
    try:
        return _utc(f"TRUSTED_CLOCK_{phase}", clock_provider())
    except LiveCanaryProviderBoundPrebootstrapAdmissionError:
        raise
    except Exception:
        raise LiveCanaryProviderBoundPrebootstrapAdmissionError(
            "TRUSTED_CLOCK_UNAVAILABLE"
        ) from None


def _require_central_live_lock() -> None:
    if execution_policy.LIVE_ALLOWED is not False:
        _reject("CENTRAL_LIVE_LOCK_NOT_FALSE")
    allowed, reasons = execution_policy.execution_mode_policy_decision("LIVE")
    if allowed is not False or reasons != ("LIVE_MODE_LOCKED",):
        _reject("CENTRAL_LIVE_POLICY_DECISION_DRIFT")


def _demo_source_projection(
    verification: WindowsExecutionSourceBoundCandidateVerification,
) -> dict[str, object]:
    return {
        "archive_sha256": verification.archive_sha256,
        "archive_size_bytes": verification.archive_size_bytes,
        "binding_identity_sha256": verification.binding_identity_sha256,
        "source_archive_sha256": verification.source_archive_sha256,
        "source_identity_sha256": verification.source_identity_sha256,
        "bootstrap_binding_sha256": verification.bootstrap_binding_sha256,
        "stage_binding_sha256": verification.stage_binding_sha256,
        "champion_archive_sha256": verification.champion_archive_sha256,
        "champion_package_identity_sha256": (
            verification.champion_package_identity_sha256
        ),
        "champion_model_artifact_sha256": (
            verification.champion_model_artifact_sha256
        ),
        "champion_training_snapshot_sha256": (
            verification.champion_training_snapshot_sha256
        ),
        "champion_config_sha256": verification.champion_config_sha256,
        "champion_runtime_binding_sha256": (
            verification.champion_runtime_binding_sha256
        ),
        "production_config_sha256": verification.production_config_sha256,
        "candidate_id": verification.candidate_id,
        "candidate_content_sha256": verification.candidate_content_sha256,
        "provider_pack_identity_sha256": (
            verification.provider_pack_identity_sha256
        ),
        "provider_configuration_sha256": (
            verification.provider_configuration_sha256
        ),
        "configured_release_identity_sha256": (
            verification.configured_release_identity_sha256
        ),
        "configured_archive_sha256": verification.configured_archive_sha256,
        "execution_factory_template_sha256": (
            verification.execution_factory_template_sha256
        ),
        "task_definition_sha256": verification.task_definition_sha256,
        "suite_identity_sha256": verification.suite_identity_sha256,
        "execution_base_archive_sha256": (
            verification.execution_base_archive_sha256
        ),
        "execution_base_release_identity_sha256": (
            verification.execution_base_release_identity_sha256
        ),
        "git_commit": verification.git_commit,
        "git_tree": verification.git_tree,
        "schema_version": (
            "windows-execution-source-bound-verification-projection-v1"
        ),
    }


@dataclass(frozen=True, slots=True)
class LiveCanaryProviderBoundPrebootstrapAdmission(CanonicalContract):
    """Sealed proof of fresh provider binding with no runtime authority."""

    checked_at: datetime
    provider_acceptance_valid_until_utc: datetime
    legacy_admission_sha256: str
    candidate_sha256: str
    demo_source_bound_verification_sha256: str
    demo_source_bound_archive_sha256: str
    demo_source_bound_binding_identity_sha256: str
    live_source_bound_verification_sha256: str
    live_bound_archive_sha256: str
    live_binding_identity_sha256: str
    provider_acceptance_sha256: str
    provider_acceptance_policy_sha256: str
    provider_conformance_review_sha256: str
    target_host_identity_sha256: str
    installed_environment_sha256: str
    live_execution_release_identity_sha256: str
    live_execution_task_definition_sha256: str
    trust_policy_sha256: str
    authorization_id: str
    authorization_sha256: str
    request_sha256: str
    activation_binding_sha256: str
    validation_sha256: str
    live_commit_sha: str
    live_git_tree: str
    symbol: str
    max_lot: float
    max_concurrent_positions: int
    provider_count: int
    credential_reference_count: int
    status: str = field(default=ADMISSION_STATUS, init=False)
    provider_accepted: bool = field(default=True, init=False)
    provider_binding_complete: bool = field(default=True, init=False)
    portable_custody_required: bool = field(default=True, init=False)
    central_unlock_required: bool = field(default=True, init=False)
    bootstrap_authorized: bool = field(default=False, init=False)
    process_launch_authorized: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    broker_mutation_authorized: bool = field(default=False, init=False)
    live_allowed: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    promotion_eligible: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    schema_version: str = field(default=ADMISSION_SCHEMA_VERSION, init=False)
    _provider_bound_seal: object = field(
        init=False,
        repr=False,
        compare=False,
    )
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _REPORT_SEAL:
            raise TypeError(
                "provider-bound prebootstrap admission requires its verifier"
            )
        checked = _utc("CHECKED_AT", self.checked_at)
        valid_until = _utc(
            "PROVIDER_ACCEPTANCE_VALID_UNTIL_UTC",
            self.provider_acceptance_valid_until_utc,
        )
        if checked >= valid_until:
            _reject("PROVIDER_BOUND_ADMISSION_EXPIRED")
        for name in (
            "legacy_admission_sha256",
            "candidate_sha256",
            "demo_source_bound_verification_sha256",
            "demo_source_bound_archive_sha256",
            "demo_source_bound_binding_identity_sha256",
            "live_source_bound_verification_sha256",
            "live_bound_archive_sha256",
            "live_binding_identity_sha256",
            "provider_acceptance_sha256",
            "provider_acceptance_policy_sha256",
            "provider_conformance_review_sha256",
            "target_host_identity_sha256",
            "installed_environment_sha256",
            "live_execution_release_identity_sha256",
            "live_execution_task_definition_sha256",
            "trust_policy_sha256",
            "authorization_sha256",
            "request_sha256",
            "activation_binding_sha256",
            "validation_sha256",
        ):
            _sha256(name, getattr(self, name))
        _identifier("AUTHORIZATION_ID", self.authorization_id)
        _git_sha("LIVE_COMMIT_SHA", self.live_commit_sha)
        _git_sha("LIVE_GIT_TREE", self.live_git_tree)
        if self.symbol != "XAUUSD":
            _reject("PROVIDER_BOUND_SYMBOL_INVALID")
        _fixed_float("MAX_LOT", self.max_lot, LIVE_CANARY_MAX_LOT)
        if (
            type(self.max_concurrent_positions) is not int
            or self.max_concurrent_positions
            != LIVE_CANARY_MAX_CONCURRENT_POSITIONS
            or type(self.provider_count) is not int
            or self.provider_count != PROVIDER_COUNT
            or type(self.credential_reference_count) is not int
            or self.credential_reference_count != CREDENTIAL_REFERENCE_COUNT
        ):
            _reject("PROVIDER_BOUND_INVENTORY_INVALID")
        if (
            self.status != ADMISSION_STATUS
            or self.provider_accepted is not True
            or self.provider_binding_complete is not True
            or self.portable_custody_required is not True
            or self.central_unlock_required is not True
            or self.bootstrap_authorized is not False
            or self.process_launch_authorized is not False
            or self.execution_authorized is not False
            or self.activation_authorized is not False
            or self.broker_mutation_authorized is not False
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or self.promotion_eligible is not False
            or self.order_capability != ORDER_CAPABILITY
            or self.schema_version != ADMISSION_SCHEMA_VERSION
        ):
            _reject("PROVIDER_BOUND_ADMISSION_SAFETY_DRIFT")
        object.__setattr__(
            self,
            "_provider_bound_seal",
            _REPORT_SEAL,
        )

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            item.name: canonicalize(getattr(self, item.name))
            for item in fields(self)
            if item.name != "_provider_bound_seal"
        }


def is_live_canary_provider_bound_prebootstrap_admission(
    value: object,
) -> bool:
    """Return true only for a result sealed by this module."""

    return (
        type(value) is LiveCanaryProviderBoundPrebootstrapAdmission
        and getattr(value, "_provider_bound_seal", None) is _REPORT_SEAL
    )


def _require_exact_upstream_inputs(
    *,
    candidate: object,
    legacy_admission: object,
    demo_source_bound_verification: object,
    live_source_bound_verification: object,
    activation_trust_policy: object,
    authorization: object,
    validation: object,
) -> tuple[
    LiveCanaryRuntimeCandidate,
    LiveCanaryPrebootstrapAdmission,
    WindowsExecutionSourceBoundCandidateVerification,
    WindowsLiveCanaryExecutionSourceBoundCandidateVerification,
    LiveCanaryTrustPolicy,
    LiveCanaryActivationAuthorization,
    LiveCanaryActivationValidation,
]:
    if type(candidate) is not LiveCanaryRuntimeCandidate:
        _reject("LIVE_RUNTIME_CANDIDATE_TYPE_INVALID")
    if not is_live_canary_prebootstrap_admission(legacy_admission):
        _reject("LEGACY_PREBOOTSTRAP_ADMISSION_UNSEALED")
    if not is_windows_execution_source_bound_candidate_verification(
        demo_source_bound_verification
    ):
        _reject("DEMO_SOURCE_BOUND_VERIFICATION_UNSEALED")
    if not is_windows_live_canary_execution_source_bound_candidate_verification(
        live_source_bound_verification
    ):
        _reject("LIVE_SOURCE_BOUND_VERIFICATION_UNSEALED")
    if type(activation_trust_policy) is not LiveCanaryTrustPolicy:
        _reject("ACTIVATION_TRUST_POLICY_TYPE_INVALID")
    if type(authorization) is not LiveCanaryActivationAuthorization:
        _reject("ACTIVATION_AUTHORIZATION_TYPE_INVALID")
    if type(validation) is not LiveCanaryActivationValidation:
        _reject("ACTIVATION_VALIDATION_TYPE_INVALID")
    return (
        candidate,
        legacy_admission,
        demo_source_bound_verification,
        live_source_bound_verification,
        activation_trust_policy,
        authorization,
        validation,
    )


def _require_legacy_binding(
    *,
    candidate: LiveCanaryRuntimeCandidate,
    legacy_admission: LiveCanaryPrebootstrapAdmission,
    demo_source: WindowsExecutionSourceBoundCandidateVerification,
    activation_trust_policy: LiveCanaryTrustPolicy,
    authorization: LiveCanaryActivationAuthorization,
    validation: LiveCanaryActivationValidation,
) -> str:
    demo_projection_sha256 = canonical_sha256(
        _demo_source_projection(demo_source)
    )
    request = authorization.request
    expected = (
        (legacy_admission.candidate_sha256, candidate.content_sha256),
        (
            legacy_admission.source_bound_verification_sha256,
            demo_projection_sha256,
        ),
        (
            legacy_admission.source_bound_archive_sha256,
            demo_source.archive_sha256,
        ),
        (
            legacy_admission.source_bound_binding_identity_sha256,
            demo_source.binding_identity_sha256,
        ),
        (
            legacy_admission.trust_policy_sha256,
            activation_trust_policy.policy_sha256,
        ),
        (legacy_admission.authorization_id, authorization.authorization_id),
        (
            legacy_admission.authorization_sha256,
            authorization.content_sha256,
        ),
        (legacy_admission.request_sha256, request.content_sha256),
        (
            legacy_admission.activation_binding_sha256,
            request.binding.binding_sha256,
        ),
        (legacy_admission.validation_sha256, validation.content_sha256),
        (legacy_admission.live_commit_sha, candidate.commit_sha),
        (legacy_admission.champion_git_tree, candidate.champion_git_tree),
        (legacy_admission.symbol, candidate.symbol_map[0][0]),
        (legacy_admission.max_lot, candidate.max_lot),
        (
            legacy_admission.max_concurrent_positions,
            candidate.max_concurrent_positions,
        ),
        (validation.authorization_id, authorization.authorization_id),
        (validation.authorization_sha256, authorization.content_sha256),
        (validation.request_sha256, request.content_sha256),
        (validation.binding_sha256, request.binding.binding_sha256),
    )
    if any(left != right for left, right in expected):
        _reject("LEGACY_ADMISSION_BINDING_MISMATCH")
    if (
        validation.valid is not True
        or validation.consumed_once is not True
        or validation.reason_codes
    ):
        _reject("ACTIVATION_VALIDATION_NOT_CONSUMED")
    return demo_projection_sha256


def _require_live_source_binding(
    *,
    candidate: LiveCanaryRuntimeCandidate,
    demo_source: WindowsExecutionSourceBoundCandidateVerification,
    live_source: WindowsLiveCanaryExecutionSourceBoundCandidateVerification,
) -> str:
    expected = (
        (live_source.source_bound_archive_sha256, demo_source.archive_sha256),
        (
            live_source.source_bound_binding_identity_sha256,
            demo_source.binding_identity_sha256,
        ),
        (live_source.source_archive_sha256, demo_source.source_archive_sha256),
        (
            live_source.bootstrap_binding_sha256,
            demo_source.bootstrap_binding_sha256,
        ),
        (live_source.suite_identity_sha256, demo_source.suite_identity_sha256),
        (
            live_source.execution_base_archive_sha256,
            demo_source.execution_base_archive_sha256,
        ),
        (
            live_source.execution_base_release_identity_sha256,
            demo_source.execution_base_release_identity_sha256,
        ),
        (live_source.git_commit, demo_source.git_commit),
        (live_source.git_tree, demo_source.git_tree),
        (candidate.commit_sha, live_source.git_commit),
        (candidate.champion_git_tree, live_source.git_tree),
        (
            candidate.release_manifest_sha256,
            live_source.configured_release_identity_sha256,
        ),
    )
    if any(left != right for left, right in expected):
        _reject("LIVE_SOURCE_ANCESTRY_MISMATCH")
    try:
        projection = live_execution_source_binding_from_verification(
            live_source
        )
    except Exception:
        raise LiveCanaryProviderBoundPrebootstrapAdmissionError(
            "LIVE_SOURCE_PROJECTION_INVALID"
        ) from None
    return canonical_sha256(projection)


def _require_provider_authority_separation(
    *,
    candidate: LiveCanaryRuntimeCandidate,
    activation_trust_policy: LiveCanaryTrustPolicy,
    provider_acceptance_policy: WindowsLiveProviderAcceptancePolicy,
) -> None:
    provider_ids = {
        provider_acceptance_policy.owner_authority_key_id,
        provider_acceptance_policy.runtime_authority_key_id,
    }
    provider_fingerprints = {
        provider_acceptance_policy.owner_public_key_fingerprint_sha256,
        provider_acceptance_policy.runtime_public_key_fingerprint_sha256,
    }
    if (
        provider_ids & candidate.runtime_key_ids
        or provider_ids & activation_trust_policy.authority_key_ids
        or provider_fingerprints & candidate.runtime_key_fingerprints
        or provider_fingerprints
        & activation_trust_policy.authority_key_fingerprints
    ):
        _reject("PROVIDER_AUTHORITY_REUSE")


def assess_live_canary_provider_bound_prebootstrap_admission(
    *,
    candidate: LiveCanaryRuntimeCandidate,
    legacy_admission: LiveCanaryPrebootstrapAdmission,
    demo_source_bound_verification: WindowsExecutionSourceBoundCandidateVerification,
    live_source_bound_verification: (
        WindowsLiveCanaryExecutionSourceBoundCandidateVerification
    ),
    conformance_review: WindowsThreeServiceProviderConformanceReview,
    provider_acceptance_policy: WindowsLiveProviderAcceptancePolicy,
    owner_acceptance: WindowsLiveProviderOwnerAcceptance,
    runtime_attestation: WindowsLiveProviderRuntimeAttestation,
    owner_validation_receipt_bytes: bytes,
    runtime_evidence_bytes: bytes,
    runtime_validation_receipt_bytes: bytes,
    expected_provider_acceptance_policy_sha256: str,
    expected_target_host_identity_sha256: str,
    activation_trust_policy: LiveCanaryTrustPolicy,
    authorization: LiveCanaryActivationAuthorization,
    validation: LiveCanaryActivationValidation,
    clock_provider: Callable[[], datetime],
) -> LiveCanaryProviderBoundPrebootstrapAdmission:
    """Reverify and compose exact provider evidence while LIVE is locked."""

    _require_central_live_lock()
    (
        typed_candidate,
        typed_legacy,
        typed_demo_source,
        typed_live_source,
        typed_activation_policy,
        typed_authorization,
        typed_validation,
    ) = _require_exact_upstream_inputs(
        candidate=candidate,
        legacy_admission=legacy_admission,
        demo_source_bound_verification=demo_source_bound_verification,
        live_source_bound_verification=live_source_bound_verification,
        activation_trust_policy=activation_trust_policy,
        authorization=authorization,
        validation=validation,
    )
    started = _clock(clock_provider, phase="START")
    if (
        started < typed_legacy.checked_at
        or started < typed_validation.checked_at
        or started < typed_authorization.request.issued_at
        or started >= typed_authorization.request.expires_at
    ):
        _reject("PROVIDER_BOUND_PREBOOTSTRAP_TIME_INVALID")

    demo_projection_sha256 = _require_legacy_binding(
        candidate=typed_candidate,
        legacy_admission=typed_legacy,
        demo_source=typed_demo_source,
        activation_trust_policy=typed_activation_policy,
        authorization=typed_authorization,
        validation=typed_validation,
    )
    live_projection_sha256 = _require_live_source_binding(
        candidate=typed_candidate,
        demo_source=typed_demo_source,
        live_source=typed_live_source,
    )

    if type(provider_acceptance_policy) is not WindowsLiveProviderAcceptancePolicy:
        _reject("PROVIDER_ACCEPTANCE_POLICY_TYPE_INVALID")
    _require_provider_authority_separation(
        candidate=typed_candidate,
        activation_trust_policy=typed_activation_policy,
        provider_acceptance_policy=provider_acceptance_policy,
    )
    try:
        provider_acceptance = (
            prepare_windows_live_provider_conformance_acceptance(
                source_verification=typed_live_source,
                conformance_review=conformance_review,
                trust_policy=provider_acceptance_policy,
                owner_acceptance=owner_acceptance,
                runtime_attestation=runtime_attestation,
                owner_validation_receipt_bytes=(
                    owner_validation_receipt_bytes
                ),
                runtime_evidence_bytes=runtime_evidence_bytes,
                runtime_validation_receipt_bytes=(
                    runtime_validation_receipt_bytes
                ),
                expected_policy_sha256=(
                    expected_provider_acceptance_policy_sha256
                ),
                expected_target_host_identity_sha256=(
                    expected_target_host_identity_sha256
                ),
                clock_provider=clock_provider,
            )
        )
    except WindowsLiveProviderConformanceAcceptanceError:
        raise LiveCanaryProviderBoundPrebootstrapAdmissionError(
            "PROVIDER_ACCEPTANCE_INVALID"
        ) from None
    except Exception:
        raise LiveCanaryProviderBoundPrebootstrapAdmissionError(
            "PROVIDER_ACCEPTANCE_INVALID"
        ) from None
    if not is_windows_live_provider_conformance_acceptance(
        provider_acceptance
    ):
        _reject("PROVIDER_ACCEPTANCE_UNSEALED")

    expected_provider_bindings = (
        (
            provider_acceptance.live_bound_archive_sha256,
            typed_live_source.archive_sha256,
        ),
        (
            provider_acceptance.live_binding_identity_sha256,
            typed_live_source.binding_identity_sha256,
        ),
        (
            provider_acceptance.source_bound_archive_sha256,
            typed_demo_source.archive_sha256,
        ),
        (
            provider_acceptance.source_archive_sha256,
            typed_demo_source.source_archive_sha256,
        ),
        (
            provider_acceptance.suite_identity_sha256,
            typed_live_source.suite_identity_sha256,
        ),
        (
            provider_acceptance.execution_release_identity_sha256,
            typed_live_source.configured_release_identity_sha256,
        ),
        (
            provider_acceptance.target_host_identity_sha256,
            expected_target_host_identity_sha256,
        ),
        (
            provider_acceptance.installed_environment_sha256,
            typed_candidate.installed_environment_sha256,
        ),
        (provider_acceptance.provider_count, PROVIDER_COUNT),
        (
            provider_acceptance.credential_reference_count,
            CREDENTIAL_REFERENCE_COUNT,
        ),
    )
    for index, (left, right) in enumerate(expected_provider_bindings):
        if left != right:
            if index == 7:
                _reject("INSTALLED_ENVIRONMENT_MISMATCH")
            _reject("PROVIDER_ACCEPTANCE_BINDING_MISMATCH")

    valid_until = min(
        owner_acceptance.expires_at_utc,
        runtime_attestation.expires_at_utc,
        typed_authorization.request.expires_at,
    )
    completed = _clock(clock_provider, phase="COMPLETION")
    if (
        provider_acceptance.checked_at_utc < started
        or completed < started
        or completed < provider_acceptance.checked_at_utc
        or completed >= valid_until
    ):
        _reject("PROVIDER_BOUND_PREBOOTSTRAP_CLOCK_WINDOW_INVALID")
    _require_central_live_lock()

    return LiveCanaryProviderBoundPrebootstrapAdmission(
        checked_at=completed,
        provider_acceptance_valid_until_utc=valid_until,
        legacy_admission_sha256=typed_legacy.content_sha256,
        candidate_sha256=typed_candidate.content_sha256,
        demo_source_bound_verification_sha256=demo_projection_sha256,
        demo_source_bound_archive_sha256=typed_demo_source.archive_sha256,
        demo_source_bound_binding_identity_sha256=(
            typed_demo_source.binding_identity_sha256
        ),
        live_source_bound_verification_sha256=live_projection_sha256,
        live_bound_archive_sha256=typed_live_source.archive_sha256,
        live_binding_identity_sha256=(
            typed_live_source.binding_identity_sha256
        ),
        provider_acceptance_sha256=provider_acceptance.content_sha256,
        provider_acceptance_policy_sha256=(
            provider_acceptance_policy.content_sha256
        ),
        provider_conformance_review_sha256=(
            provider_acceptance.provider_conformance_review_sha256
        ),
        target_host_identity_sha256=(
            provider_acceptance.target_host_identity_sha256
        ),
        installed_environment_sha256=(
            provider_acceptance.installed_environment_sha256
        ),
        live_execution_release_identity_sha256=(
            typed_live_source.configured_release_identity_sha256
        ),
        live_execution_task_definition_sha256=(
            typed_live_source.task_definition_sha256
        ),
        trust_policy_sha256=typed_activation_policy.policy_sha256,
        authorization_id=typed_authorization.authorization_id,
        authorization_sha256=typed_authorization.content_sha256,
        request_sha256=typed_authorization.request.content_sha256,
        activation_binding_sha256=(
            typed_authorization.request.binding.binding_sha256
        ),
        validation_sha256=typed_validation.content_sha256,
        live_commit_sha=typed_candidate.commit_sha,
        live_git_tree=typed_live_source.git_tree,
        symbol=typed_candidate.symbol_map[0][0],
        max_lot=typed_candidate.max_lot,
        max_concurrent_positions=(
            typed_candidate.max_concurrent_positions
        ),
        provider_count=provider_acceptance.provider_count,
        credential_reference_count=(
            provider_acceptance.credential_reference_count
        ),
        _seal=_REPORT_SEAL,
    )


__all__ = [
    "ADMISSION_SCHEMA_VERSION",
    "ADMISSION_STATUS",
    "LiveCanaryProviderBoundPrebootstrapAdmission",
    "LiveCanaryProviderBoundPrebootstrapAdmissionError",
    "assess_live_canary_provider_bound_prebootstrap_admission",
    "is_live_canary_provider_bound_prebootstrap_admission",
]
