"""Deny-only prebootstrap admission for the first XAUUSD live canary.

This module composes already-verified immutable evidence.  It deliberately
contains no runtime materialization, credential, provider, process, network,
database, scheduler, broker, permit, or order effect.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field, fields as dataclass_fields
from datetime import datetime
import math
import re
from typing import Callable

import execution_policy

from .contracts import CanonicalContract, canonical_sha256, canonicalize
from .live_canary_runtime_candidate import (
    LiveCanaryPrebootstrapAdmissionError,
    LiveCanaryRuntimeCandidate,
    ORDER_CAPABILITY,
)
from .live_canary_activation import (
    LIVE_CANARY_MAX_CONCURRENT_POSITIONS,
    LIVE_CANARY_MAX_LOT,
    LiveCanaryActivationAuthorization,
    LiveCanaryActivationValidation,
    LiveCanaryTrustPolicy,
)
from .windows_execution_source_bound_candidate import (
    WindowsExecutionSourceBoundCandidateVerification,
    is_windows_execution_source_bound_candidate_verification,
)


ADMISSION_SCHEMA_VERSION = "live-canary-prebootstrap-admission-v1"
ADMISSION_STATUS = "PREBOOTSTRAP_EVIDENCE_COMPLETE_CENTRAL_UNLOCK_REQUIRED"

_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_REPORT_SEAL = object()

_SOURCE_HASH_BINDINGS = (
    ("demo_source_bound_archive_sha256", "archive_sha256"),
    (
        "demo_source_bound_binding_identity_sha256",
        "binding_identity_sha256",
    ),
    ("demo_source_archive_sha256", "source_archive_sha256"),
    ("demo_source_identity_sha256", "source_identity_sha256"),
    ("demo_production_config_sha256", "production_config_sha256"),
    ("demo_bootstrap_binding_sha256", "bootstrap_binding_sha256"),
    ("demo_stage_binding_sha256", "stage_binding_sha256"),
    (
        "demo_configured_release_identity_sha256",
        "configured_release_identity_sha256",
    ),
    ("demo_configured_archive_sha256", "configured_archive_sha256"),
    (
        "demo_execution_factory_template_sha256",
        "execution_factory_template_sha256",
    ),
    (
        "demo_execution_candidate_content_sha256",
        "candidate_content_sha256",
    ),
    (
        "demo_provider_pack_identity_sha256",
        "provider_pack_identity_sha256",
    ),
    (
        "demo_provider_configuration_sha256",
        "provider_configuration_sha256",
    ),
    ("demo_task_definition_sha256", "task_definition_sha256"),
    ("demo_base_suite_identity_sha256", "suite_identity_sha256"),
    (
        "demo_execution_base_archive_sha256",
        "execution_base_archive_sha256",
    ),
    (
        "demo_execution_base_release_identity_sha256",
        "execution_base_release_identity_sha256",
    ),
    ("model_artifact_sha256", "champion_model_artifact_sha256"),
    ("champion_archive_sha256", "champion_archive_sha256"),
    (
        "champion_package_identity_sha256",
        "champion_package_identity_sha256",
    ),
    (
        "champion_training_snapshot_sha256",
        "champion_training_snapshot_sha256",
    ),
    ("champion_config_sha256", "champion_config_sha256"),
    (
        "champion_runtime_binding_sha256",
        "champion_runtime_binding_sha256",
    ),
)


def _reject(reason_code: str) -> None:
    raise LiveCanaryPrebootstrapAdmissionError(reason_code)


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


@dataclass(frozen=True, slots=True)
class LiveCanaryPrebootstrapAdmission(CanonicalContract):
    """Verifier-sealed evidence that still grants no bootstrap authority."""

    checked_at: datetime
    candidate_sha256: str
    source_bound_verification_sha256: str
    source_bound_archive_sha256: str
    source_bound_binding_identity_sha256: str
    trust_policy_sha256: str
    authorization_id: str
    authorization_sha256: str
    request_sha256: str
    activation_binding_sha256: str
    validation_sha256: str
    live_commit_sha: str
    champion_git_tree: str
    symbol: str
    max_lot: float
    max_concurrent_positions: int
    status: str = field(default=ADMISSION_STATUS, init=False)
    central_unlock_required: bool = field(default=True, init=False)
    bootstrap_authorized: bool = field(default=False, init=False)
    live_allowed: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    schema_version: str = field(default=ADMISSION_SCHEMA_VERSION, init=False)
    _admission_seal: object = field(init=False, repr=False, compare=False)
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _REPORT_SEAL:
            raise TypeError("prebootstrap admission requires its verifier")
        _utc("checked_at", self.checked_at)
        for name in (
            "candidate_sha256",
            "source_bound_verification_sha256",
            "source_bound_archive_sha256",
            "source_bound_binding_identity_sha256",
            "trust_policy_sha256",
            "authorization_sha256",
            "request_sha256",
            "activation_binding_sha256",
            "validation_sha256",
        ):
            _sha256(name, getattr(self, name))
        _identifier("authorization_id", self.authorization_id)
        _git_sha("live_commit_sha", self.live_commit_sha)
        _git_sha("champion_git_tree", self.champion_git_tree)
        if self.symbol != "XAUUSD":
            _reject("PREBOOTSTRAP_SYMBOL_INVALID")
        _fixed_float("max_lot", self.max_lot, LIVE_CANARY_MAX_LOT)
        if self.max_concurrent_positions != LIVE_CANARY_MAX_CONCURRENT_POSITIONS:
            _reject("PREBOOTSTRAP_POSITION_LIMIT_INVALID")
        if (
            self.status != ADMISSION_STATUS
            or self.central_unlock_required is not True
            or any(
                (
                    self.bootstrap_authorized,
                    self.live_allowed,
                    self.safe_to_demo_auto_order,
                    self.execution_authorized,
                    self.activation_authorized,
                    self.order_capability != ORDER_CAPABILITY,
                    self.schema_version != ADMISSION_SCHEMA_VERSION,
                )
            )
        ):
            _reject("PREBOOTSTRAP_REPORT_SAFETY_DRIFT")
        object.__setattr__(self, "_admission_seal", _REPORT_SEAL)

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            item.name: canonicalize(getattr(self, item.name))
            for item in dataclass_fields(self)
            if item.name != "_admission_seal"
        }


def is_live_canary_prebootstrap_admission(value: object) -> bool:
    """Return true only for an admission sealed by this verifier module."""

    return (
        type(value) is LiveCanaryPrebootstrapAdmission
        and getattr(value, "_admission_seal", None) is _REPORT_SEAL
    )


def _source_projection(
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
        "schema_version": "windows-execution-source-bound-verification-projection-v1",
    }


def _require_source_binding(
    candidate: LiveCanaryRuntimeCandidate,
    verification: WindowsExecutionSourceBoundCandidateVerification,
) -> None:
    for candidate_name, verification_name in _SOURCE_HASH_BINDINGS:
        if getattr(candidate, candidate_name) != getattr(
            verification,
            verification_name,
        ):
            _reject("LIVE_CANARY_DEMO_SOURCE_BOUND_MISMATCH")
    if candidate.demo_execution_candidate_id != verification.candidate_id:
        _reject("LIVE_CANARY_DEMO_SOURCE_BOUND_MISMATCH")
    if (
        candidate.demo_git_commit != verification.git_commit
        or candidate.demo_git_tree != verification.git_tree
        or candidate.champion_git_tree != verification.git_tree
    ):
        _reject("LIVE_CANARY_DEMO_SOURCE_GIT_MISMATCH")


def _require_activation_binding(
    candidate: LiveCanaryRuntimeCandidate,
    authorization: LiveCanaryActivationAuthorization,
    validation: LiveCanaryActivationValidation,
    trust_policy: LiveCanaryTrustPolicy,
) -> None:
    request = authorization.request
    binding = request.binding
    if (
        binding.acceptance_policy_sha256 != trust_policy.policy_sha256
        or candidate.activation_policy_sha256 != trust_policy.policy_sha256
    ):
        _reject("LIVE_CANARY_PREBOOTSTRAP_POLICY_MISMATCH")
    if (
        validation.valid is not True
        or validation.consumed_once is not True
        or validation.reason_codes
    ):
        _reject("LIVE_CANARY_VALIDATION_NOT_CONSUMED")
    if (
        validation.authorization_id != authorization.authorization_id
        or validation.authorization_sha256 != authorization.content_sha256
        or validation.request_sha256 != request.content_sha256
        or validation.binding_sha256 != binding.binding_sha256
    ):
        _reject("LIVE_CANARY_VALIDATION_BINDING_MISMATCH")
    if (
        candidate.runtime_key_ids & trust_policy.authority_key_ids
        or candidate.runtime_key_fingerprints
        & trust_policy.authority_key_fingerprints
    ):
        _reject("LIVE_CANARY_RUNTIME_AUTHORITY_KEY_REUSE")

    expected = (
        (candidate.content_sha256, binding.live_config_sha256),
        (candidate.broker_id, binding.broker_id),
        (candidate.account_alias_sha256, binding.live_account_alias_sha256),
        (candidate.server, binding.live_server),
        (candidate.journal_sha256, binding.live_journal_sha256),
        (candidate.commit_sha, binding.live_commit_sha),
        (candidate.dependency_lock_sha256, binding.live_dependency_lock_sha256),
        (candidate.broker_spec_sha256, binding.live_broker_spec_sha256),
        (candidate.session_calendar_sha256, binding.live_session_calendar_sha256),
        (candidate.runtime_profile_sha256, binding.live_runtime_profile_sha256),
        (candidate.release_manifest_sha256, binding.live_release_manifest_sha256),
        (candidate.model_artifact_sha256, binding.model_artifact_sha256),
        (candidate.champion_archive_sha256, binding.champion_archive_sha256),
        (
            candidate.champion_package_identity_sha256,
            binding.champion_package_identity_sha256,
        ),
        (
            candidate.champion_training_snapshot_sha256,
            binding.champion_training_snapshot_sha256,
        ),
        (candidate.champion_git_tree, binding.champion_git_tree),
        (
            candidate.champion_runtime_binding_sha256,
            binding.champion_runtime_binding_sha256,
        ),
        (candidate.demo_production_config_sha256, binding.demo_config_sha256),
        (candidate.demo_git_commit, binding.demo_commit_sha),
        (candidate.symbol_map[0][0], binding.symbol),
        (candidate.max_lot, binding.max_lot),
        (
            candidate.max_concurrent_positions,
            binding.max_concurrent_positions,
        ),
    )
    if any(left != right for left, right in expected):
        _reject("LIVE_CANARY_RUNTIME_ACTIVATION_BINDING_MISMATCH")


def assess_live_canary_prebootstrap_admission(
    *,
    candidate: LiveCanaryRuntimeCandidate,
    source_bound_verification: WindowsExecutionSourceBoundCandidateVerification,
    trust_policy: LiveCanaryTrustPolicy,
    authorization: LiveCanaryActivationAuthorization,
    validation: LiveCanaryActivationValidation,
    clock_provider: Callable[[], datetime],
) -> LiveCanaryPrebootstrapAdmission:
    """Compose exact evidence into a sealed report while LIVE stays locked."""

    if type(candidate) is not LiveCanaryRuntimeCandidate:
        _reject("LIVE_RUNTIME_CANDIDATE_TYPE_INVALID")
    if not is_windows_execution_source_bound_candidate_verification(
        source_bound_verification
    ):
        _reject("DEMO_SOURCE_BOUND_VERIFICATION_UNSEALED")
    if type(trust_policy) is not LiveCanaryTrustPolicy:
        _reject("LIVE_CANARY_TRUST_POLICY_TYPE_INVALID")
    if type(authorization) is not LiveCanaryActivationAuthorization:
        _reject("LIVE_CANARY_AUTHORIZATION_TYPE_INVALID")
    if type(validation) is not LiveCanaryActivationValidation:
        _reject("LIVE_CANARY_VALIDATION_TYPE_INVALID")
    if not callable(clock_provider):
        _reject("TRUSTED_CLOCK_PROVIDER_INVALID")
    if execution_policy.LIVE_ALLOWED is not False:
        _reject("CENTRAL_LIVE_LOCK_NOT_FALSE")
    allowed, reasons = execution_policy.execution_mode_policy_decision("LIVE")
    if allowed is not False or reasons != ("LIVE_MODE_LOCKED",):
        _reject("CENTRAL_LIVE_POLICY_DECISION_DRIFT")

    try:
        started_at = _utc("TRUSTED_CLOCK", clock_provider())
    except LiveCanaryPrebootstrapAdmissionError:
        raise
    except Exception as exc:
        raise LiveCanaryPrebootstrapAdmissionError(
            "TRUSTED_CLOCK_UNAVAILABLE"
        ) from exc
    if (
        started_at < validation.checked_at
        or started_at < authorization.request.issued_at
        or started_at >= authorization.request.expires_at
    ):
        _reject("LIVE_CANARY_PREBOOTSTRAP_TIME_INVALID")

    _require_source_binding(candidate, source_bound_verification)
    _require_activation_binding(
        candidate,
        authorization,
        validation,
        trust_policy,
    )

    try:
        completed_at = _utc("TRUSTED_CLOCK", clock_provider())
    except LiveCanaryPrebootstrapAdmissionError:
        raise
    except Exception as exc:
        raise LiveCanaryPrebootstrapAdmissionError(
            "TRUSTED_CLOCK_UNAVAILABLE"
        ) from exc
    if (
        completed_at < started_at
        or completed_at >= authorization.request.expires_at
    ):
        _reject("LIVE_CANARY_PREBOOTSTRAP_CLOCK_WINDOW_INVALID")

    source_projection = _source_projection(source_bound_verification)
    return LiveCanaryPrebootstrapAdmission(
        checked_at=started_at,
        candidate_sha256=candidate.content_sha256,
        source_bound_verification_sha256=canonical_sha256(source_projection),
        source_bound_archive_sha256=source_bound_verification.archive_sha256,
        source_bound_binding_identity_sha256=(
            source_bound_verification.binding_identity_sha256
        ),
        trust_policy_sha256=trust_policy.policy_sha256,
        authorization_id=authorization.authorization_id,
        authorization_sha256=authorization.content_sha256,
        request_sha256=authorization.request.content_sha256,
        activation_binding_sha256=(
            authorization.request.binding.binding_sha256
        ),
        validation_sha256=validation.content_sha256,
        live_commit_sha=candidate.commit_sha,
        champion_git_tree=candidate.champion_git_tree,
        symbol=candidate.symbol_map[0][0],
        max_lot=candidate.max_lot,
        max_concurrent_positions=candidate.max_concurrent_positions,
        _seal=_REPORT_SEAL,
    )


__all__ = [
    "ADMISSION_STATUS",
    "LiveCanaryPrebootstrapAdmission",
    "LiveCanaryPrebootstrapAdmissionError",
    "LiveCanaryRuntimeCandidate",
    "assess_live_canary_prebootstrap_admission",
    "is_live_canary_prebootstrap_admission",
]
