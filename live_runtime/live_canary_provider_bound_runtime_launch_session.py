"""Provider-bound composition for one LIVE canary launch-only session.

The verifier composes a freshly consumed legacy v1 checkpoint/nonce session
with exact provider-bound admission and WORM custody proofs.  It grants no
order authority and performs no broker, process, storage, or network effect.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field, fields
from datetime import datetime
import re
from typing import Callable

from .asymmetric_release_trust import ExternalLauncherTrustPolicy
from .contracts import CanonicalContract, canonicalize
from .live_canary_portable_launch_custody import (
    LiveCanaryOneUseLaunchCapability,
    VerifiedLiveCanaryAdmissionCustody,
    is_live_canary_one_use_launch_capability,
    is_verified_live_canary_admission_custody,
)
from .live_canary_prebootstrap_admission import (
    LiveCanaryPrebootstrapAdmission,
    LiveCanaryRuntimeCandidate,
    is_live_canary_prebootstrap_admission,
)
from .live_canary_provider_bound_portable_custody import (
    VerifiedLiveCanaryProviderBoundAdmissionCustody,
    is_verified_live_canary_provider_bound_admission_custody,
)
from .live_canary_provider_bound_prebootstrap_admission import (
    LiveCanaryProviderBoundPrebootstrapAdmission,
    is_live_canary_provider_bound_prebootstrap_admission,
)
from .live_canary_runtime_authority import (
    LiveCanaryRuntimeLaunchSessionError,
    _REGISTRATION_SEAL,
    _SESSION_SEAL,
    _register_live_canary_provider_bound_runtime_launch_session_type,
    is_live_canary_provider_bound_runtime_launch_session,
    is_live_canary_runtime_launch_session,
)
from .live_canary_runtime_launch_session import (
    LiveCanaryRuntimeLaunchSession,
    _clock,
    _require_central_live_policy,
    activate_live_canary_runtime_launch_session,
)


PROVIDER_BOUND_RUNTIME_LAUNCH_SESSION_SCHEMA = (
    "live-canary-provider-bound-runtime-launch-session-v2"
)
ORDER_CAPABILITY = "GATED_PRESENT"
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


def _reject(reason_code: str) -> None:
    raise LiveCanaryRuntimeLaunchSessionError(reason_code)


def _sha256(name: str, value: object) -> str:
    if (
        type(value) is not str
        or _HEX_64.fullmatch(value) is None
        or value == "0" * 64
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


@dataclass(frozen=True, slots=True)
class LiveCanaryProviderBoundRuntimeLaunchSession(CanonicalContract):
    """Sealed provider-bound launch authority that cannot authorize orders."""

    activated_at_utc: datetime
    valid_until_utc: datetime
    sequence: int
    candidate_sha256: str
    admission_sha256: str
    launch_capability_sha256: str
    checkpoint_sha256: str
    launch_nonce_sha256: str
    launcher_attestation_sha256: str
    launcher_trust_policy_sha256: str
    runtime_profile_sha256: str
    release_manifest_sha256: str
    live_stage_binding_sha256: str
    deployment_host_alias_sha256: str
    service_account_alias_sha256: str
    task_definition_sha256: str
    legacy_launch_session_sha256: str
    legacy_custody_verification_sha256: str
    custody_policy_sha256: str
    provider_bound_admission_sha256: str
    provider_bound_custody_sha256: str
    provider_acceptance_sha256: str
    provider_acceptance_policy_sha256: str
    provider_conformance_review_sha256: str
    target_host_identity_sha256: str
    installed_environment_sha256: str
    live_execution_release_identity_sha256: str
    live_execution_task_definition_sha256: str
    provider_acceptance_valid_until_utc: datetime
    provider_bound_custody_valid_until_utc: datetime
    external_checkpoint_observations: int = field(default=2, init=False)
    external_nonce_observations: int = field(default=2, init=False)
    symbol: str = field(default="XAUUSD", init=False)
    max_lot: float = field(default=0.01, init=False)
    max_concurrent_positions: int = field(default=1, init=False)
    central_live_policy_enabled: bool = field(default=True, init=False)
    launch_reservation_consumed_once: bool = field(default=True, init=False)
    launch_capability_activation_consumed_once: bool = field(
        default=True,
        init=False,
    )
    provider_bound_admission_verified: bool = field(default=True, init=False)
    provider_bound_custody_verified: bool = field(default=True, init=False)
    bootstrap_authorized: bool = field(default=True, init=False)
    process_launch_authorized: bool = field(default=True, init=False)
    live_allowed: bool = field(default=True, init=False)
    execution_authorized: bool = field(default=False, init=False)
    broker_mutation_authorized: bool = field(default=False, init=False)
    independent_per_order_authorization_required: bool = field(
        default=True,
        init=False,
    )
    signed_promotion_evidence_required: bool = field(default=True, init=False)
    risk_and_news_guards_required: bool = field(default=True, init=False)
    durable_journal_lease_required: bool = field(default=True, init=False)
    final_mt5_submission_guard_required: bool = field(default=True, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    schema_version: str = field(
        default=PROVIDER_BOUND_RUNTIME_LAUNCH_SESSION_SCHEMA,
        init=False,
    )
    _session_seal: object = field(init=False, repr=False, compare=False)
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _SESSION_SEAL:
            raise TypeError(
                "provider-bound runtime launch session requires its verifier"
            )
        activated = _utc("ACTIVATED_AT_UTC", self.activated_at_utc)
        valid_until = _utc("VALID_UNTIL_UTC", self.valid_until_utc)
        provider_expiry = _utc(
            "PROVIDER_ACCEPTANCE_VALID_UNTIL_UTC",
            self.provider_acceptance_valid_until_utc,
        )
        custody_expiry = _utc(
            "PROVIDER_BOUND_CUSTODY_VALID_UNTIL_UTC",
            self.provider_bound_custody_valid_until_utc,
        )
        if (
            activated >= valid_until
            or valid_until > provider_expiry
            or valid_until > custody_expiry
        ):
            _reject("PROVIDER_BOUND_RUNTIME_LAUNCH_WINDOW_INVALID")
        if type(self.sequence) is not int or not 1 <= self.sequence <= 2**63 - 1:
            _reject("SEQUENCE_INVALID")
        for name in (
            "candidate_sha256",
            "admission_sha256",
            "launch_capability_sha256",
            "checkpoint_sha256",
            "launch_nonce_sha256",
            "launcher_attestation_sha256",
            "launcher_trust_policy_sha256",
            "runtime_profile_sha256",
            "release_manifest_sha256",
            "live_stage_binding_sha256",
            "deployment_host_alias_sha256",
            "service_account_alias_sha256",
            "task_definition_sha256",
            "legacy_launch_session_sha256",
            "legacy_custody_verification_sha256",
            "custody_policy_sha256",
            "provider_bound_admission_sha256",
            "provider_bound_custody_sha256",
            "provider_acceptance_sha256",
            "provider_acceptance_policy_sha256",
            "provider_conformance_review_sha256",
            "target_host_identity_sha256",
            "installed_environment_sha256",
            "live_execution_release_identity_sha256",
            "live_execution_task_definition_sha256",
        ):
            _sha256(name, getattr(self, name))
        if (
            self.external_checkpoint_observations != 2
            or self.external_nonce_observations != 2
            or self.symbol != "XAUUSD"
            or type(self.max_lot) is not float
            or self.max_lot != 0.01
            or self.max_concurrent_positions != 1
            or self.central_live_policy_enabled is not True
            or self.launch_reservation_consumed_once is not True
            or self.launch_capability_activation_consumed_once is not True
            or self.provider_bound_admission_verified is not True
            or self.provider_bound_custody_verified is not True
            or self.bootstrap_authorized is not True
            or self.process_launch_authorized is not True
            or self.live_allowed is not True
            or self.execution_authorized is not False
            or self.broker_mutation_authorized is not False
            or self.independent_per_order_authorization_required is not True
            or self.signed_promotion_evidence_required is not True
            or self.risk_and_news_guards_required is not True
            or self.durable_journal_lease_required is not True
            or self.final_mt5_submission_guard_required is not True
            or self.safe_to_demo_auto_order is not False
            or self.order_capability != ORDER_CAPABILITY
            or self.schema_version
            != PROVIDER_BOUND_RUNTIME_LAUNCH_SESSION_SCHEMA
        ):
            _reject("PROVIDER_BOUND_RUNTIME_LAUNCH_SAFETY_DRIFT")
        object.__setattr__(self, "_session_seal", _SESSION_SEAL)

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            item.name: canonicalize(getattr(self, item.name))
            for item in fields(self)
            if not item.name.startswith("_")
        }

    def assert_current(self, *, now: datetime) -> None:
        """Fail if the provider-bound launch authority is no longer current."""

        checked = _utc("NOW", now)
        _require_central_live_policy()
        if not self.activated_at_utc <= checked < self.valid_until_utc:
            _reject("PROVIDER_BOUND_RUNTIME_LAUNCH_SESSION_NOT_CURRENT")


_register_live_canary_provider_bound_runtime_launch_session_type(
    LiveCanaryProviderBoundRuntimeLaunchSession,
    _seal=_REGISTRATION_SEAL,
)


def _require_provider_bound_inputs(
    *,
    candidate: LiveCanaryRuntimeCandidate,
    legacy_admission: LiveCanaryPrebootstrapAdmission,
    provider_bound_admission: LiveCanaryProviderBoundPrebootstrapAdmission,
    provider_bound_custody: (
        VerifiedLiveCanaryProviderBoundAdmissionCustody
    ),
    legacy_custody_verification: VerifiedLiveCanaryAdmissionCustody,
    launch_capability: LiveCanaryOneUseLaunchCapability,
    launcher_policy: ExternalLauncherTrustPolicy,
    expected_provider_bound_admission_sha256: str,
    expected_provider_bound_custody_sha256: str,
) -> None:
    if type(candidate) is not LiveCanaryRuntimeCandidate:
        _reject("LIVE_CANARY_RUNTIME_CANDIDATE_NOT_EXACT")
    if not is_live_canary_prebootstrap_admission(legacy_admission):
        _reject("LIVE_CANARY_PREBOOTSTRAP_ADMISSION_NOT_SEALED")
    if not is_live_canary_provider_bound_prebootstrap_admission(
        provider_bound_admission
    ):
        _reject("PROVIDER_BOUND_PREBOOTSTRAP_ADMISSION_NOT_SEALED")
    if not is_verified_live_canary_provider_bound_admission_custody(
        provider_bound_custody
    ):
        _reject("PROVIDER_BOUND_ADMISSION_CUSTODY_NOT_SEALED")
    if not is_verified_live_canary_admission_custody(
        legacy_custody_verification
    ):
        _reject("LEGACY_ADMISSION_CUSTODY_NOT_SEALED")
    if not is_live_canary_one_use_launch_capability(launch_capability):
        _reject("LIVE_CANARY_LAUNCH_CAPABILITY_NOT_SEALED")
    if type(launcher_policy) is not ExternalLauncherTrustPolicy:
        _reject("EXTERNAL_LAUNCHER_TRUST_POLICY_NOT_EXACT")

    admission_pin = _sha256(
        "EXPECTED_PROVIDER_BOUND_ADMISSION_SHA256",
        expected_provider_bound_admission_sha256,
    )
    custody_pin = _sha256(
        "EXPECTED_PROVIDER_BOUND_CUSTODY_SHA256",
        expected_provider_bound_custody_sha256,
    )
    expected = (
        (admission_pin, provider_bound_admission.content_sha256),
        (custody_pin, provider_bound_custody.content_sha256),
        (
            provider_bound_admission.legacy_admission_sha256,
            legacy_admission.content_sha256,
        ),
        (
            provider_bound_admission.candidate_sha256,
            candidate.content_sha256,
        ),
        (
            provider_bound_admission.trust_policy_sha256,
            legacy_admission.trust_policy_sha256,
        ),
        (
            provider_bound_admission.authorization_sha256,
            legacy_admission.authorization_sha256,
        ),
        (
            provider_bound_admission.request_sha256,
            legacy_admission.request_sha256,
        ),
        (
            provider_bound_admission.activation_binding_sha256,
            legacy_admission.activation_binding_sha256,
        ),
        (
            provider_bound_admission.validation_sha256,
            legacy_admission.validation_sha256,
        ),
        (provider_bound_admission.live_commit_sha, candidate.commit_sha),
        (
            provider_bound_admission.installed_environment_sha256,
            candidate.installed_environment_sha256,
        ),
        (
            provider_bound_admission.live_execution_release_identity_sha256,
            candidate.release_manifest_sha256,
        ),
        (
            provider_bound_admission.target_host_identity_sha256,
            launcher_policy.deployment_host_alias_sha256,
        ),
        (
            provider_bound_admission.live_execution_task_definition_sha256,
            launcher_policy.task_definition_sha256,
        ),
        (
            provider_bound_custody.provider_bound_admission_sha256,
            provider_bound_admission.content_sha256,
        ),
        (
            provider_bound_custody.legacy_admission_sha256,
            legacy_admission.content_sha256,
        ),
        (
            provider_bound_custody.candidate_sha256,
            candidate.content_sha256,
        ),
        (
            provider_bound_custody.provider_acceptance_sha256,
            provider_bound_admission.provider_acceptance_sha256,
        ),
        (
            provider_bound_custody.provider_acceptance_policy_sha256,
            provider_bound_admission.provider_acceptance_policy_sha256,
        ),
        (
            provider_bound_custody.provider_conformance_review_sha256,
            provider_bound_admission.provider_conformance_review_sha256,
        ),
        (
            provider_bound_custody.target_host_identity_sha256,
            provider_bound_admission.target_host_identity_sha256,
        ),
        (
            provider_bound_custody.installed_environment_sha256,
            provider_bound_admission.installed_environment_sha256,
        ),
        (
            provider_bound_custody.live_execution_release_identity_sha256,
            provider_bound_admission.live_execution_release_identity_sha256,
        ),
        (
            provider_bound_custody.live_execution_task_definition_sha256,
            provider_bound_admission.live_execution_task_definition_sha256,
        ),
        (
            provider_bound_custody.authorization_sha256,
            provider_bound_admission.authorization_sha256,
        ),
        (
            provider_bound_custody.validation_sha256,
            provider_bound_admission.validation_sha256,
        ),
        (
            provider_bound_custody.launcher_trust_policy_sha256,
            launcher_policy.content_sha256,
        ),
        (
            provider_bound_custody.service_account_alias_sha256,
            launcher_policy.service_account_alias_sha256,
        ),
        (
            provider_bound_custody.custody_policy_sha256,
            legacy_custody_verification.custody_policy_sha256,
        ),
        (
            legacy_custody_verification.admission_sha256,
            legacy_admission.content_sha256,
        ),
        (
            legacy_custody_verification.candidate_sha256,
            candidate.content_sha256,
        ),
        (
            launch_capability.custody_verification_sha256,
            legacy_custody_verification.content_sha256,
        ),
        (launch_capability.candidate_sha256, candidate.content_sha256),
        (
            launch_capability.admission_sha256,
            legacy_admission.content_sha256,
        ),
    )
    if any(left != right for left, right in expected):
        _reject("PROVIDER_BOUND_LAUNCH_BINDING_MISMATCH")
    if (
        provider_bound_admission.symbol != "XAUUSD"
        or provider_bound_admission.max_lot != 0.01
        or provider_bound_admission.max_concurrent_positions != 1
        or provider_bound_admission.provider_accepted is not True
        or provider_bound_admission.provider_binding_complete is not True
        or provider_bound_admission.live_allowed is not False
        or provider_bound_admission.execution_authorized is not False
        or provider_bound_admission.process_launch_authorized is not False
        or provider_bound_admission.order_capability != "DISABLED"
        or provider_bound_custody.provider_bound_custody_verified is not True
        or provider_bound_custody.live_allowed is not False
        or provider_bound_custody.execution_authorized is not False
        or provider_bound_custody.process_launch_authorized is not False
        or provider_bound_custody.order_capability != "DISABLED"
    ):
        _reject("PROVIDER_BOUND_LAUNCH_SAFETY_DRIFT")


def _require_provider_bound_window(
    *,
    checked: datetime,
    legacy_admission: LiveCanaryPrebootstrapAdmission,
    provider_bound_admission: LiveCanaryProviderBoundPrebootstrapAdmission,
    provider_bound_custody: (
        VerifiedLiveCanaryProviderBoundAdmissionCustody
    ),
    legacy_custody_verification: VerifiedLiveCanaryAdmissionCustody,
    launch_capability: LiveCanaryOneUseLaunchCapability,
) -> datetime:
    limiting_expiry = min(
        launch_capability.expires_at_utc,
        provider_bound_admission.provider_acceptance_valid_until_utc,
        provider_bound_custody.valid_until_utc,
    )
    if (
        checked < legacy_admission.checked_at
        or checked < provider_bound_admission.checked_at
        or checked < provider_bound_custody.checked_at_utc
        or checked < legacy_custody_verification.checked_at_utc
        or checked < launch_capability.checked_at_utc
        or checked >= limiting_expiry
    ):
        _reject("PROVIDER_BOUND_RUNTIME_LAUNCH_WINDOW_INVALID")
    return limiting_expiry


def activate_live_canary_provider_bound_runtime_launch_session(
    *,
    candidate: LiveCanaryRuntimeCandidate,
    legacy_admission: LiveCanaryPrebootstrapAdmission,
    provider_bound_admission: LiveCanaryProviderBoundPrebootstrapAdmission,
    provider_bound_custody: (
        VerifiedLiveCanaryProviderBoundAdmissionCustody
    ),
    legacy_custody_verification: VerifiedLiveCanaryAdmissionCustody,
    launch_capability: LiveCanaryOneUseLaunchCapability,
    expected_candidate_sha256: str,
    expected_admission_sha256: str,
    expected_launch_capability_sha256: str,
    expected_checkpoint_sha256: str,
    expected_launch_nonce_sha256: str,
    expected_runtime_profile_sha256: str,
    expected_release_manifest_sha256: str,
    expected_live_stage_binding_sha256: str,
    launcher_policy: ExternalLauncherTrustPolicy,
    expected_launcher_policy_sha256: str,
    expected_deployment_host_alias_sha256: str,
    expected_service_account_alias_sha256: str,
    expected_task_definition_sha256: str,
    expected_provider_bound_admission_sha256: str,
    expected_provider_bound_custody_sha256: str,
    external_checkpoint_provider: Callable[[], bytes],
    external_nonce_seen_provider: Callable[[str], bool],
    clock_provider: Callable[[], datetime],
) -> LiveCanaryProviderBoundRuntimeLaunchSession:
    """Return v2 launch-only authority after exact provider checks."""

    _require_provider_bound_inputs(
        candidate=candidate,
        legacy_admission=legacy_admission,
        provider_bound_admission=provider_bound_admission,
        provider_bound_custody=provider_bound_custody,
        legacy_custody_verification=legacy_custody_verification,
        launch_capability=launch_capability,
        launcher_policy=launcher_policy,
        expected_provider_bound_admission_sha256=(
            expected_provider_bound_admission_sha256
        ),
        expected_provider_bound_custody_sha256=(
            expected_provider_bound_custody_sha256
        ),
    )
    _require_central_live_policy()
    started = _clock(clock_provider, phase="PROVIDER_BOUND_START")
    limiting_expiry = _require_provider_bound_window(
        checked=started,
        legacy_admission=legacy_admission,
        provider_bound_admission=provider_bound_admission,
        provider_bound_custody=provider_bound_custody,
        legacy_custody_verification=legacy_custody_verification,
        launch_capability=launch_capability,
    )

    legacy_session = activate_live_canary_runtime_launch_session(
        candidate=candidate,
        admission=legacy_admission,
        launch_capability=launch_capability,
        expected_candidate_sha256=expected_candidate_sha256,
        expected_admission_sha256=expected_admission_sha256,
        expected_launch_capability_sha256=(
            expected_launch_capability_sha256
        ),
        expected_checkpoint_sha256=expected_checkpoint_sha256,
        expected_launch_nonce_sha256=expected_launch_nonce_sha256,
        expected_runtime_profile_sha256=expected_runtime_profile_sha256,
        expected_release_manifest_sha256=(
            expected_release_manifest_sha256
        ),
        expected_live_stage_binding_sha256=(
            expected_live_stage_binding_sha256
        ),
        launcher_policy=launcher_policy,
        expected_launcher_policy_sha256=expected_launcher_policy_sha256,
        expected_deployment_host_alias_sha256=(
            expected_deployment_host_alias_sha256
        ),
        expected_service_account_alias_sha256=(
            expected_service_account_alias_sha256
        ),
        expected_task_definition_sha256=expected_task_definition_sha256,
        external_checkpoint_provider=external_checkpoint_provider,
        external_nonce_seen_provider=external_nonce_seen_provider,
        clock_provider=clock_provider,
    )
    if (
        type(legacy_session) is not LiveCanaryRuntimeLaunchSession
        or not is_live_canary_runtime_launch_session(legacy_session)
    ):
        _reject("LEGACY_RUNTIME_LAUNCH_SESSION_NOT_SEALED")

    completed = _clock(clock_provider, phase="PROVIDER_BOUND_COMPLETION")
    _require_provider_bound_inputs(
        candidate=candidate,
        legacy_admission=legacy_admission,
        provider_bound_admission=provider_bound_admission,
        provider_bound_custody=provider_bound_custody,
        legacy_custody_verification=legacy_custody_verification,
        launch_capability=launch_capability,
        launcher_policy=launcher_policy,
        expected_provider_bound_admission_sha256=(
            expected_provider_bound_admission_sha256
        ),
        expected_provider_bound_custody_sha256=(
            expected_provider_bound_custody_sha256
        ),
    )
    if completed < started or completed < legacy_session.activated_at_utc:
        _reject("PROVIDER_BOUND_RUNTIME_LAUNCH_CLOCK_REGRESSION")
    limiting_expiry = min(limiting_expiry, legacy_session.valid_until_utc)
    if completed >= limiting_expiry:
        _reject("PROVIDER_BOUND_RUNTIME_LAUNCH_WINDOW_INVALID")
    legacy_session.assert_current(now=completed)
    _require_central_live_policy()

    return LiveCanaryProviderBoundRuntimeLaunchSession(
        activated_at_utc=completed,
        valid_until_utc=limiting_expiry,
        sequence=legacy_session.sequence,
        candidate_sha256=legacy_session.candidate_sha256,
        admission_sha256=legacy_session.admission_sha256,
        launch_capability_sha256=legacy_session.launch_capability_sha256,
        checkpoint_sha256=legacy_session.checkpoint_sha256,
        launch_nonce_sha256=legacy_session.launch_nonce_sha256,
        launcher_attestation_sha256=(
            legacy_session.launcher_attestation_sha256
        ),
        launcher_trust_policy_sha256=(
            legacy_session.launcher_trust_policy_sha256
        ),
        runtime_profile_sha256=legacy_session.runtime_profile_sha256,
        release_manifest_sha256=legacy_session.release_manifest_sha256,
        live_stage_binding_sha256=legacy_session.live_stage_binding_sha256,
        deployment_host_alias_sha256=(
            legacy_session.deployment_host_alias_sha256
        ),
        service_account_alias_sha256=(
            legacy_session.service_account_alias_sha256
        ),
        task_definition_sha256=legacy_session.task_definition_sha256,
        legacy_launch_session_sha256=legacy_session.content_sha256,
        legacy_custody_verification_sha256=(
            legacy_custody_verification.content_sha256
        ),
        custody_policy_sha256=provider_bound_custody.custody_policy_sha256,
        provider_bound_admission_sha256=(
            provider_bound_admission.content_sha256
        ),
        provider_bound_custody_sha256=provider_bound_custody.content_sha256,
        provider_acceptance_sha256=(
            provider_bound_admission.provider_acceptance_sha256
        ),
        provider_acceptance_policy_sha256=(
            provider_bound_admission.provider_acceptance_policy_sha256
        ),
        provider_conformance_review_sha256=(
            provider_bound_admission.provider_conformance_review_sha256
        ),
        target_host_identity_sha256=(
            provider_bound_admission.target_host_identity_sha256
        ),
        installed_environment_sha256=(
            provider_bound_admission.installed_environment_sha256
        ),
        live_execution_release_identity_sha256=(
            provider_bound_admission.live_execution_release_identity_sha256
        ),
        live_execution_task_definition_sha256=(
            provider_bound_admission.live_execution_task_definition_sha256
        ),
        provider_acceptance_valid_until_utc=(
            provider_bound_admission.provider_acceptance_valid_until_utc
        ),
        provider_bound_custody_valid_until_utc=(
            provider_bound_custody.valid_until_utc
        ),
        _seal=_SESSION_SEAL,
    )


__all__ = [
    "LiveCanaryProviderBoundRuntimeLaunchSession",
    "LiveCanaryRuntimeLaunchSessionError",
    "ORDER_CAPABILITY",
    "PROVIDER_BOUND_RUNTIME_LAUNCH_SESSION_SCHEMA",
    "activate_live_canary_provider_bound_runtime_launch_session",
    "is_live_canary_provider_bound_runtime_launch_session",
]
