"""Central-unlock composition for one live-canary runtime launch session.

The boundary consumes an already sealed one-use launcher reservation and
rechecks its external checkpoint and nonce state.  It can authorize only a
short-lived process/bootstrap launch.  It cannot authorize execution or
broker mutation, and it performs no external effect beyond the supplied
read-only data callbacks.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field, fields as dataclass_fields
from datetime import datetime
import hashlib
import re
import threading
from typing import Callable

import execution_policy

from .asymmetric_release_trust import (
    EXECUTION_RELEASE_PROFILE,
    ExternalLauncherTrustPolicy,
)
from .contracts import CanonicalContract, canonicalize
from .live_canary_activation import (
    LIVE_CANARY_MAX_CONCURRENT_POSITIONS,
    LIVE_CANARY_MAX_LOT,
)
from .live_canary_portable_launch_custody import (
    LiveCanaryOneUseLaunchCapability,
    LiveCanaryPortableLaunchCustodyError,
    decode_live_canary_launch_checkpoint,
    is_live_canary_one_use_launch_capability,
)
from .live_canary_prebootstrap_admission import (
    LiveCanaryPrebootstrapAdmission,
    LiveCanaryRuntimeCandidate,
    is_live_canary_prebootstrap_admission,
)


RUNTIME_LAUNCH_SESSION_SCHEMA = "live-canary-runtime-launch-session-v1"
ORDER_CAPABILITY = "GATED_PRESENT"
MAXIMUM_CHECKPOINT_BYTES = 262_144
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SESSION_SEAL = object()
_ACTIVATION_REPLAY_LOCK = threading.Lock()
_ACTIVATED_CAPABILITIES: dict[str, datetime] = {}


class LiveCanaryRuntimeLaunchSessionError(RuntimeError):
    """One launch-session invariant failed with a stable public reason code."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: object) -> None:
        normalized = re.sub(
            r"[^A-Z0-9_]+",
            "_",
            str(reason_code or "").strip().upper(),
        ).strip("_")
        self.reason_code = normalized or "LIVE_CANARY_RUNTIME_LAUNCH_INVALID"
        super().__init__(self.reason_code)


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


def _integer(name: str, value: object, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _reject(f"{name}_INVALID")
    return value


def _clock(provider: Callable[[], datetime], *, phase: str) -> datetime:
    if not callable(provider):
        _reject("CLOCK_PROVIDER_INVALID")
    try:
        value = provider()
    except Exception as exc:
        raise LiveCanaryRuntimeLaunchSessionError(
            f"TRUSTED_CLOCK_{phase}_FAILED"
        ) from exc
    return _utc(f"TRUSTED_CLOCK_{phase}", value)


def _checkpoint_payload(
    provider: Callable[[], bytes],
    *,
    phase: str,
) -> bytes:
    if not callable(provider):
        _reject("EXTERNAL_CHECKPOINT_PROVIDER_INVALID")
    try:
        payload = provider()
    except Exception as exc:
        raise LiveCanaryRuntimeLaunchSessionError(
            f"EXTERNAL_CHECKPOINT_{phase}_FAILED"
        ) from exc
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > MAXIMUM_CHECKPOINT_BYTES
    ):
        _reject(f"EXTERNAL_CHECKPOINT_{phase}_INVALID")
    return payload


def _nonce_seen(
    provider: Callable[[str], bool],
    nonce_sha256: str,
    *,
    phase: str,
) -> bool:
    if not callable(provider):
        _reject("EXTERNAL_NONCE_PROVIDER_INVALID")
    try:
        result = provider(nonce_sha256)
    except Exception as exc:
        raise LiveCanaryRuntimeLaunchSessionError(
            f"EXTERNAL_NONCE_{phase}_FAILED"
        ) from exc
    if type(result) is not bool:
        _reject(f"EXTERNAL_NONCE_{phase}_INVALID")
    if result is not True:
        _reject("LIVE_CANARY_LAUNCH_NONCE_NOT_CONSUMED")
    return result


def _require_central_live_policy() -> None:
    if execution_policy.LIVE_ALLOWED is not True:
        _reject("CENTRAL_LIVE_LOCK_NOT_ENABLED")
    if execution_policy.SAFE_TO_DEMO_AUTO_ORDER is not False:
        _reject("CENTRAL_EXECUTION_POLICY_MUTUAL_EXCLUSION_FAILED")
    allowed, reasons = execution_policy.execution_mode_policy_decision("LIVE")
    if allowed is not True or reasons != ():
        _reject("CENTRAL_LIVE_POLICY_DECISION_INVALID")
    if execution_policy.LIVE_CANARY_EXECUTION_APPROVED_SYMBOLS != frozenset(
        {"XAUUSD"}
    ):
        _reject("CENTRAL_LIVE_SYMBOL_SCOPE_DRIFT")
    if (
        type(execution_policy.EXECUTION_MIN_LOT) is not float
        or type(execution_policy.EXECUTION_MAX_LOT) is not float
        or execution_policy.EXECUTION_MIN_LOT != LIVE_CANARY_MAX_LOT
        or execution_policy.EXECUTION_MAX_LOT != LIVE_CANARY_MAX_LOT
    ):
        _reject("CENTRAL_LIVE_LOT_SCOPE_DRIFT")
    symbol_allowed, _symbol_reason = execution_policy.validate_execution_symbol(
        "XAUUSD",
        mode="LIVE",
    )
    lot_allowed, _lot_reason = execution_policy.validate_execution_lot(
        LIVE_CANARY_MAX_LOT
    )
    if symbol_allowed is not True or lot_allowed is not True:
        _reject("CENTRAL_LIVE_EXECUTION_SCOPE_INVALID")


def _consume_activation_once(
    capability_sha256: str,
    *,
    now: datetime,
    expires_at: datetime,
) -> None:
    normalized = _sha256("LAUNCH_CAPABILITY_SHA256", capability_sha256)
    checked = _utc("ACTIVATION_CONSUMED_AT_UTC", now)
    expiry = _utc("ACTIVATION_EXPIRES_AT_UTC", expires_at)
    with _ACTIVATION_REPLAY_LOCK:
        expired = tuple(
            key
            for key, retained_until in _ACTIVATED_CAPABILITIES.items()
            if retained_until <= checked
        )
        for key in expired:
            del _ACTIVATED_CAPABILITIES[key]
        if normalized in _ACTIVATED_CAPABILITIES:
            _reject("LIVE_CANARY_LAUNCH_CAPABILITY_REPLAYED")
        _ACTIVATED_CAPABILITIES[normalized] = expiry


@dataclass(frozen=True, slots=True)
class LiveCanaryRuntimeLaunchSession(CanonicalContract):
    """Sealed authority for process/bootstrap launch, never for an order."""

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
    external_checkpoint_observations: int = field(default=2, init=False)
    external_nonce_observations: int = field(default=2, init=False)
    symbol: str = field(default="XAUUSD", init=False)
    max_lot: float = field(default=LIVE_CANARY_MAX_LOT, init=False)
    max_concurrent_positions: int = field(
        default=LIVE_CANARY_MAX_CONCURRENT_POSITIONS,
        init=False,
    )
    central_live_policy_enabled: bool = field(default=True, init=False)
    launch_reservation_consumed_once: bool = field(default=True, init=False)
    launch_capability_activation_consumed_once: bool = field(
        default=True,
        init=False,
    )
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
        default=RUNTIME_LAUNCH_SESSION_SCHEMA,
        init=False,
    )
    _session_seal: object = field(init=False, repr=False, compare=False)
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _SESSION_SEAL:
            raise TypeError("runtime launch session requires its verifier")
        activated = _utc("ACTIVATED_AT_UTC", self.activated_at_utc)
        expires = _utc("VALID_UNTIL_UTC", self.valid_until_utc)
        if activated >= expires:
            _reject("RUNTIME_LAUNCH_SESSION_WINDOW_INVALID")
        _integer("SEQUENCE", self.sequence, minimum=1, maximum=2**63 - 1)
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
        ):
            _sha256(name, getattr(self, name))
        if (
            self.external_checkpoint_observations != 2
            or self.external_nonce_observations != 2
            or self.symbol != "XAUUSD"
            or type(self.max_lot) is not float
            or self.max_lot != LIVE_CANARY_MAX_LOT
            or self.max_concurrent_positions
            != LIVE_CANARY_MAX_CONCURRENT_POSITIONS
            or self.central_live_policy_enabled is not True
            or self.launch_reservation_consumed_once is not True
            or self.launch_capability_activation_consumed_once is not True
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
            or self.schema_version != RUNTIME_LAUNCH_SESSION_SCHEMA
        ):
            _reject("RUNTIME_LAUNCH_SESSION_SAFETY_DRIFT")
        object.__setattr__(self, "_session_seal", _SESSION_SEAL)

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            item.name: canonicalize(getattr(self, item.name))
            for item in dataclass_fields(self)
            if not item.name.startswith("_")
        }

    def assert_current(self, *, now: datetime) -> None:
        """Fail if the in-memory launch authority is no longer current."""

        checked = _utc("NOW", now)
        _require_central_live_policy()
        if not self.activated_at_utc <= checked < self.valid_until_utc:
            _reject("RUNTIME_LAUNCH_SESSION_NOT_CURRENT")


def is_live_canary_runtime_launch_session(value: object) -> bool:
    """Return true only for a session sealed by this verifier module."""

    return (
        type(value) is LiveCanaryRuntimeLaunchSession
        and getattr(value, "_session_seal", None) is _SESSION_SEAL
    )


def _require_exact_inputs(
    *,
    candidate: LiveCanaryRuntimeCandidate,
    admission: LiveCanaryPrebootstrapAdmission,
    launch_capability: LiveCanaryOneUseLaunchCapability,
    launcher_policy: ExternalLauncherTrustPolicy,
    pins: dict[str, str],
) -> None:
    if type(candidate) is not LiveCanaryRuntimeCandidate:
        _reject("LIVE_CANARY_RUNTIME_CANDIDATE_NOT_EXACT")
    if not is_live_canary_prebootstrap_admission(admission):
        _reject("LIVE_CANARY_PREBOOTSTRAP_ADMISSION_NOT_SEALED")
    if not is_live_canary_one_use_launch_capability(launch_capability):
        _reject("LIVE_CANARY_LAUNCH_CAPABILITY_NOT_SEALED")
    if type(launcher_policy) is not ExternalLauncherTrustPolicy:
        _reject("EXTERNAL_LAUNCHER_TRUST_POLICY_NOT_EXACT")
    normalized = {name: _sha256(name, value) for name, value in pins.items()}
    expected = (
        (normalized["EXPECTED_CANDIDATE_SHA256"], candidate.content_sha256),
        (normalized["EXPECTED_ADMISSION_SHA256"], admission.content_sha256),
        (
            normalized["EXPECTED_LAUNCH_CAPABILITY_SHA256"],
            launch_capability.content_sha256,
        ),
        (
            normalized["EXPECTED_CHECKPOINT_SHA256"],
            launch_capability.checkpoint_sha256,
        ),
        (
            normalized["EXPECTED_LAUNCH_NONCE_SHA256"],
            launch_capability.launch_nonce_sha256,
        ),
        (
            normalized["EXPECTED_RUNTIME_PROFILE_SHA256"],
            candidate.runtime_profile_sha256,
        ),
        (
            normalized["EXPECTED_RELEASE_MANIFEST_SHA256"],
            candidate.release_manifest_sha256,
        ),
        (
            normalized["EXPECTED_LIVE_STAGE_BINDING_SHA256"],
            candidate.live_stage_binding_sha256,
        ),
        (
            normalized["EXPECTED_LAUNCHER_POLICY_SHA256"],
            launcher_policy.content_sha256,
        ),
        (
            normalized["EXPECTED_DEPLOYMENT_HOST_ALIAS_SHA256"],
            launcher_policy.deployment_host_alias_sha256,
        ),
        (
            normalized["EXPECTED_SERVICE_ACCOUNT_ALIAS_SHA256"],
            launcher_policy.service_account_alias_sha256,
        ),
        (
            normalized["EXPECTED_TASK_DEFINITION_SHA256"],
            launcher_policy.task_definition_sha256,
        ),
        (admission.candidate_sha256, candidate.content_sha256),
        (launch_capability.candidate_sha256, candidate.content_sha256),
        (launch_capability.admission_sha256, admission.content_sha256),
    )
    if any(left != right for left, right in expected):
        _reject("LIVE_CANARY_RUNTIME_LAUNCH_BINDING_MISMATCH")
    if (
        candidate.environment != "LIVE"
        or candidate.mode != "LIVE"
        or candidate.symbol_map[0][0] != "XAUUSD"
        or len(candidate.symbol_map) != 1
        or type(candidate.max_lot) is not float
        or candidate.max_lot != LIVE_CANARY_MAX_LOT
        or candidate.max_concurrent_positions
        != LIVE_CANARY_MAX_CONCURRENT_POSITIONS
        or launcher_policy.release_profile != EXECUTION_RELEASE_PROFILE
        or candidate.live_allowed is not False
        or candidate.execution_authorized is not False
        or candidate.order_capability != "DISABLED"
        or admission.bootstrap_authorized is not False
        or admission.execution_authorized is not False
        or admission.live_allowed is not False
        or admission.order_capability != "DISABLED"
        or launch_capability.launch_reservation_consumed_once is not True
        or launch_capability.launch_prerequisite_verified is not True
        or launch_capability.central_unlock_required is not True
        or launch_capability.process_launch_authorized is not False
        or launch_capability.bootstrap_authorized is not False
        or launch_capability.execution_authorized is not False
        or launch_capability.live_allowed is not False
        or launch_capability.order_capability != "DISABLED"
    ):
        _reject("LIVE_CANARY_RUNTIME_LAUNCH_SAFETY_DRIFT")
    if admission.checked_at > launch_capability.checked_at_utc:
        _reject("LIVE_CANARY_RUNTIME_LAUNCH_TIME_LINEAGE_INVALID")


def _verify_current_checkpoint(
    payload: bytes,
    *,
    candidate: LiveCanaryRuntimeCandidate,
    admission: LiveCanaryPrebootstrapAdmission,
    launch_capability: LiveCanaryOneUseLaunchCapability,
    launcher_policy: ExternalLauncherTrustPolicy,
    expected_checkpoint_sha256: str,
    expected_deployment_host_alias_sha256: str,
    expected_service_account_alias_sha256: str,
    expected_task_definition_sha256: str,
) -> None:
    try:
        checkpoint = decode_live_canary_launch_checkpoint(payload)
    except (LiveCanaryPortableLaunchCustodyError, TypeError, ValueError) as exc:
        raise LiveCanaryRuntimeLaunchSessionError(
            "EXTERNAL_CHECKPOINT_DOCUMENT_INVALID"
        ) from exc
    proposal = checkpoint.proposal
    if (
        hashlib.sha256(payload).hexdigest() != checkpoint.content_sha256
        or checkpoint.content_sha256 != expected_checkpoint_sha256
        or checkpoint.content_sha256 != launch_capability.checkpoint_sha256
        or checkpoint.proposal_sha256 != launch_capability.proposal_sha256
        or proposal.content_sha256 != launch_capability.proposal_sha256
        or proposal.sequence != launch_capability.sequence
        or proposal.candidate_sha256 != candidate.content_sha256
        or proposal.admission_sha256 != admission.content_sha256
        or proposal.custody_verification_sha256
        != launch_capability.custody_verification_sha256
        or proposal.launcher_attestation_sha256
        != launch_capability.launcher_attestation_sha256
        or proposal.launcher_trust_policy_sha256
        != launcher_policy.content_sha256
        or proposal.launcher_nonce_sha256
        != launch_capability.launch_nonce_sha256
        or proposal.release_identity_sha256
        != candidate.release_manifest_sha256
        or proposal.deployment_host_alias_sha256
        != expected_deployment_host_alias_sha256
        or proposal.service_account_alias_sha256
        != expected_service_account_alias_sha256
        or proposal.task_definition_sha256 != expected_task_definition_sha256
        or proposal.expires_at_utc != launch_capability.expires_at_utc
        or proposal.requested_at_utc > launch_capability.checked_at_utc
        or checkpoint.committed_at_utc > launch_capability.checked_at_utc
    ):
        _reject("EXTERNAL_CHECKPOINT_LAUNCH_BINDING_MISMATCH")


def activate_live_canary_runtime_launch_session(
    *,
    candidate: LiveCanaryRuntimeCandidate,
    admission: LiveCanaryPrebootstrapAdmission,
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
    external_checkpoint_provider: Callable[[], bytes],
    external_nonce_seen_provider: Callable[[str], bool],
    clock_provider: Callable[[], datetime],
) -> LiveCanaryRuntimeLaunchSession:
    """Activate one launch-only session after the reviewed central unlock."""

    pins = {
        "EXPECTED_CANDIDATE_SHA256": expected_candidate_sha256,
        "EXPECTED_ADMISSION_SHA256": expected_admission_sha256,
        "EXPECTED_LAUNCH_CAPABILITY_SHA256": (
            expected_launch_capability_sha256
        ),
        "EXPECTED_CHECKPOINT_SHA256": expected_checkpoint_sha256,
        "EXPECTED_LAUNCH_NONCE_SHA256": expected_launch_nonce_sha256,
        "EXPECTED_RUNTIME_PROFILE_SHA256": expected_runtime_profile_sha256,
        "EXPECTED_RELEASE_MANIFEST_SHA256": expected_release_manifest_sha256,
        "EXPECTED_LIVE_STAGE_BINDING_SHA256": (
            expected_live_stage_binding_sha256
        ),
        "EXPECTED_LAUNCHER_POLICY_SHA256": expected_launcher_policy_sha256,
        "EXPECTED_DEPLOYMENT_HOST_ALIAS_SHA256": (
            expected_deployment_host_alias_sha256
        ),
        "EXPECTED_SERVICE_ACCOUNT_ALIAS_SHA256": (
            expected_service_account_alias_sha256
        ),
        "EXPECTED_TASK_DEFINITION_SHA256": expected_task_definition_sha256,
    }
    _require_exact_inputs(
        candidate=candidate,
        admission=admission,
        launch_capability=launch_capability,
        launcher_policy=launcher_policy,
        pins=pins,
    )
    _require_central_live_policy()
    started = _clock(clock_provider, phase="START")
    if (
        started < admission.checked_at
        or started < launch_capability.checked_at_utc
        or started >= launch_capability.expires_at_utc
    ):
        _reject("LIVE_CANARY_RUNTIME_LAUNCH_WINDOW_INVALID")

    first_payload = _checkpoint_payload(
        external_checkpoint_provider,
        phase="INITIAL_READ",
    )
    _verify_current_checkpoint(
        first_payload,
        candidate=candidate,
        admission=admission,
        launch_capability=launch_capability,
        launcher_policy=launcher_policy,
        expected_checkpoint_sha256=pins["EXPECTED_CHECKPOINT_SHA256"],
        expected_deployment_host_alias_sha256=pins[
            "EXPECTED_DEPLOYMENT_HOST_ALIAS_SHA256"
        ],
        expected_service_account_alias_sha256=pins[
            "EXPECTED_SERVICE_ACCOUNT_ALIAS_SHA256"
        ],
        expected_task_definition_sha256=pins[
            "EXPECTED_TASK_DEFINITION_SHA256"
        ],
    )
    _nonce_seen(
        external_nonce_seen_provider,
        launch_capability.launch_nonce_sha256,
        phase="INITIAL_READ",
    )
    second_payload = _checkpoint_payload(
        external_checkpoint_provider,
        phase="FINAL_READ",
    )
    if second_payload != first_payload:
        _reject("EXTERNAL_CHECKPOINT_CHANGED_DURING_ACTIVATION")
    _verify_current_checkpoint(
        second_payload,
        candidate=candidate,
        admission=admission,
        launch_capability=launch_capability,
        launcher_policy=launcher_policy,
        expected_checkpoint_sha256=pins["EXPECTED_CHECKPOINT_SHA256"],
        expected_deployment_host_alias_sha256=pins[
            "EXPECTED_DEPLOYMENT_HOST_ALIAS_SHA256"
        ],
        expected_service_account_alias_sha256=pins[
            "EXPECTED_SERVICE_ACCOUNT_ALIAS_SHA256"
        ],
        expected_task_definition_sha256=pins[
            "EXPECTED_TASK_DEFINITION_SHA256"
        ],
    )
    _nonce_seen(
        external_nonce_seen_provider,
        launch_capability.launch_nonce_sha256,
        phase="FINAL_READ",
    )
    completed = _clock(clock_provider, phase="COMPLETION")
    if completed < started or completed >= launch_capability.expires_at_utc:
        _reject("LIVE_CANARY_RUNTIME_LAUNCH_CLOCK_WINDOW_INVALID")
    _require_central_live_policy()
    _consume_activation_once(
        launch_capability.content_sha256,
        now=completed,
        expires_at=launch_capability.expires_at_utc,
    )

    return LiveCanaryRuntimeLaunchSession(
        activated_at_utc=completed,
        valid_until_utc=launch_capability.expires_at_utc,
        sequence=launch_capability.sequence,
        candidate_sha256=candidate.content_sha256,
        admission_sha256=admission.content_sha256,
        launch_capability_sha256=launch_capability.content_sha256,
        checkpoint_sha256=launch_capability.checkpoint_sha256,
        launch_nonce_sha256=launch_capability.launch_nonce_sha256,
        launcher_attestation_sha256=(
            launch_capability.launcher_attestation_sha256
        ),
        launcher_trust_policy_sha256=launcher_policy.content_sha256,
        runtime_profile_sha256=candidate.runtime_profile_sha256,
        release_manifest_sha256=candidate.release_manifest_sha256,
        live_stage_binding_sha256=candidate.live_stage_binding_sha256,
        deployment_host_alias_sha256=pins[
            "EXPECTED_DEPLOYMENT_HOST_ALIAS_SHA256"
        ],
        service_account_alias_sha256=pins[
            "EXPECTED_SERVICE_ACCOUNT_ALIAS_SHA256"
        ],
        task_definition_sha256=pins["EXPECTED_TASK_DEFINITION_SHA256"],
        _seal=_SESSION_SEAL,
    )


__all__ = [
    "LiveCanaryRuntimeLaunchSession",
    "LiveCanaryRuntimeLaunchSessionError",
    "ORDER_CAPABILITY",
    "RUNTIME_LAUNCH_SESSION_SCHEMA",
    "activate_live_canary_runtime_launch_session",
    "is_live_canary_runtime_launch_session",
]
