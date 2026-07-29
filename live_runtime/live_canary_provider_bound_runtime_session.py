"""Minimal provider-bound LIVE launch-session contract for Execution.

This module intentionally contains only the exact sealed v2 session consumed
by the Windows Execution runtime.  Admission assembly, provider-conformance
review, WORM/CAS verification, and one-use activation remain in operator-side
modules and are not imported here.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field, fields
from datetime import datetime
import re

import execution_policy

from .contracts import CanonicalContract, canonicalize
from .live_canary_runtime_authority import (
    LiveCanaryRuntimeLaunchSessionError,
    _REGISTRATION_SEAL,
    _SESSION_SEAL,
    _register_live_canary_provider_bound_runtime_launch_session_type,
    is_live_canary_provider_bound_runtime_launch_session,
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


def _require_central_live_policy() -> None:
    if execution_policy.LIVE_ALLOWED is not True:
        _reject("CENTRAL_LIVE_LOCK_NOT_ENABLED")
    if execution_policy.SAFE_TO_DEMO_AUTO_ORDER is not False:
        _reject("CENTRAL_EXECUTION_POLICY_MUTUAL_EXCLUSION_FAILED")
    allowed, reasons = execution_policy.execution_mode_policy_decision("LIVE")
    if allowed is not True or reasons != ():
        _reject("CENTRAL_LIVE_POLICY_DECISION_INVALID")


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


__all__ = [
    "LiveCanaryProviderBoundRuntimeLaunchSession",
    "LiveCanaryRuntimeLaunchSessionError",
    "ORDER_CAPABILITY",
    "PROVIDER_BOUND_RUNTIME_LAUNCH_SESSION_SCHEMA",
    "is_live_canary_provider_bound_runtime_launch_session",
]
