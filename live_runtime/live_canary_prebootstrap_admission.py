"""Deny-only prebootstrap admission for the first XAUUSD live canary.

This module composes already-verified immutable evidence.  It deliberately
contains no runtime materialization, credential, provider, process, network,
database, scheduler, broker, permit, or order effect.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field, fields as dataclass_fields
from datetime import datetime
from pathlib import PurePosixPath, PureWindowsPath
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
from .windows_execution_source_bound_candidate import (
    WindowsExecutionSourceBoundCandidateVerification,
    is_windows_execution_source_bound_candidate_verification,
)


RUNTIME_CANDIDATE_SCHEMA_VERSION = "live-canary-runtime-candidate-v1"
ADMISSION_SCHEMA_VERSION = "live-canary-prebootstrap-admission-v1"
ADMISSION_STATUS = "PREBOOTSTRAP_EVIDENCE_COMPLETE_CENTRAL_UNLOCK_REQUIRED"
ORDER_CAPABILITY = "DISABLED"
EXPECTED_DISTRIBUTION_VERSION = "5.0.5735"
EXPECTED_WHEEL_SHA256 = (
    "f6e8584e48f2c3f5de818f17ee65f0f5adfa1e4af29cd5f4bf3f72b91ff06e10"
)

_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
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


class LiveCanaryPrebootstrapAdmissionError(RuntimeError):
    """One prebootstrap invariant failed with a stable public reason code."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: object) -> None:
        normalized = re.sub(
            r"[^A-Z0-9_]+",
            "_",
            str(reason_code or "").strip().upper(),
        ).strip("_")
        self.reason_code = normalized or "LIVE_CANARY_PREBOOTSTRAP_INVALID"
        super().__init__(self.reason_code)


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


def _absolute_path(name: str, value: object) -> str:
    normalized = _text(name, value)
    if not (
        PurePosixPath(normalized).is_absolute()
        or PureWindowsPath(normalized).is_absolute()
    ):
        _reject(f"{name}_INVALID")
    return normalized


def _basename(value: str) -> str:
    windows_name = PureWindowsPath(value).name
    posix_name = PurePosixPath(value).name
    return windows_name if "\\" in value else posix_name


def _fixed_float(name: str, value: object, expected: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _reject(f"{name}_INVALID")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized != expected:
        _reject(f"{name}_INVALID")
    return normalized


def _bounded_int(
    name: str,
    value: object,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if (
        type(value) is not int
        or value < minimum
        or value > maximum
    ):
        _reject(f"{name}_INVALID")
    return value


def _symbol_pairs(
    name: str,
    value: object,
    *,
    require_xau_only: bool,
) -> tuple[tuple[str, str], ...]:
    if type(value) not in {tuple, list}:
        _reject(f"{name}_INVALID")
    pairs: list[tuple[str, str]] = []
    for item in value:
        if type(item) not in {tuple, list} or len(item) != 2:
            _reject(f"{name}_INVALID")
        canonical = _text(f"{name}_CANONICAL_SYMBOL", item[0]).upper()
        broker = _text(f"{name}_BROKER_SYMBOL", item[1])
        if canonical != item[0]:
            _reject(f"{name}_INVALID")
        pairs.append((canonical, broker))
    normalized = tuple(sorted(pairs))
    if (
        tuple(pairs) != normalized
        or len({item[0] for item in normalized}) != len(normalized)
        or len({item[1] for item in normalized}) != len(normalized)
    ):
        _reject(f"{name}_INVALID")
    if require_xau_only and (
        len(normalized) != 1 or normalized[0][0] != "XAUUSD"
    ):
        _reject(f"{name}_INVALID")
    return normalized


@dataclass(frozen=True, slots=True)
class LiveCanaryRuntimeCandidate(CanonicalContract):
    """Complete non-secret LIVE candidate that grants no runtime authority."""

    candidate_id: str
    broker_id: str
    broker_legal_name: str
    server: str
    account_alias_sha256: str
    account_currency: str
    journal_database: str
    supervisor_database: str
    dependency_lock_file: str
    symbol_map: tuple[tuple[str, str], ...]
    usd_account_currency_symbols: tuple[tuple[str, str], ...]
    journal_sha256: str
    commit_sha: str
    dependency_lock_sha256: str
    installed_environment_sha256: str
    mt5_site_packages_sha256: str
    mt5_site_packages_tree_sha256: str
    mt5_distribution_record_sha256: str
    mt5_module_file_sha256: str
    mt5_module_relative_path_sha256: str
    runtime_profile_sha256: str
    release_manifest_sha256: str
    session_calendar_sha256: str
    broker_spec_sha256: str
    live_stage_binding_sha256: str
    activation_policy_sha256: str
    model_artifact_sha256: str
    champion_archive_sha256: str
    champion_package_identity_sha256: str
    champion_training_snapshot_sha256: str
    champion_config_sha256: str
    champion_git_tree: str
    champion_runtime_binding_sha256: str
    demo_source_bound_archive_sha256: str
    demo_source_bound_binding_identity_sha256: str
    demo_source_archive_sha256: str
    demo_source_identity_sha256: str
    demo_production_config_sha256: str
    demo_bootstrap_binding_sha256: str
    demo_stage_binding_sha256: str
    demo_configured_release_identity_sha256: str
    demo_configured_archive_sha256: str
    demo_execution_factory_template_sha256: str
    demo_execution_candidate_id: str
    demo_execution_candidate_content_sha256: str
    demo_provider_pack_identity_sha256: str
    demo_provider_configuration_sha256: str
    demo_task_definition_sha256: str
    demo_base_suite_identity_sha256: str
    demo_execution_base_archive_sha256: str
    demo_execution_base_release_identity_sha256: str
    demo_git_commit: str
    demo_git_tree: str
    manual_demo_custodian_trust_sha256: str
    news_guard_provider_id: str
    news_guard_key_id: str
    news_guard_key_fingerprint_sha256: str
    news_guard_ruleset_sha256: str
    news_guard_blackout_window_sha256: str
    supervisor_key_id: str
    supervisor_key_fingerprint_sha256: str
    supervisor_checkpoint_key_id: str
    supervisor_checkpoint_key_fingerprint_sha256: str
    credential_session_key_id: str
    credential_session_key_fingerprint_sha256: str
    journal_provisioning_key_id: str
    journal_provisioning_key_fingerprint_sha256: str
    worm_audit_key_id: str
    worm_audit_key_fingerprint_sha256: str
    risk_ledger_id: str
    risk_ledger_key_id: str
    risk_ledger_key_fingerprint_sha256: str
    journal_checkpoint_key_id: str
    journal_checkpoint_key_fingerprint_sha256: str
    permit_secret_fingerprint_sha256: str
    magic_number: int
    deviation_points: int
    max_tick_age_seconds: int
    intent_ttl_seconds: float
    environment: str = field(default="LIVE", init=False)
    mode: str = field(default="LIVE", init=False)
    max_lot: float = field(default=LIVE_CANARY_MAX_LOT, init=False)
    max_concurrent_positions: int = field(
        default=LIVE_CANARY_MAX_CONCURRENT_POSITIONS,
        init=False,
    )
    live_allowed: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    mt5_distribution_version: str = field(
        default=EXPECTED_DISTRIBUTION_VERSION,
        init=False,
    )
    mt5_wheel_sha256: str = field(default=EXPECTED_WHEEL_SHA256, init=False)
    schema_version: str = field(
        default=RUNTIME_CANDIDATE_SCHEMA_VERSION,
        init=False,
    )

    def __post_init__(self) -> None:
        for name in (
            "candidate_id",
            "broker_id",
            "demo_execution_candidate_id",
            "news_guard_provider_id",
            "news_guard_key_id",
            "supervisor_key_id",
            "supervisor_checkpoint_key_id",
            "credential_session_key_id",
            "journal_provisioning_key_id",
            "worm_audit_key_id",
            "risk_ledger_id",
            "risk_ledger_key_id",
            "journal_checkpoint_key_id",
        ):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        for name in ("broker_legal_name", "server"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        currency = _text("account_currency", self.account_currency).upper()
        if currency != self.account_currency or _CURRENCY.fullmatch(currency) is None:
            _reject("ACCOUNT_CURRENCY_INVALID")
        object.__setattr__(self, "account_currency", currency)

        for name in (
            "journal_database",
            "supervisor_database",
            "dependency_lock_file",
        ):
            object.__setattr__(
                self,
                name,
                _absolute_path(name, getattr(self, name)),
            )
        if self.journal_database.casefold() == self.supervisor_database.casefold():
            _reject("LIVE_RUNTIME_DATABASE_PATH_COLLISION")
        if _basename(self.dependency_lock_file) != "pylock.windows-cp312.toml":
            _reject("DEPENDENCY_LOCK_PATH_INVALID")

        object.__setattr__(
            self,
            "symbol_map",
            _symbol_pairs("symbol_map", self.symbol_map, require_xau_only=True),
        )
        object.__setattr__(
            self,
            "usd_account_currency_symbols",
            _symbol_pairs(
                "usd_account_currency_symbols",
                self.usd_account_currency_symbols,
                require_xau_only=False,
            ),
        )

        hash_fields = (
            "account_alias_sha256",
            "journal_sha256",
            "dependency_lock_sha256",
            "installed_environment_sha256",
            "mt5_site_packages_sha256",
            "mt5_site_packages_tree_sha256",
            "mt5_distribution_record_sha256",
            "mt5_module_file_sha256",
            "mt5_module_relative_path_sha256",
            "runtime_profile_sha256",
            "release_manifest_sha256",
            "session_calendar_sha256",
            "broker_spec_sha256",
            "live_stage_binding_sha256",
            "activation_policy_sha256",
            "model_artifact_sha256",
            "champion_archive_sha256",
            "champion_package_identity_sha256",
            "champion_training_snapshot_sha256",
            "champion_config_sha256",
            "champion_runtime_binding_sha256",
            "demo_source_bound_archive_sha256",
            "demo_source_bound_binding_identity_sha256",
            "demo_source_archive_sha256",
            "demo_source_identity_sha256",
            "demo_production_config_sha256",
            "demo_bootstrap_binding_sha256",
            "demo_stage_binding_sha256",
            "demo_configured_release_identity_sha256",
            "demo_configured_archive_sha256",
            "demo_execution_factory_template_sha256",
            "demo_execution_candidate_content_sha256",
            "demo_provider_pack_identity_sha256",
            "demo_provider_configuration_sha256",
            "demo_task_definition_sha256",
            "demo_base_suite_identity_sha256",
            "demo_execution_base_archive_sha256",
            "demo_execution_base_release_identity_sha256",
            "manual_demo_custodian_trust_sha256",
            "news_guard_key_fingerprint_sha256",
            "news_guard_ruleset_sha256",
            "news_guard_blackout_window_sha256",
            "supervisor_key_fingerprint_sha256",
            "supervisor_checkpoint_key_fingerprint_sha256",
            "credential_session_key_fingerprint_sha256",
            "journal_provisioning_key_fingerprint_sha256",
            "worm_audit_key_fingerprint_sha256",
            "risk_ledger_key_fingerprint_sha256",
            "journal_checkpoint_key_fingerprint_sha256",
            "permit_secret_fingerprint_sha256",
        )
        for name in hash_fields:
            object.__setattr__(self, name, _sha256(name, getattr(self, name)))
        for name in ("commit_sha", "champion_git_tree", "demo_git_commit", "demo_git_tree"):
            object.__setattr__(self, name, _git_sha(name, getattr(self, name)))

        key_ids = self.runtime_key_ids
        fingerprints = self.runtime_key_fingerprints
        if len(key_ids) != 8 or len(fingerprints) != 9:
            _reject("LIVE_RUNTIME_TRUST_DOMAIN_REUSE")
        _bounded_int("magic_number", self.magic_number, minimum=1, maximum=2_147_483_647)
        _bounded_int("deviation_points", self.deviation_points, minimum=0, maximum=10_000)
        _bounded_int("max_tick_age_seconds", self.max_tick_age_seconds, minimum=1, maximum=60)
        if isinstance(self.intent_ttl_seconds, bool) or not isinstance(
            self.intent_ttl_seconds,
            (int, float),
        ):
            _reject("INTENT_TTL_SECONDS_INVALID")
        ttl = float(self.intent_ttl_seconds)
        if not math.isfinite(ttl) or not 0 < ttl <= 1:
            _reject("INTENT_TTL_SECONDS_INVALID")
        object.__setattr__(self, "intent_ttl_seconds", ttl)

        if (
            self.environment != "LIVE"
            or self.mode != "LIVE"
            or _fixed_float("max_lot", self.max_lot, LIVE_CANARY_MAX_LOT)
            != LIVE_CANARY_MAX_LOT
            or self.max_concurrent_positions
            != LIVE_CANARY_MAX_CONCURRENT_POSITIONS
            or any(
                (
                    self.live_allowed,
                    self.safe_to_demo_auto_order,
                    self.execution_authorized,
                    self.activation_authorized,
                    self.order_capability != ORDER_CAPABILITY,
                )
            )
            or self.mt5_distribution_version != EXPECTED_DISTRIBUTION_VERSION
            or self.mt5_wheel_sha256 != EXPECTED_WHEEL_SHA256
            or self.schema_version != RUNTIME_CANDIDATE_SCHEMA_VERSION
        ):
            _reject("LIVE_RUNTIME_CANDIDATE_SAFETY_DRIFT")

    @property
    def runtime_key_ids(self) -> frozenset[str]:
        return frozenset(
            (
                self.news_guard_key_id,
                self.supervisor_key_id,
                self.supervisor_checkpoint_key_id,
                self.credential_session_key_id,
                self.journal_provisioning_key_id,
                self.worm_audit_key_id,
                self.risk_ledger_key_id,
                self.journal_checkpoint_key_id,
            )
        )

    @property
    def runtime_key_fingerprints(self) -> frozenset[str]:
        return frozenset(
            (
                self.news_guard_key_fingerprint_sha256,
                self.supervisor_key_fingerprint_sha256,
                self.supervisor_checkpoint_key_fingerprint_sha256,
                self.credential_session_key_fingerprint_sha256,
                self.journal_provisioning_key_fingerprint_sha256,
                self.worm_audit_key_fingerprint_sha256,
                self.risk_ledger_key_fingerprint_sha256,
                self.journal_checkpoint_key_fingerprint_sha256,
                self.permit_secret_fingerprint_sha256,
            )
        )


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
