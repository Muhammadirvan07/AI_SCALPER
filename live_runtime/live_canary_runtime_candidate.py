"""Immutable deny-only LIVE canary candidate consumer.

The Windows Execution release owns this small contract so an independently
pinned candidate document can be reconstructed without importing operator-side
activation, admission, conformance, or custody code.  Candidate loading grants
no launch session, permit, credential access, provider access, or order
authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields as dataclass_fields
import json
import math
from pathlib import PurePosixPath, PureWindowsPath
import re
from typing import Any, cast

from .contracts import CanonicalContract
from .live_canary_runtime_authority import (
    _CANDIDATE_SEAL,
    _REGISTRATION_SEAL,
    _register_live_canary_runtime_candidate_type,
    is_live_canary_runtime_candidate,
)


RUNTIME_CANDIDATE_SCHEMA_VERSION = "live-canary-runtime-candidate-v1"
RUNTIME_CANDIDATE_DOCUMENT_SCHEMA_VERSION = (
    "windows-live-canary-runtime-candidate-document-v1"
)
MAXIMUM_LIVE_CANARY_RUNTIME_CANDIDATE_DOCUMENT_BYTES = 1024 * 1024
LIVE_CANARY_MAX_LOT = 0.01
LIVE_CANARY_MAX_CONCURRENT_POSITIONS = 1
ORDER_CAPABILITY = "DISABLED"
EXPECTED_DISTRIBUTION_VERSION = "5.0.5735"
EXPECTED_WHEEL_SHA256 = (
    "f6e8584e48f2c3f5de818f17ee65f0f5adfa1e4af29cd5f4bf3f72b91ff06e10"
)

_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_DOCUMENT_FIELDS = frozenset(
    {"schema_version", "candidate", "candidate_sha256"}
)


class LiveCanaryPrebootstrapAdmissionError(RuntimeError):
    """One candidate/admission invariant failed with a public reason code."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: object) -> None:
        normalized = re.sub(
            r"[^A-Z0-9_]+",
            "_",
            str(reason_code or "").strip().upper(),
        ).strip("_")
        self.reason_code = normalized or "LIVE_CANARY_PREBOOTSTRAP_INVALID"
        super().__init__(self.reason_code)


class LiveCanaryRuntimeCandidateDocumentError(RuntimeError):
    """One candidate-document invariant failed with a public reason code."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: object) -> None:
        normalized = re.sub(
            r"[^A-Z0-9_]+",
            "_",
            str(reason_code or "").strip().upper(),
        ).strip("_")
        self.reason_code = normalized or "LIVE_CANARY_CANDIDATE_DOCUMENT_INVALID"
        super().__init__(self.reason_code)


def _reject(reason_code: str) -> None:
    raise LiveCanaryPrebootstrapAdmissionError(reason_code)


def _reject_document(reason_code: str) -> None:
    raise LiveCanaryRuntimeCandidateDocumentError(reason_code)


def _text(name: str, value: object) -> str:
    if type(value) is not str:
        _reject(f"{name}_INVALID")
    raw = cast(str, value)
    normalized = raw.strip()
    if not normalized or normalized != raw or "\x00" in normalized:
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
    return cast(str, value)


def _git_sha(name: str, value: object) -> str:
    if (
        type(value) is not str
        or _HEX_40.fullmatch(value) is None
        or value == "0" * 40
    ):
        _reject(f"{name}_INVALID")
    return cast(str, value)


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
    normalized = float(cast(int | float, value))
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
    if type(value) is not int:
        _reject(f"{name}_INVALID")
    normalized = cast(int, value)
    if normalized < minimum or normalized > maximum:
        _reject(f"{name}_INVALID")
    return normalized


def _symbol_pairs(
    name: str,
    value: object,
    *,
    require_xau_only: bool,
) -> tuple[tuple[str, str], ...]:
    if type(value) not in {tuple, list}:
        _reject(f"{name}_INVALID")
    pairs: list[tuple[str, str]] = []
    items = cast(tuple[object, ...] | list[object], value)
    for item in items:
        if type(item) not in {tuple, list}:
            _reject(f"{name}_INVALID")
        pair = cast(tuple[object, ...] | list[object], item)
        if len(pair) != 2:
            _reject(f"{name}_INVALID")
        canonical = _text(f"{name}_CANONICAL_SYMBOL", pair[0]).upper()
        broker = _text(f"{name}_BROKER_SYMBOL", pair[1])
        if canonical != pair[0]:
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
        for name in (
            "commit_sha",
            "champion_git_tree",
            "demo_git_commit",
            "demo_git_tree",
        ):
            object.__setattr__(self, name, _git_sha(name, getattr(self, name)))

        key_ids = self.runtime_key_ids
        fingerprints = self.runtime_key_fingerprints
        if len(key_ids) != 8 or len(fingerprints) != 9:
            _reject("LIVE_RUNTIME_TRUST_DOMAIN_REUSE")
        _bounded_int(
            "magic_number",
            self.magic_number,
            minimum=1,
            maximum=2_147_483_647,
        )
        _bounded_int(
            "deviation_points",
            self.deviation_points,
            minimum=0,
            maximum=10_000,
        )
        _bounded_int(
            "max_tick_age_seconds",
            self.max_tick_age_seconds,
            minimum=1,
            maximum=60,
        )
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
        object.__setattr__(self, "_candidate_seal", _CANDIDATE_SEAL)

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


_register_live_canary_runtime_candidate_type(
    LiveCanaryRuntimeCandidate,
    _seal=_REGISTRATION_SEAL,
)


def _canonical_document_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
    except (RecursionError, TypeError, ValueError, UnicodeError) as exc:
        raise LiveCanaryRuntimeCandidateDocumentError(
            "LIVE_CANARY_CANDIDATE_DOCUMENT_CANONICALIZATION_FAILED"
        ) from exc


def canonical_live_canary_runtime_candidate_document(
    candidate: LiveCanaryRuntimeCandidate,
) -> bytes:
    """Return the only accepted canonical one-LF document bytes."""

    if not is_live_canary_runtime_candidate(candidate):
        _reject_document("LIVE_CANARY_CANDIDATE_DOCUMENT_TYPE_INVALID")
    return _canonical_document_bytes(
        {
            "schema_version": RUNTIME_CANDIDATE_DOCUMENT_SCHEMA_VERSION,
            "candidate": candidate.to_canonical_dict(),
            "candidate_sha256": candidate.content_sha256,
        }
    )


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _reject_document("LIVE_CANARY_CANDIDATE_DOCUMENT_DUPLICATE_KEY")
        value[key] = item
    return value


def _nonfinite_constant(_value: str) -> None:
    _reject_document("LIVE_CANARY_CANDIDATE_DOCUMENT_NONFINITE_VALUE")


def load_live_canary_runtime_candidate_document(
    document: bytes,
    *,
    expected_candidate_sha256: str,
) -> LiveCanaryRuntimeCandidate:
    """Load one exact canonical candidate document under an external hash pin."""

    if (
        type(expected_candidate_sha256) is not str
        or _HEX_64.fullmatch(expected_candidate_sha256) is None
        or expected_candidate_sha256 == "0" * 64
    ):
        _reject_document("LIVE_CANARY_CANDIDATE_EXTERNAL_PIN_INVALID")
    if type(document) is not bytes:
        _reject_document("LIVE_CANARY_CANDIDATE_DOCUMENT_BYTES_INVALID")
    if not document or len(document) > MAXIMUM_LIVE_CANARY_RUNTIME_CANDIDATE_DOCUMENT_BYTES:
        _reject_document("LIVE_CANARY_CANDIDATE_DOCUMENT_SIZE_INVALID")
    if not document.endswith(b"\n") or document.endswith(b"\n\n"):
        _reject_document("LIVE_CANARY_CANDIDATE_DOCUMENT_TERMINATOR_INVALID")

    try:
        decoded = document[:-1].decode("utf-8", errors="strict")
        wrapper = json.loads(
            decoded,
            object_pairs_hook=_closed_object,
            parse_constant=_nonfinite_constant,
        )
    except LiveCanaryRuntimeCandidateDocumentError:
        raise
    except (
        RecursionError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        raise LiveCanaryRuntimeCandidateDocumentError(
            "LIVE_CANARY_CANDIDATE_DOCUMENT_JSON_INVALID"
        ) from exc
    if type(wrapper) is not dict or frozenset(wrapper) != _DOCUMENT_FIELDS:
        _reject_document("LIVE_CANARY_CANDIDATE_DOCUMENT_FIELDS_INVALID")
    if wrapper.get("schema_version") != RUNTIME_CANDIDATE_DOCUMENT_SCHEMA_VERSION:
        _reject_document("LIVE_CANARY_CANDIDATE_DOCUMENT_SCHEMA_INVALID")
    if type(wrapper.get("candidate")) is not dict:
        _reject_document("LIVE_CANARY_CANDIDATE_PAYLOAD_INVALID")
    embedded_sha256 = wrapper.get("candidate_sha256")
    if (
        type(embedded_sha256) is not str
        or _HEX_64.fullmatch(embedded_sha256) is None
        or embedded_sha256 == "0" * 64
        or embedded_sha256 != expected_candidate_sha256
    ):
        _reject_document("LIVE_CANARY_CANDIDATE_PIN_MISMATCH")
    if _canonical_document_bytes(wrapper) != document:
        _reject_document("LIVE_CANARY_CANDIDATE_DOCUMENT_NONCANONICAL")

    payload = wrapper["candidate"]
    all_fields = tuple(dataclass_fields(LiveCanaryRuntimeCandidate))
    expected_fields = frozenset(item.name for item in all_fields)
    if frozenset(payload) != expected_fields:
        _reject_document("LIVE_CANARY_CANDIDATE_FIELDS_INVALID")
    kwargs = {
        item.name: payload[item.name]
        for item in all_fields
        if item.init
    }
    for pair_field in ("symbol_map", "usd_account_currency_symbols"):
        raw_pairs = kwargs.get(pair_field)
        if type(raw_pairs) is not list:
            _reject_document("LIVE_CANARY_CANDIDATE_PAIR_COLLECTION_INVALID")
        converted: list[tuple[object, object]] = []
        for pair in cast(list[Any], raw_pairs):
            if type(pair) is not list or len(pair) != 2:
                _reject_document("LIVE_CANARY_CANDIDATE_PAIR_INVALID")
            converted.append((pair[0], pair[1]))
        kwargs[pair_field] = tuple(converted)
    try:
        candidate = LiveCanaryRuntimeCandidate(**kwargs)
    except (LiveCanaryPrebootstrapAdmissionError, TypeError, ValueError) as exc:
        raise LiveCanaryRuntimeCandidateDocumentError(
            "LIVE_CANARY_CANDIDATE_RECONSTRUCTION_REJECTED"
        ) from exc
    if (
        not is_live_canary_runtime_candidate(candidate)
        or candidate.content_sha256 != embedded_sha256
        or candidate.content_sha256 != expected_candidate_sha256
        or candidate.to_canonical_dict() != payload
        or canonical_live_canary_runtime_candidate_document(candidate) != document
    ):
        _reject_document("LIVE_CANARY_CANDIDATE_ROUND_TRIP_MISMATCH")
    if (
        candidate.live_allowed
        or candidate.safe_to_demo_auto_order
        or candidate.execution_authorized
        or candidate.activation_authorized
        or candidate.order_capability != ORDER_CAPABILITY
    ):
        _reject_document("LIVE_CANARY_CANDIDATE_AUTHORITY_DRIFT")
    return candidate


__all__ = [
    "EXPECTED_DISTRIBUTION_VERSION",
    "EXPECTED_WHEEL_SHA256",
    "LiveCanaryPrebootstrapAdmissionError",
    "LiveCanaryRuntimeCandidate",
    "LiveCanaryRuntimeCandidateDocumentError",
    "MAXIMUM_LIVE_CANARY_RUNTIME_CANDIDATE_DOCUMENT_BYTES",
    "ORDER_CAPABILITY",
    "RUNTIME_CANDIDATE_DOCUMENT_SCHEMA_VERSION",
    "RUNTIME_CANDIDATE_SCHEMA_VERSION",
    "canonical_live_canary_runtime_candidate_document",
    "is_live_canary_runtime_candidate",
    "load_live_canary_runtime_candidate_document",
]
