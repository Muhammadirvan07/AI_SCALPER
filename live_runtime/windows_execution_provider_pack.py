"""Fail-closed provider foundation for the Windows Execution service.

This module owns the exact static configuration boundary used by the
Execution provider pack.  Parsing and validation are pure.  Runtime
materialization is an explicit Windows-only boundary and can never be reached
on another platform.

The implementation deliberately imports no MetaTrader5 module and exposes no
order primitive.  The production bootstrap remains the sole MT5
import/attestation and execution composition authority.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, fields
import hashlib
import json
import math
import re
from pathlib import Path, PureWindowsPath
import sys
from typing import Callable, Mapping

import execution_policy

from .contracts import (
    CanonicalContract,
    require_hash,
    require_text,
)
from .offhost_delivery import DeliveryOutbox
from .production_bootstrap import (
    ProductionRuntimeBootstrap,
    ProductionRuntimeConfig,
    ProductionRuntimePorts,
)
from .stage_authorization import StageBinding
from .windows_execution_production_config_source import (
    MAX_JSON_MEMBER_BYTES as PRODUCTION_CONFIG_SOURCE_MAX_JSON_BYTES,
    canonical_source_file as canonical_production_config_source_file,
    strict_source_json as strict_production_config_source_json,
    verify_windows_execution_production_config_source,
)
from .windows_provider_primitives import WindowsClockBinding
from .windows_service_entrypoint import (
    WindowsServiceFactoryContext,
    WindowsServiceFactoryResult,
    seal_windows_service_factory_result,
)
from .windows_service_factory_template import provider_contracts


PROVIDER_CONFIGURATION_SCHEMA = (
    "windows-execution-provider-configuration-v1"
)
PROVIDER_VALIDATION_SCHEMA = (
    "windows-execution-provider-validation-v1"
)
ORDER_CAPABILITY = "DISABLED"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_LOT = 0.01
PROMOTION_ELIGIBLE = False
PRODUCTION_EXECUTION_READY = False
EXECUTION_CREDENTIAL_TARGET_PREFIX = (
    "AI_SCALPER/WINDOWS_SERVICE/EXECUTION"
)

_CONTRACTS = provider_contracts()
EXECUTION_PROVIDER_ROLES = tuple(item.port_name for item in _CONTRACTS)
EXECUTION_CREDENTIAL_PURPOSES = tuple(
    item.credential_purpose
    for item in _CONTRACTS
    if item.credential_purpose is not None
)
_CONTRACT_BY_ROLE = {item.port_name: item for item in _CONTRACTS}
_RESULT_SEAL = object()
_PRODUCTION_CONFIG_SOURCE_SEAL = object()
_REASON = re.compile(r"^[A-Z][A-Z0-9_]*$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_DRIVE = re.compile(r"^[A-Z]:$")
_WINDOWS_RESERVED = frozenset(
    {
        "aux",
        "clock$",
        "con",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)
_CONFIGURATION_FIELDS = frozenset(
    {
        "base_suite_identity_sha256",
        "clock_attestation_path",
        "clock_binding",
        "credential_references",
        "credential_target_prefix",
        "execution_base_release_identity_sha256",
        "live_allowed",
        "max_lot",
        "order_capability",
        "pack_id",
        "production_config_sha256",
        "production_execution_ready",
        "promotion_eligible",
        "provider_bindings",
        "runtime_mode",
        "safe_to_demo_auto_order",
        "schema_version",
        "service_config_file_sha256",
    }
)
_CREDENTIAL_FIELDS = frozenset(
    {
        "fingerprint_sha256",
        "key_id",
        "purpose",
        "reference_id",
        "target_name",
    }
)
_PROVIDER_FIELDS = frozenset(
    {
        "configuration_sha256",
        "contract_sha256",
        "credential_reference_id",
        "implementation_sha256",
        "port_name",
        "provider_id",
        "provider_kind",
    }
)
_CLOCK_FIELDS = frozenset(item.name for item in fields(WindowsClockBinding))
_SERVICE_CONFIGURATION_FIELDS = frozenset(
    {
        "cycle_deadline_seconds",
        "cycle_interval_seconds",
        "heartbeat_ttl_seconds",
        "lease_seconds",
        "max_cycles",
        "owner_id",
        "service_id",
    }
)


class WindowsExecutionProviderError(RuntimeError):
    """One execution provider boundary failed with a stable reason code."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: str) -> None:
        normalized = str(reason_code or "").strip().upper()
        if _REASON.fullmatch(normalized) is None:
            normalized = "WINDOWS_EXECUTION_PROVIDER_INVALID"
        self.reason_code = normalized
        super().__init__(normalized)


def _mapping(
    value: object,
    expected: frozenset[str],
    reason_code: str,
) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise WindowsExecutionProviderError(reason_code)
    return dict(value)


def _identifier(value: object, reason_code: str) -> str:
    if (
        type(value) is not str
        or _ID.fullmatch(value) is None
        or value != value.strip()
    ):
        raise WindowsExecutionProviderError(reason_code)
    return value


def _hash(value: object, reason_code: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise WindowsExecutionProviderError(reason_code)
    try:
        normalized = require_hash("sha256", value)
    except (TypeError, ValueError) as exc:
        raise WindowsExecutionProviderError(reason_code) from exc
    if normalized == "0" * 64:
        raise WindowsExecutionProviderError(reason_code)
    return normalized


def _unique_casefold(values: tuple[str, ...], reason_code: str) -> None:
    if len(values) != len({item.casefold() for item in values}):
        raise WindowsExecutionProviderError(reason_code)


def _windows_file_path(value: object) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise WindowsExecutionProviderError(
            "EXECUTION_PROVIDER_PATH_INVALID"
        )
    if (
        value.startswith(("\\\\", "//"))
        or "\x00" in value
        or "/" in value
    ):
        raise WindowsExecutionProviderError(
            "EXECUTION_PROVIDER_PATH_INVALID"
        )
    parsed = PureWindowsPath(value)
    if (
        not parsed.is_absolute()
        or _WINDOWS_DRIVE.fullmatch(parsed.drive) is None
        or parsed.anchor != parsed.drive + "\\"
        or parsed.name in {"", ".", ".."}
        or any(part in {"", ".", ".."} for part in parsed.parts[1:])
    ):
        raise WindowsExecutionProviderError(
            "EXECUTION_PROVIDER_PATH_INVALID"
        )
    for part in parsed.parts[1:]:
        if (
            ":" in part
            or part.rstrip(" .") != part
            or part.split(".", 1)[0].casefold() in _WINDOWS_RESERVED
            or any(ord(character) < 32 for character in part)
        ):
            raise WindowsExecutionProviderError(
                "EXECUTION_PROVIDER_PATH_INVALID"
            )
    return str(parsed)


@dataclass(frozen=True, slots=True)
class ExecutionCredentialReference(CanonicalContract):
    """One purpose-bound, non-secret Credential Manager reference."""

    reference_id: str
    key_id: str
    target_name: str
    purpose: str
    fingerprint_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "reference_id",
            _identifier(
                self.reference_id,
                "EXECUTION_CREDENTIAL_REFERENCE_INVALID",
            ),
        )
        object.__setattr__(
            self,
            "key_id",
            _identifier(
                self.key_id,
                "EXECUTION_CREDENTIAL_REFERENCE_INVALID",
            ),
        )
        if (
            type(self.target_name) is not str
            or not self.target_name
            or self.target_name != self.target_name.strip()
            or "\\" in self.target_name
            or "//" in self.target_name
            or any(
                ord(character) < 32 for character in self.target_name
            )
        ):
            raise WindowsExecutionProviderError(
                "EXECUTION_CREDENTIAL_REFERENCE_INVALID"
            )
        object.__setattr__(
            self,
            "purpose",
            require_text(
                "credential purpose",
                self.purpose,
                upper=True,
            ),
        )
        object.__setattr__(
            self,
            "fingerprint_sha256",
            _hash(
                self.fingerprint_sha256,
                "EXECUTION_CREDENTIAL_REFERENCE_INVALID",
            ),
        )


@dataclass(frozen=True, slots=True)
class ExecutionProviderBinding(CanonicalContract):
    """One exact implementation/configuration binding for a runtime port."""

    port_name: str
    provider_id: str
    provider_kind: str
    contract_sha256: str
    implementation_sha256: str
    configuration_sha256: str
    credential_reference_id: str | None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "port_name",
            _identifier(
                self.port_name,
                "EXECUTION_PROVIDER_BINDING_INVALID",
            ),
        )
        object.__setattr__(
            self,
            "provider_id",
            _identifier(
                self.provider_id,
                "EXECUTION_PROVIDER_BINDING_INVALID",
            ),
        )
        if self.provider_kind not in {"CALLABLE", "COMPONENT"}:
            raise WindowsExecutionProviderError(
                "EXECUTION_PROVIDER_BINDING_INVALID"
            )
        for name in (
            "contract_sha256",
            "implementation_sha256",
            "configuration_sha256",
        ):
            object.__setattr__(
                self,
                name,
                _hash(
                    getattr(self, name),
                    "EXECUTION_PROVIDER_BINDING_INVALID",
                ),
            )
        if self.credential_reference_id is not None:
            object.__setattr__(
                self,
                "credential_reference_id",
                _identifier(
                    self.credential_reference_id,
                    "EXECUTION_PROVIDER_BINDING_INVALID",
                ),
            )


@dataclass(frozen=True, slots=True)
class WindowsExecutionProviderConfiguration(CanonicalContract):
    """Exact immutable non-secret configuration for one Execution pack."""

    pack_id: str
    runtime_mode: str
    base_suite_identity_sha256: str
    execution_base_release_identity_sha256: str
    production_config_sha256: str
    service_config_file_sha256: str
    credential_target_prefix: str
    credential_references: tuple[ExecutionCredentialReference, ...]
    provider_bindings: tuple[ExecutionProviderBinding, ...]
    clock_binding: WindowsClockBinding
    clock_attestation_path: str
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    max_lot: float = MAX_LOT
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    production_execution_ready: bool = PRODUCTION_EXECUTION_READY
    order_capability: str = ORDER_CAPABILITY
    schema_version: str = PROVIDER_CONFIGURATION_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "pack_id",
            _identifier(
                self.pack_id,
                "EXECUTION_PROVIDER_CONFIGURATION_INVALID",
            ),
        )
        mode = require_text(
            "runtime_mode",
            self.runtime_mode,
            upper=True,
        )
        if mode not in {"DEMO", "DEMO_AUTO"}:
            raise WindowsExecutionProviderError(
                "EXECUTION_PROVIDER_CONFIGURATION_INVALID"
            )
        object.__setattr__(self, "runtime_mode", mode)
        for name in (
            "base_suite_identity_sha256",
            "execution_base_release_identity_sha256",
            "production_config_sha256",
            "service_config_file_sha256",
        ):
            object.__setattr__(
                self,
                name,
                _hash(
                    getattr(self, name),
                    "EXECUTION_PROVIDER_CONFIGURATION_INVALID",
                ),
            )
        if (
            type(self.credential_target_prefix) is not str
            or self.credential_target_prefix
            != EXECUTION_CREDENTIAL_TARGET_PREFIX
        ):
            raise WindowsExecutionProviderError(
                "EXECUTION_CREDENTIAL_TARGET_PREFIX_INVALID"
            )
        if (
            type(self.credential_references) is not tuple
            or len(self.credential_references)
            != len(EXECUTION_CREDENTIAL_PURPOSES)
            or any(
                type(item) is not ExecutionCredentialReference
                for item in self.credential_references
            )
        ):
            raise WindowsExecutionProviderError(
                "EXECUTION_CREDENTIAL_REFERENCE_SET_INVALID"
            )
        references = self.credential_references
        if tuple(item.purpose for item in references) != (
            EXECUTION_CREDENTIAL_PURPOSES
        ):
            raise WindowsExecutionProviderError(
                "EXECUTION_CREDENTIAL_PURPOSE_SET_INVALID"
            )
        for item in references:
            if item.target_name != (
                f"{self.credential_target_prefix}/{item.key_id}"
            ):
                raise WindowsExecutionProviderError(
                    "EXECUTION_CREDENTIAL_TARGET_MISMATCH"
                )
        _unique_casefold(
            tuple(item.reference_id for item in references),
            "EXECUTION_CREDENTIAL_REFERENCE_DUPLICATE",
        )
        _unique_casefold(
            tuple(item.key_id for item in references),
            "EXECUTION_CREDENTIAL_KEY_DUPLICATE",
        )
        _unique_casefold(
            tuple(item.target_name for item in references),
            "EXECUTION_CREDENTIAL_TARGET_DUPLICATE",
        )
        if len(
            {item.fingerprint_sha256 for item in references}
        ) != len(references):
            raise WindowsExecutionProviderError(
                "EXECUTION_CREDENTIAL_FINGERPRINT_REUSED"
            )
        if (
            type(self.provider_bindings) is not tuple
            or len(self.provider_bindings) != len(_CONTRACTS)
            or any(
                type(item) is not ExecutionProviderBinding
                for item in self.provider_bindings
            )
        ):
            raise WindowsExecutionProviderError(
                "EXECUTION_PROVIDER_BINDING_SET_INVALID"
            )
        if tuple(
            item.port_name for item in self.provider_bindings
        ) != EXECUTION_PROVIDER_ROLES:
            raise WindowsExecutionProviderError(
                "EXECUTION_PROVIDER_BINDING_SET_INVALID"
            )
        _unique_casefold(
            tuple(item.provider_id for item in self.provider_bindings),
            "EXECUTION_PROVIDER_ID_DUPLICATE",
        )
        references_by_id = {
            item.reference_id: item for item in references
        }
        for binding, contract in zip(
            self.provider_bindings,
            _CONTRACTS,
            strict=True,
        ):
            if (
                binding.port_name != contract.port_name
                or binding.provider_kind != contract.provider_kind
                or binding.contract_sha256
                != contract.contract_sha256
            ):
                raise WindowsExecutionProviderError(
                    "EXECUTION_PROVIDER_CONTRACT_MISMATCH"
                )
            if contract.credential_purpose is None:
                if binding.credential_reference_id is not None:
                    raise WindowsExecutionProviderError(
                        "EXECUTION_PROVIDER_CREDENTIAL_FORBIDDEN"
                    )
            else:
                reference = references_by_id.get(
                    binding.credential_reference_id or ""
                )
                if (
                    reference is None
                    or reference.purpose
                    != contract.credential_purpose
                ):
                    raise WindowsExecutionProviderError(
                        "EXECUTION_PROVIDER_CREDENTIAL_MISMATCH"
                    )
        if type(self.clock_binding) is not WindowsClockBinding:
            raise WindowsExecutionProviderError(
                "EXECUTION_CLOCK_BINDING_INVALID"
            )
        if (
            self.clock_binding.authority_key_id.casefold()
            in {item.key_id.casefold() for item in references}
            or self.clock_binding.authority_key_fingerprint_sha256
            in {item.fingerprint_sha256 for item in references}
        ):
            raise WindowsExecutionProviderError(
                "EXECUTION_CLOCK_TRUST_DOMAIN_REUSED"
            )
        object.__setattr__(
            self,
            "clock_attestation_path",
            _windows_file_path(self.clock_attestation_path),
        )
        if (
            type(self.live_allowed) is not bool
            or self.live_allowed is not False
            or type(self.safe_to_demo_auto_order) is not bool
            or self.safe_to_demo_auto_order is not False
            or type(self.max_lot) is not float
            or self.max_lot != MAX_LOT
            or type(self.promotion_eligible) is not bool
            or self.promotion_eligible is not False
            or type(self.production_execution_ready) is not bool
            or self.production_execution_ready is not False
            or self.order_capability != ORDER_CAPABILITY
            or self.schema_version != PROVIDER_CONFIGURATION_SCHEMA
        ):
            raise WindowsExecutionProviderError(
                "EXECUTION_PROVIDER_SAFETY_LOCK_INVALID"
            )


@dataclass(frozen=True, slots=True)
class WindowsExecutionProviderValidation(CanonicalContract):
    """Pure-data validation receipt. It grants no provider acceptance."""

    configuration_sha256: str
    provider_count: int
    credential_reference_count: int
    provider_accepted: bool = False
    provider_materialized: bool = False
    credential_access_performed: bool = False
    sqlite_open_performed: bool = False
    mt5_initialized: bool = False
    network_access_performed: bool = False
    broker_mutation_performed: bool = False
    task_installation_performed: bool = False
    production_execution_ready: bool = False
    promotion_eligible: bool = False
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    order_capability: str = ORDER_CAPABILITY
    max_lot: float = MAX_LOT
    schema_version: str = PROVIDER_VALIDATION_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _RESULT_SEAL:
            raise TypeError(
                "execution provider validation requires validator seal"
            )
        object.__setattr__(
            self,
            "configuration_sha256",
            _hash(
                self.configuration_sha256,
                "EXECUTION_PROVIDER_VALIDATION_INVALID",
            ),
        )
        if (
            self.provider_count != len(EXECUTION_PROVIDER_ROLES)
            or self.credential_reference_count
            != len(EXECUTION_CREDENTIAL_PURPOSES)
            or self.provider_accepted is not False
            or self.provider_materialized is not False
            or self.credential_access_performed is not False
            or self.sqlite_open_performed is not False
            or self.mt5_initialized is not False
            or self.network_access_performed is not False
            or self.broker_mutation_performed is not False
            or self.task_installation_performed is not False
            or self.production_execution_ready is not False
            or self.promotion_eligible is not False
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or self.order_capability != ORDER_CAPABILITY
            or self.max_lot != MAX_LOT
            or self.schema_version != PROVIDER_VALIDATION_SCHEMA
        ):
            raise ValueError("execution provider validation safety drift")


@dataclass(frozen=True, slots=True)
class WindowsExecutionProductionConfigSource:
    """One exact pre-reviewed production configuration source."""

    config: ProductionRuntimeConfig
    source_sha256: str
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _PRODUCTION_CONFIG_SOURCE_SEAL:
            raise TypeError(
                "production config source requires seven-pin loader seal"
            )
        if type(self.config) is not ProductionRuntimeConfig:
            raise TypeError(
                "config must be exact ProductionRuntimeConfig"
            )
        object.__setattr__(
            self,
            "source_sha256",
            _hash(
                self.source_sha256,
                "EXECUTION_PRODUCTION_CONFIG_SOURCE_INVALID",
            ),
        )


def load_windows_execution_production_config_source(
    archive_path: str | Path,
    *,
    expected_source_archive_sha256: str,
    expected_champion_archive_sha256: str,
    expected_model_artifact_sha256: str,
    expected_training_snapshot_sha256: str,
    expected_config_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
) -> WindowsExecutionProductionConfigSource:
    """Load one seven-pin-verified source into the exact runtime contract.

    Verification and object reconstruction are still effect-free.  No
    provider is imported or materialized, and no credential, SQLite, MT5,
    network, task, service, permit, or broker boundary is reached.
    """

    report = verify_windows_execution_production_config_source(
        archive_path,
        expected_source_archive_sha256=(
            expected_source_archive_sha256
        ),
        expected_champion_archive_sha256=(
            expected_champion_archive_sha256
        ),
        expected_model_artifact_sha256=(
            expected_model_artifact_sha256
        ),
        expected_training_snapshot_sha256=(
            expected_training_snapshot_sha256
        ),
        expected_config_sha256=expected_config_sha256,
        expected_git_commit=expected_git_commit,
        expected_git_tree=expected_git_tree,
    )
    config_payload = strict_production_config_source_json(
        report.production_config_bytes,
        maximum_bytes=PRODUCTION_CONFIG_SOURCE_MAX_JSON_BYTES,
    )
    stage_document = strict_production_config_source_json(
        report.stage_binding_bytes,
        maximum_bytes=PRODUCTION_CONFIG_SOURCE_MAX_JSON_BYTES,
    )
    binding_payload = stage_document.get("binding")
    if type(binding_payload) is not dict:
        raise WindowsExecutionProviderError(
            "EXECUTION_PRODUCTION_CONFIG_SOURCE_INVALID"
        )
    config_values = dict(config_payload)
    for name in (
        "journal_database",
        "supervisor_database",
        "dependency_lock_file",
    ):
        config_values[name] = Path(str(config_values[name]))
    for name in ("symbol_map", "usd_account_currency_symbols"):
        raw_pairs = config_values[name]
        if type(raw_pairs) is not list:
            raise WindowsExecutionProviderError(
                "EXECUTION_PRODUCTION_CONFIG_SOURCE_INVALID"
            )
        config_values[name] = tuple(
            tuple(str(value) for value in item)
            for item in raw_pairs
        )
    try:
        stage = StageBinding(**binding_payload)
        config = ProductionRuntimeConfig(**config_values)
    except Exception as exc:
        raise WindowsExecutionProviderError(
            "EXECUTION_PRODUCTION_CONFIG_SOURCE_INVALID"
        ) from exc
    if (
        canonical_production_config_source_file(
            stage.to_canonical_dict()
        )
        != canonical_production_config_source_file(binding_payload)
        or stage.binding_sha256 != report.stage_binding_sha256
        or config.stage_binding_sha256 != stage.binding_sha256
        or config.safe_binding_sha256 != report.bootstrap_binding_sha256
        or canonical_production_config_source_file(
            config.reviewed_configuration_payload
        )
        != report.production_config_bytes
    ):
        raise WindowsExecutionProviderError(
            "EXECUTION_PRODUCTION_CONFIG_SOURCE_INVALID"
        )
    return WindowsExecutionProductionConfigSource(
        config=config,
        source_sha256=report.archive_sha256,
        _seal=_PRODUCTION_CONFIG_SOURCE_SEAL,
    )


@dataclass(frozen=True, slots=True)
class WindowsExecutionHeartbeatTransport:
    """Transport plus the exact off-host destination identity."""

    destination_id: str
    transport: object

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "destination_id",
            _identifier(
                self.destination_id,
                "EXECUTION_HEARTBEAT_TRANSPORT_INVALID",
            ),
        )
        if not callable(getattr(self.transport, "deliver", None)):
            raise WindowsExecutionProviderError(
                "EXECUTION_HEARTBEAT_TRANSPORT_INVALID"
            )


@dataclass(frozen=True, slots=True)
class WindowsExecutionProviderMaterializationHooks:
    """Explicit Windows effect seams used by reviewed provider runtimes.

    The hooks are dependency-injection seams, not activation authority.  The
    first-party generated factory supplies none; until an independently
    reviewed Windows implementation is installed, the public materializer
    fails with ``EXECUTION_PROVIDER_RUNTIME_NOT_CONFIGURED``.
    """

    production_config_reader: Callable[..., object]
    credential_backend_factory: Callable[..., object]
    clock_attestation_reader: Callable[..., object]
    provider_state_reader: Callable[..., object]
    sqlite_opener: Callable[..., object]
    mt5_importer: Callable[..., object]
    network_sender: Callable[..., object]

    def __post_init__(self) -> None:
        for item in fields(self):
            if not callable(getattr(self, item.name)):
                raise TypeError(
                    f"{item.name} materialization hook must be callable"
                )


def windows_execution_provider_configuration_from_dict(
    payload: Mapping[str, object],
) -> WindowsExecutionProviderConfiguration:
    """Parse one exact non-secret provider configuration."""

    raw = _mapping(
        payload,
        _CONFIGURATION_FIELDS,
        "EXECUTION_PROVIDER_CONFIGURATION_FIELDS_INVALID",
    )
    credentials_raw = raw["credential_references"]
    providers_raw = raw["provider_bindings"]
    if (
        type(credentials_raw) is not list
        or type(providers_raw) is not list
    ):
        raise WindowsExecutionProviderError(
            "EXECUTION_PROVIDER_CONFIGURATION_INVALID"
        )
    credentials: list[ExecutionCredentialReference] = []
    for item in credentials_raw:
        values = _mapping(
            item,
            _CREDENTIAL_FIELDS,
            "EXECUTION_CREDENTIAL_REFERENCE_INVALID",
        )
        try:
            credentials.append(
                ExecutionCredentialReference(**values)  # type: ignore[arg-type]
            )
        except WindowsExecutionProviderError:
            raise
        except (TypeError, ValueError) as exc:
            raise WindowsExecutionProviderError(
                "EXECUTION_CREDENTIAL_REFERENCE_INVALID"
            ) from exc
    providers: list[ExecutionProviderBinding] = []
    for item in providers_raw:
        values = _mapping(
            item,
            _PROVIDER_FIELDS,
            "EXECUTION_PROVIDER_BINDING_INVALID",
        )
        try:
            providers.append(
                ExecutionProviderBinding(**values)  # type: ignore[arg-type]
            )
        except WindowsExecutionProviderError:
            raise
        except (TypeError, ValueError) as exc:
            raise WindowsExecutionProviderError(
                "EXECUTION_PROVIDER_BINDING_INVALID"
            ) from exc
    clock_raw = _mapping(
        raw["clock_binding"],
        _CLOCK_FIELDS,
        "EXECUTION_CLOCK_BINDING_INVALID",
    )
    try:
        clock = WindowsClockBinding(**clock_raw)  # type: ignore[arg-type]
        return WindowsExecutionProviderConfiguration(
            pack_id=raw["pack_id"],  # type: ignore[arg-type]
            runtime_mode=raw["runtime_mode"],  # type: ignore[arg-type]
            base_suite_identity_sha256=raw[
                "base_suite_identity_sha256"
            ],  # type: ignore[arg-type]
            execution_base_release_identity_sha256=raw[
                "execution_base_release_identity_sha256"
            ],  # type: ignore[arg-type]
            production_config_sha256=raw[
                "production_config_sha256"
            ],  # type: ignore[arg-type]
            service_config_file_sha256=raw[
                "service_config_file_sha256"
            ],  # type: ignore[arg-type]
            credential_target_prefix=raw[
                "credential_target_prefix"
            ],  # type: ignore[arg-type]
            credential_references=tuple(credentials),
            provider_bindings=tuple(providers),
            clock_binding=clock,
            clock_attestation_path=raw[
                "clock_attestation_path"
            ],  # type: ignore[arg-type]
            live_allowed=raw["live_allowed"],  # type: ignore[arg-type]
            safe_to_demo_auto_order=raw[
                "safe_to_demo_auto_order"
            ],  # type: ignore[arg-type]
            max_lot=raw["max_lot"],  # type: ignore[arg-type]
            promotion_eligible=raw[
                "promotion_eligible"
            ],  # type: ignore[arg-type]
            production_execution_ready=raw[
                "production_execution_ready"
            ],  # type: ignore[arg-type]
            order_capability=raw[
                "order_capability"
            ],  # type: ignore[arg-type]
            schema_version=raw["schema_version"],  # type: ignore[arg-type]
        )
    except WindowsExecutionProviderError:
        raise
    except (TypeError, ValueError) as exc:
        raise WindowsExecutionProviderError(
            "EXECUTION_PROVIDER_CONFIGURATION_INVALID"
        ) from exc


def validate_windows_execution_provider_configuration(
    config: WindowsExecutionProviderConfiguration,
    *,
    effect_probe: Callable[[str], object] | None = None,
) -> WindowsExecutionProviderValidation:
    """Validate one already parsed configuration without invoking effects."""

    if type(config) is not WindowsExecutionProviderConfiguration:
        raise TypeError(
            "config must be exact WindowsExecutionProviderConfiguration"
        )
    if effect_probe is not None and not callable(effect_probe):
        raise TypeError("effect_probe must be callable or None")
    # effect_probe is intentionally not invoked. Tests use it as a sentinel
    # proving that pure validation has no materialization edge.
    return WindowsExecutionProviderValidation(
        configuration_sha256=config.content_sha256,
        provider_count=len(config.provider_bindings),
        credential_reference_count=len(config.credential_references),
        _seal=_RESULT_SEAL,
    )


def _service_configuration_sha256(
    value: Mapping[str, object],
) -> str:
    raw = _mapping(
        value,
        _SERVICE_CONFIGURATION_FIELDS,
        "EXECUTION_RUNTIME_CONFIGURATION_INVALID",
    )
    for name in ("service_id", "owner_id"):
        item = raw[name]
        if (
            type(item) is not str
            or _ID.fullmatch(item) is None
            or len(item) > 64
        ):
            raise WindowsExecutionProviderError(
                "EXECUTION_RUNTIME_CONFIGURATION_INVALID"
            )
    for name, minimum, maximum in (
        ("max_cycles", 1, 100_000),
        ("lease_seconds", 1, 300),
        ("heartbeat_ttl_seconds", 2, 30),
    ):
        item = raw[name]
        if (
            type(item) is not int
            or not minimum <= item <= maximum
        ):
            raise WindowsExecutionProviderError(
                "EXECUTION_RUNTIME_CONFIGURATION_INVALID"
            )
    heartbeat = raw["heartbeat_ttl_seconds"]
    interval = raw["cycle_interval_seconds"]
    deadline = raw["cycle_deadline_seconds"]
    if (
        isinstance(interval, bool)
        or not isinstance(interval, (int, float))
        or not math.isfinite(float(interval))
        or not 0.25
        <= float(interval)
        <= min(15.0, float(heartbeat) / 2.0)
        or isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(float(deadline))
        or not 1.0 <= float(deadline) <= float(heartbeat)
    ):
        raise WindowsExecutionProviderError(
            "EXECUTION_RUNTIME_CONFIGURATION_INVALID"
        )
    raw["cycle_interval_seconds"] = float(interval)
    raw["cycle_deadline_seconds"] = float(deadline)
    try:
        encoded = (
            json.dumps(
                raw,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as exc:
        raise WindowsExecutionProviderError(
            "EXECUTION_RUNTIME_CONFIGURATION_INVALID"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _provider_reference(
    *,
    config: WindowsExecutionProviderConfiguration,
    binding: ExecutionProviderBinding,
) -> ExecutionCredentialReference | None:
    if binding.credential_reference_id is None:
        return None
    matches = tuple(
        item
        for item in config.credential_references
        if item.reference_id == binding.credential_reference_id
    )
    if len(matches) != 1:
        raise WindowsExecutionProviderError(
            "EXECUTION_PROVIDER_CREDENTIAL_MISMATCH"
        )
    return matches[0]


def _read_provider_value(
    *,
    hooks: WindowsExecutionProviderMaterializationHooks,
    binding: ExecutionProviderBinding,
    credential_reference: ExecutionCredentialReference | None,
    provider_config: WindowsExecutionProviderConfiguration,
    production_config: ProductionRuntimeConfig,
    credential_backend: object,
    clock_provider: Callable[[], object],
) -> object:
    try:
        value = hooks.provider_state_reader(
            binding=binding,
            credential_reference=credential_reference,
            provider_config=provider_config,
            production_config=production_config,
            credential_backend=credential_backend,
            clock_provider=clock_provider,
            sqlite_opener=hooks.sqlite_opener,
            network_sender=hooks.network_sender,
        )
    except WindowsExecutionProviderError:
        raise
    except Exception as exc:
        raise WindowsExecutionProviderError(
            "EXECUTION_PROVIDER_STATE_UNAVAILABLE"
        ) from exc
    contract = _CONTRACT_BY_ROLE[binding.port_name]
    if (
        not contract.required
        and provider_config.runtime_mode == "DEMO"
        and value is None
    ):
        return None
    if binding.port_name == "heartbeat_transport":
        if type(value) is not WindowsExecutionHeartbeatTransport:
            raise WindowsExecutionProviderError(
                "EXECUTION_HEARTBEAT_TRANSPORT_INVALID"
            )
        return value
    if binding.provider_kind == "CALLABLE":
        if not callable(value):
            raise WindowsExecutionProviderError(
                "EXECUTION_PROVIDER_VALUE_INVALID"
            )
    elif value is None:
        raise WindowsExecutionProviderError(
            "EXECUTION_PROVIDER_VALUE_INVALID"
        )
    return value


def build_windows_execution_factory_result(
    *,
    runtime_config: Mapping[str, object],
    factory_context: object,
    provider_config: WindowsExecutionProviderConfiguration,
    hooks: WindowsExecutionProviderMaterializationHooks | None = None,
    platform: str | None = None,
) -> WindowsServiceFactoryResult:
    """Enter the explicit Windows-only materialization boundary.

    The platform and every static cross-binding are checked before any
    credential, provider state, SQLite, clock, or transport dependency is
    touched.  Construction never imports MetaTrader5 and always injects
    ``mt5_module=None`` into the production bootstrap.
    """

    observed_platform = sys.platform if platform is None else platform
    if observed_platform != "win32":
        raise WindowsExecutionProviderError(
            "WINDOWS_PLATFORM_REQUIRED"
        )
    if not isinstance(runtime_config, Mapping):
        raise WindowsExecutionProviderError(
            "EXECUTION_RUNTIME_CONFIGURATION_INVALID"
        )
    if type(factory_context) is not WindowsServiceFactoryContext:
        raise WindowsExecutionProviderError(
            "EXECUTION_FACTORY_CONTEXT_INVALID"
        )
    if type(provider_config) is not WindowsExecutionProviderConfiguration:
        raise WindowsExecutionProviderError(
            "EXECUTION_PROVIDER_CONFIGURATION_INVALID"
        )
    service_config_sha256 = _service_configuration_sha256(
        runtime_config
    )
    if (
        service_config_sha256
        != provider_config.service_config_file_sha256
        or factory_context.service_config_file_sha256
        != provider_config.service_config_file_sha256
    ):
        raise WindowsExecutionProviderError(
            "EXECUTION_SERVICE_CONFIGURATION_BINDING_MISMATCH"
        )
    if (
        provider_config.runtime_mode == "DEMO_AUTO"
        and not execution_policy.demo_auto_execution_policy_enabled()
    ):
        raise WindowsExecutionProviderError(
            "DEMO_AUTO_MODE_POLICY_LOCKED"
        )
    if hooks is None:
        raise WindowsExecutionProviderError(
            "EXECUTION_PROVIDER_RUNTIME_NOT_CONFIGURED"
        )
    if type(hooks) is not WindowsExecutionProviderMaterializationHooks:
        raise WindowsExecutionProviderError(
            "EXECUTION_MATERIALIZATION_HOOKS_INVALID"
        )
    try:
        source = hooks.production_config_reader(provider_config)
    except WindowsExecutionProviderError:
        raise
    except Exception as exc:
        raise WindowsExecutionProviderError(
            "EXECUTION_PRODUCTION_CONFIG_UNAVAILABLE"
        ) from exc
    if type(source) is not WindowsExecutionProductionConfigSource:
        raise WindowsExecutionProviderError(
            "EXECUTION_PRODUCTION_CONFIG_SOURCE_INVALID"
        )
    production_config = source.config
    if (
        source.source_sha256 != provider_config.production_config_sha256
        or production_config.safe_binding_sha256
        != factory_context.bootstrap_binding_sha256
        or production_config.mode != provider_config.runtime_mode
        or production_config.live_allowed is not False
        or production_config.safe_to_demo_auto_order is not False
        or production_config.order_capability != "DISABLED"
    ):
        raise WindowsExecutionProviderError(
            "EXECUTION_PRODUCTION_CONFIG_BINDING_MISMATCH"
        )
    try:
        credential_backend = hooks.credential_backend_factory(
            target_prefix=provider_config.credential_target_prefix,
            references=provider_config.credential_references,
        )
    except Exception as exc:
        raise WindowsExecutionProviderError(
            "EXECUTION_CREDENTIAL_BACKEND_UNAVAILABLE"
        ) from exc
    try:
        clock_provider = hooks.clock_attestation_reader(
            binding=provider_config.clock_binding,
            path=provider_config.clock_attestation_path,
            credential_reference=None,
            credential_backend=credential_backend,
        )
    except WindowsExecutionProviderError:
        raise
    except Exception as exc:
        raise WindowsExecutionProviderError(
            "EXECUTION_CLOCK_PROVIDER_UNAVAILABLE"
        ) from exc
    if not callable(clock_provider):
        raise WindowsExecutionProviderError(
            "EXECUTION_CLOCK_PROVIDER_INVALID"
        )
    values: dict[str, object] = {"clock_provider": clock_provider}
    for binding in provider_config.provider_bindings:
        if binding.port_name == "clock_provider":
            continue
        contract = _CONTRACT_BY_ROLE[binding.port_name]
        if (
            provider_config.runtime_mode == "DEMO"
            and not contract.required
            and not (
                binding.port_name == "manual_approval_key_provider"
                and production_config.expected_manual_approval_key_id
                is not None
            )
        ):
            values[binding.port_name] = None
            continue
        values[binding.port_name] = _read_provider_value(
            hooks=hooks,
            binding=binding,
            credential_reference=_provider_reference(
                config=provider_config,
                binding=binding,
            ),
            provider_config=provider_config,
            production_config=production_config,
            credential_backend=credential_backend,
            clock_provider=clock_provider,
        )
    runtime_port_names = tuple(
        item.name
        for item in fields(ProductionRuntimePorts)
        if item.name != "mt5_module"
    )
    if any(name not in values for name in runtime_port_names):
        raise WindowsExecutionProviderError(
            "EXECUTION_RUNTIME_PORT_SET_INVALID"
        )
    try:
        ports = ProductionRuntimePorts(
            mt5_module=None,
            **{
                name: values[name]
                for name in runtime_port_names
            },
        )
        bootstrap = ProductionRuntimeBootstrap(
            production_config,
            ports,
        )
    except Exception as exc:
        raise WindowsExecutionProviderError(
            "EXECUTION_BOOTSTRAP_CONFIGURATION_INVALID"
        ) from exc
    outbox = values["heartbeat_outbox"]
    route = values["heartbeat_transport"]
    sender_provider = values["heartbeat_sender_key_provider"]
    remote_provider = values["heartbeat_remote_key_provider"]
    if (
        type(outbox) is not DeliveryOutbox
        or type(route) is not WindowsExecutionHeartbeatTransport
        or not callable(sender_provider)
        or not callable(remote_provider)
    ):
        raise WindowsExecutionProviderError(
            "EXECUTION_HEARTBEAT_PROVIDER_INVALID"
        )
    sender_binding = next(
        item
        for item in provider_config.provider_bindings
        if item.port_name == "heartbeat_sender_key_provider"
    )
    remote_binding = next(
        item
        for item in provider_config.provider_bindings
        if item.port_name == "heartbeat_remote_key_provider"
    )
    sender_reference = _provider_reference(
        config=provider_config,
        binding=sender_binding,
    )
    remote_reference = _provider_reference(
        config=provider_config,
        binding=remote_binding,
    )
    if sender_reference is None or remote_reference is None:
        raise WindowsExecutionProviderError(
            "EXECUTION_HEARTBEAT_CREDENTIAL_INVALID"
        )
    try:
        return seal_windows_service_factory_result(
            bootstrap=bootstrap,
            context=factory_context,
            heartbeat_outbox=outbox,
            heartbeat_transport=route.transport,
            heartbeat_destination_id=route.destination_id,
            heartbeat_sender_key_id=sender_reference.key_id,
            heartbeat_sender_key_fingerprint_sha256=(
                sender_reference.fingerprint_sha256
            ),
            heartbeat_remote_key_id=remote_reference.key_id,
            heartbeat_remote_key_fingerprint_sha256=(
                remote_reference.fingerprint_sha256
            ),
            heartbeat_sender_key_provider=sender_provider,
            heartbeat_remote_key_provider=remote_provider,
            clock_provider=clock_provider,
        )
    except Exception as exc:
        raise WindowsExecutionProviderError(
            "EXECUTION_FACTORY_RESULT_INVALID"
        ) from exc


__all__ = [
    "EXECUTION_CREDENTIAL_PURPOSES",
    "EXECUTION_CREDENTIAL_TARGET_PREFIX",
    "EXECUTION_PROVIDER_ROLES",
    "ExecutionCredentialReference",
    "ExecutionProviderBinding",
    "WindowsExecutionHeartbeatTransport",
    "WindowsExecutionProductionConfigSource",
    "WindowsExecutionProviderConfiguration",
    "WindowsExecutionProviderError",
    "WindowsExecutionProviderMaterializationHooks",
    "WindowsExecutionProviderValidation",
    "build_windows_execution_factory_result",
    "load_windows_execution_production_config_source",
    "validate_windows_execution_provider_configuration",
    "windows_execution_provider_configuration_from_dict",
]
