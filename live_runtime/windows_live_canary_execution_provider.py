"""Fail-closed Windows LIVE canary Execution materialization boundary.

The historical Windows Execution provider v1 remains DEMO/DEMO_AUTO-only.
This additive module defines the exact LIVE-only 49-port surface and composes
an already reviewed, sealed LIVE runtime source. Static parsing and validation
perform no provider, credential, clock, SQLite, MT5, network, task, process,
permit, or broker effect.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, fields
from datetime import datetime
import hashlib
import json
import math
from pathlib import PureWindowsPath
import re
import sys
from typing import Any, Callable, Mapping

import execution_policy

from .contracts import CanonicalContract, require_utc
from .live_canary_activation import LIVE_CANARY_MAX_LOT
from .offhost_delivery import DeliveryOutbox
from .production_bootstrap import (
    ProductionBootstrapError,
    ProductionRuntimeBootstrap,
    ProductionRuntimeConfig,
    ProductionRuntimePorts,
    _require_live_runtime_authority,
)
from .windows_execution_provider_pack import (
    ExecutionCredentialReference,
    ExecutionProviderBinding,
    WindowsExecutionHeartbeatTransport,
)
from .windows_provider_primitives import WindowsClockBinding
from .windows_service_entrypoint import (
    WindowsServiceFactoryContext,
    WindowsServiceFactoryResult,
    seal_windows_service_factory_result,
)
from .windows_service_factory_template import (
    ExternalProviderContract,
    provider_contracts,
)


PROVIDER_CONFIGURATION_SCHEMA = (
    "windows-live-canary-execution-provider-configuration-v1"
)
PROVIDER_VALIDATION_SCHEMA = (
    "windows-live-canary-execution-provider-validation-v1"
)
ORDER_CAPABILITY = "DISABLED"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_LOT = LIVE_CANARY_MAX_LOT
PROMOTION_ELIGIBLE = False
PRODUCTION_EXECUTION_READY = False
MAX_CONFIGURATION_BYTES = 4 * 1024 * 1024
LIVE_EXECUTION_CREDENTIAL_TARGET_PREFIX = (
    "AI_SCALPER/WINDOWS_SERVICE/LIVE_EXECUTION"
)

_RESULT_SEAL = object()
_RUNTIME_SOURCE_SEAL = object()
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
_LIVE_FORBIDDEN_PROVIDER_PORTS = frozenset(
    {
        "stage_binding",
        "manual_approval_key_provider",
        "demo_auto_ipc_input_provider",
        "demo_auto_session_lease_provider",
        "demo_auto_session_store",
        "demo_auto_permit_validation_provider",
        "demo_auto_promotion_validation_provider",
        "demo_auto_environment_arm_provider",
        "demo_auto_execution_cycle_provider",
    }
)


class WindowsLiveCanaryExecutionProviderError(RuntimeError):
    """One LIVE Windows provider invariant failed with a stable code."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: object) -> None:
        normalized = str(reason_code or "").strip().upper()
        if _REASON.fullmatch(normalized) is None:
            normalized = "WINDOWS_LIVE_EXECUTION_PROVIDER_INVALID"
        self.reason_code = normalized
        super().__init__(normalized)


def _reject(reason_code: str) -> None:
    raise WindowsLiveCanaryExecutionProviderError(reason_code)


def _canonical_bytes(value: object, *, newline: bool = False) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WindowsLiveCanaryExecutionProviderError(
            "LIVE_EXECUTION_PROVIDER_CONFIGURATION_INVALID"
        ) from exc
    return encoded + (b"\n" if newline else b"")


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _mapping(
    value: object,
    expected: frozenset[str],
    reason_code: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        _reject(reason_code)
    return dict(value)


def _identifier(value: object, reason_code: str) -> str:
    if (
        type(value) is not str
        or _ID.fullmatch(value) is None
        or value != value.strip()
    ):
        _reject(reason_code)
    return value


def _hash(value: object, reason_code: str) -> str:
    if (
        type(value) is not str
        or _HASH.fullmatch(value) is None
        or value == "0" * 64
    ):
        _reject(reason_code)
    return value


def _unique_casefold(values: tuple[str, ...], reason_code: str) -> None:
    if len(values) != len({item.casefold() for item in values}):
        _reject(reason_code)


def _windows_file_path(value: object) -> str:
    if type(value) is not str or not value or value != value.strip():
        _reject("LIVE_EXECUTION_PROVIDER_PATH_INVALID")
    if (
        value.startswith(("\\\\", "//"))
        or "\x00" in value
        or "/" in value
    ):
        _reject("LIVE_EXECUTION_PROVIDER_PATH_INVALID")
    parsed = PureWindowsPath(value)
    if (
        not parsed.is_absolute()
        or _WINDOWS_DRIVE.fullmatch(parsed.drive) is None
        or parsed.anchor != parsed.drive + "\\"
        or parsed.name in {"", ".", ".."}
        or any(part in {"", ".", ".."} for part in parsed.parts[1:])
    ):
        _reject("LIVE_EXECUTION_PROVIDER_PATH_INVALID")
    for part in parsed.parts[1:]:
        if (
            ":" in part
            or part.rstrip(" .") != part
            or part.split(".", 1)[0].casefold() in _WINDOWS_RESERVED
            or any(ord(character) < 32 for character in part)
        ):
            _reject("LIVE_EXECUTION_PROVIDER_PATH_INVALID")
    return str(parsed)


def _live_contracts() -> tuple[ExternalProviderContract, ...]:
    result: list[ExternalProviderContract] = []
    for contract in provider_contracts():
        if contract.port_name == "credential_session_provider":
            result.append(
                ExternalProviderContract(
                    port_name=contract.port_name,
                    provider_kind=contract.provider_kind,
                    call_contract=contract.call_contract,
                    required=contract.required,
                    credential_purpose="MT5_LIVE_SESSION",
                )
            )
        elif contract.port_name == "stage_binding":
            result.append(
                ExternalProviderContract(
                    port_name=contract.port_name,
                    provider_kind=contract.provider_kind,
                    call_contract="None",
                    required=False,
                    credential_purpose=None,
                )
            )
        elif contract.port_name == "promotion_evidence_key_provider":
            result.append(
                ExternalProviderContract(
                    port_name=contract.port_name,
                    provider_kind=contract.provider_kind,
                    call_contract="Callable[[str], str|bytes]",
                    required=True,
                    credential_purpose=contract.credential_purpose,
                )
            )
        else:
            result.append(contract)
    result.extend(
        (
            ExternalProviderContract(
                port_name="live_prepared_order_provider",
                provider_kind="CALLABLE",
                call_contract=(
                    "Callable[[RuntimeSupervisorDecision],"
                    "LiveCanaryPreparedOrder]"
                ),
                required=True,
                credential_purpose=None,
            ),
            ExternalProviderContract(
                port_name="live_order_authorization_provider",
                provider_kind="CALLABLE",
                call_contract="Callable[...,LiveCanaryOrderAuthorization]",
                required=True,
                credential_purpose=None,
            ),
            ExternalProviderContract(
                port_name="live_execution_cycle_provider",
                provider_kind="CALLABLE",
                call_contract="Callable[...,RuntimeLiveCanaryExecutionResult]",
                required=True,
                credential_purpose=None,
            ),
        )
    )
    return tuple(result)


_CONTRACTS = _live_contracts()
_CONTRACT_BY_ROLE = {item.port_name: item for item in _CONTRACTS}
LIVE_EXECUTION_PROVIDER_ROLES = tuple(item.port_name for item in _CONTRACTS)
LIVE_EXECUTION_CREDENTIAL_PURPOSES = tuple(
    item.credential_purpose
    for item in _CONTRACTS
    if item.credential_purpose is not None
)
LIVE_WINDOWS_FACTORY_PROVIDER_CONTRACT_SET_SHA256 = _canonical_hash(
    [
        {
            "port_name": item.port_name,
            "provider_kind": item.provider_kind,
            "call_contract": item.call_contract,
            "required": item.required,
            "credential_purpose": item.credential_purpose,
            "schema_version": item.schema_version,
            "contract_sha256": item.contract_sha256,
        }
        for item in _CONTRACTS
    ]
)

if (
    len(_CONTRACTS) != 49
    or len(LIVE_EXECUTION_CREDENTIAL_PURPOSES) != 12
    or sum(item.required for item in _CONTRACTS) != 40
    or {item.port_name for item in _CONTRACTS if not item.required}
    != _LIVE_FORBIDDEN_PROVIDER_PORTS
):
    raise RuntimeError("Windows LIVE provider contract invariant drift")


def live_provider_contracts() -> tuple[ExternalProviderContract, ...]:
    """Return the immutable, additive LIVE provider surface."""

    return _CONTRACTS


@dataclass(frozen=True, slots=True)
class WindowsLiveCanaryExecutionProviderConfiguration(CanonicalContract):
    """Exact immutable, non-secret configuration for a LIVE provider."""

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
                "LIVE_EXECUTION_PROVIDER_CONFIGURATION_INVALID",
            ),
        )
        if self.runtime_mode != "LIVE":
            _reject("LIVE_EXECUTION_PROVIDER_CONFIGURATION_INVALID")
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
                    "LIVE_EXECUTION_PROVIDER_CONFIGURATION_INVALID",
                ),
            )
        if (
            type(self.credential_target_prefix) is not str
            or self.credential_target_prefix
            != LIVE_EXECUTION_CREDENTIAL_TARGET_PREFIX
        ):
            _reject("LIVE_EXECUTION_CREDENTIAL_TARGET_PREFIX_INVALID")
        references = self.credential_references
        if (
            type(references) is not tuple
            or len(references) != len(LIVE_EXECUTION_CREDENTIAL_PURPOSES)
            or any(type(item) is not ExecutionCredentialReference for item in references)
            or tuple(item.purpose for item in references)
            != LIVE_EXECUTION_CREDENTIAL_PURPOSES
        ):
            _reject("LIVE_EXECUTION_CREDENTIAL_PURPOSE_SET_INVALID")
        for item in references:
            if item.target_name != (
                f"{self.credential_target_prefix}/{item.key_id}"
            ):
                _reject("LIVE_EXECUTION_CREDENTIAL_TARGET_MISMATCH")
        _unique_casefold(
            tuple(item.reference_id for item in references),
            "LIVE_EXECUTION_CREDENTIAL_REFERENCE_DUPLICATE",
        )
        _unique_casefold(
            tuple(item.key_id for item in references),
            "LIVE_EXECUTION_CREDENTIAL_KEY_DUPLICATE",
        )
        _unique_casefold(
            tuple(item.target_name for item in references),
            "LIVE_EXECUTION_CREDENTIAL_TARGET_DUPLICATE",
        )
        if len({item.fingerprint_sha256 for item in references}) != len(
            references
        ):
            _reject("LIVE_EXECUTION_CREDENTIAL_FINGERPRINT_REUSED")
        bindings = self.provider_bindings
        if (
            type(bindings) is not tuple
            or len(bindings) != len(_CONTRACTS)
            or any(type(item) is not ExecutionProviderBinding for item in bindings)
            or tuple(item.port_name for item in bindings)
            != LIVE_EXECUTION_PROVIDER_ROLES
        ):
            _reject("LIVE_EXECUTION_PROVIDER_BINDING_SET_INVALID")
        _unique_casefold(
            tuple(item.provider_id for item in bindings),
            "LIVE_EXECUTION_PROVIDER_ID_DUPLICATE",
        )
        references_by_id = {item.reference_id: item for item in references}
        for binding, contract in zip(bindings, _CONTRACTS, strict=True):
            if (
                binding.port_name != contract.port_name
                or binding.provider_kind != contract.provider_kind
                or binding.contract_sha256 != contract.contract_sha256
            ):
                _reject("LIVE_EXECUTION_PROVIDER_CONTRACT_MISMATCH")
            if contract.credential_purpose is None:
                if binding.credential_reference_id is not None:
                    _reject("LIVE_EXECUTION_PROVIDER_CREDENTIAL_FORBIDDEN")
            else:
                reference = references_by_id.get(
                    binding.credential_reference_id or ""
                )
                if (
                    reference is None
                    or reference.purpose != contract.credential_purpose
                ):
                    _reject("LIVE_EXECUTION_PROVIDER_CREDENTIAL_MISMATCH")
        if type(self.clock_binding) is not WindowsClockBinding:
            _reject("LIVE_EXECUTION_CLOCK_BINDING_INVALID")
        if (
            self.clock_binding.authority_key_id.casefold()
            in {item.key_id.casefold() for item in references}
            or self.clock_binding.authority_key_fingerprint_sha256
            in {item.fingerprint_sha256 for item in references}
        ):
            _reject("LIVE_EXECUTION_CLOCK_TRUST_DOMAIN_REUSED")
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
            _reject("LIVE_EXECUTION_PROVIDER_SAFETY_LOCK_INVALID")


@dataclass(frozen=True, slots=True)
class WindowsLiveCanaryExecutionProviderValidation(CanonicalContract):
    """Pure deny-only validation receipt with no external effects."""

    configuration_sha256: str
    provider_count: int
    credential_reference_count: int
    provider_accepted: bool = False
    provider_materialized: bool = False
    credential_access_performed: bool = False
    clock_access_performed: bool = False
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
            raise TypeError("LIVE provider validation requires validator seal")
        object.__setattr__(
            self,
            "configuration_sha256",
            _hash(
                self.configuration_sha256,
                "LIVE_EXECUTION_PROVIDER_VALIDATION_INVALID",
            ),
        )
        if (
            self.provider_count != len(LIVE_EXECUTION_PROVIDER_ROLES)
            or self.credential_reference_count
            != len(LIVE_EXECUTION_CREDENTIAL_PURPOSES)
            or any(
                value is not False
                for value in (
                    self.provider_accepted,
                    self.provider_materialized,
                    self.credential_access_performed,
                    self.clock_access_performed,
                    self.sqlite_open_performed,
                    self.mt5_initialized,
                    self.network_access_performed,
                    self.broker_mutation_performed,
                    self.task_installation_performed,
                    self.production_execution_ready,
                    self.promotion_eligible,
                    self.live_allowed,
                    self.safe_to_demo_auto_order,
                )
            )
            or self.order_capability != ORDER_CAPABILITY
            or self.max_lot != MAX_LOT
            or self.schema_version != PROVIDER_VALIDATION_SCHEMA
        ):
            raise ValueError("LIVE provider validation safety drift")


@dataclass(frozen=True, slots=True)
class WindowsLiveCanaryRuntimeSource:
    """Verifier-sealed, current LIVE configuration/candidate/session source."""

    config: ProductionRuntimeConfig
    live_candidate: object
    live_launch_session: object
    source_sha256: str
    verified_at_utc: datetime
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _RUNTIME_SOURCE_SEAL:
            raise TypeError("LIVE runtime source requires sealing factory")
        if type(self.config) is not ProductionRuntimeConfig:
            raise TypeError("config must be exact ProductionRuntimeConfig")
        object.__setattr__(
            self,
            "source_sha256",
            _hash(
                self.source_sha256,
                "LIVE_EXECUTION_RUNTIME_SOURCE_INVALID",
            ),
        )
        object.__setattr__(
            self,
            "verified_at_utc",
            require_utc("verified_at_utc", self.verified_at_utc),
        )


@dataclass(frozen=True, slots=True)
class WindowsLiveCanaryProviderMaterializationHooks:
    """Explicit Windows-only effects supplied by a reviewed runtime."""

    runtime_source_reader: Callable[..., object]
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


def _duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def windows_live_canary_execution_provider_configuration_from_json(
    payload: bytes,
) -> WindowsLiveCanaryExecutionProviderConfiguration:
    """Parse one bounded canonical JSON document with duplicate rejection."""

    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > MAX_CONFIGURATION_BYTES
    ):
        _reject("LIVE_EXECUTION_PROVIDER_CONFIGURATION_JSON_INVALID")
    try:
        parsed = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON")
            ),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise WindowsLiveCanaryExecutionProviderError(
            "LIVE_EXECUTION_PROVIDER_CONFIGURATION_JSON_INVALID"
        ) from exc
    if type(parsed) is not dict or payload != _canonical_bytes(
        parsed,
        newline=True,
    ):
        _reject("LIVE_EXECUTION_PROVIDER_CONFIGURATION_JSON_NONCANONICAL")
    return windows_live_canary_execution_provider_configuration_from_dict(
        parsed
    )


def windows_live_canary_execution_provider_configuration_from_dict(
    payload: Mapping[str, object],
) -> WindowsLiveCanaryExecutionProviderConfiguration:
    """Parse an exact non-secret LIVE provider configuration."""

    raw = _mapping(
        payload,
        _CONFIGURATION_FIELDS,
        "LIVE_EXECUTION_PROVIDER_CONFIGURATION_FIELDS_INVALID",
    )
    credentials_raw = raw["credential_references"]
    providers_raw = raw["provider_bindings"]
    if type(credentials_raw) is not list or type(providers_raw) is not list:
        _reject("LIVE_EXECUTION_PROVIDER_CONFIGURATION_INVALID")
    if (
        len(credentials_raw) > len(LIVE_EXECUTION_CREDENTIAL_PURPOSES)
        or len(providers_raw) > len(LIVE_EXECUTION_PROVIDER_ROLES)
    ):
        _reject("LIVE_EXECUTION_PROVIDER_CONFIGURATION_INVALID")
    credentials: list[ExecutionCredentialReference] = []
    for item in credentials_raw:
        values = _mapping(
            item,
            _CREDENTIAL_FIELDS,
            "LIVE_EXECUTION_CREDENTIAL_REFERENCE_INVALID",
        )
        try:
            credentials.append(ExecutionCredentialReference(**values))
        except Exception as exc:
            raise WindowsLiveCanaryExecutionProviderError(
                "LIVE_EXECUTION_CREDENTIAL_REFERENCE_INVALID"
            ) from exc
    providers: list[ExecutionProviderBinding] = []
    for item in providers_raw:
        values = _mapping(
            item,
            _PROVIDER_FIELDS,
            "LIVE_EXECUTION_PROVIDER_BINDING_INVALID",
        )
        try:
            providers.append(ExecutionProviderBinding(**values))
        except Exception as exc:
            raise WindowsLiveCanaryExecutionProviderError(
                "LIVE_EXECUTION_PROVIDER_BINDING_INVALID"
            ) from exc
    clock_raw = _mapping(
        raw["clock_binding"],
        _CLOCK_FIELDS,
        "LIVE_EXECUTION_CLOCK_BINDING_INVALID",
    )
    try:
        clock = WindowsClockBinding(**clock_raw)
        return WindowsLiveCanaryExecutionProviderConfiguration(
            pack_id=raw["pack_id"],
            runtime_mode=raw["runtime_mode"],
            base_suite_identity_sha256=raw[
                "base_suite_identity_sha256"
            ],
            execution_base_release_identity_sha256=raw[
                "execution_base_release_identity_sha256"
            ],
            production_config_sha256=raw["production_config_sha256"],
            service_config_file_sha256=raw[
                "service_config_file_sha256"
            ],
            credential_target_prefix=raw["credential_target_prefix"],
            credential_references=tuple(credentials),
            provider_bindings=tuple(providers),
            clock_binding=clock,
            clock_attestation_path=raw["clock_attestation_path"],
            live_allowed=raw["live_allowed"],
            safe_to_demo_auto_order=raw["safe_to_demo_auto_order"],
            max_lot=raw["max_lot"],
            promotion_eligible=raw["promotion_eligible"],
            production_execution_ready=raw[
                "production_execution_ready"
            ],
            order_capability=raw["order_capability"],
            schema_version=raw["schema_version"],
        )
    except WindowsLiveCanaryExecutionProviderError:
        raise
    except Exception as exc:
        raise WindowsLiveCanaryExecutionProviderError(
            "LIVE_EXECUTION_PROVIDER_CONFIGURATION_INVALID"
        ) from exc


def validate_windows_live_canary_execution_provider_configuration(
    config: WindowsLiveCanaryExecutionProviderConfiguration,
    *,
    effect_probe: Callable[[str], object] | None = None,
) -> WindowsLiveCanaryExecutionProviderValidation:
    """Validate a parsed configuration without invoking any effect."""

    if type(config) is not WindowsLiveCanaryExecutionProviderConfiguration:
        raise TypeError(
            "config must be exact WindowsLiveCanaryExecutionProviderConfiguration"
        )
    if effect_probe is not None and not callable(effect_probe):
        raise TypeError("effect_probe must be callable or None")
    return WindowsLiveCanaryExecutionProviderValidation(
        configuration_sha256=config.content_sha256,
        provider_count=len(config.provider_bindings),
        credential_reference_count=len(config.credential_references),
        _seal=_RESULT_SEAL,
    )


def _require_live_policy() -> None:
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
        or execution_policy.EXECUTION_MIN_LOT != MAX_LOT
        or execution_policy.EXECUTION_MAX_LOT != MAX_LOT
    ):
        _reject("CENTRAL_LIVE_LOT_SCOPE_DRIFT")
    symbol_allowed, _symbol_reason = execution_policy.validate_execution_symbol(
        "XAUUSD",
        mode="LIVE",
    )
    lot_allowed, _lot_reason = execution_policy.validate_execution_lot(MAX_LOT)
    if symbol_allowed is not True or lot_allowed is not True:
        _reject("CENTRAL_LIVE_EXECUTION_SCOPE_INVALID")


def _invoke_effect(
    callback: Callable[..., object],
    *,
    reason_code: str,
    args: tuple[object, ...] = (),
    kwargs: Mapping[str, object] | None = None,
) -> object:
    _require_live_policy()
    try:
        result = callback(*args, **dict(kwargs or {}))
    except WindowsLiveCanaryExecutionProviderError:
        _require_live_policy()
        raise
    except Exception as exc:
        _require_live_policy()
        raise WindowsLiveCanaryExecutionProviderError(reason_code) from exc
    _require_live_policy()
    return result


def _require_runtime_authority(
    config: ProductionRuntimeConfig,
    *,
    live_candidate: object,
    live_launch_session: object,
    now: datetime,
) -> None:
    try:
        _require_live_runtime_authority(
            config,
            live_candidate=live_candidate,
            live_launch_session=live_launch_session,
            now=now,
        )
    except ProductionBootstrapError as exc:
        raise WindowsLiveCanaryExecutionProviderError(
            str(exc).split(":", 1)[0]
        ) from exc
    except Exception as exc:
        raise WindowsLiveCanaryExecutionProviderError(
            "LIVE_EXECUTION_RUNTIME_SOURCE_INVALID"
        ) from exc


def seal_windows_live_canary_runtime_source(
    *,
    config: ProductionRuntimeConfig,
    live_candidate: object,
    live_launch_session: object,
    source_sha256: str,
    now: datetime | None = None,
) -> WindowsLiveCanaryRuntimeSource:
    """Seal an already verified, current LIVE authority triple."""

    if type(config) is not ProductionRuntimeConfig:
        _reject("LIVE_EXECUTION_RUNTIME_CONFIG_NOT_EXACT")
    checked_at = (
        getattr(live_launch_session, "activated_at_utc", None)
        if now is None
        else now
    )
    try:
        verified_at = require_utc("LIVE runtime source time", checked_at)
    except Exception as exc:
        raise WindowsLiveCanaryExecutionProviderError(
            "LIVE_EXECUTION_RUNTIME_SOURCE_TIME_INVALID"
        ) from exc
    _require_live_policy()
    _require_runtime_authority(
        config,
        live_candidate=live_candidate,
        live_launch_session=live_launch_session,
        now=verified_at,
    )
    return WindowsLiveCanaryRuntimeSource(
        config=config,
        live_candidate=live_candidate,
        live_launch_session=live_launch_session,
        source_sha256=source_sha256,
        verified_at_utc=verified_at,
        _seal=_RUNTIME_SOURCE_SEAL,
    )


def _service_configuration_sha256(value: Mapping[str, object]) -> str:
    raw = _mapping(
        value,
        _SERVICE_CONFIGURATION_FIELDS,
        "LIVE_EXECUTION_RUNTIME_CONFIGURATION_INVALID",
    )
    for name in ("service_id", "owner_id"):
        item = raw[name]
        if type(item) is not str or _ID.fullmatch(item) is None or len(item) > 64:
            _reject("LIVE_EXECUTION_RUNTIME_CONFIGURATION_INVALID")
    for name, minimum, maximum in (
        ("max_cycles", 1, 100_000),
        ("lease_seconds", 1, 300),
        ("heartbeat_ttl_seconds", 2, 30),
    ):
        item = raw[name]
        if type(item) is not int or not minimum <= item <= maximum:
            _reject("LIVE_EXECUTION_RUNTIME_CONFIGURATION_INVALID")
    heartbeat = raw["heartbeat_ttl_seconds"]
    interval = raw["cycle_interval_seconds"]
    deadline = raw["cycle_deadline_seconds"]
    if (
        isinstance(interval, bool)
        or not isinstance(interval, (int, float))
        or not math.isfinite(float(interval))
        or not 0.25 <= float(interval) <= min(15.0, float(heartbeat) / 2.0)
        or isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(float(deadline))
        or not 1.0 <= float(deadline) <= float(heartbeat)
    ):
        _reject("LIVE_EXECUTION_RUNTIME_CONFIGURATION_INVALID")
    raw["cycle_interval_seconds"] = float(interval)
    raw["cycle_deadline_seconds"] = float(deadline)
    return hashlib.sha256(_canonical_bytes(raw, newline=True)).hexdigest()


def _provider_reference(
    *,
    config: WindowsLiveCanaryExecutionProviderConfiguration,
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
        _reject("LIVE_EXECUTION_PROVIDER_CREDENTIAL_MISMATCH")
    return matches[0]


def _read_provider_value(
    *,
    hooks: WindowsLiveCanaryProviderMaterializationHooks,
    binding: ExecutionProviderBinding,
    credential_reference: ExecutionCredentialReference | None,
    provider_config: WindowsLiveCanaryExecutionProviderConfiguration,
    production_config: ProductionRuntimeConfig,
    credential_backend: object,
    clock_provider: Callable[[], object],
) -> object:
    value = _invoke_effect(
        hooks.provider_state_reader,
        reason_code="LIVE_EXECUTION_PROVIDER_STATE_UNAVAILABLE",
        kwargs={
            "binding": binding,
            "credential_reference": credential_reference,
            "provider_config": provider_config,
            "production_config": production_config,
            "credential_backend": credential_backend,
            "clock_provider": clock_provider,
            "sqlite_opener": hooks.sqlite_opener,
            "network_sender": hooks.network_sender,
        },
    )
    if binding.port_name == "heartbeat_transport":
        if type(value) is not WindowsExecutionHeartbeatTransport:
            _reject("LIVE_EXECUTION_HEARTBEAT_TRANSPORT_INVALID")
        return value
    if binding.provider_kind == "CALLABLE":
        if not callable(value):
            _reject("LIVE_EXECUTION_PROVIDER_VALUE_INVALID")
    elif value is None:
        _reject("LIVE_EXECUTION_PROVIDER_VALUE_INVALID")
    return value


def _guarded_key_provider(
    provider: Callable[[str], str | bytes],
    *,
    reason_code: str,
) -> Callable[[str], str | bytes]:
    def guarded(key_id: str) -> str | bytes:
        value = _invoke_effect(
            provider,
            reason_code=reason_code,
            args=(key_id,),
        )
        if not isinstance(value, (str, bytes)) or not value:
            _reject(reason_code)
        return value

    return guarded


def build_windows_live_canary_execution_factory_result(
    *,
    runtime_config: Mapping[str, object],
    factory_context: object,
    provider_config: WindowsLiveCanaryExecutionProviderConfiguration,
    hooks: WindowsLiveCanaryProviderMaterializationHooks | None = None,
    platform: str | None = None,
) -> WindowsServiceFactoryResult:
    """Compose one sealed LIVE bootstrap without importing MT5 or ordering."""

    observed_platform = sys.platform if platform is None else platform
    if observed_platform != "win32":
        _reject("WINDOWS_PLATFORM_REQUIRED")
    if not isinstance(runtime_config, Mapping):
        _reject("LIVE_EXECUTION_RUNTIME_CONFIGURATION_INVALID")
    if type(factory_context) is not WindowsServiceFactoryContext:
        _reject("LIVE_EXECUTION_FACTORY_CONTEXT_INVALID")
    if type(provider_config) is not WindowsLiveCanaryExecutionProviderConfiguration:
        _reject("LIVE_EXECUTION_PROVIDER_CONFIGURATION_INVALID")
    service_config_sha256 = _service_configuration_sha256(runtime_config)
    if (
        service_config_sha256 != provider_config.service_config_file_sha256
        or factory_context.service_config_file_sha256
        != provider_config.service_config_file_sha256
    ):
        _reject("LIVE_EXECUTION_SERVICE_CONFIGURATION_BINDING_MISMATCH")
    _require_live_policy()
    if hooks is None:
        _reject("LIVE_EXECUTION_PROVIDER_RUNTIME_NOT_CONFIGURED")
    if type(hooks) is not WindowsLiveCanaryProviderMaterializationHooks:
        _reject("LIVE_EXECUTION_MATERIALIZATION_HOOKS_INVALID")

    source = _invoke_effect(
        hooks.runtime_source_reader,
        reason_code="LIVE_EXECUTION_RUNTIME_SOURCE_UNAVAILABLE",
        args=(provider_config,),
    )
    if type(source) is not WindowsLiveCanaryRuntimeSource:
        _reject("LIVE_EXECUTION_RUNTIME_SOURCE_INVALID")
    production_config = source.config
    if (
        source.source_sha256 != provider_config.production_config_sha256
        or production_config.safe_binding_sha256
        != factory_context.bootstrap_binding_sha256
        or production_config.environment != "LIVE"
        or production_config.mode != "LIVE"
        or production_config.live_allowed is not False
        or production_config.safe_to_demo_auto_order is not False
        or production_config.order_capability != "DISABLED"
        or production_config.config_sha256
        != source.live_candidate.content_sha256
        or source.live_launch_session.candidate_sha256
        != source.live_candidate.content_sha256
    ):
        _reject("LIVE_EXECUTION_RUNTIME_SOURCE_BINDING_MISMATCH")
    _require_runtime_authority(
        production_config,
        live_candidate=source.live_candidate,
        live_launch_session=source.live_launch_session,
        now=source.verified_at_utc,
    )

    clock_provider = _invoke_effect(
        hooks.clock_attestation_reader,
        reason_code="LIVE_EXECUTION_CLOCK_PROVIDER_UNAVAILABLE",
        kwargs={
            "binding": provider_config.clock_binding,
            "path": provider_config.clock_attestation_path,
            "credential_reference": None,
            "credential_backend": None,
        },
    )
    if not callable(clock_provider):
        _reject("LIVE_EXECUTION_CLOCK_PROVIDER_INVALID")
    observed_at = _invoke_effect(
        clock_provider,
        reason_code="LIVE_EXECUTION_CLOCK_READ_FAILED",
    )
    try:
        trusted_now = require_utc("LIVE trusted clock", observed_at)
    except Exception as exc:
        raise WindowsLiveCanaryExecutionProviderError(
            "LIVE_EXECUTION_CLOCK_VALUE_INVALID"
        ) from exc
    _require_runtime_authority(
        production_config,
        live_candidate=source.live_candidate,
        live_launch_session=source.live_launch_session,
        now=trusted_now,
    )

    credential_backend = _invoke_effect(
        hooks.credential_backend_factory,
        reason_code="LIVE_EXECUTION_CREDENTIAL_BACKEND_UNAVAILABLE",
        kwargs={
            "target_prefix": provider_config.credential_target_prefix,
            "references": provider_config.credential_references,
        },
    )
    if credential_backend is None:
        _reject("LIVE_EXECUTION_CREDENTIAL_BACKEND_INVALID")

    values: dict[str, object] = {"clock_provider": clock_provider}
    for binding in provider_config.provider_bindings:
        if binding.port_name == "clock_provider":
            continue
        contract = _CONTRACT_BY_ROLE[binding.port_name]
        if not contract.required:
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
        _reject("LIVE_EXECUTION_RUNTIME_PORT_SET_INVALID")
    try:
        ports = ProductionRuntimePorts(
            mt5_module=None,
            **{name: values[name] for name in runtime_port_names},
        )
        bootstrap = ProductionRuntimeBootstrap(
            production_config,
            ports,
            live_candidate=source.live_candidate,
            live_launch_session=source.live_launch_session,
        )
    except Exception as exc:
        raise WindowsLiveCanaryExecutionProviderError(
            "LIVE_EXECUTION_BOOTSTRAP_CONFIGURATION_INVALID"
        ) from exc
    _require_live_policy()

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
        _reject("LIVE_EXECUTION_HEARTBEAT_PROVIDER_INVALID")
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
        _reject("LIVE_EXECUTION_HEARTBEAT_CREDENTIAL_INVALID")
    guarded_sender = _guarded_key_provider(
        sender_provider,
        reason_code="LIVE_EXECUTION_HEARTBEAT_SENDER_KEY_UNAVAILABLE",
    )
    guarded_remote = _guarded_key_provider(
        remote_provider,
        reason_code="LIVE_EXECUTION_HEARTBEAT_REMOTE_KEY_UNAVAILABLE",
    )
    try:
        result = seal_windows_service_factory_result(
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
            heartbeat_sender_key_provider=guarded_sender,
            heartbeat_remote_key_provider=guarded_remote,
            clock_provider=clock_provider,
        )
    except WindowsLiveCanaryExecutionProviderError:
        raise
    except Exception as exc:
        raise WindowsLiveCanaryExecutionProviderError(
            "LIVE_EXECUTION_FACTORY_RESULT_INVALID"
        ) from exc
    _require_live_policy()
    return result


__all__ = [
    "LIVE_EXECUTION_CREDENTIAL_PURPOSES",
    "LIVE_EXECUTION_CREDENTIAL_TARGET_PREFIX",
    "LIVE_EXECUTION_PROVIDER_ROLES",
    "LIVE_WINDOWS_FACTORY_PROVIDER_CONTRACT_SET_SHA256",
    "WindowsLiveCanaryExecutionProviderConfiguration",
    "WindowsLiveCanaryExecutionProviderError",
    "WindowsLiveCanaryExecutionProviderValidation",
    "WindowsLiveCanaryProviderMaterializationHooks",
    "WindowsLiveCanaryRuntimeSource",
    "build_windows_live_canary_execution_factory_result",
    "live_provider_contracts",
    "seal_windows_live_canary_runtime_source",
    "validate_windows_live_canary_execution_provider_configuration",
    "windows_live_canary_execution_provider_configuration_from_dict",
    "windows_live_canary_execution_provider_configuration_from_json",
]
