"""Offline generator for one secret-free Windows Execution provider pack.

The generator verifies the exact Execution role in an atomic base suite and
writes four deterministic overlay files.  It never imports a generated
provider, resolves a credential, opens SQLite, reads provider state, starts a
process, imports MetaTrader5, installs a task, or performs broker work.
"""

from __future__ import annotations

import ast
from dataclasses import InitVar, dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PureWindowsPath
import re
import stat
from typing import Any, Mapping
import zipfile

from .contracts import canonical_sha256
from .windows_base_release_suite import (
    BaseReleaseSuiteVerificationError,
    VerifiedBaseReleaseSuite,
    VerifiedBaseReleaseSuiteRole,
    suite_binding_for_base_archive,
    verify_base_release_suite,
)
from .windows_service_factory_template import (
    ExternalProviderContract,
    provider_contracts,
)


PACK_INPUT_SCHEMA = "windows-execution-provider-pack-input-v1"
PACK_VALIDATION_SCHEMA = (
    "windows-execution-provider-pack-validation-v1"
)
PACK_STATUS = "EXTERNAL_PROVIDER_ACCEPTANCE_REQUIRED"
LIVE_PACK_INPUT_SCHEMA = (
    "windows-live-canary-execution-provider-pack-input-v1"
)
LIVE_PACK_VALIDATION_SCHEMA = (
    "windows-live-canary-execution-provider-pack-validation-v1"
)
LIVE_PACK_STATUS = "EXTERNAL_LIVE_PROVIDER_ACCEPTANCE_REQUIRED"
EXECUTION_PROFILE = "WINDOWS_GATED_EXECUTION_SERVICE_V1"
FOUNDATION_PATHS = (
    "live_runtime/windows_execution_provider_pack.py",
    "live_runtime/windows_provider_primitives.py",
)
LIVE_FOUNDATION_PATHS = (
    "live_runtime/windows_live_canary_execution_provider.py",
    *FOUNDATION_PATHS,
)
GENERATED_PATHS = (
    "config/windows_service_config.json",
    "configured_providers/__init__.py",
    "configured_providers/execution_provider.py",
    "reviewed_windows_factory.py",
)
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_BASE_ARCHIVE_BYTES = 256 * 1024 * 1024
ORDER_CAPABILITY = "DISABLED"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_LOT = 0.01
PROMOTION_ELIGIBLE = False
PRODUCTION_EXECUTION_READY = False
EXECUTION_CREDENTIAL_TARGET_PREFIX = (
    "AI_SCALPER/WINDOWS_SERVICE/EXECUTION"
)
LIVE_EXECUTION_CREDENTIAL_TARGET_PREFIX = (
    "AI_SCALPER/WINDOWS_SERVICE/LIVE_EXECUTION"
)

_CONTRACTS = provider_contracts()
EXECUTION_PROVIDER_ROLES = tuple(
    item.port_name for item in _CONTRACTS
)
EXECUTION_CREDENTIAL_PURPOSES = tuple(
    item.credential_purpose
    for item in _CONTRACTS
    if item.credential_purpose is not None
)


def _live_contracts() -> tuple[ExternalProviderContract, ...]:
    result: list[ExternalProviderContract] = []
    for contract in _CONTRACTS:
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
                call_contract=(
                    "Callable[...,RuntimeLiveCanaryExecutionResult]"
                ),
                required=True,
                credential_purpose=None,
            ),
        )
    )
    return tuple(result)


_LIVE_CONTRACTS = _live_contracts()
LIVE_EXECUTION_PROVIDER_CONTRACTS = _LIVE_CONTRACTS
LIVE_EXECUTION_PROVIDER_ROLES = tuple(
    item.port_name for item in _LIVE_CONTRACTS
)
LIVE_EXECUTION_CREDENTIAL_PURPOSES = tuple(
    item.credential_purpose
    for item in _LIVE_CONTRACTS
    if item.credential_purpose is not None
)
LIVE_EXECUTION_PROVIDER_CONTRACT_SET_SHA256 = canonical_sha256(
    [
        {
            "call_contract": item.call_contract,
            "contract_sha256": item.contract_sha256,
            "credential_purpose": item.credential_purpose,
            "port_name": item.port_name,
            "provider_kind": item.provider_kind,
            "required": item.required,
            "schema_version": item.schema_version,
        }
        for item in _LIVE_CONTRACTS
    ]
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
if (
    len(_LIVE_CONTRACTS) != 49
    or len(LIVE_EXECUTION_CREDENTIAL_PURPOSES) != 12
    or sum(item.required for item in _LIVE_CONTRACTS) != 40
    or {
        item.port_name for item in _LIVE_CONTRACTS if not item.required
    }
    != _LIVE_FORBIDDEN_PROVIDER_PORTS
):
    raise RuntimeError("Windows LIVE provider-pack contract invariant drift")

_HASH = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REASON = re.compile(r"^[A-Z][A-Z0-9_]*$")
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
_SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bgh[oprsu]_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
)
_SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "arm",
        "arm_flag",
        "login",
        "password",
        "permit",
        "private_key",
        "refresh_token",
        "secret",
        "token",
    }
)
_INPUT_FIELDS = frozenset(
    {"provider_configuration", "schema_version", "service_config"}
)
_SERVICE_FIELDS = frozenset(
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
_PROVIDER_CORE_FIELDS = frozenset(
    {
        "clock_attestation_path",
        "clock_binding",
        "credential_references",
        "credential_target_prefix",
        "live_allowed",
        "max_lot",
        "order_capability",
        "pack_id",
        "production_config_sha256",
        "production_execution_ready",
        "promotion_eligible",
        "runtime_mode",
        "safe_to_demo_auto_order",
        "schema_version",
    }
)
_PROVIDER_CONFIGURATION_FIELDS = _PROVIDER_CORE_FIELDS | frozenset(
    {
        "base_suite_identity_sha256",
        "execution_base_release_identity_sha256",
        "provider_bindings",
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
_CLOCK_FIELDS = frozenset(
    {
        "authority_issuer_id",
        "authority_key_fingerprint_sha256",
        "authority_key_id",
        "host_identity_sha256",
        "maximum_absolute_drift_ms",
        "maximum_attestation_age_ms",
        "provider_id",
        "schema_version",
    }
)
_SAFETY = {
    "live_allowed": False,
    "max_lot": 0.01,
    "order_capability": "DISABLED",
    "production_execution_ready": False,
    "promotion_eligible": False,
    "safe_to_demo_auto_order": False,
}
_FACTORY_IMPORTS = frozenset(
    {"configured_providers.execution_provider"}
)
_PROVIDER_IMPORTS = frozenset(
    {
        "json",
        "live_runtime.windows_execution_provider_pack",
    }
)
_LIVE_PROVIDER_IMPORTS = frozenset(
    {
        "json",
        "live_runtime.windows_live_canary_execution_provider",
    }
)
_RESULT_SEAL = object()


class ExecutionProviderPackError(RuntimeError):
    """One pack failed closed with a stable, non-secret reason code."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: str) -> None:
        normalized = str(reason_code or "").strip().upper()
        if _REASON.fullmatch(normalized) is None:
            normalized = "EXECUTION_PROVIDER_PACK_INVALID"
        self.reason_code = normalized
        super().__init__(normalized)


@dataclass(frozen=True, slots=True)
class StaticExecutionCredentialReference:
    """Pure-data credential reference used only by offline tooling."""

    fingerprint_sha256: str
    key_id: str
    purpose: str
    reference_id: str
    target_name: str


@dataclass(frozen=True, slots=True)
class StaticExecutionProviderBinding:
    """Pure-data provider binding used only by offline tooling."""

    configuration_sha256: str
    contract_sha256: str
    credential_reference_id: str | None
    implementation_sha256: str
    port_name: str
    provider_id: str
    provider_kind: str


@dataclass(frozen=True, slots=True)
class StaticWindowsExecutionProviderConfiguration:
    """Validated configuration view with no runtime provider dependency."""

    pack_id: str
    runtime_mode: str
    base_suite_identity_sha256: str
    execution_base_release_identity_sha256: str
    production_config_sha256: str
    service_config_file_sha256: str
    credential_target_prefix: str
    credential_references: tuple[
        StaticExecutionCredentialReference, ...
    ]
    provider_bindings: tuple[StaticExecutionProviderBinding, ...]
    clock_binding: Mapping[str, Any]
    clock_attestation_path: str
    content_sha256: str


@dataclass(frozen=True, slots=True)
class WindowsExecutionProviderPackValidation:
    """Pure-data receipt for one exact, deny-only provider pack."""

    output_root: str
    pack_id: str
    pack_identity_sha256: str
    base_suite_identity_sha256: str
    execution_base_release_identity_sha256: str
    provider_configuration_sha256: str
    service_config_file_sha256: str
    file_sha256: tuple[tuple[str, str], ...]
    provider_count: int
    credential_reference_count: int
    status: str = PACK_STATUS
    provider_accepted: bool = False
    provider_materialized: bool = False
    credential_access_performed: bool = False
    sqlite_open_performed: bool = False
    provider_request_performed: bool = False
    runtime_process_started: bool = False
    mt5_initialized: bool = False
    network_access_performed: bool = False
    task_installation_performed: bool = False
    broker_mutation_performed: bool = False
    production_execution_ready: bool = False
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    max_lot: float = MAX_LOT
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    schema_version: str = PACK_VALIDATION_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _RESULT_SEAL:
            raise TypeError(
                "execution provider pack validation requires seal"
            )
        hashes = (
            self.pack_identity_sha256,
            self.base_suite_identity_sha256,
            self.execution_base_release_identity_sha256,
            self.provider_configuration_sha256,
            self.service_config_file_sha256,
        )
        if (
            type(self.output_root) is not str
            or not self.output_root
            or _ID.fullmatch(self.pack_id) is None
            or any(
                _HASH.fullmatch(value) is None or value == "0" * 64
                for value in hashes
            )
            or tuple(path for path, _value in self.file_sha256)
            != GENERATED_PATHS
            or any(
                _HASH.fullmatch(value) is None
                for _path, value in self.file_sha256
            )
            or self.provider_count != len(EXECUTION_PROVIDER_ROLES)
            or self.credential_reference_count
            != len(EXECUTION_CREDENTIAL_PURPOSES)
            or self.status != PACK_STATUS
            or self.provider_accepted is not False
            or self.provider_materialized is not False
            or self.credential_access_performed is not False
            or self.sqlite_open_performed is not False
            or self.provider_request_performed is not False
            or self.runtime_process_started is not False
            or self.mt5_initialized is not False
            or self.network_access_performed is not False
            or self.task_installation_performed is not False
            or self.broker_mutation_performed is not False
            or self.production_execution_ready is not False
            or self.order_capability != ORDER_CAPABILITY
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or self.max_lot != MAX_LOT
            or self.promotion_eligible is not False
            or self.schema_version != PACK_VALIDATION_SCHEMA
        ):
            raise ValueError(
                "execution provider pack validation safety drift"
            )


@dataclass(frozen=True, slots=True)
class WindowsLiveCanaryExecutionProviderPackValidation:
    """Pure-data receipt for one exact, deny-only LIVE provider pack."""

    output_root: str
    pack_id: str
    pack_identity_sha256: str
    base_suite_identity_sha256: str
    execution_base_release_identity_sha256: str
    provider_configuration_sha256: str
    service_config_file_sha256: str
    file_sha256: tuple[tuple[str, str], ...]
    provider_count: int
    credential_reference_count: int
    status: str = LIVE_PACK_STATUS
    provider_accepted: bool = False
    provider_materialized: bool = False
    credential_access_performed: bool = False
    sqlite_open_performed: bool = False
    provider_request_performed: bool = False
    runtime_process_started: bool = False
    mt5_initialized: bool = False
    network_access_performed: bool = False
    task_installation_performed: bool = False
    broker_mutation_performed: bool = False
    production_execution_ready: bool = False
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    max_lot: float = MAX_LOT
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    schema_version: str = LIVE_PACK_VALIDATION_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _RESULT_SEAL:
            raise TypeError(
                "LIVE execution provider pack validation requires seal"
            )
        hashes = (
            self.pack_identity_sha256,
            self.base_suite_identity_sha256,
            self.execution_base_release_identity_sha256,
            self.provider_configuration_sha256,
            self.service_config_file_sha256,
        )
        if (
            type(self.output_root) is not str
            or not self.output_root
            or _ID.fullmatch(self.pack_id) is None
            or any(
                _HASH.fullmatch(value) is None or value == "0" * 64
                for value in hashes
            )
            or tuple(path for path, _value in self.file_sha256)
            != GENERATED_PATHS
            or any(
                _HASH.fullmatch(value) is None
                for _path, value in self.file_sha256
            )
            or self.provider_count != len(LIVE_EXECUTION_PROVIDER_ROLES)
            or self.credential_reference_count
            != len(LIVE_EXECUTION_CREDENTIAL_PURPOSES)
            or self.status != LIVE_PACK_STATUS
            or self.provider_accepted is not False
            or self.provider_materialized is not False
            or self.credential_access_performed is not False
            or self.sqlite_open_performed is not False
            or self.provider_request_performed is not False
            or self.runtime_process_started is not False
            or self.mt5_initialized is not False
            or self.network_access_performed is not False
            or self.task_installation_performed is not False
            or self.broker_mutation_performed is not False
            or self.production_execution_ready is not False
            or self.order_capability != ORDER_CAPABILITY
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or self.max_lot != MAX_LOT
            or self.promotion_eligible is not False
            or self.schema_version != LIVE_PACK_VALIDATION_SCHEMA
        ):
            raise ValueError(
                "LIVE execution provider pack validation safety drift"
            )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(
    value: object,
    *,
    newline: bool = False,
) -> bytes:
    try:
        result = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_DOCUMENT_INVALID"
        ) from exc
    return result + (b"\n" if newline else b"")


def _duplicates(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _strict_json(data: bytes, *, canonical: bool) -> dict[str, Any]:
    if (
        type(data) is not bytes
        or not data
        or len(data) > MAX_FILE_BYTES
    ):
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_INPUT_INVALID"
        )
    try:
        parsed = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON")
            ),
        )
    except (
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_INPUT_INVALID"
        ) from exc
    if type(parsed) is not dict:
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_INPUT_INVALID"
        )
    if canonical and data != _canonical_bytes(parsed, newline=True):
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_INPUT_NONCANONICAL"
        )
    return parsed


def _mapping(
    value: object,
    fields: frozenset[str],
    reason_code: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ExecutionProviderPackError(reason_code)
    return dict(value)


def _identifier(value: object, reason_code: str) -> str:
    if (
        type(value) is not str
        or _ID.fullmatch(value) is None
        or value != value.strip()
    ):
        raise ExecutionProviderPackError(reason_code)
    return value


def _hash(value: object, reason_code: str) -> str:
    if (
        type(value) is not str
        or _HASH.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise ExecutionProviderPackError(reason_code)
    return value


def _unique_casefold(
    values: tuple[str, ...],
    reason_code: str,
) -> None:
    if len(values) != len({item.casefold() for item in values}):
        raise ExecutionProviderPackError(reason_code)


def _windows_file_path(value: object) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PATH_INVALID"
        )
    if (
        value.startswith(("\\\\", "//"))
        or "\x00" in value
        or "/" in value
    ):
        raise ExecutionProviderPackError(
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
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PATH_INVALID"
        )
    for part in parsed.parts[1:]:
        if (
            ":" in part
            or part.rstrip(" .") != part
            or part.split(".", 1)[0].casefold() in _WINDOWS_RESERVED
            or any(ord(character) < 32 for character in part)
        ):
            raise ExecutionProviderPackError(
                "EXECUTION_PROVIDER_PATH_INVALID"
            )
    return str(parsed)


def _clock_binding(value: object) -> dict[str, Any]:
    clock = _mapping(
        value,
        _CLOCK_FIELDS,
        "EXECUTION_CLOCK_BINDING_INVALID",
    )
    for name in (
        "provider_id",
        "authority_issuer_id",
        "authority_key_id",
    ):
        item = clock[name]
        if type(item) is not str or not item.strip():
            raise ExecutionProviderPackError(
                "EXECUTION_CLOCK_BINDING_INVALID"
            )
        clock[name] = item.strip()
    for name in (
        "host_identity_sha256",
        "authority_key_fingerprint_sha256",
    ):
        clock[name] = _hash(
            clock[name],
            "EXECUTION_CLOCK_BINDING_INVALID",
        )
    for name, minimum, maximum in (
        ("maximum_attestation_age_ms", 1, 60_000),
        ("maximum_absolute_drift_ms", 0, 1_000),
    ):
        item = clock[name]
        if (
            type(item) is not int
            or not minimum <= item <= maximum
        ):
            raise ExecutionProviderPackError(
                "EXECUTION_CLOCK_BINDING_INVALID"
            )
    if clock["schema_version"] != "windows-clock-binding-v1":
        raise ExecutionProviderPackError(
            "EXECUTION_CLOCK_BINDING_INVALID"
        )
    return clock


def _credential_references(
    value: object,
    *,
    target_prefix: str,
    credential_purposes: tuple[str, ...] = EXECUTION_CREDENTIAL_PURPOSES,
) -> tuple[StaticExecutionCredentialReference, ...]:
    if type(value) is not list:
        raise ExecutionProviderPackError(
            "EXECUTION_CREDENTIAL_REFERENCE_SET_INVALID"
        )
    references: list[StaticExecutionCredentialReference] = []
    for item in value:
        raw = _mapping(
            item,
            _CREDENTIAL_FIELDS,
            "EXECUTION_CREDENTIAL_REFERENCE_INVALID",
        )
        reference_id = _identifier(
            raw["reference_id"],
            "EXECUTION_CREDENTIAL_REFERENCE_INVALID",
        )
        key_id = _identifier(
            raw["key_id"],
            "EXECUTION_CREDENTIAL_REFERENCE_INVALID",
        )
        target_name = raw["target_name"]
        purpose = raw["purpose"]
        if (
            type(target_name) is not str
            or not target_name
            or target_name != target_name.strip()
            or "\\" in target_name
            or "//" in target_name
            or any(ord(character) < 32 for character in target_name)
            or type(purpose) is not str
            or not purpose.strip()
            or purpose != purpose.strip().upper()
        ):
            raise ExecutionProviderPackError(
                "EXECUTION_CREDENTIAL_REFERENCE_INVALID"
            )
        fingerprint = _hash(
            raw["fingerprint_sha256"],
            "EXECUTION_CREDENTIAL_REFERENCE_INVALID",
        )
        if target_name != f"{target_prefix}/{key_id}":
            raise ExecutionProviderPackError(
                "EXECUTION_CREDENTIAL_TARGET_MISMATCH"
            )
        references.append(
            StaticExecutionCredentialReference(
                fingerprint_sha256=fingerprint,
                key_id=key_id,
                purpose=purpose,
                reference_id=reference_id,
                target_name=target_name,
            )
        )
    result = tuple(references)
    if (
        len(result) != len(credential_purposes)
        or tuple(item.purpose for item in result)
        != credential_purposes
    ):
        raise ExecutionProviderPackError(
            "EXECUTION_CREDENTIAL_PURPOSE_SET_INVALID"
        )
    _unique_casefold(
        tuple(item.reference_id for item in result),
        "EXECUTION_CREDENTIAL_REFERENCE_DUPLICATE",
    )
    _unique_casefold(
        tuple(item.key_id for item in result),
        "EXECUTION_CREDENTIAL_KEY_DUPLICATE",
    )
    _unique_casefold(
        tuple(item.target_name for item in result),
        "EXECUTION_CREDENTIAL_TARGET_DUPLICATE",
    )
    if len({item.fingerprint_sha256 for item in result}) != len(result):
        raise ExecutionProviderPackError(
            "EXECUTION_CREDENTIAL_FINGERPRINT_REUSED"
        )
    return result


def _static_provider_bindings(
    value: object,
    *,
    references: tuple[StaticExecutionCredentialReference, ...],
    contracts: tuple[ExternalProviderContract, ...] = _CONTRACTS,
    provider_roles: tuple[str, ...] = EXECUTION_PROVIDER_ROLES,
) -> tuple[StaticExecutionProviderBinding, ...]:
    if type(value) is not list:
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_BINDING_SET_INVALID"
        )
    bindings: list[StaticExecutionProviderBinding] = []
    for item in value:
        raw = _mapping(
            item,
            _PROVIDER_FIELDS,
            "EXECUTION_PROVIDER_BINDING_INVALID",
        )
        credential_id = raw["credential_reference_id"]
        if credential_id is not None:
            credential_id = _identifier(
                credential_id,
                "EXECUTION_PROVIDER_BINDING_INVALID",
            )
        provider_kind = raw["provider_kind"]
        if provider_kind not in {"CALLABLE", "COMPONENT"}:
            raise ExecutionProviderPackError(
                "EXECUTION_PROVIDER_BINDING_INVALID"
            )
        bindings.append(
            StaticExecutionProviderBinding(
                configuration_sha256=_hash(
                    raw["configuration_sha256"],
                    "EXECUTION_PROVIDER_BINDING_INVALID",
                ),
                contract_sha256=_hash(
                    raw["contract_sha256"],
                    "EXECUTION_PROVIDER_BINDING_INVALID",
                ),
                credential_reference_id=credential_id,
                implementation_sha256=_hash(
                    raw["implementation_sha256"],
                    "EXECUTION_PROVIDER_BINDING_INVALID",
                ),
                port_name=_identifier(
                    raw["port_name"],
                    "EXECUTION_PROVIDER_BINDING_INVALID",
                ),
                provider_id=_identifier(
                    raw["provider_id"],
                    "EXECUTION_PROVIDER_BINDING_INVALID",
                ),
                provider_kind=provider_kind,
            )
        )
    result = tuple(bindings)
    if (
        len(result) != len(contracts)
        or tuple(item.port_name for item in result)
        != provider_roles
    ):
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_BINDING_SET_INVALID"
        )
    _unique_casefold(
        tuple(item.provider_id for item in result),
        "EXECUTION_PROVIDER_ID_DUPLICATE",
    )
    references_by_id = {
        item.reference_id: item for item in references
    }
    for binding, contract in zip(result, contracts, strict=True):
        if (
            binding.provider_kind != contract.provider_kind
            or binding.contract_sha256 != contract.contract_sha256
        ):
            raise ExecutionProviderPackError(
                "EXECUTION_PROVIDER_CONTRACT_MISMATCH"
            )
        if contract.credential_purpose is None:
            if binding.credential_reference_id is not None:
                raise ExecutionProviderPackError(
                    "EXECUTION_PROVIDER_CREDENTIAL_FORBIDDEN"
                )
        else:
            reference = references_by_id.get(
                binding.credential_reference_id or ""
            )
            if (
                reference is None
                or reference.purpose != contract.credential_purpose
            ):
                raise ExecutionProviderPackError(
                    "EXECUTION_PROVIDER_CREDENTIAL_MISMATCH"
                )
    return result


def static_windows_execution_provider_configuration_from_dict(
    payload: Mapping[str, object],
) -> StaticWindowsExecutionProviderConfiguration:
    """Validate provider configuration without importing runtime effects."""

    raw = _mapping(
        payload,
        _PROVIDER_CONFIGURATION_FIELDS,
        "EXECUTION_PROVIDER_CONFIGURATION_FIELDS_INVALID",
    )
    if (
        raw["schema_version"]
        != "windows-execution-provider-configuration-v1"
        or raw["runtime_mode"] not in {"DEMO", "DEMO_AUTO"}
        or raw["credential_target_prefix"]
        != EXECUTION_CREDENTIAL_TARGET_PREFIX
        or raw["live_allowed"] is not False
        or raw["safe_to_demo_auto_order"] is not False
        or raw["production_execution_ready"] is not False
        or raw["promotion_eligible"] is not False
        or raw["order_capability"] != ORDER_CAPABILITY
        or type(raw["max_lot"]) is not float
        or raw["max_lot"] != MAX_LOT
    ):
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_CONFIGURATION_INVALID"
        )
    pack_id = _identifier(
        raw["pack_id"],
        "EXECUTION_PROVIDER_CONFIGURATION_INVALID",
    )
    references = _credential_references(
        raw["credential_references"],
        target_prefix=EXECUTION_CREDENTIAL_TARGET_PREFIX,
    )
    bindings = _static_provider_bindings(
        raw["provider_bindings"],
        references=references,
    )
    clock = _clock_binding(raw["clock_binding"])
    return StaticWindowsExecutionProviderConfiguration(
        pack_id=pack_id,
        runtime_mode=str(raw["runtime_mode"]),
        base_suite_identity_sha256=_hash(
            raw["base_suite_identity_sha256"],
            "EXECUTION_PROVIDER_CONFIGURATION_INVALID",
        ),
        execution_base_release_identity_sha256=_hash(
            raw["execution_base_release_identity_sha256"],
            "EXECUTION_PROVIDER_CONFIGURATION_INVALID",
        ),
        production_config_sha256=_hash(
            raw["production_config_sha256"],
            "EXECUTION_PROVIDER_CONFIGURATION_INVALID",
        ),
        service_config_file_sha256=_hash(
            raw["service_config_file_sha256"],
            "EXECUTION_PROVIDER_CONFIGURATION_INVALID",
        ),
        credential_target_prefix=EXECUTION_CREDENTIAL_TARGET_PREFIX,
        credential_references=references,
        provider_bindings=bindings,
        clock_binding=clock,
        clock_attestation_path=_windows_file_path(
            raw["clock_attestation_path"]
        ),
        content_sha256=canonical_sha256(raw),
    )


def static_windows_live_canary_execution_provider_configuration_from_dict(
    payload: Mapping[str, object],
) -> StaticWindowsExecutionProviderConfiguration:
    """Validate one LIVE configuration without importing runtime code."""

    raw = _mapping(
        payload,
        _PROVIDER_CONFIGURATION_FIELDS,
        "LIVE_EXECUTION_PROVIDER_CONFIGURATION_FIELDS_INVALID",
    )
    if (
        raw["schema_version"]
        != "windows-live-canary-execution-provider-configuration-v1"
        or raw["runtime_mode"] != "LIVE"
        or raw["credential_target_prefix"]
        != LIVE_EXECUTION_CREDENTIAL_TARGET_PREFIX
        or raw["live_allowed"] is not False
        or raw["safe_to_demo_auto_order"] is not False
        or raw["production_execution_ready"] is not False
        or raw["promotion_eligible"] is not False
        or raw["order_capability"] != ORDER_CAPABILITY
        or type(raw["max_lot"]) is not float
        or raw["max_lot"] != MAX_LOT
    ):
        raise ExecutionProviderPackError(
            "LIVE_EXECUTION_PROVIDER_CONFIGURATION_INVALID"
        )
    pack_id = _identifier(
        raw["pack_id"],
        "LIVE_EXECUTION_PROVIDER_CONFIGURATION_INVALID",
    )
    references = _credential_references(
        raw["credential_references"],
        target_prefix=LIVE_EXECUTION_CREDENTIAL_TARGET_PREFIX,
        credential_purposes=LIVE_EXECUTION_CREDENTIAL_PURPOSES,
    )
    bindings = _static_provider_bindings(
        raw["provider_bindings"],
        references=references,
        contracts=_LIVE_CONTRACTS,
        provider_roles=LIVE_EXECUTION_PROVIDER_ROLES,
    )
    clock = _clock_binding(raw["clock_binding"])
    if (
        clock["authority_key_id"].casefold()
        in {item.key_id.casefold() for item in references}
        or clock["authority_key_fingerprint_sha256"]
        in {item.fingerprint_sha256 for item in references}
    ):
        raise ExecutionProviderPackError(
            "LIVE_EXECUTION_CLOCK_CREDENTIAL_DOMAIN_COLLISION"
        )
    return StaticWindowsExecutionProviderConfiguration(
        pack_id=pack_id,
        runtime_mode="LIVE",
        base_suite_identity_sha256=_hash(
            raw["base_suite_identity_sha256"],
            "LIVE_EXECUTION_PROVIDER_CONFIGURATION_INVALID",
        ),
        execution_base_release_identity_sha256=_hash(
            raw["execution_base_release_identity_sha256"],
            "LIVE_EXECUTION_PROVIDER_CONFIGURATION_INVALID",
        ),
        production_config_sha256=_hash(
            raw["production_config_sha256"],
            "LIVE_EXECUTION_PROVIDER_CONFIGURATION_INVALID",
        ),
        service_config_file_sha256=_hash(
            raw["service_config_file_sha256"],
            "LIVE_EXECUTION_PROVIDER_CONFIGURATION_INVALID",
        ),
        credential_target_prefix=LIVE_EXECUTION_CREDENTIAL_TARGET_PREFIX,
        credential_references=references,
        provider_bindings=bindings,
        clock_binding=clock,
        clock_attestation_path=_windows_file_path(
            raw["clock_attestation_path"]
        ),
        content_sha256=canonical_sha256(raw),
    )


def _reject_sensitive(value: object) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).casefold() in _SENSITIVE_KEYS:
                raise ExecutionProviderPackError(
                    "EXECUTION_PROVIDER_PACK_SECRET_FIELD_FORBIDDEN"
                )
            _reject_sensitive(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_sensitive(item)


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(
        int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    )


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(
            getattr(
                metadata,
                "st_mtime_ns",
                round(float(metadata.st_mtime) * 1_000_000_000),
            )
        ),
    )


def _stable_read(
    path: str | Path,
    *,
    maximum_bytes: int,
    reason_code: str,
) -> bytes:
    target = Path(path).expanduser().absolute()
    descriptor: int | None = None
    try:
        before = target.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or _is_reparse(before)
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            raise OSError("invalid input")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags)
        opened = os.fstat(descriptor)
        if _identity(before) != _identity(opened):
            raise OSError("input changed")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, maximum_bytes + 1),
            )
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise OSError("input too large")
            chunks.append(chunk)
        if _identity(opened) != _identity(os.fstat(descriptor)):
            raise OSError("input changed")
        final = target.lstat()
        if _identity(before) != _identity(final):
            raise OSError("input changed")
        data = b"".join(chunks)
        if len(data) != before.st_size:
            raise OSError("short read")
        return data
    except OSError as exc:
        raise ExecutionProviderPackError(reason_code) from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _service_config(value: object) -> dict[str, Any]:
    config = _mapping(
        value,
        _SERVICE_FIELDS,
        "EXECUTION_SERVICE_CONFIGURATION_INVALID",
    )
    for name in ("service_id", "owner_id"):
        item = config[name]
        if (
            type(item) is not str
            or _ID.fullmatch(item) is None
            or len(item) > 64
        ):
            raise ExecutionProviderPackError(
                "EXECUTION_SERVICE_CONFIGURATION_INVALID"
            )
    for name, minimum, maximum in (
        ("max_cycles", 1, 100_000),
        ("lease_seconds", 1, 300),
        ("heartbeat_ttl_seconds", 2, 30),
    ):
        item = config[name]
        if (
            type(item) is not int
            or not minimum <= item <= maximum
        ):
            raise ExecutionProviderPackError(
                "EXECUTION_SERVICE_CONFIGURATION_INVALID"
            )
    heartbeat = config["heartbeat_ttl_seconds"]
    interval = config["cycle_interval_seconds"]
    deadline = config["cycle_deadline_seconds"]
    if (
        isinstance(interval, bool)
        or not isinstance(interval, (int, float))
        or not 0.25 <= float(interval) <= min(15.0, heartbeat / 2)
        or isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not 1.0 <= float(deadline) <= heartbeat
    ):
        raise ExecutionProviderPackError(
            "EXECUTION_SERVICE_CONFIGURATION_INVALID"
        )
    config["cycle_interval_seconds"] = float(interval)
    config["cycle_deadline_seconds"] = float(deadline)
    return config


def _provider_core(value: object) -> dict[str, Any]:
    core = _mapping(
        value,
        _PROVIDER_CORE_FIELDS,
        "EXECUTION_PROVIDER_CONFIGURATION_INVALID",
    )
    if (
        core["schema_version"]
        != "windows-execution-provider-configuration-v1"
        or core["live_allowed"] is not False
        or core["safe_to_demo_auto_order"] is not False
        or core["production_execution_ready"] is not False
        or core["promotion_eligible"] is not False
        or core["order_capability"] != ORDER_CAPABILITY
        or type(core["max_lot"]) is not float
        or core["max_lot"] != MAX_LOT
    ):
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_CONFIGURATION_INVALID"
        )
    return core


def _live_provider_core(value: object) -> dict[str, Any]:
    core = _mapping(
        value,
        _PROVIDER_CORE_FIELDS,
        "LIVE_EXECUTION_PROVIDER_CONFIGURATION_INVALID",
    )
    if (
        core["schema_version"]
        != "windows-live-canary-execution-provider-configuration-v1"
        or core["runtime_mode"] != "LIVE"
        or core["credential_target_prefix"]
        != LIVE_EXECUTION_CREDENTIAL_TARGET_PREFIX
        or core["live_allowed"] is not False
        or core["safe_to_demo_auto_order"] is not False
        or core["production_execution_ready"] is not False
        or core["promotion_eligible"] is not False
        or core["order_capability"] != ORDER_CAPABILITY
        or type(core["max_lot"]) is not float
        or core["max_lot"] != MAX_LOT
    ):
        raise ExecutionProviderPackError(
            "LIVE_EXECUTION_PROVIDER_CONFIGURATION_INVALID"
        )
    return core


def _validated_input(value: object) -> dict[str, Any]:
    root = _mapping(
        value,
        _INPUT_FIELDS,
        "EXECUTION_PROVIDER_PACK_INPUT_INVALID",
    )
    if root["schema_version"] != PACK_INPUT_SCHEMA:
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_INPUT_INVALID"
        )
    _reject_sensitive(root)
    return {
        "schema_version": PACK_INPUT_SCHEMA,
        "provider_configuration": _provider_core(
            root["provider_configuration"]
        ),
        "service_config": _service_config(root["service_config"]),
    }


def _validated_live_input(value: object) -> dict[str, Any]:
    root = _mapping(
        value,
        _INPUT_FIELDS,
        "LIVE_EXECUTION_PROVIDER_PACK_INPUT_INVALID",
    )
    if root["schema_version"] != LIVE_PACK_INPUT_SCHEMA:
        raise ExecutionProviderPackError(
            "LIVE_EXECUTION_PROVIDER_PACK_INPUT_INVALID"
        )
    _reject_sensitive(root)
    return {
        "schema_version": LIVE_PACK_INPUT_SCHEMA,
        "provider_configuration": _live_provider_core(
            root["provider_configuration"]
        ),
        "service_config": _service_config(root["service_config"]),
    }


def _verify_suite_and_foundation(
    *,
    base_suite_root: str | Path,
    execution_base_release: str | Path,
    foundation_paths: tuple[str, ...] = FOUNDATION_PATHS,
) -> tuple[
    VerifiedBaseReleaseSuite,
    VerifiedBaseReleaseSuiteRole,
    dict[str, bytes],
]:
    try:
        suite = verify_base_release_suite(base_suite_root)
        binding = suite_binding_for_base_archive(
            suite,
            execution_base_release,
            EXECUTION_PROFILE,
        )
        role = suite.role("EXECUTION")
    except (
        BaseReleaseSuiteVerificationError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise ExecutionProviderPackError(
            "EXECUTION_BASE_SUITE_BINDING_MISMATCH"
        ) from exc
    if (
        binding["role"] != "EXECUTION"
        or role.archive_path
        != Path(execution_base_release).expanduser().absolute()
    ):
        raise ExecutionProviderPackError(
            "EXECUTION_BASE_SUITE_BINDING_MISMATCH"
        )
    archive_bytes = _stable_read(
        role.archive_path,
        maximum_bytes=MAX_BASE_ARCHIVE_BYTES,
        reason_code="EXECUTION_BASE_ARCHIVE_INVALID",
    )
    if _sha256(archive_bytes) != role.archive_sha256:
        raise ExecutionProviderPackError(
            "EXECUTION_BASE_ARCHIVE_CHANGED"
        )
    members: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(
            io.BytesIO(archive_bytes),
            "r",
        ) as archive:
            for relative in foundation_paths:
                matches = [
                    item
                    for item in archive.infolist()
                    if item.filename == relative
                ]
                if len(matches) != 1:
                    raise ExecutionProviderPackError(
                        "EXECUTION_PROVIDER_FOUNDATION_MISSING"
                    )
                info = matches[0]
                if (
                    info.is_dir()
                    or info.file_size <= 0
                    or info.file_size > MAX_FILE_BYTES
                ):
                    raise ExecutionProviderPackError(
                        "EXECUTION_PROVIDER_FOUNDATION_MISSING"
                    )
                data = archive.read(info)
                if len(data) != info.file_size:
                    raise ExecutionProviderPackError(
                        "EXECUTION_PROVIDER_FOUNDATION_MISSING"
                    )
                local = Path(__file__).resolve().parents[1] / relative
                try:
                    local_bytes = local.read_bytes()
                except OSError as exc:
                    raise ExecutionProviderPackError(
                        "EXECUTION_PROVIDER_FOUNDATION_LOCAL_MISMATCH"
                    ) from exc
                if data != local_bytes:
                    raise ExecutionProviderPackError(
                        "EXECUTION_PROVIDER_FOUNDATION_LOCAL_MISMATCH"
                    )
                members[relative] = data
    except ExecutionProviderPackError:
        raise
    except (KeyError, OSError, zipfile.BadZipFile) as exc:
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_FOUNDATION_MISSING"
        ) from exc
    return suite, role, members


def _implementation_hashes(
    foundation_files: Mapping[str, bytes],
    *,
    foundation_paths: tuple[str, ...] = FOUNDATION_PATHS,
    provider_roles: tuple[str, ...] = EXECUTION_PROVIDER_ROLES,
    schema_version: str = "windows-execution-provider-implementation-v1",
) -> dict[str, str]:
    if set(foundation_files) != set(foundation_paths):
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_FOUNDATION_MISSING"
        )
    inventory = [
        {
            "path": path,
            "sha256": _sha256(foundation_files[path]),
        }
        for path in foundation_paths
    ]
    return {
        role: canonical_sha256(
            {
                "foundation_files": inventory,
                "role": role,
                "schema_version": schema_version,
            }
        )
        for role in provider_roles
    }


def _credential_by_purpose(
    references: object,
    *,
    credential_purposes: tuple[str, ...] = EXECUTION_CREDENTIAL_PURPOSES,
) -> dict[str, str]:
    if type(references) is not list:
        raise ExecutionProviderPackError(
            "EXECUTION_CREDENTIAL_REFERENCE_SET_INVALID"
        )
    result: dict[str, str] = {}
    for item in references:
        if not isinstance(item, Mapping):
            raise ExecutionProviderPackError(
                "EXECUTION_CREDENTIAL_REFERENCE_SET_INVALID"
            )
        purpose = item.get("purpose")
        reference_id = item.get("reference_id")
        if type(purpose) is not str or type(reference_id) is not str:
            raise ExecutionProviderPackError(
                "EXECUTION_CREDENTIAL_REFERENCE_SET_INVALID"
            )
        if purpose in result:
            raise ExecutionProviderPackError(
                "EXECUTION_CREDENTIAL_REFERENCE_SET_INVALID"
            )
        result[purpose] = reference_id
    if tuple(result) != credential_purposes:
        raise ExecutionProviderPackError(
            "EXECUTION_CREDENTIAL_REFERENCE_SET_INVALID"
        )
    return result


def _provider_bindings(
    *,
    core: Mapping[str, Any],
    foundation_files: Mapping[str, bytes],
    contracts: tuple[ExternalProviderContract, ...] = _CONTRACTS,
    provider_roles: tuple[str, ...] = EXECUTION_PROVIDER_ROLES,
    credential_purposes: tuple[str, ...] = EXECUTION_CREDENTIAL_PURPOSES,
    foundation_paths: tuple[str, ...] = FOUNDATION_PATHS,
    implementation_schema: str = (
        "windows-execution-provider-implementation-v1"
    ),
    role_configuration_schema: str = (
        "windows-execution-provider-role-config-v1"
    ),
    provider_id_prefix: str = "execution-provider",
) -> list[dict[str, Any]]:
    implementations = _implementation_hashes(
        foundation_files,
        foundation_paths=foundation_paths,
        provider_roles=provider_roles,
        schema_version=implementation_schema,
    )
    credentials = _credential_by_purpose(
        core["credential_references"],
        credential_purposes=credential_purposes,
    )
    result: list[dict[str, Any]] = []
    for index, contract in enumerate(contracts, start=1):
        result.append(
            {
                "configuration_sha256": canonical_sha256(
                    {
                        "provider_configuration": core,
                        "role": contract.port_name,
                        "schema_version": role_configuration_schema,
                    }
                ),
                "contract_sha256": contract.contract_sha256,
                "credential_reference_id": (
                    credentials[contract.credential_purpose]
                    if contract.credential_purpose is not None
                    else None
                ),
                "implementation_sha256": implementations[
                    contract.port_name
                ],
                "port_name": contract.port_name,
                "provider_id": f"{provider_id_prefix}-{index:02d}",
                "provider_kind": contract.provider_kind,
            }
        )
    return result


def _provider_module_bytes(
    configuration: Mapping[str, Any],
) -> bytes:
    payload = json.dumps(
        configuration,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return (
        '"""Generated non-secret Windows Execution provider configuration."""\n'
        "\n"
        "import json\n"
        "\n"
        "from live_runtime.windows_execution_provider_pack import (\n"
        "    build_windows_execution_factory_result,\n"
        "    windows_execution_provider_configuration_from_dict,\n"
        ")\n"
        "\n"
        f"_PROVIDER_CONFIGURATION_JSON = {payload!r}\n"
        "\n"
        "\n"
        "def build_execution_factory(runtime_config, context):\n"
        "    provider_config = (\n"
        "        windows_execution_provider_configuration_from_dict(\n"
        "            json.loads(_PROVIDER_CONFIGURATION_JSON)\n"
        "        )\n"
        "    )\n"
        "    return build_windows_execution_factory_result(\n"
        "        runtime_config=runtime_config,\n"
        "        factory_context=context,\n"
        "        provider_config=provider_config,\n"
        "    )\n"
    ).encode("utf-8")


def _factory_bytes() -> bytes:
    return (
        b'"""Generated sealed Execution factory; no activation authority."""\n'
        b"\n"
        b"from configured_providers.execution_provider import (\n"
        b"    build_execution_factory,\n"
        b")\n"
        b"\n"
        b"\n"
        b"def build(runtime_config, context):\n"
        b"    return build_execution_factory(runtime_config, context)\n"
    )


def _initializer_bytes() -> bytes:
    return b'"""Closed generated Windows Execution providers."""\n'


def _generated_files(
    *,
    pack: Mapping[str, Any],
    suite: VerifiedBaseReleaseSuite,
    role: VerifiedBaseReleaseSuiteRole,
    foundation_files: Mapping[str, bytes],
) -> tuple[dict[str, bytes], dict[str, Any]]:
    service = dict(pack["service_config"])
    service_bytes = _canonical_bytes(service, newline=True)
    core = {
        **dict(pack["provider_configuration"]),
        "base_suite_identity_sha256": suite.suite_identity_sha256,
        "execution_base_release_identity_sha256": (
            role.release_identity_sha256
        ),
        "service_config_file_sha256": _sha256(service_bytes),
    }
    bindings = _provider_bindings(
        core=core,
        foundation_files=foundation_files,
    )
    configuration = {**core, "provider_bindings": bindings}
    try:
        parsed = static_windows_execution_provider_configuration_from_dict(
            configuration
        )
    except (ExecutionProviderPackError, TypeError, ValueError) as exc:
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_CONFIGURATION_INVALID"
        ) from exc
    if parsed.content_sha256 != canonical_sha256(configuration):
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_CONFIGURATION_HASH_MISMATCH"
        )
    files = {
        "config/windows_service_config.json": service_bytes,
        "configured_providers/__init__.py": _initializer_bytes(),
        "configured_providers/execution_provider.py": (
            _provider_module_bytes(configuration)
        ),
        "reviewed_windows_factory.py": _factory_bytes(),
    }
    if (
        tuple(sorted(files)) != GENERATED_PATHS
        or sum(len(value) for value in files.values())
        > MAX_TOTAL_BYTES
        or any(
            not value or len(value) > MAX_FILE_BYTES
            for value in files.values()
        )
    ):
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_OUTPUT_INVALID"
        )
    return files, configuration


def _live_provider_module_bytes(
    configuration: Mapping[str, Any],
) -> bytes:
    payload = json.dumps(
        configuration,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return (
        '"""Generated non-secret Windows LIVE Execution configuration."""\n'
        "\n"
        "import json\n"
        "\n"
        "from live_runtime.windows_live_canary_execution_provider import (\n"
        "    build_windows_live_canary_execution_factory_result,\n"
        "    windows_live_canary_execution_provider_configuration_from_dict,\n"
        ")\n"
        "\n"
        f"_PROVIDER_CONFIGURATION_JSON = {payload!r}\n"
        "\n"
        "\n"
        "def build_execution_factory(runtime_config, context):\n"
        "    provider_config = (\n"
        "        windows_live_canary_execution_provider_configuration_from_dict(\n"
        "            json.loads(_PROVIDER_CONFIGURATION_JSON)\n"
        "        )\n"
        "    )\n"
        "    return build_windows_live_canary_execution_factory_result(\n"
        "        runtime_config=runtime_config,\n"
        "        factory_context=context,\n"
        "        provider_config=provider_config,\n"
        "    )\n"
    ).encode("utf-8")


def _live_factory_bytes() -> bytes:
    return (
        b'"""Generated sealed LIVE Execution factory; no authority."""\n'
        b"\n"
        b"from configured_providers.execution_provider import (\n"
        b"    build_execution_factory,\n"
        b")\n"
        b"\n"
        b"\n"
        b"def build(runtime_config, context):\n"
        b"    return build_execution_factory(runtime_config, context)\n"
    )


def _live_initializer_bytes() -> bytes:
    return b'"""Closed generated Windows LIVE Execution providers."""\n'


def _live_generated_files(
    *,
    pack: Mapping[str, Any],
    suite: VerifiedBaseReleaseSuite,
    role: VerifiedBaseReleaseSuiteRole,
    foundation_files: Mapping[str, bytes],
) -> tuple[dict[str, bytes], dict[str, Any]]:
    service = dict(pack["service_config"])
    service_bytes = _canonical_bytes(service, newline=True)
    core = {
        **dict(pack["provider_configuration"]),
        "base_suite_identity_sha256": suite.suite_identity_sha256,
        "execution_base_release_identity_sha256": (
            role.release_identity_sha256
        ),
        "service_config_file_sha256": _sha256(service_bytes),
    }
    bindings = _provider_bindings(
        core=core,
        foundation_files=foundation_files,
        contracts=_LIVE_CONTRACTS,
        provider_roles=LIVE_EXECUTION_PROVIDER_ROLES,
        credential_purposes=LIVE_EXECUTION_CREDENTIAL_PURPOSES,
        foundation_paths=LIVE_FOUNDATION_PATHS,
        implementation_schema=(
            "windows-live-canary-execution-provider-implementation-v1"
        ),
        role_configuration_schema=(
            "windows-live-canary-execution-provider-role-config-v1"
        ),
        provider_id_prefix="live-execution-provider",
    )
    configuration = {**core, "provider_bindings": bindings}
    try:
        parsed = (
            static_windows_live_canary_execution_provider_configuration_from_dict(
                configuration
            )
        )
    except (ExecutionProviderPackError, TypeError, ValueError) as exc:
        raise ExecutionProviderPackError(
            "LIVE_EXECUTION_PROVIDER_CONFIGURATION_INVALID"
        ) from exc
    if parsed.content_sha256 != canonical_sha256(configuration):
        raise ExecutionProviderPackError(
            "LIVE_EXECUTION_PROVIDER_CONFIGURATION_HASH_MISMATCH"
        )
    files = {
        "config/windows_service_config.json": service_bytes,
        "configured_providers/__init__.py": _live_initializer_bytes(),
        "configured_providers/execution_provider.py": (
            _live_provider_module_bytes(configuration)
        ),
        "reviewed_windows_factory.py": _live_factory_bytes(),
    }
    if (
        tuple(sorted(files)) != GENERATED_PATHS
        or sum(len(value) for value in files.values()) > MAX_TOTAL_BYTES
        or any(
            not value or len(value) > MAX_FILE_BYTES
            for value in files.values()
        )
    ):
        raise ExecutionProviderPackError(
            "LIVE_EXECUTION_PROVIDER_PACK_OUTPUT_INVALID"
        )
    return files, configuration


def _imports(source: bytes, reason_code: str) -> frozenset[str]:
    try:
        tree = ast.parse(source.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise ExecutionProviderPackError(reason_code) from exc
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(item.name for item in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0 or not node.module:
                raise ExecutionProviderPackError(reason_code)
            modules.add(node.module)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id
            in {"eval", "exec", "compile", "__import__"}
        ):
            raise ExecutionProviderPackError(reason_code)
    return frozenset(modules)


def _extract_provider_configuration(
    source: bytes,
) -> dict[str, Any]:
    try:
        tree = ast.parse(source.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_MODULE_INVALID"
        ) from exc
    values: list[str] = []
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id
            == "_PROVIDER_CONFIGURATION_JSON"
            and isinstance(node.value, ast.Constant)
            and type(node.value.value) is str
        ):
            values.append(node.value.value)
    if len(values) != 1:
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_MODULE_INVALID"
        )
    try:
        encoded = values[0].encode("ascii") + b"\n"
    except UnicodeEncodeError as exc:
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_MODULE_INVALID"
        ) from exc
    return _strict_json(encoded, canonical=True)


def extract_windows_execution_provider_configuration(
    source: bytes,
) -> dict[str, Any]:
    """Extract generated non-secret configuration without importing code."""

    return _extract_provider_configuration(source)


def extract_windows_live_canary_execution_provider_configuration(
    source: bytes,
) -> dict[str, Any]:
    """Extract generated LIVE configuration without importing code."""

    return _extract_provider_configuration(source)


def _pack_root(path: str | Path) -> Path:
    root = Path(path).expanduser().absolute()
    try:
        metadata = root.lstat()
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_ROOT_INVALID"
        ) from exc
    if (
        root != resolved
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_ROOT_INVALID"
        )
    return root


def _pack_files(root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    try:
        items = sorted(root.rglob("*"))
    except OSError as exc:
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_MEMBER_INVALID"
        ) from exc
    for item in items:
        relative = item.relative_to(root).as_posix()
        try:
            metadata = item.lstat()
        except OSError as exc:
            raise ExecutionProviderPackError(
                "EXECUTION_PROVIDER_PACK_MEMBER_INVALID"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
            raise ExecutionProviderPackError(
                "EXECUTION_PROVIDER_PACK_MEMBER_INVALID"
            )
        if stat.S_ISDIR(metadata.st_mode):
            directories.add(relative)
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or relative not in GENERATED_PATHS
        ):
            raise ExecutionProviderPackError(
                "EXECUTION_PROVIDER_PACK_MEMBER_INVALID"
            )
        files[relative] = _stable_read(
            item,
            maximum_bytes=MAX_FILE_BYTES,
            reason_code="EXECUTION_PROVIDER_PACK_MEMBER_INVALID",
        )
    if (
        set(files) != set(GENERATED_PATHS)
        or directories != {"config", "configured_providers"}
        or sum(len(value) for value in files.values())
        > MAX_TOTAL_BYTES
    ):
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_MEMBER_INVALID"
        )
    return files


def _pack_identity(
    *,
    pack_id: str,
    suite_identity_sha256: str,
    release_identity_sha256: str,
    files: Mapping[str, bytes],
) -> str:
    return canonical_sha256(
        {
            "base_suite_identity_sha256": suite_identity_sha256,
            "execution_base_release_identity_sha256": (
                release_identity_sha256
            ),
            "files": [
                {
                    "path": path,
                    "sha256": _sha256(files[path]),
                    "size_bytes": len(files[path]),
                }
                for path in GENERATED_PATHS
            ],
            "pack_id": pack_id,
            "safety": _SAFETY,
            "schema_version": (
                "windows-execution-provider-pack-identity-v1"
            ),
        }
    )


def _result(
    *,
    root: Path,
    config: StaticWindowsExecutionProviderConfiguration,
    suite: VerifiedBaseReleaseSuite,
    role: VerifiedBaseReleaseSuiteRole,
    files: Mapping[str, bytes],
) -> WindowsExecutionProviderPackValidation:
    pack_id = config.pack_id
    return WindowsExecutionProviderPackValidation(
        output_root=str(root),
        pack_id=pack_id,
        pack_identity_sha256=_pack_identity(
            pack_id=pack_id,
            suite_identity_sha256=suite.suite_identity_sha256,
            release_identity_sha256=role.release_identity_sha256,
            files=files,
        ),
        base_suite_identity_sha256=suite.suite_identity_sha256,
        execution_base_release_identity_sha256=(
            role.release_identity_sha256
        ),
        provider_configuration_sha256=config.content_sha256,
        service_config_file_sha256=_sha256(
            files["config/windows_service_config.json"]
        ),
        file_sha256=tuple(
            (path, _sha256(files[path])) for path in GENERATED_PATHS
        ),
        provider_count=len(config.provider_bindings),
        credential_reference_count=len(config.credential_references),
        _seal=_RESULT_SEAL,
    )


def _live_pack_identity(
    *,
    pack_id: str,
    suite_identity_sha256: str,
    release_identity_sha256: str,
    files: Mapping[str, bytes],
) -> str:
    return canonical_sha256(
        {
            "base_suite_identity_sha256": suite_identity_sha256,
            "execution_base_release_identity_sha256": (
                release_identity_sha256
            ),
            "files": [
                {
                    "path": path,
                    "sha256": _sha256(files[path]),
                    "size_bytes": len(files[path]),
                }
                for path in GENERATED_PATHS
            ],
            "pack_id": pack_id,
            "safety": _SAFETY,
            "schema_version": (
                "windows-live-canary-execution-provider-pack-identity-v1"
            ),
        }
    )


def _live_result(
    *,
    root: Path,
    config: StaticWindowsExecutionProviderConfiguration,
    suite: VerifiedBaseReleaseSuite,
    role: VerifiedBaseReleaseSuiteRole,
    files: Mapping[str, bytes],
) -> WindowsLiveCanaryExecutionProviderPackValidation:
    return WindowsLiveCanaryExecutionProviderPackValidation(
        output_root=str(root),
        pack_id=config.pack_id,
        pack_identity_sha256=_live_pack_identity(
            pack_id=config.pack_id,
            suite_identity_sha256=suite.suite_identity_sha256,
            release_identity_sha256=role.release_identity_sha256,
            files=files,
        ),
        base_suite_identity_sha256=suite.suite_identity_sha256,
        execution_base_release_identity_sha256=(
            role.release_identity_sha256
        ),
        provider_configuration_sha256=config.content_sha256,
        service_config_file_sha256=_sha256(
            files["config/windows_service_config.json"]
        ),
        file_sha256=tuple(
            (path, _sha256(files[path])) for path in GENERATED_PATHS
        ),
        provider_count=len(config.provider_bindings),
        credential_reference_count=len(config.credential_references),
        _seal=_RESULT_SEAL,
    )


def validate_windows_execution_provider_pack(
    *,
    base_suite_root: str | Path,
    execution_base_release: str | Path,
    pack_root: str | Path,
) -> WindowsExecutionProviderPackValidation:
    """Validate exact pack bytes without importing or materializing them."""

    suite, role, foundation = _verify_suite_and_foundation(
        base_suite_root=base_suite_root,
        execution_base_release=execution_base_release,
    )
    root = _pack_root(pack_root)
    files = _pack_files(root)
    if any(
        pattern.search(data)
        for data in files.values()
        for pattern in _SECRET_PATTERNS
    ):
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_SECRET_PATTERN_FORBIDDEN"
        )
    if (
        _imports(
            files["reviewed_windows_factory.py"],
            "EXECUTION_PROVIDER_FACTORY_INVALID",
        )
        != _FACTORY_IMPORTS
        or _imports(
            files["configured_providers/execution_provider.py"],
            "EXECUTION_PROVIDER_MODULE_INVALID",
        )
        != _PROVIDER_IMPORTS
        or files["configured_providers/__init__.py"]
        != _initializer_bytes()
        or files["reviewed_windows_factory.py"]
        != _factory_bytes()
    ):
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_GENERATED_SOURCE_MISMATCH"
        )
    configuration_raw = _extract_provider_configuration(
        files["configured_providers/execution_provider.py"]
    )
    try:
        configuration = (
            static_windows_execution_provider_configuration_from_dict(
                configuration_raw
            )
        )
    except (ExecutionProviderPackError, TypeError, ValueError) as exc:
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_CONFIGURATION_INVALID"
        ) from exc
    if (
        configuration.base_suite_identity_sha256
        != suite.suite_identity_sha256
        or configuration.execution_base_release_identity_sha256
        != role.release_identity_sha256
        or files["configured_providers/execution_provider.py"]
        != _provider_module_bytes(configuration_raw)
    ):
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_BASE_IDENTITY_MISMATCH"
        )
    try:
        service = _service_config(
            _strict_json(
                files["config/windows_service_config.json"],
                canonical=True,
            )
        )
    except ExecutionProviderPackError:
        raise
    if (
        _sha256(_canonical_bytes(service, newline=True))
        != configuration.service_config_file_sha256
    ):
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_SERVICE_CONFIG_MISMATCH"
        )
    core = dict(configuration_raw)
    bindings = core.pop("provider_bindings")
    expected = _provider_bindings(
        core=core,
        foundation_files=foundation,
    )
    if bindings != expected:
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_BINDING_HASH_MISMATCH"
        )
    return _result(
        root=root,
        config=configuration,
        suite=suite,
        role=role,
        files=files,
    )


def validate_windows_live_canary_execution_provider_pack(
    *,
    base_suite_root: str | Path,
    execution_base_release: str | Path,
    pack_root: str | Path,
) -> WindowsLiveCanaryExecutionProviderPackValidation:
    """Validate exact LIVE pack bytes without importing providers."""

    suite, role, foundation = _verify_suite_and_foundation(
        base_suite_root=base_suite_root,
        execution_base_release=execution_base_release,
        foundation_paths=LIVE_FOUNDATION_PATHS,
    )
    root = _pack_root(pack_root)
    files = _pack_files(root)
    if any(
        pattern.search(data)
        for data in files.values()
        for pattern in _SECRET_PATTERNS
    ):
        raise ExecutionProviderPackError(
            "LIVE_EXECUTION_PROVIDER_PACK_SECRET_PATTERN_FORBIDDEN"
        )
    if (
        _imports(
            files["reviewed_windows_factory.py"],
            "LIVE_EXECUTION_PROVIDER_FACTORY_INVALID",
        )
        != _FACTORY_IMPORTS
        or _imports(
            files["configured_providers/execution_provider.py"],
            "LIVE_EXECUTION_PROVIDER_MODULE_INVALID",
        )
        != _LIVE_PROVIDER_IMPORTS
        or files["configured_providers/__init__.py"]
        != _live_initializer_bytes()
        or files["reviewed_windows_factory.py"]
        != _live_factory_bytes()
    ):
        raise ExecutionProviderPackError(
            "LIVE_EXECUTION_PROVIDER_GENERATED_SOURCE_MISMATCH"
        )
    configuration_raw = _extract_provider_configuration(
        files["configured_providers/execution_provider.py"]
    )
    try:
        configuration = (
            static_windows_live_canary_execution_provider_configuration_from_dict(
                configuration_raw
            )
        )
    except (ExecutionProviderPackError, TypeError, ValueError) as exc:
        raise ExecutionProviderPackError(
            "LIVE_EXECUTION_PROVIDER_CONFIGURATION_INVALID"
        ) from exc
    if (
        configuration.base_suite_identity_sha256
        != suite.suite_identity_sha256
        or configuration.execution_base_release_identity_sha256
        != role.release_identity_sha256
        or files["configured_providers/execution_provider.py"]
        != _live_provider_module_bytes(configuration_raw)
    ):
        raise ExecutionProviderPackError(
            "LIVE_EXECUTION_PROVIDER_BASE_IDENTITY_MISMATCH"
        )
    service = _service_config(
        _strict_json(
            files["config/windows_service_config.json"],
            canonical=True,
        )
    )
    if (
        _sha256(_canonical_bytes(service, newline=True))
        != configuration.service_config_file_sha256
    ):
        raise ExecutionProviderPackError(
            "LIVE_EXECUTION_PROVIDER_SERVICE_CONFIG_MISMATCH"
        )
    core = dict(configuration_raw)
    bindings = core.pop("provider_bindings")
    expected = _provider_bindings(
        core=core,
        foundation_files=foundation,
        contracts=_LIVE_CONTRACTS,
        provider_roles=LIVE_EXECUTION_PROVIDER_ROLES,
        credential_purposes=LIVE_EXECUTION_CREDENTIAL_PURPOSES,
        foundation_paths=LIVE_FOUNDATION_PATHS,
        implementation_schema=(
            "windows-live-canary-execution-provider-implementation-v1"
        ),
        role_configuration_schema=(
            "windows-live-canary-execution-provider-role-config-v1"
        ),
        provider_id_prefix="live-execution-provider",
    )
    if bindings != expected:
        raise ExecutionProviderPackError(
            "LIVE_EXECUTION_PROVIDER_BINDING_HASH_MISMATCH"
        )
    return _live_result(
        root=root,
        config=configuration,
        suite=suite,
        role=role,
        files=files,
    )


def _safe_new_root(path: str | Path) -> Path:
    root = Path(path).expanduser().absolute()
    if root.exists() or root.is_symlink():
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_OUTPUT_EXISTS"
        )
    try:
        parent = root.parent.lstat()
    except OSError as exc:
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_OUTPUT_PARENT_INVALID"
        ) from exc
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or _is_reparse(parent)
    ):
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_OUTPUT_PARENT_INVALID"
        )
    return root


def _remove_created_file(
    path: Path,
    identity: tuple[int, int] | None,
) -> None:
    if identity is None:
        return
    try:
        observed = path.lstat()
    except OSError:
        return
    if (
        not stat.S_ISREG(observed.st_mode)
        or _is_reparse(observed)
        or (int(observed.st_dev), int(observed.st_ino)) != identity
    ):
        return
    try:
        path.unlink()
    except OSError:
        pass


def _directory_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _write_exclusive(path: Path, payload: bytes) -> tuple[int, ...]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    created_identity: tuple[int, int] | None = None
    completed_identity: tuple[int, ...] | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        created = os.fstat(descriptor)
        created_identity = (
            int(created.st_dev),
            int(created.st_ino),
        )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.fsync(descriptor)
        completed_identity = _identity(os.fstat(descriptor))
    except OSError as exc:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
            descriptor = None
        _remove_created_file(path, created_identity)
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_OUTPUT_WRITE_FAILED"
        ) from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if completed_identity is None:
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_OUTPUT_WRITE_FAILED"
        )
    return completed_identity


def _cleanup(
    root: Path,
    root_identity: tuple[int, int, int, int] | None,
    files: list[tuple[Path, tuple[int, ...]]],
) -> None:
    if root_identity is None:
        return
    try:
        observed_root = root.lstat()
    except OSError:
        return
    if (
        _directory_identity(observed_root) != root_identity
        or not stat.S_ISDIR(observed_root.st_mode)
        or stat.S_ISLNK(observed_root.st_mode)
        or _is_reparse(observed_root)
    ):
        return
    for target, identity in reversed(files):
        try:
            observed = target.lstat()
            if (
                _identity(observed) == identity
                and stat.S_ISREG(observed.st_mode)
                and not _is_reparse(observed)
            ):
                target.unlink()
        except OSError:
            pass
    for relative in ("configured_providers", "config"):
        try:
            (root / relative).rmdir()
        except OSError:
            pass
    try:
        root.rmdir()
    except OSError:
        pass


def prepare_windows_execution_provider_pack(
    *,
    base_suite_root: str | Path,
    execution_base_release: str | Path,
    pack_input_path: str | Path,
    output_root: str | Path,
) -> WindowsExecutionProviderPackValidation:
    """Generate and independently validate one deterministic pack."""

    suite, role, foundation = _verify_suite_and_foundation(
        base_suite_root=base_suite_root,
        execution_base_release=execution_base_release,
    )
    input_bytes = _stable_read(
        pack_input_path,
        maximum_bytes=MAX_FILE_BYTES,
        reason_code="EXECUTION_PROVIDER_PACK_INPUT_INVALID",
    )
    if any(
        pattern.search(input_bytes) for pattern in _SECRET_PATTERNS
    ):
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_SECRET_PATTERN_FORBIDDEN"
        )
    pack = _validated_input(
        _strict_json(input_bytes, canonical=True)
    )
    files, _configuration = _generated_files(
        pack=pack,
        suite=suite,
        role=role,
        foundation_files=foundation,
    )
    if any(
        pattern.search(data)
        for data in files.values()
        for pattern in _SECRET_PATTERNS
    ):
        raise ExecutionProviderPackError(
            "EXECUTION_PROVIDER_PACK_SECRET_PATTERN_FORBIDDEN"
        )
    root = _safe_new_root(output_root)
    root_identity: tuple[int, int, int, int] | None = None
    created_files: list[tuple[Path, tuple[int, ...]]] = []
    try:
        root.mkdir(mode=0o700)
        root_identity = _directory_identity(root.lstat())
        (root / "config").mkdir(mode=0o700)
        (root / "configured_providers").mkdir(mode=0o700)
        for relative in GENERATED_PATHS:
            target = root / relative
            created_files.append(
                (target, _write_exclusive(target, files[relative]))
            )
        return validate_windows_execution_provider_pack(
            base_suite_root=base_suite_root,
            execution_base_release=execution_base_release,
            pack_root=root,
        )
    except Exception:
        _cleanup(root, root_identity, created_files)
        raise


def prepare_windows_live_canary_execution_provider_pack(
    *,
    base_suite_root: str | Path,
    execution_base_release: str | Path,
    pack_input_path: str | Path,
    output_root: str | Path,
) -> WindowsLiveCanaryExecutionProviderPackValidation:
    """Generate and independently validate one deterministic LIVE pack."""

    suite, role, foundation = _verify_suite_and_foundation(
        base_suite_root=base_suite_root,
        execution_base_release=execution_base_release,
        foundation_paths=LIVE_FOUNDATION_PATHS,
    )
    input_bytes = _stable_read(
        pack_input_path,
        maximum_bytes=MAX_FILE_BYTES,
        reason_code="LIVE_EXECUTION_PROVIDER_PACK_INPUT_INVALID",
    )
    if any(pattern.search(input_bytes) for pattern in _SECRET_PATTERNS):
        raise ExecutionProviderPackError(
            "LIVE_EXECUTION_PROVIDER_PACK_SECRET_PATTERN_FORBIDDEN"
        )
    pack = _validated_live_input(
        _strict_json(input_bytes, canonical=True)
    )
    files, _configuration = _live_generated_files(
        pack=pack,
        suite=suite,
        role=role,
        foundation_files=foundation,
    )
    if any(
        pattern.search(data)
        for data in files.values()
        for pattern in _SECRET_PATTERNS
    ):
        raise ExecutionProviderPackError(
            "LIVE_EXECUTION_PROVIDER_PACK_SECRET_PATTERN_FORBIDDEN"
        )
    root = _safe_new_root(output_root)
    root_identity: tuple[int, int, int, int] | None = None
    created_files: list[tuple[Path, tuple[int, ...]]] = []
    try:
        root.mkdir(mode=0o700)
        root_identity = _directory_identity(root.lstat())
        (root / "config").mkdir(mode=0o700)
        (root / "configured_providers").mkdir(mode=0o700)
        for relative in GENERATED_PATHS:
            target = root / relative
            created_files.append(
                (target, _write_exclusive(target, files[relative]))
            )
        return validate_windows_live_canary_execution_provider_pack(
            base_suite_root=base_suite_root,
            execution_base_release=execution_base_release,
            pack_root=root,
        )
    except Exception:
        _cleanup(root, root_identity, created_files)
        raise


__all__ = [
    "EXECUTION_CREDENTIAL_PURPOSES",
    "EXECUTION_PROVIDER_ROLES",
    "FOUNDATION_PATHS",
    "GENERATED_PATHS",
    "LIVE_EXECUTION_CREDENTIAL_PURPOSES",
    "LIVE_EXECUTION_PROVIDER_CONTRACT_SET_SHA256",
    "LIVE_EXECUTION_PROVIDER_CONTRACTS",
    "LIVE_EXECUTION_PROVIDER_ROLES",
    "LIVE_FOUNDATION_PATHS",
    "LIVE_PACK_INPUT_SCHEMA",
    "LIVE_PACK_STATUS",
    "PACK_INPUT_SCHEMA",
    "ExecutionProviderPackError",
    "StaticWindowsExecutionProviderConfiguration",
    "WindowsLiveCanaryExecutionProviderPackValidation",
    "WindowsExecutionProviderPackValidation",
    "extract_windows_execution_provider_configuration",
    "extract_windows_live_canary_execution_provider_configuration",
    "prepare_windows_execution_provider_pack",
    "prepare_windows_live_canary_execution_provider_pack",
    "static_windows_execution_provider_configuration_from_dict",
    "static_windows_live_canary_execution_provider_configuration_from_dict",
    "validate_windows_execution_provider_pack",
    "validate_windows_live_canary_execution_provider_pack",
]
