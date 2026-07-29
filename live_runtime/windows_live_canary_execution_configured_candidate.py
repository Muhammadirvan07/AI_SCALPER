"""Immutable, deny-only configured candidate for Windows LIVE Execution.

This offline boundary binds an exact LIVE provider pack to the Execution
member of one atomic base suite.  It labels the configured archive ``LIVE``
but deliberately grants no provider acceptance, launch authority, central
unlock, credential access, MT5 initialization, broker mutation, or order
capability.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Mapping
import zipfile
import xml.etree.ElementTree as ElementTree

from .configured_service_release import (
    ConfiguredReleaseError,
    build_configured_service_release,
    prepare_live_canary_configured_overlay_candidate,
    verify_configured_service_release,
)
from .windows_base_release_suite import (
    BaseReleaseSuiteVerificationError,
    verify_base_release_suite,
)
from .windows_execution_provider_pack_generator import (
    GENERATED_PATHS,
    LIVE_EXECUTION_CREDENTIAL_PURPOSES,
    LIVE_EXECUTION_PROVIDER_CONTRACT_SET_SHA256,
    LIVE_EXECUTION_PROVIDER_CONTRACTS,
    LIVE_EXECUTION_PROVIDER_ROLES,
    ExecutionProviderPackError,
    StaticWindowsExecutionProviderConfiguration,
    extract_windows_live_canary_execution_provider_configuration,
    static_windows_live_canary_execution_provider_configuration_from_dict,
    validate_windows_live_canary_execution_provider_pack,
)


CANDIDATE_INPUT_SCHEMA = (
    "windows-live-canary-execution-configured-candidate-input-v1"
)
CANDIDATE_SCHEMA = (
    "windows-live-canary-execution-configured-candidate-v1"
)
CANDIDATE_RECEIPT_NAME = (
    "LIVE_EXECUTION_CONFIGURED_CANDIDATE.json"
)
CANDIDATE_STATUS = "EXTERNAL_LIVE_PROVIDER_CONFORMANCE_REQUIRED"
FACTORY_TEMPLATE_SCHEMA = (
    "windows-live-canary-execution-factory-template-v1"
)
EXECUTION_PROFILE = "WINDOWS_GATED_EXECUTION_SERVICE_V1"
EXECUTION_ROLE = "EXECUTION"
CONFIGURED_ARCHIVE_NAME = "live-execution-configured-v1.zip"
CONFIGURED_SIDECAR_NAME = (
    "live-execution-configured-v1.zip.manifest.json"
)
FACTORY_TEMPLATE_NAME = "live-execution-factory-template.json"
OVERLAY_DESCRIPTOR_NAME = "configured-overlay.json"
TASK_DEFINITION_NAME = "reviewed-task-definition.xml"
LIVE_MATERIALIZER_MEMBER = (
    "live_runtime/windows_live_canary_execution_provider.py"
)
MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_LOT = 0.01

_HASH = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REASON = re.compile(r"^[A-Z][A-Z0-9_]*$")
_SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bgh[oprsu]_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
)
_TASK_SECRET_NAMES = frozenset(
    {"password", "privatekey", "secret", "token"}
)
_SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "account_login",
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
    {"bootstrap_binding_sha256", "schema_version", "task_scheduler"}
)
_TASK_FIELDS = frozenset(
    {
        "acl_policy_sha256",
        "host_identity_sha256",
        "launcher_path_sha256",
        "logon_type",
        "multiple_instances_policy",
        "release_root_path_sha256",
        "run_level",
        "service_account_principal_sha256",
        "service_account_sid_sha256",
        "task_path",
    }
)
_TEMPLATE_TASK_FIELDS = frozenset(
    {*_TASK_FIELDS, "task_definition_sha256"}
)
_TEMPLATE_FIELDS = frozenset(
    {
        "bootstrap_binding_sha256",
        "credential_manager_references",
        "expected_release_identity_sha256",
        "live_provider_contract_set_sha256",
        "production_config_sha256",
        "provider_bindings",
        "provider_configuration_sha256",
        "release_profile",
        "runtime_mode",
        "safety",
        "schema_version",
        "service_config_file_sha256",
        "task_scheduler",
        "template_id",
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
_EFFECTS = {
    "broker_mutation_performed": False,
    "credential_access_performed": False,
    "mt5_initialized": False,
    "network_access_performed": False,
    "provider_imported": False,
    "provider_materialized": False,
    "provider_request_performed": False,
    "runtime_process_started": False,
    "sqlite_open_performed": False,
    "task_installation_performed": False,
}
_SAFETY = {
    "live_allowed": False,
    "max_lot": MAX_LOT,
    "order_capability": "DISABLED",
    "production_execution_ready": False,
    "promotion_eligible": False,
    "provider_accepted": False,
    "safe_to_demo_auto_order": False,
}
_PACK_PREFIX = "provider-pack"
_OVERLAY_PREFIX = "configured-overlay"
_PACK_FILES = tuple(f"{_PACK_PREFIX}/{path}" for path in GENERATED_PATHS)
_OVERLAY_SOURCE_FILES = tuple(
    f"{_OVERLAY_PREFIX}/{path}" for path in GENERATED_PATHS
)
_OVERLAY_MANIFEST = (
    f"{_OVERLAY_PREFIX}/config/windows_factory_manifest.json"
)
_NON_RECEIPT_FILES = frozenset(
    {
        *_PACK_FILES,
        *_OVERLAY_SOURCE_FILES,
        _OVERLAY_MANIFEST,
        OVERLAY_DESCRIPTOR_NAME,
        CONFIGURED_ARCHIVE_NAME,
        CONFIGURED_SIDECAR_NAME,
        FACTORY_TEMPLATE_NAME,
        TASK_DEFINITION_NAME,
    }
)
_ALL_FILES = frozenset({*_NON_RECEIPT_FILES, CANDIDATE_RECEIPT_NAME})
_EXPECTED_DIRECTORIES = frozenset(
    {
        _PACK_PREFIX,
        f"{_PACK_PREFIX}/config",
        f"{_PACK_PREFIX}/configured_providers",
        _OVERLAY_PREFIX,
        f"{_OVERLAY_PREFIX}/config",
        f"{_OVERLAY_PREFIX}/configured_providers",
    }
)
_FILE_ENTRY_FIELDS = frozenset({"path", "sha256", "size_bytes"})
_RECEIPT_FIELDS = frozenset(
    {
        "base_suite_identity_sha256",
        "base_suite_manifest_sha256",
        "bootstrap_binding_sha256",
        "candidate_id",
        "configured_archive_sha256",
        "configured_manifest_sha256",
        "configured_release_identity_sha256",
        "content_sha256",
        "credential_reference_count",
        "effects",
        "execution_base_archive_sha256",
        "execution_base_release_identity_sha256",
        "execution_factory_template_sha256",
        "files",
        "git_commit",
        "git_tree",
        "live_provider_contract_set_sha256",
        "overlay_descriptor_sha256",
        "provider_configuration_sha256",
        "provider_count",
        "provider_pack_identity_sha256",
        "runtime_mode",
        "safety",
        "schema_version",
        "status",
        "task_definition_sha256",
    }
)
_RESULT_SEAL = object()
_TEMPLATE_SEAL = object()


class LiveExecutionConfiguredCandidateError(RuntimeError):
    """One LIVE candidate failed closed with a stable reason code."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: object) -> None:
        normalized = str(reason_code or "").strip().upper()
        if _REASON.fullmatch(normalized) is None:
            normalized = "LIVE_EXECUTION_CONFIGURED_CANDIDATE_INVALID"
        self.reason_code = normalized
        super().__init__(normalized)


@dataclass(frozen=True, slots=True)
class LiveFactoryCredentialReference:
    """One non-secret credential reference embedded in the template."""

    fingerprint_sha256: str
    key_id: str
    purpose: str
    reference_id: str
    target_name: str


@dataclass(frozen=True, slots=True)
class LiveFactoryProviderBinding:
    """One exact public provider binding embedded in the template."""

    configuration_sha256: str
    contract_sha256: str
    credential_reference_id: str | None
    implementation_sha256: str
    port_name: str
    provider_id: str
    provider_kind: str


@dataclass(frozen=True, slots=True)
class WindowsLiveCanaryExecutionFactoryTemplate:
    """Validated pure-data view of the LIVE factory template."""

    template_id: str
    runtime_mode: str
    release_profile: str
    expected_release_identity_sha256: str
    provider_configuration_sha256: str
    live_provider_contract_set_sha256: str
    bootstrap_binding_sha256: str
    production_config_sha256: str
    service_config_file_sha256: str
    task_definition_sha256: str
    provider_bindings: tuple[LiveFactoryProviderBinding, ...]
    credential_manager_references: tuple[
        LiveFactoryCredentialReference, ...
    ]
    provider_count: int
    credential_reference_count: int
    order_capability: str = "DISABLED"
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    max_lot: float = MAX_LOT
    promotion_eligible: bool = False
    provider_accepted: bool = False
    production_execution_ready: bool = False
    schema_version: str = FACTORY_TEMPLATE_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if (
            _seal is not _TEMPLATE_SEAL
            or self.runtime_mode != "LIVE"
            or self.release_profile != EXECUTION_PROFILE
            or self.provider_count != len(LIVE_EXECUTION_PROVIDER_ROLES)
            or self.credential_reference_count
            != len(LIVE_EXECUTION_CREDENTIAL_PURPOSES)
            or self.order_capability != "DISABLED"
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or self.max_lot != MAX_LOT
            or self.promotion_eligible is not False
            or self.provider_accepted is not False
            or self.production_execution_ready is not False
            or self.schema_version != FACTORY_TEMPLATE_SCHEMA
        ):
            raise ValueError("LIVE factory template safety drift")


@dataclass(frozen=True, slots=True)
class WindowsLiveCanaryExecutionConfiguredCandidate:
    """Pure-data receipt for one exact immutable LIVE candidate."""

    output_root: str
    candidate_id: str
    runtime_mode: str
    base_suite_identity_sha256: str
    base_suite_manifest_sha256: str
    execution_base_release_identity_sha256: str
    execution_base_archive_sha256: str
    provider_pack_identity_sha256: str
    provider_configuration_sha256: str
    live_provider_contract_set_sha256: str
    bootstrap_binding_sha256: str
    overlay_descriptor_sha256: str
    task_definition_sha256: str
    configured_release_identity_sha256: str
    configured_archive_sha256: str
    configured_manifest_sha256: str
    execution_factory_template_sha256: str
    provider_count: int
    credential_reference_count: int
    content_sha256: str
    status: str = CANDIDATE_STATUS
    provider_accepted: bool = False
    production_execution_ready: bool = False
    credential_access_performed: bool = False
    provider_imported: bool = False
    provider_materialized: bool = False
    provider_request_performed: bool = False
    sqlite_open_performed: bool = False
    runtime_process_started: bool = False
    mt5_initialized: bool = False
    network_access_performed: bool = False
    task_installation_performed: bool = False
    broker_mutation_performed: bool = False
    order_capability: str = "DISABLED"
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    max_lot: float = MAX_LOT
    promotion_eligible: bool = False
    schema_version: str = CANDIDATE_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        hashes = (
            self.base_suite_identity_sha256,
            self.base_suite_manifest_sha256,
            self.execution_base_release_identity_sha256,
            self.execution_base_archive_sha256,
            self.provider_pack_identity_sha256,
            self.provider_configuration_sha256,
            self.live_provider_contract_set_sha256,
            self.bootstrap_binding_sha256,
            self.overlay_descriptor_sha256,
            self.task_definition_sha256,
            self.configured_release_identity_sha256,
            self.configured_archive_sha256,
            self.configured_manifest_sha256,
            self.execution_factory_template_sha256,
            self.content_sha256,
        )
        if (
            _seal is not _RESULT_SEAL
            or not self.output_root
            or _ID.fullmatch(self.candidate_id) is None
            or self.runtime_mode != "LIVE"
            or any(_HASH.fullmatch(item) is None for item in hashes)
            or self.provider_count != len(LIVE_EXECUTION_PROVIDER_ROLES)
            or self.credential_reference_count
            != len(LIVE_EXECUTION_CREDENTIAL_PURPOSES)
            or self.status != CANDIDATE_STATUS
            or self.provider_accepted is not False
            or self.production_execution_ready is not False
            or self.credential_access_performed is not False
            or self.provider_imported is not False
            or self.provider_materialized is not False
            or self.provider_request_performed is not False
            or self.sqlite_open_performed is not False
            or self.runtime_process_started is not False
            or self.mt5_initialized is not False
            or self.network_access_performed is not False
            or self.task_installation_performed is not False
            or self.broker_mutation_performed is not False
            or self.order_capability != "DISABLED"
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or self.max_lot != MAX_LOT
            or self.promotion_eligible is not False
            or self.schema_version != CANDIDATE_SCHEMA
        ):
            raise ValueError("LIVE configured candidate safety drift")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: object, *, newline: bool = False) -> bytes:
    try:
        data = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_DOCUMENT_INVALID"
        ) from exc
    return data + (b"\n" if newline else b"")


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _strict_json(data: bytes, reason_code: str) -> dict[str, Any]:
    if not data or len(data) > MAX_DOCUMENT_BYTES:
        raise LiveExecutionConfiguredCandidateError(reason_code)
    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON")
            ),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise LiveExecutionConfiguredCandidateError(reason_code) from exc
    if type(value) is not dict or _canonical_bytes(value, newline=True) != data:
        raise LiveExecutionConfiguredCandidateError(reason_code)
    return value


def _safe_json(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).casefold() in _SENSITIVE_KEYS:
                raise LiveExecutionConfiguredCandidateError(
                    "CANDIDATE_SENSITIVE_FIELD_FORBIDDEN"
                )
            _safe_json(child)
    elif isinstance(value, list):
        for child in value:
            _safe_json(child)


def _hash(value: object, reason_code: str) -> str:
    if (
        type(value) is not str
        or _HASH.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise LiveExecutionConfiguredCandidateError(reason_code)
    return value


def _identifier(value: object, reason_code: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise LiveExecutionConfiguredCandidateError(reason_code)
    return value


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _stable_read(
    path: Path,
    *,
    maximum_bytes: int,
    reason_code: str,
) -> bytes:
    descriptor: int | None = None
    try:
        before = path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or _is_reparse(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            raise OSError("unsafe input")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _identity(before) != _identity(opened):
            raise OSError("input changed")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise OSError("input too large")
        data = b"".join(chunks)
        after = path.lstat()
        if (
            _identity(before) != _identity(after)
            or len(data) != before.st_size
            or not data
        ):
            raise OSError("input changed")
        return data
    except OSError as exc:
        raise LiveExecutionConfiguredCandidateError(reason_code) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _existing_root(path: str | Path, reason_code: str) -> Path:
    root = Path(path).expanduser().absolute()
    try:
        metadata = root.lstat()
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise LiveExecutionConfiguredCandidateError(reason_code) from exc
    if (
        root != resolved
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise LiveExecutionConfiguredCandidateError(reason_code)
    return root


def _new_root(path: str | Path) -> Path:
    root = Path(path).expanduser().absolute()
    if root.exists() or root.is_symlink():
        raise LiveExecutionConfiguredCandidateError("CANDIDATE_OUTPUT_EXISTS")
    try:
        metadata = root.parent.lstat()
    except OSError as exc:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_OUTPUT_PARENT_INVALID"
        ) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_OUTPUT_PARENT_INVALID"
        )
    return root


def _overlap(first: Path, second: Path) -> bool:
    left = first.absolute().parts
    right = second.absolute().parts
    length = min(len(left), len(right))
    return left[:length] == right[:length]


def _mkdir(path: Path) -> None:
    try:
        path.mkdir(mode=0o700)
    except OSError as exc:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_DIRECTORY_CREATE_FAILED"
        ) from exc


def _write(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.fsync(descriptor)
    except OSError as exc:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_FILE_WRITE_FAILED"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _cleanup(root: Path, identity: tuple[int, int, int, int] | None) -> None:
    """Remove only an exact invocation-owned candidate root."""

    if identity is None:
        return
    try:
        metadata = root.lstat()
    except OSError:
        return
    observed = (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(getattr(metadata, "st_file_attributes", 0)),
    )
    if (
        observed != identity
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        return
    for relative in sorted(
        _ALL_FILES,
        key=lambda item: len(PurePosixPath(item).parts),
        reverse=True,
    ):
        try:
            member = root / relative
            child = member.lstat()
            if stat.S_ISREG(child.st_mode) or stat.S_ISLNK(child.st_mode):
                member.unlink()
        except OSError:
            pass
    for relative in sorted(
        _EXPECTED_DIRECTORIES,
        key=lambda item: len(PurePosixPath(item).parts),
        reverse=True,
    ):
        try:
            (root / relative).rmdir()
        except OSError:
            pass
    try:
        root.rmdir()
    except OSError:
        pass


def _task_binding(value: object, reason_code: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _TASK_FIELDS:
        raise LiveExecutionConfiguredCandidateError(reason_code)
    result = dict(value)
    for name in (
        "acl_policy_sha256",
        "host_identity_sha256",
        "launcher_path_sha256",
        "release_root_path_sha256",
        "service_account_principal_sha256",
        "service_account_sid_sha256",
    ):
        result[name] = _hash(result.get(name), reason_code)
    task_path = result.get("task_path")
    if (
        type(task_path) is not str
        or not task_path
        or task_path != task_path.strip()
        or result.get("logon_type") != "SERVICE_ACCOUNT"
        or result.get("run_level") != "LIMITED"
        or result.get("multiple_instances_policy") != "IGNORE_NEW"
    ):
        raise LiveExecutionConfiguredCandidateError(reason_code)
    return result


def _candidate_input(data: bytes) -> dict[str, Any]:
    if any(pattern.search(data) for pattern in _SECRET_PATTERNS):
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_SECRET_PATTERN_FORBIDDEN"
        )
    value = _strict_json(data, "CANDIDATE_INPUT_INVALID")
    _safe_json(value)
    if (
        set(value) != _INPUT_FIELDS
        or value.get("schema_version") != CANDIDATE_INPUT_SCHEMA
    ):
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_INPUT_INVALID"
        )
    return {
        "bootstrap_binding_sha256": _hash(
            value.get("bootstrap_binding_sha256"),
            "CANDIDATE_INPUT_INVALID",
        ),
        "schema_version": CANDIDATE_INPUT_SCHEMA,
        "task_scheduler": _task_binding(
            value.get("task_scheduler"),
            "CANDIDATE_TASK_BINDING_INVALID",
        ),
    }


def _validate_task_definition(data: bytes) -> None:
    if any(pattern.search(data) for pattern in _SECRET_PATTERNS):
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_TASK_SECRET_PATTERN_FORBIDDEN"
        )
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_TASK_DEFINITION_INVALID"
        )
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as exc:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_TASK_DEFINITION_INVALID"
        ) from exc

    def local_name(value: object) -> str:
        if type(value) is not str:
            return ""
        return value.rsplit("}", 1)[-1].rsplit(":", 1)[-1].casefold()

    if local_name(root.tag) != "task":
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_TASK_DEFINITION_INVALID"
        )
    enabled: list[ElementTree.Element] = []
    for element in root.iter():
        if local_name(element.tag) in _TASK_SECRET_NAMES or any(
            local_name(name) in _TASK_SECRET_NAMES
            for name in element.attrib
        ):
            raise LiveExecutionConfiguredCandidateError(
                "CANDIDATE_TASK_SECRET_PATTERN_FORBIDDEN"
            )
        if local_name(element.tag) == "enabled":
            enabled.append(element)
    if (
        len(enabled) != 1
        or (enabled[0].text or "").strip().casefold() != "false"
    ):
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_TASK_NOT_DISABLED"
        )


def _provider_configuration(
    provider_module: bytes,
) -> StaticWindowsExecutionProviderConfiguration:
    try:
        raw = extract_windows_live_canary_execution_provider_configuration(
            provider_module
        )
        return (
            static_windows_live_canary_execution_provider_configuration_from_dict(
                raw
            )
        )
    except (ExecutionProviderPackError, TypeError, ValueError) as exc:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_PROVIDER_CONFIGURATION_INVALID"
        ) from exc


def _template_payload(
    *,
    candidate_id: str,
    configured_identity: str,
    provider_config: StaticWindowsExecutionProviderConfiguration,
    task_binding: Mapping[str, Any],
    task_sha256: str,
    bootstrap_sha256: str,
) -> dict[str, Any]:
    return {
        "bootstrap_binding_sha256": bootstrap_sha256,
        "credential_manager_references": [
            {
                "fingerprint_sha256": item.fingerprint_sha256,
                "key_id": item.key_id,
                "purpose": item.purpose,
                "reference_id": item.reference_id,
                "target_name": item.target_name,
            }
            for item in provider_config.credential_references
        ],
        "expected_release_identity_sha256": configured_identity,
        "live_provider_contract_set_sha256": (
            LIVE_EXECUTION_PROVIDER_CONTRACT_SET_SHA256
        ),
        "production_config_sha256": provider_config.production_config_sha256,
        "provider_bindings": [
            {
                "configuration_sha256": item.configuration_sha256,
                "contract_sha256": item.contract_sha256,
                "credential_reference_id": item.credential_reference_id,
                "implementation_sha256": item.implementation_sha256,
                "port_name": item.port_name,
                "provider_id": item.provider_id,
                "provider_kind": item.provider_kind,
            }
            for item in provider_config.provider_bindings
        ],
        "provider_configuration_sha256": provider_config.content_sha256,
        "release_profile": EXECUTION_PROFILE,
        "runtime_mode": "LIVE",
        "safety": dict(_SAFETY),
        "schema_version": FACTORY_TEMPLATE_SCHEMA,
        "service_config_file_sha256": (
            provider_config.service_config_file_sha256
        ),
        "task_scheduler": {
            **dict(task_binding),
            "task_definition_sha256": task_sha256,
        },
        "template_id": candidate_id,
    }


def validate_windows_live_canary_execution_factory_template(
    data: bytes,
) -> WindowsLiveCanaryExecutionFactoryTemplate:
    """Validate a canonical LIVE template without importing providers."""

    if any(pattern.search(data) for pattern in _SECRET_PATTERNS):
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_FACTORY_TEMPLATE_SECRET_PATTERN"
        )
    value = _strict_json(data, "CANDIDATE_FACTORY_TEMPLATE_INVALID")
    _safe_json(value)
    if (
        set(value) != _TEMPLATE_FIELDS
        or value.get("schema_version") != FACTORY_TEMPLATE_SCHEMA
        or value.get("release_profile") != EXECUTION_PROFILE
        or value.get("runtime_mode") != "LIVE"
        or value.get("safety") != _SAFETY
    ):
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_FACTORY_TEMPLATE_INVALID"
        )
    template_id = _identifier(
        value.get("template_id"), "CANDIDATE_FACTORY_TEMPLATE_INVALID"
    )
    expected_identity = _hash(
        value.get("expected_release_identity_sha256"),
        "CANDIDATE_FACTORY_TEMPLATE_INVALID",
    )
    provider_config_sha256 = _hash(
        value.get("provider_configuration_sha256"),
        "CANDIDATE_FACTORY_TEMPLATE_INVALID",
    )
    contract_set_sha256 = _hash(
        value.get("live_provider_contract_set_sha256"),
        "CANDIDATE_FACTORY_TEMPLATE_INVALID",
    )
    if contract_set_sha256 != LIVE_EXECUTION_PROVIDER_CONTRACT_SET_SHA256:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_FACTORY_TEMPLATE_CONTRACT_MISMATCH"
        )
    bootstrap = _hash(
        value.get("bootstrap_binding_sha256"),
        "CANDIDATE_FACTORY_TEMPLATE_INVALID",
    )
    production = _hash(
        value.get("production_config_sha256"),
        "CANDIDATE_FACTORY_TEMPLATE_INVALID",
    )
    service = _hash(
        value.get("service_config_file_sha256"),
        "CANDIDATE_FACTORY_TEMPLATE_INVALID",
    )

    raw_task = value.get("task_scheduler")
    if not isinstance(raw_task, Mapping) or set(raw_task) != _TEMPLATE_TASK_FIELDS:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_FACTORY_TEMPLATE_TASK_INVALID"
        )
    task_definition = _hash(
        raw_task.get("task_definition_sha256"),
        "CANDIDATE_FACTORY_TEMPLATE_TASK_INVALID",
    )
    _task_binding(
        {key: raw_task[key] for key in _TASK_FIELDS},
        "CANDIDATE_FACTORY_TEMPLATE_TASK_INVALID",
    )

    raw_credentials = value.get("credential_manager_references")
    if type(raw_credentials) is not list:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_FACTORY_TEMPLATE_CREDENTIALS_INVALID"
        )
    credentials: list[LiveFactoryCredentialReference] = []
    references_by_purpose: dict[str, str] = {}
    seen_reference_ids: set[str] = set()
    seen_key_ids: set[str] = set()
    for item in raw_credentials:
        if not isinstance(item, Mapping) or set(item) != _CREDENTIAL_FIELDS:
            raise LiveExecutionConfiguredCandidateError(
                "CANDIDATE_FACTORY_TEMPLATE_CREDENTIALS_INVALID"
            )
        purpose = _identifier(
            item.get("purpose"),
            "CANDIDATE_FACTORY_TEMPLATE_CREDENTIALS_INVALID",
        )
        reference_id = _identifier(
            item.get("reference_id"),
            "CANDIDATE_FACTORY_TEMPLATE_CREDENTIALS_INVALID",
        )
        key_id = _identifier(
            item.get("key_id"),
            "CANDIDATE_FACTORY_TEMPLATE_CREDENTIALS_INVALID",
        )
        fingerprint = _hash(
            item.get("fingerprint_sha256"),
            "CANDIDATE_FACTORY_TEMPLATE_CREDENTIALS_INVALID",
        )
        target_name = item.get("target_name")
        if (
            type(target_name) is not str
            or not target_name.startswith(
                "AI_SCALPER/WINDOWS_SERVICE/LIVE_EXECUTION/"
            )
            or purpose in references_by_purpose
            or reference_id.casefold() in seen_reference_ids
            or key_id.casefold() in seen_key_ids
        ):
            raise LiveExecutionConfiguredCandidateError(
                "CANDIDATE_FACTORY_TEMPLATE_CREDENTIALS_INVALID"
            )
        references_by_purpose[purpose] = reference_id
        seen_reference_ids.add(reference_id.casefold())
        seen_key_ids.add(key_id.casefold())
        credentials.append(
            LiveFactoryCredentialReference(
                fingerprint_sha256=fingerprint,
                key_id=key_id,
                purpose=purpose,
                reference_id=reference_id,
                target_name=target_name,
            )
        )
    if tuple(references_by_purpose) != LIVE_EXECUTION_CREDENTIAL_PURPOSES:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_FACTORY_TEMPLATE_CREDENTIALS_INVALID"
        )

    raw_providers = value.get("provider_bindings")
    if type(raw_providers) is not list:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_FACTORY_TEMPLATE_PROVIDERS_INVALID"
        )
    providers: list[LiveFactoryProviderBinding] = []
    seen_provider_ids: set[str] = set()
    for index, (item, contract) in enumerate(
        zip(
            raw_providers,
            LIVE_EXECUTION_PROVIDER_CONTRACTS,
            strict=False,
        ),
        start=1,
    ):
        if not isinstance(item, Mapping) or set(item) != _PROVIDER_FIELDS:
            raise LiveExecutionConfiguredCandidateError(
                "CANDIDATE_FACTORY_TEMPLATE_PROVIDERS_INVALID"
            )
        port = item.get("port_name")
        kind = item.get("provider_kind")
        contract_sha256 = _hash(
            item.get("contract_sha256"),
            "CANDIDATE_FACTORY_TEMPLATE_PROVIDERS_INVALID",
        )
        provider_id = _identifier(
            item.get("provider_id"),
            "CANDIDATE_FACTORY_TEMPLATE_PROVIDERS_INVALID",
        )
        credential_reference_id = item.get("credential_reference_id")
        expected_reference = (
            references_by_purpose[contract.credential_purpose]
            if contract.credential_purpose is not None
            else None
        )
        if (
            port != contract.port_name
            or kind != contract.provider_kind
            or contract_sha256 != contract.contract_sha256
            or credential_reference_id != expected_reference
            or provider_id != f"live-execution-provider-{index:02d}"
            or provider_id.casefold() in seen_provider_ids
        ):
            raise LiveExecutionConfiguredCandidateError(
                "CANDIDATE_FACTORY_TEMPLATE_PROVIDERS_INVALID"
            )
        seen_provider_ids.add(provider_id.casefold())
        providers.append(
            LiveFactoryProviderBinding(
                configuration_sha256=_hash(
                    item.get("configuration_sha256"),
                    "CANDIDATE_FACTORY_TEMPLATE_PROVIDERS_INVALID",
                ),
                contract_sha256=contract_sha256,
                credential_reference_id=credential_reference_id,
                implementation_sha256=_hash(
                    item.get("implementation_sha256"),
                    "CANDIDATE_FACTORY_TEMPLATE_PROVIDERS_INVALID",
                ),
                port_name=str(port),
                provider_id=provider_id,
                provider_kind=str(kind),
            )
        )
    if (
        len(raw_providers) != len(LIVE_EXECUTION_PROVIDER_CONTRACTS)
        or len(providers) != len(LIVE_EXECUTION_PROVIDER_CONTRACTS)
    ):
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_FACTORY_TEMPLATE_PROVIDERS_INVALID"
        )
    return WindowsLiveCanaryExecutionFactoryTemplate(
        template_id=template_id,
        runtime_mode="LIVE",
        release_profile=EXECUTION_PROFILE,
        expected_release_identity_sha256=expected_identity,
        provider_configuration_sha256=provider_config_sha256,
        live_provider_contract_set_sha256=contract_set_sha256,
        bootstrap_binding_sha256=bootstrap,
        production_config_sha256=production,
        service_config_file_sha256=service,
        task_definition_sha256=task_definition,
        provider_bindings=tuple(providers),
        credential_manager_references=tuple(credentials),
        provider_count=len(providers),
        credential_reference_count=len(credentials),
        _seal=_TEMPLATE_SEAL,
    )


def _inventory(root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    folded: set[str] = set()
    try:
        paths = sorted(root.rglob("*"))
    except OSError as exc:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_MEMBER_INVALID"
        ) from exc
    for path in paths:
        relative = path.relative_to(root).as_posix()
        if relative.casefold() in folded:
            raise LiveExecutionConfiguredCandidateError(
                "CANDIDATE_MEMBER_INVALID"
            )
        folded.add(relative.casefold())
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise LiveExecutionConfiguredCandidateError(
                "CANDIDATE_MEMBER_INVALID"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
            raise LiveExecutionConfiguredCandidateError(
                "CANDIDATE_MEMBER_INVALID"
            )
        if stat.S_ISDIR(metadata.st_mode):
            directories.add(relative)
            continue
        if not stat.S_ISREG(metadata.st_mode) or relative not in _ALL_FILES:
            raise LiveExecutionConfiguredCandidateError(
                "CANDIDATE_MEMBER_INVALID"
            )
        files[relative] = _stable_read(
            path,
            maximum_bytes=(
                MAX_ARCHIVE_BYTES
                if relative == CONFIGURED_ARCHIVE_NAME
                else MAX_DOCUMENT_BYTES
            ),
            reason_code="CANDIDATE_MEMBER_INVALID",
        )
    if set(files) != _ALL_FILES or directories != _EXPECTED_DIRECTORIES:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_MEMBER_INVALID"
        )
    return files


def _entries(files: Mapping[str, bytes]) -> list[dict[str, object]]:
    return [
        {
            "path": path,
            "sha256": _sha256(files[path]),
            "size_bytes": len(files[path]),
        }
        for path in sorted(files)
    ]


def _receipt(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _RECEIPT_FIELDS:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_RECEIPT_INVALID"
        )
    result = dict(value)
    for name in (
        "base_suite_identity_sha256",
        "base_suite_manifest_sha256",
        "bootstrap_binding_sha256",
        "configured_archive_sha256",
        "configured_manifest_sha256",
        "configured_release_identity_sha256",
        "content_sha256",
        "execution_base_archive_sha256",
        "execution_base_release_identity_sha256",
        "execution_factory_template_sha256",
        "live_provider_contract_set_sha256",
        "overlay_descriptor_sha256",
        "provider_configuration_sha256",
        "provider_pack_identity_sha256",
        "task_definition_sha256",
    ):
        _hash(result.get(name), "CANDIDATE_RECEIPT_INVALID")
    if (
        _identifier(result.get("candidate_id"), "CANDIDATE_RECEIPT_INVALID")
        != result.get("candidate_id")
        or result.get("runtime_mode") != "LIVE"
        or result.get("schema_version") != CANDIDATE_SCHEMA
        or result.get("status") != CANDIDATE_STATUS
        or result.get("effects") != _EFFECTS
        or result.get("safety") != _SAFETY
        or result.get("provider_count") != len(LIVE_EXECUTION_PROVIDER_ROLES)
        or result.get("credential_reference_count")
        != len(LIVE_EXECUTION_CREDENTIAL_PURPOSES)
        or result.get("live_provider_contract_set_sha256")
        != LIVE_EXECUTION_PROVIDER_CONTRACT_SET_SHA256
        or type(result.get("git_commit")) is not str
        or not result["git_commit"]
        or type(result.get("git_tree")) is not str
        or not result["git_tree"]
    ):
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_RECEIPT_INVALID"
        )
    raw_files = result.get("files")
    if type(raw_files) is not list:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_RECEIPT_INVALID"
        )
    paths: list[str] = []
    for item in raw_files:
        if (
            not isinstance(item, Mapping)
            or set(item) != _FILE_ENTRY_FIELDS
            or type(item.get("path")) is not str
            or item["path"] not in _NON_RECEIPT_FILES
            or type(item.get("size_bytes")) is not int
            or item["size_bytes"] <= 0
            or type(item.get("sha256")) is not str
            or _HASH.fullmatch(str(item["sha256"])) is None
        ):
            raise LiveExecutionConfiguredCandidateError(
                "CANDIDATE_RECEIPT_INVALID"
            )
        paths.append(str(item["path"]))
    if paths != sorted(_NON_RECEIPT_FILES):
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_RECEIPT_INVALID"
        )
    unsigned = dict(result)
    content = unsigned.pop("content_sha256")
    if _sha256(_canonical_bytes(unsigned)) != content:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_RECEIPT_HASH_MISMATCH"
        )
    return result


def _result(
    root: Path,
    receipt: Mapping[str, Any],
) -> WindowsLiveCanaryExecutionConfiguredCandidate:
    return WindowsLiveCanaryExecutionConfiguredCandidate(
        output_root=str(root),
        candidate_id=receipt["candidate_id"],
        runtime_mode="LIVE",
        base_suite_identity_sha256=receipt["base_suite_identity_sha256"],
        base_suite_manifest_sha256=receipt["base_suite_manifest_sha256"],
        execution_base_release_identity_sha256=receipt[
            "execution_base_release_identity_sha256"
        ],
        execution_base_archive_sha256=receipt[
            "execution_base_archive_sha256"
        ],
        provider_pack_identity_sha256=receipt[
            "provider_pack_identity_sha256"
        ],
        provider_configuration_sha256=receipt[
            "provider_configuration_sha256"
        ],
        live_provider_contract_set_sha256=receipt[
            "live_provider_contract_set_sha256"
        ],
        bootstrap_binding_sha256=receipt["bootstrap_binding_sha256"],
        overlay_descriptor_sha256=receipt["overlay_descriptor_sha256"],
        task_definition_sha256=receipt["task_definition_sha256"],
        configured_release_identity_sha256=receipt[
            "configured_release_identity_sha256"
        ],
        configured_archive_sha256=receipt["configured_archive_sha256"],
        configured_manifest_sha256=receipt["configured_manifest_sha256"],
        execution_factory_template_sha256=receipt[
            "execution_factory_template_sha256"
        ],
        provider_count=receipt["provider_count"],
        credential_reference_count=receipt["credential_reference_count"],
        content_sha256=receipt["content_sha256"],
        _seal=_RESULT_SEAL,
    )


def _template_matches_configuration(
    template: WindowsLiveCanaryExecutionFactoryTemplate,
    configuration: StaticWindowsExecutionProviderConfiguration,
) -> bool:
    credentials = tuple(
        (
            item.fingerprint_sha256,
            item.key_id,
            item.purpose,
            item.reference_id,
            item.target_name,
        )
        for item in template.credential_manager_references
    )
    expected_credentials = tuple(
        (
            item.fingerprint_sha256,
            item.key_id,
            item.purpose,
            item.reference_id,
            item.target_name,
        )
        for item in configuration.credential_references
    )
    providers = tuple(
        (
            item.configuration_sha256,
            item.contract_sha256,
            item.credential_reference_id,
            item.implementation_sha256,
            item.port_name,
            item.provider_id,
            item.provider_kind,
        )
        for item in template.provider_bindings
    )
    expected_providers = tuple(
        (
            item.configuration_sha256,
            item.contract_sha256,
            item.credential_reference_id,
            item.implementation_sha256,
            item.port_name,
            item.provider_id,
            item.provider_kind,
        )
        for item in configuration.provider_bindings
    )
    return credentials == expected_credentials and providers == expected_providers


def assemble_windows_live_canary_execution_configured_candidate(
    *,
    base_suite_root: str | Path,
    execution_base_release: str | Path,
    provider_pack_root: str | Path,
    task_definition_path: str | Path,
    candidate_input_path: str | Path,
    candidate_id: str,
    output_root: str | Path,
) -> WindowsLiveCanaryExecutionConfiguredCandidate:
    """Assemble one immutable LIVE-labelled candidate without authority."""

    candidate_name = _identifier(candidate_id, "CANDIDATE_ID_INVALID")
    try:
        suite = verify_base_release_suite(base_suite_root)
        role = suite.role(EXECUTION_ROLE)
        original = validate_windows_live_canary_execution_provider_pack(
            base_suite_root=base_suite_root,
            execution_base_release=execution_base_release,
            pack_root=provider_pack_root,
        )
    except (
        BaseReleaseSuiteVerificationError,
        ExecutionProviderPackError,
        KeyError,
    ) as exc:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_INPUT_INVALID"
        ) from exc
    pack_root = _existing_root(
        provider_pack_root, "CANDIDATE_PROVIDER_PACK_INVALID"
    )
    execution_path = Path(execution_base_release).expanduser().absolute()
    task_path = Path(task_definition_path).expanduser().absolute()
    input_path = Path(candidate_input_path).expanduser().absolute()
    output_path = Path(output_root).expanduser().absolute()
    if any(
        _overlap(output_path, item)
        for item in (
            pack_root,
            suite.root,
            execution_path,
            task_path,
            input_path,
        )
    ):
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_OUTPUT_INPUT_OVERLAP"
        )
    pack_bytes = {
        relative: _stable_read(
            pack_root / relative,
            maximum_bytes=MAX_DOCUMENT_BYTES,
            reason_code="CANDIDATE_PROVIDER_PACK_INVALID",
        )
        for relative in GENERATED_PATHS
    }
    task_bytes = _stable_read(
        task_path,
        maximum_bytes=MAX_DOCUMENT_BYTES,
        reason_code="CANDIDATE_TASK_DEFINITION_INVALID",
    )
    _validate_task_definition(task_bytes)
    candidate_input = _candidate_input(
        _stable_read(
            input_path,
            maximum_bytes=MAX_DOCUMENT_BYTES,
            reason_code="CANDIDATE_INPUT_INVALID",
        )
    )
    provider_config = _provider_configuration(
        pack_bytes["configured_providers/execution_provider.py"]
    )
    if (
        provider_config.runtime_mode != "LIVE"
        or provider_config.base_suite_identity_sha256
        != suite.suite_identity_sha256
        or provider_config.execution_base_release_identity_sha256
        != role.release_identity_sha256
        or provider_config.content_sha256
        != original.provider_configuration_sha256
    ):
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_PROVIDER_CONFIGURATION_MISMATCH"
        )

    root = _new_root(output_path)
    root_identity: tuple[int, int, int, int] | None = None
    try:
        _mkdir(root)
        metadata = root.lstat()
        root_identity = (
            int(metadata.st_dev),
            int(metadata.st_ino),
            int(metadata.st_mode),
            int(getattr(metadata, "st_file_attributes", 0)),
        )
        for relative in sorted(
            _EXPECTED_DIRECTORIES,
            key=lambda item: (len(PurePosixPath(item).parts), item),
        ):
            _mkdir(root / relative)
        for relative, data in pack_bytes.items():
            _write(root / _PACK_PREFIX / relative, data)
            _write(root / _OVERLAY_PREFIX / relative, data)
        _write(root / TASK_DEFINITION_NAME, task_bytes)

        copied = validate_windows_live_canary_execution_provider_pack(
            base_suite_root=base_suite_root,
            execution_base_release=execution_base_release,
            pack_root=root / _PACK_PREFIX,
        )
        if copied.pack_identity_sha256 != original.pack_identity_sha256:
            raise LiveExecutionConfiguredCandidateError(
                "CANDIDATE_PROVIDER_PACK_COPY_MISMATCH"
            )
        descriptor_path = root / OVERLAY_DESCRIPTOR_NAME
        try:
            prepare_live_canary_configured_overlay_candidate(
                base_archive=execution_base_release,
                overlay_root=root / _OVERLAY_PREFIX,
                task_definition_path=root / TASK_DEFINITION_NAME,
                overlay_id=candidate_name,
                bootstrap_binding_sha256=candidate_input[
                    "bootstrap_binding_sha256"
                ],
                descriptor_output_path=descriptor_path,
            )
            archive_path = root / CONFIGURED_ARCHIVE_NAME
            built = build_configured_service_release(
                execution_base_release,
                root / _OVERLAY_PREFIX,
                descriptor_path,
                archive_path,
                base_release_suite_root=base_suite_root,
            )
            configured = verify_configured_service_release(
                archive_path,
                expected_release_identity_sha256=str(
                    built["release_identity_sha256"]
                ),
                expected_base_release_identity_sha256=(
                    role.release_identity_sha256
                ),
            )
        except (ConfiguredReleaseError, TypeError, ValueError) as exc:
            raise LiveExecutionConfiguredCandidateError(
                "CANDIDATE_CONFIGURED_RELEASE_INVALID"
            ) from exc
        if (
            configured.release_profile != EXECUTION_PROFILE
            or configured.runtime_mode != "LIVE"
            or not configured.base_release_suite_bound
            or configured.base_release_suite_role != EXECUTION_ROLE
            or configured.base_release_suite_identity_sha256
            != suite.suite_identity_sha256
            or configured.production_execution_ready
            or configured.order_capability != "GATED_PRESENT"
            or configured.live_allowed
            or configured.safe_to_demo_auto_order
        ):
            raise LiveExecutionConfiguredCandidateError(
                "CANDIDATE_CONFIGURED_RELEASE_AUTHORITY_DRIFT"
            )
        template_payload = _template_payload(
            candidate_id=candidate_name,
            configured_identity=configured.release_identity_sha256,
            provider_config=provider_config,
            task_binding=candidate_input["task_scheduler"],
            task_sha256=_sha256(task_bytes),
            bootstrap_sha256=candidate_input[
                "bootstrap_binding_sha256"
            ],
        )
        template_bytes = _canonical_bytes(template_payload, newline=True)
        validate_windows_live_canary_execution_factory_template(
            template_bytes
        )
        _write(root / FACTORY_TEMPLATE_NAME, template_bytes)

        non_receipt = {
            relative: _stable_read(
                root / relative,
                maximum_bytes=(
                    MAX_ARCHIVE_BYTES
                    if relative == CONFIGURED_ARCHIVE_NAME
                    else MAX_DOCUMENT_BYTES
                ),
                reason_code="CANDIDATE_FILE_INVALID",
            )
            for relative in sorted(_NON_RECEIPT_FILES)
        }
        receipt: dict[str, Any] = {
            "base_suite_identity_sha256": suite.suite_identity_sha256,
            "base_suite_manifest_sha256": suite.manifest_sha256,
            "bootstrap_binding_sha256": candidate_input[
                "bootstrap_binding_sha256"
            ],
            "candidate_id": candidate_name,
            "configured_archive_sha256": _sha256(
                non_receipt[CONFIGURED_ARCHIVE_NAME]
            ),
            "configured_manifest_sha256": _sha256(
                non_receipt[CONFIGURED_SIDECAR_NAME]
            ),
            "configured_release_identity_sha256": (
                configured.release_identity_sha256
            ),
            "credential_reference_count": len(
                LIVE_EXECUTION_CREDENTIAL_PURPOSES
            ),
            "effects": dict(_EFFECTS),
            "execution_base_archive_sha256": role.archive_sha256,
            "execution_base_release_identity_sha256": (
                role.release_identity_sha256
            ),
            "execution_factory_template_sha256": _sha256(template_bytes),
            "files": _entries(non_receipt),
            "git_commit": suite.git_commit,
            "git_tree": suite.git_tree,
            "live_provider_contract_set_sha256": (
                LIVE_EXECUTION_PROVIDER_CONTRACT_SET_SHA256
            ),
            "overlay_descriptor_sha256": _sha256(
                non_receipt[OVERLAY_DESCRIPTOR_NAME]
            ),
            "provider_configuration_sha256": provider_config.content_sha256,
            "provider_count": len(LIVE_EXECUTION_PROVIDER_ROLES),
            "provider_pack_identity_sha256": original.pack_identity_sha256,
            "runtime_mode": "LIVE",
            "safety": dict(_SAFETY),
            "schema_version": CANDIDATE_SCHEMA,
            "status": CANDIDATE_STATUS,
            "task_definition_sha256": _sha256(task_bytes),
        }
        receipt["content_sha256"] = _sha256(_canonical_bytes(receipt))
        receipt = _receipt(receipt)
        _write(
            root / CANDIDATE_RECEIPT_NAME,
            _canonical_bytes(receipt, newline=True),
        )
        return validate_windows_live_canary_execution_configured_candidate(
            base_suite_root=base_suite_root,
            execution_base_release=execution_base_release,
            candidate_root=root,
        )
    except Exception:
        _cleanup(root, root_identity)
        raise


def _archive_member(archive_bytes: bytes, member: str) -> bytes:
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            return archive.read(member)
    except (KeyError, OSError, zipfile.BadZipFile) as exc:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_CONFIGURED_ARTIFACT_INVALID"
        ) from exc


def validate_windows_live_canary_execution_configured_candidate(
    *,
    base_suite_root: str | Path,
    execution_base_release: str | Path,
    candidate_root: str | Path,
) -> WindowsLiveCanaryExecutionConfiguredCandidate:
    """Independently validate exact candidate bytes without provider import."""

    root = _existing_root(candidate_root, "CANDIDATE_ROOT_INVALID")
    files = _inventory(root)
    _validate_task_definition(files[TASK_DEFINITION_NAME])
    receipt = _receipt(
        _strict_json(
            files[CANDIDATE_RECEIPT_NAME],
            "CANDIDATE_RECEIPT_INVALID",
        )
    )
    try:
        suite = verify_base_release_suite(base_suite_root)
        role = suite.role(EXECUTION_ROLE)
        pack = validate_windows_live_canary_execution_provider_pack(
            base_suite_root=base_suite_root,
            execution_base_release=execution_base_release,
            pack_root=root / _PACK_PREFIX,
        )
    except (
        BaseReleaseSuiteVerificationError,
        ExecutionProviderPackError,
        KeyError,
    ) as exc:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_BASE_OR_PACK_INVALID"
        ) from exc
    for relative in GENERATED_PATHS:
        if (
            files[f"{_PACK_PREFIX}/{relative}"]
            != files[f"{_OVERLAY_PREFIX}/{relative}"]
        ):
            raise LiveExecutionConfiguredCandidateError(
                "CANDIDATE_PROVIDER_PACK_OVERLAY_MISMATCH"
            )
    provider_config = _provider_configuration(
        files[
            f"{_PACK_PREFIX}/configured_providers/execution_provider.py"
        ]
    )
    descriptor = _strict_json(
        files[OVERLAY_DESCRIPTOR_NAME],
        "CANDIDATE_OVERLAY_DESCRIPTOR_INVALID",
    )
    base_archive_bytes = _stable_read(
        Path(execution_base_release).expanduser().absolute(),
        maximum_bytes=MAX_ARCHIVE_BYTES,
        reason_code="CANDIDATE_EXECUTION_BASE_INVALID",
    )
    if _sha256(base_archive_bytes) != role.archive_sha256:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_EXECUTION_BASE_INVALID"
        )
    materializer_sha256 = _sha256(
        _archive_member(base_archive_bytes, LIVE_MATERIALIZER_MEMBER)
    )
    if (
        descriptor.get("schema_version")
        != "windows-live-canary-configured-service-overlay-v1"
        or descriptor.get("runtime_mode") != "LIVE"
        or descriptor.get("base_release_profile") != EXECUTION_PROFILE
        or descriptor.get("reviewed_factory_template_sha256")
        != materializer_sha256
        or descriptor.get("task_definition_sha256")
        != _sha256(files[TASK_DEFINITION_NAME])
    ):
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_OVERLAY_DESCRIPTOR_INVALID"
        )
    try:
        configured = verify_configured_service_release(
            root / CONFIGURED_ARCHIVE_NAME,
            expected_release_identity_sha256=receipt[
                "configured_release_identity_sha256"
            ],
            expected_base_release_identity_sha256=role.release_identity_sha256,
        )
        template = validate_windows_live_canary_execution_factory_template(
            files[FACTORY_TEMPLATE_NAME]
        )
    except (
        ConfiguredReleaseError,
        LiveExecutionConfiguredCandidateError,
        TypeError,
        ValueError,
    ) as exc:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_CONFIGURED_ARTIFACT_INVALID"
        ) from exc
    if (
        files[CONFIGURED_SIDECAR_NAME]
        != _archive_member(
            files[CONFIGURED_ARCHIVE_NAME], "RELEASE_MANIFEST.json"
        )
        or configured.release_profile != EXECUTION_PROFILE
        or configured.runtime_mode != "LIVE"
        or configured.base_release_suite_role != EXECUTION_ROLE
        or configured.base_release_suite_identity_sha256
        != suite.suite_identity_sha256
        or configured.overlay_descriptor_sha256
        != _sha256(files[OVERLAY_DESCRIPTOR_NAME])
        or configured.production_execution_ready
        or configured.order_capability != "GATED_PRESENT"
        or configured.live_allowed
        or configured.safe_to_demo_auto_order
        or template.template_id != receipt["candidate_id"]
        or template.expected_release_identity_sha256
        != configured.release_identity_sha256
        or template.provider_configuration_sha256
        != provider_config.content_sha256
        or template.live_provider_contract_set_sha256
        != LIVE_EXECUTION_PROVIDER_CONTRACT_SET_SHA256
        or template.bootstrap_binding_sha256
        != receipt["bootstrap_binding_sha256"]
        or template.production_config_sha256
        != provider_config.production_config_sha256
        or template.service_config_file_sha256
        != provider_config.service_config_file_sha256
        or template.task_definition_sha256
        != _sha256(files[TASK_DEFINITION_NAME])
        or not _template_matches_configuration(template, provider_config)
    ):
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_CROSS_BINDING_MISMATCH"
        )
    non_receipt = {
        path: data
        for path, data in files.items()
        if path != CANDIDATE_RECEIPT_NAME
    }
    expected: dict[str, Any] = {
        "base_suite_identity_sha256": suite.suite_identity_sha256,
        "base_suite_manifest_sha256": suite.manifest_sha256,
        "bootstrap_binding_sha256": template.bootstrap_binding_sha256,
        "candidate_id": receipt["candidate_id"],
        "configured_archive_sha256": _sha256(
            files[CONFIGURED_ARCHIVE_NAME]
        ),
        "configured_manifest_sha256": _sha256(
            files[CONFIGURED_SIDECAR_NAME]
        ),
        "configured_release_identity_sha256": (
            configured.release_identity_sha256
        ),
        "credential_reference_count": len(
            LIVE_EXECUTION_CREDENTIAL_PURPOSES
        ),
        "effects": dict(_EFFECTS),
        "execution_base_archive_sha256": role.archive_sha256,
        "execution_base_release_identity_sha256": role.release_identity_sha256,
        "execution_factory_template_sha256": _sha256(
            files[FACTORY_TEMPLATE_NAME]
        ),
        "files": _entries(non_receipt),
        "git_commit": suite.git_commit,
        "git_tree": suite.git_tree,
        "live_provider_contract_set_sha256": (
            LIVE_EXECUTION_PROVIDER_CONTRACT_SET_SHA256
        ),
        "overlay_descriptor_sha256": _sha256(
            files[OVERLAY_DESCRIPTOR_NAME]
        ),
        "provider_configuration_sha256": provider_config.content_sha256,
        "provider_count": len(LIVE_EXECUTION_PROVIDER_ROLES),
        "provider_pack_identity_sha256": pack.pack_identity_sha256,
        "runtime_mode": "LIVE",
        "safety": dict(_SAFETY),
        "schema_version": CANDIDATE_SCHEMA,
        "status": CANDIDATE_STATUS,
        "task_definition_sha256": _sha256(files[TASK_DEFINITION_NAME]),
    }
    expected["content_sha256"] = _sha256(_canonical_bytes(expected))
    if receipt != expected:
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_RECEIPT_CROSS_BINDING_MISMATCH"
        )
    if (
        provider_config.content_sha256
        != pack.provider_configuration_sha256
        or provider_config.base_suite_identity_sha256
        != suite.suite_identity_sha256
        or provider_config.execution_base_release_identity_sha256
        != role.release_identity_sha256
        or receipt["execution_base_archive_sha256"] != role.archive_sha256
    ):
        raise LiveExecutionConfiguredCandidateError(
            "CANDIDATE_PROVIDER_BINDING_MISMATCH"
        )
    return _result(root, receipt)


__all__ = [
    "CANDIDATE_INPUT_SCHEMA",
    "CANDIDATE_RECEIPT_NAME",
    "CANDIDATE_SCHEMA",
    "CANDIDATE_STATUS",
    "FACTORY_TEMPLATE_SCHEMA",
    "LiveExecutionConfiguredCandidateError",
    "WindowsLiveCanaryExecutionConfiguredCandidate",
    "WindowsLiveCanaryExecutionFactoryTemplate",
    "assemble_windows_live_canary_execution_configured_candidate",
    "validate_windows_live_canary_execution_configured_candidate",
    "validate_windows_live_canary_execution_factory_template",
]
