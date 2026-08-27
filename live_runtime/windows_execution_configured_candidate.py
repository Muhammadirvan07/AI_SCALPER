"""Immutable, deny-only configured candidate for Windows Execution.

The assembler copies and cryptographically binds an already validated
Execution provider pack to one atomic base-suite role, one disabled reviewed
task definition, one configured release, and one static 46-port factory
template.  It never imports generated code or touches credentials, SQLite,
MT5, network, Task Scheduler, a process, or a broker.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Mapping

from .configured_service_release import (
    ConfiguredReleaseError,
    build_configured_service_release,
    prepare_configured_overlay_candidate,
    verify_configured_service_release,
)
from .windows_base_release_suite import (
    BaseReleaseSuiteVerificationError,
    verify_base_release_suite,
)
from .windows_execution_provider_pack_generator import (
    EXECUTION_CREDENTIAL_PURPOSES,
    EXECUTION_PROVIDER_ROLES,
    GENERATED_PATHS,
    ExecutionProviderPackError,
    StaticWindowsExecutionProviderConfiguration,
    extract_windows_execution_provider_configuration,
    static_windows_execution_provider_configuration_from_dict,
    validate_windows_execution_provider_pack,
)
from .windows_service_factory_template import (
    WindowsFactoryTemplateError,
    generate_windows_service_factory_template,
    validate_windows_service_factory_template,
)


CANDIDATE_INPUT_SCHEMA = (
    "windows-execution-configured-candidate-input-v1"
)
CANDIDATE_SCHEMA = "windows-execution-configured-candidate-v1"
CANDIDATE_RECEIPT_NAME = "EXECUTION_CONFIGURED_CANDIDATE.json"
CANDIDATE_STATUS = "EXTERNAL_PROVIDER_CONFORMANCE_REQUIRED"
EXECUTION_PROFILE = "WINDOWS_GATED_EXECUTION_SERVICE_V1"
EXECUTION_ROLE = "EXECUTION"
CONFIGURED_ARCHIVE_NAME = "execution-configured-v1.zip"
CONFIGURED_SIDECAR_NAME = (
    "execution-configured-v1.zip.manifest.json"
)
FACTORY_TEMPLATE_NAME = "execution-factory-template.json"
OVERLAY_DESCRIPTOR_NAME = "configured-overlay.json"
TASK_DEFINITION_NAME = "reviewed-task-definition.xml"
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
_PACK_FILES = tuple(
    f"{_PACK_PREFIX}/{path}" for path in GENERATED_PATHS
)
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
_ALL_FILES = frozenset(
    {*_NON_RECEIPT_FILES, CANDIDATE_RECEIPT_NAME}
)
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


class ExecutionConfiguredCandidateError(RuntimeError):
    """One candidate failed closed with a stable, non-secret reason."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: str) -> None:
        normalized = str(reason_code or "").strip().upper()
        if _REASON.fullmatch(normalized) is None:
            normalized = "EXECUTION_CONFIGURED_CANDIDATE_INVALID"
        self.reason_code = normalized
        super().__init__(normalized)


@dataclass(frozen=True, slots=True)
class WindowsExecutionConfiguredCandidate:
    """Pure-data receipt for one exact immutable candidate."""

    output_root: str
    candidate_id: str
    runtime_mode: str
    base_suite_identity_sha256: str
    base_suite_manifest_sha256: str
    execution_base_release_identity_sha256: str
    execution_base_archive_sha256: str
    provider_pack_identity_sha256: str
    provider_configuration_sha256: str
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
            or type(self.output_root) is not str
            or not self.output_root
            or _ID.fullmatch(self.candidate_id) is None
            or self.runtime_mode not in {"DEMO", "DEMO_AUTO"}
            or any(
                type(value) is not str
                or _HASH.fullmatch(value) is None
                or value == "0" * 64
                for value in hashes
            )
            or self.provider_count != len(EXECUTION_PROVIDER_ROLES)
            or self.credential_reference_count
            != len(EXECUTION_CREDENTIAL_PURPOSES)
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
            raise ValueError(
                "Execution configured candidate safety drift"
            )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: object, *, newline: bool = False) -> bytes:
    try:
        result = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_DOCUMENT_INVALID"
        ) from exc
    return result + (b"\n" if newline else b"")


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _strict_json(
    data: bytes,
    reason_code: str,
    *,
    canonical: bool = True,
) -> dict[str, Any]:
    if (
        type(data) is not bytes
        or not data
        or len(data) > MAX_DOCUMENT_BYTES
    ):
        raise ExecutionConfiguredCandidateError(reason_code)
    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON")
            ),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ExecutionConfiguredCandidateError(reason_code) from exc
    if type(value) is not dict or (
        canonical and _canonical_bytes(value, newline=True) != data
    ):
        raise ExecutionConfiguredCandidateError(reason_code)
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
    try:
        before = path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or _is_reparse(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            raise OSError("unsafe candidate member")
        flags = os.O_RDONLY
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if _identity(before) != _identity(opened):
                raise OSError("candidate member changed")
            chunks: list[bytes] = []
            remaining = maximum_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 65_536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
        finally:
            os.close(descriptor)
        after = path.lstat()
        if (
            _identity(before) != _identity(after)
            or len(data) != before.st_size
            or not data
            or len(data) > maximum_bytes
        ):
            raise OSError("candidate member changed")
        return data
    except (FileNotFoundError, OSError) as exc:
        raise ExecutionConfiguredCandidateError(reason_code) from exc


def _existing_root(path: str | Path, reason_code: str) -> Path:
    root = Path(path).expanduser().absolute()
    try:
        metadata = root.lstat()
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ExecutionConfiguredCandidateError(reason_code) from exc
    if (
        root != resolved
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise ExecutionConfiguredCandidateError(reason_code)
    return root


def _new_root(path: str | Path) -> Path:
    root = Path(path).expanduser().absolute()
    if root.exists() or root.is_symlink():
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_OUTPUT_EXISTS"
        )
    try:
        parent = root.parent.lstat()
    except OSError as exc:
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_OUTPUT_PARENT_INVALID"
        ) from exc
    if (
        stat.S_ISLNK(parent.st_mode)
        or _is_reparse(parent)
        or not stat.S_ISDIR(parent.st_mode)
    ):
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_OUTPUT_PARENT_INVALID"
        )
    return root


def _overlap(first: Path, second: Path) -> bool:
    first_parts = first.absolute().parts
    second_parts = second.absolute().parts
    size = min(len(first_parts), len(second_parts))
    return first_parts[:size] == second_parts[:size]


def _mkdir(path: Path) -> None:
    try:
        path.mkdir(mode=0o700)
    except OSError as exc:
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_DIRECTORY_CREATE_FAILED"
        ) from exc


def _write(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_FILE_WRITE_FAILED"
        ) from exc
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short candidate write")
            offset += written
        os.fsync(descriptor)
    except OSError as exc:
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_FILE_WRITE_FAILED"
        ) from exc
    finally:
        os.close(descriptor)


def _cleanup(
    root: Path,
    identity: tuple[int, int, int, int] | None,
) -> None:
    if identity is None:
        return
    try:
        root_metadata = root.lstat()
    except OSError:
        return
    if (
        (
            int(root_metadata.st_dev),
            int(root_metadata.st_ino),
            int(root_metadata.st_mode),
            int(getattr(root_metadata, "st_file_attributes", 0)),
        )
        != identity
        or not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_ISLNK(root_metadata.st_mode)
        or _is_reparse(root_metadata)
    ):
        return
    for relative in sorted(
        _ALL_FILES,
        key=lambda value: len(PurePosixPath(value).parts),
        reverse=True,
    ):
        try:
            path = root / relative
            metadata = path.lstat()
            if stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(
                metadata.st_mode
            ):
                path.unlink()
        except (FileNotFoundError, OSError):
            pass
    for relative in sorted(
        _EXPECTED_DIRECTORIES,
        key=lambda value: len(PurePosixPath(value).parts),
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


def _safe_json(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).casefold() in _SENSITIVE_KEYS:
                raise ExecutionConfiguredCandidateError(
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
        raise ExecutionConfiguredCandidateError(reason_code)
    return value


def _candidate_input(data: bytes) -> dict[str, Any]:
    if any(pattern.search(data) for pattern in _SECRET_PATTERNS):
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_SECRET_PATTERN_FORBIDDEN"
        )
    value = _strict_json(data, "CANDIDATE_INPUT_INVALID")
    _safe_json(value)
    if (
        set(value) != _INPUT_FIELDS
        or value.get("schema_version") != CANDIDATE_INPUT_SCHEMA
    ):
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_INPUT_INVALID"
        )
    bootstrap = _hash(
        value.get("bootstrap_binding_sha256"),
        "CANDIDATE_INPUT_INVALID",
    )
    task = value.get("task_scheduler")
    if not isinstance(task, Mapping) or set(task) != _TASK_FIELDS:
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_TASK_BINDING_INVALID"
        )
    normalized = dict(task)
    for name in (
        "acl_policy_sha256",
        "host_identity_sha256",
        "launcher_path_sha256",
        "release_root_path_sha256",
        "service_account_principal_sha256",
        "service_account_sid_sha256",
    ):
        normalized[name] = _hash(
            normalized.get(name),
            "CANDIDATE_TASK_BINDING_INVALID",
        )
    task_path = normalized.get("task_path")
    if (
        type(task_path) is not str
        or not task_path
        or task_path != task_path.strip()
        or normalized.get("logon_type") != "SERVICE_ACCOUNT"
        or normalized.get("run_level") != "LIMITED"
        or normalized.get("multiple_instances_policy")
        != "IGNORE_NEW"
    ):
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_TASK_BINDING_INVALID"
        )
    return {
        "bootstrap_binding_sha256": bootstrap,
        "schema_version": CANDIDATE_INPUT_SCHEMA,
        "task_scheduler": normalized,
    }


def _inventory(root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    try:
        paths = sorted(root.rglob("*"))
    except OSError as exc:
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_MEMBER_INVALID"
        ) from exc
    for path in paths:
        relative = path.relative_to(root).as_posix()
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ExecutionConfiguredCandidateError(
                "CANDIDATE_MEMBER_INVALID"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
            raise ExecutionConfiguredCandidateError(
                "CANDIDATE_MEMBER_INVALID"
            )
        if stat.S_ISDIR(metadata.st_mode):
            directories.add(relative)
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or relative not in _ALL_FILES
        ):
            raise ExecutionConfiguredCandidateError(
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
    if (
        set(files) != _ALL_FILES
        or directories != _EXPECTED_DIRECTORIES
    ):
        raise ExecutionConfiguredCandidateError(
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
        raise ExecutionConfiguredCandidateError(
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
        "overlay_descriptor_sha256",
        "provider_configuration_sha256",
        "provider_pack_identity_sha256",
        "task_definition_sha256",
    ):
        _hash(result.get(name), "CANDIDATE_RECEIPT_INVALID")
    if (
        type(result.get("candidate_id")) is not str
        or _ID.fullmatch(str(result["candidate_id"])) is None
        or result.get("runtime_mode") not in {"DEMO", "DEMO_AUTO"}
        or result.get("schema_version") != CANDIDATE_SCHEMA
        or result.get("status") != CANDIDATE_STATUS
        or result.get("effects") != _EFFECTS
        or result.get("safety") != _SAFETY
        or result.get("provider_count")
        != len(EXECUTION_PROVIDER_ROLES)
        or result.get("credential_reference_count")
        != len(EXECUTION_CREDENTIAL_PURPOSES)
        or type(result.get("git_commit")) is not str
        or not result["git_commit"]
        or type(result.get("git_tree")) is not str
        or not result["git_tree"]
    ):
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_RECEIPT_INVALID"
        )
    raw_files = result.get("files")
    if type(raw_files) is not list:
        raise ExecutionConfiguredCandidateError(
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
            raise ExecutionConfiguredCandidateError(
                "CANDIDATE_RECEIPT_INVALID"
            )
        paths.append(str(item["path"]))
    if paths != sorted(_NON_RECEIPT_FILES):
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_RECEIPT_INVALID"
        )
    unsigned = dict(result)
    content = unsigned.pop("content_sha256")
    if _sha256(_canonical_bytes(unsigned)) != content:
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_RECEIPT_HASH_MISMATCH"
        )
    return result


def _result(
    root: Path,
    receipt: Mapping[str, Any],
) -> WindowsExecutionConfiguredCandidate:
    return WindowsExecutionConfiguredCandidate(
        output_root=str(root),
        candidate_id=receipt["candidate_id"],
        runtime_mode=receipt["runtime_mode"],
        base_suite_identity_sha256=receipt[
            "base_suite_identity_sha256"
        ],
        base_suite_manifest_sha256=receipt[
            "base_suite_manifest_sha256"
        ],
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
        bootstrap_binding_sha256=receipt[
            "bootstrap_binding_sha256"
        ],
        overlay_descriptor_sha256=receipt[
            "overlay_descriptor_sha256"
        ],
        task_definition_sha256=receipt["task_definition_sha256"],
        configured_release_identity_sha256=receipt[
            "configured_release_identity_sha256"
        ],
        configured_archive_sha256=receipt[
            "configured_archive_sha256"
        ],
        configured_manifest_sha256=receipt[
            "configured_manifest_sha256"
        ],
        execution_factory_template_sha256=receipt[
            "execution_factory_template_sha256"
        ],
        provider_count=receipt["provider_count"],
        credential_reference_count=receipt[
            "credential_reference_count"
        ],
        content_sha256=receipt["content_sha256"],
        _seal=_RESULT_SEAL,
    )


def _provider_configuration(
    provider_module: bytes,
) -> StaticWindowsExecutionProviderConfiguration:
    try:
        raw = extract_windows_execution_provider_configuration(
            provider_module
        )
        return static_windows_execution_provider_configuration_from_dict(
            raw
        )
    except (
        ExecutionProviderPackError,
        TypeError,
        ValueError,
    ) as exc:
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_PROVIDER_CONFIGURATION_INVALID"
        ) from exc


def _factory_template(
    *,
    candidate_id: str,
    configured_identity: str,
    provider_config: StaticWindowsExecutionProviderConfiguration,
    task_binding: Mapping[str, Any],
    task_sha256: str,
    bootstrap_sha256: str,
) -> bytes:
    credentials = [
        {
            "key_id": item.key_id,
            "purpose": item.purpose,
            "reference_id": item.reference_id,
            "target_name": item.target_name,
        }
        for item in provider_config.credential_references
    ]
    providers = [
        {
            "configuration_sha256": item.configuration_sha256,
            "credential_reference_id": (
                item.credential_reference_id
            ),
            "implementation_sha256": item.implementation_sha256,
            "port_name": item.port_name,
            "provider_id": item.provider_id,
        }
        for item in provider_config.provider_bindings
    ]
    task = {
        **dict(task_binding),
        "task_definition_sha256": task_sha256,
    }
    draft = {
        "bootstrap_binding_sha256": bootstrap_sha256,
        "credential_manager_references": credentials,
        "expected_release_identity_sha256": configured_identity,
        "production_config_sha256": (
            provider_config.production_config_sha256
        ),
        "provider_bindings": providers,
        "release_profile": EXECUTION_PROFILE,
        "runtime_mode": provider_config.runtime_mode,
        "service_config_file_sha256": (
            provider_config.service_config_file_sha256
        ),
        "task_scheduler": task,
        "template_id": candidate_id,
    }
    try:
        data = generate_windows_service_factory_template(draft)
        validation = validate_windows_service_factory_template(data)
    except (
        WindowsFactoryTemplateError,
        TypeError,
        ValueError,
    ) as exc:
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_FACTORY_TEMPLATE_INVALID"
        ) from exc
    if (
        validation.expected_release_identity_sha256
        != configured_identity
        or validation.bootstrap_binding_sha256 != bootstrap_sha256
        or validation.production_config_sha256
        != provider_config.production_config_sha256
        or validation.service_config_file_sha256
        != provider_config.service_config_file_sha256
        or validation.provider_count
        != len(EXECUTION_PROVIDER_ROLES)
        or validation.credential_reference_count
        != len(EXECUTION_CREDENTIAL_PURPOSES)
    ):
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_FACTORY_TEMPLATE_BINDING_MISMATCH"
        )
    return data


def assemble_windows_execution_configured_candidate(
    *,
    base_suite_root: str | Path,
    execution_base_release: str | Path,
    provider_pack_root: str | Path,
    task_definition_path: str | Path,
    candidate_input_path: str | Path,
    candidate_id: str,
    output_root: str | Path,
) -> WindowsExecutionConfiguredCandidate:
    """Assemble one immutable candidate without materializing authority."""

    if type(candidate_id) is not str or _ID.fullmatch(candidate_id) is None:
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_ID_INVALID"
        )
    try:
        suite = verify_base_release_suite(base_suite_root)
        role = suite.role(EXECUTION_ROLE)
        original = validate_windows_execution_provider_pack(
            base_suite_root=base_suite_root,
            execution_base_release=execution_base_release,
            pack_root=provider_pack_root,
        )
    except (
        BaseReleaseSuiteVerificationError,
        ExecutionProviderPackError,
        KeyError,
    ) as exc:
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_INPUT_INVALID"
        ) from exc
    pack_root = _existing_root(
        provider_pack_root,
        "CANDIDATE_PROVIDER_PACK_INVALID",
    )
    task_path = Path(task_definition_path).expanduser().absolute()
    input_path = Path(candidate_input_path).expanduser().absolute()
    output = Path(output_root).expanduser().absolute()
    if (
        _overlap(output, pack_root)
        or _overlap(output, suite.root)
        or output == task_path
        or output == input_path
    ):
        raise ExecutionConfiguredCandidateError(
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
    if any(pattern.search(task_bytes) for pattern in _SECRET_PATTERNS):
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_TASK_SECRET_PATTERN_FORBIDDEN"
        )
    candidate_input = _candidate_input(
        _stable_read(
            input_path,
            maximum_bytes=MAX_DOCUMENT_BYTES,
            reason_code="CANDIDATE_INPUT_INVALID",
        )
    )
    provider_config = _provider_configuration(
        pack_bytes[
            "configured_providers/execution_provider.py"
        ]
    )
    if (
        provider_config.base_suite_identity_sha256
        != suite.suite_identity_sha256
        or provider_config.execution_base_release_identity_sha256
        != role.release_identity_sha256
        or provider_config.content_sha256
        != original.provider_configuration_sha256
    ):
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_PROVIDER_CONFIGURATION_MISMATCH"
        )

    root = _new_root(output)
    root_identity: tuple[int, int, int, int] | None = None
    try:
        _mkdir(root)
        root_metadata = root.lstat()
        root_identity = (
            int(root_metadata.st_dev),
            int(root_metadata.st_ino),
            int(root_metadata.st_mode),
            int(getattr(root_metadata, "st_file_attributes", 0)),
        )
        for relative in sorted(
            _EXPECTED_DIRECTORIES,
            key=lambda value: (
                len(PurePosixPath(value).parts),
                value,
            ),
        ):
            _mkdir(root / relative)
        for relative, data in pack_bytes.items():
            _write(root / _PACK_PREFIX / relative, data)
            _write(root / _OVERLAY_PREFIX / relative, data)
        _write(root / TASK_DEFINITION_NAME, task_bytes)

        copied = validate_windows_execution_provider_pack(
            base_suite_root=base_suite_root,
            execution_base_release=execution_base_release,
            pack_root=root / _PACK_PREFIX,
        )
        if copied.pack_identity_sha256 != original.pack_identity_sha256:
            raise ExecutionConfiguredCandidateError(
                "CANDIDATE_PROVIDER_PACK_COPY_MISMATCH"
            )
        descriptor_path = root / OVERLAY_DESCRIPTOR_NAME
        try:
            prepare_configured_overlay_candidate(
                base_archive=execution_base_release,
                overlay_root=root / _OVERLAY_PREFIX,
                task_definition_path=root / TASK_DEFINITION_NAME,
                overlay_id=candidate_id,
                bootstrap_binding_sha256=candidate_input[
                    "bootstrap_binding_sha256"
                ],
                runtime_mode=provider_config.runtime_mode,
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
            raise ExecutionConfiguredCandidateError(
                "CANDIDATE_CONFIGURED_RELEASE_INVALID"
            ) from exc
        if (
            configured.release_profile != EXECUTION_PROFILE
            or configured.runtime_mode != provider_config.runtime_mode
            or not configured.base_release_suite_bound
            or configured.base_release_suite_role != EXECUTION_ROLE
            or configured.base_release_suite_identity_sha256
            != suite.suite_identity_sha256
            or configured.production_execution_ready
            or configured.order_capability != "GATED_PRESENT"
            or configured.live_allowed
            or configured.safe_to_demo_auto_order
        ):
            raise ExecutionConfiguredCandidateError(
                "CANDIDATE_CONFIGURED_RELEASE_AUTHORITY_DRIFT"
            )
        template = _factory_template(
            candidate_id=candidate_id,
            configured_identity=configured.release_identity_sha256,
            provider_config=provider_config,
            task_binding=candidate_input["task_scheduler"],
            task_sha256=_sha256(task_bytes),
            bootstrap_sha256=candidate_input[
                "bootstrap_binding_sha256"
            ],
        )
        _write(root / FACTORY_TEMPLATE_NAME, template)

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
            "base_suite_identity_sha256": (
                suite.suite_identity_sha256
            ),
            "base_suite_manifest_sha256": suite.manifest_sha256,
            "bootstrap_binding_sha256": candidate_input[
                "bootstrap_binding_sha256"
            ],
            "candidate_id": candidate_id,
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
                EXECUTION_CREDENTIAL_PURPOSES
            ),
            "effects": dict(_EFFECTS),
            "execution_base_archive_sha256": role.archive_sha256,
            "execution_base_release_identity_sha256": (
                role.release_identity_sha256
            ),
            "execution_factory_template_sha256": _sha256(template),
            "files": _entries(non_receipt),
            "git_commit": suite.git_commit,
            "git_tree": suite.git_tree,
            "overlay_descriptor_sha256": _sha256(
                non_receipt[OVERLAY_DESCRIPTOR_NAME]
            ),
            "provider_configuration_sha256": (
                provider_config.content_sha256
            ),
            "provider_count": len(EXECUTION_PROVIDER_ROLES),
            "provider_pack_identity_sha256": (
                original.pack_identity_sha256
            ),
            "runtime_mode": provider_config.runtime_mode,
            "safety": dict(_SAFETY),
            "schema_version": CANDIDATE_SCHEMA,
            "status": CANDIDATE_STATUS,
            "task_definition_sha256": _sha256(task_bytes),
        }
        receipt["content_sha256"] = _sha256(
            _canonical_bytes(receipt)
        )
        receipt = _receipt(receipt)
        _write(
            root / CANDIDATE_RECEIPT_NAME,
            _canonical_bytes(receipt, newline=True),
        )
        return validate_windows_execution_configured_candidate(
            base_suite_root=base_suite_root,
            execution_base_release=execution_base_release,
            candidate_root=root,
        )
    except Exception:
        _cleanup(root, root_identity)
        raise


def validate_windows_execution_configured_candidate(
    *,
    base_suite_root: str | Path,
    execution_base_release: str | Path,
    candidate_root: str | Path,
) -> WindowsExecutionConfiguredCandidate:
    """Validate exact candidate bytes without importing generated code."""

    root = _existing_root(
        candidate_root,
        "CANDIDATE_ROOT_INVALID",
    )
    files = _inventory(root)
    receipt = _receipt(
        _strict_json(
            files[CANDIDATE_RECEIPT_NAME],
            "CANDIDATE_RECEIPT_INVALID",
        )
    )
    try:
        suite = verify_base_release_suite(base_suite_root)
        role = suite.role(EXECUTION_ROLE)
        pack = validate_windows_execution_provider_pack(
            base_suite_root=base_suite_root,
            execution_base_release=execution_base_release,
            pack_root=root / _PACK_PREFIX,
        )
    except (
        BaseReleaseSuiteVerificationError,
        ExecutionProviderPackError,
        KeyError,
    ) as exc:
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_BASE_OR_PACK_INVALID"
        ) from exc
    for relative in GENERATED_PATHS:
        if (
            files[f"{_PACK_PREFIX}/{relative}"]
            != files[f"{_OVERLAY_PREFIX}/{relative}"]
        ):
            raise ExecutionConfiguredCandidateError(
                "CANDIDATE_PROVIDER_PACK_OVERLAY_MISMATCH"
            )
    provider_config = _provider_configuration(
        files[
            f"{_PACK_PREFIX}/configured_providers/"
            "execution_provider.py"
        ]
    )
    try:
        configured = verify_configured_service_release(
            root / CONFIGURED_ARCHIVE_NAME,
            expected_release_identity_sha256=receipt[
                "configured_release_identity_sha256"
            ],
            expected_base_release_identity_sha256=(
                role.release_identity_sha256
            ),
        )
        template = validate_windows_service_factory_template(
            files[FACTORY_TEMPLATE_NAME]
        )
    except (
        ConfiguredReleaseError,
        WindowsFactoryTemplateError,
        TypeError,
        ValueError,
    ) as exc:
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_CONFIGURED_ARTIFACT_INVALID"
        ) from exc
    if (
        configured.release_profile != EXECUTION_PROFILE
        or configured.runtime_mode != provider_config.runtime_mode
        or configured.base_release_suite_role != EXECUTION_ROLE
        or configured.base_release_suite_identity_sha256
        != suite.suite_identity_sha256
        or configured.production_execution_ready
        or configured.order_capability != "GATED_PRESENT"
        or template.expected_release_identity_sha256
        != configured.release_identity_sha256
        or template.bootstrap_binding_sha256
        != receipt["bootstrap_binding_sha256"]
        or template.production_config_sha256
        != provider_config.production_config_sha256
        or template.service_config_file_sha256
        != provider_config.service_config_file_sha256
        or template.runtime_mode != provider_config.runtime_mode
        or template.provider_count != len(EXECUTION_PROVIDER_ROLES)
        or template.credential_reference_count
        != len(EXECUTION_CREDENTIAL_PURPOSES)
    ):
        raise ExecutionConfiguredCandidateError(
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
        "bootstrap_binding_sha256": (
            template.bootstrap_binding_sha256
        ),
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
            EXECUTION_CREDENTIAL_PURPOSES
        ),
        "effects": dict(_EFFECTS),
        "execution_base_archive_sha256": role.archive_sha256,
        "execution_base_release_identity_sha256": (
            role.release_identity_sha256
        ),
        "execution_factory_template_sha256": _sha256(
            files[FACTORY_TEMPLATE_NAME]
        ),
        "files": _entries(non_receipt),
        "git_commit": suite.git_commit,
        "git_tree": suite.git_tree,
        "overlay_descriptor_sha256": _sha256(
            files[OVERLAY_DESCRIPTOR_NAME]
        ),
        "provider_configuration_sha256": (
            provider_config.content_sha256
        ),
        "provider_count": len(EXECUTION_PROVIDER_ROLES),
        "provider_pack_identity_sha256": pack.pack_identity_sha256,
        "runtime_mode": provider_config.runtime_mode,
        "safety": dict(_SAFETY),
        "schema_version": CANDIDATE_SCHEMA,
        "status": CANDIDATE_STATUS,
        "task_definition_sha256": _sha256(
            files[TASK_DEFINITION_NAME]
        ),
    }
    expected["content_sha256"] = _sha256(
        _canonical_bytes(expected)
    )
    if receipt != expected:
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_RECEIPT_CROSS_BINDING_MISMATCH"
        )
    if (
        provider_config.content_sha256
        != pack.provider_configuration_sha256
        or provider_config.base_suite_identity_sha256
        != suite.suite_identity_sha256
        or provider_config.execution_base_release_identity_sha256
        != role.release_identity_sha256
        or receipt["execution_base_archive_sha256"]
        != role.archive_sha256
    ):
        raise ExecutionConfiguredCandidateError(
            "CANDIDATE_PROVIDER_BINDING_MISMATCH"
        )
    return _result(root, receipt)


__all__ = [
    "CANDIDATE_INPUT_SCHEMA",
    "CANDIDATE_RECEIPT_NAME",
    "CANDIDATE_SCHEMA",
    "CANDIDATE_STATUS",
    "ExecutionConfiguredCandidateError",
    "WindowsExecutionConfiguredCandidate",
    "assemble_windows_execution_configured_candidate",
    "validate_windows_execution_configured_candidate",
]
