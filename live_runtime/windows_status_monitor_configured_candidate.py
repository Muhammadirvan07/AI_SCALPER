"""Assemble one deny-only configured Windows Status Monitor candidate.

This release-operator boundary copies and binds already verified artifacts.
It never imports a provider factory, resolves credentials, opens provider
state, issues external requests, installs a task, starts a process,
initializes MT5, mutates a broker, or submits an order.
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
    build_configured_service_release,
    prepare_configured_overlay_candidate,
    verify_configured_service_release,
)
from .contracts import canonical_sha256
from .windows_base_release_suite import (
    BaseReleaseSuiteVerificationError,
    verify_base_release_suite,
)
from .windows_external_status_monitor_factory_template import (
    MONITOR_PROVIDER_ROLES,
    WindowsExternalStatusMonitorFactoryTemplate,
    validate_windows_external_status_monitor_factory_template,
)
from .windows_status_monitor_provider_pack_generator import (
    GENERATED_PATHS,
    StatusMonitorProviderPackError,
    validate_windows_status_monitor_runtime_configuration,
    validate_windows_status_monitor_provider_pack,
)


CANDIDATE_SCHEMA = "windows-status-monitor-configured-candidate-v1"
CANDIDATE_RECEIPT_NAME = "STATUS_MONITOR_CONFIGURED_CANDIDATE.json"
CANDIDATE_STATUS = "EXTERNAL_PROVIDER_CONFORMANCE_REQUIRED"
STATUS_MONITOR_PROFILE = "WINDOWS_EXTERNAL_STATUS_MONITOR_V1"
STATUS_MONITOR_ROLE = "STATUS_MONITOR"
CONFIGURED_ARCHIVE_NAME = "status-monitor-configured-v1.zip"
CONFIGURED_SIDECAR_NAME = (
    "status-monitor-configured-v1.zip.manifest.json"
)
FACTORY_TEMPLATE_NAME = "status-monitor-factory-template.json"
OVERLAY_DESCRIPTOR_NAME = "configured-overlay.json"
TASK_DEFINITION_NAME = "reviewed-task-definition.xml"
MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_LOT = 0.01

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bgh[oprsu]_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
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
    "max_lot": 0.01,
    "order_capability": "DISABLED",
    "production_execution_ready": False,
    "promotion_eligible": False,
    "provider_accepted": False,
    "safe_to_demo_auto_order": False,
    "status_only": True,
}
_PACK_PREFIX = "provider-pack"
_OVERLAY_PREFIX = "configured-overlay"
_PACK_FILES = tuple(
    f"{_PACK_PREFIX}/{path}" for path in GENERATED_PATHS
)
_OVERLAY_ORIGINAL_FILES = tuple(
    f"{_OVERLAY_PREFIX}/{path}" for path in GENERATED_PATHS
)
_OVERLAY_MANIFEST = (
    f"{_OVERLAY_PREFIX}/config/windows_factory_manifest.json"
)
_NON_RECEIPT_FILES = frozenset(
    {
        *_PACK_FILES,
        *_OVERLAY_ORIGINAL_FILES,
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
        "effects",
        "files",
        "git_commit",
        "git_tree",
        "overlay_descriptor_sha256",
        "provider_count",
        "provider_pack_identity_sha256",
        "safety",
        "schema_version",
        "status",
        "status_monitor_base_archive_sha256",
        "status_monitor_base_release_identity_sha256",
        "status_monitor_factory_template_sha256",
        "task_definition_sha256",
    }
)
_RESULT_SEAL = object()


class StatusMonitorConfiguredCandidateError(RuntimeError):
    """One configured candidate failed closed."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: str) -> None:
        normalized = str(reason_code or "").strip().upper()
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", normalized) is None:
            normalized = "STATUS_MONITOR_CONFIGURED_CANDIDATE_INVALID"
        self.reason_code = normalized
        super().__init__(normalized)


@dataclass(frozen=True, slots=True)
class WindowsStatusMonitorConfiguredCandidate:
    output_root: str
    candidate_id: str
    base_suite_identity_sha256: str
    base_suite_manifest_sha256: str
    status_monitor_base_release_identity_sha256: str
    status_monitor_base_archive_sha256: str
    provider_pack_identity_sha256: str
    bootstrap_binding_sha256: str
    overlay_descriptor_sha256: str
    task_definition_sha256: str
    configured_release_identity_sha256: str
    configured_archive_sha256: str
    configured_manifest_sha256: str
    status_monitor_factory_template_sha256: str
    provider_count: int
    content_sha256: str
    status: str = CANDIDATE_STATUS
    status_only: bool = True
    provider_accepted: bool = False
    production_execution_ready: bool = False
    credential_access_performed: bool = False
    provider_imported: bool = False
    provider_materialized: bool = False
    provider_request_performed: bool = False
    sqlite_open_performed: bool = False
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
            self.status_monitor_base_release_identity_sha256,
            self.status_monitor_base_archive_sha256,
            self.provider_pack_identity_sha256,
            self.bootstrap_binding_sha256,
            self.overlay_descriptor_sha256,
            self.task_definition_sha256,
            self.configured_release_identity_sha256,
            self.configured_archive_sha256,
            self.configured_manifest_sha256,
            self.status_monitor_factory_template_sha256,
            self.content_sha256,
        )
        if (
            _seal is not _RESULT_SEAL
            or type(self.output_root) is not str
            or not self.output_root
            or _ID.fullmatch(self.candidate_id) is None
            or any(
                _HASH.fullmatch(value) is None or value == "0" * 64
                for value in hashes
            )
            or self.provider_count != len(MONITOR_PROVIDER_ROLES)
            or self.status != CANDIDATE_STATUS
            or self.status_only is not True
            or self.provider_accepted is not False
            or self.production_execution_ready is not False
            or self.credential_access_performed is not False
            or self.provider_imported is not False
            or self.provider_materialized is not False
            or self.provider_request_performed is not False
            or self.sqlite_open_performed is not False
            or self.task_installation_performed is not False
            or self.broker_mutation_performed is not False
            or self.order_capability != "DISABLED"
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or self.max_lot != MAX_LOT
            or self.promotion_eligible is not False
            or self.schema_version != CANDIDATE_SCHEMA
        ):
            raise ValueError("Status Monitor configured candidate safety drift")


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
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_DOCUMENT_INVALID"
        ) from exc
    return data + (b"\n" if newline else b"")


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _strict_json(data: bytes, code: str) -> dict[str, Any]:
    if (
        type(data) is not bytes
        or not data
        or len(data) > MAX_DOCUMENT_BYTES
    ):
        raise StatusMonitorConfiguredCandidateError(code)
    try:
        parsed = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite")
            ),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise StatusMonitorConfiguredCandidateError(code) from exc
    if (
        type(parsed) is not dict
        or _canonical_bytes(parsed, newline=True) != data
    ):
        raise StatusMonitorConfiguredCandidateError(code)
    return parsed


def _is_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse and attributes & reparse)


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _stable_read(
    path: Path,
    *,
    maximum_bytes: int,
    code: str,
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
            raise OSError("unsafe candidate file")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if _identity(before) != _identity(opened):
                raise OSError("file identity changed")
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
            raise OSError("candidate file changed")
        return data
    except (FileNotFoundError, OSError) as exc:
        raise StatusMonitorConfiguredCandidateError(code) from exc


def _safe_existing_root(path: str | Path, code: str) -> Path:
    root = Path(path).expanduser().absolute()
    try:
        metadata = root.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise StatusMonitorConfiguredCandidateError(code) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise StatusMonitorConfiguredCandidateError(code)
    return root


def _safe_new_root(path: str | Path) -> Path:
    root = Path(path).expanduser().absolute()
    if root.exists() or root.is_symlink():
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_OUTPUT_EXISTS"
        )
    try:
        parent = root.parent.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_OUTPUT_PARENT_INVALID"
        ) from exc
    if (
        stat.S_ISLNK(parent.st_mode)
        or _is_reparse(parent)
        or not stat.S_ISDIR(parent.st_mode)
    ):
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_OUTPUT_PARENT_INVALID"
        )
    return root


def _overlap(first: Path, second: Path) -> bool:
    first_parts = first.absolute().parts
    second_parts = second.absolute().parts
    length = min(len(first_parts), len(second_parts))
    return first_parts[:length] == second_parts[:length]


def _mkdir(path: Path) -> None:
    try:
        path.mkdir(mode=0o700)
    except OSError as exc:
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_DIRECTORY_CREATE_FAILED"
        ) from exc


def _write(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_FILE_WRITE_FAILED"
        ) from exc
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.fsync(descriptor)
    except OSError as exc:
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_FILE_WRITE_FAILED"
        ) from exc
    finally:
        os.close(descriptor)


def _cleanup(root: Path) -> None:
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


def _inventory(root: Path) -> dict[str, bytes]:
    files = {}
    directories = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
            raise StatusMonitorConfiguredCandidateError(
                "CANDIDATE_MEMBER_INVALID"
            )
        if stat.S_ISDIR(metadata.st_mode):
            directories.add(relative)
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or relative not in _ALL_FILES
        ):
            raise StatusMonitorConfiguredCandidateError(
                "CANDIDATE_MEMBER_INVALID"
            )
        files[relative] = _stable_read(
            path,
            maximum_bytes=(
                MAX_ARCHIVE_BYTES
                if relative == CONFIGURED_ARCHIVE_NAME
                else MAX_DOCUMENT_BYTES
            ),
            code="CANDIDATE_MEMBER_INVALID",
        )
    if (
        set(files) != _ALL_FILES
        or directories != _EXPECTED_DIRECTORIES
    ):
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_MEMBER_INVALID"
        )
    return files


def _file_entries(
    files: Mapping[str, bytes],
) -> list[dict[str, object]]:
    return [
        {
            "path": path,
            "sha256": _sha256(files[path]),
            "size_bytes": len(files[path]),
        }
        for path in sorted(files)
    ]


def _validated_receipt(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _RECEIPT_FIELDS:
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_RECEIPT_INVALID"
        )
    receipt = dict(value)
    for name in (
        "base_suite_identity_sha256",
        "base_suite_manifest_sha256",
        "bootstrap_binding_sha256",
        "configured_archive_sha256",
        "configured_manifest_sha256",
        "configured_release_identity_sha256",
        "content_sha256",
        "overlay_descriptor_sha256",
        "provider_pack_identity_sha256",
        "status_monitor_base_archive_sha256",
        "status_monitor_base_release_identity_sha256",
        "status_monitor_factory_template_sha256",
        "task_definition_sha256",
    ):
        if (
            type(receipt[name]) is not str
            or _HASH.fullmatch(receipt[name]) is None
            or receipt[name] == "0" * 64
        ):
            raise StatusMonitorConfiguredCandidateError(
                "CANDIDATE_RECEIPT_INVALID"
            )
    if (
        type(receipt["candidate_id"]) is not str
        or _ID.fullmatch(receipt["candidate_id"]) is None
        or receipt["schema_version"] != CANDIDATE_SCHEMA
        or receipt["status"] != CANDIDATE_STATUS
        or receipt["effects"] != _EFFECTS
        or receipt["safety"] != _SAFETY
        or receipt["provider_count"] != len(MONITOR_PROVIDER_ROLES)
        or type(receipt["git_commit"]) is not str
        or not receipt["git_commit"]
        or type(receipt["git_tree"]) is not str
        or not receipt["git_tree"]
    ):
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_RECEIPT_INVALID"
        )
    raw_files = receipt["files"]
    if type(raw_files) is not list:
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_RECEIPT_INVALID"
        )
    paths = []
    for item in raw_files:
        if (
            not isinstance(item, Mapping)
            or set(item) != _FILE_ENTRY_FIELDS
            or type(item["path"]) is not str
            or item["path"] not in _NON_RECEIPT_FILES
            or type(item["size_bytes"]) is not int
            or item["size_bytes"] <= 0
            or type(item["sha256"]) is not str
            or _HASH.fullmatch(item["sha256"]) is None
        ):
            raise StatusMonitorConfiguredCandidateError(
                "CANDIDATE_RECEIPT_INVALID"
            )
        paths.append(item["path"])
    if paths != sorted(_NON_RECEIPT_FILES):
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_RECEIPT_INVALID"
        )
    unsigned = dict(receipt)
    content = unsigned.pop("content_sha256")
    if _sha256(_canonical_bytes(unsigned)) != content:
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_RECEIPT_HASH_MISMATCH"
        )
    return receipt


def _result(
    root: Path,
    receipt: Mapping[str, Any],
) -> WindowsStatusMonitorConfiguredCandidate:
    return WindowsStatusMonitorConfiguredCandidate(
        output_root=str(root),
        candidate_id=receipt["candidate_id"],
        base_suite_identity_sha256=(
            receipt["base_suite_identity_sha256"]
        ),
        base_suite_manifest_sha256=(
            receipt["base_suite_manifest_sha256"]
        ),
        status_monitor_base_release_identity_sha256=(
            receipt[
                "status_monitor_base_release_identity_sha256"
            ]
        ),
        status_monitor_base_archive_sha256=(
            receipt["status_monitor_base_archive_sha256"]
        ),
        provider_pack_identity_sha256=(
            receipt["provider_pack_identity_sha256"]
        ),
        bootstrap_binding_sha256=(
            receipt["bootstrap_binding_sha256"]
        ),
        overlay_descriptor_sha256=(
            receipt["overlay_descriptor_sha256"]
        ),
        task_definition_sha256=receipt["task_definition_sha256"],
        configured_release_identity_sha256=(
            receipt["configured_release_identity_sha256"]
        ),
        configured_archive_sha256=(
            receipt["configured_archive_sha256"]
        ),
        configured_manifest_sha256=(
            receipt["configured_manifest_sha256"]
        ),
        status_monitor_factory_template_sha256=(
            receipt["status_monitor_factory_template_sha256"]
        ),
        provider_count=receipt["provider_count"],
        content_sha256=receipt["content_sha256"],
        _seal=_RESULT_SEAL,
    )


def validate_windows_status_monitor_configured_candidate(
    *,
    base_suite_root: str | Path,
    status_monitor_base_release: str | Path,
    candidate_root: str | Path,
) -> WindowsStatusMonitorConfiguredCandidate:
    """Validate one complete candidate without provider effects."""

    try:
        suite = verify_base_release_suite(base_suite_root)
        role = suite.role(STATUS_MONITOR_ROLE)
    except (BaseReleaseSuiteVerificationError, KeyError) as exc:
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_BASE_SUITE_INVALID"
        ) from exc
    if (
        role.archive_path
        != Path(status_monitor_base_release).expanduser().absolute()
    ):
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_BASE_SUITE_INVALID"
        )
    root = _safe_existing_root(
        candidate_root,
        "CANDIDATE_ROOT_INVALID",
    )
    files = _inventory(root)
    receipt = _validated_receipt(
        _strict_json(
            files[CANDIDATE_RECEIPT_NAME],
            "CANDIDATE_RECEIPT_INVALID",
        )
    )
    try:
        pack = validate_windows_status_monitor_provider_pack(
            base_suite_root=base_suite_root,
            status_monitor_base_release=status_monitor_base_release,
            pack_root=root / _PACK_PREFIX,
        )
    except StatusMonitorProviderPackError as exc:
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_PROVIDER_PACK_INVALID"
        ) from exc
    for relative in GENERATED_PATHS:
        if (
            files[f"{_PACK_PREFIX}/{relative}"]
            != files[f"{_OVERLAY_PREFIX}/{relative}"]
        ):
            raise StatusMonitorConfiguredCandidateError(
                "CANDIDATE_OVERLAY_PROVIDER_PACK_MISMATCH"
            )
    try:
        configured = verify_configured_service_release(
            root / CONFIGURED_ARCHIVE_NAME,
            expected_release_identity_sha256=(
                receipt["configured_release_identity_sha256"]
            ),
            expected_base_release_identity_sha256=(
                role.release_identity_sha256
            ),
        )
    except Exception as exc:
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_CONFIGURED_RELEASE_INVALID"
        ) from exc
    try:
        runtime, runtime_bindings = (
            validate_windows_status_monitor_runtime_configuration(
                _strict_json(
                    files[
                        f"{_PACK_PREFIX}/config/windows_service_config.json"
                    ],
                    "CANDIDATE_RUNTIME_CONFIG_INVALID",
                )
            )
        )
    except (
        StatusMonitorProviderPackError,
        TypeError,
        ValueError,
    ) as exc:
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_RUNTIME_CONFIG_INVALID"
        ) from exc
    bootstrap = canonical_sha256(runtime)
    factory_bytes = files[
        f"{_OVERLAY_PREFIX}/reviewed_windows_factory.py"
    ]
    config_bytes = files[
        f"{_OVERLAY_PREFIX}/config/windows_service_config.json"
    ]
    try:
        template_payload = _strict_json(
            files[FACTORY_TEMPLATE_NAME],
            "CANDIDATE_FACTORY_TEMPLATE_INVALID",
        )
        template = (
            validate_windows_external_status_monitor_factory_template(
                template_payload,
                expected_release_identity_sha256=(
                    configured.release_identity_sha256
                ),
            )
        )
    except (TypeError, ValueError) as exc:
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_FACTORY_TEMPLATE_INVALID"
        ) from exc
    expected_template = WindowsExternalStatusMonitorFactoryTemplate(
        service_id=runtime["monitor_service_id"],
        monitor_provider_id=runtime["monitor_provider_id"],
        release_identity_sha256=configured.release_identity_sha256,
        factory_implementation_sha256=_sha256(factory_bytes),
        factory_configuration_sha256=_sha256(config_bytes),
        providers=runtime_bindings,
    )
    if template != expected_template:
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_FACTORY_TEMPLATE_MISMATCH"
        )
    non_receipt = {
        path: files[path] for path in _NON_RECEIPT_FILES
    }
    expected_receipt: dict[str, Any] = {
        "base_suite_identity_sha256": suite.suite_identity_sha256,
        "base_suite_manifest_sha256": suite.manifest_sha256,
        "bootstrap_binding_sha256": bootstrap,
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
        "effects": dict(_EFFECTS),
        "files": _file_entries(non_receipt),
        "git_commit": suite.git_commit,
        "git_tree": suite.git_tree,
        "overlay_descriptor_sha256": _sha256(
            files[OVERLAY_DESCRIPTOR_NAME]
        ),
        "provider_count": len(MONITOR_PROVIDER_ROLES),
        "provider_pack_identity_sha256": (
            pack.pack_identity_sha256
        ),
        "safety": dict(_SAFETY),
        "schema_version": CANDIDATE_SCHEMA,
        "status": CANDIDATE_STATUS,
        "status_monitor_base_archive_sha256": role.archive_sha256,
        "status_monitor_base_release_identity_sha256": (
            role.release_identity_sha256
        ),
        "status_monitor_factory_template_sha256": _sha256(
            files[FACTORY_TEMPLATE_NAME]
        ),
        "task_definition_sha256": _sha256(
            files[TASK_DEFINITION_NAME]
        ),
    }
    expected_receipt["content_sha256"] = _sha256(
        _canonical_bytes(expected_receipt)
    )
    if receipt != expected_receipt:
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_CROSS_BINDING_MISMATCH"
        )
    if (
        configured.release_profile != STATUS_MONITOR_PROFILE
        or not configured.base_release_suite_bound
        or configured.base_release_suite_role != STATUS_MONITOR_ROLE
        or configured.base_release_suite_identity_sha256
        != suite.suite_identity_sha256
        or configured.production_execution_ready
        or configured.order_capability != "DISABLED"
        or configured.live_allowed
        or configured.safe_to_demo_auto_order
    ):
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_CONFIGURED_AUTHORITY_DRIFT"
        )
    return _result(root, receipt)


def assemble_windows_status_monitor_configured_candidate(
    *,
    base_suite_root: str | Path,
    status_monitor_base_release: str | Path,
    provider_pack_root: str | Path,
    task_definition_path: str | Path,
    candidate_id: str,
    output_root: str | Path,
) -> WindowsStatusMonitorConfiguredCandidate:
    """Assemble one exact immutable Status Monitor candidate."""

    if type(candidate_id) is not str or _ID.fullmatch(candidate_id) is None:
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_ID_INVALID"
        )
    try:
        suite = verify_base_release_suite(base_suite_root)
        role = suite.role(STATUS_MONITOR_ROLE)
        original = validate_windows_status_monitor_provider_pack(
            base_suite_root=base_suite_root,
            status_monitor_base_release=status_monitor_base_release,
            pack_root=provider_pack_root,
        )
    except (
        BaseReleaseSuiteVerificationError,
        StatusMonitorProviderPackError,
        KeyError,
    ) as exc:
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_INPUT_INVALID"
        ) from exc
    original_root = _safe_existing_root(
        provider_pack_root,
        "PROVIDER_PACK_ROOT_INVALID",
    )
    task_path = Path(task_definition_path).expanduser().absolute()
    output = Path(output_root).expanduser().absolute()
    if (
        _overlap(output, original_root)
        or _overlap(output, suite.root)
        or output == task_path
    ):
        raise StatusMonitorConfiguredCandidateError(
            "CANDIDATE_OUTPUT_INPUT_OVERLAP"
        )
    original_bytes = {
        relative: _stable_read(
            original_root / relative,
            maximum_bytes=MAX_DOCUMENT_BYTES,
            code="PROVIDER_PACK_FILE_INVALID",
        )
        for relative in GENERATED_PATHS
    }
    task_bytes = _stable_read(
        task_path,
        maximum_bytes=MAX_DOCUMENT_BYTES,
        code="TASK_DEFINITION_INVALID",
    )
    if any(pattern.search(task_bytes) for pattern in _SECRET_PATTERNS):
        raise StatusMonitorConfiguredCandidateError(
            "TASK_DEFINITION_SECRET_MATERIAL_FORBIDDEN"
        )
    root = _safe_new_root(output)
    created = False
    try:
        _mkdir(root)
        created = True
        for relative in sorted(
            _EXPECTED_DIRECTORIES,
            key=lambda value: (
                len(PurePosixPath(value).parts),
                value,
            ),
        ):
            _mkdir(root / relative)
        for relative, data in original_bytes.items():
            _write(root / _PACK_PREFIX / relative, data)
            _write(root / _OVERLAY_PREFIX / relative, data)
        _write(root / TASK_DEFINITION_NAME, task_bytes)

        copied = validate_windows_status_monitor_provider_pack(
            base_suite_root=base_suite_root,
            status_monitor_base_release=status_monitor_base_release,
            pack_root=root / _PACK_PREFIX,
        )
        if copied.pack_identity_sha256 != original.pack_identity_sha256:
            raise StatusMonitorConfiguredCandidateError(
                "COPIED_PROVIDER_PACK_MISMATCH"
            )
        try:
            runtime, runtime_bindings = (
                validate_windows_status_monitor_runtime_configuration(
                    _strict_json(
                        original_bytes[
                            "config/windows_service_config.json"
                        ],
                        "CANDIDATE_RUNTIME_CONFIG_INVALID",
                    )
                )
            )
        except (
            StatusMonitorProviderPackError,
            TypeError,
            ValueError,
        ) as exc:
            raise StatusMonitorConfiguredCandidateError(
                "CANDIDATE_RUNTIME_CONFIG_INVALID"
            ) from exc
        bootstrap = canonical_sha256(runtime)
        descriptor = root / OVERLAY_DESCRIPTOR_NAME
        prepare_configured_overlay_candidate(
            base_archive=status_monitor_base_release,
            overlay_root=root / _OVERLAY_PREFIX,
            task_definition_path=root / TASK_DEFINITION_NAME,
            overlay_id=candidate_id,
            bootstrap_binding_sha256=bootstrap,
            runtime_mode="DEMO_AUTO",
            descriptor_output_path=descriptor,
        )
        archive = root / CONFIGURED_ARCHIVE_NAME
        built = build_configured_service_release(
            status_monitor_base_release,
            root / _OVERLAY_PREFIX,
            descriptor,
            archive,
            base_release_suite_root=base_suite_root,
        )
        configured = verify_configured_service_release(
            archive,
            expected_release_identity_sha256=str(
                built["release_identity_sha256"]
            ),
            expected_base_release_identity_sha256=(
                role.release_identity_sha256
            ),
        )
        factory_bytes = _stable_read(
            root / _OVERLAY_PREFIX / "reviewed_windows_factory.py",
            maximum_bytes=MAX_DOCUMENT_BYTES,
            code="CANDIDATE_FACTORY_INVALID",
        )
        config_bytes = _stable_read(
            root
            / _OVERLAY_PREFIX
            / "config/windows_service_config.json",
            maximum_bytes=MAX_DOCUMENT_BYTES,
            code="CANDIDATE_RUNTIME_CONFIG_INVALID",
        )
        template = WindowsExternalStatusMonitorFactoryTemplate(
            service_id=runtime["monitor_service_id"],
            monitor_provider_id=runtime["monitor_provider_id"],
            release_identity_sha256=(
                configured.release_identity_sha256
            ),
            factory_implementation_sha256=_sha256(factory_bytes),
            factory_configuration_sha256=_sha256(config_bytes),
            providers=runtime_bindings,
        )
        template_bytes = _canonical_bytes(
            template.to_canonical_dict(),
            newline=True,
        )
        validate_windows_external_status_monitor_factory_template(
            _strict_json(
                template_bytes,
                "CANDIDATE_FACTORY_TEMPLATE_INVALID",
            ),
            expected_release_identity_sha256=(
                configured.release_identity_sha256
            ),
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
                code="CANDIDATE_FILE_INVALID",
            )
            for relative in sorted(_NON_RECEIPT_FILES)
        }
        receipt: dict[str, Any] = {
            "base_suite_identity_sha256": (
                suite.suite_identity_sha256
            ),
            "base_suite_manifest_sha256": suite.manifest_sha256,
            "bootstrap_binding_sha256": bootstrap,
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
            "effects": dict(_EFFECTS),
            "files": _file_entries(non_receipt),
            "git_commit": suite.git_commit,
            "git_tree": suite.git_tree,
            "overlay_descriptor_sha256": _sha256(
                non_receipt[OVERLAY_DESCRIPTOR_NAME]
            ),
            "provider_count": len(MONITOR_PROVIDER_ROLES),
            "provider_pack_identity_sha256": (
                original.pack_identity_sha256
            ),
            "safety": dict(_SAFETY),
            "schema_version": CANDIDATE_SCHEMA,
            "status": CANDIDATE_STATUS,
            "status_monitor_base_archive_sha256": role.archive_sha256,
            "status_monitor_base_release_identity_sha256": (
                role.release_identity_sha256
            ),
            "status_monitor_factory_template_sha256": _sha256(
                template_bytes
            ),
            "task_definition_sha256": _sha256(task_bytes),
        }
        receipt["content_sha256"] = _sha256(
            _canonical_bytes(receipt)
        )
        _write(
            root / CANDIDATE_RECEIPT_NAME,
            _canonical_bytes(receipt, newline=True),
        )
        result = validate_windows_status_monitor_configured_candidate(
            base_suite_root=base_suite_root,
            status_monitor_base_release=status_monitor_base_release,
            candidate_root=root,
        )
        after = {
            relative: _stable_read(
                original_root / relative,
                maximum_bytes=MAX_DOCUMENT_BYTES,
                code="PROVIDER_PACK_FILE_INVALID",
            )
            for relative in GENERATED_PATHS
        }
        if after != original_bytes:
            raise StatusMonitorConfiguredCandidateError(
                "ORIGINAL_PROVIDER_PACK_MUTATED"
            )
        return result
    except Exception:
        if created:
            _cleanup(root)
        raise


__all__ = [
    "CANDIDATE_RECEIPT_NAME",
    "CANDIDATE_SCHEMA",
    "CANDIDATE_STATUS",
    "StatusMonitorConfiguredCandidateError",
    "WindowsStatusMonitorConfiguredCandidate",
    "assemble_windows_status_monitor_configured_candidate",
    "validate_windows_status_monitor_configured_candidate",
]
