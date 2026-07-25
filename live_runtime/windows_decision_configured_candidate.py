"""Assemble and validate one deny-only configured Decision candidate.

This release-operator boundary joins existing, independently verified
artifacts without importing a provider, resolving a credential, installing a
task, starting a process, initializing MT5, or performing broker work.  The
validated four-file provider pack is copied twice: once as immutable evidence
and once as the working configured overlay.
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
from .windows_decision_provider_pack_generator import (
    GENERATED_PATHS,
    DecisionProviderPackError,
    validate_windows_decision_provider_pack,
)
from .windows_decision_service_factory_template import (
    PROVIDER_ROLES,
    validate_windows_decision_service_factory_template,
)


CANDIDATE_SCHEMA = "windows-decision-configured-candidate-v1"
CANDIDATE_RECEIPT_NAME = "DECISION_CONFIGURED_CANDIDATE.json"
CANDIDATE_STATUS = "EXTERNAL_PROVIDER_CONFORMANCE_REQUIRED"
DECISION_PROFILE = "WINDOWS_DECISION_SERVICE_V1"
DECISION_ROLE = "DECISION"
CONFIGURED_ARCHIVE_NAME = "decision-configured-v1.zip"
CONFIGURED_SIDECAR_NAME = "decision-configured-v1.zip.manifest.json"
FACTORY_TEMPLATE_NAME = "decision-factory-template.json"
OVERLAY_DESCRIPTOR_NAME = "configured-overlay.json"
TASK_DEFINITION_NAME = "reviewed-task-definition.xml"
MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_LOT = 0.01

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bgh[oprsu]_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
)
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
        "decision_base_archive_sha256",
        "decision_base_release_identity_sha256",
        "decision_factory_template_sha256",
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
        "task_definition_sha256",
    }
)
_FILE_FIELDS = frozenset({"path", "sha256", "size_bytes"})
_EFFECTS = {
    "broker_mutation_performed": False,
    "cas_request_performed": False,
    "credential_access_performed": False,
    "mt5_initialized": False,
    "network_access_performed": False,
    "provider_imported": False,
    "provider_materialized": False,
    "runtime_process_started": False,
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
_RESULT_SEAL = object()


class DecisionConfiguredCandidateError(RuntimeError):
    """One candidate input failed closed with one stable reason code."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: str) -> None:
        normalized = str(reason_code or "").strip().upper()
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", normalized) is None:
            normalized = "DECISION_CONFIGURED_CANDIDATE_INVALID"
        self.reason_code = normalized
        super().__init__(normalized)


@dataclass(frozen=True, slots=True)
class WindowsDecisionConfiguredCandidate:
    """Sealed deny-only result returned by assembly or validation."""

    output_root: str
    candidate_id: str
    base_suite_identity_sha256: str
    base_suite_manifest_sha256: str
    decision_base_release_identity_sha256: str
    decision_base_archive_sha256: str
    provider_pack_identity_sha256: str
    bootstrap_binding_sha256: str
    overlay_descriptor_sha256: str
    task_definition_sha256: str
    configured_release_identity_sha256: str
    configured_archive_sha256: str
    configured_manifest_sha256: str
    decision_factory_template_sha256: str
    provider_count: int
    content_sha256: str
    status: str = CANDIDATE_STATUS
    provider_accepted: bool = False
    production_execution_ready: bool = False
    credential_access_performed: bool = False
    provider_imported: bool = False
    provider_materialized: bool = False
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
        if _seal is not _RESULT_SEAL:
            raise TypeError(
                "configured Decision candidate requires validator seal"
            )
        hashes = (
            self.base_suite_identity_sha256,
            self.base_suite_manifest_sha256,
            self.decision_base_release_identity_sha256,
            self.decision_base_archive_sha256,
            self.provider_pack_identity_sha256,
            self.bootstrap_binding_sha256,
            self.overlay_descriptor_sha256,
            self.task_definition_sha256,
            self.configured_release_identity_sha256,
            self.configured_archive_sha256,
            self.configured_manifest_sha256,
            self.decision_factory_template_sha256,
            self.content_sha256,
        )
        if (
            not isinstance(self.output_root, str)
            or not self.output_root
            or _ID.fullmatch(self.candidate_id) is None
            or any(
                _HASH.fullmatch(value) is None or value == "0" * 64
                for value in hashes
            )
            or self.provider_count != len(PROVIDER_ROLES)
            or self.status != CANDIDATE_STATUS
            or self.provider_accepted is not False
            or self.production_execution_ready is not False
            or self.credential_access_performed is not False
            or self.provider_imported is not False
            or self.provider_materialized is not False
            or self.task_installation_performed is not False
            or self.broker_mutation_performed is not False
            or self.order_capability != "DISABLED"
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or self.max_lot != MAX_LOT
            or self.promotion_eligible is not False
            or self.schema_version != CANDIDATE_SCHEMA
        ):
            raise ValueError("configured Decision candidate safety drift")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DecisionConfiguredCandidateError(
            "CANDIDATE_JSON_INVALID"
        ) from exc


def _canonical_file(value: object) -> bytes:
    return _canonical_bytes(value) + b"\n"


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(
        int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    )


def _identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _same_file(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        int(first.st_dev),
        int(first.st_ino),
        int(first.st_mode),
        int(first.st_size),
        int(first.st_mtime_ns),
        int(getattr(first, "st_file_attributes", 0)),
    ) == _identity(second)


def _stable_read(
    path: Path,
    *,
    maximum_bytes: int,
    code: str,
    allow_empty: bool = False,
) -> bytes:
    descriptor: int | None = None
    try:
        configured = path.expanduser().absolute()
        resolved = configured.resolve(strict=True)
        if configured != resolved:
            raise OSError("path indirection is forbidden")
        path = configured
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or _is_reparse(before)
            or (before.st_size == 0 and not allow_empty)
            or before.st_size > maximum_bytes
        ):
            raise OSError("unsafe file")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not _same_file(before, opened):
            raise OSError("file changed before read")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, maximum_bytes + 1),
            )
            if not chunk:
                break
            size += len(chunk)
            if size > maximum_bytes:
                raise OSError("file too large")
            chunks.append(chunk)
        after_open = os.fstat(descriptor)
        after_path = path.lstat()
        if (
            not _same_file(opened, after_open)
            or not _same_file(after_open, after_path)
        ):
            raise OSError("file changed during read")
        data = b"".join(chunks)
        if len(data) != before.st_size:
            raise OSError("file size drift")
        return data
    except (OSError, ValueError) as exc:
        raise DecisionConfiguredCandidateError(code) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _strict_json(
    data: bytes,
    *,
    code: str,
    canonical: bool,
) -> dict[str, Any]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise DecisionConfiguredCandidateError(code)
            result[key] = value
        return result

    def reject(_value: str) -> object:
        raise DecisionConfiguredCandidateError(code)

    try:
        payload = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=reject,
        )
    except DecisionConfiguredCandidateError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecisionConfiguredCandidateError(code) from exc
    if not isinstance(payload, dict):
        raise DecisionConfiguredCandidateError(code)
    if canonical and data != _canonical_file(payload):
        raise DecisionConfiguredCandidateError(code)
    return payload


def _safe_existing_root(path: str | Path, *, code: str) -> Path:
    configured = Path(path).expanduser().absolute()
    if ".." in configured.parts:
        raise DecisionConfiguredCandidateError(code)
    try:
        metadata = configured.lstat()
        resolved = configured.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise DecisionConfiguredCandidateError(code) from exc
    if (
        configured != resolved
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        raise DecisionConfiguredCandidateError(code)
    return resolved


def _safe_new_root(path: str | Path) -> tuple[Path, tuple[int, ...]]:
    configured = Path(path).expanduser().absolute()
    created = False
    if ".." in configured.parts:
        raise DecisionConfiguredCandidateError(
            "CANDIDATE_OUTPUT_INVALID"
        )
    try:
        parent_metadata = configured.parent.lstat()
        resolved_parent = configured.parent.resolve(strict=True)
        if (
            configured.parent != resolved_parent
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_ISLNK(parent_metadata.st_mode)
            or _is_reparse(parent_metadata)
        ):
            raise OSError("unsafe output parent")
        os.mkdir(configured, 0o700)
        created = True
        metadata = configured.lstat()
        resolved = configured.resolve(strict=True)
    except FileExistsError as exc:
        raise DecisionConfiguredCandidateError(
            "CANDIDATE_OUTPUT_ALREADY_EXISTS"
        ) from exc
    except OSError as exc:
        if created:
            try:
                configured.rmdir()
            except OSError:
                pass
        raise DecisionConfiguredCandidateError(
            "CANDIDATE_OUTPUT_INVALID"
        ) from exc
    if (
        configured != resolved
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        try:
            configured.rmdir()
        except OSError:
            pass
        raise DecisionConfiguredCandidateError(
            "CANDIDATE_OUTPUT_INVALID"
        )
    return configured, (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _paths_overlap(first: Path, second: Path) -> bool:
    try:
        return (
            first == second
            or first.is_relative_to(second)
            or second.is_relative_to(first)
        )
    except (TypeError, ValueError):
        return True


def _mkdir_exclusive(path: Path) -> None:
    try:
        os.mkdir(path, 0o700)
    except OSError as exc:
        raise DecisionConfiguredCandidateError(
            "CANDIDATE_OUTPUT_WRITE_FAILED"
        ) from exc


def _write_exclusive(path: Path, payload: bytes) -> None:
    descriptor: int | None = None
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise DecisionConfiguredCandidateError(
            "CANDIDATE_OUTPUT_WRITE_FAILED"
        ) from exc


def _remove_owned_tree(
    root: Path,
    root_identity: tuple[int, ...],
) -> None:
    def matches_root() -> bool:
        try:
            metadata = root.lstat()
        except OSError:
            return False
        return (
            int(metadata.st_dev),
            int(metadata.st_ino),
            int(metadata.st_mode),
            int(getattr(metadata, "st_file_attributes", 0)),
        ) == root_identity

    try:
        if not matches_root():
            return
    except OSError:
        return

    def remove(directory: Path) -> None:
        try:
            items = list(os.scandir(directory))
        except OSError:
            return
        for item in items:
            path = Path(item.path)
            try:
                metadata = path.lstat()
            except OSError:
                continue
            if stat.S_ISDIR(metadata.st_mode) and not (
                stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata)
            ):
                remove(path)
                try:
                    path.rmdir()
                except OSError:
                    pass
            else:
                try:
                    path.unlink()
                except OSError:
                    pass

    remove(root)
    try:
        if matches_root():
            root.rmdir()
    except OSError:
        pass


def _candidate_inventory(root: Path) -> dict[str, bytes]:
    observed_files: dict[str, bytes] = {}
    observed_directories: set[str] = set()
    total = 0
    try:
        items = sorted(root.rglob("*"))
    except OSError as exc:
        raise DecisionConfiguredCandidateError(
            "CANDIDATE_FILE_SET_INVALID"
        ) from exc
    for item in items:
        try:
            metadata = item.lstat()
        except OSError as exc:
            raise DecisionConfiguredCandidateError(
                "CANDIDATE_FILE_SET_INVALID"
            ) from exc
        relative = item.relative_to(root).as_posix()
        if (
            PurePosixPath(relative).as_posix() != relative
            or "\\" in relative
        ):
            raise DecisionConfiguredCandidateError(
                "CANDIDATE_FILE_SET_INVALID"
            )
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
                raise DecisionConfiguredCandidateError(
                    "CANDIDATE_FILE_SET_INVALID"
                )
            observed_directories.add(relative)
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
            or relative not in _ALL_FILES
        ):
            raise DecisionConfiguredCandidateError(
                "CANDIDATE_FILE_SET_INVALID"
            )
        maximum = (
            MAX_ARCHIVE_BYTES
            if relative == CONFIGURED_ARCHIVE_NAME
            else MAX_DOCUMENT_BYTES
        )
        data = _stable_read(
            item,
            maximum_bytes=maximum,
            code="CANDIDATE_FILE_INVALID",
        )
        if relative != CONFIGURED_ARCHIVE_NAME:
            if any(pattern.search(data) for pattern in _SECRET_PATTERNS):
                raise DecisionConfiguredCandidateError(
                    "CANDIDATE_SECRET_MATERIAL_FORBIDDEN"
                )
            total += len(data)
            if total > MAX_TOTAL_DOCUMENT_BYTES:
                raise DecisionConfiguredCandidateError(
                    "CANDIDATE_TOTAL_SIZE_EXCEEDED"
                )
        observed_files[relative] = data
    if (
        set(observed_files) != _ALL_FILES
        or observed_directories != _EXPECTED_DIRECTORIES
        or len({path.casefold() for path in observed_files})
        != len(observed_files)
        or len({path.casefold() for path in observed_directories})
        != len(observed_directories)
    ):
        raise DecisionConfiguredCandidateError(
            "CANDIDATE_FILE_SET_INVALID"
        )
    return observed_files


def _archive_members(archive_bytes: bytes) -> dict[str, bytes]:
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            if (
                len(names) != len(set(names))
                or len({name.casefold() for name in names}) != len(names)
                or any(
                    not name
                    or name.endswith("/")
                    or "\\" in name
                    or PurePosixPath(name).is_absolute()
                    or ".." in PurePosixPath(name).parts
                    or PurePosixPath(name).as_posix() != name
                    for name in names
                )
            ):
                raise DecisionConfiguredCandidateError(
                    "CONFIGURED_ARCHIVE_INVALID"
                )
            return {item.filename: archive.read(item) for item in infos}
    except DecisionConfiguredCandidateError:
        raise
    except (OSError, KeyError, zipfile.BadZipFile) as exc:
        raise DecisionConfiguredCandidateError(
            "CONFIGURED_ARCHIVE_INVALID"
        ) from exc


def _file_entries(
    files: Mapping[str, bytes],
) -> list[dict[str, object]]:
    return [
        {
            "path": path,
            "sha256": _sha256(data),
            "size_bytes": len(data),
        }
        for path, data in sorted(files.items())
    ]


def _receipt_files(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) != len(
        _NON_RECEIPT_FILES
    ):
        raise DecisionConfiguredCandidateError(
            "CANDIDATE_RECEIPT_INVALID"
        )
    result: list[dict[str, object]] = []
    folded: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping) or set(item) != _FILE_FIELDS:
            raise DecisionConfiguredCandidateError(
                "CANDIDATE_RECEIPT_INVALID"
            )
        path = item.get("path")
        size = item.get("size_bytes")
        digest = item.get("sha256")
        if (
            not isinstance(path, str)
            or path not in _NON_RECEIPT_FILES
            or path.casefold() in folded
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or not isinstance(digest, str)
            or _HASH.fullmatch(digest) is None
        ):
            raise DecisionConfiguredCandidateError(
                "CANDIDATE_RECEIPT_INVALID"
            )
        folded.add(path.casefold())
        result.append(dict(item))
    if [item["path"] for item in result] != sorted(
        _NON_RECEIPT_FILES
    ):
        raise DecisionConfiguredCandidateError(
            "CANDIDATE_RECEIPT_INVALID"
        )
    return result


def _decision_runtime_contract(
    data: bytes,
) -> tuple[dict[str, Any], str]:
    """Return an already pack-validated static runtime projection."""

    payload = _strict_json(
        data,
        code="DECISION_RUNTIME_CONFIG_INVALID",
        canonical=True,
    )
    expected_fields = {
        "cycle_deadline_seconds",
        "decision_producer_binding",
        "live_allowed",
        "max_cycles",
        "max_lot",
        "order_capability",
        "poll_seconds",
        "providers",
        "safe_to_demo_auto_order",
        "schema_version",
        "service_id",
    }
    producer = payload.get("decision_producer_binding")
    providers = payload.get("providers")
    if (
        set(payload) != expected_fields
        or not isinstance(producer, Mapping)
        or not isinstance(providers, list)
        or len(providers) != len(PROVIDER_ROLES)
        or not isinstance(payload.get("service_id"), str)
        or payload.get("live_allowed") is not False
        or payload.get("safe_to_demo_auto_order") is not False
        or payload.get("max_lot") != MAX_LOT
        or payload.get("order_capability") != "DISABLED"
    ):
        raise DecisionConfiguredCandidateError(
            "DECISION_RUNTIME_CONFIG_INVALID"
        )
    return payload, _sha256(_canonical_bytes(producer))


def _factory_template(
    runtime: Mapping[str, Any],
    *,
    release_identity_sha256: str,
    factory_implementation_sha256: str,
    factory_configuration_sha256: str,
):
    payload = {
        "factory_configuration_sha256": (
            factory_configuration_sha256
        ),
        "factory_implementation_sha256": (
            factory_implementation_sha256
        ),
        "live_allowed": False,
        "materialization_enabled": False,
        "order_capability": "DISABLED",
        "providers": runtime["providers"],
        "release_identity_sha256": release_identity_sha256,
        "release_profile": DECISION_PROFILE,
        "safe_to_demo_auto_order": False,
        "schema_version": (
            "windows-decision-service-factory-template-v1"
        ),
        "service_id": runtime["service_id"],
    }
    try:
        return validate_windows_decision_service_factory_template(
            payload,
            expected_release_identity_sha256=release_identity_sha256,
        )
    except (TypeError, ValueError) as exc:
        raise DecisionConfiguredCandidateError(
            "DECISION_FACTORY_TEMPLATE_INVALID"
        ) from exc


def _validated_receipt(
    data: bytes,
    *,
    non_receipt_files: Mapping[str, bytes],
) -> dict[str, Any]:
    payload = _strict_json(
        data,
        code="CANDIDATE_RECEIPT_INVALID",
        canonical=True,
    )
    if (
        set(payload) != _RECEIPT_FIELDS
        or payload.get("schema_version") != CANDIDATE_SCHEMA
        or payload.get("status") != CANDIDATE_STATUS
        or not isinstance(payload.get("candidate_id"), str)
        or _ID.fullmatch(str(payload["candidate_id"])) is None
        or payload.get("effects") != _EFFECTS
        or payload.get("safety") != _SAFETY
        or payload.get("provider_count") != len(PROVIDER_ROLES)
        or not isinstance(payload.get("git_commit"), str)
        or _COMMIT.fullmatch(str(payload["git_commit"])) is None
        or not isinstance(payload.get("git_tree"), str)
        or _COMMIT.fullmatch(str(payload["git_tree"])) is None
    ):
        raise DecisionConfiguredCandidateError(
            "CANDIDATE_RECEIPT_INVALID"
        )
    hash_fields = (
        "base_suite_identity_sha256",
        "base_suite_manifest_sha256",
        "decision_base_release_identity_sha256",
        "decision_base_archive_sha256",
        "provider_pack_identity_sha256",
        "bootstrap_binding_sha256",
        "overlay_descriptor_sha256",
        "task_definition_sha256",
        "configured_release_identity_sha256",
        "configured_archive_sha256",
        "configured_manifest_sha256",
        "decision_factory_template_sha256",
        "content_sha256",
    )
    if any(
        not isinstance(payload.get(name), str)
        or _HASH.fullmatch(str(payload[name])) is None
        or payload[name] == "0" * 64
        for name in hash_fields
    ):
        raise DecisionConfiguredCandidateError(
            "CANDIDATE_RECEIPT_INVALID"
        )
    entries = _receipt_files(payload.get("files"))
    if entries != _file_entries(non_receipt_files):
        raise DecisionConfiguredCandidateError(
            "CANDIDATE_INVENTORY_MISMATCH"
        )
    unsigned = dict(payload)
    content_hash = str(unsigned.pop("content_sha256"))
    if _sha256(_canonical_bytes(unsigned)) != content_hash:
        raise DecisionConfiguredCandidateError(
            "CANDIDATE_RECEIPT_HASH_MISMATCH"
        )
    return payload


def _known_error(exc: Exception) -> DecisionConfiguredCandidateError:
    reason = getattr(exc, "reason_code", None)
    if isinstance(reason, str) and reason:
        return DecisionConfiguredCandidateError(reason)
    return DecisionConfiguredCandidateError(
        "DECISION_CONFIGURED_CANDIDATE_INVALID"
    )


def _result(
    root: Path,
    receipt: Mapping[str, object],
) -> WindowsDecisionConfiguredCandidate:
    return WindowsDecisionConfiguredCandidate(
        output_root=str(root),
        candidate_id=str(receipt["candidate_id"]),
        base_suite_identity_sha256=str(
            receipt["base_suite_identity_sha256"]
        ),
        base_suite_manifest_sha256=str(
            receipt["base_suite_manifest_sha256"]
        ),
        decision_base_release_identity_sha256=str(
            receipt["decision_base_release_identity_sha256"]
        ),
        decision_base_archive_sha256=str(
            receipt["decision_base_archive_sha256"]
        ),
        provider_pack_identity_sha256=str(
            receipt["provider_pack_identity_sha256"]
        ),
        bootstrap_binding_sha256=str(
            receipt["bootstrap_binding_sha256"]
        ),
        overlay_descriptor_sha256=str(
            receipt["overlay_descriptor_sha256"]
        ),
        task_definition_sha256=str(
            receipt["task_definition_sha256"]
        ),
        configured_release_identity_sha256=str(
            receipt["configured_release_identity_sha256"]
        ),
        configured_archive_sha256=str(
            receipt["configured_archive_sha256"]
        ),
        configured_manifest_sha256=str(
            receipt["configured_manifest_sha256"]
        ),
        decision_factory_template_sha256=str(
            receipt["decision_factory_template_sha256"]
        ),
        provider_count=int(receipt["provider_count"]),
        content_sha256=str(receipt["content_sha256"]),
        _seal=_RESULT_SEAL,
    )


def validate_windows_decision_configured_candidate(
    *,
    base_suite_root: str | Path,
    decision_base_release: str | Path,
    candidate_root: str | Path,
) -> WindowsDecisionConfiguredCandidate:
    """Independently validate the exact candidate without provider effects."""

    try:
        suite = verify_base_release_suite(base_suite_root)
        role = suite.role(DECISION_ROLE)
        pack = validate_windows_decision_provider_pack(
            base_suite_root=base_suite_root,
            decision_base_release=decision_base_release,
            pack_root=Path(candidate_root) / _PACK_PREFIX,
        )
    except (
        BaseReleaseSuiteVerificationError,
        DecisionProviderPackError,
        KeyError,
    ) as exc:
        raise _known_error(exc) from exc
    root = _safe_existing_root(
        candidate_root,
        code="CANDIDATE_ROOT_INVALID",
    )
    files = _candidate_inventory(root)
    non_receipt = {
        path: data
        for path, data in files.items()
        if path != CANDIDATE_RECEIPT_NAME
    }
    receipt = _validated_receipt(
        files[CANDIDATE_RECEIPT_NAME],
        non_receipt_files=non_receipt,
    )

    for relative in GENERATED_PATHS:
        if (
            files[f"{_PACK_PREFIX}/{relative}"]
            != files[f"{_OVERLAY_PREFIX}/{relative}"]
        ):
            raise DecisionConfiguredCandidateError(
                "CANDIDATE_PACK_OVERLAY_MISMATCH"
            )

    archive_bytes = files[CONFIGURED_ARCHIVE_NAME]
    sidecar_bytes = files[CONFIGURED_SIDECAR_NAME]
    try:
        configured = verify_configured_service_release(
            archive_bytes,
            expected_release_identity_sha256=str(
                receipt["configured_release_identity_sha256"]
            ),
            expected_base_release_identity_sha256=(
                role.release_identity_sha256
            ),
        )
    except ConfiguredReleaseError as exc:
        raise _known_error(exc) from exc
    archive_members = _archive_members(archive_bytes)
    if archive_members.get("RELEASE_MANIFEST.json") != sidecar_bytes:
        raise DecisionConfiguredCandidateError(
            "CONFIGURED_SIDECAR_MISMATCH"
        )
    manifest = _strict_json(
        sidecar_bytes,
        code="CONFIGURED_SIDECAR_INVALID",
        canonical=True,
    )
    binding = manifest.get("configured_release")
    if not isinstance(binding, Mapping):
        raise DecisionConfiguredCandidateError(
            "CONFIGURED_BINDING_INVALID"
        )
    descriptor = _strict_json(
        files[OVERLAY_DESCRIPTOR_NAME],
        code="OVERLAY_DESCRIPTOR_INVALID",
        canonical=True,
    )
    if (
        _sha256(files[OVERLAY_DESCRIPTOR_NAME])
        != binding.get("overlay_descriptor_sha256")
        or descriptor != binding.get("overlay_descriptor")
        or descriptor.get("runtime_mode") != "DEMO_AUTO"
        or descriptor.get("task_definition_sha256")
        != _sha256(files[TASK_DEFINITION_NAME])
    ):
        raise DecisionConfiguredCandidateError(
            "OVERLAY_DESCRIPTOR_BINDING_MISMATCH"
        )
    descriptor_files = descriptor.get("files")
    if not isinstance(descriptor_files, list):
        raise DecisionConfiguredCandidateError(
            "OVERLAY_DESCRIPTOR_INVALID"
        )
    expected_overlay_paths = {
        relative.removeprefix(f"{_OVERLAY_PREFIX}/")
        for relative in _OVERLAY_ORIGINAL_FILES
    } | {"config/windows_factory_manifest.json"}
    observed_overlay_paths = {
        item.get("path")
        for item in descriptor_files
        if isinstance(item, Mapping)
    }
    if observed_overlay_paths != expected_overlay_paths:
        raise DecisionConfiguredCandidateError(
            "CONFIGURED_OVERLAY_PARTITION_INVALID"
        )
    for relative in expected_overlay_paths:
        local = files[f"{_OVERLAY_PREFIX}/{relative}"]
        if archive_members.get(relative) != local:
            raise DecisionConfiguredCandidateError(
                "CONFIGURED_OVERLAY_ARCHIVE_MISMATCH"
            )

    runtime, bootstrap = _decision_runtime_contract(
        files[f"{_PACK_PREFIX}/config/windows_service_config.json"]
    )
    if (
        binding.get("bootstrap_binding_sha256") != bootstrap
        or receipt["bootstrap_binding_sha256"] != bootstrap
    ):
        raise DecisionConfiguredCandidateError(
            "BOOTSTRAP_BINDING_MISMATCH"
        )
    expected_template = _factory_template(
        runtime,
        release_identity_sha256=configured.release_identity_sha256,
        factory_implementation_sha256=_sha256(
            files[f"{_OVERLAY_PREFIX}/reviewed_windows_factory.py"]
        ),
        factory_configuration_sha256=_sha256(
            files[
                f"{_OVERLAY_PREFIX}/config/windows_service_config.json"
            ]
        ),
    )
    expected_template_bytes = _canonical_file(
        expected_template.to_canonical_dict()
    )
    if files[FACTORY_TEMPLATE_NAME] != expected_template_bytes:
        raise DecisionConfiguredCandidateError(
            "DECISION_FACTORY_TEMPLATE_MISMATCH"
        )
    template_payload = _strict_json(
        files[FACTORY_TEMPLATE_NAME],
        code="DECISION_FACTORY_TEMPLATE_INVALID",
        canonical=True,
    )
    try:
        template = validate_windows_decision_service_factory_template(
            template_payload,
            expected_release_identity_sha256=(
                configured.release_identity_sha256
            ),
        )
    except (TypeError, ValueError) as exc:
        raise DecisionConfiguredCandidateError(
            "DECISION_FACTORY_TEMPLATE_INVALID"
        ) from exc

    expected_receipt = {
        "base_suite_identity_sha256": suite.suite_identity_sha256,
        "base_suite_manifest_sha256": suite.manifest_sha256,
        "bootstrap_binding_sha256": bootstrap,
        "candidate_id": descriptor.get("overlay_id"),
        "configured_archive_sha256": _sha256(archive_bytes),
        "configured_manifest_sha256": _sha256(sidecar_bytes),
        "configured_release_identity_sha256": (
            configured.release_identity_sha256
        ),
        "decision_base_archive_sha256": role.archive_sha256,
        "decision_base_release_identity_sha256": (
            role.release_identity_sha256
        ),
        "decision_factory_template_sha256": _sha256(
            files[FACTORY_TEMPLATE_NAME]
        ),
        "effects": dict(_EFFECTS),
        "files": _file_entries(non_receipt),
        "git_commit": suite.git_commit,
        "git_tree": suite.git_tree,
        "overlay_descriptor_sha256": _sha256(
            files[OVERLAY_DESCRIPTOR_NAME]
        ),
        "provider_count": len(template.providers),
        "provider_pack_identity_sha256": pack.pack_identity_sha256,
        "safety": dict(_SAFETY),
        "schema_version": CANDIDATE_SCHEMA,
        "status": CANDIDATE_STATUS,
        "task_definition_sha256": _sha256(
            files[TASK_DEFINITION_NAME]
        ),
    }
    expected_receipt["content_sha256"] = _sha256(
        _canonical_bytes(expected_receipt)
    )
    if receipt != expected_receipt:
        raise DecisionConfiguredCandidateError(
            "CANDIDATE_CROSS_BINDING_MISMATCH"
        )
    if (
        configured.release_profile != DECISION_PROFILE
        or not configured.base_release_suite_bound
        or configured.base_release_suite_role != DECISION_ROLE
        or configured.base_release_suite_identity_sha256
        != suite.suite_identity_sha256
        or configured.production_execution_ready
        or configured.order_capability != "DISABLED"
        or configured.live_allowed
        or configured.safe_to_demo_auto_order
    ):
        raise DecisionConfiguredCandidateError(
            "CONFIGURED_RELEASE_AUTHORITY_DRIFT"
        )
    return _result(root, receipt)


def assemble_windows_decision_configured_candidate(
    *,
    base_suite_root: str | Path,
    decision_base_release: str | Path,
    provider_pack_root: str | Path,
    task_definition_path: str | Path,
    candidate_id: str,
    output_root: str | Path,
) -> WindowsDecisionConfiguredCandidate:
    """Assemble one exact candidate while preserving all input bytes."""

    if not isinstance(candidate_id, str) or _ID.fullmatch(candidate_id) is None:
        raise DecisionConfiguredCandidateError("CANDIDATE_ID_INVALID")
    try:
        suite = verify_base_release_suite(base_suite_root)
        role = suite.role(DECISION_ROLE)
        original = validate_windows_decision_provider_pack(
            base_suite_root=base_suite_root,
            decision_base_release=decision_base_release,
            pack_root=provider_pack_root,
        )
    except (
        BaseReleaseSuiteVerificationError,
        DecisionProviderPackError,
        KeyError,
    ) as exc:
        raise _known_error(exc) from exc
    original_root = _safe_existing_root(
        provider_pack_root,
        code="PROVIDER_PACK_ROOT_INVALID",
    )
    output_target = Path(output_root).expanduser().absolute()
    if (
        _paths_overlap(output_target, original_root)
        or _paths_overlap(output_target, suite.root)
        or output_target
        == Path(task_definition_path).expanduser().absolute()
    ):
        raise DecisionConfiguredCandidateError(
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
        Path(task_definition_path).expanduser().absolute(),
        maximum_bytes=MAX_DOCUMENT_BYTES,
        code="TASK_DEFINITION_INVALID",
    )
    if any(pattern.search(task_bytes) for pattern in _SECRET_PATTERNS):
        raise DecisionConfiguredCandidateError(
            "TASK_DEFINITION_SECRET_MATERIAL_FORBIDDEN"
        )

    root, root_identity = _safe_new_root(output_target)
    try:
        for relative in sorted(
            _EXPECTED_DIRECTORIES,
            key=lambda item: (len(PurePosixPath(item).parts), item),
        ):
            _mkdir_exclusive(root / relative)
        for relative, data in original_bytes.items():
            _write_exclusive(root / _PACK_PREFIX / relative, data)
            _write_exclusive(root / _OVERLAY_PREFIX / relative, data)
        _write_exclusive(root / TASK_DEFINITION_NAME, task_bytes)

        copied_pack = validate_windows_decision_provider_pack(
            base_suite_root=base_suite_root,
            decision_base_release=decision_base_release,
            pack_root=root / _PACK_PREFIX,
        )
        if copied_pack.pack_identity_sha256 != original.pack_identity_sha256:
            raise DecisionConfiguredCandidateError(
                "COPIED_PROVIDER_PACK_MISMATCH"
            )
        runtime, bootstrap = _decision_runtime_contract(
            original_bytes["config/windows_service_config.json"]
        )
        descriptor_path = root / OVERLAY_DESCRIPTOR_NAME
        prepare_configured_overlay_candidate(
            base_archive=decision_base_release,
            overlay_root=root / _OVERLAY_PREFIX,
            task_definition_path=root / TASK_DEFINITION_NAME,
            overlay_id=candidate_id,
            bootstrap_binding_sha256=bootstrap,
            runtime_mode="DEMO_AUTO",
            descriptor_output_path=descriptor_path,
        )
        archive_path = root / CONFIGURED_ARCHIVE_NAME
        built = build_configured_service_release(
            decision_base_release,
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
        factory_bytes = _stable_read(
            root / _OVERLAY_PREFIX / "reviewed_windows_factory.py",
            maximum_bytes=MAX_DOCUMENT_BYTES,
            code="CONFIGURED_FACTORY_INVALID",
        )
        config_bytes = _stable_read(
            root
            / _OVERLAY_PREFIX
            / "config/windows_service_config.json",
            maximum_bytes=MAX_DOCUMENT_BYTES,
            code="CONFIGURED_SERVICE_CONFIG_INVALID",
        )
        template = _factory_template(
            runtime,
            release_identity_sha256=(
                configured.release_identity_sha256
            ),
            factory_implementation_sha256=_sha256(factory_bytes),
            factory_configuration_sha256=_sha256(config_bytes),
        )
        template_bytes = _canonical_file(template.to_canonical_dict())
        validate_windows_decision_service_factory_template(
            _strict_json(
                template_bytes,
                code="DECISION_FACTORY_TEMPLATE_INVALID",
                canonical=True,
            ),
            expected_release_identity_sha256=(
                configured.release_identity_sha256
            ),
        )
        _write_exclusive(root / FACTORY_TEMPLATE_NAME, template_bytes)

        non_receipt_files = {
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
        receipt: dict[str, object] = {
            "base_suite_identity_sha256": suite.suite_identity_sha256,
            "base_suite_manifest_sha256": suite.manifest_sha256,
            "bootstrap_binding_sha256": bootstrap,
            "candidate_id": candidate_id,
            "configured_archive_sha256": _sha256(
                non_receipt_files[CONFIGURED_ARCHIVE_NAME]
            ),
            "configured_manifest_sha256": _sha256(
                non_receipt_files[CONFIGURED_SIDECAR_NAME]
            ),
            "configured_release_identity_sha256": (
                configured.release_identity_sha256
            ),
            "decision_base_archive_sha256": role.archive_sha256,
            "decision_base_release_identity_sha256": (
                role.release_identity_sha256
            ),
            "decision_factory_template_sha256": _sha256(
                template_bytes
            ),
            "effects": dict(_EFFECTS),
            "files": _file_entries(non_receipt_files),
            "git_commit": suite.git_commit,
            "git_tree": suite.git_tree,
            "overlay_descriptor_sha256": _sha256(
                non_receipt_files[OVERLAY_DESCRIPTOR_NAME]
            ),
            "provider_count": len(template.providers),
            "provider_pack_identity_sha256": (
                original.pack_identity_sha256
            ),
            "safety": dict(_SAFETY),
            "schema_version": CANDIDATE_SCHEMA,
            "status": CANDIDATE_STATUS,
            "task_definition_sha256": _sha256(task_bytes),
        }
        receipt["content_sha256"] = _sha256(
            _canonical_bytes(receipt)
        )
        _write_exclusive(
            root / CANDIDATE_RECEIPT_NAME,
            _canonical_file(receipt),
        )

        result = validate_windows_decision_configured_candidate(
            base_suite_root=base_suite_root,
            decision_base_release=decision_base_release,
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
            raise DecisionConfiguredCandidateError(
                "ORIGINAL_PROVIDER_PACK_MUTATED"
            )
        revalidated = validate_windows_decision_provider_pack(
            base_suite_root=base_suite_root,
            decision_base_release=decision_base_release,
            pack_root=original_root,
        )
        if (
            revalidated.pack_identity_sha256
            != original.pack_identity_sha256
        ):
            raise DecisionConfiguredCandidateError(
                "ORIGINAL_PROVIDER_PACK_MUTATED"
            )
        return result
    except Exception:
        _remove_owned_tree(root, root_identity)
        raise


__all__ = [
    "CANDIDATE_RECEIPT_NAME",
    "CANDIDATE_SCHEMA",
    "CANDIDATE_STATUS",
    "DecisionConfiguredCandidateError",
    "WindowsDecisionConfiguredCandidate",
    "assemble_windows_decision_configured_candidate",
    "validate_windows_decision_configured_candidate",
]
