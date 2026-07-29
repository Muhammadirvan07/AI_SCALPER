"""Portable deny-only source closure for one Windows LIVE candidate.

The archive produced here packages one already verified DEMO source-bound
Execution artifact together with every exact member of one LIVE configured
Execution candidate.  Verification reconstructs both inputs from packaged
bytes and invokes their authoritative validators.  This module never imports
generated providers and grants no launch, credential, broker, or order
authority.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
from typing import Any, BinaryIO, Mapping
import zipfile

from .windows_execution_source_bound_candidate import (
    WindowsExecutionSourceBoundCandidateError,
    WindowsExecutionSourceBoundCandidateVerification,
    verify_windows_execution_source_bound_candidate,
)
from .windows_live_canary_execution_configured_candidate import (
    CANDIDATE_RECEIPT_NAME,
    LiveExecutionConfiguredCandidateError,
    WindowsLiveCanaryExecutionConfiguredCandidate,
    WindowsLiveCanaryExecutionFactoryTemplate,
    validate_windows_live_canary_execution_configured_candidate,
    validate_windows_live_canary_execution_factory_template,
)


SCHEMA_VERSION = (
    "windows-live-canary-execution-source-bound-candidate-v1"
)
MANIFEST_MEMBER = (
    "WINDOWS_LIVE_CANARY_EXECUTION_SOURCE_BOUND_CANDIDATE.json"
)
SOURCE_BOUND_MEMBER = (
    "source/windows-execution-source-bound-candidate-v1.zip"
)
LIVE_CANDIDATE_FILES = tuple(
    sorted(
        (
            CANDIDATE_RECEIPT_NAME,
            "configured-overlay.json",
            "configured-overlay/config/windows_factory_manifest.json",
            "configured-overlay/config/windows_service_config.json",
            "configured-overlay/configured_providers/__init__.py",
            "configured-overlay/configured_providers/execution_provider.py",
            "configured-overlay/reviewed_windows_factory.py",
            "live-execution-configured-v1.zip",
            "live-execution-configured-v1.zip.manifest.json",
            "live-execution-factory-template.json",
            "provider-pack/config/windows_service_config.json",
            "provider-pack/configured_providers/__init__.py",
            "provider-pack/configured_providers/execution_provider.py",
            "provider-pack/reviewed_windows_factory.py",
            "reviewed-task-definition.xml",
        )
    )
)
CANDIDATE_MEMBERS = tuple(
    f"candidate/{path}" for path in LIVE_CANDIDATE_FILES
)
PAYLOAD_MEMBERS = tuple(
    sorted((SOURCE_BOUND_MEMBER, *CANDIDATE_MEMBERS))
)
ARCHIVE_MEMBERS = tuple(sorted((MANIFEST_MEMBER, *PAYLOAD_MEMBERS)))
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
FIXED_ZIP_MODE = stat.S_IFREG | 0o644
MAX_JSON_MEMBER_BYTES = 4 * 1024 * 1024
MAX_SOURCE_BOUND_ARCHIVE_BYTES = 384 * 1024 * 1024
MAX_CONFIGURED_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_CANDIDATE_EXPANDED_BYTES = 320 * 1024 * 1024
MAX_ARCHIVE_BYTES = 768 * 1024 * 1024
ORDER_CAPABILITY = "DISABLED"
MAX_LOT = 0.01

SAFETY = {
    "provider_accepted": False,
    "production_execution_ready": False,
    "promotion_eligible": False,
    "order_capability": ORDER_CAPABILITY,
    "safe_to_demo_auto_order": False,
    "live_allowed": False,
    "max_lot": MAX_LOT,
}
EFFECTS = {
    "temporary_extraction": "PERFORMED_VERIFICATION_ONLY",
    "credential_access": "NOT_PERFORMED",
    "private_key_access": "NOT_PERFORMED",
    "provider_import": "NOT_PERFORMED",
    "provider_materialization": "NOT_PERFORMED",
    "sqlite_open": "NOT_PERFORMED",
    "mt5_initialization": "NOT_PERFORMED",
    "network_access": "NOT_PERFORMED",
    "task_installation": "NOT_PERFORMED",
    "service_start": "NOT_PERFORMED",
    "permit_issuance": "NOT_PERFORMED",
    "signature_issuance": "NOT_PERFORMED",
    "central_policy_mutation": "NOT_PERFORMED",
    "broker_mutation": "NOT_PERFORMED",
    "order_submission": "NOT_PERFORMED",
}

_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_OUTPUT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.zip$")
_REASON = re.compile(r"^[A-Z][A-Z0-9_]*$")
_RESULT_SEAL = object()

_CANDIDATE_DIRECTORIES = frozenset(
    {
        "configured-overlay",
        "configured-overlay/config",
        "configured-overlay/configured_providers",
        "provider-pack",
        "provider-pack/config",
        "provider-pack/configured_providers",
    }
)
_MANIFEST_FIELDS = frozenset(
    {
        "binding_identity_sha256",
        "effects",
        "live_candidate",
        "members",
        "safety",
        "schema_version",
        "source_bound",
    }
)
_MEMBER_FIELDS = frozenset({"path", "sha256", "size_bytes"})
_SOURCE_FIELDS = frozenset(
    {
        "archive_sha256",
        "binding_identity_sha256",
        "bootstrap_binding_sha256",
        "champion_archive_sha256",
        "champion_config_sha256",
        "champion_git_commit",
        "champion_git_tree",
        "champion_model_artifact_sha256",
        "champion_package_identity_sha256",
        "champion_runtime_binding_sha256",
        "champion_training_snapshot_sha256",
        "configured_archive_sha256",
        "configured_release_identity_sha256",
        "demo_candidate_content_sha256",
        "demo_candidate_id",
        "execution_base_archive_sha256",
        "execution_base_release_identity_sha256",
        "execution_factory_template_sha256",
        "git_commit",
        "git_tree",
        "production_config_sha256",
        "provider_configuration_sha256",
        "provider_pack_identity_sha256",
        "source_archive_sha256",
        "source_identity_sha256",
        "stage_binding_sha256",
        "suite_identity_sha256",
        "task_definition_sha256",
    }
)
_LIVE_FIELDS = frozenset(
    {
        "base_suite_identity_sha256",
        "bootstrap_binding_sha256",
        "candidate_id",
        "configured_archive_sha256",
        "configured_release_identity_sha256",
        "content_sha256",
        "credential_reference_count",
        "execution_base_archive_sha256",
        "execution_base_release_identity_sha256",
        "execution_factory_template_sha256",
        "git_commit",
        "git_tree",
        "live_provider_contract_set_sha256",
        "production_config_sha256",
        "provider_configuration_sha256",
        "provider_count",
        "provider_pack_identity_sha256",
        "runtime_mode",
        "task_definition_sha256",
    }
)


class WindowsLiveCanaryExecutionSourceBoundCandidateError(RuntimeError):
    """One LIVE source-bound artifact failed with a stable reason."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: object) -> None:
        normalized = str(reason_code or "").strip().upper()
        if _REASON.fullmatch(normalized) is None:
            normalized = "LIVE_EXECUTION_SOURCE_BOUND_CANDIDATE_INVALID"
        self.reason_code = normalized
        super().__init__(normalized)


@dataclass(frozen=True, slots=True)
class WindowsLiveCanaryExecutionSourceBoundCandidateVerification:
    """Sealed pure-data result of ten-pin packaged-byte verification."""

    archive_path: Path = field(compare=False)
    archive_sha256: str
    archive_size_bytes: int
    binding_identity_sha256: str
    source_bound_archive_sha256: str
    source_bound_binding_identity_sha256: str
    source_archive_sha256: str
    bootstrap_binding_sha256: str
    candidate_id: str
    candidate_content_sha256: str
    production_config_sha256: str
    provider_pack_identity_sha256: str
    provider_configuration_sha256: str
    live_provider_contract_set_sha256: str
    configured_release_identity_sha256: str
    configured_archive_sha256: str
    execution_factory_template_sha256: str
    task_definition_sha256: str
    suite_identity_sha256: str
    execution_base_archive_sha256: str
    execution_base_release_identity_sha256: str
    git_commit: str
    git_tree: str
    provider_count: int
    credential_reference_count: int
    runtime_mode: str = "LIVE"
    _verification_seal: object = field(
        init=False,
        repr=False,
        compare=False,
    )
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        hashes = (
            self.archive_sha256,
            self.binding_identity_sha256,
            self.source_bound_archive_sha256,
            self.source_bound_binding_identity_sha256,
            self.source_archive_sha256,
            self.bootstrap_binding_sha256,
            self.candidate_content_sha256,
            self.production_config_sha256,
            self.provider_pack_identity_sha256,
            self.provider_configuration_sha256,
            self.live_provider_contract_set_sha256,
            self.configured_release_identity_sha256,
            self.configured_archive_sha256,
            self.execution_factory_template_sha256,
            self.task_definition_sha256,
            self.suite_identity_sha256,
            self.execution_base_archive_sha256,
            self.execution_base_release_identity_sha256,
        )
        if (
            _seal is not _RESULT_SEAL
            or not isinstance(self.archive_path, Path)
            or type(self.archive_size_bytes) is not int
            or self.archive_size_bytes <= 0
            or any(
                type(value) is not str
                or _HEX_64.fullmatch(value) is None
                or value == "0" * 64
                for value in hashes
            )
            or type(self.candidate_id) is not str
            or _IDENTIFIER.fullmatch(self.candidate_id) is None
            or type(self.git_commit) is not str
            or _HEX_40.fullmatch(self.git_commit) is None
            or self.git_commit == "0" * 40
            or type(self.git_tree) is not str
            or _HEX_40.fullmatch(self.git_tree) is None
            or self.git_tree == "0" * 40
            or type(self.provider_count) is not int
            or self.provider_count != 49
            or type(self.credential_reference_count) is not int
            or self.credential_reference_count != 12
            or self.runtime_mode != "LIVE"
        ):
            raise TypeError(
                "LIVE source-bound verification requires verifier seal"
            )
        object.__setattr__(self, "_verification_seal", _RESULT_SEAL)

    @property
    def safety(self) -> dict[str, object]:
        return dict(SAFETY)

    @property
    def effects(self) -> dict[str, str]:
        return dict(EFFECTS)

    @property
    def provider_accepted(self) -> bool:
        return False

    @property
    def production_execution_ready(self) -> bool:
        return False

    @property
    def promotion_eligible(self) -> bool:
        return False

    @property
    def safe_to_demo_auto_order(self) -> bool:
        return False

    @property
    def live_allowed(self) -> bool:
        return False

    @property
    def order_capability(self) -> str:
        return ORDER_CAPABILITY

    @property
    def max_lot(self) -> float:
        return MAX_LOT


def is_windows_live_canary_execution_source_bound_candidate_verification(
    value: object,
) -> bool:
    """Return true only for a result sealed by this module."""

    return (
        type(value)
        is WindowsLiveCanaryExecutionSourceBoundCandidateVerification
        and getattr(value, "_verification_seal", None) is _RESULT_SEAL
    )


def _reject(reason_code: str) -> None:
    raise WindowsLiveCanaryExecutionSourceBoundCandidateError(reason_code)


def _sha256(data: bytes) -> str:
    if type(data) is not bytes:
        raise TypeError("hash input must be exact bytes")
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
        raise WindowsLiveCanaryExecutionSourceBoundCandidateError(
            "LIVE_BOUND_JSON_INVALID"
        ) from exc
    return result + (b"\n" if newline else b"")


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject("LIVE_BOUND_JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _nonfinite(_value: str) -> object:
    _reject("LIVE_BOUND_JSON_NONFINITE_VALUE")


def _strict_json(data: bytes, *, maximum_bytes: int) -> dict[str, Any]:
    if (
        type(data) is not bytes
        or not data
        or len(data) > maximum_bytes
        or not data.endswith(b"\n")
        or data.endswith(b"\n\n")
    ):
        _reject("LIVE_BOUND_JSON_INVALID")
    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicates,
            parse_constant=_nonfinite,
        )
    except WindowsLiveCanaryExecutionSourceBoundCandidateError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise WindowsLiveCanaryExecutionSourceBoundCandidateError(
            "LIVE_BOUND_JSON_INVALID"
        ) from exc
    if type(value) is not dict or _canonical_bytes(value, newline=True) != data:
        _reject("LIVE_BOUND_JSON_INVALID")
    return value


def _pin(value: object, pattern: re.Pattern[str]) -> str:
    if (
        type(value) is not str
        or pattern.fullmatch(value) is None
        or set(value) == {"0"}
    ):
        _reject("LIVE_BOUND_EXTERNAL_PIN_INVALID")
    return value


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        getattr(left, name, None) == getattr(right, name, None)
        for name in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
    )


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        getattr(left, name, None) == getattr(right, name, None)
        for name in ("st_dev", "st_ino", "st_mode")
    )


def _stable_read(
    path: str | Path,
    *,
    maximum_bytes: int,
    reason_code: str = "LIVE_BOUND_INPUT_INVALID",
) -> tuple[Path, bytes]:
    candidate = Path(path).expanduser().absolute()
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise WindowsLiveCanaryExecutionSourceBoundCandidateError(
            reason_code
        ) from exc
    if (
        candidate != resolved
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or metadata.st_size <= 0
        or metadata.st_size > maximum_bytes
    ):
        _reject(reason_code)
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    handle: BinaryIO | None = None
    try:
        descriptor = os.open(candidate, flags)
        handle = os.fdopen(descriptor, "rb")
        opened = os.fstat(handle.fileno())
        if not _same_stat(metadata, opened):
            _reject("LIVE_BOUND_INPUT_UNSTABLE")
        data = handle.read(maximum_bytes + 1)
        after = os.fstat(handle.fileno())
        current = candidate.lstat()
        current_resolved = candidate.resolve(strict=True)
    except WindowsLiveCanaryExecutionSourceBoundCandidateError:
        raise
    except OSError as exc:
        raise WindowsLiveCanaryExecutionSourceBoundCandidateError(
            "LIVE_BOUND_INPUT_UNSTABLE"
        ) from exc
    finally:
        if handle is not None:
            handle.close()
    if (
        len(data) != opened.st_size
        or len(data) > maximum_bytes
        or candidate != current_resolved
        or not _same_stat(opened, after)
        or not _same_stat(opened, current)
    ):
        _reject("LIVE_BOUND_INPUT_UNSTABLE")
    return candidate, data


def _candidate_inventory(
    root_path: str | Path,
) -> tuple[Path, dict[str, bytes]]:
    root = Path(root_path).expanduser().absolute()
    try:
        root_before = root.lstat()
        resolved = root.resolve(strict=True)
        paths = sorted(root.rglob("*"))
    except OSError as exc:
        raise WindowsLiveCanaryExecutionSourceBoundCandidateError(
            "LIVE_BOUND_CANDIDATE_INPUT_INVALID"
        ) from exc
    if (
        root != resolved
        or not stat.S_ISDIR(root_before.st_mode)
        or stat.S_ISLNK(root_before.st_mode)
        or _is_reparse(root_before)
    ):
        _reject("LIVE_BOUND_CANDIDATE_INPUT_INVALID")
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    folded: set[str] = set()
    total = 0
    for path in paths:
        relative = path.relative_to(root).as_posix()
        if relative.casefold() in folded:
            _reject("LIVE_BOUND_CANDIDATE_INPUT_INVALID")
        folded.add(relative.casefold())
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise WindowsLiveCanaryExecutionSourceBoundCandidateError(
                "LIVE_BOUND_CANDIDATE_INPUT_INVALID"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
            _reject("LIVE_BOUND_CANDIDATE_INPUT_INVALID")
        if stat.S_ISDIR(metadata.st_mode):
            directories.add(relative)
            continue
        if not stat.S_ISREG(metadata.st_mode) or relative not in LIVE_CANDIDATE_FILES:
            _reject("LIVE_BOUND_CANDIDATE_INPUT_INVALID")
        maximum = (
            MAX_CONFIGURED_ARCHIVE_BYTES
            if relative == "live-execution-configured-v1.zip"
            else MAX_JSON_MEMBER_BYTES
        )
        _path, data = _stable_read(
            path,
            maximum_bytes=maximum,
            reason_code="LIVE_BOUND_CANDIDATE_INPUT_INVALID",
        )
        files[relative] = data
        total += len(data)
    try:
        root_after = root.lstat()
        final_paths = sorted(
            item.relative_to(root).as_posix() for item in root.rglob("*")
        )
    except OSError as exc:
        raise WindowsLiveCanaryExecutionSourceBoundCandidateError(
            "LIVE_BOUND_INPUT_UNSTABLE"
        ) from exc
    if (
        set(files) != set(LIVE_CANDIDATE_FILES)
        or directories != _CANDIDATE_DIRECTORIES
        or total > MAX_CANDIDATE_EXPANDED_BYTES
        or not _same_stat(root_before, root_after)
        or final_paths
        != sorted(item.relative_to(root).as_posix() for item in paths)
    ):
        _reject("LIVE_BOUND_CANDIDATE_INPUT_INVALID")
    return root, files


def _write_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
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
        raise WindowsLiveCanaryExecutionSourceBoundCandidateError(
            "LIVE_BOUND_TEMPORARY_EXTRACTION_FAILED"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _materialized_payloads(
    source_bound_bytes: bytes,
    candidate_files: Mapping[str, bytes],
):
    temporary = tempfile.TemporaryDirectory(prefix="ai-scalper-live-bound-")
    root = Path(temporary.name).resolve(strict=True)
    try:
        metadata = root.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
        ):
            _reject("LIVE_BOUND_TEMPORARY_EXTRACTION_FAILED")
        source_root = root / "source"
        candidate_root = root / "candidate"
        source_root.mkdir(mode=0o700)
        candidate_root.mkdir(mode=0o700)
        for relative in sorted(
            _CANDIDATE_DIRECTORIES,
            key=lambda value: (len(PurePosixPath(value).parts), value),
        ):
            (candidate_root / relative).mkdir(mode=0o700)
        source_path = source_root / Path(SOURCE_BOUND_MEMBER).name
        _write_exclusive(source_path, source_bound_bytes)
        for relative in LIVE_CANDIDATE_FILES:
            _write_exclusive(candidate_root / relative, candidate_files[relative])
        return temporary, source_path, candidate_root
    except Exception:
        temporary.cleanup()
        raise


def _source_projection(
    value: WindowsExecutionSourceBoundCandidateVerification,
) -> dict[str, object]:
    return {
        "archive_sha256": value.archive_sha256,
        "binding_identity_sha256": value.binding_identity_sha256,
        "bootstrap_binding_sha256": value.bootstrap_binding_sha256,
        "champion_archive_sha256": value.champion_archive_sha256,
        "champion_config_sha256": value.champion_config_sha256,
        "champion_git_commit": value.git_commit,
        "champion_git_tree": value.git_tree,
        "champion_model_artifact_sha256": value.champion_model_artifact_sha256,
        "champion_package_identity_sha256": (
            value.champion_package_identity_sha256
        ),
        "champion_runtime_binding_sha256": (
            value.champion_runtime_binding_sha256
        ),
        "champion_training_snapshot_sha256": (
            value.champion_training_snapshot_sha256
        ),
        "configured_archive_sha256": value.configured_archive_sha256,
        "configured_release_identity_sha256": (
            value.configured_release_identity_sha256
        ),
        "demo_candidate_content_sha256": value.candidate_content_sha256,
        "demo_candidate_id": value.candidate_id,
        "execution_base_archive_sha256": value.execution_base_archive_sha256,
        "execution_base_release_identity_sha256": (
            value.execution_base_release_identity_sha256
        ),
        "execution_factory_template_sha256": (
            value.execution_factory_template_sha256
        ),
        "git_commit": value.git_commit,
        "git_tree": value.git_tree,
        "production_config_sha256": value.production_config_sha256,
        "provider_configuration_sha256": (
            value.provider_configuration_sha256
        ),
        "provider_pack_identity_sha256": value.provider_pack_identity_sha256,
        "source_archive_sha256": value.source_archive_sha256,
        "source_identity_sha256": value.source_identity_sha256,
        "stage_binding_sha256": value.stage_binding_sha256,
        "suite_identity_sha256": value.suite_identity_sha256,
        "task_definition_sha256": value.task_definition_sha256,
    }


def _receipt(data: bytes) -> dict[str, Any]:
    value = _strict_json(data, maximum_bytes=MAX_JSON_MEMBER_BYTES)
    required = {
        "candidate_id",
        "content_sha256",
        "git_commit",
        "git_tree",
        "runtime_mode",
    }
    if not required.issubset(value):
        _reject("LIVE_BOUND_CANDIDATE_RECEIPT_INVALID")
    return value


def _live_projection(
    candidate: WindowsLiveCanaryExecutionConfiguredCandidate,
    template: WindowsLiveCanaryExecutionFactoryTemplate,
    receipt: Mapping[str, Any],
) -> dict[str, object]:
    return {
        "base_suite_identity_sha256": candidate.base_suite_identity_sha256,
        "bootstrap_binding_sha256": candidate.bootstrap_binding_sha256,
        "candidate_id": candidate.candidate_id,
        "configured_archive_sha256": candidate.configured_archive_sha256,
        "configured_release_identity_sha256": (
            candidate.configured_release_identity_sha256
        ),
        "content_sha256": candidate.content_sha256,
        "credential_reference_count": candidate.credential_reference_count,
        "execution_base_archive_sha256": (
            candidate.execution_base_archive_sha256
        ),
        "execution_base_release_identity_sha256": (
            candidate.execution_base_release_identity_sha256
        ),
        "execution_factory_template_sha256": (
            candidate.execution_factory_template_sha256
        ),
        "git_commit": receipt["git_commit"],
        "git_tree": receipt["git_tree"],
        "live_provider_contract_set_sha256": (
            candidate.live_provider_contract_set_sha256
        ),
        "production_config_sha256": template.production_config_sha256,
        "provider_configuration_sha256": (
            candidate.provider_configuration_sha256
        ),
        "provider_count": candidate.provider_count,
        "provider_pack_identity_sha256": candidate.provider_pack_identity_sha256,
        "runtime_mode": candidate.runtime_mode,
        "task_definition_sha256": candidate.task_definition_sha256,
    }


def _verify_payloads(
    *,
    source_bound_bytes: bytes,
    candidate_files: Mapping[str, bytes],
    base_suite_root: str | Path,
    execution_base_release: str | Path,
    pins: Mapping[str, str],
) -> tuple[
    WindowsExecutionSourceBoundCandidateVerification,
    WindowsLiveCanaryExecutionConfiguredCandidate,
    WindowsLiveCanaryExecutionFactoryTemplate,
    dict[str, Any],
]:
    temporary, source_path, candidate_root = _materialized_payloads(
        source_bound_bytes,
        candidate_files,
    )
    try:
        try:
            source = verify_windows_execution_source_bound_candidate(
                source_path,
                base_suite_root=base_suite_root,
                execution_base_release=execution_base_release,
                expected_bound_archive_sha256=pins["source_bound"],
                expected_source_archive_sha256=pins["source"],
                expected_champion_archive_sha256=pins["champion"],
                expected_model_artifact_sha256=pins["model"],
                expected_training_snapshot_sha256=pins["snapshot"],
                expected_config_sha256=pins["config"],
                expected_git_commit=pins["commit"],
                expected_git_tree=pins["tree"],
                expected_suite_identity_sha256=pins["suite"],
            )
        except WindowsExecutionSourceBoundCandidateError as exc:
            raise WindowsLiveCanaryExecutionSourceBoundCandidateError(
                "LIVE_BOUND_SOURCE_ANCESTRY_INVALID"
            ) from exc
        try:
            candidate = (
                validate_windows_live_canary_execution_configured_candidate(
                    base_suite_root=base_suite_root,
                    execution_base_release=execution_base_release,
                    candidate_root=candidate_root,
                )
            )
            template = validate_windows_live_canary_execution_factory_template(
                candidate_files["live-execution-factory-template.json"]
            )
        except LiveExecutionConfiguredCandidateError as exc:
            raise WindowsLiveCanaryExecutionSourceBoundCandidateError(
                "LIVE_BOUND_CONFIGURED_CANDIDATE_INVALID"
            ) from exc
        receipt = _receipt(candidate_files[CANDIDATE_RECEIPT_NAME])
    finally:
        temporary.cleanup()
    if template.production_config_sha256 != source.source_archive_sha256:
        _reject("LIVE_BOUND_SOURCE_PROVIDER_MISMATCH")
    if (
        candidate.bootstrap_binding_sha256 != source.bootstrap_binding_sha256
        or template.bootstrap_binding_sha256 != source.bootstrap_binding_sha256
    ):
        _reject("LIVE_BOUND_SOURCE_BOOTSTRAP_MISMATCH")
    if (
        candidate.base_suite_identity_sha256 != source.suite_identity_sha256
        or candidate.execution_base_archive_sha256
        != source.execution_base_archive_sha256
        or candidate.execution_base_release_identity_sha256
        != source.execution_base_release_identity_sha256
    ):
        _reject("LIVE_BOUND_SUITE_BINDING_MISMATCH")
    if (
        receipt.get("git_commit") != source.git_commit
        or receipt.get("git_tree") != source.git_tree
        or source.git_commit != pins["commit"]
        or source.git_tree != pins["tree"]
    ):
        _reject("LIVE_BOUND_GIT_BINDING_MISMATCH")
    if (
        candidate.runtime_mode != "LIVE"
        or template.runtime_mode != "LIVE"
        or template.template_id != candidate.candidate_id
        or template.expected_release_identity_sha256
        != candidate.configured_release_identity_sha256
        or template.provider_configuration_sha256
        != candidate.provider_configuration_sha256
        or template.live_provider_contract_set_sha256
        != candidate.live_provider_contract_set_sha256
        or template.task_definition_sha256
        != candidate.task_definition_sha256
        or template.provider_count != candidate.provider_count
        or template.credential_reference_count
        != candidate.credential_reference_count
        or candidate.provider_count != 49
        or candidate.credential_reference_count != 12
    ):
        _reject("LIVE_BOUND_CANDIDATE_BINDING_MISMATCH")
    return source, candidate, template, receipt


def _member_rows(payloads: Mapping[str, bytes]) -> list[dict[str, object]]:
    return [
        {
            "path": path,
            "sha256": _sha256(payloads[path]),
            "size_bytes": len(payloads[path]),
        }
        for path in PAYLOAD_MEMBERS
    ]


def _manifest_identity(payload: Mapping[str, object]) -> str:
    core = dict(payload)
    core.pop("binding_identity_sha256", None)
    return _sha256(_canonical_bytes(core))


def _build_manifest(
    *,
    payloads: Mapping[str, bytes],
    source: WindowsExecutionSourceBoundCandidateVerification,
    candidate: WindowsLiveCanaryExecutionConfiguredCandidate,
    template: WindowsLiveCanaryExecutionFactoryTemplate,
    receipt: Mapping[str, Any],
) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "members": _member_rows(payloads),
        "source_bound": _source_projection(source),
        "live_candidate": _live_projection(candidate, template, receipt),
        "safety": dict(SAFETY),
        "effects": dict(EFFECTS),
    }
    return {
        **unsigned,
        "binding_identity_sha256": _manifest_identity(unsigned),
    }


def _hash_field(value: object, pattern: re.Pattern[str]) -> bool:
    return (
        type(value) is str
        and pattern.fullmatch(value) is not None
        and set(value) != {"0"}
    )


def _validate_manifest(value: dict[str, Any]) -> dict[str, dict[str, object]]:
    source = value.get("source_bound")
    candidate = value.get("live_candidate")
    rows = value.get("members")
    if (
        set(value) != _MANIFEST_FIELDS
        or value.get("schema_version") != SCHEMA_VERSION
        or type(value.get("safety")) is not dict
        or _canonical_bytes(value["safety"]) != _canonical_bytes(SAFETY)
        or type(value.get("effects")) is not dict
        or _canonical_bytes(value["effects"]) != _canonical_bytes(EFFECTS)
        or value.get("binding_identity_sha256") != _manifest_identity(value)
        or type(source) is not dict
        or set(source) != _SOURCE_FIELDS
        or type(candidate) is not dict
        or set(candidate) != _LIVE_FIELDS
        or type(rows) is not list
        or len(rows) != len(PAYLOAD_MEMBERS)
    ):
        _reject("LIVE_BOUND_MANIFEST_INVALID")
    if not isinstance(source, dict) or not isinstance(candidate, dict):
        _reject("LIVE_BOUND_MANIFEST_INVALID")
    for name, item in source.items():
        if name in {"demo_candidate_id"}:
            if type(item) is not str or _IDENTIFIER.fullmatch(item) is None:
                _reject("LIVE_BOUND_MANIFEST_INVALID")
            continue
        pattern = _HEX_40 if name in {"champion_git_commit", "champion_git_tree", "git_commit", "git_tree"} else _HEX_64
        if not _hash_field(item, pattern):
            _reject("LIVE_BOUND_MANIFEST_INVALID")
    for name, item in candidate.items():
        if name == "candidate_id":
            if type(item) is not str or _IDENTIFIER.fullmatch(item) is None:
                _reject("LIVE_BOUND_MANIFEST_INVALID")
        elif name == "runtime_mode":
            if item != "LIVE":
                _reject("LIVE_BOUND_MANIFEST_INVALID")
        elif name in {"provider_count", "credential_reference_count"}:
            expected = 49 if name == "provider_count" else 12
            if type(item) is not int or item != expected:
                _reject("LIVE_BOUND_MANIFEST_INVALID")
        else:
            pattern = _HEX_40 if name in {"git_commit", "git_tree"} else _HEX_64
            if not _hash_field(item, pattern):
                _reject("LIVE_BOUND_MANIFEST_INVALID")
    entries: dict[str, dict[str, object]] = {}
    order: list[str] = []
    folded: set[str] = set()
    for row in rows:
        if type(row) is not dict or set(row) != _MEMBER_FIELDS:
            _reject("LIVE_BOUND_MANIFEST_INVALID")
        path = row.get("path")
        size = row.get("size_bytes")
        digest = row.get("sha256")
        if (
            type(path) is not str
            or path not in PAYLOAD_MEMBERS
            or path.casefold() in folded
            or type(size) is not int
            or size <= 0
            or not _hash_field(digest, _HEX_64)
        ):
            _reject("LIVE_BOUND_MANIFEST_INVALID")
        folded.add(path.casefold())
        entries[path] = row
        order.append(path)
    if tuple(order) != PAYLOAD_MEMBERS or set(entries) != set(PAYLOAD_MEMBERS):
        _reject("LIVE_BOUND_MANIFEST_INVALID")
    return entries


def _valid_member_path(value: object) -> bool:
    if type(value) is not str or not value or "\\" in value or ":" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and str(path) == value
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _member_maximum(name: str) -> int:
    if name == SOURCE_BOUND_MEMBER:
        return MAX_SOURCE_BOUND_ARCHIVE_BYTES
    if name == "candidate/live-execution-configured-v1.zip":
        return MAX_CONFIGURED_ARCHIVE_BYTES
    return MAX_JSON_MEMBER_BYTES


def _validate_eocd(data: bytes) -> None:
    if len(data) < 22:
        _reject("LIVE_BOUND_ZIP_INVALID")
    eocd = data[-22:]
    if (
        eocd[:4] != b"PK\x05\x06"
        or int.from_bytes(eocd[4:6], "little") != 0
        or int.from_bytes(eocd[6:8], "little") != 0
        or int.from_bytes(eocd[8:10], "little") != len(ARCHIVE_MEMBERS)
        or int.from_bytes(eocd[10:12], "little") != len(ARCHIVE_MEMBERS)
        or int.from_bytes(eocd[20:22], "little") != 0
    ):
        _reject("LIVE_BOUND_ZIP_INVALID")
    central_size = int.from_bytes(eocd[12:16], "little")
    central_offset = int.from_bytes(eocd[16:20], "little")
    if (
        central_size in {0, 0xFFFFFFFF}
        or central_offset == 0xFFFFFFFF
        or central_offset + central_size != len(data) - 22
    ):
        _reject("LIVE_BOUND_ZIP_INVALID")


def _zip_inventory(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    try:
        infos = archive.infolist()
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise WindowsLiveCanaryExecutionSourceBoundCandidateError(
            "LIVE_BOUND_ZIP_INVALID"
        ) from exc
    if (
        len(infos) != len(ARCHIVE_MEMBERS)
        or tuple(info.filename for info in infos) != ARCHIVE_MEMBERS
        or archive.comment != b""
    ):
        _reject("LIVE_BOUND_ZIP_INVENTORY_INVALID")
    observed: dict[str, zipfile.ZipInfo] = {}
    offsets: set[int] = set()
    candidate_total = 0
    for info in infos:
        mode = (info.external_attr >> 16) & 0xFFFF
        maximum = _member_maximum(info.filename)
        if (
            not _valid_member_path(info.filename)
            or info.filename.casefold()
            in {name.casefold() for name in observed}
            or info.is_dir()
            or info.compress_type != zipfile.ZIP_DEFLATED
            or info.flag_bits != 0
            or info.date_time != FIXED_ZIP_TIMESTAMP
            or info.create_system != 3
            or info.create_version != 20
            or info.extract_version != 20
            or mode != FIXED_ZIP_MODE
            or info.external_attr != FIXED_ZIP_MODE << 16
            or info.internal_attr != 0
            or info.volume != 0
            or info.extra != b""
            or info.comment != b""
            or info.file_size <= 0
            or info.file_size > maximum
            or info.compress_size <= 0
            or info.header_offset in offsets
        ):
            _reject("LIVE_BOUND_ZIP_METADATA_INVALID")
        observed[info.filename] = info
        offsets.add(info.header_offset)
        if info.filename.startswith("candidate/"):
            candidate_total += info.file_size
    if (
        candidate_total > MAX_CANDIDATE_EXPANDED_BYTES
        or set(observed) != set(ARCHIVE_MEMBERS)
    ):
        _reject("LIVE_BOUND_ZIP_INVENTORY_INVALID")
    return observed


def _read_zip_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
) -> bytes:
    maximum = _member_maximum(info.filename)
    try:
        with archive.open(info, "r") as source:
            data = source.read(maximum + 1)
    except (OSError, RuntimeError, EOFError, zipfile.BadZipFile) as exc:
        raise WindowsLiveCanaryExecutionSourceBoundCandidateError(
            "LIVE_BOUND_ZIP_INVALID"
        ) from exc
    if len(data) != info.file_size or len(data) > maximum:
        _reject("LIVE_BOUND_ZIP_INVALID")
    return data


def _result(
    *,
    archive_path: Path,
    archive_bytes: bytes,
    manifest: Mapping[str, Any],
) -> WindowsLiveCanaryExecutionSourceBoundCandidateVerification:
    source = manifest["source_bound"]
    candidate = manifest["live_candidate"]
    return WindowsLiveCanaryExecutionSourceBoundCandidateVerification(
        archive_path=archive_path,
        archive_sha256=_sha256(archive_bytes),
        archive_size_bytes=len(archive_bytes),
        binding_identity_sha256=manifest["binding_identity_sha256"],
        source_bound_archive_sha256=source["archive_sha256"],
        source_bound_binding_identity_sha256=source[
            "binding_identity_sha256"
        ],
        source_archive_sha256=source["source_archive_sha256"],
        bootstrap_binding_sha256=source["bootstrap_binding_sha256"],
        candidate_id=candidate["candidate_id"],
        candidate_content_sha256=candidate["content_sha256"],
        production_config_sha256=candidate["production_config_sha256"],
        provider_pack_identity_sha256=candidate[
            "provider_pack_identity_sha256"
        ],
        provider_configuration_sha256=candidate[
            "provider_configuration_sha256"
        ],
        live_provider_contract_set_sha256=candidate[
            "live_provider_contract_set_sha256"
        ],
        configured_release_identity_sha256=candidate[
            "configured_release_identity_sha256"
        ],
        configured_archive_sha256=candidate["configured_archive_sha256"],
        execution_factory_template_sha256=candidate[
            "execution_factory_template_sha256"
        ],
        task_definition_sha256=candidate["task_definition_sha256"],
        suite_identity_sha256=candidate["base_suite_identity_sha256"],
        execution_base_archive_sha256=candidate[
            "execution_base_archive_sha256"
        ],
        execution_base_release_identity_sha256=candidate[
            "execution_base_release_identity_sha256"
        ],
        git_commit=candidate["git_commit"],
        git_tree=candidate["git_tree"],
        provider_count=candidate["provider_count"],
        credential_reference_count=candidate["credential_reference_count"],
        _seal=_RESULT_SEAL,
    )


def _verify_archive_bytes(
    data: bytes,
    *,
    archive_path: Path,
    base_suite_root: str | Path,
    execution_base_release: str | Path,
    pins: Mapping[str, str],
) -> WindowsLiveCanaryExecutionSourceBoundCandidateVerification:
    if type(data) is not bytes or not data or len(data) > MAX_ARCHIVE_BYTES:
        _reject("LIVE_BOUND_ARCHIVE_INVALID")
    if _sha256(data) != pins["live_bound"]:
        _reject("LIVE_BOUND_ARCHIVE_PIN_MISMATCH")
    _validate_eocd(data)
    try:
        archive = zipfile.ZipFile(io.BytesIO(data), "r")
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise WindowsLiveCanaryExecutionSourceBoundCandidateError(
            "LIVE_BOUND_ZIP_INVALID"
        ) from exc
    with archive:
        inventory = _zip_inventory(archive)
        payloads = {
            name: _read_zip_member(archive, inventory[name])
            for name in ARCHIVE_MEMBERS
        }
    manifest = _strict_json(
        payloads[MANIFEST_MEMBER],
        maximum_bytes=MAX_JSON_MEMBER_BYTES,
    )
    rows = _validate_manifest(manifest)
    for name in PAYLOAD_MEMBERS:
        if (
            rows[name]["size_bytes"] != len(payloads[name])
            or rows[name]["sha256"] != _sha256(payloads[name])
        ):
            _reject("LIVE_BOUND_MEMBER_MISMATCH")
    candidate_files = {
        name.removeprefix("candidate/"): payloads[name]
        for name in CANDIDATE_MEMBERS
    }
    source, candidate, template, receipt = _verify_payloads(
        source_bound_bytes=payloads[SOURCE_BOUND_MEMBER],
        candidate_files=candidate_files,
        base_suite_root=base_suite_root,
        execution_base_release=execution_base_release,
        pins=pins,
    )
    expected = _build_manifest(
        payloads={name: payloads[name] for name in PAYLOAD_MEMBERS},
        source=source,
        candidate=candidate,
        template=template,
        receipt=receipt,
    )
    if _canonical_bytes(manifest) != _canonical_bytes(expected):
        _reject("LIVE_BOUND_MANIFEST_BINDING_MISMATCH")
    return _result(
        archive_path=archive_path,
        archive_bytes=data,
        manifest=manifest,
    )


def _pins(
    *,
    expected_live_bound_archive_sha256: str,
    expected_source_bound_archive_sha256: str,
    expected_source_archive_sha256: str,
    expected_champion_archive_sha256: str,
    expected_model_artifact_sha256: str,
    expected_training_snapshot_sha256: str,
    expected_config_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
    expected_suite_identity_sha256: str,
) -> dict[str, str]:
    return {
        "live_bound": _pin(expected_live_bound_archive_sha256, _HEX_64),
        "source_bound": _pin(expected_source_bound_archive_sha256, _HEX_64),
        "source": _pin(expected_source_archive_sha256, _HEX_64),
        "champion": _pin(expected_champion_archive_sha256, _HEX_64),
        "model": _pin(expected_model_artifact_sha256, _HEX_64),
        "snapshot": _pin(expected_training_snapshot_sha256, _HEX_64),
        "config": _pin(expected_config_sha256, _HEX_64),
        "commit": _pin(expected_git_commit, _HEX_40),
        "tree": _pin(expected_git_tree, _HEX_40),
        "suite": _pin(expected_suite_identity_sha256, _HEX_64),
    }


def verify_windows_live_canary_execution_source_bound_candidate(
    archive_path: str | Path,
    *,
    base_suite_root: str | Path,
    execution_base_release: str | Path,
    expected_live_bound_archive_sha256: str,
    expected_source_bound_archive_sha256: str,
    expected_source_archive_sha256: str,
    expected_champion_archive_sha256: str,
    expected_model_artifact_sha256: str,
    expected_training_snapshot_sha256: str,
    expected_config_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
    expected_suite_identity_sha256: str,
) -> WindowsLiveCanaryExecutionSourceBoundCandidateVerification:
    """Verify one portable LIVE archive against ten independent pins."""

    pins = _pins(
        expected_live_bound_archive_sha256=(
            expected_live_bound_archive_sha256
        ),
        expected_source_bound_archive_sha256=(
            expected_source_bound_archive_sha256
        ),
        expected_source_archive_sha256=expected_source_archive_sha256,
        expected_champion_archive_sha256=(
            expected_champion_archive_sha256
        ),
        expected_model_artifact_sha256=expected_model_artifact_sha256,
        expected_training_snapshot_sha256=(
            expected_training_snapshot_sha256
        ),
        expected_config_sha256=expected_config_sha256,
        expected_git_commit=expected_git_commit,
        expected_git_tree=expected_git_tree,
        expected_suite_identity_sha256=expected_suite_identity_sha256,
    )
    path, data = _stable_read(
        archive_path,
        maximum_bytes=MAX_ARCHIVE_BYTES,
    )
    return _verify_archive_bytes(
        data,
        archive_path=path,
        base_suite_root=base_suite_root,
        execution_base_release=execution_base_release,
        pins=pins,
    )


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = FIXED_ZIP_MODE << 16
    return info


def _archive_bytes(members: Mapping[str, bytes]) -> bytes:
    destination = io.BytesIO()
    try:
        with zipfile.ZipFile(
            destination,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            for name in ARCHIVE_MEMBERS:
                archive.writestr(
                    _zip_info(name),
                    members[name],
                    compress_type=zipfile.ZIP_DEFLATED,
                    compresslevel=9,
                )
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        raise WindowsLiveCanaryExecutionSourceBoundCandidateError(
            "LIVE_BOUND_ARCHIVE_BUILD_FAILED"
        ) from exc
    data = destination.getvalue()
    if not data or len(data) > MAX_ARCHIVE_BYTES:
        _reject("LIVE_BOUND_ARCHIVE_BUILD_FAILED")
    return data


def _validate_destination(output: str | Path) -> tuple[Path, os.stat_result]:
    candidate = Path(output).expanduser().absolute()
    if _OUTPUT_NAME.fullmatch(candidate.name) is None:
        _reject("LIVE_BOUND_DESTINATION_INVALID")
    parent = candidate.parent
    try:
        metadata = parent.lstat()
        resolved = parent.resolve(strict=True)
    except OSError as exc:
        raise WindowsLiveCanaryExecutionSourceBoundCandidateError(
            "LIVE_BOUND_DESTINATION_INVALID"
        ) from exc
    if (
        parent != resolved
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or os.path.lexists(candidate)
    ):
        _reject("LIVE_BOUND_DESTINATION_INVALID")
    return candidate, metadata


def _remove_created_output(
    path: Path,
    identity: os.stat_result | None,
    expected_bytes: bytes,
) -> None:
    if identity is None:
        return
    try:
        current = path.lstat()
        if (
            stat.S_ISREG(current.st_mode)
            and not stat.S_ISLNK(current.st_mode)
            and not _is_reparse(current)
            and _same_identity(identity, current)
            and current.st_size == len(expected_bytes)
            and path.read_bytes() == expected_bytes
        ):
            path.unlink()
    except OSError:
        pass


def _publish_exclusive(
    output: Path,
    data: bytes,
    parent_state: os.stat_result,
) -> os.stat_result:
    try:
        current_parent = output.parent.stat(follow_symlinks=False)
    except OSError as exc:
        raise WindowsLiveCanaryExecutionSourceBoundCandidateError(
            "LIVE_BOUND_PUBLICATION_FAILED"
        ) from exc
    if (
        not _same_identity(parent_state, current_parent)
        or output.parent.is_symlink()
        or _is_reparse(current_parent)
        or os.path.lexists(output)
    ):
        _reject("LIVE_BOUND_PUBLICATION_FAILED")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    descriptor: int | None = None
    identity: os.stat_result | None = None
    try:
        descriptor = os.open(output, flags, 0o600)
        identity = os.fstat(descriptor)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        current = output.lstat()
        if (
            not stat.S_ISREG(current.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or _is_reparse(current)
            or not _same_identity(identity, current)
            or current.st_size != len(data)
        ):
            _reject("LIVE_BOUND_PUBLICATION_FAILED")
        return identity
    except WindowsLiveCanaryExecutionSourceBoundCandidateError:
        _remove_created_output(output, identity, data)
        raise
    except OSError as exc:
        _remove_created_output(output, identity, data)
        raise WindowsLiveCanaryExecutionSourceBoundCandidateError(
            "LIVE_BOUND_PUBLICATION_FAILED"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def prepare_windows_live_canary_execution_source_bound_candidate(
    *,
    base_suite_root: str | Path,
    execution_base_release: str | Path,
    demo_source_bound_archive: str | Path,
    live_configured_candidate_root: str | Path,
    expected_source_bound_archive_sha256: str,
    expected_source_archive_sha256: str,
    expected_champion_archive_sha256: str,
    expected_model_artifact_sha256: str,
    expected_training_snapshot_sha256: str,
    expected_config_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
    expected_suite_identity_sha256: str,
    output: str | Path,
) -> WindowsLiveCanaryExecutionSourceBoundCandidateVerification:
    """Prepare, self-verify, and exclusively publish one LIVE archive."""

    pins = _pins(
        expected_live_bound_archive_sha256="1" * 64,
        expected_source_bound_archive_sha256=(
            expected_source_bound_archive_sha256
        ),
        expected_source_archive_sha256=expected_source_archive_sha256,
        expected_champion_archive_sha256=(
            expected_champion_archive_sha256
        ),
        expected_model_artifact_sha256=expected_model_artifact_sha256,
        expected_training_snapshot_sha256=(
            expected_training_snapshot_sha256
        ),
        expected_config_sha256=expected_config_sha256,
        expected_git_commit=expected_git_commit,
        expected_git_tree=expected_git_tree,
        expected_suite_identity_sha256=expected_suite_identity_sha256,
    )
    destination, parent_state = _validate_destination(output)
    source_path, source_bound_bytes = _stable_read(
        demo_source_bound_archive,
        maximum_bytes=MAX_SOURCE_BOUND_ARCHIVE_BYTES,
    )
    candidate_root, candidate_files = _candidate_inventory(
        live_configured_candidate_root
    )
    suite_root = Path(base_suite_root).expanduser().absolute()
    if (
        destination == source_path
        or destination.is_relative_to(candidate_root)
        or destination.is_relative_to(suite_root)
    ):
        _reject("LIVE_BOUND_DESTINATION_INVALID")
    source, candidate, template, receipt = _verify_payloads(
        source_bound_bytes=source_bound_bytes,
        candidate_files=candidate_files,
        base_suite_root=base_suite_root,
        execution_base_release=execution_base_release,
        pins=pins,
    )
    payloads = {
        SOURCE_BOUND_MEMBER: source_bound_bytes,
        **{
            f"candidate/{path}": candidate_files[path]
            for path in LIVE_CANDIDATE_FILES
        },
    }
    manifest = _build_manifest(
        payloads=payloads,
        source=source,
        candidate=candidate,
        template=template,
        receipt=receipt,
    )
    data = _archive_bytes(
        {
            MANIFEST_MEMBER: _canonical_bytes(manifest, newline=True),
            **payloads,
        }
    )
    archive_sha256 = _sha256(data)
    verification_pins = {**pins, "live_bound": archive_sha256}
    _verify_archive_bytes(
        data,
        archive_path=destination,
        base_suite_root=base_suite_root,
        execution_base_release=execution_base_release,
        pins=verification_pins,
    )
    identity: os.stat_result | None = None
    try:
        identity = _publish_exclusive(destination, data, parent_state)
        return verify_windows_live_canary_execution_source_bound_candidate(
            destination,
            base_suite_root=base_suite_root,
            execution_base_release=execution_base_release,
            expected_live_bound_archive_sha256=archive_sha256,
            expected_source_bound_archive_sha256=pins["source_bound"],
            expected_source_archive_sha256=pins["source"],
            expected_champion_archive_sha256=pins["champion"],
            expected_model_artifact_sha256=pins["model"],
            expected_training_snapshot_sha256=pins["snapshot"],
            expected_config_sha256=pins["config"],
            expected_git_commit=pins["commit"],
            expected_git_tree=pins["tree"],
            expected_suite_identity_sha256=pins["suite"],
        )
    except Exception:
        _remove_created_output(destination, identity, data)
        raise


__all__ = [
    "ARCHIVE_MEMBERS",
    "CANDIDATE_MEMBERS",
    "EFFECTS",
    "FIXED_ZIP_MODE",
    "FIXED_ZIP_TIMESTAMP",
    "LIVE_CANDIDATE_FILES",
    "MANIFEST_MEMBER",
    "MAX_ARCHIVE_BYTES",
    "ORDER_CAPABILITY",
    "PAYLOAD_MEMBERS",
    "SAFETY",
    "SCHEMA_VERSION",
    "SOURCE_BOUND_MEMBER",
    "WindowsLiveCanaryExecutionSourceBoundCandidateError",
    "WindowsLiveCanaryExecutionSourceBoundCandidateVerification",
    "is_windows_live_canary_execution_source_bound_candidate_verification",
    "prepare_windows_live_canary_execution_source_bound_candidate",
    "verify_windows_live_canary_execution_source_bound_candidate",
]
