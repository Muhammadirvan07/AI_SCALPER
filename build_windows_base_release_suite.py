"""Atomically build the five fixed Windows base-release artifacts.

This is release-operator tooling only.  It composes the existing deterministic
role builders, independently verifies their outputs, and publishes one
same-commit suite directory.  It has no provider, credential, MT5, activation,
or broker capability.
"""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable, Mapping

from build_windows_configured_release_tooling import (
    build_configured_release_tooling,
)
from build_windows_decision_release import build_decision_release
from build_windows_execution_release import build_execution_release
from build_windows_release import build_release
from build_windows_status_monitor_release import build_status_monitor_release


REPO_ROOT = Path(__file__).resolve().parent
SUITE_SCHEMA = "ai-scalper-windows-base-release-suite-v1"
SUITE_PROFILE = "WINDOWS_ATOMIC_BASE_RELEASE_SUITE_V1"
SUITE_MANIFEST_NAME = "BASE_RELEASE_SUITE.json"
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
HEX_40 = re.compile(r"[0-9a-f]{40}")
HEX_64 = re.compile(r"[0-9a-f]{64}")
ROLE_RECORD_KEYS = frozenset(
    {
        "role",
        "release_profile",
        "archive_path",
        "archive_size_bytes",
        "archive_sha256",
        "sidecar_path",
        "sidecar_size_bytes",
        "sidecar_sha256",
        "release_identity_sha256",
        "source_file_count",
        "order_capability",
        "production_execution_ready",
    }
)
SUITE_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "release_profile",
        "git_commit",
        "git_tree",
        "roles",
        "effects",
        "safety",
        "suite_identity_sha256",
    }
)
LOCKED_SAFETY = {
    "live_allowed": False,
    "safe_to_demo_auto_order": False,
    "max_lot": 0.01,
    "promotion_eligible": False,
}
SUITE_EFFECTS = {
    "network_access": False,
    "git_subprocess": True,
    "provider_import": False,
    "provider_materialization": False,
    "credential_access": False,
    "task_installation": False,
    "runtime_process_launch": False,
    "mt5_initialization": False,
    "broker_mutation": False,
    "activation": False,
    "permit_issuance": False,
}


class BaseReleaseSuiteError(RuntimeError):
    """Stable, public, fail-closed suite construction error."""


@dataclass(frozen=True)
class BaseReleaseRolePolicy:
    role: str
    builder_name: str
    allowlist_relative: str
    archive_name: str
    release_profile: str
    manifest_schema: str
    order_capability: str
    manifest_keys: frozenset[str]
    result_keys: frozenset[str]
    production_field_required: bool


_COMMON_MANIFEST_KEYS = {
    "schema_version",
    "release_profile",
    "git_commit",
    "git_tree",
    "allowlist_sha256",
    "safety",
    "usage_policy",
    "source_files",
    "release_identity_sha256",
}
_SERVICE_RESULT_KEYS = frozenset(
    {
        "archive",
        "archive_sha256",
        "manifest",
        "release_identity_sha256",
        "file_count",
        "order_capability",
        "production_execution_ready",
    }
)
ROLE_POLICIES = (
    BaseReleaseRolePolicy(
        role="DECISION",
        builder_name="build_decision_release",
        allowlist_relative=(
            "config/windows_decision_service_allowlist.v1.json"
        ),
        archive_name="decision-base-v1.zip",
        release_profile="WINDOWS_DECISION_SERVICE_V1",
        manifest_schema="ai-scalper-windows-decision-service-manifest-v1",
        order_capability="DISABLED",
        manifest_keys=frozenset(
            _COMMON_MANIFEST_KEYS
            | {
                "dependency_lock_summary",
                "production_execution_ready",
                "readiness_blockers",
                "runtime_factory",
                "runtime_loader",
                "required_factory_provider_contracts",
                "trust_boundaries",
                "effects_during_validation",
            }
        ),
        result_keys=_SERVICE_RESULT_KEYS,
        production_field_required=True,
    ),
    BaseReleaseRolePolicy(
        role="EXECUTION",
        builder_name="build_execution_release",
        allowlist_relative=(
            "config/windows_execution_service_allowlist.v1.json"
        ),
        archive_name="execution-base-v1.zip",
        release_profile="WINDOWS_GATED_EXECUTION_SERVICE_V1",
        manifest_schema="ai-scalper-windows-execution-service-manifest-v1",
        order_capability="GATED_PRESENT",
        manifest_keys=frozenset(
            _COMMON_MANIFEST_KEYS
            | {
                "activation_requires",
                "decision_process",
                "demo_auto_gate_semantics",
                "dependency_lock_summary",
                "foundation_status",
                "full_pending_gate_catalog",
                "order_primitive_inventory",
                "production_execution_ready",
                "readiness_blockers",
                "readiness_blockers_by_category",
            }
        ),
        result_keys=_SERVICE_RESULT_KEYS,
        production_field_required=True,
    ),
    BaseReleaseRolePolicy(
        role="STATUS_MONITOR",
        builder_name="build_status_monitor_release",
        allowlist_relative=(
            "config/windows_status_monitor_allowlist.v1.json"
        ),
        archive_name="status-monitor-base-v1.zip",
        release_profile="WINDOWS_EXTERNAL_STATUS_MONITOR_V1",
        manifest_schema="ai-scalper-windows-status-monitor-manifest-v1",
        order_capability="DISABLED",
        manifest_keys=frozenset(
            _COMMON_MANIFEST_KEYS
            | {
                "dependency_lock_summary",
                "production_execution_ready",
                "readiness_blockers",
                "runtime_factory",
                "runtime_loader",
                "required_factory_provider_contracts",
                "trust_boundaries",
                "effects_during_validation",
            }
        ),
        result_keys=_SERVICE_RESULT_KEYS,
        production_field_required=True,
    ),
    BaseReleaseRolePolicy(
        role="READ_ONLY_SHADOW",
        builder_name="build_release",
        allowlist_relative="config/windows_shadow_service_allowlist.v1.json",
        archive_name="read-only-shadow-base-v1.zip",
        release_profile="WINDOWS_READ_ONLY_SHADOW_SERVICE_V1",
        manifest_schema="ai-scalper-windows-release-manifest-v1",
        order_capability="DISABLED",
        manifest_keys=frozenset(_COMMON_MANIFEST_KEYS),
        result_keys=frozenset(
            {
                "archive",
                "archive_sha256",
                "manifest",
                "release_identity_sha256",
                "file_count",
                "bundle_class",
                "execution_context",
            }
        ),
        production_field_required=False,
    ),
    BaseReleaseRolePolicy(
        role="CONFIGURED_RELEASE_TOOLING",
        builder_name="build_configured_release_tooling",
        allowlist_relative=(
            "config/windows_configured_release_tooling_allowlist.v1.json"
        ),
        archive_name="configured-release-tooling-v1.zip",
        release_profile="WINDOWS_CONFIGURED_RELEASE_OPERATOR_TOOLING_V1",
        manifest_schema=(
            "ai-scalper-windows-configured-release-tooling-manifest-v1"
        ),
        order_capability="DISABLED",
        manifest_keys=frozenset(
            _COMMON_MANIFEST_KEYS
            | {
                "effects_during_build",
                "production_execution_ready",
                "readiness_blockers",
                "stdlib_only",
            }
        ),
        result_keys=_SERVICE_RESULT_KEYS,
        production_field_required=True,
    ),
)


def _canonical_json(payload: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BaseReleaseSuiteError(
            "BASE_RELEASE_SUITE_MANIFEST_INVALID"
        ) from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValueError("non-finite JSON number")


def _strict_json(
    data: bytes,
    *,
    expected_keys: frozenset[str],
) -> dict[str, Any]:
    if not data or len(data) > MAX_MANIFEST_BYTES or not data.endswith(b"\n"):
        raise BaseReleaseSuiteError("BASE_RELEASE_SUITE_MANIFEST_INVALID")
    try:
        text = data.decode("utf-8")
        payload = json.loads(
            text,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise BaseReleaseSuiteError(
            "BASE_RELEASE_SUITE_MANIFEST_INVALID"
        ) from exc
    if (
        not isinstance(payload, dict)
        or frozenset(payload) != expected_keys
        or _canonical_json(payload) + b"\n" != data
    ):
        raise BaseReleaseSuiteError("BASE_RELEASE_SUITE_MANIFEST_INVALID")
    return payload


def _stable_read(path: Path, *, maximum_bytes: int) -> bytes:
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise OSError("not a regular file")
        flags = os.O_RDONLY
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum_bytes:
                    raise OSError("file exceeds bound")
                chunks.append(chunk)
            after_open = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = path.lstat()
        facts = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_size",
            "st_mtime_ns",
        )
        if any(
            getattr(before, name) != getattr(opened, name)
            or getattr(opened, name) != getattr(after_open, name)
            or getattr(after_open, name) != getattr(after_path, name)
            for name in facts
        ):
            raise OSError("file changed during read")
        return b"".join(chunks)
    except (OSError, ValueError) as exc:
        raise BaseReleaseSuiteError(
            "BASE_RELEASE_SUITE_MANIFEST_INVALID"
        ) from exc


def _git(
    root: Path,
    *args: str,
    binary: bool = False,
) -> str | bytes:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BaseReleaseSuiteError(
            "BASE_RELEASE_SUITE_SOURCE_NOT_CLEAN"
        ) from exc
    if binary:
        return completed.stdout
    try:
        return completed.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise BaseReleaseSuiteError(
            "BASE_RELEASE_SUITE_SOURCE_NOT_CLEAN"
        ) from exc


def _clean_source_state(repo_root: Path) -> tuple[str, str]:
    commit = _git(repo_root, "rev-parse", "HEAD")
    tree = _git(repo_root, "rev-parse", "HEAD^{tree}")
    status_bytes = _git(
        repo_root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        binary=True,
    )
    if (
        not isinstance(commit, str)
        or HEX_40.fullmatch(commit) is None
        or not isinstance(tree, str)
        or HEX_40.fullmatch(tree) is None
        or not isinstance(status_bytes, bytes)
        or status_bytes
    ):
        raise BaseReleaseSuiteError("BASE_RELEASE_SUITE_SOURCE_NOT_CLEAN")
    return commit, tree


def _is_junction(path: Path) -> bool:
    predicate = getattr(os.path, "isjunction", None)
    return bool(predicate(path)) if callable(predicate) else False


def _validate_destination(repo_root: Path, output_root: Path) -> tuple[Path, os.stat_result]:
    if ".." in output_root.parts:
        raise BaseReleaseSuiteError(
            "BASE_RELEASE_SUITE_DESTINATION_INVALID"
        )
    try:
        repository = repo_root.resolve(strict=True)
        if not repository.is_dir():
            raise OSError("repository is not a directory")
        candidate = output_root.absolute()
        if os.path.lexists(candidate):
            raise OSError("destination exists")
        parent = candidate.parent
        if (
            not parent.exists()
            or not parent.is_dir()
            or parent.is_symlink()
            or _is_junction(parent)
            or parent.resolve(strict=True) != parent
        ):
            raise OSError("unsafe destination parent")
        resolved_parent = parent.resolve(strict=True)
        resolved = resolved_parent / candidate.name
        try:
            resolved.relative_to(repository)
        except ValueError:
            pass
        else:
            raise OSError("destination is inside repository")
        parent_state = parent.stat(follow_symlinks=False)
        if not stat.S_ISDIR(parent_state.st_mode):
            raise OSError("destination parent is not a directory")
        return resolved, parent_state
    except (OSError, RuntimeError, ValueError) as exc:
        raise BaseReleaseSuiteError(
            "BASE_RELEASE_SUITE_DESTINATION_INVALID"
        ) from exc


def _source_files_valid(value: object) -> bool:
    if not isinstance(value, list) or not value:
        return False
    paths: list[str] = []
    for item in value:
        if (
            not isinstance(item, dict)
            or frozenset(item) != {"path", "size_bytes", "sha256"}
            or not isinstance(item["path"], str)
            or not item["path"]
            or PurePosixPath(item["path"]).is_absolute()
            or ".." in PurePosixPath(item["path"]).parts
            or not _is_int(item["size_bytes"])
            or item["size_bytes"] < 0
            or not isinstance(item["sha256"], str)
            or HEX_64.fullmatch(item["sha256"]) is None
        ):
            return False
        paths.append(item["path"])
    return paths == sorted(paths) and len(paths) == len(set(paths))


def _identity_valid(payload: Mapping[str, Any]) -> bool:
    identity = payload.get("release_identity_sha256")
    if not isinstance(identity, str) or HEX_64.fullmatch(identity) is None:
        return False
    body = dict(payload)
    body.pop("release_identity_sha256", None)
    return _sha256(_canonical_json(body)) == identity


def _role_builder(policy: BaseReleaseRolePolicy) -> Callable[..., Mapping[str, Any]]:
    builder = getattr(sys.modules[__name__], policy.builder_name, None)
    if not callable(builder):
        raise BaseReleaseSuiteError("BASE_RELEASE_SUITE_ROLE_BUILD_FAILED")
    return builder


def _expected_result_path(value: object, expected: Path) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return Path(value).resolve(strict=False) == expected.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return False


def _validate_role(
    policy: BaseReleaseRolePolicy,
    staging: Path,
    result: object,
    *,
    commit: str,
    tree: str,
) -> dict[str, Any]:
    archive = staging / policy.archive_name
    sidecar = staging / f"{policy.archive_name}.manifest.json"
    if (
        not isinstance(result, Mapping)
        or frozenset(result) != policy.result_keys
        or not _expected_result_path(result.get("archive"), archive)
        or not _expected_result_path(result.get("manifest"), sidecar)
    ):
        raise BaseReleaseSuiteError(
            "BASE_RELEASE_SUITE_ROLE_RESULT_MISMATCH"
        )
    archive_bytes = _stable_read(archive, maximum_bytes=MAX_ARCHIVE_BYTES)
    sidecar_bytes = _stable_read(sidecar, maximum_bytes=MAX_MANIFEST_BYTES)
    if (
        not archive_bytes
        or result.get("archive_sha256") != _sha256(archive_bytes)
    ):
        raise BaseReleaseSuiteError(
            "BASE_RELEASE_SUITE_ROLE_RESULT_MISMATCH"
        )
    manifest = _strict_json(
        sidecar_bytes,
        expected_keys=policy.manifest_keys,
    )
    if (
        manifest.get("schema_version") != policy.manifest_schema
        or manifest.get("release_profile") != policy.release_profile
        or manifest.get("git_commit") != commit
        or manifest.get("git_tree") != tree
        or not _identity_valid(manifest)
        or not _source_files_valid(manifest.get("source_files"))
    ):
        raise BaseReleaseSuiteError("BASE_RELEASE_SUITE_ROLE_MISMATCH")
    expected_safety = {
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "max_lot": 0.01,
        "order_capability": policy.order_capability,
    }
    if (
        manifest.get("safety") != expected_safety
        or (
            policy.production_field_required
            and manifest.get("production_execution_ready") is not False
        )
        or manifest.get("production_execution_ready") is True
    ):
        raise BaseReleaseSuiteError("BASE_RELEASE_SUITE_SAFETY_MISMATCH")
    source_file_count = len(manifest["source_files"])
    if (
        result.get("release_identity_sha256")
        != manifest["release_identity_sha256"]
        or not _is_int(result.get("file_count"))
        or result.get("file_count") != source_file_count
    ):
        raise BaseReleaseSuiteError(
            "BASE_RELEASE_SUITE_ROLE_RESULT_MISMATCH"
        )
    if policy.role == "READ_ONLY_SHADOW":
        if (
            result.get("bundle_class") != "READ_ONLY_SHADOW_SERVICE"
            or result.get("execution_context")
            != "WINDOWS_TASK_SCHEDULER_SERVICE_ACCOUNT"
        ):
            raise BaseReleaseSuiteError(
                "BASE_RELEASE_SUITE_ROLE_RESULT_MISMATCH"
            )
    elif (
        result.get("order_capability") != policy.order_capability
        or result.get("production_execution_ready") is not False
    ):
        raise BaseReleaseSuiteError(
            "BASE_RELEASE_SUITE_ROLE_RESULT_MISMATCH"
        )
    return {
        "role": policy.role,
        "release_profile": policy.release_profile,
        "archive_path": policy.archive_name,
        "archive_size_bytes": len(archive_bytes),
        "archive_sha256": _sha256(archive_bytes),
        "sidecar_path": sidecar.name,
        "sidecar_size_bytes": len(sidecar_bytes),
        "sidecar_sha256": _sha256(sidecar_bytes),
        "release_identity_sha256": manifest[
            "release_identity_sha256"
        ],
        "source_file_count": source_file_count,
        "order_capability": policy.order_capability,
        "production_execution_ready": False,
    }


def _write_exclusive(path: Path, data: bytes) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as exc:
        raise BaseReleaseSuiteError(
            "BASE_RELEASE_SUITE_MANIFEST_INVALID"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _suite_manifest(
    *,
    commit: str,
    tree: str,
    roles: list[dict[str, Any]],
) -> dict[str, Any]:
    base = {
        "schema_version": SUITE_SCHEMA,
        "release_profile": SUITE_PROFILE,
        "git_commit": commit,
        "git_tree": tree,
        "roles": roles,
        "effects": dict(SUITE_EFFECTS),
        "safety": dict(LOCKED_SAFETY),
    }
    return {
        **base,
        "suite_identity_sha256": _sha256(_canonical_json(base)),
    }


def _validate_suite_manifest_bytes(data: bytes) -> dict[str, Any]:
    payload = _strict_json(data, expected_keys=SUITE_MANIFEST_KEYS)
    identity = payload.get("suite_identity_sha256")
    body = dict(payload)
    body.pop("suite_identity_sha256", None)
    roles = payload.get("roles")
    if (
        payload.get("schema_version") != SUITE_SCHEMA
        or payload.get("release_profile") != SUITE_PROFILE
        or not isinstance(payload.get("git_commit"), str)
        or HEX_40.fullmatch(payload["git_commit"]) is None
        or not isinstance(payload.get("git_tree"), str)
        or HEX_40.fullmatch(payload["git_tree"]) is None
        or payload.get("effects") != SUITE_EFFECTS
        or payload.get("safety") != LOCKED_SAFETY
        or not isinstance(identity, str)
        or HEX_64.fullmatch(identity) is None
        or _sha256(_canonical_json(body)) != identity
        or not isinstance(roles, list)
        or len(roles) != len(ROLE_POLICIES)
    ):
        raise BaseReleaseSuiteError(
            "BASE_RELEASE_SUITE_MANIFEST_INVALID"
        )
    for policy, record in zip(ROLE_POLICIES, roles):
        if (
            not isinstance(record, dict)
            or frozenset(record) != ROLE_RECORD_KEYS
            or record.get("role") != policy.role
            or record.get("release_profile") != policy.release_profile
            or record.get("archive_path") != policy.archive_name
            or record.get("sidecar_path")
            != f"{policy.archive_name}.manifest.json"
            or record.get("order_capability") != policy.order_capability
            or record.get("production_execution_ready") is not False
        ):
            raise BaseReleaseSuiteError(
                "BASE_RELEASE_SUITE_MANIFEST_INVALID"
            )
        for name in ("archive_sha256", "sidecar_sha256", "release_identity_sha256"):
            if (
                not isinstance(record.get(name), str)
                or HEX_64.fullmatch(record[name]) is None
            ):
                raise BaseReleaseSuiteError(
                    "BASE_RELEASE_SUITE_MANIFEST_INVALID"
                )
        for name in (
            "archive_size_bytes",
            "sidecar_size_bytes",
            "source_file_count",
        ):
            if not _is_int(record.get(name)) or record[name] <= 0:
                raise BaseReleaseSuiteError(
                    "BASE_RELEASE_SUITE_MANIFEST_INVALID"
                )
    return payload


def _revalidate_staged_role_bytes(
    staging: Path,
    roles: list[dict[str, Any]],
) -> None:
    for policy, record in zip(ROLE_POLICIES, roles):
        archive = _stable_read(
            staging / policy.archive_name,
            maximum_bytes=MAX_ARCHIVE_BYTES,
        )
        sidecar = _stable_read(
            staging / f"{policy.archive_name}.manifest.json",
            maximum_bytes=MAX_MANIFEST_BYTES,
        )
        if (
            len(archive) != record["archive_size_bytes"]
            or _sha256(archive) != record["archive_sha256"]
            or len(sidecar) != record["sidecar_size_bytes"]
            or _sha256(sidecar) != record["sidecar_sha256"]
        ):
            raise BaseReleaseSuiteError(
                "BASE_RELEASE_SUITE_ROLE_RESULT_MISMATCH"
            )


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        getattr(left, name) == getattr(right, name)
        for name in ("st_dev", "st_ino", "st_mode")
    )


def _rename_no_replace(source: Path, destination: Path) -> None:
    if os.name == "nt":
        os.rename(source, destination)
        return

    library = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    result: int
    if sys.platform == "darwin":
        rename_exclusive = getattr(library, "renamex_np", None)
        if rename_exclusive is None:
            raise OSError(
                errno.ENOTSUP,
                "atomic no-replace rename is unavailable",
            )
        rename_exclusive.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename_exclusive.restype = ctypes.c_int
        result = rename_exclusive(
            source_bytes,
            destination_bytes,
            0x00000004,
        )
    elif sys.platform.startswith("linux"):
        rename_exclusive = getattr(library, "renameat2", None)
        if rename_exclusive is None:
            raise OSError(
                errno.ENOTSUP,
                "atomic no-replace rename is unavailable",
            )
        rename_exclusive.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename_exclusive.restype = ctypes.c_int
        result = rename_exclusive(
            -100,
            source_bytes,
            -100,
            destination_bytes,
            1,
        )
    else:
        raise OSError(
            errno.ENOTSUP,
            "atomic no-replace rename is unavailable",
        )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(
            error_number,
            os.strerror(error_number),
            str(destination),
        )


def _atomic_publish(staging: Path, destination: Path) -> None:
    lock = destination.parent / f".{destination.name}.publish.lock"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            lock,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        if os.path.lexists(destination):
            raise FileExistsError(str(destination))
        _rename_no_replace(staging, destination)
    except OSError as exc:
        raise BaseReleaseSuiteError(
            "BASE_RELEASE_SUITE_PUBLICATION_FAILED"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            lock.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _cleanup_staging(staging: Path | None, parent: Path, prefix: str) -> None:
    if staging is None:
        return
    try:
        if (
            staging.parent != parent
            or not staging.name.startswith(prefix)
            or not os.path.lexists(staging)
        ):
            return
        if staging.is_symlink():
            staging.unlink()
        else:
            shutil.rmtree(staging)
    except OSError:
        pass


def build_base_release_suite(
    repo_root: Path,
    output_root: Path,
) -> dict[str, object]:
    output, parent_state = _validate_destination(repo_root, output_root)
    try:
        repository = repo_root.resolve(strict=True)
        commit, tree = _clean_source_state(repository)
    except BaseReleaseSuiteError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise BaseReleaseSuiteError(
            "BASE_RELEASE_SUITE_SOURCE_NOT_CLEAN"
        ) from exc

    prefix = f".{output.name}.staging-"
    staging: Path | None = None
    try:
        try:
            staging = Path(
                tempfile.mkdtemp(prefix=prefix, dir=output.parent)
            ).resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as exc:
            raise BaseReleaseSuiteError(
                "BASE_RELEASE_SUITE_DESTINATION_INVALID"
            ) from exc
        if staging.parent != output.parent or staging.is_symlink():
            raise BaseReleaseSuiteError(
                "BASE_RELEASE_SUITE_DESTINATION_INVALID"
            )

        role_records: list[dict[str, Any]] = []
        for policy in ROLE_POLICIES:
            archive = staging / policy.archive_name
            sidecar = staging / f"{policy.archive_name}.manifest.json"
            try:
                result = _role_builder(policy)(
                    repository,
                    repository / policy.allowlist_relative,
                    archive,
                    manifest_output_path=sidecar,
                )
            except BaseReleaseSuiteError:
                raise
            except Exception as exc:
                raise BaseReleaseSuiteError(
                    "BASE_RELEASE_SUITE_ROLE_BUILD_FAILED"
                ) from exc
            role_records.append(
                _validate_role(
                    policy,
                    staging,
                    result,
                    commit=commit,
                    tree=tree,
                )
            )

        expected_before_manifest = {
            name
            for policy in ROLE_POLICIES
            for name in (
                policy.archive_name,
                f"{policy.archive_name}.manifest.json",
            )
        }
        if {item.name for item in staging.iterdir()} != expected_before_manifest:
            raise BaseReleaseSuiteError(
                "BASE_RELEASE_SUITE_ROLE_RESULT_MISMATCH"
            )

        manifest = _suite_manifest(
            commit=commit,
            tree=tree,
            roles=role_records,
        )
        manifest_path = staging / SUITE_MANIFEST_NAME
        _write_exclusive(
            manifest_path,
            _canonical_json(manifest) + b"\n",
        )
        manifest_bytes = _stable_read(
            manifest_path,
            maximum_bytes=MAX_MANIFEST_BYTES,
        )
        verified_manifest = _validate_suite_manifest_bytes(manifest_bytes)
        if verified_manifest != manifest:
            raise BaseReleaseSuiteError(
                "BASE_RELEASE_SUITE_MANIFEST_INVALID"
            )
        _revalidate_staged_role_bytes(staging, role_records)

        try:
            final_commit, final_tree = _clean_source_state(repository)
        except BaseReleaseSuiteError as exc:
            raise BaseReleaseSuiteError(
                "BASE_RELEASE_SUITE_SOURCE_CHANGED"
            ) from exc
        if (final_commit, final_tree) != (commit, tree):
            raise BaseReleaseSuiteError(
                "BASE_RELEASE_SUITE_SOURCE_CHANGED"
            )
        try:
            final_parent_state = output.parent.stat(follow_symlinks=False)
        except OSError as exc:
            raise BaseReleaseSuiteError(
                "BASE_RELEASE_SUITE_PUBLICATION_FAILED"
            ) from exc
        if (
            not _same_stat(parent_state, final_parent_state)
            or output.parent.is_symlink()
            or _is_junction(output.parent)
        ):
            raise BaseReleaseSuiteError(
                "BASE_RELEASE_SUITE_PUBLICATION_FAILED"
            )
        _atomic_publish(staging, output)
        staging = None
        return {
            "output_root": str(output),
            "manifest_path": str(output / SUITE_MANIFEST_NAME),
            "suite_identity_sha256": manifest[
                "suite_identity_sha256"
            ],
            "git_commit": commit,
            "git_tree": tree,
            "roles": role_records,
        }
    finally:
        _cleanup_staging(staging, output.parent, prefix)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build one atomic same-commit five-role Windows base-release suite"
        )
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        required=True,
        help="New suite directory outside the repository",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = build_base_release_suite(REPO_ROOT, args.output_root)
    except BaseReleaseSuiteError as exc:
        print(f"BASE_RELEASE_SUITE_REJECTED: {exc}")
        return 2
    print("WINDOWS_ATOMIC_BASE_RELEASE_SUITE_READY")
    print(f"Output root: {result['output_root']}")
    print(f"Manifest: {result['manifest_path']}")
    print(f"Suite identity SHA-256: {result['suite_identity_sha256']}")
    print(f"Git commit: {result['git_commit']}")
    print(f"Git tree: {result['git_tree']}")
    for role in result["roles"]:
        print(
            f"{role['role']}: {role['archive_sha256']} "
            f"({role['archive_path']})"
        )
    print("Order capability: DISABLED_AT_SUITE_BOUNDARY")
    print("Production execution ready: false")
    print("Provider import: NOT_PERFORMED")
    print("Credential access: NOT_PERFORMED")
    print("Task installation: NOT_PERFORMED")
    print("Git subprocess: PERFORMED_PACKAGING_ONLY")
    print("Runtime/service process launch: NOT_PERFORMED")
    print("MT5 initialization: NOT_PERFORMED")
    print("Broker mutation: NOT_PERFORMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
