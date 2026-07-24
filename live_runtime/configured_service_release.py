"""Deterministic, secret-free configured Windows service release assembly.

The base decision, execution, and status-monitor releases intentionally
exclude deployment-specific factory and provider files. This module binds a
reviewed overlay into a new release inventory and identity without importing
the factory, resolving a credential, installing a task, initializing MT5, or
performing broker work.
"""

from __future__ import annotations

import ast
from dataclasses import InitVar, dataclass
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Mapping
import unicodedata
import zipfile


MANIFEST_MEMBER = "RELEASE_MANIFEST.json"
CONFIGURED_OVERLAY_SCHEMA = "windows-configured-service-overlay-v1"
CONFIGURED_BINDING_SCHEMA = "windows-configured-service-release-binding-v1"
VERIFICATION_REPORT_SCHEMA = "windows-configured-service-verification-v1"
FACTORY_MANIFEST_SCHEMA = "windows-service-factory-manifest-v1"
FACTORY_CONTEXT_SCHEMA = "windows-service-factory-context-v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 512
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)

EXECUTION_PROFILE = "WINDOWS_GATED_EXECUTION_SERVICE_V1"
DECISION_PROFILE = "WINDOWS_DECISION_SERVICE_V1"
MONITOR_PROFILE = "WINDOWS_EXTERNAL_STATUS_MONITOR_V1"
_PROFILE_POLICY = {
    EXECUTION_PROFILE: {
        "manifest_schema": "ai-scalper-windows-execution-service-manifest-v1",
        "order_capability": "GATED_PRESENT",
    },
    DECISION_PROFILE: {
        "manifest_schema": "ai-scalper-windows-decision-service-manifest-v1",
        "order_capability": "DISABLED",
    },
    MONITOR_PROFILE: {
        "manifest_schema": "ai-scalper-windows-status-monitor-manifest-v1",
        "order_capability": "DISABLED",
    },
}

_DESCRIPTOR_FIELDS = frozenset(
    {
        "base_release_identity_sha256",
        "base_release_profile",
        "factory_manifest_relative_path",
        "factory_source_relative_path",
        "files",
        "overlay_id",
        "provider_source_relative_paths",
        "reviewed_factory_template_sha256",
        "runtime_mode",
        "safety",
        "schema_version",
        "service_config_relative_path",
        "task_definition_sha256",
    }
)
_DESCRIPTOR_FILE_FIELDS = frozenset({"path", "sha256", "size_bytes"})
_DESCRIPTOR_SAFETY = {
    "credential_values_embedded": False,
    "live_allowed": False,
    "max_lot": 0.01,
    "provider_materialization_during_build": False,
    "safe_to_demo_auto_order": False,
    "task_installation_during_build": False,
}
_FACTORY_MANIFEST_FIELDS = frozenset(
    {
        "bootstrap_binding_sha256",
        "factory_attribute",
        "factory_contract_sha256",
        "factory_file_sha256",
        "factory_module",
        "factory_relative_path",
        "release_profile",
        "schema_version",
        "service_config_file_sha256",
        "service_config_relative_path",
    }
)
_SOURCE_ENTRY_FIELDS = frozenset({"path", "sha256", "size_bytes"})
_MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bgh[oprsu]_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
)
_SENSITIVE_JSON_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "client_secret",
        "login",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "token",
    }
)
_FORBIDDEN_IMPORTS = frozenset(
    {
        "MetaTrader5",
        "ctypes",
        "importlib",
        "multiprocessing",
        "runpy",
        "subprocess",
    }
)
_FORBIDDEN_DYNAMIC_CALLS = frozenset(
    {
        "__import__",
        "compile",
        "eval",
        "exec",
    }
)
_FORBIDDEN_ORDER_MEMBERS = frozenset({"order_check", "order_send"})
_FORBIDDEN_OS_PROCESS_MEMBERS = frozenset(
    {
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "fork",
        "posix_spawn",
        "posix_spawnp",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "startfile",
        "system",
    }
)
_FORBIDDEN_NATIVE_LOADER_MEMBERS = frozenset(
    {"CDLL", "LibraryLoader", "OleDLL", "PyDLL", "WinDLL", "cdll", "oledll", "pydll", "windll"}
)
_FORBIDDEN_SUFFIXES = frozenset(
    {
        ".dll",
        ".dylib",
        ".exe",
        ".key",
        ".p12",
        ".pem",
        ".pfx",
        ".pyc",
        ".pyd",
        ".so",
    }
)
_WINDOWS_RESERVED_STEMS = frozenset(
    {
        "aux",
        "clock$",
        "com1",
        "com2",
        "com3",
        "com4",
        "com5",
        "com6",
        "com7",
        "com8",
        "com9",
        "con",
        "lpt1",
        "lpt2",
        "lpt3",
        "lpt4",
        "lpt5",
        "lpt6",
        "lpt7",
        "lpt8",
        "lpt9",
        "nul",
        "prn",
    }
)
_READINESS_BLOCKERS = (
    "CONFIGURED_RELEASE_EXTERNAL_ACCEPTANCE_REQUIRED",
    "EXTERNAL_LAUNCHER_ATTESTATION_REQUIRED",
    "EXTERNAL_PROVIDER_RUNTIME_ATTESTATION_REQUIRED",
    "EXTERNAL_TASK_INSTALLATION_AND_ACL_ATTESTATION_REQUIRED",
)
_REPORT_SEAL = object()


class ConfiguredReleaseError(RuntimeError):
    """One configured-release input failed closed with a stable reason code."""

    def __init__(self, reason_code: str) -> None:
        normalized = str(reason_code or "").strip().upper()
        self.reason_code = normalized or "CONFIGURED_RELEASE_INVALID"
        super().__init__(self.reason_code)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
        raise ConfiguredReleaseError("CANONICAL_JSON_INVALID") from exc


def _canonical_file(value: object) -> bytes:
    return _canonical_bytes(value) + b"\n"


def _require_nonzero_hash(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or _HASH_RE.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise ConfiguredReleaseError(code)
    return value


def _require_id(value: object, code: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise ConfiguredReleaseError(code)
    return value


def _reject_json_constant(_value: str) -> object:
    raise ConfiguredReleaseError("JSON_NONFINITE_VALUE")


def _strict_json(
    data: bytes,
    *,
    kind: str,
    canonical: bool,
) -> dict[str, Any]:
    if not isinstance(data, bytes) or len(data) > MAX_DOCUMENT_BYTES:
        raise ConfiguredReleaseError(f"{kind}_TOO_LARGE")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfiguredReleaseError(f"{kind}_JSON_INVALID") from exc

    def exact_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ConfiguredReleaseError(f"{kind}_DUPLICATE_KEY")
            result[key] = value
        return result

    try:
        payload = json.loads(
            text,
            object_pairs_hook=exact_object,
            parse_constant=_reject_json_constant,
        )
    except ConfiguredReleaseError:
        raise
    except (TypeError, json.JSONDecodeError) as exc:
        raise ConfiguredReleaseError(f"{kind}_JSON_INVALID") from exc
    if not isinstance(payload, dict):
        raise ConfiguredReleaseError(f"{kind}_SCHEMA_INVALID")
    if canonical and data != _canonical_file(payload):
        raise ConfiguredReleaseError(f"{kind}_NOT_CANONICAL")
    return payload


def _normalize_path(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
    ):
        raise ConfiguredReleaseError(code)
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or unicodedata.normalize("NFC", value) != value
    ):
        raise ConfiguredReleaseError(code)
    for part in path.parts:
        if (
            any(ord(character) < 32 or character in '<>:"|?*' for character in part)
            or part.endswith((" ", "."))
            or part.split(".", 1)[0].casefold() in _WINDOWS_RESERVED_STEMS
        ):
            raise ConfiguredReleaseError(code)
    if path.suffix.casefold() in _FORBIDDEN_SUFFIXES:
        raise ConfiguredReleaseError(code)
    return path.as_posix()


def _overlay_path(value: object) -> str:
    path = _normalize_path(value, "OVERLAY_PATH_INVALID")
    suffix = PurePosixPath(path).suffix.casefold()
    if suffix not in {".json", ".py"}:
        raise ConfiguredReleaseError("OVERLAY_PATH_INVALID")
    if suffix == ".json" and PurePosixPath(path).parts[0] != "config":
        raise ConfiguredReleaseError("OVERLAY_JSON_PATH_INVALID")
    return path


def _safe_json_value(value: object, path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if str(key).casefold() in _SENSITIVE_JSON_KEYS:
                allowed_empty_value = (
                    child is None
                    or child is False
                    or (
                        isinstance(child, str)
                        and child in {"", "NOT_STORED", "REDACTED"}
                    )
                )
                if not allowed_empty_value:
                    raise ConfiguredReleaseError("OVERLAY_SECRET_JSON_VALUE")
            _safe_json_value(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _safe_json_value(child, f"{path}[{index}]")
    elif isinstance(value, float) and not math.isfinite(value):
        raise ConfiguredReleaseError("OVERLAY_JSON_NONFINITE_VALUE")


def _module_name(path: str) -> tuple[str, bool] | None:
    parsed = PurePosixPath(path)
    if parsed.suffix != ".py":
        return None
    parts = list(parsed.with_suffix("").parts)
    is_package = bool(parts and parts[-1] == "__init__")
    if is_package:
        parts.pop()
    if not parts or any(_MODULE_RE.fullmatch(part) is None for part in parts):
        return None
    return ".".join(parts), is_package


def _local_module_inventory(paths: set[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(paths):
        module = _module_name(path)
        if module is None:
            continue
        name, _is_package = module
        if name:
            result[name] = path
    return result


def _resolve_local_import(module: str, inventory: Mapping[str, str]) -> str | None:
    current = module
    while current:
        if current in inventory:
            return inventory[current]
        current = current.rpartition(".")[0]
    return None


def _relative_module(
    current_module: str,
    is_package: bool,
    level: int,
    imported: str | None,
) -> str:
    package = (
        current_module.split(".")
        if is_package
        else current_module.split(".")[:-1]
    )
    upward = level - 1
    if upward > len(package):
        raise ConfiguredReleaseError("OVERLAY_IMPORT_CLOSURE_INVALID")
    parts = package[: len(package) - upward]
    if imported:
        parts.extend(imported.split("."))
    return ".".join(parts)


def _validate_python_sources(
    overlay: Mapping[str, bytes],
    *,
    combined_paths: set[str],
) -> None:
    inventory = _local_module_inventory(combined_paths)
    local_tops = {name.split(".", 1)[0] for name in inventory}
    for path, data in overlay.items():
        if not path.endswith(".py"):
            continue
        for pattern in _SECRET_PATTERNS:
            if pattern.search(data):
                raise ConfiguredReleaseError("OVERLAY_SECRET_PATTERN")
        try:
            tree = ast.parse(data.decode("utf-8"), filename=path)
        except (UnicodeDecodeError, SyntaxError) as exc:
            raise ConfiguredReleaseError("OVERLAY_PYTHON_INVALID") from exc
        module_info = _module_name(path)
        if module_info is None:
            raise ConfiguredReleaseError("OVERLAY_MODULE_PATH_INVALID")
        current_module, is_package = module_info
        os_module_aliases: set[str] = set()
        os_process_aliases: set[str] = set()
        for node in ast.walk(tree):
            imported_modules: list[str] = []
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.append(alias.name)
                    if alias.name == "os":
                        os_module_aliases.add(alias.asname or "os")
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    base = _relative_module(
                        current_module,
                        is_package,
                        node.level,
                        node.module,
                    )
                else:
                    base = node.module or ""
                if base:
                    imported_modules.append(base)
                if node.level == 0 and node.module == "os":
                    for alias in node.names:
                        if alias.name in _FORBIDDEN_OS_PROCESS_MEMBERS:
                            os_process_aliases.add(
                                alias.asname or alias.name
                            )
            for imported in imported_modules:
                top = imported.split(".", 1)[0]
                if imported in _FORBIDDEN_IMPORTS or top in _FORBIDDEN_IMPORTS:
                    raise ConfiguredReleaseError("OVERLAY_IMPORT_FORBIDDEN")
                if top in local_tops and _resolve_local_import(
                    imported, inventory
                ) is None:
                    raise ConfiguredReleaseError("OVERLAY_IMPORT_CLOSURE_INVALID")
            if isinstance(node, ast.Attribute):
                if node.attr in _FORBIDDEN_ORDER_MEMBERS:
                    raise ConfiguredReleaseError(
                        "OVERLAY_ORDER_PRIMITIVE_FORBIDDEN"
                    )
                if node.attr in _FORBIDDEN_NATIVE_LOADER_MEMBERS:
                    raise ConfiguredReleaseError(
                        "OVERLAY_NATIVE_LOADER_FORBIDDEN"
                    )
            if isinstance(node, ast.Call):
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id in _FORBIDDEN_DYNAMIC_CALLS
                ):
                    raise ConfiguredReleaseError("OVERLAY_DYNAMIC_CODE_FORBIDDEN")
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id in os_process_aliases
                ):
                    raise ConfiguredReleaseError(
                        "OVERLAY_PROCESS_LAUNCH_FORBIDDEN"
                    )
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in os_module_aliases
                    and node.func.attr in _FORBIDDEN_OS_PROCESS_MEMBERS
                ):
                    raise ConfiguredReleaseError(
                        "OVERLAY_PROCESS_LAUNCH_FORBIDDEN"
                    )


def _read_stable_file(
    path: Path,
    *,
    code: str,
    max_bytes: int = MAX_FILE_BYTES,
) -> bytes:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or int(getattr(before, "st_file_attributes", 0)) & 0x400
            or before.st_size > max_bytes
        ):
            raise ConfiguredReleaseError(code)
        with path.open("rb") as handle:
            opened_before = os.fstat(handle.fileno())
            data = handle.read(max_bytes + 1)
            opened_after = os.fstat(handle.fileno())
        after = path.lstat()
    except ConfiguredReleaseError:
        raise
    except OSError as exc:
        raise ConfiguredReleaseError(code) from exc
    identity = lambda item: (
        int(item.st_dev),
        int(item.st_ino),
        int(item.st_mode),
        int(item.st_size),
        int(item.st_mtime_ns),
        int(getattr(item, "st_file_attributes", 0)),
    )
    if (
        len(data) > max_bytes
        or identity(before) != identity(opened_before)
        or identity(before) != identity(opened_after)
        or identity(before) != identity(after)
        or len(data) != before.st_size
    ):
        raise ConfiguredReleaseError(code)
    return data


def _source_entries(
    payload: object,
    *,
    code: str,
    overlay_paths: bool,
) -> list[dict[str, object]]:
    if not isinstance(payload, list) or not payload:
        raise ConfiguredReleaseError(code)
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    seen_folded: set[str] = set()
    for item in payload:
        if not isinstance(item, Mapping) or set(item) != _SOURCE_ENTRY_FIELDS:
            raise ConfiguredReleaseError(code)
        path = (
            _overlay_path(item.get("path"))
            if overlay_paths
            else _normalize_path(item.get("path"), code)
        )
        size = item.get("size_bytes")
        digest = _require_nonzero_hash(item.get("sha256"), code)
        if (
            path in seen
            or path.casefold() in seen_folded
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= MAX_FILE_BYTES
        ):
            raise ConfiguredReleaseError(code)
        seen.add(path)
        seen_folded.add(path.casefold())
        result.append({"path": path, "size_bytes": size, "sha256": digest})
    if [item["path"] for item in result] != sorted(seen):
        raise ConfiguredReleaseError(code)
    return result


def _archive_members(source: bytes | str | Path, *, kind: str) -> tuple[bytes, dict[str, bytes]]:
    if isinstance(source, bytes):
        archive_bytes = source
    elif isinstance(source, (str, Path)):
        archive_bytes = _read_stable_file(
            Path(source),
            code=f"{kind}_ARCHIVE_INVALID",
            max_bytes=MAX_TOTAL_BYTES,
        )
    else:
        raise TypeError("archive source must be bytes or a path")
    members: dict[str, bytes] = {}
    folded: set[str] = set()
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_ARCHIVE_MEMBERS:
                raise ConfiguredReleaseError(f"{kind}_ARCHIVE_INVALID")
            for info in infos:
                path = _normalize_path(info.filename, f"{kind}_ARCHIVE_MEMBER_INVALID")
                if path in members:
                    raise ConfiguredReleaseError(
                        f"{kind}_ARCHIVE_DUPLICATE_MEMBER"
                    )
                if path.casefold() in folded:
                    raise ConfiguredReleaseError(
                        f"{kind}_ARCHIVE_CASE_COLLISION"
                    )
                if (
                    info.is_dir()
                    or info.flag_bits & 0x1
                    or info.compress_type != zipfile.ZIP_DEFLATED
                    or info.file_size > MAX_FILE_BYTES
                ):
                    raise ConfiguredReleaseError(
                        f"{kind}_ARCHIVE_MEMBER_INVALID"
                    )
                mode = (info.external_attr >> 16) & 0xFFFF
                if mode and not stat.S_ISREG(mode):
                    raise ConfiguredReleaseError(
                        f"{kind}_ARCHIVE_MEMBER_INVALID"
                    )
                data = archive.read(info)
                if len(data) != info.file_size:
                    raise ConfiguredReleaseError(
                        f"{kind}_ARCHIVE_MEMBER_INVALID"
                    )
                total += len(data)
                if total > MAX_TOTAL_BYTES:
                    raise ConfiguredReleaseError(f"{kind}_ARCHIVE_TOO_LARGE")
                members[path] = data
                folded.add(path.casefold())
    except ConfiguredReleaseError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise ConfiguredReleaseError(f"{kind}_ARCHIVE_INVALID") from exc
    return archive_bytes, members


def _expected_safety(profile: str) -> dict[str, object]:
    policy = _PROFILE_POLICY.get(profile)
    if policy is None:
        raise ConfiguredReleaseError("BASE_PROFILE_UNSUPPORTED")
    return {
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "max_lot": 0.01,
        "order_capability": policy["order_capability"],
    }


def _validate_base_manifest(
    manifest: Mapping[str, object],
    members: Mapping[str, bytes],
    *,
    require_exact_file_set: bool,
) -> dict[str, Any]:
    if not isinstance(manifest, Mapping):
        raise ConfiguredReleaseError("BASE_MANIFEST_SCHEMA_INVALID")
    profile = manifest.get("release_profile")
    if not isinstance(profile, str) or profile not in _PROFILE_POLICY:
        raise ConfiguredReleaseError("BASE_PROFILE_UNSUPPORTED")
    if manifest.get("schema_version") != _PROFILE_POLICY[profile]["manifest_schema"]:
        raise ConfiguredReleaseError("BASE_MANIFEST_SCHEMA_INVALID")
    if manifest.get("safety") != _expected_safety(profile):
        raise ConfiguredReleaseError("BASE_SAFETY_LOCK_DRIFT")
    if manifest.get("production_execution_ready") is not False:
        raise ConfiguredReleaseError("BASE_READINESS_LOCK_DRIFT")
    readiness_blockers = manifest.get("readiness_blockers")
    if (
        not isinstance(readiness_blockers, list)
        or not readiness_blockers
        or any(
            not isinstance(item, str) or not item
            for item in readiness_blockers
        )
        or len(readiness_blockers) != len(set(readiness_blockers))
    ):
        raise ConfiguredReleaseError("BASE_READINESS_BLOCKERS_INVALID")
    if "configured_release" in manifest:
        raise ConfiguredReleaseError("CONFIGURED_RELEASE_NESTING_FORBIDDEN")
    identity = _require_nonzero_hash(
        manifest.get("release_identity_sha256"),
        "BASE_IDENTITY_INVALID",
    )
    unsigned = dict(manifest)
    unsigned.pop("release_identity_sha256", None)
    if _sha256(_canonical_bytes(unsigned)) != identity:
        raise ConfiguredReleaseError("BASE_IDENTITY_INVALID")
    source_entries = _source_entries(
        manifest.get("source_files"),
        code="BASE_SOURCE_INVENTORY_INVALID",
        overlay_paths=False,
    )
    expected_paths = {item["path"] for item in source_entries}
    observed_paths = set(members)
    if require_exact_file_set:
        if observed_paths != expected_paths | {MANIFEST_MEMBER}:
            raise ConfiguredReleaseError("BASE_ARCHIVE_FILE_SET_MISMATCH")
    elif not expected_paths.issubset(observed_paths):
        raise ConfiguredReleaseError("BASE_ARCHIVE_FILE_SET_MISMATCH")
    for item in source_entries:
        data = members[item["path"]]
        if len(data) != item["size_bytes"] or _sha256(data) != item["sha256"]:
            raise ConfiguredReleaseError("BASE_SOURCE_HASH_MISMATCH")
    return dict(manifest)


def _load_base_release(
    source: bytes | str | Path,
) -> tuple[bytes, dict[str, Any], dict[str, bytes]]:
    archive_bytes, members = _archive_members(source, kind="BASE")
    manifest_data = members.get(MANIFEST_MEMBER)
    if manifest_data is None:
        raise ConfiguredReleaseError("BASE_MANIFEST_MISSING")
    manifest = _strict_json(
        manifest_data,
        kind="BASE_MANIFEST",
        canonical=True,
    )
    validated = _validate_base_manifest(
        manifest,
        members,
        require_exact_file_set=True,
    )
    sources = {
        path: data for path, data in members.items() if path != MANIFEST_MEMBER
    }
    if archive_bytes != _create_archive(
        sources,
        _canonical_file(validated),
    ):
        raise ConfiguredReleaseError("BASE_ARCHIVE_NONDETERMINISTIC")
    return (
        archive_bytes,
        validated,
        sources,
    )


def _validate_descriptor(payload: Mapping[str, object]) -> dict[str, Any]:
    if not isinstance(payload, Mapping) or set(payload) != _DESCRIPTOR_FIELDS:
        raise ConfiguredReleaseError("DESCRIPTOR_SCHEMA_INVALID")
    if payload.get("schema_version") != CONFIGURED_OVERLAY_SCHEMA:
        raise ConfiguredReleaseError("DESCRIPTOR_SCHEMA_INVALID")
    profile = payload.get("base_release_profile")
    if not isinstance(profile, str) or profile not in _PROFILE_POLICY:
        raise ConfiguredReleaseError("DESCRIPTOR_PROFILE_INVALID")
    identity = _require_nonzero_hash(
        payload.get("base_release_identity_sha256"),
        "DESCRIPTOR_BASE_IDENTITY_INVALID",
    )
    runtime_mode = payload.get("runtime_mode")
    if runtime_mode not in {"DEMO", "DEMO_AUTO"}:
        raise ConfiguredReleaseError("DESCRIPTOR_RUNTIME_MODE_INVALID")
    overlay_id = _require_id(payload.get("overlay_id"), "DESCRIPTOR_ID_INVALID")
    if payload.get("safety") != _DESCRIPTOR_SAFETY:
        raise ConfiguredReleaseError("DESCRIPTOR_SAFETY_LOCK_DRIFT")
    factory_manifest_path = _overlay_path(
        payload.get("factory_manifest_relative_path")
    )
    factory_source_path = _overlay_path(
        payload.get("factory_source_relative_path")
    )
    service_config_path = _overlay_path(
        payload.get("service_config_relative_path")
    )
    if (
        PurePosixPath(factory_source_path).parent.as_posix() != "."
        or PurePosixPath(factory_source_path).suffix != ".py"
        or _MODULE_RE.fullmatch(PurePosixPath(factory_source_path).stem) is None
    ):
        raise ConfiguredReleaseError("DESCRIPTOR_FACTORY_PATH_INVALID")
    if (
        PurePosixPath(factory_manifest_path).parts[0] != "config"
        or PurePosixPath(service_config_path).parts[0] != "config"
        or PurePosixPath(factory_manifest_path).suffix != ".json"
        or PurePosixPath(service_config_path).suffix != ".json"
    ):
        raise ConfiguredReleaseError("DESCRIPTOR_CONFIG_PATH_INVALID")
    raw_providers = payload.get("provider_source_relative_paths")
    if not isinstance(raw_providers, list) or not raw_providers:
        raise ConfiguredReleaseError("DESCRIPTOR_PROVIDER_PATH_INVALID")
    providers = [_overlay_path(value) for value in raw_providers]
    if (
        providers != sorted(providers)
        or len(providers) != len(set(providers))
        or len({item.casefold() for item in providers}) != len(providers)
        or any(
            PurePosixPath(item).parts[0] != "configured_providers"
            or PurePosixPath(item).suffix != ".py"
            for item in providers
        )
        or "configured_providers/__init__.py" not in providers
    ):
        raise ConfiguredReleaseError("DESCRIPTOR_PROVIDER_PATH_INVALID")
    files = _source_entries(
        payload.get("files"),
        code="DESCRIPTOR_FILE_INVENTORY_INVALID",
        overlay_paths=True,
    )
    expected = {
        factory_manifest_path,
        factory_source_path,
        service_config_path,
        *providers,
    }
    if {item["path"] for item in files} != expected:
        raise ConfiguredReleaseError("DESCRIPTOR_FILE_INVENTORY_INVALID")
    return {
        **dict(payload),
        "overlay_id": overlay_id,
        "base_release_profile": profile,
        "base_release_identity_sha256": identity,
        "runtime_mode": runtime_mode,
        "factory_manifest_relative_path": factory_manifest_path,
        "factory_source_relative_path": factory_source_path,
        "service_config_relative_path": service_config_path,
        "provider_source_relative_paths": providers,
        "reviewed_factory_template_sha256": _require_nonzero_hash(
            payload.get("reviewed_factory_template_sha256"),
            "DESCRIPTOR_FACTORY_TEMPLATE_HASH_INVALID",
        ),
        "task_definition_sha256": _require_nonzero_hash(
            payload.get("task_definition_sha256"),
            "DESCRIPTOR_TASK_HASH_INVALID",
        ),
        "files": files,
    }


def _read_overlay(
    root: Path,
    descriptor: Mapping[str, object],
) -> dict[str, bytes]:
    try:
        root_meta = root.lstat()
        if (
            not stat.S_ISDIR(root_meta.st_mode)
            or stat.S_ISLNK(root_meta.st_mode)
            or int(getattr(root_meta, "st_file_attributes", 0)) & 0x400
        ):
            raise ConfiguredReleaseError("OVERLAY_ROOT_INVALID")
        resolved_root = root.resolve(strict=True)
    except ConfiguredReleaseError:
        raise
    except OSError as exc:
        raise ConfiguredReleaseError("OVERLAY_ROOT_INVALID") from exc
    expected = {item["path"]: item for item in descriptor["files"]}
    observed: dict[str, bytes] = {}
    observed_folded: set[str] = set()
    total = 0
    try:
        paths = sorted(resolved_root.rglob("*"))
    except OSError as exc:
        raise ConfiguredReleaseError("OVERLAY_FILE_SET_MISMATCH") from exc
    for path in paths:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ConfiguredReleaseError("OVERLAY_FILE_NOT_REGULAR") from exc
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_ISLNK(metadata.st_mode) or int(
                getattr(metadata, "st_file_attributes", 0)
            ) & 0x400:
                raise ConfiguredReleaseError("OVERLAY_FILE_NOT_REGULAR")
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or int(getattr(metadata, "st_file_attributes", 0)) & 0x400
        ):
            raise ConfiguredReleaseError("OVERLAY_FILE_NOT_REGULAR")
        try:
            relative = path.resolve(strict=True).relative_to(resolved_root).as_posix()
        except (OSError, ValueError) as exc:
            raise ConfiguredReleaseError("OVERLAY_FILE_NOT_REGULAR") from exc
        relative = _overlay_path(relative)
        if relative.casefold() in observed_folded:
            raise ConfiguredReleaseError("OVERLAY_FILE_CASE_COLLISION")
        data = _read_stable_file(path, code="OVERLAY_FILE_NOT_REGULAR")
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ConfiguredReleaseError("OVERLAY_TOTAL_SIZE_EXCEEDED")
        observed[relative] = data
        observed_folded.add(relative.casefold())
    if set(observed) != set(expected):
        raise ConfiguredReleaseError("OVERLAY_FILE_SET_MISMATCH")
    for path, item in expected.items():
        data = observed[path]
        if len(data) != item["size_bytes"] or _sha256(data) != item["sha256"]:
            raise ConfiguredReleaseError("OVERLAY_FILE_HASH_MISMATCH")
        for pattern in _SECRET_PATTERNS:
            if pattern.search(data):
                raise ConfiguredReleaseError("OVERLAY_SECRET_PATTERN")
        if path.endswith(".json"):
            parsed = _strict_json(data, kind="OVERLAY", canonical=True)
            _safe_json_value(parsed)
    return observed


def _factory_contract_hash(manifest: Mapping[str, object]) -> str:
    return _sha256(
        _canonical_bytes(
            {
                "release_profile": manifest["release_profile"],
                "factory_module": manifest["factory_module"],
                "factory_attribute": manifest["factory_attribute"],
                "factory_relative_path": manifest["factory_relative_path"],
                "factory_file_sha256": manifest["factory_file_sha256"],
                "service_config_relative_path": manifest[
                    "service_config_relative_path"
                ],
                "service_config_file_sha256": manifest[
                    "service_config_file_sha256"
                ],
                "bootstrap_binding_sha256": manifest[
                    "bootstrap_binding_sha256"
                ],
                "schema_version": FACTORY_CONTEXT_SCHEMA,
            }
        )
    )


def _validate_factory_manifest(
    data: bytes,
    *,
    descriptor: Mapping[str, object],
    overlay: Mapping[str, bytes],
) -> dict[str, Any]:
    manifest = _strict_json(data, kind="FACTORY_MANIFEST", canonical=True)
    if set(manifest) != _FACTORY_MANIFEST_FIELDS:
        raise ConfiguredReleaseError("FACTORY_MANIFEST_INVALID")
    if (
        manifest.get("schema_version") != FACTORY_MANIFEST_SCHEMA
        or manifest.get("release_profile") != descriptor["base_release_profile"]
        or manifest.get("factory_relative_path")
        != descriptor["factory_source_relative_path"]
        or manifest.get("service_config_relative_path")
        != descriptor["service_config_relative_path"]
    ):
        raise ConfiguredReleaseError("FACTORY_MANIFEST_INVALID")
    factory_module = manifest.get("factory_module")
    factory_attribute = manifest.get("factory_attribute")
    if (
        not isinstance(factory_module, str)
        or _MODULE_RE.fullmatch(factory_module) is None
        or not isinstance(factory_attribute, str)
        or _MODULE_RE.fullmatch(factory_attribute) is None
        or PurePosixPath(str(manifest["factory_relative_path"])).stem
        != factory_module
    ):
        raise ConfiguredReleaseError("FACTORY_MANIFEST_INVALID")
    for field in (
        "factory_file_sha256",
        "service_config_file_sha256",
        "bootstrap_binding_sha256",
        "factory_contract_sha256",
    ):
        _require_nonzero_hash(manifest.get(field), "FACTORY_MANIFEST_INVALID")
    factory_data = overlay[descriptor["factory_source_relative_path"]]
    config_data = overlay[descriptor["service_config_relative_path"]]
    if (
        _sha256(factory_data) != manifest["factory_file_sha256"]
        or _sha256(config_data) != manifest["service_config_file_sha256"]
        or _factory_contract_hash(manifest) != manifest["factory_contract_sha256"]
    ):
        raise ConfiguredReleaseError("FACTORY_MANIFEST_INVALID")
    return manifest


def _zip_member(path: str, data: bytes) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(path, FIXED_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info, data


def _create_archive(sources: Mapping[str, bytes], manifest: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for path in sorted(sources):
            archive.writestr(*_zip_member(path, sources[path]))
        archive.writestr(*_zip_member(MANIFEST_MEMBER, manifest))
    return output.getvalue()


def _write_exclusive(path: Path, data: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise ConfiguredReleaseError("OUTPUT_ALREADY_EXISTS_OR_UNAVAILABLE") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _combined_source_entries(sources: Mapping[str, bytes]) -> list[dict[str, object]]:
    return [
        {"path": path, "size_bytes": len(data), "sha256": _sha256(data)}
        for path, data in sorted(sources.items())
    ]


def _overlay_set_hash(descriptor: Mapping[str, object]) -> str:
    return _sha256(_canonical_bytes(descriptor["files"]))


def build_configured_service_release(
    base_archive: str | Path,
    overlay_root: str | Path,
    descriptor_path: str | Path,
    output_path: str | Path,
    *,
    manifest_output_path: str | Path | None = None,
) -> dict[str, Any]:
    """Build one deterministic configured release without materialization."""

    base_bytes, base_manifest, base_sources = _load_base_release(base_archive)
    descriptor_bytes = _read_stable_file(
        Path(descriptor_path),
        code="DESCRIPTOR_UNAVAILABLE",
    )
    descriptor_payload = _strict_json(
        descriptor_bytes,
        kind="DESCRIPTOR",
        canonical=True,
    )
    descriptor = _validate_descriptor(descriptor_payload)
    if descriptor["base_release_profile"] != base_manifest["release_profile"]:
        raise ConfiguredReleaseError("BASE_PROFILE_MISMATCH")
    if (
        descriptor["base_release_identity_sha256"]
        != base_manifest["release_identity_sha256"]
    ):
        raise ConfiguredReleaseError("BASE_IDENTITY_MISMATCH")
    overlay = _read_overlay(Path(overlay_root), descriptor)
    base_folded = {path.casefold() for path in base_sources}
    if any(path.casefold() in base_folded for path in overlay):
        raise ConfiguredReleaseError("OVERLAY_BASE_PATH_COLLISION")
    _validate_python_sources(
        overlay,
        combined_paths=set(base_sources) | set(overlay),
    )
    factory_manifest = _validate_factory_manifest(
        overlay[descriptor["factory_manifest_relative_path"]],
        descriptor=descriptor,
        overlay=overlay,
    )
    configured_binding = {
        "schema_version": CONFIGURED_BINDING_SCHEMA,
        "overlay_id": descriptor["overlay_id"],
        "runtime_mode": descriptor["runtime_mode"],
        "base_release_profile": base_manifest["release_profile"],
        "base_release_identity_sha256": base_manifest[
            "release_identity_sha256"
        ],
        "base_release_archive_sha256": _sha256(base_bytes),
        "base_release_manifest_sha256": _sha256(
            _canonical_file(base_manifest)
        ),
        "base_release_manifest": base_manifest,
        "overlay_descriptor_sha256": _sha256(descriptor_bytes),
        "overlay_descriptor": descriptor,
        "overlay_file_set_sha256": _overlay_set_hash(descriptor),
        "factory_manifest_relative_path": descriptor[
            "factory_manifest_relative_path"
        ],
        "factory_source_relative_path": descriptor[
            "factory_source_relative_path"
        ],
        "service_config_relative_path": descriptor[
            "service_config_relative_path"
        ],
        "provider_source_relative_paths": descriptor[
            "provider_source_relative_paths"
        ],
        "reviewed_factory_template_sha256": descriptor[
            "reviewed_factory_template_sha256"
        ],
        "task_definition_sha256": descriptor["task_definition_sha256"],
        "factory_contract_sha256": factory_manifest[
            "factory_contract_sha256"
        ],
        "bootstrap_binding_sha256": factory_manifest[
            "bootstrap_binding_sha256"
        ],
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "max_lot": 0.01,
        "provider_materialization_performed": False,
        "credential_access_performed": False,
        "task_installation_performed": False,
        "broker_mutation_performed": False,
    }
    combined = {**base_sources, **overlay}
    unsigned = dict(base_manifest)
    unsigned.pop("release_identity_sha256", None)
    unsigned["source_files"] = _combined_source_entries(combined)
    unsigned["configured_release"] = configured_binding
    unsigned["production_execution_ready"] = False
    inherited_blockers = unsigned.get("readiness_blockers")
    blockers = (
        [item for item in inherited_blockers if isinstance(item, str)]
        if isinstance(inherited_blockers, list)
        else []
    )
    unsigned["readiness_blockers"] = sorted(
        {*blockers, *_READINESS_BLOCKERS}
    )
    identity = _sha256(_canonical_bytes(unsigned))
    manifest = {**unsigned, "release_identity_sha256": identity}
    manifest_bytes = _canonical_file(manifest)
    archive_bytes = _create_archive(combined, manifest_bytes)
    verify_configured_service_release(
        archive_bytes,
        expected_release_identity_sha256=identity,
        expected_base_release_identity_sha256=base_manifest[
            "release_identity_sha256"
        ],
    )
    output = Path(output_path).expanduser().absolute()
    sidecar = (
        output.with_suffix(output.suffix + ".manifest.json")
        if manifest_output_path is None
        else Path(manifest_output_path).expanduser().absolute()
    )
    if output == sidecar:
        raise ConfiguredReleaseError("OUTPUT_PATH_COLLISION")
    _write_exclusive(output, archive_bytes)
    try:
        _write_exclusive(sidecar, manifest_bytes)
    except Exception:
        output.unlink(missing_ok=True)
        raise
    return {
        "archive": str(output),
        "archive_sha256": _sha256(archive_bytes),
        "manifest": str(sidecar),
        "manifest_sha256": _sha256(manifest_bytes),
        "release_profile": base_manifest["release_profile"],
        "base_release_identity_sha256": base_manifest[
            "release_identity_sha256"
        ],
        "release_identity_sha256": identity,
        "file_count": len(combined),
        "order_capability": _expected_safety(
            str(base_manifest["release_profile"])
        )["order_capability"],
        "production_execution_ready": False,
        "provider_materialization_performed": False,
        "credential_access_performed": False,
        "task_installation_performed": False,
        "broker_mutation_performed": False,
    }


@dataclass(frozen=True)
class ConfiguredReleaseVerificationReport:
    configured_release_valid: bool
    release_profile: str
    runtime_mode: str
    base_release_identity_sha256: str
    release_identity_sha256: str
    overlay_descriptor_sha256: str
    factory_contract_sha256: str
    file_count: int
    readiness_blockers: tuple[str, ...]
    production_execution_ready: bool = False
    provider_materialization_performed: bool = False
    credential_access_performed: bool = False
    task_installation_performed: bool = False
    broker_mutation_performed: bool = False
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    max_lot: float = 0.01
    order_capability: str = "DISABLED"
    schema_version: str = VERIFICATION_REPORT_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _REPORT_SEAL:
            raise TypeError("configured release reports require verifier seal")
        if (
            self.configured_release_valid is not True
            or self.production_execution_ready
            or self.provider_materialization_performed
            or self.credential_access_performed
            or self.task_installation_performed
            or self.broker_mutation_performed
            or self.live_allowed
            or self.safe_to_demo_auto_order
            or self.max_lot != 0.01
        ):
            raise ValueError("configured release verification cannot grant authority")
        if self.release_profile not in _PROFILE_POLICY:
            raise ValueError("configured release profile is unsupported")
        if (
            self.order_capability
            != _PROFILE_POLICY[self.release_profile]["order_capability"]
        ):
            raise ValueError("configured release order capability drift")
        if self.schema_version != VERIFICATION_REPORT_SCHEMA:
            raise ValueError("configured release report schema drift")


def verify_configured_service_release(
    archive: bytes | str | Path,
    *,
    expected_release_identity_sha256: str | None = None,
    expected_base_release_identity_sha256: str | None = None,
) -> ConfiguredReleaseVerificationReport:
    """Independently verify one configured archive without importing providers."""

    _archive_bytes, members = _archive_members(archive, kind="CONFIGURED")
    manifest_data = members.get(MANIFEST_MEMBER)
    if manifest_data is None:
        raise ConfiguredReleaseError("CONFIGURED_MANIFEST_MISSING")
    manifest = _strict_json(
        manifest_data,
        kind="CONFIGURED_MANIFEST",
        canonical=True,
    )
    profile = manifest.get("release_profile")
    if not isinstance(profile, str) or profile not in _PROFILE_POLICY:
        raise ConfiguredReleaseError("CONFIGURED_PROFILE_INVALID")
    if manifest.get("schema_version") != _PROFILE_POLICY[profile]["manifest_schema"]:
        raise ConfiguredReleaseError("CONFIGURED_MANIFEST_SCHEMA_INVALID")
    if manifest.get("safety") != _expected_safety(profile):
        raise ConfiguredReleaseError("CONFIGURED_SAFETY_LOCK_DRIFT")
    if manifest.get("production_execution_ready") is not False:
        raise ConfiguredReleaseError("CONFIGURED_READINESS_LOCK_DRIFT")
    identity = _require_nonzero_hash(
        manifest.get("release_identity_sha256"),
        "CONFIGURED_IDENTITY_INVALID",
    )
    unsigned = dict(manifest)
    unsigned.pop("release_identity_sha256", None)
    if _sha256(_canonical_bytes(unsigned)) != identity:
        raise ConfiguredReleaseError("CONFIGURED_IDENTITY_INVALID")
    if expected_release_identity_sha256 is not None and identity != _require_nonzero_hash(
        expected_release_identity_sha256,
        "EXPECTED_CONFIGURED_IDENTITY_INVALID",
    ):
        raise ConfiguredReleaseError("CONFIGURED_IDENTITY_MISMATCH")
    source_entries = _source_entries(
        manifest.get("source_files"),
        code="CONFIGURED_SOURCE_INVENTORY_INVALID",
        overlay_paths=False,
    )
    source_paths = {item["path"] for item in source_entries}
    if set(members) != source_paths | {MANIFEST_MEMBER}:
        raise ConfiguredReleaseError("CONFIGURED_ARCHIVE_FILE_SET_MISMATCH")
    for item in source_entries:
        data = members[item["path"]]
        if len(data) != item["size_bytes"] or _sha256(data) != item["sha256"]:
            raise ConfiguredReleaseError("CONFIGURED_SOURCE_HASH_MISMATCH")
    binding = manifest.get("configured_release")
    if not isinstance(binding, Mapping):
        raise ConfiguredReleaseError("CONFIGURED_BINDING_MISSING")
    if binding.get("schema_version") != CONFIGURED_BINDING_SCHEMA:
        raise ConfiguredReleaseError("CONFIGURED_BINDING_INVALID")
    required_binding_fields = frozenset(
        {
            "base_release_archive_sha256",
            "base_release_identity_sha256",
            "base_release_manifest",
            "base_release_manifest_sha256",
            "base_release_profile",
            "bootstrap_binding_sha256",
            "broker_mutation_performed",
            "credential_access_performed",
            "factory_contract_sha256",
            "factory_manifest_relative_path",
            "factory_source_relative_path",
            "live_allowed",
            "max_lot",
            "overlay_descriptor",
            "overlay_descriptor_sha256",
            "overlay_file_set_sha256",
            "overlay_id",
            "provider_materialization_performed",
            "provider_source_relative_paths",
            "reviewed_factory_template_sha256",
            "runtime_mode",
            "safe_to_demo_auto_order",
            "schema_version",
            "service_config_relative_path",
            "task_definition_sha256",
            "task_installation_performed",
        }
    )
    if set(binding) != required_binding_fields:
        raise ConfiguredReleaseError("CONFIGURED_BINDING_INVALID")
    if (
        binding.get("base_release_profile") != profile
        or binding.get("live_allowed") is not False
        or binding.get("safe_to_demo_auto_order") is not False
        or binding.get("max_lot") != 0.01
        or binding.get("provider_materialization_performed") is not False
        or binding.get("credential_access_performed") is not False
        or binding.get("task_installation_performed") is not False
        or binding.get("broker_mutation_performed") is not False
    ):
        raise ConfiguredReleaseError("CONFIGURED_BINDING_INVALID")
    base_manifest = binding.get("base_release_manifest")
    if not isinstance(base_manifest, Mapping):
        raise ConfiguredReleaseError("CONFIGURED_BASE_MANIFEST_INVALID")
    base_identity = _require_nonzero_hash(
        binding.get("base_release_identity_sha256"),
        "CONFIGURED_BASE_IDENTITY_INVALID",
    )
    if (
        base_manifest.get("release_identity_sha256") != base_identity
        or _sha256(_canonical_file(base_manifest))
        != binding.get("base_release_manifest_sha256")
    ):
        raise ConfiguredReleaseError("CONFIGURED_BASE_MANIFEST_INVALID")
    _validate_base_manifest(
        base_manifest,
        members,
        require_exact_file_set=False,
    )
    base_blockers = base_manifest.get("readiness_blockers")
    if not isinstance(base_blockers, list):
        raise ConfiguredReleaseError("CONFIGURED_BASE_MANIFEST_INVALID")
    expected_blockers = sorted({*base_blockers, *_READINESS_BLOCKERS})
    expected_unsigned = dict(base_manifest)
    expected_unsigned.pop("release_identity_sha256", None)
    expected_unsigned["source_files"] = source_entries
    expected_unsigned["configured_release"] = dict(binding)
    expected_unsigned["production_execution_ready"] = False
    expected_unsigned["readiness_blockers"] = expected_blockers
    if unsigned != expected_unsigned:
        raise ConfiguredReleaseError("CONFIGURED_BASE_INHERITANCE_DRIFT")
    if expected_base_release_identity_sha256 is not None and base_identity != _require_nonzero_hash(
        expected_base_release_identity_sha256,
        "EXPECTED_BASE_IDENTITY_INVALID",
    ):
        raise ConfiguredReleaseError("CONFIGURED_BASE_IDENTITY_MISMATCH")
    base_paths = {
        item["path"]
        for item in _source_entries(
            base_manifest.get("source_files"),
            code="BASE_SOURCE_INVENTORY_INVALID",
            overlay_paths=False,
        )
    }
    base_sources = {path: members[path] for path in base_paths}
    recreated_base = _create_archive(
        base_sources,
        _canonical_file(base_manifest),
    )
    if _sha256(recreated_base) != binding.get("base_release_archive_sha256"):
        raise ConfiguredReleaseError("CONFIGURED_BASE_ARCHIVE_HASH_MISMATCH")
    descriptor_payload = binding.get("overlay_descriptor")
    if not isinstance(descriptor_payload, Mapping):
        raise ConfiguredReleaseError("CONFIGURED_DESCRIPTOR_INVALID")
    descriptor = _validate_descriptor(descriptor_payload)
    descriptor_bytes = _canonical_file(descriptor)
    if (
        _sha256(descriptor_bytes) != binding.get("overlay_descriptor_sha256")
        or _overlay_set_hash(descriptor) != binding.get("overlay_file_set_sha256")
        or descriptor["base_release_profile"] != profile
        or descriptor["base_release_identity_sha256"] != base_identity
    ):
        raise ConfiguredReleaseError("CONFIGURED_DESCRIPTOR_INVALID")
    overlay_paths = {item["path"] for item in descriptor["files"]}
    if base_paths & overlay_paths or source_paths != base_paths | overlay_paths:
        raise ConfiguredReleaseError("CONFIGURED_SOURCE_PARTITION_INVALID")
    overlay = {path: members[path] for path in overlay_paths}
    for item in descriptor["files"]:
        data = overlay[item["path"]]
        if len(data) != item["size_bytes"] or _sha256(data) != item["sha256"]:
            raise ConfiguredReleaseError("CONFIGURED_OVERLAY_HASH_MISMATCH")
        if item["path"].endswith(".json"):
            parsed = _strict_json(data, kind="OVERLAY", canonical=True)
            _safe_json_value(parsed)
    _validate_python_sources(overlay, combined_paths=source_paths)
    factory_manifest = _validate_factory_manifest(
        overlay[descriptor["factory_manifest_relative_path"]],
        descriptor=descriptor,
        overlay=overlay,
    )
    if (
        factory_manifest["factory_contract_sha256"]
        != binding.get("factory_contract_sha256")
        or factory_manifest["bootstrap_binding_sha256"]
        != binding.get("bootstrap_binding_sha256")
        or descriptor["runtime_mode"] != binding.get("runtime_mode")
        or descriptor["overlay_id"] != binding.get("overlay_id")
        or descriptor["reviewed_factory_template_sha256"]
        != binding.get("reviewed_factory_template_sha256")
        or descriptor["task_definition_sha256"]
        != binding.get("task_definition_sha256")
        or descriptor["factory_manifest_relative_path"]
        != binding.get("factory_manifest_relative_path")
        or descriptor["factory_source_relative_path"]
        != binding.get("factory_source_relative_path")
        or descriptor["service_config_relative_path"]
        != binding.get("service_config_relative_path")
        or descriptor["provider_source_relative_paths"]
        != binding.get("provider_source_relative_paths")
    ):
        raise ConfiguredReleaseError("CONFIGURED_BINDING_INVALID")
    return ConfiguredReleaseVerificationReport(
        configured_release_valid=True,
        release_profile=profile,
        runtime_mode=descriptor["runtime_mode"],
        base_release_identity_sha256=base_identity,
        release_identity_sha256=identity,
        overlay_descriptor_sha256=binding["overlay_descriptor_sha256"],
        factory_contract_sha256=binding["factory_contract_sha256"],
        file_count=len(source_paths),
        readiness_blockers=tuple(
            sorted(
                {
                    *(
                        item
                        for item in manifest.get("readiness_blockers", [])
                        if isinstance(item, str)
                    ),
                    *_READINESS_BLOCKERS,
                }
            )
        ),
        order_capability=str(_PROFILE_POLICY[profile]["order_capability"]),
        _seal=_REPORT_SEAL,
    )


__all__ = [
    "CONFIGURED_BINDING_SCHEMA",
    "CONFIGURED_OVERLAY_SCHEMA",
    "ConfiguredReleaseError",
    "ConfiguredReleaseVerificationReport",
    "build_configured_service_release",
    "verify_configured_service_release",
]
