"""Runnable, fail-closed Windows service orchestration for the GATED runtime.

The entrypoint loads one release-local ports factory only after the exact
factory source and non-secret config bytes match a reviewed manifest.  It then
materializes the exact :class:`ProductionRuntimeBootstrap`, emits signed
off-host heartbeats, and runs a bounded supervisor loop.  This module has no
MT5 import and receives no credential or HMAC material from command-line
arguments or JSON files.
"""

from __future__ import annotations

import ast
import builtins
from contextlib import contextmanager
from dataclasses import InitVar, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import importlib.util
import inspect
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import queue
import re
import signal
import stat
import sys
import sysconfig
import threading
import time
from types import FunctionType, ModuleType
from typing import TYPE_CHECKING, Any, Callable, Mapping, Sequence, cast
import uuid

from .contracts import CanonicalContract, canonical_json, require_hash, require_int, require_text, require_utc
from .offhost_delivery import (
    DeliveryAcknowledgement,
    DeliveryEnvelope,
    DeliveryOutbox,
    OffHostDeliverySupervisor,
)
from .production_bootstrap import (
    ProductionBootstrapError,
    ProductionRuntimeBootstrap,
    ProductionRuntimeComposition,
)

if TYPE_CHECKING:
    from .windows_live_canary_execution_provider import (
        WindowsLiveCanaryProviderMaterializationHooks,
    )


UTC = timezone.utc
WINDOWS_SERVICE_FACTORY_MANIFEST_SCHEMA = "windows-service-factory-manifest-v1"
WINDOWS_SERVICE_FACTORY_CONTEXT_SCHEMA = "windows-service-factory-context-v1"
WINDOWS_SERVICE_FACTORY_RESULT_SCHEMA = "windows-service-factory-result-v1"
WINDOWS_SERVICE_STATUS_SCHEMA = "windows-gated-service-status-v1"
EXECUTION_RELEASE_MANIFEST_SCHEMA = "ai-scalper-windows-execution-service-manifest-v1"
EXECUTION_RELEASE_MANIFEST_MEMBER = "RELEASE_MANIFEST.json"
MAX_HEARTBEAT_TTL_SECONDS = 30
SERVICE_DEADLINE_EXIT_CODE = 70
_FACTORY_RESULT_SEAL = object()
_STATUS_SEAL = object()
_EXTERNAL_RUNTIME_CONTEXT_SEAL = object()
_EXTERNAL_RUNTIME_SOURCE_VALIDATION_SEAL = object()
_FACTORY_IMPORT_SCOPE_LOCK = threading.RLock()
_FACTORY_IMPORT_AUDIT_LOCAL = threading.local()
_MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ATTRIBUTE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SERVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SERVICE_CONFIG_FIELDS = frozenset(
    {
        "service_id",
        "owner_id",
        "max_cycles",
        "lease_seconds",
        "heartbeat_ttl_seconds",
        "cycle_interval_seconds",
        "cycle_deadline_seconds",
    }
)
_ALLOWED_PHASES = frozenset(
    {"STARTING", "INITIALIZED", "RUNNING", "STOPPING", "STOPPED", "FAILED"}
)
WINDOWS_LIVE_EXTERNAL_RUNTIME_CONTEXT_SCHEMA = (
    "windows-live-canary-external-runtime-context-v1"
)
WINDOWS_LIVE_EXTERNAL_RUNTIME_SOURCE_VALIDATION_SCHEMA = (
    "windows-live-canary-external-runtime-source-validation-v1"
)
MAX_LIVE_RUNTIME_PROVIDER_BYTES = 4 * 1024 * 1024
LIVE_RUNTIME_PROVIDER_BUILDER = "build_live_canary_materialization_hooks"
_LIVE_RUNTIME_HOOKS_TYPE_NAME = (
    "WindowsLiveCanaryProviderMaterializationHooks"
)
_LIVE_RUNTIME_HOOK_FIELDS = frozenset(
    {
        "clock_attestation_reader",
        "credential_backend_factory",
        "mt5_importer",
        "network_sender",
        "provider_state_reader",
        "runtime_source_reader",
        "sqlite_opener",
    }
)
_LIVE_RUNTIME_ORDER_PRIMITIVE_RE = re.compile(
    r"^order_(?:check|send)$",
    flags=re.IGNORECASE,
)
_LIVE_RUNTIME_DYNAMIC_ATTRIBUTES = frozenset(
    {
        "find_spec",
        "import_module",
        "module_from_spec",
        "reload",
        "spec_from_file_location",
        "spec_from_loader",
    }
)
_LIVE_RUNTIME_DYNAMIC_NAMES = frozenset(
    {
        "__import__",
        "compile",
        "delattr",
        "eval",
        "exec",
        "getattr",
        "setattr",
        "vars",
    }
)
_LIVE_RUNTIME_PROCESS_ATTRIBUTES = frozenset(
    {
        "Popen",
        "create_subprocess_exec",
        "create_subprocess_shell",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "posix_spawn",
        "posix_spawnp",
        "popen",
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


class WindowsServiceError(RuntimeError):
    """Fail-closed Windows service composition or lifecycle error."""


def _hard_terminate_process(exit_code: int) -> None:
    """Terminate every Python thread after a cycle boundary is lost."""

    os._exit(exit_code)


def _now() -> datetime:
    return datetime.now(UTC)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _key_fingerprint(value: str | bytes) -> str:
    if isinstance(value, str):
        material = value.encode("utf-8")
    elif isinstance(value, bytes):
        material = value
    else:
        raise WindowsServiceError("SERVICE_KEY_PROVIDER_FAILED")
    if len(material) < 32:
        raise WindowsServiceError("SERVICE_KEY_MATERIAL_TOO_SHORT")
    return _sha256_bytes(material)


def _validate_service_config(value: object) -> dict[str, Any]:
    """Accept only the exact non-secret operational schedule schema."""

    if not isinstance(value, Mapping) or set(value) != _SERVICE_CONFIG_FIELDS:
        raise WindowsServiceError("SERVICE_CONFIG_SCHEMA_INVALID")
    config = dict(value)
    for name in ("service_id", "owner_id"):
        item = config.get(name)
        if not isinstance(item, str) or _SERVICE_ID_RE.fullmatch(item) is None:
            raise WindowsServiceError("SERVICE_CONFIG_ID_INVALID")
    try:
        require_int("max_cycles", config["max_cycles"], minimum=1, maximum=100_000)
        require_int("lease_seconds", config["lease_seconds"], minimum=1, maximum=300)
        heartbeat_ttl = require_int(
            "heartbeat_ttl_seconds",
            config["heartbeat_ttl_seconds"],
            minimum=2,
            maximum=MAX_HEARTBEAT_TTL_SECONDS,
        )
    except (TypeError, ValueError) as exc:
        raise WindowsServiceError("SERVICE_CONFIG_INTEGER_INVALID") from exc
    interval_value = config["cycle_interval_seconds"]
    if isinstance(interval_value, bool) or not isinstance(interval_value, (int, float)):
        raise WindowsServiceError("SERVICE_CYCLE_INTERVAL_INVALID")
    interval = float(interval_value)
    if not 0.25 <= interval <= min(15.0, heartbeat_ttl / 2.0):
        raise WindowsServiceError("SERVICE_CYCLE_INTERVAL_INVALID")
    deadline_value = config["cycle_deadline_seconds"]
    if isinstance(deadline_value, bool) or not isinstance(deadline_value, (int, float)):
        raise WindowsServiceError("SERVICE_CYCLE_DEADLINE_INVALID")
    deadline = float(deadline_value)
    if not 1.0 <= deadline <= heartbeat_ttl:
        raise WindowsServiceError("SERVICE_CYCLE_DEADLINE_INVALID")
    config["cycle_interval_seconds"] = interval
    config["cycle_deadline_seconds"] = deadline
    return config


def _canonical_release_manifest(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value), ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _verify_execution_release_manifest(
    *,
    root: Path,
    expected_release_identity_sha256: str,
) -> tuple[Mapping[str, Any], Mapping[str, Mapping[str, Any]]]:
    """Verify the independently pinned deterministic execution release."""

    expected_identity = require_hash(
        "expected_release_identity_sha256", expected_release_identity_sha256
    )
    manifest_file = _require_release_file(
        root, EXECUTION_RELEASE_MANIFEST_MEMBER, suffix=".json"
    )
    try:
        manifest = json.loads(
            _read_release_bytes(manifest_file, label="RELEASE_MANIFEST").decode(
                "utf-8"
            )
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WindowsServiceError("SERVICE_RELEASE_MANIFEST_INVALID") from exc
    if not isinstance(manifest, Mapping):
        raise WindowsServiceError("SERVICE_RELEASE_MANIFEST_INVALID")
    identity = manifest.get("release_identity_sha256")
    if (
        manifest.get("schema_version") != EXECUTION_RELEASE_MANIFEST_SCHEMA
        or identity != expected_identity
    ):
        raise WindowsServiceError("SERVICE_RELEASE_IDENTITY_MISMATCH")
    unsigned = dict(manifest)
    unsigned.pop("release_identity_sha256", None)
    if _sha256_bytes(_canonical_release_manifest(unsigned)) != expected_identity:
        raise WindowsServiceError("SERVICE_RELEASE_MANIFEST_HASH_INVALID")
    safety = manifest.get("safety")
    if safety != {
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "max_lot": 0.01,
        "order_capability": "GATED_PRESENT",
    }:
        raise WindowsServiceError("SERVICE_RELEASE_SAFETY_LOCK_DRIFT")
    raw_files = manifest.get("source_files")
    if not isinstance(raw_files, list) or not raw_files:
        raise WindowsServiceError("SERVICE_RELEASE_INVENTORY_INVALID")
    inventory: dict[str, Mapping[str, Any]] = {}
    casefolded_inventory: set[str] = set()
    for item in raw_files:
        if not isinstance(item, Mapping) or set(item) != {
            "path",
            "size_bytes",
            "sha256",
        }:
            raise WindowsServiceError("SERVICE_RELEASE_INVENTORY_INVALID")
        relative = item.get("path")
        size = item.get("size_bytes")
        digest = item.get("sha256")
        normalized_relative = (
            PurePosixPath(relative).as_posix()
            if isinstance(relative, str)
            else None
        )
        if (
            not isinstance(relative, str)
            or not relative
            or "\\" in relative
            or normalized_relative != relative
            or relative in inventory
            or relative.casefold() in casefolded_inventory
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
        ):
            raise WindowsServiceError("SERVICE_RELEASE_INVENTORY_INVALID")
        try:
            checked_digest = require_hash("release member sha256", digest)
            member = _require_release_file(
                root, relative, suffix=Path(relative).suffix
            )
            payload = _read_release_bytes(member, label="RELEASE_MEMBER")
        except (TypeError, ValueError) as exc:
            raise WindowsServiceError("SERVICE_RELEASE_INVENTORY_INVALID") from exc
        if len(payload) != size or _sha256_bytes(payload) != checked_digest:
            raise WindowsServiceError("SERVICE_RELEASE_MEMBER_HASH_MISMATCH")
        inventory[relative] = dict(item)
        casefolded_inventory.add(relative.casefold())
    _verify_exact_release_root(
        root,
        expected_members={*inventory, EXECUTION_RELEASE_MANIFEST_MEMBER},
    )
    return dict(manifest), inventory


def _verify_exact_release_root(root: Path, *, expected_members: set[str]) -> None:
    """Reject every extracted member that is not in the pinned inventory."""

    normalized = {PurePosixPath(item).as_posix() for item in expected_members}
    expected_casefold = {item.casefold() for item in normalized}
    if len(expected_casefold) != len(normalized):
        raise WindowsServiceError("SERVICE_RELEASE_INVENTORY_INVALID")
    expected_directories: set[str] = set()
    for item in normalized:
        parent = PurePosixPath(item).parent
        while parent.as_posix() not in {"", "."}:
            expected_directories.add(parent.as_posix().casefold())
            parent = parent.parent

    observed: set[str] = set()
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for directory in tuple(directories):
            candidate = current_path / directory
            _reject_path_indirection(candidate)
            relative = candidate.relative_to(root).as_posix()
            if relative.casefold() not in expected_directories:
                raise WindowsServiceError("SERVICE_RELEASE_EXTRA_MEMBER")
        for filename in files:
            candidate = current_path / filename
            _reject_path_indirection(candidate)
            try:
                metadata = candidate.stat(follow_symlinks=False)
            except OSError as exc:
                raise WindowsServiceError("SERVICE_RELEASE_PATH_UNAVAILABLE") from exc
            if not stat.S_ISREG(metadata.st_mode):
                raise WindowsServiceError("SERVICE_RELEASE_FILE_NOT_REGULAR")
            relative = candidate.relative_to(root).as_posix()
            folded = relative.casefold()
            if folded not in expected_casefold or folded in observed:
                raise WindowsServiceError("SERVICE_RELEASE_EXTRA_MEMBER")
            observed.add(folded)
    if observed != expected_casefold:
        raise WindowsServiceError("SERVICE_RELEASE_INVENTORY_INVALID")


def _reject_path_indirection(path: Path) -> None:
    """Reject symlink/junction/reparse indirection in every configured component."""

    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise WindowsServiceError("SERVICE_RELEASE_PATH_UNAVAILABLE") from exc
        if stat.S_ISLNK(metadata.st_mode) or int(
            getattr(metadata, "st_file_attributes", 0)
        ) & 0x400:
            raise WindowsServiceError("SERVICE_RELEASE_PATH_INDIRECTION_DENIED")


def _require_release_root(value: str | Path) -> Path:
    configured = Path(value).expanduser().absolute()
    _reject_path_indirection(configured)
    try:
        metadata = configured.stat(follow_symlinks=False)
        resolved = configured.resolve(strict=True)
    except OSError as exc:
        raise WindowsServiceError("SERVICE_RELEASE_ROOT_UNAVAILABLE") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise WindowsServiceError("SERVICE_RELEASE_ROOT_NOT_DIRECTORY")
    return resolved


def _require_release_file(root: Path, relative: str, *, suffix: str) -> Path:
    normalized = require_text("release relative path", relative)
    candidate = Path(normalized)
    if candidate.is_absolute() or ".." in candidate.parts or candidate.suffix != suffix:
        raise WindowsServiceError("SERVICE_RELEASE_PATH_INVALID")
    configured = root / candidate
    _reject_path_indirection(configured)
    try:
        resolved = configured.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
        metadata = resolved.stat(follow_symlinks=False)
    except (OSError, ValueError) as exc:
        raise WindowsServiceError("SERVICE_RELEASE_FILE_UNAVAILABLE") from exc
    if not stat.S_ISREG(metadata.st_mode) or int(
        getattr(metadata, "st_file_attributes", 0)
    ) & 0x400:
        raise WindowsServiceError("SERVICE_RELEASE_FILE_NOT_REGULAR")
    return resolved


def _read_release_bytes(path: Path, *, label: str) -> bytes:
    """Read a reviewed file only while its inode and path remain stable."""

    _reject_path_indirection(path)
    try:
        before = path.stat(follow_symlinks=False)
        payload = path.read_bytes()
        after = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise WindowsServiceError(f"SERVICE_{label}_READ_FAILED") from exc
    identity_before = (
        int(before.st_dev),
        int(before.st_ino),
        int(before.st_size),
        int(before.st_mtime_ns),
    )
    identity_after = (
        int(after.st_dev),
        int(after.st_ino),
        int(after.st_size),
        int(after.st_mtime_ns),
    )
    if identity_before != identity_after or not stat.S_ISREG(after.st_mode):
        raise WindowsServiceError(f"SERVICE_{label}_CHANGED_DURING_READ")
    return payload


@dataclass(frozen=True)
class WindowsServiceFactoryManifest(CanonicalContract):
    release_profile: str
    factory_module: str
    factory_attribute: str
    factory_relative_path: str
    factory_file_sha256: str
    service_config_relative_path: str
    service_config_file_sha256: str
    bootstrap_binding_sha256: str
    factory_contract_sha256: str
    schema_version: str = WINDOWS_SERVICE_FACTORY_MANIFEST_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "release_profile", require_text("release_profile", self.release_profile)
        )
        module = require_text("factory_module", self.factory_module)
        attribute = require_text("factory_attribute", self.factory_attribute)
        if _MODULE_RE.fullmatch(module) is None or _ATTRIBUTE_RE.fullmatch(attribute) is None:
            raise ValueError("factory module/attribute is invalid")
        object.__setattr__(self, "factory_module", module)
        object.__setattr__(self, "factory_attribute", attribute)
        for name in ("factory_relative_path", "service_config_relative_path"):
            value = require_text(name, getattr(self, name))
            if Path(value).is_absolute() or ".." in Path(value).parts:
                raise ValueError(f"{name} must be release-relative")
            object.__setattr__(self, name, value)
        for name in (
            "factory_file_sha256",
            "service_config_file_sha256",
            "bootstrap_binding_sha256",
            "factory_contract_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        expected_contract = canonical_service_factory_contract_sha256(
            release_profile=self.release_profile,
            factory_module=self.factory_module,
            factory_attribute=self.factory_attribute,
            factory_relative_path=self.factory_relative_path,
            factory_file_sha256=self.factory_file_sha256,
            service_config_relative_path=self.service_config_relative_path,
            service_config_file_sha256=self.service_config_file_sha256,
            bootstrap_binding_sha256=self.bootstrap_binding_sha256,
        )
        if self.factory_contract_sha256 != expected_contract:
            raise ValueError("factory_contract_sha256 is invalid")
        if self.schema_version != WINDOWS_SERVICE_FACTORY_MANIFEST_SCHEMA:
            raise ValueError("unsupported Windows service factory manifest schema")


def canonical_service_factory_contract_sha256(
    *,
    release_profile: str,
    factory_module: str,
    factory_attribute: str,
    factory_relative_path: str,
    factory_file_sha256: str,
    service_config_relative_path: str,
    service_config_file_sha256: str,
    bootstrap_binding_sha256: str,
) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "release_profile": release_profile,
                "factory_module": factory_module,
                "factory_attribute": factory_attribute,
                "factory_relative_path": factory_relative_path,
                "factory_file_sha256": factory_file_sha256,
                "service_config_relative_path": service_config_relative_path,
                "service_config_file_sha256": service_config_file_sha256,
                "bootstrap_binding_sha256": bootstrap_binding_sha256,
                "schema_version": WINDOWS_SERVICE_FACTORY_CONTEXT_SCHEMA,
            }
        ).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class WindowsServiceFactoryContext(CanonicalContract):
    release_root_sha256: str
    factory_contract_sha256: str
    factory_file_sha256: str
    service_config_file_sha256: str
    bootstrap_binding_sha256: str
    schema_version: str = WINDOWS_SERVICE_FACTORY_CONTEXT_SCHEMA

    def __post_init__(self) -> None:
        for name in (
            "release_root_sha256",
            "factory_contract_sha256",
            "factory_file_sha256",
            "service_config_file_sha256",
            "bootstrap_binding_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if self.schema_version != WINDOWS_SERVICE_FACTORY_CONTEXT_SCHEMA:
            raise ValueError("unsupported Windows service factory context schema")


@dataclass(frozen=True)
class WindowsLiveRuntimeProviderSourceValidation(CanonicalContract):
    source_sha256: str
    source_size_bytes: int
    builder_name: str
    source_accepted: bool = False
    module_imported: bool = False
    hooks_built: bool = False
    broker_mutation_performed: bool = False
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    order_capability: str = "DISABLED"
    schema_version: str = (
        WINDOWS_LIVE_EXTERNAL_RUNTIME_SOURCE_VALIDATION_SCHEMA
    )
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _EXTERNAL_RUNTIME_SOURCE_VALIDATION_SEAL:
            raise TypeError(
                "external runtime source validation requires validator seal"
            )
        object.__setattr__(
            self,
            "source_sha256",
            require_hash("source_sha256", self.source_sha256),
        )
        require_int(
            "source_size_bytes",
            self.source_size_bytes,
            minimum=1,
            maximum=MAX_LIVE_RUNTIME_PROVIDER_BYTES,
        )
        if self.builder_name != LIVE_RUNTIME_PROVIDER_BUILDER:
            raise ValueError("external runtime builder name is invalid")
        if any(
            value is not False
            for value in (
                self.source_accepted,
                self.module_imported,
                self.hooks_built,
                self.broker_mutation_performed,
                self.live_allowed,
                self.safe_to_demo_auto_order,
            )
        ) or self.order_capability != "DISABLED":
            raise ValueError("external runtime source validation must be deny-only")
        if (
            self.schema_version
            != WINDOWS_LIVE_EXTERNAL_RUNTIME_SOURCE_VALIDATION_SCHEMA
        ):
            raise ValueError("external runtime source schema is unsupported")


@dataclass(frozen=True)
class WindowsLiveCanaryExternalRuntimeContext(CanonicalContract):
    runtime_provider_sha256: str
    release_identity_sha256: str
    release_root_sha256: str
    factory_contract_sha256: str
    factory_file_sha256: str
    service_config_file_sha256: str
    bootstrap_binding_sha256: str
    observed_at_utc: datetime
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    order_capability: str = "DISABLED"
    schema_version: str = WINDOWS_LIVE_EXTERNAL_RUNTIME_CONTEXT_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _EXTERNAL_RUNTIME_CONTEXT_SEAL:
            raise TypeError("external runtime context requires launcher seal")
        for name in (
            "runtime_provider_sha256",
            "release_identity_sha256",
            "release_root_sha256",
            "factory_contract_sha256",
            "factory_file_sha256",
            "service_config_file_sha256",
            "bootstrap_binding_sha256",
        ):
            digest = require_hash(name, getattr(self, name))
            if digest == "0" * 64:
                raise ValueError(f"{name} cannot be the zero hash")
            object.__setattr__(self, name, digest)
        object.__setattr__(
            self,
            "observed_at_utc",
            require_utc("observed_at_utc", self.observed_at_utc),
        )
        if (
            self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or self.order_capability != "DISABLED"
        ):
            raise ValueError("external runtime context cannot grant authority")
        if self.schema_version != WINDOWS_LIVE_EXTERNAL_RUNTIME_CONTEXT_SCHEMA:
            raise ValueError("external runtime context schema is unsupported")


def _literal_runtime_assignment(value: ast.AST | None) -> bool:
    if value is None or isinstance(value, ast.Constant):
        return True
    if isinstance(value, (ast.Tuple, ast.List, ast.Set)):
        return all(_literal_runtime_assignment(item) for item in value.elts)
    if isinstance(value, ast.Dict):
        return all(
            _literal_runtime_assignment(key)
            and _literal_runtime_assignment(item)
            for key, item in zip(value.keys, value.values)
        )
    return False


def _runtime_assignment_targets_are_names(
    targets: Sequence[ast.AST],
) -> bool:
    return bool(targets) and all(isinstance(item, ast.Name) for item in targets)


def _runtime_function_definition_is_declarative(
    node: ast.FunctionDef,
) -> bool:
    arguments = node.args
    annotated_arguments = (
        *arguments.posonlyargs,
        *arguments.args,
        *arguments.kwonlyargs,
    )
    if arguments.vararg is not None:
        annotated_arguments += (arguments.vararg,)
    if arguments.kwarg is not None:
        annotated_arguments += (arguments.kwarg,)
    return (
        not node.decorator_list
        and not node.type_params
        and node.returns is None
        and all(item.annotation is None for item in annotated_arguments)
        and all(
            _literal_runtime_assignment(item)
            for item in arguments.defaults
        )
        and all(
            item is None or _literal_runtime_assignment(item)
            for item in arguments.kw_defaults
        )
    )


def _runtime_class_definition_is_declarative(node: ast.ClassDef) -> bool:
    if (
        node.decorator_list
        or node.keywords
        or node.type_params
        or node.bases
    ):
        return False
    for item in node.body:
        if isinstance(item, ast.Pass):
            continue
        if (
            isinstance(item, ast.Expr)
            and isinstance(item.value, ast.Constant)
            and isinstance(item.value.value, str)
        ):
            continue
        if isinstance(item, ast.FunctionDef):
            if not _runtime_function_definition_is_declarative(item):
                return False
            continue
        if isinstance(item, ast.Assign):
            if not (
                _runtime_assignment_targets_are_names(item.targets)
                and _literal_runtime_assignment(item.value)
            ):
                return False
            continue
        return False
    return True


def _runtime_builder_is_declarative(builder: ast.FunctionDef) -> bool:
    body = list(builder.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body.pop(0)
    if not body or not isinstance(body[-1], ast.Return):
        return False
    definitions: set[str] = set()
    for item in body[:-1]:
        if not isinstance(item, ast.FunctionDef):
            return False
        if (
            item.name == _LIVE_RUNTIME_HOOKS_TYPE_NAME
            or item.name in definitions
            or not _runtime_function_definition_is_declarative(item)
        ):
            return False
        definitions.add(item.name)
    returned = body[-1].value
    if (
        not isinstance(returned, ast.Call)
        or not isinstance(returned.func, ast.Name)
        or returned.func.id != _LIVE_RUNTIME_HOOKS_TYPE_NAME
        or returned.args
        or {item.arg for item in returned.keywords} != _LIVE_RUNTIME_HOOK_FIELDS
        or any(
            item.arg is None or not isinstance(item.value, ast.Name)
            for item in returned.keywords
        )
    ):
        return False
    return True


def validate_windows_live_runtime_provider_source(
    payload: bytes,
    *,
    effect_probe: Callable[[str], object] | None = None,
) -> WindowsLiveRuntimeProviderSourceValidation:
    """Validate exact external provider source without executing any byte."""

    if effect_probe is not None and not callable(effect_probe):
        raise TypeError("effect_probe must be callable or None")
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > MAX_LIVE_RUNTIME_PROVIDER_BYTES
    ):
        raise WindowsServiceError("LIVE_RUNTIME_PROVIDER_SOURCE_INVALID")
    try:
        source = payload.decode("utf-8", errors="strict")
        tree = ast.parse(source, filename="<reviewed-live-runtime-provider>")
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise WindowsServiceError(
            "LIVE_RUNTIME_PROVIDER_SOURCE_INVALID"
        ) from exc

    builder_nodes = [
        item
        for item in tree.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name == LIVE_RUNTIME_PROVIDER_BUILDER
    ]
    if len(builder_nodes) != 1 or isinstance(builder_nodes[0], ast.AsyncFunctionDef):
        raise WindowsServiceError("LIVE_RUNTIME_PROVIDER_BUILDER_INVALID")
    builder = builder_nodes[0]
    arguments = builder.args
    if (
        len(arguments.posonlyargs) + len(arguments.args) != 1
        or arguments.vararg is not None
        or arguments.kwarg is not None
        or arguments.kwonlyargs
        or arguments.defaults
        or arguments.kw_defaults
        or builder.decorator_list
    ):
        raise WindowsServiceError("LIVE_RUNTIME_PROVIDER_BUILDER_INVALID")

    for item in tree.body:
        if isinstance(item, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(item, ast.FunctionDef):
            if not _runtime_function_definition_is_declarative(item):
                raise WindowsServiceError(
                    "LIVE_RUNTIME_PROVIDER_TOP_LEVEL_EFFECT_FORBIDDEN"
                )
            continue
        if isinstance(item, ast.ClassDef):
            if not _runtime_class_definition_is_declarative(item):
                raise WindowsServiceError(
                    "LIVE_RUNTIME_PROVIDER_TOP_LEVEL_EFFECT_FORBIDDEN"
                )
            continue
        if (
            isinstance(item, ast.Assign)
            and _runtime_assignment_targets_are_names(item.targets)
            and _literal_runtime_assignment(item.value)
        ):
            continue
        if (
            isinstance(item, ast.Expr)
            and isinstance(item.value, ast.Constant)
            and isinstance(item.value.value, str)
        ):
            continue
        raise WindowsServiceError(
            "LIVE_RUNTIME_PROVIDER_TOP_LEVEL_EFFECT_FORBIDDEN"
        )

    exact_hooks_imports = 0
    reserved_binding_count = 0
    for item in tree.body:
        if isinstance(item, (ast.Import, ast.ImportFrom)):
            for alias in item.names:
                binding_name = alias.asname or alias.name.split(".", 1)[0]
                if binding_name == _LIVE_RUNTIME_HOOKS_TYPE_NAME:
                    reserved_binding_count += 1
                    if (
                        isinstance(item, ast.ImportFrom)
                        and item.module
                        == "live_runtime.windows_live_canary_execution_provider"
                        and alias.name == _LIVE_RUNTIME_HOOKS_TYPE_NAME
                        and alias.asname is None
                    ):
                        exact_hooks_imports += 1
        if isinstance(item, (ast.FunctionDef, ast.ClassDef)):
            if item.name == _LIVE_RUNTIME_HOOKS_TYPE_NAME:
                reserved_binding_count += 1
        if isinstance(item, ast.Assign):
            reserved_binding_count += sum(
                isinstance(target, ast.Name)
                and target.id == _LIVE_RUNTIME_HOOKS_TYPE_NAME
                for target in item.targets
            )
    if exact_hooks_imports != 1 or reserved_binding_count != 1:
        raise WindowsServiceError("LIVE_RUNTIME_PROVIDER_HOOKS_IMPORT_INVALID")
    if not _runtime_builder_is_declarative(builder):
        raise WindowsServiceError("LIVE_RUNTIME_PROVIDER_BUILDER_INVALID")

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            aliases = node.names
            if any(alias.name == "*" for alias in aliases):
                raise WindowsServiceError(
                    "LIVE_RUNTIME_PROVIDER_IMPORT_FORBIDDEN"
                )
            if isinstance(node, ast.ImportFrom):
                for alias in aliases:
                    if alias.name in _LIVE_RUNTIME_DYNAMIC_NAMES:
                        raise WindowsServiceError(
                            "LIVE_RUNTIME_PROVIDER_DYNAMIC_IMPORT_FORBIDDEN"
                        )
                    if alias.name in _LIVE_RUNTIME_PROCESS_ATTRIBUTES:
                        raise WindowsServiceError(
                            "LIVE_RUNTIME_PROVIDER_PROCESS_EFFECT_FORBIDDEN"
                        )
                    if alias.name in {"__dict__", "modules"}:
                        raise WindowsServiceError(
                            "LIVE_RUNTIME_PROVIDER_MODULE_REGISTRY_FORBIDDEN"
                        )
                    if _LIVE_RUNTIME_ORDER_PRIMITIVE_RE.fullmatch(alias.name):
                        raise WindowsServiceError(
                            "LIVE_RUNTIME_PROVIDER_ORDER_PRIMITIVE_FORBIDDEN"
                        )
            module_names = [
                alias.name for alias in aliases
            ] + ([str(node.module or "")] if isinstance(node, ast.ImportFrom) else [])
            for module_name in module_names:
                root_name = module_name.split(".", 1)[0].casefold()
                if root_name in {
                    "importlib",
                    "multiprocessing",
                    "subprocess",
                    "taskschd",
                    "win32com",
                } or module_name.casefold() == "metatrader5":
                    raise WindowsServiceError(
                        "LIVE_RUNTIME_PROVIDER_IMPORT_FORBIDDEN"
                    )
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value.casefold() == "metatrader5":
                raise WindowsServiceError(
                    "LIVE_RUNTIME_PROVIDER_MT5_REFERENCE_FORBIDDEN"
                )
            if _LIVE_RUNTIME_ORDER_PRIMITIVE_RE.fullmatch(node.value):
                raise WindowsServiceError(
                    "LIVE_RUNTIME_PROVIDER_ORDER_PRIMITIVE_FORBIDDEN"
                )
        if isinstance(node, ast.Name):
            if _LIVE_RUNTIME_ORDER_PRIMITIVE_RE.fullmatch(node.id):
                raise WindowsServiceError(
                    "LIVE_RUNTIME_PROVIDER_ORDER_PRIMITIVE_FORBIDDEN"
                )
        if isinstance(node, ast.Attribute):
            if node.attr in {"__dict__", "modules"}:
                raise WindowsServiceError(
                    "LIVE_RUNTIME_PROVIDER_MODULE_REGISTRY_FORBIDDEN"
                )
            if _LIVE_RUNTIME_ORDER_PRIMITIVE_RE.fullmatch(node.attr):
                raise WindowsServiceError(
                    "LIVE_RUNTIME_PROVIDER_ORDER_PRIMITIVE_FORBIDDEN"
                )
            if node.attr in _LIVE_RUNTIME_DYNAMIC_ATTRIBUTES:
                raise WindowsServiceError(
                    "LIVE_RUNTIME_PROVIDER_DYNAMIC_IMPORT_FORBIDDEN"
                )
            if node.attr in _LIVE_RUNTIME_PROCESS_ATTRIBUTES:
                raise WindowsServiceError(
                    "LIVE_RUNTIME_PROVIDER_PROCESS_EFFECT_FORBIDDEN"
                )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in _LIVE_RUNTIME_DYNAMIC_NAMES:
                raise WindowsServiceError(
                    "LIVE_RUNTIME_PROVIDER_DYNAMIC_EVALUATION_FORBIDDEN"
                )
    return WindowsLiveRuntimeProviderSourceValidation(
        source_sha256=_sha256_bytes(payload),
        source_size_bytes=len(payload),
        builder_name=LIVE_RUNTIME_PROVIDER_BUILDER,
        _seal=_EXTERNAL_RUNTIME_SOURCE_VALIDATION_SEAL,
    )


@dataclass(frozen=True)
class WindowsServiceFactoryResult:
    bootstrap: ProductionRuntimeBootstrap
    factory_contract_sha256: str
    service_config_file_sha256: str
    heartbeat_outbox: DeliveryOutbox
    heartbeat_transport: object
    heartbeat_destination_id: str
    heartbeat_sender_key_id: str
    heartbeat_sender_key_fingerprint_sha256: str
    heartbeat_remote_key_id: str
    heartbeat_remote_key_fingerprint_sha256: str
    heartbeat_sender_key_provider: Callable[[str], str | bytes]
    heartbeat_remote_key_provider: Callable[[str], str | bytes]
    clock_provider: Callable[[], datetime]
    schema_version: str = WINDOWS_SERVICE_FACTORY_RESULT_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _FACTORY_RESULT_SEAL:
            raise TypeError("Windows service factory results require the sealing factory")
        if type(self.bootstrap) is not ProductionRuntimeBootstrap:
            raise TypeError("bootstrap must be exact ProductionRuntimeBootstrap")
        if type(self.heartbeat_outbox) is not DeliveryOutbox:
            raise TypeError("heartbeat_outbox must be exact DeliveryOutbox")
        if not callable(getattr(self.heartbeat_transport, "deliver", None)):
            raise TypeError("heartbeat_transport must expose deliver")
        for name in (
            "heartbeat_sender_key_provider",
            "heartbeat_remote_key_provider",
            "clock_provider",
        ):
            if not callable(getattr(self, name)):
                raise TypeError(f"{name} must be callable")
        for name in (
            "factory_contract_sha256",
            "service_config_file_sha256",
            "heartbeat_sender_key_fingerprint_sha256",
            "heartbeat_remote_key_fingerprint_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        for name in (
            "heartbeat_destination_id",
            "heartbeat_sender_key_id",
            "heartbeat_remote_key_id",
        ):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        if self.schema_version != WINDOWS_SERVICE_FACTORY_RESULT_SCHEMA:
            raise ValueError("unsupported Windows service factory result schema")


def seal_windows_service_factory_result(
    *,
    bootstrap: ProductionRuntimeBootstrap,
    context: WindowsServiceFactoryContext,
    heartbeat_outbox: DeliveryOutbox,
    heartbeat_transport: object,
    heartbeat_destination_id: str,
    heartbeat_sender_key_id: str,
    heartbeat_sender_key_fingerprint_sha256: str,
    heartbeat_remote_key_id: str,
    heartbeat_remote_key_fingerprint_sha256: str,
    heartbeat_sender_key_provider: Callable[[str], str | bytes],
    heartbeat_remote_key_provider: Callable[[str], str | bytes],
    clock_provider: Callable[[], datetime],
) -> WindowsServiceFactoryResult:
    """Seal a reviewed factory result; this performs no broker operation."""

    if bootstrap.config.safe_binding_sha256 != context.bootstrap_binding_sha256:
        raise WindowsServiceError("SERVICE_BOOTSTRAP_BINDING_MISMATCH")
    result = WindowsServiceFactoryResult(
        bootstrap=bootstrap,
        factory_contract_sha256=context.factory_contract_sha256,
        service_config_file_sha256=context.service_config_file_sha256,
        heartbeat_outbox=heartbeat_outbox,
        heartbeat_transport=heartbeat_transport,
        heartbeat_destination_id=heartbeat_destination_id,
        heartbeat_sender_key_id=heartbeat_sender_key_id,
        heartbeat_sender_key_fingerprint_sha256=heartbeat_sender_key_fingerprint_sha256,
        heartbeat_remote_key_id=heartbeat_remote_key_id,
        heartbeat_remote_key_fingerprint_sha256=heartbeat_remote_key_fingerprint_sha256,
        heartbeat_sender_key_provider=heartbeat_sender_key_provider,
        heartbeat_remote_key_provider=heartbeat_remote_key_provider,
        clock_provider=clock_provider,
        _seal=_FACTORY_RESULT_SEAL,
    )
    sender = result.heartbeat_sender_key_provider(result.heartbeat_sender_key_id)
    remote = result.heartbeat_remote_key_provider(result.heartbeat_remote_key_id)
    if (
        _key_fingerprint(sender) != result.heartbeat_sender_key_fingerprint_sha256
        or _key_fingerprint(remote) != result.heartbeat_remote_key_fingerprint_sha256
    ):
        raise WindowsServiceError("SERVICE_HEARTBEAT_KEY_FINGERPRINT_MISMATCH")
    return result


def validate_reviewed_windows_service_factory_manifest(
    *,
    release_root: str | Path,
    manifest_path: str | Path,
    expected_release_identity_sha256: str,
) -> tuple[
    WindowsServiceFactoryManifest,
    Mapping[str, Any],
    WindowsServiceFactoryContext,
]:
    """Perform secret-free, import-free validation of the reviewed bundle.

    This function does not import or invoke the factory and therefore cannot
    resolve credential, signing-key, broker, or heartbeat providers.
    """

    root = _require_release_root(release_root)
    manifest_file = Path(manifest_path).expanduser().absolute()
    _reject_path_indirection(manifest_file)
    try:
        manifest_file.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise WindowsServiceError("SERVICE_FACTORY_MANIFEST_INVALID") from exc
    release_manifest, inventory = _verify_execution_release_manifest(
        root=root,
        expected_release_identity_sha256=expected_release_identity_sha256,
    )
    try:
        raw_manifest = json.loads(
            _read_release_bytes(manifest_file, label="FACTORY_MANIFEST").decode(
                "utf-8"
            )
        )
        manifest = WindowsServiceFactoryManifest(**raw_manifest)
    except WindowsServiceError:
        raise
    except (OSError, UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise WindowsServiceError("SERVICE_FACTORY_MANIFEST_INVALID") from exc
    if Path(manifest.factory_relative_path).name != f"{manifest.factory_module}.py":
        raise WindowsServiceError("SERVICE_FACTORY_MODULE_PATH_MISMATCH")
    if manifest.release_profile != release_manifest.get("release_profile"):
        raise WindowsServiceError("SERVICE_FACTORY_RELEASE_PROFILE_MISMATCH")
    try:
        manifest_relative = manifest_file.resolve(strict=True).relative_to(root).as_posix()
    except (OSError, ValueError) as exc:
        raise WindowsServiceError("SERVICE_FACTORY_MANIFEST_INVALID") from exc
    bound_members = {
        manifest_relative: _sha256_bytes(
            _read_release_bytes(manifest_file, label="FACTORY_MANIFEST")
        ),
        manifest.factory_relative_path: manifest.factory_file_sha256,
        manifest.service_config_relative_path: manifest.service_config_file_sha256,
    }
    for relative, digest in bound_members.items():
        item = inventory.get(relative)
        if not isinstance(item, Mapping) or item.get("sha256") != digest:
            raise WindowsServiceError("SERVICE_FACTORY_MEMBER_NOT_RELEASE_BOUND")
    factory_file = _require_release_file(
        root, manifest.factory_relative_path, suffix=".py"
    )
    config_file = _require_release_file(
        root, manifest.service_config_relative_path, suffix=".json"
    )
    factory_bytes = _read_release_bytes(factory_file, label="FACTORY_SOURCE")
    config_bytes = _read_release_bytes(config_file, label="SERVICE_CONFIG")
    if (
        _sha256_bytes(factory_bytes) != manifest.factory_file_sha256
        or _sha256_bytes(config_bytes) != manifest.service_config_file_sha256
    ):
        raise WindowsServiceError("SERVICE_FACTORY_OR_CONFIG_HASH_MISMATCH")
    try:
        service_config = json.loads(config_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WindowsServiceError("SERVICE_CONFIG_JSON_INVALID") from exc
    service_config = _validate_service_config(service_config)
    context = WindowsServiceFactoryContext(
        release_root_sha256=_sha256_bytes(str(root).encode("utf-8")),
        factory_contract_sha256=manifest.factory_contract_sha256,
        factory_file_sha256=manifest.factory_file_sha256,
        service_config_file_sha256=manifest.service_config_file_sha256,
        bootstrap_binding_sha256=manifest.bootstrap_binding_sha256,
    )
    return manifest, dict(service_config), context


def _load_exact_factory_module(
    *,
    manifest: WindowsServiceFactoryManifest,
    factory_file: Path,
    release_root: Path,
    inventory: Mapping[str, Mapping[str, Any]],
) -> ModuleType:
    """Load the reviewed top-level module from its exact file, without import lookup."""

    module_name = manifest.factory_module
    spec = importlib.util.spec_from_file_location(module_name, factory_file)
    if (
        spec is None
        or spec.loader is None
        or spec.origin is None
        or Path(spec.origin).resolve(strict=True) != factory_file
    ):
        raise WindowsServiceError("SERVICE_FACTORY_MODULE_SPEC_INVALID")
    factory_namespace = importlib.util.module_from_spec(spec)
    original_sys_path = list(sys.path)
    original_dont_write_bytecode = sys.dont_write_bytecode
    stdlib_roots = {
        Path(value).resolve(strict=True)
        for key in ("stdlib", "platstdlib")
        if (value := sysconfig.get_path(key))
    }
    sanitized_path = [str(release_root)]
    for item in original_sys_path:
        if not item:
            continue
        try:
            resolved = Path(item).resolve(strict=True)
        except OSError:
            continue
        if any(_is_relative_to(resolved, root) for root in stdlib_roots):
            if not {part.casefold() for part in resolved.parts}.intersection(
                {"site-packages", "dist-packages"}
            ):
                sanitized_path.append(str(resolved))
    try:
        sys.dont_write_bytecode = True
        sys.path[:] = list(dict.fromkeys(sanitized_path))
        with _reviewed_import_scope(
            release_root=release_root,
            inventory=inventory,
        ):
            spec.loader.exec_module(factory_namespace)
    except WindowsServiceError:
        raise
    except Exception as exc:
        raise WindowsServiceError("SERVICE_FACTORY_MODULE_LOAD_FAILED") from exc
    finally:
        sys.path[:] = original_sys_path
        sys.dont_write_bytecode = original_dont_write_bytecode
    if (
        type(factory_namespace) is not ModuleType
        or factory_namespace.__name__ != module_name
    ):
        raise WindowsServiceError("SERVICE_FACTORY_MODULE_INVALID")
    referenced_modules = {
        value
        for value in factory_namespace.__dict__.values()
        if type(value) is ModuleType
    }
    _verify_imported_module_origins(
        release_root=release_root,
        inventory=inventory,
        modules=referenced_modules,
    )
    return factory_namespace


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _reviewed_factory_sys_path(root: Path, current: list[str]) -> list[str]:
    """Return release + stdlib paths, excluding cwd and site-package lookup."""

    stdlib_roots = {
        Path(value).resolve(strict=True)
        for key in ("stdlib", "platstdlib")
        if (value := sysconfig.get_path(key))
    }
    reviewed = [str(root)]
    for item in current:
        if not item:
            continue
        try:
            resolved = Path(item).resolve(strict=True)
        except OSError:
            continue
        folded_parts = {part.casefold() for part in resolved.parts}
        if folded_parts.intersection({"site-packages", "dist-packages"}):
            continue
        if any(_is_relative_to(resolved, base) for base in stdlib_roots):
            reviewed.append(str(resolved))
    return list(dict.fromkeys(reviewed))


def _snapshot_module_registry() -> dict[str, tuple[int, bool]]:
    """Capture identity/type only; never expose cached modules to the factory."""

    return {
        name: (id(value), type(value) is ModuleType)
        for name, value in tuple(sys.modules.items())
        if isinstance(name, str)
    }


def _record_factory_import_modules(modules: set[ModuleType]) -> None:
    """Bind even previously captured import wrappers to the active audit scope."""

    stack = getattr(_FACTORY_IMPORT_AUDIT_LOCAL, "stack", None)
    if not isinstance(stack, list) or not stack:
        raise WindowsServiceError("SERVICE_FACTORY_IMPORT_SCOPE_INACTIVE")
    stack[-1].update(modules)


def _verify_module_registry_delta(
    *,
    before: Mapping[str, tuple[int, bool]],
    release_root: Path,
    inventory: Mapping[str, Mapping[str, Any]],
) -> None:
    """Reject replacement/removal and attest every newly cached module."""

    current = {
        name: value
        for name, value in tuple(sys.modules.items())
        if isinstance(name, str)
    }
    if any(name not in current for name in before):
        raise WindowsServiceError("SERVICE_FACTORY_MODULE_REGISTRY_MUTATED")
    added: set[ModuleType] = set()
    for name, value in current.items():
        previous = before.get(name)
        if previous is not None:
            if previous != (id(value), type(value) is ModuleType):
                raise WindowsServiceError("SERVICE_FACTORY_MODULE_REGISTRY_MUTATED")
            continue
        if type(value) is not ModuleType:
            raise WindowsServiceError("SERVICE_FACTORY_MODULE_REGISTRY_INVALID")
        added.add(value)
    _verify_imported_module_origins(
        release_root=release_root,
        inventory=inventory,
        modules=added,
    )


def _factory_dynamic_loader_denied(*_args: object, **_kwargs: object) -> object:
    raise WindowsServiceError("SERVICE_FACTORY_DYNAMIC_LOADER_DENIED")


@contextmanager
def _reviewed_import_scope(
    *,
    release_root: Path,
    inventory: Mapping[str, Mapping[str, Any]],
):
    """Reject unreviewed imports, including modules already in ``sys.modules``.

    Restricting ``sys.path`` is insufficient because Python consults its module
    cache first.  The reviewed factory may import inside the factory function,
    so guard both module execution and invocation and attest every module the
    import machinery returns to the caller.
    """

    original_import = builtins.__import__
    original_importlib_import = importlib.__import__
    original_import_module = importlib.import_module
    original_reload = importlib.reload
    guarded_util_names = (
        "find_spec",
        "module_from_spec",
        "spec_from_file_location",
        "spec_from_loader",
    )
    original_util = {
        name: getattr(importlib.util, name)
        for name in guarded_util_names
    }
    registry_before = _snapshot_module_registry()
    tracked_modules: set[ModuleType] = set()

    def attest(modules: set[ModuleType]) -> None:
        _verify_imported_module_origins(
            release_root=release_root,
            inventory=inventory,
            modules=modules,
        )
        _record_factory_import_modules(modules)

    def reviewed_import(
        name: str,
        globals_: Mapping[str, Any] | None = None,
        locals_: Mapping[str, Any] | None = None,
        fromlist: tuple[str, ...] | list[str] = (),
        level: int = 0,
    ) -> object:
        imported = original_import(name, globals_, locals_, fromlist, level)
        modules: set[ModuleType] = set()
        if type(imported) is ModuleType:
            modules.add(imported)
        package = (
            globals_.get("__package__")
            if isinstance(globals_, Mapping)
            else None
        )
        try:
            absolute_name = (
                importlib.util.resolve_name(f"{'.' * level}{name}", package)
                if level
                else name
            )
        except (ImportError, ValueError, TypeError):
            absolute_name = name
        candidate = imported if type(imported) is ModuleType else None
        if candidate is not None:
            current: object = candidate
            current_parts = candidate.__name__.split(".")
            target_parts = absolute_name.split(".")
            if target_parts[: len(current_parts)] == current_parts:
                for part in target_parts[len(current_parts) :]:
                    current = getattr(current, part, None)
                    if type(current) is not ModuleType:
                        break
                    modules.add(current)
                if type(current) is ModuleType:
                    candidate = current
        for member in tuple(fromlist or ()):
            if not isinstance(member, str) or member == "*":
                continue
            attribute = getattr(candidate, member, None)
            if type(attribute) is ModuleType:
                modules.add(attribute)
        attest(modules)
        return imported

    def reviewed_import_module(name: str, package: str | None = None) -> ModuleType:
        imported = original_import_module(name, package)
        if type(imported) is not ModuleType:
            raise WindowsServiceError("SERVICE_FACTORY_IMPORT_RESULT_INVALID")
        attest({imported})
        return imported

    def reviewed_reload(module: ModuleType) -> ModuleType:
        if type(module) is not ModuleType:
            raise WindowsServiceError("SERVICE_FACTORY_IMPORT_RESULT_INVALID")
        attest({module})
        imported = original_reload(module)
        if type(imported) is not ModuleType:
            raise WindowsServiceError("SERVICE_FACTORY_IMPORT_RESULT_INVALID")
        attest({imported})
        return imported

    with _FACTORY_IMPORT_SCOPE_LOCK:
        stack = getattr(_FACTORY_IMPORT_AUDIT_LOCAL, "stack", None)
        if stack is None:
            stack = []
            _FACTORY_IMPORT_AUDIT_LOCAL.stack = stack
        stack.append(tracked_modules)
        builtins.__import__ = cast(Any, reviewed_import)
        importlib.__import__ = cast(Any, reviewed_import)
        importlib.import_module = reviewed_import_module
        importlib.reload = reviewed_reload
        for name in guarded_util_names:
            setattr(importlib.util, name, _factory_dynamic_loader_denied)
        validation_error: BaseException | None = None
        try:
            yield
        finally:
            try:
                if (
                    builtins.__import__ is not reviewed_import
                    or importlib.__import__ is not reviewed_import
                    or importlib.import_module is not reviewed_import_module
                    or importlib.reload is not reviewed_reload
                    or any(
                        getattr(importlib.util, name) is not _factory_dynamic_loader_denied
                        for name in guarded_util_names
                    )
                ):
                    raise WindowsServiceError("SERVICE_FACTORY_IMPORT_GUARD_MUTATED")
                _verify_imported_module_origins(
                    release_root=release_root,
                    inventory=inventory,
                    modules=set(tracked_modules),
                )
                _verify_module_registry_delta(
                    before=registry_before,
                    release_root=release_root,
                    inventory=inventory,
                )
            except BaseException as exc:  # preserve fail-closed cleanup below
                validation_error = exc
            finally:
                builtins.__import__ = original_import
                importlib.__import__ = original_importlib_import
                importlib.import_module = original_import_module
                importlib.reload = original_reload
                for name, value in original_util.items():
                    setattr(importlib.util, name, value)
                if stack and stack[-1] is tracked_modules:
                    stack.pop()
                else:
                    validation_error = WindowsServiceError(
                        "SERVICE_FACTORY_IMPORT_AUDIT_CORRUPTED"
                    )
            if validation_error is not None:
                raise validation_error


def _verify_imported_module_origins(
    *,
    release_root: Path,
    inventory: Mapping[str, Mapping[str, Any]],
    modules: set[ModuleType],
) -> None:
    """Allow only pinned release modules or Python's non-site stdlib."""

    stdlib_roots = {
        Path(value).resolve(strict=True)
        for key in ("stdlib", "platstdlib")
        if (value := sysconfig.get_path(key))
    }
    for module in sorted(modules, key=lambda item: item.__name__):
        origin = getattr(getattr(module, "__spec__", None), "origin", None)
        if origin in {"built-in", "frozen"}:
            continue
        if origin is None:
            namespace_paths = tuple(getattr(module, "__path__", ()) or ())
            if not namespace_paths:
                raise WindowsServiceError("SERVICE_FACTORY_IMPORT_ORIGIN_INVALID")
            for namespace_path in namespace_paths:
                try:
                    resolved_namespace = Path(namespace_path).resolve(strict=True)
                except (OSError, TypeError) as exc:
                    raise WindowsServiceError(
                        "SERVICE_FACTORY_IMPORT_ORIGIN_INVALID"
                    ) from exc
                folded_parts = {
                    part.casefold() for part in resolved_namespace.parts
                }
                if folded_parts.intersection(
                    {"site-packages", "dist-packages"}
                ) or not (
                    _is_relative_to(resolved_namespace, release_root)
                    or any(
                        _is_relative_to(resolved_namespace, root)
                        for root in stdlib_roots
                    )
                ):
                    raise WindowsServiceError(
                        "SERVICE_FACTORY_IMPORT_ORIGIN_DENIED"
                    )
            continue
        try:
            path = Path(origin).resolve(strict=True)
        except (OSError, TypeError) as exc:
            raise WindowsServiceError("SERVICE_FACTORY_IMPORT_ORIGIN_INVALID") from exc
        if _is_relative_to(path, release_root):
            relative = path.relative_to(release_root).as_posix()
            item = inventory.get(relative)
            if not isinstance(item, Mapping):
                raise WindowsServiceError("SERVICE_FACTORY_IMPORT_NOT_RELEASE_BOUND")
            payload = _read_release_bytes(path, label="IMPORTED_MODULE")
            if (
                len(payload) != item.get("size_bytes")
                or _sha256_bytes(payload) != item.get("sha256")
            ):
                raise WindowsServiceError("SERVICE_FACTORY_IMPORT_HASH_MISMATCH")
            continue
        folded_parts = {part.casefold() for part in path.parts}
        if folded_parts.intersection({"site-packages", "dist-packages"}) or not any(
            _is_relative_to(path, root) for root in stdlib_roots
        ):
            raise WindowsServiceError("SERVICE_FACTORY_IMPORT_ORIGIN_DENIED")


def _external_runtime_file_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        int(getattr(value, "st_file_attributes", 0)),
    )


def _stable_read_windows_live_runtime_provider(
    *,
    runtime_provider_path: str | Path,
    release_root: Path,
    expected_runtime_provider_sha256: str,
    platform_overridden: bool,
) -> tuple[Path, bytes]:
    raw = str(runtime_provider_path)
    configured = Path(runtime_provider_path).expanduser()
    if (
        not raw
        or raw != raw.strip()
        or "\x00" in raw
        or raw.startswith(("\\\\", "//"))
        or not configured.is_absolute()
    ):
        raise WindowsServiceError("LIVE_RUNTIME_PROVIDER_PATH_INVALID")
    if sys.platform == "win32" and not platform_overridden:
        parsed = PureWindowsPath(raw)
        if (
            not parsed.is_absolute()
            or not parsed.drive
            or parsed.anchor != parsed.drive + "\\"
            or any(":" in part for part in parsed.parts[1:])
        ):
            raise WindowsServiceError("LIVE_RUNTIME_PROVIDER_PATH_INVALID")
    expected = require_hash(
        "expected_runtime_provider_sha256",
        expected_runtime_provider_sha256,
    )
    if expected == "0" * 64:
        raise WindowsServiceError("LIVE_RUNTIME_PROVIDER_HASH_INVALID")
    configured = configured.absolute()
    try:
        before = configured.lstat()
        resolved = configured.resolve(strict=True)
        resolved.relative_to(release_root)
    except ValueError:
        pass
    except OSError as exc:
        raise WindowsServiceError(
            "LIVE_RUNTIME_PROVIDER_UNAVAILABLE"
        ) from exc
    else:
        raise WindowsServiceError("LIVE_RUNTIME_PROVIDER_MUST_BE_EXTERNAL")
    reparse = int(getattr(before, "st_file_attributes", 0)) & 0x400
    if (
        stat.S_ISLNK(before.st_mode)
        or reparse
        or not stat.S_ISREG(before.st_mode)
        or before.st_size <= 0
        or before.st_size > MAX_LIVE_RUNTIME_PROVIDER_BYTES
    ):
        raise WindowsServiceError("LIVE_RUNTIME_PROVIDER_FILE_INVALID")
    try:
        with configured.open("rb") as handle:
            opened_before = os.fstat(handle.fileno())
            payload = handle.read(MAX_LIVE_RUNTIME_PROVIDER_BYTES + 1)
            opened_after = os.fstat(handle.fileno())
        after = configured.lstat()
    except OSError as exc:
        raise WindowsServiceError(
            "LIVE_RUNTIME_PROVIDER_UNAVAILABLE"
        ) from exc
    identity = _external_runtime_file_identity(before)
    if (
        len(payload) != before.st_size
        or len(payload) > MAX_LIVE_RUNTIME_PROVIDER_BYTES
        or _external_runtime_file_identity(opened_before) != identity
        or _external_runtime_file_identity(opened_after) != identity
        or _external_runtime_file_identity(after) != identity
    ):
        raise WindowsServiceError("LIVE_RUNTIME_PROVIDER_CHANGED_DURING_READ")
    if _sha256_bytes(payload) != expected:
        raise WindowsServiceError("LIVE_RUNTIME_PROVIDER_HASH_MISMATCH")
    return resolved, payload


def _load_exact_live_runtime_provider_module(
    *,
    source_path: Path,
    source_payload: bytes,
    context: WindowsLiveCanaryExternalRuntimeContext,
    release_root: Path,
    inventory: Mapping[str, Mapping[str, Any]],
) -> "WindowsLiveCanaryProviderMaterializationHooks":
    """Execute only the exact prevalidated bytes under reviewed imports."""

    module_name = (
        "_ai_scalper_windows_live_runtime_"
        + context.runtime_provider_sha256[:16]
    )
    namespace = ModuleType(module_name)
    namespace.__file__ = str(source_path)
    namespace.__package__ = ""
    try:
        code = builtins.compile(
            source_payload,
            str(source_path),
            "exec",
            flags=0,
            dont_inherit=True,
            optimize=0,
        )
    except (SyntaxError, ValueError) as exc:
        raise WindowsServiceError(
            "LIVE_RUNTIME_PROVIDER_SOURCE_INVALID"
        ) from exc
    try:
        with _reviewed_import_scope(
            release_root=release_root,
            inventory=inventory,
        ):
            builtins.exec(code, namespace.__dict__)
            builder = namespace.__dict__.get(LIVE_RUNTIME_PROVIDER_BUILDER)
            if (
                type(builder) is not FunctionType
                or builder.__module__ != module_name
            ):
                raise WindowsServiceError(
                    "LIVE_RUNTIME_PROVIDER_BUILDER_INVALID"
                )
            signature = inspect.signature(builder)
            parameters = tuple(signature.parameters.values())
            if (
                len(parameters) != 1
                or parameters[0].kind
                not in {
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                }
                or parameters[0].default is not inspect.Parameter.empty
            ):
                raise WindowsServiceError(
                    "LIVE_RUNTIME_PROVIDER_BUILDER_INVALID"
                )
            hooks = builder(context)
    except WindowsServiceError:
        raise
    except Exception as exc:
        raise WindowsServiceError(
            "LIVE_RUNTIME_PROVIDER_BUILDER_FAILED"
        ) from exc
    return hooks


def load_reviewed_windows_live_runtime_hooks(
    *,
    release_root: str | Path,
    expected_release_identity_sha256: str,
    factory_context: WindowsServiceFactoryContext,
    runtime_provider_path: str | Path,
    expected_runtime_provider_sha256: str,
    clock_provider: Callable[[], datetime] = _now,
    platform: str | None = None,
) -> tuple[
    WindowsLiveCanaryExternalRuntimeContext,
    "WindowsLiveCanaryProviderMaterializationHooks",
]:
    """Load one exact external LIVE hook provider after all local locks."""

    observed_platform = sys.platform if platform is None else platform
    if observed_platform != "win32":
        raise WindowsServiceError("WINDOWS_PLATFORM_REQUIRED")
    if type(factory_context) is not WindowsServiceFactoryContext:
        raise WindowsServiceError("LIVE_RUNTIME_FACTORY_CONTEXT_INVALID")
    if not callable(clock_provider):
        raise TypeError("clock_provider must be callable")
    try:
        from .windows_live_canary_execution_provider import (
            WindowsLiveCanaryProviderMaterializationHooks,
            require_windows_live_canary_policy,
        )

        require_windows_live_canary_policy()
    except Exception as exc:
        reason = getattr(exc, "reason_code", "CENTRAL_LIVE_LOCK_NOT_ENABLED")
        raise WindowsServiceError(reason) from exc
    root = _require_release_root(release_root)
    expected_identity = require_hash(
        "expected_release_identity_sha256",
        expected_release_identity_sha256,
    )
    if expected_identity == "0" * 64:
        raise WindowsServiceError("SERVICE_RELEASE_IDENTITY_MISMATCH")
    _manifest, inventory = _verify_execution_release_manifest(
        root=root,
        expected_release_identity_sha256=expected_identity,
    )
    expected_root_sha256 = _sha256_bytes(str(root).encode("utf-8"))
    if factory_context.release_root_sha256 != expected_root_sha256:
        raise WindowsServiceError("LIVE_RUNTIME_FACTORY_CONTEXT_MISMATCH")
    source_path, payload = _stable_read_windows_live_runtime_provider(
        runtime_provider_path=runtime_provider_path,
        release_root=root,
        expected_runtime_provider_sha256=(
            expected_runtime_provider_sha256
        ),
        platform_overridden=platform is not None,
    )
    validate_windows_live_runtime_provider_source(payload)
    try:
        require_windows_live_canary_policy()
        observed_at = require_utc(
            "external runtime observation",
            clock_provider(),
        )
        context = WindowsLiveCanaryExternalRuntimeContext(
            runtime_provider_sha256=_sha256_bytes(payload),
            release_identity_sha256=expected_identity,
            release_root_sha256=factory_context.release_root_sha256,
            factory_contract_sha256=(
                factory_context.factory_contract_sha256
            ),
            factory_file_sha256=factory_context.factory_file_sha256,
            service_config_file_sha256=(
                factory_context.service_config_file_sha256
            ),
            bootstrap_binding_sha256=(
                factory_context.bootstrap_binding_sha256
            ),
            observed_at_utc=observed_at,
            _seal=_EXTERNAL_RUNTIME_CONTEXT_SEAL,
        )
        hooks = _load_exact_live_runtime_provider_module(
            source_path=source_path,
            source_payload=payload,
            context=context,
            release_root=root,
            inventory=inventory,
        )
        require_windows_live_canary_policy()
    except WindowsServiceError:
        raise
    except Exception as exc:
        reason = getattr(exc, "reason_code", "LIVE_RUNTIME_PROVIDER_INVALID")
        raise WindowsServiceError(reason) from exc
    if type(hooks) is not WindowsLiveCanaryProviderMaterializationHooks:
        raise WindowsServiceError("LIVE_RUNTIME_PROVIDER_HOOKS_INVALID")
    _second_path, second_payload = _stable_read_windows_live_runtime_provider(
        runtime_provider_path=runtime_provider_path,
        release_root=root,
        expected_runtime_provider_sha256=(
            expected_runtime_provider_sha256
        ),
        platform_overridden=platform is not None,
    )
    if _second_path != source_path or second_payload != payload:
        raise WindowsServiceError("LIVE_RUNTIME_PROVIDER_CHANGED_DURING_BUILD")
    try:
        require_windows_live_canary_policy()
    except Exception as exc:
        reason = getattr(exc, "reason_code", "CENTRAL_LIVE_LOCK_NOT_ENABLED")
        raise WindowsServiceError(reason) from exc
    return context, hooks


def load_reviewed_windows_service_factory(
    *,
    release_root: str | Path,
    manifest_path: str | Path,
    expected_release_identity_sha256: str,
) -> tuple[WindowsServiceFactoryManifest, Mapping[str, Any], WindowsServiceFactoryResult]:
    """Load and invoke one release-local, exact-hash ports factory."""

    root = _require_release_root(release_root)
    _release_manifest, inventory = _verify_execution_release_manifest(
        root=root,
        expected_release_identity_sha256=expected_release_identity_sha256,
    )
    manifest, service_config, context = (
        validate_reviewed_windows_service_factory_manifest(
            release_root=root,
            manifest_path=manifest_path,
            expected_release_identity_sha256=expected_release_identity_sha256,
        )
    )
    factory_file = _require_release_file(
        root, manifest.factory_relative_path, suffix=".py"
    )
    config_file = _require_release_file(
        root, manifest.service_config_relative_path, suffix=".json"
    )
    factory_bytes = _read_release_bytes(factory_file, label="FACTORY_SOURCE")
    config_bytes = _read_release_bytes(config_file, label="SERVICE_CONFIG")
    if (
        _sha256_bytes(factory_bytes) != manifest.factory_file_sha256
        or _sha256_bytes(config_bytes) != manifest.service_config_file_sha256
    ):
        raise WindowsServiceError("SERVICE_FACTORY_OR_CONFIG_HASH_MISMATCH")
    factory_namespace = _load_exact_factory_module(
        manifest=manifest,
        factory_file=factory_file,
        release_root=root,
        inventory=inventory,
    )
    factory = getattr(factory_namespace, manifest.factory_attribute, None)
    if type(factory) is not FunctionType or factory.__module__ != manifest.factory_module:
        raise WindowsServiceError("SERVICE_FACTORY_CALLABLE_INVALID")
    # Re-check exact source/config immediately before and after the call.  A
    # reviewed factory cannot race a replacement into the trust boundary.
    if (
        _sha256_bytes(_read_release_bytes(factory_file, label="FACTORY_SOURCE"))
        != manifest.factory_file_sha256
        or _sha256_bytes(_read_release_bytes(config_file, label="SERVICE_CONFIG"))
        != manifest.service_config_file_sha256
    ):
        raise WindowsServiceError("SERVICE_FACTORY_OR_CONFIG_HASH_MISMATCH")
    original_sys_path = list(sys.path)
    sys.path[:] = _reviewed_factory_sys_path(root, original_sys_path)
    try:
        with _reviewed_import_scope(release_root=root, inventory=inventory):
            result = factory(dict(service_config), context)
    except WindowsServiceError:
        raise
    except Exception as exc:
        raise WindowsServiceError("SERVICE_FACTORY_CALL_FAILED") from exc
    finally:
        sys.path[:] = original_sys_path
    if (
        _sha256_bytes(_read_release_bytes(factory_file, label="FACTORY_SOURCE"))
        != manifest.factory_file_sha256
        or _sha256_bytes(_read_release_bytes(config_file, label="SERVICE_CONFIG"))
        != manifest.service_config_file_sha256
    ):
        raise WindowsServiceError("SERVICE_FACTORY_OR_CONFIG_CHANGED")
    if type(result) is not WindowsServiceFactoryResult:
        raise WindowsServiceError("SERVICE_FACTORY_RESULT_NOT_SEALED")
    if (
        result.factory_contract_sha256 != manifest.factory_contract_sha256
        or result.service_config_file_sha256
        != manifest.service_config_file_sha256
        or result.bootstrap.config.safe_binding_sha256
        != manifest.bootstrap_binding_sha256
    ):
        raise WindowsServiceError("SERVICE_FACTORY_RESULT_BINDING_MISMATCH")
    return manifest, service_config, result


@dataclass(frozen=True)
class WindowsServiceStatus(CanonicalContract):
    service_id: str
    service_run_id: str
    phase: str
    sequence: int
    previous_status_sha256: str
    occurred_at_utc: datetime
    valid_until_utc: datetime
    bootstrap_binding_sha256: str
    factory_contract_sha256: str
    supervisor_receipt_sha256: str | None
    reason_code: str | None
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    max_lot: float = 0.01
    schema_version: str = WINDOWS_SERVICE_STATUS_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _STATUS_SEAL:
            raise TypeError("Windows service status requires service lifecycle issuer")
        object.__setattr__(self, "service_id", require_text("service_id", self.service_id))
        try:
            normalized_run_id = str(uuid.UUID(require_text("service_run_id", self.service_run_id)))
        except (ValueError, AttributeError) as exc:
            raise ValueError("service_run_id must be a canonical UUID") from exc
        if normalized_run_id != self.service_run_id:
            raise ValueError("service_run_id must be a canonical UUID")
        object.__setattr__(self, "service_run_id", normalized_run_id)
        phase = require_text("phase", self.phase, upper=True)
        if phase not in _ALLOWED_PHASES:
            raise ValueError("unsupported Windows service phase")
        object.__setattr__(self, "phase", phase)
        require_int("sequence", self.sequence, minimum=1)
        object.__setattr__(
            self,
            "previous_status_sha256",
            require_hash("previous_status_sha256", self.previous_status_sha256),
        )
        if self.sequence == 1 and self.previous_status_sha256 != "0" * 64:
            raise ValueError("first service status must start at the zero predecessor")
        if self.sequence > 1 and self.previous_status_sha256 == "0" * 64:
            raise ValueError("later service status requires a non-zero predecessor")
        occurred = require_utc("occurred_at_utc", self.occurred_at_utc)
        valid_until = require_utc("valid_until_utc", self.valid_until_utc)
        if not occurred < valid_until <= occurred + timedelta(
            seconds=MAX_HEARTBEAT_TTL_SECONDS
        ):
            raise ValueError("service status validity must be in (0, 30] seconds")
        for name in ("bootstrap_binding_sha256", "factory_contract_sha256"):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if self.supervisor_receipt_sha256 is not None:
            object.__setattr__(
                self,
                "supervisor_receipt_sha256",
                require_hash("supervisor_receipt_sha256", self.supervisor_receipt_sha256),
            )
        if self.reason_code is not None:
            object.__setattr__(
                self, "reason_code", require_text("reason_code", self.reason_code, upper=True)
            )
        if self.live_allowed or self.safe_to_demo_auto_order or self.max_lot != 0.01:
            raise ValueError("service status cannot override execution locks")
        if self.schema_version != WINDOWS_SERVICE_STATUS_SCHEMA:
            raise ValueError("unsupported Windows service status schema")


def _service_status_from_payload(payload: object) -> WindowsServiceStatus:
    if not isinstance(payload, Mapping):
        raise WindowsServiceError("SERVICE_HEARTBEAT_PAYLOAD_INVALID")
    values = dict(payload)
    expected = {
        "service_id",
        "service_run_id",
        "phase",
        "sequence",
        "previous_status_sha256",
        "occurred_at_utc",
        "valid_until_utc",
        "bootstrap_binding_sha256",
        "factory_contract_sha256",
        "supervisor_receipt_sha256",
        "reason_code",
        "live_allowed",
        "safe_to_demo_auto_order",
        "max_lot",
        "schema_version",
    }
    if set(values) != expected:
        raise WindowsServiceError("SERVICE_HEARTBEAT_PAYLOAD_INVALID")
    try:
        for field in ("occurred_at_utc", "valid_until_utc"):
            raw = values[field]
            if not isinstance(raw, str):
                raise ValueError(field)
            values[field] = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return WindowsServiceStatus(**values, _seal=_STATUS_SEAL)
    except (TypeError, ValueError) as exc:
        raise WindowsServiceError("SERVICE_HEARTBEAT_PAYLOAD_INVALID") from exc


class WindowsGatedServiceRunner:
    """Initialize, start, run bounded cycles, heartbeat, and shut down safely."""

    def __init__(
        self,
        result: WindowsServiceFactoryResult,
        *,
        service_id: str,
        owner_id: str,
        heartbeat_ttl_seconds: int = 30,
        service_run_id: str | None = None,
    ) -> None:
        if type(result) is not WindowsServiceFactoryResult:
            raise TypeError("result must be exact sealed WindowsServiceFactoryResult")
        self.result = result
        self.service_id = require_text("service_id", service_id)
        self.owner_id = require_text("owner_id", owner_id)
        generated_run_id = str(uuid.uuid4()) if service_run_id is None else service_run_id
        try:
            self.service_run_id = str(uuid.UUID(generated_run_id))
        except (ValueError, AttributeError) as exc:
            raise ValueError("service_run_id must be a UUID") from exc
        if self.service_run_id != generated_run_id:
            raise ValueError("service_run_id must be a canonical UUID")
        self.heartbeat_ttl_seconds = require_int(
            "heartbeat_ttl_seconds",
            heartbeat_ttl_seconds,
            minimum=1,
            maximum=MAX_HEARTBEAT_TTL_SECONDS,
        )
        self.sequence = 0
        self.previous_status_sha256 = "0" * 64
        self.composition: ProductionRuntimeComposition | None = None
        self.stop_event = threading.Event()
        self._lifecycle_abort_handled = False

    def _trusted_now(self) -> datetime:
        return require_utc("service clock", self.result.clock_provider())

    def _heartbeat(
        self,
        phase: str,
        *,
        supervisor_receipt_sha256: str | None = None,
        reason_code: str | None = None,
    ) -> WindowsServiceStatus:
        now = self._trusted_now()
        sender_key = self.result.heartbeat_sender_key_provider(
            self.result.heartbeat_sender_key_id
        )
        if (
            _key_fingerprint(sender_key)
            != self.result.heartbeat_sender_key_fingerprint_sha256
        ):
            raise WindowsServiceError("SERVICE_HEARTBEAT_SENDER_KEY_MISMATCH")
        delivery_supervisor = OffHostDeliverySupervisor(
            outbox=self.result.heartbeat_outbox,
            remote_key_provider=self.result.heartbeat_remote_key_provider,
            clock_provider=self.result.clock_provider,
        )
        # A successor is never created while any prior envelope is unresolved.
        # This makes the outbox's unique idempotency key the durable CAS for
        # (service_id, service_run_id, sequence).
        pending_delivery = delivery_supervisor.deliver_pending(
            self.result.heartbeat_transport, attempted_at=now
        )
        if pending_delivery.failed or pending_delivery.pending_after:
            raise WindowsServiceError("SERVICE_HEARTBEAT_PREDECESSOR_UNRESOLVED")
        sequence, predecessor = self._durable_heartbeat_head(sender_key)
        next_sequence = sequence + 1
        status = WindowsServiceStatus(
            service_id=self.service_id,
            service_run_id=self.service_run_id,
            phase=phase,
            sequence=next_sequence,
            previous_status_sha256=predecessor,
            occurred_at_utc=now,
            valid_until_utc=now + timedelta(seconds=self.heartbeat_ttl_seconds),
            bootstrap_binding_sha256=self.result.bootstrap.config.safe_binding_sha256,
            factory_contract_sha256=self.result.factory_contract_sha256,
            supervisor_receipt_sha256=supervisor_receipt_sha256,
            reason_code=reason_code,
            _seal=_STATUS_SEAL,
        )
        envelope = DeliveryEnvelope.create(
            idempotency_key=(
                f"{self.service_id}:{self.service_run_id}:{status.sequence}"
            ),
            destination_id=self.result.heartbeat_destination_id,
            artifact_type="HEARTBEAT",
            payload=status.to_canonical_dict(),
            created_at_utc=now,
            sender_key_id=self.result.heartbeat_sender_key_id,
            secret=sender_key,
        )
        self.result.heartbeat_outbox.enqueue(envelope)
        delivery = delivery_supervisor.deliver_pending(
            self.result.heartbeat_transport, attempted_at=now
        )
        record = self.result.heartbeat_outbox.get(envelope.envelope_id)
        acknowledgement = record.get("acknowledgement")
        if (
            envelope.envelope_id not in delivery.acknowledged
            or delivery.failed
            or delivery.pending_after
            or record.get("state") != "ACKNOWLEDGED"
            or not isinstance(acknowledgement, Mapping)
        ):
            raise WindowsServiceError("SERVICE_HEARTBEAT_NOT_ACKNOWLEDGED_OFFHOST")
        ack = DeliveryAcknowledgement.from_dict(acknowledgement)
        if (
            ack.remote_key_id != self.result.heartbeat_remote_key_id
            or _key_fingerprint(
                self.result.heartbeat_remote_key_provider(ack.remote_key_id)
            )
            != self.result.heartbeat_remote_key_fingerprint_sha256
        ):
            raise WindowsServiceError("SERVICE_HEARTBEAT_REMOTE_TRUST_MISMATCH")
        self.sequence = status.sequence
        self.previous_status_sha256 = status.content_sha256
        return status

    def _durable_heartbeat_head(self, sender_key: str | bytes) -> tuple[int, str]:
        if not self.result.heartbeat_outbox.integrity_check() or not (
            self.result.heartbeat_outbox.verify_records(
                self.result.heartbeat_remote_key_provider
            )
        ):
            raise WindowsServiceError("SERVICE_HEARTBEAT_OUTBOX_INTEGRITY_FAILURE")
        statuses: list[WindowsServiceStatus] = []
        for record in self.result.heartbeat_outbox.records():
            envelope = record["envelope"]
            if (
                envelope.artifact_type != "HEARTBEAT"
                or envelope.destination_id
                != self.result.heartbeat_destination_id
            ):
                continue
            try:
                payload = json.loads(envelope.payload_json)
            except json.JSONDecodeError as exc:
                raise WindowsServiceError(
                    "SERVICE_HEARTBEAT_PAYLOAD_INVALID"
                ) from exc
            if not isinstance(payload, Mapping):
                raise WindowsServiceError("SERVICE_HEARTBEAT_PAYLOAD_INVALID")
            if (
                payload.get("service_id") != self.service_id
                or payload.get("service_run_id") != self.service_run_id
            ):
                continue
            if (
                record["state"] != "ACKNOWLEDGED"
                or record["acknowledgement"] is None
                or envelope.sender_key_id
                != self.result.heartbeat_sender_key_id
                or not envelope.verify_sender(sender_key)
            ):
                raise WindowsServiceError("SERVICE_HEARTBEAT_CHAIN_UNACKNOWLEDGED")
            statuses.append(_service_status_from_payload(payload))
        statuses.sort(key=lambda item: item.sequence)
        predecessor = "0" * 64
        for expected_sequence, status in enumerate(statuses, start=1):
            if (
                status.sequence != expected_sequence
                or status.previous_status_sha256 != predecessor
                or status.service_id != self.service_id
                or status.service_run_id != self.service_run_id
                or status.bootstrap_binding_sha256
                != self.result.bootstrap.config.safe_binding_sha256
                or status.factory_contract_sha256
                != self.result.factory_contract_sha256
            ):
                raise WindowsServiceError("SERVICE_HEARTBEAT_CHAIN_INVALID")
            predecessor = status.content_sha256
        return len(statuses), predecessor

    def request_stop(self) -> None:
        self.stop_event.set()

    def _terminate_active_cycle(
        self,
        *,
        composition: ProductionRuntimeComposition,
        reason_code: str,
        cause: Exception,
    ) -> None:
        """Latch/revoke best-effort, then kill the process unconditionally.

        Python threads cannot be safely killed.  Once the synchronous cycle
        deadline is lost, returning to the service loop would leave a worker
        able to make a later broker call.  Hard process termination is thus a
        mandatory part of this boundary; the next process must reconcile the
        broker before startup can pass.
        """

        self._lifecycle_abort_handled = True
        watchdog = threading.Timer(
            1.0,
            _hard_terminate_process,
            args=(SERVICE_DEADLINE_EXIT_CODE,),
        )
        watchdog.daemon = True
        watchdog.start()
        try:
            composition.abort_fail_closed(reason_code, cause=cause)
        except Exception:
            pass
        try:
            _hard_terminate_process(SERVICE_DEADLINE_EXIT_CODE)
        finally:
            watchdog.cancel()
        raise WindowsServiceError("SERVICE_HARD_TERMINATION_RETURNED")

    def _run_cycle_with_deadline(
        self,
        *,
        composition: ProductionRuntimeComposition,
        deadline_seconds: float,
        prior_receipt_sha256: str,
    ) -> Any:
        result_queue: queue.Queue[tuple[str, object]] = queue.Queue(maxsize=1)

        def worker() -> None:
            try:
                result_queue.put_nowait(("RECEIPT", composition.run_cycle()))
            except Exception as exc:
                result_queue.put_nowait(("ERROR", exc))

        thread = threading.Thread(
            target=worker,
            name=f"{self.service_id}-bounded-cycle",
            daemon=True,
        )
        started_at = time.monotonic()
        thread.start()
        while True:
            remaining = deadline_seconds - (time.monotonic() - started_at)
            if remaining <= 0:
                failure = WindowsServiceError("SERVICE_CYCLE_DEADLINE_EXCEEDED")
                self._terminate_active_cycle(
                    composition=composition,
                    reason_code="SERVICE_CYCLE_DEADLINE_EXCEEDED",
                    cause=failure,
                )
            try:
                kind, value = result_queue.get(
                    timeout=min(remaining, self.heartbeat_ttl_seconds / 3.0)
                )
            except queue.Empty:
                try:
                    self._heartbeat(
                        "RUNNING",
                        supervisor_receipt_sha256=prior_receipt_sha256,
                    )
                except Exception as exc:
                    self._terminate_active_cycle(
                        composition=composition,
                        reason_code="SERVICE_HEARTBEAT_FAILED_DURING_CYCLE",
                        cause=exc,
                    )
                continue
            if kind == "ERROR":
                if not isinstance(value, Exception):
                    failure = WindowsServiceError(
                        "SERVICE_CYCLE_WORKER_RESULT_INVALID"
                    )
                    self._terminate_active_cycle(
                        composition=composition,
                        reason_code="SERVICE_CYCLE_WORKER_RESULT_INVALID",
                        cause=failure,
                    )
                thread.join(timeout=min(0.1, max(remaining, 0.0)))
                raise cast(Exception, value)
            thread.join(timeout=min(0.1, max(remaining, 0.0)))
            if kind != "RECEIPT" or thread.is_alive():
                failure = WindowsServiceError(
                    "SERVICE_CYCLE_WORKER_RESULT_INVALID"
                )
                self._terminate_active_cycle(
                    composition=composition,
                    reason_code="SERVICE_CYCLE_WORKER_RESULT_INVALID",
                    cause=failure,
                )
            return value

    def run(
        self,
        *,
        max_cycles: int,
        lease_seconds: int = 30,
        cycle_interval_seconds: float = 5.0,
        cycle_deadline_seconds: float = 20.0,
    ) -> tuple[Any, ...]:
        count = require_int("max_cycles", max_cycles, minimum=1, maximum=100_000)
        lease = require_int("lease_seconds", lease_seconds, minimum=1, maximum=300)
        if isinstance(cycle_interval_seconds, bool) or not isinstance(
            cycle_interval_seconds, (int, float)
        ):
            raise TypeError("cycle_interval_seconds must be numeric")
        interval = float(cycle_interval_seconds)
        if not 0.25 <= interval <= min(15.0, self.heartbeat_ttl_seconds / 2.0):
            raise ValueError("cycle_interval_seconds is outside the reviewed range")
        if isinstance(cycle_deadline_seconds, bool) or not isinstance(
            cycle_deadline_seconds, (int, float)
        ):
            raise TypeError("cycle_deadline_seconds must be numeric")
        deadline = float(cycle_deadline_seconds)
        if not 1.0 <= deadline <= self.heartbeat_ttl_seconds:
            raise ValueError("cycle_deadline_seconds is outside the heartbeat TTL")
        started = False
        composition_failure_handled = False
        receipts: tuple[Any, ...] = ()
        try:
            self._heartbeat("STARTING")
            composition = self.result.bootstrap.materialize()
            if type(composition) is not ProductionRuntimeComposition:
                raise WindowsServiceError("SERVICE_COMPOSITION_NOT_EXACT")
            self.composition = composition
            composition.initialize()
            self._heartbeat("INITIALIZED")
            startup = composition.start(owner_id=self.owner_id, lease_seconds=lease)
            started = True
            self._heartbeat(
                "RUNNING", supervisor_receipt_sha256=startup.content_sha256
            )
            cycle_receipts: list[Any] = []
            for index in range(count):
                if self.stop_event.is_set():
                    break
                if index:
                    # A monotonic, interruptible cadence prevents a tight loop
                    # from hammering MT5/reconciliation or the same M15 bar.
                    wait_started = time.monotonic()
                    while True:
                        remaining = interval - (time.monotonic() - wait_started)
                        if remaining <= 0 or self.stop_event.is_set():
                            break
                        if self.stop_event.wait(
                            min(remaining, self.heartbeat_ttl_seconds / 3.0)
                        ):
                            break
                        self._heartbeat(
                            "RUNNING",
                            supervisor_receipt_sha256=(
                                cycle_receipts[-1].content_sha256
                                if cycle_receipts
                                else startup.content_sha256
                            ),
                        )
                if self.stop_event.is_set():
                    break
                # Each public composition cycle performs pre/post external
                # evidence attestation without stopping the supervisor.
                try:
                    receipt = self._run_cycle_with_deadline(
                        composition=composition,
                        deadline_seconds=deadline,
                        prior_receipt_sha256=(
                            cycle_receipts[-1].content_sha256
                            if cycle_receipts
                            else startup.content_sha256
                        ),
                    )
                except Exception:
                    # ProductionRuntimeComposition.run_cycle owns the single
                    # fail-closed latch for failures within its boundary.
                    composition_failure_handled = True
                    raise
                cycle_receipts.append(receipt)
                self._heartbeat(
                    "RUNNING",
                    supervisor_receipt_sha256=receipt.content_sha256,
                )
                if self.stop_event.is_set():
                    break
            receipts = tuple(cycle_receipts)
            final_cycle_sha = receipts[-1].content_sha256 if receipts else None
            self._heartbeat(
                "STOPPING", supervisor_receipt_sha256=final_cycle_sha
            )
            try:
                stop_receipt = composition.stop()
            except Exception:
                # ProductionRuntimeComposition.stop owns the single latch.
                composition_failure_handled = True
                raise
            self._heartbeat(
                "STOPPED", supervisor_receipt_sha256=stop_receipt.content_sha256
            )
            started = False
            return receipts
        except Exception as exc:
            if (
                started
                and not composition_failure_handled
                and not self._lifecycle_abort_handled
                and self.composition is not None
            ):
                try:
                    self.composition.supervisor.fail_closed(
                        "WINDOWS_SERVICE_LIFECYCLE_FAILED", cause=exc
                    )
                except Exception:
                    pass
            try:
                self._heartbeat(
                    "FAILED", reason_code=f"SERVICE_{type(exc).__name__.upper()}"
                )
            except Exception:
                pass
            raise
        finally:
            if self.composition is not None:
                self.composition.shutdown()


def install_signal_handlers(runner: WindowsGatedServiceRunner) -> None:
    """Request graceful shutdown; this never installs a Task Scheduler job."""

    def handle(_signum: int, _frame: object) -> None:
        runner.request_stop()

    for name in ("SIGINT", "SIGTERM"):
        value = getattr(signal, name, None)
        if value is not None:
            signal.signal(value, handle)


__all__ = [
    "LIVE_RUNTIME_PROVIDER_BUILDER",
    "MAX_LIVE_RUNTIME_PROVIDER_BYTES",
    "MAX_HEARTBEAT_TTL_SECONDS",
    "WINDOWS_LIVE_EXTERNAL_RUNTIME_CONTEXT_SCHEMA",
    "WINDOWS_LIVE_EXTERNAL_RUNTIME_SOURCE_VALIDATION_SCHEMA",
    "WINDOWS_SERVICE_FACTORY_CONTEXT_SCHEMA",
    "WINDOWS_SERVICE_FACTORY_MANIFEST_SCHEMA",
    "WINDOWS_SERVICE_FACTORY_RESULT_SCHEMA",
    "WINDOWS_SERVICE_STATUS_SCHEMA",
    "WindowsGatedServiceRunner",
    "WindowsLiveCanaryExternalRuntimeContext",
    "WindowsLiveRuntimeProviderSourceValidation",
    "WindowsServiceError",
    "WindowsServiceFactoryContext",
    "WindowsServiceFactoryManifest",
    "WindowsServiceFactoryResult",
    "WindowsServiceStatus",
    "canonical_service_factory_contract_sha256",
    "install_signal_handlers",
    "load_reviewed_windows_live_runtime_hooks",
    "load_reviewed_windows_service_factory",
    "seal_windows_service_factory_result",
    "validate_reviewed_windows_service_factory_manifest",
    "validate_windows_live_runtime_provider_source",
]
