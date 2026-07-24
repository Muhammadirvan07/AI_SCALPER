"""Configured factory boundary for the external status-only monitor.

The secure configured-release loader is implemented in this module alongside
the typed factory contracts so a monitor release can validate every byte
before importing a reviewed provider factory.
"""

from __future__ import annotations

import builtins
from contextlib import contextmanager
from dataclasses import InitVar, dataclass, fields
import hashlib
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import sysconfig
import threading
from types import FunctionType, ModuleType
from typing import Any, Mapping
import zipfile

from .configured_service_release import (
    ConfiguredReleaseError,
    verify_configured_service_release,
)
from .contracts import (
    CanonicalContract,
    canonical_sha256,
    require_hash,
    require_text,
)
from .windows_external_status_monitor import (
    CONFIG_SCHEMA,
    MAX_LOT,
    ORDER_CAPABILITY,
    RELEASE_PROFILE,
    ExternalMonitorConfig,
    ExternalMonitorThresholds,
    ExternalStatusMonitorError,
    StatusMonitorDependencies,
    WindowsExternalStatusMonitor,
)
from .windows_external_status_monitor_factory_template import (
    MonitorProviderBinding,
    WindowsExternalStatusMonitorFactoryTemplate,
    windows_external_status_monitor_factory_contract,
)


MONITOR_FACTORY_CONTEXT_SCHEMA = (
    "windows-external-status-monitor-factory-context-v1"
)
MONITOR_FACTORY_RESULT_SCHEMA = (
    "windows-external-status-monitor-factory-result-v1"
)
GENERIC_FACTORY_MANIFEST_SCHEMA = "windows-service-factory-manifest-v1"
GENERIC_FACTORY_CONTEXT_SCHEMA = "windows-service-factory-context-v1"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
PROMOTION_ELIGIBLE = False
_FACTORY_RESULT_SEAL = object()
_FACTORY_IMPORT_SCOPE_LOCK = threading.RLock()
_FACTORY_IMPORT_AUDIT_LOCAL = threading.local()
MONITOR_RELEASE_MANIFEST_MEMBER = "RELEASE_MANIFEST.json"
MONITOR_RELEASE_MANIFEST_SCHEMA = (
    "ai-scalper-windows-status-monitor-manifest-v1"
)
CONFIGURED_BINDING_SCHEMA = (
    "windows-configured-service-release-binding-v1"
)
CONFIGURED_OVERLAY_SCHEMA = "windows-configured-service-overlay-v1"
MAX_RELEASE_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_RELEASE_TOTAL_BYTES = 128 * 1024 * 1024
MAX_RELEASE_MEMBERS = 512
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SOURCE_ENTRY_FIELDS = frozenset({"path", "sha256", "size_bytes"})
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

_CONFIG_FIELDS = frozenset(
    item.name
    for item in fields(ExternalMonitorConfig)
    if item.init
)
_THRESHOLD_FIELDS = frozenset(
    item.name
    for item in fields(ExternalMonitorThresholds)
    if item.init
)
_PROVIDER_FIELDS = frozenset(
    item.name
    for item in fields(MonitorProviderBinding)
    if item.init
)


def _nonzero_hash(name: str, value: object) -> str:
    normalized = require_hash(name, value)
    if normalized == "0" * 64:
        raise ValueError(f"{name} cannot be the zero hash")
    return normalized


def parse_windows_external_status_monitor_config(
    payload: Mapping[str, object],
) -> ExternalMonitorConfig:
    """Parse one exact canonical configuration without materialization."""

    if not isinstance(payload, Mapping) or set(payload) != _CONFIG_FIELDS:
        raise ValueError("external monitor configuration fields drift")
    values: dict[str, Any] = dict(payload)
    raw_thresholds = values.get("thresholds")
    if (
        not isinstance(raw_thresholds, Mapping)
        or set(raw_thresholds) != _THRESHOLD_FIELDS
    ):
        raise ValueError("external monitor threshold fields drift")
    values["thresholds"] = ExternalMonitorThresholds(
        **dict(raw_thresholds)
    )
    raw_providers = values.get("providers")
    if not isinstance(raw_providers, list):
        raise TypeError("external monitor providers must be a list")
    providers = []
    for raw in raw_providers:
        if not isinstance(raw, Mapping) or set(raw) != _PROVIDER_FIELDS:
            raise ValueError("external monitor provider fields drift")
        providers.append(MonitorProviderBinding(**dict(raw)))
    values["providers"] = tuple(providers)
    return ExternalMonitorConfig(**values)


def canonical_monitor_factory_contract_sha256() -> str:
    """Hash the static reviewed monitor-factory contract."""

    return canonical_sha256(
        windows_external_status_monitor_factory_contract()
    )


def canonical_monitor_configured_factory_contract_sha256(
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
    """Hash the generic configured-release factory binding."""

    payload = {
        "release_profile": require_text(
            "release_profile", release_profile
        ),
        "factory_module": require_text(
            "factory_module", factory_module
        ),
        "factory_attribute": require_text(
            "factory_attribute", factory_attribute
        ),
        "factory_relative_path": require_text(
            "factory_relative_path", factory_relative_path
        ),
        "factory_file_sha256": _nonzero_hash(
            "factory_file_sha256", factory_file_sha256
        ),
        "service_config_relative_path": require_text(
            "service_config_relative_path",
            service_config_relative_path,
        ),
        "service_config_file_sha256": _nonzero_hash(
            "service_config_file_sha256",
            service_config_file_sha256,
        ),
        "bootstrap_binding_sha256": _nonzero_hash(
            "bootstrap_binding_sha256",
            bootstrap_binding_sha256,
        ),
        "schema_version": GENERIC_FACTORY_CONTEXT_SCHEMA,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class ExternalStatusMonitorRuntimeError(RuntimeError):
    """One configured monitor runtime boundary failed closed."""

    def __init__(self, reason_code: str) -> None:
        normalized = str(reason_code or "").strip().upper()
        self.reason_code = normalized or "STATUS_MONITOR_RUNTIME_INVALID"
        super().__init__(self.reason_code)


def _sha256_bytes(value: bytes) -> str:
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
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_CANONICAL_JSON_INVALID"
        ) from exc


def _canonical_file(value: object) -> bytes:
    return _canonical_bytes(value) + b"\n"


def _strict_json_bytes(
    value: bytes,
    *,
    label: str,
    canonical: bool,
) -> dict[str, Any]:
    if (
        not isinstance(value, bytes)
        or not value
        or len(value) > MAX_RELEASE_DOCUMENT_BYTES
    ):
        raise ExternalStatusMonitorRuntimeError(
            f"STATUS_MONITOR_{label}_INVALID"
        )
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ExternalStatusMonitorRuntimeError(
            f"STATUS_MONITOR_{label}_INVALID"
        ) from exc

    def pairs_hook(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ExternalStatusMonitorRuntimeError(
                    f"STATUS_MONITOR_{label}_DUPLICATE_KEY"
                )
            result[key] = item
        return result

    def reject_constant(_value: str) -> object:
        raise ExternalStatusMonitorRuntimeError(
            f"STATUS_MONITOR_{label}_NONFINITE"
        )

    try:
        payload = json.loads(
            text,
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        )
    except ExternalStatusMonitorRuntimeError:
        raise
    except (TypeError, json.JSONDecodeError) as exc:
        raise ExternalStatusMonitorRuntimeError(
            f"STATUS_MONITOR_{label}_INVALID"
        ) from exc
    if not isinstance(payload, dict):
        raise ExternalStatusMonitorRuntimeError(
            f"STATUS_MONITOR_{label}_INVALID"
        )
    if canonical and value != _canonical_file(payload):
        raise ExternalStatusMonitorRuntimeError(
            f"STATUS_MONITOR_{label}_NOT_CANONICAL"
        )
    return payload


def _normalize_release_relative(
    value: object,
    *,
    code: str,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
    ):
        raise ExternalStatusMonitorRuntimeError(code)
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ExternalStatusMonitorRuntimeError(code)
    return value


def _source_inventory(
    value: object,
    *,
    code: str,
) -> tuple[list[dict[str, object]], dict[str, dict[str, object]]]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > MAX_RELEASE_MEMBERS
    ):
        raise ExternalStatusMonitorRuntimeError(code)
    entries: list[dict[str, object]] = []
    inventory: dict[str, dict[str, object]] = {}
    folded: set[str] = set()
    total = 0
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != _SOURCE_ENTRY_FIELDS:
            raise ExternalStatusMonitorRuntimeError(code)
        path = _normalize_release_relative(raw.get("path"), code=code)
        size = raw.get("size_bytes")
        try:
            digest = _nonzero_hash("release member sha256", raw.get("sha256"))
        except (TypeError, ValueError) as exc:
            raise ExternalStatusMonitorRuntimeError(code) from exc
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or path in inventory
            or path.casefold() in folded
        ):
            raise ExternalStatusMonitorRuntimeError(code)
        total += size
        if total > MAX_RELEASE_TOTAL_BYTES:
            raise ExternalStatusMonitorRuntimeError(code)
        item = {"path": path, "size_bytes": size, "sha256": digest}
        entries.append(item)
        inventory[path] = item
        folded.add(path.casefold())
    if [item["path"] for item in entries] != sorted(inventory):
        raise ExternalStatusMonitorRuntimeError(code)
    return entries, inventory


def _reject_release_path_indirection(path: Path) -> None:
    absolute = path.expanduser().absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise ExternalStatusMonitorRuntimeError(
                "STATUS_MONITOR_RELEASE_PATH_UNAVAILABLE"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or int(
            getattr(metadata, "st_file_attributes", 0)
        ) & 0x400:
            raise ExternalStatusMonitorRuntimeError(
                "STATUS_MONITOR_RELEASE_PATH_INDIRECTION_DENIED"
            )


def _require_release_root(value: str | Path) -> Path:
    configured = Path(value).expanduser().absolute()
    _reject_release_path_indirection(configured)
    try:
        metadata = configured.stat(follow_symlinks=False)
        resolved = configured.resolve(strict=True)
    except OSError as exc:
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_RELEASE_ROOT_UNAVAILABLE"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_RELEASE_ROOT_INVALID"
        )
    return resolved


def _read_release_bytes(
    path: Path,
    *,
    label: str,
    maximum: int = MAX_RELEASE_DOCUMENT_BYTES,
) -> bytes:
    _reject_release_path_indirection(path)
    try:
        before = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ExternalStatusMonitorRuntimeError(
                f"STATUS_MONITOR_{label}_INVALID"
            )
        with path.open("rb") as handle:
            opened_before = os.fstat(handle.fileno())
            payload = handle.read(maximum + 1)
            opened_after = os.fstat(handle.fileno())
        after = path.stat(follow_symlinks=False)
    except ExternalStatusMonitorRuntimeError:
        raise
    except OSError as exc:
        raise ExternalStatusMonitorRuntimeError(
            f"STATUS_MONITOR_{label}_READ_FAILED"
        ) from exc

    def identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
        return (
            int(value.st_dev),
            int(value.st_ino),
            int(value.st_mode),
            int(value.st_size),
            int(value.st_mtime_ns),
            int(getattr(value, "st_file_attributes", 0)),
        )

    expected = identity(before)
    if (
        len(payload) > maximum
        or len(payload) != before.st_size
        or identity(opened_before) != expected
        or identity(opened_after) != expected
        or identity(after) != expected
        or not stat.S_ISREG(after.st_mode)
    ):
        raise ExternalStatusMonitorRuntimeError(
            f"STATUS_MONITOR_{label}_CHANGED_DURING_READ"
        )
    return payload


def _collect_exact_release_root(root: Path) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    folded: set[str] = set()
    total = 0
    for current, directories, files in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        current_path = Path(current)
        for directory in tuple(directories):
            candidate = current_path / directory
            _reject_release_path_indirection(candidate)
            try:
                metadata = candidate.stat(follow_symlinks=False)
            except OSError as exc:
                raise ExternalStatusMonitorRuntimeError(
                    "STATUS_MONITOR_RELEASE_PATH_UNAVAILABLE"
                ) from exc
            if not stat.S_ISDIR(metadata.st_mode):
                raise ExternalStatusMonitorRuntimeError(
                    "STATUS_MONITOR_RELEASE_MEMBER_NOT_REGULAR"
                )
        for filename in files:
            candidate = current_path / filename
            relative = candidate.relative_to(root).as_posix()
            normalized = _normalize_release_relative(
                relative,
                code="STATUS_MONITOR_RELEASE_PATH_INVALID",
            )
            if (
                normalized in members
                or normalized.casefold() in folded
                or len(members) >= MAX_RELEASE_MEMBERS
            ):
                raise ExternalStatusMonitorRuntimeError(
                    "STATUS_MONITOR_RELEASE_MEMBER_COLLISION"
                )
            payload = _read_release_bytes(
                candidate,
                label="RELEASE_MEMBER",
                maximum=MAX_RELEASE_TOTAL_BYTES,
            )
            total += len(payload)
            if total > MAX_RELEASE_TOTAL_BYTES:
                raise ExternalStatusMonitorRuntimeError(
                    "STATUS_MONITOR_RELEASE_TOTAL_SIZE_EXCEEDED"
                )
            members[normalized] = payload
            folded.add(normalized.casefold())
    if MONITOR_RELEASE_MANIFEST_MEMBER not in members:
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_RELEASE_MANIFEST_MISSING"
        )
    return members


def _verify_exact_release_directories(
    root: Path,
    *,
    expected_members: set[str],
) -> None:
    expected_directories: set[str] = set()
    for member in expected_members:
        parent = PurePosixPath(member).parent
        while parent.as_posix() not in {"", "."}:
            expected_directories.add(parent.as_posix().casefold())
            parent = parent.parent
    observed: set[str] = set()
    for current, directories, _files in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        current_path = Path(current)
        for directory in tuple(directories):
            candidate = current_path / directory
            _reject_release_path_indirection(candidate)
            relative = candidate.relative_to(root).as_posix().casefold()
            if (
                relative not in expected_directories
                or relative in observed
            ):
                raise ExternalStatusMonitorRuntimeError(
                    "STATUS_MONITOR_RELEASE_EXTRA_MEMBER"
                )
            observed.add(relative)
    if observed != expected_directories:
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_RELEASE_INVENTORY_INVALID"
        )


def _deterministic_archive(
    sources: Mapping[str, bytes],
    manifest: bytes,
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for name, data in (
            *sorted(sources.items()),
            (MONITOR_RELEASE_MANIFEST_MEMBER, manifest),
        ):
            info = zipfile.ZipInfo(name, FIXED_ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data)
    return output.getvalue()


def _release_file(root: Path, relative: str, *, suffix: str) -> Path:
    normalized = _normalize_release_relative(
        relative,
        code="STATUS_MONITOR_RELEASE_PATH_INVALID",
    )
    if PurePosixPath(normalized).suffix != suffix:
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_RELEASE_PATH_INVALID"
        )
    candidate = root / normalized
    _reject_release_path_indirection(candidate)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        metadata = resolved.stat(follow_symlinks=False)
    except (OSError, ValueError) as exc:
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_RELEASE_FILE_UNAVAILABLE"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_RELEASE_FILE_NOT_REGULAR"
        )
    return resolved


@dataclass(frozen=True)
class WindowsExternalStatusMonitorFactoryManifest(CanonicalContract):
    release_profile: str
    factory_module: str
    factory_attribute: str
    factory_relative_path: str
    factory_file_sha256: str
    service_config_relative_path: str
    service_config_file_sha256: str
    bootstrap_binding_sha256: str
    factory_contract_sha256: str
    schema_version: str = GENERIC_FACTORY_MANIFEST_SCHEMA

    def __post_init__(self) -> None:
        if self.release_profile != RELEASE_PROFILE:
            raise ValueError("external monitor factory profile drift")
        module = require_text("factory_module", self.factory_module)
        attribute = require_text(
            "factory_attribute", self.factory_attribute
        )
        if (
            _MODULE_RE.fullmatch(module) is None
            or _MODULE_RE.fullmatch(attribute) is None
        ):
            raise ValueError("external monitor factory symbol is invalid")
        object.__setattr__(self, "factory_module", module)
        object.__setattr__(self, "factory_attribute", attribute)
        factory_path = _normalize_release_relative(
            self.factory_relative_path,
            code="STATUS_MONITOR_FACTORY_MANIFEST_INVALID",
        )
        config_path = _normalize_release_relative(
            self.service_config_relative_path,
            code="STATUS_MONITOR_FACTORY_MANIFEST_INVALID",
        )
        if (
            PurePosixPath(factory_path).parent.as_posix() != "."
            or PurePosixPath(factory_path).suffix != ".py"
            or PurePosixPath(factory_path).stem != module
            or PurePosixPath(config_path).suffix != ".json"
            or PurePosixPath(config_path).parts[0] != "config"
        ):
            raise ValueError("external monitor factory paths are invalid")
        object.__setattr__(self, "factory_relative_path", factory_path)
        object.__setattr__(
            self, "service_config_relative_path", config_path
        )
        for name in (
            "factory_file_sha256",
            "service_config_file_sha256",
            "bootstrap_binding_sha256",
            "factory_contract_sha256",
        ):
            object.__setattr__(
                self,
                name,
                _nonzero_hash(name, getattr(self, name)),
            )
        expected = canonical_monitor_configured_factory_contract_sha256(
            release_profile=self.release_profile,
            factory_module=self.factory_module,
            factory_attribute=self.factory_attribute,
            factory_relative_path=self.factory_relative_path,
            factory_file_sha256=self.factory_file_sha256,
            service_config_relative_path=(
                self.service_config_relative_path
            ),
            service_config_file_sha256=(
                self.service_config_file_sha256
            ),
            bootstrap_binding_sha256=self.bootstrap_binding_sha256,
        )
        if self.factory_contract_sha256 != expected:
            raise ValueError(
                "external monitor configured factory contract drift"
            )
        if self.schema_version != GENERIC_FACTORY_MANIFEST_SCHEMA:
            raise ValueError("external monitor factory manifest schema drift")


@dataclass(frozen=True)
class WindowsExternalStatusMonitorFactoryContext(CanonicalContract):
    release_identity_sha256: str
    factory_contract_sha256: str
    factory_file_sha256: str
    service_config_file_sha256: str
    bootstrap_binding_sha256: str
    provider_template_sha256: str
    release_profile: str = RELEASE_PROFILE
    status_only: bool = True
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    max_lot: float = MAX_LOT
    schema_version: str = MONITOR_FACTORY_CONTEXT_SCHEMA

    def __post_init__(self) -> None:
        for name in (
            "release_identity_sha256",
            "factory_contract_sha256",
            "factory_file_sha256",
            "service_config_file_sha256",
            "bootstrap_binding_sha256",
            "provider_template_sha256",
        ):
            object.__setattr__(
                self,
                name,
                _nonzero_hash(name, getattr(self, name)),
            )
        if self.release_profile != RELEASE_PROFILE:
            raise ValueError("external monitor factory context profile drift")
        if (
            self.status_only is not True
            or self.order_capability != ORDER_CAPABILITY
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or self.promotion_eligible is not False
            or self.max_lot != MAX_LOT
        ):
            raise ValueError("external monitor factory context safety drift")
        if self.schema_version != MONITOR_FACTORY_CONTEXT_SCHEMA:
            raise ValueError("external monitor factory context schema drift")


@dataclass(frozen=True)
class WindowsExternalStatusMonitorFactoryResult:
    monitor: WindowsExternalStatusMonitor
    service_id: str
    bootstrap_binding_sha256: str
    factory_contract_sha256: str
    service_config_file_sha256: str
    provider_template_sha256: str
    status_only: bool = True
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    max_lot: float = MAX_LOT
    schema_version: str = MONITOR_FACTORY_RESULT_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _FACTORY_RESULT_SEAL:
            raise TypeError(
                "external monitor factory results require sealing factory"
            )
        if type(self.monitor) is not WindowsExternalStatusMonitor:
            raise TypeError(
                "monitor must be exact WindowsExternalStatusMonitor"
            )
        object.__setattr__(
            self,
            "service_id",
            require_text("service_id", self.service_id),
        )
        for name in (
            "bootstrap_binding_sha256",
            "factory_contract_sha256",
            "service_config_file_sha256",
            "provider_template_sha256",
        ):
            object.__setattr__(
                self,
                name,
                _nonzero_hash(name, getattr(self, name)),
            )
        if (
            self.status_only is not True
            or self.order_capability != ORDER_CAPABILITY
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or self.promotion_eligible is not False
            or self.max_lot != MAX_LOT
        ):
            raise ValueError("external monitor factory result safety drift")
        if self.schema_version != MONITOR_FACTORY_RESULT_SCHEMA:
            raise ValueError("external monitor factory result schema drift")


def seal_windows_external_status_monitor_factory_result(
    *,
    runtime_config: ExternalMonitorConfig,
    provider_template: WindowsExternalStatusMonitorFactoryTemplate,
    context: WindowsExternalStatusMonitorFactoryContext,
    dependencies: StatusMonitorDependencies,
) -> WindowsExternalStatusMonitorFactoryResult:
    """Seal one exact configured monitor without running a cycle."""

    if type(runtime_config) is not ExternalMonitorConfig:
        raise TypeError("runtime_config must be exact ExternalMonitorConfig")
    if type(provider_template) is not (
        WindowsExternalStatusMonitorFactoryTemplate
    ):
        raise TypeError(
            "provider_template must be exact "
            "WindowsExternalStatusMonitorFactoryTemplate"
        )
    if type(context) is not WindowsExternalStatusMonitorFactoryContext:
        raise TypeError(
            "context must be exact "
            "WindowsExternalStatusMonitorFactoryContext"
        )
    if type(dependencies) is not StatusMonitorDependencies:
        raise TypeError(
            "dependencies must be exact StatusMonitorDependencies"
        )
    if (
        runtime_config.content_sha256
        != context.bootstrap_binding_sha256
        or provider_template.service_id
        != runtime_config.monitor_service_id
        or provider_template.monitor_provider_id
        != runtime_config.monitor_provider_id
        or provider_template.release_identity_sha256
        != context.release_identity_sha256
        or provider_template.factory_implementation_sha256
        != context.factory_file_sha256
        or provider_template.factory_configuration_sha256
        != context.service_config_file_sha256
        or provider_template.providers != runtime_config.providers
        or provider_template.content_sha256
        != context.provider_template_sha256
    ):
        raise ExternalStatusMonitorError(
            "MONITOR_FACTORY_RESULT_BINDING_MISMATCH"
        )
    monitor = WindowsExternalStatusMonitor(
        runtime_config,
        dependencies,
    )
    return WindowsExternalStatusMonitorFactoryResult(
        monitor=monitor,
        service_id=runtime_config.monitor_service_id,
        bootstrap_binding_sha256=runtime_config.content_sha256,
        factory_contract_sha256=context.factory_contract_sha256,
        service_config_file_sha256=(
            context.service_config_file_sha256
        ),
        provider_template_sha256=context.provider_template_sha256,
        _seal=_FACTORY_RESULT_SEAL,
    )


def _verify_configured_monitor_release(
    *,
    root: Path,
    expected_release_identity_sha256: str,
) -> tuple[
    dict[str, Any],
    dict[str, dict[str, object]],
    dict[str, object],
    dict[str, object],
]:
    try:
        expected_identity = _nonzero_hash(
            "expected_release_identity_sha256",
            expected_release_identity_sha256,
        )
    except (TypeError, ValueError) as exc:
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_EXPECTED_RELEASE_IDENTITY_INVALID"
        ) from exc
    members = _collect_exact_release_root(root)
    manifest_bytes = members[MONITOR_RELEASE_MANIFEST_MEMBER]
    manifest = _strict_json_bytes(
        manifest_bytes,
        label="RELEASE_MANIFEST",
        canonical=True,
    )
    if (
        manifest.get("schema_version")
        != MONITOR_RELEASE_MANIFEST_SCHEMA
        or manifest.get("release_profile") != RELEASE_PROFILE
        or manifest.get("safety")
        != {
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "max_lot": 0.01,
            "order_capability": "DISABLED",
        }
        or manifest.get("production_execution_ready") is not False
        or manifest.get("release_identity_sha256") != expected_identity
    ):
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_RELEASE_MANIFEST_INVALID"
        )
    source_entries, inventory = _source_inventory(
        manifest.get("source_files"),
        code="STATUS_MONITOR_RELEASE_INVENTORY_INVALID",
    )
    if set(members) != {
        *inventory,
        MONITOR_RELEASE_MANIFEST_MEMBER,
    }:
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_RELEASE_EXTRA_MEMBER"
        )
    _verify_exact_release_directories(
        root,
        expected_members=set(members),
    )
    sources: dict[str, bytes] = {}
    for item in source_entries:
        path = str(item["path"])
        data = members[path]
        if (
            len(data) != item["size_bytes"]
            or _sha256_bytes(data) != item["sha256"]
        ):
            raise ExternalStatusMonitorRuntimeError(
                "STATUS_MONITOR_RELEASE_MEMBER_HASH_MISMATCH"
            )
        sources[path] = data
    unsigned = dict(manifest)
    unsigned.pop("release_identity_sha256", None)
    if _sha256_bytes(_canonical_bytes(unsigned)) != expected_identity:
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_RELEASE_IDENTITY_MISMATCH"
        )
    archive = _deterministic_archive(sources, manifest_bytes)
    try:
        report = verify_configured_service_release(
            archive,
            expected_release_identity_sha256=expected_identity,
        )
    except ConfiguredReleaseError as exc:
        raise ExternalStatusMonitorRuntimeError(
            f"STATUS_MONITOR_CONFIGURED_RELEASE_{exc.reason_code}"
        ) from exc
    if (
        report.release_profile != RELEASE_PROFILE
        or report.release_identity_sha256 != expected_identity
        or report.order_capability != ORDER_CAPABILITY
        or report.production_execution_ready is not False
    ):
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_CONFIGURED_RELEASE_INVALID"
        )
    raw_binding = manifest.get("configured_release")
    if not isinstance(raw_binding, Mapping):
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_CONFIGURED_BINDING_MISSING"
        )
    binding = dict(raw_binding)
    if (
        binding.get("schema_version") != CONFIGURED_BINDING_SCHEMA
        or binding.get("base_release_profile") != RELEASE_PROFILE
        or binding.get("factory_contract_sha256")
        != report.factory_contract_sha256
        or binding.get("live_allowed") is not False
        or binding.get("safe_to_demo_auto_order") is not False
        or binding.get("max_lot") != MAX_LOT
        or binding.get("provider_materialization_performed") is not False
        or binding.get("credential_access_performed") is not False
        or binding.get("task_installation_performed") is not False
        or binding.get("broker_mutation_performed") is not False
    ):
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_CONFIGURED_BINDING_INVALID"
        )
    raw_descriptor = binding.get("overlay_descriptor")
    if not isinstance(raw_descriptor, Mapping):
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_CONFIGURED_DESCRIPTOR_INVALID"
        )
    descriptor = dict(raw_descriptor)
    if (
        descriptor.get("schema_version") != CONFIGURED_OVERLAY_SCHEMA
        or descriptor.get("base_release_profile") != RELEASE_PROFILE
        or descriptor.get("runtime_mode") not in {"DEMO", "DEMO_AUTO"}
        or descriptor.get("reviewed_factory_template_sha256")
        != canonical_monitor_factory_contract_sha256()
        or descriptor.get("factory_manifest_relative_path")
        != binding.get("factory_manifest_relative_path")
        or descriptor.get("factory_source_relative_path")
        != binding.get("factory_source_relative_path")
        or descriptor.get("service_config_relative_path")
        != binding.get("service_config_relative_path")
    ):
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_CONFIGURED_DESCRIPTOR_INVALID"
        )
    return manifest, inventory, binding, descriptor


def validate_reviewed_windows_external_status_monitor_factory_manifest(
    *,
    release_root: str | Path,
    manifest_path: str | Path,
    expected_release_identity_sha256: str,
) -> tuple[
    WindowsExternalStatusMonitorFactoryManifest,
    ExternalMonitorConfig,
    WindowsExternalStatusMonitorFactoryContext,
]:
    """Validate an exact configured monitor without importing providers."""

    root = _require_release_root(release_root)
    (
        release_manifest,
        inventory,
        binding,
        descriptor,
    ) = _verify_configured_monitor_release(
        root=root,
        expected_release_identity_sha256=(
            expected_release_identity_sha256
        ),
    )
    configured_manifest = Path(manifest_path).expanduser().absolute()
    try:
        _reject_release_path_indirection(configured_manifest)
        relative = (
            configured_manifest.resolve(strict=True)
            .relative_to(root)
            .as_posix()
        )
    except (
        ExternalStatusMonitorRuntimeError,
        OSError,
        ValueError,
    ) as exc:
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_FACTORY_MANIFEST_NOT_RELEASE_BOUND"
        ) from exc
    if (
        relative != binding.get("factory_manifest_relative_path")
        or relative != descriptor.get("factory_manifest_relative_path")
    ):
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_FACTORY_MANIFEST_NOT_RELEASE_BOUND"
        )
    raw_manifest = _read_release_bytes(
        configured_manifest,
        label="FACTORY_MANIFEST",
    )
    payload = _strict_json_bytes(
        raw_manifest,
        label="FACTORY_MANIFEST",
        canonical=True,
    )
    if set(payload) != _FACTORY_MANIFEST_FIELDS:
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_FACTORY_MANIFEST_INVALID"
        )
    try:
        factory_manifest = (
            WindowsExternalStatusMonitorFactoryManifest(**payload)
        )
    except (TypeError, ValueError) as exc:
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_FACTORY_MANIFEST_INVALID"
        ) from exc
    if (
        factory_manifest.factory_relative_path
        != binding.get("factory_source_relative_path")
        or factory_manifest.service_config_relative_path
        != binding.get("service_config_relative_path")
        or factory_manifest.factory_contract_sha256
        != binding.get("factory_contract_sha256")
        or factory_manifest.bootstrap_binding_sha256
        != binding.get("bootstrap_binding_sha256")
    ):
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_FACTORY_MANIFEST_BINDING_MISMATCH"
        )
    bound = {
        relative: _sha256_bytes(raw_manifest),
        factory_manifest.factory_relative_path: (
            factory_manifest.factory_file_sha256
        ),
        factory_manifest.service_config_relative_path: (
            factory_manifest.service_config_file_sha256
        ),
    }
    if any(
        not isinstance(inventory.get(path), Mapping)
        or inventory[path].get("sha256") != digest
        for path, digest in bound.items()
    ):
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_FACTORY_MEMBER_NOT_RELEASE_BOUND"
        )
    factory_file = _release_file(
        root,
        factory_manifest.factory_relative_path,
        suffix=".py",
    )
    config_file = _release_file(
        root,
        factory_manifest.service_config_relative_path,
        suffix=".json",
    )
    if (
        _sha256_bytes(
            _read_release_bytes(factory_file, label="FACTORY_SOURCE")
        )
        != factory_manifest.factory_file_sha256
    ):
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_FACTORY_SOURCE_HASH_MISMATCH"
        )
    config_bytes = _read_release_bytes(
        config_file,
        label="SERVICE_CONFIG",
    )
    if (
        _sha256_bytes(config_bytes)
        != factory_manifest.service_config_file_sha256
    ):
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_SERVICE_CONFIG_HASH_MISMATCH"
        )
    config_payload = _strict_json_bytes(
        config_bytes,
        label="SERVICE_CONFIG",
        canonical=True,
    )
    try:
        runtime_config = (
            parse_windows_external_status_monitor_config(config_payload)
        )
    except (TypeError, ValueError) as exc:
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_SERVICE_CONFIG_INVALID"
        ) from exc
    if (
        runtime_config.content_sha256
        != factory_manifest.bootstrap_binding_sha256
    ):
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_BOOTSTRAP_BINDING_MISMATCH"
        )
    release_identity = str(
        release_manifest["release_identity_sha256"]
    )
    provider_template = runtime_config.factory_template(
        release_identity_sha256=release_identity,
        factory_implementation_sha256=(
            factory_manifest.factory_file_sha256
        ),
        factory_configuration_sha256=(
            factory_manifest.service_config_file_sha256
        ),
    )
    context = WindowsExternalStatusMonitorFactoryContext(
        release_identity_sha256=release_identity,
        factory_contract_sha256=(
            factory_manifest.factory_contract_sha256
        ),
        factory_file_sha256=factory_manifest.factory_file_sha256,
        service_config_file_sha256=(
            factory_manifest.service_config_file_sha256
        ),
        bootstrap_binding_sha256=runtime_config.content_sha256,
        provider_template_sha256=provider_template.content_sha256,
    )
    return factory_manifest, runtime_config, context


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _reviewed_factory_sys_path(
    root: Path,
    current: list[str],
) -> list[str]:
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
        folded = {part.casefold() for part in resolved.parts}
        if folded.intersection({"site-packages", "dist-packages"}):
            continue
        if any(_is_relative_to(resolved, base) for base in stdlib_roots):
            reviewed.append(str(resolved))
    return list(dict.fromkeys(reviewed))


def _verify_imported_module_origins(
    *,
    release_root: Path,
    inventory: Mapping[str, Mapping[str, object]],
    modules: set[ModuleType],
) -> None:
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
                raise ExternalStatusMonitorRuntimeError(
                    "STATUS_MONITOR_FACTORY_IMPORT_ORIGIN_INVALID"
                )
            for namespace_path in namespace_paths:
                try:
                    resolved = Path(namespace_path).resolve(strict=True)
                except (OSError, TypeError) as exc:
                    raise ExternalStatusMonitorRuntimeError(
                        "STATUS_MONITOR_FACTORY_IMPORT_ORIGIN_INVALID"
                    ) from exc
                folded = {part.casefold() for part in resolved.parts}
                if folded.intersection(
                    {"site-packages", "dist-packages"}
                ) or not (
                    _is_relative_to(resolved, release_root)
                    or any(
                        _is_relative_to(resolved, root)
                        for root in stdlib_roots
                    )
                ):
                    raise ExternalStatusMonitorRuntimeError(
                        "STATUS_MONITOR_FACTORY_IMPORT_ORIGIN_DENIED"
                    )
            continue
        try:
            path = Path(origin).resolve(strict=True)
        except (OSError, TypeError) as exc:
            raise ExternalStatusMonitorRuntimeError(
                "STATUS_MONITOR_FACTORY_IMPORT_ORIGIN_INVALID"
            ) from exc
        if _is_relative_to(path, release_root):
            relative = path.relative_to(release_root).as_posix()
            item = inventory.get(relative)
            if not isinstance(item, Mapping):
                raise ExternalStatusMonitorRuntimeError(
                    "STATUS_MONITOR_FACTORY_IMPORT_NOT_RELEASE_BOUND"
                )
            payload = _read_release_bytes(
                path,
                label="IMPORTED_MODULE",
            )
            if (
                len(payload) != item.get("size_bytes")
                or _sha256_bytes(payload) != item.get("sha256")
            ):
                raise ExternalStatusMonitorRuntimeError(
                    "STATUS_MONITOR_FACTORY_IMPORT_HASH_MISMATCH"
                )
            continue
        folded = {part.casefold() for part in path.parts}
        if folded.intersection(
            {"site-packages", "dist-packages"}
        ) or not any(
            _is_relative_to(path, root) for root in stdlib_roots
        ):
            raise ExternalStatusMonitorRuntimeError(
                "STATUS_MONITOR_FACTORY_IMPORT_ORIGIN_DENIED"
            )


def _snapshot_module_registry() -> dict[str, tuple[int, bool]]:
    return {
        name: (id(value), type(value) is ModuleType)
        for name, value in tuple(sys.modules.items())
        if isinstance(name, str)
    }


def _factory_dynamic_loader_denied(
    *_args: object,
    **_kwargs: object,
) -> object:
    raise ExternalStatusMonitorRuntimeError(
        "STATUS_MONITOR_FACTORY_DYNAMIC_LOADER_DENIED"
    )


@contextmanager
def _reviewed_import_scope(
    *,
    release_root: Path,
    inventory: Mapping[str, Mapping[str, object]],
):
    original_import = builtins.__import__
    original_import_module = importlib.import_module
    original_reload = importlib.reload
    guarded_util_names = (
        "find_spec",
        "module_from_spec",
        "spec_from_file_location",
        "spec_from_loader",
    )
    original_util = {
        name: getattr(importlib.util, name) for name in guarded_util_names
    }
    registry_before = _snapshot_module_registry()
    tracked_modules: set[ModuleType] = set()

    def attest(modules: set[ModuleType]) -> None:
        _verify_imported_module_origins(
            release_root=release_root,
            inventory=inventory,
            modules=modules,
        )
        tracked_modules.update(modules)

    def reviewed_import(
        name: str,
        globals_: Mapping[str, Any] | None = None,
        locals_: Mapping[str, Any] | None = None,
        fromlist: tuple[str, ...] | list[str] = (),
        level: int = 0,
    ) -> object:
        imported = original_import(
            name,
            globals_,
            locals_,
            fromlist,
            level,
        )
        modules: set[ModuleType] = set()
        if type(imported) is ModuleType:
            modules.add(imported)
        for member in tuple(fromlist or ()):
            if not isinstance(member, str) or member == "*":
                continue
            candidate = getattr(imported, member, None)
            if type(candidate) is ModuleType:
                modules.add(candidate)
        attest(modules)
        return imported

    def reviewed_import_module(
        name: str,
        package: str | None = None,
    ) -> ModuleType:
        imported = original_import_module(name, package)
        if type(imported) is not ModuleType:
            raise ExternalStatusMonitorRuntimeError(
                "STATUS_MONITOR_FACTORY_IMPORT_RESULT_INVALID"
            )
        attest({imported})
        return imported

    def reviewed_reload(module: ModuleType) -> ModuleType:
        if type(module) is not ModuleType:
            raise ExternalStatusMonitorRuntimeError(
                "STATUS_MONITOR_FACTORY_IMPORT_RESULT_INVALID"
            )
        attest({module})
        imported = original_reload(module)
        if type(imported) is not ModuleType:
            raise ExternalStatusMonitorRuntimeError(
                "STATUS_MONITOR_FACTORY_IMPORT_RESULT_INVALID"
            )
        attest({imported})
        return imported

    with _FACTORY_IMPORT_SCOPE_LOCK:
        builtins.__import__ = reviewed_import
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
                    or importlib.import_module is not reviewed_import_module
                    or importlib.reload is not reviewed_reload
                    or any(
                        getattr(importlib.util, name)
                        is not _factory_dynamic_loader_denied
                        for name in guarded_util_names
                    )
                ):
                    raise ExternalStatusMonitorRuntimeError(
                        "STATUS_MONITOR_FACTORY_IMPORT_GUARD_MUTATED"
                    )
                current = {
                    name: value
                    for name, value in tuple(sys.modules.items())
                    if isinstance(name, str)
                }
                if any(name not in current for name in registry_before):
                    raise ExternalStatusMonitorRuntimeError(
                        "STATUS_MONITOR_FACTORY_MODULE_REGISTRY_MUTATED"
                    )
                added: set[ModuleType] = set()
                for name, value in current.items():
                    previous = registry_before.get(name)
                    if previous is not None:
                        if previous != (
                            id(value),
                            type(value) is ModuleType,
                        ):
                            raise ExternalStatusMonitorRuntimeError(
                                "STATUS_MONITOR_FACTORY_MODULE_REGISTRY_MUTATED"
                            )
                    elif type(value) is ModuleType:
                        added.add(value)
                    else:
                        raise ExternalStatusMonitorRuntimeError(
                            "STATUS_MONITOR_FACTORY_MODULE_REGISTRY_INVALID"
                        )
                _verify_imported_module_origins(
                    release_root=release_root,
                    inventory=inventory,
                    modules={*tracked_modules, *added},
                )
            except BaseException as exc:
                validation_error = exc
            finally:
                builtins.__import__ = original_import
                importlib.import_module = original_import_module
                importlib.reload = original_reload
                for name, value in original_util.items():
                    setattr(importlib.util, name, value)
            if validation_error is not None:
                raise validation_error


def _load_exact_monitor_factory_module(
    *,
    manifest: WindowsExternalStatusMonitorFactoryManifest,
    factory_file: Path,
    release_root: Path,
    inventory: Mapping[str, Mapping[str, object]],
) -> ModuleType:
    if manifest.factory_module in sys.modules:
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_FACTORY_MODULE_PRELOADED"
        )
    spec = importlib.util.spec_from_file_location(
        manifest.factory_module,
        factory_file,
    )
    if (
        spec is None
        or spec.loader is None
        or spec.origin is None
        or Path(spec.origin).resolve(strict=True) != factory_file
    ):
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_FACTORY_MODULE_SPEC_INVALID"
        )
    namespace = importlib.util.module_from_spec(spec)
    original_sys_path = list(sys.path)
    original_dont_write_bytecode = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        sys.path[:] = _reviewed_factory_sys_path(
            release_root,
            original_sys_path,
        )
        with _reviewed_import_scope(
            release_root=release_root,
            inventory=inventory,
        ):
            spec.loader.exec_module(namespace)
    except ExternalStatusMonitorRuntimeError:
        raise
    except ModuleNotFoundError as exc:
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_FACTORY_IMPORT_ORIGIN_DENIED"
        ) from exc
    except Exception as exc:
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_FACTORY_MODULE_LOAD_FAILED"
        ) from exc
    finally:
        sys.path[:] = original_sys_path
        sys.dont_write_bytecode = original_dont_write_bytecode
    if (
        type(namespace) is not ModuleType
        or namespace.__name__ != manifest.factory_module
    ):
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_FACTORY_MODULE_INVALID"
        )
    referenced = {
        value
        for value in namespace.__dict__.values()
        if type(value) is ModuleType
    }
    _verify_imported_module_origins(
        release_root=release_root,
        inventory=inventory,
        modules=referenced,
    )
    return namespace


def load_reviewed_windows_external_status_monitor_factory(
    *,
    release_root: str | Path,
    manifest_path: str | Path,
    expected_release_identity_sha256: str,
) -> tuple[
    WindowsExternalStatusMonitorFactoryManifest,
    ExternalMonitorConfig,
    WindowsExternalStatusMonitorFactoryResult,
]:
    """Import and invoke one exact configured external-monitor factory."""

    root = _require_release_root(release_root)
    _release_manifest, inventory, _binding, _descriptor = (
        _verify_configured_monitor_release(
            root=root,
            expected_release_identity_sha256=(
                expected_release_identity_sha256
            ),
        )
    )
    manifest, runtime_config, context = (
        validate_reviewed_windows_external_status_monitor_factory_manifest(
            release_root=root,
            manifest_path=manifest_path,
            expected_release_identity_sha256=(
                expected_release_identity_sha256
            ),
        )
    )
    factory_file = _release_file(
        root,
        manifest.factory_relative_path,
        suffix=".py",
    )
    config_file = _release_file(
        root,
        manifest.service_config_relative_path,
        suffix=".json",
    )

    def assert_stable() -> None:
        if (
            _sha256_bytes(
                _read_release_bytes(
                    factory_file,
                    label="FACTORY_SOURCE",
                )
            )
            != manifest.factory_file_sha256
            or _sha256_bytes(
                _read_release_bytes(
                    config_file,
                    label="SERVICE_CONFIG",
                )
            )
            != manifest.service_config_file_sha256
        ):
            raise ExternalStatusMonitorRuntimeError(
                "STATUS_MONITOR_FACTORY_OR_CONFIG_CHANGED"
            )

    assert_stable()
    namespace = _load_exact_monitor_factory_module(
        manifest=manifest,
        factory_file=factory_file,
        release_root=root,
        inventory=inventory,
    )
    factory = getattr(namespace, manifest.factory_attribute, None)
    if (
        type(factory) is not FunctionType
        or factory.__module__ != manifest.factory_module
    ):
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_FACTORY_CALLABLE_INVALID"
        )
    assert_stable()
    original_sys_path = list(sys.path)
    sys.path[:] = _reviewed_factory_sys_path(root, original_sys_path)
    try:
        with _reviewed_import_scope(
            release_root=root,
            inventory=inventory,
        ):
            result = factory(runtime_config, context)
    except ExternalStatusMonitorRuntimeError:
        raise
    except Exception as exc:
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_FACTORY_CALL_FAILED"
        ) from exc
    finally:
        sys.path[:] = original_sys_path
    assert_stable()
    if type(result) is not WindowsExternalStatusMonitorFactoryResult:
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_FACTORY_RESULT_NOT_SEALED"
        )
    if (
        result.service_id != runtime_config.monitor_service_id
        or result.bootstrap_binding_sha256
        != runtime_config.content_sha256
        or result.factory_contract_sha256
        != manifest.factory_contract_sha256
        or result.service_config_file_sha256
        != manifest.service_config_file_sha256
        or result.provider_template_sha256
        != context.provider_template_sha256
        or result.monitor.config != runtime_config
    ):
        raise ExternalStatusMonitorRuntimeError(
            "STATUS_MONITOR_FACTORY_RESULT_BINDING_MISMATCH"
        )
    return manifest, runtime_config, result


__all__ = [
    "ExternalStatusMonitorRuntimeError",
    "GENERIC_FACTORY_MANIFEST_SCHEMA",
    "MONITOR_FACTORY_CONTEXT_SCHEMA",
    "MONITOR_FACTORY_RESULT_SCHEMA",
    "WindowsExternalStatusMonitorFactoryContext",
    "WindowsExternalStatusMonitorFactoryManifest",
    "WindowsExternalStatusMonitorFactoryResult",
    "canonical_monitor_configured_factory_contract_sha256",
    "canonical_monitor_factory_contract_sha256",
    "load_reviewed_windows_external_status_monitor_factory",
    "parse_windows_external_status_monitor_config",
    "seal_windows_external_status_monitor_factory_result",
    "validate_reviewed_windows_external_status_monitor_factory_manifest",
]
