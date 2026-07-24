"""Fail-closed runtime primitives for the Windows decision-only service.

This module owns no broker, account, risk, permit, reconciliation, or order
surface.  A reviewed release-local factory may only return an exact sealed
``BrokerlessDecisionProducerService`` bound to the immutable runtime
configuration and factory context defined here.
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
import math
import os
from pathlib import Path, PurePosixPath
import queue
import re
import signal
import stat
import sys
import sysconfig
import threading
from types import FunctionType, ModuleType
from typing import Any, Mapping
import zipfile

from .brokerless_decision_producer import (
    BrokerlessDecisionProducerService,
    DecisionProducerBinding,
    DecisionProducerCycleResult,
    DecisionProducerLaneConfig,
)
from .contracts import (
    CanonicalContract,
    canonical_sha256,
    require_hash,
    require_int,
    require_text,
)
from .windows_decision_service_factory_template import (
    DecisionServiceProviderBinding,
    RELEASE_PROFILE,
    WindowsDecisionServiceFactoryTemplate,
    windows_decision_service_factory_contract,
)


DECISION_RUNTIME_CONFIG_SCHEMA = "windows-decision-service-runtime-config-v1"
DECISION_FACTORY_CONTEXT_SCHEMA = "windows-decision-service-factory-context-v1"
DECISION_FACTORY_RESULT_SCHEMA = "windows-decision-service-factory-result-v1"
ORDER_CAPABILITY = "DISABLED"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_LOT = 0.01
DECISION_DEADLINE_EXIT_CODE = 71
DECISION_RELEASE_MANIFEST_MEMBER = "RELEASE_MANIFEST.json"
DECISION_RELEASE_MANIFEST_SCHEMA = (
    "ai-scalper-windows-decision-service-manifest-v1"
)
CONFIGURED_BINDING_SCHEMA = (
    "windows-configured-service-release-binding-v1"
)
CONFIGURED_OVERLAY_SCHEMA = "windows-configured-service-overlay-v1"
GENERIC_FACTORY_MANIFEST_SCHEMA = "windows-service-factory-manifest-v1"
GENERIC_FACTORY_CONTEXT_SCHEMA = "windows-service-factory-context-v1"
MAX_RELEASE_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_RELEASE_TOTAL_BYTES = 128 * 1024 * 1024
MAX_RELEASE_MEMBERS = 512
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)

_FACTORY_RESULT_SEAL = object()
_FACTORY_IMPORT_SCOPE_LOCK = threading.RLock()
_FACTORY_IMPORT_AUDIT_LOCAL = threading.local()
_MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
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
_DESCRIPTOR_SAFETY = {
    "credential_values_embedded": False,
    "live_allowed": False,
    "max_lot": 0.01,
    "provider_materialization_during_build": False,
    "safe_to_demo_auto_order": False,
    "task_installation_during_build": False,
}
_CONFIGURED_BINDING_FIELDS = frozenset(
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
_CONFIGURED_READINESS_BLOCKERS = (
    "CONFIGURED_RELEASE_EXTERNAL_ACCEPTANCE_REQUIRED",
    "EXTERNAL_LAUNCHER_ATTESTATION_REQUIRED",
    "EXTERNAL_PROVIDER_RUNTIME_ATTESTATION_REQUIRED",
    "EXTERNAL_TASK_INSTALLATION_AND_ACL_ATTESTATION_REQUIRED",
)
_CONFIG_FIELDS = frozenset(
    {
        "service_id",
        "max_cycles",
        "poll_seconds",
        "cycle_deadline_seconds",
        "decision_producer_binding",
        "providers",
        "order_capability",
        "live_allowed",
        "safe_to_demo_auto_order",
        "max_lot",
        "schema_version",
    }
)
_BINDING_FIELDS = frozenset(
    item.name for item in fields(DecisionProducerBinding)
)
_LANE_FIELDS = frozenset(
    item.name for item in fields(DecisionProducerLaneConfig)
)
_PROVIDER_FIELDS = frozenset(
    item.name for item in fields(DecisionServiceProviderBinding)
)


class DecisionServiceRuntimeError(RuntimeError):
    """The decision-only service failed one runtime trust boundary."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


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
        raise DecisionServiceRuntimeError(
            f"DECISION_SERVICE_{label}_INVALID"
        )
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecisionServiceRuntimeError(
            f"DECISION_SERVICE_{label}_INVALID"
        ) from exc

    def pairs_hook(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise DecisionServiceRuntimeError(
                    f"DECISION_SERVICE_{label}_DUPLICATE_KEY"
                )
            result[key] = item
        return result

    def reject_constant(_value: str) -> object:
        raise DecisionServiceRuntimeError(
            f"DECISION_SERVICE_{label}_NONFINITE"
        )

    try:
        payload = json.loads(
            text,
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        )
    except DecisionServiceRuntimeError:
        raise
    except (TypeError, json.JSONDecodeError) as exc:
        raise DecisionServiceRuntimeError(
            f"DECISION_SERVICE_{label}_INVALID"
        ) from exc
    if not isinstance(payload, dict):
        raise DecisionServiceRuntimeError(
            f"DECISION_SERVICE_{label}_INVALID"
        )
    if canonical and value != _canonical_file(payload):
        raise DecisionServiceRuntimeError(
            f"DECISION_SERVICE_{label}_NOT_CANONICAL"
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
        raise DecisionServiceRuntimeError(code)
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise DecisionServiceRuntimeError(code)
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
        raise DecisionServiceRuntimeError(code)
    entries: list[dict[str, object]] = []
    inventory: dict[str, dict[str, object]] = {}
    folded: set[str] = set()
    total = 0
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != _SOURCE_ENTRY_FIELDS:
            raise DecisionServiceRuntimeError(code)
        path = _normalize_release_relative(raw.get("path"), code=code)
        size = raw.get("size_bytes")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise DecisionServiceRuntimeError(code)
        try:
            digest = _nonzero_hash("release member sha256", raw.get("sha256"))
        except (TypeError, ValueError) as exc:
            raise DecisionServiceRuntimeError(code) from exc
        if path in inventory or path.casefold() in folded:
            raise DecisionServiceRuntimeError(code)
        total += size
        if total > MAX_RELEASE_TOTAL_BYTES:
            raise DecisionServiceRuntimeError(code)
        item = {"path": path, "size_bytes": size, "sha256": digest}
        entries.append(item)
        inventory[path] = item
        folded.add(path.casefold())
    if [item["path"] for item in entries] != sorted(inventory):
        raise DecisionServiceRuntimeError(code)
    return entries, inventory


def _reject_release_path_indirection(path: Path) -> None:
    absolute = path.expanduser().absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise DecisionServiceRuntimeError(
                "DECISION_SERVICE_RELEASE_PATH_UNAVAILABLE"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or int(
            getattr(metadata, "st_file_attributes", 0)
        ) & 0x400:
            raise DecisionServiceRuntimeError(
                "DECISION_SERVICE_RELEASE_PATH_INDIRECTION_DENIED"
            )


def _require_release_root(value: str | Path) -> Path:
    configured = Path(value).expanduser().absolute()
    _reject_release_path_indirection(configured)
    try:
        metadata = configured.stat(follow_symlinks=False)
        resolved = configured.resolve(strict=True)
    except OSError as exc:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_RELEASE_ROOT_UNAVAILABLE"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_RELEASE_ROOT_INVALID"
        )
    return resolved


def _require_release_file(
    root: Path,
    relative: str,
    *,
    suffix: str,
) -> Path:
    normalized = _normalize_release_relative(
        relative,
        code="DECISION_SERVICE_RELEASE_PATH_INVALID",
    )
    candidate = Path(normalized)
    if candidate.suffix != suffix:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_RELEASE_PATH_INVALID"
        )
    configured = root / candidate
    _reject_release_path_indirection(configured)
    try:
        resolved = configured.resolve(strict=True)
        resolved.relative_to(root)
        metadata = resolved.stat(follow_symlinks=False)
    except (OSError, ValueError) as exc:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_RELEASE_FILE_UNAVAILABLE"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or int(
        getattr(metadata, "st_file_attributes", 0)
    ) & 0x400:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_RELEASE_FILE_NOT_REGULAR"
        )
    return resolved


def _read_release_bytes(path: Path, *, label: str) -> bytes:
    _reject_release_path_indirection(path)
    try:
        before = path.stat(follow_symlinks=False)
        if before.st_size > MAX_RELEASE_DOCUMENT_BYTES:
            raise DecisionServiceRuntimeError(
                f"DECISION_SERVICE_{label}_TOO_LARGE"
            )
        with path.open("rb") as handle:
            opened_before = os.fstat(handle.fileno())
            payload = handle.read(MAX_RELEASE_DOCUMENT_BYTES + 1)
            opened_after = os.fstat(handle.fileno())
        after = path.stat(follow_symlinks=False)
    except DecisionServiceRuntimeError:
        raise
    except OSError as exc:
        raise DecisionServiceRuntimeError(
            f"DECISION_SERVICE_{label}_READ_FAILED"
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
        len(payload) > MAX_RELEASE_DOCUMENT_BYTES
        or len(payload) != before.st_size
        or identity(opened_before) != expected
        or identity(opened_after) != expected
        or identity(after) != expected
        or not stat.S_ISREG(after.st_mode)
    ):
        raise DecisionServiceRuntimeError(
            f"DECISION_SERVICE_{label}_CHANGED_DURING_READ"
        )
    return payload


def _verify_exact_release_root(
    root: Path,
    *,
    expected_members: set[str],
) -> None:
    expected = {
        _normalize_release_relative(
            item,
            code="DECISION_SERVICE_RELEASE_INVENTORY_INVALID",
        )
        for item in expected_members
    }
    folded_expected = {item.casefold() for item in expected}
    if len(folded_expected) != len(expected):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_RELEASE_INVENTORY_INVALID"
        )
    expected_directories: set[str] = set()
    for item in expected:
        parent = PurePosixPath(item).parent
        while parent.as_posix() not in {"", "."}:
            expected_directories.add(parent.as_posix().casefold())
            parent = parent.parent

    observed: set[str] = set()
    for current, directories, files in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        current_path = Path(current)
        for directory in tuple(directories):
            candidate = current_path / directory
            _reject_release_path_indirection(candidate)
            relative = candidate.relative_to(root).as_posix()
            if relative.casefold() not in expected_directories:
                raise DecisionServiceRuntimeError(
                    "DECISION_SERVICE_RELEASE_EXTRA_MEMBER"
                )
        for filename in files:
            candidate = current_path / filename
            _reject_release_path_indirection(candidate)
            try:
                metadata = candidate.stat(follow_symlinks=False)
            except OSError as exc:
                raise DecisionServiceRuntimeError(
                    "DECISION_SERVICE_RELEASE_PATH_UNAVAILABLE"
                ) from exc
            if not stat.S_ISREG(metadata.st_mode):
                raise DecisionServiceRuntimeError(
                    "DECISION_SERVICE_RELEASE_FILE_NOT_REGULAR"
                )
            relative = candidate.relative_to(root).as_posix().casefold()
            if relative not in folded_expected or relative in observed:
                raise DecisionServiceRuntimeError(
                    "DECISION_SERVICE_RELEASE_EXTRA_MEMBER"
                )
            observed.add(relative)
    if observed != folded_expected:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_RELEASE_INVENTORY_INVALID"
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
            (DECISION_RELEASE_MANIFEST_MEMBER, manifest),
        ):
            info = zipfile.ZipInfo(name, FIXED_ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data)
    return output.getvalue()


def _nonzero_hash(name: str, value: object) -> str:
    normalized = require_hash(name, value)
    if normalized == "0" * 64:
        raise ValueError(f"{name} cannot be the zero hash")
    return normalized


def _finite_number(
    name: str,
    value: object,
    *,
    minimum: float,
    maximum: float,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric")
    normalized = float(value)
    if not math.isfinite(normalized) or not minimum <= normalized <= maximum:
        raise ValueError(
            f"{name.replace('_', ' ')} must be finite and within bounds"
        )
    return normalized


def _parse_decision_producer_binding(
    value: object,
) -> DecisionProducerBinding:
    if not isinstance(value, Mapping) or set(value) != _BINDING_FIELDS:
        raise ValueError("decision producer binding fields drift")
    raw_lanes = value.get("lanes")
    if not isinstance(raw_lanes, list) or not raw_lanes:
        raise TypeError("decision producer binding lanes must be a list")
    lanes: list[DecisionProducerLaneConfig] = []
    for item in raw_lanes:
        if not isinstance(item, Mapping) or set(item) != _LANE_FIELDS:
            raise ValueError("decision producer lane fields drift")
        lanes.append(DecisionProducerLaneConfig(**dict(item)))
    payload = dict(value)
    payload["lanes"] = tuple(lanes)
    return DecisionProducerBinding(**payload)


def _parse_provider_bindings(
    value: object,
) -> tuple[DecisionServiceProviderBinding, ...]:
    if not isinstance(value, list) or not value:
        raise TypeError("decision service providers must be a list")
    providers: list[DecisionServiceProviderBinding] = []
    for item in value:
        if not isinstance(item, Mapping) or set(item) != _PROVIDER_FIELDS:
            raise ValueError("decision service provider fields drift")
        providers.append(DecisionServiceProviderBinding(**dict(item)))
    normalized = tuple(sorted(providers, key=lambda item: item.role))
    # Constructing the template is the authoritative completeness check.  The
    # temporary non-zero hashes here carry no authority and never leave this
    # call.
    WindowsDecisionServiceFactoryTemplate(
        service_id="provider-set-validation",
        release_identity_sha256="1" * 64,
        factory_implementation_sha256="2" * 64,
        factory_configuration_sha256="3" * 64,
        providers=normalized,
    )
    return normalized


@dataclass(frozen=True)
class WindowsDecisionServiceRuntimeConfig(CanonicalContract):
    """Exact non-secret schedule, producer binding, and provider declarations."""

    service_id: str
    max_cycles: int
    poll_seconds: float
    cycle_deadline_seconds: float
    decision_producer_binding: DecisionProducerBinding
    providers: tuple[DecisionServiceProviderBinding, ...]
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    max_lot: float = MAX_LOT
    schema_version: str = DECISION_RUNTIME_CONFIG_SCHEMA

    def __post_init__(self) -> None:
        service_id = require_text("service_id", self.service_id)
        object.__setattr__(self, "service_id", service_id)
        object.__setattr__(
            self,
            "max_cycles",
            require_int(
                "max_cycles", self.max_cycles, minimum=1, maximum=100_000
            ),
        )
        object.__setattr__(
            self,
            "poll_seconds",
            _finite_number(
                "poll_seconds",
                self.poll_seconds,
                minimum=0.0,
                maximum=15.0,
            ),
        )
        object.__setattr__(
            self,
            "cycle_deadline_seconds",
            _finite_number(
                "cycle_deadline_seconds",
                self.cycle_deadline_seconds,
                minimum=0.05,
                maximum=30.0,
            ),
        )
        if type(self.decision_producer_binding) is not DecisionProducerBinding:
            raise TypeError(
                "decision_producer_binding must be exact DecisionProducerBinding"
            )
        if self.decision_producer_binding.service_id != service_id:
            raise ValueError(
                "runtime service ID does not match decision producer service ID"
            )
        if not isinstance(self.providers, tuple) or any(
            type(item) is not DecisionServiceProviderBinding
            for item in self.providers
        ):
            raise TypeError(
                "providers must contain exact DecisionServiceProviderBinding"
            )
        normalized = tuple(sorted(self.providers, key=lambda item: item.role))
        # Reuse the static template as the single provider-set/custody
        # authority. It rejects missing, duplicate, and reordered role sets.
        WindowsDecisionServiceFactoryTemplate(
            service_id=service_id,
            release_identity_sha256="1" * 64,
            factory_implementation_sha256="2" * 64,
            factory_configuration_sha256="3" * 64,
            providers=normalized,
        )
        object.__setattr__(self, "providers", normalized)
        if (
            self.order_capability != ORDER_CAPABILITY
            or type(self.live_allowed) is not bool
            or type(self.safe_to_demo_auto_order) is not bool
            or self.live_allowed
            or self.safe_to_demo_auto_order
            or isinstance(self.max_lot, bool)
            or self.max_lot != MAX_LOT
        ):
            raise ValueError("decision runtime safety locks drift")
        if self.schema_version != DECISION_RUNTIME_CONFIG_SCHEMA:
            raise ValueError("decision runtime config schema drift")

    def factory_template(
        self,
        *,
        release_identity_sha256: str,
        factory_implementation_sha256: str,
        factory_configuration_sha256: str,
    ) -> WindowsDecisionServiceFactoryTemplate:
        """Bind the static provider declarations to exact configured bytes."""

        return WindowsDecisionServiceFactoryTemplate(
            service_id=self.service_id,
            release_identity_sha256=release_identity_sha256,
            factory_implementation_sha256=factory_implementation_sha256,
            factory_configuration_sha256=factory_configuration_sha256,
            providers=self.providers,
        )


def parse_windows_decision_service_runtime_config(
    value: object,
) -> WindowsDecisionServiceRuntimeConfig:
    """Parse one exact canonical-compatible runtime configuration object."""

    if not isinstance(value, Mapping) or set(value) != _CONFIG_FIELDS:
        raise ValueError("decision runtime config root fields drift")
    payload = dict(value)
    payload["decision_producer_binding"] = _parse_decision_producer_binding(
        payload["decision_producer_binding"]
    )
    payload["providers"] = _parse_provider_bindings(payload["providers"])
    return WindowsDecisionServiceRuntimeConfig(**payload)


def canonical_decision_service_factory_contract_sha256(
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
    """Return the generic configured-release factory contract hash."""

    return _sha256_bytes(
        _canonical_bytes(
            {
                "release_profile": release_profile,
                "factory_module": factory_module,
                "factory_attribute": factory_attribute,
                "factory_relative_path": factory_relative_path,
                "factory_file_sha256": factory_file_sha256,
                "service_config_relative_path": (
                    service_config_relative_path
                ),
                "service_config_file_sha256": (
                    service_config_file_sha256
                ),
                "bootstrap_binding_sha256": bootstrap_binding_sha256,
                "schema_version": GENERIC_FACTORY_CONTEXT_SCHEMA,
            }
        )
    )


@dataclass(frozen=True)
class WindowsDecisionServiceFactoryManifest(CanonicalContract):
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
            raise ValueError("decision factory release profile drift")
        module = require_text("factory_module", self.factory_module)
        attribute = require_text("factory_attribute", self.factory_attribute)
        if (
            _MODULE_RE.fullmatch(module) is None
            or _MODULE_RE.fullmatch(attribute) is None
        ):
            raise ValueError("decision factory module or attribute is invalid")
        object.__setattr__(self, "factory_module", module)
        object.__setattr__(self, "factory_attribute", attribute)
        for name, suffix in (
            ("factory_relative_path", ".py"),
            ("service_config_relative_path", ".json"),
        ):
            value = _normalize_release_relative(
                getattr(self, name),
                code="DECISION_SERVICE_FACTORY_MANIFEST_INVALID",
            )
            if PurePosixPath(value).suffix != suffix:
                raise ValueError(f"{name} has the wrong suffix")
            object.__setattr__(self, name, value)
        if (
            PurePosixPath(self.factory_relative_path).parent.as_posix() != "."
            or PurePosixPath(self.factory_relative_path).stem
            != self.factory_module
            or PurePosixPath(
                self.service_config_relative_path
            ).parts[0]
            != "config"
        ):
            raise ValueError("decision factory paths are invalid")
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
        expected = canonical_decision_service_factory_contract_sha256(
            release_profile=self.release_profile,
            factory_module=self.factory_module,
            factory_attribute=self.factory_attribute,
            factory_relative_path=self.factory_relative_path,
            factory_file_sha256=self.factory_file_sha256,
            service_config_relative_path=self.service_config_relative_path,
            service_config_file_sha256=self.service_config_file_sha256,
            bootstrap_binding_sha256=self.bootstrap_binding_sha256,
        )
        if self.factory_contract_sha256 != expected:
            raise ValueError("decision factory contract hash is invalid")
        if self.schema_version != GENERIC_FACTORY_MANIFEST_SCHEMA:
            raise ValueError("decision factory manifest schema drift")


def _validate_configured_descriptor(
    value: object,
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    if not isinstance(value, Mapping) or set(value) != _DESCRIPTOR_FIELDS:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIGURED_DESCRIPTOR_INVALID"
        )
    descriptor = dict(value)
    if (
        descriptor.get("schema_version") != CONFIGURED_OVERLAY_SCHEMA
        or descriptor.get("base_release_profile") != RELEASE_PROFILE
        or descriptor.get("runtime_mode") not in {"DEMO", "DEMO_AUTO"}
        or descriptor.get("safety") != _DESCRIPTOR_SAFETY
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIGURED_DESCRIPTOR_INVALID"
        )
    try:
        descriptor["base_release_identity_sha256"] = _nonzero_hash(
            "base_release_identity_sha256",
            descriptor.get("base_release_identity_sha256"),
        )
        descriptor["reviewed_factory_template_sha256"] = _nonzero_hash(
            "reviewed_factory_template_sha256",
            descriptor.get("reviewed_factory_template_sha256"),
        )
        descriptor["task_definition_sha256"] = _nonzero_hash(
            "task_definition_sha256",
            descriptor.get("task_definition_sha256"),
        )
    except (TypeError, ValueError) as exc:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIGURED_DESCRIPTOR_INVALID"
        ) from exc
    expected_static_contract = canonical_sha256(
        windows_decision_service_factory_contract()
    )
    if (
        descriptor["reviewed_factory_template_sha256"]
        != expected_static_contract
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_FACTORY_TEMPLATE_CONTRACT_MISMATCH"
        )
    for name in (
        "factory_manifest_relative_path",
        "factory_source_relative_path",
        "service_config_relative_path",
    ):
        descriptor[name] = _normalize_release_relative(
            descriptor.get(name),
            code="DECISION_SERVICE_CONFIGURED_DESCRIPTOR_INVALID",
        )
    factory_path = PurePosixPath(
        str(descriptor["factory_source_relative_path"])
    )
    factory_manifest_path = PurePosixPath(
        str(descriptor["factory_manifest_relative_path"])
    )
    service_config_path = PurePosixPath(
        str(descriptor["service_config_relative_path"])
    )
    if (
        factory_path.parent.as_posix() != "."
        or factory_path.suffix != ".py"
        or _MODULE_RE.fullmatch(factory_path.stem) is None
        or factory_manifest_path.parts[0] != "config"
        or factory_manifest_path.suffix != ".json"
        or service_config_path.parts[0] != "config"
        or service_config_path.suffix != ".json"
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIGURED_DESCRIPTOR_INVALID"
        )
    raw_providers = descriptor.get("provider_source_relative_paths")
    if not isinstance(raw_providers, list) or not raw_providers:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIGURED_DESCRIPTOR_INVALID"
        )
    providers = [
        _normalize_release_relative(
            item,
            code="DECISION_SERVICE_CONFIGURED_DESCRIPTOR_INVALID",
        )
        for item in raw_providers
    ]
    if (
        providers != sorted(providers)
        or len(providers) != len(set(providers))
        or len({item.casefold() for item in providers}) != len(providers)
        or "configured_providers/__init__.py" not in providers
        or any(
            PurePosixPath(item).parts[0] != "configured_providers"
            or PurePosixPath(item).suffix != ".py"
            for item in providers
        )
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIGURED_DESCRIPTOR_INVALID"
        )
    descriptor["provider_source_relative_paths"] = providers
    file_entries, file_inventory = _source_inventory(
        descriptor.get("files"),
        code="DECISION_SERVICE_CONFIGURED_DESCRIPTOR_INVALID",
    )
    expected_files = {
        str(descriptor["factory_manifest_relative_path"]),
        str(descriptor["factory_source_relative_path"]),
        str(descriptor["service_config_relative_path"]),
        *providers,
    }
    if set(file_inventory) != expected_files:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIGURED_DESCRIPTOR_INVALID"
        )
    descriptor["files"] = file_entries
    return descriptor, file_inventory


def _verify_configured_decision_release(
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
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_EXPECTED_RELEASE_IDENTITY_INVALID"
        ) from exc
    manifest_file = _require_release_file(
        root,
        DECISION_RELEASE_MANIFEST_MEMBER,
        suffix=".json",
    )
    manifest_bytes = _read_release_bytes(
        manifest_file,
        label="RELEASE_MANIFEST",
    )
    manifest = _strict_json_bytes(
        manifest_bytes,
        label="RELEASE_MANIFEST",
        canonical=True,
    )
    if (
        manifest.get("schema_version") != DECISION_RELEASE_MANIFEST_SCHEMA
        or manifest.get("release_profile") != RELEASE_PROFILE
        or manifest.get("safety")
        != {
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "max_lot": 0.01,
            "order_capability": "DISABLED",
        }
        or manifest.get("production_execution_ready") is not False
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_RELEASE_MANIFEST_INVALID"
        )
    try:
        identity = _nonzero_hash(
            "release_identity_sha256",
            manifest.get("release_identity_sha256"),
        )
    except (TypeError, ValueError) as exc:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_RELEASE_IDENTITY_INVALID"
        ) from exc
    unsigned = dict(manifest)
    unsigned.pop("release_identity_sha256", None)
    if (
        identity != expected_identity
        or _sha256_bytes(_canonical_bytes(unsigned)) != identity
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_RELEASE_IDENTITY_MISMATCH"
        )
    source_entries, inventory = _source_inventory(
        manifest.get("source_files"),
        code="DECISION_SERVICE_RELEASE_INVENTORY_INVALID",
    )
    _verify_exact_release_root(
        root,
        expected_members={
            *inventory,
            DECISION_RELEASE_MANIFEST_MEMBER,
        },
    )
    member_bytes: dict[str, bytes] = {}
    for item in source_entries:
        path = _require_release_file(
            root,
            str(item["path"]),
            suffix=PurePosixPath(str(item["path"])).suffix,
        )
        data = _read_release_bytes(path, label="RELEASE_MEMBER")
        if (
            len(data) != item["size_bytes"]
            or _sha256_bytes(data) != item["sha256"]
        ):
            raise DecisionServiceRuntimeError(
                "DECISION_SERVICE_RELEASE_MEMBER_HASH_MISMATCH"
            )
        member_bytes[str(item["path"])] = data

    raw_binding = manifest.get("configured_release")
    if not isinstance(raw_binding, Mapping):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIGURED_BINDING_MISSING"
        )
    binding = dict(raw_binding)
    if (
        set(binding) != _CONFIGURED_BINDING_FIELDS
        or binding.get("schema_version") != CONFIGURED_BINDING_SCHEMA
        or binding.get("base_release_profile") != RELEASE_PROFILE
        or binding.get("runtime_mode") not in {"DEMO", "DEMO_AUTO"}
        or binding.get("live_allowed") is not False
        or binding.get("safe_to_demo_auto_order") is not False
        or binding.get("max_lot") != 0.01
        or binding.get("provider_materialization_performed") is not False
        or binding.get("credential_access_performed") is not False
        or binding.get("task_installation_performed") is not False
        or binding.get("broker_mutation_performed") is not False
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIGURED_BINDING_INVALID"
        )
    for name in (
        "base_release_archive_sha256",
        "base_release_identity_sha256",
        "base_release_manifest_sha256",
        "bootstrap_binding_sha256",
        "factory_contract_sha256",
        "overlay_descriptor_sha256",
        "overlay_file_set_sha256",
        "reviewed_factory_template_sha256",
        "task_definition_sha256",
    ):
        try:
            binding[name] = _nonzero_hash(name, binding.get(name))
        except (TypeError, ValueError) as exc:
            raise DecisionServiceRuntimeError(
                "DECISION_SERVICE_CONFIGURED_BINDING_INVALID"
            ) from exc

    raw_base_manifest = binding.get("base_release_manifest")
    if not isinstance(raw_base_manifest, Mapping):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIGURED_BASE_MANIFEST_INVALID"
        )
    base_manifest = dict(raw_base_manifest)
    base_identity = binding["base_release_identity_sha256"]
    if (
        base_manifest.get("schema_version")
        != DECISION_RELEASE_MANIFEST_SCHEMA
        or base_manifest.get("release_profile") != RELEASE_PROFILE
        or base_manifest.get("safety")
        != {
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "max_lot": 0.01,
            "order_capability": "DISABLED",
        }
        or base_manifest.get("production_execution_ready") is not False
        or "configured_release" in base_manifest
        or base_manifest.get("release_identity_sha256") != base_identity
        or _sha256_bytes(_canonical_file(base_manifest))
        != binding["base_release_manifest_sha256"]
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIGURED_BASE_MANIFEST_INVALID"
        )
    base_unsigned = dict(base_manifest)
    base_unsigned.pop("release_identity_sha256", None)
    if _sha256_bytes(_canonical_bytes(base_unsigned)) != base_identity:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIGURED_BASE_MANIFEST_INVALID"
        )
    base_entries, base_inventory = _source_inventory(
        base_manifest.get("source_files"),
        code="DECISION_SERVICE_CONFIGURED_BASE_MANIFEST_INVALID",
    )
    if any(inventory.get(path) != item for path, item in base_inventory.items()):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIGURED_BASE_MANIFEST_INVALID"
        )
    base_sources = {
        str(item["path"]): member_bytes[str(item["path"])]
        for item in base_entries
    }
    recreated_base = _deterministic_archive(
        base_sources,
        _canonical_file(base_manifest),
    )
    if (
        _sha256_bytes(recreated_base)
        != binding["base_release_archive_sha256"]
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIGURED_BASE_ARCHIVE_MISMATCH"
        )

    descriptor, overlay_inventory = _validate_configured_descriptor(
        binding.get("overlay_descriptor")
    )
    if (
        descriptor["base_release_identity_sha256"] != base_identity
        or descriptor["runtime_mode"] != binding.get("runtime_mode")
        or descriptor["overlay_id"] != binding.get("overlay_id")
        or descriptor["factory_manifest_relative_path"]
        != binding.get("factory_manifest_relative_path")
        or descriptor["factory_source_relative_path"]
        != binding.get("factory_source_relative_path")
        or descriptor["service_config_relative_path"]
        != binding.get("service_config_relative_path")
        or descriptor["provider_source_relative_paths"]
        != binding.get("provider_source_relative_paths")
        or descriptor["reviewed_factory_template_sha256"]
        != binding["reviewed_factory_template_sha256"]
        or descriptor["task_definition_sha256"]
        != binding["task_definition_sha256"]
        or _sha256_bytes(_canonical_file(descriptor))
        != binding["overlay_descriptor_sha256"]
        or _sha256_bytes(_canonical_bytes(descriptor["files"]))
        != binding["overlay_file_set_sha256"]
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIGURED_BINDING_INVALID"
        )
    if (
        set(base_inventory) & set(overlay_inventory)
        or set(inventory)
        != set(base_inventory) | set(overlay_inventory)
        or any(
            inventory.get(path) != item
            for path, item in overlay_inventory.items()
        )
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIGURED_SOURCE_PARTITION_INVALID"
        )
    base_blockers = base_manifest.get("readiness_blockers")
    if (
        not isinstance(base_blockers, list)
        or not base_blockers
        or any(not isinstance(item, str) or not item for item in base_blockers)
        or len(base_blockers) != len(set(base_blockers))
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIGURED_BASE_MANIFEST_INVALID"
        )
    expected_unsigned = dict(base_manifest)
    expected_unsigned.pop("release_identity_sha256", None)
    expected_unsigned["source_files"] = source_entries
    expected_unsigned["configured_release"] = dict(binding)
    expected_unsigned["production_execution_ready"] = False
    expected_unsigned["readiness_blockers"] = sorted(
        {*base_blockers, *_CONFIGURED_READINESS_BLOCKERS}
    )
    if unsigned != expected_unsigned:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIGURED_BASE_INHERITANCE_DRIFT"
        )
    return manifest, inventory, binding, descriptor


def validate_reviewed_windows_decision_service_factory_manifest(
    *,
    release_root: str | Path,
    manifest_path: str | Path,
    expected_release_identity_sha256: str,
) -> tuple[
    WindowsDecisionServiceFactoryManifest,
    WindowsDecisionServiceRuntimeConfig,
    "WindowsDecisionServiceFactoryContext",
]:
    """Validate the configured release without importing its factory."""

    root = _require_release_root(release_root)
    manifest_file = Path(manifest_path).expanduser().absolute()
    try:
        _reject_release_path_indirection(manifest_file)
        manifest_relative = (
            manifest_file.resolve(strict=True).relative_to(root).as_posix()
        )
    except (DecisionServiceRuntimeError, OSError, ValueError) as exc:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_FACTORY_MANIFEST_NOT_RELEASE_BOUND"
        ) from exc
    (
        release_manifest,
        inventory,
        binding,
        descriptor,
    ) = _verify_configured_decision_release(
        root=root,
        expected_release_identity_sha256=(
            expected_release_identity_sha256
        ),
    )
    if (
        manifest_relative
        != binding["factory_manifest_relative_path"]
        or manifest_relative
        != descriptor["factory_manifest_relative_path"]
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_FACTORY_MANIFEST_NOT_RELEASE_BOUND"
        )
    manifest_data = _read_release_bytes(
        manifest_file,
        label="FACTORY_MANIFEST",
    )
    raw_factory_manifest = _strict_json_bytes(
        manifest_data,
        label="FACTORY_MANIFEST",
        canonical=True,
    )
    if set(raw_factory_manifest) != _FACTORY_MANIFEST_FIELDS:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_FACTORY_MANIFEST_INVALID"
        )
    try:
        factory_manifest = WindowsDecisionServiceFactoryManifest(
            **raw_factory_manifest
        )
    except (
        DecisionServiceRuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_FACTORY_MANIFEST_INVALID"
        ) from exc
    if (
        factory_manifest.factory_relative_path
        != binding["factory_source_relative_path"]
        or factory_manifest.service_config_relative_path
        != binding["service_config_relative_path"]
        or factory_manifest.factory_contract_sha256
        != binding["factory_contract_sha256"]
        or factory_manifest.bootstrap_binding_sha256
        != binding["bootstrap_binding_sha256"]
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_FACTORY_MANIFEST_BINDING_MISMATCH"
        )
    bound = {
        manifest_relative: _sha256_bytes(manifest_data),
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
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_FACTORY_MEMBER_NOT_RELEASE_BOUND"
        )
    factory_file = _require_release_file(
        root,
        factory_manifest.factory_relative_path,
        suffix=".py",
    )
    config_file = _require_release_file(
        root,
        factory_manifest.service_config_relative_path,
        suffix=".json",
    )
    factory_bytes = _read_release_bytes(
        factory_file,
        label="FACTORY_SOURCE",
    )
    config_bytes = _read_release_bytes(
        config_file,
        label="SERVICE_CONFIG",
    )
    if (
        _sha256_bytes(factory_bytes)
        != factory_manifest.factory_file_sha256
        or _sha256_bytes(config_bytes)
        != factory_manifest.service_config_file_sha256
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_FACTORY_OR_CONFIG_HASH_MISMATCH"
        )
    raw_config = _strict_json_bytes(
        config_bytes,
        label="SERVICE_CONFIG",
        canonical=True,
    )
    try:
        runtime_config = parse_windows_decision_service_runtime_config(
            raw_config
        )
    except (TypeError, ValueError) as exc:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_CONFIG_INVALID"
        ) from exc
    if (
        runtime_config.decision_producer_binding.content_sha256
        != factory_manifest.bootstrap_binding_sha256
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_BOOTSTRAP_BINDING_MISMATCH"
        )
    provider_template = runtime_config.factory_template(
        release_identity_sha256=str(
            release_manifest["release_identity_sha256"]
        ),
        factory_implementation_sha256=(
            factory_manifest.factory_file_sha256
        ),
        factory_configuration_sha256=(
            factory_manifest.service_config_file_sha256
        ),
    )
    context = WindowsDecisionServiceFactoryContext(
        release_identity_sha256=str(
            release_manifest["release_identity_sha256"]
        ),
        factory_contract_sha256=(
            factory_manifest.factory_contract_sha256
        ),
        factory_file_sha256=factory_manifest.factory_file_sha256,
        service_config_file_sha256=(
            factory_manifest.service_config_file_sha256
        ),
        bootstrap_binding_sha256=(
            factory_manifest.bootstrap_binding_sha256
        ),
        provider_template_sha256=provider_template.content_sha256,
    )
    return factory_manifest, runtime_config, context


@dataclass(frozen=True)
class WindowsDecisionServiceFactoryContext(CanonicalContract):
    """Immutable hashes supplied to one reviewed decision factory."""

    release_identity_sha256: str
    factory_contract_sha256: str
    factory_file_sha256: str
    service_config_file_sha256: str
    bootstrap_binding_sha256: str
    provider_template_sha256: str
    release_profile: str = RELEASE_PROFILE
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    max_lot: float = MAX_LOT
    schema_version: str = DECISION_FACTORY_CONTEXT_SCHEMA

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
                self, name, _nonzero_hash(name, getattr(self, name))
            )
        if self.release_profile != RELEASE_PROFILE:
            raise ValueError("decision factory context release profile drift")
        if (
            self.order_capability != ORDER_CAPABILITY
            or self.live_allowed
            or self.safe_to_demo_auto_order
            or self.max_lot != MAX_LOT
        ):
            raise ValueError("decision factory context safety locks drift")
        if self.schema_version != DECISION_FACTORY_CONTEXT_SCHEMA:
            raise ValueError("decision factory context schema drift")


@dataclass(frozen=True)
class WindowsDecisionServiceFactoryResult:
    """Sealed decision-only runtime product returned by a reviewed factory."""

    service: BrokerlessDecisionProducerService
    service_id: str
    bootstrap_binding_sha256: str
    factory_contract_sha256: str
    service_config_file_sha256: str
    provider_template_sha256: str
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    max_lot: float = MAX_LOT
    schema_version: str = DECISION_FACTORY_RESULT_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _FACTORY_RESULT_SEAL:
            raise TypeError(
                "decision service factory results require the sealing factory"
            )
        if type(self.service) is not BrokerlessDecisionProducerService:
            raise TypeError(
                "service must be exact BrokerlessDecisionProducerService"
            )
        object.__setattr__(
            self, "service_id", require_text("service_id", self.service_id)
        )
        for name in (
            "bootstrap_binding_sha256",
            "factory_contract_sha256",
            "service_config_file_sha256",
            "provider_template_sha256",
        ):
            object.__setattr__(
                self, name, _nonzero_hash(name, getattr(self, name))
            )
        if (
            self.order_capability != ORDER_CAPABILITY
            or self.live_allowed
            or self.safe_to_demo_auto_order
            or self.max_lot != MAX_LOT
        ):
            raise ValueError("decision factory result safety locks drift")
        if self.schema_version != DECISION_FACTORY_RESULT_SCHEMA:
            raise ValueError("decision factory result schema drift")


def seal_windows_decision_service_factory_result(
    *,
    service: BrokerlessDecisionProducerService,
    runtime_config: WindowsDecisionServiceRuntimeConfig,
    provider_template: WindowsDecisionServiceFactoryTemplate,
    context: WindowsDecisionServiceFactoryContext,
) -> WindowsDecisionServiceFactoryResult:
    """Seal a reviewed factory product without performing a decision cycle."""

    if type(service) is not BrokerlessDecisionProducerService:
        raise TypeError(
            "service must be exact BrokerlessDecisionProducerService"
        )
    if type(runtime_config) is not WindowsDecisionServiceRuntimeConfig:
        raise TypeError(
            "runtime_config must be exact WindowsDecisionServiceRuntimeConfig"
        )
    if type(provider_template) is not WindowsDecisionServiceFactoryTemplate:
        raise TypeError(
            "provider_template must be exact WindowsDecisionServiceFactoryTemplate"
        )
    if type(context) is not WindowsDecisionServiceFactoryContext:
        raise TypeError(
            "context must be exact WindowsDecisionServiceFactoryContext"
        )
    binding = service.binding
    if (
        binding != runtime_config.decision_producer_binding
        or binding.content_sha256 != context.bootstrap_binding_sha256
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_BOOTSTRAP_BINDING_MISMATCH"
        )
    if (
        binding.service_id != runtime_config.service_id
        or provider_template.service_id != runtime_config.service_id
        or provider_template.release_identity_sha256
        != context.release_identity_sha256
        or provider_template.factory_implementation_sha256
        != context.factory_file_sha256
        or provider_template.factory_configuration_sha256
        != context.service_config_file_sha256
        or provider_template.providers != runtime_config.providers
        or provider_template.content_sha256 != context.provider_template_sha256
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_FACTORY_RESULT_BINDING_MISMATCH"
        )
    return WindowsDecisionServiceFactoryResult(
        service=service,
        service_id=binding.service_id,
        bootstrap_binding_sha256=binding.content_sha256,
        factory_contract_sha256=context.factory_contract_sha256,
        service_config_file_sha256=context.service_config_file_sha256,
        provider_template_sha256=context.provider_template_sha256,
        _seal=_FACTORY_RESULT_SEAL,
    )


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


def _snapshot_module_registry() -> dict[str, tuple[int, bool]]:
    return {
        name: (id(value), type(value) is ModuleType)
        for name, value in tuple(sys.modules.items())
        if isinstance(name, str)
    }


def _record_factory_import_modules(modules: set[ModuleType]) -> None:
    stack = getattr(_FACTORY_IMPORT_AUDIT_LOCAL, "stack", None)
    if not isinstance(stack, list) or not stack:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_FACTORY_IMPORT_SCOPE_INACTIVE"
        )
    stack[-1].update(modules)


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
                raise DecisionServiceRuntimeError(
                    "DECISION_SERVICE_FACTORY_IMPORT_ORIGIN_INVALID"
                )
            for namespace_path in namespace_paths:
                try:
                    resolved = Path(namespace_path).resolve(strict=True)
                except (OSError, TypeError) as exc:
                    raise DecisionServiceRuntimeError(
                        "DECISION_SERVICE_FACTORY_IMPORT_ORIGIN_INVALID"
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
                    raise DecisionServiceRuntimeError(
                        "DECISION_SERVICE_FACTORY_IMPORT_ORIGIN_DENIED"
                    )
            continue
        try:
            path = Path(origin).resolve(strict=True)
        except (OSError, TypeError) as exc:
            raise DecisionServiceRuntimeError(
                "DECISION_SERVICE_FACTORY_IMPORT_ORIGIN_INVALID"
            ) from exc
        if _is_relative_to(path, release_root):
            relative = path.relative_to(release_root).as_posix()
            item = inventory.get(relative)
            if not isinstance(item, Mapping):
                raise DecisionServiceRuntimeError(
                    "DECISION_SERVICE_FACTORY_IMPORT_NOT_RELEASE_BOUND"
                )
            payload = _read_release_bytes(path, label="IMPORTED_MODULE")
            if (
                len(payload) != item.get("size_bytes")
                or _sha256_bytes(payload) != item.get("sha256")
            ):
                raise DecisionServiceRuntimeError(
                    "DECISION_SERVICE_FACTORY_IMPORT_HASH_MISMATCH"
                )
            continue
        folded = {part.casefold() for part in path.parts}
        if folded.intersection(
            {"site-packages", "dist-packages"}
        ) or not any(
            _is_relative_to(path, root) for root in stdlib_roots
        ):
            raise DecisionServiceRuntimeError(
                "DECISION_SERVICE_FACTORY_IMPORT_ORIGIN_DENIED"
            )


def _verify_module_registry_delta(
    *,
    before: Mapping[str, tuple[int, bool]],
    release_root: Path,
    inventory: Mapping[str, Mapping[str, object]],
) -> None:
    current = {
        name: value
        for name, value in tuple(sys.modules.items())
        if isinstance(name, str)
    }
    if any(name not in current for name in before):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_FACTORY_MODULE_REGISTRY_MUTATED"
        )
    added: set[ModuleType] = set()
    for name, value in current.items():
        previous = before.get(name)
        if previous is not None:
            if previous != (id(value), type(value) is ModuleType):
                raise DecisionServiceRuntimeError(
                    "DECISION_SERVICE_FACTORY_MODULE_REGISTRY_MUTATED"
                )
            continue
        if type(value) is not ModuleType:
            raise DecisionServiceRuntimeError(
                "DECISION_SERVICE_FACTORY_MODULE_REGISTRY_INVALID"
            )
        added.add(value)
    _verify_imported_module_origins(
        release_root=release_root,
        inventory=inventory,
        modules=added,
    )


def _factory_dynamic_loader_denied(
    *_args: object,
    **_kwargs: object,
) -> object:
    raise DecisionServiceRuntimeError(
        "DECISION_SERVICE_FACTORY_DYNAMIC_LOADER_DENIED"
    )


@contextmanager
def _reviewed_import_scope(
    *,
    release_root: Path,
    inventory: Mapping[str, Mapping[str, object]],
):
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
            current = candidate
            current_parts = current.__name__.split(".")
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

    def reviewed_import_module(
        name: str,
        package: str | None = None,
    ) -> ModuleType:
        imported = original_import_module(name, package)
        if type(imported) is not ModuleType:
            raise DecisionServiceRuntimeError(
                "DECISION_SERVICE_FACTORY_IMPORT_RESULT_INVALID"
            )
        attest({imported})
        return imported

    def reviewed_reload(module: ModuleType) -> ModuleType:
        if type(module) is not ModuleType:
            raise DecisionServiceRuntimeError(
                "DECISION_SERVICE_FACTORY_IMPORT_RESULT_INVALID"
            )
        attest({module})
        imported = original_reload(module)
        if type(imported) is not ModuleType:
            raise DecisionServiceRuntimeError(
                "DECISION_SERVICE_FACTORY_IMPORT_RESULT_INVALID"
            )
        attest({imported})
        return imported

    with _FACTORY_IMPORT_SCOPE_LOCK:
        stack = getattr(_FACTORY_IMPORT_AUDIT_LOCAL, "stack", None)
        if stack is None:
            stack = []
            _FACTORY_IMPORT_AUDIT_LOCAL.stack = stack
        stack.append(tracked_modules)
        builtins.__import__ = reviewed_import
        importlib.__import__ = reviewed_import
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
                        getattr(importlib.util, name)
                        is not _factory_dynamic_loader_denied
                        for name in guarded_util_names
                    )
                ):
                    raise DecisionServiceRuntimeError(
                        "DECISION_SERVICE_FACTORY_IMPORT_GUARD_MUTATED"
                    )
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
            except BaseException as exc:
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
                    validation_error = DecisionServiceRuntimeError(
                        "DECISION_SERVICE_FACTORY_IMPORT_AUDIT_CORRUPTED"
                    )
            if validation_error is not None:
                raise validation_error


def _load_exact_decision_factory_module(
    *,
    manifest: WindowsDecisionServiceFactoryManifest,
    factory_file: Path,
    release_root: Path,
    inventory: Mapping[str, Mapping[str, object]],
) -> ModuleType:
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
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_FACTORY_MODULE_SPEC_INVALID"
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
    except DecisionServiceRuntimeError:
        raise
    except Exception as exc:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_FACTORY_MODULE_LOAD_FAILED"
        ) from exc
    finally:
        sys.path[:] = original_sys_path
        sys.dont_write_bytecode = original_dont_write_bytecode
    if type(namespace) is not ModuleType or namespace.__name__ != (
        manifest.factory_module
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_FACTORY_MODULE_INVALID"
        )
    referenced_modules = {
        value
        for value in namespace.__dict__.values()
        if type(value) is ModuleType
    }
    _verify_imported_module_origins(
        release_root=release_root,
        inventory=inventory,
        modules=referenced_modules,
    )
    return namespace


def load_reviewed_windows_decision_service_factory(
    *,
    release_root: str | Path,
    manifest_path: str | Path,
    expected_release_identity_sha256: str,
) -> tuple[
    WindowsDecisionServiceFactoryManifest,
    WindowsDecisionServiceRuntimeConfig,
    WindowsDecisionServiceFactoryResult,
]:
    """Import and invoke one exact configured decision-service factory."""

    root = _require_release_root(release_root)
    _release_manifest, inventory, _binding, _descriptor = (
        _verify_configured_decision_release(
            root=root,
            expected_release_identity_sha256=(
                expected_release_identity_sha256
            ),
        )
    )
    manifest, runtime_config, context = (
        validate_reviewed_windows_decision_service_factory_manifest(
            release_root=root,
            manifest_path=manifest_path,
            expected_release_identity_sha256=(
                expected_release_identity_sha256
            ),
        )
    )
    factory_file = _require_release_file(
        root,
        manifest.factory_relative_path,
        suffix=".py",
    )
    config_file = _require_release_file(
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
            raise DecisionServiceRuntimeError(
                "DECISION_SERVICE_FACTORY_OR_CONFIG_CHANGED"
            )

    assert_stable()
    namespace = _load_exact_decision_factory_module(
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
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_FACTORY_CALLABLE_INVALID"
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
    except DecisionServiceRuntimeError:
        raise
    except Exception as exc:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_FACTORY_CALL_FAILED"
        ) from exc
    finally:
        sys.path[:] = original_sys_path
    assert_stable()
    if type(result) is not WindowsDecisionServiceFactoryResult:
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_FACTORY_RESULT_NOT_SEALED"
        )
    if (
        result.service_id != runtime_config.service_id
        or result.bootstrap_binding_sha256
        != manifest.bootstrap_binding_sha256
        or result.factory_contract_sha256
        != manifest.factory_contract_sha256
        or result.service_config_file_sha256
        != manifest.service_config_file_sha256
        or result.provider_template_sha256
        != context.provider_template_sha256
        or result.service.binding
        != runtime_config.decision_producer_binding
    ):
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_FACTORY_RESULT_BINDING_MISMATCH"
        )
    return manifest, runtime_config, result


def _hard_terminate_process(exit_code: int) -> None:
    os._exit(exit_code)


class WindowsDecisionServiceRunner:
    """Run one exact decision service with bounded, interruptible cadence."""

    def __init__(
        self,
        result: WindowsDecisionServiceFactoryResult,
        *,
        runtime_config: WindowsDecisionServiceRuntimeConfig,
    ) -> None:
        if type(result) is not WindowsDecisionServiceFactoryResult:
            raise TypeError(
                "result must be exact WindowsDecisionServiceFactoryResult"
            )
        if type(runtime_config) is not WindowsDecisionServiceRuntimeConfig:
            raise TypeError(
                "runtime_config must be exact WindowsDecisionServiceRuntimeConfig"
            )
        if (
            result.service_id != runtime_config.service_id
            or result.bootstrap_binding_sha256
            != runtime_config.decision_producer_binding.content_sha256
        ):
            raise DecisionServiceRuntimeError(
                "DECISION_SERVICE_RUNNER_BINDING_MISMATCH"
            )
        self.result = result
        self.runtime_config = runtime_config
        self._stop_event = threading.Event()

    def request_stop(self) -> None:
        self._stop_event.set()

    def stop_requested(self) -> bool:
        return self._stop_event.is_set()

    def _run_cycle_with_deadline(self) -> DecisionProducerCycleResult:
        result_queue: queue.Queue[tuple[str, object]] = queue.Queue(maxsize=1)

        def worker() -> None:
            try:
                result_queue.put_nowait(
                    ("RESULT", self.result.service.run_cycle())
                )
            except BaseException as exc:
                try:
                    result_queue.put_nowait(("ERROR", exc))
                except queue.Full:
                    pass

        thread = threading.Thread(
            target=worker,
            name=f"{self.result.service_id}-decision-cycle",
            daemon=True,
        )
        thread.start()
        try:
            kind, value = result_queue.get(
                timeout=self.runtime_config.cycle_deadline_seconds
            )
        except queue.Empty:
            _hard_terminate_process(DECISION_DEADLINE_EXIT_CODE)
            raise DecisionServiceRuntimeError(
                "DECISION_SERVICE_HARD_TERMINATION_RETURNED"
            )
        if kind == "ERROR":
            if isinstance(value, BaseException):
                raise value
            raise DecisionServiceRuntimeError(
                "DECISION_SERVICE_CYCLE_ERROR_INVALID"
            )
        thread.join(timeout=0.1)
        if (
            kind != "RESULT"
            or thread.is_alive()
            or type(value) is not DecisionProducerCycleResult
        ):
            _hard_terminate_process(DECISION_DEADLINE_EXIT_CODE)
            raise DecisionServiceRuntimeError(
                "DECISION_SERVICE_HARD_TERMINATION_RETURNED"
            )
        return value

    def run(self) -> tuple[DecisionProducerCycleResult, ...]:
        results: list[DecisionProducerCycleResult] = []
        while (
            len(results) < self.runtime_config.max_cycles
            and not self.stop_requested()
        ):
            results.append(self._run_cycle_with_deadline())
            if (
                len(results) < self.runtime_config.max_cycles
                and not self.stop_requested()
                and self.runtime_config.poll_seconds
            ):
                self._stop_event.wait(self.runtime_config.poll_seconds)
        return tuple(results)


def install_decision_signal_handlers(
    runner: WindowsDecisionServiceRunner,
) -> None:
    """Install stop-only handlers on the process main thread."""

    if type(runner) is not WindowsDecisionServiceRunner:
        raise TypeError(
            "runner must be exact WindowsDecisionServiceRunner"
        )
    if threading.current_thread() is not threading.main_thread():
        raise DecisionServiceRuntimeError(
            "DECISION_SERVICE_SIGNAL_INSTALL_REQUIRES_MAIN_THREAD"
        )

    def request_stop(
        _signum: int,
        _frame: object,
    ) -> None:
        runner.request_stop()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)


__all__ = [
    "CONFIGURED_BINDING_SCHEMA",
    "DECISION_DEADLINE_EXIT_CODE",
    "DECISION_FACTORY_CONTEXT_SCHEMA",
    "DECISION_FACTORY_RESULT_SCHEMA",
    "DECISION_RELEASE_MANIFEST_MEMBER",
    "DECISION_RUNTIME_CONFIG_SCHEMA",
    "DecisionServiceRuntimeError",
    "WindowsDecisionServiceFactoryManifest",
    "WindowsDecisionServiceFactoryContext",
    "WindowsDecisionServiceFactoryResult",
    "WindowsDecisionServiceRunner",
    "WindowsDecisionServiceRuntimeConfig",
    "canonical_decision_service_factory_contract_sha256",
    "install_decision_signal_handlers",
    "load_reviewed_windows_decision_service_factory",
    "parse_windows_decision_service_runtime_config",
    "seal_windows_decision_service_factory_result",
    "validate_reviewed_windows_decision_service_factory_manifest",
]
