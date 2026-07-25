"""Offline generator for one secret-free Status Monitor provider pack.

The tooling verifies exact local release bytes and writes four deterministic
overlay files.  It never imports a generated factory, resolves a credential,
opens SQLite provider state, issues provider traffic, starts a process,
initializes MT5, installs a task, or performs broker/order work.
"""

from __future__ import annotations

import ast
from dataclasses import InitVar, dataclass
import hashlib
import io
import json
import math
import os
from pathlib import Path, PureWindowsPath
import re
import stat
from typing import Any, Mapping
import zipfile

from .contracts import canonical_sha256
from .windows_base_release_suite import (
    BaseReleaseSuiteVerificationError,
    VerifiedBaseReleaseSuite,
    VerifiedBaseReleaseSuiteRole,
    suite_binding_for_base_archive,
    verify_base_release_suite,
)
from .windows_external_status_monitor_factory_template import (
    MONITOR_PROVIDER_ROLES,
    MonitorProviderBinding,
    monitor_provider_contracts,
    windows_external_status_monitor_factory_contract,
)


PACK_INPUT_SCHEMA = "windows-status-monitor-provider-pack-input-v1"
PROVIDER_CONFIGURATION_SCHEMA = (
    "windows-status-monitor-provider-configuration-v1"
)
PACK_VALIDATION_SCHEMA = (
    "windows-status-monitor-provider-pack-validation-v1"
)
PACK_STATUS = "EXTERNAL_PROVIDER_ACCEPTANCE_REQUIRED"
STATUS_MONITOR_PROFILE = "WINDOWS_EXTERNAL_STATUS_MONITOR_V1"
FOUNDATION_PATHS = (
    "live_runtime/offhost_delivery.py",
    "live_runtime/windows_provider_primitives.py",
    "live_runtime/windows_status_monitor_provider_pack.py",
)
GENERATED_PATHS = (
    "config/windows_service_config.json",
    "configured_providers/__init__.py",
    "configured_providers/status_monitor_provider.py",
    "reviewed_windows_factory.py",
)
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_BASE_ARCHIVE_BYTES = 256 * 1024 * 1024
ORDER_CAPABILITY = "DISABLED"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_LOT = 0.01
PROMOTION_ELIGIBLE = False
PRODUCTION_EXECUTION_READY = False

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_DRIVE = re.compile(r"^[A-Z]:$")
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
        "url",
    }
)
_WINDOWS_RESERVED = frozenset(
    {
        "aux",
        "clock$",
        "con",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)
_INPUT_FIELDS = frozenset(
    {
        "checkpoint",
        "clock_binding",
        "credential_references",
        "credential_target_prefix",
        "delivery",
        "incident",
        "keys",
        "pack_id",
        "provider_timeout_seconds",
        "runtime",
        "safety",
        "schema_version",
        "storage",
    }
)
_RUNTIME_INPUT_FIELDS = frozenset(
    {
        "alert_destination_id",
        "cycle_deadline_seconds",
        "decision_ipc_binding_sha256",
        "decision_release_identity_sha256",
        "decision_service_account_id",
        "decision_service_id",
        "decision_task_definition_sha256",
        "execution_release_identity_sha256",
        "execution_service_account_id",
        "execution_service_id",
        "execution_task_definition_sha256",
        "heartbeat_destination_id",
        "incident_latch_provider_id",
        "max_cycles",
        "monitor_provider_id",
        "monitor_service_account_id",
        "monitor_service_id",
        "poll_seconds",
        "snapshot_checkpoint_provider_id",
        "thresholds",
    }
)
_RUNTIME_OUTPUT_FIELDS = frozenset(
    {
        *_RUNTIME_INPUT_FIELDS,
        "live_allowed",
        "max_lot",
        "order_capability",
        "production_execution_ready",
        "promotion_eligible",
        "providers",
        "release_profile",
        "safe_to_demo_auto_order",
        "schema_version",
        "status_only",
    }
) - {"production_execution_ready"}
_THRESHOLD_FIELDS = frozenset(
    {
        "max_audit_export_age_seconds",
        "max_backup_anchor_age_seconds",
        "max_clock_drift_seconds",
        "max_service_status_age_seconds",
        "max_snapshot_age_seconds",
        "minimum_free_disk_gib",
        "schema_version",
    }
)
_CLOCK_FIELDS = frozenset(
    {
        "authority_issuer_id",
        "authority_key_fingerprint_sha256",
        "authority_key_id",
        "host_identity_sha256",
        "maximum_absolute_drift_ms",
        "maximum_attestation_age_ms",
        "provider_id",
        "schema_version",
    }
)
_CREDENTIAL_FIELDS = frozenset(
    {"fingerprint_sha256", "key_id", "target_name"}
)
_KEY_FIELDS = frozenset(
    {
        "alert_sender_key_id",
        "checkpoint_key_id",
        "heartbeat_sender_key_id",
        "incident_key_id",
        "remote_ack_key_id",
        "snapshot_key_id",
    }
)
_STORAGE_FIELDS = frozenset(
    {
        "alert_outbox_database",
        "checkpoint_current_path",
        "clock_attestation_path",
        "heartbeat_outbox_database",
        "snapshot_directory",
    }
)
_CHECKPOINT_FIELDS = frozenset(
    {"provider_id", "request_directory", "response_directory"}
)
_INCIDENT_FIELDS = _CHECKPOINT_FIELDS
_DELIVERY_FIELDS = frozenset(
    {
        "alert_acknowledgement_directory",
        "alert_outbound_directory",
        "heartbeat_acknowledgement_directory",
        "heartbeat_outbound_directory",
    }
)
_SAFETY = {
    "live_allowed": False,
    "max_lot": 0.01,
    "order_capability": "DISABLED",
    "production_execution_ready": False,
    "promotion_eligible": False,
    "safe_to_demo_auto_order": False,
    "status_only": True,
}
_PROVIDER_CONFIG_FIELDS = frozenset(
    {
        "alert_acknowledgement_directory",
        "alert_outbound_directory",
        "alert_outbox_database",
        "alert_sender_key_id",
        "base_suite_identity_sha256",
        "checkpoint_current_path",
        "checkpoint_key_id",
        "checkpoint_provider_id",
        "checkpoint_request_directory",
        "checkpoint_response_directory",
        "clock_attestation_path",
        "clock_binding",
        "credential_references",
        "credential_target_prefix",
        "heartbeat_acknowledgement_directory",
        "heartbeat_outbound_directory",
        "heartbeat_outbox_database",
        "heartbeat_sender_key_id",
        "incident_key_id",
        "incident_provider_id",
        "incident_request_directory",
        "incident_response_directory",
        "live_allowed",
        "max_lot",
        "order_capability",
        "pack_id",
        "production_execution_ready",
        "promotion_eligible",
        "provider_bindings",
        "provider_timeout_seconds",
        "remote_ack_key_id",
        "runtime_config_sha256",
        "safe_to_demo_auto_order",
        "schema_version",
        "snapshot_directory",
        "snapshot_key_id",
        "status_monitor_base_release_identity_sha256",
        "status_only",
    }
)
_PROVIDER_BINDING_FIELDS = frozenset(
    {
        "configuration_sha256",
        "contract_sha256",
        "custody_mode",
        "implementation_sha256",
        "role",
    }
)
_CUSTODY = {
    item["role"]: item["custody_mode"]
    for item in windows_external_status_monitor_factory_contract()[
        "providers"
    ]
}
_FACTORY_IMPORTS = frozenset(
    {
        "configured_providers.status_monitor_provider",
        "live_runtime.windows_external_status_monitor_entrypoint",
    }
)
_PROVIDER_IMPORTS = frozenset(
    {
        "json",
        "live_runtime.windows_status_monitor_provider_pack",
    }
)
_RESULT_SEAL = object()


class StatusMonitorProviderPackError(RuntimeError):
    """One pack failed closed with a stable non-sensitive reason."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: str) -> None:
        normalized = str(reason_code or "").strip().upper()
        if _REASON.fullmatch(normalized) is None:
            normalized = "STATUS_MONITOR_PROVIDER_PACK_INVALID"
        self.reason_code = normalized
        super().__init__(normalized)


@dataclass(frozen=True, slots=True)
class StatusMonitorProviderPackValidation:
    output_root: str
    pack_id: str
    pack_identity_sha256: str
    base_suite_identity_sha256: str
    status_monitor_base_release_identity_sha256: str
    file_sha256: tuple[tuple[str, str], ...]
    status: str = PACK_STATUS
    credential_access_performed: bool = False
    provider_materialization_performed: bool = False
    provider_request_performed: bool = False
    sqlite_open_performed: bool = False
    runtime_process_started: bool = False
    mt5_initialized: bool = False
    broker_mutation_performed: bool = False
    production_execution_ready: bool = False
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    max_lot: float = MAX_LOT
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    schema_version: str = PACK_VALIDATION_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _RESULT_SEAL:
            raise TypeError("provider pack validation requires seal")
        if (
            type(self.output_root) is not str
            or not self.output_root
            or _ID.fullmatch(self.pack_id) is None
            or _HASH.fullmatch(self.pack_identity_sha256) is None
            or _HASH.fullmatch(self.base_suite_identity_sha256) is None
            or _HASH.fullmatch(
                self.status_monitor_base_release_identity_sha256
            )
            is None
            or tuple(path for path, _value in self.file_sha256)
            != GENERATED_PATHS
            or any(_HASH.fullmatch(value) is None for _, value in self.file_sha256)
            or self.status != PACK_STATUS
            or self.credential_access_performed is not False
            or self.provider_materialization_performed is not False
            or self.provider_request_performed is not False
            or self.sqlite_open_performed is not False
            or self.runtime_process_started is not False
            or self.mt5_initialized is not False
            or self.broker_mutation_performed is not False
            or self.production_execution_ready is not False
            or self.order_capability != ORDER_CAPABILITY
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or self.max_lot != MAX_LOT
            or self.promotion_eligible is not False
            or self.schema_version != PACK_VALIDATION_SCHEMA
        ):
            raise ValueError("provider pack validation safety drift")


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
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_DOCUMENT_INVALID"
        ) from exc
    return data + (b"\n" if newline else b"")


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _strict_json(data: bytes, *, canonical: bool) -> dict[str, Any]:
    if type(data) is not bytes or not data or len(data) > MAX_FILE_BYTES:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_INPUT_INVALID"
        )
    try:
        parsed = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON")
            ),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_INPUT_INVALID"
        ) from exc
    if type(parsed) is not dict:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_INPUT_INVALID"
        )
    expected = _canonical_bytes(parsed, newline=True)
    if canonical and expected != data:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_INPUT_NONCANONICAL"
        )
    return parsed


def _reject_sensitive(value: object) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).casefold() in _SENSITIVE_KEYS:
                raise StatusMonitorProviderPackError(
                    "PROVIDER_PACK_SECRET_FIELD_FORBIDDEN"
                )
            _reject_sensitive(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_sensitive(item)


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
    path: str | Path,
    *,
    maximum_bytes: int,
    reason_code: str,
) -> bytes:
    target = Path(path)
    try:
        before = target.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or _is_reparse(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            raise OSError("unsafe file")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(target, flags)
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
        after = target.lstat()
        if (
            _identity(before) != _identity(after)
            or len(data) != before.st_size
            or not data
            or len(data) > maximum_bytes
        ):
            raise OSError("file changed")
        return data
    except (FileNotFoundError, OSError) as exc:
        raise StatusMonitorProviderPackError(reason_code) from exc


def _mapping(
    value: object,
    fields: frozenset[str],
    code: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise StatusMonitorProviderPackError(code)
    return dict(value)


def _identifier(value: object, code: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise StatusMonitorProviderPackError(code)
    return value


def _hash(value: object, code: str, *, zero_allowed: bool = False) -> str:
    if (
        type(value) is not str
        or _HASH.fullmatch(value) is None
        or (not zero_allowed and value == "0" * 64)
    ):
        raise StatusMonitorProviderPackError(code)
    return value


def _integer(
    value: object,
    code: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise StatusMonitorProviderPackError(code)
    return value


def _number(
    value: object,
    code: str,
    *,
    minimum: float,
    maximum: float,
    positive: bool = False,
) -> float:
    if isinstance(value, bool):
        raise StatusMonitorProviderPackError(code)
    try:
        normalized = float(value)
    except (TypeError, ValueError) as exc:
        raise StatusMonitorProviderPackError(code) from exc
    if (
        not math.isfinite(normalized)
        or normalized < minimum
        or normalized > maximum
        or (positive and normalized <= 0)
    ):
        raise StatusMonitorProviderPackError(code)
    return normalized


def _windows_path(value: object) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_WINDOWS_PATH_INVALID"
        )
    if "/" in value or "\x00" in value:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_WINDOWS_PATH_INVALID"
        )
    path = PureWindowsPath(value)
    parts = path.parts
    if (
        not path.is_absolute()
        or not parts
        or _DRIVE.fullmatch(path.drive) is None
        or path.drive != path.drive.upper()
        or path.anchor != f"{path.drive}\\"
        or str(path) != value
        or any(
            part in {"", ".", ".."}
            or part.endswith((" ", "."))
            or ":" in part
            or part.casefold().split(".", 1)[0] in _WINDOWS_RESERVED
            for part in parts[1:]
        )
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_WINDOWS_PATH_INVALID"
        )
    return value


def _paths_overlap(values: list[str]) -> bool:
    paths = [
        tuple(part.casefold() for part in PureWindowsPath(value).parts)
        for value in values
    ]
    for index, first in enumerate(paths):
        for second in paths[index + 1 :]:
            length = min(len(first), len(second))
            if first[:length] == second[:length]:
                return True
    return False


def _validated_runtime(value: object) -> dict[str, Any]:
    runtime = _mapping(
        value,
        _RUNTIME_INPUT_FIELDS,
        "PROVIDER_PACK_RUNTIME_INVALID",
    )
    for name in (
        "alert_destination_id",
        "decision_service_account_id",
        "decision_service_id",
        "execution_service_account_id",
        "execution_service_id",
        "heartbeat_destination_id",
        "incident_latch_provider_id",
        "monitor_provider_id",
        "monitor_service_account_id",
        "monitor_service_id",
        "snapshot_checkpoint_provider_id",
    ):
        runtime[name] = _identifier(
            runtime[name],
            "PROVIDER_PACK_RUNTIME_INVALID",
        )
    services = {
        runtime["monitor_service_id"].casefold(),
        runtime["decision_service_id"].casefold(),
        runtime["execution_service_id"].casefold(),
    }
    accounts = {
        runtime["monitor_service_account_id"].casefold(),
        runtime["decision_service_account_id"].casefold(),
        runtime["execution_service_account_id"].casefold(),
    }
    providers = {
        runtime["monitor_provider_id"].casefold(),
        runtime["snapshot_checkpoint_provider_id"].casefold(),
        runtime["incident_latch_provider_id"].casefold(),
    }
    destinations = {
        runtime["heartbeat_destination_id"].casefold(),
        runtime["alert_destination_id"].casefold(),
    }
    if (
        len(services) != 3
        or len(accounts) != 3
        or len(providers) != 3
        or len(destinations) != 2
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_RUNTIME_IDENTITY_COLLISION"
        )
    for name in (
        "decision_ipc_binding_sha256",
        "decision_release_identity_sha256",
        "decision_task_definition_sha256",
        "execution_release_identity_sha256",
        "execution_task_definition_sha256",
    ):
        runtime[name] = _hash(
            runtime[name],
            "PROVIDER_PACK_RUNTIME_INVALID",
        )
    if (
        runtime["decision_release_identity_sha256"]
        == runtime["execution_release_identity_sha256"]
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_RUNTIME_INVALID"
        )
    thresholds = _mapping(
        runtime["thresholds"],
        _THRESHOLD_FIELDS,
        "PROVIDER_PACK_THRESHOLDS_INVALID",
    )
    if (
        thresholds["schema_version"]
        != "windows-external-status-monitor-thresholds-v1"
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_THRESHOLDS_INVALID"
        )
    thresholds["max_clock_drift_seconds"] = _number(
        thresholds["max_clock_drift_seconds"],
        "PROVIDER_PACK_THRESHOLDS_INVALID",
        minimum=0.000001,
        maximum=1.0,
        positive=True,
    )
    thresholds["minimum_free_disk_gib"] = _number(
        thresholds["minimum_free_disk_gib"],
        "PROVIDER_PACK_THRESHOLDS_INVALID",
        minimum=5.0,
        maximum=1_000_000.0,
    )
    for name, maximum in (
        ("max_service_status_age_seconds", 30),
        ("max_audit_export_age_seconds", 300),
        ("max_backup_anchor_age_seconds", 86_400),
        ("max_snapshot_age_seconds", 30),
    ):
        thresholds[name] = _integer(
            thresholds[name],
            "PROVIDER_PACK_THRESHOLDS_INVALID",
            minimum=1,
            maximum=maximum,
        )
    runtime["thresholds"] = thresholds
    runtime["max_cycles"] = _integer(
        runtime["max_cycles"],
        "PROVIDER_PACK_RUNTIME_INVALID",
        minimum=1,
        maximum=1_000_000,
    )
    runtime["poll_seconds"] = _number(
        runtime["poll_seconds"],
        "PROVIDER_PACK_RUNTIME_INVALID",
        minimum=0.0,
        maximum=60.0,
    )
    runtime["cycle_deadline_seconds"] = _number(
        runtime["cycle_deadline_seconds"],
        "PROVIDER_PACK_RUNTIME_INVALID",
        minimum=0.01,
        maximum=30.0,
        positive=True,
    )
    return runtime


def _validated_clock(value: object) -> dict[str, Any]:
    clock = _mapping(
        value,
        _CLOCK_FIELDS,
        "PROVIDER_PACK_CLOCK_INVALID",
    )
    for name in (
        "authority_issuer_id",
        "authority_key_id",
        "provider_id",
    ):
        clock[name] = _identifier(
            clock[name],
            "PROVIDER_PACK_CLOCK_INVALID",
        )
    for name in (
        "authority_key_fingerprint_sha256",
        "host_identity_sha256",
    ):
        clock[name] = _hash(
            clock[name],
            "PROVIDER_PACK_CLOCK_INVALID",
        )
    clock["maximum_attestation_age_ms"] = _integer(
        clock["maximum_attestation_age_ms"],
        "PROVIDER_PACK_CLOCK_INVALID",
        minimum=1,
        maximum=60_000,
    )
    clock["maximum_absolute_drift_ms"] = _integer(
        clock["maximum_absolute_drift_ms"],
        "PROVIDER_PACK_CLOCK_INVALID",
        minimum=0,
        maximum=1_000,
    )
    if clock["schema_version"] != "windows-clock-binding-v1":
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_CLOCK_INVALID"
        )
    return clock


def _validated_input(payload: object) -> dict[str, Any]:
    root = _mapping(
        payload,
        _INPUT_FIELDS,
        "PROVIDER_PACK_FIELDS_INVALID",
    )
    _reject_sensitive(root)
    if root["schema_version"] != PACK_INPUT_SCHEMA:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_SCHEMA_INVALID"
        )
    root["pack_id"] = _identifier(
        root["pack_id"],
        "PROVIDER_PACK_ID_INVALID",
    )
    runtime = _validated_runtime(root["runtime"])
    if root["pack_id"] != runtime["monitor_provider_id"]:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_RUNTIME_BINDING_MISMATCH"
        )
    clock = _validated_clock(root["clock_binding"])
    prefix = root["credential_target_prefix"]
    if (
        type(prefix) is not str
        or not prefix
        or prefix != prefix.strip()
        or prefix.endswith(("/", "\\"))
        or "\\" in prefix
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_CREDENTIAL_PREFIX_INVALID"
        )
    keys = _mapping(
        root["keys"],
        _KEY_FIELDS,
        "PROVIDER_PACK_KEYS_INVALID",
    )
    for name in keys:
        keys[name] = _identifier(
            keys[name],
            "PROVIDER_PACK_KEYS_INVALID",
        )
    role_key_ids = (
        clock["authority_key_id"],
        keys["snapshot_key_id"],
        keys["checkpoint_key_id"],
        keys["incident_key_id"],
        keys["heartbeat_sender_key_id"],
        keys["alert_sender_key_id"],
        keys["remote_ack_key_id"],
    )
    if len({value.casefold() for value in role_key_ids}) != 7:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_KEY_DOMAIN_COLLISION"
        )
    raw_references = root["credential_references"]
    if type(raw_references) is not list or len(raw_references) != 7:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_CREDENTIAL_REFERENCES_INVALID"
        )
    references = []
    for raw in raw_references:
        item = _mapping(
            raw,
            _CREDENTIAL_FIELDS,
            "PROVIDER_PACK_CREDENTIAL_REFERENCES_INVALID",
        )
        item["key_id"] = _identifier(
            item["key_id"],
            "PROVIDER_PACK_CREDENTIAL_REFERENCES_INVALID",
        )
        item["fingerprint_sha256"] = _hash(
            item["fingerprint_sha256"],
            "PROVIDER_PACK_CREDENTIAL_REFERENCES_INVALID",
        )
        if item["target_name"] != f"{prefix}/{item['key_id']}":
            raise StatusMonitorProviderPackError(
                "PROVIDER_PACK_CREDENTIAL_REFERENCES_INVALID"
            )
        references.append(item)
    references.sort(key=lambda item: item["key_id"])
    if (
        {item["key_id"] for item in references} != set(role_key_ids)
        or len(
            {item["key_id"].casefold() for item in references}
        )
        != 7
        or len(
            {item["target_name"].casefold() for item in references}
        )
        != 7
        or next(
            item
            for item in references
            if item["key_id"] == clock["authority_key_id"]
        )["fingerprint_sha256"]
        != clock["authority_key_fingerprint_sha256"]
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_CREDENTIAL_REFERENCES_INVALID"
        )
    storage = _mapping(
        root["storage"],
        _STORAGE_FIELDS,
        "PROVIDER_PACK_STORAGE_INVALID",
    )
    checkpoint = _mapping(
        root["checkpoint"],
        _CHECKPOINT_FIELDS,
        "PROVIDER_PACK_CHECKPOINT_INVALID",
    )
    incident = _mapping(
        root["incident"],
        _INCIDENT_FIELDS,
        "PROVIDER_PACK_INCIDENT_INVALID",
    )
    delivery = _mapping(
        root["delivery"],
        _DELIVERY_FIELDS,
        "PROVIDER_PACK_DELIVERY_INVALID",
    )
    for mapping in (storage, checkpoint, incident, delivery):
        for name, value in tuple(mapping.items()):
            if name == "provider_id":
                mapping[name] = _identifier(
                    value,
                    "PROVIDER_PACK_PROVIDER_ID_INVALID",
                )
            else:
                mapping[name] = _windows_path(value)
    if (
        checkpoint["provider_id"]
        != runtime["snapshot_checkpoint_provider_id"]
        or incident["provider_id"]
        != runtime["incident_latch_provider_id"]
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_RUNTIME_BINDING_MISMATCH"
        )
    paths = [
        *storage.values(),
        checkpoint["request_directory"],
        checkpoint["response_directory"],
        incident["request_directory"],
        incident["response_directory"],
        *delivery.values(),
    ]
    if _paths_overlap(paths):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_PATH_COLLISION"
        )
    timeout = _number(
        root["provider_timeout_seconds"],
        "PROVIDER_PACK_TIMEOUT_INVALID",
        minimum=0.0,
        maximum=2.0,
        positive=True,
    )
    if root["safety"] != _SAFETY:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_SAFETY_INVALID"
        )
    root.update(
        {
            "runtime": runtime,
            "clock_binding": clock,
            "credential_target_prefix": prefix,
            "credential_references": references,
            "keys": keys,
            "storage": storage,
            "checkpoint": checkpoint,
            "incident": incident,
            "delivery": delivery,
            "provider_timeout_seconds": timeout,
        }
    )
    return root


def _verify_suite_and_foundation(
    *,
    base_suite_root: str | Path,
    status_monitor_base_release: str | Path,
) -> tuple[
    VerifiedBaseReleaseSuite,
    VerifiedBaseReleaseSuiteRole,
    dict[str, bytes],
]:
    try:
        suite = verify_base_release_suite(base_suite_root)
        binding = suite_binding_for_base_archive(
            suite,
            status_monitor_base_release,
            STATUS_MONITOR_PROFILE,
        )
        role = suite.role("STATUS_MONITOR")
    except (
        BaseReleaseSuiteVerificationError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise StatusMonitorProviderPackError(
            "STATUS_MONITOR_BASE_SUITE_BINDING_MISMATCH"
        ) from exc
    if (
        binding["role"] != "STATUS_MONITOR"
        or role.archive_path
        != Path(status_monitor_base_release).expanduser().absolute()
    ):
        raise StatusMonitorProviderPackError(
            "STATUS_MONITOR_BASE_SUITE_BINDING_MISMATCH"
        )
    archive_bytes = _stable_read(
        role.archive_path,
        maximum_bytes=MAX_BASE_ARCHIVE_BYTES,
        reason_code="STATUS_MONITOR_BASE_ARCHIVE_INVALID",
    )
    if _sha256(archive_bytes) != role.archive_sha256:
        raise StatusMonitorProviderPackError(
            "STATUS_MONITOR_BASE_ARCHIVE_CHANGED"
        )
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            members = {}
            for path in FOUNDATION_PATHS:
                matches = [
                    item
                    for item in archive.infolist()
                    if item.filename == path
                ]
                if len(matches) != 1:
                    raise StatusMonitorProviderPackError(
                        "STATUS_MONITOR_PROVIDER_FOUNDATION_MISSING"
                    )
                info = matches[0]
                if (
                    info.is_dir()
                    or info.file_size <= 0
                    or info.file_size > MAX_FILE_BYTES
                ):
                    raise StatusMonitorProviderPackError(
                        "STATUS_MONITOR_PROVIDER_FOUNDATION_MISSING"
                    )
                data = archive.read(info)
                if len(data) != info.file_size:
                    raise StatusMonitorProviderPackError(
                        "STATUS_MONITOR_PROVIDER_FOUNDATION_MISSING"
                    )
                members[path] = data
    except StatusMonitorProviderPackError:
        raise
    except (KeyError, OSError, zipfile.BadZipFile) as exc:
        raise StatusMonitorProviderPackError(
            "STATUS_MONITOR_PROVIDER_FOUNDATION_MISSING"
        ) from exc
    return suite, role, members


def _runtime_core(runtime: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **dict(runtime),
        "status_only": True,
        "order_capability": ORDER_CAPABILITY,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "promotion_eligible": False,
        "max_lot": MAX_LOT,
        "release_profile": STATUS_MONITOR_PROFILE,
        "schema_version": "windows-external-status-monitor-config-v1",
    }


def _validated_runtime_output(
    value: object,
) -> tuple[dict[str, Any], tuple[MonitorProviderBinding, ...]]:
    payload = _mapping(
        value,
        _RUNTIME_OUTPUT_FIELDS,
        "PROVIDER_PACK_RUNTIME_CONFIG_INVALID",
    )
    normalized = _validated_runtime(
        {name: payload[name] for name in _RUNTIME_INPUT_FIELDS}
    )
    if (
        payload["status_only"] is not True
        or payload["order_capability"] != ORDER_CAPABILITY
        or payload["live_allowed"] is not False
        or payload["safe_to_demo_auto_order"] is not False
        or payload["promotion_eligible"] is not False
        or payload["max_lot"] != MAX_LOT
        or payload["release_profile"] != STATUS_MONITOR_PROFILE
        or payload["schema_version"]
        != "windows-external-status-monitor-config-v1"
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_RUNTIME_CONFIG_INVALID"
        )
    raw_bindings = payload.get("providers")
    if type(raw_bindings) is not list:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_RUNTIME_CONFIG_INVALID"
        )
    bindings = []
    for item in raw_bindings:
        raw = _mapping(
            item,
            _PROVIDER_BINDING_FIELDS,
            "PROVIDER_PACK_RUNTIME_CONFIG_INVALID",
        )
        try:
            bindings.append(MonitorProviderBinding(**raw))
        except (TypeError, ValueError) as exc:
            raise StatusMonitorProviderPackError(
                "PROVIDER_PACK_RUNTIME_CONFIG_INVALID"
            ) from exc
    if tuple(item.role for item in bindings) != MONITOR_PROVIDER_ROLES:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_RUNTIME_CONFIG_INVALID"
        )
    return {
        **normalized,
        "status_only": True,
        "order_capability": ORDER_CAPABILITY,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "promotion_eligible": False,
        "max_lot": MAX_LOT,
        "release_profile": STATUS_MONITOR_PROFILE,
        "schema_version": "windows-external-status-monitor-config-v1",
        "providers": [
            item.to_canonical_dict() for item in bindings
        ],
    }, tuple(bindings)


def validate_windows_status_monitor_runtime_configuration(
    value: object,
) -> tuple[dict[str, Any], tuple[MonitorProviderBinding, ...]]:
    """Validate canonical runtime data without importing service runtime code."""

    return _validated_runtime_output(value)


def _provider_core(
    pack: Mapping[str, Any],
    *,
    suite_identity_sha256: str,
    release_identity_sha256: str,
) -> dict[str, Any]:
    storage = pack["storage"]
    checkpoint = pack["checkpoint"]
    incident = pack["incident"]
    delivery = pack["delivery"]
    keys = pack["keys"]
    return {
        "pack_id": pack["pack_id"],
        "base_suite_identity_sha256": suite_identity_sha256,
        "status_monitor_base_release_identity_sha256": (
            release_identity_sha256
        ),
        "runtime_config_sha256": canonical_sha256(
            _runtime_core(pack["runtime"])
        ),
        "clock_binding": pack["clock_binding"],
        "credential_target_prefix": (
            pack["credential_target_prefix"]
        ),
        "credential_references": pack["credential_references"],
        **keys,
        **storage,
        "checkpoint_provider_id": checkpoint["provider_id"],
        "checkpoint_request_directory": (
            checkpoint["request_directory"]
        ),
        "checkpoint_response_directory": (
            checkpoint["response_directory"]
        ),
        "incident_provider_id": incident["provider_id"],
        "incident_request_directory": incident["request_directory"],
        "incident_response_directory": (
            incident["response_directory"]
        ),
        **delivery,
        "provider_timeout_seconds": (
            pack["provider_timeout_seconds"]
        ),
        **_SAFETY,
        "schema_version": PROVIDER_CONFIGURATION_SCHEMA,
    }


def _implementation_hashes(
    foundation_files: Mapping[str, bytes],
) -> dict[str, str]:
    if set(foundation_files) != set(FOUNDATION_PATHS):
        raise StatusMonitorProviderPackError(
            "STATUS_MONITOR_PROVIDER_FOUNDATION_MISSING"
        )
    inventory = [
        {
            "path": path,
            "sha256": _sha256(foundation_files[path]),
        }
        for path in FOUNDATION_PATHS
    ]
    return {
        role: canonical_sha256(
            {
                "schema_version": (
                    "windows-status-monitor-provider-implementation-v1"
                ),
                "role": role,
                "foundation_files": inventory,
            }
        )
        for role in MONITOR_PROVIDER_ROLES
    }


def _provider_bindings(
    core: Mapping[str, Any],
    foundation_files: Mapping[str, bytes],
) -> list[dict[str, Any]]:
    implementations = _implementation_hashes(foundation_files)
    contracts = monitor_provider_contracts()
    return [
        MonitorProviderBinding(
            role=role,
            contract_sha256=contracts[role],
            implementation_sha256=implementations[role],
            configuration_sha256=canonical_sha256(
                {
                    "schema_version": (
                        "windows-status-monitor-provider-role-config-v1"
                    ),
                    "role": role,
                    "provider_configuration": core,
                }
            ),
            custody_mode=_CUSTODY[role],
        ).to_canonical_dict()
        for role in MONITOR_PROVIDER_ROLES
    ]


def _factory_bytes() -> bytes:
    return (
        b'"""Generated sealed Status Monitor factory; no activation authority."""\n'
        b"\n"
        b"from configured_providers.status_monitor_provider import build_dependencies\n"
        b"from live_runtime.windows_external_status_monitor_entrypoint import (\n"
        b"    seal_windows_external_status_monitor_factory_result,\n"
        b")\n"
        b"\n"
        b"\n"
        b"def build(runtime_config, context):\n"
        b"    provider_template = runtime_config.factory_template(\n"
        b"        release_identity_sha256=context.release_identity_sha256,\n"
        b"        factory_implementation_sha256=context.factory_file_sha256,\n"
        b"        factory_configuration_sha256=context.service_config_file_sha256,\n"
        b"    )\n"
        b"    dependencies = build_dependencies(runtime_config)\n"
        b"    return seal_windows_external_status_monitor_factory_result(\n"
        b"        runtime_config=runtime_config,\n"
        b"        provider_template=provider_template,\n"
        b"        context=context,\n"
        b"        dependencies=dependencies,\n"
        b"    )\n"
    )


def _provider_module_bytes(configuration: Mapping[str, Any]) -> bytes:
    payload = json.dumps(
        configuration,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return (
        '"""Generated non-secret Status Monitor provider configuration."""\n'
        "\n"
        "import json\n"
        "\n"
        "from live_runtime.windows_status_monitor_provider_pack import (\n"
        "    build_windows_status_monitor_dependencies,\n"
        "    windows_status_monitor_provider_configuration_from_dict,\n"
        ")\n"
        "\n"
        f"_PROVIDER_CONFIGURATION_JSON = {payload!r}\n"
        "\n"
        "\n"
        "def build_dependencies(runtime_config):\n"
        "    provider_config = (\n"
        "        windows_status_monitor_provider_configuration_from_dict(\n"
        "            json.loads(_PROVIDER_CONFIGURATION_JSON)\n"
        "        )\n"
        "    )\n"
        "    return build_windows_status_monitor_dependencies(\n"
        "        runtime_config=runtime_config,\n"
        "        provider_config=provider_config,\n"
        "    )\n"
    ).encode("utf-8")


def _initializer_bytes() -> bytes:
    return b'"""Closed generated Status Monitor provider package."""\n'


def _generated_files(
    pack: Mapping[str, Any],
    *,
    suite: VerifiedBaseReleaseSuite,
    role: VerifiedBaseReleaseSuiteRole,
    foundation_files: Mapping[str, bytes],
) -> tuple[dict[str, bytes], dict[str, Any]]:
    core = _provider_core(
        pack,
        suite_identity_sha256=suite.suite_identity_sha256,
        release_identity_sha256=role.release_identity_sha256,
    )
    bindings = _provider_bindings(core, foundation_files)
    provider_configuration = {
        **core,
        "provider_bindings": bindings,
    }
    runtime = {
        **_runtime_core(pack["runtime"]),
        "providers": bindings,
    }
    parsed, parsed_bindings = _validated_runtime_output(runtime)
    if (
        canonical_sha256(_runtime_core(pack["runtime"]))
        != provider_configuration["runtime_config_sha256"]
        or parsed_bindings
        != tuple(MonitorProviderBinding(**item) for item in bindings)
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_RUNTIME_CONFIG_INVALID"
        )
    files = {
        "config/windows_service_config.json": _canonical_bytes(
            runtime,
            newline=True,
        ),
        "configured_providers/__init__.py": _initializer_bytes(),
        "configured_providers/status_monitor_provider.py": (
            _provider_module_bytes(provider_configuration)
        ),
        "reviewed_windows_factory.py": _factory_bytes(),
    }
    if (
        tuple(sorted(files)) != GENERATED_PATHS
        or sum(len(value) for value in files.values()) > MAX_TOTAL_BYTES
        or any(len(value) > MAX_FILE_BYTES for value in files.values())
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_OUTPUT_INVALID"
        )
    return files, provider_configuration


def _imports(source: bytes, code: str) -> frozenset[str]:
    try:
        tree = ast.parse(source.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise StatusMonitorProviderPackError(code) from exc
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(item.name for item in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0 or not node.module:
                raise StatusMonitorProviderPackError(code)
            modules.add(node.module)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {"eval", "exec", "compile", "__import__"}:
                raise StatusMonitorProviderPackError(code)
    return frozenset(modules)


def _extract_provider_configuration(source: bytes) -> dict[str, Any]:
    try:
        tree = ast.parse(source.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_PROVIDER_MODULE_INVALID"
        ) from exc
    values = []
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "_PROVIDER_CONFIGURATION_JSON"
        ):
            try:
                value = ast.literal_eval(node.value)
            except (TypeError, ValueError) as exc:
                raise StatusMonitorProviderPackError(
                    "PROVIDER_PACK_PROVIDER_MODULE_INVALID"
                ) from exc
            values.append(value)
    if len(values) != 1 or type(values[0]) is not str:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_PROVIDER_MODULE_INVALID"
        )
    try:
        parsed = json.loads(
            values[0],
            object_pairs_hook=_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON")
            ),
        )
    except (ValueError, json.JSONDecodeError) as exc:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_PROVIDER_MODULE_INVALID"
        ) from exc
    if (
        type(parsed) is not dict
        or json.dumps(
            parsed,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        != values[0]
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_PROVIDER_MODULE_INVALID"
        )
    return parsed


def _validated_provider_configuration(
    value: object,
) -> dict[str, Any]:
    config = _mapping(
        value,
        _PROVIDER_CONFIG_FIELDS,
        "PROVIDER_PACK_PROVIDER_CONFIGURATION_INVALID",
    )
    if (
        config["schema_version"] != PROVIDER_CONFIGURATION_SCHEMA
        or config["status_only"] is not True
        or config["order_capability"] != ORDER_CAPABILITY
        or config["live_allowed"] is not False
        or config["safe_to_demo_auto_order"] is not False
        or config["max_lot"] != MAX_LOT
        or config["promotion_eligible"] is not False
        or config["production_execution_ready"] is not False
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_PROVIDER_CONFIGURATION_INVALID"
        )
    for name in (
        "pack_id",
        "snapshot_key_id",
        "checkpoint_key_id",
        "incident_key_id",
        "heartbeat_sender_key_id",
        "alert_sender_key_id",
        "remote_ack_key_id",
        "checkpoint_provider_id",
        "incident_provider_id",
    ):
        config[name] = _identifier(
            config[name],
            "PROVIDER_PACK_PROVIDER_CONFIGURATION_INVALID",
        )
    for name in (
        "base_suite_identity_sha256",
        "status_monitor_base_release_identity_sha256",
        "runtime_config_sha256",
    ):
        config[name] = _hash(
            config[name],
            "PROVIDER_PACK_PROVIDER_CONFIGURATION_INVALID",
        )
    config["clock_binding"] = _validated_clock(
        config["clock_binding"]
    )
    references = config["credential_references"]
    if type(references) is not list or len(references) != 7:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_PROVIDER_CONFIGURATION_INVALID"
        )
    for item in references:
        _mapping(
            item,
            _CREDENTIAL_FIELDS,
            "PROVIDER_PACK_PROVIDER_CONFIGURATION_INVALID",
        )
    for name in (
        "clock_attestation_path",
        "snapshot_directory",
        "checkpoint_current_path",
        "checkpoint_request_directory",
        "checkpoint_response_directory",
        "incident_request_directory",
        "incident_response_directory",
        "heartbeat_outbox_database",
        "alert_outbox_database",
        "heartbeat_outbound_directory",
        "heartbeat_acknowledgement_directory",
        "alert_outbound_directory",
        "alert_acknowledgement_directory",
    ):
        config[name] = _windows_path(config[name])
    config["provider_timeout_seconds"] = _number(
        config["provider_timeout_seconds"],
        "PROVIDER_PACK_PROVIDER_CONFIGURATION_INVALID",
        minimum=0.0,
        maximum=2.0,
        positive=True,
    )
    bindings = config["provider_bindings"]
    if type(bindings) is not list or len(bindings) != len(
        MONITOR_PROVIDER_ROLES
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_PROVIDER_CONFIGURATION_INVALID"
        )
    parsed_bindings = []
    for item in bindings:
        raw = _mapping(
            item,
            _PROVIDER_BINDING_FIELDS,
            "PROVIDER_PACK_PROVIDER_CONFIGURATION_INVALID",
        )
        try:
            parsed_bindings.append(MonitorProviderBinding(**raw))
        except (TypeError, ValueError) as exc:
            raise StatusMonitorProviderPackError(
                "PROVIDER_PACK_PROVIDER_CONFIGURATION_INVALID"
            ) from exc
    if tuple(item.role for item in parsed_bindings) != MONITOR_PROVIDER_ROLES:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_PROVIDER_CONFIGURATION_INVALID"
        )
    return config


def _real_pack_root(path: str | Path) -> Path:
    root = Path(path).expanduser().absolute()
    try:
        metadata = root.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_ROOT_INVALID"
        ) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_ROOT_INVALID"
        )
    return root


def _pack_files(root: Path) -> dict[str, bytes]:
    files = {}
    expected_directories = {
        "config",
        "configured_providers",
    }
    observed_directories = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
            raise StatusMonitorProviderPackError(
                "PROVIDER_PACK_MEMBER_INVALID"
            )
        if path.is_dir():
            observed_directories.add(relative)
            continue
        if not stat.S_ISREG(metadata.st_mode) or relative not in GENERATED_PATHS:
            raise StatusMonitorProviderPackError(
                "PROVIDER_PACK_MEMBER_INVALID"
            )
        files[relative] = _stable_read(
            path,
            maximum_bytes=MAX_FILE_BYTES,
            reason_code="PROVIDER_PACK_MEMBER_INVALID",
        )
    if (
        set(files) != set(GENERATED_PATHS)
        or observed_directories != expected_directories
        or sum(len(value) for value in files.values()) > MAX_TOTAL_BYTES
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_MEMBER_INVALID"
        )
    return files


def _pack_identity(
    *,
    pack_id: str,
    suite_identity_sha256: str,
    release_identity_sha256: str,
    files: Mapping[str, bytes],
) -> str:
    return canonical_sha256(
        {
            "schema_version": (
                "windows-status-monitor-provider-pack-identity-v1"
            ),
            "pack_id": pack_id,
            "base_suite_identity_sha256": suite_identity_sha256,
            "status_monitor_base_release_identity_sha256": (
                release_identity_sha256
            ),
            "files": [
                {
                    "path": path,
                    "sha256": _sha256(files[path]),
                    "size_bytes": len(files[path]),
                }
                for path in GENERATED_PATHS
            ],
            "safety": _SAFETY,
        }
    )


def _result(
    *,
    root: Path,
    pack_id: str,
    suite_identity_sha256: str,
    release_identity_sha256: str,
    files: Mapping[str, bytes],
) -> StatusMonitorProviderPackValidation:
    return StatusMonitorProviderPackValidation(
        output_root=str(root),
        pack_id=pack_id,
        pack_identity_sha256=_pack_identity(
            pack_id=pack_id,
            suite_identity_sha256=suite_identity_sha256,
            release_identity_sha256=release_identity_sha256,
            files=files,
        ),
        base_suite_identity_sha256=suite_identity_sha256,
        status_monitor_base_release_identity_sha256=(
            release_identity_sha256
        ),
        file_sha256=tuple(
            (path, _sha256(files[path])) for path in GENERATED_PATHS
        ),
        _seal=_RESULT_SEAL,
    )


def validate_windows_status_monitor_provider_pack(
    *,
    base_suite_root: str | Path,
    status_monitor_base_release: str | Path,
    pack_root: str | Path,
) -> StatusMonitorProviderPackValidation:
    """Validate exact bytes without importing or materializing providers."""

    suite, role, foundation = _verify_suite_and_foundation(
        base_suite_root=base_suite_root,
        status_monitor_base_release=status_monitor_base_release,
    )
    root = _real_pack_root(pack_root)
    files = _pack_files(root)
    for data in files.values():
        if any(pattern.search(data) for pattern in _SECRET_PATTERNS):
            raise StatusMonitorProviderPackError(
                "PROVIDER_PACK_SECRET_PATTERN_FORBIDDEN"
            )
    if _imports(
        files["reviewed_windows_factory.py"],
        "PROVIDER_PACK_FACTORY_INVALID",
    ) != _FACTORY_IMPORTS:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_FACTORY_INVALID"
        )
    if _imports(
        files["configured_providers/status_monitor_provider.py"],
        "PROVIDER_PACK_PROVIDER_MODULE_INVALID",
    ) != _PROVIDER_IMPORTS:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_PROVIDER_MODULE_INVALID"
        )
    if (
        files["configured_providers/__init__.py"]
        != _initializer_bytes()
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_INITIALIZER_INVALID"
        )
    configuration = _validated_provider_configuration(
        _extract_provider_configuration(
            files["configured_providers/status_monitor_provider.py"]
        )
    )
    if (
        configuration["base_suite_identity_sha256"]
        != suite.suite_identity_sha256
        or configuration[
            "status_monitor_base_release_identity_sha256"
        ]
        != role.release_identity_sha256
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_BASE_IDENTITY_MISMATCH"
        )
    try:
        runtime_payload = _strict_json(
            files["config/windows_service_config.json"],
            canonical=True,
        )
        runtime, runtime_bindings = _validated_runtime_output(
            runtime_payload
        )
    except (
        StatusMonitorProviderPackError,
        TypeError,
        ValueError,
    ) as exc:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_RUNTIME_CONFIG_INVALID"
        ) from exc
    runtime_core = dict(runtime_payload)
    runtime_core.pop("providers")
    if (
        canonical_sha256(runtime_core)
        != configuration["runtime_config_sha256"]
        or runtime["monitor_provider_id"] != configuration["pack_id"]
        or runtime["snapshot_checkpoint_provider_id"]
        != configuration["checkpoint_provider_id"]
        or runtime["incident_latch_provider_id"]
        != configuration["incident_provider_id"]
        or [item.to_canonical_dict() for item in runtime_bindings]
        != configuration["provider_bindings"]
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_RUNTIME_BINDING_MISMATCH"
        )
    core = dict(configuration)
    bindings = core.pop("provider_bindings")
    expected_bindings = _provider_bindings(core, foundation)
    if bindings != expected_bindings:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_PROVIDER_HASH_MISMATCH"
        )
    expected_provider = _provider_module_bytes(configuration)
    if (
        files["configured_providers/status_monitor_provider.py"]
        != expected_provider
        or files["reviewed_windows_factory.py"] != _factory_bytes()
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_GENERATED_SOURCE_MISMATCH"
        )
    return _result(
        root=root,
        pack_id=configuration["pack_id"],
        suite_identity_sha256=suite.suite_identity_sha256,
        release_identity_sha256=role.release_identity_sha256,
        files=files,
    )


def _safe_new_root(path: str | Path) -> Path:
    root = Path(path).expanduser().absolute()
    if root.exists() or root.is_symlink():
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_OUTPUT_EXISTS"
        )
    parent = root.parent
    try:
        metadata = parent.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_OUTPUT_PARENT_INVALID"
        ) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_OUTPUT_PARENT_INVALID"
        )
    return root


def _write_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_OUTPUT_WRITE_FAILED"
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
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_OUTPUT_WRITE_FAILED"
        ) from exc
    finally:
        os.close(descriptor)


def _cleanup(root: Path, files: Mapping[str, bytes]) -> None:
    for relative in reversed(GENERATED_PATHS):
        path = root / relative
        try:
            if path.is_file() and path.read_bytes() == files[relative]:
                path.unlink()
        except OSError:
            pass
    for relative in ("configured_providers", "config"):
        try:
            (root / relative).rmdir()
        except OSError:
            pass
    try:
        root.rmdir()
    except OSError:
        pass


def prepare_windows_status_monitor_provider_pack(
    *,
    base_suite_root: str | Path,
    status_monitor_base_release: str | Path,
    pack_input_path: str | Path,
    output_root: str | Path,
) -> StatusMonitorProviderPackValidation:
    """Generate and independently validate one deterministic pack."""

    suite, role, foundation = _verify_suite_and_foundation(
        base_suite_root=base_suite_root,
        status_monitor_base_release=status_monitor_base_release,
    )
    payload_bytes = _stable_read(
        pack_input_path,
        maximum_bytes=MAX_FILE_BYTES,
        reason_code="PROVIDER_PACK_INPUT_INVALID",
    )
    if any(pattern.search(payload_bytes) for pattern in _SECRET_PATTERNS):
        raise StatusMonitorProviderPackError(
            "PROVIDER_PACK_SECRET_PATTERN_FORBIDDEN"
        )
    pack = _validated_input(
        _strict_json(payload_bytes, canonical=True)
    )
    files, _configuration = _generated_files(
        pack,
        suite=suite,
        role=role,
        foundation_files=foundation,
    )
    for data in files.values():
        if any(pattern.search(data) for pattern in _SECRET_PATTERNS):
            raise StatusMonitorProviderPackError(
                "PROVIDER_PACK_SECRET_PATTERN_FORBIDDEN"
            )
    root = _safe_new_root(output_root)
    created = False
    try:
        root.mkdir(mode=0o700)
        created = True
        (root / "config").mkdir(mode=0o700)
        (root / "configured_providers").mkdir(mode=0o700)
        for relative in GENERATED_PATHS:
            _write_exclusive(root / relative, files[relative])
        result = validate_windows_status_monitor_provider_pack(
            base_suite_root=base_suite_root,
            status_monitor_base_release=status_monitor_base_release,
            pack_root=root,
        )
    except Exception:
        if created:
            _cleanup(root, files)
        raise
    return result


__all__ = [
    "FOUNDATION_PATHS",
    "GENERATED_PATHS",
    "PACK_INPUT_SCHEMA",
    "PACK_STATUS",
    "StatusMonitorProviderPackError",
    "StatusMonitorProviderPackValidation",
    "_implementation_hashes",
    "prepare_windows_status_monitor_provider_pack",
    "validate_windows_status_monitor_runtime_configuration",
    "validate_windows_status_monitor_provider_pack",
]
