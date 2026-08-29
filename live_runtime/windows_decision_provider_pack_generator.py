"""Offline generation and validation for a Windows decision provider pack.

This module is release-operator tooling.  It verifies exact local bytes and
writes a secret-free four-file overlay.  It never imports a generated
factory, resolves a credential, opens provider state, issues CAS traffic,
starts a process, initializes MT5, or performs broker work.
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
import unicodedata
import zipfile

from .windows_base_release_suite import (
    BaseReleaseSuiteVerificationError,
    VerifiedBaseReleaseSuite,
    VerifiedBaseReleaseSuiteRole,
    suite_binding_for_base_archive,
    verify_base_release_suite,
)
from .windows_decision_service_factory_template import (
    PROVIDER_ROLES,
    provider_contracts,
    windows_decision_service_factory_contract,
)


PACK_INPUT_SCHEMA = "windows-decision-provider-pack-input-v1"
PROVIDER_CONFIGURATION_SCHEMA = (
    "windows-decision-provider-configuration-v1"
)
PACK_VALIDATION_SCHEMA = "windows-decision-provider-pack-validation-v1"
PACK_STATUS = "EXTERNAL_PROVIDER_ACCEPTANCE_REQUIRED"
DECISION_PROFILE = "WINDOWS_DECISION_SERVICE_V1"
FOUNDATION_PATH = "live_runtime/windows_decision_provider_pack.py"
PRIMITIVES_PATH = "live_runtime/windows_provider_primitives.py"
FOUNDATION_PATHS = (
    FOUNDATION_PATH,
    PRIMITIVES_PATH,
)
GENERATED_PATHS = (
    "config/windows_service_config.json",
    "configured_providers/__init__.py",
    "configured_providers/decision_provider.py",
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
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DRIVE = re.compile(r"^[A-Z]:$")
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
_PACK_INPUT_FIELDS = frozenset(
    {
        "cas_timeout_seconds",
        "clock_binding",
        "credential_references",
        "credential_target_prefix",
        "decision_feed_binding",
        "decision_ipc_binding",
        "external_cas",
        "pack_id",
        "runtime",
        "safety",
        "schema_version",
        "storage",
    }
)
_RUNTIME_INPUT_FIELDS = frozenset(
    {
        "cycle_deadline_seconds",
        "decision_producer_binding",
        "max_cycles",
        "poll_seconds",
        "service_id",
    }
)
_RUNTIME_OUTPUT_FIELDS = frozenset(
    {
        *_RUNTIME_INPUT_FIELDS,
        "live_allowed",
        "max_lot",
        "order_capability",
        "providers",
        "safe_to_demo_auto_order",
        "schema_version",
    }
)
_SAFETY = {
    "live_allowed": False,
    "max_lot": 0.01,
    "order_capability": "DISABLED",
    "production_execution_ready": False,
    "promotion_eligible": False,
    "safe_to_demo_auto_order": False,
}
_STORAGE_FIELDS = frozenset(
    {
        "clock_attestation_path",
        "decision_ipc_database",
        "finalized_m15_directory",
        "producer_cursor_database",
    }
)
_EXTERNAL_CAS_FIELDS = frozenset({"ipc", "producer"})
_CAS_ENDPOINT_FIELDS = frozenset(
    {"provider_id", "request_directory", "response_directory"}
)
_CREDENTIAL_FIELDS = frozenset(
    {"fingerprint_sha256", "key_id", "target_name"}
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
_PRODUCER_FIELDS = frozenset(
    {
        "custody_issuer_id",
        "custody_key_fingerprint_sha256",
        "custody_key_id",
        "lanes",
        "schema_version",
        "service_id",
    }
)
_PRODUCER_LANE_FIELDS = frozenset(
    {
        "commit_sha",
        "config_sha256",
        "data_contract_sha256",
        "lane_id",
        "maximum_processing_lag_ms",
        "model_artifact_sha256",
        "model_version",
        "session_calendar_issuer_id",
        "session_calendar_key_fingerprint_sha256",
        "session_calendar_key_id",
        "session_calendar_sha256",
        "source_name",
        "symbol",
        "timeframe",
    }
)
_FEED_FIELDS = frozenset(
    {
        "broker_account_identity_sha256",
        "broker_server",
        "feed_id",
        "lanes",
        "live_allowed",
        "max_lot",
        "order_capability",
        "publisher_issuer_id",
        "publisher_key_fingerprint_sha256",
        "publisher_key_id",
        "safe_to_demo_auto_order",
        "schema_version",
    }
)
_FEED_LANE_FIELDS = frozenset(
    {
        "broker_symbol",
        "data_contract_sha256",
        "lane_id",
        "session_calendar_sha256",
        "source_name",
        "symbol",
    }
)
_IPC_FIELDS = frozenset(
    {
        "account_id_sha256",
        "commit_sha",
        "config_sha256",
        "custody_issuer_id",
        "custody_key_fingerprint_sha256",
        "custody_key_id",
        "data_contract_sha256",
        "decision_issuer_id",
        "decision_key_fingerprint_sha256",
        "decision_key_id",
        "environment",
        "journal_sha256",
        "model_artifact_sha256",
        "permit_key_fingerprint_sha256",
        "permit_key_id",
        "queue_id",
        "schema_version",
        "server",
    }
)
_PROVIDER_CONFIGURATION_FIELDS = frozenset(
    {
        "base_suite_identity_sha256",
        "cas_timeout_seconds",
        "clock_attestation_path",
        "clock_binding",
        "credential_references",
        "credential_target_prefix",
        "decision_base_release_identity_sha256",
        "decision_feed_binding",
        "decision_ipc_binding",
        "decision_ipc_database",
        "decision_producer_binding",
        "finalized_m15_directory",
        "ipc_cas_provider_id",
        "ipc_cas_request_directory",
        "ipc_cas_response_directory",
        "live_allowed",
        "max_lot",
        "order_capability",
        "pack_id",
        "producer_cas_provider_id",
        "producer_cas_request_directory",
        "producer_cas_response_directory",
        "producer_cursor_database",
        "promotion_eligible",
        "safe_to_demo_auto_order",
        "schema_version",
    }
)
_PROVIDER_OUTPUT_FIELDS = frozenset(
    {
        "configuration_sha256",
        "contract_sha256",
        "custody_mode",
        "implementation_sha256",
        "role",
    }
)
_CUSTODY_MODES = dict(
    windows_decision_service_factory_contract()[
        "provider_custody_modes"
    ]
)
_RESULT_SEAL = object()


class DecisionProviderPackError(RuntimeError):
    """A pack input failed closed with one stable public reason code."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: str) -> None:
        normalized = str(reason_code or "").strip().upper()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", normalized):
            normalized = "DECISION_PROVIDER_PACK_INVALID"
        self.reason_code = normalized
        super().__init__(normalized)


@dataclass(frozen=True, slots=True)
class DecisionProviderPackValidation:
    output_root: str
    base_suite_identity_sha256: str
    decision_base_release_identity_sha256: str
    pack_id: str
    pack_identity_sha256: str
    file_sha256: tuple[tuple[str, str], ...]
    status: str = PACK_STATUS
    production_execution_ready: bool = PRODUCTION_EXECUTION_READY
    credential_access_performed: bool = False
    provider_materialization_performed: bool = False
    cas_request_performed: bool = False
    runtime_process_started: bool = False
    mt5_initialized: bool = False
    broker_mutation_performed: bool = False
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    max_lot: float = MAX_LOT
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    schema_version: str = PACK_VALIDATION_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _RESULT_SEAL:
            raise TypeError("decision provider pack result requires validator")
        if (
            self.status != PACK_STATUS
            or self.production_execution_ready is not False
            or self.credential_access_performed is not False
            or self.provider_materialization_performed is not False
            or self.cas_request_performed is not False
            or self.runtime_process_started is not False
            or self.mt5_initialized is not False
            or self.broker_mutation_performed is not False
            or self.order_capability != ORDER_CAPABILITY
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or self.max_lot != MAX_LOT
            or self.promotion_eligible is not False
            or self.schema_version != PACK_VALIDATION_SCHEMA
        ):
            raise ValueError("decision provider pack safety drift")


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
        raise DecisionProviderPackError("PACK_JSON_INVALID") from exc


def _canonical_file(value: object) -> bytes:
    return _canonical_bytes(value) + b"\n"


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DecisionProviderPackError("PACK_JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise DecisionProviderPackError("PACK_JSON_NONFINITE")


def _strict_json(data: bytes, *, canonical: bool) -> dict[str, Any]:
    if not data or len(data) > MAX_FILE_BYTES:
        raise DecisionProviderPackError("PACK_JSON_INVALID")
    if any(pattern.search(data) for pattern in _SECRET_PATTERNS):
        raise DecisionProviderPackError("PACK_SECRET_MATERIAL_FORBIDDEN")
    try:
        payload = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_duplicates,
            parse_constant=_reject_constant,
        )
    except DecisionProviderPackError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecisionProviderPackError("PACK_JSON_INVALID") from exc
    if not isinstance(payload, dict):
        raise DecisionProviderPackError("PACK_JSON_INVALID")
    if canonical and data != _canonical_file(payload):
        raise DecisionProviderPackError("PACK_JSON_NOT_CANONICAL")
    _reject_sensitive_json(payload)
    return payload


def _reject_sensitive_json(value: object) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if (
                type(key) is not str
                or key.casefold() in _SENSITIVE_KEYS
            ):
                raise DecisionProviderPackError(
                    "PACK_SENSITIVE_FIELD_FORBIDDEN"
                )
            _reject_sensitive_json(item)
    elif isinstance(value, list):
        for item in value:
            _reject_sensitive_json(item)
    elif isinstance(value, str):
        encoded = value.encode("utf-8", errors="strict")
        if (
            value.casefold().startswith(("hex:", "bearer "))
            or any(pattern.search(encoded) for pattern in _SECRET_PATTERNS)
        ):
            raise DecisionProviderPackError(
                "PACK_SECRET_MATERIAL_FORBIDDEN"
            )


def _stable_read(
    path: Path,
    *,
    maximum_bytes: int,
    reason_code: str,
) -> bytes:
    descriptor: int | None = None
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or _is_reparse(before)
            or before.st_size < 0
            or before.st_size > maximum_bytes
        ):
            raise DecisionProviderPackError(reason_code)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened_before = os.fstat(descriptor)
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        opened_after = os.fstat(descriptor)
        after = path.lstat()
    except DecisionProviderPackError:
        raise
    except OSError as exc:
        raise DecisionProviderPackError(reason_code) from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    payload = b"".join(chunks)
    if (
        len(payload) > maximum_bytes
        or len(payload) != int(before.st_size)
        or _identity(before) != _identity(opened_before)
        or _identity(before) != _identity(opened_after)
        or _identity(before) != _identity(after)
    ):
        raise DecisionProviderPackError(reason_code)
    return payload


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


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(
        int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    )


def _mapping(
    value: object,
    fields: frozenset[str],
    code: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or frozenset(value) != fields:
        raise DecisionProviderPackError(code)
    return dict(value)


def _text(value: object, code: str, *, identifier: bool = False) -> str:
    if (
        type(value) is not str
        or not value
        or value != unicodedata.normalize("NFC", value)
        or any(ord(character) < 32 for character in value)
    ):
        raise DecisionProviderPackError(code)
    if identifier and _ID.fullmatch(value) is None:
        raise DecisionProviderPackError(code)
    return value


def _hash(value: object, code: str) -> str:
    if (
        type(value) is not str
        or _HASH.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise DecisionProviderPackError(code)
    return value


def _commit(value: object, code: str) -> str:
    if type(value) is not str or _COMMIT.fullmatch(value) is None:
        raise DecisionProviderPackError(code)
    return value


def _integer(
    value: object,
    code: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise DecisionProviderPackError(code)
    return value


def _number(
    value: object,
    code: str,
    *,
    minimum: float,
    maximum: float,
    lower_exclusive: bool = False,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DecisionProviderPackError(code)
    normalized = float(value)
    lower_valid = (
        normalized > minimum
        if lower_exclusive
        else normalized >= minimum
    )
    if (
        not math.isfinite(normalized)
        or not lower_valid
        or normalized > maximum
    ):
        raise DecisionProviderPackError(code)
    return normalized


def _windows_path(value: object) -> str:
    text = _text(value, "WINDOWS_PATH_INVALID")
    if (
        len(text) > 240
        or "/" in text
        or "%" in text
        or "$" in text
        or text.startswith("\\\\")
    ):
        raise DecisionProviderPackError("WINDOWS_PATH_INVALID")
    parsed = PureWindowsPath(text)
    if (
        not parsed.is_absolute()
        or _DRIVE.fullmatch(parsed.drive) is None
        or str(parsed) != text
        or parsed.anchor != f"{parsed.drive}\\"
    ):
        raise DecisionProviderPackError("WINDOWS_PATH_INVALID")
    for part in parsed.parts[1:]:
        stem = part.split(".", 1)[0].casefold()
        if (
            part in {"", ".", ".."}
            or part.endswith((" ", "."))
            or any(character in '<>:"|?*' for character in part)
            or any(ord(character) < 32 for character in part)
            or stem in _WINDOWS_RESERVED
        ):
            raise DecisionProviderPackError("WINDOWS_PATH_INVALID")
    return text


def _windows_paths_overlap(paths: list[str]) -> bool:
    normalized = [
        tuple(part.casefold() for part in PureWindowsPath(item).parts)
        for item in paths
    ]
    for index, first in enumerate(normalized):
        for second in normalized[index + 1 :]:
            shorter = min(len(first), len(second))
            if first[:shorter] == second[:shorter]:
                return True
    return False


def _provider_safety(mapping: Mapping[str, object], code: str) -> None:
    if (
        mapping.get("order_capability") != ORDER_CAPABILITY
        or mapping.get("live_allowed") is not False
        or mapping.get("safe_to_demo_auto_order") is not False
        or type(mapping.get("max_lot")) is not float
        or mapping.get("max_lot") != MAX_LOT
    ):
        raise DecisionProviderPackError(code)


def _producer(value: object) -> dict[str, Any]:
    payload = _mapping(
        value,
        _PRODUCER_FIELDS,
        "PRODUCER_BINDING_INVALID",
    )
    if payload["schema_version"] != (
        "brokerless-decision-producer-binding-v2"
    ):
        raise DecisionProviderPackError("PRODUCER_BINDING_INVALID")
    _text(payload["service_id"], "PRODUCER_BINDING_INVALID")
    for name in ("custody_issuer_id", "custody_key_id"):
        _text(payload[name], "PRODUCER_BINDING_INVALID")
    _hash(
        payload["custody_key_fingerprint_sha256"],
        "PRODUCER_BINDING_INVALID",
    )
    lanes = payload["lanes"]
    if not isinstance(lanes, list) or not 1 <= len(lanes) <= 4:
        raise DecisionProviderPackError("PRODUCER_LANE_SET_INVALID")
    normalized: list[dict[str, Any]] = []
    for lane_value in lanes:
        lane = _mapping(
            lane_value,
            _PRODUCER_LANE_FIELDS,
            "PRODUCER_LANE_INVALID",
        )
        for name in (
            "lane_id",
            "source_name",
            "model_version",
            "session_calendar_issuer_id",
            "session_calendar_key_id",
        ):
            _text(lane[name], "PRODUCER_LANE_INVALID")
        symbol = _text(lane["symbol"], "PRODUCER_LANE_INVALID")
        if symbol != symbol.upper():
            raise DecisionProviderPackError("PRODUCER_LANE_INVALID")
        for name in (
            "data_contract_sha256",
            "model_artifact_sha256",
            "config_sha256",
            "session_calendar_sha256",
            "session_calendar_key_fingerprint_sha256",
        ):
            _hash(lane[name], "PRODUCER_LANE_INVALID")
        _commit(lane["commit_sha"], "PRODUCER_LANE_INVALID")
        _integer(
            lane["maximum_processing_lag_ms"],
            "PRODUCER_LANE_INVALID",
            minimum=1,
            maximum=10_000,
        )
        if lane["timeframe"] != "M15":
            raise DecisionProviderPackError("PRODUCER_LANE_INVALID")
        normalized.append(lane)
    normalized.sort(key=lambda item: item["lane_id"])
    ids = [item["lane_id"] for item in normalized]
    if (
        len(ids) != len(set(ids))
        or len(ids) != len({item.casefold() for item in ids})
    ):
        raise DecisionProviderPackError("PRODUCER_LANE_SET_INVALID")
    payload["lanes"] = normalized
    return payload


def _feed(value: object) -> dict[str, Any]:
    payload = _mapping(value, _FEED_FIELDS, "FEED_BINDING_INVALID")
    if payload["schema_version"] != "signed-decision-feed-binding-v1":
        raise DecisionProviderPackError("FEED_BINDING_INVALID")
    _provider_safety(payload, "FEED_BINDING_INVALID")
    for name in (
        "feed_id",
        "broker_server",
        "publisher_issuer_id",
        "publisher_key_id",
    ):
        _text(payload[name], "FEED_BINDING_INVALID")
    for name in (
        "broker_account_identity_sha256",
        "publisher_key_fingerprint_sha256",
    ):
        _hash(payload[name], "FEED_BINDING_INVALID")
    lanes = payload["lanes"]
    if not isinstance(lanes, list) or not 1 <= len(lanes) <= 4:
        raise DecisionProviderPackError("FEED_BINDING_INVALID")
    normalized: list[dict[str, Any]] = []
    for lane_value in lanes:
        lane = _mapping(
            lane_value,
            _FEED_LANE_FIELDS,
            "FEED_LANE_INVALID",
        )
        for name in ("lane_id", "broker_symbol", "source_name"):
            _text(lane[name], "FEED_LANE_INVALID")
        symbol = _text(lane["symbol"], "FEED_LANE_INVALID")
        if symbol != symbol.upper():
            raise DecisionProviderPackError("FEED_LANE_INVALID")
        for name in (
            "data_contract_sha256",
            "session_calendar_sha256",
        ):
            _hash(lane[name], "FEED_LANE_INVALID")
        normalized.append(lane)
    normalized.sort(key=lambda item: item["lane_id"])
    ids = [item["lane_id"] for item in normalized]
    if (
        len(ids) != len(set(ids))
        or len(ids) != len({item.casefold() for item in ids})
    ):
        raise DecisionProviderPackError("FEED_BINDING_INVALID")
    payload["lanes"] = normalized
    return payload


def _ipc(value: object) -> dict[str, Any]:
    payload = _mapping(value, _IPC_FIELDS, "IPC_BINDING_INVALID")
    if (
        payload["schema_version"] != "decision-ipc-binding-v2"
        or payload["environment"] != "DEMO"
    ):
        raise DecisionProviderPackError("IPC_BINDING_INVALID")
    for name in (
        "queue_id",
        "server",
        "decision_issuer_id",
        "decision_key_id",
        "custody_issuer_id",
        "custody_key_id",
        "permit_key_id",
    ):
        _text(payload[name], "IPC_BINDING_INVALID")
    for name in (
        "account_id_sha256",
        "journal_sha256",
        "config_sha256",
        "model_artifact_sha256",
        "data_contract_sha256",
        "decision_key_fingerprint_sha256",
        "custody_key_fingerprint_sha256",
        "permit_key_fingerprint_sha256",
    ):
        _hash(payload[name], "IPC_BINDING_INVALID")
    _commit(payload["commit_sha"], "IPC_BINDING_INVALID")
    return payload


def _clock(value: object) -> dict[str, Any]:
    payload = _mapping(value, _CLOCK_FIELDS, "CLOCK_BINDING_INVALID")
    if payload["schema_version"] != "windows-clock-binding-v1":
        raise DecisionProviderPackError("CLOCK_BINDING_INVALID")
    for name in (
        "provider_id",
        "authority_issuer_id",
        "authority_key_id",
    ):
        _text(payload[name], "CLOCK_BINDING_INVALID")
    for name in (
        "host_identity_sha256",
        "authority_key_fingerprint_sha256",
    ):
        _hash(payload[name], "CLOCK_BINDING_INVALID")
    _integer(
        payload["maximum_attestation_age_ms"],
        "CLOCK_BINDING_INVALID",
        minimum=1,
        maximum=60_000,
    )
    _integer(
        payload["maximum_absolute_drift_ms"],
        "CLOCK_BINDING_INVALID",
        minimum=0,
        maximum=1_000,
    )
    return payload


def _credential_references(
    value: object,
    *,
    prefix: str,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise DecisionProviderPackError("CREDENTIAL_REFERENCE_SET_INVALID")
    references: list[dict[str, Any]] = []
    for raw in value:
        item = _mapping(
            raw,
            _CREDENTIAL_FIELDS,
            "CREDENTIAL_REFERENCE_INVALID",
        )
        key_id = _text(
            item["key_id"],
            "CREDENTIAL_REFERENCE_INVALID",
        )
        _hash(
            item["fingerprint_sha256"],
            "CREDENTIAL_REFERENCE_INVALID",
        )
        if item["target_name"] != f"{prefix}/{key_id}":
            raise DecisionProviderPackError(
                "CREDENTIAL_TARGET_BINDING_INVALID"
            )
        references.append(item)
    references.sort(key=lambda item: item["key_id"])
    ids = [item["key_id"] for item in references]
    targets = [item["target_name"] for item in references]
    if (
        len({item.casefold() for item in ids}) != len(ids)
        or len({item.casefold() for item in targets}) != len(targets)
    ):
        raise DecisionProviderPackError(
            "CREDENTIAL_REFERENCE_SET_INVALID"
        )
    return references


def _validate_cross_bindings(
    *,
    runtime: Mapping[str, object],
    producer: Mapping[str, object],
    feed: Mapping[str, object],
    ipc: Mapping[str, object],
    clock: Mapping[str, object],
    references: list[dict[str, Any]],
) -> None:
    if (
        runtime["service_id"] != producer["service_id"]
        or ipc["decision_issuer_id"] != producer["service_id"]
        or feed["broker_server"] != ipc["server"]
        or feed["broker_account_identity_sha256"]
        != ipc["account_id_sha256"]
    ):
        raise DecisionProviderPackError(
            "PROVIDER_CROSS_BINDING_MISMATCH"
        )
    feed_lanes = {
        item["lane_id"]: item for item in feed["lanes"]
    }
    if set(feed_lanes) != {
        item["lane_id"] for item in producer["lanes"]
    }:
        raise DecisionProviderPackError(
            "PROVIDER_CROSS_BINDING_MISMATCH"
        )
    for lane in producer["lanes"]:
        observed = feed_lanes[lane["lane_id"]]
        if (
            observed["symbol"] != lane["symbol"]
            or observed["source_name"] != lane["source_name"]
            or observed["data_contract_sha256"]
            != lane["data_contract_sha256"]
            or observed["session_calendar_sha256"]
            != lane["session_calendar_sha256"]
            or lane["commit_sha"] != ipc["commit_sha"]
            or lane["config_sha256"] != ipc["config_sha256"]
            or lane["model_artifact_sha256"]
            != ipc["model_artifact_sha256"]
            or lane["data_contract_sha256"]
            != ipc["data_contract_sha256"]
        ):
            raise DecisionProviderPackError(
                "PROVIDER_CROSS_BINDING_MISMATCH"
            )

    required: dict[str, str] = {}

    def add(key_id: str, fingerprint: str) -> None:
        existing = required.get(key_id)
        if existing is not None and existing != fingerprint:
            raise DecisionProviderPackError(
                "CREDENTIAL_BINDING_COLLISION"
            )
        required[key_id] = fingerprint

    add(feed["publisher_key_id"], feed["publisher_key_fingerprint_sha256"])
    add(ipc["decision_key_id"], ipc["decision_key_fingerprint_sha256"])
    add(ipc["custody_key_id"], ipc["custody_key_fingerprint_sha256"])
    add(
        producer["custody_key_id"],
        producer["custody_key_fingerprint_sha256"],
    )
    for lane in producer["lanes"]:
        add(
            lane["session_calendar_key_id"],
            lane["session_calendar_key_fingerprint_sha256"],
        )
    add(
        clock["authority_key_id"],
        clock["authority_key_fingerprint_sha256"],
    )
    configured = {
        item["key_id"]: item["fingerprint_sha256"]
        for item in references
    }
    if configured != required:
        raise DecisionProviderPackError(
            "CREDENTIAL_REFERENCE_BINDING_MISMATCH"
        )


def _validated_input(payload: object) -> dict[str, Any]:
    root = _mapping(
        payload,
        _PACK_INPUT_FIELDS,
        "PACK_INPUT_FIELDS_INVALID",
    )
    if root["schema_version"] != PACK_INPUT_SCHEMA:
        raise DecisionProviderPackError("PACK_INPUT_SCHEMA_INVALID")
    if root["safety"] != _SAFETY:
        raise DecisionProviderPackError("PACK_SAFETY_INVALID")
    root["pack_id"] = _text(
        root["pack_id"],
        "PACK_ID_INVALID",
        identifier=True,
    )
    runtime = _mapping(
        root["runtime"],
        _RUNTIME_INPUT_FIELDS,
        "PACK_RUNTIME_INVALID",
    )
    runtime["service_id"] = _text(
        runtime["service_id"],
        "PACK_RUNTIME_INVALID",
    )
    runtime["max_cycles"] = _integer(
        runtime["max_cycles"],
        "PACK_RUNTIME_INVALID",
        minimum=1,
        maximum=100_000,
    )
    runtime["poll_seconds"] = _number(
        runtime["poll_seconds"],
        "PACK_RUNTIME_INVALID",
        minimum=0,
        maximum=15,
    )
    runtime["cycle_deadline_seconds"] = _number(
        runtime["cycle_deadline_seconds"],
        "PACK_RUNTIME_INVALID",
        minimum=0.05,
        maximum=30,
    )
    producer = _producer(runtime["decision_producer_binding"])
    runtime["decision_producer_binding"] = producer
    feed = _feed(root["decision_feed_binding"])
    ipc = _ipc(root["decision_ipc_binding"])
    clock = _clock(root["clock_binding"])
    prefix = _text(
        root["credential_target_prefix"],
        "CREDENTIAL_TARGET_PREFIX_INVALID",
    )
    if prefix.endswith(("/", "\\")) or "\\" in prefix:
        raise DecisionProviderPackError(
            "CREDENTIAL_TARGET_PREFIX_INVALID"
        )
    references = _credential_references(
        root["credential_references"],
        prefix=prefix,
    )
    storage = _mapping(
        root["storage"],
        _STORAGE_FIELDS,
        "PACK_STORAGE_INVALID",
    )
    for name in _STORAGE_FIELDS:
        storage[name] = _windows_path(storage[name])
    external = _mapping(
        root["external_cas"],
        _EXTERNAL_CAS_FIELDS,
        "EXTERNAL_CAS_CONFIGURATION_INVALID",
    )
    for domain in ("ipc", "producer"):
        endpoint = _mapping(
            external[domain],
            _CAS_ENDPOINT_FIELDS,
            "EXTERNAL_CAS_CONFIGURATION_INVALID",
        )
        endpoint["provider_id"] = _text(
            endpoint["provider_id"],
            "EXTERNAL_CAS_CONFIGURATION_INVALID",
            identifier=True,
        )
        endpoint["request_directory"] = _windows_path(
            endpoint["request_directory"]
        )
        endpoint["response_directory"] = _windows_path(
            endpoint["response_directory"]
        )
        external[domain] = endpoint
    if (
        external["ipc"]["provider_id"]
        == external["producer"]["provider_id"]
    ):
        raise DecisionProviderPackError(
            "EXTERNAL_CAS_CONFIGURATION_INVALID"
        )
    root["cas_timeout_seconds"] = _number(
        root["cas_timeout_seconds"],
        "EXTERNAL_CAS_TIMEOUT_INVALID",
        minimum=0,
        maximum=2,
        lower_exclusive=True,
    )
    paths = [
        *storage.values(),
        external["ipc"]["request_directory"],
        external["ipc"]["response_directory"],
        external["producer"]["request_directory"],
        external["producer"]["response_directory"],
    ]
    if _windows_paths_overlap(paths):
        raise DecisionProviderPackError("PROVIDER_PATH_COLLISION")
    _validate_cross_bindings(
        runtime=runtime,
        producer=producer,
        feed=feed,
        ipc=ipc,
        clock=clock,
        references=references,
    )
    root.update(
        {
            "runtime": runtime,
            "decision_feed_binding": feed,
            "decision_ipc_binding": ipc,
            "clock_binding": clock,
            "credential_references": references,
            "credential_target_prefix": prefix,
            "storage": storage,
            "external_cas": external,
        }
    )
    return root


def _verify_suite_and_foundation(
    *,
    base_suite_root: str | Path,
    decision_base_release: str | Path,
) -> tuple[
    VerifiedBaseReleaseSuite,
    VerifiedBaseReleaseSuiteRole,
    dict[str, bytes],
]:
    try:
        suite = verify_base_release_suite(base_suite_root)
        binding = suite_binding_for_base_archive(
            suite,
            decision_base_release,
            DECISION_PROFILE,
        )
        role = suite.role("DECISION")
    except (
        BaseReleaseSuiteVerificationError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise DecisionProviderPackError(
            "DECISION_BASE_SUITE_BINDING_MISMATCH"
        ) from exc
    if (
        binding["role"] != "DECISION"
        or role.archive_path
        != Path(decision_base_release).expanduser().absolute()
    ):
        raise DecisionProviderPackError(
            "DECISION_BASE_SUITE_BINDING_MISMATCH"
        )
    archive_bytes = _stable_read(
        role.archive_path,
        maximum_bytes=MAX_BASE_ARCHIVE_BYTES,
        reason_code="DECISION_BASE_ARCHIVE_INVALID",
    )
    if _sha256(archive_bytes) != role.archive_sha256:
        raise DecisionProviderPackError(
            "DECISION_BASE_ARCHIVE_CHANGED"
        )
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            members: dict[str, bytes] = {}
            for path in FOUNDATION_PATHS:
                matching = [
                    info
                    for info in archive.infolist()
                    if info.filename == path
                ]
                if len(matching) != 1:
                    raise DecisionProviderPackError(
                        "DECISION_PROVIDER_FOUNDATION_MISSING"
                    )
                info = matching[0]
                if (
                    info.is_dir()
                    or info.file_size <= 0
                    or info.file_size > MAX_FILE_BYTES
                ):
                    raise DecisionProviderPackError(
                        "DECISION_PROVIDER_FOUNDATION_MISSING"
                    )
                data = archive.read(info)
                if len(data) != info.file_size:
                    raise DecisionProviderPackError(
                        "DECISION_PROVIDER_FOUNDATION_MISSING"
                    )
                members[path] = data
    except DecisionProviderPackError:
        raise
    except (KeyError, OSError, zipfile.BadZipFile) as exc:
        raise DecisionProviderPackError(
            "DECISION_PROVIDER_FOUNDATION_MISSING"
        ) from exc
    return suite, role, members


def _provider_configuration(
    pack: Mapping[str, Any],
    *,
    suite_identity_sha256: str,
    decision_release_identity_sha256: str,
) -> dict[str, Any]:
    storage = pack["storage"]
    external = pack["external_cas"]
    return {
        "base_suite_identity_sha256": suite_identity_sha256,
        "cas_timeout_seconds": pack["cas_timeout_seconds"],
        "clock_attestation_path": storage["clock_attestation_path"],
        "clock_binding": pack["clock_binding"],
        "credential_references": pack["credential_references"],
        "credential_target_prefix": pack["credential_target_prefix"],
        "decision_base_release_identity_sha256": (
            decision_release_identity_sha256
        ),
        "decision_feed_binding": pack["decision_feed_binding"],
        "decision_ipc_binding": pack["decision_ipc_binding"],
        "decision_ipc_database": storage["decision_ipc_database"],
        "decision_producer_binding": (
            pack["runtime"]["decision_producer_binding"]
        ),
        "finalized_m15_directory": storage["finalized_m15_directory"],
        "ipc_cas_provider_id": external["ipc"]["provider_id"],
        "ipc_cas_request_directory": (
            external["ipc"]["request_directory"]
        ),
        "ipc_cas_response_directory": (
            external["ipc"]["response_directory"]
        ),
        "live_allowed": False,
        "max_lot": 0.01,
        "order_capability": "DISABLED",
        "pack_id": pack["pack_id"],
        "producer_cas_provider_id": external["producer"]["provider_id"],
        "producer_cas_request_directory": (
            external["producer"]["request_directory"]
        ),
        "producer_cas_response_directory": (
            external["producer"]["response_directory"]
        ),
        "producer_cursor_database": storage["producer_cursor_database"],
        "promotion_eligible": False,
        "safe_to_demo_auto_order": False,
        "schema_version": PROVIDER_CONFIGURATION_SCHEMA,
    }


def _provider_configuration_hashes(
    configuration: Mapping[str, Any],
) -> dict[str, str]:
    common = {
        "schema_version": configuration["schema_version"],
        "pack_id": configuration["pack_id"],
        "base_suite_identity_sha256": (
            configuration["base_suite_identity_sha256"]
        ),
        "decision_base_release_identity_sha256": (
            configuration["decision_base_release_identity_sha256"]
        ),
        "credential_references": configuration[
            "credential_references"
        ],
        "credential_target_prefix": configuration[
            "credential_target_prefix"
        ],
        "safety": {
            "order_capability": configuration["order_capability"],
            "live_allowed": configuration["live_allowed"],
            "safe_to_demo_auto_order": configuration[
                "safe_to_demo_auto_order"
            ],
            "max_lot": configuration["max_lot"],
            "promotion_eligible": configuration["promotion_eligible"],
        },
    }
    producer = configuration["decision_producer_binding"]
    ipc = configuration["decision_ipc_binding"]
    details: dict[str, object] = {
        "FINALIZED_M15_DATA": {
            "binding": configuration["decision_feed_binding"],
            "directory": configuration["finalized_m15_directory"],
        },
        "IPC_CHECKPOINT_CAS": {
            "binding": ipc,
            "provider_id": configuration["ipc_cas_provider_id"],
            "request_directory": configuration[
                "ipc_cas_request_directory"
            ],
            "response_directory": configuration[
                "ipc_cas_response_directory"
            ],
            "timeout_seconds": configuration["cas_timeout_seconds"],
        },
        "IPC_SIGNING_KEY_CUSTODY": {
            "decision_key_id": ipc["decision_key_id"],
            "decision_key_fingerprint_sha256": ipc[
                "decision_key_fingerprint_sha256"
            ],
            "ipc_custody_key_id": ipc["custody_key_id"],
            "ipc_custody_key_fingerprint_sha256": ipc[
                "custody_key_fingerprint_sha256"
            ],
        },
        "PRODUCER_CURSOR_ACK_VERIFIER": {
            "provider_id": configuration["producer_cas_provider_id"],
            "binding": producer,
            "producer_cursor_database": configuration[
                "producer_cursor_database"
            ],
        },
        "PRODUCER_CURSOR_CAS": {
            "provider_id": configuration["producer_cas_provider_id"],
            "binding": producer,
            "request_directory": configuration[
                "producer_cas_request_directory"
            ],
            "response_directory": configuration[
                "producer_cas_response_directory"
            ],
            "timeout_seconds": configuration["cas_timeout_seconds"],
        },
        "SESSION_CALENDAR_VERIFIER": {
            "calendar_bindings": [
                {
                    "lane_id": lane["lane_id"],
                    "calendar_sha256": lane[
                        "session_calendar_sha256"
                    ],
                    "issuer_id": lane[
                        "session_calendar_issuer_id"
                    ],
                    "key_id": lane["session_calendar_key_id"],
                    "key_fingerprint_sha256": lane[
                        "session_calendar_key_fingerprint_sha256"
                    ],
                }
                for lane in producer["lanes"]
            ],
        },
        "TRUSTED_CLOCK": {
            "binding": configuration["clock_binding"],
            "attestation_path": configuration[
                "clock_attestation_path"
            ],
        },
    }
    return {
        role: _sha256(
            _canonical_bytes(
                {
                    "common": common,
                    "configuration": details[role],
                    "role": role,
                }
            )
        )
        for role in PROVIDER_ROLES
    }


def _provider_module_bytes(
    configuration: Mapping[str, Any],
) -> bytes:
    configuration_json = _canonical_bytes(configuration).decode("ascii")
    source = (
        '"""Reviewed decision-only provider composition."""\n'
        "\n"
        "from __future__ import annotations\n"
        "\n"
        "import json\n"
        "\n"
        "from live_runtime.windows_decision_provider_pack import (\n"
        "    build_windows_decision_provider_service,\n"
        "    parse_windows_decision_provider_configuration,\n"
        ")\n"
        "\n"
        f"_PROVIDER_CONFIGURATION_JSON = {configuration_json!r}\n"
        "\n"
        "\n"
        "def build_decision_provider_service(runtime_config):\n"
        "    provider_config = parse_windows_decision_provider_configuration(\n"
        "        json.loads(_PROVIDER_CONFIGURATION_JSON)\n"
        "    )\n"
        "    return build_windows_decision_provider_service(\n"
        "        runtime_config=runtime_config,\n"
        "        provider_config=provider_config,\n"
        "    )\n"
    )
    return source.encode("utf-8")


def _factory_bytes() -> bytes:
    return (
        b'"""Reviewed sealed factory for the decision-only service."""\n'
        b"\n"
        b"from __future__ import annotations\n"
        b"\n"
        b"from configured_providers.decision_provider import (\n"
        b"    build_decision_provider_service,\n"
        b")\n"
        b"from live_runtime.windows_decision_service_entrypoint import (\n"
        b"    seal_windows_decision_service_factory_result,\n"
        b")\n"
        b"\n"
        b"\n"
        b"def build(runtime_config, context):\n"
        b"    provider_template = runtime_config.factory_template(\n"
        b"        release_identity_sha256=context.release_identity_sha256,\n"
        b"        factory_implementation_sha256=context.factory_file_sha256,\n"
        b"        factory_configuration_sha256=(\n"
        b"            context.service_config_file_sha256\n"
        b"        ),\n"
        b"    )\n"
        b"    if (\n"
        b"        runtime_config.decision_producer_binding.content_sha256\n"
        b"        != context.bootstrap_binding_sha256\n"
        b"        or provider_template.content_sha256\n"
        b"        != context.provider_template_sha256\n"
        b"    ):\n"
        b"        raise ValueError(\"DECISION_PROVIDER_FACTORY_BINDING_MISMATCH\")\n"
        b"    service = build_decision_provider_service(runtime_config)\n"
        b"    return seal_windows_decision_service_factory_result(\n"
        b"        service=service,\n"
        b"        runtime_config=runtime_config,\n"
        b"        provider_template=provider_template,\n"
        b"        context=context,\n"
        b"    )\n"
    )


def _initializer_bytes() -> bytes:
    return b'"""Configured decision-only providers."""\n'


def _implementation_hashes(
    *,
    foundation_files: Mapping[str, bytes],
    provider_module_bytes: bytes,
) -> dict[str, str]:
    if (
        set(foundation_files) != set(FOUNDATION_PATHS)
        or any(
            not isinstance(data, bytes) or not data
            for data in foundation_files.values()
        )
    ):
        raise DecisionProviderPackError(
            "DECISION_PROVIDER_FOUNDATION_MISSING"
        )
    contracts = provider_contracts()
    bound_foundations = [
        {
            "path": path,
            "sha256": _sha256(foundation_files[path]),
        }
        for path in sorted(FOUNDATION_PATHS)
    ]
    module_sha256 = _sha256(provider_module_bytes)
    return {
        role: _sha256(
            _canonical_bytes(
                {
                    "contract_sha256": contracts[role],
                    "foundation_files": bound_foundations,
                    "generated_provider_path": (
                        "configured_providers/decision_provider.py"
                    ),
                    "generated_provider_sha256": module_sha256,
                    "role": role,
                    "schema_version": (
                        "windows-decision-provider-implementation-v2"
                    ),
                }
            )
        )
        for role in PROVIDER_ROLES
    }


def _runtime_configuration(
    pack: Mapping[str, Any],
    *,
    implementation_hashes: Mapping[str, str],
    configuration_hashes: Mapping[str, str],
) -> dict[str, Any]:
    contracts = provider_contracts()
    providers = [
        {
            "configuration_sha256": configuration_hashes[role],
            "contract_sha256": contracts[role],
            "custody_mode": _CUSTODY_MODES[role],
            "implementation_sha256": implementation_hashes[role],
            "role": role,
        }
        for role in PROVIDER_ROLES
    ]
    runtime = pack["runtime"]
    return {
        "cycle_deadline_seconds": runtime["cycle_deadline_seconds"],
        "decision_producer_binding": runtime[
            "decision_producer_binding"
        ],
        "live_allowed": False,
        "max_cycles": runtime["max_cycles"],
        "max_lot": 0.01,
        "order_capability": "DISABLED",
        "poll_seconds": runtime["poll_seconds"],
        "providers": providers,
        "safe_to_demo_auto_order": False,
        "schema_version": (
            "windows-decision-service-runtime-config-v1"
        ),
        "service_id": runtime["service_id"],
    }


def _generated_files(
    *,
    pack: Mapping[str, Any],
    suite: VerifiedBaseReleaseSuite,
    role: VerifiedBaseReleaseSuiteRole,
    foundation_files: Mapping[str, bytes],
) -> dict[str, bytes]:
    configuration = _provider_configuration(
        pack,
        suite_identity_sha256=suite.suite_identity_sha256,
        decision_release_identity_sha256=(
            role.release_identity_sha256
        ),
    )
    provider_module = _provider_module_bytes(configuration)
    implementations = _implementation_hashes(
        foundation_files=foundation_files,
        provider_module_bytes=provider_module,
    )
    configurations = _provider_configuration_hashes(configuration)
    runtime = _runtime_configuration(
        pack,
        implementation_hashes=implementations,
        configuration_hashes=configurations,
    )
    return {
        "config/windows_service_config.json": _canonical_file(runtime),
        "configured_providers/__init__.py": _initializer_bytes(),
        "configured_providers/decision_provider.py": provider_module,
        "reviewed_windows_factory.py": _factory_bytes(),
    }


def _extract_provider_configuration(module_bytes: bytes) -> dict[str, Any]:
    try:
        tree = ast.parse(
            module_bytes.decode("utf-8"),
            filename="configured_providers/decision_provider.py",
        )
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise DecisionProviderPackError(
            "GENERATED_PROVIDER_SOURCE_INVALID"
        ) from exc
    values: list[str] = []
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "_PROVIDER_CONFIGURATION_JSON"
            and isinstance(node.value, ast.Constant)
            and type(node.value.value) is str
        ):
            values.append(node.value.value)
    if len(values) != 1:
        raise DecisionProviderPackError(
            "GENERATED_PROVIDER_SOURCE_INVALID"
        )
    try:
        raw = values[0].encode("ascii") + b"\n"
    except UnicodeEncodeError as exc:
        raise DecisionProviderPackError(
            "GENERATED_PROVIDER_SOURCE_INVALID"
        ) from exc
    return _strict_json(raw, canonical=True)


def _validated_provider_configuration(
    payload: object,
    *,
    suite: VerifiedBaseReleaseSuite,
    role: VerifiedBaseReleaseSuiteRole,
) -> dict[str, Any]:
    configuration = _mapping(
        payload,
        _PROVIDER_CONFIGURATION_FIELDS,
        "PROVIDER_CONFIGURATION_FIELDS_INVALID",
    )
    if (
        configuration["schema_version"]
        != PROVIDER_CONFIGURATION_SCHEMA
        or configuration["base_suite_identity_sha256"]
        != suite.suite_identity_sha256
        or configuration["decision_base_release_identity_sha256"]
        != role.release_identity_sha256
        or configuration["order_capability"] != ORDER_CAPABILITY
        or configuration["live_allowed"] is not False
        or configuration["safe_to_demo_auto_order"] is not False
        or type(configuration["max_lot"]) is not float
        or configuration["max_lot"] != MAX_LOT
        or configuration["promotion_eligible"] is not False
    ):
        raise DecisionProviderPackError(
            "PROVIDER_CONFIGURATION_INVALID"
        )
    configuration["pack_id"] = _text(
        configuration["pack_id"],
        "PROVIDER_CONFIGURATION_INVALID",
        identifier=True,
    )
    producer = _producer(configuration["decision_producer_binding"])
    feed = _feed(configuration["decision_feed_binding"])
    ipc = _ipc(configuration["decision_ipc_binding"])
    clock = _clock(configuration["clock_binding"])
    prefix = _text(
        configuration["credential_target_prefix"],
        "CREDENTIAL_TARGET_PREFIX_INVALID",
    )
    if prefix.endswith(("/", "\\")) or "\\" in prefix:
        raise DecisionProviderPackError(
            "CREDENTIAL_TARGET_PREFIX_INVALID"
        )
    references = _credential_references(
        configuration["credential_references"],
        prefix=prefix,
    )
    for name in (
        "finalized_m15_directory",
        "decision_ipc_database",
        "producer_cursor_database",
        "ipc_cas_request_directory",
        "ipc_cas_response_directory",
        "producer_cas_request_directory",
        "producer_cas_response_directory",
        "clock_attestation_path",
    ):
        configuration[name] = _windows_path(configuration[name])
    paths = [
        configuration["finalized_m15_directory"],
        configuration["decision_ipc_database"],
        configuration["producer_cursor_database"],
        configuration["ipc_cas_request_directory"],
        configuration["ipc_cas_response_directory"],
        configuration["producer_cas_request_directory"],
        configuration["producer_cas_response_directory"],
        configuration["clock_attestation_path"],
    ]
    if _windows_paths_overlap(paths):
        raise DecisionProviderPackError("PROVIDER_PATH_COLLISION")
    for name in ("ipc_cas_provider_id", "producer_cas_provider_id"):
        configuration[name] = _text(
            configuration[name],
            "EXTERNAL_CAS_CONFIGURATION_INVALID",
            identifier=True,
        )
    if (
        configuration["ipc_cas_provider_id"]
        == configuration["producer_cas_provider_id"]
    ):
        raise DecisionProviderPackError(
            "EXTERNAL_CAS_CONFIGURATION_INVALID"
        )
    configuration["cas_timeout_seconds"] = _number(
        configuration["cas_timeout_seconds"],
        "EXTERNAL_CAS_TIMEOUT_INVALID",
        minimum=0,
        maximum=2,
        lower_exclusive=True,
    )
    runtime = {
        "service_id": producer["service_id"],
    }
    _validate_cross_bindings(
        runtime=runtime,
        producer=producer,
        feed=feed,
        ipc=ipc,
        clock=clock,
        references=references,
    )
    configuration.update(
        {
            "decision_producer_binding": producer,
            "decision_feed_binding": feed,
            "decision_ipc_binding": ipc,
            "clock_binding": clock,
            "credential_references": references,
            "credential_target_prefix": prefix,
        }
    )
    return configuration


def _validated_runtime(
    payload: object,
    *,
    configuration: Mapping[str, Any],
    foundation_files: Mapping[str, bytes],
    provider_module_bytes: bytes,
) -> dict[str, Any]:
    runtime = _mapping(
        payload,
        _RUNTIME_OUTPUT_FIELDS,
        "GENERATED_RUNTIME_CONFIGURATION_INVALID",
    )
    if (
        runtime["schema_version"]
        != "windows-decision-service-runtime-config-v1"
        or runtime["order_capability"] != ORDER_CAPABILITY
        or runtime["live_allowed"] is not False
        or runtime["safe_to_demo_auto_order"] is not False
        or type(runtime["max_lot"]) is not float
        or runtime["max_lot"] != MAX_LOT
    ):
        raise DecisionProviderPackError(
            "GENERATED_RUNTIME_CONFIGURATION_INVALID"
        )
    runtime["service_id"] = _text(
        runtime["service_id"],
        "GENERATED_RUNTIME_CONFIGURATION_INVALID",
    )
    runtime["max_cycles"] = _integer(
        runtime["max_cycles"],
        "GENERATED_RUNTIME_CONFIGURATION_INVALID",
        minimum=1,
        maximum=100_000,
    )
    runtime["poll_seconds"] = _number(
        runtime["poll_seconds"],
        "GENERATED_RUNTIME_CONFIGURATION_INVALID",
        minimum=0,
        maximum=15,
    )
    runtime["cycle_deadline_seconds"] = _number(
        runtime["cycle_deadline_seconds"],
        "GENERATED_RUNTIME_CONFIGURATION_INVALID",
        minimum=0.05,
        maximum=30,
    )
    runtime["decision_producer_binding"] = _producer(
        runtime["decision_producer_binding"]
    )
    if (
        runtime["decision_producer_binding"]
        != configuration["decision_producer_binding"]
        or runtime["service_id"]
        != runtime["decision_producer_binding"]["service_id"]
    ):
        raise DecisionProviderPackError(
            "PROVIDER_CROSS_BINDING_MISMATCH"
        )
    providers = runtime["providers"]
    if not isinstance(providers, list) or len(providers) != len(
        PROVIDER_ROLES
    ):
        raise DecisionProviderPackError(
            "GENERATED_PROVIDER_BINDINGS_INVALID"
        )
    contracts = provider_contracts()
    expected_implementation = _implementation_hashes(
        foundation_files=foundation_files,
        provider_module_bytes=provider_module_bytes,
    )
    expected_configuration = _provider_configuration_hashes(
        configuration
    )
    normalized: list[dict[str, Any]] = []
    for role, raw in zip(PROVIDER_ROLES, providers, strict=True):
        item = _mapping(
            raw,
            _PROVIDER_OUTPUT_FIELDS,
            "GENERATED_PROVIDER_BINDINGS_INVALID",
        )
        if item != {
            "configuration_sha256": expected_configuration[role],
            "contract_sha256": contracts[role],
            "custody_mode": _CUSTODY_MODES[role],
            "implementation_sha256": expected_implementation[role],
            "role": role,
        }:
            raise DecisionProviderPackError(
                "GENERATED_PROVIDER_BINDINGS_INVALID"
            )
        normalized.append(item)
    runtime["providers"] = normalized
    return runtime


def _real_pack_root(path: str | Path) -> Path:
    configured = Path(path).expanduser().absolute()
    try:
        configured_meta = configured.lstat()
        resolved = configured.resolve(strict=True)
        resolved_meta = resolved.stat(follow_symlinks=False)
    except OSError as exc:
        raise DecisionProviderPackError("PACK_ROOT_INVALID") from exc
    if (
        configured != resolved
        or not stat.S_ISDIR(configured_meta.st_mode)
        or stat.S_ISLNK(configured_meta.st_mode)
        or _is_reparse(configured_meta)
        or not stat.S_ISDIR(resolved_meta.st_mode)
        or _is_reparse(resolved_meta)
    ):
        raise DecisionProviderPackError("PACK_ROOT_INVALID")
    return resolved


def _pack_files(root: Path) -> dict[str, bytes]:
    observed: dict[str, bytes] = {}
    total = 0
    try:
        items = sorted(root.rglob("*"))
    except OSError as exc:
        raise DecisionProviderPackError("PACK_FILE_SET_INVALID") from exc
    for item in items:
        try:
            metadata = item.lstat()
        except OSError as exc:
            raise DecisionProviderPackError(
                "PACK_FILE_SET_INVALID"
            ) from exc
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
                raise DecisionProviderPackError(
                    "PACK_FILE_SET_INVALID"
                )
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
        ):
            raise DecisionProviderPackError("PACK_FILE_SET_INVALID")
        relative = item.relative_to(root).as_posix()
        if relative not in GENERATED_PATHS:
            raise DecisionProviderPackError("PACK_FILE_SET_INVALID")
        data = _stable_read(
            item,
            maximum_bytes=MAX_FILE_BYTES,
            reason_code="PACK_FILE_INVALID",
        )
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise DecisionProviderPackError("PACK_TOTAL_SIZE_EXCEEDED")
        observed[relative] = data
    if set(observed) != set(GENERATED_PATHS):
        raise DecisionProviderPackError("PACK_FILE_SET_INVALID")
    return observed


def _pack_identity(
    *,
    suite: VerifiedBaseReleaseSuite,
    role: VerifiedBaseReleaseSuiteRole,
    files: Mapping[str, bytes],
) -> str:
    return _sha256(
        _canonical_bytes(
            {
                "base_suite_identity_sha256": (
                    suite.suite_identity_sha256
                ),
                "decision_base_release_identity_sha256": (
                    role.release_identity_sha256
                ),
                "files": [
                    {
                        "path": path,
                        "sha256": _sha256(data),
                        "size_bytes": len(data),
                    }
                    for path, data in sorted(files.items())
                ],
                "schema_version": PACK_VALIDATION_SCHEMA,
                "status": PACK_STATUS,
            }
        )
    )


def _result(
    *,
    root: Path,
    suite: VerifiedBaseReleaseSuite,
    role: VerifiedBaseReleaseSuiteRole,
    configuration: Mapping[str, Any],
    files: Mapping[str, bytes],
) -> DecisionProviderPackValidation:
    return DecisionProviderPackValidation(
        output_root=str(root),
        base_suite_identity_sha256=suite.suite_identity_sha256,
        decision_base_release_identity_sha256=(
            role.release_identity_sha256
        ),
        pack_id=str(configuration["pack_id"]),
        pack_identity_sha256=_pack_identity(
            suite=suite,
            role=role,
            files=files,
        ),
        file_sha256=tuple(
            (path, _sha256(data)) for path, data in sorted(files.items())
        ),
        _seal=_RESULT_SEAL,
    )


def validate_windows_decision_provider_pack(
    *,
    base_suite_root: str | Path,
    decision_base_release: str | Path,
    pack_root: str | Path,
) -> DecisionProviderPackValidation:
    """Validate one generated pack without importing or materializing it."""

    suite, role, foundation_files = _verify_suite_and_foundation(
        base_suite_root=base_suite_root,
        decision_base_release=decision_base_release,
    )
    root = _real_pack_root(pack_root)
    files = _pack_files(root)
    if (
        files["reviewed_windows_factory.py"] != _factory_bytes()
        or files["configured_providers/__init__.py"]
        != _initializer_bytes()
    ):
        raise DecisionProviderPackError("GENERATED_SOURCE_DRIFT")
    provider_bytes = files[
        "configured_providers/decision_provider.py"
    ]
    configuration = _validated_provider_configuration(
        _extract_provider_configuration(provider_bytes),
        suite=suite,
        role=role,
    )
    if provider_bytes != _provider_module_bytes(configuration):
        raise DecisionProviderPackError("GENERATED_PROVIDER_SOURCE_DRIFT")
    runtime_payload = _strict_json(
        files["config/windows_service_config.json"],
        canonical=True,
    )
    _validated_runtime(
        runtime_payload,
        configuration=configuration,
        foundation_files=foundation_files,
        provider_module_bytes=provider_bytes,
    )
    return _result(
        root=root,
        suite=suite,
        role=role,
        configuration=configuration,
        files=files,
    )


def _remove_created_file(
    path: Path,
    identity: tuple[int, int] | None,
) -> None:
    if identity is None:
        return
    try:
        observed = path.lstat()
    except OSError:
        return
    if (
        not stat.S_ISREG(observed.st_mode)
        or _is_reparse(observed)
        or (int(observed.st_dev), int(observed.st_ino)) != identity
    ):
        return
    try:
        path.unlink()
    except OSError:
        pass


def _directory_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _write_exclusive(path: Path, payload: bytes) -> tuple[int, ...]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    created_identity: tuple[int, int] | None = None
    completed_identity: tuple[int, ...] | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            created = os.fstat(handle.fileno())
            created_identity = (
                int(created.st_dev),
                int(created.st_ino),
            )
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            completed_identity = _identity(os.fstat(handle.fileno()))
    except DecisionProviderPackError:
        raise
    except OSError as exc:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        _remove_created_file(path, created_identity)
        raise DecisionProviderPackError("PACK_OUTPUT_WRITE_FAILED") from exc
    if completed_identity is None:
        raise DecisionProviderPackError("PACK_OUTPUT_WRITE_FAILED")
    return completed_identity


def _remove_if_same(
    path: Path,
    identity: tuple[int, ...],
) -> None:
    try:
        if _identity(path.lstat()) == identity:
            path.unlink()
    except OSError:
        pass


def _cleanup_created(
    root: Path,
    root_identity: tuple[int, int, int, int],
    files: list[tuple[Path, tuple[int, ...]]],
) -> None:
    try:
        observed_root = root.lstat()
    except OSError:
        return
    if (
        _directory_identity(observed_root) != root_identity
        or not stat.S_ISDIR(observed_root.st_mode)
        or stat.S_ISLNK(observed_root.st_mode)
        or _is_reparse(observed_root)
    ):
        return
    for path, identity in reversed(files):
        _remove_if_same(path, identity)
    for directory in (
        root / "configured_providers",
        root / "config",
        root,
    ):
        try:
            directory.rmdir()
        except OSError:
            pass


def prepare_windows_decision_provider_pack(
    *,
    base_suite_root: str | Path,
    decision_base_release: str | Path,
    pack_input_path: str | Path,
    output_root: str | Path,
) -> DecisionProviderPackValidation:
    """Generate one deterministic, create-exclusive four-file overlay."""

    suite, role, foundation_files = _verify_suite_and_foundation(
        base_suite_root=base_suite_root,
        decision_base_release=decision_base_release,
    )
    input_bytes = _stable_read(
        Path(pack_input_path).expanduser().absolute(),
        maximum_bytes=MAX_FILE_BYTES,
        reason_code="PACK_INPUT_INVALID",
    )
    pack = _validated_input(_strict_json(input_bytes, canonical=True))
    files = _generated_files(
        pack=pack,
        suite=suite,
        role=role,
        foundation_files=foundation_files,
    )
    if (
        set(files) != set(GENERATED_PATHS)
        or any(len(data) > MAX_FILE_BYTES for data in files.values())
        or sum(len(data) for data in files.values()) > MAX_TOTAL_BYTES
    ):
        raise DecisionProviderPackError("GENERATED_FILE_SET_INVALID")

    root = Path(output_root).expanduser().absolute()
    parent = root.parent
    try:
        parent_metadata = parent.lstat()
        parent_resolved = parent.resolve(strict=True)
    except OSError as exc:
        raise DecisionProviderPackError("PACK_OUTPUT_PARENT_INVALID") from exc
    if (
        parent != parent_resolved
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or stat.S_ISLNK(parent_metadata.st_mode)
        or _is_reparse(parent_metadata)
    ):
        raise DecisionProviderPackError("PACK_OUTPUT_PARENT_INVALID")
    try:
        os.mkdir(root, 0o700)
    except FileExistsError as exc:
        raise DecisionProviderPackError(
            "PACK_OUTPUT_ALREADY_EXISTS"
        ) from exc
    except OSError as exc:
        raise DecisionProviderPackError("PACK_OUTPUT_CREATE_FAILED") from exc
    root_identity = _directory_identity(root.lstat())

    created: list[tuple[Path, tuple[int, ...]]] = []
    try:
        os.mkdir(root / "config", 0o700)
        os.mkdir(root / "configured_providers", 0o700)
        for relative in GENERATED_PATHS:
            target = root / relative
            created.append(
                (target, _write_exclusive(target, files[relative]))
            )
        result = validate_windows_decision_provider_pack(
            base_suite_root=base_suite_root,
            decision_base_release=decision_base_release,
            pack_root=root,
        )
    except BaseException:
        _cleanup_created(root, root_identity, created)
        raise
    return result


__all__ = [
    "DecisionProviderPackError",
    "DecisionProviderPackValidation",
    "GENERATED_PATHS",
    "PACK_INPUT_SCHEMA",
    "PACK_STATUS",
    "prepare_windows_decision_provider_pack",
    "validate_windows_decision_provider_pack",
]
