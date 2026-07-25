"""Fail-closed Windows provider foundation for the Status Monitor.

The module materializes status-only dependencies from exact non-secret
configuration.  Credential lookup is read-only, provider state must be
preprovisioned, and no broker, MT5, process, network, task-installation, risk,
intent, permit, reconciliation, or order capability is present.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import sys
import threading
import time
from typing import Any, Callable, Mapping

from .contracts import (
    CanonicalContract,
    canonical_json,
    canonical_sha256,
    require_finite,
    require_hash,
    require_text,
    require_utc,
)
from .offhost_delivery import (
    DeliveryOutbox,
    DirectoryDropTransport,
)
from .windows_external_status_monitor import (
    ExternalMonitorConfig,
    ExternalStatusAssessment,
    ExternalStatusSnapshot,
    MonitorCheckpoint,
    MonitorCheckpointAcknowledgement,
    MonitorHostObservation,
    MonitorIncidentAcknowledgement,
    MonitoredServiceObservation,
    StatusMonitorDependencies,
)
from .windows_external_status_monitor_factory_template import (
    MONITOR_PROVIDER_ROLES,
    MonitorProviderBinding,
)
from .windows_provider_primitives import (
    AttestedTrustedUTCProvider,
    CredentialReference,
    WindowsClockAttestation,
    WindowsClockBinding,
    WindowsCredentialManagerKeyProvider,
)


UTC = timezone.utc
ORDER_CAPABILITY = "DISABLED"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_LOT = 0.01
PROMOTION_ELIGIBLE = False
PRODUCTION_EXECUTION_READY = False
PROVIDER_CONFIGURATION_SCHEMA = (
    "windows-status-monitor-provider-configuration-v1"
)
SNAPSHOT_ENVELOPE_SCHEMA = "windows-status-snapshot-envelope-v1"
SNAPSHOT_ATTESTATION_BINDING_SCHEMA = (
    "windows-status-snapshot-attestation-binding-v1"
)
CHECKPOINT_CURRENT_SCHEMA = "windows-monitor-checkpoint-current-v1"
CHECKPOINT_REQUEST_SCHEMA = "windows-monitor-checkpoint-request-v1"
CHECKPOINT_RESPONSE_SCHEMA = "windows-monitor-checkpoint-response-v1"
INCIDENT_REQUEST_SCHEMA = "windows-monitor-incident-request-v1"
INCIDENT_RESPONSE_SCHEMA = "windows-monitor-incident-response-v1"
MAX_PROVIDER_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_VERIFIED_OBJECTS = 64

_SNAPSHOT_DOMAIN = b"AI_SCALPER_WINDOWS_STATUS_SNAPSHOT_V1\x00"
_CHECKPOINT_CURRENT_DOMAIN = (
    b"AI_SCALPER_WINDOWS_MONITOR_CHECKPOINT_CURRENT_V1\x00"
)
_CHECKPOINT_RESPONSE_DOMAIN = (
    b"AI_SCALPER_WINDOWS_MONITOR_CHECKPOINT_RESPONSE_V1\x00"
)
_INCIDENT_RESPONSE_DOMAIN = (
    b"AI_SCALPER_WINDOWS_MONITOR_INCIDENT_RESPONSE_V1\x00"
)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_REASON = re.compile(r"^[A-Z][A-Z0-9_]*$")
_DRIVE = re.compile(r"^[A-Z]:$")
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
_SNAPSHOT_FIELDS = frozenset(
    {
        "expires_at_utc",
        "hmac_sha256",
        "issued_at_utc",
        "key_id",
        "monitor_service_id",
        "previous_snapshot_sha256",
        "provider_id",
        "schema_version",
        "sequence",
        "snapshot",
        "snapshot_sha256",
    }
)
_CHECKPOINT_CURRENT_FIELDS = frozenset(
    {
        "checkpoint",
        "checkpoint_sha256",
        "expires_at_utc",
        "hmac_sha256",
        "issued_at_utc",
        "key_id",
        "monitor_service_id",
        "provider_id",
        "schema_version",
    }
)
_CHECKPOINT_RESPONSE_FIELDS = frozenset(
    {
        "acknowledgement",
        "current_checkpoint",
        "current_checkpoint_sha256",
        "hmac_sha256",
        "key_id",
        "monitor_service_id",
        "provider_id",
        "request_id",
        "request_sha256",
        "responded_at_utc",
        "schema_version",
    }
)
_INCIDENT_RESPONSE_FIELDS = frozenset(
    {
        "acknowledgement",
        "hmac_sha256",
        "key_id",
        "monitor_service_id",
        "provider_id",
        "request_id",
        "request_sha256",
        "responded_at_utc",
        "schema_version",
    }
)
_CREDENTIAL_FIELDS = frozenset(
    {"fingerprint_sha256", "key_id", "target_name"}
)
_CLOCK_FIELDS = frozenset(
    item.name for item in fields(WindowsClockBinding)
)
_PROVIDER_BINDING_FIELDS = frozenset(
    item.name for item in fields(MonitorProviderBinding) if item.init
)
_CONFIGURATION_FIELDS = frozenset(
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
_PATH_FIELDS = (
    "alert_acknowledgement_directory",
    "alert_outbound_directory",
    "alert_outbox_database",
    "checkpoint_current_path",
    "checkpoint_request_directory",
    "checkpoint_response_directory",
    "clock_attestation_path",
    "heartbeat_acknowledgement_directory",
    "heartbeat_outbound_directory",
    "heartbeat_outbox_database",
    "incident_request_directory",
    "incident_response_directory",
    "snapshot_directory",
)
_FILE_PATH_FIELDS = frozenset(
    {
        "alert_outbox_database",
        "checkpoint_current_path",
        "clock_attestation_path",
        "heartbeat_outbox_database",
    }
)
_DIRECTORY_PATH_FIELDS = frozenset(_PATH_FIELDS) - _FILE_PATH_FIELDS


class WindowsStatusMonitorProviderError(RuntimeError):
    """One provider boundary failed closed with no sensitive detail."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: str) -> None:
        normalized = str(reason_code or "").strip().upper()
        if _REASON.fullmatch(normalized) is None:
            normalized = "WINDOWS_STATUS_MONITOR_PROVIDER_INVALID"
        self.reason_code = normalized
        super().__init__(normalized)


def _canonical_bytes(value: object) -> bytes:
    try:
        return canonical_json(value).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WindowsStatusMonitorProviderError(
            "PROVIDER_DOCUMENT_INVALID"
        ) from exc


def _hash(value: object, code: str) -> str:
    try:
        result = require_hash("sha256", value)
    except (TypeError, ValueError) as exc:
        raise WindowsStatusMonitorProviderError(code) from exc
    if result == "0" * 64:
        raise WindowsStatusMonitorProviderError(code)
    return result


def _identifier(value: object, code: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise WindowsStatusMonitorProviderError(code)
    return value


def _exact_mapping(
    value: object,
    expected_fields: frozenset[str],
    code: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        raise WindowsStatusMonitorProviderError(code)
    return dict(value)


def _parse_utc(value: object, code: str) -> datetime:
    if type(value) is not str:
        raise WindowsStatusMonitorProviderError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        parsed = require_utc("provider UTC", parsed).astimezone(UTC)
    except (TypeError, ValueError) as exc:
        raise WindowsStatusMonitorProviderError(code) from exc
    exact = (
        parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    )
    if exact != value:
        raise WindowsStatusMonitorProviderError(code)
    return parsed


def _strict_json(data: bytes, code: str) -> dict[str, Any]:
    if (
        type(data) is not bytes
        or not data
        or len(data) > MAX_PROVIDER_DOCUMENT_BYTES
    ):
        raise WindowsStatusMonitorProviderError(code)
    try:
        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in items:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = item
            return result

        parsed = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON")
            ),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise WindowsStatusMonitorProviderError(code) from exc
    if type(parsed) is not dict or _canonical_bytes(parsed) != data:
        raise WindowsStatusMonitorProviderError(code)
    return parsed


def _is_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse and attributes & reparse)


def _same_identity(
    first: os.stat_result,
    second: os.stat_result,
) -> bool:
    return (
        first.st_dev,
        first.st_ino,
        first.st_mode,
        first.st_size,
        first.st_mtime_ns,
    ) == (
        second.st_dev,
        second.st_ino,
        second.st_mode,
        second.st_size,
        second.st_mtime_ns,
    )


def _stable_read(path: Path, code: str) -> bytes:
    try:
        before = path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or _is_reparse(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > MAX_PROVIDER_DOCUMENT_BYTES
        ):
            raise OSError("unsafe provider document")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not _same_identity(before, opened):
                raise OSError("provider document identity changed")
            chunks: list[bytes] = []
            remaining = MAX_PROVIDER_DOCUMENT_BYTES + 1
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
            not _same_identity(before, after)
            or len(data) != before.st_size
            or not data
            or len(data) > MAX_PROVIDER_DOCUMENT_BYTES
        ):
            raise OSError("provider document changed")
        return data
    except WindowsStatusMonitorProviderError:
        raise
    except (FileNotFoundError, OSError) as exc:
        raise WindowsStatusMonitorProviderError(code) from exc


def _existing_directory(path: Path, code: str) -> None:
    try:
        metadata = path.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise WindowsStatusMonitorProviderError(code) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise WindowsStatusMonitorProviderError(code)


def _existing_file(path: Path, code: str) -> None:
    try:
        metadata = path.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise WindowsStatusMonitorProviderError(code) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise WindowsStatusMonitorProviderError(code)


def _write_exclusive(path: Path, data: bytes, code: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        if _stable_read(path, code) != data:
            raise WindowsStatusMonitorProviderError(code)
        return
    except OSError as exc:
        raise WindowsStatusMonitorProviderError(code) from exc
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short provider request write")
            offset += written
        os.fsync(descriptor)
    except OSError as exc:
        try:
            path.unlink()
        except OSError:
            pass
        raise WindowsStatusMonitorProviderError(code) from exc
    finally:
        os.close(descriptor)


def _wait_response(
    path: Path,
    *,
    timeout_seconds: float,
    code: str,
) -> bytes:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            return _stable_read(path, code)
        except WindowsStatusMonitorProviderError as exc:
            if exc.reason_code != code or time.monotonic() >= deadline:
                raise
            time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))


def _key_bytes(value: object, code: str) -> bytes:
    if type(value) is bytes:
        result = value
    elif type(value) is str:
        result = value.encode("utf-8")
    else:
        raise WindowsStatusMonitorProviderError(code)
    if len(result) < 32 or len(result) > 4_096:
        raise WindowsStatusMonitorProviderError(code)
    return result


def _verify_hmac(
    payload: dict[str, Any],
    *,
    key_id: str,
    key_provider: Callable[[str], str | bytes],
    domain: bytes,
    code: str,
) -> None:
    signature = payload.get("hmac_sha256")
    if type(signature) is not str or _HASH.fullmatch(signature) is None:
        raise WindowsStatusMonitorProviderError(code)
    if payload.get("key_id") != key_id:
        raise WindowsStatusMonitorProviderError(code)
    unsigned = dict(payload)
    unsigned.pop("hmac_sha256", None)
    try:
        key = _key_bytes(key_provider(key_id), code)
    except WindowsStatusMonitorProviderError:
        raise
    except Exception as exc:
        raise WindowsStatusMonitorProviderError(code) from exc
    expected = hmac.new(
        key,
        domain + _canonical_bytes(unsigned),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise WindowsStatusMonitorProviderError(code)


def _fresh_window(
    payload: Mapping[str, object],
    *,
    now: datetime,
    timeout_seconds: float,
    code: str,
) -> tuple[datetime, datetime]:
    issued = _parse_utc(payload.get("issued_at_utc"), code)
    expires = _parse_utc(payload.get("expires_at_utc"), code)
    if (
        issued > now
        or expires <= now
        or expires <= issued
        or (expires - issued).total_seconds() > timeout_seconds
    ):
        raise WindowsStatusMonitorProviderError(code)
    return issued, expires


def _parse_checkpoint(value: object) -> MonitorCheckpoint:
    expected = frozenset(item.name for item in fields(MonitorCheckpoint))
    raw = _exact_mapping(
        value,
        expected,
        "MONITOR_CHECKPOINT_DOCUMENT_INVALID",
    )
    raw["updated_at_utc"] = _parse_utc(
        raw["updated_at_utc"],
        "MONITOR_CHECKPOINT_DOCUMENT_INVALID",
    )
    try:
        return MonitorCheckpoint(**raw)
    except (TypeError, ValueError) as exc:
        raise WindowsStatusMonitorProviderError(
            "MONITOR_CHECKPOINT_DOCUMENT_INVALID"
        ) from exc


def _parse_checkpoint_acknowledgement(
    value: object,
) -> MonitorCheckpointAcknowledgement:
    expected = frozenset(
        item.name for item in fields(MonitorCheckpointAcknowledgement)
    )
    raw = _exact_mapping(
        value,
        expected,
        "MONITOR_CHECKPOINT_ACK_DOCUMENT_INVALID",
    )
    raw["acknowledged_at_utc"] = _parse_utc(
        raw["acknowledged_at_utc"],
        "MONITOR_CHECKPOINT_ACK_DOCUMENT_INVALID",
    )
    try:
        return MonitorCheckpointAcknowledgement(**raw)
    except (TypeError, ValueError) as exc:
        raise WindowsStatusMonitorProviderError(
            "MONITOR_CHECKPOINT_ACK_DOCUMENT_INVALID"
        ) from exc


def _parse_incident_acknowledgement(
    value: object,
) -> MonitorIncidentAcknowledgement:
    expected = frozenset(
        item.name for item in fields(MonitorIncidentAcknowledgement)
    )
    raw = _exact_mapping(
        value,
        expected,
        "MONITOR_INCIDENT_ACK_DOCUMENT_INVALID",
    )
    raw["acknowledged_at_utc"] = _parse_utc(
        raw["acknowledged_at_utc"],
        "MONITOR_INCIDENT_ACK_DOCUMENT_INVALID",
    )
    try:
        return MonitorIncidentAcknowledgement(**raw)
    except (TypeError, ValueError) as exc:
        raise WindowsStatusMonitorProviderError(
            "MONITOR_INCIDENT_ACK_DOCUMENT_INVALID"
        ) from exc


def _parse_service(value: object) -> MonitoredServiceObservation:
    expected = frozenset(
        item.name for item in fields(MonitoredServiceObservation)
    )
    raw = _exact_mapping(
        value,
        expected,
        "STATUS_SNAPSHOT_DOCUMENT_INVALID",
    )
    for name in ("status_occurred_at_utc", "status_valid_until_utc"):
        raw[name] = _parse_utc(
            raw[name],
            "STATUS_SNAPSHOT_DOCUMENT_INVALID",
        )
    if type(raw.get("reason_codes")) is not list:
        raise WindowsStatusMonitorProviderError(
            "STATUS_SNAPSHOT_DOCUMENT_INVALID"
        )
    raw["reason_codes"] = tuple(raw["reason_codes"])
    try:
        return MonitoredServiceObservation(**raw)
    except (TypeError, ValueError) as exc:
        raise WindowsStatusMonitorProviderError(
            "STATUS_SNAPSHOT_DOCUMENT_INVALID"
        ) from exc


def _parse_host(value: object) -> MonitorHostObservation:
    expected = frozenset(item.name for item in fields(MonitorHostObservation))
    raw = _exact_mapping(
        value,
        expected,
        "STATUS_SNAPSHOT_DOCUMENT_INVALID",
    )
    for name in (
        "observed_at_utc",
        "audit_exported_at_utc",
        "backup_anchored_at_utc",
    ):
        raw[name] = _parse_utc(
            raw[name],
            "STATUS_SNAPSHOT_DOCUMENT_INVALID",
        )
    if type(raw.get("critical_reason_codes")) is not list:
        raise WindowsStatusMonitorProviderError(
            "STATUS_SNAPSHOT_DOCUMENT_INVALID"
        )
    raw["critical_reason_codes"] = tuple(raw["critical_reason_codes"])
    try:
        return MonitorHostObservation(**raw)
    except (TypeError, ValueError) as exc:
        raise WindowsStatusMonitorProviderError(
            "STATUS_SNAPSHOT_DOCUMENT_INVALID"
        ) from exc


def _parse_snapshot(value: object) -> ExternalStatusSnapshot:
    expected = frozenset(item.name for item in fields(ExternalStatusSnapshot))
    raw = _exact_mapping(
        value,
        expected,
        "STATUS_SNAPSHOT_DOCUMENT_INVALID",
    )
    raw["captured_at_utc"] = _parse_utc(
        raw["captured_at_utc"],
        "STATUS_SNAPSHOT_DOCUMENT_INVALID",
    )
    raw["decision"] = _parse_service(raw["decision"])
    raw["execution"] = _parse_service(raw["execution"])
    raw["host"] = _parse_host(raw["host"])
    try:
        return ExternalStatusSnapshot(**raw)
    except (TypeError, ValueError) as exc:
        raise WindowsStatusMonitorProviderError(
            "STATUS_SNAPSHOT_DOCUMENT_INVALID"
        ) from exc


def _parse_clock_attestation(
    value: object,
) -> WindowsClockAttestation:
    expected = frozenset(
        item.name for item in fields(WindowsClockAttestation)
    )
    raw = _exact_mapping(
        value,
        expected,
        "CLOCK_ATTESTATION_FILE_INVALID",
    )
    for name in (
        "authority_utc",
        "observed_system_utc",
        "issued_at_utc",
        "expires_at_utc",
    ):
        raw[name] = _parse_utc(
            raw[name],
            "CLOCK_ATTESTATION_FILE_INVALID",
        )
    try:
        return WindowsClockAttestation(**raw)
    except (TypeError, ValueError) as exc:
        raise WindowsStatusMonitorProviderError(
            "CLOCK_ATTESTATION_FILE_INVALID"
        ) from exc


class _VerifiedHashes:
    __slots__ = ("__items", "__lock")

    def __init__(self) -> None:
        self.__items: list[str] = []
        self.__lock = threading.Lock()

    def add(self, value: str) -> None:
        with self.__lock:
            if value in self.__items:
                self.__items.remove(value)
            self.__items.append(value)
            del self.__items[:-MAX_VERIFIED_OBJECTS]

    def contains(self, value: str) -> bool:
        with self.__lock:
            return value in self.__items


class SignedStatusSnapshotDirectory:
    """Read one exact externally signed checkpoint successor."""

    __slots__ = (
        "__clock_provider",
        "__directory",
        "__key_id",
        "__key_provider",
        "__monitor_service_id",
        "__provider_id",
        "__timeout_seconds",
    )

    def __init__(
        self,
        *,
        provider_id: str,
        monitor_service_id: str,
        directory: str | Path,
        key_id: str,
        key_provider: Callable[[str], str | bytes],
        clock_provider: Callable[[], datetime],
        timeout_seconds: float,
    ) -> None:
        self.__provider_id = _identifier(
            provider_id,
            "STATUS_SNAPSHOT_PROVIDER_ID_INVALID",
        )
        self.__monitor_service_id = _identifier(
            monitor_service_id,
            "STATUS_SNAPSHOT_SERVICE_ID_INVALID",
        )
        self.__key_id = _identifier(
            key_id,
            "STATUS_SNAPSHOT_KEY_ID_INVALID",
        )
        if not callable(key_provider) or not callable(clock_provider):
            raise TypeError("snapshot providers must be callable")
        timeout = require_finite(
            "timeout_seconds",
            timeout_seconds,
            positive=True,
        )
        if timeout > 2.0:
            raise ValueError("snapshot timeout cannot exceed two seconds")
        self.__directory = Path(directory)
        _existing_directory(
            self.__directory,
            "STATUS_SNAPSHOT_DIRECTORY_INVALID",
        )
        self.__key_provider = key_provider
        self.__clock_provider = clock_provider
        self.__timeout_seconds = timeout

    def __call__(
        self,
        checkpoint: MonitorCheckpoint,
    ) -> ExternalStatusSnapshot:
        if type(checkpoint) is not MonitorCheckpoint:
            raise WindowsStatusMonitorProviderError(
                "STATUS_SNAPSHOT_CHECKPOINT_INVALID"
            )
        if checkpoint.monitor_service_id != self.__monitor_service_id:
            raise WindowsStatusMonitorProviderError(
                "STATUS_SNAPSHOT_CHECKPOINT_INVALID"
            )
        expected_sequence = checkpoint.sequence + 1
        path = self.__directory / (
            f"{expected_sequence:020d}.snapshot.json"
        )
        packet = _strict_json(
            _stable_read(path, "STATUS_SNAPSHOT_FILE_INVALID"),
            "STATUS_SNAPSHOT_FILE_INVALID",
        )
        if set(packet) != _SNAPSHOT_FIELDS:
            raise WindowsStatusMonitorProviderError(
                "STATUS_SNAPSHOT_DOCUMENT_INVALID"
            )
        if (
            packet.get("schema_version") != SNAPSHOT_ENVELOPE_SCHEMA
            or packet.get("provider_id") != self.__provider_id
            or packet.get("monitor_service_id")
            != self.__monitor_service_id
            or packet.get("sequence") != expected_sequence
            or packet.get("previous_snapshot_sha256")
            != checkpoint.snapshot_sha256
        ):
            raise WindowsStatusMonitorProviderError(
                "STATUS_SNAPSHOT_SEQUENCE_INVALID"
            )
        try:
            now = require_utc(
                "status snapshot trusted UTC",
                self.__clock_provider(),
            )
        except Exception as exc:
            raise WindowsStatusMonitorProviderError(
                "STATUS_SNAPSHOT_CLOCK_INVALID"
            ) from exc
        issued, expires = _fresh_window(
            packet,
            now=now,
            timeout_seconds=self.__timeout_seconds,
            code="STATUS_SNAPSHOT_TIME_INVALID",
        )
        _verify_hmac(
            packet,
            key_id=self.__key_id,
            key_provider=self.__key_provider,
            domain=_SNAPSHOT_DOMAIN,
            code="STATUS_SNAPSHOT_SIGNATURE_INVALID",
        )
        snapshot = _parse_snapshot(packet.get("snapshot"))
        expected_attestation = canonical_sha256(
            {
                "schema_version": (
                    SNAPSHOT_ATTESTATION_BINDING_SCHEMA
                ),
                "provider_id": self.__provider_id,
                "monitor_service_id": self.__monitor_service_id,
                "sequence": expected_sequence,
                "previous_snapshot_sha256": checkpoint.snapshot_sha256,
                "key_id": self.__key_id,
                "issued_at_utc": issued,
                "expires_at_utc": expires,
            }
        )
        if (
            snapshot.monitor_provider_id != self.__provider_id
            or snapshot.sequence != expected_sequence
            or snapshot.previous_snapshot_sha256
            != checkpoint.snapshot_sha256
            or snapshot.source_attestation_verified is not True
            or snapshot.source_attestation_sha256
            != expected_attestation
        ):
            raise WindowsStatusMonitorProviderError(
                "STATUS_SNAPSHOT_ATTESTATION_INVALID"
            )
        if (
            packet.get("snapshot_sha256") != snapshot.content_sha256
        ):
            raise WindowsStatusMonitorProviderError(
                "STATUS_SNAPSHOT_HASH_INVALID"
            )
        return snapshot


class ExternalMonitorCheckpointCAS:
    """Create-exclusive external checkpoint CAS with signed readback."""

    __slots__ = (
        "__acknowledgements",
        "__clock_provider",
        "__current_path",
        "__key_id",
        "__key_provider",
        "__monitor_service_id",
        "__provider_id",
        "__request_directory",
        "__response_directory",
        "__timeout_seconds",
        "__verified_checkpoints",
    )

    def __init__(
        self,
        *,
        provider_id: str,
        monitor_service_id: str,
        current_path: str | Path,
        request_directory: str | Path,
        response_directory: str | Path,
        key_id: str,
        key_provider: Callable[[str], str | bytes],
        clock_provider: Callable[[], datetime],
        timeout_seconds: float,
    ) -> None:
        self.__provider_id = _identifier(
            provider_id,
            "MONITOR_CHECKPOINT_PROVIDER_ID_INVALID",
        )
        self.__monitor_service_id = _identifier(
            monitor_service_id,
            "MONITOR_CHECKPOINT_SERVICE_ID_INVALID",
        )
        self.__key_id = _identifier(
            key_id,
            "MONITOR_CHECKPOINT_KEY_ID_INVALID",
        )
        if not callable(key_provider) or not callable(clock_provider):
            raise TypeError("checkpoint providers must be callable")
        timeout = require_finite(
            "timeout_seconds",
            timeout_seconds,
            positive=True,
        )
        if timeout > 2.0:
            raise ValueError("checkpoint timeout cannot exceed two seconds")
        self.__current_path = Path(current_path)
        self.__request_directory = Path(request_directory)
        self.__response_directory = Path(response_directory)
        _existing_file(
            self.__current_path,
            "MONITOR_CHECKPOINT_CURRENT_INVALID",
        )
        _existing_directory(
            self.__request_directory,
            "MONITOR_CHECKPOINT_REQUEST_DIRECTORY_INVALID",
        )
        _existing_directory(
            self.__response_directory,
            "MONITOR_CHECKPOINT_RESPONSE_DIRECTORY_INVALID",
        )
        self.__key_provider = key_provider
        self.__clock_provider = clock_provider
        self.__timeout_seconds = timeout
        self.__verified_checkpoints = _VerifiedHashes()
        self.__acknowledgements = _VerifiedHashes()

    def current(self) -> MonitorCheckpoint:
        packet = _strict_json(
            _stable_read(
                self.__current_path,
                "MONITOR_CHECKPOINT_CURRENT_INVALID",
            ),
            "MONITOR_CHECKPOINT_CURRENT_INVALID",
        )
        if set(packet) != _CHECKPOINT_CURRENT_FIELDS:
            raise WindowsStatusMonitorProviderError(
                "MONITOR_CHECKPOINT_CURRENT_INVALID"
            )
        if (
            packet.get("schema_version") != CHECKPOINT_CURRENT_SCHEMA
            or packet.get("provider_id") != self.__provider_id
            or packet.get("monitor_service_id")
            != self.__monitor_service_id
        ):
            raise WindowsStatusMonitorProviderError(
                "MONITOR_CHECKPOINT_CURRENT_INVALID"
            )
        try:
            now = require_utc(
                "checkpoint trusted UTC",
                self.__clock_provider(),
            )
        except Exception as exc:
            raise WindowsStatusMonitorProviderError(
                "MONITOR_CHECKPOINT_CLOCK_INVALID"
            ) from exc
        _fresh_window(
            packet,
            now=now,
            timeout_seconds=self.__timeout_seconds,
            code="MONITOR_CHECKPOINT_TIME_INVALID",
        )
        _verify_hmac(
            packet,
            key_id=self.__key_id,
            key_provider=self.__key_provider,
            domain=_CHECKPOINT_CURRENT_DOMAIN,
            code="MONITOR_CHECKPOINT_SIGNATURE_INVALID",
        )
        checkpoint = _parse_checkpoint(packet.get("checkpoint"))
        if (
            checkpoint.monitor_service_id != self.__monitor_service_id
            or packet.get("checkpoint_sha256")
            != checkpoint.content_sha256
        ):
            raise WindowsStatusMonitorProviderError(
                "MONITOR_CHECKPOINT_CURRENT_INVALID"
            )
        self.__verified_checkpoints.add(checkpoint.content_sha256)
        return checkpoint

    def verify(self, checkpoint: MonitorCheckpoint) -> bool:
        return (
            type(checkpoint) is MonitorCheckpoint
            and checkpoint.monitor_service_id
            == self.__monitor_service_id
            and self.__verified_checkpoints.contains(
                checkpoint.content_sha256
            )
        )

    def compare_and_swap(
        self,
        expected: MonitorCheckpoint,
        proposed: MonitorCheckpoint,
    ) -> MonitorCheckpointAcknowledgement:
        if (
            type(expected) is not MonitorCheckpoint
            or type(proposed) is not MonitorCheckpoint
            or not self.verify(expected)
            or proposed.monitor_service_id != self.__monitor_service_id
            or proposed.sequence != expected.sequence + 1
            or proposed.snapshot_sha256 == "0" * 64
        ):
            raise WindowsStatusMonitorProviderError(
                "MONITOR_CHECKPOINT_PROPOSAL_INVALID"
            )
        issued = proposed.updated_at_utc
        expires = issued + timedelta(
            seconds=self.__timeout_seconds
        )
        material = {
            "schema_version": CHECKPOINT_REQUEST_SCHEMA,
            "provider_id": self.__provider_id,
            "monitor_service_id": self.__monitor_service_id,
            "expected_checkpoint": expected.to_canonical_dict(),
            "expected_checkpoint_sha256": expected.content_sha256,
            "proposed_checkpoint": proposed.to_canonical_dict(),
            "proposed_checkpoint_sha256": proposed.content_sha256,
            "issued_at_utc": issued,
            "expires_at_utc": expires,
        }
        request_id = (
            "monitor_checkpoint_request_"
            + canonical_sha256(material)[:32]
        )
        request = {
            **material,
            "request_id": request_id,
        }
        request_bytes = _canonical_bytes(request)
        request_path = (
            self.__request_directory
            / f"{request_id}.request.json"
        )
        _write_exclusive(
            request_path,
            request_bytes,
            "MONITOR_CHECKPOINT_REQUEST_CONFLICT",
        )
        response_path = (
            self.__response_directory
            / f"{request_id}.response.json"
        )
        response = _strict_json(
            _wait_response(
                response_path,
                timeout_seconds=self.__timeout_seconds,
                code="MONITOR_CHECKPOINT_RESPONSE_UNAVAILABLE",
            ),
            "MONITOR_CHECKPOINT_RESPONSE_INVALID",
        )
        if set(response) != _CHECKPOINT_RESPONSE_FIELDS:
            raise WindowsStatusMonitorProviderError(
                "MONITOR_CHECKPOINT_RESPONSE_INVALID"
            )
        if (
            response.get("schema_version")
            != CHECKPOINT_RESPONSE_SCHEMA
            or response.get("provider_id") != self.__provider_id
            or response.get("monitor_service_id")
            != self.__monitor_service_id
            or response.get("request_id") != request_id
            or response.get("request_sha256")
            != canonical_sha256(request)
        ):
            raise WindowsStatusMonitorProviderError(
                "MONITOR_CHECKPOINT_RESPONSE_INVALID"
            )
        responded = _parse_utc(
            response.get("responded_at_utc"),
            "MONITOR_CHECKPOINT_RESPONSE_INVALID",
        )
        try:
            observed = require_utc(
                "checkpoint response trusted UTC",
                self.__clock_provider(),
            )
        except Exception as exc:
            raise WindowsStatusMonitorProviderError(
                "MONITOR_CHECKPOINT_CLOCK_INVALID"
            ) from exc
        if (
            responded < issued
            or responded >= expires
            or observed >= expires
        ):
            raise WindowsStatusMonitorProviderError(
                "MONITOR_CHECKPOINT_RESPONSE_STALE"
            )
        _verify_hmac(
            response,
            key_id=self.__key_id,
            key_provider=self.__key_provider,
            domain=_CHECKPOINT_RESPONSE_DOMAIN,
            code="MONITOR_CHECKPOINT_RESPONSE_SIGNATURE_INVALID",
        )
        acknowledgement = _parse_checkpoint_acknowledgement(
            response.get("acknowledgement")
        )
        current = _parse_checkpoint(
            response.get("current_checkpoint")
        )
        if (
            current != proposed
            or response.get("current_checkpoint_sha256")
            != proposed.content_sha256
            or acknowledgement.monitor_service_id
            != self.__monitor_service_id
            or acknowledgement.provider_id != self.__provider_id
            or acknowledgement.expected_sequence != expected.sequence
            or acknowledgement.committed_sequence != proposed.sequence
            or acknowledgement.committed_snapshot_sha256
            != proposed.snapshot_sha256
            or acknowledgement.acknowledged_at_utc != responded
        ):
            raise WindowsStatusMonitorProviderError(
                "MONITOR_CHECKPOINT_READBACK_MISMATCH"
            )
        self.__verified_checkpoints.add(current.content_sha256)
        self.__acknowledgements.add(
            acknowledgement.content_sha256
        )
        return acknowledgement

    def verify_acknowledgement(
        self,
        acknowledgement: MonitorCheckpointAcknowledgement,
    ) -> bool:
        return (
            type(acknowledgement)
            is MonitorCheckpointAcknowledgement
            and acknowledgement.provider_id == self.__provider_id
            and acknowledgement.monitor_service_id
            == self.__monitor_service_id
            and self.__acknowledgements.contains(
                acknowledgement.content_sha256
            )
        )


class ExternalMonitorIncidentLatch:
    """External append-only incident request with signed acknowledgement."""

    __slots__ = (
        "__acknowledgements",
        "__clock_provider",
        "__key_id",
        "__key_provider",
        "__monitor_service_id",
        "__provider_id",
        "__request_directory",
        "__response_directory",
        "__timeout_seconds",
    )

    def __init__(
        self,
        *,
        provider_id: str,
        monitor_service_id: str,
        request_directory: str | Path,
        response_directory: str | Path,
        key_id: str,
        key_provider: Callable[[str], str | bytes],
        clock_provider: Callable[[], datetime],
        timeout_seconds: float,
    ) -> None:
        self.__provider_id = _identifier(
            provider_id,
            "MONITOR_INCIDENT_PROVIDER_ID_INVALID",
        )
        self.__monitor_service_id = _identifier(
            monitor_service_id,
            "MONITOR_INCIDENT_SERVICE_ID_INVALID",
        )
        self.__key_id = _identifier(
            key_id,
            "MONITOR_INCIDENT_KEY_ID_INVALID",
        )
        if not callable(key_provider) or not callable(clock_provider):
            raise TypeError("incident providers must be callable")
        timeout = require_finite(
            "timeout_seconds",
            timeout_seconds,
            positive=True,
        )
        if timeout > 2.0:
            raise ValueError("incident timeout cannot exceed two seconds")
        self.__request_directory = Path(request_directory)
        self.__response_directory = Path(response_directory)
        _existing_directory(
            self.__request_directory,
            "MONITOR_INCIDENT_REQUEST_DIRECTORY_INVALID",
        )
        _existing_directory(
            self.__response_directory,
            "MONITOR_INCIDENT_RESPONSE_DIRECTORY_INVALID",
        )
        self.__key_provider = key_provider
        self.__clock_provider = clock_provider
        self.__timeout_seconds = timeout
        self.__acknowledgements = _VerifiedHashes()

    def __call__(
        self,
        assessment: ExternalStatusAssessment,
    ) -> MonitorIncidentAcknowledgement:
        if (
            type(assessment) is not ExternalStatusAssessment
            or assessment.monitor_service_id
            != self.__monitor_service_id
            or assessment.incident_required is not True
            or assessment.incident_id is None
        ):
            raise WindowsStatusMonitorProviderError(
                "MONITOR_INCIDENT_ASSESSMENT_INVALID"
            )
        issued = assessment.evaluated_at_utc
        expires = issued + timedelta(
            seconds=self.__timeout_seconds
        )
        material = {
            "schema_version": INCIDENT_REQUEST_SCHEMA,
            "provider_id": self.__provider_id,
            "monitor_service_id": self.__monitor_service_id,
            "incident_id": assessment.incident_id,
            "assessment": assessment.to_canonical_dict(),
            "assessment_sha256": assessment.content_sha256,
            "issued_at_utc": issued,
            "expires_at_utc": expires,
        }
        request_id = (
            "monitor_incident_request_"
            + canonical_sha256(material)[:32]
        )
        request = {**material, "request_id": request_id}
        _write_exclusive(
            self.__request_directory
            / f"{request_id}.request.json",
            _canonical_bytes(request),
            "MONITOR_INCIDENT_REQUEST_CONFLICT",
        )
        response = _strict_json(
            _wait_response(
                self.__response_directory
                / f"{request_id}.response.json",
                timeout_seconds=self.__timeout_seconds,
                code="MONITOR_INCIDENT_RESPONSE_UNAVAILABLE",
            ),
            "MONITOR_INCIDENT_RESPONSE_INVALID",
        )
        if set(response) != _INCIDENT_RESPONSE_FIELDS:
            raise WindowsStatusMonitorProviderError(
                "MONITOR_INCIDENT_RESPONSE_INVALID"
            )
        if (
            response.get("schema_version") != INCIDENT_RESPONSE_SCHEMA
            or response.get("provider_id") != self.__provider_id
            or response.get("monitor_service_id")
            != self.__monitor_service_id
            or response.get("request_id") != request_id
            or response.get("request_sha256")
            != canonical_sha256(request)
        ):
            raise WindowsStatusMonitorProviderError(
                "MONITOR_INCIDENT_RESPONSE_INVALID"
            )
        responded = _parse_utc(
            response.get("responded_at_utc"),
            "MONITOR_INCIDENT_RESPONSE_INVALID",
        )
        try:
            observed = require_utc(
                "incident response trusted UTC",
                self.__clock_provider(),
            )
        except Exception as exc:
            raise WindowsStatusMonitorProviderError(
                "MONITOR_INCIDENT_CLOCK_INVALID"
            ) from exc
        if (
            responded < issued
            or responded >= expires
            or observed >= expires
        ):
            raise WindowsStatusMonitorProviderError(
                "MONITOR_INCIDENT_RESPONSE_STALE"
            )
        _verify_hmac(
            response,
            key_id=self.__key_id,
            key_provider=self.__key_provider,
            domain=_INCIDENT_RESPONSE_DOMAIN,
            code="MONITOR_INCIDENT_RESPONSE_SIGNATURE_INVALID",
        )
        acknowledgement = _parse_incident_acknowledgement(
            response.get("acknowledgement")
        )
        if (
            acknowledgement.incident_id != assessment.incident_id
            or acknowledgement.assessment_sha256
            != assessment.content_sha256
            or acknowledgement.provider_id != self.__provider_id
            or acknowledgement.acknowledged_at_utc != responded
        ):
            raise WindowsStatusMonitorProviderError(
                "MONITOR_INCIDENT_ACKNOWLEDGEMENT_MISMATCH"
            )
        self.__acknowledgements.add(
            acknowledgement.content_sha256
        )
        return acknowledgement

    def verify_acknowledgement(
        self,
        acknowledgement: MonitorIncidentAcknowledgement,
    ) -> bool:
        return (
            type(acknowledgement) is MonitorIncidentAcknowledgement
            and acknowledgement.provider_id == self.__provider_id
            and self.__acknowledgements.contains(
                acknowledgement.content_sha256
            )
        )


def _windows_path(value: object) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise WindowsStatusMonitorProviderError(
            "STATUS_MONITOR_PROVIDER_PATH_INVALID"
        )
    if "/" in value or "\x00" in value:
        raise WindowsStatusMonitorProviderError(
            "STATUS_MONITOR_PROVIDER_PATH_INVALID"
        )
    pure = PureWindowsPath(value)
    parts = pure.parts
    if (
        not pure.is_absolute()
        or not parts
        or _DRIVE.fullmatch(pure.drive) is None
        or pure.drive != pure.drive.upper()
        or pure.anchor != f"{pure.drive}\\"
        or str(pure) != value
        or any(
            part in {"", ".", ".."}
            or part.endswith((" ", "."))
            or ":" in part
            or part.casefold().split(".", 1)[0] in _WINDOWS_RESERVED
            for part in parts[1:]
        )
    ):
        raise WindowsStatusMonitorProviderError(
            "STATUS_MONITOR_PROVIDER_PATH_INVALID"
        )
    return value


def _windows_paths_overlap(values: list[str]) -> bool:
    normalized = [
        tuple(part.casefold() for part in PureWindowsPath(value).parts)
        for value in values
    ]
    for index, first in enumerate(normalized):
        for second in normalized[index + 1 :]:
            length = min(len(first), len(second))
            if first[:length] == second[:length]:
                return True
    return False


@dataclass(frozen=True, slots=True)
class WindowsStatusMonitorProviderConfiguration(CanonicalContract):
    pack_id: str
    base_suite_identity_sha256: str
    status_monitor_base_release_identity_sha256: str
    runtime_config_sha256: str
    clock_binding: WindowsClockBinding
    credential_target_prefix: str
    credential_references: tuple[CredentialReference, ...]
    snapshot_key_id: str
    checkpoint_key_id: str
    incident_key_id: str
    heartbeat_sender_key_id: str
    alert_sender_key_id: str
    remote_ack_key_id: str
    clock_attestation_path: str
    snapshot_directory: str
    checkpoint_current_path: str
    checkpoint_request_directory: str
    checkpoint_response_directory: str
    incident_request_directory: str
    incident_response_directory: str
    heartbeat_outbox_database: str
    alert_outbox_database: str
    heartbeat_outbound_directory: str
    heartbeat_acknowledgement_directory: str
    alert_outbound_directory: str
    alert_acknowledgement_directory: str
    checkpoint_provider_id: str
    incident_provider_id: str
    provider_timeout_seconds: float
    provider_bindings: tuple[MonitorProviderBinding, ...]
    status_only: bool = True
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    max_lot: float = MAX_LOT
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    production_execution_ready: bool = PRODUCTION_EXECUTION_READY
    schema_version: str = PROVIDER_CONFIGURATION_SCHEMA

    def __post_init__(self) -> None:
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
            object.__setattr__(
                self,
                name,
                _identifier(
                    getattr(self, name),
                    "STATUS_MONITOR_PROVIDER_ID_INVALID",
                ),
            )
        for name in (
            "base_suite_identity_sha256",
            "status_monitor_base_release_identity_sha256",
            "runtime_config_sha256",
        ):
            object.__setattr__(
                self,
                name,
                _hash(
                    getattr(self, name),
                    "STATUS_MONITOR_PROVIDER_HASH_INVALID",
                ),
            )
        if type(self.clock_binding) is not WindowsClockBinding:
            raise TypeError("clock_binding must be exact WindowsClockBinding")
        if (
            type(self.credential_target_prefix) is not str
            or not self.credential_target_prefix
        ):
            raise ValueError("credential_target_prefix is required")
        if (
            type(self.credential_references) is not tuple
            or any(
                type(item) is not CredentialReference
                for item in self.credential_references
            )
        ):
            raise TypeError(
                "credential_references must contain exact references"
            )
        key_ids = (
            self.clock_binding.authority_key_id,
            self.snapshot_key_id,
            self.checkpoint_key_id,
            self.incident_key_id,
            self.heartbeat_sender_key_id,
            self.alert_sender_key_id,
            self.remote_ack_key_id,
        )
        if (
            len({value.casefold() for value in key_ids}) != len(key_ids)
            or {item.key_id for item in self.credential_references}
            != set(key_ids)
        ):
            raise ValueError(
                "status monitor custody key domains must be exact and distinct"
            )
        references = tuple(
            sorted(
                self.credential_references,
                key=lambda item: item.key_id,
            )
        )
        object.__setattr__(
            self,
            "credential_references",
            references,
        )
        paths = []
        for name in _PATH_FIELDS:
            normalized = _windows_path(getattr(self, name))
            object.__setattr__(self, name, normalized)
            paths.append(normalized)
        if _windows_paths_overlap(paths):
            raise ValueError("status monitor provider paths overlap")
        timeout = require_finite(
            "provider_timeout_seconds",
            self.provider_timeout_seconds,
            positive=True,
        )
        if timeout > 2.0:
            raise ValueError("provider timeout cannot exceed two seconds")
        object.__setattr__(
            self,
            "provider_timeout_seconds",
            timeout,
        )
        if (
            type(self.provider_bindings) is not tuple
            or any(
                type(item) is not MonitorProviderBinding
                for item in self.provider_bindings
            )
            or tuple(
                item.role
                for item in sorted(
                    self.provider_bindings,
                    key=lambda item: item.role,
                )
            )
            != MONITOR_PROVIDER_ROLES
        ):
            raise ValueError("status monitor provider bindings are incomplete")
        object.__setattr__(
            self,
            "provider_bindings",
            tuple(
                sorted(
                    self.provider_bindings,
                    key=lambda item: item.role,
                )
            ),
        )
        if (
            self.status_only is not True
            or self.order_capability != ORDER_CAPABILITY
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or self.max_lot != MAX_LOT
            or self.promotion_eligible is not False
            or self.production_execution_ready is not False
            or self.schema_version != PROVIDER_CONFIGURATION_SCHEMA
        ):
            raise ValueError("status monitor provider safety drift")


def windows_status_monitor_provider_configuration_from_dict(
    value: Mapping[str, object],
) -> WindowsStatusMonitorProviderConfiguration:
    """Strictly reconstruct one generated non-secret configuration."""

    root = _exact_mapping(
        value,
        _CONFIGURATION_FIELDS,
        "STATUS_MONITOR_PROVIDER_CONFIGURATION_INVALID",
    )
    raw_clock = _exact_mapping(
        root.get("clock_binding"),
        _CLOCK_FIELDS,
        "STATUS_MONITOR_PROVIDER_CONFIGURATION_INVALID",
    )
    try:
        root["clock_binding"] = WindowsClockBinding(**raw_clock)
    except (TypeError, ValueError) as exc:
        raise WindowsStatusMonitorProviderError(
            "STATUS_MONITOR_PROVIDER_CONFIGURATION_INVALID"
        ) from exc
    raw_references = root.get("credential_references")
    if type(raw_references) is not list:
        raise WindowsStatusMonitorProviderError(
            "STATUS_MONITOR_PROVIDER_CONFIGURATION_INVALID"
        )
    references = []
    for raw in raw_references:
        item = _exact_mapping(
            raw,
            _CREDENTIAL_FIELDS,
            "STATUS_MONITOR_PROVIDER_CONFIGURATION_INVALID",
        )
        try:
            references.append(CredentialReference(**item))
        except (TypeError, ValueError) as exc:
            raise WindowsStatusMonitorProviderError(
                "STATUS_MONITOR_PROVIDER_CONFIGURATION_INVALID"
            ) from exc
    root["credential_references"] = tuple(references)
    raw_bindings = root.get("provider_bindings")
    if type(raw_bindings) is not list:
        raise WindowsStatusMonitorProviderError(
            "STATUS_MONITOR_PROVIDER_CONFIGURATION_INVALID"
        )
    bindings = []
    for raw in raw_bindings:
        item = _exact_mapping(
            raw,
            _PROVIDER_BINDING_FIELDS,
            "STATUS_MONITOR_PROVIDER_CONFIGURATION_INVALID",
        )
        try:
            bindings.append(MonitorProviderBinding(**item))
        except (TypeError, ValueError) as exc:
            raise WindowsStatusMonitorProviderError(
                "STATUS_MONITOR_PROVIDER_CONFIGURATION_INVALID"
            ) from exc
    root["provider_bindings"] = tuple(bindings)
    try:
        return WindowsStatusMonitorProviderConfiguration(**root)
    except WindowsStatusMonitorProviderError:
        raise
    except (TypeError, ValueError) as exc:
        raise WindowsStatusMonitorProviderError(
            "STATUS_MONITOR_PROVIDER_CONFIGURATION_INVALID"
        ) from exc


class _ClockAttestationFile:
    __slots__ = ("__path",)

    def __init__(self, path: Path) -> None:
        self.__path = path

    def __call__(self) -> WindowsClockAttestation:
        payload = _strict_json(
            _stable_read(
                self.__path,
                "CLOCK_ATTESTATION_FILE_INVALID",
            ),
            "CLOCK_ATTESTATION_FILE_INVALID",
        )
        return _parse_clock_attestation(payload)


def build_windows_status_monitor_dependencies(
    *,
    runtime_config: ExternalMonitorConfig,
    provider_config: WindowsStatusMonitorProviderConfiguration,
    platform: str | None = None,
    credential_backend: object | None = None,
    path_resolver: Callable[[str], Path] | None = None,
    system_clock: Callable[[], datetime] | None = None,
) -> StatusMonitorDependencies:
    """Materialize exact status-only dependencies after complete validation."""

    if type(runtime_config) is not ExternalMonitorConfig:
        raise TypeError("runtime_config must be exact ExternalMonitorConfig")
    if type(provider_config) is not WindowsStatusMonitorProviderConfiguration:
        raise TypeError(
            "provider_config must be exact "
            "WindowsStatusMonitorProviderConfiguration"
        )
    runtime_core = runtime_config.to_canonical_dict()
    runtime_core.pop("providers", None)
    if (
        canonical_sha256(runtime_core)
        != provider_config.runtime_config_sha256
        or runtime_config.providers != provider_config.provider_bindings
        or runtime_config.monitor_provider_id
        != provider_config.pack_id
        or runtime_config.snapshot_checkpoint_provider_id
        != provider_config.checkpoint_provider_id
        or runtime_config.incident_latch_provider_id
        != provider_config.incident_provider_id
    ):
        raise WindowsStatusMonitorProviderError(
            "STATUS_MONITOR_PROVIDER_RUNTIME_BINDING_MISMATCH"
        )
    observed_platform = sys.platform if platform is None else platform
    if observed_platform != "win32":
        raise WindowsStatusMonitorProviderError(
            "WINDOWS_PLATFORM_REQUIRED"
        )
    if path_resolver is not None and not callable(path_resolver):
        raise TypeError("path_resolver must be callable")
    resolver = path_resolver or Path
    resolved: dict[str, Path] = {}
    try:
        for name in _PATH_FIELDS:
            resolved[name] = Path(
                resolver(getattr(provider_config, name))
            )
    except Exception as exc:
        raise WindowsStatusMonitorProviderError(
            "STATUS_MONITOR_PROVIDER_PATH_INVALID"
        ) from exc
    for name in _FILE_PATH_FIELDS:
        _existing_file(
            resolved[name],
            "STATUS_MONITOR_PROVIDER_STATE_NOT_PROVISIONED",
        )
    for name in _DIRECTORY_PATH_FIELDS:
        _existing_directory(
            resolved[name],
            "STATUS_MONITOR_PROVIDER_STATE_NOT_PROVISIONED",
        )

    references = {
        item.key_id: item
        for item in provider_config.credential_references
    }
    if (
        references[provider_config.clock_binding.authority_key_id]
        .fingerprint_sha256
        != provider_config.clock_binding.authority_key_fingerprint_sha256
    ):
        raise WindowsStatusMonitorProviderError(
            "STATUS_MONITOR_CLOCK_KEY_BINDING_MISMATCH"
        )
    key_provider = WindowsCredentialManagerKeyProvider(
        target_prefix=provider_config.credential_target_prefix,
        references=provider_config.credential_references,
        backend=credential_backend,  # type: ignore[arg-type]
        platform=observed_platform,
    )
    trusted_clock = AttestedTrustedUTCProvider(
        binding=provider_config.clock_binding,
        attestation_provider=_ClockAttestationFile(
            resolved["clock_attestation_path"]
        ),
        key_provider=key_provider,
        system_clock=system_clock or (lambda: datetime.now(UTC)),
    )
    snapshot = SignedStatusSnapshotDirectory(
        provider_id=runtime_config.monitor_provider_id,
        monitor_service_id=runtime_config.monitor_service_id,
        directory=resolved["snapshot_directory"],
        key_id=provider_config.snapshot_key_id,
        key_provider=key_provider,
        clock_provider=trusted_clock,
        timeout_seconds=provider_config.provider_timeout_seconds,
    )
    checkpoint = ExternalMonitorCheckpointCAS(
        provider_id=provider_config.checkpoint_provider_id,
        monitor_service_id=runtime_config.monitor_service_id,
        current_path=resolved["checkpoint_current_path"],
        request_directory=resolved[
            "checkpoint_request_directory"
        ],
        response_directory=resolved[
            "checkpoint_response_directory"
        ],
        key_id=provider_config.checkpoint_key_id,
        key_provider=key_provider,
        clock_provider=trusted_clock,
        timeout_seconds=provider_config.provider_timeout_seconds,
    )
    incident = ExternalMonitorIncidentLatch(
        provider_id=provider_config.incident_provider_id,
        monitor_service_id=runtime_config.monitor_service_id,
        request_directory=resolved["incident_request_directory"],
        response_directory=resolved["incident_response_directory"],
        key_id=provider_config.incident_key_id,
        key_provider=key_provider,
        clock_provider=trusted_clock,
        timeout_seconds=provider_config.provider_timeout_seconds,
    )
    heartbeat_outbox = DeliveryOutbox(
        resolved["heartbeat_outbox_database"],
        require_existing=True,
    )
    alert_outbox = DeliveryOutbox(
        resolved["alert_outbox_database"],
        require_existing=True,
    )
    heartbeat_transport = DirectoryDropTransport(
        resolved["heartbeat_outbound_directory"],
        resolved["heartbeat_acknowledgement_directory"],
        require_existing=True,
    )
    alert_transport = DirectoryDropTransport(
        resolved["alert_outbound_directory"],
        resolved["alert_acknowledgement_directory"],
        require_existing=True,
    )
    return StatusMonitorDependencies(
        snapshot_provider=snapshot,
        checkpoint_provider=checkpoint.current,
        checkpoint_verifier=checkpoint.verify,
        checkpoint_compare_and_swap=checkpoint.compare_and_swap,
        checkpoint_acknowledgement_verifier=(
            checkpoint.verify_acknowledgement
        ),
        incident_latch=incident,
        incident_acknowledgement_verifier=(
            incident.verify_acknowledgement
        ),
        heartbeat_outbox=heartbeat_outbox,
        heartbeat_transport=heartbeat_transport,
        alert_outbox=alert_outbox,
        alert_transport=alert_transport,
        heartbeat_sender_key_id=(
            provider_config.heartbeat_sender_key_id
        ),
        alert_sender_key_id=provider_config.alert_sender_key_id,
        sender_key_provider=key_provider,
        heartbeat_sender_key_fingerprint_sha256=(
            references[
                provider_config.heartbeat_sender_key_id
            ].fingerprint_sha256
        ),
        alert_sender_key_fingerprint_sha256=(
            references[
                provider_config.alert_sender_key_id
            ].fingerprint_sha256
        ),
        remote_ack_key_id=provider_config.remote_ack_key_id,
        remote_ack_key_provider=key_provider,
        remote_ack_key_fingerprint_sha256=(
            references[
                provider_config.remote_ack_key_id
            ].fingerprint_sha256
        ),
        clock_provider=trusted_clock,
    )


__all__ = [
    "CHECKPOINT_CURRENT_SCHEMA",
    "CHECKPOINT_REQUEST_SCHEMA",
    "CHECKPOINT_RESPONSE_SCHEMA",
    "ExternalMonitorCheckpointCAS",
    "ExternalMonitorIncidentLatch",
    "INCIDENT_REQUEST_SCHEMA",
    "INCIDENT_RESPONSE_SCHEMA",
    "LIVE_ALLOWED",
    "MAX_LOT",
    "ORDER_CAPABILITY",
    "PRODUCTION_EXECUTION_READY",
    "PROMOTION_ELIGIBLE",
    "PROVIDER_CONFIGURATION_SCHEMA",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "SNAPSHOT_ATTESTATION_BINDING_SCHEMA",
    "SNAPSHOT_ENVELOPE_SCHEMA",
    "SignedStatusSnapshotDirectory",
    "WindowsStatusMonitorProviderConfiguration",
    "WindowsStatusMonitorProviderError",
    "build_windows_status_monitor_dependencies",
    "windows_status_monitor_provider_configuration_from_dict",
]
