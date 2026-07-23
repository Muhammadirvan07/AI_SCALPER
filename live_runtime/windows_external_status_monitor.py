"""Fail-closed, status-only monitor for the dual Windows service boundary.

The monitor is deliberately outside both the decision and execution services.
It consumes reviewed status snapshots, emits authenticated off-host
heartbeats/alerts, and advances an externally held checkpoint only after every
required acknowledgement is verified.  It has no broker, credential, permit,
risk, reconciliation, order, process-launch, or task-install surface.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from datetime import datetime, timedelta
import hashlib
import math
import os
import queue
import re
import signal
import threading
from typing import Callable

from .contracts import (
    CanonicalContract,
    require_finite,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from .offhost_delivery import (
    DeliveryAcknowledgement,
    DeliveryEnvelope,
    DeliveryOutbox,
    OffHostDeliverySupervisor,
)
from .windows_external_status_monitor_factory_template import (
    MONITOR_PROVIDER_ROLES,
    MonitorProviderBinding,
    WindowsExternalStatusMonitorFactoryTemplate,
)


RELEASE_PROFILE = "WINDOWS_EXTERNAL_STATUS_MONITOR_V1"
CONFIG_SCHEMA = "windows-external-status-monitor-config-v1"
THRESHOLDS_SCHEMA = "windows-external-status-monitor-thresholds-v1"
SERVICE_OBSERVATION_SCHEMA = "windows-monitored-service-observation-v1"
HOST_OBSERVATION_SCHEMA = "windows-monitor-host-observation-v1"
SNAPSHOT_SCHEMA = "windows-external-status-snapshot-v1"
ASSESSMENT_SCHEMA = "windows-external-status-assessment-v1"
CHECKPOINT_SCHEMA = "windows-external-status-monitor-checkpoint-v1"
CHECKPOINT_ACK_SCHEMA = (
    "windows-external-status-monitor-checkpoint-acknowledgement-v1"
)
INCIDENT_ACK_SCHEMA = (
    "windows-external-status-monitor-incident-acknowledgement-v1"
)
ORDER_CAPABILITY = "DISABLED"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
PROMOTION_ELIGIBLE = False
MAX_LOT = 0.01
MONITOR_DEADLINE_EXIT_CODE = 72
ZERO_SHA256 = "0" * 64

_ASSESSMENT_SEAL = object()
_REASON_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_SERVICE_ROLES = frozenset({"DECISION", "EXECUTION"})
_TASK_STATES = frozenset({"RUNNING", "READY", "DISABLED", "UNKNOWN"})
_SERVICE_PHASES = frozenset(
    {
        "STARTING",
        "INITIALIZED",
        "RUNNING",
        "STOPPING",
        "STOPPED",
        "FAILED",
        "DEGRADED",
        "UNKNOWN",
    }
)


class ExternalStatusMonitorError(RuntimeError):
    """One monitor trust, continuity, delivery, or deadline boundary failed."""

    def __init__(self, reason_code: str) -> None:
        normalized = str(reason_code or "").strip().upper()
        self.reason_code = normalized or "EXTERNAL_STATUS_MONITOR_FAILED"
        super().__init__(self.reason_code)


def _require_exact_bool(name: str, value: object) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{name} must be an exact bool")
    return value


def _require_false(name: str, value: object) -> bool:
    normalized = _require_exact_bool(name, value)
    if normalized is not False:
        raise ValueError("monitor safety locks cannot be overridden")
    return normalized


def _nonzero_hash(name: str, value: object) -> str:
    normalized = require_hash(name, value)
    if normalized == ZERO_SHA256:
        raise ValueError(f"{name} cannot be the zero hash")
    return normalized


def _provider_id(name: str, value: object) -> str:
    normalized = require_text(name, value)
    if (
        len(normalized) > 160
        or any(character.isspace() for character in normalized)
        or "://" in normalized
        or "\\" in normalized
        or "/" in normalized
    ):
        raise ValueError(f"{name} must be an opaque provider identifier")
    return normalized


def _reason_codes(name: str, values: object) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise TypeError(f"{name} must be a tuple")
    normalized: list[str] = []
    for value in values:
        reason = require_text(name, value, upper=True)
        if _REASON_RE.fullmatch(reason) is None:
            raise ValueError(f"{name} contains an invalid reason code")
        normalized.append(reason)
    if (
        normalized != sorted(normalized)
        or len(normalized) != len(set(normalized))
    ):
        raise ValueError(f"{name} must be sorted and unique")
    return tuple(normalized)


def _key_fingerprint(value: str | bytes) -> str:
    if isinstance(value, str):
        raw = value.encode("utf-8")
    elif isinstance(value, bytes):
        raw = value
    else:
        raise TypeError("monitor key must be str or bytes")
    if len(raw) < 32:
        raise ValueError("monitor key must contain at least 32 bytes")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class ExternalMonitorThresholds(CanonicalContract):
    max_clock_drift_seconds: float = 1.0
    minimum_free_disk_gib: float = 10.0
    max_service_status_age_seconds: int = 30
    max_audit_export_age_seconds: int = 300
    max_backup_anchor_age_seconds: int = 86_400
    max_snapshot_age_seconds: int = 30
    schema_version: str = THRESHOLDS_SCHEMA

    def __post_init__(self) -> None:
        clock = require_finite(
            "max_clock_drift_seconds",
            self.max_clock_drift_seconds,
            positive=True,
        )
        if clock > 1.0:
            raise ValueError("max_clock_drift_seconds cannot exceed one second")
        object.__setattr__(self, "max_clock_drift_seconds", clock)
        disk = require_finite(
            "minimum_free_disk_gib",
            self.minimum_free_disk_gib,
            positive=True,
        )
        if disk < 5.0:
            raise ValueError("minimum_free_disk_gib cannot be below five GiB")
        object.__setattr__(self, "minimum_free_disk_gib", disk)
        bounds = {
            "max_service_status_age_seconds": (1, 30),
            "max_audit_export_age_seconds": (1, 300),
            "max_backup_anchor_age_seconds": (1, 86_400),
            "max_snapshot_age_seconds": (1, 30),
        }
        for field, (minimum, maximum) in bounds.items():
            require_int(
                field,
                getattr(self, field),
                minimum=minimum,
                maximum=maximum,
            )
        if self.schema_version != THRESHOLDS_SCHEMA:
            raise ValueError("external monitor threshold schema drift")


@dataclass(frozen=True)
class ExternalMonitorConfig(CanonicalContract):
    monitor_service_id: str
    monitor_provider_id: str
    monitor_service_account_id: str
    decision_service_id: str
    execution_service_id: str
    decision_service_account_id: str
    execution_service_account_id: str
    decision_release_identity_sha256: str
    execution_release_identity_sha256: str
    decision_task_definition_sha256: str
    execution_task_definition_sha256: str
    decision_ipc_binding_sha256: str
    snapshot_checkpoint_provider_id: str
    incident_latch_provider_id: str
    heartbeat_destination_id: str
    alert_destination_id: str
    thresholds: ExternalMonitorThresholds
    providers: tuple[MonitorProviderBinding, ...]
    max_cycles: int
    poll_seconds: float
    cycle_deadline_seconds: float
    status_only: bool = True
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    max_lot: float = MAX_LOT
    release_profile: str = RELEASE_PROFILE
    schema_version: str = CONFIG_SCHEMA

    def __post_init__(self) -> None:
        service_ids = []
        for name in (
            "monitor_service_id",
            "decision_service_id",
            "execution_service_id",
        ):
            value = _provider_id(name, getattr(self, name))
            object.__setattr__(self, name, value)
            service_ids.append(value.casefold())
        if len(set(service_ids)) != 3:
            raise ValueError("monitor and monitored service IDs must be distinct")

        service_accounts = []
        for name in (
            "monitor_service_account_id",
            "decision_service_account_id",
            "execution_service_account_id",
        ):
            value = _provider_id(name, getattr(self, name))
            object.__setattr__(self, name, value)
            service_accounts.append(value.casefold())
        if len(set(service_accounts)) != 3:
            raise ValueError(
                "monitor and monitored service accounts must be distinct"
            )

        provider_ids = []
        for name in (
            "monitor_provider_id",
            "snapshot_checkpoint_provider_id",
            "incident_latch_provider_id",
        ):
            value = _provider_id(name, getattr(self, name))
            object.__setattr__(self, name, value)
            provider_ids.append(value.casefold())
        if len(set(provider_ids)) != len(provider_ids):
            raise ValueError("external monitor provider IDs must be distinct")

        destinations = []
        for name in ("heartbeat_destination_id", "alert_destination_id"):
            value = _provider_id(name, getattr(self, name))
            object.__setattr__(self, name, value)
            destinations.append(value.casefold())
        if len(set(destinations)) != 2:
            raise ValueError(
                "monitor heartbeat and alert destinations must be distinct"
            )

        for name in (
            "decision_release_identity_sha256",
            "execution_release_identity_sha256",
            "decision_task_definition_sha256",
            "execution_task_definition_sha256",
            "decision_ipc_binding_sha256",
        ):
            object.__setattr__(
                self,
                name,
                _nonzero_hash(name, getattr(self, name)),
            )
        if (
            self.decision_release_identity_sha256
            == self.execution_release_identity_sha256
        ):
            raise ValueError(
                "decision and execution release identities must be distinct"
            )
        if type(self.thresholds) is not ExternalMonitorThresholds:
            raise TypeError("thresholds must be exact ExternalMonitorThresholds")
        if not isinstance(self.providers, tuple) or any(
            type(item) is not MonitorProviderBinding
            for item in self.providers
        ):
            raise TypeError(
                "providers must contain exact MonitorProviderBinding"
            )
        providers = tuple(
            sorted(self.providers, key=lambda item: item.role)
        )
        # Reuse the static reviewed template as the single exact provider-set
        # and custody validator without materializing any provider.
        WindowsExternalStatusMonitorFactoryTemplate(
            service_id=self.monitor_service_id,
            monitor_provider_id=self.monitor_provider_id,
            release_identity_sha256="1" * 64,
            factory_implementation_sha256="2" * 64,
            factory_configuration_sha256="3" * 64,
            providers=providers,
        )
        if tuple(item.role for item in providers) != MONITOR_PROVIDER_ROLES:
            raise ValueError(
                "external monitor provider set is incomplete or duplicated"
            )
        object.__setattr__(self, "providers", providers)
        require_int("max_cycles", self.max_cycles, minimum=1, maximum=1_000_000)
        poll = require_finite(
            "poll_seconds",
            self.poll_seconds,
            nonnegative=True,
        )
        if poll > 60.0:
            raise ValueError("poll_seconds cannot exceed 60")
        object.__setattr__(self, "poll_seconds", poll)
        deadline = require_finite(
            "cycle_deadline_seconds",
            self.cycle_deadline_seconds,
            positive=True,
        )
        if not 0.01 <= deadline <= 30.0:
            raise ValueError("cycle_deadline_seconds must be in [0.01, 30]")
        object.__setattr__(self, "cycle_deadline_seconds", deadline)
        if _require_exact_bool("status_only", self.status_only) is not True:
            raise ValueError("external monitor must remain status-only")
        capability = require_text(
            "order_capability",
            self.order_capability,
            upper=True,
        )
        if capability != ORDER_CAPABILITY:
            raise ValueError("external monitor order capability must be disabled")
        object.__setattr__(self, "order_capability", capability)
        _require_false("live_allowed", self.live_allowed)
        _require_false(
            "safe_to_demo_auto_order",
            self.safe_to_demo_auto_order,
        )
        _require_false("promotion_eligible", self.promotion_eligible)
        lot = require_finite("max_lot", self.max_lot, positive=True)
        if lot != MAX_LOT:
            raise ValueError("monitor safety locks cannot be overridden")
        object.__setattr__(self, "max_lot", lot)
        if self.release_profile != RELEASE_PROFILE:
            raise ValueError("external monitor release profile drift")
        if self.schema_version != CONFIG_SCHEMA:
            raise ValueError("external monitor configuration schema drift")

    def factory_template(
        self,
        *,
        release_identity_sha256: str,
        factory_implementation_sha256: str,
        factory_configuration_sha256: str,
    ) -> WindowsExternalStatusMonitorFactoryTemplate:
        """Bind static provider declarations to exact configured bytes."""

        return WindowsExternalStatusMonitorFactoryTemplate(
            service_id=self.monitor_service_id,
            monitor_provider_id=self.monitor_provider_id,
            release_identity_sha256=release_identity_sha256,
            factory_implementation_sha256=(
                factory_implementation_sha256
            ),
            factory_configuration_sha256=(
                factory_configuration_sha256
            ),
            providers=self.providers,
        )


@dataclass(frozen=True)
class MonitoredServiceObservation(CanonicalContract):
    role: str
    service_id: str
    service_account_id: str
    release_identity_sha256: str
    task_definition_sha256: str
    task_state: str
    process_alive: bool
    phase: str
    status_sequence: int
    status_sha256: str
    status_occurred_at_utc: datetime
    status_valid_until_utc: datetime
    status_signature_verified: bool
    status_chain_verified: bool
    restart_reconciled: bool
    reason_codes: tuple[str, ...]
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    max_lot: float = MAX_LOT
    schema_version: str = SERVICE_OBSERVATION_SCHEMA

    def __post_init__(self) -> None:
        role = require_text("role", self.role, upper=True)
        if role not in _SERVICE_ROLES:
            raise ValueError("unsupported monitored service role")
        object.__setattr__(self, "role", role)
        for name in ("service_id", "service_account_id"):
            object.__setattr__(
                self,
                name,
                _provider_id(name, getattr(self, name)),
            )
        for name in ("release_identity_sha256", "task_definition_sha256"):
            object.__setattr__(
                self,
                name,
                _nonzero_hash(name, getattr(self, name)),
            )
        task_state = require_text(
            "task_state",
            self.task_state,
            upper=True,
        )
        if task_state not in _TASK_STATES:
            raise ValueError("unsupported monitored task state")
        object.__setattr__(self, "task_state", task_state)
        _require_exact_bool("process_alive", self.process_alive)
        phase = require_text("phase", self.phase, upper=True)
        if phase not in _SERVICE_PHASES:
            raise ValueError("unsupported monitored service phase")
        object.__setattr__(self, "phase", phase)
        require_int("status_sequence", self.status_sequence, minimum=1)
        object.__setattr__(
            self,
            "status_sha256",
            _nonzero_hash("status_sha256", self.status_sha256),
        )
        occurred = require_utc(
            "status_occurred_at_utc",
            self.status_occurred_at_utc,
        )
        valid_until = require_utc(
            "status_valid_until_utc",
            self.status_valid_until_utc,
        )
        if not (
            occurred
            < valid_until
            <= occurred + timedelta(seconds=30)
        ):
            raise ValueError(
                "status validity must be in (0, 30] seconds"
            )
        for name in (
            "status_signature_verified",
            "status_chain_verified",
            "restart_reconciled",
        ):
            _require_exact_bool(name, getattr(self, name))
        object.__setattr__(
            self,
            "reason_codes",
            _reason_codes("service reason_codes", self.reason_codes),
        )
        _require_false("live_allowed", self.live_allowed)
        _require_false(
            "safe_to_demo_auto_order",
            self.safe_to_demo_auto_order,
        )
        lot = require_finite("max_lot", self.max_lot, positive=True)
        if lot != MAX_LOT:
            raise ValueError("monitor safety locks cannot be overridden")
        object.__setattr__(self, "max_lot", lot)
        if self.schema_version != SERVICE_OBSERVATION_SCHEMA:
            raise ValueError("monitored service observation schema drift")


@dataclass(frozen=True)
class MonitorHostObservation(CanonicalContract):
    observed_at_utc: datetime
    clock_drift_seconds: float
    free_disk_gib: float
    mt5_connected: bool
    news_status_fresh: bool
    decision_ipc_continuity_verified: bool
    audit_exported_at_utc: datetime
    backup_anchored_at_utc: datetime
    offhost_delivery_healthy: bool
    critical_reason_codes: tuple[str, ...]
    broker_mutation_capability: str = ORDER_CAPABILITY
    schema_version: str = HOST_OBSERVATION_SCHEMA

    def __post_init__(self) -> None:
        require_utc("observed_at_utc", self.observed_at_utc)
        object.__setattr__(
            self,
            "clock_drift_seconds",
            require_finite(
                "clock_drift_seconds",
                self.clock_drift_seconds,
            ),
        )
        object.__setattr__(
            self,
            "free_disk_gib",
            require_finite(
                "free_disk_gib",
                self.free_disk_gib,
                nonnegative=True,
            ),
        )
        for name in (
            "mt5_connected",
            "news_status_fresh",
            "decision_ipc_continuity_verified",
            "offhost_delivery_healthy",
        ):
            _require_exact_bool(name, getattr(self, name))
        require_utc("audit_exported_at_utc", self.audit_exported_at_utc)
        require_utc("backup_anchored_at_utc", self.backup_anchored_at_utc)
        object.__setattr__(
            self,
            "critical_reason_codes",
            _reason_codes(
                "host critical_reason_codes",
                self.critical_reason_codes,
            ),
        )
        capability = require_text(
            "broker_mutation_capability",
            self.broker_mutation_capability,
            upper=True,
        )
        if capability != ORDER_CAPABILITY:
            raise ValueError("monitor host observation cannot mutate broker")
        object.__setattr__(self, "broker_mutation_capability", capability)
        if self.schema_version != HOST_OBSERVATION_SCHEMA:
            raise ValueError("monitor host observation schema drift")


@dataclass(frozen=True)
class ExternalStatusSnapshot(CanonicalContract):
    monitor_provider_id: str
    sequence: int
    previous_snapshot_sha256: str
    captured_at_utc: datetime
    source_attestation_sha256: str
    source_attestation_verified: bool
    decision: MonitoredServiceObservation
    execution: MonitoredServiceObservation
    host: MonitorHostObservation
    status_only: bool = True
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    max_lot: float = MAX_LOT
    schema_version: str = SNAPSHOT_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "monitor_provider_id",
            _provider_id(
                "monitor_provider_id",
                self.monitor_provider_id,
            ),
        )
        require_int("sequence", self.sequence, minimum=1)
        predecessor = require_hash(
            "previous_snapshot_sha256",
            self.previous_snapshot_sha256,
        )
        if self.sequence == 1 and predecessor != ZERO_SHA256:
            raise ValueError(
                "first status snapshot must use the zero predecessor"
            )
        if self.sequence > 1 and predecessor == ZERO_SHA256:
            raise ValueError(
                "later status snapshot requires a non-zero predecessor"
            )
        object.__setattr__(
            self,
            "previous_snapshot_sha256",
            predecessor,
        )
        require_utc("captured_at_utc", self.captured_at_utc)
        object.__setattr__(
            self,
            "source_attestation_sha256",
            _nonzero_hash(
                "source_attestation_sha256",
                self.source_attestation_sha256,
            ),
        )
        _require_exact_bool(
            "source_attestation_verified",
            self.source_attestation_verified,
        )
        if type(self.decision) is not MonitoredServiceObservation:
            raise TypeError(
                "decision must be exact MonitoredServiceObservation"
            )
        if type(self.execution) is not MonitoredServiceObservation:
            raise TypeError(
                "execution must be exact MonitoredServiceObservation"
            )
        if self.decision.role != "DECISION":
            raise ValueError("decision observation role mismatch")
        if self.execution.role != "EXECUTION":
            raise ValueError("execution observation role mismatch")
        if type(self.host) is not MonitorHostObservation:
            raise TypeError("host must be exact MonitorHostObservation")
        if _require_exact_bool("status_only", self.status_only) is not True:
            raise ValueError("external status snapshot must remain status-only")
        capability = require_text(
            "order_capability",
            self.order_capability,
            upper=True,
        )
        if capability != ORDER_CAPABILITY:
            raise ValueError("external status snapshot cannot carry orders")
        object.__setattr__(self, "order_capability", capability)
        _require_false("live_allowed", self.live_allowed)
        _require_false(
            "safe_to_demo_auto_order",
            self.safe_to_demo_auto_order,
        )
        _require_false("promotion_eligible", self.promotion_eligible)
        lot = require_finite("max_lot", self.max_lot, positive=True)
        if lot != MAX_LOT:
            raise ValueError("monitor safety locks cannot be overridden")
        object.__setattr__(self, "max_lot", lot)
        if self.schema_version != SNAPSHOT_SCHEMA:
            raise ValueError("external status snapshot schema drift")


@dataclass(frozen=True)
class ExternalStatusAssessment(CanonicalContract):
    monitor_service_id: str
    snapshot_sha256: str
    evaluated_at_utc: datetime
    status: str
    reason_codes: tuple[str, ...]
    incident_required: bool
    incident_id: str | None
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    max_lot: float = MAX_LOT
    schema_version: str = ASSESSMENT_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _ASSESSMENT_SEAL:
            raise TypeError(
                "external status assessment requires monitor evaluator"
            )
        object.__setattr__(
            self,
            "monitor_service_id",
            _provider_id(
                "monitor_service_id",
                self.monitor_service_id,
            ),
        )
        object.__setattr__(
            self,
            "snapshot_sha256",
            _nonzero_hash("snapshot_sha256", self.snapshot_sha256),
        )
        require_utc("evaluated_at_utc", self.evaluated_at_utc)
        status = require_text("status", self.status, upper=True)
        if status not in {"HEALTHY", "CRITICAL"}:
            raise ValueError("unsupported external monitor assessment status")
        object.__setattr__(self, "status", status)
        reasons = _reason_codes("assessment reason_codes", self.reason_codes)
        object.__setattr__(self, "reason_codes", reasons)
        _require_exact_bool("incident_required", self.incident_required)
        if status == "HEALTHY":
            if reasons or self.incident_required or self.incident_id is not None:
                raise ValueError("healthy assessment cannot carry an incident")
        else:
            if (
                not reasons
                or self.incident_required is not True
                or not isinstance(self.incident_id, str)
                or not self.incident_id.startswith("monitor_incident_")
            ):
                raise ValueError(
                    "critical assessment requires a deterministic incident"
                )
        capability = require_text(
            "order_capability",
            self.order_capability,
            upper=True,
        )
        if capability != ORDER_CAPABILITY:
            raise ValueError("external status assessment cannot carry orders")
        object.__setattr__(self, "order_capability", capability)
        _require_false("live_allowed", self.live_allowed)
        _require_false(
            "safe_to_demo_auto_order",
            self.safe_to_demo_auto_order,
        )
        _require_false("promotion_eligible", self.promotion_eligible)
        lot = require_finite("max_lot", self.max_lot, positive=True)
        if lot != MAX_LOT:
            raise ValueError("monitor safety locks cannot be overridden")
        object.__setattr__(self, "max_lot", lot)
        if self.schema_version != ASSESSMENT_SCHEMA:
            raise ValueError("external status assessment schema drift")


@dataclass(frozen=True)
class MonitorCheckpoint(CanonicalContract):
    monitor_service_id: str
    sequence: int
    snapshot_sha256: str
    updated_at_utc: datetime
    schema_version: str = CHECKPOINT_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "monitor_service_id",
            _provider_id(
                "monitor_service_id",
                self.monitor_service_id,
            ),
        )
        require_int("sequence", self.sequence, minimum=0)
        snapshot = require_hash("snapshot_sha256", self.snapshot_sha256)
        if (self.sequence == 0) != (snapshot == ZERO_SHA256):
            raise ValueError("monitor checkpoint zero-state mismatch")
        object.__setattr__(self, "snapshot_sha256", snapshot)
        require_utc("updated_at_utc", self.updated_at_utc)
        if self.schema_version != CHECKPOINT_SCHEMA:
            raise ValueError("monitor checkpoint schema drift")


@dataclass(frozen=True)
class MonitorCheckpointAcknowledgement(CanonicalContract):
    monitor_service_id: str
    expected_sequence: int
    committed_sequence: int
    committed_snapshot_sha256: str
    provider_id: str
    acknowledged_at_utc: datetime
    receipt_sha256: str
    schema_version: str = CHECKPOINT_ACK_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "monitor_service_id",
            _provider_id(
                "monitor_service_id",
                self.monitor_service_id,
            ),
        )
        require_int("expected_sequence", self.expected_sequence, minimum=0)
        require_int("committed_sequence", self.committed_sequence, minimum=1)
        if self.committed_sequence != self.expected_sequence + 1:
            raise ValueError("monitor checkpoint acknowledgement sequence drift")
        object.__setattr__(
            self,
            "committed_snapshot_sha256",
            _nonzero_hash(
                "committed_snapshot_sha256",
                self.committed_snapshot_sha256,
            ),
        )
        object.__setattr__(
            self,
            "provider_id",
            _provider_id("provider_id", self.provider_id),
        )
        require_utc("acknowledged_at_utc", self.acknowledged_at_utc)
        object.__setattr__(
            self,
            "receipt_sha256",
            _nonzero_hash("receipt_sha256", self.receipt_sha256),
        )
        if self.schema_version != CHECKPOINT_ACK_SCHEMA:
            raise ValueError("monitor checkpoint acknowledgement schema drift")


@dataclass(frozen=True)
class MonitorIncidentAcknowledgement(CanonicalContract):
    incident_id: str
    assessment_sha256: str
    provider_id: str
    acknowledged_at_utc: datetime
    receipt_sha256: str
    schema_version: str = INCIDENT_ACK_SCHEMA

    def __post_init__(self) -> None:
        incident_id = require_text("incident_id", self.incident_id)
        if not incident_id.startswith("monitor_incident_"):
            raise ValueError("monitor incident acknowledgement ID invalid")
        object.__setattr__(self, "incident_id", incident_id)
        object.__setattr__(
            self,
            "assessment_sha256",
            _nonzero_hash(
                "assessment_sha256",
                self.assessment_sha256,
            ),
        )
        object.__setattr__(
            self,
            "provider_id",
            _provider_id("provider_id", self.provider_id),
        )
        require_utc("acknowledged_at_utc", self.acknowledged_at_utc)
        object.__setattr__(
            self,
            "receipt_sha256",
            _nonzero_hash("receipt_sha256", self.receipt_sha256),
        )
        if self.schema_version != INCIDENT_ACK_SCHEMA:
            raise ValueError("monitor incident acknowledgement schema drift")


def _age_seconds(now: datetime, value: datetime) -> float:
    return (now - value).total_seconds()


def _assess_service(
    *,
    role: str,
    observation: MonitoredServiceObservation,
    config: ExternalMonitorConfig,
    evaluated_at_utc: datetime,
) -> set[str]:
    prefix = role.upper()
    reasons: set[str] = set()
    expected = {
        "service_id": getattr(config, f"{role.lower()}_service_id"),
        "service_account_id": getattr(
            config,
            f"{role.lower()}_service_account_id",
        ),
        "release_identity_sha256": getattr(
            config,
            f"{role.lower()}_release_identity_sha256",
        ),
        "task_definition_sha256": getattr(
            config,
            f"{role.lower()}_task_definition_sha256",
        ),
    }
    if observation.role != prefix:
        reasons.add(f"{prefix}_ROLE_MISMATCH")
    if observation.service_id != expected["service_id"]:
        reasons.add(f"{prefix}_SERVICE_ID_MISMATCH")
    if observation.service_account_id != expected["service_account_id"]:
        reasons.add(f"{prefix}_SERVICE_ACCOUNT_MISMATCH")
    if (
        observation.release_identity_sha256
        != expected["release_identity_sha256"]
    ):
        reasons.add(f"{prefix}_RELEASE_IDENTITY_MISMATCH")
    if (
        observation.task_definition_sha256
        != expected["task_definition_sha256"]
    ):
        reasons.add(f"{prefix}_TASK_DEFINITION_MISMATCH")
    if observation.task_state != "RUNNING":
        reasons.add(f"{prefix}_TASK_NOT_RUNNING")
    if observation.process_alive is not True:
        reasons.add(f"{prefix}_PROCESS_NOT_RUNNING")
    if observation.phase != "RUNNING":
        reasons.add(f"{prefix}_PHASE_NOT_RUNNING")
    if observation.status_signature_verified is not True:
        reasons.add(f"{prefix}_STATUS_SIGNATURE_INVALID")
    if observation.status_chain_verified is not True:
        reasons.add(f"{prefix}_STATUS_CHAIN_INVALID")
    threshold = config.thresholds.max_service_status_age_seconds
    clock_tolerance = config.thresholds.max_clock_drift_seconds
    age = _age_seconds(evaluated_at_utc, observation.status_occurred_at_utc)
    if age < -clock_tolerance:
        reasons.add(f"{prefix}_STATUS_CLOCK_AHEAD")
    if (
        age > threshold
        or observation.status_valid_until_utc < evaluated_at_utc
    ):
        reasons.add(f"{prefix}_STATUS_STALE")
    if role == "EXECUTION" and observation.restart_reconciled is not True:
        reasons.add("EXECUTION_RESTART_NOT_RECONCILED")
    reasons.update(
        f"{prefix}_{reason}" for reason in observation.reason_codes
    )
    return reasons


def evaluate_external_status_snapshot(
    config: ExternalMonitorConfig,
    snapshot: ExternalStatusSnapshot,
    *,
    evaluated_at_utc: datetime,
) -> ExternalStatusAssessment:
    """Evaluate one exact snapshot without producing any side effect."""

    if type(config) is not ExternalMonitorConfig:
        raise TypeError("config must be exact ExternalMonitorConfig")
    if type(snapshot) is not ExternalStatusSnapshot:
        raise ExternalStatusMonitorError("MONITOR_SNAPSHOT_TYPE_INVALID")
    now = require_utc("evaluated_at_utc", evaluated_at_utc)
    reasons: set[str] = set()
    if snapshot.monitor_provider_id != config.monitor_provider_id:
        reasons.add("MONITOR_PROVIDER_ID_MISMATCH")
    if snapshot.source_attestation_verified is not True:
        reasons.add("SNAPSHOT_SOURCE_ATTESTATION_INVALID")
    snapshot_age = _age_seconds(now, snapshot.captured_at_utc)
    if snapshot_age < -config.thresholds.max_clock_drift_seconds:
        reasons.add("SNAPSHOT_CLOCK_AHEAD")
    if snapshot_age > config.thresholds.max_snapshot_age_seconds:
        reasons.add("SNAPSHOT_STALE")

    reasons.update(
        _assess_service(
            role="DECISION",
            observation=snapshot.decision,
            config=config,
            evaluated_at_utc=now,
        )
    )
    reasons.update(
        _assess_service(
            role="EXECUTION",
            observation=snapshot.execution,
            config=config,
            evaluated_at_utc=now,
        )
    )

    host = snapshot.host
    host_age = _age_seconds(now, host.observed_at_utc)
    if host_age < -config.thresholds.max_clock_drift_seconds:
        reasons.add("HOST_OBSERVATION_CLOCK_AHEAD")
    if host_age > config.thresholds.max_snapshot_age_seconds:
        reasons.add("HOST_OBSERVATION_STALE")
    if (
        abs(host.clock_drift_seconds)
        > config.thresholds.max_clock_drift_seconds
    ):
        reasons.add("CLOCK_DRIFT_LIMIT_EXCEEDED")
    if host.free_disk_gib < config.thresholds.minimum_free_disk_gib:
        reasons.add("DISK_SPACE_LIMIT_BREACHED")
    if host.mt5_connected is not True:
        reasons.add("MT5_DISCONNECTED")
    if host.news_status_fresh is not True:
        reasons.add("NEWS_STATUS_STALE")
    if host.decision_ipc_continuity_verified is not True:
        reasons.add("DECISION_IPC_CONTINUITY_INVALID")
    audit_age = _age_seconds(now, host.audit_exported_at_utc)
    if (
        audit_age < -config.thresholds.max_clock_drift_seconds
        or audit_age > config.thresholds.max_audit_export_age_seconds
    ):
        reasons.add("AUDIT_EXPORT_STALE")
    backup_age = _age_seconds(now, host.backup_anchored_at_utc)
    if (
        backup_age < -config.thresholds.max_clock_drift_seconds
        or backup_age > config.thresholds.max_backup_anchor_age_seconds
    ):
        reasons.add("BACKUP_ANCHOR_STALE")
    if host.offhost_delivery_healthy is not True:
        reasons.add("OFFHOST_DELIVERY_UNHEALTHY")
    reasons.update(host.critical_reason_codes)

    ordered_reasons = tuple(sorted(reasons))
    critical = bool(ordered_reasons)
    incident_id = None
    if critical:
        incident_material = (
            config.monitor_service_id
            + snapshot.content_sha256
            + "|".join(ordered_reasons)
        ).encode("utf-8")
        incident_id = (
            "monitor_incident_"
            + hashlib.sha256(incident_material).hexdigest()[:32]
        )
    return ExternalStatusAssessment(
        monitor_service_id=config.monitor_service_id,
        snapshot_sha256=snapshot.content_sha256,
        evaluated_at_utc=now,
        status="CRITICAL" if critical else "HEALTHY",
        reason_codes=ordered_reasons,
        incident_required=critical,
        incident_id=incident_id,
        _seal=_ASSESSMENT_SEAL,
    )


@dataclass(frozen=True)
class StatusMonitorDependencies:
    snapshot_provider: Callable[[MonitorCheckpoint], ExternalStatusSnapshot]
    checkpoint_provider: Callable[[], MonitorCheckpoint]
    checkpoint_verifier: Callable[[MonitorCheckpoint], bool]
    checkpoint_compare_and_swap: Callable[
        [MonitorCheckpoint, MonitorCheckpoint],
        MonitorCheckpointAcknowledgement,
    ]
    checkpoint_acknowledgement_verifier: Callable[
        [MonitorCheckpointAcknowledgement],
        bool,
    ]
    incident_latch: Callable[
        [ExternalStatusAssessment],
        MonitorIncidentAcknowledgement,
    ]
    incident_acknowledgement_verifier: Callable[
        [MonitorIncidentAcknowledgement],
        bool,
    ]
    heartbeat_outbox: DeliveryOutbox
    heartbeat_transport: object
    alert_outbox: DeliveryOutbox
    alert_transport: object
    heartbeat_sender_key_id: str
    alert_sender_key_id: str
    sender_key_provider: Callable[[str], str | bytes]
    heartbeat_sender_key_fingerprint_sha256: str
    alert_sender_key_fingerprint_sha256: str
    remote_ack_key_id: str
    remote_ack_key_provider: Callable[[str], str | bytes]
    remote_ack_key_fingerprint_sha256: str
    clock_provider: Callable[[], datetime]

    def __post_init__(self) -> None:
        callables = (
            "snapshot_provider",
            "checkpoint_provider",
            "checkpoint_verifier",
            "checkpoint_compare_and_swap",
            "checkpoint_acknowledgement_verifier",
            "incident_latch",
            "incident_acknowledgement_verifier",
            "sender_key_provider",
            "remote_ack_key_provider",
            "clock_provider",
        )
        for name in callables:
            if not callable(getattr(self, name)):
                raise TypeError(f"{name} must be callable")
        for name in ("heartbeat_outbox", "alert_outbox"):
            if type(getattr(self, name)) is not DeliveryOutbox:
                raise TypeError(f"{name} must be exact DeliveryOutbox")
        if self.heartbeat_outbox.path == self.alert_outbox.path:
            raise ValueError("monitor heartbeat and alert outboxes must be distinct")
        for name in ("heartbeat_transport", "alert_transport"):
            if not callable(getattr(getattr(self, name), "deliver", None)):
                raise TypeError(f"{name} must expose deliver")
        for name in (
            "heartbeat_sender_key_id",
            "alert_sender_key_id",
            "remote_ack_key_id",
        ):
            object.__setattr__(
                self,
                name,
                _provider_id(name, getattr(self, name)),
            )
        if (
            self.heartbeat_sender_key_id.casefold()
            == self.alert_sender_key_id.casefold()
        ):
            raise ValueError("heartbeat and alert sender key IDs must be distinct")
        for name in (
            "heartbeat_sender_key_fingerprint_sha256",
            "alert_sender_key_fingerprint_sha256",
            "remote_ack_key_fingerprint_sha256",
        ):
            object.__setattr__(
                self,
                name,
                _nonzero_hash(name, getattr(self, name)),
            )


class WindowsExternalStatusMonitor:
    """Run bounded status-only monitor cycles with durable external progress."""

    def __init__(
        self,
        config: ExternalMonitorConfig,
        dependencies: StatusMonitorDependencies,
    ) -> None:
        if type(config) is not ExternalMonitorConfig:
            raise TypeError("config must be exact ExternalMonitorConfig")
        if type(dependencies) is not StatusMonitorDependencies:
            raise TypeError(
                "dependencies must be exact StatusMonitorDependencies"
            )
        self.config = config
        self.dependencies = dependencies
        self._stop_event = threading.Event()

    def request_stop(self) -> None:
        self._stop_event.set()

    def stop_requested(self) -> bool:
        return self._stop_event.is_set()

    def _trusted_now(self) -> datetime:
        return require_utc(
            "external monitor trusted clock",
            self.dependencies.clock_provider(),
        )

    def _checkpoint(self, now: datetime) -> MonitorCheckpoint:
        checkpoint = self.dependencies.checkpoint_provider()
        if type(checkpoint) is not MonitorCheckpoint:
            raise ExternalStatusMonitorError(
                "MONITOR_CHECKPOINT_TYPE_INVALID"
            )
        if checkpoint.monitor_service_id != self.config.monitor_service_id:
            raise ExternalStatusMonitorError(
                "MONITOR_CHECKPOINT_SERVICE_ID_MISMATCH"
            )
        if self.dependencies.checkpoint_verifier(checkpoint) is not True:
            raise ExternalStatusMonitorError("MONITOR_CHECKPOINT_INVALID")
        if (
            checkpoint.updated_at_utc
            > now
            + timedelta(
                seconds=self.config.thresholds.max_clock_drift_seconds
            )
        ):
            raise ExternalStatusMonitorError(
                "MONITOR_CHECKPOINT_CLOCK_AHEAD"
            )
        return checkpoint

    def _assert_snapshot_successor(
        self,
        checkpoint: MonitorCheckpoint,
        snapshot: object,
    ) -> ExternalStatusSnapshot:
        if type(snapshot) is not ExternalStatusSnapshot:
            raise ExternalStatusMonitorError("MONITOR_SNAPSHOT_TYPE_INVALID")
        if snapshot.sequence != checkpoint.sequence + 1:
            raise ExternalStatusMonitorError(
                "MONITOR_SNAPSHOT_SEQUENCE_INVALID"
            )
        if snapshot.previous_snapshot_sha256 != checkpoint.snapshot_sha256:
            raise ExternalStatusMonitorError(
                "MONITOR_SNAPSHOT_PREDECESSOR_INVALID"
            )
        return snapshot

    def _sender_key(
        self,
        *,
        sender_key_id: str,
        expected_fingerprint_sha256: str,
    ) -> str | bytes:
        sender = self.dependencies.sender_key_provider(sender_key_id)
        if (
            _key_fingerprint(sender)
            != expected_fingerprint_sha256
        ):
            raise ExternalStatusMonitorError(
                "MONITOR_SENDER_KEY_FINGERPRINT_MISMATCH"
            )
        return sender

    def _remote_key(self) -> str | bytes:
        remote = self.dependencies.remote_ack_key_provider(
            self.dependencies.remote_ack_key_id
        )
        if (
            _key_fingerprint(remote)
            != self.dependencies.remote_ack_key_fingerprint_sha256
        ):
            raise ExternalStatusMonitorError(
                "MONITOR_REMOTE_ACK_KEY_FINGERPRINT_MISMATCH"
            )
        return remote

    def _deliver(
        self,
        *,
        artifact_type: str,
        assessment: ExternalStatusAssessment,
        now: datetime,
    ) -> None:
        if artifact_type == "HEARTBEAT":
            outbox = self.dependencies.heartbeat_outbox
            transport = self.dependencies.heartbeat_transport
            destination = self.config.heartbeat_destination_id
            sender_key_id = self.dependencies.heartbeat_sender_key_id
            sender_key_fingerprint = (
                self.dependencies.heartbeat_sender_key_fingerprint_sha256
            )
        elif artifact_type == "ALERT":
            outbox = self.dependencies.alert_outbox
            transport = self.dependencies.alert_transport
            destination = self.config.alert_destination_id
            sender_key_id = self.dependencies.alert_sender_key_id
            sender_key_fingerprint = (
                self.dependencies.alert_sender_key_fingerprint_sha256
            )
        else:
            raise ExternalStatusMonitorError(
                "MONITOR_ARTIFACT_TYPE_INVALID"
            )
        sender_key = self._sender_key(
            sender_key_id=sender_key_id,
            expected_fingerprint_sha256=sender_key_fingerprint,
        )
        self._remote_key()
        supervisor = OffHostDeliverySupervisor(
            outbox=outbox,
            remote_key_provider=(
                self.dependencies.remote_ack_key_provider
            ),
            clock_provider=self.dependencies.clock_provider,
        )
        prior = supervisor.deliver_pending(transport, attempted_at=now)
        if prior.failed or prior.pending_after:
            raise ExternalStatusMonitorError(
                f"MONITOR_{artifact_type}_PREDECESSOR_UNRESOLVED"
            )
        suffix = (
            assessment.incident_id
            if artifact_type == "ALERT"
            else assessment.snapshot_sha256
        )
        envelope = DeliveryEnvelope.create(
            idempotency_key=(
                f"{self.config.monitor_service_id}:"
                f"{artifact_type.lower()}:{suffix}"
            ),
            destination_id=destination,
            artifact_type=artifact_type,
            payload=assessment.to_canonical_dict(),
            created_at_utc=now,
            sender_key_id=sender_key_id,
            secret=sender_key,
        )
        outbox.enqueue(envelope)
        report = supervisor.deliver_pending(transport, attempted_at=now)
        record = outbox.get(envelope.envelope_id)
        acknowledgement = record.get("acknowledgement")
        if (
            envelope.envelope_id not in report.acknowledged
            or report.failed
            or report.pending_after
            or record.get("state") != "ACKNOWLEDGED"
            or not isinstance(acknowledgement, dict)
        ):
            raise ExternalStatusMonitorError(
                f"MONITOR_{artifact_type}_NOT_ACKNOWLEDGED"
            )
        ack = DeliveryAcknowledgement.from_dict(acknowledgement)
        if (
            ack.remote_key_id != self.dependencies.remote_ack_key_id
            or _key_fingerprint(
                self.dependencies.remote_ack_key_provider(
                    ack.remote_key_id
                )
            )
            != self.dependencies.remote_ack_key_fingerprint_sha256
        ):
            raise ExternalStatusMonitorError(
                f"MONITOR_{artifact_type}_REMOTE_TRUST_MISMATCH"
            )

    def _latch_incident(
        self,
        assessment: ExternalStatusAssessment,
        now: datetime,
    ) -> None:
        acknowledgement = self.dependencies.incident_latch(assessment)
        if type(acknowledgement) is not MonitorIncidentAcknowledgement:
            raise ExternalStatusMonitorError(
                "MONITOR_INCIDENT_ACKNOWLEDGEMENT_TYPE_INVALID"
            )
        if (
            acknowledgement.incident_id != assessment.incident_id
            or acknowledgement.assessment_sha256
            != assessment.content_sha256
            or acknowledgement.provider_id
            != self.config.incident_latch_provider_id
            or acknowledgement.acknowledged_at_utc
            < assessment.evaluated_at_utc
            or acknowledgement.acknowledged_at_utc
            > now
            + timedelta(
                seconds=self.config.thresholds.max_clock_drift_seconds
            )
            or self.dependencies.incident_acknowledgement_verifier(
                acknowledgement
            )
            is not True
        ):
            raise ExternalStatusMonitorError(
                "MONITOR_INCIDENT_ACKNOWLEDGEMENT_INVALID"
            )

    def _advance_checkpoint(
        self,
        *,
        checkpoint: MonitorCheckpoint,
        snapshot: ExternalStatusSnapshot,
        now: datetime,
    ) -> None:
        updated = MonitorCheckpoint(
            monitor_service_id=self.config.monitor_service_id,
            sequence=snapshot.sequence,
            snapshot_sha256=snapshot.content_sha256,
            updated_at_utc=now,
        )
        acknowledgement = (
            self.dependencies.checkpoint_compare_and_swap(
                checkpoint,
                updated,
            )
        )
        if type(acknowledgement) is not MonitorCheckpointAcknowledgement:
            raise ExternalStatusMonitorError(
                "MONITOR_CHECKPOINT_ACKNOWLEDGEMENT_TYPE_INVALID"
            )
        if (
            acknowledgement.monitor_service_id
            != self.config.monitor_service_id
            or acknowledgement.expected_sequence != checkpoint.sequence
            or acknowledgement.committed_sequence != updated.sequence
            or acknowledgement.committed_snapshot_sha256
            != updated.snapshot_sha256
            or acknowledgement.provider_id
            != self.config.snapshot_checkpoint_provider_id
            or acknowledgement.acknowledged_at_utc < now
            or acknowledgement.acknowledged_at_utc
            > now
            + timedelta(
                seconds=self.config.thresholds.max_clock_drift_seconds
            )
            or self.dependencies.checkpoint_acknowledgement_verifier(
                acknowledgement
            )
            is not True
        ):
            raise ExternalStatusMonitorError(
                "MONITOR_CHECKPOINT_ACKNOWLEDGEMENT_INVALID"
            )

    def _run_cycle(self) -> ExternalStatusAssessment:
        now = self._trusted_now()
        checkpoint = self._checkpoint(now)
        snapshot = self._assert_snapshot_successor(
            checkpoint,
            self.dependencies.snapshot_provider(checkpoint),
        )
        assessment = evaluate_external_status_snapshot(
            self.config,
            snapshot,
            evaluated_at_utc=now,
        )
        if assessment.incident_required:
            self._latch_incident(assessment, now)
            self._deliver(
                artifact_type="ALERT",
                assessment=assessment,
                now=now,
            )
        self._deliver(
            artifact_type="HEARTBEAT",
            assessment=assessment,
            now=now,
        )
        self._advance_checkpoint(
            checkpoint=checkpoint,
            snapshot=snapshot,
            now=now,
        )
        return assessment

    def _run_cycle_with_deadline(self) -> ExternalStatusAssessment:
        result_queue: queue.Queue[tuple[str, object]] = queue.Queue(maxsize=1)

        def worker() -> None:
            try:
                result_queue.put_nowait(("RESULT", self._run_cycle()))
            except BaseException as exc:
                try:
                    result_queue.put_nowait(("ERROR", exc))
                except queue.Full:
                    pass

        thread = threading.Thread(
            target=worker,
            name=f"{self.config.monitor_service_id}-status-cycle",
            daemon=True,
        )
        thread.start()
        try:
            kind, value = result_queue.get(
                timeout=self.config.cycle_deadline_seconds
            )
        except queue.Empty:
            _hard_terminate_process(MONITOR_DEADLINE_EXIT_CODE)
            raise ExternalStatusMonitorError(
                "MONITOR_HARD_TERMINATION_RETURNED"
            )
        if kind == "ERROR":
            if isinstance(value, BaseException):
                raise value
            raise ExternalStatusMonitorError(
                "MONITOR_CYCLE_ERROR_INVALID"
            )
        thread.join(timeout=0.1)
        if (
            kind != "RESULT"
            or thread.is_alive()
            or type(value) is not ExternalStatusAssessment
        ):
            _hard_terminate_process(MONITOR_DEADLINE_EXIT_CODE)
            raise ExternalStatusMonitorError(
                "MONITOR_HARD_TERMINATION_RETURNED"
            )
        return value

    def run(self) -> tuple[ExternalStatusAssessment, ...]:
        assessments: list[ExternalStatusAssessment] = []
        while (
            len(assessments) < self.config.max_cycles
            and not self.stop_requested()
        ):
            assessments.append(self._run_cycle_with_deadline())
            if (
                len(assessments) < self.config.max_cycles
                and not self.stop_requested()
                and self.config.poll_seconds
            ):
                self._stop_event.wait(self.config.poll_seconds)
        return tuple(assessments)


def _hard_terminate_process(exit_code: int) -> None:
    os._exit(exit_code)


def install_monitor_signal_handlers(
    monitor: WindowsExternalStatusMonitor,
) -> None:
    """Install stop-only signal handlers on the process main thread."""

    if type(monitor) is not WindowsExternalStatusMonitor:
        raise TypeError(
            "monitor must be exact WindowsExternalStatusMonitor"
        )
    if threading.current_thread() is not threading.main_thread():
        raise ExternalStatusMonitorError(
            "MONITOR_SIGNAL_INSTALL_REQUIRES_MAIN_THREAD"
        )

    def request_stop(_signum: int, _frame: object) -> None:
        monitor.request_stop()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)


__all__ = [
    "ASSESSMENT_SCHEMA",
    "CHECKPOINT_ACK_SCHEMA",
    "CHECKPOINT_SCHEMA",
    "CONFIG_SCHEMA",
    "ExternalMonitorConfig",
    "ExternalMonitorThresholds",
    "ExternalStatusAssessment",
    "ExternalStatusMonitorError",
    "ExternalStatusSnapshot",
    "HOST_OBSERVATION_SCHEMA",
    "INCIDENT_ACK_SCHEMA",
    "MAX_LOT",
    "MONITOR_DEADLINE_EXIT_CODE",
    "MonitorCheckpoint",
    "MonitorCheckpointAcknowledgement",
    "MonitorHostObservation",
    "MonitorIncidentAcknowledgement",
    "MonitoredServiceObservation",
    "ORDER_CAPABILITY",
    "PROMOTION_ELIGIBLE",
    "RELEASE_PROFILE",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "SERVICE_OBSERVATION_SCHEMA",
    "SNAPSHOT_SCHEMA",
    "StatusMonitorDependencies",
    "THRESHOLDS_SCHEMA",
    "WindowsExternalStatusMonitor",
    "evaluate_external_status_snapshot",
    "install_monitor_signal_handlers",
]
