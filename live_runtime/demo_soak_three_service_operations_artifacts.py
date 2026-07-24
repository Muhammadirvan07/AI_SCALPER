"""Immutable review artifacts for the exact three-service Windows topology.

This boundary accepts non-secret metadata, reconstructs the typed decision,
execution, and status-monitor operations plan, and renders validation-only
review material.  It has no credential backend, provider loader, scheduler
mutation, process launcher, network, MT5, or broker surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping

from .contracts import canonical_sha256, require_hash, require_text, require_utc
from .demo_soak_dual_release_operations import DecisionExecutionIPCBinding
from .demo_soak_operations import (
    CleanReleaseBinding,
    CredentialManagerReference,
    MT5AccountBinding,
    OffHostProviderReferences,
    OperationsThresholds,
    PythonRuntimeBinding,
    REQUIRED_DRILLS,
    RuntimeStoragePaths,
    assert_no_embedded_secrets,
)
from .demo_soak_three_service_operations import (
    ConfiguredServiceRoleBinding,
    MonitorOperationsBinding,
    ThreeServiceOperationsError,
    ThreeServiceSecurityPosture,
    WindowsThreeServiceDemoSoakOperationsPlan,
    assess_three_service_operations_readiness,
)


INPUT_SCHEMA_VERSION = "windows-three-service-demo-soak-operations-input-v3"
BUNDLE_SCHEMA_VERSION = (
    "windows-three-service-demo-soak-operations-review-bundle-v3"
)
FAILURE_DRILL_MANIFEST_SCHEMA_VERSION = (
    "windows-three-service-failure-drill-manifest-v3"
)
PLAN_SCHEMA_VERSION = "windows-demo-soak-three-service-operations-v3"
MAXIMUM_INPUT_BYTES = 1_048_576

_INPUT_FIELDS = frozenset(
    {
        "schema_version",
        "decision",
        "execution",
        "status_monitor",
        "broker",
        "credentials",
        "providers",
        "thresholds",
        "storage",
        "security",
        "ipc",
        "monitor",
    }
)
_ROLE_FIELDS = frozenset(
    {
        "role",
        "base_release_profile",
        "base_release_identity_sha256",
        "configured_release_identity_sha256",
        "service_id",
        "service_account_id",
        "validation_task_name",
        "release",
        "python",
        "runner_entrypoint_relative_path",
        "runner_entrypoint_sha256",
        "validator_entrypoint_relative_path",
        "validator_entrypoint_sha256",
        "factory_contract_sha256",
        "factory_manifest_sha256",
        "runtime_configuration_sha256",
        "task_definition_sha256",
        "launcher_trust_policy_sha256",
        "broker_sdk_present",
        "gated_execution_boundary_present",
        "status_only",
        "order_capability",
        "factory_materialization_enabled",
        "task_installed",
        "launcher_attestation_issued",
    }
)
_RELEASE_FIELDS = frozenset(
    {
        "source_repository_root",
        "release_root",
        "git_commit",
        "git_tree",
        "archive_sha256",
        "manifest_sha256",
        "configuration_sha256",
        "reproducibility_receipt_sha256",
        "clean_checkout",
        "tracked_build",
        "tracked_file_hashes",
    }
)
_PYTHON_FIELDS = frozenset(
    {
        "executable_path",
        "executable_sha256",
        "version",
        "architecture",
        "dependency_lock_sha256",
        "sbom_sha256",
    }
)
_BROKER_FIELDS = frozenset(
    {
        "candidate_id",
        "terminal_path",
        "terminal_sha256",
        "terminal_build",
        "company",
        "server",
        "environment",
        "account_alias_sha256",
        "account_currency",
        "symbol_bindings",
    }
)
_CREDENTIAL_FIELDS = frozenset({"purpose", "target_name", "key_id", "backend"})
_PROVIDER_FIELDS = frozenset(
    {
        "heartbeat_destination_id",
        "audit_destination_id",
        "backup_destination_id",
        "alert_destination_id",
        "remote_receipt_key_provider_id",
    }
)
_THRESHOLD_FIELDS = frozenset(
    {
        "max_clock_drift_seconds",
        "minimum_free_disk_gib",
        "max_heartbeat_age_seconds",
        "max_audit_export_age_seconds",
        "max_backup_anchor_age_seconds",
        "watchdog_interval_seconds",
    }
)
_STORAGE_FIELDS = frozenset(
    {
        "journal_database",
        "risk_database",
        "supervisor_database",
        "manual_demo_database",
        "soak_database",
        "log_directory",
        "immutable_audit_export_directory",
    }
)
_SECURITY_FIELDS = frozenset(
    {
        "decision_service_account_id",
        "execution_service_account_id",
        "monitor_service_account_id",
        "rdp_ingress_scope",
        "vpn_required",
        "mfa_required",
        "least_privilege",
        "public_rdp_exposed",
        "firewall_policy_sha256",
        "event_log_source",
    }
)
_IPC_FIELDS = frozenset(
    {
        "database_path",
        "binding_schema_version",
        "binding_sha256",
        "publisher_service_id",
        "consumer_service_id",
        "acl_policy_sha256",
        "checkpoint_cas_provider_id",
        "producer_cursor_cas_provider_id",
        "ack_verifier_provider_id",
        "signing_key_custody_provider_id",
        "external_custody_required",
    }
)
_MONITOR_FIELDS = frozenset(
    {
        "decision_configured_release_identity_sha256",
        "execution_configured_release_identity_sha256",
        "monitor_configured_release_identity_sha256",
        "decision_ipc_binding_sha256",
        "status_snapshot_provider_id",
        "trusted_clock_provider_id",
        "checkpoint_cas_provider_id",
        "checkpoint_ack_verifier_provider_id",
        "incident_latch_provider_id",
        "incident_ack_verifier_provider_id",
        "sender_key_custody_provider_id",
        "remote_ack_key_custody_provider_id",
        "heartbeat_outbox_provider_id",
        "heartbeat_transport_provider_id",
        "alert_outbox_provider_id",
        "alert_transport_provider_id",
        "heartbeat_destination_id",
        "alert_destination_id",
        "status_only",
        "configured_release_accepted",
        "offhost_delivery_accepted",
        "task_installed",
    }
)
_CANONICAL_PLAN_FIELDS = frozenset(
    {
        "broker",
        "credentials",
        "decision",
        "execution",
        "execution_enabled",
        "ipc",
        "live_allowed",
        "max_lot",
        "monitor",
        "order_capability",
        "promotion_eligible",
        "providers",
        "safe_to_demo_auto_order",
        "schema_version",
        "security",
        "status_monitor",
        "storage",
        "task_install_allowed",
        "thresholds",
        "validation_tasks_only",
    }
)
_BUNDLE_FIELDS = frozenset(
    {
        "schema_version",
        "issued_at_utc",
        "plan",
        "plan_sha256",
        "failure_drill_manifest",
        "failure_drill_manifest_sha256",
        "scheduler_reviews",
        "readiness",
        "effects",
        "safety",
        "content_sha256",
    }
)
_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "plan_sha256",
        "decision_release_identity_sha256",
        "execution_release_identity_sha256",
        "status_monitor_release_identity_sha256",
        "decision_release_manifest_sha256",
        "execution_release_manifest_sha256",
        "status_monitor_release_manifest_sha256",
        "git_commit",
        "git_tree",
        "candidate_id",
        "server",
        "account_alias_sha256",
        "issued_at_utc",
        "required_drills",
    }
)
_SCHEDULER_REVIEW_FIELDS = frozenset(
    {
        "task_name",
        "task_xml",
        "task_xml_sha256",
        "validation_powershell",
        "validation_powershell_sha256",
    }
)
_READINESS_FIELDS = frozenset(
    {
        "plan_sha256",
        "local_three_service_plan_valid",
        "validation_tasks_only",
        "status",
        "external_blockers",
        "task_install_allowed",
        "execution_enabled",
        "safe_to_demo_auto_order",
        "live_allowed",
        "promotion_eligible",
        "order_capability",
        "max_lot",
    }
)
_EFFECT_FIELDS = frozenset(
    {
        "credential_access_performed",
        "task_install_performed",
        "process_launch_performed",
        "network_access_performed",
        "provider_materialization_performed",
        "mt5_initialization_performed",
        "broker_mutation_performed",
    }
)
_SAFETY_FIELDS = frozenset(
    {
        "execution_enabled",
        "task_install_allowed",
        "validation_tasks_only",
        "safe_to_demo_auto_order",
        "live_allowed",
        "promotion_eligible",
        "order_capability",
        "max_lot",
    }
)


class ThreeServiceOperationsArtifactError(RuntimeError):
    """A strict input or immutable review bundle failed closed."""


def _mapping(
    value: object,
    *,
    fields: frozenset[str],
    label: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ThreeServiceOperationsArtifactError(
            f"{label.upper()}_FIELDS_DRIFT"
        )
    return value


def _list(value: object, *, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ThreeServiceOperationsArtifactError(
            f"{label.upper()}_LIST_REQUIRED"
        )
    return value


def _rows(
    value: object,
    *,
    width: int,
    label: str,
) -> tuple[tuple[Any, ...], ...]:
    result: list[tuple[Any, ...]] = []
    for row in _list(value, label=label):
        if not isinstance(row, (list, tuple)) or len(row) != width:
            raise ThreeServiceOperationsArtifactError(
                f"{label.upper()}_ROW_INVALID"
            )
        result.append(tuple(row))
    return tuple(result)


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ThreeServiceOperationsArtifactError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def _read_json_object(path: str | Path) -> Mapping[str, Any]:
    source = Path(path)
    try:
        before = source.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or int(getattr(before, "st_file_attributes", 0)) & 0x400
            or before.st_size <= 0
            or before.st_size > MAXIMUM_INPUT_BYTES
        ):
            raise ThreeServiceOperationsArtifactError(
                "THREE_SERVICE_OPERATIONS_INPUT_FILE_INVALID"
            )
        with source.open("rb") as handle:
            opened_before = os.fstat(handle.fileno())
            payload = handle.read(MAXIMUM_INPUT_BYTES + 1)
            opened_after = os.fstat(handle.fileno())
        after = source.lstat()
    except ThreeServiceOperationsArtifactError:
        raise
    except OSError as exc:
        raise ThreeServiceOperationsArtifactError(
            "THREE_SERVICE_OPERATIONS_INPUT_FILE_UNAVAILABLE"
        ) from exc
    expected = _file_identity(before)
    if (
        _file_identity(opened_before) != expected
        or _file_identity(opened_after) != expected
        or _file_identity(after) != expected
        or len(payload) != before.st_size
        or len(payload) > MAXIMUM_INPUT_BYTES
    ):
        raise ThreeServiceOperationsArtifactError(
            "THREE_SERVICE_OPERATIONS_INPUT_CHANGED_DURING_READ"
        )
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ThreeServiceOperationsArtifactError(
                    f"NONFINITE_JSON_NUMBER_{value}"
                )
            ),
        )
    except ThreeServiceOperationsArtifactError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ThreeServiceOperationsArtifactError(
            "THREE_SERVICE_OPERATIONS_INPUT_JSON_INVALID"
        ) from exc
    if not isinstance(document, Mapping):
        raise ThreeServiceOperationsArtifactError(
            "THREE_SERVICE_OPERATIONS_INPUT_OBJECT_REQUIRED"
        )
    return document


def _release(value: object, *, label: str) -> CleanReleaseBinding:
    raw = _mapping(value, fields=_RELEASE_FIELDS, label=label)
    values = dict(raw)
    values["tracked_file_hashes"] = _rows(
        raw["tracked_file_hashes"],
        width=2,
        label=f"{label}_tracked_file_hashes",
    )
    return CleanReleaseBinding(**values)


def _python(value: object, *, label: str) -> PythonRuntimeBinding:
    return PythonRuntimeBinding(
        **dict(_mapping(value, fields=_PYTHON_FIELDS, label=label))
    )


def _role(
    value: object,
    *,
    label: str,
) -> ConfiguredServiceRoleBinding:
    raw = _mapping(value, fields=_ROLE_FIELDS, label=label)
    values = dict(raw)
    values["release"] = _release(raw["release"], label=f"{label}_release")
    values["python"] = _python(raw["python"], label=f"{label}_python")
    return ConfiguredServiceRoleBinding(**values)


def _plan_from_mapping(
    document: Mapping[str, Any],
) -> WindowsThreeServiceDemoSoakOperationsPlan:
    root = _mapping(
        document,
        fields=_INPUT_FIELDS,
        label="three_service_operations_input",
    )
    if root.get("schema_version") != INPUT_SCHEMA_VERSION:
        raise ThreeServiceOperationsArtifactError(
            "THREE_SERVICE_OPERATIONS_INPUT_SCHEMA_MISMATCH"
        )
    assert_no_embedded_secrets(root)
    broker_raw = _mapping(
        root["broker"], fields=_BROKER_FIELDS, label="broker"
    )
    broker_values = dict(broker_raw)
    broker_values["symbol_bindings"] = _rows(
        broker_raw["symbol_bindings"],
        width=3,
        label="broker_symbol_bindings",
    )
    credentials = tuple(
        CredentialManagerReference(
            **dict(
                _mapping(
                    item,
                    fields=_CREDENTIAL_FIELDS,
                    label="credential_reference",
                )
            )
        )
        for item in _list(root["credentials"], label="credentials")
    )
    return WindowsThreeServiceDemoSoakOperationsPlan(
        decision=_role(root["decision"], label="decision"),
        execution=_role(root["execution"], label="execution"),
        status_monitor=_role(
            root["status_monitor"], label="status_monitor"
        ),
        broker=MT5AccountBinding(**broker_values),
        credentials=credentials,
        providers=OffHostProviderReferences(
            **dict(
                _mapping(
                    root["providers"],
                    fields=_PROVIDER_FIELDS,
                    label="providers",
                )
            )
        ),
        thresholds=OperationsThresholds(
            **dict(
                _mapping(
                    root["thresholds"],
                    fields=_THRESHOLD_FIELDS,
                    label="thresholds",
                )
            )
        ),
        storage=RuntimeStoragePaths(
            **dict(
                _mapping(
                    root["storage"],
                    fields=_STORAGE_FIELDS,
                    label="storage",
                )
            )
        ),
        security=ThreeServiceSecurityPosture(
            **dict(
                _mapping(
                    root["security"],
                    fields=_SECURITY_FIELDS,
                    label="security",
                )
            )
        ),
        ipc=DecisionExecutionIPCBinding(
            **dict(_mapping(root["ipc"], fields=_IPC_FIELDS, label="ipc"))
        ),
        monitor=MonitorOperationsBinding(
            **dict(
                _mapping(
                    root["monitor"],
                    fields=_MONITOR_FIELDS,
                    label="monitor",
                )
            )
        ),
    )


def load_windows_three_service_demo_soak_operations_plan(
    path: str | Path,
) -> WindowsThreeServiceDemoSoakOperationsPlan:
    """Read and reconstruct one exact non-secret v3 operations plan."""

    try:
        return _plan_from_mapping(_read_json_object(path))
    except (
        ThreeServiceOperationsArtifactError,
        ThreeServiceOperationsError,
        TypeError,
        ValueError,
    ) as exc:
        if type(exc) is ThreeServiceOperationsArtifactError:
            raise
        raise ThreeServiceOperationsArtifactError(
            f"THREE_SERVICE_OPERATIONS_INPUT_REJECTED:{exc}"
        ) from exc


def _utc_text(value: datetime) -> str:
    return require_utc("timestamp", value).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _utc_from_text(value: object, *, label: str) -> datetime:
    text = require_text(label, value)
    try:
        parsed = require_utc(
            label, datetime.fromisoformat(text.replace("Z", "+00:00"))
        )
    except (TypeError, ValueError) as exc:
        raise ThreeServiceOperationsArtifactError(
            f"{label.upper()}_INVALID"
        ) from exc
    if _utc_text(parsed) != text:
        raise ThreeServiceOperationsArtifactError(
            f"{label.upper()}_NOT_CANONICAL_UTC"
        )
    return parsed


@dataclass(frozen=True)
class ThreeServiceFailureDrillManifest:
    """Bind all three configured releases to one failure-drill review."""

    plan_sha256: str
    decision_release_identity_sha256: str
    execution_release_identity_sha256: str
    status_monitor_release_identity_sha256: str
    decision_release_manifest_sha256: str
    execution_release_manifest_sha256: str
    status_monitor_release_manifest_sha256: str
    git_commit: str
    git_tree: str
    candidate_id: str
    server: str
    account_alias_sha256: str
    issued_at_utc: datetime
    required_drills: tuple[str, ...] = REQUIRED_DRILLS
    schema_version: str = FAILURE_DRILL_MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "plan_sha256",
            "decision_release_identity_sha256",
            "execution_release_identity_sha256",
            "status_monitor_release_identity_sha256",
            "decision_release_manifest_sha256",
            "execution_release_manifest_sha256",
            "status_monitor_release_manifest_sha256",
            "account_alias_sha256",
        ):
            object.__setattr__(
                self, name, require_hash(name, getattr(self, name))
            )
        for name in ("git_commit", "git_tree"):
            value = require_text(name, getattr(self, name)).lower()
            if len(value) != 40 or any(
                character not in "0123456789abcdef" for character in value
            ):
                raise ThreeServiceOperationsArtifactError(
                    f"{name.upper()}_INVALID"
                )
            object.__setattr__(self, name, value)
        object.__setattr__(
            self,
            "candidate_id",
            require_text("candidate_id", self.candidate_id),
        )
        object.__setattr__(
            self, "server", require_text("server", self.server)
        )
        require_utc("issued_at_utc", self.issued_at_utc)
        drills = tuple(
            require_text("drill_id", item, upper=True)
            for item in self.required_drills
        )
        if drills != REQUIRED_DRILLS:
            raise ThreeServiceOperationsArtifactError(
                "REQUIRED_FAILURE_DRILLS_CHANGED"
            )
        object.__setattr__(self, "required_drills", drills)
        if self.schema_version != FAILURE_DRILL_MANIFEST_SCHEMA_VERSION:
            raise ThreeServiceOperationsArtifactError(
                "FAILURE_DRILL_MANIFEST_SCHEMA_MISMATCH"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "account_alias_sha256": self.account_alias_sha256,
            "candidate_id": self.candidate_id,
            "decision_release_identity_sha256": (
                self.decision_release_identity_sha256
            ),
            "decision_release_manifest_sha256": (
                self.decision_release_manifest_sha256
            ),
            "execution_release_identity_sha256": (
                self.execution_release_identity_sha256
            ),
            "execution_release_manifest_sha256": (
                self.execution_release_manifest_sha256
            ),
            "git_commit": self.git_commit,
            "git_tree": self.git_tree,
            "issued_at_utc": _utc_text(self.issued_at_utc),
            "plan_sha256": self.plan_sha256,
            "required_drills": list(self.required_drills),
            "schema_version": self.schema_version,
            "server": self.server,
            "status_monitor_release_identity_sha256": (
                self.status_monitor_release_identity_sha256
            ),
            "status_monitor_release_manifest_sha256": (
                self.status_monitor_release_manifest_sha256
            ),
        }

    @property
    def manifest_sha256(self) -> str:
        return canonical_sha256(self.to_dict())


def _manifest(
    plan: WindowsThreeServiceDemoSoakOperationsPlan,
    *,
    issued_at_utc: datetime,
) -> ThreeServiceFailureDrillManifest:
    return ThreeServiceFailureDrillManifest(
        plan_sha256=plan.plan_sha256,
        decision_release_identity_sha256=(
            plan.decision.configured_release_identity_sha256
        ),
        execution_release_identity_sha256=(
            plan.execution.configured_release_identity_sha256
        ),
        status_monitor_release_identity_sha256=(
            plan.status_monitor.configured_release_identity_sha256
        ),
        decision_release_manifest_sha256=(
            plan.decision.release.manifest_sha256
        ),
        execution_release_manifest_sha256=(
            plan.execution.release.manifest_sha256
        ),
        status_monitor_release_manifest_sha256=(
            plan.status_monitor.release.manifest_sha256
        ),
        git_commit=plan.decision.release.git_commit,
        git_tree=plan.decision.release.git_tree,
        candidate_id=plan.broker.candidate_id,
        server=plan.broker.server,
        account_alias_sha256=plan.broker.account_alias_sha256,
        issued_at_utc=issued_at_utc,
    )


def _scheduler_reviews(
    plan: WindowsThreeServiceDemoSoakOperationsPlan,
) -> list[dict[str, object]]:
    reviews: list[dict[str, object]] = []
    for task in plan.validation_scheduler_definitions():
        task_xml = task.render_xml()
        validation = task.render_validation_powershell()
        reviews.append(
            {
                "task_name": task.task_name,
                "task_xml": task_xml,
                "task_xml_sha256": canonical_sha256(task_xml),
                "validation_powershell": validation,
                "validation_powershell_sha256": canonical_sha256(validation),
            }
        )
    return reviews


def _readiness(
    plan: WindowsThreeServiceDemoSoakOperationsPlan,
) -> dict[str, object]:
    result = assess_three_service_operations_readiness(plan)
    return {
        "execution_enabled": result.execution_enabled,
        "external_blockers": list(result.external_blockers),
        "live_allowed": result.live_allowed,
        "local_three_service_plan_valid": (
            result.local_three_service_plan_valid
        ),
        "max_lot": result.max_lot,
        "order_capability": result.order_capability,
        "plan_sha256": result.plan_sha256,
        "promotion_eligible": result.promotion_eligible,
        "safe_to_demo_auto_order": result.safe_to_demo_auto_order,
        "status": result.status,
        "task_install_allowed": result.task_install_allowed,
        "validation_tasks_only": result.validation_tasks_only,
    }


def _effects() -> dict[str, bool]:
    return {
        "broker_mutation_performed": False,
        "credential_access_performed": False,
        "mt5_initialization_performed": False,
        "network_access_performed": False,
        "process_launch_performed": False,
        "provider_materialization_performed": False,
        "task_install_performed": False,
    }


def _safety() -> dict[str, object]:
    return {
        "execution_enabled": False,
        "live_allowed": False,
        "max_lot": 0.01,
        "order_capability": "DISABLED",
        "promotion_eligible": False,
        "safe_to_demo_auto_order": False,
        "task_install_allowed": False,
        "validation_tasks_only": True,
    }


def build_windows_three_service_demo_soak_review_bundle(
    plan: WindowsThreeServiceDemoSoakOperationsPlan,
    *,
    issued_at_utc: datetime,
) -> dict[str, object]:
    """Build and self-verify one deterministic v3 review bundle."""

    if type(plan) is not WindowsThreeServiceDemoSoakOperationsPlan:
        raise TypeError(
            "plan must be exact WindowsThreeServiceDemoSoakOperationsPlan"
        )
    issued = require_utc("issued_at_utc", issued_at_utc)
    manifest = _manifest(plan, issued_at_utc=issued)
    payload: dict[str, object] = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "issued_at_utc": _utc_text(issued),
        "plan": plan.to_dict(),
        "plan_sha256": plan.plan_sha256,
        "failure_drill_manifest": manifest.to_dict(),
        "failure_drill_manifest_sha256": manifest.manifest_sha256,
        "scheduler_reviews": _scheduler_reviews(plan),
        "readiness": _readiness(plan),
        "effects": _effects(),
        "safety": _safety(),
    }
    assert_no_embedded_secrets(payload)
    payload["content_sha256"] = canonical_sha256(payload)
    verify_windows_three_service_demo_soak_review_bundle(payload)
    return payload


def _canonical_plan_to_input(value: object) -> dict[str, object]:
    plan = _mapping(
        value,
        fields=_CANONICAL_PLAN_FIELDS,
        label="canonical_three_service_plan",
    )
    locks = {
        "execution_enabled": False,
        "live_allowed": False,
        "max_lot": 0.01,
        "order_capability": "DISABLED",
        "promotion_eligible": False,
        "safe_to_demo_auto_order": False,
        "task_install_allowed": False,
        "validation_tasks_only": True,
        "schema_version": PLAN_SCHEMA_VERSION,
    }
    if any(plan.get(name) != expected for name, expected in locks.items()):
        raise ThreeServiceOperationsArtifactError(
            "CANONICAL_THREE_SERVICE_PLAN_SAFETY_LOCK_DRIFT"
        )
    return {
        "schema_version": INPUT_SCHEMA_VERSION,
        "decision": plan["decision"],
        "execution": plan["execution"],
        "status_monitor": plan["status_monitor"],
        "broker": plan["broker"],
        "credentials": plan["credentials"],
        "providers": plan["providers"],
        "thresholds": plan["thresholds"],
        "storage": plan["storage"],
        "security": plan["security"],
        "ipc": plan["ipc"],
        "monitor": plan["monitor"],
    }


def _rebuild_manifest(value: object) -> ThreeServiceFailureDrillManifest:
    raw = _mapping(
        value,
        fields=_MANIFEST_FIELDS,
        label="three_service_failure_drill_manifest",
    )
    return ThreeServiceFailureDrillManifest(
        plan_sha256=raw["plan_sha256"],
        decision_release_identity_sha256=raw[
            "decision_release_identity_sha256"
        ],
        execution_release_identity_sha256=raw[
            "execution_release_identity_sha256"
        ],
        status_monitor_release_identity_sha256=raw[
            "status_monitor_release_identity_sha256"
        ],
        decision_release_manifest_sha256=raw[
            "decision_release_manifest_sha256"
        ],
        execution_release_manifest_sha256=raw[
            "execution_release_manifest_sha256"
        ],
        status_monitor_release_manifest_sha256=raw[
            "status_monitor_release_manifest_sha256"
        ],
        git_commit=raw["git_commit"],
        git_tree=raw["git_tree"],
        candidate_id=raw["candidate_id"],
        server=raw["server"],
        account_alias_sha256=raw["account_alias_sha256"],
        issued_at_utc=_utc_from_text(
            raw["issued_at_utc"],
            label="failure_drill_manifest_issued_at_utc",
        ),
        required_drills=tuple(
            _list(raw["required_drills"], label="required_drills")
        ),
        schema_version=raw["schema_version"],
    )


def verify_windows_three_service_demo_soak_review_bundle(
    payload: Mapping[str, object],
) -> WindowsThreeServiceDemoSoakOperationsPlan:
    """Reconstruct and verify every component of a v3 review bundle."""

    root = _mapping(
        payload,
        fields=_BUNDLE_FIELDS,
        label="three_service_operations_bundle",
    )
    if root.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise ThreeServiceOperationsArtifactError(
            "THREE_SERVICE_OPERATIONS_BUNDLE_SCHEMA_MISMATCH"
        )
    unsigned = dict(root)
    claimed = require_hash("content_sha256", unsigned.pop("content_sha256"))
    if canonical_sha256(unsigned) != claimed:
        raise ThreeServiceOperationsArtifactError(
            "THREE_SERVICE_OPERATIONS_BUNDLE_CONTENT_HASH_MISMATCH"
        )
    issued = _utc_from_text(root["issued_at_utc"], label="issued_at_utc")
    try:
        plan = _plan_from_mapping(_canonical_plan_to_input(root["plan"]))
    except (
        ThreeServiceOperationsArtifactError,
        ThreeServiceOperationsError,
        TypeError,
        ValueError,
    ) as exc:
        raise ThreeServiceOperationsArtifactError(
            "THREE_SERVICE_OPERATIONS_BUNDLE_PLAN_INVALID"
        ) from exc
    if root["plan"] != plan.to_dict():
        raise ThreeServiceOperationsArtifactError(
            "THREE_SERVICE_OPERATIONS_BUNDLE_PLAN_NOT_CANONICAL"
        )
    if root["plan_sha256"] != plan.plan_sha256:
        raise ThreeServiceOperationsArtifactError(
            "THREE_SERVICE_OPERATIONS_BUNDLE_PLAN_HASH_MISMATCH"
        )

    observed_manifest = _rebuild_manifest(root["failure_drill_manifest"])
    expected_manifest = _manifest(plan, issued_at_utc=issued)
    if (
        observed_manifest != expected_manifest
        or root["failure_drill_manifest"] != expected_manifest.to_dict()
        or root["failure_drill_manifest_sha256"]
        != expected_manifest.manifest_sha256
    ):
        raise ThreeServiceOperationsArtifactError(
            "THREE_SERVICE_FAILURE_DRILL_MANIFEST_BINDING_MISMATCH"
        )

    reviews = _list(root["scheduler_reviews"], label="scheduler_reviews")
    for item in reviews:
        _mapping(
            item,
            fields=_SCHEDULER_REVIEW_FIELDS,
            label="scheduler_review",
        )
    if len(reviews) != 3 or reviews != _scheduler_reviews(plan):
        raise ThreeServiceOperationsArtifactError(
            "THREE_SERVICE_SCHEDULER_REVIEW_BINDING_MISMATCH"
        )

    readiness = _mapping(
        root["readiness"], fields=_READINESS_FIELDS, label="readiness"
    )
    if dict(readiness) != _readiness(plan):
        raise ThreeServiceOperationsArtifactError(
            "THREE_SERVICE_READINESS_BINDING_MISMATCH"
        )
    effects = _mapping(root["effects"], fields=_EFFECT_FIELDS, label="effects")
    if dict(effects) != _effects():
        raise ThreeServiceOperationsArtifactError(
            "THREE_SERVICE_EFFECT_ESCALATION_DETECTED"
        )
    safety = _mapping(root["safety"], fields=_SAFETY_FIELDS, label="safety")
    if dict(safety) != _safety():
        raise ThreeServiceOperationsArtifactError(
            "THREE_SERVICE_SAFETY_LOCK_DRIFT"
        )
    assert_no_embedded_secrets(root)
    return plan


__all__ = [
    "BUNDLE_SCHEMA_VERSION",
    "FAILURE_DRILL_MANIFEST_SCHEMA_VERSION",
    "INPUT_SCHEMA_VERSION",
    "MAXIMUM_INPUT_BYTES",
    "ThreeServiceFailureDrillManifest",
    "ThreeServiceOperationsArtifactError",
    "build_windows_three_service_demo_soak_review_bundle",
    "load_windows_three_service_demo_soak_operations_plan",
    "verify_windows_three_service_demo_soak_review_bundle",
]
