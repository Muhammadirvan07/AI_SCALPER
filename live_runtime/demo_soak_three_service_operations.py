"""Deny-only operations contract for the exact three-service Windows topology.

The decision, gated execution, and external status-monitor processes ship as
three configured deterministic releases with separate Python environments and
service identities.  This module binds review metadata only.  It never imports
a provider, resolves a credential, installs a task, initializes MT5, launches a
process, or grants broker authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PureWindowsPath
import re
from typing import Any

from .contracts import canonical_sha256, require_hash, require_text
from .demo_soak_dual_release_operations import DecisionExecutionIPCBinding
from .demo_soak_operations import (
    CleanReleaseBinding,
    CredentialManagerReference,
    MT5AccountBinding,
    OffHostProviderReferences,
    OperationsThresholds,
    PythonRuntimeBinding,
    REQUIRED_CREDENTIAL_PURPOSES,
    RuntimeStoragePaths,
    SchedulerTaskDefinition,
    assert_no_embedded_secrets,
)


SCHEMA_VERSION = "windows-demo-soak-three-service-operations-v3"
DECISION_RELEASE_PROFILE = "WINDOWS_DECISION_SERVICE_V1"
EXECUTION_RELEASE_PROFILE = "WINDOWS_GATED_EXECUTION_SERVICE_V1"
MONITOR_RELEASE_PROFILE = "WINDOWS_EXTERNAL_STATUS_MONITOR_V1"
ORDER_CAPABILITY = "DISABLED"
MAX_LOT = 0.01

_ROLE_POLICY = {
    "DECISION_SERVICE": {
        "profile": DECISION_RELEASE_PROFILE,
        "runner": "run_windows_decision_service.py",
        "validator": "validate_windows_decision_service.py",
        "broker_sdk_present": False,
        "gated_execution_boundary_present": False,
        "status_only": False,
        "order_capability": "DISABLED",
        "startup_delay_seconds": 15,
    },
    "EXECUTION_SERVICE": {
        "profile": EXECUTION_RELEASE_PROFILE,
        "runner": "run_windows_gated_execution_service.py",
        "validator": "validate_windows_gated_execution_service.py",
        "broker_sdk_present": True,
        "gated_execution_boundary_present": True,
        "status_only": False,
        "order_capability": "GATED_PRESENT",
        "startup_delay_seconds": 30,
    },
    "STATUS_MONITOR_SERVICE": {
        "profile": MONITOR_RELEASE_PROFILE,
        "runner": "run_windows_external_status_monitor.py",
        "validator": "validate_windows_external_status_monitor.py",
        "broker_sdk_present": False,
        "gated_execution_boundary_present": False,
        "status_only": True,
        "order_capability": "DISABLED",
        "startup_delay_seconds": 45,
    },
}

_TASK_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,96}$")
_ID_RE = re.compile(r"^[a-z][a-z0-9._:-]{2,127}$")
_EVENT_SOURCE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_. -]{2,95}$")

EXTERNAL_READINESS_BLOCKERS = (
    "EXTERNAL_DECISION_EXECUTION_IPC_CUSTODY_REQUIRED",
    "EXTERNAL_DECISION_FACTORY_PROVIDER_CONFIGURATION_REQUIRED",
    "EXTERNAL_EXECUTION_FACTORY_PROVIDER_CONFIGURATION_REQUIRED",
    "EXTERNAL_LAUNCHER_ATTESTATIONS_REQUIRED",
    "EXTERNAL_MONITOR_OFFHOST_DELIVERY_ACCEPTANCE_REQUIRED",
    "EXTERNAL_STATUS_MONITOR_CONFIGURED_RELEASE_ACCEPTANCE_REQUIRED",
    "EXTERNAL_THREE_SERVICE_TASK_INSTALLATION_AND_ACL_ATTESTATION_REQUIRED",
    "MANUAL_DEMO_10_CONTROLLED_ORDERS_REQUIRED",
    "WINDOWS_VPS_HARDENING_AND_FAILURE_DRILLS_REQUIRED",
    "XAUUSD_MINIMUM_LOT_RISK_FEASIBILITY_REQUIRED",
)


class ThreeServiceOperationsError(ValueError):
    """A three-service review binding failed with a stable reason code."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = require_text("reason_code", reason_code, upper=True)
        super().__init__(self.reason_code)


def _nonzero_hash(name: str, value: object) -> str:
    normalized = require_hash(name, value)
    if normalized == "0" * 64:
        raise ThreeServiceOperationsError(
            f"{name.upper()}_ZERO_HASH_REJECTED"
        )
    return normalized


def _provider_id(name: str, value: object) -> str:
    normalized = require_text(name, value).lower()
    if "://" in normalized or _ID_RE.fullmatch(normalized) is None:
        raise ThreeServiceOperationsError(
            f"{name.upper()}_PROVIDER_ID_REQUIRED"
        )
    return normalized


def _service_account(name: str, value: object) -> str:
    normalized = require_text(name, value)
    if "@" in normalized or "\\" not in normalized:
        raise ThreeServiceOperationsError(
            f"{name.upper()}_LOCAL_OR_DOMAIN_ACCOUNT_REQUIRED"
        )
    return normalized


def _relative_path(name: str, value: object) -> str:
    normalized = require_text(name, value).replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise ThreeServiceOperationsError(
            f"{name.upper()}_RELEASE_RELATIVE_REQUIRED"
        )
    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ThreeServiceOperationsError(f"{name.upper()}_INVALID")
    return "/".join(parts)


def _windows_path(name: str, value: object) -> str:
    normalized = require_text(name, value).replace("/", "\\")
    path = PureWindowsPath(normalized)
    if (
        not path.is_absolute()
        or not path.drive
        or path.anchor.startswith("\\\\")
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise ThreeServiceOperationsError(
            f"{name.upper()}_LOCAL_ABSOLUTE_PATH_REQUIRED"
        )
    return str(path)


def _path_key(value: str) -> str:
    return str(PureWindowsPath(value)).rstrip("\\").casefold()


def _is_within(path: str, root: str) -> bool:
    child = _path_key(path)
    parent = _path_key(root)
    return child == parent or child.startswith(parent + "\\")


def _exact_bool(name: str, value: object, expected: bool) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{name} must be bool")
    if value is not expected:
        raise ThreeServiceOperationsError(
            f"{name.upper()}_MUST_BE_{str(expected).upper()}"
        )
    return value


def _all_distinct(values: list[str], reason_code: str) -> None:
    normalized = [value.casefold() for value in values]
    if len(normalized) != len(set(normalized)):
        raise ThreeServiceOperationsError(reason_code)


@dataclass(frozen=True)
class ConfiguredServiceRoleBinding:
    """Bind one exact configured release to one non-activating service role."""

    role: str
    base_release_profile: str
    base_release_identity_sha256: str
    configured_release_identity_sha256: str
    service_id: str
    service_account_id: str
    validation_task_name: str
    release: CleanReleaseBinding
    python: PythonRuntimeBinding
    runner_entrypoint_relative_path: str
    runner_entrypoint_sha256: str
    validator_entrypoint_relative_path: str
    validator_entrypoint_sha256: str
    factory_contract_sha256: str
    factory_manifest_sha256: str
    runtime_configuration_sha256: str
    task_definition_sha256: str
    launcher_trust_policy_sha256: str
    broker_sdk_present: bool
    gated_execution_boundary_present: bool
    status_only: bool
    order_capability: str
    factory_materialization_enabled: bool = False
    task_installed: bool = False
    launcher_attestation_issued: bool = False

    def __post_init__(self) -> None:
        role = require_text("service_role", self.role, upper=True)
        if role not in _ROLE_POLICY:
            raise ThreeServiceOperationsError("SERVICE_ROLE_INVALID")
        object.__setattr__(self, "role", role)
        policy = _ROLE_POLICY[role]

        profile = require_text(
            "base_release_profile", self.base_release_profile, upper=True
        )
        if profile != policy["profile"]:
            raise ThreeServiceOperationsError(
                "SERVICE_RELEASE_PROFILE_MISMATCH"
            )
        object.__setattr__(self, "base_release_profile", profile)
        for name in (
            "base_release_identity_sha256",
            "configured_release_identity_sha256",
        ):
            object.__setattr__(
                self,
                name,
                _nonzero_hash(name, getattr(self, name)),
            )
        if (
            self.base_release_identity_sha256
            == self.configured_release_identity_sha256
        ):
            raise ThreeServiceOperationsError(
                "BASE_AND_CONFIGURED_IDENTITIES_MUST_DIFFER"
            )

        object.__setattr__(
            self,
            "service_id",
            _provider_id("service_id", self.service_id),
        )
        object.__setattr__(
            self,
            "service_account_id",
            _service_account("service_account_id", self.service_account_id),
        )
        task_name = require_text(
            "validation_task_name", self.validation_task_name
        )
        if _TASK_NAME_RE.fullmatch(task_name) is None:
            raise ThreeServiceOperationsError("VALIDATION_TASK_NAME_INVALID")
        object.__setattr__(self, "validation_task_name", task_name)

        if type(self.release) is not CleanReleaseBinding:
            raise TypeError("release must be exact CleanReleaseBinding")
        if type(self.python) is not PythonRuntimeBinding:
            raise TypeError("python must be exact PythonRuntimeBinding")
        for name in (
            "archive_sha256",
            "manifest_sha256",
            "configuration_sha256",
            "reproducibility_receipt_sha256",
        ):
            _nonzero_hash(name, getattr(self.release, name))
        for _path, digest in self.release.tracked_file_hashes:
            _nonzero_hash("tracked_release_file_sha256", digest)
        for name in (
            "executable_sha256",
            "dependency_lock_sha256",
            "sbom_sha256",
        ):
            _nonzero_hash(name, getattr(self.python, name))

        runner = _relative_path(
            "runner_entrypoint_relative_path",
            self.runner_entrypoint_relative_path,
        )
        validator = _relative_path(
            "validator_entrypoint_relative_path",
            self.validator_entrypoint_relative_path,
        )
        if (
            runner != policy["runner"]
            or validator != policy["validator"]
        ):
            raise ThreeServiceOperationsError(
                "SERVICE_ENTRYPOINT_CONTRACT_MISMATCH"
            )
        object.__setattr__(
            self, "runner_entrypoint_relative_path", runner
        )
        object.__setattr__(
            self, "validator_entrypoint_relative_path", validator
        )
        object.__setattr__(
            self,
            "runner_entrypoint_sha256",
            _nonzero_hash(
                "runner_entrypoint_sha256",
                self.runner_entrypoint_sha256,
            ),
        )
        object.__setattr__(
            self,
            "validator_entrypoint_sha256",
            _nonzero_hash(
                "validator_entrypoint_sha256",
                self.validator_entrypoint_sha256,
            ),
        )
        for name in (
            "factory_contract_sha256",
            "factory_manifest_sha256",
            "runtime_configuration_sha256",
            "task_definition_sha256",
            "launcher_trust_policy_sha256",
        ):
            object.__setattr__(
                self,
                name,
                _nonzero_hash(name, getattr(self, name)),
            )

        for name in (
            "broker_sdk_present",
            "gated_execution_boundary_present",
            "status_only",
        ):
            _exact_bool(name, getattr(self, name), bool(policy[name]))
        capability = require_text(
            "order_capability", self.order_capability, upper=True
        )
        if capability != policy["order_capability"]:
            raise ThreeServiceOperationsError(
                "SERVICE_ORDER_CAPABILITY_MISMATCH"
            )
        object.__setattr__(self, "order_capability", capability)
        _exact_bool(
            "factory_materialization_enabled",
            self.factory_materialization_enabled,
            False,
        )
        _exact_bool("task_installed", self.task_installed, False)
        _exact_bool(
            "launcher_attestation_issued",
            self.launcher_attestation_issued,
            False,
        )

        tracked = {
            path.casefold(): digest
            for path, digest in self.release.tracked_file_hashes
        }
        if tracked.get(runner.casefold()) != self.runner_entrypoint_sha256:
            raise ThreeServiceOperationsError(
                "RUNNER_ENTRYPOINT_NOT_IN_EXACT_RELEASE"
            )
        if (
            tracked.get(validator.casefold())
            != self.validator_entrypoint_sha256
        ):
            raise ThreeServiceOperationsError(
                "VALIDATOR_ENTRYPOINT_NOT_IN_EXACT_RELEASE"
            )
        if _is_within(
            self.python.executable_path,
            self.release.source_repository_root,
        ) or _is_within(
            self.python.executable_path,
            self.release.release_root,
        ):
            raise ThreeServiceOperationsError(
                "PYTHON_RUNTIME_MUST_BE_OUTSIDE_SOURCE_AND_RELEASE"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_release_identity_sha256": (
                self.base_release_identity_sha256
            ),
            "base_release_profile": self.base_release_profile,
            "broker_sdk_present": self.broker_sdk_present,
            "configured_release_identity_sha256": (
                self.configured_release_identity_sha256
            ),
            "factory_contract_sha256": self.factory_contract_sha256,
            "factory_manifest_sha256": self.factory_manifest_sha256,
            "factory_materialization_enabled": (
                self.factory_materialization_enabled
            ),
            "gated_execution_boundary_present": (
                self.gated_execution_boundary_present
            ),
            "launcher_attestation_issued": (
                self.launcher_attestation_issued
            ),
            "launcher_trust_policy_sha256": (
                self.launcher_trust_policy_sha256
            ),
            "order_capability": self.order_capability,
            "python": dict(self.python.__dict__),
            "release": {
                **self.release.__dict__,
                "tracked_file_hashes": [
                    list(row) for row in self.release.tracked_file_hashes
                ],
            },
            "role": self.role,
            "runner_entrypoint_relative_path": (
                self.runner_entrypoint_relative_path
            ),
            "runner_entrypoint_sha256": self.runner_entrypoint_sha256,
            "runtime_configuration_sha256": (
                self.runtime_configuration_sha256
            ),
            "service_account_id": self.service_account_id,
            "service_id": self.service_id,
            "status_only": self.status_only,
            "task_definition_sha256": self.task_definition_sha256,
            "task_installed": self.task_installed,
            "validation_task_name": self.validation_task_name,
            "validator_entrypoint_relative_path": (
                self.validator_entrypoint_relative_path
            ),
            "validator_entrypoint_sha256": (
                self.validator_entrypoint_sha256
            ),
        }

    def validation_scheduler_definition(self) -> SchedulerTaskDefinition:
        validator = str(
            PureWindowsPath(self.release.release_root)
            / PureWindowsPath(
                self.validator_entrypoint_relative_path.replace("/", "\\")
            )
        )
        return SchedulerTaskDefinition(
            task_name=self.validation_task_name,
            description=(
                "AI_SCALPER validation-only "
                f"{self.role.lower().replace('_', ' ')} "
                f"{self.configured_release_identity_sha256[:16]}"
            ),
            executable_path=self.python.executable_path,
            arguments=("-B", validator, "--allow-blocked-report"),
            working_directory=self.release.release_root,
            service_account_id=self.service_account_id,
            restart_count=0,
            startup_delay_seconds=int(
                _ROLE_POLICY[self.role]["startup_delay_seconds"]
            ),
        )


@dataclass(frozen=True)
class ThreeServiceSecurityPosture:
    decision_service_account_id: str
    execution_service_account_id: str
    monitor_service_account_id: str
    rdp_ingress_scope: str
    vpn_required: bool
    mfa_required: bool
    least_privilege: bool
    public_rdp_exposed: bool
    firewall_policy_sha256: str
    event_log_source: str

    def __post_init__(self) -> None:
        accounts: list[str] = []
        for name in (
            "decision_service_account_id",
            "execution_service_account_id",
            "monitor_service_account_id",
        ):
            value = _service_account(name, getattr(self, name))
            object.__setattr__(self, name, value)
            accounts.append(value)
        _all_distinct(
            accounts,
            "THREE_SERVICE_ACCOUNTS_MUST_BE_DISTINCT",
        )
        scope = require_text(
            "rdp_ingress_scope", self.rdp_ingress_scope, upper=True
        )
        if scope != "VPN_ONLY":
            raise ThreeServiceOperationsError("PUBLIC_RDP_REJECTED")
        object.__setattr__(self, "rdp_ingress_scope", scope)
        _exact_bool("vpn_required", self.vpn_required, True)
        _exact_bool("mfa_required", self.mfa_required, True)
        _exact_bool("least_privilege", self.least_privilege, True)
        _exact_bool(
            "public_rdp_exposed", self.public_rdp_exposed, False
        )
        object.__setattr__(
            self,
            "firewall_policy_sha256",
            _nonzero_hash(
                "firewall_policy_sha256",
                self.firewall_policy_sha256,
            ),
        )
        event_source = require_text(
            "event_log_source", self.event_log_source
        )
        if _EVENT_SOURCE_RE.fullmatch(event_source) is None:
            raise ThreeServiceOperationsError(
                "WINDOWS_EVENT_SOURCE_INVALID"
            )
        object.__setattr__(self, "event_log_source", event_source)


_MONITOR_PROVIDER_FIELDS = (
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
)


@dataclass(frozen=True)
class MonitorOperationsBinding:
    decision_configured_release_identity_sha256: str
    execution_configured_release_identity_sha256: str
    monitor_configured_release_identity_sha256: str
    decision_ipc_binding_sha256: str
    status_snapshot_provider_id: str
    trusted_clock_provider_id: str
    checkpoint_cas_provider_id: str
    checkpoint_ack_verifier_provider_id: str
    incident_latch_provider_id: str
    incident_ack_verifier_provider_id: str
    sender_key_custody_provider_id: str
    remote_ack_key_custody_provider_id: str
    heartbeat_outbox_provider_id: str
    heartbeat_transport_provider_id: str
    alert_outbox_provider_id: str
    alert_transport_provider_id: str
    heartbeat_destination_id: str
    alert_destination_id: str
    status_only: bool
    configured_release_accepted: bool
    offhost_delivery_accepted: bool
    task_installed: bool

    def __post_init__(self) -> None:
        for name in (
            "decision_configured_release_identity_sha256",
            "execution_configured_release_identity_sha256",
            "monitor_configured_release_identity_sha256",
            "decision_ipc_binding_sha256",
        ):
            object.__setattr__(
                self,
                name,
                _nonzero_hash(name, getattr(self, name)),
            )
        providers: list[str] = []
        for name in _MONITOR_PROVIDER_FIELDS:
            value = _provider_id(name, getattr(self, name))
            object.__setattr__(self, name, value)
            providers.append(value)
        _all_distinct(
            providers,
            "MONITOR_PROVIDER_IDS_MUST_BE_DISTINCT",
        )
        destinations: list[str] = []
        for name in (
            "heartbeat_destination_id",
            "alert_destination_id",
        ):
            value = _provider_id(name, getattr(self, name))
            object.__setattr__(self, name, value)
            destinations.append(value)
        _all_distinct(
            destinations,
            "MONITOR_DESTINATIONS_MUST_BE_DISTINCT",
        )
        _exact_bool("status_only", self.status_only, True)
        _exact_bool(
            "configured_release_accepted",
            self.configured_release_accepted,
            False,
        )
        _exact_bool(
            "offhost_delivery_accepted",
            self.offhost_delivery_accepted,
            False,
        )
        _exact_bool("monitor_task_installed", self.task_installed, False)

    @property
    def provider_ids(self) -> tuple[str, ...]:
        return tuple(getattr(self, name) for name in _MONITOR_PROVIDER_FIELDS)


@dataclass(frozen=True)
class WindowsThreeServiceDemoSoakOperationsPlan:
    decision: ConfiguredServiceRoleBinding
    execution: ConfiguredServiceRoleBinding
    status_monitor: ConfiguredServiceRoleBinding
    broker: MT5AccountBinding
    credentials: tuple[CredentialManagerReference, ...]
    providers: OffHostProviderReferences
    thresholds: OperationsThresholds
    storage: RuntimeStoragePaths
    security: ThreeServiceSecurityPosture
    ipc: DecisionExecutionIPCBinding
    monitor: MonitorOperationsBinding
    live_allowed: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    execution_enabled: bool = field(default=False, init=False)
    promotion_eligible: bool = field(default=False, init=False)
    task_install_allowed: bool = field(default=False, init=False)
    validation_tasks_only: bool = field(default=True, init=False)
    max_lot: float = field(default=MAX_LOT, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    schema_version: str = field(default=SCHEMA_VERSION, init=False)

    def __post_init__(self) -> None:
        expected_types = (
            ("decision", ConfiguredServiceRoleBinding),
            ("execution", ConfiguredServiceRoleBinding),
            ("status_monitor", ConfiguredServiceRoleBinding),
            ("broker", MT5AccountBinding),
            ("providers", OffHostProviderReferences),
            ("thresholds", OperationsThresholds),
            ("storage", RuntimeStoragePaths),
            ("security", ThreeServiceSecurityPosture),
            ("ipc", DecisionExecutionIPCBinding),
            ("monitor", MonitorOperationsBinding),
        )
        for name, expected in expected_types:
            if type(getattr(self, name)) is not expected:
                raise TypeError(
                    f"{name} must be exact {expected.__name__}"
                )
        services = (
            self.decision,
            self.execution,
            self.status_monitor,
        )
        if tuple(item.role for item in services) != (
            "DECISION_SERVICE",
            "EXECUTION_SERVICE",
            "STATUS_MONITOR_SERVICE",
        ):
            raise ThreeServiceOperationsError(
                "EXACT_THREE_SERVICE_ROLES_REQUIRED"
            )

        releases = tuple(item.release for item in services)
        source_keys = {
            _path_key(item.source_repository_root) for item in releases
        }
        commits = {item.git_commit for item in releases}
        trees = {item.git_tree for item in releases}
        if len(source_keys) != 1 or len(commits) != 1 or len(trees) != 1:
            raise ThreeServiceOperationsError(
                "THREE_SERVICE_SOURCE_COMMIT_TREE_MISMATCH"
            )
        for index, left in enumerate(releases):
            for right in releases[index + 1 :]:
                if _is_within(
                    left.release_root, right.release_root
                ) or _is_within(right.release_root, left.release_root):
                    raise ThreeServiceOperationsError(
                        "THREE_SERVICE_RELEASE_ROOTS_MUST_BE_DISTINCT"
                    )

        distinct_fields = (
            ("base_release_identity_sha256", services),
            ("configured_release_identity_sha256", services),
            ("service_id", services),
            ("service_account_id", services),
            ("validation_task_name", services),
            ("task_definition_sha256", services),
            ("factory_manifest_sha256", services),
            ("runtime_configuration_sha256", services),
            ("launcher_trust_policy_sha256", services),
            ("archive_sha256", releases),
            ("manifest_sha256", releases),
            ("configuration_sha256", releases),
            ("reproducibility_receipt_sha256", releases),
        )
        for name, values in distinct_fields:
            _all_distinct(
                [str(getattr(item, name)) for item in values],
                f"THREE_SERVICE_{name.upper()}_MUST_BE_DISTINCT",
            )
        runtimes = tuple(item.python for item in services)
        for name in (
            "executable_path",
            "dependency_lock_sha256",
            "sbom_sha256",
        ):
            _all_distinct(
                [str(getattr(item, name)) for item in runtimes],
                f"THREE_SERVICE_{name.upper()}_MUST_BE_DISTINCT",
            )

        expected_accounts = (
            self.security.decision_service_account_id,
            self.security.execution_service_account_id,
            self.security.monitor_service_account_id,
        )
        if tuple(
            item.service_account_id for item in services
        ) != expected_accounts:
            raise ThreeServiceOperationsError(
                "SERVICE_ACCOUNT_SECURITY_BINDING_MISMATCH"
            )

        canonical_symbols = {
            canonical
            for canonical, _broker, _spec in self.broker.symbol_bindings
        }
        if canonical_symbols != {"XAUUSD"}:
            raise ThreeServiceOperationsError(
                "INITIAL_DEMO_AUTO_SCOPE_MUST_BE_EXACT_XAUUSD"
            )

        code_roots = (
            releases[0].source_repository_root,
            *(item.release_root for item in releases),
        )
        if any(
            _is_within(runtime.executable_path, root)
            for runtime in runtimes
            for root in code_roots
        ):
            raise ThreeServiceOperationsError(
                "PYTHON_RUNTIME_INSIDE_SOURCE_OR_RELEASE"
            )
        self.storage.assert_outside(*code_roots)
        if any(
            _is_within(self.ipc.database_path, root)
            for root in code_roots
        ):
            raise ThreeServiceOperationsError(
                "DECISION_IPC_PATH_INSIDE_SOURCE_OR_RELEASE"
            )
        state_databases = {
            _path_key(getattr(self.storage, name))
            for name in (
                "journal_database",
                "risk_database",
                "supervisor_database",
                "manual_demo_database",
                "soak_database",
            )
        }
        if _path_key(self.ipc.database_path) in state_databases:
            raise ThreeServiceOperationsError(
                "DECISION_IPC_DATABASE_MUST_BE_DISTINCT"
            )
        if (
            self.ipc.publisher_service_id != self.decision.service_id
            or self.ipc.consumer_service_id != self.execution.service_id
        ):
            raise ThreeServiceOperationsError(
                "DECISION_IPC_SERVICE_IDENTITY_MISMATCH"
            )

        if (
            self.monitor.decision_configured_release_identity_sha256
            != self.decision.configured_release_identity_sha256
            or self.monitor.execution_configured_release_identity_sha256
            != self.execution.configured_release_identity_sha256
            or self.monitor.monitor_configured_release_identity_sha256
            != self.status_monitor.configured_release_identity_sha256
        ):
            raise ThreeServiceOperationsError(
                "MONITOR_CONFIGURED_RELEASE_IDENTITY_BINDING_MISMATCH"
            )
        if (
            self.monitor.decision_ipc_binding_sha256
            != self.ipc.binding_sha256
        ):
            raise ThreeServiceOperationsError(
                "MONITOR_DECISION_IPC_BINDING_MISMATCH"
            )
        if (
            self.monitor.heartbeat_destination_id
            != self.providers.heartbeat_destination_id
            or self.monitor.alert_destination_id
            != self.providers.alert_destination_id
        ):
            raise ThreeServiceOperationsError(
                "MONITOR_OFFHOST_DESTINATION_BINDING_MISMATCH"
            )
        if any(
            _is_within(self.broker.terminal_path, root)
            for root in code_roots
        ):
            raise ThreeServiceOperationsError(
                "MT5_TERMINAL_INSIDE_SOURCE_OR_RELEASE"
            )
        _nonzero_hash("terminal_sha256", self.broker.terminal_sha256)
        _nonzero_hash(
            "account_alias_sha256", self.broker.account_alias_sha256
        )
        for _canonical, _broker_symbol, specification_sha256 in (
            self.broker.symbol_bindings
        ):
            _nonzero_hash(
                "broker_specification_sha256",
                specification_sha256,
            )

        offhost_ids = [
            getattr(self.providers, name)
            for name in self.providers.__dataclass_fields__
        ]
        ipc_ids = [
            self.ipc.checkpoint_cas_provider_id,
            self.ipc.producer_cursor_cas_provider_id,
            self.ipc.ack_verifier_provider_id,
            self.ipc.signing_key_custody_provider_id,
        ]
        _all_distinct(
            [*offhost_ids, *ipc_ids, *self.monitor.provider_ids],
            "CROSS_DOMAIN_PROVIDER_IDS_MUST_BE_DISTINCT",
        )

        credentials = tuple(self.credentials)
        if not credentials or any(
            type(item) is not CredentialManagerReference
            for item in credentials
        ):
            raise TypeError(
                "credentials must contain exact "
                "CredentialManagerReference values"
            )
        purposes = [item.purpose for item in credentials]
        if (
            set(purposes) != REQUIRED_CREDENTIAL_PURPOSES
            or len(purposes) != len(REQUIRED_CREDENTIAL_PURPOSES)
        ):
            raise ThreeServiceOperationsError(
                "EXACT_CREDENTIAL_REFERENCE_PURPOSES_REQUIRED"
            )
        _all_distinct(
            [item.target_name for item in credentials],
            "CREDENTIAL_TARGET_NAMES_MUST_BE_DISTINCT",
        )
        _all_distinct(
            [item.key_id for item in credentials],
            "CREDENTIAL_KEY_IDS_MUST_BE_DISTINCT",
        )
        object.__setattr__(
            self,
            "credentials",
            tuple(sorted(credentials, key=lambda item: item.purpose)),
        )
        assert_no_embedded_secrets(self.to_dict())

    @property
    def plan_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "broker": {
                **self.broker.__dict__,
                "symbol_bindings": [
                    list(row) for row in self.broker.symbol_bindings
                ],
            },
            "credentials": [
                dict(item.__dict__) for item in self.credentials
            ],
            "decision": self.decision.to_dict(),
            "execution": self.execution.to_dict(),
            "execution_enabled": self.execution_enabled,
            "ipc": dict(self.ipc.__dict__),
            "live_allowed": self.live_allowed,
            "max_lot": self.max_lot,
            "monitor": dict(self.monitor.__dict__),
            "order_capability": self.order_capability,
            "promotion_eligible": self.promotion_eligible,
            "providers": dict(self.providers.__dict__),
            "safe_to_demo_auto_order": self.safe_to_demo_auto_order,
            "schema_version": self.schema_version,
            "security": dict(self.security.__dict__),
            "status_monitor": self.status_monitor.to_dict(),
            "storage": dict(self.storage.__dict__),
            "task_install_allowed": self.task_install_allowed,
            "thresholds": dict(self.thresholds.__dict__),
            "validation_tasks_only": self.validation_tasks_only,
        }

    def validation_scheduler_definitions(
        self,
    ) -> tuple[
        SchedulerTaskDefinition,
        SchedulerTaskDefinition,
        SchedulerTaskDefinition,
    ]:
        return (
            self.decision.validation_scheduler_definition(),
            self.execution.validation_scheduler_definition(),
            self.status_monitor.validation_scheduler_definition(),
        )


@dataclass(frozen=True)
class ThreeServiceOperationsReadiness:
    plan_sha256: str
    local_three_service_plan_valid: bool
    validation_tasks_only: bool
    status: str
    external_blockers: tuple[str, ...]
    task_install_allowed: bool = False
    execution_enabled: bool = False
    safe_to_demo_auto_order: bool = False
    live_allowed: bool = False
    promotion_eligible: bool = False
    order_capability: str = ORDER_CAPABILITY
    max_lot: float = MAX_LOT

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "plan_sha256",
            _nonzero_hash("plan_sha256", self.plan_sha256),
        )
        _exact_bool(
            "local_three_service_plan_valid",
            self.local_three_service_plan_valid,
            True,
        )
        _exact_bool(
            "validation_tasks_only",
            self.validation_tasks_only,
            True,
        )
        if self.status != "BLOCKED_EXTERNAL_ACCEPTANCE":
            raise ThreeServiceOperationsError(
                "READINESS_STATUS_MUST_REMAIN_BLOCKED"
            )
        blockers = tuple(sorted(set(self.external_blockers)))
        if blockers != tuple(sorted(EXTERNAL_READINESS_BLOCKERS)):
            raise ThreeServiceOperationsError(
                "EXTERNAL_READINESS_BLOCKERS_MISMATCH"
            )
        object.__setattr__(self, "external_blockers", blockers)
        for name in (
            "task_install_allowed",
            "execution_enabled",
            "safe_to_demo_auto_order",
            "live_allowed",
            "promotion_eligible",
        ):
            _exact_bool(name, getattr(self, name), False)
        if (
            self.order_capability != ORDER_CAPABILITY
            or self.max_lot != MAX_LOT
        ):
            raise ThreeServiceOperationsError(
                "READINESS_SAFETY_LOCK_DRIFT"
            )


def assess_three_service_operations_readiness(
    plan: WindowsThreeServiceDemoSoakOperationsPlan,
) -> ThreeServiceOperationsReadiness:
    if type(plan) is not WindowsThreeServiceDemoSoakOperationsPlan:
        raise TypeError(
            "plan must be exact "
            "WindowsThreeServiceDemoSoakOperationsPlan"
        )
    return ThreeServiceOperationsReadiness(
        plan_sha256=plan.plan_sha256,
        local_three_service_plan_valid=True,
        validation_tasks_only=True,
        status="BLOCKED_EXTERNAL_ACCEPTANCE",
        external_blockers=EXTERNAL_READINESS_BLOCKERS,
    )


__all__ = [
    "DECISION_RELEASE_PROFILE",
    "EXECUTION_RELEASE_PROFILE",
    "EXTERNAL_READINESS_BLOCKERS",
    "MONITOR_RELEASE_PROFILE",
    "ConfiguredServiceRoleBinding",
    "MonitorOperationsBinding",
    "ThreeServiceOperationsError",
    "ThreeServiceOperationsReadiness",
    "ThreeServiceSecurityPosture",
    "WindowsThreeServiceDemoSoakOperationsPlan",
    "assess_three_service_operations_readiness",
]
