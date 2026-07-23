"""Deny-only operations contract for the real dual-release Windows topology.

The decision service and gated execution service deliberately ship as separate
deterministic releases with separate Python dependency environments.  This
module binds that topology, the decision IPC boundary, and an external monitor
reference without installing a task, importing a provider, reading a
credential, initializing MT5, or granting execution authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PureWindowsPath
import re
from typing import Any

from .contracts import canonical_sha256, require_hash, require_text
from .decision_ipc import DECISION_IPC_BINDING_SCHEMA_VERSION
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


SCHEMA_VERSION = "windows-demo-soak-dual-release-operations-v2"
DECISION_RELEASE_PROFILE = "WINDOWS_DECISION_SERVICE_V1"
EXECUTION_RELEASE_PROFILE = "WINDOWS_GATED_EXECUTION_SERVICE_V1"
ORDER_CAPABILITY = "DISABLED"
MAX_LOT = 0.01

_ROLE_PROFILES = {
    "DECISION_SERVICE": DECISION_RELEASE_PROFILE,
    "EXECUTION_SERVICE": EXECUTION_RELEASE_PROFILE,
}
_ROLE_ENTRYPOINTS = {
    "DECISION_SERVICE": (
        "run_windows_decision_service.py",
        "validate_windows_decision_service.py",
    ),
    "EXECUTION_SERVICE": (
        "run_windows_gated_execution_service.py",
        "validate_windows_gated_execution_service.py",
    ),
}
_TASK_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,96}$")
_ID_RE = re.compile(r"^[a-z][a-z0-9._:-]{2,127}$")
_EVENT_SOURCE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_. -]{2,95}$")

EXTERNAL_READINESS_BLOCKERS = (
    "EXTERNAL_DECISION_EXECUTION_IPC_CUSTODY_REQUIRED",
    "EXTERNAL_DECISION_FACTORY_PROVIDER_CONFIGURATION_REQUIRED",
    "EXTERNAL_EXECUTION_FACTORY_PROVIDER_CONFIGURATION_REQUIRED",
    "EXTERNAL_LAUNCHER_ATTESTATIONS_REQUIRED",
    "EXTERNAL_MONITOR_WATCHDOG_IMPLEMENTATION_REQUIRED",
    "EXTERNAL_TASK_INSTALLATION_AND_ACL_ATTESTATION_REQUIRED",
    "MANUAL_DEMO_10_CONTROLLED_ORDERS_REQUIRED",
    "WINDOWS_VPS_HARDENING_AND_FAILURE_DRILLS_REQUIRED",
)


class DualReleaseOperationsError(ValueError):
    """A dual-release review binding failed with a stable reason code."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = require_text("reason_code", reason_code, upper=True)
        super().__init__(self.reason_code)


def _nonzero_hash(name: str, value: object) -> str:
    normalized = require_hash(name, value)
    if normalized == "0" * 64:
        raise DualReleaseOperationsError(f"{name.upper()}_ZERO_HASH_REJECTED")
    return normalized


def _provider_id(name: str, value: object) -> str:
    normalized = require_text(name, value).lower()
    if "://" in normalized or _ID_RE.fullmatch(normalized) is None:
        raise DualReleaseOperationsError(f"{name.upper()}_PROVIDER_ID_REQUIRED")
    return normalized


def _service_account(name: str, value: object) -> str:
    normalized = require_text(name, value)
    if "@" in normalized or "\\" not in normalized:
        raise DualReleaseOperationsError(
            f"{name.upper()}_LOCAL_OR_DOMAIN_ACCOUNT_REQUIRED"
        )
    return normalized


def _relative_path(name: str, value: object) -> str:
    normalized = require_text(name, value).replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise DualReleaseOperationsError(f"{name.upper()}_RELEASE_RELATIVE_REQUIRED")
    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise DualReleaseOperationsError(f"{name.upper()}_INVALID")
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
        raise DualReleaseOperationsError(f"{name.upper()}_LOCAL_ABSOLUTE_PATH_REQUIRED")
    return str(path)


def _path_key(value: str) -> str:
    return str(PureWindowsPath(value)).rstrip("\\").casefold()


def _is_within(path: str, root: str) -> bool:
    child = _path_key(path)
    parent = _path_key(root)
    return child == parent or child.startswith(parent + "\\")


def _require_exact_bool(name: str, value: object, expected: bool) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{name} must be bool")
    if value is not expected:
        raise DualReleaseOperationsError(
            f"{name.upper()}_MUST_BE_{str(expected).upper()}"
        )
    return value


@dataclass(frozen=True)
class ServiceReleaseRoleBinding:
    """Bind one deterministic release, runtime, and validation-only task."""

    role: str
    release_profile: str
    release_identity_sha256: str
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
    factory_configuration_sha256: str
    factory_materialization_enabled: bool = False
    broker_mutation_capability: str = ORDER_CAPABILITY

    def __post_init__(self) -> None:
        role = require_text("service release role", self.role, upper=True)
        if role not in _ROLE_PROFILES:
            raise DualReleaseOperationsError("SERVICE_RELEASE_ROLE_INVALID")
        object.__setattr__(self, "role", role)
        profile = require_text("release_profile", self.release_profile, upper=True)
        if profile != _ROLE_PROFILES[role]:
            raise DualReleaseOperationsError("SERVICE_RELEASE_PROFILE_MISMATCH")
        object.__setattr__(self, "release_profile", profile)
        object.__setattr__(
            self,
            "release_identity_sha256",
            _nonzero_hash(
                "release_identity_sha256", self.release_identity_sha256
            ),
        )
        object.__setattr__(self, "service_id", _provider_id("service_id", self.service_id))
        object.__setattr__(
            self,
            "service_account_id",
            _service_account("service_account_id", self.service_account_id),
        )
        task_name = require_text("validation_task_name", self.validation_task_name)
        if _TASK_NAME_RE.fullmatch(task_name) is None:
            raise DualReleaseOperationsError("VALIDATION_TASK_NAME_INVALID")
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
        expected_runner, expected_validator = _ROLE_ENTRYPOINTS[role]
        if runner != expected_runner or validator != expected_validator:
            raise DualReleaseOperationsError("SERVICE_ENTRYPOINT_CONTRACT_MISMATCH")
        object.__setattr__(self, "runner_entrypoint_relative_path", runner)
        object.__setattr__(self, "validator_entrypoint_relative_path", validator)
        object.__setattr__(
            self,
            "runner_entrypoint_sha256",
            _nonzero_hash(
                "runner_entrypoint_sha256", self.runner_entrypoint_sha256
            ),
        )
        object.__setattr__(
            self,
            "validator_entrypoint_sha256",
            _nonzero_hash(
                "validator_entrypoint_sha256", self.validator_entrypoint_sha256
            ),
        )
        for name in (
            "factory_contract_sha256",
            "factory_configuration_sha256",
        ):
            object.__setattr__(
                self, name, _nonzero_hash(name, getattr(self, name))
            )
        _require_exact_bool(
            "factory_materialization_enabled",
            self.factory_materialization_enabled,
            False,
        )
        capability = require_text(
            "broker_mutation_capability",
            self.broker_mutation_capability,
            upper=True,
        )
        if capability != ORDER_CAPABILITY:
            raise DualReleaseOperationsError(
                "VALIDATION_BROKER_MUTATION_MUST_REMAIN_DISABLED"
            )
        object.__setattr__(self, "broker_mutation_capability", capability)

        tracked = {
            path.casefold(): digest
            for path, digest in self.release.tracked_file_hashes
        }
        if tracked.get(runner.casefold()) != self.runner_entrypoint_sha256:
            raise DualReleaseOperationsError(
                "RUNNER_ENTRYPOINT_NOT_IN_EXACT_RELEASE"
            )
        if tracked.get(validator.casefold()) != self.validator_entrypoint_sha256:
            raise DualReleaseOperationsError(
                "VALIDATOR_ENTRYPOINT_NOT_IN_EXACT_RELEASE"
            )
        if _is_within(
            self.python.executable_path, self.release.source_repository_root
        ) or _is_within(self.python.executable_path, self.release.release_root):
            raise DualReleaseOperationsError(
                "PYTHON_RUNTIME_MUST_BE_OUTSIDE_SOURCE_AND_RELEASE"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "broker_mutation_capability": self.broker_mutation_capability,
            "factory_configuration_sha256": self.factory_configuration_sha256,
            "factory_contract_sha256": self.factory_contract_sha256,
            "factory_materialization_enabled": self.factory_materialization_enabled,
            "python": dict(self.python.__dict__),
            "release": {
                **self.release.__dict__,
                "tracked_file_hashes": [
                    list(row) for row in self.release.tracked_file_hashes
                ],
            },
            "release_identity_sha256": self.release_identity_sha256,
            "release_profile": self.release_profile,
            "role": self.role,
            "runner_entrypoint_relative_path": (
                self.runner_entrypoint_relative_path
            ),
            "runner_entrypoint_sha256": self.runner_entrypoint_sha256,
            "service_account_id": self.service_account_id,
            "service_id": self.service_id,
            "validation_task_name": self.validation_task_name,
            "validator_entrypoint_relative_path": (
                self.validator_entrypoint_relative_path
            ),
            "validator_entrypoint_sha256": self.validator_entrypoint_sha256,
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
                f"{self.release_identity_sha256[:16]}"
            ),
            executable_path=self.python.executable_path,
            arguments=("-B", validator, "--allow-blocked-report"),
            working_directory=self.release.release_root,
            service_account_id=self.service_account_id,
            restart_count=0,
            startup_delay_seconds=15 if self.role == "DECISION_SERVICE" else 30,
        )


@dataclass(frozen=True)
class DualReleaseSecurityPosture:
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
            accounts.append(value.casefold())
        if len(set(accounts)) != 3:
            raise DualReleaseOperationsError(
                "DECISION_EXECUTION_MONITOR_IDENTITIES_MUST_BE_DISTINCT"
            )
        scope = require_text(
            "rdp_ingress_scope", self.rdp_ingress_scope, upper=True
        )
        if scope != "VPN_ONLY":
            raise DualReleaseOperationsError("PUBLIC_RDP_REJECTED")
        object.__setattr__(self, "rdp_ingress_scope", scope)
        _require_exact_bool("vpn_required", self.vpn_required, True)
        _require_exact_bool("mfa_required", self.mfa_required, True)
        _require_exact_bool("least_privilege", self.least_privilege, True)
        _require_exact_bool(
            "public_rdp_exposed", self.public_rdp_exposed, False
        )
        object.__setattr__(
            self,
            "firewall_policy_sha256",
            _nonzero_hash(
                "firewall_policy_sha256", self.firewall_policy_sha256
            ),
        )
        event_source = require_text("event_log_source", self.event_log_source)
        if _EVENT_SOURCE_RE.fullmatch(event_source) is None:
            raise DualReleaseOperationsError("WINDOWS_EVENT_SOURCE_INVALID")
        object.__setattr__(self, "event_log_source", event_source)


@dataclass(frozen=True)
class DecisionExecutionIPCBinding:
    database_path: str
    binding_schema_version: str
    binding_sha256: str
    publisher_service_id: str
    consumer_service_id: str
    acl_policy_sha256: str
    checkpoint_cas_provider_id: str
    producer_cursor_cas_provider_id: str
    ack_verifier_provider_id: str
    signing_key_custody_provider_id: str
    external_custody_required: bool

    def __post_init__(self) -> None:
        database = _windows_path("decision_ipc_database_path", self.database_path)
        if PureWindowsPath(database).suffix.casefold() not in {".db", ".sqlite3"}:
            raise DualReleaseOperationsError(
                "DECISION_IPC_SQLITE_EXTENSION_REQUIRED"
            )
        object.__setattr__(self, "database_path", database)
        schema = require_text(
            "binding_schema_version", self.binding_schema_version
        )
        if schema != DECISION_IPC_BINDING_SCHEMA_VERSION:
            raise DualReleaseOperationsError(
                "DECISION_IPC_BINDING_SCHEMA_MISMATCH"
            )
        object.__setattr__(self, "binding_schema_version", schema)
        object.__setattr__(
            self,
            "binding_sha256",
            _nonzero_hash("binding_sha256", self.binding_sha256),
        )
        object.__setattr__(
            self,
            "publisher_service_id",
            _provider_id("publisher_service_id", self.publisher_service_id),
        )
        object.__setattr__(
            self,
            "consumer_service_id",
            _provider_id("consumer_service_id", self.consumer_service_id),
        )
        if self.publisher_service_id == self.consumer_service_id:
            raise DualReleaseOperationsError(
                "IPC_PUBLISHER_AND_CONSUMER_MUST_BE_DISTINCT"
            )
        object.__setattr__(
            self,
            "acl_policy_sha256",
            _nonzero_hash("acl_policy_sha256", self.acl_policy_sha256),
        )
        provider_names = (
            "checkpoint_cas_provider_id",
            "producer_cursor_cas_provider_id",
            "ack_verifier_provider_id",
            "signing_key_custody_provider_id",
        )
        provider_values: list[str] = []
        for name in provider_names:
            value = _provider_id(name, getattr(self, name))
            object.__setattr__(self, name, value)
            provider_values.append(value)
        if len(set(provider_values)) != len(provider_values):
            raise DualReleaseOperationsError(
                "DECISION_IPC_PROVIDER_IDS_MUST_BE_DISTINCT"
            )
        _require_exact_bool(
            "external_custody_required",
            self.external_custody_required,
            True,
        )


@dataclass(frozen=True)
class ExternalMonitorBinding:
    monitor_provider_id: str
    implementation_sha256: str
    configuration_sha256: str
    task_definition_sha256: str
    service_account_id: str
    heartbeat_destination_id: str
    alert_destination_id: str
    status_only: bool
    installed: bool
    broker_mutation_capability: str = ORDER_CAPABILITY

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "monitor_provider_id",
            _provider_id("monitor_provider_id", self.monitor_provider_id),
        )
        for name in (
            "implementation_sha256",
            "configuration_sha256",
            "task_definition_sha256",
        ):
            object.__setattr__(
                self, name, _nonzero_hash(name, getattr(self, name))
            )
        object.__setattr__(
            self,
            "service_account_id",
            _service_account("monitor_service_account_id", self.service_account_id),
        )
        for name in ("heartbeat_destination_id", "alert_destination_id"):
            object.__setattr__(
                self, name, _provider_id(name, getattr(self, name))
            )
        if self.heartbeat_destination_id == self.alert_destination_id:
            raise DualReleaseOperationsError(
                "MONITOR_DESTINATIONS_MUST_BE_DISTINCT"
            )
        _require_exact_bool("monitor_status_only", self.status_only, True)
        _require_exact_bool("monitor_installed", self.installed, False)
        capability = require_text(
            "monitor broker_mutation_capability",
            self.broker_mutation_capability,
            upper=True,
        )
        if capability != ORDER_CAPABILITY:
            raise DualReleaseOperationsError(
                "MONITOR_BROKER_MUTATION_MUST_REMAIN_DISABLED"
            )
        object.__setattr__(self, "broker_mutation_capability", capability)


@dataclass(frozen=True)
class WindowsDualReleaseDemoSoakOperationsPlan:
    decision: ServiceReleaseRoleBinding
    execution: ServiceReleaseRoleBinding
    broker: MT5AccountBinding
    credentials: tuple[CredentialManagerReference, ...]
    providers: OffHostProviderReferences
    thresholds: OperationsThresholds
    storage: RuntimeStoragePaths
    security: DualReleaseSecurityPosture
    ipc: DecisionExecutionIPCBinding
    monitor: ExternalMonitorBinding
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
        typed = (
            ("decision", ServiceReleaseRoleBinding),
            ("execution", ServiceReleaseRoleBinding),
            ("broker", MT5AccountBinding),
            ("providers", OffHostProviderReferences),
            ("thresholds", OperationsThresholds),
            ("storage", RuntimeStoragePaths),
            ("security", DualReleaseSecurityPosture),
            ("ipc", DecisionExecutionIPCBinding),
            ("monitor", ExternalMonitorBinding),
        )
        for name, expected in typed:
            if type(getattr(self, name)) is not expected:
                raise TypeError(f"{name} must be exact {expected.__name__}")
        if (
            self.decision.role != "DECISION_SERVICE"
            or self.execution.role != "EXECUTION_SERVICE"
        ):
            raise DualReleaseOperationsError("DECISION_EXECUTION_ROLES_REQUIRED")

        decision_release = self.decision.release
        execution_release = self.execution.release
        if (
            _path_key(decision_release.source_repository_root)
            != _path_key(execution_release.source_repository_root)
            or decision_release.git_commit != execution_release.git_commit
            or decision_release.git_tree != execution_release.git_tree
        ):
            raise DualReleaseOperationsError(
                "DUAL_RELEASE_SOURCE_COMMIT_TREE_MISMATCH"
            )
        if _is_within(
            decision_release.release_root, execution_release.release_root
        ) or _is_within(
            execution_release.release_root, decision_release.release_root
        ):
            raise DualReleaseOperationsError("DUAL_RELEASE_ROOTS_MUST_BE_DISTINCT")
        distinct_release_values = (
            (
                self.decision.release_identity_sha256,
                self.execution.release_identity_sha256,
                "DUAL_RELEASE_IDENTITIES_MUST_BE_DISTINCT",
            ),
            (
                decision_release.archive_sha256,
                execution_release.archive_sha256,
                "DUAL_RELEASE_ARCHIVES_MUST_BE_DISTINCT",
            ),
            (
                decision_release.manifest_sha256,
                execution_release.manifest_sha256,
                "DUAL_RELEASE_MANIFESTS_MUST_BE_DISTINCT",
            ),
            (
                decision_release.configuration_sha256,
                execution_release.configuration_sha256,
                "DUAL_RELEASE_CONFIGURATIONS_MUST_BE_DISTINCT",
            ),
            (
                decision_release.reproducibility_receipt_sha256,
                execution_release.reproducibility_receipt_sha256,
                "DUAL_RELEASE_REPRODUCIBILITY_RECEIPTS_MUST_BE_DISTINCT",
            ),
        )
        for left, right, reason in distinct_release_values:
            if left == right:
                raise DualReleaseOperationsError(reason)
        if (
            _path_key(self.decision.python.executable_path)
            == _path_key(self.execution.python.executable_path)
            or self.decision.python.dependency_lock_sha256
            == self.execution.python.dependency_lock_sha256
            or self.decision.python.sbom_sha256
            == self.execution.python.sbom_sha256
        ):
            raise DualReleaseOperationsError(
                "DECISION_EXECUTION_PYTHON_RUNTIMES_MUST_BE_DISTINCT"
            )
        if (
            self.decision.service_account_id
            != self.security.decision_service_account_id
            or self.execution.service_account_id
            != self.security.execution_service_account_id
        ):
            raise DualReleaseOperationsError(
                "SERVICE_ACCOUNT_SECURITY_BINDING_MISMATCH"
            )

        canonical_symbols = {
            canonical for canonical, _broker, _spec in self.broker.symbol_bindings
        }
        if canonical_symbols != {"XAUUSD"}:
            raise DualReleaseOperationsError(
                "INITIAL_DEMO_AUTO_SCOPE_MUST_BE_EXACT_XAUUSD"
            )
        code_roots = (
            decision_release.source_repository_root,
            decision_release.release_root,
            execution_release.release_root,
        )
        if any(
            _is_within(runtime.executable_path, root)
            for runtime in (self.decision.python, self.execution.python)
            for root in code_roots
        ):
            raise DualReleaseOperationsError(
                "PYTHON_RUNTIME_INSIDE_SOURCE_OR_RELEASE"
            )
        self.storage.assert_outside(*code_roots)
        if any(_is_within(self.ipc.database_path, root) for root in code_roots):
            raise DualReleaseOperationsError(
                "DECISION_IPC_PATH_INSIDE_SOURCE_OR_RELEASE"
            )
        storage_databases = {
            _path_key(getattr(self.storage, name))
            for name in (
                "journal_database",
                "risk_database",
                "supervisor_database",
                "manual_demo_database",
                "soak_database",
            )
        }
        if _path_key(self.ipc.database_path) in storage_databases:
            raise DualReleaseOperationsError(
                "DECISION_IPC_DATABASE_MUST_BE_DISTINCT"
            )
        if (
            self.ipc.publisher_service_id != self.decision.service_id
            or self.ipc.consumer_service_id != self.execution.service_id
        ):
            raise DualReleaseOperationsError(
                "DECISION_IPC_SERVICE_IDENTITY_MISMATCH"
            )
        if (
            self.monitor.service_account_id
            != self.security.monitor_service_account_id
        ):
            raise DualReleaseOperationsError(
                "MONITOR_SERVICE_ACCOUNT_SECURITY_BINDING_MISMATCH"
            )
        if (
            self.monitor.heartbeat_destination_id
            != self.providers.heartbeat_destination_id
            or self.monitor.alert_destination_id
            != self.providers.alert_destination_id
        ):
            raise DualReleaseOperationsError(
                "MONITOR_OFFHOST_DESTINATION_BINDING_MISMATCH"
            )
        if any(
            _is_within(self.broker.terminal_path, root) for root in code_roots
        ):
            raise DualReleaseOperationsError(
                "MT5_TERMINAL_INSIDE_SOURCE_OR_RELEASE"
            )
        _nonzero_hash("terminal_sha256", self.broker.terminal_sha256)
        _nonzero_hash(
            "account_alias_sha256", self.broker.account_alias_sha256
        )
        for _canonical, _broker_symbol, specification_sha256 in (
            self.broker.symbol_bindings
        ):
            _nonzero_hash("broker_specification_sha256", specification_sha256)

        external_provider_ids = [
            getattr(self.providers, name)
            for name in self.providers.__dataclass_fields__
        ]
        ipc_provider_ids = [
            self.ipc.checkpoint_cas_provider_id,
            self.ipc.producer_cursor_cas_provider_id,
            self.ipc.ack_verifier_provider_id,
            self.ipc.signing_key_custody_provider_id,
        ]
        all_provider_ids = [
            *(value.casefold() for value in external_provider_ids),
            *(value.casefold() for value in ipc_provider_ids),
            self.monitor.monitor_provider_id.casefold(),
        ]
        if len(set(all_provider_ids)) != len(all_provider_ids):
            raise DualReleaseOperationsError(
                "CROSS_DOMAIN_PROVIDER_IDS_MUST_BE_DISTINCT"
            )

        credentials = tuple(self.credentials)
        if not credentials or any(
            type(item) is not CredentialManagerReference for item in credentials
        ):
            raise TypeError(
                "credentials must contain exact CredentialManagerReference values"
            )
        purposes = [item.purpose for item in credentials]
        if set(purposes) != REQUIRED_CREDENTIAL_PURPOSES or len(purposes) != len(
            REQUIRED_CREDENTIAL_PURPOSES
        ):
            raise DualReleaseOperationsError(
                "EXACT_CREDENTIAL_REFERENCE_PURPOSES_REQUIRED"
            )
        if len({item.target_name.casefold() for item in credentials}) != len(
            credentials
        ) or len({item.key_id.casefold() for item in credentials}) != len(
            credentials
        ):
            raise DualReleaseOperationsError(
                "CREDENTIAL_REFERENCE_IDENTITIES_MUST_BE_DISTINCT"
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
            "credentials": [dict(item.__dict__) for item in self.credentials],
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
            "storage": dict(self.storage.__dict__),
            "task_install_allowed": self.task_install_allowed,
            "thresholds": dict(self.thresholds.__dict__),
            "validation_tasks_only": self.validation_tasks_only,
        }

    def validation_scheduler_definitions(
        self,
    ) -> tuple[SchedulerTaskDefinition, SchedulerTaskDefinition]:
        return (
            self.decision.validation_scheduler_definition(),
            self.execution.validation_scheduler_definition(),
        )


@dataclass(frozen=True)
class DualReleaseOperationsReadiness:
    plan_sha256: str
    local_dual_release_plan_valid: bool
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
            self, "plan_sha256", _nonzero_hash("plan_sha256", self.plan_sha256)
        )
        _require_exact_bool(
            "local_dual_release_plan_valid",
            self.local_dual_release_plan_valid,
            True,
        )
        _require_exact_bool(
            "validation_tasks_only", self.validation_tasks_only, True
        )
        if self.status != "BLOCKED_EXTERNAL_ACCEPTANCE":
            raise DualReleaseOperationsError("READINESS_STATUS_MUST_REMAIN_BLOCKED")
        blockers = tuple(sorted(set(self.external_blockers)))
        if blockers != tuple(sorted(EXTERNAL_READINESS_BLOCKERS)):
            raise DualReleaseOperationsError(
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
            _require_exact_bool(name, getattr(self, name), False)
        if self.order_capability != ORDER_CAPABILITY or self.max_lot != MAX_LOT:
            raise DualReleaseOperationsError("READINESS_SAFETY_LOCK_DRIFT")


def assess_dual_release_operations_readiness(
    plan: WindowsDualReleaseDemoSoakOperationsPlan,
) -> DualReleaseOperationsReadiness:
    if type(plan) is not WindowsDualReleaseDemoSoakOperationsPlan:
        raise TypeError(
            "plan must be exact WindowsDualReleaseDemoSoakOperationsPlan"
        )
    return DualReleaseOperationsReadiness(
        plan_sha256=plan.plan_sha256,
        local_dual_release_plan_valid=True,
        validation_tasks_only=True,
        status="BLOCKED_EXTERNAL_ACCEPTANCE",
        external_blockers=EXTERNAL_READINESS_BLOCKERS,
    )


__all__ = [
    "DECISION_RELEASE_PROFILE",
    "EXECUTION_RELEASE_PROFILE",
    "EXTERNAL_READINESS_BLOCKERS",
    "DecisionExecutionIPCBinding",
    "DualReleaseOperationsError",
    "DualReleaseOperationsReadiness",
    "DualReleaseSecurityPosture",
    "ExternalMonitorBinding",
    "MAX_LOT",
    "ORDER_CAPABILITY",
    "SCHEMA_VERSION",
    "ServiceReleaseRoleBinding",
    "WindowsDualReleaseDemoSoakOperationsPlan",
    "assess_dual_release_operations_readiness",
]
