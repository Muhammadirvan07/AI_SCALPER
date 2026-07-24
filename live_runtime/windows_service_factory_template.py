"""Static, non-materializing Windows service factory template contract.

The module describes the exact external authority surface required by the
reviewed Windows composition root.  It never imports an external provider,
reads Windows Credential Manager, initializes MetaTrader, or constructs a
``ProductionRuntimeBootstrap``.  Successful validation is therefore evidence
of schema/binding completeness only, never execution authorization.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field
import hashlib
import json
import re
from typing import Any, Mapping


WINDOWS_FACTORY_TEMPLATE_SCHEMA = "windows-service-factory-template-v1"
WINDOWS_FACTORY_PROVIDER_CONTRACT_SCHEMA = (
    "windows-service-factory-provider-contract-v1"
)
WINDOWS_FACTORY_PROVIDER_BINDING_SCHEMA = (
    "windows-service-factory-provider-binding-v1"
)
WINDOWS_CREDENTIAL_REFERENCE_SCHEMA = "windows-credential-manager-reference-v1"
WINDOWS_TASK_SCHEDULER_BINDING_SCHEMA = "windows-task-scheduler-binding-v1"
WINDOWS_FACTORY_TEMPLATE_REPORT_SCHEMA = (
    "windows-service-factory-template-validation-v1"
)
WINDOWS_SERVICE_CONFIG_CONTRACT_SCHEMA = "windows-service-config-contract-v1"
EXTERNAL_FACTORY_PROVIDER_CONFIGURATION_BLOCKER = (
    "EXTERNAL_FACTORY_PROVIDER_CONFIGURATION_REQUIRED"
)
FACTORY_MODULE = "reviewed_windows_factory"
FACTORY_ATTRIBUTE = "build"
RELEASE_PROFILE = "WINDOWS_GATED_EXECUTION_SERVICE_V1"
CREDENTIAL_SOURCE = "WINDOWS_CREDENTIAL_MANAGER"
ORDER_CAPABILITY = "DISABLED"
FACTORY_MATERIALIZATION_ENABLED = False
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_TEMPLATE_JSON_BYTES = 262_144

_REPORT_SEAL = object()
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[a-z][a-z0-9.-]{0,95}$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TARGET_RE = re.compile(r"^AI_SCALPER/WINDOWS_SERVICE/[A-Za-z0-9._/-]{1,128}$")
_TASK_PATH_RE = re.compile(r"^\\AI_SCALPER\\[A-Za-z0-9._-]{1,64}$")
_PORT_RE = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
_PURPOSE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,95}$")

_DRAFT_FIELDS = frozenset(
    {
        "release_profile",
        "runtime_mode",
        "template_id",
        "expected_release_identity_sha256",
        "bootstrap_binding_sha256",
        "production_config_sha256",
        "service_config_file_sha256",
        "task_scheduler",
        "credential_manager_references",
        "provider_bindings",
    }
)
_TEMPLATE_FIELDS = frozenset(
    {
        "schema_version",
        "release_profile",
        "runtime_mode",
        "template_id",
        "factory_module",
        "factory_attribute",
        "expected_release_identity_sha256",
        "bootstrap_binding_sha256",
        "production_config_sha256",
        "service_config_file_sha256",
        "task_scheduler",
        "credential_manager_references",
        "credential_reference_set_sha256",
        "provider_bindings",
        "provider_binding_set_sha256",
        "provider_contract_set_sha256",
        "service_config_contract_sha256",
        "live_allowed",
        "safe_to_demo_auto_order",
        "factory_materialization_enabled",
        "order_capability",
        "template_sha256",
    }
)
_TASK_DRAFT_FIELDS = frozenset(
    {
        "task_path",
        "task_definition_sha256",
        "service_account_sid_sha256",
        "service_account_principal_sha256",
        "host_identity_sha256",
        "launcher_path_sha256",
        "release_root_path_sha256",
        "acl_policy_sha256",
        "logon_type",
        "run_level",
        "multiple_instances_policy",
    }
)
_TASK_OUTPUT_FIELDS = _TASK_DRAFT_FIELDS | frozenset(
    {"expected_release_identity_sha256", "binding_sha256", "schema_version"}
)
_CREDENTIAL_DRAFT_FIELDS = frozenset(
    {"reference_id", "target_name", "purpose", "key_id"}
)
_CREDENTIAL_OUTPUT_FIELDS = _CREDENTIAL_DRAFT_FIELDS | frozenset(
    {
        "source",
        "target_name_sha256",
        "service_account_sid_sha256",
        "reference_sha256",
        "schema_version",
    }
)
_PROVIDER_DRAFT_FIELDS = frozenset(
    {
        "port_name",
        "provider_id",
        "implementation_sha256",
        "configuration_sha256",
        "credential_reference_id",
    }
)
_PROVIDER_OUTPUT_FIELDS = _PROVIDER_DRAFT_FIELDS | frozenset(
    {
        "provider_kind",
        "provider_contract_sha256",
        "binding_sha256",
        "schema_version",
    }
)


class WindowsFactoryTemplateError(RuntimeError):
    """Stable fail-closed static-template validation error."""


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _require_mapping(
    value: object,
    fields: frozenset[str],
    code: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WindowsFactoryTemplateError(code)
    return dict(value)


def _require_list(value: object, code: str) -> list[object]:
    if not isinstance(value, list):
        raise WindowsFactoryTemplateError(code)
    return list(value)


def _require_text(value: object, code: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise WindowsFactoryTemplateError(code)
    if pattern is not None and pattern.fullmatch(value) is None:
        raise WindowsFactoryTemplateError(code)
    return value


def _require_hash(value: object) -> str:
    if (
        not isinstance(value, str)
        or _HASH_RE.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise WindowsFactoryTemplateError("HASH_INVALID")
    return value


def _unique_casefold(values: list[str], code: str) -> None:
    if len(values) != len({item.casefold() for item in values}):
        raise WindowsFactoryTemplateError(code)


@dataclass(frozen=True)
class ExternalProviderContract:
    port_name: str
    provider_kind: str
    call_contract: str
    required: bool
    credential_purpose: str | None = None
    schema_version: str = WINDOWS_FACTORY_PROVIDER_CONTRACT_SCHEMA
    contract_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if _PORT_RE.fullmatch(self.port_name) is None:
            raise ValueError("provider contract port name is invalid")
        if self.provider_kind not in {"CALLABLE", "COMPONENT"}:
            raise ValueError("provider contract kind is invalid")
        if not isinstance(self.call_contract, str) or not self.call_contract:
            raise ValueError("provider call contract is invalid")
        if type(self.required) is not bool:
            raise TypeError("provider required flag must be bool")
        if self.credential_purpose is not None and (
            not isinstance(self.credential_purpose, str)
            or _PURPOSE_RE.fullmatch(self.credential_purpose) is None
        ):
            raise ValueError("provider credential purpose is invalid")
        if self.schema_version != WINDOWS_FACTORY_PROVIDER_CONTRACT_SCHEMA:
            raise ValueError("provider contract schema is invalid")
        object.__setattr__(
            self,
            "contract_sha256",
            _canonical_hash(
                {
                    "port_name": self.port_name,
                    "provider_kind": self.provider_kind,
                    "call_contract": self.call_contract,
                    "required": self.required,
                    "credential_purpose": self.credential_purpose,
                    "schema_version": self.schema_version,
                }
            ),
        )


# The strings are review contracts, not dynamically evaluated annotations.
_PROVIDER_CONTRACT_SPECS: tuple[tuple[str, str, str, bool, str | None], ...] = (
    (
        "credential_session_provider",
        "CALLABLE",
        "Callable[[], VerifiedCredentialSession]",
        True,
        "MT5_DEMO_SESSION",
    ),
    (
        "external_receipt_key_provider",
        "CALLABLE",
        "Callable[[str], str|bytes]",
        True,
        "BOOTSTRAP_EXTERNAL_RECEIPT_HMAC",
    ),
    (
        "journal_provisioning_provider",
        "CALLABLE",
        "Callable[[], VerifiedBootstrapExternalReceipt]",
        True,
        None,
    ),
    (
        "worm_audit_provider",
        "CALLABLE",
        "Callable[[], VerifiedBootstrapExternalReceipt]",
        True,
        None,
    ),
    ("risk_ledger", "COMPONENT", "RiskLedgerProtocol", True, None),
    (
        "risk_ledger_key_provider",
        "CALLABLE",
        "Callable[[str], str|bytes]",
        True,
        "RISK_LEDGER_HMAC",
    ),
    (
        "risk_source_provider",
        "CALLABLE",
        "Callable[[], RiskSourceReceipt]",
        True,
        None,
    ),
    (
        "risk_checkpoint_provider",
        "CALLABLE",
        "Callable[[], RiskStateReceipt]",
        True,
        None,
    ),
    (
        "risk_checkpoint_exporter",
        "CALLABLE",
        "Callable[[str,RiskStateReceipt],RiskStateCheckpointCASAcknowledgement]",
        True,
        None,
    ),
    (
        "journal_checkpoint_provider",
        "CALLABLE",
        "Callable[[], ExecutionJournalCheckpoint]",
        True,
        None,
    ),
    (
        "journal_checkpoint_key_provider",
        "CALLABLE",
        "Callable[[str], str|bytes]",
        True,
        "JOURNAL_CHECKPOINT_HMAC",
    ),
    (
        "external_journal_checkpoint_provider",
        "CALLABLE",
        "Callable[[], ExecutionJournalCheckpoint|None]",
        True,
        None,
    ),
    (
        "journal_checkpoint_exporter",
        "CALLABLE",
        "Callable[[str,ExecutionJournalCheckpoint],ExecutionJournalCheckpointCASAcknowledgement]",
        True,
        None,
    ),
    (
        "supervisor_checkpoint_provider",
        "CALLABLE",
        "Callable[[], RuntimeSupervisorCheckpoint|None]",
        True,
        None,
    ),
    (
        "supervisor_checkpoint_exporter",
        "CALLABLE",
        "Callable[[str,RuntimeSupervisorCheckpoint],RuntimeSupervisorCheckpointCASAcknowledgement]",
        True,
        None,
    ),
    (
        "supervisor_key_provider",
        "CALLABLE",
        "Callable[[str], str|bytes]",
        True,
        "SUPERVISOR_RECEIPT_HMAC",
    ),
    (
        "supervisor_checkpoint_key_provider",
        "CALLABLE",
        "Callable[[str], str|bytes]",
        True,
        "SUPERVISOR_CHECKPOINT_HMAC",
    ),
    (
        "reconciliation_provider",
        "CALLABLE",
        "Callable[[], RuntimeReconciliationRiskResult]",
        True,
        None,
    ),
    (
        "broker_reconciliation_receipt_verifier",
        "CALLABLE",
        "Callable[[BrokerReconciliationReceipt,ReconciliationResult],BrokerReconciliationReceipt]",
        True,
        None,
    ),
    (
        "broker_deal_receipt_verifier",
        "CALLABLE",
        "Callable[[BrokerDealReceipt,BrokerReconciliationReceipt],BrokerDealReceipt]",
        True,
        None,
    ),
    (
        "broker_closed_trade_receipt_verifier",
        "CALLABLE",
        "Callable[[BrokerClosedTradeReceipt,BrokerReconciliationReceipt],BrokerClosedTradeReceipt]",
        True,
        None,
    ),
    (
        "runtime_fact_provider",
        "CALLABLE",
        "Callable[[], Sequence[object]]",
        True,
        None,
    ),
    (
        "runtime_fact_verifier",
        "CALLABLE",
        "Callable[[object], object]",
        True,
        None,
    ),
    (
        "news_guard_provider",
        "CALLABLE",
        "Callable[[], RuntimeNewsGuardReceipt]",
        True,
        None,
    ),
    (
        "news_guard_key_provider",
        "CALLABLE",
        "Callable[[str], str|bytes]",
        True,
        "NEWS_GUARD_HMAC",
    ),
    (
        "decision_provider",
        "CALLABLE",
        "Callable[[tuple[object,...],RiskStateReceipt],RuntimeSupervisorDecision]",
        True,
        None,
    ),
    ("stage_binding", "COMPONENT", "StageBinding", True, None),
    (
        "stage_authorization_ports_provider",
        "CALLABLE",
        "Callable[[], RuntimeStageAuthorizationPorts]",
        True,
        None,
    ),
    (
        "permit_secret_provider",
        "CALLABLE",
        "Callable[[], str|bytes]",
        True,
        "PROMOTION_PERMIT_HMAC",
    ),
    (
        "manual_approval_provider",
        "CALLABLE",
        "Callable[[RuntimeSupervisorDecision], object]",
        True,
        None,
    ),
    (
        "manual_demo_policy_callback",
        "CALLABLE",
        "Callable[[RuntimeSupervisorDecision,object], bool]",
        True,
        None,
    ),
    (
        "execution_cycle_provider",
        "CALLABLE",
        "Callable[[LiveRuntimeService,RuntimeSupervisorDecision,object],RuntimeManualDemoExecutionResult]",
        True,
        None,
    ),
    (
        "clock_provider",
        "CALLABLE",
        "Callable[[], datetime]",
        True,
        None,
    ),
    (
        "promotion_evidence_key_provider",
        "CALLABLE",
        "Callable[[str], str|bytes]|None",
        False,
        "PROMOTION_EVIDENCE_HMAC",
    ),
    (
        "manual_approval_key_provider",
        "CALLABLE",
        "Callable[[str], str|bytes]|None",
        False,
        "MANUAL_APPROVAL_HMAC",
    ),
    (
        "demo_auto_ipc_input_provider",
        "CALLABLE",
        "Callable[[RuntimeSupervisorDecision], object]|None",
        False,
        None,
    ),
    (
        "demo_auto_session_lease_provider",
        "CALLABLE",
        "Callable[[RuntimeSupervisorDecision,object], object]|None",
        False,
        None,
    ),
    (
        "demo_auto_session_store",
        "COMPONENT",
        "DemoAutoSessionCapabilityStore|None",
        False,
        None,
    ),
    (
        "demo_auto_permit_validation_provider",
        "CALLABLE",
        "Callable[[RuntimeSupervisorDecision,object], object]|None",
        False,
        None,
    ),
    (
        "demo_auto_promotion_validation_provider",
        "CALLABLE",
        "Callable[[RuntimeSupervisorDecision,object], object]|None",
        False,
        None,
    ),
    (
        "demo_auto_environment_arm_provider",
        "CALLABLE",
        "Callable[[RuntimeSupervisorDecision,object], object]|None",
        False,
        None,
    ),
    (
        "demo_auto_execution_cycle_provider",
        "CALLABLE",
        "Callable[...,RuntimeDemoAutoExecutionResult]|None",
        False,
        None,
    ),
    ("heartbeat_outbox", "COMPONENT", "DeliveryOutbox", True, None),
    (
        "heartbeat_transport",
        "COMPONENT",
        "OffHostTransportProtocol",
        True,
        None,
    ),
    (
        "heartbeat_sender_key_provider",
        "CALLABLE",
        "Callable[[str], str|bytes]",
        True,
        "HEARTBEAT_SENDER_HMAC",
    ),
    (
        "heartbeat_remote_key_provider",
        "CALLABLE",
        "Callable[[str], str|bytes]",
        True,
        "HEARTBEAT_REMOTE_ACK_HMAC",
    ),
)

_PROVIDER_CONTRACTS = tuple(
    ExternalProviderContract(*spec) for spec in _PROVIDER_CONTRACT_SPECS
)
_CONTRACT_BY_PORT = {item.port_name: item for item in _PROVIDER_CONTRACTS}
_DEMO_AUTO_PROVIDER_PORTS = frozenset(
    {
        "promotion_evidence_key_provider",
        "demo_auto_ipc_input_provider",
        "demo_auto_session_lease_provider",
        "demo_auto_session_store",
        "demo_auto_permit_validation_provider",
        "demo_auto_promotion_validation_provider",
        "demo_auto_environment_arm_provider",
        "demo_auto_execution_cycle_provider",
    }
)

_SERVICE_CONFIG_CONTRACT: dict[str, object] = {
    "fields": {
        "service_id": {"type": "CANONICAL_ID"},
        "owner_id": {"type": "CANONICAL_ID"},
        "max_cycles": {"type": "INTEGER", "minimum": 1, "maximum": 100_000},
        "lease_seconds": {"type": "INTEGER", "minimum": 1, "maximum": 300},
        "heartbeat_ttl_seconds": {
            "type": "INTEGER",
            "minimum": 2,
            "maximum": 30,
        },
        "cycle_interval_seconds": {
            "type": "NUMBER",
            "minimum": 0.25,
            "maximum": "MIN(15,heartbeat_ttl_seconds/2)",
        },
        "cycle_deadline_seconds": {
            "type": "NUMBER",
            "minimum": 1,
            "maximum": "heartbeat_ttl_seconds",
        },
    },
    "additional_fields": False,
    "credential_fields_allowed": False,
    "schema_version": WINDOWS_SERVICE_CONFIG_CONTRACT_SCHEMA,
}
WINDOWS_SERVICE_CONFIG_CONTRACT_SHA256 = _canonical_hash(_SERVICE_CONFIG_CONTRACT)


def _provider_contract_payload(contract: ExternalProviderContract) -> dict[str, object]:
    return {
        "port_name": contract.port_name,
        "provider_kind": contract.provider_kind,
        "call_contract": contract.call_contract,
        "required": contract.required,
        "credential_purpose": contract.credential_purpose,
        "schema_version": contract.schema_version,
        "contract_sha256": contract.contract_sha256,
    }


WINDOWS_FACTORY_PROVIDER_CONTRACT_SET_SHA256 = _canonical_hash(
    [_provider_contract_payload(item) for item in _PROVIDER_CONTRACTS]
)


def provider_contracts() -> tuple[ExternalProviderContract, ...]:
    """Return the immutable, release-local external provider surface."""

    return _PROVIDER_CONTRACTS


def windows_service_config_contract() -> dict[str, object]:
    """Return an isolated copy of the exact non-secret service config schema."""

    return json.loads(_canonical_bytes(_SERVICE_CONFIG_CONTRACT))


def _task_scheduler_output(
    value: object,
    *,
    expected_release_identity_sha256: str,
    output: bool,
) -> dict[str, Any]:
    fields = _TASK_OUTPUT_FIELDS if output else _TASK_DRAFT_FIELDS
    task = _require_mapping(value, fields, "TASK_SCHEDULER_SCHEMA_INVALID")
    task_path = _require_text(
        task["task_path"], "TASK_SCHEDULER_PATH_INVALID", _TASK_PATH_RE
    )
    hashes = {
        name: _require_hash(task[name])
        for name in (
            "task_definition_sha256",
            "service_account_sid_sha256",
            "service_account_principal_sha256",
            "host_identity_sha256",
            "launcher_path_sha256",
            "release_root_path_sha256",
            "acl_policy_sha256",
        )
    }
    if task["logon_type"] != "SERVICE_ACCOUNT":
        raise WindowsFactoryTemplateError("TASK_SCHEDULER_LOGON_TYPE_INVALID")
    if task["run_level"] != "LIMITED":
        raise WindowsFactoryTemplateError("TASK_SCHEDULER_RUN_LEVEL_INVALID")
    if task["multiple_instances_policy"] != "IGNORE_NEW":
        raise WindowsFactoryTemplateError("TASK_SCHEDULER_INSTANCE_POLICY_INVALID")
    result = {
        "task_path": task_path,
        **hashes,
        "expected_release_identity_sha256": expected_release_identity_sha256,
        "logon_type": "SERVICE_ACCOUNT",
        "run_level": "LIMITED",
        "multiple_instances_policy": "IGNORE_NEW",
        "schema_version": WINDOWS_TASK_SCHEDULER_BINDING_SCHEMA,
    }
    result["binding_sha256"] = _canonical_hash(result)
    if output:
        if task["schema_version"] != WINDOWS_TASK_SCHEDULER_BINDING_SCHEMA:
            raise WindowsFactoryTemplateError("TASK_SCHEDULER_SCHEMA_INVALID")
        if task["expected_release_identity_sha256"] != expected_release_identity_sha256:
            raise WindowsFactoryTemplateError("TASK_SCHEDULER_RELEASE_IDENTITY_MISMATCH")
        if task["binding_sha256"] != result["binding_sha256"]:
            raise WindowsFactoryTemplateError("TASK_SCHEDULER_BINDING_HASH_MISMATCH")
    return result


def _credential_outputs(
    values: object,
    *,
    service_account_sid_sha256: str,
    output: bool,
) -> list[dict[str, Any]]:
    items = _require_list(values, "CREDENTIAL_REFERENCE_LIST_INVALID")
    maximum_credentials = sum(
        item.credential_purpose is not None for item in _PROVIDER_CONTRACTS
    )
    # Permit one extra entry so duplicate/unknown diagnostics remain precise;
    # larger payloads are rejected before per-item work.
    if len(items) > maximum_credentials + 1:
        raise WindowsFactoryTemplateError("CREDENTIAL_REFERENCE_LIST_INVALID")
    raw_items = [
        _require_mapping(
            raw,
            _CREDENTIAL_OUTPUT_FIELDS if output else _CREDENTIAL_DRAFT_FIELDS,
            "CREDENTIAL_REFERENCE_SCHEMA_INVALID",
        )
        for raw in items
    ]
    raw_identifiers = [
        item.get("reference_id")
        for item in raw_items
        if isinstance(item.get("reference_id"), str)
    ]
    if len(raw_identifiers) == len(raw_items):
        _unique_casefold(raw_identifiers, "DUPLICATE_CREDENTIAL_REFERENCE")
    result: list[dict[str, Any]] = []
    identifiers: list[str] = []
    targets: list[str] = []
    key_ids: list[str] = []
    for item in raw_items:
        reference_id = _require_text(
            item["reference_id"], "CREDENTIAL_REFERENCE_ID_INVALID", _ID_RE
        )
        target = _require_text(
            item["target_name"], "CREDENTIAL_TARGET_INVALID", _TARGET_RE
        )
        if "//" in target or "/../" in target or target.endswith("/.."):
            raise WindowsFactoryTemplateError("CREDENTIAL_TARGET_INVALID")
        purpose = _require_text(item["purpose"], "CREDENTIAL_PURPOSE_INVALID")
        key_id = _require_text(
            item["key_id"], "CREDENTIAL_KEY_ID_INVALID", _KEY_ID_RE
        )
        normalized = {
            "reference_id": reference_id,
            "source": CREDENTIAL_SOURCE,
            "target_name": target,
            "target_name_sha256": _canonical_hash({"target_name": target}),
            "purpose": purpose,
            "key_id": key_id,
            "service_account_sid_sha256": service_account_sid_sha256,
            "schema_version": WINDOWS_CREDENTIAL_REFERENCE_SCHEMA,
        }
        normalized["reference_sha256"] = _canonical_hash(normalized)
        if output:
            if item["source"] != CREDENTIAL_SOURCE:
                raise WindowsFactoryTemplateError("CREDENTIAL_SOURCE_INVALID")
            if item["service_account_sid_sha256"] != service_account_sid_sha256:
                raise WindowsFactoryTemplateError(
                    "CREDENTIAL_SERVICE_IDENTITY_MISMATCH"
                )
            if item["schema_version"] != WINDOWS_CREDENTIAL_REFERENCE_SCHEMA:
                raise WindowsFactoryTemplateError("CREDENTIAL_REFERENCE_SCHEMA_INVALID")
            if item["target_name_sha256"] != normalized["target_name_sha256"]:
                raise WindowsFactoryTemplateError("CREDENTIAL_TARGET_HASH_MISMATCH")
            if item["reference_sha256"] != normalized["reference_sha256"]:
                raise WindowsFactoryTemplateError("CREDENTIAL_REFERENCE_HASH_MISMATCH")
        identifiers.append(reference_id)
        targets.append(target)
        key_ids.append(key_id)
        result.append(normalized)
    _unique_casefold(identifiers, "DUPLICATE_CREDENTIAL_REFERENCE")
    _unique_casefold(targets, "DUPLICATE_CREDENTIAL_TARGET")
    _unique_casefold(key_ids, "DUPLICATE_CREDENTIAL_KEY_ID")
    return sorted(result, key=lambda item: item["reference_id"])


def _provider_outputs(
    values: object,
    *,
    credential_references: list[dict[str, Any]],
    runtime_mode: str,
    output: bool,
) -> list[dict[str, Any]]:
    items = _require_list(values, "PROVIDER_BINDING_LIST_INVALID")
    if len(items) > len(_PROVIDER_CONTRACTS) + 1:
        raise WindowsFactoryTemplateError("PROVIDER_BINDING_LIST_INVALID")
    raw_items = [
        _require_mapping(
            raw,
            _PROVIDER_OUTPUT_FIELDS if output else _PROVIDER_DRAFT_FIELDS,
            "PROVIDER_BINDING_SCHEMA_INVALID",
        )
        for raw in items
    ]
    raw_names = [
        item.get("port_name")
        for item in raw_items
        if isinstance(item.get("port_name"), str)
    ]
    if len(raw_names) == len(raw_items):
        _unique_casefold(raw_names, "DUPLICATE_PROVIDER")
    credentials = {item["reference_id"]: item for item in credential_references}
    bindings: list[dict[str, Any]] = []
    names: list[str] = []
    provider_ids: list[str] = []
    used_credentials: list[str] = []
    for item in raw_items:
        port_name = _require_text(item["port_name"], "PROVIDER_PORT_INVALID")
        contract = _CONTRACT_BY_PORT.get(port_name)
        if contract is None:
            raise WindowsFactoryTemplateError("UNKNOWN_PROVIDER")
        provider_id = _require_text(
            item["provider_id"], "PROVIDER_ID_INVALID", _ID_RE
        )
        implementation_hash = _require_hash(item["implementation_sha256"])
        configuration_hash = _require_hash(item["configuration_sha256"])
        reference_id = item["credential_reference_id"]
        if contract.credential_purpose is None:
            if reference_id is not None:
                raise WindowsFactoryTemplateError("CREDENTIAL_REFERENCE_FORBIDDEN")
        else:
            if not isinstance(reference_id, str) or not reference_id:
                raise WindowsFactoryTemplateError("CREDENTIAL_REFERENCE_REQUIRED")
            credential = credentials.get(reference_id)
            if credential is None:
                raise WindowsFactoryTemplateError("CREDENTIAL_REFERENCE_REQUIRED")
            if credential["purpose"] != contract.credential_purpose:
                raise WindowsFactoryTemplateError("CREDENTIAL_PURPOSE_MISMATCH")
            used_credentials.append(reference_id)
        normalized = {
            "port_name": port_name,
            "provider_id": provider_id,
            "provider_kind": contract.provider_kind,
            "implementation_sha256": implementation_hash,
            "configuration_sha256": configuration_hash,
            "provider_contract_sha256": contract.contract_sha256,
            "credential_reference_id": reference_id,
            "schema_version": WINDOWS_FACTORY_PROVIDER_BINDING_SCHEMA,
        }
        normalized["binding_sha256"] = _canonical_hash(normalized)
        if output:
            if item["provider_kind"] != contract.provider_kind:
                raise WindowsFactoryTemplateError("PROVIDER_KIND_MISMATCH")
            if item["provider_contract_sha256"] != contract.contract_sha256:
                raise WindowsFactoryTemplateError("PROVIDER_CONTRACT_HASH_MISMATCH")
            if item["schema_version"] != WINDOWS_FACTORY_PROVIDER_BINDING_SCHEMA:
                raise WindowsFactoryTemplateError("PROVIDER_BINDING_SCHEMA_INVALID")
            if item["binding_sha256"] != normalized["binding_sha256"]:
                raise WindowsFactoryTemplateError("PROVIDER_BINDING_HASH_MISMATCH")
        names.append(port_name)
        provider_ids.append(provider_id)
        bindings.append(normalized)
    _unique_casefold(names, "DUPLICATE_PROVIDER")
    _unique_casefold(provider_ids, "DUPLICATE_PROVIDER_ID")
    required = {
        item.port_name for item in _PROVIDER_CONTRACTS if item.required
    }
    if runtime_mode == "DEMO_AUTO":
        required.update(_DEMO_AUTO_PROVIDER_PORTS)
    missing = required.difference(names)
    if missing:
        raise WindowsFactoryTemplateError("REQUIRED_PROVIDER_MISSING")
    _unique_casefold(used_credentials, "CREDENTIAL_REFERENCE_REUSED")
    if set(used_credentials) != set(credentials):
        raise WindowsFactoryTemplateError("UNUSED_CREDENTIAL_REFERENCE")
    return sorted(bindings, key=lambda item: item["port_name"])


def _template_from_draft(payload: Mapping[str, object]) -> dict[str, Any]:
    draft = _require_mapping(payload, _DRAFT_FIELDS, "TEMPLATE_SCHEMA_INVALID")
    release_profile = _require_text(
        draft["release_profile"], "RELEASE_PROFILE_INVALID"
    )
    if release_profile != RELEASE_PROFILE:
        raise WindowsFactoryTemplateError("RELEASE_PROFILE_INVALID")
    runtime_mode = _require_text(draft["runtime_mode"], "RUNTIME_MODE_INVALID")
    if runtime_mode not in {"DEMO", "DEMO_AUTO"}:
        raise WindowsFactoryTemplateError("RUNTIME_MODE_INVALID")
    template_id = _require_text(draft["template_id"], "TEMPLATE_ID_INVALID", _ID_RE)
    release_identity = _require_hash(draft["expected_release_identity_sha256"])
    bootstrap_binding = _require_hash(draft["bootstrap_binding_sha256"])
    production_config = _require_hash(draft["production_config_sha256"])
    service_config = _require_hash(draft["service_config_file_sha256"])
    task = _task_scheduler_output(
        draft["task_scheduler"],
        expected_release_identity_sha256=release_identity,
        output=False,
    )
    credentials = _credential_outputs(
        draft["credential_manager_references"],
        service_account_sid_sha256=task["service_account_sid_sha256"],
        output=False,
    )
    providers = _provider_outputs(
        draft["provider_bindings"],
        credential_references=credentials,
        runtime_mode=runtime_mode,
        output=False,
    )
    result = {
        "schema_version": WINDOWS_FACTORY_TEMPLATE_SCHEMA,
        "release_profile": release_profile,
        "runtime_mode": runtime_mode,
        "template_id": template_id,
        "factory_module": FACTORY_MODULE,
        "factory_attribute": FACTORY_ATTRIBUTE,
        "expected_release_identity_sha256": release_identity,
        "bootstrap_binding_sha256": bootstrap_binding,
        "production_config_sha256": production_config,
        "service_config_file_sha256": service_config,
        "task_scheduler": task,
        "credential_manager_references": credentials,
        "credential_reference_set_sha256": _canonical_hash(credentials),
        "provider_bindings": providers,
        "provider_binding_set_sha256": _canonical_hash(providers),
        "provider_contract_set_sha256": (
            WINDOWS_FACTORY_PROVIDER_CONTRACT_SET_SHA256
        ),
        "service_config_contract_sha256": (
            WINDOWS_SERVICE_CONFIG_CONTRACT_SHA256
        ),
        "live_allowed": LIVE_ALLOWED,
        "safe_to_demo_auto_order": SAFE_TO_DEMO_AUTO_ORDER,
        "factory_materialization_enabled": FACTORY_MATERIALIZATION_ENABLED,
        "order_capability": ORDER_CAPABILITY,
    }
    result["template_sha256"] = _canonical_hash(result)
    return result


def generate_windows_service_factory_template(
    payload: Mapping[str, object],
) -> bytes:
    """Generate canonical, non-secret template JSON without materialization."""

    if not isinstance(payload, Mapping):
        raise WindowsFactoryTemplateError("TEMPLATE_SCHEMA_INVALID")
    return _canonical_bytes(_template_from_draft(payload))


def _strict_json(value: bytes | str) -> dict[str, Any]:
    raw_size = len(value) if isinstance(value, bytes) else len(value.encode("utf-8"))
    if raw_size > MAX_TEMPLATE_JSON_BYTES:
        raise WindowsFactoryTemplateError("TEMPLATE_JSON_TOO_LARGE")
    try:
        text = value.decode("utf-8") if isinstance(value, bytes) else value
    except UnicodeDecodeError as exc:
        raise WindowsFactoryTemplateError("TEMPLATE_JSON_INVALID") from exc
    if not isinstance(text, str):
        raise WindowsFactoryTemplateError("TEMPLATE_JSON_INVALID")

    def exact_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise WindowsFactoryTemplateError("DUPLICATE_JSON_KEY")
            result[key] = item
        return result

    try:
        payload = json.loads(text, object_pairs_hook=exact_object)
    except WindowsFactoryTemplateError:
        raise
    except json.JSONDecodeError as exc:
        raise WindowsFactoryTemplateError("TEMPLATE_JSON_INVALID") from exc
    if not isinstance(payload, dict):
        raise WindowsFactoryTemplateError("TEMPLATE_SCHEMA_INVALID")
    return payload


@dataclass(frozen=True)
class WindowsServiceFactoryTemplateValidationReport:
    template_valid: bool
    runtime_mode: str
    template_sha256: str
    expected_release_identity_sha256: str
    bootstrap_binding_sha256: str
    production_config_sha256: str
    service_config_file_sha256: str
    task_scheduler_binding_sha256: str
    provider_binding_set_sha256: str
    provider_contract_set_sha256: str
    service_config_contract_sha256: str
    credential_reference_set_sha256: str
    provider_count: int
    credential_reference_count: int
    readiness_blockers: tuple[str, ...]
    production_execution_ready: bool = False
    factory_imported: bool = False
    credential_manager_read: bool = False
    broker_component_materialized: bool = False
    broker_mutation_performed: bool = False
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    factory_materialization_enabled: bool = FACTORY_MATERIALIZATION_ENABLED
    order_capability: str = ORDER_CAPABILITY
    schema_version: str = WINDOWS_FACTORY_TEMPLATE_REPORT_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _REPORT_SEAL:
            raise TypeError("factory template report requires validator seal")
        if (
            not self.template_valid
            or self.production_execution_ready
            or self.factory_imported
            or self.credential_manager_read
            or self.broker_component_materialized
            or self.broker_mutation_performed
            or self.live_allowed
            or self.safe_to_demo_auto_order
            or self.factory_materialization_enabled
            or self.order_capability != ORDER_CAPABILITY
        ):
            raise ValueError("factory template report cannot grant execution")


def validate_windows_service_factory_template(
    payload: Mapping[str, object] | bytes | str,
) -> WindowsServiceFactoryTemplateValidationReport:
    """Validate one exact template without resolving any external authority."""

    raw = _strict_json(payload) if isinstance(payload, (bytes, str)) else payload
    template = _require_mapping(raw, _TEMPLATE_FIELDS, "TEMPLATE_SCHEMA_INVALID")
    if template["schema_version"] != WINDOWS_FACTORY_TEMPLATE_SCHEMA:
        raise WindowsFactoryTemplateError("TEMPLATE_SCHEMA_INVALID")
    if template["factory_module"] != FACTORY_MODULE:
        raise WindowsFactoryTemplateError("FACTORY_MODULE_INVALID")
    if template["factory_attribute"] != FACTORY_ATTRIBUTE:
        raise WindowsFactoryTemplateError("FACTORY_ATTRIBUTE_INVALID")
    if template["live_allowed"] is not False:
        raise WindowsFactoryTemplateError("LIVE_LOCK_INVALID")
    if template["safe_to_demo_auto_order"] is not False:
        raise WindowsFactoryTemplateError("DEMO_AUTO_LOCK_INVALID")
    if template["factory_materialization_enabled"] is not False:
        raise WindowsFactoryTemplateError("FACTORY_MATERIALIZATION_LOCK_INVALID")
    if template["order_capability"] != ORDER_CAPABILITY:
        raise WindowsFactoryTemplateError("ORDER_CAPABILITY_INVALID")
    release_profile = _require_text(
        template["release_profile"], "RELEASE_PROFILE_INVALID"
    )
    if release_profile != RELEASE_PROFILE:
        raise WindowsFactoryTemplateError("RELEASE_PROFILE_INVALID")
    runtime_mode = _require_text(
        template["runtime_mode"], "RUNTIME_MODE_INVALID"
    )
    if runtime_mode not in {"DEMO", "DEMO_AUTO"}:
        raise WindowsFactoryTemplateError("RUNTIME_MODE_INVALID")
    _require_text(template["template_id"], "TEMPLATE_ID_INVALID", _ID_RE)
    release_identity = _require_hash(template["expected_release_identity_sha256"])
    bootstrap_binding = _require_hash(template["bootstrap_binding_sha256"])
    production_config = _require_hash(template["production_config_sha256"])
    service_config = _require_hash(template["service_config_file_sha256"])
    task = _task_scheduler_output(
        template["task_scheduler"],
        expected_release_identity_sha256=release_identity,
        output=True,
    )
    credentials = _credential_outputs(
        template["credential_manager_references"],
        service_account_sid_sha256=task["service_account_sid_sha256"],
        output=True,
    )
    providers = _provider_outputs(
        template["provider_bindings"],
        credential_references=credentials,
        runtime_mode=runtime_mode,
        output=True,
    )
    credential_set_hash = _canonical_hash(credentials)
    provider_set_hash = _canonical_hash(providers)
    if template["credential_reference_set_sha256"] != credential_set_hash:
        raise WindowsFactoryTemplateError("CREDENTIAL_SET_HASH_MISMATCH")
    if template["provider_binding_set_sha256"] != provider_set_hash:
        raise WindowsFactoryTemplateError("PROVIDER_SET_HASH_MISMATCH")
    if (
        template["provider_contract_set_sha256"]
        != WINDOWS_FACTORY_PROVIDER_CONTRACT_SET_SHA256
    ):
        raise WindowsFactoryTemplateError("PROVIDER_CONTRACT_SET_HASH_MISMATCH")
    if (
        template["service_config_contract_sha256"]
        != WINDOWS_SERVICE_CONFIG_CONTRACT_SHA256
    ):
        raise WindowsFactoryTemplateError("SERVICE_CONFIG_CONTRACT_HASH_MISMATCH")
    unsigned = dict(template)
    template_hash = _require_hash(unsigned.pop("template_sha256"))
    if template_hash != _canonical_hash(unsigned):
        raise WindowsFactoryTemplateError("TEMPLATE_HASH_MISMATCH")
    return WindowsServiceFactoryTemplateValidationReport(
        template_valid=True,
        runtime_mode=runtime_mode,
        template_sha256=template_hash,
        expected_release_identity_sha256=release_identity,
        bootstrap_binding_sha256=bootstrap_binding,
        production_config_sha256=production_config,
        service_config_file_sha256=service_config,
        task_scheduler_binding_sha256=task["binding_sha256"],
        provider_binding_set_sha256=provider_set_hash,
        provider_contract_set_sha256=(
            WINDOWS_FACTORY_PROVIDER_CONTRACT_SET_SHA256
        ),
        service_config_contract_sha256=WINDOWS_SERVICE_CONFIG_CONTRACT_SHA256,
        credential_reference_set_sha256=credential_set_hash,
        provider_count=len(providers),
        credential_reference_count=len(credentials),
        readiness_blockers=(
            EXTERNAL_FACTORY_PROVIDER_CONFIGURATION_BLOCKER,
            "EXTERNAL_PROVIDER_IMPLEMENTATION_ATTESTATION_REQUIRED",
            "TASK_SCHEDULER_REGISTRATION_ATTESTATION_REQUIRED",
        ),
        _seal=_REPORT_SEAL,
    )


__all__ = [
    "CREDENTIAL_SOURCE",
    "EXTERNAL_FACTORY_PROVIDER_CONFIGURATION_BLOCKER",
    "ExternalProviderContract",
    "FACTORY_ATTRIBUTE",
    "FACTORY_MATERIALIZATION_ENABLED",
    "FACTORY_MODULE",
    "LIVE_ALLOWED",
    "MAX_TEMPLATE_JSON_BYTES",
    "ORDER_CAPABILITY",
    "RELEASE_PROFILE",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "WINDOWS_FACTORY_TEMPLATE_SCHEMA",
    "WINDOWS_FACTORY_PROVIDER_CONTRACT_SET_SHA256",
    "WINDOWS_SERVICE_CONFIG_CONTRACT_SHA256",
    "WindowsFactoryTemplateError",
    "WindowsServiceFactoryTemplateValidationReport",
    "generate_windows_service_factory_template",
    "provider_contracts",
    "validate_windows_service_factory_template",
    "windows_service_config_contract",
]
