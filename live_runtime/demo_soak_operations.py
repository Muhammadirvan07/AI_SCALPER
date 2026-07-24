"""Deny-only Windows operations plan for manual-demo and demo-soak preparation.

This module is deliberately side-effect free.  It validates immutable deployment
metadata, renders reviewable Task Scheduler definitions, and evaluates signed
failure-drill observations.  It never installs a task, reads a credential,
launches a process, connects to MT5, or enables broker mutation.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
import hashlib
import hmac
import json
import math
from pathlib import PureWindowsPath
import re
from typing import Any, Callable, Iterable, Mapping, Sequence
from xml.sax.saxutils import escape as xml_escape

from .contracts import canonical_sha256, require_hash, require_text, require_utc


SCHEMA_VERSION = "windows-demo-soak-operations-v1"
ORDER_CAPABILITY = "DISABLED"
MAX_LOT = 0.01
PROCESS_ROLES = frozenset({"DECISION_RUNTIME", "EXECUTOR_RECONCILER"})
REQUIRED_CREDENTIAL_PURPOSES = frozenset(
    {
        "BROKER_ACCOUNT",
        "SUPERVISOR_HMAC",
        "JOURNAL_HMAC",
        "RISK_LEDGER_HMAC",
        "MANUAL_DEMO_HMAC",
        "MANUAL_DEMO_CUSTODY_HMAC",
        "SOAK_TRACKER_HMAC",
        "OFFHOST_DELIVERY_HMAC",
    }
)
REQUIRED_DRILLS = (
    "VPS_REBOOT",
    "MT5_RESTART",
    "NETWORK_PARTITION",
    "DISK_FULL",
    "SQLITE_CONTENTION",
    "SQLITE_CORRUPTION",
    "CLOCK_DRIFT",
    "RELEASE_ROLLBACK",
)

_PROVIDER_ID_RE = re.compile(r"^[a-z][a-z0-9._:-]{2,127}$")
_TASK_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,96}$")
_EVENT_SOURCE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_. -]{2,95}$")
_PYTHON_VERSION_RE = re.compile(r"^3\.12\.[0-9]+$")
_GIT_HASH_RE = re.compile(r"^[0-9a-f]{40}$")
_SENSITIVE_KEY_RE = re.compile(
    r"(?:password|passwd|passphrase|secret|private[_-]?key|api[_-]?(?:key|token)|access[_-]?token|refresh[_-]?token|broker[_-]?login)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE_RE = re.compile(
    r"(?:--(?:password|secret|token|api-key)|(?:password|secret|token|api[_-]?key|login)\s*=)",
    re.IGNORECASE,
)


class DemoSoakOperationsError(ValueError):
    """Fail-closed configuration or observation error with a stable reason code."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = require_text("reason_code", reason_code, upper=True)
        super().__init__(self.reason_code)


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _key(secret: str | bytes) -> bytes:
    if isinstance(secret, str):
        value = secret.encode("utf-8")
    elif isinstance(secret, bytes):
        value = secret
    else:
        raise TypeError("failure-drill signing key must be str or bytes")
    if len(value) < 32:
        raise ValueError("failure-drill signing key must contain at least 32 bytes")
    return value


def _require_bool(name: str, value: object, expected: bool | None = None) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{name} must be bool")
    if expected is not None and value is not expected:
        raise DemoSoakOperationsError(f"{name.upper()}_MUST_BE_{str(expected).upper()}")
    return value


def _require_provider_id(name: str, value: object) -> str:
    normalized = require_text(name, value).lower()
    if "://" in normalized or _PROVIDER_ID_RE.fullmatch(normalized) is None:
        raise DemoSoakOperationsError(f"{name.upper()}_PROVIDER_ID_REQUIRED")
    return normalized


def _require_git_hash(name: str, value: object) -> str:
    normalized = require_text(name, value).lower()
    if _GIT_HASH_RE.fullmatch(normalized) is None:
        raise DemoSoakOperationsError(f"{name.upper()}_FULL_GIT_SHA_REQUIRED")
    return normalized


def _normalize_windows_path(name: str, value: object) -> str:
    normalized = require_text(name, value).replace("/", "\\")
    path = PureWindowsPath(normalized)
    if not path.is_absolute() or not path.drive or path.anchor.startswith("\\\\"):
        raise DemoSoakOperationsError(f"{name.upper()}_LOCAL_ABSOLUTE_PATH_REQUIRED")
    if any(part in {".", ".."} for part in path.parts):
        raise DemoSoakOperationsError(f"{name.upper()}_PATH_TRAVERSAL_REJECTED")
    return str(path)


def _path_key(value: str) -> str:
    return str(PureWindowsPath(value)).rstrip("\\").casefold()


def _is_within(path: str, root: str) -> bool:
    child = _path_key(path)
    parent = _path_key(root)
    return child == parent or child.startswith(parent + "\\")


def _require_relative_release_path(name: str, value: object) -> str:
    normalized = require_text(name, value).replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise DemoSoakOperationsError(f"{name.upper()}_MUST_BE_RELEASE_RELATIVE")
    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise DemoSoakOperationsError(f"{name.upper()}_INVALID")
    return "/".join(parts)


def assert_no_embedded_secrets(payload: object, *, path: str = "config") -> None:
    """Reject secret-like keys and command-line values before typed construction."""

    if isinstance(payload, Mapping):
        for raw_key, value in payload.items():
            key = str(raw_key)
            if _SENSITIVE_KEY_RE.search(key):
                raise DemoSoakOperationsError("RAW_SECRET_FIELD_REJECTED")
            assert_no_embedded_secrets(value, path=f"{path}.{key}")
        return
    if isinstance(payload, (tuple, list, set, frozenset)):
        for index, value in enumerate(payload):
            assert_no_embedded_secrets(value, path=f"{path}[{index}]")
        return
    if isinstance(payload, str) and _SENSITIVE_VALUE_RE.search(payload):
        raise DemoSoakOperationsError("RAW_SECRET_VALUE_REJECTED")


@dataclass(frozen=True)
class CleanReleaseBinding:
    source_repository_root: str
    release_root: str
    git_commit: str
    git_tree: str
    archive_sha256: str
    manifest_sha256: str
    configuration_sha256: str
    reproducibility_receipt_sha256: str
    clean_checkout: bool
    tracked_build: bool
    tracked_file_hashes: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        source = _normalize_windows_path(
            "source_repository_root", self.source_repository_root
        )
        release = _normalize_windows_path("release_root", self.release_root)
        if _is_within(release, source) or _is_within(source, release):
            raise DemoSoakOperationsError("RELEASE_ROOT_MUST_BE_OUTSIDE_REPOSITORY")
        object.__setattr__(self, "source_repository_root", source)
        object.__setattr__(self, "release_root", release)
        object.__setattr__(self, "git_commit", _require_git_hash("git_commit", self.git_commit))
        object.__setattr__(self, "git_tree", _require_git_hash("git_tree", self.git_tree))
        for field_name in (
            "archive_sha256",
            "manifest_sha256",
            "configuration_sha256",
            "reproducibility_receipt_sha256",
        ):
            object.__setattr__(
                self, field_name, require_hash(field_name, getattr(self, field_name))
            )
        _require_bool("clean_checkout", self.clean_checkout, True)
        _require_bool("tracked_build", self.tracked_build, True)
        normalized: list[tuple[str, str]] = []
        seen: set[str] = set()
        for raw_path, raw_hash in self.tracked_file_hashes:
            path = _require_relative_release_path("tracked_file_path", raw_path)
            key = path.casefold()
            if key in seen:
                raise DemoSoakOperationsError("DUPLICATE_TRACKED_RELEASE_FILE")
            normalized.append((path, require_hash("tracked_file_sha256", raw_hash)))
            seen.add(key)
        if not normalized:
            raise DemoSoakOperationsError("TRACKED_RELEASE_FILES_REQUIRED")
        object.__setattr__(self, "tracked_file_hashes", tuple(sorted(normalized)))

    @property
    def tracked_files(self) -> Mapping[str, str]:
        return dict(self.tracked_file_hashes)


@dataclass(frozen=True)
class PythonRuntimeBinding:
    executable_path: str
    executable_sha256: str
    version: str
    architecture: str
    dependency_lock_sha256: str
    sbom_sha256: str

    def __post_init__(self) -> None:
        path = _normalize_windows_path("python_executable_path", self.executable_path)
        if PureWindowsPath(path).name.casefold() != "python.exe":
            raise DemoSoakOperationsError("CPYTHON_EXECUTABLE_REQUIRED")
        object.__setattr__(self, "executable_path", path)
        for field_name in (
            "executable_sha256",
            "dependency_lock_sha256",
            "sbom_sha256",
        ):
            object.__setattr__(
                self, field_name, require_hash(field_name, getattr(self, field_name))
            )
        version = require_text("python_version", self.version)
        if _PYTHON_VERSION_RE.fullmatch(version) is None:
            raise DemoSoakOperationsError("CPYTHON_3_12_PATCH_REQUIRED")
        object.__setattr__(self, "version", version)
        architecture = require_text("architecture", self.architecture, upper=True)
        if architecture not in {"AMD64", "X86_64"}:
            raise DemoSoakOperationsError("WINDOWS_X86_64_REQUIRED")
        object.__setattr__(self, "architecture", "AMD64")


@dataclass(frozen=True)
class MT5AccountBinding:
    candidate_id: str
    terminal_path: str
    terminal_sha256: str
    terminal_build: int
    company: str
    server: str
    environment: str
    account_alias_sha256: str
    account_currency: str
    symbol_bindings: tuple[tuple[str, str, str], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidate_id", require_text("candidate_id", self.candidate_id))
        terminal = _normalize_windows_path("terminal_path", self.terminal_path)
        if PureWindowsPath(terminal).name.casefold() != "terminal64.exe":
            raise DemoSoakOperationsError("MT5_TERMINAL64_REQUIRED")
        object.__setattr__(self, "terminal_path", terminal)
        object.__setattr__(
            self, "terminal_sha256", require_hash("terminal_sha256", self.terminal_sha256)
        )
        if isinstance(self.terminal_build, bool) or not isinstance(self.terminal_build, int):
            raise TypeError("terminal_build must be an integer")
        if self.terminal_build <= 0:
            raise DemoSoakOperationsError("MT5_TERMINAL_BUILD_REQUIRED")
        object.__setattr__(self, "company", require_text("company", self.company))
        object.__setattr__(self, "server", require_text("server", self.server))
        environment = require_text("environment", self.environment, upper=True)
        if environment != "DEMO":
            raise DemoSoakOperationsError("DEMO_ACCOUNT_REQUIRED")
        object.__setattr__(self, "environment", environment)
        object.__setattr__(
            self,
            "account_alias_sha256",
            require_hash("account_alias_sha256", self.account_alias_sha256),
        )
        currency = require_text("account_currency", self.account_currency, upper=True)
        if re.fullmatch(r"[A-Z]{3}", currency) is None:
            raise DemoSoakOperationsError("ACCOUNT_CURRENCY_INVALID")
        object.__setattr__(self, "account_currency", currency)
        normalized: list[tuple[str, str, str]] = []
        seen: set[str] = set()
        for canonical, broker_symbol, spec_sha256 in self.symbol_bindings:
            canonical_symbol = require_text("canonical_symbol", canonical, upper=True)
            if canonical_symbol in seen:
                raise DemoSoakOperationsError("DUPLICATE_CANONICAL_SYMBOL")
            normalized.append(
                (
                    canonical_symbol,
                    require_text("broker_symbol", broker_symbol),
                    require_hash("broker_spec_sha256", spec_sha256),
                )
            )
            seen.add(canonical_symbol)
        if not normalized:
            raise DemoSoakOperationsError("BROKER_SYMBOL_BINDINGS_REQUIRED")
        object.__setattr__(self, "symbol_bindings", tuple(sorted(normalized)))


@dataclass(frozen=True)
class CredentialManagerReference:
    purpose: str
    target_name: str
    key_id: str
    backend: str = "WINDOWS_CREDENTIAL_MANAGER"

    def __post_init__(self) -> None:
        purpose = require_text("credential purpose", self.purpose, upper=True)
        if purpose not in REQUIRED_CREDENTIAL_PURPOSES:
            raise DemoSoakOperationsError("UNSUPPORTED_CREDENTIAL_PURPOSE")
        object.__setattr__(self, "purpose", purpose)
        target = require_text("credential target_name", self.target_name)
        if _SENSITIVE_VALUE_RE.search(target) or len(target) > 180:
            raise DemoSoakOperationsError("CREDENTIAL_REFERENCE_INVALID")
        object.__setattr__(self, "target_name", target)
        object.__setattr__(self, "key_id", require_text("credential key_id", self.key_id))
        backend = require_text("credential backend", self.backend, upper=True)
        if backend != "WINDOWS_CREDENTIAL_MANAGER":
            raise DemoSoakOperationsError("WINDOWS_CREDENTIAL_MANAGER_REQUIRED")
        object.__setattr__(self, "backend", backend)


@dataclass(frozen=True)
class OffHostProviderReferences:
    heartbeat_destination_id: str
    audit_destination_id: str
    backup_destination_id: str
    alert_destination_id: str
    remote_receipt_key_provider_id: str

    def __post_init__(self) -> None:
        values: list[str] = []
        for field_name in self.__dataclass_fields__:
            normalized = _require_provider_id(field_name, getattr(self, field_name))
            object.__setattr__(self, field_name, normalized)
            values.append(normalized)
        if len(values) != len(set(values)):
            raise DemoSoakOperationsError("OFFHOST_PROVIDER_IDS_MUST_BE_DISTINCT")


@dataclass(frozen=True)
class OperationsThresholds:
    max_clock_drift_seconds: float = 1.0
    minimum_free_disk_gib: float = 10.0
    max_heartbeat_age_seconds: int = 30
    max_audit_export_age_seconds: int = 300
    max_backup_anchor_age_seconds: int = 86_400
    watchdog_interval_seconds: int = 30

    def __post_init__(self) -> None:
        numeric = {
            "max_clock_drift_seconds": (self.max_clock_drift_seconds, 0.0, 1.0),
            "minimum_free_disk_gib": (self.minimum_free_disk_gib, 5.0, None),
            "max_heartbeat_age_seconds": (self.max_heartbeat_age_seconds, 1, 30),
            "max_audit_export_age_seconds": (
                self.max_audit_export_age_seconds,
                1,
                300,
            ),
            "max_backup_anchor_age_seconds": (
                self.max_backup_anchor_age_seconds,
                1,
                86_400,
            ),
            "watchdog_interval_seconds": (self.watchdog_interval_seconds, 10, 60),
        }
        for name, (value, minimum, maximum) in numeric.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be numeric")
            if not math.isfinite(float(value)):
                raise DemoSoakOperationsError(
                    f"{name.upper()}_MUST_BE_FINITE"
                )
            if (
                name
                not in {
                    "max_clock_drift_seconds",
                    "minimum_free_disk_gib",
                }
                and type(value) is not int
            ):
                raise TypeError(f"{name} must be an integer")
            if value < minimum or (maximum is not None and value > maximum):
                raise DemoSoakOperationsError(f"{name.upper()}_OUTSIDE_SAFE_BOUND")


@dataclass(frozen=True)
class RuntimeStoragePaths:
    journal_database: str
    risk_database: str
    supervisor_database: str
    manual_demo_database: str
    soak_database: str
    log_directory: str
    immutable_audit_export_directory: str

    def __post_init__(self) -> None:
        normalized: dict[str, str] = {}
        for field_name in self.__dataclass_fields__:
            normalized[field_name] = _normalize_windows_path(
                field_name, getattr(self, field_name)
            )
            object.__setattr__(self, field_name, normalized[field_name])
        database_fields = (
            "journal_database",
            "risk_database",
            "supervisor_database",
            "manual_demo_database",
            "soak_database",
        )
        if any(
            PureWindowsPath(normalized[field_name]).suffix.casefold() not in {".db", ".sqlite3"}
            for field_name in database_fields
        ):
            raise DemoSoakOperationsError("SQLITE_DATABASE_EXTENSION_REQUIRED")
        if len({_path_key(normalized[name]) for name in database_fields}) != len(database_fields):
            raise DemoSoakOperationsError("RUNTIME_DATABASE_PATHS_MUST_BE_DISTINCT")
        if _is_within(
            normalized["immutable_audit_export_directory"], normalized["log_directory"]
        ):
            raise DemoSoakOperationsError("AUDIT_EXPORT_MUST_BE_SEPARATE_FROM_LOGS")

    def assert_outside(self, *roots: str) -> None:
        for field_name in self.__dataclass_fields__:
            value = getattr(self, field_name)
            if any(_is_within(value, root) for root in roots):
                raise DemoSoakOperationsError("RUNTIME_STATE_PATH_INSIDE_CODE_ROOT")


@dataclass(frozen=True)
class WindowsSecurityPosture:
    service_account_id: str
    rdp_ingress_scope: str
    vpn_required: bool
    mfa_required: bool
    least_privilege: bool
    public_rdp_exposed: bool
    firewall_policy_sha256: str
    event_log_source: str

    def __post_init__(self) -> None:
        account = require_text("service_account_id", self.service_account_id)
        if "@" in account or "\\" not in account:
            raise DemoSoakOperationsError("LOCAL_OR_DOMAIN_SERVICE_ACCOUNT_REQUIRED")
        object.__setattr__(self, "service_account_id", account)
        scope = require_text("rdp_ingress_scope", self.rdp_ingress_scope, upper=True)
        if scope != "VPN_ONLY":
            raise DemoSoakOperationsError("PUBLIC_RDP_REJECTED")
        object.__setattr__(self, "rdp_ingress_scope", scope)
        _require_bool("vpn_required", self.vpn_required, True)
        _require_bool("mfa_required", self.mfa_required, True)
        _require_bool("least_privilege", self.least_privilege, True)
        _require_bool("public_rdp_exposed", self.public_rdp_exposed, False)
        object.__setattr__(
            self,
            "firewall_policy_sha256",
            require_hash("firewall_policy_sha256", self.firewall_policy_sha256),
        )
        source = require_text("event_log_source", self.event_log_source)
        if _EVENT_SOURCE_RE.fullmatch(source) is None:
            raise DemoSoakOperationsError("WINDOWS_EVENT_SOURCE_INVALID")
        object.__setattr__(self, "event_log_source", source)


@dataclass(frozen=True)
class RuntimeProcessDefinition:
    role: str
    task_name: str
    entrypoint_relative_path: str
    arguments: tuple[str, ...]
    working_directory: str
    service_account_id: str
    entrypoint_sha256: str
    broker_mutation_capability: str = "DISABLED"

    def __post_init__(self) -> None:
        role = require_text("process role", self.role, upper=True)
        if role not in PROCESS_ROLES:
            raise DemoSoakOperationsError("PROCESS_ROLE_INVALID")
        object.__setattr__(self, "role", role)
        name = require_text("task_name", self.task_name)
        if _TASK_NAME_RE.fullmatch(name) is None:
            raise DemoSoakOperationsError("TASK_NAME_INVALID")
        object.__setattr__(self, "task_name", name)
        object.__setattr__(
            self,
            "entrypoint_relative_path",
            _require_relative_release_path(
                "entrypoint_relative_path", self.entrypoint_relative_path
            ),
        )
        arguments = tuple(require_text("process argument", item) for item in self.arguments)
        if "--deny-orders" not in arguments:
            raise DemoSoakOperationsError("DENY_ORDERS_ARGUMENT_REQUIRED")
        joined = " ".join(arguments)
        if _SENSITIVE_VALUE_RE.search(joined):
            raise DemoSoakOperationsError("RAW_SECRET_VALUE_REJECTED")
        prohibited = ("--live", "--demo-auto", "--enable-orders", "--allow-orders")
        if any(item.casefold() in prohibited for item in arguments):
            raise DemoSoakOperationsError("ORDER_ENABLING_ARGUMENT_REJECTED")
        object.__setattr__(self, "arguments", arguments)
        object.__setattr__(
            self,
            "working_directory",
            _normalize_windows_path("working_directory", self.working_directory),
        )
        object.__setattr__(
            self,
            "service_account_id",
            require_text("service_account_id", self.service_account_id),
        )
        object.__setattr__(
            self,
            "entrypoint_sha256",
            require_hash("entrypoint_sha256", self.entrypoint_sha256),
        )
        capability = require_text(
            "broker_mutation_capability", self.broker_mutation_capability, upper=True
        )
        if capability != "DISABLED":
            raise DemoSoakOperationsError("BROKER_MUTATION_MUST_REMAIN_DISABLED")
        object.__setattr__(self, "broker_mutation_capability", capability)

    def action_arguments(self, release_root: str) -> tuple[str, ...]:
        entrypoint = str(
            PureWindowsPath(release_root)
            / PureWindowsPath(self.entrypoint_relative_path.replace("/", "\\"))
        )
        return ("-B", entrypoint, *self.arguments)


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


@dataclass(frozen=True)
class SchedulerTaskDefinition:
    task_name: str
    description: str
    executable_path: str
    arguments: tuple[str, ...]
    working_directory: str
    service_account_id: str
    restart_count: int = 3
    restart_interval_minutes: int = 1
    startup_delay_seconds: int = 15
    allow_demand_start: bool = False

    def __post_init__(self) -> None:
        name = require_text("task_name", self.task_name)
        if _TASK_NAME_RE.fullmatch(name) is None:
            raise DemoSoakOperationsError("TASK_NAME_INVALID")
        object.__setattr__(self, "task_name", name)
        object.__setattr__(self, "description", require_text("description", self.description))
        object.__setattr__(
            self,
            "executable_path",
            _normalize_windows_path("task_executable_path", self.executable_path),
        )
        arguments = tuple(require_text("task argument", item) for item in self.arguments)
        joined = " ".join(arguments)
        if _SENSITIVE_VALUE_RE.search(joined):
            raise DemoSoakOperationsError("RAW_SECRET_VALUE_REJECTED")
        object.__setattr__(self, "arguments", arguments)
        object.__setattr__(
            self,
            "working_directory",
            _normalize_windows_path("task_working_directory", self.working_directory),
        )
        object.__setattr__(
            self,
            "service_account_id",
            require_text("task service_account_id", self.service_account_id),
        )
        for field_name, minimum, maximum in (
            ("restart_count", 0, 5),
            ("restart_interval_minutes", 1, 5),
            ("startup_delay_seconds", 0, 300),
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field_name} must be an integer")
            if value < minimum or value > maximum:
                raise DemoSoakOperationsError(f"{field_name.upper()}_OUTSIDE_SAFE_BOUND")
        _require_bool("allow_demand_start", self.allow_demand_start, False)

    @property
    def argument_line(self) -> str:
        def quote(item: str) -> str:
            return f'"{item}"' if any(char.isspace() for char in item) else item

        return " ".join(quote(item) for item in self.arguments)

    def render_xml(self) -> str:
        """Render deterministic Task Scheduler XML; this method never installs it."""

        values = {
            "description": xml_escape(self.description),
            "delay": f"PT{self.startup_delay_seconds}S",
            "user": xml_escape(self.service_account_id),
            "command": xml_escape(self.executable_path),
            "arguments": xml_escape(self.argument_line),
            "working": xml_escape(self.working_directory),
            "restart_interval": f"PT{self.restart_interval_minutes}M",
            "restart_count": str(self.restart_count),
        }
        return (
            '<?xml version="1.0" encoding="UTF-16"?>\n'
            '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
            f'  <RegistrationInfo><Description>{values["description"]}</Description></RegistrationInfo>\n'
            '  <Triggers><BootTrigger><Enabled>true</Enabled>'
            f'<Delay>{values["delay"]}</Delay></BootTrigger></Triggers>\n'
            '  <Principals><Principal id="ServiceAccount">'
            f'<UserId>{values["user"]}</UserId><LogonType>S4U</LogonType>'
            '<RunLevel>LeastPrivilege</RunLevel></Principal></Principals>\n'
            '  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>'
            '<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>'
            '<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>'
            '<AllowHardTerminate>true</AllowHardTerminate>'
            '<StartWhenAvailable>true</StartWhenAvailable>'
            '<RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>'
            '<AllowStartOnDemand>false</AllowStartOnDemand>'
            '<Enabled>true</Enabled><Hidden>false</Hidden>'
            '<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>'
            f'<RestartOnFailure><Interval>{values["restart_interval"]}</Interval>'
            f'<Count>{values["restart_count"]}</Count></RestartOnFailure></Settings>\n'
            '  <Actions Context="ServiceAccount"><Exec>'
            f'<Command>{values["command"]}</Command>'
            f'<Arguments>{values["arguments"]}</Arguments>'
            f'<WorkingDirectory>{values["working"]}</WorkingDirectory>'
            '</Exec></Actions>\n'
            '</Task>\n'
        )

    def render_validation_powershell(self) -> str:
        """Render a read-only validation script; it cannot register or start tasks."""

        expected = {
            "task": _ps_quote(self.task_name),
            "command": _ps_quote(self.executable_path),
            "arguments": _ps_quote(self.argument_line),
            "working": _ps_quote(self.working_directory),
        }
        return (
            f"$task = Get-ScheduledTask -TaskName {expected['task']} -ErrorAction Stop\n"
            "$action = @($task.Actions)[0]\n"
            f"if ($action.Execute -cne {expected['command']}) {{ throw 'TASK_EXECUTABLE_MISMATCH' }}\n"
            f"if ($action.Arguments -cne {expected['arguments']}) {{ throw 'TASK_ARGUMENTS_MISMATCH' }}\n"
            f"if ($action.WorkingDirectory -cne {expected['working']}) {{ throw 'TASK_WORKDIR_MISMATCH' }}\n"
            "if ($task.Principal.RunLevel -ne 'Limited') { throw 'TASK_NOT_LEAST_PRIVILEGE' }\n"
            "if ($task.Principal.LogonType -ne 'S4U') { throw 'TASK_LOGON_TYPE_MISMATCH' }\n"
            "$task | Select-Object TaskName,State,@{n='Execute';e={$action.Execute}},@{n='Arguments';e={$action.Arguments}}\n"
        )


@dataclass(frozen=True)
class WindowsDemoSoakOperationsPlan:
    release: CleanReleaseBinding
    python: PythonRuntimeBinding
    broker: MT5AccountBinding
    credentials: tuple[CredentialManagerReference, ...]
    providers: OffHostProviderReferences
    thresholds: OperationsThresholds
    storage: RuntimeStoragePaths
    security: WindowsSecurityPosture
    processes: tuple[RuntimeProcessDefinition, ...]
    watchdog_entrypoint_relative_path: str
    watchdog_entrypoint_sha256: str
    live_allowed: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    execution_enabled: bool = field(default=False, init=False)
    promotion_eligible: bool = field(default=False, init=False)
    task_install_allowed: bool = field(default=False, init=False)
    max_lot: float = field(default=MAX_LOT, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    schema_version: str = field(default=SCHEMA_VERSION, init=False)

    def __post_init__(self) -> None:
        for name, expected_type in (
            ("release", CleanReleaseBinding),
            ("python", PythonRuntimeBinding),
            ("broker", MT5AccountBinding),
            ("providers", OffHostProviderReferences),
            ("thresholds", OperationsThresholds),
            ("storage", RuntimeStoragePaths),
            ("security", WindowsSecurityPosture),
        ):
            if not isinstance(getattr(self, name), expected_type):
                raise TypeError(f"{name} must be {expected_type.__name__}")
        credentials = tuple(self.credentials)
        if not credentials or any(
            not isinstance(item, CredentialManagerReference) for item in credentials
        ):
            raise TypeError("credentials must contain CredentialManagerReference values")
        purposes = [item.purpose for item in credentials]
        if len(purposes) != len(set(purposes)):
            raise DemoSoakOperationsError("DUPLICATE_CREDENTIAL_PURPOSE")
        missing = REQUIRED_CREDENTIAL_PURPOSES.difference(purposes)
        if missing:
            raise DemoSoakOperationsError("REQUIRED_CREDENTIAL_REFERENCES_MISSING")
        if len({item.target_name.casefold() for item in credentials}) != len(credentials):
            raise DemoSoakOperationsError("CREDENTIAL_TARGETS_MUST_BE_DISTINCT")
        if len({item.key_id for item in credentials}) != len(credentials):
            raise DemoSoakOperationsError("CREDENTIAL_KEY_IDS_MUST_BE_DISTINCT")
        object.__setattr__(self, "credentials", tuple(sorted(credentials, key=lambda x: x.purpose)))
        processes = tuple(self.processes)
        if len(processes) != 2 or any(
            not isinstance(item, RuntimeProcessDefinition) for item in processes
        ):
            raise DemoSoakOperationsError("EXACTLY_TWO_RUNTIME_PROCESSES_REQUIRED")
        roles = {item.role for item in processes}
        if roles != PROCESS_ROLES:
            raise DemoSoakOperationsError("DECISION_AND_EXECUTOR_RECONCILER_REQUIRED")
        if len({item.task_name.casefold() for item in processes}) != 2:
            raise DemoSoakOperationsError("PROCESS_TASK_NAMES_MUST_BE_DISTINCT")
        object.__setattr__(self, "processes", tuple(sorted(processes, key=lambda x: x.role)))
        watchdog_path = _require_relative_release_path(
            "watchdog_entrypoint_relative_path", self.watchdog_entrypoint_relative_path
        )
        object.__setattr__(self, "watchdog_entrypoint_relative_path", watchdog_path)
        object.__setattr__(
            self,
            "watchdog_entrypoint_sha256",
            require_hash("watchdog_entrypoint_sha256", self.watchdog_entrypoint_sha256),
        )
        self.storage.assert_outside(
            self.release.source_repository_root, self.release.release_root
        )
        if any(item.working_directory != self.release.release_root for item in processes):
            raise DemoSoakOperationsError("PROCESS_WORKDIR_MUST_EQUAL_RELEASE_ROOT")
        if any(item.service_account_id != self.security.service_account_id for item in processes):
            raise DemoSoakOperationsError("PROCESS_SERVICE_ACCOUNT_MISMATCH")
        tracked = {path.casefold(): digest for path, digest in self.release.tracked_file_hashes}
        for item in processes:
            if tracked.get(item.entrypoint_relative_path.casefold()) != item.entrypoint_sha256:
                raise DemoSoakOperationsError("PROCESS_ENTRYPOINT_NOT_IN_TRACKED_BUILD")
        if tracked.get(watchdog_path.casefold()) != self.watchdog_entrypoint_sha256:
            raise DemoSoakOperationsError("WATCHDOG_ENTRYPOINT_NOT_IN_TRACKED_BUILD")
        if _is_within(self.python.executable_path, self.release.source_repository_root):
            raise DemoSoakOperationsError("PYTHON_EXECUTABLE_INSIDE_REPOSITORY")
        if _is_within(self.broker.terminal_path, self.release.source_repository_root):
            raise DemoSoakOperationsError("MT5_TERMINAL_INSIDE_REPOSITORY")
        assert_no_embedded_secrets(self.to_dict())

    @property
    def plan_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "broker": {
                **self.broker.__dict__,
                "symbol_bindings": list(self.broker.symbol_bindings),
            },
            "credentials": [item.__dict__ for item in self.credentials],
            "execution_enabled": self.execution_enabled,
            "live_allowed": self.live_allowed,
            "max_lot": self.max_lot,
            "order_capability": self.order_capability,
            "processes": [
                {**item.__dict__, "arguments": list(item.arguments)} for item in self.processes
            ],
            "promotion_eligible": self.promotion_eligible,
            "providers": self.providers.__dict__,
            "python": self.python.__dict__,
            "release": {
                **self.release.__dict__,
                "tracked_file_hashes": list(self.release.tracked_file_hashes),
            },
            "safe_to_demo_auto_order": self.safe_to_demo_auto_order,
            "schema_version": self.schema_version,
            "security": self.security.__dict__,
            "storage": self.storage.__dict__,
            "task_install_allowed": self.task_install_allowed,
            "thresholds": self.thresholds.__dict__,
            "watchdog_entrypoint_relative_path": self.watchdog_entrypoint_relative_path,
            "watchdog_entrypoint_sha256": self.watchdog_entrypoint_sha256,
        }

    def scheduler_definitions(self) -> tuple[SchedulerTaskDefinition, ...]:
        definitions: list[SchedulerTaskDefinition] = []
        for index, item in enumerate(self.processes):
            definitions.append(
                SchedulerTaskDefinition(
                    task_name=item.task_name,
                    description=(
                        f"AI_SCALPER deny-only {item.role.lower().replace('_', ' ')}; "
                        f"plan {self.plan_sha256[:16]}"
                    ),
                    executable_path=self.python.executable_path,
                    arguments=item.action_arguments(self.release.release_root),
                    working_directory=self.release.release_root,
                    service_account_id=self.security.service_account_id,
                    startup_delay_seconds=15 + (index * 15),
                )
            )
        watchdog_path = str(
            PureWindowsPath(self.release.release_root)
            / PureWindowsPath(self.watchdog_entrypoint_relative_path.replace("/", "\\"))
        )
        definitions.append(
            SchedulerTaskDefinition(
                task_name="AI_SCALPER-DemoSoak-Watchdog",
                description=f"AI_SCALPER status-only watchdog; plan {self.plan_sha256[:16]}",
                executable_path=self.python.executable_path,
                arguments=(
                    "-B",
                    watchdog_path,
                    "--status-only",
                    "--deny-orders",
                    "--interval-seconds",
                    str(self.thresholds.watchdog_interval_seconds),
                ),
                working_directory=self.release.release_root,
                service_account_id=self.security.service_account_id,
                startup_delay_seconds=45,
            )
        )
        return tuple(definitions)


@dataclass(frozen=True)
class FailureDrillManifest:
    plan_sha256: str
    release_manifest_sha256: str
    git_commit: str
    candidate_id: str
    server: str
    account_alias_sha256: str
    issued_at_utc: datetime
    required_drills: tuple[str, ...] = REQUIRED_DRILLS
    schema_version: str = "windows-failure-drill-manifest-v1"

    def __post_init__(self) -> None:
        for field_name in ("plan_sha256", "release_manifest_sha256", "account_alias_sha256"):
            object.__setattr__(
                self, field_name, require_hash(field_name, getattr(self, field_name))
            )
        object.__setattr__(self, "git_commit", _require_git_hash("git_commit", self.git_commit))
        object.__setattr__(self, "candidate_id", require_text("candidate_id", self.candidate_id))
        object.__setattr__(self, "server", require_text("server", self.server))
        require_utc("issued_at_utc", self.issued_at_utc)
        drills = tuple(require_text("drill_id", item, upper=True) for item in self.required_drills)
        if drills != REQUIRED_DRILLS:
            raise DemoSoakOperationsError("REQUIRED_FAILURE_DRILLS_CHANGED")
        object.__setattr__(self, "required_drills", drills)
        if self.schema_version != "windows-failure-drill-manifest-v1":
            raise DemoSoakOperationsError("FAILURE_DRILL_MANIFEST_SCHEMA_MISMATCH")

    @property
    def manifest_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_alias_sha256": self.account_alias_sha256,
            "candidate_id": self.candidate_id,
            "git_commit": self.git_commit,
            "issued_at_utc": self.issued_at_utc,
            "plan_sha256": self.plan_sha256,
            "release_manifest_sha256": self.release_manifest_sha256,
            "required_drills": list(self.required_drills),
            "schema_version": self.schema_version,
            "server": self.server,
        }


@dataclass(frozen=True)
class FailureDrillObservation:
    drill_id: str
    manifest_sha256: str
    plan_sha256: str
    release_manifest_sha256: str
    git_commit: str
    candidate_id: str
    server: str
    account_alias_sha256: str
    outcome: str
    evidence_sha256: str
    observed_at_utc: datetime
    observer_key_id: str
    signature_hmac_sha256: str = ""
    schema_version: str = "windows-failure-drill-observation-v1"

    def __post_init__(self) -> None:
        drill = require_text("drill_id", self.drill_id, upper=True)
        if drill not in REQUIRED_DRILLS:
            raise DemoSoakOperationsError("FAILURE_DRILL_ID_INVALID")
        object.__setattr__(self, "drill_id", drill)
        for field_name in (
            "manifest_sha256",
            "plan_sha256",
            "release_manifest_sha256",
            "account_alias_sha256",
            "evidence_sha256",
        ):
            object.__setattr__(
                self, field_name, require_hash(field_name, getattr(self, field_name))
            )
        object.__setattr__(self, "git_commit", _require_git_hash("git_commit", self.git_commit))
        object.__setattr__(self, "candidate_id", require_text("candidate_id", self.candidate_id))
        object.__setattr__(self, "server", require_text("server", self.server))
        outcome = require_text("outcome", self.outcome, upper=True)
        if outcome not in {"PASSED", "FAILED"}:
            raise DemoSoakOperationsError("FAILURE_DRILL_OUTCOME_INVALID")
        object.__setattr__(self, "outcome", outcome)
        require_utc("observed_at_utc", self.observed_at_utc)
        object.__setattr__(
            self, "observer_key_id", require_text("observer_key_id", self.observer_key_id)
        )
        signature = str(self.signature_hmac_sha256 or "").strip().lower()
        if signature:
            signature = require_hash("signature_hmac_sha256", signature)
        object.__setattr__(self, "signature_hmac_sha256", signature)
        if self.schema_version != "windows-failure-drill-observation-v1":
            raise DemoSoakOperationsError("FAILURE_DRILL_OBSERVATION_SCHEMA_MISMATCH")

    @property
    def signing_payload(self) -> bytes:
        return _canonical(
            {
                "account_alias_sha256": self.account_alias_sha256,
                "candidate_id": self.candidate_id,
                "drill_id": self.drill_id,
                "evidence_sha256": self.evidence_sha256,
                "git_commit": self.git_commit,
                "manifest_sha256": self.manifest_sha256,
                "observed_at_utc": self.observed_at_utc.isoformat(timespec="microseconds").replace(
                    "+00:00", "Z"
                ),
                "observer_key_id": self.observer_key_id,
                "outcome": self.outcome,
                "plan_sha256": self.plan_sha256,
                "release_manifest_sha256": self.release_manifest_sha256,
                "schema_version": self.schema_version,
                "server": self.server,
            }
        )

    @property
    def observation_id(self) -> str:
        return "drill_" + hashlib.sha256(self.signing_payload).hexdigest()[:32]

    def sign(self, secret: str | bytes) -> "FailureDrillObservation":
        signature = hmac.new(_key(secret), self.signing_payload, hashlib.sha256).hexdigest()
        return replace(self, signature_hmac_sha256=signature)

    def verify(self, secret: str | bytes) -> bool:
        if not self.signature_hmac_sha256:
            return False
        expected = hmac.new(_key(secret), self.signing_payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature_hmac_sha256)


def issue_failure_drill_observation(
    manifest: FailureDrillManifest,
    *,
    drill_id: str,
    outcome: str,
    evidence_sha256: str,
    observed_at_utc: datetime,
    observer_key_id: str,
    secret: str | bytes,
) -> FailureDrillObservation:
    if type(manifest) is not FailureDrillManifest:
        raise TypeError("manifest must be exact FailureDrillManifest")
    observed = require_utc("observed_at_utc", observed_at_utc)
    if observed < manifest.issued_at_utc:
        raise DemoSoakOperationsError("DRILL_OBSERVED_BEFORE_MANIFEST")
    return FailureDrillObservation(
        drill_id=drill_id,
        manifest_sha256=manifest.manifest_sha256,
        plan_sha256=manifest.plan_sha256,
        release_manifest_sha256=manifest.release_manifest_sha256,
        git_commit=manifest.git_commit,
        candidate_id=manifest.candidate_id,
        server=manifest.server,
        account_alias_sha256=manifest.account_alias_sha256,
        outcome=outcome,
        evidence_sha256=evidence_sha256,
        observed_at_utc=observed,
        observer_key_id=observer_key_id,
    ).sign(secret)


@dataclass(frozen=True)
class FailureDrillAssessment:
    passed_drills: tuple[str, ...]
    failed_drills: tuple[str, ...]
    missing_drills: tuple[str, ...]
    invalid_drills: tuple[str, ...]
    complete: bool
    status: str
    ready_for_demo_auto_soak: bool = field(default=False, init=False)
    ready_for_live: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)


class FailureDrillTracker:
    """Strict verifier over externally persisted, signed drill observations."""

    def __init__(
        self,
        manifest: FailureDrillManifest,
        observations: Iterable[FailureDrillObservation] = (),
    ) -> None:
        if type(manifest) is not FailureDrillManifest:
            raise TypeError("manifest must be exact FailureDrillManifest")
        values = tuple(observations)
        # Observations are signed gate evidence.  Exact types prevent a
        # subclass from replacing ``verify`` and fabricating a passed drill.
        if any(type(item) is not FailureDrillObservation for item in values):
            raise TypeError(
                "observations must contain exact FailureDrillObservation values"
            )
        ids = [item.observation_id for item in values]
        if len(ids) != len(set(ids)):
            raise DemoSoakOperationsError("FAILURE_DRILL_OBSERVATION_REPLAY")
        self.manifest = manifest
        self.observations = values

    def assess(
        self,
        *,
        key_provider: Callable[[str], str | bytes],
        checked_at_utc: datetime,
    ) -> FailureDrillAssessment:
        if not callable(key_provider):
            raise TypeError("key_provider must be callable")
        checked = require_utc("checked_at_utc", checked_at_utc)
        grouped: dict[str, list[FailureDrillObservation]] = {
            drill: [] for drill in REQUIRED_DRILLS
        }
        invalid: set[str] = set()
        for item in self.observations:
            grouped[item.drill_id].append(item)
            if not self._binding_matches(item):
                invalid.add(item.drill_id)
                continue
            if item.observed_at_utc < self.manifest.issued_at_utc or item.observed_at_utc > checked:
                invalid.add(item.drill_id)
                continue
            try:
                if not item.verify(key_provider(item.observer_key_id)):
                    invalid.add(item.drill_id)
            except (KeyError, TypeError, ValueError):
                invalid.add(item.drill_id)

        passed: list[str] = []
        failed: list[str] = []
        missing: list[str] = []
        for drill in REQUIRED_DRILLS:
            values = grouped[drill]
            if not values:
                missing.append(drill)
                continue
            latest_at = max(item.observed_at_utc for item in values)
            latest = [item for item in values if item.observed_at_utc == latest_at]
            if len(latest) != 1:
                invalid.add(drill)
                continue
            if drill in invalid:
                continue
            if latest[0].outcome == "PASSED":
                passed.append(drill)
            else:
                failed.append(drill)
        complete = not invalid and not failed and not missing and tuple(passed) == REQUIRED_DRILLS
        status = "SIGNED_FAILURE_DRILLS_COMPLETE" if complete else "FAILURE_DRILLS_INCOMPLETE"
        return FailureDrillAssessment(
            passed_drills=tuple(passed),
            failed_drills=tuple(failed),
            missing_drills=tuple(missing),
            invalid_drills=tuple(sorted(invalid)),
            complete=complete,
            status=status,
        )

    def _binding_matches(self, item: FailureDrillObservation) -> bool:
        manifest = self.manifest
        return (
            item.manifest_sha256 == manifest.manifest_sha256
            and item.plan_sha256 == manifest.plan_sha256
            and item.release_manifest_sha256 == manifest.release_manifest_sha256
            and item.git_commit == manifest.git_commit
            and item.candidate_id == manifest.candidate_id
            and item.server == manifest.server
            and item.account_alias_sha256 == manifest.account_alias_sha256
        )


@dataclass(frozen=True)
class OperationsReadinessAssessment:
    local_plan_valid: bool
    signed_failure_drills_complete: bool
    status: str
    external_blockers: tuple[str, ...]
    task_install_allowed: bool = field(default=False, init=False)
    execution_enabled: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    live_allowed: bool = field(default=False, init=False)
    promotion_eligible: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    max_lot: float = field(default=MAX_LOT, init=False)


def assess_operations_readiness(
    plan: WindowsDemoSoakOperationsPlan,
    *,
    drill_assessment: FailureDrillAssessment | None = None,
) -> OperationsReadinessAssessment:
    if not isinstance(plan, WindowsDemoSoakOperationsPlan):
        raise TypeError("plan must be WindowsDemoSoakOperationsPlan")
    if drill_assessment is not None and not isinstance(
        drill_assessment, FailureDrillAssessment
    ):
        raise TypeError("drill_assessment must be FailureDrillAssessment")
    drills_complete = bool(drill_assessment and drill_assessment.complete)
    blockers = [
        "TASK_SCHEDULER_DEFINITIONS_REQUIRE_REVIEW_AND_INSTALLATION",
        "WINDOWS_CREDENTIAL_MANAGER_REFERENCES_REQUIRE_PROVISION_AND_ATTESTATION",
        "OFFHOST_PROVIDER_IDS_REQUIRE_ENDPOINT_MAPPING_AND_SIGNED_ACK_TESTS",
        "TRUSTED_CLOCK_DISK_EVENTLOG_AND_BACKUP_ADAPTERS_REQUIRE_WINDOWS_ATTESTATION",
        "TEN_CONTROLLED_MANUAL_DEMO_ORDERS_REQUIRE_SIGNED_ACCEPTANCE",
        "DEMO_AUTO_PROMOTION_PERMIT_AND_ENVIRONMENT_ARM_REMAIN_UNISSUED",
        "THIRTY_DAY_FIFTY_FILL_TWENTY_XAU_DEMO_SOAK_REMAINS_UNOBSERVED",
        "BROKER_FORWARD_OOS_EIGHT_WEEK_AND_LANE_GATES_REMAIN_EXTERNAL",
        "INDEPENDENT_SECURITY_LEGAL_AND_OPERATOR_APPROVAL_REMAINS_REQUIRED",
    ]
    if not drills_complete:
        blockers.insert(0, "SIGNED_FAILURE_DRILLS_INCOMPLETE")
    return OperationsReadinessAssessment(
        local_plan_valid=True,
        signed_failure_drills_complete=drills_complete,
        status="LOCAL_OPERATIONS_FOUNDATION_VALID_EXTERNAL_GATES_PENDING",
        external_blockers=tuple(blockers),
    )


__all__ = [
    "CleanReleaseBinding",
    "CredentialManagerReference",
    "DemoSoakOperationsError",
    "FailureDrillAssessment",
    "FailureDrillManifest",
    "FailureDrillObservation",
    "FailureDrillTracker",
    "MT5AccountBinding",
    "OffHostProviderReferences",
    "OperationsReadinessAssessment",
    "OperationsThresholds",
    "PythonRuntimeBinding",
    "REQUIRED_DRILLS",
    "RuntimeProcessDefinition",
    "RuntimeStoragePaths",
    "SchedulerTaskDefinition",
    "WindowsDemoSoakOperationsPlan",
    "WindowsSecurityPosture",
    "assert_no_embedded_secrets",
    "assess_operations_readiness",
    "issue_failure_drill_observation",
]
