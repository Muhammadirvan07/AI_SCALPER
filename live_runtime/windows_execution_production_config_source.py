"""Deterministic, deny-only Windows Execution configuration source.

The archive binds one canonical production configuration, one exact stage
binding, and one independently pinned rule-core champion.  This module is
stdlib-only and deliberately has no provider, credential, SQLite, MT5,
network, task, service, permit, or broker effect.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
from typing import BinaryIO, Mapping
import zipfile

from .rule_core_model_artifact import (
    RuleCoreModelArtifactError,
    verify_archive_with_pins,
)


SCHEMA_VERSION = "windows-execution-production-config-source-v1"
STAGE_SCHEMA_VERSION = "stage-readiness-authorization-v3"
BOOTSTRAP_SCHEMA_VERSION = "windows-production-bootstrap-v2"
MANIFEST_MEMBER = "WINDOWS_EXECUTION_PRODUCTION_CONFIG_SOURCE.json"
CONFIG_MEMBER = "config/windows_production_runtime_config.json"
CHAMPION_MEMBER = "evidence/rule-core-champion-artifact.zip"
STAGE_MEMBER = "evidence/windows_stage_binding.json"
PAYLOAD_MEMBERS = tuple(sorted((CONFIG_MEMBER, CHAMPION_MEMBER, STAGE_MEMBER)))
ARCHIVE_MEMBERS = tuple(sorted((MANIFEST_MEMBER, *PAYLOAD_MEMBERS)))
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
FIXED_ZIP_MODE = stat.S_IFREG | 0o644
MAX_JSON_MEMBER_BYTES = 1024 * 1024
MAX_CHAMPION_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_BYTES = 40 * 1024 * 1024
MAX_EXPANDED_BYTES = MAX_CHAMPION_BYTES + (3 * MAX_JSON_MEMBER_BYTES)
ORDER_CAPABILITY = "DISABLED"
EXPECTED_MT5_DISTRIBUTION_VERSION = "5.0.5735"
EXPECTED_MT5_WHEEL_SHA256 = (
    "f6e8584e48f2c3f5de818f17ee65f0f5adfa1e4af29cd5f4bf3f72b91ff06e10"
)

SAFETY = {
    "provider_accepted": False,
    "production_execution_ready": False,
    "promotion_eligible": False,
    "order_capability": ORDER_CAPABILITY,
    "safe_to_demo_auto_order": False,
    "live_allowed": False,
}
EFFECTS = {
    "credential_access": "NOT_PERFORMED",
    "private_key_access": "NOT_PERFORMED",
    "provider_import": "NOT_PERFORMED",
    "provider_materialization": "NOT_PERFORMED",
    "sqlite_open": "NOT_PERFORMED",
    "mt5_initialization": "NOT_PERFORMED",
    "network_access": "NOT_PERFORMED",
    "task_installation": "NOT_PERFORMED",
    "service_start": "NOT_PERFORMED",
    "permit_issuance": "NOT_PERFORMED",
    "broker_mutation": "NOT_PERFORMED",
}

_HEX_40 = re.compile(r"[0-9a-f]{40}")
_HEX_64 = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}")
_OUTPUT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.zip")
_REPORT_SEAL = object()

_CONFIG_FIELDS = frozenset(
    {
        "journal_database",
        "supervisor_database",
        "dependency_lock_file",
        "account_alias_sha256",
        "broker_legal_name",
        "server",
        "environment",
        "account_currency",
        "session_calendar_sha256",
        "symbol_map",
        "journal_sha256",
        "broker_spec_sha256",
        "commit_sha",
        "config_sha256",
        "stage_binding_sha256",
        "champion_archive_sha256",
        "champion_package_identity_sha256",
        "champion_training_snapshot_sha256",
        "champion_git_tree",
        "champion_runtime_binding_sha256",
        "manual_demo_custodian_trust_sha256",
        "news_guard_provider_id",
        "news_guard_key_id",
        "news_guard_ruleset_sha256",
        "news_guard_blackout_window_sha256",
        "supervisor_key_id",
        "supervisor_checkpoint_key_id",
        "risk_ledger_id",
        "risk_ledger_key_id",
        "risk_ledger_key_fingerprint_sha256",
        "journal_checkpoint_key_id",
        "journal_checkpoint_key_fingerprint_sha256",
        "news_guard_key_fingerprint_sha256",
        "permit_secret_fingerprint_sha256",
        "dependency_lock_sha256",
        "installed_environment_sha256",
        "mt5_site_packages_sha256",
        "mt5_site_packages_tree_sha256",
        "mt5_distribution_record_sha256",
        "mt5_module_file_sha256",
        "mt5_module_relative_path_sha256",
        "supervisor_key_fingerprint_sha256",
        "supervisor_checkpoint_key_fingerprint_sha256",
        "credential_session_key_id",
        "credential_session_key_fingerprint_sha256",
        "journal_provisioning_key_id",
        "journal_provisioning_key_fingerprint_sha256",
        "worm_audit_key_id",
        "worm_audit_key_fingerprint_sha256",
        "mt5_distribution_version",
        "mt5_wheel_sha256",
        "usd_account_currency_symbols",
        "mode",
        "magic_number",
        "deviation_points",
        "max_tick_age_seconds",
        "intent_ttl_seconds",
        "expected_manual_approver_id",
        "expected_manual_approval_key_id",
        "manual_approval_key_fingerprint_sha256",
        "demo_auto_session_binding_sha256",
        "demo_auto_session_ledger_id",
        "demo_auto_session_custody_key_id",
        "demo_auto_session_custody_key_fingerprint_sha256",
        "live_allowed",
        "safe_to_demo_auto_order",
        "order_capability",
        "schema_version",
    }
)
_STAGE_FIELDS = frozenset(
    {
        "broker_id",
        "account_alias_sha256",
        "server",
        "environment",
        "symbol",
        "strategy",
        "lane_id",
        "journal_sha256",
        "commit_sha",
        "config_sha256",
        "dependency_lock_sha256",
        "broker_spec_sha256",
        "session_calendar_sha256",
        "evidence_contract_sha256",
        "broker_profile_sha256",
        "runtime_profile_sha256",
        "model_artifact_sha256",
        "champion_archive_sha256",
        "champion_package_identity_sha256",
        "champion_training_snapshot_sha256",
        "champion_git_tree",
        "champion_runtime_binding_sha256",
        "acceptance_authority_policy_sha256",
        "manual_demo_custodian_trust_sha256",
    }
)
_STAGE_DOCUMENT_FIELDS = frozenset(
    {"schema_version", "binding", "binding_sha256"}
)
_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "source_identity_sha256",
        "members",
        "production_config_source_sha256",
        "bootstrap_binding_sha256",
        "stage_binding_sha256",
        "champion",
        "safety",
        "effects",
    }
)
_MEMBER_FIELDS = frozenset({"path", "size_bytes", "sha256"})
_CHAMPION_FIELDS = frozenset(
    {
        "archive_sha256",
        "package_identity_sha256",
        "model_artifact_sha256",
        "training_snapshot_sha256",
        "config_sha256",
        "git_commit",
        "git_tree",
        "runtime_binding_sha256",
    }
)
_CONFIG_HASH_FIELDS = frozenset(
    name
    for name in _CONFIG_FIELDS
    if name.endswith("_sha256")
    and name
    not in {
        "commit_sha",
        "manual_approval_key_fingerprint_sha256",
        "demo_auto_session_binding_sha256",
        "demo_auto_session_custody_key_fingerprint_sha256",
    }
)
_STAGE_HASH_FIELDS = frozenset(
    name
    for name in _STAGE_FIELDS
    if name.endswith("_sha256") and name != "commit_sha"
)
_TRUST_KEY_FIELDS = (
    "credential_session_key_id",
    "journal_provisioning_key_id",
    "worm_audit_key_id",
    "supervisor_key_id",
    "supervisor_checkpoint_key_id",
    "news_guard_key_id",
    "risk_ledger_key_id",
    "journal_checkpoint_key_id",
)
_TRUST_FINGERPRINT_FIELDS = (
    "credential_session_key_fingerprint_sha256",
    "journal_provisioning_key_fingerprint_sha256",
    "worm_audit_key_fingerprint_sha256",
    "supervisor_key_fingerprint_sha256",
    "supervisor_checkpoint_key_fingerprint_sha256",
    "risk_ledger_key_fingerprint_sha256",
    "journal_checkpoint_key_fingerprint_sha256",
    "news_guard_key_fingerprint_sha256",
    "permit_secret_fingerprint_sha256",
)


class WindowsExecutionProductionConfigSourceError(RuntimeError):
    """One source artifact failed closed with a stable reason code."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class WindowsExecutionProductionConfigSourceVerification:
    """Sealed result of exact seven-pin source verification."""

    archive_path: Path
    archive_sha256: str
    archive_size_bytes: int
    source_identity_sha256: str
    production_config_source_sha256: str
    bootstrap_binding_sha256: str
    stage_binding_sha256: str
    champion_archive_sha256: str
    champion_package_identity_sha256: str
    champion_model_artifact_sha256: str
    champion_training_snapshot_sha256: str
    champion_config_sha256: str
    champion_git_commit: str
    champion_git_tree: str
    champion_runtime_binding_sha256: str
    production_config_bytes: bytes = field(repr=False)
    stage_binding_bytes: bytes = field(repr=False)
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _REPORT_SEAL:
            raise TypeError("verified configuration sources require verifier seal")

    @property
    def safety(self) -> dict[str, object]:
        return dict(SAFETY)

    @property
    def provider_accepted(self) -> bool:
        return False

    @property
    def production_execution_ready(self) -> bool:
        return False

    @property
    def promotion_eligible(self) -> bool:
        return False

    @property
    def live_allowed(self) -> bool:
        return False

    @property
    def safe_to_demo_auto_order(self) -> bool:
        return False

    @property
    def order_capability(self) -> str:
        return ORDER_CAPABILITY


def _reject(reason_code: str) -> None:
    raise WindowsExecutionProductionConfigSourceError(reason_code)


def _sha256(data: bytes) -> str:
    if type(data) is not bytes:
        raise TypeError("hash input must be exact bytes")
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(payload: object) -> bytes:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WindowsExecutionProductionConfigSourceError(
            "SOURCE_JSON_INVALID"
        ) from exc


def canonical_source_file(payload: object) -> bytes:
    """Return the only accepted JSON file encoding for this artifact."""

    return _canonical_bytes(payload) + b"\n"


def _duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            _reject("SOURCE_JSON_DUPLICATE_KEY")
        output[key] = value
    return output


def _nonfinite(_value: str) -> object:
    _reject("SOURCE_JSON_NONFINITE_VALUE")


def strict_source_json(data: bytes, *, maximum_bytes: int) -> dict[str, object]:
    if (
        type(data) is not bytes
        or not data
        or len(data) > maximum_bytes
        or not data.endswith(b"\n")
        or data.endswith(b"\n\n")
    ):
        _reject("SOURCE_JSON_INVALID")
    try:
        payload = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicate_object,
            parse_constant=_nonfinite,
        )
    except WindowsExecutionProductionConfigSourceError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise WindowsExecutionProductionConfigSourceError(
            "SOURCE_JSON_INVALID"
        ) from exc
    if type(payload) is not dict or canonical_source_file(payload) != data:
        _reject("SOURCE_JSON_INVALID")
    return payload


def _is_hash(value: object, pattern: re.Pattern[str], *, nonzero: bool = True) -> bool:
    return (
        type(value) is str
        and pattern.fullmatch(value) is not None
        and (not nonzero or set(value) != {"0"})
    )


def _pin(value: object, pattern: re.Pattern[str]) -> str:
    if not _is_hash(value, pattern):
        _reject("SOURCE_EXTERNAL_PIN_INVALID")
    return str(value)


def _text(value: object) -> bool:
    return type(value) is str and bool(value) and value == value.strip()


def _absolute_path(value: object) -> bool:
    if not _text(value) or "\x00" in str(value):
        return False
    return Path(str(value)).is_absolute() or PureWindowsPath(str(value)).is_absolute()


def _pairs(value: object, *, allow_empty: bool) -> tuple[tuple[str, str], ...]:
    if type(value) is not list or (not value and not allow_empty):
        _reject("SOURCE_PRODUCTION_CONFIG_INVALID")
    result: list[tuple[str, str]] = []
    for item in value:
        if (
            type(item) is not list
            or len(item) != 2
            or not _text(item[0])
            or not _text(item[1])
            or str(item[0]).upper() != item[0]
        ):
            _reject("SOURCE_PRODUCTION_CONFIG_INVALID")
        result.append((str(item[0]), str(item[1])))
    if tuple(result) != tuple(sorted(result)):
        _reject("SOURCE_PRODUCTION_CONFIG_INVALID")
    if len({item[0] for item in result}) != len(result):
        _reject("SOURCE_PRODUCTION_CONFIG_INVALID")
    if len({item[1] for item in result}) != len(result):
        _reject("SOURCE_PRODUCTION_CONFIG_INVALID")
    return tuple(result)


def _validate_production_config(payload: dict[str, object]) -> str:
    if set(payload) != _CONFIG_FIELDS:
        _reject("SOURCE_PRODUCTION_CONFIG_INVALID")
    if (
        payload.get("schema_version") != BOOTSTRAP_SCHEMA_VERSION
        or payload.get("environment") != "DEMO"
        or payload.get("mode") != "DEMO"
        or payload.get("live_allowed") is not False
        or payload.get("safe_to_demo_auto_order") is not False
        or payload.get("order_capability") != ORDER_CAPABILITY
        or payload.get("mt5_distribution_version")
        != EXPECTED_MT5_DISTRIBUTION_VERSION
        or payload.get("mt5_wheel_sha256") != EXPECTED_MT5_WHEEL_SHA256
        or not _text(payload.get("broker_legal_name"))
        or not _text(payload.get("server"))
        or type(payload.get("account_currency")) is not str
        or re.fullmatch(r"[A-Z]{3}", str(payload.get("account_currency"))) is None
    ):
        _reject("SOURCE_PRODUCTION_CONFIG_INVALID")
    for name in _CONFIG_HASH_FIELDS:
        if not _is_hash(payload.get(name), _HEX_64):
            _reject("SOURCE_PRODUCTION_CONFIG_INVALID")
    if (
        not _is_hash(payload.get("commit_sha"), _HEX_40)
        or not _is_hash(payload.get("champion_git_tree"), _HEX_40)
    ):
        _reject("SOURCE_PRODUCTION_CONFIG_INVALID")
    for name in (
        "journal_database",
        "supervisor_database",
        "dependency_lock_file",
    ):
        if not _absolute_path(payload.get(name)):
            _reject("SOURCE_PRODUCTION_CONFIG_INVALID")
    if (
        payload["journal_database"] == payload["supervisor_database"]
        or PurePosixPath(str(payload["dependency_lock_file"])).name
        != "pylock.windows-cp312.toml"
        and PureWindowsPath(str(payload["dependency_lock_file"])).name
        != "pylock.windows-cp312.toml"
    ):
        _reject("SOURCE_PRODUCTION_CONFIG_INVALID")
    _pairs(payload.get("symbol_map"), allow_empty=False)
    _pairs(payload.get("usd_account_currency_symbols"), allow_empty=True)
    for name in (
        "news_guard_provider_id",
        "news_guard_key_id",
        "supervisor_key_id",
        "supervisor_checkpoint_key_id",
        "credential_session_key_id",
        "journal_provisioning_key_id",
        "worm_audit_key_id",
        "risk_ledger_id",
        "risk_ledger_key_id",
        "journal_checkpoint_key_id",
        "mt5_distribution_version",
    ):
        if not _text(payload.get(name)):
            _reject("SOURCE_PRODUCTION_CONFIG_INVALID")
    key_ids = tuple(str(payload[name]) for name in _TRUST_KEY_FIELDS)
    fingerprints = tuple(str(payload[name]) for name in _TRUST_FINGERPRINT_FIELDS)
    if len(set(key_ids)) != len(key_ids) or len(set(fingerprints)) != len(fingerprints):
        _reject("SOURCE_PRODUCTION_CONFIG_INVALID")
    for name, minimum in (
        ("magic_number", 1),
        ("deviation_points", 0),
        ("max_tick_age_seconds", 1),
    ):
        value = payload.get(name)
        if type(value) is not int or value < minimum:
            _reject("SOURCE_PRODUCTION_CONFIG_INVALID")
    ttl = payload.get("intent_ttl_seconds")
    if type(ttl) not in {int, float} or not 0 < float(ttl) <= 1:
        _reject("SOURCE_PRODUCTION_CONFIG_INVALID")
    manual = (
        payload.get("expected_manual_approver_id"),
        payload.get("expected_manual_approval_key_id"),
        payload.get("manual_approval_key_fingerprint_sha256"),
    )
    if any(value is not None for value in manual):
        if (
            not all(value is not None for value in manual)
            or not _text(manual[0])
            or not _text(manual[1])
            or not _is_hash(manual[2], _HEX_64)
            or manual[1] in key_ids
            or manual[2] in fingerprints
        ):
            _reject("SOURCE_PRODUCTION_CONFIG_INVALID")
    demo_auto = (
        payload.get("demo_auto_session_binding_sha256"),
        payload.get("demo_auto_session_ledger_id"),
        payload.get("demo_auto_session_custody_key_id"),
        payload.get("demo_auto_session_custody_key_fingerprint_sha256"),
    )
    if any(value is not None for value in demo_auto):
        _reject("SOURCE_PRODUCTION_CONFIG_INVALID")
    return _sha256(_canonical_bytes(payload))


def _validate_stage_document(
    payload: dict[str, object],
) -> tuple[dict[str, object], str]:
    binding = payload.get("binding")
    if (
        set(payload) != _STAGE_DOCUMENT_FIELDS
        or payload.get("schema_version") != STAGE_SCHEMA_VERSION
        or type(binding) is not dict
        or set(binding) != _STAGE_FIELDS
    ):
        _reject("SOURCE_STAGE_BINDING_INVALID")
    assert isinstance(binding, dict)
    for name in (
        "broker_id",
        "server",
        "environment",
        "symbol",
        "strategy",
        "lane_id",
    ):
        if not _text(binding.get(name)):
            _reject("SOURCE_STAGE_BINDING_INVALID")
    if (
        _IDENTIFIER.fullmatch(str(binding["broker_id"])) is None
        or binding["environment"] != "DEMO"
        or binding["symbol"] != str(binding["symbol"]).upper()
        or binding["strategy"] != str(binding["strategy"]).upper()
        or binding["lane_id"]
        != f"{binding['symbol']}:{binding['strategy']}:{binding['config_sha256']}"
        or not _is_hash(binding.get("commit_sha"), _HEX_40)
        or not _is_hash(binding.get("champion_git_tree"), _HEX_40)
    ):
        _reject("SOURCE_STAGE_BINDING_INVALID")
    for name in _STAGE_HASH_FIELDS:
        if not _is_hash(binding.get(name), _HEX_64):
            _reject("SOURCE_STAGE_BINDING_INVALID")
    observed = _sha256(_canonical_bytes(binding))
    if payload.get("binding_sha256") != observed:
        _reject("SOURCE_STAGE_BINDING_INVALID")
    return binding, observed


def _validate_cross_bindings(
    config: dict[str, object],
    stage: dict[str, object],
    stage_sha256: str,
    champion: Mapping[str, object],
) -> None:
    direct = {
        "account_alias_sha256": "account_alias_sha256",
        "server": "server",
        "environment": "environment",
        "journal_sha256": "journal_sha256",
        "config_sha256": "config_sha256",
        "dependency_lock_sha256": "dependency_lock_sha256",
        "broker_spec_sha256": "broker_spec_sha256",
        "session_calendar_sha256": "session_calendar_sha256",
        "manual_demo_custodian_trust_sha256": (
            "manual_demo_custodian_trust_sha256"
        ),
        "commit_sha": "commit_sha",
        "champion_archive_sha256": "champion_archive_sha256",
        "champion_package_identity_sha256": (
            "champion_package_identity_sha256"
        ),
        "champion_training_snapshot_sha256": (
            "champion_training_snapshot_sha256"
        ),
        "champion_git_tree": "champion_git_tree",
        "champion_runtime_binding_sha256": (
            "champion_runtime_binding_sha256"
        ),
    }
    if any(config[left] != stage[right] for left, right in direct.items()):
        _reject("SOURCE_CONFIG_STAGE_MISMATCH")
    if config.get("stage_binding_sha256") != stage_sha256:
        _reject("SOURCE_CONFIG_STAGE_MISMATCH")
    symbol = stage["symbol"]
    symbols = _pairs(config["symbol_map"], allow_empty=False)
    if sum(item[0] == symbol for item in symbols) != 1:
        _reject("SOURCE_CONFIG_STAGE_MISMATCH")
    champion_expected = {
        "archive_sha256": config["champion_archive_sha256"],
        "package_identity_sha256": config[
            "champion_package_identity_sha256"
        ],
        "model_artifact_sha256": stage["model_artifact_sha256"],
        "training_snapshot_sha256": config[
            "champion_training_snapshot_sha256"
        ],
        "config_sha256": config["config_sha256"],
        "git_commit": config["commit_sha"],
        "git_tree": config["champion_git_tree"],
        "runtime_binding_sha256": config[
            "champion_runtime_binding_sha256"
        ],
    }
    if any(champion.get(name) != value for name, value in champion_expected.items()):
        _reject("SOURCE_CHAMPION_BINDING_MISMATCH")


def _manifest_identity(payload: Mapping[str, object]) -> str:
    core = dict(payload)
    core.pop("source_identity_sha256", None)
    return _sha256(_canonical_bytes(core))


def _build_manifest(
    *,
    config_bytes: bytes,
    stage_bytes: bytes,
    champion_bytes: bytes,
    bootstrap_binding_sha256: str,
    stage_binding_sha256: str,
    champion: Mapping[str, object],
) -> dict[str, object]:
    payloads = {
        CONFIG_MEMBER: config_bytes,
        CHAMPION_MEMBER: champion_bytes,
        STAGE_MEMBER: stage_bytes,
    }
    unsigned: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "members": [
            {
                "path": path,
                "size_bytes": len(payloads[path]),
                "sha256": _sha256(payloads[path]),
            }
            for path in PAYLOAD_MEMBERS
        ],
        "production_config_source_sha256": _sha256(config_bytes),
        "bootstrap_binding_sha256": bootstrap_binding_sha256,
        "stage_binding_sha256": stage_binding_sha256,
        "champion": {
            name: champion[name]
            for name in sorted(_CHAMPION_FIELDS)
        },
        "safety": dict(SAFETY),
        "effects": dict(EFFECTS),
    }
    return {
        **unsigned,
        "source_identity_sha256": _manifest_identity(unsigned),
    }


def _validate_manifest(
    payload: dict[str, object],
) -> tuple[dict[str, dict[str, object]], dict[str, object]]:
    champion = payload.get("champion")
    rows = payload.get("members")
    if (
        set(payload) != _MANIFEST_FIELDS
        or payload.get("schema_version") != SCHEMA_VERSION
        or payload.get("safety") != SAFETY
        or payload.get("effects") != EFFECTS
        or type(champion) is not dict
        or set(champion) != _CHAMPION_FIELDS
        or type(rows) is not list
        or payload.get("source_identity_sha256") != _manifest_identity(payload)
    ):
        _reject("SOURCE_MANIFEST_INVALID")
    assert isinstance(champion, dict)
    for name in _CHAMPION_FIELDS:
        pattern = _HEX_40 if name in {"git_commit", "git_tree"} else _HEX_64
        if not _is_hash(champion.get(name), pattern):
            _reject("SOURCE_MANIFEST_INVALID")
    for name in (
        "production_config_source_sha256",
        "bootstrap_binding_sha256",
        "stage_binding_sha256",
    ):
        if not _is_hash(payload.get(name), _HEX_64):
            _reject("SOURCE_MANIFEST_INVALID")
    if len(rows) != len(PAYLOAD_MEMBERS):
        _reject("SOURCE_MANIFEST_INVALID")
    result: dict[str, dict[str, object]] = {}
    order: list[str] = []
    for row in rows:
        if type(row) is not dict or set(row) != _MEMBER_FIELDS:
            _reject("SOURCE_MANIFEST_INVALID")
        path = row.get("path")
        size = row.get("size_bytes")
        digest = row.get("sha256")
        if (
            path not in PAYLOAD_MEMBERS
            or type(size) is not int
            or size <= 0
            or not _is_hash(digest, _HEX_64)
            or str(path).casefold() in {item.casefold() for item in result}
        ):
            _reject("SOURCE_MANIFEST_INVALID")
        result[str(path)] = row
        order.append(str(path))
    if tuple(order) != PAYLOAD_MEMBERS or tuple(result) != PAYLOAD_MEMBERS:
        _reject("SOURCE_MANIFEST_INVALID")
    return result, champion


def _valid_member_path(value: object) -> bool:
    if type(value) is not str or not value or "\\" in value or ":" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and str(path) == value
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _zip_inventory(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    try:
        infos = archive.infolist()
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise WindowsExecutionProductionConfigSourceError(
            "SOURCE_ZIP_INVALID"
        ) from exc
    if (
        len(infos) != len(ARCHIVE_MEMBERS)
        or tuple(info.filename for info in infos) != ARCHIVE_MEMBERS
        or archive.comment != b""
    ):
        _reject("SOURCE_ZIP_INVENTORY_INVALID")
    observed: dict[str, zipfile.ZipInfo] = {}
    offsets: set[int] = set()
    total = 0
    for info in infos:
        mode = (info.external_attr >> 16) & 0xFFFF
        maximum = (
            MAX_CHAMPION_BYTES
            if info.filename == CHAMPION_MEMBER
            else MAX_JSON_MEMBER_BYTES
        )
        if (
            not _valid_member_path(info.filename)
            or info.filename.casefold()
            in {name.casefold() for name in observed}
            or info.is_dir()
            or info.compress_type != zipfile.ZIP_DEFLATED
            or info.flag_bits != 0
            or info.date_time != FIXED_ZIP_TIMESTAMP
            or info.create_system != 3
            or info.create_version != 20
            or info.extract_version != 20
            or mode != FIXED_ZIP_MODE
            or info.external_attr != FIXED_ZIP_MODE << 16
            or info.internal_attr != 0
            or info.volume != 0
            or info.extra != b""
            or info.comment != b""
            or info.file_size <= 0
            or info.file_size > maximum
            or info.compress_size <= 0
            or info.header_offset in offsets
        ):
            _reject("SOURCE_ZIP_METADATA_INVALID")
        observed[info.filename] = info
        offsets.add(info.header_offset)
        total += info.file_size
    if total > MAX_EXPANDED_BYTES or set(observed) != set(ARCHIVE_MEMBERS):
        _reject("SOURCE_ZIP_INVENTORY_INVALID")
    return observed


def _validate_eocd(data: bytes) -> None:
    if len(data) < 22:
        _reject("SOURCE_ZIP_INVALID")
    eocd = data[-22:]
    if (
        eocd[:4] != b"PK\x05\x06"
        or int.from_bytes(eocd[4:6], "little") != 0
        or int.from_bytes(eocd[6:8], "little") != 0
        or int.from_bytes(eocd[8:10], "little") != len(ARCHIVE_MEMBERS)
        or int.from_bytes(eocd[10:12], "little") != len(ARCHIVE_MEMBERS)
        or int.from_bytes(eocd[20:22], "little") != 0
    ):
        _reject("SOURCE_ZIP_INVALID")
    central_size = int.from_bytes(eocd[12:16], "little")
    central_offset = int.from_bytes(eocd[16:20], "little")
    if (
        central_size in {0, 0xFFFFFFFF}
        or central_offset == 0xFFFFFFFF
        or central_offset + central_size != len(data) - 22
    ):
        _reject("SOURCE_ZIP_INVALID")


def _read_zip_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    maximum_bytes: int,
) -> bytes:
    try:
        with archive.open(info, "r") as source:
            data = source.read(maximum_bytes + 1)
    except (OSError, RuntimeError, EOFError, zipfile.BadZipFile) as exc:
        raise WindowsExecutionProductionConfigSourceError(
            "SOURCE_ZIP_INVALID"
        ) from exc
    if len(data) != info.file_size or len(data) > maximum_bytes:
        _reject("SOURCE_ZIP_INVALID")
    return data


def _verify_archive_bytes(
    data: bytes,
    *,
    archive_path: Path,
    expected_source_archive_sha256: str,
    expected_champion_archive_sha256: str,
    expected_model_artifact_sha256: str,
    expected_training_snapshot_sha256: str,
    expected_config_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
) -> WindowsExecutionProductionConfigSourceVerification:
    pins = {
        "source": _pin(expected_source_archive_sha256, _HEX_64),
        "champion": _pin(expected_champion_archive_sha256, _HEX_64),
        "model": _pin(expected_model_artifact_sha256, _HEX_64),
        "snapshot": _pin(expected_training_snapshot_sha256, _HEX_64),
        "config": _pin(expected_config_sha256, _HEX_64),
        "commit": _pin(expected_git_commit, _HEX_40),
        "tree": _pin(expected_git_tree, _HEX_40),
    }
    if type(data) is not bytes or not data or len(data) > MAX_ARCHIVE_BYTES:
        _reject("SOURCE_ARCHIVE_INVALID")
    observed_archive = _sha256(data)
    if observed_archive != pins["source"]:
        _reject("SOURCE_ARCHIVE_PIN_MISMATCH")
    _validate_eocd(data)
    try:
        archive = zipfile.ZipFile(io.BytesIO(data), "r")
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise WindowsExecutionProductionConfigSourceError(
            "SOURCE_ZIP_INVALID"
        ) from exc
    with archive:
        inventory = _zip_inventory(archive)
        manifest_bytes = _read_zip_member(
            archive,
            inventory[MANIFEST_MEMBER],
            MAX_JSON_MEMBER_BYTES,
        )
        config_bytes = _read_zip_member(
            archive,
            inventory[CONFIG_MEMBER],
            MAX_JSON_MEMBER_BYTES,
        )
        stage_bytes = _read_zip_member(
            archive,
            inventory[STAGE_MEMBER],
            MAX_JSON_MEMBER_BYTES,
        )
        champion_bytes = _read_zip_member(
            archive,
            inventory[CHAMPION_MEMBER],
            MAX_CHAMPION_BYTES,
        )
    manifest = strict_source_json(
        manifest_bytes,
        maximum_bytes=MAX_JSON_MEMBER_BYTES,
    )
    rows, manifest_champion = _validate_manifest(manifest)
    payloads = {
        CONFIG_MEMBER: config_bytes,
        CHAMPION_MEMBER: champion_bytes,
        STAGE_MEMBER: stage_bytes,
    }
    for name in PAYLOAD_MEMBERS:
        if (
            rows[name]["size_bytes"] != len(payloads[name])
            or rows[name]["sha256"] != _sha256(payloads[name])
        ):
            _reject("SOURCE_MEMBER_MISMATCH")
    config = strict_source_json(
        config_bytes,
        maximum_bytes=MAX_JSON_MEMBER_BYTES,
    )
    stage_document = strict_source_json(
        stage_bytes,
        maximum_bytes=MAX_JSON_MEMBER_BYTES,
    )
    bootstrap_binding = _validate_production_config(config)
    stage, stage_binding = _validate_stage_document(stage_document)
    try:
        champion = verify_archive_with_pins(
            champion_bytes,
            expected_archive_sha256=pins["champion"],
            expected_model_artifact_sha256=pins["model"],
            expected_training_snapshot_sha256=pins["snapshot"],
            expected_config_sha256=pins["config"],
            expected_git_commit=pins["commit"],
            expected_git_tree=pins["tree"],
        )
    except (RuleCoreModelArtifactError, TypeError, ValueError) as exc:
        raise WindowsExecutionProductionConfigSourceError(
            "SOURCE_CHAMPION_INVALID"
        ) from exc
    _validate_cross_bindings(config, stage, stage_binding, champion)
    expected_champion = {
        name: champion[name] for name in _CHAMPION_FIELDS
    }
    if (
        manifest.get("production_config_source_sha256") != _sha256(config_bytes)
        or manifest.get("bootstrap_binding_sha256") != bootstrap_binding
        or manifest.get("stage_binding_sha256") != stage_binding
        or manifest_champion != expected_champion
    ):
        _reject("SOURCE_MANIFEST_BINDING_MISMATCH")
    return WindowsExecutionProductionConfigSourceVerification(
        archive_path=archive_path,
        archive_sha256=observed_archive,
        archive_size_bytes=len(data),
        source_identity_sha256=str(manifest["source_identity_sha256"]),
        production_config_source_sha256=_sha256(config_bytes),
        bootstrap_binding_sha256=bootstrap_binding,
        stage_binding_sha256=stage_binding,
        champion_archive_sha256=str(champion["archive_sha256"]),
        champion_package_identity_sha256=str(
            champion["package_identity_sha256"]
        ),
        champion_model_artifact_sha256=str(
            champion["model_artifact_sha256"]
        ),
        champion_training_snapshot_sha256=str(
            champion["training_snapshot_sha256"]
        ),
        champion_config_sha256=str(champion["config_sha256"]),
        champion_git_commit=str(champion["git_commit"]),
        champion_git_tree=str(champion["git_tree"]),
        champion_runtime_binding_sha256=str(
            champion["runtime_binding_sha256"]
        ),
        production_config_bytes=config_bytes,
        stage_binding_bytes=stage_bytes,
        _seal=_REPORT_SEAL,
    )


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        getattr(left, name, None) == getattr(right, name, None)
        for name in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
    )


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        getattr(left, name, None) == getattr(right, name, None)
        for name in ("st_dev", "st_ino", "st_mode")
    )


def _read_regular_bytes(
    path: str | Path,
    *,
    maximum_bytes: int,
) -> tuple[Path, bytes]:
    candidate = Path(path).expanduser().absolute()
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise WindowsExecutionProductionConfigSourceError(
            "SOURCE_INPUT_INVALID"
        ) from exc
    if (
        candidate != resolved
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or metadata.st_size <= 0
        or metadata.st_size > maximum_bytes
    ):
        _reject("SOURCE_INPUT_INVALID")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    handle: BinaryIO | None = None
    try:
        descriptor = os.open(candidate, flags)
        handle = os.fdopen(descriptor, "rb")
        opened = os.fstat(handle.fileno())
        if not _same_stat(metadata, opened):
            _reject("SOURCE_INPUT_UNSTABLE")
        data = handle.read(maximum_bytes + 1)
        after = os.fstat(handle.fileno())
        current = candidate.lstat()
        current_resolved = candidate.resolve(strict=True)
    except WindowsExecutionProductionConfigSourceError:
        raise
    except OSError as exc:
        raise WindowsExecutionProductionConfigSourceError(
            "SOURCE_INPUT_UNSTABLE"
        ) from exc
    finally:
        if handle is not None:
            handle.close()
    if (
        len(data) != opened.st_size
        or len(data) > maximum_bytes
        or candidate != current_resolved
        or not _same_stat(opened, after)
        or not _same_stat(opened, current)
    ):
        _reject("SOURCE_INPUT_UNSTABLE")
    return candidate, data


def verify_windows_execution_production_config_source(
    archive_path: str | Path,
    *,
    expected_source_archive_sha256: str,
    expected_champion_archive_sha256: str,
    expected_model_artifact_sha256: str,
    expected_training_snapshot_sha256: str,
    expected_config_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
) -> WindowsExecutionProductionConfigSourceVerification:
    """Verify one source archive against seven independent pins."""

    path, data = _read_regular_bytes(
        archive_path,
        maximum_bytes=MAX_ARCHIVE_BYTES,
    )
    return _verify_archive_bytes(
        data,
        archive_path=path,
        expected_source_archive_sha256=expected_source_archive_sha256,
        expected_champion_archive_sha256=expected_champion_archive_sha256,
        expected_model_artifact_sha256=expected_model_artifact_sha256,
        expected_training_snapshot_sha256=expected_training_snapshot_sha256,
        expected_config_sha256=expected_config_sha256,
        expected_git_commit=expected_git_commit,
        expected_git_tree=expected_git_tree,
    )


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = FIXED_ZIP_MODE << 16
    return info


def _archive_bytes(members: Mapping[str, bytes]) -> bytes:
    destination = io.BytesIO()
    try:
        with zipfile.ZipFile(
            destination,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            for name in ARCHIVE_MEMBERS:
                archive.writestr(
                    _zip_info(name),
                    members[name],
                    compress_type=zipfile.ZIP_DEFLATED,
                    compresslevel=9,
                )
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        raise WindowsExecutionProductionConfigSourceError(
            "SOURCE_ARCHIVE_BUILD_FAILED"
        ) from exc
    data = destination.getvalue()
    if not data or len(data) > MAX_ARCHIVE_BYTES:
        _reject("SOURCE_ARCHIVE_BUILD_FAILED")
    return data


def _validate_destination(output: str | Path) -> tuple[Path, os.stat_result]:
    candidate = Path(output).expanduser().absolute()
    if _OUTPUT_NAME.fullmatch(candidate.name) is None:
        _reject("SOURCE_DESTINATION_INVALID")
    parent = candidate.parent
    try:
        metadata = parent.lstat()
        resolved = parent.resolve(strict=True)
    except OSError as exc:
        raise WindowsExecutionProductionConfigSourceError(
            "SOURCE_DESTINATION_INVALID"
        ) from exc
    if (
        parent != resolved
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or os.path.lexists(candidate)
    ):
        _reject("SOURCE_DESTINATION_INVALID")
    return candidate, metadata


def _remove_created_output(
    path: Path,
    identity: os.stat_result | None,
    expected_bytes: bytes,
) -> None:
    if identity is None:
        return
    try:
        current = path.lstat()
        if (
            stat.S_ISREG(current.st_mode)
            and not stat.S_ISLNK(current.st_mode)
            and not _is_reparse(current)
            and _same_identity(identity, current)
            and current.st_size == len(expected_bytes)
            and path.read_bytes() == expected_bytes
        ):
            path.unlink()
    except OSError:
        pass


def _publish_exclusive(
    output: Path,
    data: bytes,
    parent_state: os.stat_result,
) -> os.stat_result:
    try:
        current_parent = output.parent.stat(follow_symlinks=False)
    except OSError as exc:
        raise WindowsExecutionProductionConfigSourceError(
            "SOURCE_PUBLICATION_FAILED"
        ) from exc
    if (
        not _same_identity(parent_state, current_parent)
        or output.parent.is_symlink()
        or _is_reparse(current_parent)
        or os.path.lexists(output)
    ):
        _reject("SOURCE_PUBLICATION_FAILED")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    descriptor: int | None = None
    identity: os.stat_result | None = None
    try:
        descriptor = os.open(output, flags, 0o600)
        identity = os.fstat(descriptor)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        current = output.lstat()
        if (
            not stat.S_ISREG(current.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or _is_reparse(current)
            or not _same_identity(identity, current)
            or current.st_size != len(data)
        ):
            _reject("SOURCE_PUBLICATION_FAILED")
        return identity
    except WindowsExecutionProductionConfigSourceError:
        _remove_created_output(output, identity, data)
        raise
    except OSError as exc:
        _remove_created_output(output, identity, data)
        raise WindowsExecutionProductionConfigSourceError(
            "SOURCE_PUBLICATION_FAILED"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def prepare_windows_execution_production_config_source(
    *,
    production_config_path: str | Path,
    stage_binding_path: str | Path,
    champion_artifact_path: str | Path,
    expected_champion_archive_sha256: str,
    expected_model_artifact_sha256: str,
    expected_training_snapshot_sha256: str,
    expected_config_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
    output: str | Path,
) -> WindowsExecutionProductionConfigSourceVerification:
    """Prepare, self-verify, and exclusively publish one exact source ZIP."""

    pins = {
        "champion": _pin(expected_champion_archive_sha256, _HEX_64),
        "model": _pin(expected_model_artifact_sha256, _HEX_64),
        "snapshot": _pin(expected_training_snapshot_sha256, _HEX_64),
        "config": _pin(expected_config_sha256, _HEX_64),
        "commit": _pin(expected_git_commit, _HEX_40),
        "tree": _pin(expected_git_tree, _HEX_40),
    }
    destination, parent_state = _validate_destination(output)
    _config_path, config_bytes = _read_regular_bytes(
        production_config_path,
        maximum_bytes=MAX_JSON_MEMBER_BYTES,
    )
    _stage_path, stage_bytes = _read_regular_bytes(
        stage_binding_path,
        maximum_bytes=MAX_JSON_MEMBER_BYTES,
    )
    _champion_path, champion_bytes = _read_regular_bytes(
        champion_artifact_path,
        maximum_bytes=MAX_CHAMPION_BYTES,
    )
    config = strict_source_json(
        config_bytes,
        maximum_bytes=MAX_JSON_MEMBER_BYTES,
    )
    stage_document = strict_source_json(
        stage_bytes,
        maximum_bytes=MAX_JSON_MEMBER_BYTES,
    )
    bootstrap_binding = _validate_production_config(config)
    stage, stage_binding = _validate_stage_document(stage_document)
    try:
        champion = verify_archive_with_pins(
            champion_bytes,
            expected_archive_sha256=pins["champion"],
            expected_model_artifact_sha256=pins["model"],
            expected_training_snapshot_sha256=pins["snapshot"],
            expected_config_sha256=pins["config"],
            expected_git_commit=pins["commit"],
            expected_git_tree=pins["tree"],
        )
    except (RuleCoreModelArtifactError, TypeError, ValueError) as exc:
        raise WindowsExecutionProductionConfigSourceError(
            "SOURCE_CHAMPION_INVALID"
        ) from exc
    _validate_cross_bindings(config, stage, stage_binding, champion)
    manifest = _build_manifest(
        config_bytes=config_bytes,
        stage_bytes=stage_bytes,
        champion_bytes=champion_bytes,
        bootstrap_binding_sha256=bootstrap_binding,
        stage_binding_sha256=stage_binding,
        champion=champion,
    )
    data = _archive_bytes(
        {
            MANIFEST_MEMBER: canonical_source_file(manifest),
            CONFIG_MEMBER: config_bytes,
            CHAMPION_MEMBER: champion_bytes,
            STAGE_MEMBER: stage_bytes,
        }
    )
    archive_sha256 = _sha256(data)
    _verify_archive_bytes(
        data,
        archive_path=destination,
        expected_source_archive_sha256=archive_sha256,
        expected_champion_archive_sha256=pins["champion"],
        expected_model_artifact_sha256=pins["model"],
        expected_training_snapshot_sha256=pins["snapshot"],
        expected_config_sha256=pins["config"],
        expected_git_commit=pins["commit"],
        expected_git_tree=pins["tree"],
    )
    identity: os.stat_result | None = None
    try:
        identity = _publish_exclusive(destination, data, parent_state)
        return verify_windows_execution_production_config_source(
            destination,
            expected_source_archive_sha256=archive_sha256,
            expected_champion_archive_sha256=pins["champion"],
            expected_model_artifact_sha256=pins["model"],
            expected_training_snapshot_sha256=pins["snapshot"],
            expected_config_sha256=pins["config"],
            expected_git_commit=pins["commit"],
            expected_git_tree=pins["tree"],
        )
    except Exception:
        _remove_created_output(destination, identity, data)
        raise


__all__ = [
    "ARCHIVE_MEMBERS",
    "BOOTSTRAP_SCHEMA_VERSION",
    "CHAMPION_MEMBER",
    "CONFIG_MEMBER",
    "EFFECTS",
    "FIXED_ZIP_MODE",
    "FIXED_ZIP_TIMESTAMP",
    "MANIFEST_MEMBER",
    "MAX_ARCHIVE_BYTES",
    "MAX_CHAMPION_BYTES",
    "MAX_JSON_MEMBER_BYTES",
    "ORDER_CAPABILITY",
    "PAYLOAD_MEMBERS",
    "SAFETY",
    "SCHEMA_VERSION",
    "STAGE_MEMBER",
    "STAGE_SCHEMA_VERSION",
    "WindowsExecutionProductionConfigSourceError",
    "WindowsExecutionProductionConfigSourceVerification",
    "canonical_source_file",
    "prepare_windows_execution_production_config_source",
    "strict_source_json",
    "verify_windows_execution_production_config_source",
]
