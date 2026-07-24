"""Strict immutable artifacts for the deny-only Windows operations plan.

The operations model in :mod:`live_runtime.demo_soak_operations` is pure, but
an operator still needs a safe boundary for supplying reviewed host metadata
and exporting deterministic Task Scheduler review material.  This module is
that boundary.  It reads one exact, non-secret JSON document, constructs the
typed plan, and produces one self-verifying review bundle.

It deliberately has no credential backend, process launcher, shell, MT5,
network, task-installation, or broker-mutation capability.
"""

from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping, Sequence

from .contracts import canonical_sha256, require_hash, require_text, require_utc
from .demo_soak_operations import (
    CleanReleaseBinding,
    CredentialManagerReference,
    DemoSoakOperationsError,
    FailureDrillManifest,
    MT5AccountBinding,
    OffHostProviderReferences,
    OperationsThresholds,
    PythonRuntimeBinding,
    RuntimeProcessDefinition,
    RuntimeStoragePaths,
    WindowsDemoSoakOperationsPlan,
    WindowsSecurityPosture,
    assert_no_embedded_secrets,
    assess_operations_readiness,
)


INPUT_SCHEMA_VERSION = "windows-demo-soak-operations-input-v1"
BUNDLE_SCHEMA_VERSION = "windows-demo-soak-operations-review-bundle-v1"
MAXIMUM_INPUT_BYTES = 1_048_576

_INPUT_FIELDS = frozenset(
    {
        "schema_version",
        "release",
        "python",
        "broker",
        "credentials",
        "providers",
        "thresholds",
        "storage",
        "security",
        "processes",
        "watchdog_entrypoint_relative_path",
        "watchdog_entrypoint_sha256",
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
        "service_account_id",
        "rdp_ingress_scope",
        "vpn_required",
        "mfa_required",
        "least_privilege",
        "public_rdp_exposed",
        "firewall_policy_sha256",
        "event_log_source",
    }
)
_PROCESS_FIELDS = frozenset(
    {
        "role",
        "task_name",
        "entrypoint_relative_path",
        "arguments",
        "working_directory",
        "service_account_id",
        "entrypoint_sha256",
        "broker_mutation_capability",
    }
)
_CANONICAL_PLAN_FIELDS = frozenset(
    {
        "broker",
        "credentials",
        "execution_enabled",
        "live_allowed",
        "max_lot",
        "order_capability",
        "processes",
        "promotion_eligible",
        "providers",
        "python",
        "release",
        "safe_to_demo_auto_order",
        "schema_version",
        "security",
        "storage",
        "task_install_allowed",
        "thresholds",
        "watchdog_entrypoint_relative_path",
        "watchdog_entrypoint_sha256",
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
        "local_plan_valid",
        "signed_failure_drills_complete",
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
        "broker_mutation_performed",
    }
)
_SAFETY_FIELDS = frozenset(
    {
        "execution_enabled",
        "task_install_allowed",
        "safe_to_demo_auto_order",
        "live_allowed",
        "promotion_eligible",
        "order_capability",
        "max_lot",
    }
)


class OperationsArtifactError(RuntimeError):
    """Fail-closed input, bundle, or immutable-artifact error."""


def _mapping(
    value: object,
    *,
    fields: frozenset[str],
    label: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise OperationsArtifactError(f"{label.upper()}_FIELDS_DRIFT")
    return value


def _list(value: object, *, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise OperationsArtifactError(f"{label.upper()}_LIST_REQUIRED")
    return value


def _pairs(
    value: object,
    *,
    width: int,
    label: str,
    allow_tuple_rows: bool = False,
) -> tuple[tuple[Any, ...], ...]:
    rows = _list(value, label=label)
    normalized: list[tuple[Any, ...]] = []
    for row in rows:
        accepted_types = (list, tuple) if allow_tuple_rows else (list,)
        if not isinstance(row, accepted_types) or len(row) != width:
            raise OperationsArtifactError(f"{label.upper()}_ROW_INVALID")
        normalized.append(tuple(row))
    return tuple(normalized)


def _duplicate_rejecting_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise OperationsArtifactError("DUPLICATE_JSON_KEY")
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
            raise OperationsArtifactError("OPERATIONS_INPUT_FILE_INVALID")
        with source.open("rb") as handle:
            opened_before = os.fstat(handle.fileno())
            payload = handle.read(MAXIMUM_INPUT_BYTES + 1)
            opened_after = os.fstat(handle.fileno())
        after = source.lstat()
    except OperationsArtifactError:
        raise
    except OSError as exc:
        raise OperationsArtifactError("OPERATIONS_INPUT_FILE_UNAVAILABLE") from exc
    expected = _file_identity(before)
    if (
        _file_identity(opened_before) != expected
        or _file_identity(opened_after) != expected
        or _file_identity(after) != expected
        or len(payload) != before.st_size
        or len(payload) > MAXIMUM_INPUT_BYTES
    ):
        raise OperationsArtifactError("OPERATIONS_INPUT_CHANGED_DURING_READ")
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                OperationsArtifactError(f"NONFINITE_JSON_NUMBER_{value}")
            ),
        )
    except OperationsArtifactError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperationsArtifactError("OPERATIONS_INPUT_JSON_INVALID") from exc
    if not isinstance(document, Mapping):
        raise OperationsArtifactError("OPERATIONS_INPUT_OBJECT_REQUIRED")
    return document


def _plan_from_input_mapping(document: Mapping[str, Any]) -> WindowsDemoSoakOperationsPlan:
    root = _mapping(document, fields=_INPUT_FIELDS, label="operations_input")
    if root.get("schema_version") != INPUT_SCHEMA_VERSION:
        raise OperationsArtifactError("OPERATIONS_INPUT_SCHEMA_MISMATCH")
    assert_no_embedded_secrets(root)

    release_raw = _mapping(
        root["release"], fields=_RELEASE_FIELDS, label="release"
    )
    release_values = dict(release_raw)
    release_values["tracked_file_hashes"] = _pairs(
        release_raw["tracked_file_hashes"],
        width=2,
        label="tracked_file_hashes",
    )
    release = CleanReleaseBinding(**release_values)

    python_runtime = PythonRuntimeBinding(
        **dict(_mapping(root["python"], fields=_PYTHON_FIELDS, label="python"))
    )

    broker_raw = _mapping(root["broker"], fields=_BROKER_FIELDS, label="broker")
    broker_values = dict(broker_raw)
    broker_values["symbol_bindings"] = _pairs(
        broker_raw["symbol_bindings"],
        width=3,
        label="symbol_bindings",
    )
    broker = MT5AccountBinding(**broker_values)

    credentials = tuple(
        CredentialManagerReference(
            **dict(_mapping(value, fields=_CREDENTIAL_FIELDS, label="credential"))
        )
        for value in _list(root["credentials"], label="credentials")
    )
    providers = OffHostProviderReferences(
        **dict(_mapping(root["providers"], fields=_PROVIDER_FIELDS, label="providers"))
    )
    thresholds = OperationsThresholds(
        **dict(
            _mapping(
                root["thresholds"],
                fields=_THRESHOLD_FIELDS,
                label="thresholds",
            )
        )
    )
    storage = RuntimeStoragePaths(
        **dict(_mapping(root["storage"], fields=_STORAGE_FIELDS, label="storage"))
    )
    security = WindowsSecurityPosture(
        **dict(_mapping(root["security"], fields=_SECURITY_FIELDS, label="security"))
    )
    processes = tuple(
        RuntimeProcessDefinition(
            **{
                **dict(
                    _mapping(value, fields=_PROCESS_FIELDS, label="runtime_process")
                ),
                "arguments": tuple(
                    _list(
                        _mapping(
                            value,
                            fields=_PROCESS_FIELDS,
                            label="runtime_process",
                        )["arguments"],
                        label="process_arguments",
                    )
                ),
            }
        )
        for value in _list(root["processes"], label="processes")
    )
    return WindowsDemoSoakOperationsPlan(
        release=release,
        python=python_runtime,
        broker=broker,
        credentials=credentials,
        providers=providers,
        thresholds=thresholds,
        storage=storage,
        security=security,
        processes=processes,
        watchdog_entrypoint_relative_path=root[
            "watchdog_entrypoint_relative_path"
        ],
        watchdog_entrypoint_sha256=root["watchdog_entrypoint_sha256"],
    )


def load_windows_demo_soak_operations_plan(
    path: str | Path,
) -> WindowsDemoSoakOperationsPlan:
    """Load one exact reviewed, non-secret operations input document."""

    try:
        return _plan_from_input_mapping(_read_json_object(path))
    except (DemoSoakOperationsError, TypeError, ValueError) as exc:
        raise OperationsArtifactError(
            f"OPERATIONS_INPUT_REJECTED:{exc}"
        ) from exc


def _utc_text(value: datetime) -> str:
    return require_utc("timestamp", value).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _utc_from_text(value: object, *, label: str) -> datetime:
    text = require_text(label, value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        parsed = require_utc(label, parsed)
    except (TypeError, ValueError) as exc:
        raise OperationsArtifactError(f"{label.upper()}_INVALID") from exc
    if _utc_text(parsed) != text:
        raise OperationsArtifactError(f"{label.upper()}_NOT_CANONICAL_UTC")
    return parsed


def _canonical_plan_to_input(plan_payload: object) -> Mapping[str, Any]:
    canonical = _mapping(
        plan_payload,
        fields=_CANONICAL_PLAN_FIELDS,
        label="canonical_plan",
    )
    expected_locks = {
        "execution_enabled": False,
        "live_allowed": False,
        "max_lot": 0.01,
        "order_capability": "DISABLED",
        "promotion_eligible": False,
        "safe_to_demo_auto_order": False,
        "task_install_allowed": False,
        "schema_version": "windows-demo-soak-operations-v1",
    }
    if any(canonical.get(name) != value for name, value in expected_locks.items()):
        raise OperationsArtifactError("CANONICAL_PLAN_SAFETY_LOCK_DRIFT")
    release = dict(
        _mapping(canonical["release"], fields=_RELEASE_FIELDS, label="release")
    )
    release["tracked_file_hashes"] = [
        list(row)
        for row in _pairs(
            release["tracked_file_hashes"],
            width=2,
            label="tracked_file_hashes",
            allow_tuple_rows=True,
        )
    ]
    broker = dict(
        _mapping(canonical["broker"], fields=_BROKER_FIELDS, label="broker")
    )
    broker["symbol_bindings"] = [
        list(row)
        for row in _pairs(
            broker["symbol_bindings"],
            width=3,
            label="symbol_bindings",
            allow_tuple_rows=True,
        )
    ]
    return {
        "schema_version": INPUT_SCHEMA_VERSION,
        "release": release,
        "python": canonical["python"],
        "broker": broker,
        "credentials": canonical["credentials"],
        "providers": canonical["providers"],
        "thresholds": canonical["thresholds"],
        "storage": canonical["storage"],
        "security": canonical["security"],
        "processes": canonical["processes"],
        "watchdog_entrypoint_relative_path": canonical[
            "watchdog_entrypoint_relative_path"
        ],
        "watchdog_entrypoint_sha256": canonical[
            "watchdog_entrypoint_sha256"
        ],
    }


def _manifest_payload(
    plan: WindowsDemoSoakOperationsPlan,
    *,
    issued_at_utc: datetime,
) -> tuple[FailureDrillManifest, dict[str, object]]:
    manifest = FailureDrillManifest(
        plan_sha256=plan.plan_sha256,
        release_manifest_sha256=plan.release.manifest_sha256,
        git_commit=plan.release.git_commit,
        candidate_id=plan.broker.candidate_id,
        server=plan.broker.server,
        account_alias_sha256=plan.broker.account_alias_sha256,
        issued_at_utc=issued_at_utc,
    )
    payload = manifest.to_dict()
    payload["issued_at_utc"] = _utc_text(manifest.issued_at_utc)
    return manifest, payload


def _scheduler_reviews(
    plan: WindowsDemoSoakOperationsPlan,
) -> list[dict[str, object]]:
    reviews: list[dict[str, object]] = []
    for task in plan.scheduler_definitions():
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


def _readiness_payload(
    plan: WindowsDemoSoakOperationsPlan,
) -> dict[str, object]:
    assessment = assess_operations_readiness(plan)
    return {
        "local_plan_valid": assessment.local_plan_valid,
        "signed_failure_drills_complete": assessment.signed_failure_drills_complete,
        "status": assessment.status,
        "external_blockers": list(assessment.external_blockers),
        "task_install_allowed": assessment.task_install_allowed,
        "execution_enabled": assessment.execution_enabled,
        "safe_to_demo_auto_order": assessment.safe_to_demo_auto_order,
        "live_allowed": assessment.live_allowed,
        "promotion_eligible": assessment.promotion_eligible,
        "order_capability": assessment.order_capability,
        "max_lot": assessment.max_lot,
    }


def _effects_payload() -> dict[str, bool]:
    return {
        "credential_access_performed": False,
        "task_install_performed": False,
        "process_launch_performed": False,
        "network_access_performed": False,
        "broker_mutation_performed": False,
    }


def _safety_payload() -> dict[str, object]:
    return {
        "execution_enabled": False,
        "task_install_allowed": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
        "promotion_eligible": False,
        "order_capability": "DISABLED",
        "max_lot": 0.01,
    }


def build_windows_demo_soak_review_bundle(
    plan: WindowsDemoSoakOperationsPlan,
    *,
    issued_at_utc: datetime,
) -> dict[str, object]:
    """Build one deterministic review bundle without installing or launching."""

    if type(plan) is not WindowsDemoSoakOperationsPlan:
        raise TypeError("plan must be an exact WindowsDemoSoakOperationsPlan")
    issued = require_utc("issued_at_utc", issued_at_utc)
    manifest, manifest_payload = _manifest_payload(
        plan,
        issued_at_utc=issued,
    )
    payload: dict[str, object] = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "issued_at_utc": _utc_text(issued),
        "plan": plan.to_dict(),
        "plan_sha256": plan.plan_sha256,
        "failure_drill_manifest": manifest_payload,
        "failure_drill_manifest_sha256": manifest.manifest_sha256,
        "scheduler_reviews": _scheduler_reviews(plan),
        "readiness": _readiness_payload(plan),
        "effects": _effects_payload(),
        "safety": _safety_payload(),
    }
    assert_no_embedded_secrets(payload)
    payload["content_sha256"] = canonical_sha256(payload)
    verify_windows_demo_soak_review_bundle(payload)
    return payload


def _rebuild_manifest(value: object) -> FailureDrillManifest:
    fields = frozenset(
        {
            "account_alias_sha256",
            "candidate_id",
            "git_commit",
            "issued_at_utc",
            "plan_sha256",
            "release_manifest_sha256",
            "required_drills",
            "schema_version",
            "server",
        }
    )
    raw = _mapping(value, fields=fields, label="failure_drill_manifest")
    return FailureDrillManifest(
        plan_sha256=raw["plan_sha256"],
        release_manifest_sha256=raw["release_manifest_sha256"],
        git_commit=raw["git_commit"],
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


def verify_windows_demo_soak_review_bundle(
    payload: Mapping[str, object],
) -> WindowsDemoSoakOperationsPlan:
    """Rebuild and verify every deterministic component in a review bundle."""

    root = _mapping(payload, fields=_BUNDLE_FIELDS, label="operations_bundle")
    if root.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise OperationsArtifactError("OPERATIONS_BUNDLE_SCHEMA_MISMATCH")
    unsigned = dict(root)
    claimed = require_hash("content_sha256", unsigned.pop("content_sha256"))
    if canonical_sha256(unsigned) != claimed:
        raise OperationsArtifactError("OPERATIONS_BUNDLE_CONTENT_HASH_MISMATCH")
    issued = _utc_from_text(root["issued_at_utc"], label="issued_at_utc")
    try:
        plan = _plan_from_input_mapping(
            _canonical_plan_to_input(root["plan"])
        )
    except (DemoSoakOperationsError, TypeError, ValueError) as exc:
        raise OperationsArtifactError("OPERATIONS_BUNDLE_PLAN_INVALID") from exc
    if root["plan"] != plan.to_dict():
        raise OperationsArtifactError("OPERATIONS_BUNDLE_PLAN_NOT_CANONICAL")
    if root["plan_sha256"] != plan.plan_sha256:
        raise OperationsArtifactError("OPERATIONS_BUNDLE_PLAN_HASH_MISMATCH")

    manifest = _rebuild_manifest(root["failure_drill_manifest"])
    expected_manifest, expected_manifest_payload = _manifest_payload(
        plan,
        issued_at_utc=issued,
    )
    if (
        manifest != expected_manifest
        or root["failure_drill_manifest"] != expected_manifest_payload
        or root["failure_drill_manifest_sha256"]
        != expected_manifest.manifest_sha256
    ):
        raise OperationsArtifactError("FAILURE_DRILL_MANIFEST_BINDING_MISMATCH")

    scheduler_reviews = _list(
        root["scheduler_reviews"],
        label="scheduler_reviews",
    )
    for item in scheduler_reviews:
        _mapping(
            item,
            fields=_SCHEDULER_REVIEW_FIELDS,
            label="scheduler_review",
        )
    if scheduler_reviews != _scheduler_reviews(plan):
        raise OperationsArtifactError("SCHEDULER_REVIEW_BINDING_MISMATCH")

    readiness = _mapping(
        root["readiness"],
        fields=_READINESS_FIELDS,
        label="readiness",
    )
    if dict(readiness) != _readiness_payload(plan):
        raise OperationsArtifactError("OPERATIONS_READINESS_BINDING_MISMATCH")
    effects = _mapping(root["effects"], fields=_EFFECT_FIELDS, label="effects")
    if dict(effects) != _effects_payload():
        raise OperationsArtifactError("OPERATIONS_EFFECT_ESCALATION_DETECTED")
    safety = _mapping(root["safety"], fields=_SAFETY_FIELDS, label="safety")
    if dict(safety) != _safety_payload():
        raise OperationsArtifactError("OPERATIONS_SAFETY_LOCK_DRIFT")
    assert_no_embedded_secrets(root)
    return plan


__all__ = [
    "BUNDLE_SCHEMA_VERSION",
    "INPUT_SCHEMA_VERSION",
    "MAXIMUM_INPUT_BYTES",
    "OperationsArtifactError",
    "build_windows_demo_soak_review_bundle",
    "load_windows_demo_soak_operations_plan",
    "verify_windows_demo_soak_review_bundle",
]
