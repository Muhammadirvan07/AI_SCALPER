"""Run one deadline-bound, read-only XM evidence cycle on Windows."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
from types import ModuleType


LOCK_FILE_NAME = "pylock.windows-cp312.toml"
STARTUP_GUARD_SCHEMA_VERSION = "xm-shadow-startup-guard-v1"
REPO_ROOT = Path(__file__).resolve().parent


def _load_local_module(module_name: str, relative_path: str) -> ModuleType:
    existing = sys.modules.get(module_name)
    if isinstance(existing, ModuleType):
        return existing
    path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"local bootstrap module is unavailable: {relative_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    return module


_operational_guard = _load_local_module(
    "shadow_operational_guard",
    "shadow_operational_guard.py",
)
DEFAULT_HEARTBEAT_STALE_SECONDS = (
    _operational_guard.DEFAULT_HEARTBEAT_STALE_SECONDS
)
DEFAULT_MINIMUM_FREE_BYTES = _operational_guard.DEFAULT_MINIMUM_FREE_BYTES
ShadowOperationalStore = _operational_guard.ShadowOperationalStore
check_minimum_free_disk = _operational_guard.check_minimum_free_disk
OPERATIONAL_KEY_NAME = _operational_guard.RUNTIME_KEY


def _repo_path(path: str | Path) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = REPO_ROOT / candidate
    return candidate.resolve()


def _load_dependency_guard() -> ModuleType:
    """Load the stdlib-only dependency guard before the runtime package."""

    path = REPO_ROOT / "live_runtime" / "dependency_lock.py"
    spec = importlib.util.spec_from_file_location(
        "_ai_scalper_xm_shadow_dependency_guard",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Windows dependency guard loader is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _verify_and_activate_dependencies(
    lock_path: Path,
) -> tuple[ModuleType, dict[str, object]]:
    dependency_guard = _load_dependency_guard()
    dependency_guard.require_current_windows_runtime()
    dependency_receipt = dependency_guard.verify_installed_lock(lock_path)
    verified_site_packages = str(
        dependency_guard.activate_verified_site_packages(
            dependency_receipt
        )
    )
    if verified_site_packages not in sys.path:
        raise RuntimeError(
            "verified site-packages was not activated"
        )
    repo_path = str(REPO_ROOT)
    while repo_path in sys.path:
        sys.path.remove(repo_path)
    site_index = sys.path.index(verified_site_packages)
    sys.path.insert(site_index, repo_path)
    return dependency_guard, dependency_receipt


def _record_startup_guard(
    journal: Path,
    *,
    observed_at: datetime,
    status: str,
    reason: str,
    dependency_receipt: dict[str, object] | None = None,
    detail: str | None = None,
) -> dict[str, object]:
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise RuntimeError("startup guard timestamp must be timezone-aware")
    normalized_status = str(status).strip().upper()
    if normalized_status not in {"PASS", "HOLD"}:
        raise RuntimeError("startup guard status is invalid")
    cycle_id = "xm-shadow-startup-" + observed_at.strftime("%Y%m%dT%H%M%S%fZ")
    payload = {
        "schema_version": STARTUP_GUARD_SCHEMA_VERSION,
        "startup_guard_id": cycle_id,
        "observed_at_utc": observed_at.isoformat().replace("+00:00", "Z"),
        "status": normalized_status,
        "reason": str(reason).strip(),
        "detail": None if detail is None else str(detail),
        "dependency_receipt": dependency_receipt,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "order_capability": "DISABLED",
        "max_lot": 0.01,
    }
    payload_json = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    payload_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    journal.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(journal)) as connection:
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS shadow_startup_guards (
                startup_guard_id TEXT PRIMARY KEY,
                observed_at_utc TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TRIGGER IF NOT EXISTS shadow_startup_guards_no_update
            BEFORE UPDATE ON shadow_startup_guards
            BEGIN
                SELECT RAISE(ABORT, 'shadow_startup_guards is append-only');
            END"""
        )
        connection.execute(
            """CREATE TRIGGER IF NOT EXISTS shadow_startup_guards_no_delete
            BEFORE DELETE ON shadow_startup_guards
            BEGIN
                SELECT RAISE(ABORT, 'shadow_startup_guards is append-only');
            END"""
        )
        connection.commit()
        connection.execute("BEGIN IMMEDIATE")
        if normalized_status == "PASS":
            current_environment = (
                dependency_receipt or {}
            ).get("installed_environment_sha256")
            if (
                not isinstance(current_environment, str)
                or len(current_environment) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in current_environment
                )
            ):
                raise RuntimeError("installed environment fingerprint is invalid")
            previous = connection.execute(
                "SELECT payload_json FROM shadow_startup_guards "
                "WHERE status='PASS' "
                "ORDER BY observed_at_utc, startup_guard_id LIMIT 1"
            ).fetchone()
            if previous is not None:
                try:
                    previous_payload = json.loads(previous[0])
                    previous_environment = previous_payload[
                        "dependency_receipt"
                    ]["installed_environment_sha256"]
                except (KeyError, TypeError, json.JSONDecodeError) as exc:
                    raise RuntimeError(
                        "stored dependency baseline receipt is invalid"
                    ) from exc
                if previous_environment != current_environment:
                    raise RuntimeError("installed environment fingerprint drift")
        connection.execute(
            "INSERT INTO shadow_startup_guards VALUES (?, ?, ?, ?, ?)",
            (
                cycle_id,
                payload["observed_at_utc"],
                normalized_status,
                payload_json,
                payload_sha256,
            ),
        )
        connection.commit()
    return {
        "startup_guard_id": cycle_id,
        "status": normalized_status,
        "payload_sha256": payload_sha256,
        "installed_environment_sha256": (
            None
            if not isinstance(dependency_receipt, dict)
            else dependency_receipt.get(
                "installed_environment_sha256"
            )
        ),
    }


def _load_runtime_components():
    """Import dependency-locked runtime code only after the startup guard."""

    from live_runtime.evidence_bootstrap import KEY_NAME
    from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
    from live_runtime.mt5_readonly import (
        ReadOnlyMT5Facade,
        attest_mt5_read_only,
    )
    from live_runtime.shadow_collector import (
        ShadowCycleAlreadyRunning,
        ShadowCycleStore,
        run_shadow_cycle,
    )

    return (
        KEY_NAME,
        WindowsEvidenceKeyStore,
        ReadOnlyMT5Facade,
        attest_mt5_read_only,
        ShadowCycleAlreadyRunning,
        ShadowCycleStore,
        run_shadow_cycle,
    )


def _load_mt5_module() -> ModuleType:
    return importlib.import_module("MetaTrader5")


def _print_runtime_status(status) -> None:
    print("Runtime status: " + status.reported_state)
    print("Runtime recorded state: " + status.recorded_state)
    print("Heartbeat stale: " + ("YES" if status.stale else "NO"))
    print("Runtime failed: " + ("YES" if status.failed else "NO"))
    if status.heartbeat_at is not None:
        print(
            "Heartbeat at UTC: "
            + status.heartbeat_at.isoformat().replace("+00:00", "Z")
        )
    if status.last_success_at is not None:
        print(
            "Last success at UTC: "
            + status.last_success_at.isoformat().replace("+00:00", "Z")
        )
    if status.last_success_cycle_id is not None:
        print("Last success cycle: " + status.last_success_cycle_id)
    if status.failure_code is not None:
        print("Runtime failure code: " + status.failure_code)


def _finalize_invocation(
    operational: ShadowOperationalStore,
    *,
    invocation_id: str,
    outcome: str,
    reason_code: str,
    exit_code: int,
    audit_export_directory: Path,
    heartbeat_stale_seconds: int,
    success_cycle_id: str | None = None,
    detail_type: str | None = None,
) -> int:
    terminal_at = datetime.now(timezone.utc)
    try:
        operational.finish_invocation(
            invocation_id=invocation_id,
            observed_at=terminal_at,
            outcome=outcome,
            reason_code=reason_code,
            success_cycle_id=success_cycle_id,
            detail_type=detail_type,
        )
    except Exception as exc:
        print("Shadow cycle: HOLD")
        print("Reason: OPERATIONAL_TERMINAL_RECEIPT_FAILED")
        print(f"Operational receipt detail: {type(exc).__name__}")
        print("Order capability: DISABLED")
        return 2

    try:
        audit_export = operational.create_verified_audit_export(
            export_directory=audit_export_directory,
            invocation_id=invocation_id,
            observed_at=datetime.now(timezone.utc),
        )
    except Exception as exc:
        try:
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage="AUDIT_EXPORT",
                outcome="HOLD",
                reason_code="AUDIT_EXPORT_FAILED",
                detail_type=type(exc).__name__,
                runtime_state="FAILED",
            )
        except Exception:
            pass
        print("Shadow cycle: HOLD")
        print("Reason: AUDIT_EXPORT_FAILED")
        print(f"Audit export detail: {type(exc).__name__}")
        print("Order capability: DISABLED")
        try:
            _print_runtime_status(
                operational.read_status(
                    observed_at=datetime.now(timezone.utc),
                    stale_after_seconds=heartbeat_stale_seconds,
                )
            )
        except Exception:
            pass
        return 2

    print("Audit export: " + str(audit_export.export_path))
    print("Audit export manifest: " + str(audit_export.manifest_path))
    print("Audit export SHA-256: " + audit_export.export_sha256)
    try:
        _print_runtime_status(
            operational.read_status(
                observed_at=datetime.now(timezone.utc),
                stale_after_seconds=heartbeat_stale_seconds,
            )
        )
    except Exception as exc:
        try:
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage="RUNTIME_STATUS",
                outcome="HOLD",
                reason_code="RUNTIME_STATUS_READ_FAILED",
                detail_type=type(exc).__name__,
                runtime_state="FAILED",
            )
        except Exception:
            pass
        print("Shadow cycle: HOLD")
        print("Reason: RUNTIME_STATUS_READ_FAILED")
        print(f"Runtime status detail: {type(exc).__name__}")
        print("Order capability: DISABLED")
        return 2
    return int(exit_code)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one XM read-only shadow cycle")
    parser.add_argument(
        "--lock",
        type=Path,
        default=Path(LOCK_FILE_NAME),
    )
    parser.add_argument(
        "--artifact-root", type=Path, default=Path("validation_artifacts")
    )
    parser.add_argument(
        "--journal",
        type=Path,
        default=Path("runtime_state/shadow/xm-shadow-cycles.sqlite3"),
    )
    parser.add_argument(
        "--audit-export-dir",
        "--backup-dir",
        dest="audit_export_dir",
        type=Path,
        default=None,
        help="Write create-exclusive verified invocation audit exports here",
    )
    parser.add_argument(
        "--minimum-free-bytes",
        type=int,
        default=DEFAULT_MINIMUM_FREE_BYTES,
    )
    parser.add_argument(
        "--heartbeat-stale-seconds",
        type=int,
        default=DEFAULT_HEARTBEAT_STALE_SECONDS,
    )
    parser.add_argument(
        "--status-only",
        action="store_true",
        help="Read the local heartbeat/status projection without loading MT5",
    )
    args = parser.parse_args(argv)
    args.lock = _repo_path(args.lock)
    args.artifact_root = _repo_path(args.artifact_root)
    args.journal = _repo_path(args.journal)
    if args.audit_export_dir is not None:
        args.audit_export_dir = _repo_path(args.audit_export_dir)
    audit_export_directory = (
        args.audit_export_dir
        if args.audit_export_dir is not None
        else args.journal.parent / "audit_exports"
    )

    try:
        operational = ShadowOperationalStore(args.journal)
    except Exception as exc:
        print("Shadow cycle: HOLD")
        print("Reason: OPERATIONAL_JOURNAL_UNAVAILABLE")
        print(f"Operational journal detail: {type(exc).__name__}")
        print("Order capability: DISABLED")
        return 2
    try:
        dependency_guard = None
        dependency_receipt = None
        runtime_components = None
        key = None
        if operational.has_authenticated_events():
            try:
                (
                    dependency_guard,
                    dependency_receipt,
                ) = _verify_and_activate_dependencies(args.lock)
                runtime_components = _load_runtime_components()
                key_name = runtime_components[0]
                key_store_class = runtime_components[1]
                key = key_store_class().load(key_name)
                operational.install_signing_key(key)
            except Exception as exc:
                print("Shadow cycle: HOLD")
                print("Reason: OPERATIONAL_AUTHENTICATION_FAILED")
                print(f"Operational authentication detail: {type(exc).__name__}")
                print("Order capability: DISABLED")
                return 2
        if args.status_only:
            try:
                status = operational.read_status(
                    observed_at=datetime.now(timezone.utc),
                    stale_after_seconds=args.heartbeat_stale_seconds,
                )
            except Exception as exc:
                print("Runtime status: FAILED")
                print(f"Runtime status detail: {type(exc).__name__}")
                print("Order capability: DISABLED")
                return 2
            _print_runtime_status(status)
            print("Order capability: DISABLED")
            return 2 if status.stale or status.failed else 0

        try:
            invocation_id = operational.begin_invocation(
                datetime.now(timezone.utc)
            )
        except Exception as exc:
            print("Shadow cycle: HOLD")
            print("Reason: OPERATIONAL_INVOCATION_RECEIPT_FAILED")
            print(f"Operational journal detail: {type(exc).__name__}")
            print("Order capability: DISABLED")
            return 2

        current_stage = "DEPENDENCY_INTEGRITY"
        mt5 = None
        cycle_store = None
        receipt = None
        terminal_outcome = "HOLD"
        terminal_reason = "UNEXPECTED_EXCEPTION"
        terminal_detail_type: str | None = None
        terminal_exit_code = 2
        success_cycle_id: str | None = None

        try:
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage=current_stage,
                outcome="STARTED",
                reason_code="DEPENDENCY_INTEGRITY_CHECK_STARTED",
            )
            try:
                if dependency_receipt is None:
                    (
                        dependency_guard,
                        dependency_receipt,
                    ) = _verify_and_activate_dependencies(args.lock)
            except Exception as exc:
                detail = f"{type(exc).__name__}: {exc}"
                operational.record_stage(
                    invocation_id=invocation_id,
                    observed_at=datetime.now(timezone.utc),
                    stage=current_stage,
                    outcome="HOLD",
                    reason_code="DEPENDENCY_INTEGRITY_REJECTED",
                    detail_type=type(exc).__name__,
                )
                try:
                    guard_receipt = _record_startup_guard(
                        args.journal,
                        observed_at=datetime.now(timezone.utc),
                        status="HOLD",
                        reason="DEPENDENCY_INTEGRITY_REJECTED",
                        detail=detail,
                    )
                    operational.record_stage(
                        invocation_id=invocation_id,
                        observed_at=datetime.now(timezone.utc),
                        stage="STARTUP_GUARD_JOURNAL",
                        outcome="PASS",
                        reason_code="STARTUP_GUARD_RECEIPT_DURABLE",
                        metadata={
                            "receipt_binding": {
                                "receipt_type": "STARTUP_GUARD",
                                "receipt_id": guard_receipt[
                                    "startup_guard_id"
                                ],
                                "status": guard_receipt["status"],
                                "payload_sha256": guard_receipt[
                                    "payload_sha256"
                                ],
                                "installed_environment_sha256": None,
                            }
                        },
                    )
                except (OSError, RuntimeError, sqlite3.Error) as journal_exc:
                    print("Shadow cycle: HOLD")
                    print("Reason: DEPENDENCY_INTEGRITY_REJECTED")
                    print(f"Dependency detail: {detail}")
                    print(
                        "Startup guard journal: FAILED "
                        f"({type(journal_exc).__name__})"
                    )
                    print("Order capability: DISABLED")
                    return _finalize_invocation(
                        operational,
                        invocation_id=invocation_id,
                        outcome="HOLD",
                        reason_code="STARTUP_GUARD_JOURNAL_FAILED",
                        detail_type=type(journal_exc).__name__,
                        exit_code=2,
                        audit_export_directory=audit_export_directory,
                        heartbeat_stale_seconds=args.heartbeat_stale_seconds,
                    )
                print("Shadow cycle: HOLD")
                print("Reason: DEPENDENCY_INTEGRITY_REJECTED")
                print(f"Dependency detail: {detail}")
                print(
                    "Startup guard SHA-256: "
                    + str(guard_receipt["payload_sha256"])
                )
                print("Order capability: DISABLED")
                return _finalize_invocation(
                    operational,
                    invocation_id=invocation_id,
                    outcome="HOLD",
                    reason_code="DEPENDENCY_INTEGRITY_REJECTED",
                    detail_type=type(exc).__name__,
                    exit_code=2,
                    audit_export_directory=audit_export_directory,
                    heartbeat_stale_seconds=args.heartbeat_stale_seconds,
                )

            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage=current_stage,
                outcome="PASS",
                reason_code="DEPENDENCY_INTEGRITY_VERIFIED",
            )
            try:
                guard_receipt = _record_startup_guard(
                    args.journal,
                    observed_at=datetime.now(timezone.utc),
                    status="PASS",
                    reason="DEPENDENCY_INTEGRITY_VERIFIED",
                    dependency_receipt=dependency_receipt,
                )
            except (OSError, RuntimeError, sqlite3.Error) as exc:
                operational.record_stage(
                    invocation_id=invocation_id,
                    observed_at=datetime.now(timezone.utc),
                    stage="STARTUP_GUARD_JOURNAL",
                    outcome="HOLD",
                    reason_code="STARTUP_GUARD_JOURNAL_FAILED",
                    detail_type=type(exc).__name__,
                )
                print("Shadow cycle: HOLD")
                print("Reason: STARTUP_GUARD_JOURNAL_FAILED")
                print(f"Startup guard detail: {type(exc).__name__}")
                print("Order capability: DISABLED")
                return _finalize_invocation(
                    operational,
                    invocation_id=invocation_id,
                    outcome="HOLD",
                    reason_code="STARTUP_GUARD_JOURNAL_FAILED",
                    detail_type=type(exc).__name__,
                    exit_code=2,
                    audit_export_directory=audit_export_directory,
                    heartbeat_stale_seconds=args.heartbeat_stale_seconds,
                )
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage="STARTUP_GUARD_JOURNAL",
                outcome="PASS",
                reason_code="STARTUP_GUARD_RECEIPT_DURABLE",
                metadata={
                    "receipt_binding": {
                        "receipt_type": "STARTUP_GUARD",
                        "receipt_id": guard_receipt[
                            "startup_guard_id"
                        ],
                        "status": guard_receipt["status"],
                        "payload_sha256": guard_receipt[
                            "payload_sha256"
                        ],
                        "installed_environment_sha256": (
                            guard_receipt[
                                "installed_environment_sha256"
                            ]
                        ),
                    }
                },
            )
            print("Dependency integrity: MATCH")
            print(
                "Installed environment SHA-256: "
                + str(dependency_receipt["installed_environment_sha256"])
            )
            print(
                "Startup guard SHA-256: "
                + str(guard_receipt["payload_sha256"])
            )

            current_stage = "RUNTIME_IMPORT"
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage=current_stage,
                outcome="STARTED",
                reason_code="RUNTIME_IMPORT_STARTED",
            )
            if runtime_components is None:
                runtime_components = _load_runtime_components()
            (
                key_name,
                key_store_class,
                read_only_facade_class,
                read_only_attestation,
                shadow_cycle_already_running,
                shadow_cycle_store_class,
                run_shadow_cycle,
            ) = runtime_components
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage=current_stage,
                outcome="PASS",
                reason_code="RUNTIME_IMPORT_COMPLETED",
            )

            current_stage = "CREDENTIAL_LOAD"
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage=current_stage,
                outcome="STARTED",
                reason_code="CREDENTIAL_LOAD_STARTED",
            )
            if key is None:
                key = key_store_class().load(key_name)
            operational_key_id = operational.install_signing_key(key)
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage=current_stage,
                outcome="PASS",
                reason_code="EVIDENCE_CREDENTIAL_LOADED",
                metadata={
                    "operational_signing_key_id": operational_key_id,
                },
            )

            current_stage = "MT5_IMPORT"
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage=current_stage,
                outcome="STARTED",
                reason_code="MT5_IMPORT_STARTED",
            )
            mt5 = _load_mt5_module()
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage=current_stage,
                outcome="PASS",
                reason_code="MT5_IMPORT_COMPLETED",
            )

            current_stage = "MT5_INITIALIZE"
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage=current_stage,
                outcome="STARTED",
                reason_code="MT5_INITIALIZE_STARTED",
            )
            if not mt5.initialize():
                raise RuntimeError("MT5 initialize returned false")
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage=current_stage,
                outcome="PASS",
                reason_code="MT5_INITIALIZED",
            )

            current_stage = "MT5_READ_ONLY_ATTESTATION"
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage=current_stage,
                outcome="STARTED",
                reason_code="MT5_READ_ONLY_ATTESTATION_STARTED",
            )
            read_only_facts = read_only_attestation(
                read_only_facade_class(mt5)
            )
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage=current_stage,
                outcome="PASS",
                reason_code="MT5_READ_ONLY_ATTESTED",
                metadata=dict(read_only_facts),
            )

            def evidence_disk_guard() -> None:
                operational.record_stage(
                    invocation_id=invocation_id,
                    observed_at=datetime.now(timezone.utc),
                    stage="EVIDENCE_DISK_GUARD",
                    outcome="STARTED",
                    reason_code="FREE_DISK_CHECK_STARTED",
                )
                try:
                    disk_receipt = check_minimum_free_disk(
                        args.artifact_root,
                        minimum_free_bytes=args.minimum_free_bytes,
                    )
                except Exception as exc:
                    operational.record_stage(
                        invocation_id=invocation_id,
                        observed_at=datetime.now(timezone.utc),
                        stage="EVIDENCE_DISK_GUARD",
                        outcome="HOLD",
                        reason_code="MINIMUM_FREE_DISK_NOT_SATISFIED",
                        detail_type=type(exc).__name__,
                    )
                    raise
                operational.record_stage(
                    invocation_id=invocation_id,
                    observed_at=datetime.now(timezone.utc),
                    stage="EVIDENCE_DISK_GUARD",
                    outcome="PASS",
                    reason_code="MINIMUM_FREE_DISK_VERIFIED",
                    metadata={
                        "free_bytes": disk_receipt["free_bytes"],
                        "minimum_free_bytes": disk_receipt[
                            "minimum_free_bytes"
                        ],
                    },
                )

            current_stage = "EVIDENCE_DISK_GUARD"
            evidence_disk_guard()

            def stage_reporter(stage: str, outcome: str, reason: str) -> None:
                operational.record_stage(
                    invocation_id=invocation_id,
                    observed_at=datetime.now(timezone.utc),
                    stage=stage,
                    outcome=outcome,
                    reason_code=reason,
                )

            current_stage = "CYCLE_STORE"
            cycle_store = shadow_cycle_store_class(args.journal)
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage=current_stage,
                outcome="PASS",
                reason_code="CYCLE_STORE_OPENED",
            )
            current_stage = "SHADOW_CYCLE"
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage=current_stage,
                outcome="STARTED",
                reason_code="SHADOW_CYCLE_STARTED",
            )
            try:
                receipt = run_shadow_cycle(
                    mt5,
                    repo_root=REPO_ROOT,
                    artifact_root=args.artifact_root,
                    signing_key=key,
                    store=cycle_store,
                    stage_reporter=stage_reporter,
                    pre_evidence_mutation_check=evidence_disk_guard,
                )
            except shadow_cycle_already_running:
                operational.record_stage(
                    invocation_id=invocation_id,
                    observed_at=datetime.now(timezone.utc),
                    stage=current_stage,
                    outcome="BUSY",
                    reason_code="SHADOW_CYCLE_ALREADY_RUNNING",
                    runtime_state="BUSY",
                )
                terminal_outcome = "BUSY"
                terminal_reason = "SHADOW_CYCLE_ALREADY_RUNNING"
                terminal_exit_code = 3
            else:
                terminal_outcome = "HOLD" if receipt.status == "HOLD" else "PASS"
                terminal_reason = (
                    "SHADOW_CYCLE_HOLD"
                    if receipt.status == "HOLD"
                    else "SHADOW_CYCLE_" + receipt.status
                )
                terminal_exit_code = 2 if receipt.status == "HOLD" else 0
                success_cycle_id = (
                    None if receipt.status == "HOLD" else receipt.cycle_id
                )
                operational.record_stage(
                    invocation_id=invocation_id,
                    observed_at=datetime.now(timezone.utc),
                    stage=current_stage,
                    outcome=terminal_outcome,
                    reason_code=terminal_reason,
                    runtime_state=(
                        "FAILED" if receipt.status == "HOLD" else "RUNNING"
                    ),
                    metadata={
                        "receipt_binding": {
                            "receipt_type": "SHADOW_CYCLE",
                            "receipt_id": receipt.cycle_id,
                            "status": receipt.status,
                            "payload_sha256": receipt.payload_sha256,
                        }
                    },
                )
        except Exception as exc:
            terminal_outcome = "HOLD"
            terminal_reason = current_stage + "_FAILED"
            terminal_detail_type = type(exc).__name__
            terminal_exit_code = 2
            try:
                operational.record_stage(
                    invocation_id=invocation_id,
                    observed_at=datetime.now(timezone.utc),
                    stage=current_stage,
                    outcome="HOLD",
                    reason_code=terminal_reason,
                    detail_type=type(exc).__name__,
                    runtime_state="FAILED",
                )
            except (OSError, RuntimeError, sqlite3.Error):
                pass
            print("Shadow cycle: HOLD")
            print("Reason: " + terminal_reason)
            print(f"Failure detail: {type(exc).__name__}")
            print("Order capability: DISABLED")
        finally:
            cleanup_failure: Exception | None = None
            if cycle_store is not None:
                try:
                    cycle_store.close()
                except Exception as exc:
                    cleanup_failure = exc
            if mt5 is not None and callable(getattr(mt5, "shutdown", None)):
                try:
                    mt5.shutdown()
                except Exception as exc:
                    cleanup_failure = cleanup_failure or exc
            if cleanup_failure is not None:
                terminal_outcome = "HOLD"
                terminal_reason = "RUNTIME_CLEANUP_FAILED"
                terminal_detail_type = type(cleanup_failure).__name__
                terminal_exit_code = 2
                success_cycle_id = None
                try:
                    operational.record_stage(
                        invocation_id=invocation_id,
                        observed_at=datetime.now(timezone.utc),
                        stage="RUNTIME_CLEANUP",
                        outcome="HOLD",
                        reason_code=terminal_reason,
                        detail_type=type(cleanup_failure).__name__,
                        runtime_state="FAILED",
                    )
                except (OSError, RuntimeError, sqlite3.Error):
                    pass

        if receipt is not None:
            print("Shadow cycle: " + receipt.cycle_id)
            print("Status: " + receipt.status)
            for symbol, status in sorted(receipt.symbol_status.items()):
                print(f"{symbol}: {status}")
            if receipt.failures:
                print("Failures: " + ",".join(receipt.failures))
            print("Receipt SHA-256: " + receipt.payload_sha256)
        elif terminal_outcome == "BUSY":
            print("Shadow cycle: BUSY")
            print("Reason: SHADOW_CYCLE_ALREADY_RUNNING")
        print("Order capability: DISABLED")
        return _finalize_invocation(
            operational,
            invocation_id=invocation_id,
            outcome=terminal_outcome,
            reason_code=terminal_reason,
            detail_type=terminal_detail_type,
            exit_code=terminal_exit_code,
            success_cycle_id=success_cycle_id,
            audit_export_directory=audit_export_directory,
            heartbeat_stale_seconds=args.heartbeat_stale_seconds,
        )
    finally:
        operational.close()


if __name__ == "__main__":
    raise SystemExit(main())
