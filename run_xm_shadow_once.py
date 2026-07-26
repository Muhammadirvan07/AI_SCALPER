"""Run one deadline-bound, read-only broker evidence cycle on Windows.

The historic filename remains as a compatibility entry point.  New broker
profiles use ``run_broker_shadow_once.py`` and an explicit ``--candidate``.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
from types import ModuleType
from typing import Callable


LOCK_FILE_NAME = "pylock.windows-cp312.toml"
STARTUP_GUARD_SCHEMA_VERSION = "xm-shadow-startup-guard-v1"
DEPENDENCY_SESSION_SCHEMA_VERSION = "broker-shadow-dependency-session-v1"
DEPENDENCY_SESSION_REFERENCE_SCHEMA_VERSION = (
    "broker-shadow-dependency-session-reference-v1"
)
WORKER_CYCLE_SECONDS = 60
WORKER_CYCLE_OFFSET_SECONDS = 2
MIN_WORKER_DURATION_SECONDS = 15 * 60
MAX_WORKER_DURATION_SECONDS = 24 * 60 * 60
REPO_ROOT = Path(__file__).resolve().parent
_CANDIDATE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")


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
_shadow_fence = _load_local_module(
    "_ai_scalper_shadow_worker_fence",
    "live_runtime/shadow_fence.py",
)
ShadowCycleAlreadyRunning = _shadow_fence.ShadowCycleAlreadyRunning
ShadowWorkerFence = _shadow_fence.ShadowWorkerFence


def _repo_path(path: str | Path) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = REPO_ROOT / candidate
    return candidate.resolve()


def _candidate_id(value: object) -> str:
    candidate = str(value or "").strip().lower()
    if _CANDIDATE_ID.fullmatch(candidate) is None:
        raise ValueError("candidate id is invalid")
    return candidate


def _validated_terminal_path(
    path: Path | None,
    *,
    required: bool,
) -> Path | None:
    """Return one exact MT5 executable path without following a symlink."""

    if path is None:
        if required:
            raise ValueError(
                "--terminal-path is required for broker-neutral evidence collection"
            )
        return None
    if not path.is_absolute():
        raise ValueError("--terminal-path must be absolute")
    if path.is_symlink():
        raise ValueError("--terminal-path must not be a symlink")
    if path.name.lower() != "terminal64.exe":
        raise ValueError("--terminal-path must reference terminal64.exe")
    if not path.is_file():
        raise ValueError("--terminal-path must be an existing regular file")
    return path.resolve(strict=True)


def _terminal_path_sha256(path: Path | None) -> str | None:
    if path is None:
        return None
    normalized = str(path).replace("\\", "/").casefold()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _operational_runtime_binding(candidate_id: str) -> tuple[str, str]:
    candidate = _candidate_id(candidate_id)
    if candidate == "xm":
        return OPERATIONAL_KEY_NAME, "xm"
    return f"{candidate}-broker-shadow-v1", candidate


def _attest_candidate_read_only(
    attestation,
    facade,
    *,
    candidate_id: str,
):
    """Apply the reviewed read-only policy for one runtime namespace.

    XM keeps the historic stricter policy. Broker-neutral investor sessions
    may report ``trade_expert=True`` while account and terminal trading remain
    unavailable; the shared attestation still requires those effective
    mutation locks and a disabled external trade API.
    """

    candidate = _candidate_id(candidate_id)
    if candidate == "xm":
        return attestation(facade)
    return attestation(
        facade,
        require_account_expert_disabled=False,
    )


def _tracked_repo_file(path: str | Path) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = REPO_ROOT / candidate
    try:
        relative = candidate.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise RuntimeError("profile configuration must be inside the repository") from exc
    current = REPO_ROOT
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise RuntimeError("profile configuration must not contain symlinks")
    if not current.is_file():
        raise RuntimeError("profile configuration is unavailable")
    return current


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


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass
class _DependencySession:
    guard: ModuleType
    lock_path: Path
    full_receipt: dict[str, object]
    full_receipt_sha256: str
    session_id: str
    verified_at_utc: str
    full_receipt_pending: bool = True


_ACTIVE_DEPENDENCY_SESSION: _DependencySession | None = None


def _normalized_runtime_path(value: str) -> str:
    return os.path.normcase(os.path.abspath(value))


def _activate_dependency_paths(
    dependency_guard: ModuleType,
    dependency_receipt: dict[str, object],
) -> None:
    verified_site_packages = str(
        dependency_guard.activate_verified_site_packages(
            dependency_receipt
        )
    )
    if verified_site_packages not in sys.path:
        raise RuntimeError("verified site-packages was not activated")
    repo_path = str(REPO_ROOT)
    normalized_repo = _normalized_runtime_path(repo_path)
    sys.path[:] = [
        entry
        for entry in sys.path
        if not (
            isinstance(entry, str)
            and entry
            and _normalized_runtime_path(entry) == normalized_repo
        )
    ]
    site_index = sys.path.index(verified_site_packages)
    sys.path.insert(site_index, repo_path)
    _require_dependency_paths_active(dependency_receipt)


def _require_dependency_paths_active(
    dependency_receipt: dict[str, object],
) -> None:
    """Verify the one-time dependency activation without mutating ``sys.path``."""

    verified_site_packages = dependency_receipt.get("site_packages")
    if not isinstance(verified_site_packages, str) or not verified_site_packages:
        raise RuntimeError("verified site-packages receipt is invalid")

    repo_path = str(REPO_ROOT)

    normalized_paths = [
        _normalized_runtime_path(entry)
        for entry in sys.path
        if isinstance(entry, str) and entry
    ]
    normalized_repo = _normalized_runtime_path(repo_path)
    normalized_site = _normalized_runtime_path(verified_site_packages)
    if (
        normalized_paths.count(normalized_repo) != 1
        or normalized_paths.count(normalized_site) != 1
    ):
        raise RuntimeError("verified dependency path activation drift")
    repo_index = normalized_paths.index(normalized_repo)
    site_index = normalized_paths.index(normalized_site)
    if repo_index + 1 != site_index:
        raise RuntimeError("verified dependency path precedence drift")


def _verify_and_activate_dependencies_fresh(
    lock_path: Path,
) -> tuple[ModuleType, dict[str, object]]:
    dependency_guard = _load_dependency_guard()
    dependency_guard.require_current_windows_runtime()
    dependency_receipt = dependency_guard.verify_installed_lock(lock_path)
    _activate_dependency_paths(dependency_guard, dependency_receipt)
    return dependency_guard, dependency_receipt


def _start_dependency_session(lock_path: Path) -> _DependencySession:
    global _ACTIVE_DEPENDENCY_SESSION
    if _ACTIVE_DEPENDENCY_SESSION is not None:
        raise RuntimeError("dependency session is already active")
    normalized_lock = lock_path.resolve(strict=True)
    dependency_guard, dependency_receipt = (
        _verify_and_activate_dependencies_fresh(normalized_lock)
    )
    verified_at_utc = datetime.now(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    full_receipt_sha256 = _canonical_sha256(dependency_receipt)
    session_claim = {
        "schema_version": DEPENDENCY_SESSION_SCHEMA_VERSION,
        "verified_at_utc": verified_at_utc,
        "lock_sha256": dependency_receipt.get("lock_sha256"),
        "installed_environment_sha256": dependency_receipt.get(
            "installed_environment_sha256"
        ),
        "full_dependency_receipt_sha256": full_receipt_sha256,
    }
    session = _DependencySession(
        guard=dependency_guard,
        lock_path=normalized_lock,
        full_receipt=dict(dependency_receipt),
        full_receipt_sha256=full_receipt_sha256,
        session_id=_canonical_sha256(session_claim),
        verified_at_utc=verified_at_utc,
    )
    _ACTIVE_DEPENDENCY_SESSION = session
    return session


def _clear_dependency_session() -> None:
    global _ACTIVE_DEPENDENCY_SESSION
    _ACTIVE_DEPENDENCY_SESSION = None


def _verify_and_activate_dependencies(
    lock_path: Path,
) -> tuple[ModuleType, dict[str, object]]:
    session = _ACTIVE_DEPENDENCY_SESSION
    if session is None:
        return _verify_and_activate_dependencies_fresh(lock_path)
    normalized_lock = lock_path.resolve(strict=True)
    if normalized_lock != session.lock_path:
        raise RuntimeError("dependency session lock binding mismatch")
    session.guard.require_current_windows_runtime()
    if session.full_receipt_pending:
        session.full_receipt_pending = False
        receipt = dict(session.full_receipt)
        receipt["dependency_session"] = {
            "schema_version": DEPENDENCY_SESSION_SCHEMA_VERSION,
            "dependency_session_id": session.session_id,
            "verified_at_utc": session.verified_at_utc,
            "full_dependency_receipt_sha256": (
                session.full_receipt_sha256
            ),
        }
    else:
        lock_receipt = session.guard.validate_windows_dependency_lock(
            normalized_lock
        )
        for field in ("lock_sha256", "install_manifest_sha256"):
            if lock_receipt.get(field) != session.full_receipt.get(field):
                raise RuntimeError(
                    f"dependency session {field} binding drift"
                )
        receipt = {
            "schema_version": (
                DEPENDENCY_SESSION_REFERENCE_SCHEMA_VERSION
            ),
            "dependency_session_id": session.session_id,
            "verified_at_utc": session.verified_at_utc,
            "full_dependency_receipt_sha256": (
                session.full_receipt_sha256
            ),
            "installed_environment_sha256": session.full_receipt[
                "installed_environment_sha256"
            ],
            "lock_file": lock_receipt["lock_file"],
            "lock_sha256": lock_receipt["lock_sha256"],
            "install_manifest_sha256": lock_receipt[
                "install_manifest_sha256"
            ],
            "verification_mode": (
                "LOADED_PROCESS_SESSION_WITH_LOCK_REVALIDATION"
            ),
        }
    _require_dependency_paths_active(session.full_receipt)
    return session.guard, receipt


def _record_startup_guard(
    journal: Path,
    *,
    observed_at: datetime,
    status: str,
    reason: str,
    dependency_receipt: dict[str, object] | None = None,
    detail: str | None = None,
    runtime_namespace: str = "xm",
) -> dict[str, object]:
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise RuntimeError("startup guard timestamp must be timezone-aware")
    normalized_status = str(status).strip().upper()
    if normalized_status not in {"PASS", "HOLD"}:
        raise RuntimeError("startup guard status is invalid")
    namespace = _candidate_id(runtime_namespace)
    cycle_id = (
        namespace
        + "-shadow-startup-"
        + observed_at.strftime("%Y%m%dT%H%M%S%fZ")
    )
    payload = {
        "schema_version": STARTUP_GUARD_SCHEMA_VERSION,
        "runtime_namespace": namespace,
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


def _load_evidence_binding(
    candidate_id: str,
    profile_config: Path,
) -> dict[str, object]:
    """Resolve one exact contract/key/build identity after lock activation."""

    from live_runtime.evidence_bootstrap import (
        CONFIG_FILES,
        CONTRACT_ID,
        KEY_NAME,
        build_current_identity,
    )

    candidate = _candidate_id(candidate_id)
    if candidate == "xm":
        config_files = tuple(CONFIG_FILES)
        return {
            "candidate_id": candidate,
            "key_name": KEY_NAME,
            "contract_id": CONTRACT_ID,
            "config_files": config_files,
            "build_identity_provider": lambda: build_current_identity(
                REPO_ROOT,
                config_files=config_files,
            ),
        }

    from live_runtime.broker_evidence_profile import (
        load_broker_evidence_profile,
    )

    tracked_profile = _tracked_repo_file(profile_config)
    profile = load_broker_evidence_profile(
        tracked_profile,
        candidate,
        require_registration_enabled=True,
    )
    config_files = (
        "config/broker_candidates.phase3.json",
        tracked_profile.relative_to(REPO_ROOT).as_posix(),
        profile.template_path,
    )
    return {
        "candidate_id": profile.candidate_id,
        "key_name": profile.key_name,
        "contract_id": profile.contract_id,
        "config_files": config_files,
        "build_identity_provider": lambda: build_current_identity(
            REPO_ROOT,
            config_files=config_files,
        ),
    }
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


def _worker_contract_id(
    candidate_id: str,
    profile_config: Path,
) -> str:
    candidate = _candidate_id(candidate_id)
    if candidate != "phillip-commodity":
        raise RuntimeError(
            "bounded worker is approved only for phillip-commodity"
        )
    tracked = _tracked_repo_file(profile_config)
    try:
        profile_module = _load_local_module(
            "_ai_scalper_broker_evidence_profile",
            "live_runtime/broker_evidence_profile.py",
        )
        profile = profile_module.load_broker_evidence_profile(
            tracked,
            candidate,
            require_registration_enabled=True,
        )
    except Exception as exc:
        raise RuntimeError("worker profile configuration is invalid") from exc
    contract_id = str(profile.contract_id)
    if contract_id != "phillip-commodity-window-01-diagnostic-v4":
        raise RuntimeError("worker contract must use the immutable v4 namespace")
    return contract_id


def _worker_one_shot_argv(args: argparse.Namespace) -> list[str]:
    values = [
        "--candidate",
        args.candidate,
        "--profile-config",
        str(args.profile_config),
        "--lock",
        str(args.lock),
        "--artifact-root",
        str(args.artifact_root),
        "--journal",
        str(args.journal),
        "--audit-export-dir",
        str(args.audit_export_dir),
        "--minimum-free-bytes",
        str(args.minimum_free_bytes),
        "--heartbeat-stale-seconds",
        str(args.heartbeat_stale_seconds),
    ]
    if args.terminal_path is not None:
        values.extend(("--terminal-path", str(args.terminal_path)))
    return values


def _next_worker_boundary(now_epoch_seconds: float) -> float:
    shifted = now_epoch_seconds - WORKER_CYCLE_OFFSET_SECONDS
    boundary_index = int(shifted // WORKER_CYCLE_SECONDS) + 1
    return (
        boundary_index * WORKER_CYCLE_SECONDS
        + WORKER_CYCLE_OFFSET_SECONDS
    )


def _run_worker_loop(
    run_once: Callable[[], int],
    *,
    duration_seconds: float,
    wall_time: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> int:
    started = monotonic()
    deadline = started + duration_seconds
    result = int(run_once())
    if result != 0:
        return result
    while True:
        remaining_runtime = deadline - monotonic()
        if remaining_runtime <= 0:
            print("Shadow worker: COMPLETED_BOUNDED_SESSION")
            print("Order capability: DISABLED")
            return 0
        target = _next_worker_boundary(wall_time())
        if target - wall_time() >= remaining_runtime:
            print("Shadow worker: COMPLETED_BOUNDED_SESSION")
            print("Order capability: DISABLED")
            return 0
        while True:
            remaining = target - wall_time()
            if remaining <= 0:
                break
            if deadline - monotonic() <= 0:
                print("Shadow worker: COMPLETED_BOUNDED_SESSION")
                print("Order capability: DISABLED")
                return 0
            sleeper(min(remaining, 30.0))
        scheduled_at = datetime.fromtimestamp(
            target,
            tz=timezone.utc,
        ).isoformat(timespec="seconds").replace("+00:00", "Z")
        print("Shadow worker scheduled cycle UTC: " + scheduled_at)
        result = int(run_once())
        if result != 0:
            print("Shadow worker: HOLD")
            print("Reason: CHILD_CYCLE_NONZERO")
            print(f"Child exit code: {result}")
            print("Order capability: DISABLED")
            return result


def _run_worker(args: argparse.Namespace) -> int:
    one_shot_argv = _worker_one_shot_argv(args)
    worker_started = time.monotonic()
    try:
        contract_id = _worker_contract_id(
            args.candidate,
            args.profile_config,
        )
        with ShadowWorkerFence(args.artifact_root, contract_id):
            _start_dependency_session(args.lock)
            elapsed_seconds = time.monotonic() - worker_started
            remaining_seconds = (
                float(args.worker_duration_seconds) - elapsed_seconds
            )
            if remaining_seconds <= 0:
                raise RuntimeError(
                    "dependency verification exhausted bounded worker lifetime"
                )
            print("Shadow worker: STARTED")
            print("Contract: " + contract_id)
            print(
                "Cycle cadence: 60-second boundary + "
                f"{WORKER_CYCLE_OFFSET_SECONDS}s"
            )
            print(
                "Bounded duration seconds: "
                + str(args.worker_duration_seconds)
            )
            print(
                "Dependency verification elapsed seconds: "
                + f"{elapsed_seconds:.3f}"
            )
            print("Order capability: DISABLED")
            return _run_worker_loop(
                lambda: main(one_shot_argv),
                duration_seconds=remaining_seconds,
            )
    except ShadowCycleAlreadyRunning:
        print("Shadow worker: BUSY")
        print("Reason: SHADOW_WORKER_ALREADY_RUNNING")
        print("Order capability: DISABLED")
        return 3
    except Exception as exc:
        print("Shadow worker: HOLD")
        print("Reason: SHADOW_WORKER_STARTUP_FAILED")
        print(f"Worker failure detail: {type(exc).__name__}")
        print("Order capability: DISABLED")
        return 2
    finally:
        _clear_dependency_session()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run one broker read-only shadow cycle or bounded worker"
    )
    parser.add_argument("--candidate", default="xm")
    parser.add_argument(
        "--profile-config",
        type=Path,
        default=Path("config/broker_evidence_profiles.v1.json"),
    )
    parser.add_argument(
        "--terminal-path",
        type=Path,
        default=None,
        help=(
            "Absolute path to the exact terminal64.exe. Required for every "
            "non-XM candidate; optional only for the legacy XM profile."
        ),
    )
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
        default=None,
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
    parser.add_argument(
        "--worker",
        action="store_true",
        help=(
            "Run a bounded persistent process with one full installed-"
            "environment verification and M15 cycle attempts"
        ),
    )
    parser.add_argument(
        "--worker-duration-seconds",
        type=int,
        default=0,
        help="Required bounded worker lifetime; maximum 86400 seconds",
    )
    args = parser.parse_args(argv)
    try:
        args.candidate = _candidate_id(args.candidate)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        args.terminal_path = _validated_terminal_path(
            args.terminal_path,
            required=(args.candidate != "xm" and not args.status_only),
        )
    except ValueError as exc:
        print("Shadow cycle: HOLD")
        print("Reason: TERMINAL_PATH_GATE_BLOCKED")
        print(f"Terminal path detail: {type(exc).__name__}")
        print("Order capability: DISABLED")
        return 2
    args.lock = _repo_path(args.lock)
    args.artifact_root = _repo_path(args.artifact_root)
    args.profile_config = _repo_path(args.profile_config)
    if args.journal is None:
        args.journal = Path(
            f"runtime_state/shadow/{args.candidate}-shadow-cycles.sqlite3"
        )
    args.journal = _repo_path(args.journal)
    if args.audit_export_dir is not None:
        args.audit_export_dir = _repo_path(args.audit_export_dir)
    audit_export_directory = (
        args.audit_export_dir
        if args.audit_export_dir is not None
        else args.journal.parent / "audit_exports"
    )
    if args.worker:
        if args.status_only:
            print("Shadow worker: HOLD")
            print("Reason: WORKER_STATUS_MODE_CONFLICT")
            print("Order capability: DISABLED")
            return 2
        if args.candidate == "xm":
            print("Shadow worker: HOLD")
            print("Reason: WORKER_REQUIRES_BROKER_NEUTRAL_CANDIDATE")
            print("Order capability: DISABLED")
            return 2
        if not (
            MIN_WORKER_DURATION_SECONDS
            <= args.worker_duration_seconds
            <= MAX_WORKER_DURATION_SECONDS
        ):
            print("Shadow worker: HOLD")
            print("Reason: WORKER_DURATION_INVALID")
            print("Order capability: DISABLED")
            return 2
        args.audit_export_dir = audit_export_directory
        return _run_worker(args)
    if args.worker_duration_seconds != 0:
        print("Shadow cycle: HOLD")
        print("Reason: WORKER_DURATION_WITHOUT_WORKER")
        print("Order capability: DISABLED")
        return 2

    runtime_key, invocation_namespace = _operational_runtime_binding(
        args.candidate
    )
    try:
        operational = ShadowOperationalStore(
            args.journal,
            runtime_key=runtime_key,
            invocation_namespace=invocation_namespace,
        )
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
        evidence_binding = None
        key = None
        if operational.has_authenticated_events():
            try:
                (
                    dependency_guard,
                    dependency_receipt,
                ) = _verify_and_activate_dependencies(args.lock)
                runtime_components = _load_runtime_components()
                evidence_binding = _load_evidence_binding(
                    args.candidate,
                    args.profile_config,
                )
                key_name = str(evidence_binding["key_name"])
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
                        runtime_namespace=args.candidate,
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
                    runtime_namespace=args.candidate,
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
                legacy_key_name,
                key_store_class,
                read_only_facade_class,
                read_only_attestation,
                shadow_cycle_already_running,
                shadow_cycle_store_class,
                run_shadow_cycle,
            ) = runtime_components
            if evidence_binding is None:
                evidence_binding = _load_evidence_binding(
                    args.candidate,
                    args.profile_config,
                )
            key_name = str(evidence_binding["key_name"])
            if args.candidate == "xm" and key_name != legacy_key_name:
                raise RuntimeError("legacy XM evidence key binding drift")
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
            terminal_binding = (
                "EXACT_PATH"
                if args.terminal_path is not None
                else "LEGACY_XM_AUTODISCOVERY"
            )
            terminal_path_sha256 = _terminal_path_sha256(args.terminal_path)
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage=current_stage,
                outcome="STARTED",
                reason_code="MT5_INITIALIZE_STARTED",
                metadata={
                    "terminal_binding": terminal_binding,
                    "terminal_path_sha256": terminal_path_sha256,
                },
            )
            initialized = (
                mt5.initialize(str(args.terminal_path))
                if args.terminal_path is not None
                else mt5.initialize()
            )
            if not initialized:
                raise RuntimeError("MT5 initialize returned false")
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage=current_stage,
                outcome="PASS",
                reason_code="MT5_INITIALIZED",
                metadata={
                    "terminal_binding": terminal_binding,
                    "terminal_path_sha256": terminal_path_sha256,
                },
            )

            current_stage = "MT5_READ_ONLY_ATTESTATION"
            operational.record_stage(
                invocation_id=invocation_id,
                observed_at=datetime.now(timezone.utc),
                stage=current_stage,
                outcome="STARTED",
                reason_code="MT5_READ_ONLY_ATTESTATION_STARTED",
            )
            read_only_facts = _attest_candidate_read_only(
                read_only_attestation,
                read_only_facade_class(mt5),
                candidate_id=args.candidate,
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
            if args.candidate == "xm":
                cycle_store = shadow_cycle_store_class(args.journal)
            else:
                cycle_store = shadow_cycle_store_class(
                    args.journal,
                    contract_id=str(evidence_binding["contract_id"]),
                )
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
                cycle_arguments = {
                    "repo_root": REPO_ROOT,
                    "artifact_root": args.artifact_root,
                    "signing_key": key,
                    "store": cycle_store,
                    "stage_reporter": stage_reporter,
                    "pre_evidence_mutation_check": evidence_disk_guard,
                }
                if args.candidate != "xm":
                    cycle_arguments.update(
                        {
                            "contract_id": str(
                                evidence_binding["contract_id"]
                            ),
                            "build_identity_provider": evidence_binding[
                                "build_identity_provider"
                            ],
                        }
                    )
                receipt = run_shadow_cycle(
                    mt5,
                    **cycle_arguments,
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
