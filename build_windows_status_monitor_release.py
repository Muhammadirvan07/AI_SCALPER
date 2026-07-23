"""Build the deterministic, status-only Windows monitor release."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Iterable, Mapping

from build_windows_release import (
    ALLOWLIST_FIELDS,
    MAX_SOURCE_FILE_BYTES,
    MAX_TOTAL_SOURCE_BYTES,
    SECRET_BYTE_PATTERNS,
    ReleaseBuildError,
    _canonical_json,
    _create_archive,
    _git,
    _json_contains_secret,
    _normalize_relative_path,
    _path_policy,
    _sha256,
    _validate_git_release_source,
    _verify_local_import_closure,
    _write_exclusive,
)
from live_runtime.windows_external_status_monitor_factory_template import (
    monitor_provider_contracts,
)


REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_ALLOWLIST = (
    REPO_ROOT / "config" / "windows_status_monitor_allowlist.v1.json"
)
ALLOWLIST_SCHEMA = "ai-scalper-windows-status-monitor-allowlist-v1"
RELEASE_PROFILE = "WINDOWS_EXTERNAL_STATUS_MONITOR_V1"
MANIFEST_SCHEMA = "ai-scalper-windows-status-monitor-manifest-v1"
ALLOWLIST_NAME_PATTERN = re.compile(
    r"windows_status_monitor_allowlist\.v[1-9][0-9]*\.json"
)

REQUIRED_SAFETY = {
    "live_allowed": False,
    "safe_to_demo_auto_order": False,
    "max_lot": 0.01,
    "order_capability": "DISABLED",
}
REQUIRED_USAGE_POLICY = {
    "bundle_class": "STATUS_ONLY_EXTERNAL_MONITOR",
    "execution_context": (
        "DISTINCT_WINDOWS_TASK_SCHEDULER_SERVICE_ACCOUNT"
    ),
    "network_capable_tooling_present": False,
    "broker_mutation_capability": False,
    "monitor_capability": (
        "SIGNED_HEARTBEAT_ALERT_AND_STATUS_CHECKPOINT_ONLY"
    ),
    "production_service_execution_allowed": False,
    "configured_service_runtime_supported": True,
    "runtime_materialization_required": True,
    "launcher_attestation_required": (
        "RSA3072_EXTERNAL_MONITOR_PROFILE"
    ),
    "runtime_entrypoint": "run_windows_external_status_monitor.py",
    "validation_entrypoint": (
        "validate_windows_external_status_monitor.py"
    ),
}
APPROVED_SOURCE_PATHS = frozenset(
    {
        "config/windows_status_monitor_allowlist.v1.json",
        "live_runtime/__init__.py",
        "live_runtime/asymmetric_release_trust.py",
        "live_runtime/configured_service_release.py",
        "live_runtime/contracts.py",
        "live_runtime/offhost_delivery.py",
        "live_runtime/windows_external_status_monitor.py",
        "live_runtime/windows_external_status_monitor_entrypoint.py",
        "live_runtime/windows_external_status_monitor_factory_template.py",
        "run_windows_external_status_monitor.py",
        "validate_windows_external_status_monitor.py",
    }
)
READINESS_BLOCKERS = (
    "EXTERNAL_STATUS_SNAPSHOT_PROVIDER_REQUIRED",
    "EXTERNAL_HEARTBEAT_AND_ALERT_TRANSPORT_REQUIRED",
    "EXTERNAL_MONITOR_KEY_CUSTODY_REQUIRED",
    "EXTERNAL_MONITOR_CHECKPOINT_CAS_REQUIRED",
    "EXTERNAL_MONITOR_INCIDENT_LATCH_REQUIRED",
    "EXTERNAL_MONITOR_PROVIDER_CONFIGURATION_REQUIRED",
    "EXTERNAL_WINDOWS_MONITOR_IDENTITY_ATTESTATION_REQUIRED",
    "EXTERNAL_RSA_LAUNCHER_ATTESTATION_REQUIRED",
    "EXTERNAL_TASK_INSTALLATION_AND_ACL_ATTESTATION_REQUIRED",
    "EXACT_WINDOWS_STATUS_MONITOR_ACCEPTANCE_REQUIRED",
)
FORBIDDEN_IMPORT_PREFIXES = (
    "MetaTrader5",
    "keyring",
    "ctypes",
    "multiprocessing",
    "runpy",
    "subprocess",
    "execution_policy",
    "live_runtime.account_fence",
    "live_runtime.brokerless_decision_producer",
    "live_runtime.controls",
    "live_runtime.decision_core",
    "live_runtime.decision_ipc",
    "live_runtime.demo_auto",
    "live_runtime.executor",
    "live_runtime.journal",
    "live_runtime.market_guard",
    "live_runtime.mt5",
    "live_runtime.permit",
    "live_runtime.production_bootstrap",
    "live_runtime.promotion_evidence",
    "live_runtime.readiness",
    "live_runtime.reconciliation",
    "live_runtime.risk",
    "live_runtime.runtime_service",
    "live_runtime.runtime_supervisor",
    "socket",
    "requests",
    "urllib",
    "http",
    "ftplib",
    "websocket",
)
FORBIDDEN_MEMBER_NAMES = frozenset(
    {
        "initialize",
        "shutdown",
        "login",
        "account_info",
        "positions_get",
        "orders_get",
        "history_deals_get",
        "symbol_info_tick",
        "copy_rates_from",
        "order_check",
        "order_send",
        "startfile",
        "system",
        "fork",
        "posix_spawn",
    }
)
FORBIDDEN_DYNAMIC_CALLS = frozenset(
    {"__import__", "eval", "exec", "compile"}
)


def _is_forbidden_import(module: str) -> bool:
    normalized = module.casefold()
    return any(
        normalized == prefix.casefold()
        or normalized.startswith(prefix.casefold() + ".")
        for prefix in FORBIDDEN_IMPORT_PREFIXES
    )


def _validate_monitor_source_security(
    source_bytes: Mapping[str, bytes],
) -> None:
    for path_text, data in source_bytes.items():
        if not path_text.endswith(".py"):
            continue
        try:
            tree = ast.parse(data.decode("utf-8"), filename=path_text)
        except (UnicodeDecodeError, SyntaxError) as exc:
            raise ReleaseBuildError(
                f"invalid Python status-monitor source: {path_text}"
            ) from exc
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [item.name for item in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                modules = [node.module or ""]
            else:
                modules = []
            for module in modules:
                if _is_forbidden_import(module):
                    raise ReleaseBuildError(
                        "forbidden status-monitor import: "
                        f"{path_text}:{module}"
                    )
            if (
                isinstance(node, ast.Attribute)
                and node.attr.casefold() in FORBIDDEN_MEMBER_NAMES
            ):
                raise ReleaseBuildError(
                    "forbidden broker/process member: "
                    f"{path_text}:{node.attr}"
                )
            if isinstance(node, ast.Call) and isinstance(
                node.func, ast.Name
            ):
                call_name = node.func.id.casefold()
                if call_name in FORBIDDEN_DYNAMIC_CALLS:
                    raise ReleaseBuildError(
                        "dynamic code loading is forbidden: "
                        f"{path_text}:{call_name}"
                    )


def load_monitor_allowlist(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseBuildError(
            "invalid status monitor allowlist"
        ) from exc
    if not isinstance(payload, dict) or set(payload) != ALLOWLIST_FIELDS:
        raise ReleaseBuildError(
            "status monitor allowlist root fields drift"
        )
    if payload.get("schema_version") != ALLOWLIST_SCHEMA:
        raise ReleaseBuildError(
            "unsupported status monitor allowlist schema"
        )
    if payload.get("release_profile") != RELEASE_PROFILE:
        raise ReleaseBuildError(
            "status monitor release profile drift"
        )
    if payload.get("safety") != REQUIRED_SAFETY:
        raise ReleaseBuildError("status monitor safety lock drift")
    if payload.get("usage_policy") != REQUIRED_USAGE_POLICY:
        raise ReleaseBuildError("status monitor usage policy drift")
    files = payload.get("files")
    if not isinstance(files, list):
        raise ReleaseBuildError("status monitor allowlist files missing")
    normalized = [_normalize_relative_path(value) for value in files]
    if (
        len(normalized) != len(set(normalized))
        or len({value.casefold() for value in normalized})
        != len(normalized)
    ):
        raise ReleaseBuildError(
            "duplicate or case-colliding status monitor path"
        )
    if set(normalized) != APPROVED_SOURCE_PATHS:
        raise ReleaseBuildError(
            "status monitor exact source allowlist drift"
        )
    for path_text in normalized:
        _path_policy(path_text)
    result = dict(payload)
    result["files"] = normalized
    result["_raw_sha256"] = _sha256(raw)
    return result


def _read_monitor_sources(
    root: Path,
    paths: Iterable[str],
    tracked: set[str],
    *,
    commit: str,
) -> dict[str, bytes]:
    sources: dict[str, bytes] = {}
    resolved_root = root.resolve()
    total_bytes = 0
    for path_text in paths:
        if path_text not in tracked:
            raise ReleaseBuildError(
                f"allowlisted file is not tracked: {path_text}"
            )
        path = root / Path(path_text)
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ReleaseBuildError(
                f"allowlisted file is unavailable: {path_text}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(
            metadata.st_mode
        ):
            raise ReleaseBuildError(
                f"allowlisted path is not a regular file: {path_text}"
            )
        current = root
        for part in PurePosixPath(path_text).parts[:-1]:
            current /= part
            try:
                if stat.S_ISLNK(current.lstat().st_mode):
                    raise ReleaseBuildError(
                        "symlinked release path component is forbidden: "
                        f"{path_text}"
                    )
            except OSError as exc:
                raise ReleaseBuildError(
                    "allowlisted path component is unavailable: "
                    f"{path_text}"
                ) from exc
        try:
            path.resolve(strict=True).relative_to(resolved_root)
        except (OSError, ValueError) as exc:
            raise ReleaseBuildError(
                f"allowlisted path escapes source root: {path_text}"
            ) from exc
        data = bytes(
            _git(root, "show", f"{commit}:{path_text}", binary=True)
        )
        if len(data) > MAX_SOURCE_FILE_BYTES:
            raise ReleaseBuildError(
                f"allowlisted file is too large: {path_text}"
            )
        total_bytes += len(data)
        if total_bytes > MAX_TOTAL_SOURCE_BYTES:
            raise ReleaseBuildError(
                "status monitor source exceeds total size limit"
            )
        for pattern in SECRET_BYTE_PATTERNS:
            if pattern.search(data):
                raise ReleaseBuildError(
                    f"probable embedded secret in {path_text}"
                )
        if path_text.casefold().endswith(".json"):
            try:
                payload = json.loads(data.decode("utf-8"))
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
            ) as exc:
                raise ReleaseBuildError(
                    f"invalid JSON release input: {path_text}"
                ) from exc
            secret_path = _json_contains_secret(payload)
            if secret_path is not None:
                raise ReleaseBuildError(
                    "sensitive JSON value is forbidden: "
                    f"{path_text}:{secret_path}"
                )
        sources[path_text] = data
    _verify_local_import_closure(root, sources)
    _validate_monitor_source_security(sources)
    return sources


def build_status_monitor_release(
    root: Path,
    allowlist_path: Path,
    output_path: Path,
    *,
    manifest_output_path: Path | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    allowlist_path = allowlist_path.resolve()
    try:
        allowlist_relative = allowlist_path.relative_to(root).as_posix()
    except ValueError as exc:
        raise ReleaseBuildError(
            "status monitor allowlist must be inside repository"
        ) from exc
    if (
        PurePosixPath(allowlist_relative).parent.as_posix() != "config"
        or ALLOWLIST_NAME_PATTERN.fullmatch(
            PurePosixPath(allowlist_relative).name
        )
        is None
    ):
        raise ReleaseBuildError(
            "status monitor allowlist path is not versioned config"
        )
    resolved_output = output_path.resolve()
    sidecar = (
        output_path.with_suffix(output_path.suffix + ".manifest.json")
        if manifest_output_path is None
        else manifest_output_path
    ).resolve()
    for destination in (resolved_output, sidecar):
        try:
            destination.relative_to(root)
        except ValueError:
            pass
        else:
            raise ReleaseBuildError(
                "status monitor release output must be outside repository"
            )

    commit, tree, tracked = _validate_git_release_source(root)
    allowlist = load_monitor_allowlist(allowlist_path)
    if allowlist_relative not in allowlist["files"]:
        raise ReleaseBuildError(
            "status monitor allowlist must include itself"
        )
    sources = _read_monitor_sources(
        root,
        allowlist["files"],
        tracked,
        commit=commit,
    )
    allowlist["_raw_sha256"] = _sha256(sources[allowlist_relative])
    try:
        embedded = json.loads(
            sources[allowlist_relative].decode("utf-8")
        )
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseBuildError(
            "embedded status monitor allowlist is invalid"
        ) from exc
    expected_embedded = {
        field: allowlist[field] for field in ALLOWLIST_FIELDS
    }
    if embedded != expected_embedded:
        raise ReleaseBuildError(
            "loaded status monitor allowlist does not match commit"
        )

    manifest_base: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA,
        "release_profile": RELEASE_PROFILE,
        "git_commit": commit,
        "git_tree": tree,
        "allowlist_sha256": allowlist["_raw_sha256"],
        "safety": dict(allowlist["safety"]),
        "usage_policy": dict(allowlist["usage_policy"]),
        "dependency_lock_summary": {
            "stdlib_only": True,
            "third_party_package_count": 0,
            "broker_sdk_present": False,
            "credential_store_dependency_present": False,
            "target_python": "3.12",
            "target_platform": "win_amd64",
        },
        "production_execution_ready": False,
        "readiness_blockers": list(READINESS_BLOCKERS),
        "runtime_factory": "CONFIGURED_RELEASE_OVERLAY_REQUIRED",
        "runtime_loader": "RELEASE_LOCAL_CONFIGURED_ONLY",
        "required_factory_provider_contracts": (
            monitor_provider_contracts()
        ),
        "trust_boundaries": {
            "service_independence": (
                "THIRD_DISTINCT_IDENTITY_AND_SERVICE_ACCOUNT"
            ),
            "status_snapshot_source": (
                "EXACT_IMPLEMENTATION_CONFIGURATION_AND_ATTESTATION_HASH"
            ),
            "checkpoint_and_incident_state": (
                "EXTERNAL_CAS_AND_LATCH_WITH_VERIFIED_ACKNOWLEDGEMENTS"
            ),
            "offhost_delivery": (
                "DISTINCT_SIGNED_HEARTBEAT_AND_ALERT_OUTBOXES"
            ),
        },
        "effects_during_validation": {
            "provider_materialization": False,
            "offhost_delivery": False,
            "checkpoint_mutation": False,
            "incident_latch_mutation": False,
            "broker_mutation": False,
        },
        "source_files": [
            {
                "path": path_text,
                "size_bytes": len(sources[path_text]),
                "sha256": _sha256(sources[path_text]),
            }
            for path_text in sorted(sources)
        ],
    }
    identity = _sha256(_canonical_json(manifest_base))
    manifest = {
        **manifest_base,
        "release_identity_sha256": identity,
    }
    manifest_bytes = _canonical_json(manifest) + b"\n"
    archive_bytes = _create_archive(sources, manifest_bytes)
    _write_exclusive(resolved_output, archive_bytes)
    try:
        _write_exclusive(sidecar, manifest_bytes)
    except Exception:
        resolved_output.unlink(missing_ok=True)
        raise
    try:
        if (
            str(_git(root, "rev-parse", "HEAD")) != commit
            or str(_git(root, "rev-parse", "HEAD^{tree}")) != tree
            or _git(
                root,
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                binary=True,
            )
        ):
            raise ReleaseBuildError(
                "status monitor release source changed during build"
            )
    except Exception:
        resolved_output.unlink(missing_ok=True)
        sidecar.unlink(missing_ok=True)
        raise
    return {
        "archive": str(resolved_output),
        "archive_sha256": _sha256(archive_bytes),
        "manifest": str(sidecar),
        "release_identity_sha256": identity,
        "file_count": len(sources),
        "order_capability": "DISABLED",
        "production_execution_ready": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build deterministic Windows external status-monitor release"
        )
    )
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=DEFAULT_ALLOWLIST,
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest-output", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = build_status_monitor_release(
            REPO_ROOT,
            args.allowlist,
            args.output,
            manifest_output_path=args.manifest_output,
        )
    except ReleaseBuildError as exc:
        print(f"STATUS_MONITOR_RELEASE_REJECTED: {exc}")
        return 2
    print(f"Status monitor release written: {result['archive']}")
    print(f"Release SHA-256: {result['archive_sha256']}")
    print(f"Release identity: {result['release_identity_sha256']}")
    print(f"Manifest: {result['manifest']}")
    print(f"Files: {result['file_count']}")
    print("Order capability: DISABLED")
    print("Production execution ready: false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
