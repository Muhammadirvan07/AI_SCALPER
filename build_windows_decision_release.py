"""Build the deterministic, decision-only Windows service release.

The profile is intentionally independent from both the read-only broker shadow
and the GATED executor release.  Its allowlist is exact and contains no broker,
risk, permit, reconciliation, credential, or order-capability module.
"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Iterable, Mapping
import tomllib

from build_windows_release import (
    ALLOWLIST_FIELDS,
    MANIFEST_MEMBER,
    ReleaseBuildError,
    _canonical_json,
    _create_archive,
    _git,
    _normalize_relative_path,
    _path_policy,
    _read_release_sources,
    _sha256,
    _validate_git_release_source,
    _write_exclusive,
)
from live_runtime.windows_decision_service_factory_template import provider_contracts


REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_ALLOWLIST = (
    REPO_ROOT / "config" / "windows_decision_service_allowlist.v1.json"
)
ALLOWLIST_SCHEMA = "ai-scalper-windows-decision-service-allowlist-v1"
RELEASE_PROFILE = "WINDOWS_DECISION_SERVICE_V1"
MANIFEST_SCHEMA = "ai-scalper-windows-decision-service-manifest-v1"
ALLOWLIST_NAME_PATTERN = re.compile(
    r"windows_decision_service_allowlist\.v[1-9][0-9]*\.json"
)

REQUIRED_SAFETY = {
    "live_allowed": False,
    "safe_to_demo_auto_order": False,
    "max_lot": 0.01,
    "order_capability": "DISABLED",
}
REQUIRED_USAGE_POLICY = {
    "bundle_class": "DECISION_ONLY_SERVICE",
    "execution_context": "WINDOWS_TASK_SCHEDULER_SERVICE_ACCOUNT",
    "network_capable_tooling_present": False,
    "broker_mutation_capability": False,
    "ipc_publish_capability": "SIGNED_DECISION_SNAPSHOT_ONLY",
    "production_service_execution_allowed": False,
    "runtime_materialization_required": False,
    "session_calendar_capability": "SIGNED_EXACT_CLOSURE_RECEIPTS_ONLY",
    "session_calendar_verifier_provider": (
        "EXACT_IMPLEMENTATION_AND_CONFIGURATION_HASH_REQUIRED"
    ),
    "cursor_cas_acknowledgement_authentication": (
        "BINDING_PINNED_HMAC_VERIFIER_PORT"
    ),
    "validation_entrypoint": "validate_windows_decision_service.py",
}

APPROVED_SOURCE_PATHS = frozenset(
    {
        "agents/market_status.py",
        "agents/supervisor_agent.py",
        "config/windows_decision_service_allowlist.v1.json",
        "live_runtime/__init__.py",
        "live_runtime/brokerless_decision_producer.py",
        "live_runtime/contracts.py",
        "live_runtime/decision_core.py",
        "live_runtime/decision_ipc.py",
        "live_runtime/windows_decision_service_factory_template.py",
        "market_data_quality.py",
        "market_regime_filter.py",
        "pylock.decision-windows-cp312.toml",
        "requirements-decision-windows-cp312.lock.txt",
        "requirements-decision-windows.txt",
        "run_windows_decision_service.py",
        "strategy/strategy_profiles.py",
        "strategy/strategy_selector.py",
        "strategy/trend_analyzer.py",
        "validate_windows_decision_service.py",
        "vendor/wheels/ta-0.11.0-py3-none-any.whl",
    }
)

REQUIRED_DEPENDENCY_FILES = frozenset(
    {
        "pylock.decision-windows-cp312.toml",
        "requirements-decision-windows-cp312.lock.txt",
        "requirements-decision-windows.txt",
    }
)
EXPECTED_DIRECT_DEPENDENCIES = {
    "numpy": "2.5.1",
    "pandas": "2.3.3",
    "ta": "0.11.0",
}
EXPECTED_RESOLVED_DEPENDENCIES = {
    "numpy": (
        "2.5.1",
        "f7d60026c0bdb1380e83bfa7a0419c4577ee4b9a08880afcb6dadeb74c649fa2",
    ),
    "pandas": (
        "2.3.3",
        "a16dcec078a01eeef8ee61bf64074b4e524a2a3f4b3be9326420cabe59c4778b",
    ),
    "python-dateutil": (
        "2.9.0.post0",
        "a8b2bc7bffae282281c8140a97d3aa9c14da0b136dfe83f850eea9a5f7470427",
    ),
    "pytz": (
        "2026.2",
        "04156e608bee23d3792fd45c94ae47fae1036688e75032eea2e3bf0323d1f126",
    ),
    "six": (
        "1.17.0",
        "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274",
    ),
    "ta": (
        "0.11.0",
        "acd933756f0badbe6b1cc28d5db42dc0d9b0ac5877956f5cf8f304ece3f50b0d",
    ),
    "tzdata": (
        "2026.3",
        "dc096730c87af6cab1b171c9d532be840741ff5d459015e7f6947bd7d7e54931",
    ),
}

READINESS_BLOCKERS = (
    "EXTERNAL_FINALIZED_M15_DATA_PROVIDER_REQUIRED",
    "EXTERNAL_SIGNED_SESSION_CALENDAR_VERIFIER_REQUIRED",
    "EXTERNAL_TRUSTED_CLOCK_PROVIDER_REQUIRED",
    "EXTERNAL_DECISION_IPC_KEY_CUSTODY_REQUIRED",
    "EXTERNAL_DECISION_IPC_CHECKPOINT_CAS_REQUIRED",
    "EXTERNAL_DECISION_CURSOR_CAS_REQUIRED",
    "EXTERNAL_DECISION_CURSOR_ACK_VERIFIER_REQUIRED",
    "EXTERNAL_DECISION_FACTORY_PROVIDER_CONFIGURATION_REQUIRED",
    "EXTERNAL_WINDOWS_DECISION_SERVICE_IDENTITY_ATTESTATION_REQUIRED",
)

FORBIDDEN_IMPORT_PREFIXES = (
    "MetaTrader5",
    "keyring",
    "execution_policy",
    "live_runtime.account_fence",
    "live_runtime.controls",
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
    }
)
FORBIDDEN_DYNAMIC_CALLS = frozenset(
    {"__import__", "eval", "exec", "compile"}
)


def _normalize_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _dependency_lines(data: bytes, path_text: str) -> list[str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseBuildError(f"dependency lock is not UTF-8: {path_text}") from exc
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _validate_dependency_lock_set(
    source_bytes: Mapping[str, bytes],
) -> dict[str, Any]:
    missing = REQUIRED_DEPENDENCY_FILES.difference(source_bytes)
    if missing:
        raise ReleaseBuildError(
            "decision dependency lock set is incomplete: "
            + ", ".join(sorted(missing))
        )
    direct_pattern = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s]+)$")
    lock_pattern = re.compile(
        r"^([A-Za-z0-9_.-]+)==([^\s]+) --hash=sha256:([0-9a-f]{64})$"
    )
    direct: dict[str, str] = {}
    for line in _dependency_lines(
        source_bytes["requirements-decision-windows.txt"],
        "requirements-decision-windows.txt",
    ):
        match = direct_pattern.fullmatch(line)
        if match is None:
            raise ReleaseBuildError("decision direct requirement is not exactly pinned")
        name = _normalize_distribution_name(match.group(1))
        if name in direct:
            raise ReleaseBuildError("duplicate decision direct requirement")
        direct[name] = match.group(2)
    if direct != EXPECTED_DIRECT_DEPENDENCIES:
        raise ReleaseBuildError("decision direct dependency set drift")

    resolved: dict[str, tuple[str, str]] = {}
    for line in _dependency_lines(
        source_bytes["requirements-decision-windows-cp312.lock.txt"],
        "requirements-decision-windows-cp312.lock.txt",
    ):
        match = lock_pattern.fullmatch(line)
        if match is None:
            raise ReleaseBuildError("decision resolved requirement is not hash pinned")
        name = _normalize_distribution_name(match.group(1))
        if name in resolved:
            raise ReleaseBuildError("duplicate decision resolved requirement")
        resolved[name] = (match.group(2), match.group(3))
    if resolved != EXPECTED_RESOLVED_DEPENDENCIES:
        raise ReleaseBuildError("decision resolved dependency closure drift")

    try:
        pylock = tomllib.loads(
            source_bytes["pylock.decision-windows-cp312.toml"].decode("utf-8")
        )
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseBuildError("decision Windows pylock is invalid") from exc
    intent = pylock.get("tool", {}).get("ai_scalper")
    if (
        pylock.get("lock-version") != "1.0"
        or pylock.get("requires-python") != ">=3.12"
        or not isinstance(intent, dict)
        or intent.get("target-python") != "3.12"
        or intent.get("target-implementation") != "CPython"
        or intent.get("target-platform") != "win_amd64"
        or intent.get("target-architecture") != "x86_64"
        or intent.get("source-manifests")
        != ["requirements-decision-windows.txt"]
    ):
        raise ReleaseBuildError("decision Windows pylock target metadata drift")
    packages = pylock.get("packages")
    if not isinstance(packages, list):
        raise ReleaseBuildError("decision Windows pylock package closure missing")
    observed: dict[str, tuple[str, str]] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise ReleaseBuildError("decision Windows pylock package invalid")
        name = _normalize_distribution_name(str(package.get("name", "")))
        version = package.get("version")
        wheels = package.get("wheels")
        if not isinstance(version, str) or not isinstance(wheels, list) or not wheels:
            raise ReleaseBuildError("decision Windows pylock package is incomplete")
        expected = resolved.get(name)
        if expected is None:
            raise ReleaseBuildError("decision Windows pylock contains extra package")
        expected_hash = expected[1]
        matching = [
            wheel
            for wheel in wheels
            if isinstance(wheel, dict)
            and isinstance(wheel.get("hashes"), dict)
            and wheel["hashes"].get("sha256") == expected_hash
        ]
        if not matching:
            raise ReleaseBuildError("decision Windows pylock wheel hash drift")
        for wheel in matching:
            path = wheel.get("path")
            if path is not None:
                if path not in source_bytes or _sha256(source_bytes[path]) != expected_hash:
                    raise ReleaseBuildError("vendored decision wheel hash drift")
        observed[name] = (version, expected_hash)
    if observed != resolved:
        raise ReleaseBuildError("decision Windows pylock closure drift")
    return {
        "direct_requirement_count": len(direct),
        "resolved_package_count": len(resolved),
        "target_python": "3.12",
        "target_platform": "win_amd64",
        "broker_sdk_present": False,
        "credential_store_dependency_present": False,
        "lock_files": sorted(REQUIRED_DEPENDENCY_FILES),
    }


def _is_forbidden_import(module: str) -> bool:
    normalized = module.casefold()
    return any(
        normalized == prefix.casefold()
        or normalized.startswith(prefix.casefold() + ".")
        for prefix in FORBIDDEN_IMPORT_PREFIXES
    )


def _validate_decision_source_security(
    source_bytes: Mapping[str, bytes],
) -> None:
    for path_text, data in source_bytes.items():
        if not path_text.endswith(".py"):
            continue
        try:
            tree = ast.parse(data.decode("utf-8"), filename=path_text)
        except (UnicodeDecodeError, SyntaxError) as exc:
            raise ReleaseBuildError(f"invalid Python decision source: {path_text}") from exc
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
                        f"forbidden decision-service import: {path_text}:{module}"
                    )
            if isinstance(node, ast.Attribute) and node.attr.casefold() in FORBIDDEN_MEMBER_NAMES:
                raise ReleaseBuildError(
                    f"forbidden broker/execution member: {path_text}:{node.attr}"
                )
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id.casefold()
                else:
                    call_name = ""
                if call_name in FORBIDDEN_DYNAMIC_CALLS:
                    raise ReleaseBuildError(
                        f"dynamic code loading is forbidden: {path_text}:{call_name}"
                    )


def load_decision_allowlist(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseBuildError("invalid decision service allowlist") from exc
    if not isinstance(payload, dict) or set(payload) != ALLOWLIST_FIELDS:
        raise ReleaseBuildError("decision service allowlist root fields drift")
    if payload.get("schema_version") != ALLOWLIST_SCHEMA:
        raise ReleaseBuildError("unsupported decision service allowlist schema")
    if payload.get("release_profile") != RELEASE_PROFILE:
        raise ReleaseBuildError("decision service release profile drift")
    if payload.get("safety") != REQUIRED_SAFETY:
        raise ReleaseBuildError("decision service safety lock drift")
    if payload.get("usage_policy") != REQUIRED_USAGE_POLICY:
        raise ReleaseBuildError("decision service usage policy drift")
    files = payload.get("files")
    if not isinstance(files, list):
        raise ReleaseBuildError("decision service allowlist files missing")
    normalized = [_normalize_relative_path(value) for value in files]
    if len(normalized) != len(set(normalized)):
        raise ReleaseBuildError("duplicate decision service allowlist path")
    if len({value.casefold() for value in normalized}) != len(normalized):
        raise ReleaseBuildError("case-colliding decision service allowlist path")
    if set(normalized) != APPROVED_SOURCE_PATHS:
        raise ReleaseBuildError("decision service exact source allowlist drift")
    for path_text in normalized:
        _path_policy(path_text)
    result = dict(payload)
    result["files"] = normalized
    result["_raw_sha256"] = _sha256(raw)
    return result


def _read_decision_sources(
    root: Path,
    paths: Iterable[str],
    tracked: set[str],
    *,
    commit: str,
) -> dict[str, bytes]:
    sources = _read_release_sources(root, paths, tracked, commit=commit)
    _validate_decision_source_security(sources)
    return sources


def build_decision_release(
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
        raise ReleaseBuildError("decision allowlist must be inside repository") from exc
    if (
        PurePosixPath(allowlist_relative).parent.as_posix() != "config"
        or ALLOWLIST_NAME_PATTERN.fullmatch(
            PurePosixPath(allowlist_relative).name
        )
        is None
    ):
        raise ReleaseBuildError("decision allowlist path is not versioned config")
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
            raise ReleaseBuildError("decision release output must be outside repository")

    commit, tree, tracked = _validate_git_release_source(root)
    allowlist = load_decision_allowlist(allowlist_path)
    if allowlist_relative not in allowlist["files"]:
        raise ReleaseBuildError("decision allowlist must include itself")
    sources = _read_decision_sources(
        root,
        allowlist["files"],
        tracked,
        commit=commit,
    )
    dependency_summary = _validate_dependency_lock_set(sources)
    try:
        embedded = json.loads(sources[allowlist_relative].decode("utf-8"))
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseBuildError("embedded decision allowlist is invalid") from exc
    expected_embedded = {field: allowlist[field] for field in ALLOWLIST_FIELDS}
    if (
        embedded != expected_embedded
        or _sha256(sources[allowlist_relative]) != allowlist["_raw_sha256"]
    ):
        raise ReleaseBuildError("loaded decision allowlist does not match commit")

    manifest_base: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA,
        "release_profile": RELEASE_PROFILE,
        "git_commit": commit,
        "git_tree": tree,
        "allowlist_sha256": allowlist["_raw_sha256"],
        "safety": dict(allowlist["safety"]),
        "usage_policy": dict(allowlist["usage_policy"]),
        "dependency_lock_summary": dependency_summary,
        "production_execution_ready": False,
        "readiness_blockers": list(READINESS_BLOCKERS),
        "runtime_factory": "EXTERNAL_NOT_BUNDLED",
        "required_factory_provider_contracts": provider_contracts(),
        "trust_boundaries": {
            "session_calendar_continuity": (
                "EXACT_SIGNED_CLOSURE_RECEIPTS_BOUND_TO_LANE_HASH"
            ),
            "producer_cursor_cas_acknowledgement": (
                "SEALED_BINDING_PINNED_HMAC_VERIFIER_PORT"
            ),
        },
        "effects_during_validation": {
            "market_data_fetch": False,
            "ipc_mutation": False,
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
    manifest = {**manifest_base, "release_identity_sha256": identity}
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
            raise ReleaseBuildError("decision release source changed during build")
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
        description="Build deterministic Windows decision-only release"
    )
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest-output", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = build_decision_release(
            REPO_ROOT,
            args.allowlist,
            args.output,
            manifest_output_path=args.manifest_output,
        )
    except ReleaseBuildError as exc:
        print(f"DECISION_RELEASE_REJECTED: {exc}")
        return 2
    print(f"Decision release written: {result['archive']}")
    print(f"Release SHA-256: {result['archive_sha256']}")
    print(f"Release identity: {result['release_identity_sha256']}")
    print(f"Manifest: {result['manifest']}")
    print(f"Files: {result['file_count']}")
    print("Order capability: DISABLED")
    print("Production execution ready: false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
