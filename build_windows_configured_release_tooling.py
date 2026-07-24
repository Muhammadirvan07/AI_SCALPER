"""Build deterministic, stdlib-only configured-release operator tooling.

This bundle is deliberately separate from the general deployment tooling
release.  Its verifier must be able to name broker order primitives as denied
AST members without weakening the general release's byte-level prohibition.
The bundle itself contains no executable broker call, credential provider,
network client, provider materialization, or task installation path.
"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any, Iterable, Mapping

from build_windows_release import (
    ALLOWLIST_FIELDS,
    MANIFEST_MEMBER,
    MAX_SOURCE_FILE_BYTES,
    MAX_TOTAL_SOURCE_BYTES,
    ReleaseBuildError,
    SECRET_BYTE_PATTERNS,
    _canonical_json,
    _create_archive,
    _git,
    _json_contains_secret,
    _normalize_relative_path,
    _sha256,
    _validate_git_release_source,
    _write_exclusive,
)


REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_ALLOWLIST = (
    REPO_ROOT
    / "config/windows_configured_release_tooling_allowlist.v1.json"
)
ALLOWLIST_SCHEMA = (
    "ai-scalper-windows-configured-release-tooling-allowlist-v1"
)
MANIFEST_SCHEMA = (
    "ai-scalper-windows-configured-release-tooling-manifest-v1"
)
RELEASE_PROFILE = "WINDOWS_CONFIGURED_RELEASE_OPERATOR_TOOLING_V1"
ALLOWLIST_NAME_PATTERN = re.compile(
    r"windows_configured_release_tooling_allowlist\.v[1-9][0-9]*\.json"
)
REQUIRED_SAFETY = {
    "live_allowed": False,
    "safe_to_demo_auto_order": False,
    "max_lot": 0.01,
    "order_capability": "DISABLED",
}
REQUIRED_USAGE_POLICY = {
    "bundle_class": "CONFIGURED_RELEASE_OPERATOR_TOOLING",
    "execution_context": "RELEASE_OPERATOR_ONLY",
    "network_capable_tooling_present": False,
    "broker_mutation_capability": False,
    "production_service_execution_allowed": False,
    "provider_import_allowed": False,
    "credential_access_allowed": False,
    "task_installation_allowed": False,
    "runtime_materialization_required": False,
}
APPROVED_SOURCE_PATHS = frozenset(
    {
        "build_windows_configured_service_release.py",
        "config/windows_configured_release_tooling_allowlist.v1.json",
        "live_runtime/__init__.py",
        "live_runtime/configured_service_release.py",
        "prepare_windows_configured_overlay_candidate.py",
        "verify_windows_configured_service_release.py",
    }
)
READINESS_BLOCKERS = (
    "EXACT_BASE_SERVICE_RELEASE_REQUIRED",
    "EXACT_REVIEWED_SECRET_FREE_PROVIDER_OVERLAY_REQUIRED",
    "EXTERNAL_CONFIGURED_RELEASE_IDENTITY_ACCEPTANCE_REQUIRED",
    "EXTERNAL_LAUNCHER_ATTESTATION_REQUIRED",
    "EXTERNAL_PROVIDER_RUNTIME_ATTESTATION_REQUIRED",
    "EXTERNAL_TASK_INSTALLATION_AND_ACL_ATTESTATION_REQUIRED",
)
ALLOWED_STDLIB_IMPORTS = frozenset(
    {
        "__future__",
        "argparse",
        "ast",
        "dataclasses",
        "hashlib",
        "io",
        "json",
        "math",
        "os",
        "pathlib",
        "re",
        "stat",
        "sys",
        "typing",
        "unicodedata",
        "zipfile",
    }
)
ALLOWED_LOCAL_IMPORTS = frozenset(
    {"live_runtime.configured_service_release"}
)
FORBIDDEN_IMPORT_TOPS = frozenset(
    {
        "MetaTrader5",
        "ctypes",
        "ftplib",
        "http",
        "keyring",
        "multiprocessing",
        "requests",
        "socket",
        "subprocess",
        "urllib",
        "websocket",
        "win32cred",
        "win32net",
        "win32service",
    }
)
FORBIDDEN_CALL_NAMES = frozenset(
    {"__import__", "compile", "eval", "exec"}
)
FORBIDDEN_ATTRIBUTE_CALLS = frozenset(
    {
        "CredRead",
        "CredWrite",
        "Popen",
        "call",
        "check_call",
        "check_output",
        "initialize",
        "login",
        "order_check",
        "order_send",
        "run",
        "shutdown",
        "startfile",
        "system",
    }
)


def load_configured_release_tooling_allowlist(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseBuildError(
            "configured-release tooling allowlist is invalid"
        ) from exc
    if not isinstance(payload, dict) or set(payload) != ALLOWLIST_FIELDS:
        raise ReleaseBuildError(
            "configured-release tooling allowlist fields drift"
        )
    if payload.get("schema_version") != ALLOWLIST_SCHEMA:
        raise ReleaseBuildError(
            "configured-release tooling allowlist schema drift"
        )
    if payload.get("release_profile") != RELEASE_PROFILE:
        raise ReleaseBuildError(
            "configured-release tooling profile drift"
        )
    if payload.get("safety") != REQUIRED_SAFETY:
        raise ReleaseBuildError(
            "configured-release tooling safety lock drift"
        )
    if payload.get("usage_policy") != REQUIRED_USAGE_POLICY:
        raise ReleaseBuildError(
            "configured-release tooling usage policy drift"
        )
    files = payload.get("files")
    if not isinstance(files, list) or not files:
        raise ReleaseBuildError(
            "configured-release tooling file inventory is invalid"
        )
    normalized = [_normalize_relative_path(item) for item in files]
    if (
        len(normalized) != len(set(normalized))
        or len({item.casefold() for item in normalized}) != len(normalized)
    ):
        raise ReleaseBuildError(
            "configured-release tooling path collision"
        )
    if set(normalized) != APPROVED_SOURCE_PATHS:
        raise ReleaseBuildError(
            "configured-release tooling must use the exact approved source set"
        )
    result = dict(payload)
    result["files"] = normalized
    result["_raw_sha256"] = _sha256(raw)
    return result


def _import_names(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Import):
        return tuple(alias.name for alias in node.names)
    if isinstance(node, ast.ImportFrom):
        if node.level:
            raise ReleaseBuildError(
                "configured-release tooling relative imports are forbidden"
            )
        return (node.module or "",)
    return ()


def _validate_tooling_source_security(
    sources: Mapping[str, bytes],
) -> None:
    if set(sources) != APPROVED_SOURCE_PATHS:
        raise ReleaseBuildError(
            "configured-release tooling must use the exact approved source set"
        )
    total = 0
    for path_text, data in sources.items():
        if not isinstance(data, bytes):
            raise ReleaseBuildError(
                "configured-release tooling source must be bytes"
            )
        if len(data) > MAX_SOURCE_FILE_BYTES:
            raise ReleaseBuildError(
                "configured-release tooling source exceeds size limit"
            )
        total += len(data)
        if total > MAX_TOTAL_SOURCE_BYTES:
            raise ReleaseBuildError(
                "configured-release tooling source set exceeds size limit"
            )
        for pattern in SECRET_BYTE_PATTERNS:
            if pattern.search(data):
                raise ReleaseBuildError(
                    "configured-release tooling contains secret material"
                )
        if path_text.endswith(".json"):
            try:
                payload = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ReleaseBuildError(
                    "configured-release tooling JSON is invalid"
                ) from exc
            secret_path = _json_contains_secret(payload)
            if secret_path is not None:
                raise ReleaseBuildError(
                    "configured-release tooling JSON contains a secret"
                )
            continue
        if not path_text.endswith(".py"):
            raise ReleaseBuildError(
                "configured-release tooling source type is unsupported"
            )
        try:
            tree = ast.parse(data.decode("utf-8"), filename=path_text)
        except (UnicodeDecodeError, SyntaxError) as exc:
            raise ReleaseBuildError(
                "configured-release tooling Python is invalid"
            ) from exc
        for node in ast.walk(tree):
            for imported in _import_names(node):
                top = imported.split(".", 1)[0]
                if top in FORBIDDEN_IMPORT_TOPS:
                    raise ReleaseBuildError(
                        "configured-release tooling forbidden import"
                    )
                if (
                    imported not in ALLOWED_STDLIB_IMPORTS
                    and top not in ALLOWED_STDLIB_IMPORTS
                    and imported not in ALLOWED_LOCAL_IMPORTS
                ):
                    raise ReleaseBuildError(
                        "configured-release tooling import closure drift"
                    )
            if isinstance(node, ast.Call):
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id in FORBIDDEN_CALL_NAMES
                ):
                    raise ReleaseBuildError(
                        "configured-release tooling dynamic execution is forbidden"
                    )
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in FORBIDDEN_ATTRIBUTE_CALLS
                ):
                    if node.func.attr in {"order_check", "order_send"}:
                        raise ReleaseBuildError(
                            "configured-release tooling broker/order call is forbidden"
                        )
                    raise ReleaseBuildError(
                        "configured-release tooling external effect call is forbidden"
                    )


def _read_committed_sources(
    root: Path,
    paths: Iterable[str],
    tracked: set[str],
    *,
    commit: str,
) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for raw_path in paths:
        path_text = _normalize_relative_path(raw_path)
        if path_text not in tracked:
            raise ReleaseBuildError(
                f"configured-release tooling source is not tracked: {path_text}"
            )
        entry = str(_git(root, "ls-tree", commit, "--", path_text))
        try:
            metadata, observed_path = entry.split("\t", 1)
            mode, kind, _object_id = metadata.split(" ", 2)
        except ValueError as exc:
            raise ReleaseBuildError(
                f"configured-release tooling Git entry is invalid: {path_text}"
            ) from exc
        if (
            observed_path != path_text
            or kind != "blob"
            or mode not in {"100644", "100755"}
        ):
            raise ReleaseBuildError(
                f"configured-release tooling source is not a regular blob: {path_text}"
            )
        data = _git(
            root,
            "show",
            f"{commit}:{path_text}",
            binary=True,
        )
        if not isinstance(data, bytes):
            raise ReleaseBuildError(
                "configured-release tooling source read failed"
            )
        result[path_text] = data
    _validate_tooling_source_security(result)
    return result


def build_configured_release_tooling(
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
            "configured-release tooling allowlist must be inside repository"
        ) from exc
    if (
        PurePosixPath(allowlist_relative).parent.as_posix() != "config"
        or ALLOWLIST_NAME_PATTERN.fullmatch(
            PurePosixPath(allowlist_relative).name
        )
        is None
    ):
        raise ReleaseBuildError(
            "configured-release tooling allowlist path is invalid"
        )
    output = output_path.resolve()
    sidecar = (
        output_path.with_suffix(output_path.suffix + ".manifest.json")
        if manifest_output_path is None
        else manifest_output_path
    ).resolve()
    if output == sidecar:
        raise ReleaseBuildError(
            "configured-release tooling output paths collide"
        )
    for destination in (output, sidecar):
        try:
            destination.relative_to(root)
        except ValueError:
            pass
        else:
            raise ReleaseBuildError(
                "configured-release tooling outputs must be outside repository"
            )

    commit, tree, tracked = _validate_git_release_source(root)
    allowlist = load_configured_release_tooling_allowlist(allowlist_path)
    if allowlist_relative not in allowlist["files"]:
        raise ReleaseBuildError(
            "configured-release tooling allowlist must include itself"
        )
    sources = _read_committed_sources(
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
            "embedded configured-release tooling allowlist is invalid"
        ) from exc
    expected_embedded = {
        field: allowlist[field] for field in ALLOWLIST_FIELDS
    }
    if (
        embedded != expected_embedded
        or _sha256(sources[allowlist_relative])
        != allowlist["_raw_sha256"]
    ):
        raise ReleaseBuildError(
            "loaded configured-release tooling allowlist does not match commit"
        )

    manifest_base: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA,
        "release_profile": RELEASE_PROFILE,
        "git_commit": commit,
        "git_tree": tree,
        "allowlist_sha256": allowlist["_raw_sha256"],
        "safety": dict(allowlist["safety"]),
        "usage_policy": dict(allowlist["usage_policy"]),
        "stdlib_only": True,
        "production_execution_ready": False,
        "readiness_blockers": list(READINESS_BLOCKERS),
        "effects_during_build": {
            "provider_import": False,
            "provider_materialization": False,
            "credential_access": False,
            "task_installation": False,
            "network_access": False,
            "mt5_initialization": False,
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
    _write_exclusive(output, archive_bytes)
    try:
        _write_exclusive(sidecar, manifest_bytes)
    except Exception:
        output.unlink(missing_ok=True)
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
                "configured-release tooling source changed during build"
            )
    except Exception:
        output.unlink(missing_ok=True)
        sidecar.unlink(missing_ok=True)
        raise
    return {
        "archive": str(output),
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
            "Build deterministic configured-service release operator tooling"
        )
    )
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest-output", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = build_configured_release_tooling(
            REPO_ROOT,
            args.allowlist,
            args.output,
            manifest_output_path=args.manifest_output,
        )
    except ReleaseBuildError as exc:
        print(f"CONFIGURED_RELEASE_TOOLING_REJECTED: {exc}", file=sys.stderr)
        return 2
    print("WINDOWS_CONFIGURED_RELEASE_TOOLING_READY")
    print(f"Archive: {result['archive']}")
    print(f"Archive SHA-256: {result['archive_sha256']}")
    print(f"Release identity SHA-256: {result['release_identity_sha256']}")
    print(f"Manifest: {result['manifest']}")
    print(f"Files: {result['file_count']}")
    print("Order capability: DISABLED")
    print("Production execution ready: false")
    print("Provider import: NOT_PERFORMED")
    print("Credential access: NOT_PERFORMED")
    print("Task installation: NOT_PERFORMED")
    print("Broker mutation: NOT_PERFORMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
