"""Build a deterministic Windows release from an explicit source allowlist.

This is intentionally not a repository archiver.  Runtime state, evidence,
broker data, histories, backups, credentials, and arbitrary tracked files are
excluded unless they pass the fixed policy and are named explicitly.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from typing import Any, Iterable, Mapping
import unicodedata
import zipfile


REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_ALLOWLIST = REPO_ROOT / "config" / "windows_release_allowlist.v1.json"
ALLOWLIST_SCHEMA = "ai-scalper-windows-release-allowlist-v1"
READ_ONLY_SERVICE_ALLOWLIST_SCHEMA = (
    "ai-scalper-windows-shadow-service-allowlist-v1"
)
ALLOWLIST_FIELDS = {
    "files",
    "release_profile",
    "safety",
    "schema_version",
    "usage_policy",
}
MANIFEST_SCHEMA = "ai-scalper-windows-release-manifest-v1"
MANIFEST_MEMBER = "RELEASE_MANIFEST.json"
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
MAX_SOURCE_FILE_BYTES = 50 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 128 * 1024 * 1024
ALLOWLIST_NAME_PATTERN = re.compile(
    r"windows_(?:release|shadow_service)_allowlist\.v[1-9][0-9]*\.json"
)
WINDOWS_RESERVED_STEMS = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}

REQUIRED_SAFETY = {
    "live_allowed": False,
    "safe_to_demo_auto_order": False,
    "max_lot": 0.01,
    "order_capability": "DISABLED",
}
REQUIRED_USAGE_POLICY = {
    "bundle_class": "DEPLOYMENT_TOOLING",
    "execution_context": "RELEASE_OPERATOR_ONLY",
    "network_capable_tooling_present": True,
    "production_service_execution_allowed": False,
    "runtime_materialization_required": True,
}
READ_ONLY_SERVICE_USAGE_POLICY = {
    "bundle_class": "READ_ONLY_SHADOW_SERVICE",
    "execution_context": "WINDOWS_TASK_SCHEDULER_SERVICE_ACCOUNT",
    "network_capable_tooling_present": True,
    "broker_mutation_capability": False,
    "production_service_execution_allowed": True,
    "runtime_materialization_required": False,
}
ALLOWLIST_USAGE_POLICIES = {
    ALLOWLIST_SCHEMA: REQUIRED_USAGE_POLICY,
    READ_ONLY_SERVICE_ALLOWLIST_SCHEMA: READ_ONLY_SERVICE_USAGE_POLICY,
}
FORBIDDEN_DIRECTORY_NAMES = {
    ".git",
    ".venv",
    "__pycache__",
    "backups",
    "data",
    "history",
    "logs",
    "runtime_snapshots",
    "runtime_state",
    "validation_artifacts",
    "venv",
}
FORBIDDEN_SUFFIXES = {
    ".bak",
    ".backup",
    ".csv",
    ".db",
    ".env",
    ".gz",
    ".history",
    ".journal",
    ".key",
    ".log",
    ".p12",
    ".patch",
    ".pem",
    ".pfx",
    ".pyc",
    ".pyo",
    ".sqlite",
    ".sqlite3",
    ".tar",
    ".zip",
}
FORBIDDEN_BASENAMES = {
    ".env",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
}
FORBIDDEN_READ_ONLY_EXECUTION_PATHS = {
    "live_runtime/executor.py",
    "live_runtime/journal.py",
    "live_runtime/mt5_adapter.py",
    "live_runtime/reconciliation.py",
    "live_runtime/runtime_service.py",
    "mt5_bridge_reader.py",
    "paper_executor.py",
}
FORBIDDEN_READ_ONLY_EXECUTION_PREFIXES = (
    "mql5/",
    "vps_package/",
)
FORBIDDEN_SERVICE_TOOL_PREFIXES = (
    "bootstrap_",
    "build_",
    "collect_",
    "generate_",
    "prepare_",
    "register_",
    "seal_",
    "setup_",
    "verify_",
)
ORDER_CAPABILITY_SOURCE_PATTERNS = (
    re.compile(rb"\border_(?:check|send)\b", re.IGNORECASE),
    re.compile(rb"\bTRADE_ACTION_[A-Z0-9_]+\b"),
    re.compile(rb"\bORDER_TYPE_(?:BUY|SELL)[A-Z0-9_]*\b"),
    re.compile(rb"\bCTrade\b"),
    re.compile(rb"\.(?:Buy|Sell)\s*\("),
)
SENSITIVE_JSON_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "client_secret",
    "login",
    "password",
    "private_key",
    "refresh_token",
    "secret",
}
SECRET_BYTE_PATTERNS = (
    re.compile(rb"-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bgh[oprsu]_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
)


class ReleaseBuildError(RuntimeError):
    """Fail-closed release construction error."""


def _canonical_json(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git(root: Path, *args: str, binary: bool = False) -> str | bytes:
    try:
        result = subprocess.run(
            ("git", *args),
            cwd=root,
            check=True,
            capture_output=True,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ReleaseBuildError(f"git command failed: {' '.join(args)}") from exc
    if binary:
        return result.stdout
    return result.stdout.decode("utf-8", errors="strict").strip()


def _validate_git_release_source(root: Path) -> tuple[str, str, set[str]]:
    top_level = Path(str(_git(root, "rev-parse", "--show-toplevel"))).resolve()
    if top_level != root.resolve():
        raise ReleaseBuildError("source root is not the Git repository root")
    status_bytes = _git(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        binary=True,
    )
    if status_bytes:
        raise ReleaseBuildError(
            "release source is dirty; commit or remove every generated artifact first"
        )
    commit = str(_git(root, "rev-parse", "HEAD"))
    tree = str(_git(root, "rev-parse", "HEAD^{tree}"))
    tracked_bytes = _git(root, "ls-files", "-z", binary=True)
    tracked = {
        item.decode("utf-8", errors="strict")
        for item in bytes(tracked_bytes).split(b"\0")
        if item
    }
    return commit, tree, tracked


def _normalize_relative_path(raw_path: object) -> str:
    if not isinstance(raw_path, str) or not raw_path:
        raise ReleaseBuildError("allowlisted path must be a non-empty string")
    if "\\" in raw_path or "\x00" in raw_path:
        raise ReleaseBuildError(f"non-canonical release path: {raw_path!r}")
    path = PurePosixPath(raw_path)
    if path.is_absolute() or raw_path != path.as_posix():
        raise ReleaseBuildError(f"release path must be canonical and relative: {raw_path}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ReleaseBuildError(f"release path traversal is forbidden: {raw_path}")
    if unicodedata.normalize("NFC", raw_path) != raw_path:
        raise ReleaseBuildError(f"release path must use NFC Unicode: {raw_path}")
    for part in path.parts:
        if (
            any(ord(character) < 32 or character in '<>:"|?*' for character in part)
            or part.endswith((" ", "."))
            or part.split(".", 1)[0].casefold() in WINDOWS_RESERVED_STEMS
        ):
            raise ReleaseBuildError(f"Windows-incompatible release path: {raw_path}")
    return path.as_posix()


def _path_policy(path_text: str) -> None:
    windows_path = path_text.casefold()
    if (
        windows_path in FORBIDDEN_READ_ONLY_EXECUTION_PATHS
        or windows_path.startswith(FORBIDDEN_READ_ONLY_EXECUTION_PREFIXES)
    ):
        raise ReleaseBuildError(
            f"execution-capable path is forbidden in a read-only release: {path_text}"
        )
    path = PurePosixPath(path_text)
    lowered_parts = tuple(part.casefold() for part in path.parts)
    if any(part in FORBIDDEN_DIRECTORY_NAMES for part in lowered_parts[:-1]):
        raise ReleaseBuildError(f"runtime or private directory is forbidden: {path_text}")
    basename = lowered_parts[-1]
    if basename in FORBIDDEN_BASENAMES or basename.startswith(".env."):
        raise ReleaseBuildError(f"credential-bearing filename is forbidden: {path_text}")
    tokens = {
        token
        for token in re.split(r"[^a-z0-9]+", basename)
        if token
    }
    if tokens.intersection({"backup", "history"}):
        raise ReleaseBuildError(f"backup/history artifact is forbidden: {path_text}")
    suffix = path.suffix.casefold()
    if suffix in FORBIDDEN_SUFFIXES:
        raise ReleaseBuildError(f"release file type is forbidden: {path_text}")
    if suffix == ".json" and lowered_parts[0] not in {"config", "vendor"}:
        raise ReleaseBuildError(
            f"JSON is allowed only as reviewed config/vendor metadata: {path_text}"
        )
    if suffix == ".whl" and lowered_parts[:2] != ("vendor", "wheels"):
        raise ReleaseBuildError(f"wheel must be under vendor/wheels: {path_text}")


def _json_contains_secret(value: object, path: str = "") -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}" if path else key_text
            if key_text.casefold() in SENSITIVE_JSON_KEYS:
                safe_placeholder = (
                    child is None
                    or child is False
                    or (
                        isinstance(child, str)
                        and child in {"", "NOT_STORED", "REDACTED"}
                    )
                )
                if not safe_placeholder:
                    return child_path
            found = _json_contains_secret(child, child_path)
            if found is not None:
                return found
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found = _json_contains_secret(child, f"{path}[{index}]")
            if found is not None:
                return found
    return None


def _content_policy(path_text: str, data: bytes) -> None:
    for pattern in SECRET_BYTE_PATTERNS:
        if pattern.search(data):
            raise ReleaseBuildError(f"probable embedded secret in {path_text}")
    if PurePosixPath(path_text).suffix.casefold() in {".mq5", ".mqh", ".py"}:
        for pattern in ORDER_CAPABILITY_SOURCE_PATTERNS:
            if pattern.search(data):
                raise ReleaseBuildError(
                    "order-capability primitive is forbidden in a read-only "
                    f"release: {path_text}"
                )
    if path_text.casefold().endswith(".json"):
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReleaseBuildError(f"invalid JSON release input: {path_text}") from exc
        secret_path = _json_contains_secret(payload)
        if secret_path is not None:
            raise ReleaseBuildError(
                f"sensitive JSON value is forbidden: {path_text}:{secret_path}"
            )


def load_allowlist(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseBuildError(f"invalid release allowlist: {path}") from exc
    if not isinstance(payload, dict):
        raise ReleaseBuildError("release allowlist must be a JSON object")
    if set(payload) != ALLOWLIST_FIELDS:
        raise ReleaseBuildError("release allowlist root fields drift")
    schema_version = payload.get("schema_version")
    if schema_version not in ALLOWLIST_USAGE_POLICIES:
        raise ReleaseBuildError("unsupported release allowlist schema")
    if payload.get("safety") != REQUIRED_SAFETY:
        raise ReleaseBuildError("release safety locks do not match the immutable policy")
    if payload.get("usage_policy") != ALLOWLIST_USAGE_POLICIES[schema_version]:
        raise ReleaseBuildError("release usage policy does not match the immutable policy")
    profile = payload.get("release_profile")
    if not isinstance(profile, str) or not profile.strip():
        raise ReleaseBuildError("release profile is missing")
    files = payload.get("files")
    if not isinstance(files, list) or not files:
        raise ReleaseBuildError("release allowlist files must be a non-empty list")
    normalized = [_normalize_relative_path(item) for item in files]
    if len(normalized) != len(set(normalized)):
        raise ReleaseBuildError("duplicate release allowlist path")
    casefolded = [item.casefold() for item in normalized]
    if len(casefolded) != len(set(casefolded)):
        raise ReleaseBuildError("case-insensitive release path collision")
    for item in normalized:
        _path_policy(item)
    if schema_version == READ_ONLY_SERVICE_ALLOWLIST_SCHEMA:
        for item in normalized:
            basename = PurePosixPath(item).name.casefold()
            if basename.startswith(FORBIDDEN_SERVICE_TOOL_PREFIXES):
                raise ReleaseBuildError(
                    f"operator/setup tooling is forbidden in service release: {item}"
                )
    result = dict(payload)
    result["files"] = normalized
    result["_raw_sha256"] = _sha256(raw)
    return result


def _module_name_for_path(path_text: str) -> tuple[str, bool]:
    path = PurePosixPath(path_text)
    parts = list(path.with_suffix("").parts)
    is_package = parts[-1] == "__init__"
    if is_package:
        parts.pop()
    return ".".join(parts), is_package


def _resolve_local_module(root: Path, module: str) -> str | None:
    if not module:
        return None
    relative = PurePosixPath(*module.split("."))
    module_path = root / Path(relative.as_posix() + ".py")
    package_path = root / Path(relative.as_posix()) / "__init__.py"
    if module_path.is_file():
        return relative.as_posix() + ".py"
    if package_path.is_file():
        return (relative / "__init__.py").as_posix()
    return None


def _relative_import_module(
    current_module: str,
    current_is_package: bool,
    level: int,
    module: str | None,
) -> str:
    package_parts = current_module.split(".") if current_is_package else current_module.split(".")[:-1]
    upward = level - 1
    if upward > len(package_parts):
        raise ReleaseBuildError(f"relative import escapes package: {current_module}")
    base = package_parts[: len(package_parts) - upward]
    if module:
        base.extend(module.split("."))
    return ".".join(base)


def _verify_local_import_closure(
    root: Path,
    source_bytes: Mapping[str, bytes],
) -> None:
    allowed = set(source_bytes)
    missing: set[tuple[str, str]] = set()
    for path_text, data in source_bytes.items():
        if not path_text.endswith(".py"):
            continue
        try:
            tree = ast.parse(data.decode("utf-8"), filename=path_text)
        except (UnicodeDecodeError, SyntaxError) as exc:
            raise ReleaseBuildError(f"invalid Python release input: {path_text}") from exc
        current_module, is_package = _module_name_for_path(path_text)
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    base = _relative_import_module(
                        current_module,
                        is_package,
                        node.level,
                        node.module,
                    )
                else:
                    base = node.module or ""
                if base:
                    modules.append(base)
                    modules.extend(
                        f"{base}.{alias.name}"
                        for alias in node.names
                        if alias.name != "*"
                    )
                elif node.level:
                    modules.extend(
                        _relative_import_module(
                            current_module,
                            is_package,
                            node.level,
                            alias.name,
                        )
                        for alias in node.names
                        if alias.name != "*"
                    )
            for module in modules:
                local_path = _resolve_local_module(root, module)
                if local_path is not None and local_path not in allowed:
                    missing.add((path_text, local_path))
    if missing:
        detail = ", ".join(
            f"{source}->{dependency}" for source, dependency in sorted(missing)
        )
        raise ReleaseBuildError(f"local import is absent from release allowlist: {detail}")


def _read_release_sources(
    root: Path,
    paths: Iterable[str],
    tracked: set[str],
    *,
    commit: str | None = None,
) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    resolved_root = root.resolve()
    total_bytes = 0
    for path_text in paths:
        if path_text not in tracked:
            raise ReleaseBuildError(f"allowlisted file is not tracked: {path_text}")
        path = root / Path(path_text)
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ReleaseBuildError(f"allowlisted file is unavailable: {path_text}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ReleaseBuildError(f"allowlisted path is not a regular file: {path_text}")
        current = root
        for part in PurePosixPath(path_text).parts[:-1]:
            current = current / part
            try:
                if stat.S_ISLNK(current.lstat().st_mode):
                    raise ReleaseBuildError(
                        f"symlinked release path component is forbidden: {path_text}"
                    )
            except OSError as exc:
                raise ReleaseBuildError(
                    f"allowlisted path component is unavailable: {path_text}"
                ) from exc
        try:
            path.resolve(strict=True).relative_to(resolved_root)
        except (OSError, ValueError) as exc:
            raise ReleaseBuildError(f"allowlisted path escapes source root: {path_text}") from exc
        if metadata.st_size > MAX_SOURCE_FILE_BYTES:
            raise ReleaseBuildError(f"allowlisted file is too large: {path_text}")
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ReleaseBuildError(f"allowlisted file cannot be read: {path_text}") from exc
        if commit is not None:
            committed = bytes(
                _git(root, "show", f"{commit}:{path_text}", binary=True)
            )
            if committed != data:
                raise ReleaseBuildError(
                    f"allowlisted file does not match the release commit: {path_text}"
                )
            data = committed
        total_bytes += len(data)
        if total_bytes > MAX_TOTAL_SOURCE_BYTES:
            raise ReleaseBuildError("release source exceeds the total size limit")
        _content_policy(path_text, data)
        result[path_text] = data
    _verify_local_import_closure(root, result)
    return result


def _zip_member(name: str, data: bytes) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info, data


def _create_archive(source_bytes: Mapping[str, bytes], manifest_bytes: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for path_text in sorted(source_bytes):
            archive.writestr(*_zip_member(path_text, source_bytes[path_text]))
        archive.writestr(*_zip_member(MANIFEST_MEMBER, manifest_bytes))
    return output.getvalue()


def _write_exclusive(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise ReleaseBuildError(f"release output already exists or is unavailable: {path}") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def build_release(
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
        raise ReleaseBuildError("release allowlist must be inside the source repository") from exc
    if (
        PurePosixPath(allowlist_relative).parent.as_posix() != "config"
        or ALLOWLIST_NAME_PATTERN.fullmatch(PurePosixPath(allowlist_relative).name)
        is None
    ):
        raise ReleaseBuildError(
            "release allowlist must be a supported versioned config Windows allowlist"
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
                "release outputs must be outside the source repository"
            )
    commit, tree, tracked = _validate_git_release_source(root)
    allowlist = load_allowlist(allowlist_path)
    if allowlist_relative not in allowlist["files"]:
        raise ReleaseBuildError("release allowlist must include itself")
    source_bytes = _read_release_sources(
        root,
        allowlist["files"],
        tracked,
        commit=commit,
    )
    try:
        embedded_allowlist = json.loads(
            source_bytes[allowlist_relative].decode("utf-8")
        )
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseBuildError("embedded release allowlist is invalid") from exc
    loaded_allowlist = {
        field: allowlist[field]
        for field in ALLOWLIST_FIELDS
    }
    if (
        embedded_allowlist != loaded_allowlist
        or _sha256(source_bytes[allowlist_relative])
        != allowlist["_raw_sha256"]
    ):
        raise ReleaseBuildError(
            "loaded allowlist does not match the committed embedded allowlist"
        )

    manifest_without_identity: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA,
        "release_profile": allowlist["release_profile"],
        "git_commit": commit,
        "git_tree": tree,
        "allowlist_sha256": allowlist["_raw_sha256"],
        "safety": dict(allowlist["safety"]),
        "usage_policy": dict(allowlist["usage_policy"]),
        "source_files": [
            {
                "path": path_text,
                "size_bytes": len(source_bytes[path_text]),
                "sha256": _sha256(source_bytes[path_text]),
            }
            for path_text in sorted(source_bytes)
        ],
    }
    release_identity = _sha256(_canonical_json(manifest_without_identity))
    manifest = {
        **manifest_without_identity,
        "release_identity_sha256": release_identity,
    }
    manifest_bytes = _canonical_json(manifest) + b"\n"
    archive_bytes = _create_archive(source_bytes, manifest_bytes)
    _write_exclusive(resolved_output, archive_bytes)
    try:
        _write_exclusive(sidecar, manifest_bytes)
    except Exception:
        try:
            resolved_output.unlink()
        except OSError:
            pass
        raise

    try:
        final_commit = str(_git(root, "rev-parse", "HEAD"))
        final_tree = str(_git(root, "rev-parse", "HEAD^{tree}"))
        final_status = _git(
            root,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            binary=True,
        )
        if final_commit != commit or final_tree != tree or final_status:
            raise ReleaseBuildError("release source changed during construction")
    except Exception:
        for destination in (resolved_output, sidecar):
            try:
                destination.unlink()
            except OSError:
                pass
        raise
    return {
        "archive": str(resolved_output),
        "archive_sha256": _sha256(archive_bytes),
        "manifest": str(sidecar),
        "release_identity_sha256": release_identity,
        "file_count": len(source_bytes),
        "bundle_class": allowlist["usage_policy"]["bundle_class"],
        "execution_context": allowlist["usage_policy"]["execution_context"],
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build an allowlist-only deterministic Windows release"
    )
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=DEFAULT_ALLOWLIST,
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Create-exclusive ZIP destination, preferably outside the repository",
    )
    parser.add_argument("--manifest-output", type=Path, default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = build_release(
            REPO_ROOT,
            args.allowlist,
            args.output,
            manifest_output_path=args.manifest_output,
        )
    except ReleaseBuildError as exc:
        print(f"RELEASE_REJECTED: {exc}")
        return 2
    print(f"Release written: {result['archive']}")
    print(f"Release SHA-256: {result['archive_sha256']}")
    print(f"Release identity: {result['release_identity_sha256']}")
    print(f"Manifest: {result['manifest']}")
    print(f"Files: {result['file_count']}")
    print(f"Bundle class: {result['bundle_class']}")
    print(f"Execution context: {result['execution_context']}")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
