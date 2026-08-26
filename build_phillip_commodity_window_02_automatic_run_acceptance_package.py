"""Build one deterministic Window 02 automatic-run acceptance toolkit ZIP."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import zipfile

from windows_operator import (
    phillip_commodity_window_02_automatic_run_acceptance as acceptance,
)


BRANCH = acceptance.BRANCH
TOOLKIT_SCHEMA = acceptance.TOOLKIT_SCHEMA
TOOLKIT_MANIFEST = acceptance.TOOLKIT_MANIFEST
TOOL_PATH = acceptance.TOOL_PATH
FIXED_ZIP_TIMESTAMP = acceptance.FIXED_ZIP_TIMESTAMP
FIXED_ZIP_MODE = acceptance.FIXED_ZIP_MODE
SOURCE_PATHS = {
    acceptance.WRAPPER_PATH: (
        "windows_operator/Invoke-PhillipCommodityWindow02AutomaticRunAcceptance.ps1"
    ),
    acceptance.READINESS_PATH: (
        "windows_operator/Test-PhillipCommodityWindow02AutomaticRunAcceptanceReadiness.ps1"
    ),
    acceptance.TOOL_PATH: (
        "windows_operator/phillip_commodity_window_02_automatic_run_acceptance.py"
    ),
    acceptance.RUNBOOK_PATH: (
        "docs/PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_ACCEPTANCE.md"
    ),
}


class ToolkitBuildError(RuntimeError):
    """The transfer artifact could not be built without weakening provenance."""


def _has_reparse(metadata: os.stat_result) -> bool:
    return bool(
        int(getattr(metadata, "st_file_attributes", 0))
        & acceptance.FILE_ATTRIBUTE_REPARSE_POINT
    )


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise ToolkitBuildError(
            f"git {' '.join(arguments)} failed: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def _source_identity(root: Path) -> tuple[str, str]:
    commit = _git(root, "rev-parse", "HEAD^{commit}")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(
        r"[0-9a-f]{40}", tree
    ):
        raise ToolkitBuildError("invalid Git source identity")
    return commit, tree


def _tracked_source(root: Path, relative: str) -> bytes:
    path = root / relative
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ToolkitBuildError(f"source is unavailable: {relative}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _has_reparse(metadata)
        or metadata.st_nlink != 1
    ):
        raise ToolkitBuildError(f"source is not a regular file: {relative}")
    expected = subprocess.run(
        ["git", "-C", str(root), "show", f"HEAD:{relative}"],
        check=False,
        capture_output=True,
    )
    if expected.returncode != 0:
        raise ToolkitBuildError(f"source is not tracked at HEAD: {relative}")
    drift = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "diff",
            "--quiet",
            "--no-ext-diff",
            "HEAD",
            "--",
            relative,
        ],
        check=False,
    )
    if drift.returncode == 1:
        raise ToolkitBuildError(f"tracked source drift: {relative}")
    if drift.returncode != 0:
        raise ToolkitBuildError(f"tracked source verification failed: {relative}")
    return expected.stdout


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _pretty(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _member_row(path: str, value: bytes) -> dict[str, object]:
    return {"path": path, "size_bytes": len(value), "sha256": _sha256(value)}


def _render_wrapper(
    value: bytes,
    *,
    commit: str,
    tree: str,
    tool_sha256: str,
    scheduler_operator_root: str,
) -> bytes:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ToolkitBuildError("wrapper is not UTF-8") from exc
    replacements = {
        "__TOOLKIT_SOURCE_COMMIT__": commit,
        "__TOOLKIT_SOURCE_TREE__": tree,
        "__ACCEPTANCE_TOOL_SHA256__": tool_sha256,
        "__SCHEDULER_OPERATOR_ROOT__": scheduler_operator_root,
    }
    for token, replacement in replacements.items():
        if text.count(token) != 1:
            raise ToolkitBuildError(f"wrapper placeholder count invalid: {token}")
        text = text.replace(token, replacement)
    if any(token in text for token in replacements):
        raise ToolkitBuildError("wrapper has unresolved placeholders")
    return text.encode("utf-8")


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, FIXED_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = FIXED_ZIP_MODE << 16
    info.create_system = 3
    return info


def _require_output_absent(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ToolkitBuildError("output path inspection failed") from exc
    raise ToolkitBuildError("output artifact already exists")


def _safe_parent(path: Path) -> None:
    current = path
    while not current.exists():
        if current.is_symlink():
            raise ToolkitBuildError("output parent must not be a symlink")
        if current == current.parent:
            break
        current = current.parent
    try:
        metadata = current.lstat()
    except OSError as exc:
        raise ToolkitBuildError("output parent inspection failed") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _has_reparse(metadata)
    ):
        raise ToolkitBuildError("output parent must not be a symlink or reparse point")


def _remove_created(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        observed = path.lstat()
    except OSError:
        return
    if stat.S_ISREG(observed.st_mode) and (observed.st_dev, observed.st_ino) == identity:
        try:
            path.unlink()
        except OSError:
            pass


def build_package(source_root: Path, output: Path) -> dict[str, object]:
    source_root = source_root.resolve()
    output = output.absolute()
    if not re.fullmatch(
        r"phillip-commodity-window-02-automatic-run-acceptance-[0-9a-f]{8,12}\.zip",
        output.name,
    ):
        raise ToolkitBuildError("output filename is not the reviewed form")
    _require_output_absent(output)
    _safe_parent(output.parent)
    output.parent.mkdir(parents=True, exist_ok=True)
    parent_metadata = output.parent.lstat()
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or stat.S_ISLNK(parent_metadata.st_mode)
        or _has_reparse(parent_metadata)
    ):
        raise ToolkitBuildError("output parent must not be a symlink or reparse point")
    commit, tree = _source_identity(source_root)
    tracked = {
        archive_path: _tracked_source(source_root, source_path)
        for archive_path, source_path in SOURCE_PATHS.items()
    }
    if _git(source_root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ToolkitBuildError("source worktree must be clean")
    scheduler_commit = acceptance.HEALTH_OPERATOR_PACKAGE_COMMIT
    if not re.fullmatch(r"[0-9a-f]{40}", scheduler_commit):
        raise ToolkitBuildError("installed scheduler commit identity is invalid")
    scheduler_operator_root = acceptance.HEALTH_OPERATOR_ROOT
    tool_sha = _sha256(tracked[TOOL_PATH])
    for path in sorted(name for name in SOURCE_PATHS if name.endswith(".ps1")):
        tracked[path] = _render_wrapper(
            tracked[path],
            commit=commit,
            tree=tree,
            tool_sha256=tool_sha,
            scheduler_operator_root=scheduler_operator_root,
        )
    rows = [_member_row(path, tracked[path]) for path in sorted(tracked)]
    manifest: dict[str, object] = {
        "schema_version": TOOLKIT_SCHEMA,
        "source": {"branch": BRANCH, "commit": commit, "tree": tree},
        "installed_scheduler": acceptance.INSTALLED_SCHEDULER_BINDING,
        "members": rows,
        "safety": acceptance.SAFETY,
    }
    manifest["toolkit_identity_sha256"] = _sha256(_canonical(manifest))
    tracked[TOOLKIT_MANIFEST] = _pretty(manifest)
    identity: tuple[int, int] | None = None
    try:
        with output.open("xb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ToolkitBuildError("created output identity is invalid")
            identity = (metadata.st_dev, metadata.st_ino)
            with zipfile.ZipFile(
                handle,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            ) as archive:
                for path in (*sorted(SOURCE_PATHS), TOOLKIT_MANIFEST):
                    archive.writestr(_zip_info(path), tracked[path])
            handle.flush()
            os.fsync(handle.fileno())
        observed = output.lstat()
        if (
            not stat.S_ISREG(observed.st_mode)
            or stat.S_ISLNK(observed.st_mode)
            or _has_reparse(observed)
            or observed.st_nlink != 1
            or (observed.st_dev, observed.st_ino) != identity
        ):
            raise ToolkitBuildError("created output identity drift")
        archive_data = output.read_bytes()
        archive_sha = _sha256(archive_data)
        acceptance.verify_toolkit_archive(
            output,
            expected_archive_sha256=archive_sha,
            expected_source_commit=commit,
            expected_source_tree=tree,
        )
    except Exception:
        _remove_created(output, identity)
        raise
    return {
        "status": "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_ACCEPTANCE_TOOLKIT_READY",
        "archive": str(output),
        "archive_sha256": archive_sha,
        "archive_size_bytes": len(archive_data),
        "source_commit": commit,
        "source_tree": tree,
        "member_count": len(tracked),
        "order_capability": "DISABLED",
        "live_allowed": False,
        "task_scheduler_mutation": "NOT_PERFORMED",
        "broker_mutation": "NOT_PERFORMED",
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the Window 02 automatic-run acceptance toolkit."
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--source-root", type=Path, default=Path(__file__).resolve().parent
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        result = build_package(arguments.source_root, arguments.output)
    except (OSError, ValueError, ToolkitBuildError) as exc:
        print(
            "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_ACCEPTANCE_TOOLKIT_REJECTED: "
            f"{exc}",
            file=sys.stderr,
        )
        return 2
    for key, value in result.items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
