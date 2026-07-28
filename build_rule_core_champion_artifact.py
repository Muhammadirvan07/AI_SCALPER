"""Build one deterministic Phillip Commodity rule-core champion artifact."""

from __future__ import annotations

import argparse
from datetime import datetime
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from live_runtime.model_governance import RULE_CORE_MODEL_SOURCE_PATHS
from live_runtime.rule_core_model_artifact import (
    CONFIG_PATH,
    RuleCoreModelArtifactError,
    build_archive_bytes,
    parse_canonical_utc,
    sha256_bytes,
    verify_archive_with_pins,
)


REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_BRANCH = "agent/live-grade-phase3"
_OUTPUT_NAME = re.compile(
    r"rule-core-phillip-commodity-champion-([0-9a-f]{8,12})\.zip"
)
_REPARSE_ATTRIBUTE = 0x400


class RuleCoreChampionBuildError(RuntimeError):
    """Raised when source or destination cannot produce a trusted artifact."""


def _git(root: Path, *args: str, binary: bool = False) -> bytes | str:
    completed = subprocess.run(
        ("git", "-C", str(root), *args),
        check=False,
        capture_output=True,
        text=not binary,
        env={**os.environ, "LC_ALL": "C"},
    )
    if completed.returncode != 0:
        stderr = completed.stderr if not binary else completed.stderr.decode(
            "utf-8", errors="replace"
        )
        raise RuleCoreChampionBuildError(
            f"git {' '.join(args)} failed: {stderr.strip()}"
        )
    return completed.stdout


def _git_text(root: Path, *args: str) -> str:
    result = _git(root, *args)
    if type(result) is not str:  # pragma: no cover - wrapper invariant
        raise RuleCoreChampionBuildError("Git text output is invalid")
    return result.strip()


def _git_bytes(root: Path, *args: str) -> bytes:
    result = _git(root, *args, binary=True)
    if type(result) is not bytes:  # pragma: no cover - wrapper invariant
        raise RuleCoreChampionBuildError("Git byte output is invalid")
    return result


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE)


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        getattr(left, name, None) == getattr(right, name, None)
        for name in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
    )


def _same_directory(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        getattr(left, name, None) == getattr(right, name, None)
        for name in ("st_dev", "st_ino", "st_mode")
    )


def _require_direct_path(path: Path, *, reason: str) -> None:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise RuleCoreChampionBuildError(reason) from exc
    if resolved != path:
        raise RuleCoreChampionBuildError(reason)


def _tracked_bytes(root: Path, relative: str, *, commit: str) -> bytes:
    path = root / relative
    _require_direct_path(path, reason=f"tracked source indirection: {relative}")
    try:
        before = path.lstat()
    except OSError as exc:
        raise RuleCoreChampionBuildError(
            f"tracked source unavailable: {relative}"
        ) from exc
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or _is_reparse(before):
        raise RuleCoreChampionBuildError(f"tracked source is not regular: {relative}")
    observed = path.read_bytes()
    after = path.lstat()
    if not _same_file(before, after):
        raise RuleCoreChampionBuildError(f"tracked source changed while read: {relative}")
    expected = _git_bytes(root, "show", f"{commit}:{relative}")
    if observed != expected:
        raise RuleCoreChampionBuildError(f"tracked source drift: {relative}")
    return observed


def _snapshot_bytes(path: Path) -> bytes:
    if path.name.casefold() != "xauusd.csv":
        raise RuleCoreChampionBuildError("snapshot filename must be xauusd.csv")
    try:
        before = path.lstat()
    except OSError as exc:
        raise RuleCoreChampionBuildError("snapshot is unavailable") from exc
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or _is_reparse(before):
        raise RuleCoreChampionBuildError("snapshot must be one regular non-reparse file")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise RuleCoreChampionBuildError("snapshot path is unavailable") from exc
    try:
        resolved_before = resolved.lstat()
    except OSError as exc:  # pragma: no cover - resolve already proved presence
        raise RuleCoreChampionBuildError("snapshot path is unavailable") from exc
    if not _same_file(before, resolved_before):
        raise RuleCoreChampionBuildError("snapshot changed while resolved")
    data = resolved.read_bytes()
    after = resolved.lstat()
    if not _same_file(before, after):
        raise RuleCoreChampionBuildError("snapshot changed while read")
    return data


def _inspect_absent(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RuleCoreChampionBuildError("output inspection failed") from exc
    raise RuleCoreChampionBuildError("output already exists")


def _validate_git_control(root: Path) -> None:
    control = root / ".git"
    try:
        metadata = control.lstat()
    except OSError as exc:
        raise RuleCoreChampionBuildError("source root is not a Git worktree") from exc
    if (
        (not stat.S_ISREG(metadata.st_mode) and not stat.S_ISDIR(metadata.st_mode))
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        raise RuleCoreChampionBuildError("Git control path is not trusted")
    try:
        top = Path(_git_text(root, "rev-parse", "--show-toplevel")).resolve(
            strict=True
        )
    except OSError as exc:
        raise RuleCoreChampionBuildError("Git worktree root is unavailable") from exc
    if top != root:
        raise RuleCoreChampionBuildError("source root is not the Git worktree root")


def _require_source_identity(
    root: Path,
    *,
    commit: str,
    tree: str,
    branch: str,
) -> None:
    if _git_text(root, "status", "--porcelain", "--untracked-files=no"):
        raise RuleCoreChampionBuildError("tracked source checkout is dirty")
    if (
        _git_text(root, "rev-parse", "HEAD^{commit}") != commit
        or _git_text(root, "rev-parse", f"{commit}^{{tree}}") != tree
        or _git_text(root, "branch", "--show-current") != branch
    ):
        raise RuleCoreChampionBuildError("source Git identity changed")


def _remove_created(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        observed = path.lstat()
    except OSError:
        return
    if (
        not stat.S_ISREG(observed.st_mode)
        or _is_reparse(observed)
        or (int(observed.st_dev), int(observed.st_ino)) != identity
    ):
        return
    try:
        path.unlink()
    except OSError:
        pass


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_exclusive(path: Path, data: bytes) -> tuple[int, int]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata):
                raise RuleCoreChampionBuildError("output is not a regular file")
            identity = (int(metadata.st_dev), int(metadata.st_ino))
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _sync_directory(path.parent)
    except Exception:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        _remove_created(path, identity)
        raise
    if identity is None:  # pragma: no cover - successful write invariant
        raise RuleCoreChampionBuildError("output identity was not captured")
    return identity


def build_champion_artifact(
    *,
    source_root: Path,
    snapshot_path: Path,
    registered_at: datetime,
    output: Path,
    expected_branch: str = DEFAULT_BRANCH,
) -> dict[str, object]:
    source_root = source_root.expanduser().resolve(strict=True)
    _validate_git_control(source_root)
    output = Path(os.path.abspath(output.expanduser()))
    match = _OUTPUT_NAME.fullmatch(output.name)
    if match is None:
        raise RuleCoreChampionBuildError("output filename is not reviewed")
    requested_parent = output.parent
    try:
        requested_parent_metadata = requested_parent.lstat()
    except OSError as exc:
        raise RuleCoreChampionBuildError(
            "output parent must already exist"
        ) from exc
    if (
        not stat.S_ISDIR(requested_parent_metadata.st_mode)
        or stat.S_ISLNK(requested_parent_metadata.st_mode)
        or _is_reparse(requested_parent_metadata)
    ):
        raise RuleCoreChampionBuildError("output parent must be a real directory")
    try:
        resolved_parent = requested_parent.resolve(strict=True)
    except OSError as exc:  # pragma: no cover - lstat already proved presence
        raise RuleCoreChampionBuildError("output parent is unavailable") from exc
    output = resolved_parent / output.name
    parent = resolved_parent.lstat()
    if not _same_directory(requested_parent_metadata, parent):
        raise RuleCoreChampionBuildError("output parent changed while resolved")
    if output.is_relative_to(source_root):
        raise RuleCoreChampionBuildError("output must be outside the source worktree")
    _inspect_absent(output)
    commit = _git_text(source_root, "rev-parse", "HEAD^{commit}")
    tree = _git_text(source_root, "rev-parse", f"{commit}^{{tree}}")
    branch = _git_text(source_root, "branch", "--show-current")
    if (
        re.fullmatch(r"[0-9a-f]{40}", commit) is None
        or re.fullmatch(r"[0-9a-f]{40}", tree) is None
        or branch != expected_branch
        or match.group(1) != commit[: len(match.group(1))]
    ):
        raise RuleCoreChampionBuildError("source Git identity is invalid")
    _require_source_identity(
        source_root,
        commit=commit,
        tree=tree,
        branch=branch,
    )
    source_members = {
        path: _tracked_bytes(source_root, path, commit=commit)
        for path in RULE_CORE_MODEL_SOURCE_PATHS
    }
    config_bytes = _tracked_bytes(source_root, CONFIG_PATH, commit=commit)
    snapshot = _snapshot_bytes(snapshot_path.expanduser().absolute())
    try:
        archive, result = build_archive_bytes(
            source_members=source_members,
            config_bytes=config_bytes,
            snapshot_bytes=snapshot,
            branch=branch,
            commit=commit,
            tree=tree,
            registered_at=registered_at,
        )
    except RuleCoreModelArtifactError as exc:
        raise RuleCoreChampionBuildError(str(exc)) from exc
    _require_source_identity(
        source_root,
        commit=commit,
        tree=tree,
        branch=branch,
    )
    identity: tuple[int, int] | None = None
    try:
        identity = _write_exclusive(output, archive)
        persisted = output.read_bytes()
        observed = output.lstat()
        current_parent = output.parent.lstat()
        if (
            (int(observed.st_dev), int(observed.st_ino)) != identity
            or persisted != archive
            or not _same_directory(parent, current_parent)
            or output.parent.resolve(strict=True) != output.parent
        ):
            raise RuleCoreChampionBuildError("published artifact drift")
        verified = verify_archive_with_pins(
            persisted,
            expected_archive_sha256=str(result["archive_sha256"]),
            expected_model_artifact_sha256=str(result["model_artifact_sha256"]),
            expected_training_snapshot_sha256=str(
                result["training_snapshot_sha256"]
            ),
            expected_config_sha256=str(result["config_sha256"]),
            expected_git_commit=commit,
            expected_git_tree=tree,
        )
    except Exception:
        _remove_created(output, identity)
        raise
    return {**verified, "archive": str(output)}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build a deterministic deny-only Phillip Commodity rule-core "
            "champion artifact."
        )
    )
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--registered-at-utc", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--branch", default=DEFAULT_BRANCH)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        registered_at = parse_canonical_utc(
            args.registered_at_utc, reason="REGISTRATION_TIME_INVALID"
        )
        result = build_champion_artifact(
            source_root=args.source_root,
            snapshot_path=args.snapshot,
            registered_at=registered_at,
            output=args.output,
            expected_branch=args.branch,
        )
    except (OSError, RuleCoreChampionBuildError, RuleCoreModelArtifactError) as exc:
        print(f"RULE_CORE_CHAMPION_ARTIFACT_REJECTED: {exc}", file=sys.stderr)
        return 2
    print("RULE_CORE_CHAMPION_ARTIFACT_READY")
    for key in (
        "archive",
        "archive_sha256",
        "package_identity_sha256",
        "model_artifact_sha256",
        "training_snapshot_sha256",
        "config_sha256",
        "git_commit",
        "git_tree",
        "snapshot_rows",
        "training_cutoff_at_utc",
        "registered_at_utc",
        "runtime_binding_sha256",
        "quality_approved",
        "promotion_eligible",
        "order_capability",
        "live_allowed",
        "broker_mutation",
    ):
        print(f"{key}: {result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
