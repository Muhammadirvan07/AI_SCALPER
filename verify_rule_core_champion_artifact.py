#!/usr/bin/env python3
"""Independently verify one rule-core champion artifact using external pins."""

from __future__ import annotations

import argparse
from pathlib import Path
import stat
import sys


def _bootstrap_release_root() -> Path:
    """Admit only the regular extracted tooling root under ``-I -S``."""

    entry = Path(__file__).expanduser().absolute()
    try:
        entry_metadata = entry.lstat()
        resolved_entry = entry.resolve(strict=True)
        root = resolved_entry.parent
        root_metadata = root.lstat()
        package = root / "live_runtime"
        package_metadata = package.lstat()
        required = (
            package / "__init__.py",
            package / "contracts.py",
            package / "model_governance.py",
            package / "rule_core_model_artifact.py",
        )
        required_metadata = tuple(path.lstat() for path in required)
    except OSError as exc:
        raise RuntimeError("RULE_CORE_TOOLING_BOOTSTRAP_REJECTED") from exc

    def reparse(metadata: object) -> bool:
        return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)

    if (
        entry != resolved_entry
        or not stat.S_ISREG(entry_metadata.st_mode)
        or stat.S_ISLNK(entry_metadata.st_mode)
        or reparse(entry_metadata)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_ISLNK(root_metadata.st_mode)
        or reparse(root_metadata)
        or not stat.S_ISDIR(package_metadata.st_mode)
        or stat.S_ISLNK(package_metadata.st_mode)
        or reparse(package_metadata)
        or any(
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or reparse(metadata)
            for metadata in required_metadata
        )
    ):
        raise RuntimeError("RULE_CORE_TOOLING_BOOTSTRAP_REJECTED")
    sys.dont_write_bytecode = True
    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    return root


try:
    _BOOTSTRAP_ROOT = _bootstrap_release_root()
except RuntimeError:
    print(
        "RULE_CORE_CHAMPION_ARTIFACT_REJECTED: TOOLING_BOOTSTRAP_REJECTED",
        file=sys.stderr,
    )
    raise SystemExit(2)


from live_runtime.rule_core_model_artifact import (
    MAX_ARCHIVE_BYTES,
    RuleCoreModelArtifactError,
    verify_archive_with_pins,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify a deny-only Phillip Commodity rule-core champion artifact."
    )
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--expected-archive-sha256", required=True)
    parser.add_argument("--expected-model-artifact-sha256", required=True)
    parser.add_argument("--expected-training-snapshot-sha256", required=True)
    parser.add_argument("--expected-config-sha256", required=True)
    parser.add_argument("--expected-git-commit", required=True)
    parser.add_argument("--expected-git-tree", required=True)
    return parser


def _regular_bytes(path: Path) -> bytes:
    absolute = path.expanduser().absolute()
    metadata = absolute.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or int(getattr(metadata, "st_file_attributes", 0)) & 0x400
        or metadata.st_size <= 0
        or metadata.st_size > MAX_ARCHIVE_BYTES
    ):
        raise RuleCoreModelArtifactError("ARTIFACT_ARCHIVE_FILE_INVALID")
    data = absolute.read_bytes()
    after = absolute.lstat()
    if any(
        getattr(metadata, name, None) != getattr(after, name, None)
        for name in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
    ):
        raise RuleCoreModelArtifactError("ARTIFACT_ARCHIVE_FILE_CHANGED")
    return data


def main() -> int:
    args = _parser().parse_args()
    try:
        result = verify_archive_with_pins(
            _regular_bytes(args.archive),
            expected_archive_sha256=args.expected_archive_sha256,
            expected_model_artifact_sha256=args.expected_model_artifact_sha256,
            expected_training_snapshot_sha256=(
                args.expected_training_snapshot_sha256
            ),
            expected_config_sha256=args.expected_config_sha256,
            expected_git_commit=args.expected_git_commit,
            expected_git_tree=args.expected_git_tree,
        )
    except (OSError, RuleCoreModelArtifactError) as exc:
        print(f"RULE_CORE_CHAMPION_ARTIFACT_REJECTED: {exc}", file=sys.stderr)
        return 2
    print("RULE_CORE_CHAMPION_ARTIFACT_VERIFIED")
    for key in (
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
