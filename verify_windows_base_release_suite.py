#!/usr/bin/env python3
"""Verify one exact atomic Windows base-release suite without side effects."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import stat
import sys


def _bootstrap_release_root() -> Path:
    """Admit only this regular extracted operator-tooling root under -I -S."""

    entry = Path(__file__).expanduser().absolute()
    try:
        entry_metadata = entry.lstat()
        resolved_entry = entry.resolve(strict=True)
        root = resolved_entry.parent
        root_metadata = root.lstat()
        required = (
            root / "live_runtime/__init__.py",
            root / "live_runtime/windows_base_release_suite.py",
        )
        required_metadata = tuple(path.lstat() for path in required)
    except OSError as exc:
        raise RuntimeError(
            "BASE_RELEASE_SUITE_TOOLING_BOOTSTRAP_REJECTED"
        ) from exc

    def reparse(metadata: object) -> bool:
        return bool(
            int(getattr(metadata, "st_file_attributes", 0)) & 0x400
        )

    if (
        entry != resolved_entry
        or not stat.S_ISREG(entry_metadata.st_mode)
        or stat.S_ISLNK(entry_metadata.st_mode)
        or reparse(entry_metadata)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_ISLNK(root_metadata.st_mode)
        or reparse(root_metadata)
        or any(
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or reparse(metadata)
            for metadata in required_metadata
        )
    ):
        raise RuntimeError(
            "BASE_RELEASE_SUITE_TOOLING_BOOTSTRAP_REJECTED"
        )
    sys.dont_write_bytecode = True
    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    return root


try:
    _BOOTSTRAP_ROOT = _bootstrap_release_root()
except RuntimeError:
    print(
        "BASE_RELEASE_SUITE_VERIFICATION_REJECTED: "
        "TOOLING_BOOTSTRAP_REJECTED",
        file=sys.stderr,
    )
    raise SystemExit(2)


from live_runtime.windows_base_release_suite import (
    BaseReleaseSuiteVerificationError,
    verify_base_release_suite,
)


_HEX_40 = re.compile(r"[0-9a-f]{40}")
_HEX_64 = re.compile(r"[0-9a-f]{64}")


class BaseReleaseSuiteCLIVerificationError(RuntimeError):
    """One externally pinned suite fact failed with a stable reason code."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


class _StableArgumentParser(argparse.ArgumentParser):
    """Convert invalid public invocations into one stable rejection code."""

    def error(self, _message: str) -> None:
        raise BaseReleaseSuiteCLIVerificationError("ARGUMENTS_INVALID")


def _required_pin(value: str, pattern: re.Pattern[str], reason: str) -> str:
    normalized = str(value or "").strip()
    if pattern.fullmatch(normalized) is None:
        raise BaseReleaseSuiteCLIVerificationError(reason)
    return normalized


def _parser() -> argparse.ArgumentParser:
    parser = _StableArgumentParser(
        description=(
            "Independently verify an atomic five-role Windows base-release "
            "suite against externally pinned suite and Git identities. "
            "No provider, credential, task, service, MT5, or broker effect "
            "is performed."
        )
    )
    parser.add_argument("--suite-root", required=True)
    parser.add_argument(
        "--expected-suite-identity-sha256",
        required=True,
        help="Externally pinned atomic-suite identity SHA-256.",
    )
    parser.add_argument(
        "--expected-git-commit",
        required=True,
        help="Externally pinned full lowercase 40-character Git commit.",
    )
    parser.add_argument(
        "--expected-git-tree",
        required=True,
        help="Externally pinned full lowercase 40-character Git tree.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        expected_identity = _required_pin(
            args.expected_suite_identity_sha256,
            _HEX_64,
            "EXPECTED_SUITE_IDENTITY_INVALID",
        )
        expected_commit = _required_pin(
            args.expected_git_commit,
            _HEX_40,
            "EXPECTED_GIT_COMMIT_INVALID",
        )
        expected_tree = _required_pin(
            args.expected_git_tree,
            _HEX_40,
            "EXPECTED_GIT_TREE_INVALID",
        )
        report = verify_base_release_suite(args.suite_root)
        if report.suite_identity_sha256 != expected_identity:
            raise BaseReleaseSuiteCLIVerificationError(
                "EXPECTED_SUITE_IDENTITY_MISMATCH"
            )
        if report.git_commit != expected_commit:
            raise BaseReleaseSuiteCLIVerificationError(
                "EXPECTED_GIT_COMMIT_MISMATCH"
            )
        if report.git_tree != expected_tree:
            raise BaseReleaseSuiteCLIVerificationError(
                "EXPECTED_GIT_TREE_MISMATCH"
            )
    except BaseReleaseSuiteVerificationError as exc:
        reason = exc.reason_code
    except BaseReleaseSuiteCLIVerificationError as exc:
        reason = exc.reason_code
    except (OSError, RuntimeError, TypeError, ValueError):
        reason = "BASE_RELEASE_SUITE_VERIFIER_ERROR"
    else:
        print("WINDOWS_BASE_RELEASE_SUITE_VERIFIED")
        print(f"Suite root: {report.root}")
        print(
            "Suite identity SHA-256: "
            f"{report.suite_identity_sha256}"
        )
        print(
            "Suite manifest SHA-256: "
            f"{report.manifest_sha256}"
        )
        print(f"Git commit: {report.git_commit}")
        print(f"Git tree: {report.git_tree}")
        print(f"Roles verified: {len(report.roles)}")
        for role in report.roles:
            print(
                f"{role.role}: "
                f"archive_sha256={role.archive_sha256}; "
                f"release_identity_sha256="
                f"{role.release_identity_sha256}; "
                f"order_capability={role.order_capability}; "
                "production_execution_ready=false"
            )
        print("Order capability: DISABLED_AT_SUITE_BOUNDARY")
        print("Production execution ready: false")
        print("Live allowed: false")
        print("Safe to demo auto order: false")
        print("Promotion eligible: false")
        print("Max lot: 0.01")
        print("Provider import: NOT_PERFORMED")
        print("Credential access: NOT_PERFORMED")
        print("Task installation: NOT_PERFORMED")
        print("Runtime/service process launch: NOT_PERFORMED")
        print("MT5 initialization: NOT_PERFORMED")
        print("Broker mutation: NOT_PERFORMED")
        return 0

    print(
        f"BASE_RELEASE_SUITE_VERIFICATION_REJECTED: {reason}",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
