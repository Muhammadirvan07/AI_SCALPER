#!/usr/bin/env python3
"""Verify one atomic base-suite transfer against four external pins."""

from __future__ import annotations

import argparse
from pathlib import Path
import stat
import sys


def _bootstrap_release_root() -> Path:
    """Admit only this regular extracted configured-tooling root under -I -S."""

    entry = Path(__file__).expanduser().absolute()
    try:
        entry_metadata = entry.lstat()
        resolved_entry = entry.resolve(strict=True)
        root = resolved_entry.parent
        root_metadata = root.lstat()
        required = (
            root / "live_runtime/__init__.py",
            root / "live_runtime/windows_base_release_suite.py",
            root / "live_runtime/windows_base_release_suite_transfer.py",
        )
        required_metadata = tuple(path.lstat() for path in required)
    except OSError as exc:
        raise RuntimeError(
            "BASE_RELEASE_SUITE_TRANSFER_TOOLING_BOOTSTRAP_REJECTED"
        ) from exc

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
        or any(
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or reparse(metadata)
            for metadata in required_metadata
        )
    ):
        raise RuntimeError(
            "BASE_RELEASE_SUITE_TRANSFER_TOOLING_BOOTSTRAP_REJECTED"
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
        "BASE_RELEASE_SUITE_TRANSFER_VERIFICATION_REJECTED: "
        "TOOLING_BOOTSTRAP_REJECTED",
        file=sys.stderr,
    )
    raise SystemExit(2)


from live_runtime.windows_base_release_suite_transfer import (
    BaseReleaseSuiteTransferVerificationError,
    verify_base_release_suite_transfer,
)


class BaseReleaseSuiteTransferCLIVerificationError(RuntimeError):
    """One public invocation failed with a stable reason code."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


class _StableArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise BaseReleaseSuiteTransferCLIVerificationError(
            "ARGUMENTS_INVALID"
        )


def _parser() -> argparse.ArgumentParser:
    parser = _StableArgumentParser(
        description=(
            "Verify one deterministic Windows base-suite transfer ZIP "
            "against independently pinned archive, suite, commit, and tree "
            "identities. Verification is read-only except for bounded private "
            "temporary extraction."
        )
    )
    parser.add_argument("--archive", required=True)
    parser.add_argument("--expected-archive-sha256", required=True)
    parser.add_argument("--expected-suite-identity-sha256", required=True)
    parser.add_argument("--expected-git-commit", required=True)
    parser.add_argument("--expected-git-tree", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        report = verify_base_release_suite_transfer(
            args.archive,
            expected_archive_sha256=args.expected_archive_sha256,
            expected_suite_identity_sha256=(
                args.expected_suite_identity_sha256
            ),
            expected_git_commit=args.expected_git_commit,
            expected_git_tree=args.expected_git_tree,
        )
    except BaseReleaseSuiteTransferVerificationError as exc:
        reason = exc.reason_code
    except BaseReleaseSuiteTransferCLIVerificationError as exc:
        reason = exc.reason_code
    except (OSError, RuntimeError, TypeError, ValueError):
        reason = "TRANSFER_VERIFIER_ERROR"
    else:
        print("WINDOWS_BASE_RELEASE_SUITE_TRANSFER_VERIFIED")
        print(f"Archive: {report.archive_path}")
        print(f"Archive SHA-256: {report.archive_sha256}")
        print(
            "Transfer identity SHA-256: "
            f"{report.transfer_identity_sha256}"
        )
        print(
            "Suite identity SHA-256: "
            f"{report.suite_identity_sha256}"
        )
        print(
            "Suite manifest SHA-256: "
            f"{report.suite_manifest_sha256}"
        )
        print(f"Git commit: {report.git_commit}")
        print(f"Git tree: {report.git_tree}")
        print(f"Payload members verified: {report.payload_member_count}")
        print(f"Roles verified: {report.role_count}")
        print("Order capability: DISABLED_AT_TRANSFER_BOUNDARY")
        print("Production execution ready: false")
        print("Live allowed: false")
        print("Safe to demo auto order: false")
        print("Provider import: NOT_PERFORMED")
        print("Credential access: NOT_PERFORMED")
        print("Task installation: NOT_PERFORMED")
        print("Runtime/service process launch: NOT_PERFORMED")
        print("MT5 initialization: NOT_PERFORMED")
        print("Broker mutation: NOT_PERFORMED")
        return 0

    print(
        "BASE_RELEASE_SUITE_TRANSFER_VERIFICATION_REJECTED: "
        f"{reason}",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
