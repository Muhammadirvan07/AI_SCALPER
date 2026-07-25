#!/usr/bin/env python3
"""Assemble one deny-only, suite-bound configured Decision candidate."""

from __future__ import annotations

import argparse
from pathlib import Path
import stat
import sys


def _bootstrap_release_root() -> Path:
    entry = Path(__file__).expanduser().absolute()
    try:
        metadata = entry.lstat()
        resolved = entry.resolve(strict=True)
        root = resolved.parent
        root_metadata = root.lstat()
        required = (
            root / "live_runtime/__init__.py",
            root
            / "live_runtime/windows_decision_configured_candidate.py",
            root / "live_runtime/configured_service_release.py",
            root / "live_runtime/windows_base_release_suite.py",
            root
            / "live_runtime/windows_decision_provider_pack_generator.py",
            root
            / "live_runtime/windows_decision_service_factory_template.py",
            root / "live_runtime/contracts.py",
        )
        required_metadata = tuple(path.lstat() for path in required)
    except OSError as exc:
        raise RuntimeError(
            "DECISION_CONFIGURED_CANDIDATE_BOOTSTRAP_REJECTED"
        ) from exc

    def reparse(item: object) -> bool:
        return bool(
            int(getattr(item, "st_file_attributes", 0)) & 0x400
        )

    if (
        entry != resolved
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or reparse(metadata)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_ISLNK(root_metadata.st_mode)
        or reparse(root_metadata)
        or any(
            not stat.S_ISREG(item.st_mode)
            or stat.S_ISLNK(item.st_mode)
            or reparse(item)
            for item in required_metadata
        )
    ):
        raise RuntimeError(
            "DECISION_CONFIGURED_CANDIDATE_BOOTSTRAP_REJECTED"
        )
    sys.dont_write_bytecode = True
    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    return root


_BOOTSTRAP_ROOT = _bootstrap_release_root()

from live_runtime.windows_decision_configured_candidate import (
    DecisionConfiguredCandidateError,
    assemble_windows_decision_configured_candidate,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Assemble a suite-bound configured Decision candidate without "
            "provider, credential, task, process, MT5, broker, or order effects."
        )
    )
    parser.add_argument("--base-suite-root", required=True)
    parser.add_argument("--decision-base-release", required=True)
    parser.add_argument("--provider-pack-root", required=True)
    parser.add_argument("--task-definition", required=True)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--output-root", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = assemble_windows_decision_configured_candidate(
            base_suite_root=args.base_suite_root,
            decision_base_release=args.decision_base_release,
            provider_pack_root=args.provider_pack_root,
            task_definition_path=args.task_definition,
            candidate_id=args.candidate_id,
            output_root=args.output_root,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        reason = getattr(
            exc,
            "reason_code",
            "DECISION_CONFIGURED_CANDIDATE_REJECTED",
        )
        print(
            f"WINDOWS_DECISION_CONFIGURED_CANDIDATE_REJECTED: {reason}",
            file=sys.stderr,
        )
        return 2
    print("WINDOWS_DECISION_CONFIGURED_CANDIDATE_ASSEMBLED")
    print(f"Status: {result.status}")
    print(f"Output root: {result.output_root}")
    print(f"Candidate ID: {result.candidate_id}")
    print(f"Candidate SHA-256: {result.content_sha256}")
    print(
        "Configured release identity SHA-256: "
        f"{result.configured_release_identity_sha256}"
    )
    print(f"Providers declared: {result.provider_count}")
    print("Provider acceptance: REQUIRED_EXTERNAL")
    print("Credential access: NOT_PERFORMED")
    print("Provider import: NOT_PERFORMED")
    print("Provider materialization: NOT_PERFORMED")
    print("Task installation: NOT_PERFORMED")
    print("Broker mutation: NOT_PERFORMED")
    print("Order capability: DISABLED")
    print("Production execution ready: false")
    print("Live allowed: false")
    print("Safe to demo auto order: false")
    print("Max lot: 0.01")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
