#!/usr/bin/env python3
"""Report locked manual-demo preparation state without external mutation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from live_runtime.manual_demo_readiness import (
    ManualDemoReadinessError,
    load_current_manual_demo_readiness,
)
from live_runtime.secure_files import SecureFileError, write_json_exclusive


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Report manual-demo readiness blockers; execution remains disabled."
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument(
        "--output",
        help="Optionally create one immutable JSON report; existing files are rejected.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = Path(__file__).resolve().parent
    try:
        report = load_current_manual_demo_readiness(
            candidate_id=args.candidate,
            project_root=root,
        )
        payload = report.to_canonical_dict()
        payload["content_sha256"] = report.content_sha256
        if args.output:
            write_json_exclusive(args.output, payload)
    except (
        FileExistsError,
        ManualDemoReadinessError,
        SecureFileError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"MANUAL_DEMO_READINESS_REJECTED: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
