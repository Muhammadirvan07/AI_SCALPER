#!/usr/bin/env python3
"""Prepare one immutable, non-executable manual-demo operator kit."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from live_runtime.manual_demo_activation_kit import (
    ManualDemoActivationKitError,
    build_manual_demo_activation_kit,
)
from live_runtime.manual_demo_readiness import (
    ManualDemoReadinessError,
    load_current_manual_demo_readiness,
)
from live_runtime.secure_files import SecureFileError, write_json_exclusive
from live_runtime.windows_service_factory_template import provider_contracts
from validate_windows_gated_execution_service import validate_gated_execution_ports


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare a blocked manual-demo activation kit; no broker order, "
            "credential read, or authorization is performed."
        )
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument(
        "--output",
        help="Optionally create one immutable JSON kit; existing files are rejected.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = Path(__file__).resolve().parent
    try:
        readiness = load_current_manual_demo_readiness(
            candidate_id=args.candidate,
            project_root=root,
        )
        kit = build_manual_demo_activation_kit(
            readiness=readiness,
            windows_validation=validate_gated_execution_ports(),
            provider_contracts=provider_contracts(),
            prepared_at_utc=datetime.now(timezone.utc),
        )
        payload = kit.to_canonical_dict()
        payload["content_sha256"] = kit.content_sha256
        if args.output:
            write_json_exclusive(args.output, payload)
    except (
        FileExistsError,
        ManualDemoActivationKitError,
        ManualDemoReadinessError,
        SecureFileError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"MANUAL_DEMO_ACTIVATION_KIT_REJECTED: {exc}", file=sys.stderr)
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
