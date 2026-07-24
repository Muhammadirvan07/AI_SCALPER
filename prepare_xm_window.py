"""Prepare one immutable, read-only XM Window 02 v3 calendar plan."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.evidence_bootstrap import KEY_NAME
from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.xm_window_plan import (
    prepare_xm_calendar_plan,
    read_json_object,
    write_xm_calendar_plan_exclusive,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prepare a signed-discovery-bound XM Window 02 plan"
    )
    parser.add_argument(
        "--template",
        type=Path,
        default=Path("config/xm_calendar_window_02.template.json"),
    )
    parser.add_argument(
        "--candidate-config",
        type=Path,
        default=Path("config/broker_candidates.phase3.json"),
    )
    parser.add_argument(
        "--discovery",
        type=Path,
        default=Path("runtime_state/broker_discovery/xm-window-02-v3.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "runtime_state/broker_discovery/xm-calendar-window-02-plan-v3.json"
        ),
    )
    args = parser.parse_args()
    signing_key = WindowsEvidenceKeyStore().load(KEY_NAME)
    plan = prepare_xm_calendar_plan(
        read_json_object(args.template),
        read_json_object(args.discovery),
        read_json_object(args.candidate_config),
        signing_key,
    )
    destination = write_xm_calendar_plan_exclusive(args.output, plan)
    print(f"XM Window 02 plan written: {destination}")
    print(f"Plan SHA-256: {plan['plan_payload_sha256']}")
    print(f"Discovery SHA-256: {plan['discovery_receipt_sha256']}")
    print(f"Source instance: {plan['source_instance_id']}")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
