"""Build the signed-discovery-bound, read-only XM shadow calendar bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from live_runtime.session_calendar import build_calendar_bundle, write_calendar_bundle_exclusive
from live_runtime.xm_window_plan import verify_prepared_xm_calendar_plan


def main() -> int:
    parser = argparse.ArgumentParser(description="Build fail-closed XM UTC calendar")
    parser.add_argument(
        "--plan",
        type=Path,
        default=Path(
            "runtime_state/broker_discovery/xm-calendar-window-02-plan-v3.json"
        ),
    )
    parser.add_argument(
        "--template",
        type=Path,
        default=Path("config/xm_calendar_window_02.template.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("runtime_state/broker_discovery/xm-calendar-window-02-v3.json"),
    )
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    template = json.loads(args.template.read_text(encoding="utf-8"))
    verify_prepared_xm_calendar_plan(plan, template=template)
    bundle = build_calendar_bundle(plan)
    destination = write_calendar_bundle_exclusive(args.output, bundle)
    print(f"Calendar bundle written: {destination}")
    print(f"SHA-256: {bundle['bundle_sha256']}")
    for symbol, value in sorted(bundle["session_calendar_sha256"].items()):
        print(f"{symbol}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
