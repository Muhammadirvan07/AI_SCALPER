#!/usr/bin/env python3
"""Fail-closed, optimization-safe verification of checked-in execution locks."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import execution_policy  # noqa: E402


class SafetyContractError(RuntimeError):
    """The repository no longer matches its diagnostic/read-only contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SafetyContractError(message)


def walk(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key), child
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def verify_json_safety() -> int:
    checked = 0
    permitted_capability_labels = {
        "DISABLED",
        "DISABLED_AT_SUITE_BOUNDARY",
        "GATED_PRESENT",
    }
    for path in sorted((ROOT / "config").glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        checked += 1
        for key, value in walk(payload):
            normalized = key.lower()
            if normalized in {"live_allowed", "safe_to_demo_auto_order"}:
                require(value is False, f"{path.name}: {key} must remain false")
            elif normalized == "max_lot":
                require(type(value) in {int, float}, f"{path.name}: max_lot must be numeric")
                require(float(value) <= 0.01, f"{path.name}: max_lot exceeds 0.01")
            elif normalized == "order_capability":
                require(
                    value in permitted_capability_labels,
                    f"{path.name}: order capability is not fail-closed",
                )
    return checked


def main() -> int:
    require(execution_policy.LIVE_ALLOWED is False, "LIVE_ALLOWED must remain false")
    require(
        execution_policy.SAFE_TO_DEMO_AUTO_ORDER is False,
        "SAFE_TO_DEMO_AUTO_ORDER must remain false",
    )
    require(
        type(execution_policy.EXECUTION_MAX_LOT) is float
        and execution_policy.EXECUTION_MAX_LOT <= 0.01,
        "EXECUTION_MAX_LOT must remain at or below 0.01",
    )
    live_allowed, live_reasons = execution_policy.execution_mode_policy_decision("LIVE")
    demo_auto_allowed, demo_reasons = execution_policy.execution_mode_policy_decision("DEMO_AUTO")
    require(live_allowed is False and live_reasons, "LIVE mode must remain explicitly denied")
    require(
        demo_auto_allowed is False and demo_reasons,
        "DEMO_AUTO mode must remain explicitly denied",
    )
    lot_allowed, _ = execution_policy.validate_execution_lot(0.02)
    require(lot_allowed is False, "lot above 0.01 must be rejected")
    config_count = verify_json_safety()
    print("SAFETY_CONTRACT_VERIFIED")
    print("LIVE_ALLOWED: false")
    print("SAFE_TO_DEMO_AUTO_ORDER: false")
    print(f"MAX_LOT: {execution_policy.EXECUTION_MAX_LOT:.2f}")
    print("ORDER_CAPABILITY: DISABLED_OR_NON_ACTIVATING_GATE")
    print(f"CONFIG_FILES_VERIFIED: {config_count}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, SafetyContractError) as exc:
        print(f"SAFETY_CONTRACT_REJECTED: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
