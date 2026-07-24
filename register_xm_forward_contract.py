"""Register the immutable XM Window 02 v3 DIAGNOSTIC contract on Windows."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.evidence_bootstrap import (
    KEY_NAME,
    register_xm_diagnostic_contract,
)
from live_runtime.evidence_credentials import WindowsEvidenceKeyStore


def main() -> int:
    parser = argparse.ArgumentParser(description="Register XM diagnostic evidence contract")
    parser.add_argument(
        "--discovery",
        type=Path,
        default=Path("runtime_state/broker_discovery/xm-window-02-v3.json"),
    )
    parser.add_argument(
        "--plan",
        type=Path,
        default=Path(
            "runtime_state/broker_discovery/xm-calendar-window-02-plan-v3.json"
        ),
    )
    parser.add_argument(
        "--calendar",
        type=Path,
        default=Path("runtime_state/broker_discovery/xm-calendar-window-02-v3.json"),
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=Path("validation_artifacts"),
    )
    args = parser.parse_args()
    key = WindowsEvidenceKeyStore().load(KEY_NAME)
    contract = register_xm_diagnostic_contract(
        Path.cwd(),
        args.artifact_root,
        args.discovery,
        args.calendar,
        key,
        plan_path=args.plan,
    )
    print("Forward contract registered: " + str(contract["contract_id"]))
    print("Profile: " + str(contract["validation_profile"]))
    print("Contract SHA-256: " + str(contract["contract_payload_sha256"]))
    print("Signing key ID: " + str(contract["signing_key_id"]))
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
