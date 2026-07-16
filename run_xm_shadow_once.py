"""Run one deadline-bound, read-only XM evidence cycle on Windows."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.evidence_bootstrap import KEY_NAME
from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.shadow_collector import ShadowCycleStore, run_shadow_cycle


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one XM read-only shadow cycle")
    parser.add_argument(
        "--artifact-root", type=Path, default=Path("validation_artifacts")
    )
    parser.add_argument(
        "--journal",
        type=Path,
        default=Path("runtime_state/shadow/xm-shadow-cycles.sqlite3"),
    )
    args = parser.parse_args()
    key = WindowsEvidenceKeyStore().load(KEY_NAME)

    import MetaTrader5 as mt5  # Windows-only, intentionally late

    if not mt5.initialize():
        raise RuntimeError(f"MT5 initialize failed: {mt5.last_error()}")
    store = ShadowCycleStore(args.journal)
    try:
        receipt = run_shadow_cycle(
            mt5,
            repo_root=Path.cwd(),
            artifact_root=args.artifact_root,
            signing_key=key,
            store=store,
        )
        print("Shadow cycle: " + receipt.cycle_id)
        print("Status: " + receipt.status)
        for symbol, status in sorted(receipt.symbol_status.items()):
            print(f"{symbol}: {status}")
        if receipt.failures:
            print("Failures: " + ",".join(receipt.failures))
        print("Receipt SHA-256: " + receipt.payload_sha256)
        print("Order capability: DISABLED")
        return 0 if receipt.status != "HOLD" else 2
    finally:
        store.close()
        mt5.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
