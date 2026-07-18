"""Windows CLI for sanitized preparation-only MT5 candidate preflight."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.mt5_preflight import (
    MT5CandidatePreflightError,
    attest_candidate_read_only,
    load_preflight_candidate,
)
from live_runtime.mt5_readonly import (
    MT5ReadOnlyCapabilityError,
    ReadOnlyMT5Facade,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Preparation-only MT5 read-only preflight; accepts no credentials"
    )
    parser.add_argument("--candidate", default="fbs")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/broker_candidates.phase3.json"),
    )
    args = parser.parse_args()

    try:
        candidate = load_preflight_candidate(args.config, args.candidate)
        import MetaTrader5 as mt5  # Windows-only dependency, intentionally late

        if not mt5.initialize():
            print("MT5_READ_ONLY_PREFLIGHT_FAILED: terminal initialization failed")
            return 1
        try:
            result = attest_candidate_read_only(
                ReadOnlyMT5Facade(mt5),
                candidate_id=args.candidate,
                candidate=candidate,
            )
        finally:
            mt5.shutdown()
    except (MT5CandidatePreflightError, MT5ReadOnlyCapabilityError, ImportError) as exc:
        print(f"MT5_READ_ONLY_PREFLIGHT_FAILED: {exc}")
        print("Safety lock remains active; no broker order was submitted.")
        return 1

    print("MT5_READ_ONLY_PREFLIGHT_PASS")
    print(f"Candidate: {result['candidate_id']}")
    print(f"Server: {result['server']}")
    print(f"Environment: {result['environment']}")
    print(f"Account currency: {result['account_currency']}")
    print(f"Leverage: {result['leverage']}:1")
    print("Symbols: " + ", ".join(sorted(result["symbols"])))
    print("Order capability: DISABLED")
    print("Discovery evidence: DISABLED")
    print("Promotion evidence: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
