"""Windows CLI for sanitized preparation-only MT5 candidate preflight."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.mt5_preflight import (
    MT5CandidatePreflightError,
    attest_candidate_read_only,
    build_preflight_receipt,
    load_preflight_candidate,
    utc_now,
    write_preflight_receipt_exclusive,
)
from live_runtime.mt5_readonly import (
    MT5ReadOnlyCapabilityError,
    ReadOnlyMT5Facade,
)
from live_runtime.secure_files import SecureFileError


REPO_ROOT = Path(__file__).resolve().parent


def _repo_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Preparation-only MT5 read-only preflight; accepts no credentials"
    )
    parser.add_argument("--candidate", default="fbs")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/broker_candidates.phase3.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        help=(
            "optional create-exclusive sanitized preflight receipt; this is "
            "diagnostic audit state, not validation evidence"
        ),
    )
    args = parser.parse_args(argv)

    try:
        candidate = load_preflight_candidate(
            _repo_path(args.config),
            args.candidate,
        )
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
            receipt = build_preflight_receipt(result, captured_at=utc_now())
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
    if args.output is not None:
        try:
            destination = write_preflight_receipt_exclusive(
                _repo_path(args.output),
                receipt,
            )
        except (
            OSError,
            SecureFileError,
            ValueError,
            TypeError,
            MT5CandidatePreflightError,
        ) as exc:
            print(f"PREFLIGHT_RECEIPT_WRITE_FAILED: {exc}")
            print("Safety lock remains active; no broker order was submitted.")
            return 1
        print(f"Sanitized receipt: {destination}")
        print(f"Receipt SHA-256: {receipt['payload_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
