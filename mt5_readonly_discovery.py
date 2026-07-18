"""Windows CLI for phase-3 MT5 discovery. It never accepts broker credentials."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from live_runtime.evidence_bootstrap import KEY_NAME
from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.mt5_discovery import (
    MT5DiscoveryError,
    discover_mt5_facts,
    utc_now,
    write_discovery_exclusive,
)
from live_runtime.mt5_readonly import ReadOnlyMT5Facade


def _candidate(path: Path, candidate_id: str) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    matches = [item for item in payload["candidates"] if item["candidate_id"] == candidate_id]
    if len(matches) != 1:
        raise MT5DiscoveryError("candidate must exist exactly once in configuration")
    candidate = matches[0]
    if candidate.get("read_only_discovery_allowed") is not True:
        raise MT5DiscoveryError(
            "candidate read-only discovery requires explicit reviewed approval"
        )
    if not candidate.get("server"):
        raise MT5DiscoveryError("candidate exact server has not been observed")
    symbols = candidate.get("broker_symbols_observed")
    if not isinstance(symbols, dict) or any(value is None for value in symbols.values()):
        raise MT5DiscoveryError("candidate four-symbol map is incomplete")
    return candidate


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only MT5 fact discovery")
    parser.add_argument("--candidate", default="xm")
    parser.add_argument(
        "--config", type=Path, default=Path("config/broker_candidates.phase3.json")
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    candidate = _candidate(args.config, args.candidate)
    signing_key = WindowsEvidenceKeyStore().load(KEY_NAME)

    import MetaTrader5 as mt5  # Windows-only dependency, intentionally late

    if not mt5.initialize():
        raise MT5DiscoveryError(f"MT5 initialize failed: {mt5.last_error()}")
    try:
        receipt = discover_mt5_facts(
            ReadOnlyMT5Facade(mt5),
            candidate_id=args.candidate,
            expected_server=str(candidate["server"]),
            broker_symbols=candidate["broker_symbols_observed"],
            captured_at=utc_now(),
            signing_key=signing_key,
        )
        destination = write_discovery_exclusive(args.output, receipt)
        print(f"Read-only discovery written: {destination}")
        print(f"SHA-256: {receipt['payload_sha256']}")
        return 0
    finally:
        mt5.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
