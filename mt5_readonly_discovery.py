"""Windows CLI for phase-3 MT5 discovery. It never accepts broker credentials."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from live_runtime.broker_evidence_profile import (
    BrokerEvidenceProfileError,
    load_broker_evidence_profile,
)
from live_runtime.evidence_bootstrap import KEY_NAME
from live_runtime.evidence_credentials import (
    EvidenceCredentialError,
    WindowsEvidenceKeyStore,
)
from live_runtime.mt5_discovery import (
    MT5DiscoveryError,
    discover_mt5_facts,
    utc_now,
    write_discovery_exclusive,
)
from live_runtime.mt5_readonly import ReadOnlyMT5Facade
from live_runtime.secure_files import SecureFileError


REPO_ROOT = Path(__file__).resolve().parent


def _repo_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def _validated_terminal_path(path: Path | None) -> str:
    if path is None:
        raise MT5DiscoveryError("--terminal-path is required for evidence discovery")
    if not path.is_absolute():
        raise MT5DiscoveryError("terminal path must be absolute")
    if path.is_symlink() or not path.is_file():
        raise MT5DiscoveryError("terminal path must be a regular file")
    if path.name.lower() != "terminal64.exe":
        raise MT5DiscoveryError("terminal path must identify terminal64.exe")
    try:
        return str(path.resolve(strict=True))
    except OSError as exc:
        raise MT5DiscoveryError("terminal path cannot be resolved") from exc


def _candidate(path: Path, candidate_id: str) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise MT5DiscoveryError("candidate configuration must be a regular file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MT5DiscoveryError("candidate configuration is invalid") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("candidates"), list):
        raise MT5DiscoveryError("candidate configuration is incomplete")
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
        raise MT5DiscoveryError("candidate lane symbol map is incomplete")
    return candidate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only MT5 fact discovery")
    parser.add_argument("--candidate", default="xm")
    parser.add_argument(
        "--config", type=Path, default=Path("config/broker_candidates.phase3.json")
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--terminal-path", type=Path)
    parser.add_argument(
        "--profile-config",
        type=Path,
        default=Path("config/broker_evidence_profiles.v1.json"),
    )
    args = parser.parse_args(argv)
    try:
        candidate = _candidate(_repo_path(args.config), args.candidate)
        key_name = KEY_NAME
        if args.candidate != "xm":
            key_name = load_broker_evidence_profile(
                _repo_path(args.profile_config),
                args.candidate,
            ).key_name
        signing_key = WindowsEvidenceKeyStore().load(key_name)
        terminal_path = _validated_terminal_path(args.terminal_path)
    except (
        BrokerEvidenceProfileError,
        EvidenceCredentialError,
        MT5DiscoveryError,
    ) as exc:
        print("MT5_DISCOVERY_GATE_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        return 2

    import MetaTrader5 as mt5  # Windows-only dependency, intentionally late

    if not mt5.initialize(terminal_path):
        print(f"MT5_DISCOVERY_FAILED: initialize failed: {mt5.last_error()}")
        print("Safety lock remains active; no broker order was submitted.")
        return 2
    try:
        try:
            receipt = discover_mt5_facts(
                ReadOnlyMT5Facade(mt5),
                candidate_id=args.candidate,
                expected_server=str(candidate["server"]),
                broker_symbols=candidate["broker_symbols_observed"],
                captured_at=utc_now(),
                signing_key=signing_key,
            )
            destination = write_discovery_exclusive(
                _repo_path(args.output),
                receipt,
            )
        except (
            MT5DiscoveryError,
            OSError,
            SecureFileError,
            TypeError,
            ValueError,
        ) as exc:
            print("MT5_DISCOVERY_FAILED: " + str(exc))
            print("Safety lock remains active; no broker order was submitted.")
            return 2
        print(f"Read-only discovery written: {destination}")
        print(f"SHA-256: {receipt['payload_sha256']}")
        return 0
    finally:
        mt5.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
