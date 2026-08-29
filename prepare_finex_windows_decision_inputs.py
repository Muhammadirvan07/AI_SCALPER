from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
from typing import Any

from live_runtime.windows_provider_primitives import _WindowsNativeCredentialBackend


SCHEMA_VERSION = "finex-windows-decision-input-preparation-v1"
PACK_SCHEMA_VERSION = "windows-decision-provider-pack-input-v1"
TARGET_PREFIX = "AI_SCALPER/FINEX/DECISION"
EXECUTION_TARGET_PREFIX = "AI_SCALPER/FINEX/EXECUTION"
KEY_TARGETS = {
    "finex-decision-signing-v1": f"{TARGET_PREFIX}/finex-decision-signing-v1",
    "finex-decision-ipc-custody-v1": f"{TARGET_PREFIX}/finex-decision-ipc-custody-v1",
    "finex-decision-cursor-v1": f"{TARGET_PREFIX}/finex-decision-cursor-v1",
    "finex-decision-feed-v1": f"{TARGET_PREFIX}/finex-decision-feed-v1",
    "finex-session-calendar-v1": f"{TARGET_PREFIX}/finex-session-calendar-v1",
    "finex-trusted-clock-v1": f"{TARGET_PREFIX}/finex-trusted-clock-v1",
    "finex-downstream-permit-v1": (
        f"{EXECUTION_TARGET_PREFIX}/finex-downstream-permit-v1"
    ),
}
DECISION_KEY_IDS = tuple(KEY_TARGETS)[:-1]
REQUIRED_SYMBOLS = ("AUDUSD", "EURUSD", "USDJPY", "XAUUSD")


class PreparationError(RuntimeError):
    pass


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _load_json(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise PreparationError(f"JSON_OBJECT_REQUIRED:{path}")
    return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _write_exclusive(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


class _CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", wintypes.LPVOID),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


def _write_windows_credential(target_name: str, secret: bytes) -> None:
    if sys.platform != "win32":
        raise PreparationError("WINDOWS_CREDENTIAL_MANAGER_REQUIRED")
    if len(secret) != 32:
        raise PreparationError("CREDENTIAL_SECRET_LENGTH_INVALID")
    blob = (ctypes.c_ubyte * len(secret)).from_buffer_copy(secret)
    credential = _CREDENTIALW(
        Flags=0,
        Type=1,
        TargetName=target_name,
        Comment="AI_SCALPER FINEX deny-only provider key",
        CredentialBlobSize=len(secret),
        CredentialBlob=ctypes.cast(blob, ctypes.POINTER(ctypes.c_ubyte)),
        Persist=2,
        AttributeCount=0,
        Attributes=None,
        TargetAlias=None,
        UserName="AI_SCALPER",
    )
    advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    cred_write = advapi32.CredWriteW
    cred_write.argtypes = [ctypes.POINTER(_CREDENTIALW), wintypes.DWORD]
    cred_write.restype = wintypes.BOOL
    if not cred_write(ctypes.byref(credential), 0):
        raise ctypes.WinError(ctypes.get_last_error())


def _ensure_credentials() -> dict[str, str]:
    backend = _WindowsNativeCredentialBackend()
    fingerprints: dict[str, str] = {}
    for key_id, target_name in KEY_TARGETS.items():
        secret = backend.read_blob(target_name)
        if secret is None:
            _write_windows_credential(target_name, secrets.token_bytes(32))
            secret = backend.read_blob(target_name)
        if secret is None or len(secret) != 32:
            raise PreparationError(f"CREDENTIAL_READBACK_INVALID:{key_id}")
        fingerprints[key_id] = _sha256_bytes(secret)
    return fingerprints


def _machine_identity_sha256() -> str:
    computer = os.environ.get("COMPUTERNAME", "").strip().lower()
    if not computer:
        raise PreparationError("COMPUTER_IDENTITY_UNAVAILABLE")
    return _sha256_bytes(("windows-host-v1:" + computer).encode("utf-8"))


def _prepare(args: argparse.Namespace) -> dict[str, Any]:
    repo = Path(args.repo_root).resolve(strict=True)
    discovery_path = Path(args.discovery).resolve(strict=True)
    suite_manifest_path = Path(args.base_suite_manifest).resolve(strict=True)
    state_root = Path(args.state_root).resolve()
    output_root = Path(args.output_root).resolve()
    if output_root.exists():
        raise PreparationError("OUTPUT_ROOT_ALREADY_EXISTS")

    discovery = _load_json(discovery_path)
    suite = _load_json(suite_manifest_path)
    account = discovery.get("account")
    symbols = discovery.get("symbols")
    if not isinstance(account, dict) or not isinstance(symbols, dict):
        raise PreparationError("DISCOVERY_CONTRACT_INVALID")
    if (
        discovery.get("candidate_id") != "finex"
        or account.get("environment") != "DEMO"
        or account.get("server") != "FinexBisnisSolusi-Demo"
        or any(symbol not in symbols for symbol in REQUIRED_SYMBOLS)
    ):
        raise PreparationError("FINEX_DISCOVERY_BINDING_INVALID")
    account_identity = account.get("account_identity_sha256")
    if not isinstance(account_identity, str) or len(account_identity) != 64:
        raise PreparationError("ACCOUNT_IDENTITY_INVALID")

    git_commit = suite.get("git_commit")
    git_tree = suite.get("git_tree")
    suite_identity = suite.get("suite_identity_sha256")
    if not all(
        isinstance(item, str) and len(item) in (40, 64)
        for item in (git_commit, git_tree, suite_identity)
    ):
        raise PreparationError("BASE_SUITE_IDENTITY_INVALID")

    schedule_path = repo / "config/finex_trading_rules_schedule.v1.json"
    strategy_path = repo / "strategy/strategy_selector.py"
    readiness_path = repo / "config/finex_demo_auto_readiness.v1.json"
    calendar_hash = _sha256_file(schedule_path)
    model_hash = _sha256_file(strategy_path)
    config_hash = _sha256_file(readiness_path)
    discovery_hash = _sha256_file(discovery_path)
    data_contract = {
        "schema_version": "finex-finalized-m15-data-contract-v1",
        "candidate_id": "finex",
        "environment": "DEMO",
        "broker_server": account["server"],
        "broker_account_identity_sha256": account_identity,
        "discovery_document_sha256": discovery_hash,
        "symbols": list(REQUIRED_SYMBOLS),
        "timeframe": "M15",
        "finalized_candles_only": True,
        "signed_append_only_required": True,
        "execution_enabled": False,
        "order_capability": "DISABLED",
    }
    data_contract_bytes = _canonical_bytes(data_contract)
    data_contract_hash = _sha256_bytes(data_contract_bytes)
    fingerprints = _ensure_credentials()

    directories = {
        "feed": state_root / "feed",
        "ipc_requests": state_root / "ipc-requests",
        "ipc_responses": state_root / "ipc-responses",
        "cursor_requests": state_root / "cursor-requests",
        "cursor_responses": state_root / "cursor-responses",
    }
    state_root.mkdir(parents=True, exist_ok=True)
    for directory in directories.values():
        directory.mkdir(parents=True, exist_ok=True)

    lanes = []
    feed_lanes = []
    for symbol in REQUIRED_SYMBOLS:
        lane_id = f"finex-{symbol.lower()}-m15-primary"
        lanes.append(
            {
                "lane_id": lane_id,
                "symbol": symbol,
                "source_name": "finex-signed-finalized-m15-feed",
                "data_contract_sha256": data_contract_hash,
                "model_version": "deterministic-strategy-selector-v1",
                "model_artifact_sha256": model_hash,
                "commit_sha": git_commit,
                "config_sha256": config_hash,
                "session_calendar_sha256": calendar_hash,
                "session_calendar_issuer_id": "finex-calendar-monitor-v1",
                "session_calendar_key_id": "finex-session-calendar-v1",
                "session_calendar_key_fingerprint_sha256": fingerprints[
                    "finex-session-calendar-v1"
                ],
                "maximum_processing_lag_ms": 1000,
                "timeframe": "M15",
            }
        )
        feed_lanes.append(
            {
                "lane_id": lane_id,
                "symbol": symbol,
                "broker_symbol": symbol,
                "source_name": "finex-signed-finalized-m15-feed",
                "data_contract_sha256": data_contract_hash,
                "session_calendar_sha256": calendar_hash,
            }
        )

    producer_binding = {
        "service_id": "finex-decision-service-v1",
        "lanes": lanes,
        "custody_issuer_id": "finex-decision-cursor-custody-v1",
        "custody_key_id": "finex-decision-cursor-v1",
        "custody_key_fingerprint_sha256": fingerprints[
            "finex-decision-cursor-v1"
        ],
        "schema_version": "brokerless-decision-producer-binding-v2",
    }
    feed_binding = {
        "feed_id": "finex-decision-feed-v1",
        "broker_server": account["server"],
        "broker_account_identity_sha256": account_identity,
        "publisher_issuer_id": "finex-decision-feed-publisher-v1",
        "publisher_key_id": "finex-decision-feed-v1",
        "publisher_key_fingerprint_sha256": fingerprints[
            "finex-decision-feed-v1"
        ],
        "lanes": feed_lanes,
        "order_capability": "DISABLED",
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "max_lot": 0.01,
        "schema_version": "signed-decision-feed-binding-v1",
    }
    ipc_binding = {
        "queue_id": "finex-decision-queue-v1",
        "account_id_sha256": account_identity,
        "server": account["server"],
        "environment": "DEMO",
        "journal_sha256": data_contract_hash,
        "commit_sha": git_commit,
        "config_sha256": config_hash,
        "model_artifact_sha256": model_hash,
        "data_contract_sha256": data_contract_hash,
        "decision_issuer_id": producer_binding["service_id"],
        "decision_key_id": "finex-decision-signing-v1",
        "decision_key_fingerprint_sha256": fingerprints[
            "finex-decision-signing-v1"
        ],
        "custody_issuer_id": "finex-decision-ipc-custody-v1",
        "custody_key_id": "finex-decision-ipc-custody-v1",
        "custody_key_fingerprint_sha256": fingerprints[
            "finex-decision-ipc-custody-v1"
        ],
        "permit_key_id": "finex-downstream-permit-v1",
        "permit_key_fingerprint_sha256": fingerprints[
            "finex-downstream-permit-v1"
        ],
        "schema_version": "decision-ipc-binding-v2",
    }
    clock_binding = {
        "provider_id": "finex-decision-clock-v1",
        "host_identity_sha256": _machine_identity_sha256(),
        "authority_issuer_id": "finex-local-clock-authority-v1",
        "authority_key_id": "finex-trusted-clock-v1",
        "authority_key_fingerprint_sha256": fingerprints[
            "finex-trusted-clock-v1"
        ],
        "maximum_attestation_age_ms": 10000,
        "maximum_absolute_drift_ms": 1000,
        "schema_version": "windows-clock-binding-v1",
    }
    references = [
        {
            "key_id": key_id,
            "target_name": KEY_TARGETS[key_id],
            "fingerprint_sha256": fingerprints[key_id],
        }
        for key_id in sorted(DECISION_KEY_IDS)
    ]
    pack_input = {
        "cas_timeout_seconds": 1.0,
        "clock_binding": clock_binding,
        "credential_references": references,
        "credential_target_prefix": TARGET_PREFIX,
        "decision_feed_binding": feed_binding,
        "decision_ipc_binding": ipc_binding,
        "external_cas": {
            "ipc": {
                "provider_id": "finex-decision-ipc-directory-cas-v1",
                "request_directory": str(directories["ipc_requests"]),
                "response_directory": str(directories["ipc_responses"]),
            },
            "producer": {
                "provider_id": "finex-decision-cursor-directory-cas-v1",
                "request_directory": str(directories["cursor_requests"]),
                "response_directory": str(directories["cursor_responses"]),
            },
        },
        "pack_id": "finex-decision-provider-pack-v1",
        "runtime": {
            "cycle_deadline_seconds": 5.0,
            "decision_producer_binding": producer_binding,
            "max_cycles": 10000,
            "poll_seconds": 0.25,
            "service_id": producer_binding["service_id"],
        },
        "safety": {
            "live_allowed": False,
            "max_lot": 0.01,
            "order_capability": "DISABLED",
            "production_execution_ready": False,
            "promotion_eligible": False,
            "safe_to_demo_auto_order": False,
        },
        "schema_version": PACK_SCHEMA_VERSION,
        "storage": {
            "clock_attestation_path": str(state_root / "clock-attestation.json"),
            "decision_ipc_database": str(state_root / "decision-ipc.sqlite3"),
            "finalized_m15_directory": str(directories["feed"]),
            "producer_cursor_database": str(state_root / "producer-cursor.sqlite3"),
        },
    }
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": "finex",
        "base_suite_identity_sha256": suite_identity,
        "git_commit": git_commit,
        "git_tree": git_tree,
        "discovery_document_sha256": discovery_hash,
        "data_contract_sha256": data_contract_hash,
        "calendar_sha256": calendar_hash,
        "model_artifact_sha256": model_hash,
        "config_sha256": config_hash,
        "credential_fingerprints": fingerprints,
        "state_root": str(state_root),
        "status": "PROVIDER_PACK_INPUT_READY_EXTERNAL_CONFORMANCE_REQUIRED",
        "remaining_blockers": [
            "SIGNED_CLOCK_ATTESTATION_REQUIRED",
            "SIGNED_FINALIZED_M15_FEED_REQUIRED",
            "EXTERNAL_CAS_CUSTODY_ACCEPTANCE_REQUIRED",
            "SERVICE_ACCOUNT_AND_ACL_ACCEPTANCE_REQUIRED",
            "REVIEWED_TASK_DEFINITION_REQUIRED",
        ],
        "authorization_granted": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "order_capability": "DISABLED",
    }
    receipt["content_sha256"] = _sha256_bytes(_canonical_bytes(receipt))

    output_root.mkdir(parents=True, exist_ok=False)
    try:
        _write_exclusive(output_root / "finex-finalized-m15-data-contract.json", data_contract_bytes)
        _write_exclusive(output_root / "decision-provider-pack-input.json", _canonical_bytes(pack_input))
        _write_exclusive(output_root / "FINEX_DECISION_INPUT_PREPARATION.json", _canonical_bytes(receipt))
    except BaseException:
        for child in output_root.iterdir():
            child.unlink(missing_ok=True)
        output_root.rmdir()
        raise
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Provision secret-free FINEX Decision provider bindings. No task, "
            "process, MT5, broker, permit, activation, or order effect occurs."
        )
    )
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parent))
    parser.add_argument("--discovery", required=True)
    parser.add_argument("--base-suite-manifest", required=True)
    parser.add_argument("--state-root", required=True)
    parser.add_argument("--output-root", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        result = _prepare(_parser().parse_args(argv))
    except (OSError, ValueError, json.JSONDecodeError, PreparationError) as exc:
        print(f"FINEX_DECISION_INPUT_PREPARATION_BLOCKED:{exc}", file=sys.stderr)
        print("Safety lock remains active; no broker order was submitted.", file=sys.stderr)
        return 2
    print("FINEX_DECISION_INPUT_PREPARATION=READY")
    print(f"Receipt SHA-256: {result['content_sha256']}")
    print(f"Status: {result['status']}")
    print("Secret material: NOT_EXPORTED")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
