from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys
from typing import Any

from live_runtime.windows_provider_primitives import _WindowsNativeCredentialBackend
from live_runtime.windows_ed25519_trusted_clock import (
    ed25519_public_key_sha256,
    normalize_ed25519_public_key,
)
from live_runtime.windows_trusted_utc_continuity_acceptance import (
    acceptance_public_key_sha256,
    normalize_openssh_ed25519_public_key,
)


SCHEMA_VERSION = "finex-windows-decision-input-preparation-v1"
PACK_SCHEMA_VERSION = "windows-decision-provider-pack-input-v1"
PACK_SCHEMA_VERSION_V2 = "windows-decision-provider-pack-input-v2"
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
V2_KEY_TARGETS = {
    key_id: target
    for key_id, target in KEY_TARGETS.items()
    if key_id not in {
        "finex-trusted-clock-v1",
        "finex-downstream-permit-v1",
    }
}
V2_KEY_TARGETS["finex-trusted-clock-continuity-v1"] = (
    f"{TARGET_PREFIX}/finex-trusted-clock-continuity-v1"
)
V2_DECISION_KEY_IDS = tuple(V2_KEY_TARGETS)
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


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)


def _root_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
    )


def _created_file_identity(
    metadata: os.stat_result,
    payload: bytes,
) -> tuple[int, int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(getattr(metadata, "st_file_attributes", 0)),
        int.from_bytes(hashlib.sha256(payload).digest(), "big"),
    )


def _remove_created_file(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        observed = path.lstat()
        if (
            stat.S_ISREG(observed.st_mode)
            and not stat.S_ISLNK(observed.st_mode)
            and not _is_reparse(observed)
            and (int(observed.st_dev), int(observed.st_ino)) == identity
        ):
            path.unlink()
    except OSError:
        pass


def _write_exclusive(path: Path, payload: bytes) -> tuple[int, ...]:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    physical_identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            created = os.fstat(descriptor)
            physical_identity = (int(created.st_dev), int(created.st_ino))
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.close(descriptor)
        descriptor = None
        completed = path.lstat()
        if (
            physical_identity
            != (int(completed.st_dev), int(completed.st_ino))
            or not stat.S_ISREG(completed.st_mode)
            or stat.S_ISLNK(completed.st_mode)
            or _is_reparse(completed)
        ):
            _remove_created_file(path, physical_identity)
            raise PreparationError("OUTPUT_FILE_IDENTITY_INVALID")
        return _created_file_identity(completed, payload)
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        _remove_created_file(path, physical_identity)
        raise


def _remove_if_unchanged(path: Path, identity: tuple[int, ...]) -> None:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or _is_reparse(before)
            or int(before.st_size) != int(identity[3])
        ):
            return
        payload = path.read_bytes()
        after = path.lstat()
        if (
            _created_file_identity(before, payload) == identity
            and _created_file_identity(after, payload) == identity
        ):
            path.unlink()
    except OSError:
        pass


def _cleanup_output(
    root: Path,
    identity: tuple[int, int, int],
    created: list[tuple[Path, tuple[int, ...]]],
) -> None:
    try:
        observed = root.lstat()
    except OSError:
        return
    if (
        _root_identity(observed) != identity
        or not stat.S_ISDIR(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or _is_reparse(observed)
    ):
        return
    for path, file_identity in reversed(created):
        _remove_if_unchanged(path, file_identity)
    try:
        root.rmdir()
    except OSError:
        pass


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


def _ensure_credentials(
    key_targets: dict[str, str] | None = None,
) -> dict[str, str]:
    targets = KEY_TARGETS if key_targets is None else key_targets
    backend = _WindowsNativeCredentialBackend()
    fingerprints: dict[str, str] = {}
    for key_id, target_name in targets.items():
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

    provider_schema = getattr(args, "provider_schema", "v2")
    if provider_schema not in {"v1", "v2"}:
        raise PreparationError("PROVIDER_SCHEMA_INVALID")
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
    if provider_schema == "v2":
        supplied_public_key = getattr(args, "clock_authority_public_key", None)
        source_host = getattr(args, "clock_source_host_identity_sha256", None)
        consumer_host = getattr(args, "clock_consumer_host_identity_sha256", None)
        supplied_executable = getattr(args, "ssh_keygen_path", None)
        supplied_executable_hash = getattr(args, "ssh_keygen_sha256", None)
        supplied_permit_fingerprint = getattr(
            args,
            "downstream_permit_key_fingerprint_sha256",
            None,
        )
        acceptance_public_path_raw = getattr(
            args, "continuity_acceptance_public_key_path", None
        )
        acceptance_public_file_hash = getattr(
            args, "continuity_acceptance_public_key_file_sha256", None
        )
        acceptance_public_pin = getattr(
            args, "continuity_acceptance_public_key_sha256", None
        )
        try:
            public_key = normalize_ed25519_public_key(supplied_public_key)
        except (TypeError, ValueError) as exc:
            raise PreparationError("CLOCK_PUBLIC_KEY_INVALID") from exc
        for label, value in (
            ("CLOCK_SOURCE_HOST_IDENTITY_INVALID", source_host),
            ("CLOCK_CONSUMER_HOST_IDENTITY_INVALID", consumer_host),
            ("SSH_KEYGEN_SHA256_INVALID", supplied_executable_hash),
            (
                "CONTINUITY_ACCEPTANCE_PUBLIC_KEY_FILE_SHA256_INVALID",
                acceptance_public_file_hash,
            ),
            (
                "CONTINUITY_ACCEPTANCE_PUBLIC_KEY_SHA256_INVALID",
                acceptance_public_pin,
            ),
            (
                "DOWNSTREAM_PERMIT_KEY_FINGERPRINT_INVALID",
                supplied_permit_fingerprint,
            ),
        ):
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(item not in "0123456789abcdef" for item in value)
            ):
                raise PreparationError(label)
        if not isinstance(supplied_executable, str):
            raise PreparationError("SSH_KEYGEN_PATH_INVALID")
        ssh_keygen = Path(supplied_executable)
        if not ssh_keygen.is_absolute():
            raise PreparationError("SSH_KEYGEN_PATH_INVALID")
        try:
            ssh_keygen = ssh_keygen.resolve(strict=True)
        except OSError as exc:
            raise PreparationError("SSH_KEYGEN_PATH_INVALID") from exc
        if (
            not ssh_keygen.is_file()
            or _sha256_file(ssh_keygen) != supplied_executable_hash
        ):
            raise PreparationError("SSH_KEYGEN_IDENTITY_MISMATCH")
        if not isinstance(acceptance_public_path_raw, str):
            raise PreparationError("CONTINUITY_ACCEPTANCE_PUBLIC_KEY_PATH_INVALID")
        acceptance_public_path = Path(acceptance_public_path_raw)
        if not acceptance_public_path.is_absolute():
            raise PreparationError("CONTINUITY_ACCEPTANCE_PUBLIC_KEY_PATH_INVALID")
        try:
            acceptance_public_path = acceptance_public_path.resolve(strict=True)
            acceptance_public_bytes = acceptance_public_path.read_bytes()
            acceptance_public_key = normalize_openssh_ed25519_public_key(
                acceptance_public_bytes.decode("ascii", errors="strict")
            )
        except (OSError, UnicodeError, TypeError, ValueError) as exc:
            raise PreparationError(
                "CONTINUITY_ACCEPTANCE_PUBLIC_KEY_PATH_INVALID"
            ) from exc
        if (
            _sha256_bytes(acceptance_public_bytes) != acceptance_public_file_hash
            or acceptance_public_key_sha256(acceptance_public_key)
            != acceptance_public_pin
        ):
            raise PreparationError(
                "CONTINUITY_ACCEPTANCE_PUBLIC_KEY_IDENTITY_MISMATCH"
            )
        key_targets = V2_KEY_TARGETS
        decision_key_ids = V2_DECISION_KEY_IDS
    else:
        public_key = None
        source_host = None
        consumer_host = None
        ssh_keygen = None
        supplied_executable_hash = None
        supplied_permit_fingerprint = None
        acceptance_public_path = None
        acceptance_public_file_hash = None
        acceptance_public_pin = None
        key_targets = KEY_TARGETS
        decision_key_ids = DECISION_KEY_IDS
    fingerprints = _ensure_credentials(key_targets)
    permit_fingerprint = (
        supplied_permit_fingerprint
        if provider_schema == "v2"
        else fingerprints["finex-downstream-permit-v1"]
    )

    directories = {
        "feed": state_root / "feed",
        "ipc_requests": state_root / "ipc-requests",
        "ipc_responses": state_root / "ipc-responses",
        "cursor_requests": state_root / "cursor-requests",
        "cursor_responses": state_root / "cursor-responses",
    }
    if provider_schema == "v2":
        directories.update(
            {
                "clock_requests": state_root / "clock-continuity-requests",
                "clock_responses": state_root / "clock-continuity-responses",
            }
        )
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
        ] if provider_schema == "v1" else permit_fingerprint,
        "schema_version": "decision-ipc-binding-v2",
    }
    if provider_schema == "v2":
        clock_binding = {
            "provider_id": "finex-decision-ed25519-clock-v1",
            "source_host_identity_sha256": source_host,
            "consumer_host_identity_sha256": consumer_host,
            "authority_issuer_id": "finex-offhost-clock-authority-v1",
            "signer_identity": "finex-offhost-clock-signer-v1",
            "authority_public_key": public_key,
            "authority_public_key_sha256": ed25519_public_key_sha256(public_key),
            "ssh_keygen_path": str(ssh_keygen),
            "ssh_keygen_sha256": supplied_executable_hash,
            "maximum_attestation_age_ms": 10000,
            "maximum_delivery_delay_ms": 3000,
            "maximum_bootstrap_drift_ms": 1000,
            "sshsig_namespace": "ai-scalper-finex-trusted-utc-v1",
            "trust_scope": "TRUSTED_UTC_ONLY",
            "schema_version": "windows-ed25519-trusted-utc-binding-v1",
        }
        clock_binding_sha256 = _sha256_bytes(_canonical_bytes(clock_binding)[:-1])
        clock_continuity_binding = {
            "provider_id": "finex-clock-continuity-directory-cas-v1",
            "clock_binding_sha256": clock_binding_sha256,
            "custody_issuer_id": "finex-clock-continuity-custody-v1",
            "custody_key_id": "finex-trusted-clock-continuity-v1",
            "custody_key_fingerprint_sha256": fingerprints[
                "finex-trusted-clock-continuity-v1"
            ],
            "schema_version": "windows-trusted-utc-continuity-cas-binding-v1",
        }
        clock_continuity_acceptance_binding = {
            "provider_id": clock_continuity_binding["provider_id"],
            "clock_binding_sha256": clock_binding_sha256,
            "source_host_identity_sha256": source_host,
            "consumer_host_identity_sha256": consumer_host,
            "custody_issuer_id": "finex-clock-continuity-acceptance-v1",
            "custody_key_id": "finex-clock-continuity-acceptance-key-v1",
            "custody_public_key_sha256": acceptance_public_pin,
            "public_key_file_sha256": acceptance_public_file_hash,
            "sshsig_namespace": (
                "ai-scalper-finex-trusted-utc-continuity-acceptance-v1"
            ),
            "response_schema_version": (
                "external-cas-response-v1+ed25519-acceptance-v1"
            ),
            "schema_version": (
                "windows-trusted-utc-continuity-acceptance-binding-v1"
            ),
        }
    else:
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
        clock_continuity_binding = None
        clock_continuity_acceptance_binding = None
    references = [
        {
            "key_id": key_id,
            "target_name": key_targets[key_id],
            "fingerprint_sha256": fingerprints[key_id],
        }
        for key_id in sorted(decision_key_ids)
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
        "pack_id": (
            "finex-decision-provider-pack-v9"
            if provider_schema == "v2"
            else "finex-decision-provider-pack-v1"
        ),
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
        "schema_version": (
            PACK_SCHEMA_VERSION_V2
            if provider_schema == "v2"
            else PACK_SCHEMA_VERSION
        ),
        "storage": {
            "clock_attestation_path": str(state_root / "clock-attestation.json"),
            "decision_ipc_database": str(state_root / "decision-ipc.sqlite3"),
            "finalized_m15_directory": str(directories["feed"]),
            "producer_cursor_database": str(state_root / "producer-cursor.sqlite3"),
        },
    }
    if provider_schema == "v2":
        pack_input["clock_continuity_binding"] = clock_continuity_binding
        pack_input["clock_continuity_acceptance_binding"] = (
            clock_continuity_acceptance_binding
        )
        pack_input["external_cas"]["clock"] = {
            "provider_id": clock_continuity_binding["provider_id"],
            "request_directory": str(directories["clock_requests"]),
            "response_directory": str(directories["clock_responses"]),
        }
        pack_input["storage"]["clock_attestation_path"] = str(
            state_root / "clock-envelope.json"
        )
        pack_input["storage"][
            "clock_continuity_acceptance_public_key_path"
        ] = str(acceptance_public_path)
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
            "SIGNED_ED25519_CLOCK_ENVELOPE_REQUIRED"
            if provider_schema == "v2"
            else "SIGNED_CLOCK_ATTESTATION_REQUIRED",
            "EXTERNAL_CLOCK_CONTINUITY_CUSTODY_ACCEPTANCE_REQUIRED"
            if provider_schema == "v2"
            else "CLOCK_AUTHORITY_CREDENTIAL_REQUIRED",
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
    output_identity = _root_identity(output_root.lstat())
    created_files: list[tuple[Path, tuple[int, ...]]] = []
    try:
        for name, payload in (
            ("finex-finalized-m15-data-contract.json", data_contract_bytes),
            ("decision-provider-pack-input.json", _canonical_bytes(pack_input)),
            ("FINEX_DECISION_INPUT_PREPARATION.json", _canonical_bytes(receipt)),
        ):
            path = output_root / name
            created_files.append((path, _write_exclusive(path, payload)))
    except BaseException:
        _cleanup_output(output_root, output_identity, created_files)
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
    parser.add_argument("--provider-schema", choices=("v1", "v2"), default="v2")
    parser.add_argument("--clock-authority-public-key")
    parser.add_argument("--clock-source-host-identity-sha256")
    parser.add_argument("--clock-consumer-host-identity-sha256")
    parser.add_argument("--ssh-keygen-path")
    parser.add_argument("--ssh-keygen-sha256")
    parser.add_argument("--downstream-permit-key-fingerprint-sha256")
    parser.add_argument("--continuity-acceptance-public-key-path")
    parser.add_argument("--continuity-acceptance-public-key-file-sha256")
    parser.add_argument("--continuity-acceptance-public-key-sha256")
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
