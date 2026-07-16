"""Deterministic bootstrap for the XM diagnostic forward-evidence contract."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Callable, Mapping

import pandas as pd

from validation_evidence import (
    DEVELOPMENT_SOURCES,
    REQUIRED_SYMBOLS,
    canonical_evidence_payload_sha256,
    create_frozen_snapshot,
    register_forward_contract,
    verify_frozen_snapshot,
)

from .contracts import canonical_sha256
from .evidence_credentials import signing_key_fingerprint


SNAPSHOT_ID = "xm-dev-pre-window-01-v2"
CONTRACT_ID = "xm-window-01-diagnostic-v2"
KEY_NAME = "xm-window-01-v2"
EXPORTER_VERSION = "mt5-evidence-exporter-v2"
DATA_FILES = {symbol: f"data/{symbol.lower()}.csv" for symbol in REQUIRED_SYMBOLS}
CONFIG_FILES = (
    "config/broker_candidates.phase3.json",
    "config/xm_calendar_window_01.json",
)
DEPENDENCY_FILES = ("requirements.txt", "requirements-live-windows.txt")
PROFILE_FILES = (
    "strategy/strategy_profiles.py",
    "strategy/strategy_selector.py",
    "live_runtime/decision_core.py",
)


class EvidenceBootstrapError(RuntimeError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _read_json(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceBootstrapError(f"invalid JSON artifact: {path}") from exc
    if not isinstance(payload, dict):
        raise EvidenceBootstrapError(f"JSON artifact must be an object: {path}")
    return payload


def _file_set_sha256(repo_root: Path, paths: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    for relative in sorted(paths):
        path = repo_root / relative
        if not path.is_file() or path.is_symlink():
            raise EvidenceBootstrapError(f"required build file is unavailable: {relative}")
        encoded_name = relative.encode("utf-8")
        content = path.read_bytes()
        digest.update(len(encoded_name).to_bytes(4, "big"))
        digest.update(encoded_name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _git_identity(repo_root: Path) -> dict[str, object]:
    def run(*args: str) -> str:
        try:
            return subprocess.run(
                ("git", *args),
                cwd=repo_root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            raise EvidenceBootstrapError("Git build identity is unavailable") from exc

    return {
        "clean": not bool(run("status", "--porcelain")),
        "commit_sha": run("rev-parse", "HEAD"),
        "tree_sha": run("rev-parse", "HEAD^{tree}"),
        "repo_root": run("rev-parse", "--show-toplevel"),
    }


def build_ruleset(repo_root: str | Path) -> dict[str, object]:
    root = Path(repo_root).resolve()
    profile_files_sha256 = _file_set_sha256(root, PROFILE_FILES)
    return {
        "config_sha256": _file_set_sha256(root, CONFIG_FILES),
        "dependency_lock_sha256": _file_set_sha256(root, DEPENDENCY_FILES),
        "strategy_rule_version": "strategy-selector-profiles-v1",
        "indicator_contract_version": "ta-indicators-contract-v1",
        "replay_execution_version": "next-open-stop-first-cost-aware-v1",
        "per_symbol_profile_sha256": {
            symbol: canonical_sha256(
                {
                    "symbol": symbol,
                    "profile_files_sha256": profile_files_sha256,
                }
            )
            for symbol in REQUIRED_SYMBOLS
        },
    }


def build_current_identity(repo_root: str | Path) -> dict[str, object]:
    git = _git_identity(Path(repo_root).resolve())
    if git["clean"] is not True:
        raise EvidenceBootstrapError("Git worktree must remain clean during evidence capture")
    return {
        **build_ruleset(repo_root),
        "git_commit_sha": git["commit_sha"],
        "git_tree_sha": git["tree_sha"],
    }


def verify_discovery_receipt(payload: Mapping[str, object]) -> None:
    body = {key: value for key, value in payload.items() if key != "payload_sha256"}
    if canonical_sha256(body) != payload.get("payload_sha256"):
        raise EvidenceBootstrapError("discovery receipt SHA-256 mismatch")
    if (
        payload.get("execution_enabled") is not False
        or payload.get("live_allowed") is not False
        or payload.get("safe_to_demo_auto_order") is not False
        or payload.get("max_lot") != 0.01
    ):
        raise EvidenceBootstrapError("discovery receipt is not read-only")


def verify_calendar_bundle(payload: Mapping[str, object]) -> None:
    body = {key: value for key, value in payload.items() if key != "bundle_sha256"}
    if canonical_evidence_payload_sha256(body) != payload.get("bundle_sha256"):
        raise EvidenceBootstrapError("calendar bundle SHA-256 mismatch")
    if (
        payload.get("execution_enabled") is not False
        or payload.get("live_allowed") is not False
        or payload.get("safe_to_demo_auto_order") is not False
        or payload.get("max_lot") != 0.01
    ):
        raise EvidenceBootstrapError("calendar bundle is not read-only")
    calendars = payload.get("calendars")
    hashes = payload.get("session_calendar_sha256")
    if not isinstance(calendars, Mapping) or not isinstance(hashes, Mapping):
        raise EvidenceBootstrapError("calendar bundle is incomplete")
    if set(calendars) != set(REQUIRED_SYMBOLS) or set(hashes) != set(REQUIRED_SYMBOLS):
        raise EvidenceBootstrapError("calendar bundle symbol set is incomplete")
    for symbol in REQUIRED_SYMBOLS:
        if canonical_evidence_payload_sha256(calendars[symbol]) != hashes[symbol]:
            raise EvidenceBootstrapError(f"calendar hash mismatch: {symbol}")


def _snapshot_inputs(repo_root: Path) -> tuple[dict, dict, dict]:
    frames: dict[str, pd.DataFrame] = {}
    boundaries: dict[str, dict[str, object]] = {}
    for symbol, relative in DATA_FILES.items():
        path = repo_root / relative
        try:
            frame = pd.read_csv(path)
        except (OSError, pd.errors.ParserError) as exc:
            raise EvidenceBootstrapError(f"development CSV unavailable: {relative}") from exc
        if "Datetime" not in frame or len(frame) < 2:
            raise EvidenceBootstrapError(f"development CSV has insufficient rows: {relative}")
        timestamps = pd.to_datetime(frame["Datetime"], errors="raise", utc=True)
        ordered = timestamps.sort_values(kind="mergesort").reset_index(drop=True)
        frames[symbol] = frame
        boundaries[symbol] = {
            "development_end_at_utc": ordered.iloc[-2],
            "seen_legacy_end_at_utc": ordered.iloc[-1],
        }
    return frames, dict(DEVELOPMENT_SOURCES), boundaries


def ensure_frozen_snapshot(
    repo_root: str | Path,
    artifact_root: str | Path,
    *,
    created_at: datetime,
) -> dict[str, object]:
    verification = verify_frozen_snapshot(artifact_root, SNAPSHOT_ID)
    if verification["valid"]:
        return verification["manifest"]
    snapshot_path = Path(artifact_root) / "snapshots" / SNAPSHOT_ID
    if snapshot_path.exists() or snapshot_path.is_symlink():
        raise EvidenceBootstrapError("existing frozen snapshot failed verification")
    frames, sources, boundaries = _snapshot_inputs(Path(repo_root).resolve())
    manifest = create_frozen_snapshot(
        artifact_root,
        frames,
        sources,
        boundaries,
        snapshot_id=SNAPSHOT_ID,
        created_at=created_at,
    )
    if not verify_frozen_snapshot(artifact_root, SNAPSHOT_ID)["valid"]:
        raise EvidenceBootstrapError("new frozen snapshot failed verification")
    return manifest


def _validate_xm_inputs(
    plan: Mapping[str, object],
    discovery: Mapping[str, object],
    calendar: Mapping[str, object],
) -> None:
    verify_discovery_receipt(discovery)
    verify_calendar_bundle(calendar)
    if plan.get("candidate_id") != discovery.get("candidate_id"):
        raise EvidenceBootstrapError("candidate binding mismatch")
    if plan.get("candidate_id") != calendar.get("candidate_id"):
        raise EvidenceBootstrapError("calendar candidate binding mismatch")
    if plan.get("discovery_receipt_sha256") != discovery.get("payload_sha256"):
        raise EvidenceBootstrapError("plan does not bind the discovery receipt")
    if calendar.get("discovery_receipt_sha256") != discovery.get("payload_sha256"):
        raise EvidenceBootstrapError("calendar does not bind the discovery receipt")
    account = discovery.get("account")
    if not isinstance(account, Mapping):
        raise EvidenceBootstrapError("discovery account facts are missing")
    if account.get("server") != plan.get("broker_server"):
        raise EvidenceBootstrapError("XM server binding mismatch")
    if account.get("company") != plan.get("broker_legal_name"):
        raise EvidenceBootstrapError("XM legal-name binding mismatch")
    calendars = calendar["calendars"]
    cohort_ids = {
        calendars[symbol]["metadata"]["source_instance_id"]
        for symbol in REQUIRED_SYMBOLS
    }
    if cohort_ids != {plan.get("source_instance_id")}:
        raise EvidenceBootstrapError("calendar terminal cohort mismatch")


def _broker_sources(
    plan: Mapping[str, object],
    calendar: Mapping[str, object],
    *,
    key_id: str,
) -> dict[str, dict[str, object]]:
    calendars = calendar["calendars"]
    return {
        symbol: {
            "provider_kind": "BROKER_EXPORT",
            "broker_legal_name": plan["broker_legal_name"],
            "broker_server": plan["broker_server"],
            "environment": "DEMO",
            "canonical_symbol": symbol,
            "broker_symbol": calendars[symbol]["metadata"]["broker_symbol"],
            "source_instance_id": plan["source_instance_id"],
            "quote_mode": "FINALIZED_BID_ASK_BARS",
            "exporter_version": EXPORTER_VERSION,
            "exporter_signing_key_id": key_id,
        }
        for symbol in REQUIRED_SYMBOLS
    }


def _instrument_specs(
    discovery: Mapping[str, object],
    calendar: Mapping[str, object],
) -> dict[str, dict[str, object]]:
    identities = {
        "XAUUSD": ("XAU", "USD", "SPOT_METAL_CFD"),
        "EURUSD": ("EUR", "USD", "FOREX_SPOT_CFD"),
        "USDJPY": ("USD", "JPY", "FOREX_SPOT_CFD"),
        "AUDUSD": ("AUD", "USD", "FOREX_SPOT_CFD"),
    }
    symbols = discovery["symbols"]
    margin_mode = int(discovery["account"]["margin_mode"])
    normalized_margin_mode = {0: "RETAIL_NETTING", 1: "EXCHANGE", 2: "RETAIL_HEDGING"}.get(
        margin_mode
    )
    if normalized_margin_mode is None:
        raise EvidenceBootstrapError("unsupported MT5 margin mode")
    result: dict[str, dict[str, object]] = {}
    for symbol in REQUIRED_SYMBOLS:
        facts = symbols[symbol]
        base, quote, kind = identities[symbol]
        result[symbol] = {
            "canonical_symbol": symbol,
            "instrument_kind": kind,
            "base_currency": base,
            "quote_currency": quote,
            "digits": int(facts["digits"]),
            "point": facts["point"],
            "tick_size": facts["trade_tick_size"],
            "contract_size": facts["trade_contract_size"],
            "tick_value": facts["trade_tick_value"],
            "volume_min": facts["volume_min"],
            "volume_max": facts["volume_max"],
            "volume_step": facts["volume_step"],
            "stops_level_points": int(facts["trade_stops_level"]),
            "freeze_level_points": int(facts["trade_freeze_level"]),
            "profit_currency": str(facts["currency_profit"]).upper(),
            "margin_currency": str(facts["currency_margin"]).upper(),
            "margin_mode": normalized_margin_mode,
            "session_calendar_sha256": calendar["session_calendar_sha256"][symbol],
        }
    return result


def register_xm_diagnostic_contract(
    repo_root: str | Path,
    artifact_root: str | Path,
    discovery_path: str | Path,
    calendar_path: str | Path,
    signing_key: bytes,
    *,
    now_provider: Callable[[], datetime] = utc_now,
    git_state_provider: Callable[[], Mapping[str, object]] | None = None,
    clock_provider: Callable[[], object] | None = None,
) -> dict[str, object]:
    root = Path(repo_root).resolve()
    plan = _read_json(root / "config/xm_calendar_window_01.json")
    discovery = _read_json(Path(discovery_path))
    calendar = _read_json(Path(calendar_path))
    _validate_xm_inputs(plan, discovery, calendar)
    snapshot = ensure_frozen_snapshot(
        root,
        artifact_root,
        created_at=now_provider(),
    )
    key_id = "wincred-" + signing_key_fingerprint(signing_key)
    registered_at = now_provider()
    return register_forward_contract(
        artifact_root,
        snapshot,
        build_ruleset(root),
        _broker_sources(plan, calendar, key_id=key_id),
        _instrument_specs(discovery, calendar),
        session_calendars=calendar["calendars"],
        contract_id=CONTRACT_ID,
        registered_at=registered_at,
        observation_start_at=plan["observation_start_at_utc"],
        blind_until=plan["blind_until_utc"],
        validation_profile="DIAGNOSTIC",
        git_state_provider=git_state_provider,
        clock_provider=clock_provider,
        signing_key=signing_key,
    )


__all__ = [
    "CONTRACT_ID",
    "DATA_FILES",
    "EvidenceBootstrapError",
    "EXPORTER_VERSION",
    "KEY_NAME",
    "SNAPSHOT_ID",
    "build_current_identity",
    "build_ruleset",
    "ensure_frozen_snapshot",
    "register_xm_diagnostic_contract",
    "verify_calendar_bundle",
    "verify_discovery_receipt",
]
