"""Deterministic bootstrap for the XM diagnostic forward-evidence contract."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
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
from .broker_evidence_profile import BrokerEvidenceProfile
from .broker_window_plan import (
    BrokerWindowPlanError,
    verify_prepared_broker_calendar_plan,
)
from .account_identity import (
    ACCOUNT_IDENTITY_SCHEME,
    DISCOVERY_RECEIPT_DOMAIN,
    payload_hmac_sha256,
    require_account_identity_sha256,
)
from .dependency_lock import (
    BOOTSTRAP_REQUIREMENTS_FILE,
    DEPENDENCY_SBOM,
    DependencyLockError,
    INSTALL_MANIFEST,
    LOCK_FILE_NAME,
    PIP_VENDOR_WHEEL,
    RUNTIME_REQUIREMENTS_FILE,
    TA_VENDOR_WHEEL,
    validate_windows_dependency_lock,
)
from .evidence_credentials import signing_key_fingerprint
from .mt5_discovery import DISCOVERY_SCHEMA_VERSION
from .session_calendar import SessionCalendarError, build_calendar_bundle
from .xm_window_plan import (
    XMWindowPlanError,
    verify_candidate_legal_binding,
    verify_prepared_xm_calendar_plan,
)


SNAPSHOT_ID = "xm-dev-pre-window-02-v3"
CONTRACT_ID = "xm-window-02-diagnostic-v3"
KEY_NAME = "xm-window-02-v3"
EXPORTER_VERSION = "mt5-evidence-exporter-v3"
DATA_FILES = {symbol: f"data/{symbol.lower()}.csv" for symbol in REQUIRED_SYMBOLS}
CONFIG_FILES = (
    "config/broker_candidates.phase3.json",
    "config/xm_calendar_window_02.template.json",
)
DEPENDENCY_FILES = (
    "requirements-live-windows.txt",
    BOOTSTRAP_REQUIREMENTS_FILE,
    RUNTIME_REQUIREMENTS_FILE,
    LOCK_FILE_NAME,
    PIP_VENDOR_WHEEL,
    TA_VENDOR_WHEEL,
    INSTALL_MANIFEST,
    DEPENDENCY_SBOM,
    "live_runtime/dependency_lock.py",
    "bootstrap_windows_dependencies.py",
    "build_windows_dependency_sbom.py",
    "build_windows_wheel_manifest.py",
    "seal_windows_release_environment.py",
    "verify_windows_dependency_lock.py",
)
PROFILE_FILES = (
    "strategy/strategy_profiles.py",
    "strategy/strategy_selector.py",
    "live_runtime/decision_core.py",
)


class EvidenceBootstrapError(RuntimeError):
    pass


def _required_symbol_subset(
    value: object,
    *,
    field: str,
) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)):
        raise EvidenceBootstrapError(f"{field} symbol set is invalid")
    try:
        requested = tuple(str(symbol).upper() for symbol in value)
    except TypeError as exc:
        raise EvidenceBootstrapError(f"{field} symbol set is invalid") from exc
    if (
        not requested
        or len(set(requested)) != len(requested)
        or not set(requested) <= set(REQUIRED_SYMBOLS)
    ):
        raise EvidenceBootstrapError(f"{field} symbol set is invalid")
    return tuple(symbol for symbol in REQUIRED_SYMBOLS if symbol in requested)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _read_json(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise EvidenceBootstrapError(f"JSON artifact must be a regular file: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceBootstrapError(f"invalid JSON artifact: {path}") from exc
    if not isinstance(payload, dict):
        raise EvidenceBootstrapError(f"JSON artifact must be an object: {path}")
    return payload


def _repository_relative_file(repo_root: Path, value: str | Path) -> str:
    raw = str(value).replace("\\", "/")
    relative = PurePosixPath(raw)
    if (
        not raw
        or relative.is_absolute()
        or "." in relative.parts
        or ".." in relative.parts
        or any(":" in part for part in relative.parts)
    ):
        raise EvidenceBootstrapError("build identity path must be repository-relative")
    candidate = repo_root
    for part in relative.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise EvidenceBootstrapError(
                f"build identity path must not contain symlinks: {relative.as_posix()}"
            )
    if not candidate.is_file():
        raise EvidenceBootstrapError(
            f"required build file is unavailable: {relative.as_posix()}"
        )
    try:
        candidate.resolve(strict=True).relative_to(repo_root)
    except (OSError, ValueError) as exc:
        raise EvidenceBootstrapError(
            f"build identity path escapes the repository: {relative.as_posix()}"
        ) from exc
    return relative.as_posix()


def _file_set_sha256(repo_root: Path, paths: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    normalized = tuple(
        _repository_relative_file(repo_root, relative) for relative in paths
    )
    if len(set(normalized)) != len(normalized):
        raise EvidenceBootstrapError("build identity file set contains duplicates")
    for relative in sorted(normalized):
        path = repo_root / relative
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


def build_ruleset(
    repo_root: str | Path,
    *,
    config_files: tuple[str, ...] = CONFIG_FILES,
) -> dict[str, object]:
    root = Path(repo_root).resolve()
    try:
        validate_windows_dependency_lock(root / LOCK_FILE_NAME)
    except DependencyLockError as exc:
        raise EvidenceBootstrapError("Windows dependency lock validation failed") from exc
    profile_files_sha256 = _file_set_sha256(root, PROFILE_FILES)
    return {
        "config_sha256": _file_set_sha256(root, config_files),
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


def build_current_identity(
    repo_root: str | Path,
    *,
    config_files: tuple[str, ...] = CONFIG_FILES,
) -> dict[str, object]:
    git = _git_identity(Path(repo_root).resolve())
    if git["clean"] is not True:
        raise EvidenceBootstrapError("Git worktree must remain clean during evidence capture")
    return {
        **build_ruleset(repo_root, config_files=config_files),
        "git_commit_sha": git["commit_sha"],
        "git_tree_sha": git["tree_sha"],
    }


def verify_discovery_receipt(
    payload: Mapping[str, object],
    signing_key: bytes,
    *,
    required_symbols: tuple[str, ...] = REQUIRED_SYMBOLS,
) -> None:
    lane_symbols = _required_symbol_subset(
        required_symbols,
        field="discovery",
    )
    expected_fields = {
        "schema_version",
        "candidate_id",
        "captured_at_utc",
        "account",
        "terminal",
        "symbols",
        "session_calendar_status",
        "execution_enabled",
        "live_allowed",
        "safe_to_demo_auto_order",
        "max_lot",
        "payload_sha256",
        "receipt_hmac_sha256",
    }
    if set(payload) != expected_fields:
        raise EvidenceBootstrapError("discovery receipt fields are invalid")
    if payload.get("schema_version") != DISCOVERY_SCHEMA_VERSION:
        raise EvidenceBootstrapError("unsupported discovery receipt schema")
    body = {
        key: value
        for key, value in payload.items()
        if key not in {"payload_sha256", "receipt_hmac_sha256"}
    }
    if canonical_sha256(body) != payload.get("payload_sha256"):
        raise EvidenceBootstrapError("discovery receipt SHA-256 mismatch")
    signed_receipt = {**body, "payload_sha256": payload["payload_sha256"]}
    expected_hmac = payload_hmac_sha256(
        signed_receipt,
        signing_key,
        domain=DISCOVERY_RECEIPT_DOMAIN,
    )
    if not hmac.compare_digest(
        expected_hmac,
        str(payload.get("receipt_hmac_sha256") or ""),
    ):
        raise EvidenceBootstrapError("discovery receipt HMAC mismatch")
    if (
        payload.get("execution_enabled") is not False
        or payload.get("live_allowed") is not False
        or payload.get("safe_to_demo_auto_order") is not False
        or payload.get("max_lot") != 0.01
    ):
        raise EvidenceBootstrapError("discovery receipt is not read-only")
    account = payload.get("account")
    required_account_fields = {
        "company",
        "server",
        "environment",
        "currency",
        "leverage",
        "margin_mode",
        "trade_allowed",
        "trade_expert",
        "account_identity_sha256",
        "account_identity_scheme",
        "account_identity_key_id",
        "login_stored",
        "name_stored",
        "balance_stored",
    }
    if not isinstance(account, Mapping) or set(account) != required_account_fields:
        raise EvidenceBootstrapError("discovery account identity is incomplete")
    if (
        account.get("environment") != "DEMO"
        or account.get("trade_allowed") is not False
        or type(account.get("trade_expert")) is not bool
        or account.get("login_stored") is not False
        or account.get("name_stored") is not False
        or account.get("balance_stored") is not False
        or account.get("account_identity_scheme") != ACCOUNT_IDENTITY_SCHEME
        or account.get("account_identity_key_id")
        != "wincred-" + signing_key_fingerprint(signing_key)
    ):
        raise EvidenceBootstrapError("discovery account identity binding mismatch")
    try:
        require_account_identity_sha256(account.get("account_identity_sha256"))
    except ValueError as exc:
        raise EvidenceBootstrapError("discovery account identity is invalid") from exc
    terminal = payload.get("terminal")
    if (
        not isinstance(terminal, Mapping)
        or set(terminal) != {"trade_allowed", "tradeapi_disabled"}
        or terminal.get("trade_allowed") is not False
        or terminal.get("tradeapi_disabled") is not True
    ):
        raise EvidenceBootstrapError(
            "discovery terminal is not locked against Python order execution"
        )
    symbols = payload.get("symbols")
    if not isinstance(symbols, Mapping) or set(symbols) != set(lane_symbols):
        raise EvidenceBootstrapError("discovery symbol set does not match the lane")

    def contains_raw_account_field(value: object) -> bool:
        if isinstance(value, Mapping):
            for key, item in value.items():
                normalized = str(key).lower()
                if normalized in {
                    "login",
                    "account_number",
                    "password",
                    "balance",
                    "equity",
                }:
                    return True
                if contains_raw_account_field(item):
                    return True
        elif isinstance(value, (list, tuple)):
            return any(contains_raw_account_field(item) for item in value)
        return False

    if contains_raw_account_field(payload):
        raise EvidenceBootstrapError("discovery receipt contains raw account data")


def verify_calendar_bundle(
    payload: Mapping[str, object],
    *,
    required_symbols: tuple[str, ...] = REQUIRED_SYMBOLS,
) -> None:
    lane_symbols = _required_symbol_subset(required_symbols, field="calendar")
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
    if set(calendars) != set(lane_symbols) or set(hashes) != set(lane_symbols):
        raise EvidenceBootstrapError("calendar bundle symbol set does not match the lane")
    for symbol in lane_symbols:
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
        frame = frame.copy()
        frame["Datetime"] = timestamps
        frames[symbol] = frame
        boundaries[symbol] = {
            "development_end_at_utc": timestamps.iloc[-2],
            "seen_legacy_end_at_utc": timestamps.iloc[-1],
        }
    return frames, dict(DEVELOPMENT_SOURCES), boundaries


def ensure_frozen_snapshot(
    repo_root: str | Path,
    artifact_root: str | Path,
    *,
    created_at: datetime,
    snapshot_id: str = SNAPSHOT_ID,
) -> dict[str, object]:
    verification = verify_frozen_snapshot(artifact_root, snapshot_id)
    if verification["valid"]:
        return verification["manifest"]
    snapshot_path = Path(artifact_root) / "snapshots" / snapshot_id
    if snapshot_path.exists() or snapshot_path.is_symlink():
        raise EvidenceBootstrapError("existing frozen snapshot failed verification")
    frames, sources, boundaries = _snapshot_inputs(Path(repo_root).resolve())
    manifest = create_frozen_snapshot(
        artifact_root,
        frames,
        sources,
        boundaries,
        snapshot_id=snapshot_id,
        created_at=created_at,
    )
    if not verify_frozen_snapshot(artifact_root, snapshot_id)["valid"]:
        raise EvidenceBootstrapError("new frozen snapshot failed verification")
    return manifest


def _validate_broker_inputs(
    plan: Mapping[str, object],
    discovery: Mapping[str, object],
    calendar: Mapping[str, object],
    *,
    signing_key: bytes,
) -> None:
    symbols = _required_symbol_subset(
        plan.get("broker_symbols", {}),
        field="plan",
    )
    verify_discovery_receipt(
        discovery,
        signing_key,
        required_symbols=symbols,
    )
    verify_calendar_bundle(calendar, required_symbols=symbols)
    try:
        expected_calendar = build_calendar_bundle(plan)
    except SessionCalendarError as exc:
        raise EvidenceBootstrapError(
            "prepared plan cannot produce a valid calendar"
        ) from exc
    if canonical_evidence_payload_sha256(
        calendar
    ) != canonical_evidence_payload_sha256(expected_calendar):
        raise EvidenceBootstrapError(
            "calendar does not exactly match the prepared plan"
        )
    if plan.get("candidate_id") != discovery.get("candidate_id"):
        raise EvidenceBootstrapError("candidate binding mismatch")
    if plan.get("candidate_id") != calendar.get("candidate_id"):
        raise EvidenceBootstrapError("calendar candidate binding mismatch")
    if plan.get("discovery_receipt_sha256") != discovery.get("payload_sha256"):
        raise EvidenceBootstrapError("plan does not bind the discovery receipt")
    if calendar.get("discovery_receipt_sha256") != discovery.get("payload_sha256"):
        raise EvidenceBootstrapError("calendar does not bind the discovery receipt")
    if calendar.get("plan_payload_sha256") != plan.get("plan_payload_sha256"):
        raise EvidenceBootstrapError("calendar does not bind the prepared plan")
    account = discovery.get("account")
    if not isinstance(account, Mapping):
        raise EvidenceBootstrapError("discovery account facts are missing")
    if account.get("server") != plan.get("broker_server"):
        raise EvidenceBootstrapError("broker server binding mismatch")
    if account.get("company") != plan.get("broker_legal_name"):
        raise EvidenceBootstrapError("broker legal-name binding mismatch")
    calendars = calendar["calendars"]
    cohort_ids = {
        calendars[symbol]["metadata"]["source_instance_id"]
        for symbol in symbols
    }
    if cohort_ids != {plan.get("source_instance_id")}:
        raise EvidenceBootstrapError("calendar terminal cohort mismatch")


_validate_xm_inputs = _validate_broker_inputs


def _broker_sources(
    plan: Mapping[str, object],
    discovery: Mapping[str, object],
    calendar: Mapping[str, object],
    *,
    key_id: str,
) -> dict[str, dict[str, object]]:
    calendars = calendar["calendars"]
    account = discovery["account"]
    if account["account_identity_key_id"] != key_id:
        raise EvidenceBootstrapError("discovery identity key does not match contract key")
    return {
        symbol: {
            "provider_kind": "BROKER_EXPORT",
            "broker_legal_name": plan["broker_legal_name"],
            "broker_server": plan["broker_server"],
            "environment": "DEMO",
            "account_identity_sha256": account["account_identity_sha256"],
            "account_identity_scheme": account["account_identity_scheme"],
            "account_identity_key_id": account["account_identity_key_id"],
            "account_currency": account["currency"],
            "account_trade_allowed": False,
            "account_trade_expert": account["trade_expert"],
            "terminal_trade_allowed": False,
            "terminal_tradeapi_disabled": True,
            "canonical_symbol": symbol,
            "broker_symbol": calendars[symbol]["metadata"]["broker_symbol"],
            "source_instance_id": plan["source_instance_id"],
            "quote_mode": "FINALIZED_BID_ASK_BARS",
            "exporter_version": EXPORTER_VERSION,
            "exporter_signing_key_id": key_id,
        }
        for symbol in _required_symbol_subset(plan["broker_symbols"], field="plan")
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
    required_symbols = _required_symbol_subset(
        calendar["calendars"],
        field="calendar",
    )
    if set(symbols) != set(required_symbols):
        raise EvidenceBootstrapError("discovery symbol set does not match calendar")
    for symbol in required_symbols:
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
    plan_path: str | Path,
    now_provider: Callable[[], datetime] = utc_now,
    git_state_provider: Callable[[], Mapping[str, object]] | None = None,
    clock_provider: Callable[[], object] | None = None,
    regulatory_approval_key_provider: (
        Callable[[str], bytes | None] | None
    ) = None,
) -> dict[str, object]:
    root = Path(repo_root).resolve()
    template = _read_json(root / "config/xm_calendar_window_02.template.json")
    plan = _read_json(Path(plan_path))
    candidate_config = _read_json(root / "config/broker_candidates.phase3.json")
    try:
        verify_prepared_xm_calendar_plan(plan, template=template)
        verify_candidate_legal_binding(
            plan,
            candidate_config,
            now_provider=now_provider,
            regulatory_approval_key_provider=(
                regulatory_approval_key_provider
            ),
        )
    except XMWindowPlanError as exc:
        raise EvidenceBootstrapError("prepared XM calendar plan is invalid") from exc
    discovery = _read_json(Path(discovery_path))
    calendar = _read_json(Path(calendar_path))
    _validate_xm_inputs(
        plan,
        discovery,
        calendar,
        signing_key=signing_key,
    )
    snapshot = ensure_frozen_snapshot(
        root,
        artifact_root,
        created_at=now_provider(),
    )
    key_id = "wincred-" + signing_key_fingerprint(signing_key)
    ruleset = build_ruleset(root)
    broker_sources = _broker_sources(
        plan,
        discovery,
        calendar,
        key_id=key_id,
    )
    instrument_specs = _instrument_specs(discovery, calendar)
    # Mint the registration claim only after all local hashing and
    # normalization work that precedes the evidence-core clock check.
    registered_at = now_provider()
    return register_forward_contract(
        artifact_root,
        snapshot,
        ruleset,
        broker_sources,
        instrument_specs,
        session_calendars=calendar["calendars"],
        contract_id=CONTRACT_ID,
        registered_at=registered_at,
        observation_start_at=plan["observation_start_at_utc"],
        blind_until=plan["blind_until_utc"],
        validation_profile=str(plan["validation_profile"]),
        git_state_provider=git_state_provider,
        clock_provider=clock_provider,
        signing_key=signing_key,
    )


def register_broker_diagnostic_contract(
    repo_root: str | Path,
    artifact_root: str | Path,
    discovery_path: str | Path,
    calendar_path: str | Path,
    signing_key: bytes,
    *,
    plan_path: str | Path,
    profile: BrokerEvidenceProfile,
    profile_config_path: str = "config/broker_evidence_profiles.v1.json",
    now_provider: Callable[[], datetime] = utc_now,
    git_state_provider: Callable[[], Mapping[str, object]] | None = None,
    clock_provider: Callable[[], object] | None = None,
    regulatory_approval_key_provider: Callable[[str], bytes | None] | None = None,
) -> dict[str, object]:
    """Register a broker-neutral DIAGNOSTIC contract from a tracked profile.

    The profile must already be explicitly enabled.  Template, discovery,
    regulatory, calendar and safety bindings are reverified inside this
    function; profile enablement alone never bypasses a gate.
    """

    if type(profile) is not BrokerEvidenceProfile:
        raise TypeError("profile must be a BrokerEvidenceProfile")
    if not profile.registration_enabled:
        raise EvidenceBootstrapError(
            "broker evidence registration remains disabled"
        )
    root = Path(repo_root).resolve()
    profile_config_relative = _repository_relative_file(
        root,
        profile_config_path,
    )
    template = _read_json(root / profile.template_path)
    plan = _read_json(Path(plan_path))
    candidate_config = _read_json(root / "config/broker_candidates.phase3.json")
    try:
        verify_prepared_broker_calendar_plan(plan, template=template)
        verify_candidate_legal_binding(
            plan,
            candidate_config,
            now_provider=now_provider,
            regulatory_approval_key_provider=regulatory_approval_key_provider,
        )
    except (BrokerWindowPlanError, XMWindowPlanError) as exc:
        raise EvidenceBootstrapError(
            "prepared broker calendar plan is invalid"
        ) from exc
    if plan.get("candidate_id") != profile.candidate_id:
        raise EvidenceBootstrapError("evidence profile candidate binding mismatch")
    discovery = _read_json(Path(discovery_path))
    calendar = _read_json(Path(calendar_path))
    _validate_broker_inputs(
        plan,
        discovery,
        calendar,
        signing_key=signing_key,
    )
    snapshot = ensure_frozen_snapshot(
        root,
        artifact_root,
        created_at=now_provider(),
        snapshot_id=profile.snapshot_id,
    )
    config_files = (
        "config/broker_candidates.phase3.json",
        profile_config_relative,
        profile.template_path,
    )
    ruleset = build_ruleset(root, config_files=config_files)
    key_id = "wincred-" + signing_key_fingerprint(signing_key)
    broker_sources = _broker_sources(
        plan,
        discovery,
        calendar,
        key_id=key_id,
    )
    instrument_specs = _instrument_specs(discovery, calendar)
    registered_at = now_provider()
    return register_forward_contract(
        artifact_root,
        snapshot,
        ruleset,
        broker_sources,
        instrument_specs,
        session_calendars=calendar["calendars"],
        calendar_amendment_policy=plan.get("calendar_amendment_policy"),
        contract_id=profile.contract_id,
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
    "register_broker_diagnostic_contract",
    "verify_calendar_bundle",
    "verify_discovery_receipt",
]
