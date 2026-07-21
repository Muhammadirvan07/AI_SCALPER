"""Read-only, deadline-bound broker shadow collector with durable receipts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
from types import MappingProxyType
from typing import Any, Callable, Mapping

from validation_evidence import (
    REQUIRED_SYMBOLS,
    load_effective_forward_contract,
    verify_forward_evidence,
)

from .broker_exporter import BrokerExportBinding, BrokerExportResult, MT5EvidenceExporter
from .contracts import canonical_json, canonical_sha256, require_text, require_utc
from .evidence_bootstrap import CONTRACT_ID, build_current_identity
from .mt5_readonly import ReadOnlyMT5Facade
from .shadow_fence import ShadowCycleAlreadyRunning, ShadowCycleFence


SHADOW_CYCLE_SCHEMA_VERSION = "xm-shadow-cycle-v1"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
PROMOTION_ELIGIBLE = False
MAX_LOT = 0.01
StageReporter = Callable[[str, str, str], None]


class ShadowCollectorError(RuntimeError):
    pass


def _canonical_symbol_subset(value: object, field: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)):
        raise ShadowCollectorError(f"{field} symbol set is invalid")
    try:
        raw = tuple(str(symbol).upper() for symbol in value)
    except TypeError as exc:
        raise ShadowCollectorError(f"{field} symbol set is invalid") from exc
    normalized = tuple(symbol for symbol in REQUIRED_SYMBOLS if symbol in raw)
    if (
        not raw
        or len(set(raw)) != len(raw)
        or raw != normalized
    ):
        raise ShadowCollectorError(f"{field} symbol set is invalid")
    return normalized


@dataclass(frozen=True)
class BarPlan:
    symbol: str
    status: str
    open_at: datetime | None
    close_at: datetime | None
    due_at: datetime | None
    reason_code: str


@dataclass(frozen=True)
class ShadowCycleReceipt:
    cycle_id: str
    observed_at: datetime
    status: str
    symbol_status: Mapping[str, str]
    result_sha256: Mapping[str, str]
    failures: tuple[str, ...]
    payload_sha256: str
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    promotion_eligible: bool = False
    max_lot: float = MAX_LOT


class ShadowCycleStore:
    """SQLite WAL receipt ledger; no trading state and no broker credentials."""

    def __init__(self, path: str | Path, *, contract_id: str = CONTRACT_ID):
        self.path = Path(path)
        self.contract_id = require_text("contract_id", contract_id)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path))
        self.connection.execute("PRAGMA busy_timeout=5000")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS shadow_cycles (
                cycle_id TEXT PRIMARY KEY,
                observed_at_utc TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL
            )"""
        )
        self.connection.execute(
            """CREATE TRIGGER IF NOT EXISTS shadow_cycles_no_update
            BEFORE UPDATE ON shadow_cycles
            BEGIN
                SELECT RAISE(ABORT, 'shadow_cycles is append-only');
            END"""
        )
        self.connection.execute(
            """CREATE TRIGGER IF NOT EXISTS shadow_cycles_no_delete
            BEFORE DELETE ON shadow_cycles
            BEGIN
                SELECT RAISE(ABORT, 'shadow_cycles is append-only');
            END"""
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def record(
        self,
        *,
        cycle_id: str,
        observed_at: datetime,
        symbol_status: Mapping[str, str],
        results: Mapping[str, BrokerExportResult],
        failures: tuple[str, ...],
        required_symbols: tuple[str, ...] = REQUIRED_SYMBOLS,
    ) -> ShadowCycleReceipt:
        normalized_cycle = require_text("cycle_id", cycle_id)
        require_utc("observed_at", observed_at)
        registered_symbols = _canonical_symbol_subset(
            required_symbols,
            "cycle receipt",
        )
        statuses = {str(key).upper(): str(value) for key, value in symbol_status.items()}
        if set(statuses) != set(registered_symbols):
            raise ShadowCollectorError(
                "cycle receipt must match the registered symbol set"
            )
        allowed_statuses = {"APPENDED", "NOT_DUE", "WINDOW_COMPLETE", "HOLD"}
        if any(value not in allowed_statuses for value in statuses.values()):
            raise ShadowCollectorError("cycle receipt contains an invalid symbol status")
        normalized_results = {str(symbol).upper(): result for symbol, result in results.items()}
        appended_symbols = {
            symbol for symbol, value in statuses.items() if value == "APPENDED"
        }
        if set(normalized_results) != appended_symbols or any(
            type(result) is not BrokerExportResult
            or result.symbol != symbol
            or result.contract_id != self.contract_id
            for symbol, result in normalized_results.items()
        ):
            raise ShadowCollectorError(
                "APPENDED statuses do not reconcile to contract-bound export receipts"
            )
        result_hashes = {
            symbol: canonical_sha256(result)
            for symbol, result in normalized_results.items()
        }
        reason_codes = tuple(sorted(set(str(item) for item in failures)))
        status = (
            "HOLD"
            if reason_codes
            else "APPENDED"
            if any(value == "APPENDED" for value in statuses.values())
            else "IDLE"
        )
        payload = {
            "schema_version": SHADOW_CYCLE_SCHEMA_VERSION,
            "contract_id": self.contract_id,
            "cycle_id": normalized_cycle,
            "observed_at_utc": observed_at,
            "status": status,
            "symbol_status": statuses,
            "result_sha256": result_hashes,
            "failures": reason_codes,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "promotion_eligible": False,
            "max_lot": MAX_LOT,
        }
        payload_json = canonical_json(payload)
        payload_hash = canonical_sha256(payload)
        existing = self.connection.execute(
            "SELECT payload_sha256 FROM shadow_cycles WHERE cycle_id=?",
            (normalized_cycle,),
        ).fetchone()
        if existing and existing[0] != payload_hash:
            raise ShadowCollectorError("cycle id already exists with different evidence")
        if not existing:
            self.connection.execute(
                "INSERT INTO shadow_cycles VALUES (?, ?, ?, ?, ?)",
                (
                    normalized_cycle,
                    observed_at.isoformat(
                        timespec="microseconds"
                    ).replace("+00:00", "Z"),
                    status,
                    payload_json,
                    payload_hash,
                ),
            )
            self.connection.commit()
        return ShadowCycleReceipt(
            cycle_id=normalized_cycle,
            observed_at=observed_at,
            status=status,
            symbol_status=MappingProxyType(statuses),
            result_sha256=MappingProxyType(result_hashes),
            failures=reason_codes,
            payload_sha256=payload_hash,
        )


def _parse_utc(value: object) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return require_utc("calendar timestamp", parsed)


def expected_bar_opens(calendar: Mapping[str, object]) -> tuple[datetime, ...]:
    values: list[datetime] = []
    for interval in calendar["market_open_intervals"]:
        cursor = _parse_utc(interval["open_at_utc"])
        end = _parse_utc(interval["close_at_utc"])
        while cursor < end:
            values.append(cursor)
            cursor += timedelta(minutes=15)
    return tuple(values)


def session_boundary_flags(
    calendar: Mapping[str, object],
    *,
    open_at: datetime,
    close_at: datetime,
) -> tuple[bool, bool]:
    """Prove whether one finalized bar is an exact registered session edge."""

    require_utc("open_at", open_at)
    require_utc("close_at", close_at)
    if close_at <= open_at:
        raise ShadowCollectorError("bar close must be after bar open")
    matching_intervals = []
    for interval in calendar["market_open_intervals"]:
        interval_open = _parse_utc(interval["open_at_utc"])
        interval_close = _parse_utc(interval["close_at_utc"])
        if interval_open <= open_at and close_at <= interval_close:
            matching_intervals.append((interval_open, interval_close))
    if len(matching_intervals) != 1:
        raise ShadowCollectorError(
            "bar does not belong to exactly one registered market-open interval"
        )
    interval_open, interval_close = matching_intervals[0]
    return open_at == interval_open, close_at == interval_close


def plan_next_bar(
    contract: Mapping[str, object],
    symbol: str,
    *,
    last_open_at: datetime | None,
    now: datetime,
) -> BarPlan:
    require_utc("now", now)
    normalized = str(symbol).upper()
    registered_symbols = _canonical_symbol_subset(
        contract.get("symbols"),
        "contract",
    )
    if normalized not in registered_symbols:
        raise ShadowCollectorError("symbol is outside the evidence contract")
    if last_open_at is not None:
        require_utc("last_open_at", last_open_at)
    opens = expected_bar_opens(contract["session_calendars"][normalized])
    next_open = next(
        (value for value in opens if last_open_at is None or value > last_open_at),
        None,
    )
    if next_open is None:
        return BarPlan(normalized, "WINDOW_COMPLETE", None, None, None, "NO_REMAINING_BAR")
    timeframe = timedelta(seconds=int(contract["timeframe_seconds"]))
    close_at = next_open + timeframe
    due_at = close_at + timedelta(seconds=int(contract["finalization_lag_seconds"]))
    deadline = due_at + timedelta(seconds=int(contract["max_append_lag_seconds"]))
    if now < due_at:
        return BarPlan(normalized, "NOT_DUE", next_open, close_at, due_at, "FINALIZATION_PENDING")
    if now > deadline:
        return BarPlan(normalized, "HOLD", next_open, close_at, due_at, "APPEND_DEADLINE_MISSED")
    return BarPlan(normalized, "DUE", next_open, close_at, due_at, "READY_READ_ONLY_EXPORT")


def _mapping(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    method = getattr(value, "_asdict", None)
    if callable(method):
        return dict(method())
    raise ShadowCollectorError("MT5 account facts are unavailable")


def _last_open_at(
    artifact_root: Path,
    symbol: str,
    *,
    contract_id: str = CONTRACT_ID,
) -> datetime | None:
    head = json.loads(
        (
            artifact_root
            / "forward"
            / contract_id
            / "heads"
            / "segments"
            / f"{symbol}.json"
        ).read_text(encoding="utf-8")
    )
    value = head.get("last_at_utc")
    return None if value is None else _parse_utc(value)


def _run_shadow_cycle_locked(
    mt5_module: Any,
    *,
    repo_root: str | Path,
    artifact_root: str | Path,
    signing_key: bytes,
    store: ShadowCycleStore,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    stage_reporter: StageReporter | None = None,
    pre_evidence_mutation_check: Callable[[], None] | None = None,
    contract_id: str = CONTRACT_ID,
    build_identity_provider: Callable[[], Mapping[str, object]] | None = None,
) -> ShadowCycleReceipt:
    repo = Path(repo_root).resolve()
    artifacts = Path(artifact_root)
    normalized_contract_id = require_text("contract_id", contract_id)
    if store.contract_id != normalized_contract_id:
        raise ShadowCollectorError("cycle store contract binding mismatch")
    identity_provider = build_identity_provider or (
        lambda: build_current_identity(repo)
    )
    if stage_reporter is not None:
        stage_reporter(
            "CONTRACT_VERIFICATION",
            "STARTED",
            "CONTRACT_VERIFICATION_STARTED",
        )
    try:
        verification = verify_forward_evidence(
            artifacts,
            normalized_contract_id,
            signing_key=signing_key,
            build_identity_provider=identity_provider,
        )
    except Exception as exc:
        if stage_reporter is not None:
            stage_reporter(
                "CONTRACT_VERIFICATION",
                "HOLD",
                f"CONTRACT_VERIFICATION_EXCEPTION_{type(exc).__name__.upper()}",
            )
        raise
    if not verification["valid"]:
        if stage_reporter is not None:
            stage_reporter(
                "CONTRACT_VERIFICATION",
                "HOLD",
                "CONTRACT_EVIDENCE_INVALID",
            )
        raise ShadowCollectorError(
            "forward evidence verification failed: "
            + ",".join(verification["failures"][:3])
    )
    if stage_reporter is not None:
        stage_reporter(
            "CONTRACT_VERIFICATION",
            "PASS",
            "CONTRACT_EVIDENCE_VERIFIED",
        )
    effective_view = load_effective_forward_contract(
        artifacts,
        normalized_contract_id,
        signing_key=signing_key,
        build_identity_provider=identity_provider,
    )
    contract = effective_view["contract"]
    contract["session_calendars"] = effective_view[
        "effective_session_calendars"
    ]
    registered_symbols = _canonical_symbol_subset(
        contract.get("symbols"),
        "contract",
    )
    facade = ReadOnlyMT5Facade(mt5_module)
    cycle_started = now_provider()
    require_utc("cycle_started", cycle_started)
    cycle_id = (
        normalized_contract_id
        + "-shadow-"
        + cycle_started.strftime("%Y%m%dT%H%M%S%fZ")
    )
    statuses: dict[str, str] = {}
    results: dict[str, BrokerExportResult] = {}
    failures: list[str] = []
    for symbol in registered_symbols:
        plan = plan_next_bar(
            contract,
            symbol,
            last_open_at=_last_open_at(
                artifacts,
                symbol,
                contract_id=normalized_contract_id,
            ),
            now=now_provider(),
        )
        if plan.status != "DUE":
            statuses[symbol] = plan.status
            if plan.status == "HOLD":
                failures.append(f"{plan.reason_code}:{symbol}")
            continue
        source = contract["broker_sources"][symbol]
        spec = contract["instrument_specs"][symbol]
        session_open_boundary, session_close_boundary = session_boundary_flags(
            contract["session_calendars"][symbol],
            open_at=plan.open_at,
            close_at=plan.close_at,
        )
        binding = BrokerExportBinding(
            expected_account_identity_sha256=source[
                "account_identity_sha256"
            ],
            account_identity_scheme=source["account_identity_scheme"],
            account_identity_key_id=source["account_identity_key_id"],
            account_alias=source["source_instance_id"],
            broker_legal_name=source["broker_legal_name"],
            server=source["broker_server"],
            environment=source["environment"],
            account_currency=source["account_currency"],
            canonical_symbol=symbol,
            broker_symbol=source["broker_symbol"],
            instrument_spec=spec,
            account_trade_allowed=source["account_trade_allowed"],
            account_trade_expert=source["account_trade_expert"],
            terminal_trade_allowed=source["terminal_trade_allowed"],
            terminal_tradeapi_disabled=source["terminal_tradeapi_disabled"],
        )
        if pre_evidence_mutation_check is not None:
            try:
                pre_evidence_mutation_check()
            except Exception as exc:
                statuses[symbol] = "HOLD"
                failures.append(
                    "PRE_EVIDENCE_MUTATION_GUARD_FAILED:"
                    f"{symbol}:{type(exc).__name__}"
                )
                continue
        try:
            result = MT5EvidenceExporter(
                facade,
                binding=binding,
                signing_key=signing_key,
                build_identity_provider=identity_provider,
                clock_provider=now_provider,
            ).export(
                artifact_root=str(artifacts),
                contract_id=normalized_contract_id,
                canonical_symbol=symbol,
                broker_symbol=source["broker_symbol"],
                source=source,
                instrument_spec=spec,
                start_utc=plan.open_at,
                end_utc=plan.close_at,
                session_open_boundary=session_open_boundary,
                session_close_boundary=session_close_boundary,
            )
        except Exception as exc:
            statuses[symbol] = "HOLD"
            failures.append(f"EXPORT_FAILED:{symbol}:{type(exc).__name__}")
        else:
            statuses[symbol] = "APPENDED"
            results[symbol] = result
    return store.record(
        cycle_id=cycle_id,
        observed_at=now_provider(),
        symbol_status=statuses,
        results=results,
        failures=tuple(failures),
        required_symbols=registered_symbols,
    )


def run_shadow_cycle(
    mt5_module: Any,
    *,
    repo_root: str | Path,
    artifact_root: str | Path,
    signing_key: bytes,
    store: ShadowCycleStore,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    stage_reporter: StageReporter | None = None,
    pre_evidence_mutation_check: Callable[[], None] | None = None,
    contract_id: str = CONTRACT_ID,
    build_identity_provider: Callable[[], Mapping[str, object]] | None = None,
) -> ShadowCycleReceipt:
    """Run one whole evidence cycle while holding the contract singleton fence."""

    artifacts = Path(artifact_root)
    normalized_contract_id = require_text("contract_id", contract_id)
    if store.contract_id != normalized_contract_id:
        raise ShadowCollectorError("cycle store contract binding mismatch")
    with ShadowCycleFence(artifacts, normalized_contract_id):
        return _run_shadow_cycle_locked(
            mt5_module,
            repo_root=repo_root,
            artifact_root=artifacts,
            signing_key=signing_key,
            store=store,
            now_provider=now_provider,
            stage_reporter=stage_reporter,
            pre_evidence_mutation_check=pre_evidence_mutation_check,
            contract_id=normalized_contract_id,
            build_identity_provider=build_identity_provider,
        )


__all__ = [
    "BarPlan",
    "ReadOnlyMT5Facade",
    "ShadowCycleAlreadyRunning",
    "ShadowCollectorError",
    "ShadowCycleReceipt",
    "ShadowCycleStore",
    "expected_bar_opens",
    "plan_next_bar",
    "run_shadow_cycle",
    "session_boundary_flags",
]
