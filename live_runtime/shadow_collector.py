"""Read-only, deadline-bound XM shadow collector with durable cycle receipts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
from types import MappingProxyType
from typing import Any, Callable, Mapping

from validation_evidence import REQUIRED_SYMBOLS, verify_forward_evidence

from .broker_exporter import BrokerExportBinding, BrokerExportResult, MT5EvidenceExporter
from .contracts import canonical_json, canonical_sha256, require_text, require_utc
from .evidence_bootstrap import CONTRACT_ID, build_current_identity


SHADOW_CYCLE_SCHEMA_VERSION = "xm-shadow-cycle-v1"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
PROMOTION_ELIGIBLE = False
MAX_LOT = 0.01


class ShadowCollectorError(RuntimeError):
    pass


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


class ReadOnlyMT5Facade:
    """Capability-reduced view of MetaTrader5; order methods are absent."""

    def __init__(self, mt5_module: Any):
        for name in ("account_info", "symbol_info", "copy_ticks_range"):
            if not callable(getattr(mt5_module, name, None)):
                raise ShadowCollectorError(f"MT5 read-only capability missing: {name}")
        self._mt5 = mt5_module
        for constant in (
            "COPY_TICKS_ALL",
            "ACCOUNT_TRADE_MODE_DEMO",
            "ACCOUNT_TRADE_MODE_REAL",
            "ACCOUNT_MARGIN_MODE_RETAIL_NETTING",
            "ACCOUNT_MARGIN_MODE_EXCHANGE",
            "ACCOUNT_MARGIN_MODE_RETAIL_HEDGING",
        ):
            object.__setattr__(self, constant, getattr(mt5_module, constant))

    def account_info(self):
        return self._mt5.account_info()

    def symbol_info(self, symbol):
        return self._mt5.symbol_info(symbol)

    def copy_ticks_range(self, symbol, start, end, flags):
        return self._mt5.copy_ticks_range(symbol, start, end, flags)


class ShadowCycleStore:
    """SQLite WAL receipt ledger; no trading state and no broker credentials."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path))
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
    ) -> ShadowCycleReceipt:
        normalized_cycle = require_text("cycle_id", cycle_id)
        require_utc("observed_at", observed_at)
        statuses = {str(key).upper(): str(value) for key, value in symbol_status.items()}
        if set(statuses) != set(REQUIRED_SYMBOLS):
            raise ShadowCollectorError("cycle receipt requires all four symbol statuses")
        allowed_statuses = {"APPENDED", "NOT_DUE", "WINDOW_COMPLETE", "HOLD"}
        if any(value not in allowed_statuses for value in statuses.values()):
            raise ShadowCollectorError("cycle receipt contains an invalid symbol status")
        normalized_results = {str(symbol).upper(): result for symbol, result in results.items()}
        appended_symbols = {
            symbol for symbol, value in statuses.items() if value == "APPENDED"
        }
        if set(normalized_results) != appended_symbols or any(
            type(result) is not BrokerExportResult or result.symbol != symbol
            for symbol, result in normalized_results.items()
        ):
            raise ShadowCollectorError("APPENDED statuses do not reconcile to export receipts")
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
            "contract_id": CONTRACT_ID,
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
                    observed_at.isoformat(),
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


def plan_next_bar(
    contract: Mapping[str, object],
    symbol: str,
    *,
    last_open_at: datetime | None,
    now: datetime,
) -> BarPlan:
    require_utc("now", now)
    normalized = str(symbol).upper()
    if normalized not in REQUIRED_SYMBOLS:
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


def _last_open_at(artifact_root: Path, symbol: str) -> datetime | None:
    head = json.loads(
        (
            artifact_root
            / "forward"
            / CONTRACT_ID
            / "heads"
            / "segments"
            / f"{symbol}.json"
        ).read_text(encoding="utf-8")
    )
    value = head.get("last_at_utc")
    return None if value is None else _parse_utc(value)


def run_shadow_cycle(
    mt5_module: Any,
    *,
    repo_root: str | Path,
    artifact_root: str | Path,
    signing_key: bytes,
    store: ShadowCycleStore,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> ShadowCycleReceipt:
    repo = Path(repo_root).resolve()
    artifacts = Path(artifact_root)
    identity_provider = lambda: build_current_identity(repo)
    verification = verify_forward_evidence(
        artifacts,
        CONTRACT_ID,
        signing_key=signing_key,
        build_identity_provider=identity_provider,
    )
    if not verification["valid"]:
        raise ShadowCollectorError(
            "forward evidence verification failed: "
            + ",".join(verification["failures"][:3])
        )
    contract_path = artifacts / "forward" / CONTRACT_ID / "contract.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    facade = ReadOnlyMT5Facade(mt5_module)
    account = _mapping(facade.account_info())
    expected_login = int(account.get("login") or 0)
    if expected_login <= 0:
        raise ShadowCollectorError("connected MT5 login is unavailable")
    cycle_started = now_provider()
    require_utc("cycle_started", cycle_started)
    cycle_id = "xm-shadow-" + cycle_started.strftime("%Y%m%dT%H%M%S%fZ")
    statuses: dict[str, str] = {}
    results: dict[str, BrokerExportResult] = {}
    failures: list[str] = []
    for symbol in sorted(REQUIRED_SYMBOLS):
        plan = plan_next_bar(
            contract,
            symbol,
            last_open_at=_last_open_at(artifacts, symbol),
            now=now_provider(),
        )
        if plan.status != "DUE":
            statuses[symbol] = plan.status
            if plan.status == "HOLD":
                failures.append(f"{plan.reason_code}:{symbol}")
            continue
        source = contract["broker_sources"][symbol]
        spec = contract["instrument_specs"][symbol]
        binding = BrokerExportBinding(
            expected_login=expected_login,
            account_alias="xm-demo-primary-window-01",
            broker_legal_name=source["broker_legal_name"],
            server=source["broker_server"],
            environment=source["environment"],
            account_currency=str(account.get("currency") or ""),
            canonical_symbol=symbol,
            broker_symbol=source["broker_symbol"],
            instrument_spec=spec,
        )
        try:
            exported_at = now_provider()
            result = MT5EvidenceExporter(
                facade,
                binding=binding,
                signing_key=signing_key,
                build_identity_provider=identity_provider,
                clock_provider=now_provider,
            ).export(
                artifact_root=str(artifacts),
                contract_id=CONTRACT_ID,
                canonical_symbol=symbol,
                broker_symbol=source["broker_symbol"],
                source=source,
                instrument_spec=spec,
                start_utc=plan.open_at,
                end_utc=plan.close_at,
                exported_at=exported_at,
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
    )


__all__ = [
    "BarPlan",
    "ReadOnlyMT5Facade",
    "ShadowCollectorError",
    "ShadowCycleReceipt",
    "ShadowCycleStore",
    "expected_bar_opens",
    "plan_next_bar",
    "run_shadow_cycle",
]
