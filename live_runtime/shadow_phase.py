"""Durable, read-only broker-shadow orchestration for roadmap phase 3.

This module deliberately has no MT5 order dependency.  It records exact public
broker bindings and receipts produced by the separate read-only evidence
exporter; credentials belong to the Windows host credential store.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import re
import sqlite3
from typing import Callable, Mapping

from .benchmark import MAX_LOT, MIN_BENCHMARK_SESSIONS, REQUIRED_SYMBOLS
from .broker_exporter import BrokerExportResult
from .contracts import canonical_json, canonical_sha256, require_text, require_utc


SHADOW_SCHEMA_VERSION = "broker-shadow-v1"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
PROMOTION_ELIGIBLE = False
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class BrokerCandidateRegistration:
    """Exact, audit-safe binding discovered from one demo MT5 terminal."""

    candidate_id: str
    legal_name: str
    server: str
    account_type: str
    regulatory_reference: str
    legal_eligible: bool
    broker_symbols: Mapping[str, str]
    instrument_spec_sha256: Mapping[str, str]
    environment: str = "DEMO"

    def __post_init__(self) -> None:
        for field in (
            "candidate_id", "legal_name", "server", "account_type",
            "regulatory_reference",
        ):
            object.__setattr__(self, field, require_text(field, getattr(self, field)))
        if type(self.legal_eligible) is not bool:
            raise TypeError("legal_eligible must be bool")
        if self.environment != "DEMO":
            raise ValueError("phase 3 accepts DEMO registrations only")
        symbols = {str(k).upper(): str(v).strip() for k, v in self.broker_symbols.items()}
        if set(symbols) != set(REQUIRED_SYMBOLS) or any(not value for value in symbols.values()):
            raise ValueError("registration must bind exactly the four required symbols")
        hashes = {str(k).upper(): str(v).lower() for k, v in self.instrument_spec_sha256.items()}
        if set(hashes) != set(REQUIRED_SYMBOLS) or any(
            _SHA256_RE.fullmatch(value) is None for value in hashes.values()
        ):
            raise ValueError("instrument spec hashes must bind all required symbols")
        object.__setattr__(self, "broker_symbols", symbols)
        object.__setattr__(self, "instrument_spec_sha256", hashes)

    @property
    def binding_sha256(self) -> str:
        return canonical_sha256(self)


@dataclass(frozen=True)
class ShadowSessionReceipt:
    candidate_id: str
    session_id: str
    observed_at: datetime
    status: str
    symbol_receipt_sha256: Mapping[str, str]
    failures: tuple[str, ...]
    payload_sha256: str
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    promotion_eligible: bool = False
    max_lot: float = MAX_LOT


class ShadowSessionStore:
    """SQLite WAL ledger with idempotent session registration."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path))
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS shadow_sessions (
                candidate_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                observed_at_utc TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                PRIMARY KEY(candidate_id, session_id)
            )"""
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def record(
        self,
        registration: BrokerCandidateRegistration,
        *,
        session_id: str,
        observed_at: datetime,
        results: Mapping[str, BrokerExportResult],
        failures: tuple[str, ...] = (),
    ) -> ShadowSessionReceipt:
        session_id = require_text("session_id", session_id)
        require_utc("observed_at", observed_at)
        normalized = {str(symbol).upper(): result for symbol, result in results.items()}
        reason_codes = list(failures)
        hashes: dict[str, str] = {}
        if set(normalized) != set(REQUIRED_SYMBOLS):
            reason_codes.append("INCOMPLETE_REQUIRED_SYMBOL_SET")
        for symbol, result in sorted(normalized.items()):
            if symbol not in REQUIRED_SYMBOLS or type(result) is not BrokerExportResult:
                reason_codes.append(f"INVALID_EXPORT_RESULT:{symbol}")
                continue
            if result.symbol != symbol:
                reason_codes.append(f"SYMBOL_BINDING_MISMATCH:{symbol}")
            if result.status != "FINALIZED_EVIDENCE_APPENDED":
                reason_codes.append(f"NO_FINALIZED_EVIDENCE:{symbol}")
            hashes[symbol] = canonical_sha256(result)
        reason_codes = sorted(set(reason_codes))
        status = "COMPLETE" if not reason_codes else "HOLD"
        payload = {
            "schema_version": SHADOW_SCHEMA_VERSION,
            "candidate_binding_sha256": registration.binding_sha256,
            "candidate_id": registration.candidate_id,
            "session_id": session_id,
            "observed_at_utc": observed_at,
            "status": status,
            "symbol_receipt_sha256": hashes,
            "failures": reason_codes,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "promotion_eligible": False,
            "max_lot": MAX_LOT,
        }
        payload_json = canonical_json(payload)
        payload_hash = canonical_sha256(payload)
        existing = self.connection.execute(
            "SELECT payload_sha256 FROM shadow_sessions WHERE candidate_id=? AND session_id=?",
            (registration.candidate_id, session_id),
        ).fetchone()
        if existing and existing[0] != payload_hash:
            raise ValueError("shadow session id already exists with different evidence")
        if not existing:
            self.connection.execute(
                "INSERT INTO shadow_sessions VALUES (?, ?, ?, ?, ?, ?)",
                (registration.candidate_id, session_id, observed_at.isoformat(), status,
                 payload_json, payload_hash),
            )
            self.connection.commit()
        return ShadowSessionReceipt(
            candidate_id=registration.candidate_id,
            session_id=session_id,
            observed_at=observed_at,
            status=status,
            symbol_receipt_sha256=hashes,
            failures=tuple(reason_codes),
            payload_sha256=payload_hash,
        )

    def completed_sessions(self, candidate_id: str) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) FROM shadow_sessions WHERE candidate_id=? AND status='COMPLETE'",
            (require_text("candidate_id", candidate_id),),
        ).fetchone()
        return int(row[0])

    def benchmark_ready(self, candidate_id: str) -> bool:
        return self.completed_sessions(candidate_id) >= MIN_BENCHMARK_SESSIONS


class ReadOnlyShadowService:
    """Runs one four-symbol export cycle through injected read-only callables."""

    def __init__(self, store: ShadowSessionStore):
        if type(store) is not ShadowSessionStore:
            raise TypeError("store must be ShadowSessionStore")
        self.store = store

    def run_once(
        self,
        registration: BrokerCandidateRegistration,
        *,
        session_id: str,
        observed_at: datetime,
        exporters: Mapping[str, Callable[[], BrokerExportResult]],
    ) -> ShadowSessionReceipt:
        normalized_exporters = {str(key).upper(): value for key, value in exporters.items()}
        if set(normalized_exporters) != set(REQUIRED_SYMBOLS):
            return self.store.record(
                registration, session_id=session_id, observed_at=observed_at,
                results={}, failures=("INCOMPLETE_EXPORTER_SET",),
            )
        results: dict[str, BrokerExportResult] = {}
        failures: list[str] = []
        for symbol in sorted(REQUIRED_SYMBOLS):
            exporter = normalized_exporters[symbol]
            if not callable(exporter):
                failures.append(f"EXPORTER_NOT_CALLABLE:{symbol}")
                continue
            try:
                results[symbol] = exporter()
            except Exception as exc:  # boundary converts broker failure to durable HOLD
                failures.append(f"EXPORT_FAILED:{symbol}:{type(exc).__name__}")
        return self.store.record(
            registration, session_id=session_id, observed_at=observed_at,
            results=results, failures=tuple(failures),
        )
