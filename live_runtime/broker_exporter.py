"""Read-only MT5 evidence exporter for raw ticks and finalized M15 bid/ask bars.

The exporter has no order API and is intentionally separate from
``MT5Adapter``.  It transforms the exact broker ticks into an immutable raw
partition and derives both bid and ask OHLC from those same ticks.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import json
import math
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Callable, Mapping

import pandas as pd

from validation_evidence import (
    EvidenceValidationError,
    append_paired_forward_evidence,
    canonical_evidence_payload_sha256,
)
# The modular monolith intentionally shares the evidence normalizer here. A
# schema change must stop the exporter instead of leaving a second validator
# that can silently accept a different instrument contract.
from validation_evidence.secure_core import (
    _validate_instrument_spec as _validate_evidence_instrument_spec,
)

from .account_identity import (
    ACCOUNT_IDENTITY_SCHEME,
    account_identity_sha256,
    require_account_identity_sha256,
)
from .contracts import (
    SCHEMA_VERSION as CONTRACT_SCHEMA_VERSION,
    BrokerSpec,
    CanonicalContract,
    canonical_json,
    canonical_sha256,
    require_text,
    require_utc,
)
from .evidence_credentials import signing_key_fingerprint


TIMEFRAME_SECONDS = 900
FINALIZATION_LAG_SECONDS = 900
EXPORT_COVERAGE_SCHEMA_VERSION = "broker-export-coverage-v3"
PAIRED_APPEND_SCHEMA_VERSION = "broker-paired-append-receipt-v2"
BOUNDARY_PROBE_SECONDS = 10
MAX_OBSERVED_TICK_GAP_SECONDS = 120
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_CANONICAL_TICK_PAYLOAD_COLUMNS = (
    "time_msc",
    "bid",
    "ask",
    "last",
    "volume",
    "volume_real",
    "flags",
)


class BrokerExportBindingError(RuntimeError):
    """Raised when the connected read-only MT5 identity drifts."""


class PairedAppendRecoveryRequired(RuntimeError):
    """Raised when paired raw/bar append state requires manual recovery."""


def _paired_expected_sequence(
    artifact_root: str | Path,
    contract_id: str,
    canonical_symbol: str,
) -> int:
    """Read the paired high-water mark used as an optimistic append fence."""

    root = Path(artifact_root)
    contract = _safe_id(contract_id, "contract_id")
    symbol = _safe_id(canonical_symbol.upper(), "canonical_symbol")
    contract_directory = root / "forward" / contract
    if contract_directory.is_symlink() or not contract_directory.is_dir():
        raise PairedAppendRecoveryRequired("forward contract directory is unavailable")
    sequences: list[int] = []
    for kind in ("segments", "raw_ticks"):
        path = contract_directory / "heads" / kind / f"{symbol}.json"
        if path.is_symlink() or not path.is_file():
            raise PairedAppendRecoveryRequired("paired evidence head is unavailable")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            sequence = payload["sequence"]
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise PairedAppendRecoveryRequired("paired evidence head is invalid") from exc
        if type(sequence) is not int or sequence < 0:
            raise PairedAppendRecoveryRequired("paired evidence head is invalid")
        sequences.append(sequence)
    if len(set(sequences)) != 1:
        raise PairedAppendRecoveryRequired("paired evidence high-water marks disagree")
    return sequences[0] + 1


def _as_mapping(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return dict(value)
    method = getattr(value, "_asdict", None)
    if callable(method):
        return dict(method())
    return {
        name: getattr(value, name)
        for name in dir(value)
        if not name.startswith("_") and not callable(getattr(value, name))
    }


def _evidence_payload(value: object) -> dict[str, object]:
    """Convert runtime contracts into the evidence store's JSON value domain."""

    payload = json.loads(canonical_json(value))
    if not isinstance(payload, dict):
        raise TypeError("evidence payload must canonicalize to a mapping")
    return payload


def _safe_id(value: object, field: str) -> str:
    normalized = require_text(field, value)
    if _SAFE_ID_RE.fullmatch(normalized) is None:
        raise ValueError(f"{field} contains unsafe path characters")
    return normalized


def _decimal(value: object, field: str, *, nonnegative: bool = False) -> Decimal:
    try:
        number = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be numeric") from exc
    if not number.is_finite() or (number < 0 if nonnegative else number <= 0):
        raise ValueError(f"{field} is outside its valid range")
    return number


def _normalize_instrument_spec(
    spec: Mapping[str, object], canonical_symbol: str
) -> Mapping[str, object]:
    canonical = require_text(
        "canonical_symbol",
        canonical_symbol,
        upper=True,
    )
    try:
        normalized = _validate_evidence_instrument_spec(canonical, spec)
    except (EvidenceValidationError, KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            "instrument_spec is incompatible with the validation-evidence schema"
        ) from exc
    return MappingProxyType(normalized)


@dataclass(frozen=True)
class EvidenceInstrumentIdentity(CanonicalContract):
    """Evidence-only fields that cannot be derived from ``BrokerSpec``."""

    instrument_kind: str
    base_currency: str
    quote_currency: str
    profit_currency: str
    margin_currency: str
    margin_mode: str

    def __post_init__(self) -> None:
        for field in (
            "instrument_kind",
            "base_currency",
            "quote_currency",
            "profit_currency",
            "margin_currency",
            "margin_mode",
        ):
            object.__setattr__(
                self,
                field,
                require_text(field, getattr(self, field), upper=True),
            )
        for field in (
            "base_currency",
            "quote_currency",
            "profit_currency",
            "margin_currency",
        ):
            if re.fullmatch(r"[A-Z]{3}", getattr(self, field)) is None:
                raise ValueError(f"{field} must be a three-letter currency code")
        if self.margin_mode not in {
            "RETAIL_NETTING",
            "RETAIL_HEDGING",
            "EXCHANGE",
        }:
            raise ValueError("margin_mode is unsupported")


@dataclass(frozen=True)
class BrokerExportBinding(CanonicalContract):
    """Exact read-only account, server, symbol, and instrument binding."""

    expected_account_identity_sha256: str
    account_identity_scheme: str
    account_identity_key_id: str
    account_alias: str
    broker_legal_name: str
    server: str
    environment: str
    account_currency: str
    canonical_symbol: str
    broker_symbol: str
    instrument_spec: Mapping[str, object]
    account_trade_allowed: bool = False
    account_trade_expert: bool = False
    terminal_trade_allowed: bool = False
    terminal_tradeapi_disabled: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "expected_account_identity_sha256",
            require_account_identity_sha256(
                self.expected_account_identity_sha256
            ),
        )
        if self.account_identity_scheme != ACCOUNT_IDENTITY_SCHEME:
            raise ValueError("account_identity_scheme is unsupported")
        for field in (
            "account_identity_key_id",
            "account_alias",
            "broker_legal_name",
            "server",
            "broker_symbol",
        ):
            object.__setattr__(self, field, require_text(field, getattr(self, field)))
        environment = require_text("environment", self.environment, upper=True)
        if environment not in {"DEMO", "LIVE_READ_ONLY"}:
            raise ValueError("export environment must be DEMO or LIVE_READ_ONLY")
        object.__setattr__(self, "environment", environment)
        currency = require_text("account_currency", self.account_currency, upper=True)
        if re.fullmatch(r"[A-Z]{3}", currency) is None:
            raise ValueError("account_currency must be an ISO currency")
        object.__setattr__(self, "account_currency", currency)
        canonical = require_text("canonical_symbol", self.canonical_symbol, upper=True)
        object.__setattr__(self, "canonical_symbol", canonical)
        object.__setattr__(
            self,
            "instrument_spec",
            _normalize_instrument_spec(self.instrument_spec, canonical),
        )
        if type(self.account_trade_expert) is not bool:
            raise ValueError("account_trade_expert must be bool")
        if (
            self.account_trade_allowed is not False
            or self.terminal_trade_allowed is not False
            or self.terminal_tradeapi_disabled is not True
        ):
            raise ValueError("broker export binding must be strictly read-only")

    @property
    def public_binding_payload(self) -> Mapping[str, object]:
        """Return audit-safe binding facts without the raw login or alias."""

        return MappingProxyType(
            _evidence_payload(
                {
                "account_identity_sha256": self.expected_account_identity_sha256,
                "account_identity_scheme": self.account_identity_scheme,
                "account_identity_key_id": self.account_identity_key_id,
                "account_alias_sha256": canonical_sha256(
                    {"account_alias": self.account_alias}
                ),
                "broker_legal_name": self.broker_legal_name,
                "server": self.server,
                "environment": self.environment,
                "account_currency": self.account_currency,
                "account_trade_allowed": self.account_trade_allowed,
                "account_trade_expert": self.account_trade_expert,
                "terminal_trade_allowed": self.terminal_trade_allowed,
                "terminal_tradeapi_disabled": self.terminal_tradeapi_disabled,
                "canonical_symbol": self.canonical_symbol,
                "broker_symbol": self.broker_symbol,
                "instrument_spec": self.instrument_spec,
                "account_identity_verified_at_runtime": True,
                }
            )
        )

    @property
    def public_binding_sha256(self) -> str:
        """Hash the audit-safe binding with the evidence canonical form."""

        return canonical_evidence_payload_sha256(self.public_binding_payload)


def broker_export_binding_from_spec(
    broker_spec: BrokerSpec,
    *,
    expected_account_identity_sha256: str,
    account_identity_key_id: str,
    evidence_identity: EvidenceInstrumentIdentity,
    account_identity_scheme: str = ACCOUNT_IDENTITY_SCHEME,
    account_trade_expert: bool = False,
) -> BrokerExportBinding:
    """Bridge one validated runtime spec into the exact evidence schema.

    Every overlapping field is derived from ``BrokerSpec``.  Callers provide
    only the evidence identity fields and the contract-bound keyed account
    identity that do not exist in the runtime contract, so they cannot
    handwrite a second numeric broker specification that silently drifts.
    """

    if type(broker_spec) is not BrokerSpec:
        raise TypeError("broker_spec must be an exact BrokerSpec")
    if type(evidence_identity) is not EvidenceInstrumentIdentity:
        raise TypeError("evidence_identity must be EvidenceInstrumentIdentity")
    if broker_spec.schema_version != CONTRACT_SCHEMA_VERSION:
        raise ValueError("BrokerSpec schema version is not supported by this bridge")
    instrument_spec: dict[str, object] = {
        "canonical_symbol": broker_spec.symbol,
        "instrument_kind": evidence_identity.instrument_kind,
        "base_currency": evidence_identity.base_currency,
        "quote_currency": evidence_identity.quote_currency,
        "digits": broker_spec.digits,
        "point": broker_spec.point,
        "tick_size": broker_spec.tick_size,
        "contract_size": broker_spec.contract_size,
        "tick_value": broker_spec.tick_value,
        "volume_min": broker_spec.volume_min,
        "volume_max": broker_spec.volume_max,
        "volume_step": broker_spec.volume_step,
        "stops_level_points": broker_spec.stops_level_points,
        "freeze_level_points": broker_spec.freeze_level_points,
        "profit_currency": evidence_identity.profit_currency,
        "margin_currency": evidence_identity.margin_currency,
        "margin_mode": evidence_identity.margin_mode,
        "session_calendar_sha256": broker_spec.session_calendar_sha256,
    }
    return BrokerExportBinding(
        expected_account_identity_sha256=expected_account_identity_sha256,
        account_identity_scheme=account_identity_scheme,
        account_identity_key_id=account_identity_key_id,
        account_alias=broker_spec.account_id,
        broker_legal_name=broker_spec.broker_legal_name,
        server=broker_spec.server,
        environment=broker_spec.environment,
        account_currency=broker_spec.account_currency,
        canonical_symbol=broker_spec.symbol,
        broker_symbol=broker_spec.broker_symbol,
        instrument_spec=instrument_spec,
        account_trade_expert=account_trade_expert,
    )


@dataclass(frozen=True)
class PairedAppendCommitReceipt(CanonicalContract):
    """In-memory projection of the authoritative HMAC paired commit.

    This object is returned to callers but is never persisted as a second
    commit authority; recovery and replay state live only in
    ``validation_evidence``.
    """

    export_id: str
    contract_id: str
    symbol: str
    raw_partition_payload_sha256: str
    bar_segment_payload_sha256: str
    coverage_metadata_sha256: str
    broker_binding_sha256: str
    sequence: int
    paired_commit_payload_sha256: str
    paired_commit_hmac_sha256: str
    committed_at: datetime
    status: str = "COMMITTED"
    schema_version: str = PAIRED_APPEND_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "export_id", _safe_id(self.export_id, "export_id"))
        object.__setattr__(self, "contract_id", _safe_id(self.contract_id, "contract_id"))
        object.__setattr__(self, "symbol", require_text("symbol", self.symbol, upper=True))
        for field in (
            "raw_partition_payload_sha256",
            "bar_segment_payload_sha256",
            "coverage_metadata_sha256",
            "broker_binding_sha256",
            "paired_commit_payload_sha256",
            "paired_commit_hmac_sha256",
        ):
            value = str(getattr(self, field) or "").lower()
            if _SHA256_RE.fullmatch(value) is None:
                raise ValueError(f"{field} must be SHA-256")
            object.__setattr__(self, field, value)
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError("paired append sequence must be a positive integer")
        require_utc("committed_at", self.committed_at)
        if self.status != "COMMITTED" or self.schema_version != PAIRED_APPEND_SCHEMA_VERSION:
            raise ValueError("paired append commit receipt is invalid")


def _receipt_hash(receipt: Mapping[str, object], field: str) -> str:
    value = receipt.get(field)
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be a 64-character SHA-256 hex digest")
    return value.lower()


def _exact_nonnegative_int(value: object, field: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{field} must be int")
    if value < 0:
        raise ValueError(f"{field} cannot be negative")
    return value


@dataclass(frozen=True)
class BrokerExportResult(CanonicalContract):
    contract_id: str
    symbol: str
    raw_tick_partition: Mapping[str, object] | None
    finalized_bar_segment: Mapping[str, object] | None
    exported_at: datetime
    coverage_metadata: Mapping[str, object]
    broker_binding_sha256: str
    status: str
    paired_commit_receipt: PairedAppendCommitReceipt | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "contract_id", require_text("contract_id", self.contract_id)
        )
        object.__setattr__(self, "symbol", require_text("symbol", self.symbol, upper=True))
        require_utc("exported_at", self.exported_at)
        binding_hash = str(self.broker_binding_sha256 or "").lower()
        if _SHA256_RE.fullmatch(binding_hash) is None:
            raise ValueError("broker_binding_sha256 must be SHA-256")
        object.__setattr__(self, "broker_binding_sha256", binding_hash)
        status = require_text("status", self.status, upper=True)
        if status not in {
            "FINALIZED_EVIDENCE_APPENDED",
            "TAIL_RETAINED_NO_FINALIZED_BAR",
        }:
            raise ValueError("unsupported broker export status")
        object.__setattr__(self, "status", status)

        has_raw = self.raw_tick_partition is not None
        has_bars = self.finalized_bar_segment is not None
        if has_raw != has_bars:
            raise ValueError("raw tick and finalized bar receipts must be paired")
        if has_raw != (status == "FINALIZED_EVIDENCE_APPENDED"):
            raise ValueError("receipt presence is inconsistent with export status")
        if has_raw != (type(self.paired_commit_receipt) is PairedAppendCommitReceipt):
            raise ValueError("paired append commit receipt is required exactly for evidence")

        if not isinstance(self.coverage_metadata, Mapping):
            raise TypeError("coverage_metadata must be a mapping")
        metadata = dict(self.coverage_metadata)
        if metadata.get("schema_version") != EXPORT_COVERAGE_SCHEMA_VERSION:
            raise ValueError("coverage metadata schema is invalid")
        for field in (
            "requested_start_at_utc",
            "requested_end_at_utc",
            "tail_requery_from_at_utc",
            "observed_left_boundary_at_utc",
            "observed_right_boundary_at_utc",
            "broker_binding_pre_checked_at_utc",
            "broker_binding_post_checked_at_utc",
        ):
            require_utc(field, metadata.get(field))
        pre_checked = metadata["broker_binding_pre_checked_at_utc"]
        post_checked = metadata["broker_binding_post_checked_at_utc"]
        if pre_checked > post_checked:
            raise ValueError("broker binding post-check precedes its pre-check")
        observed_facts_hashes = []
        for field in (
            "observed_facts_sha256",
            "broker_binding_pre_observed_facts_sha256",
            "broker_binding_post_observed_facts_sha256",
        ):
            value = str(metadata.get(field) or "").lower()
            if _SHA256_RE.fullmatch(value) is None:
                raise ValueError(f"{field} must be SHA-256")
            metadata[field] = value
            observed_facts_hashes.append(value)
        if len(set(observed_facts_hashes)) != 1:
            raise ValueError("broker binding changed during tick collection")
        observed_facts = metadata.get("broker_binding_observed_facts")
        if not isinstance(observed_facts, Mapping):
            raise ValueError("broker binding observed facts are missing")
        normalized_observed_facts = _evidence_payload(observed_facts)
        if (
            canonical_evidence_payload_sha256(normalized_observed_facts)
            != observed_facts_hashes[0]
        ):
            raise ValueError("broker binding observed facts hash is invalid")
        metadata["broker_binding_observed_facts"] = MappingProxyType(
            normalized_observed_facts
        )
        if metadata.get("coverage_boundary_proven") is not True:
            raise ValueError("requested-range boundary proof is missing")
        if metadata.get("coverage_continuity_proven") is not True:
            raise ValueError("requested-range continuity proof is missing")
        observed_gap = metadata.get("max_observed_tick_gap_seconds")
        allowed_gap = metadata.get("maximum_allowed_tick_gap_seconds")
        if isinstance(observed_gap, bool) or isinstance(allowed_gap, bool):
            raise TypeError("coverage gap proof must be numeric")
        try:
            observed_gap = float(observed_gap)
            allowed_gap = float(allowed_gap)
        except (TypeError, ValueError) as exc:
            raise TypeError("coverage gap proof must be numeric") from exc
        if (
            not math.isfinite(observed_gap)
            or not math.isfinite(allowed_gap)
            or observed_gap < 0
            or allowed_gap <= 0
            or observed_gap > allowed_gap
            or allowed_gap > MAX_OBSERVED_TICK_GAP_SECONDS
        ):
            raise ValueError("coverage continuity proof is outside its bound")
        metadata_binding = str(metadata.get("broker_binding_sha256") or "").lower()
        if metadata_binding != binding_hash:
            raise ValueError("coverage proof is not bound to the MT5 identity")
        finalized_through = metadata.get("finalized_through_at_utc")
        if finalized_through is not None:
            require_utc("finalized_through_at_utc", finalized_through)
        coverage_start = metadata["requested_start_at_utc"]
        coverage_end = metadata["requested_end_at_utc"]
        tail_requery = metadata["tail_requery_from_at_utc"]
        if not (
            coverage_start
            <= tail_requery
            <= coverage_end
        ):
            raise ValueError("tail re-query boundary is outside requested coverage")
        if not (
            metadata.get("boundary_tolerance_seconds") == BOUNDARY_PROBE_SECONDS
        ):
            raise ValueError("coverage boundary tolerance is invalid")
        left_mode = metadata.get("left_boundary_mode")
        right_mode = metadata.get("right_boundary_mode")
        left_at = metadata["observed_left_boundary_at_utc"]
        right_at = metadata["observed_right_boundary_at_utc"]
        if left_mode == "BRACKETED":
            left_valid = left_at <= coverage_start
        elif left_mode == "SESSION_OPEN_FIRST_TICK":
            left_valid = (
                coverage_start
                <= left_at
                <= coverage_start
                + timedelta(seconds=BOUNDARY_PROBE_SECONDS)
            )
        else:
            left_valid = False
        if right_mode == "BRACKETED":
            right_valid = right_at >= coverage_end
        elif right_mode == "SESSION_CLOSE_LAST_TICK":
            right_valid = (
                coverage_end
                - timedelta(seconds=BOUNDARY_PROBE_SECONDS)
                <= right_at
                < coverage_end
            )
        else:
            right_valid = False
        if not left_valid or not right_valid:
            raise ValueError("observed broker boundary mode is invalid")

        counts = {
            field: _exact_nonnegative_int(metadata.get(field), field)
            for field in (
                "collected_tick_rows",
                "archived_tick_rows",
                "tail_tick_rows",
                "finalized_bar_rows",
            )
        }
        if counts["collected_tick_rows"] != (
            counts["archived_tick_rows"] + counts["tail_tick_rows"]
        ):
            raise ValueError("archived and tail tick rows do not reconcile")
        if finalized_through is None:
            if tail_requery != coverage_start or counts["finalized_bar_rows"]:
                raise ValueError("tail-only coverage boundary is inconsistent")
        elif (
            finalized_through != tail_requery
            or not coverage_start < finalized_through <= coverage_end
            or counts["finalized_bar_rows"] <= 0
        ):
            raise ValueError("finalized coverage boundary is inconsistent")

        ranges = metadata.get("bar_tick_ranges")
        if type(ranges) is not tuple or any(not isinstance(item, Mapping) for item in ranges):
            raise TypeError("bar_tick_ranges must be a tuple of mappings")
        if len(ranges) != counts["finalized_bar_rows"]:
            raise ValueError("bar tick ranges do not reconcile to finalized bars")
        frozen_ranges = []
        previous_open: datetime | None = None
        ranged_tick_rows = 0
        for item in ranges:
            normalized_range = dict(item)
            open_time = require_utc(
                "bar range open_time_utc", normalized_range.get("open_time_utc")
            )
            open_timestamp = pd.Timestamp(open_time)
            if open_timestamp.value % (TIMEFRAME_SECONDS * 1_000_000_000) != 0:
                raise ValueError("bar tick range is not M15 aligned")
            if (
                finalized_through is None
                or open_time < coverage_start
                or open_time + pd.to_timedelta(TIMEFRAME_SECONDS, unit="s")
                > finalized_through
                or (previous_open is not None and open_time <= previous_open)
            ):
                raise ValueError("bar tick ranges are outside finalized coverage")
            first_msc = _exact_nonnegative_int(
                normalized_range.get("first_time_msc"), "bar range first_time_msc"
            )
            last_msc = _exact_nonnegative_int(
                normalized_range.get("last_time_msc"), "bar range last_time_msc"
            )
            if last_msc < first_msc:
                raise ValueError("bar tick range is reversed")
            tick_rows = _exact_nonnegative_int(
                normalized_range.get("tick_rows"), "bar range tick_rows"
            )
            if tick_rows <= 0:
                raise ValueError("bar tick range cannot be empty")
            open_msc = open_timestamp.value // 1_000_000
            close_msc = open_msc + TIMEFRAME_SECONDS * 1000
            if not open_msc <= first_msc <= last_msc < close_msc:
                raise ValueError("bar tick timestamps are outside their M15 bar")
            ranged_tick_rows += tick_rows
            previous_open = open_time
            frozen_ranges.append(MappingProxyType(normalized_range))
        if ranged_tick_rows != counts["archived_tick_rows"]:
            raise ValueError("bar tick rows do not reconcile to archived ticks")
        metadata["bar_tick_ranges"] = tuple(frozen_ranges)

        tail_fields = (
            metadata.get("tail_first_at_utc"),
            metadata.get("tail_last_at_utc"),
            metadata.get("tail_first_time_msc"),
            metadata.get("tail_last_time_msc"),
        )
        if counts["tail_tick_rows"] == 0:
            if any(value is not None for value in tail_fields):
                raise ValueError("empty tail cannot claim tick boundaries")
        else:
            tail_first_at = require_utc("tail_first_at_utc", tail_fields[0])
            tail_last_at = require_utc("tail_last_at_utc", tail_fields[1])
            tail_first_msc = _exact_nonnegative_int(
                tail_fields[2], "tail_first_time_msc"
            )
            tail_last_msc = _exact_nonnegative_int(
                tail_fields[3], "tail_last_time_msc"
            )
            if not tail_requery <= tail_first_at <= tail_last_at <= coverage_end:
                raise ValueError("tail tick timestamps are outside re-query coverage")
            if tail_last_msc < tail_first_msc:
                raise ValueError("tail tick millisecond range is reversed")
            if (
                pd.Timestamp(tail_first_at).value // 1_000_000 != tail_first_msc
                or pd.Timestamp(tail_last_at).value // 1_000_000 != tail_last_msc
            ):
                raise ValueError("tail UTC and millisecond boundaries disagree")

        if has_raw:
            if counts["archived_tick_rows"] <= 0 or counts["finalized_bar_rows"] <= 0:
                raise ValueError("finalized evidence receipts cannot be empty")
            raw_receipt = dict(self.raw_tick_partition)
            bar_receipt = dict(self.finalized_bar_segment)
            if (
                raw_receipt.get("contract_id") != self.contract_id
                or bar_receipt.get("contract_id") != self.contract_id
                or raw_receipt.get("symbol") != self.symbol
                or bar_receipt.get("symbol") != self.symbol
            ):
                raise ValueError("evidence receipts are not bound to this export")
            if _exact_nonnegative_int(raw_receipt.get("rows"), "raw receipt rows") != counts[
                "archived_tick_rows"
            ]:
                raise ValueError("raw receipt rows do not match coverage metadata")
            if _exact_nonnegative_int(bar_receipt.get("rows"), "bar receipt rows") != counts[
                "finalized_bar_rows"
            ]:
                raise ValueError("bar receipt rows do not match coverage metadata")
            raw_receipt["partition_payload_sha256"] = _receipt_hash(
                raw_receipt, "partition_payload_sha256"
            )
            bar_receipt["segment_payload_sha256"] = _receipt_hash(
                bar_receipt, "segment_payload_sha256"
            )
            object.__setattr__(self, "raw_tick_partition", MappingProxyType(raw_receipt))
            object.__setattr__(self, "finalized_bar_segment", MappingProxyType(bar_receipt))
            commit = self.paired_commit_receipt
            if (
                commit.contract_id != self.contract_id
                or commit.symbol != self.symbol
                or commit.raw_partition_payload_sha256
                != raw_receipt["partition_payload_sha256"]
                or commit.bar_segment_payload_sha256
                != bar_receipt["segment_payload_sha256"]
                or commit.coverage_metadata_sha256
                != canonical_evidence_payload_sha256(_evidence_payload(metadata))
                or commit.broker_binding_sha256 != binding_hash
            ):
                raise ValueError("paired append receipt does not bind this export")
        elif counts["archived_tick_rows"] or counts["finalized_bar_rows"]:
            raise ValueError("tail-only exports cannot claim archived evidence")

        object.__setattr__(self, "coverage_metadata", MappingProxyType(metadata))


@dataclass(frozen=True)
class M15AggregationResult:
    finalized_bars: pd.DataFrame
    evidence_ticks: pd.DataFrame
    tail_ticks: pd.DataFrame
    coverage_start_at: datetime
    coverage_end_at: datetime
    finalized_through_at: datetime | None
    tail_requery_from_at: datetime
    bar_tick_ranges: tuple[Mapping[str, object], ...]
    coverage_proof: Mapping[str, object]

    def __post_init__(self) -> None:
        for field in ("finalized_bars", "evidence_ticks", "tail_ticks"):
            if not isinstance(getattr(self, field), pd.DataFrame):
                raise TypeError(f"{field} must be a DataFrame")
        require_utc("coverage_start_at", self.coverage_start_at)
        require_utc("coverage_end_at", self.coverage_end_at)
        require_utc("tail_requery_from_at", self.tail_requery_from_at)
        if self.finalized_through_at is not None:
            require_utc("finalized_through_at", self.finalized_through_at)
        if self.coverage_end_at <= self.coverage_start_at:
            raise ValueError("coverage window must have positive duration")
        if not self.coverage_start_at <= self.tail_requery_from_at <= self.coverage_end_at:
            raise ValueError("tail re-query boundary is outside coverage")
        if self.finalized_bars.empty != (self.finalized_through_at is None):
            raise ValueError("finalized bar boundary is inconsistent")
        if len(self.bar_tick_ranges) != len(self.finalized_bars):
            raise ValueError("bar tick ranges do not reconcile to finalized bars")
        if not isinstance(self.coverage_proof, Mapping):
            raise TypeError("coverage_proof must be a mapping")
        proof = dict(self.coverage_proof)
        if (
            proof.get("coverage_boundary_proven") is not True
            or proof.get("coverage_continuity_proven") is not True
        ):
            raise ValueError("aggregation requires fail-closed range coverage proof")
        object.__setattr__(self, "coverage_proof", MappingProxyType(proof))
        if self.finalized_through_at is None:
            if not self.evidence_ticks.empty or self.tail_requery_from_at != self.coverage_start_at:
                raise ValueError("tail-only aggregation boundary is inconsistent")
        elif self.finalized_through_at != self.tail_requery_from_at:
            raise ValueError("finalized and tail boundaries must be identical")

    def coverage_metadata(self) -> Mapping[str, object]:
        tail_first_at = None
        tail_last_at = None
        tail_first_msc = None
        tail_last_msc = None
        if not self.tail_ticks.empty:
            tail_first_at = self.tail_ticks["time_utc"].iloc[0].to_pydatetime()
            tail_last_at = self.tail_ticks["time_utc"].iloc[-1].to_pydatetime()
            tail_first_msc = int(self.tail_ticks["time_msc"].iloc[0])
            tail_last_msc = int(self.tail_ticks["time_msc"].iloc[-1])
        return {
            "schema_version": EXPORT_COVERAGE_SCHEMA_VERSION,
            "requested_start_at_utc": self.coverage_start_at,
            "requested_end_at_utc": self.coverage_end_at,
            "finalized_through_at_utc": self.finalized_through_at,
            "tail_requery_from_at_utc": self.tail_requery_from_at,
            "collected_tick_rows": len(self.evidence_ticks) + len(self.tail_ticks),
            "archived_tick_rows": len(self.evidence_ticks),
            "tail_tick_rows": len(self.tail_ticks),
            "finalized_bar_rows": len(self.finalized_bars),
            "tail_first_at_utc": tail_first_at,
            "tail_last_at_utc": tail_last_at,
            "tail_first_time_msc": tail_first_msc,
            "tail_last_time_msc": tail_last_msc,
            "bar_tick_ranges": tuple(dict(item) for item in self.bar_tick_ranges),
            **dict(self.coverage_proof),
        }


def normalize_mt5_ticks(raw_ticks: object) -> pd.DataFrame:
    """Normalize the official MT5 tick schema without synthesizing quotes."""

    frame = pd.DataFrame(raw_ticks)
    if frame.empty:
        raise ValueError("broker returned no ticks")
    required = {"bid", "ask"}
    if not required.issubset(frame.columns):
        raise ValueError("broker ticks are missing bid/ask")
    if "time_msc" not in frame:
        if "time" not in frame:
            raise ValueError("broker ticks are missing time_msc/time")
        frame["time_msc"] = pd.to_numeric(frame["time"], errors="raise") * 1000
    time_msc = pd.to_numeric(frame["time_msc"], errors="raise")
    if bool((time_msc < 0).any()) or bool((time_msc % 1 != 0).any()):
        raise ValueError("broker tick time_msc must contain nonnegative integers")
    frame["time_msc"] = time_msc.astype("int64")
    has_source_sequence = "source_sequence" in frame
    computed_time_utc = pd.to_datetime(frame["time_msc"], unit="ms", utc=True)
    if "time_utc" in frame:
        provided_time_utc = pd.to_datetime(frame["time_utc"], errors="raise", utc=True)
        if provided_time_utc.isna().any() or not bool(
            (provided_time_utc.astype("int64") == computed_time_utc.astype("int64")).all()
        ):
            raise ValueError("broker time_utc does not match time_msc")
    frame["time_utc"] = computed_time_utc
    for name, default in (
        ("last", 0.0),
        ("volume", 0.0),
        ("volume_real", 0.0),
        ("flags", 0),
    ):
        if name not in frame:
            frame[name] = default
    for name in ("bid", "ask", "last", "volume", "volume_real", "flags"):
        frame[name] = pd.to_numeric(frame[name], errors="raise")
        if not all(math.isfinite(float(value)) for value in frame[name]):
            raise ValueError(f"broker tick {name} contains non-finite values")
    if bool((frame[["bid", "ask"]] <= 0).any().any()):
        raise ValueError("broker bid/ask must be positive")
    if bool((frame["ask"] < frame["bid"]).any()):
        raise ValueError("broker ask cannot be below bid")
    if bool((frame[["last", "volume", "volume_real", "flags"]] < 0).any().any()):
        raise ValueError("broker tick values cannot be negative")
    if bool((frame["flags"] % 1 != 0).any()):
        raise ValueError("broker tick flags must contain integers")
    frame["flags"] = frame["flags"].astype("int64")
    if has_source_sequence:
        sequence = pd.to_numeric(frame["source_sequence"], errors="raise")
        if bool((sequence % 1 != 0).any()):
            raise ValueError("broker source_sequence must contain integers")
        frame["source_sequence"] = sequence.astype("int64")
    identity_columns = list(_CANONICAL_TICK_PAYLOAD_COLUMNS)
    if has_source_sequence:
        identity_columns.append("source_sequence")
    if bool(frame.duplicated(subset=identity_columns, keep=False).any()):
        raise ValueError(
            "broker ticks contain indistinguishable duplicate broker tick records"
        )
    if has_source_sequence:
        frame = frame.sort_values("source_sequence", kind="mergesort").reset_index(
            drop=True
        )
        if bool((frame["source_sequence"].diff().dropna() != 1).any()):
            raise ValueError("broker source_sequence is not contiguous")
    else:
        # Ordinary MT5 copy_ticks_range results expose no authenticated sequence.
        # Preserve the broker-return order for ticks sharing one millisecond;
        # lexicographic reordering would invent an OHLC open/close sequence that
        # the broker never returned.
        frame = frame.reset_index(drop=True)
    if not frame["time_msc"].is_monotonic_increasing:
        raise ValueError("broker ticks are out of chronological order")
    columns = [
        "time_utc",
        "time_msc",
        "bid",
        "ask",
        "last",
        "volume",
        "volume_real",
        "flags",
    ]
    if has_source_sequence:
        columns.append("source_sequence")
    return frame.loc[:, columns].reset_index(drop=True)


def _coverage_boundary(
    ticks: pd.DataFrame,
    explicit: datetime | None,
    attr_name: str,
) -> datetime:
    value = explicit if explicit is not None else ticks.attrs.get(attr_name)
    if value is None:
        raise ValueError("tick coverage metadata is required to reject partial M15 bars")
    return require_utc(attr_name, value)


def _validated_coverage_proof(
    ticks: pd.DataFrame,
    coverage_start: datetime,
    coverage_end: datetime,
) -> Mapping[str, object]:
    attrs = ticks.attrs
    if (
        attrs.get("coverage_boundary_proven") is not True
        or attrs.get("coverage_continuity_proven") is not True
    ):
        raise ValueError("observed MT5 boundary and continuity proof is required")
    if (
        attrs.get("coverage_start_at_utc") != coverage_start
        or attrs.get("coverage_end_at_utc") != coverage_end
    ):
        raise ValueError("coverage proof does not match the requested range")
    left = require_utc(
        "observed_left_boundary_at_utc",
        attrs.get("observed_left_boundary_at_utc"),
    )
    right = require_utc(
        "observed_right_boundary_at_utc",
        attrs.get("observed_right_boundary_at_utc"),
    )
    pre_checked_at = require_utc(
        "broker_binding_pre_checked_at_utc",
        attrs.get("broker_binding_pre_checked_at_utc"),
    )
    post_checked_at = require_utc(
        "broker_binding_post_checked_at_utc",
        attrs.get("broker_binding_post_checked_at_utc"),
    )
    if pre_checked_at > post_checked_at:
        raise ValueError("broker binding post-check precedes its pre-check")
    try:
        boundary_tolerance = int(attrs.get("boundary_tolerance_seconds"))
    except (TypeError, ValueError) as exc:
        raise ValueError("coverage boundary tolerance is invalid") from exc
    if boundary_tolerance != BOUNDARY_PROBE_SECONDS:
        raise ValueError("coverage boundary tolerance is invalid")
    left_mode = attrs.get("left_boundary_mode")
    right_mode = attrs.get("right_boundary_mode")
    if left_mode == "BRACKETED":
        left_valid = left <= coverage_start
    elif left_mode == "SESSION_OPEN_FIRST_TICK":
        left_valid = (
            coverage_start
            <= left
            <= coverage_start + timedelta(seconds=boundary_tolerance)
        )
    else:
        left_valid = False
    if right_mode == "BRACKETED":
        right_valid = right >= coverage_end
    elif right_mode == "SESSION_CLOSE_LAST_TICK":
        right_valid = (
            coverage_end - timedelta(seconds=boundary_tolerance)
            <= right
            < coverage_end
        )
    else:
        right_valid = False
    if not left_valid or not right_valid:
        raise ValueError("observed MT5 boundary mode is invalid")
    try:
        observed_gap = float(attrs.get("max_observed_tick_gap_seconds"))
        allowed_gap = float(attrs.get("maximum_allowed_tick_gap_seconds"))
    except (TypeError, ValueError) as exc:
        raise ValueError("coverage continuity gap proof is invalid") from exc
    if (
        not math.isfinite(observed_gap)
        or not math.isfinite(allowed_gap)
        or observed_gap < 0
        or allowed_gap <= 0
        or observed_gap > allowed_gap
        or allowed_gap > MAX_OBSERVED_TICK_GAP_SECONDS
    ):
        raise ValueError("coverage continuity gap proof failed")
    binding_hash = str(attrs.get("broker_binding_sha256") or "").lower()
    if _SHA256_RE.fullmatch(binding_hash) is None:
        raise ValueError("coverage proof lacks broker binding")
    pre_observed_hash = str(
        attrs.get("broker_binding_pre_observed_facts_sha256") or ""
    ).lower()
    post_observed_hash = str(
        attrs.get("broker_binding_post_observed_facts_sha256") or ""
    ).lower()
    if (
        _SHA256_RE.fullmatch(pre_observed_hash) is None
        or _SHA256_RE.fullmatch(post_observed_hash) is None
        or pre_observed_hash != post_observed_hash
    ):
        raise ValueError("broker binding changed during tick collection")
    observed_facts = attrs.get("broker_binding_observed_facts")
    if not isinstance(observed_facts, Mapping):
        raise ValueError("broker binding observed facts are missing")
    normalized_observed_facts = _evidence_payload(observed_facts)
    if (
        canonical_evidence_payload_sha256(normalized_observed_facts)
        != pre_observed_hash
    ):
        raise ValueError("broker binding observed facts hash is invalid")
    return MappingProxyType(
        {
            "coverage_boundary_proven": True,
            "coverage_continuity_proven": True,
            "observed_left_boundary_at_utc": left,
            "observed_right_boundary_at_utc": right,
            "left_boundary_mode": left_mode,
            "right_boundary_mode": right_mode,
            "boundary_tolerance_seconds": boundary_tolerance,
            "max_observed_tick_gap_seconds": observed_gap,
            "maximum_allowed_tick_gap_seconds": allowed_gap,
            "broker_binding_sha256": binding_hash,
            "observed_facts_sha256": pre_observed_hash,
            "broker_binding_pre_observed_facts_sha256": pre_observed_hash,
            "broker_binding_post_observed_facts_sha256": post_observed_hash,
            "broker_binding_observed_facts": normalized_observed_facts,
            "broker_binding_pre_checked_at_utc": pre_checked_at,
            "broker_binding_post_checked_at_utc": post_checked_at,
        }
    )


def aggregate_m15_bid_ask_bars(
    ticks: pd.DataFrame,
    *,
    exported_at: datetime,
    coverage_start_at: datetime | None = None,
    coverage_end_at: datetime | None = None,
) -> M15AggregationResult:
    """Split a requested tick window into finalized evidence and a re-query tail."""

    require_utc("exported_at", exported_at)
    if not isinstance(ticks, pd.DataFrame) or ticks.empty:
        raise ValueError("ticks must be a non-empty DataFrame")
    required = {"time_utc", "time_msc", "bid", "ask", "volume_real"}
    if not required.issubset(ticks.columns):
        raise ValueError("normalized tick fields are missing")
    coverage_start = _coverage_boundary(
        ticks, coverage_start_at, "coverage_start_at_utc"
    )
    coverage_end = _coverage_boundary(ticks, coverage_end_at, "coverage_end_at_utc")
    if coverage_end <= coverage_start:
        raise ValueError("coverage_end_at must be after coverage_start_at")
    if coverage_end > exported_at:
        raise ValueError("tick coverage cannot extend beyond exported_at")
    coverage_proof = _validated_coverage_proof(
        ticks,
        coverage_start,
        coverage_end,
    )

    start_timestamp = pd.Timestamp(coverage_start)
    if start_timestamp.value % (TIMEFRAME_SECONDS * 1_000_000_000) != 0:
        raise ValueError("coverage_start_at must align to an M15 boundary")

    normalized = normalize_mt5_ticks(ticks)
    first_tick = normalized["time_utc"].iloc[0]
    last_tick = normalized["time_utc"].iloc[-1]
    if first_tick < start_timestamp or last_tick > pd.Timestamp(coverage_end):
        raise ValueError("ticks fall outside declared coverage")

    working = normalized.set_index("time_utc")
    grouped = working.groupby(pd.Grouper(freq="15min", origin="epoch", label="left"))
    bars = grouped.agg(
        bid_open=("bid", "first"),
        bid_high=("bid", "max"),
        bid_low=("bid", "min"),
        bid_close=("bid", "last"),
        ask_open=("ask", "first"),
        ask_high=("ask", "max"),
        ask_low=("ask", "min"),
        ask_close=("ask", "last"),
        tick_volume=("bid", "size"),
        real_volume=("volume_real", "sum"),
        first_time_msc=("time_msc", "first"),
        last_time_msc=("time_msc", "last"),
    ).dropna()
    bars.index.name = "open_time_utc"
    bars = bars.reset_index()
    close_delta = pd.to_timedelta(TIMEFRAME_SECONDS, unit="s")
    finalization_delta = pd.to_timedelta(FINALIZATION_LAG_SECONDS, unit="s")
    eligible = (
        (bars["open_time_utc"] >= start_timestamp)
        & (bars["open_time_utc"] + close_delta <= pd.Timestamp(coverage_end))
        & (
            bars["open_time_utc"] + close_delta + finalization_delta
            <= pd.Timestamp(exported_at)
        )
    )
    finalized = bars.loc[eligible].copy().reset_index(drop=True)

    finalized_through: datetime | None = None
    if finalized.empty:
        tail_requery = coverage_start
    else:
        finalized_through = (
            finalized["open_time_utc"].iloc[-1] + close_delta
        ).to_pydatetime()
        tail_requery = finalized_through

    requery_timestamp = pd.Timestamp(tail_requery)
    evidence_ticks = normalized.loc[
        normalized["time_utc"] < requery_timestamp
    ].reset_index(drop=True)
    tail_ticks = normalized.loc[
        normalized["time_utc"] >= requery_timestamp
    ].reset_index(drop=True)
    if not finalized.empty and int(finalized["tick_volume"].sum()) != len(evidence_ticks):
        raise ValueError("finalized bars do not reconcile to archived raw ticks")

    ranges = tuple(
        MappingProxyType(
            {
                "open_time_utc": row.open_time_utc.to_pydatetime(),
                "first_time_msc": int(row.first_time_msc),
                "last_time_msc": int(row.last_time_msc),
                "tick_rows": int(row.tick_volume),
            }
        )
        for row in finalized.itertuples(index=False)
    )
    finalized = finalized.drop(columns=["first_time_msc", "last_time_msc"])
    if not finalized.empty:
        finalized["is_final"] = True
    else:
        finalized["is_final"] = pd.Series(dtype=bool)
    return M15AggregationResult(
        finalized_bars=finalized,
        evidence_ticks=evidence_ticks,
        tail_ticks=tail_ticks,
        coverage_start_at=coverage_start,
        coverage_end_at=coverage_end,
        finalized_through_at=finalized_through,
        tail_requery_from_at=tail_requery,
        bar_tick_ranges=ranges,
        coverage_proof=coverage_proof,
    )


def finalized_m15_bid_ask_bars(
    ticks: pd.DataFrame,
    *,
    exported_at: datetime,
    coverage_start_at: datetime | None = None,
    coverage_end_at: datetime | None = None,
) -> pd.DataFrame:
    """Derive only bars whose close plus finalization lag has elapsed."""
    result = aggregate_m15_bid_ask_bars(
        ticks,
        exported_at=exported_at,
        coverage_start_at=coverage_start_at,
        coverage_end_at=coverage_end_at,
    )
    if result.finalized_bars.empty:
        raise ValueError("no M15 bar has passed the finalization lag")
    bars = result.finalized_bars.copy()
    bars.attrs["coverage_metadata"] = result.coverage_metadata()
    return bars


def paired_append_recovery_status(
    artifact_root: str | Path,
    contract_id: str,
    symbol: str,
) -> dict[str, object]:
    """Report the authoritative validation-evidence pending marker, if any.

    This function creates no recovery state.  HMAC validation remains inside
    ``append_paired_forward_evidence`` and the evidence verifier; this is only a
    conservative status projection over that signed journal.
    """

    contract = _safe_id(contract_id, "contract_id")
    normalized_symbol = _safe_id(symbol.upper(), "symbol")
    forward_root = Path(artifact_root) / "forward"
    contract_directory = forward_root / contract
    pending_directory = contract_directory / "paired_pending"
    pending_path = pending_directory / f"{normalized_symbol}.json"
    for path in (forward_root, contract_directory, pending_directory, pending_path):
        if path.is_symlink():
            raise PairedAppendRecoveryRequired(
                "validation-evidence recovery path cannot be a symlink"
            )
    pending_paths = (pending_path,) if pending_path.exists() else ()
    pending: list[dict[str, object]] = []
    for path in pending_paths:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PairedAppendRecoveryRequired(
                f"paired append recovery marker is unreadable: {path.name}"
            ) from exc
        if not isinstance(value, dict):
            raise PairedAppendRecoveryRequired(
                f"paired append recovery marker is invalid: {path.name}"
            )
        pending.append(value)
    return {
        "blocked": bool(pending),
        "pending_exports": tuple(pending),
        "authority": "VALIDATION_EVIDENCE_HMAC_JOURNAL",
    }


class MT5EvidenceExporter:
    """Read-only collector fenced to one exact connected MT5 identity."""

    def __init__(
        self,
        mt5_module: Any,
        *,
        binding: BrokerExportBinding,
        max_observed_tick_gap_seconds: int = MAX_OBSERVED_TICK_GAP_SECONDS,
        signing_key: bytes | str | None = None,
        build_identity_provider: Callable[[], Mapping[str, object]] | None = None,
        clock_provider: Callable[[], object] | None = None,
    ):
        required_methods = (
            "copy_ticks_range",
            "account_info",
            "terminal_info",
            "symbol_info",
        )
        if mt5_module is None or any(
            not callable(getattr(mt5_module, method, None))
            for method in required_methods
        ):
            raise TypeError(
                "mt5_module must expose read-only "
                "copy_ticks_range/account_info/terminal_info/symbol_info"
            )
        if type(binding) is not BrokerExportBinding:
            raise TypeError("binding must be BrokerExportBinding")
        if (
            type(max_observed_tick_gap_seconds) is not int
            or not 0 < max_observed_tick_gap_seconds <= MAX_OBSERVED_TICK_GAP_SECONDS
        ):
            raise ValueError("max_observed_tick_gap_seconds is outside the safe bound")
        self.mt5 = mt5_module
        self.binding = binding
        self.max_observed_tick_gap_seconds = max_observed_tick_gap_seconds
        if not isinstance(signing_key, bytes) or len(signing_key) < 32:
            raise ValueError("bound broker evidence requires a 256-bit signing key")
        expected_key_id = "wincred-" + signing_key_fingerprint(signing_key)
        if binding.account_identity_key_id != expected_key_id:
            raise ValueError("account identity key does not match exporter signing key")
        self.signing_key = signing_key
        self.build_identity_provider = build_identity_provider
        self.clock_provider = clock_provider

    def _trusted_utc_now(self) -> datetime:
        value = (
            self.clock_provider()
            if self.clock_provider is not None
            else datetime.now(timezone.utc)
        )
        return require_utc("trusted clock", value)

    def _margin_mode_name(self, raw_value: object) -> str:
        try:
            value = int(raw_value)
        except (TypeError, ValueError) as exc:
            raise BrokerExportBindingError("MT5 account margin_mode is unavailable") from exc
        values = {
            int(getattr(self.mt5, "ACCOUNT_MARGIN_MODE_RETAIL_NETTING", 0)): "RETAIL_NETTING",
            int(getattr(self.mt5, "ACCOUNT_MARGIN_MODE_EXCHANGE", 1)): "EXCHANGE",
            int(getattr(self.mt5, "ACCOUNT_MARGIN_MODE_RETAIL_HEDGING", 2)): "RETAIL_HEDGING",
        }
        if value not in values:
            raise BrokerExportBindingError("MT5 account margin_mode is unsupported")
        return values[value]

    def _assert_broker_binding(self) -> Mapping[str, object]:
        account = _as_mapping(self.mt5.account_info())
        terminal = _as_mapping(self.mt5.terminal_info())
        symbol = _as_mapping(self.mt5.symbol_info(self.binding.broker_symbol))
        if not account or not terminal or not symbol:
            raise BrokerExportBindingError(
                "MT5 account, terminal, or symbol facts are unavailable"
            )
        try:
            actual_trade_mode = int(account["trade_mode"])
        except (KeyError, TypeError, ValueError) as exc:
            raise BrokerExportBindingError("MT5 account identity is incomplete") from exc
        demo_mode = int(getattr(self.mt5, "ACCOUNT_TRADE_MODE_DEMO", 0))
        real_mode = int(getattr(self.mt5, "ACCOUNT_TRADE_MODE_REAL", 2))
        expected_trade_mode = (
            demo_mode if self.binding.environment == "DEMO" else real_mode
        )
        failures: list[str] = []
        try:
            actual_identity = account_identity_sha256(
                account,
                self.signing_key,
                environment=self.binding.environment,
            )
        except ValueError as exc:
            raise BrokerExportBindingError("MT5 account identity is incomplete") from exc
        if actual_identity != self.binding.expected_account_identity_sha256:
            failures.append("ACCOUNT_IDENTITY")
        if str(account.get("company", "") or "") != self.binding.broker_legal_name:
            failures.append("ACCOUNT_BROKER")
        if str(account.get("server", "") or "") != self.binding.server:
            failures.append("ACCOUNT_SERVER")
        if actual_trade_mode != expected_trade_mode:
            failures.append("ACCOUNT_ENVIRONMENT")
        if str(account.get("currency", "") or "").upper() != self.binding.account_currency:
            failures.append("ACCOUNT_CURRENCY")
        if account.get("trade_allowed") is not False:
            failures.append("ACCOUNT_TRADE_ALLOWED")
        if account.get("trade_expert") is not self.binding.account_trade_expert:
            failures.append("ACCOUNT_TRADE_EXPERT")
        if terminal.get("trade_allowed") is not False:
            failures.append("TERMINAL_TRADE_ALLOWED")
        if terminal.get("tradeapi_disabled") is not True:
            failures.append("TERMINAL_TRADEAPI_ENABLED")
        spec = self.binding.instrument_spec
        exact_integer_fields = {
            "digits": "digits",
            "stops_level_points": "trade_stops_level",
            "freeze_level_points": "trade_freeze_level",
        }
        for expected_field, mt5_field in exact_integer_fields.items():
            try:
                actual = int(symbol[mt5_field])
            except (KeyError, TypeError, ValueError):
                failures.append(expected_field.upper())
                continue
            if actual != int(spec[expected_field]):
                failures.append(expected_field.upper())
        exact_decimal_fields = {
            "point": "point",
            "tick_size": "trade_tick_size",
            "contract_size": "trade_contract_size",
            "volume_min": "volume_min",
            "volume_max": "volume_max",
            "volume_step": "volume_step",
        }
        for expected_field, mt5_field in exact_decimal_fields.items():
            try:
                actual = _decimal(symbol[mt5_field], mt5_field)
            except (KeyError, ValueError):
                failures.append(expected_field.upper())
                continue
            if actual != Decimal(str(spec[expected_field])):
                failures.append(expected_field.upper())
        # MT5 reports trade_tick_value in the account currency. It therefore
        # moves with conversion rates when profit currency != account currency
        # (for example EURUSD on a JPY account). Availability and positivity
        # are broker facts; exact equality is not an immutable symbol identity.
        # Runtime risk remains based on order_calc_profit(), never this snapshot.
        try:
            _decimal(symbol["trade_tick_value"], "trade_tick_value")
        except (KeyError, ValueError):
            failures.append("TICK_VALUE_UNAVAILABLE")
        if str(symbol.get("currency_profit", "") or "").upper() != spec["profit_currency"]:
            failures.append("PROFIT_CURRENCY")
        if str(symbol.get("currency_margin", "") or "").upper() != spec["margin_currency"]:
            failures.append("MARGIN_CURRENCY")
        if self._margin_mode_name(account.get("margin_mode")) != spec["margin_mode"]:
            failures.append("MARGIN_MODE")
        if failures:
            raise BrokerExportBindingError(
                "MT5 read-only binding drifted: " + ",".join(sorted(set(failures)))
            )
        checked_at = self._trusted_utc_now()
        observed_facts = {
            "account_identity_sha256": actual_identity,
            "account_identity_scheme": self.binding.account_identity_scheme,
            "account_identity_key_id": self.binding.account_identity_key_id,
            "account_alias_sha256": self.binding.public_binding_payload[
                "account_alias_sha256"
            ],
            "broker_legal_name": self.binding.broker_legal_name,
            "server": self.binding.server,
            "environment": self.binding.environment,
            "account_currency": self.binding.account_currency,
            "account_trade_allowed": account["trade_allowed"],
            "account_trade_expert": account["trade_expert"],
            "terminal_trade_allowed": terminal["trade_allowed"],
            "terminal_tradeapi_disabled": terminal["tradeapi_disabled"],
            "canonical_symbol": self.binding.canonical_symbol,
            "broker_symbol": self.binding.broker_symbol,
            "instrument_spec_sha256": canonical_evidence_payload_sha256(spec),
            "account_identity_match": True,
        }
        return MappingProxyType(
            {
                **observed_facts,
                "checked_at_utc": checked_at,
                "broker_binding_sha256": self.binding.public_binding_sha256,
                "observed_facts_sha256": canonical_evidence_payload_sha256(
                    observed_facts
                ),
            }
        )

    def _assert_export_contract_binding(
        self,
        *,
        canonical_symbol: str,
        broker_symbol: str,
        source: Mapping[str, object],
        instrument_spec: Mapping[str, object],
    ) -> None:
        if (
            canonical_symbol.upper() != self.binding.canonical_symbol
            or broker_symbol != self.binding.broker_symbol
        ):
            raise BrokerExportBindingError("requested symbol is outside exporter binding")
        expected_source = {
            "provider_kind": "BROKER_EXPORT",
            "broker_legal_name": self.binding.broker_legal_name,
            "broker_server": self.binding.server,
            "environment": self.binding.environment,
            "account_identity_sha256": (
                self.binding.expected_account_identity_sha256
            ),
            "account_identity_scheme": self.binding.account_identity_scheme,
            "account_identity_key_id": self.binding.account_identity_key_id,
            "account_currency": self.binding.account_currency,
            "account_trade_allowed": self.binding.account_trade_allowed,
            "account_trade_expert": self.binding.account_trade_expert,
            "terminal_trade_allowed": self.binding.terminal_trade_allowed,
            "terminal_tradeapi_disabled": self.binding.terminal_tradeapi_disabled,
            "canonical_symbol": self.binding.canonical_symbol,
            "broker_symbol": self.binding.broker_symbol,
        }
        if not isinstance(source, Mapping) or any(
            source.get(field) != value for field, value in expected_source.items()
        ):
            raise BrokerExportBindingError("broker evidence source does not match MT5 binding")
        normalized_spec = _normalize_instrument_spec(
            instrument_spec,
            self.binding.canonical_symbol,
        )
        if canonical_sha256(normalized_spec) != canonical_sha256(
            self.binding.instrument_spec
        ):
            raise BrokerExportBindingError("instrument spec does not match MT5 binding")

    def collect(
        self,
        broker_symbol: str,
        *,
        start_utc: datetime,
        end_utc: datetime,
        session_open_boundary: bool = False,
        session_close_boundary: bool = False,
    ) -> pd.DataFrame:
        require_utc("start_utc", start_utc)
        require_utc("end_utc", end_utc)
        if end_utc <= start_utc:
            raise ValueError("end_utc must be after start_utc")
        if (
            type(session_open_boundary) is not bool
            or type(session_close_boundary) is not bool
        ):
            raise TypeError("session boundary flags must be booleans")
        if broker_symbol != self.binding.broker_symbol:
            raise BrokerExportBindingError("broker symbol does not match exporter binding")
        pre_binding_receipt = self._assert_broker_binding()
        probe_start = start_utc - timedelta(seconds=BOUNDARY_PROBE_SECONDS)
        probe_end = end_utc + timedelta(seconds=BOUNDARY_PROBE_SECONDS)
        raw = self.mt5.copy_ticks_range(
            require_text("broker_symbol", broker_symbol),
            probe_start,
            probe_end,
            getattr(self.mt5, "COPY_TICKS_ALL"),
        )
        post_binding_receipt = self._assert_broker_binding()
        pre_identity = dict(pre_binding_receipt)
        post_identity = dict(post_binding_receipt)
        pre_identity.pop("checked_at_utc", None)
        post_identity.pop("checked_at_utc", None)
        if pre_identity != post_identity:
            raise BrokerExportBindingError(
                "MT5 read-only binding changed during tick collection"
            )
        observed = normalize_mt5_ticks(raw)
        probe_start_ts = pd.Timestamp(probe_start)
        probe_end_ts = pd.Timestamp(probe_end)
        if (
            observed["time_utc"].iloc[0] < probe_start_ts
            or observed["time_utc"].iloc[-1] > probe_end_ts
        ):
            raise ValueError("broker returned ticks outside the boundary probe")
        start_ts = pd.Timestamp(start_utc)
        end_ts = pd.Timestamp(end_utc)
        left = observed.loc[observed["time_utc"] <= start_ts]
        right = observed.loc[observed["time_utc"] >= end_ts]
        if left.empty:
            if not session_open_boundary:
                raise ValueError(
                    "broker range lacks observed left/right boundary ticks"
                )
            first = observed.loc[
                (observed["time_utc"] >= start_ts)
                & (
                    observed["time_utc"]
                    <= start_ts
                    + pd.to_timedelta(BOUNDARY_PROBE_SECONDS, unit="s")
                )
            ]
            if first.empty:
                raise ValueError(
                    "broker range lacks a timely session-open first tick"
                )
            left_at = first["time_utc"].iloc[0]
            left_mode = "SESSION_OPEN_FIRST_TICK"
        else:
            left_at = left["time_utc"].iloc[-1]
            left_mode = "BRACKETED"
        if right.empty:
            if not session_close_boundary:
                raise ValueError(
                    "broker range lacks observed left/right boundary ticks"
                )
            last = observed.loc[
                (observed["time_utc"] < end_ts)
                & (
                    observed["time_utc"]
                    >= end_ts
                    - pd.to_timedelta(BOUNDARY_PROBE_SECONDS, unit="s")
                )
            ]
            if last.empty:
                raise ValueError(
                    "broker range lacks a timely session-close last tick"
                )
            right_at = last["time_utc"].iloc[-1]
            right_mode = "SESSION_CLOSE_LAST_TICK"
        else:
            right_at = right["time_utc"].iloc[0]
            right_mode = "BRACKETED"
        proof_window = observed.loc[
            (observed["time_utc"] >= left_at)
            & (observed["time_utc"] <= right_at)
        ]
        gaps = proof_window["time_msc"].diff().dropna() / 1000.0
        max_gap = float(gaps.max()) if not gaps.empty else 0.0
        if max_gap > self.max_observed_tick_gap_seconds:
            raise ValueError(
                "broker range lacks bounded observed tick continuity: "
                f"{max_gap:.3f}s"
            )
        ticks = observed.loc[
            (observed["time_utc"] >= start_ts)
            & (observed["time_utc"] < end_ts)
        ].reset_index(drop=True)
        if ticks.empty:
            raise ValueError("broker returned no ticks inside requested range")
        ticks.attrs["coverage_start_at_utc"] = start_utc
        ticks.attrs["coverage_end_at_utc"] = end_utc
        ticks.attrs["coverage_boundary_proven"] = True
        ticks.attrs["coverage_continuity_proven"] = True
        ticks.attrs["observed_left_boundary_at_utc"] = left_at.to_pydatetime()
        ticks.attrs["observed_right_boundary_at_utc"] = right_at.to_pydatetime()
        ticks.attrs["left_boundary_mode"] = left_mode
        ticks.attrs["right_boundary_mode"] = right_mode
        ticks.attrs["boundary_tolerance_seconds"] = BOUNDARY_PROBE_SECONDS
        ticks.attrs["max_observed_tick_gap_seconds"] = max_gap
        ticks.attrs[
            "maximum_allowed_tick_gap_seconds"
        ] = self.max_observed_tick_gap_seconds
        ticks.attrs["broker_binding_sha256"] = pre_binding_receipt[
            "broker_binding_sha256"
        ]
        ticks.attrs["broker_binding_pre_observed_facts_sha256"] = (
            pre_binding_receipt["observed_facts_sha256"]
        )
        ticks.attrs["broker_binding_post_observed_facts_sha256"] = (
            post_binding_receipt["observed_facts_sha256"]
        )
        ticks.attrs["broker_binding_observed_facts"] = MappingProxyType(
            {
                key: value
                for key, value in pre_binding_receipt.items()
                if key
                not in {
                    "checked_at_utc",
                    "broker_binding_sha256",
                    "observed_facts_sha256",
                }
            }
        )
        ticks.attrs["broker_binding_pre_checked_at_utc"] = pre_binding_receipt[
            "checked_at_utc"
        ]
        ticks.attrs["broker_binding_post_checked_at_utc"] = post_binding_receipt[
            "checked_at_utc"
        ]
        return ticks

    def export(
        self,
        *,
        artifact_root: str,
        contract_id: str,
        canonical_symbol: str,
        broker_symbol: str,
        source: Mapping[str, object],
        instrument_spec: Mapping[str, object],
        start_utc: datetime,
        end_utc: datetime,
        exported_at: datetime | None = None,
        session_open_boundary: bool = False,
        session_close_boundary: bool = False,
    ) -> BrokerExportResult:
        if exported_at is not None:
            require_utc("exported_at", exported_at)
        self._assert_export_contract_binding(
            canonical_symbol=canonical_symbol,
            broker_symbol=broker_symbol,
            source=source,
            instrument_spec=instrument_spec,
        )
        ticks = self.collect(
            broker_symbol,
            start_utc=start_utc,
            end_utc=end_utc,
            session_open_boundary=session_open_boundary,
            session_close_boundary=session_close_boundary,
        )
        aggregation_at = (
            exported_at if exported_at is not None else self._trusted_utc_now()
        )
        aggregation = aggregate_m15_bid_ask_bars(
            ticks,
            exported_at=aggregation_at,
            coverage_start_at=start_utc,
            coverage_end_at=end_utc,
        )
        coverage_metadata = aggregation.coverage_metadata()
        coverage_evidence_payload = _evidence_payload(coverage_metadata)
        broker_binding_payload = dict(self.binding.public_binding_payload)
        binding_hash = str(coverage_metadata["broker_binding_sha256"])
        coverage_metadata_hash = canonical_evidence_payload_sha256(
            coverage_evidence_payload
        )
        if aggregation.finalized_bars.empty:
            return BrokerExportResult(
                contract_id=contract_id,
                symbol=canonical_symbol,
                raw_tick_partition=None,
                finalized_bar_segment=None,
                exported_at=aggregation_at,
                coverage_metadata=coverage_metadata,
                broker_binding_sha256=binding_hash,
                status="TAIL_RETAINED_NO_FINALIZED_BAR",
            )
        recovery = paired_append_recovery_status(
            artifact_root,
            contract_id,
            canonical_symbol,
        )
        if recovery["blocked"]:
            raise PairedAppendRecoveryRequired(
                "prior paired append is incomplete; evidence export remains blocked"
            )
        expected_sequence = _paired_expected_sequence(
            artifact_root,
            contract_id,
            canonical_symbol,
        )
        committed_at = (
            exported_at if exported_at is not None else self._trusted_utc_now()
        )
        if committed_at < aggregation_at:
            raise ValueError("trusted clock moved backwards during broker export")
        export_id = "export_" + canonical_sha256(
            {
                "contract_id": contract_id,
                "symbol": canonical_symbol.upper(),
                "start_utc": start_utc,
                "end_utc": end_utc,
                "exported_at": committed_at,
                "expected_sequence": expected_sequence,
                "broker_binding_sha256": binding_hash,
            }
        )[:32]
        try:
            paired_result = append_paired_forward_evidence(
                artifact_root,
                contract_id,
                canonical_symbol,
                aggregation.evidence_ticks,
                aggregation.finalized_bars,
                source,
                instrument_spec,
                export_id=export_id,
                broker_binding=broker_binding_payload,
                coverage_metadata=coverage_evidence_payload,
                broker_binding_sha256=binding_hash,
                coverage_metadata_sha256=coverage_metadata_hash,
                exported_at=committed_at,
                expected_sequence=expected_sequence,
                signing_key=self.signing_key,
                build_identity_provider=self.build_identity_provider,
                clock_provider=self.clock_provider,
                capture_start_at=aggregation.coverage_start_at,
                capture_end_at=aggregation.finalized_through_at,
            )
            raw_receipt = paired_result["raw_tick_partition"]
            bar_receipt = paired_result["forward_segment"]
            evidence_commit = paired_result["paired_commit"]
            raw_payload_hash = _receipt_hash(
                raw_receipt,
                "partition_payload_sha256",
            )
            bar_payload_hash = _receipt_hash(
                bar_receipt,
                "segment_payload_sha256",
            )
            if (
                evidence_commit.get("export_id") != export_id
                or evidence_commit.get("broker_binding_sha256") != binding_hash
                or evidence_commit.get("coverage_metadata_sha256")
                != coverage_metadata_hash
                or evidence_commit.get("raw_partition_payload_sha256")
                != raw_payload_hash
                or evidence_commit.get("bar_segment_payload_sha256")
                != bar_payload_hash
            ):
                raise EvidenceValidationError(
                    "PAIRED_COMMIT_EXPORT_BINDING_MISMATCH"
                )
            commit = PairedAppendCommitReceipt(
                export_id=export_id,
                contract_id=contract_id,
                symbol=canonical_symbol,
                raw_partition_payload_sha256=raw_payload_hash,
                bar_segment_payload_sha256=bar_payload_hash,
                coverage_metadata_sha256=coverage_metadata_hash,
                broker_binding_sha256=binding_hash,
                sequence=evidence_commit.get("sequence"),
                paired_commit_payload_sha256=_receipt_hash(
                    evidence_commit,
                    "paired_commit_payload_sha256",
                ),
                paired_commit_hmac_sha256=_receipt_hash(
                    evidence_commit,
                    "paired_commit_hmac_sha256",
                ),
                committed_at=committed_at,
            )
        except Exception as exc:
            if (
                isinstance(exc, EvidenceValidationError)
                and exc.code == "PAIRED_EXPORT_ID_REPLAY"
            ):
                raise PairedAppendRecoveryRequired(
                    "this broker export is already committed; duplicate append is blocked"
                ) from exc
            if paired_append_recovery_status(
                artifact_root,
                contract_id,
                canonical_symbol,
            )["blocked"]:
                raise PairedAppendRecoveryRequired(
                    "paired raw/bar append was interrupted; signed recovery marker blocks evidence"
                ) from exc
            raise
        return BrokerExportResult(
            contract_id=contract_id,
            symbol=canonical_symbol,
            raw_tick_partition=raw_receipt,
            finalized_bar_segment=bar_receipt,
            exported_at=committed_at,
            coverage_metadata=coverage_metadata,
            broker_binding_sha256=binding_hash,
            status="FINALIZED_EVIDENCE_APPENDED",
            paired_commit_receipt=commit,
        )


__all__ = [
    "BOUNDARY_PROBE_SECONDS",
    "BrokerExportBinding",
    "BrokerExportBindingError",
    "BrokerExportResult",
    "EvidenceInstrumentIdentity",
    "EXPORT_COVERAGE_SCHEMA_VERSION",
    "FINALIZATION_LAG_SECONDS",
    "MAX_OBSERVED_TICK_GAP_SECONDS",
    "M15AggregationResult",
    "MT5EvidenceExporter",
    "PAIRED_APPEND_SCHEMA_VERSION",
    "PairedAppendCommitReceipt",
    "PairedAppendRecoveryRequired",
    "TIMEFRAME_SECONDS",
    "aggregate_m15_bid_ask_bars",
    "broker_export_binding_from_spec",
    "finalized_m15_bid_ask_bars",
    "normalize_mt5_ticks",
    "paired_append_recovery_status",
]
