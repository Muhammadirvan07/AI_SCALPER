"""Independent recalculation boundary for promotion evidence.

The caller supplies raw immutable observations, not aggregate statistics.  This
module recalculates every `LaneEvidence` field deterministically and delegates
only the final sealed readiness decision to :mod:`live_runtime.readiness`.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from datetime import datetime
import hashlib
import json
import math
import random
from typing import Any, Iterable, Mapping

from .contracts import require_hash, require_text, require_utc
from .readiness import LaneEvidence, LaneReadiness, evaluate_lane
from .promotion_evidence import (
    PromotionEvidenceReceipt,
    issue_promotion_evidence_receipt,
)


MAX_FINITE_PROFIT_FACTOR = 1_000_000_000.0
MIN_BOOTSTRAP_RESAMPLES = 2_000
_VALIDATION_RECEIPT_OBSERVATION_SEAL = object()


class PromotionCorpusError(ValueError):
    """Invalid or internally inconsistent raw promotion corpus."""

    def __init__(self, reason_code: str, detail: str = "") -> None:
        self.reason_code = str(reason_code or "").strip().upper()
        message = self.reason_code + (f": {detail}" if detail else "")
        super().__init__(message)


def _finite(value: object, field: str) -> float:
    if isinstance(value, bool):
        raise PromotionCorpusError("NON_FINITE_OBSERVATION", field)
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise PromotionCorpusError("NON_FINITE_OBSERVATION", field) from exc
    if not math.isfinite(numeric):
        raise PromotionCorpusError("NON_FINITE_OBSERVATION", field)
    return numeric


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _hash_payload(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class ClosedTradeObservation:
    trade_id: str
    symbol: str
    strategy: str
    config_sha256: str
    source: str
    closed_at_utc: datetime
    r_multiple_before_cost: float
    measured_cost_r: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "trade_id", require_text("trade_id", self.trade_id))
        object.__setattr__(self, "symbol", require_text("symbol", self.symbol, upper=True))
        object.__setattr__(
            self, "strategy", require_text("strategy", self.strategy, upper=True)
        )
        object.__setattr__(
            self,
            "config_sha256",
            require_hash("config_sha256", self.config_sha256),
        )
        source = require_text("source", self.source, upper=True)
        if source not in {"OOS", "BROKER_FORWARD"}:
            raise PromotionCorpusError("TRADE_SOURCE_INVALID", source)
        object.__setattr__(self, "source", source)
        require_utc("closed_at_utc", self.closed_at_utc)
        object.__setattr__(
            self,
            "r_multiple_before_cost",
            _finite(self.r_multiple_before_cost, "r_multiple_before_cost"),
        )
        measured_cost = _finite(self.measured_cost_r, "measured_cost_r")
        if measured_cost < 0:
            raise PromotionCorpusError("NEGATIVE_MEASURED_COST")
        object.__setattr__(self, "measured_cost_r", measured_cost)


@dataclass(frozen=True)
class RollingFoldObservation:
    fold_id: str
    expectancy_r: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "fold_id", require_text("fold_id", self.fold_id))
        object.__setattr__(
            self, "expectancy_r", _finite(self.expectancy_r, "expectancy_r")
        )


@dataclass(frozen=True)
class ParityObservation:
    fixture_id: str
    matching_leaf_count: int
    total_leaf_count: int
    full_parity: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "fixture_id", require_text("fixture_id", self.fixture_id))
        if (
            isinstance(self.matching_leaf_count, bool)
            or isinstance(self.total_leaf_count, bool)
            or not isinstance(self.matching_leaf_count, int)
            or not isinstance(self.total_leaf_count, int)
            or self.total_leaf_count <= 0
            or not 0 <= self.matching_leaf_count <= self.total_leaf_count
        ):
            raise PromotionCorpusError("PARITY_COUNTS_INVALID")
        expected = self.matching_leaf_count == self.total_leaf_count
        if type(self.full_parity) is not bool or self.full_parity is not expected:
            raise PromotionCorpusError("PARITY_FLAG_INCONSISTENT")


@dataclass(frozen=True)
class ValidationReceiptObservation:
    """Output of the validation-evidence verifier adapter.

    Production composition creates this only after calling
    ``validation_evidence.verify_validation_receipt`` with independent key and
    build-identity providers.  It carries no performance statistics.
    """

    receipt_sha256: str
    verified: bool
    immutable_snapshot_verified: bool
    forward_contract_verified: bool
    broker_source_aligned: bool
    ruleset_drift_detected: bool
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _VALIDATION_RECEIPT_OBSERVATION_SEAL:
            raise TypeError(
                "ValidationReceiptObservation must come from "
                "validation_receipt_from_verification"
            )
        object.__setattr__(
            self,
            "receipt_sha256",
            require_hash("receipt_sha256", self.receipt_sha256),
        )
        for field in (
            "verified",
            "immutable_snapshot_verified",
            "forward_contract_verified",
            "broker_source_aligned",
            "ruleset_drift_detected",
        ):
            if type(getattr(self, field)) is not bool:
                raise TypeError(f"{field} must be bool")


@dataclass(frozen=True)
class PromotionCorpus:
    symbol: str
    strategy: str
    config_sha256: str
    oos_trades: tuple[ClosedTradeObservation, ...]
    forward_trades: tuple[ClosedTradeObservation, ...]
    rolling_folds: tuple[RollingFoldObservation, ...]
    parity_reports: tuple[ParityObservation, ...]
    validation_receipt: ValidationReceiptObservation

    def __post_init__(self) -> None:
        symbol = require_text("symbol", self.symbol, upper=True)
        strategy = require_text("strategy", self.strategy, upper=True)
        config = require_hash("config_sha256", self.config_sha256)
        object.__setattr__(self, "symbol", symbol)
        object.__setattr__(self, "strategy", strategy)
        object.__setattr__(self, "config_sha256", config)
        for field, item_type in (
            ("oos_trades", ClosedTradeObservation),
            ("forward_trades", ClosedTradeObservation),
            ("rolling_folds", RollingFoldObservation),
            ("parity_reports", ParityObservation),
        ):
            values = getattr(self, field)
            if type(values) is not tuple or any(type(item) is not item_type for item in values):
                raise TypeError(f"{field} must be a tuple of {item_type.__name__}")
        if type(self.validation_receipt) is not ValidationReceiptObservation:
            raise TypeError(
                "validation_receipt must be exact ValidationReceiptObservation"
            )
        all_trades = self.oos_trades + self.forward_trades
        for trade in all_trades:
            if (
                trade.symbol != symbol
                or trade.strategy != strategy
                or trade.config_sha256 != config
            ):
                raise PromotionCorpusError("MIXED_LANE", trade.trade_id)
        if any(trade.source != "OOS" for trade in self.oos_trades) or any(
            trade.source != "BROKER_FORWARD" for trade in self.forward_trades
        ):
            raise PromotionCorpusError("SOURCE_PARTITION_MISMATCH")
        trade_ids = [trade.trade_id for trade in all_trades]
        if len(trade_ids) != len(set(trade_ids)):
            raise PromotionCorpusError("DUPLICATE_TRADE_ID")
        fold_ids = [fold.fold_id for fold in self.rolling_folds]
        if len(self.rolling_folds) != 5 or len(fold_ids) != len(set(fold_ids)):
            raise PromotionCorpusError("ROLLING_FOLD_CORPUS_INVALID")
        parity_ids = [report.fixture_id for report in self.parity_reports]
        if not parity_ids or len(parity_ids) != len(set(parity_ids)):
            raise PromotionCorpusError("PARITY_CORPUS_INVALID")
        if self.oos_trades and self.forward_trades:
            if max(item.closed_at_utc for item in self.oos_trades) >= min(
                item.closed_at_utc for item in self.forward_trades
            ):
                raise PromotionCorpusError("SOURCE_TIME_OVERLAP")


@dataclass(frozen=True)
class IndependentPromotionAssessment:
    lane_evidence: LaneEvidence
    readiness: LaneReadiness
    validation_receipt_sha256: str
    bootstrap_receipt_sha256: str
    parity_corpus_sha256: str
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    promotion_eligible: bool = False
    max_lot: float = 0.01

    def __post_init__(self) -> None:
        if (
            self.live_allowed
            or self.safe_to_demo_auto_order
            or self.promotion_eligible
            or self.max_lot != 0.01
        ):
            raise ValueError("independent issuer safety locks cannot be overridden")


def _adjusted(trades: Iterable[ClosedTradeObservation], multiplier: float) -> list[float]:
    return [
        trade.r_multiple_before_cost - multiplier * trade.measured_cost_r
        for trade in trades
    ]


def _profit_factor(values: Iterable[float]) -> float:
    sequence = list(values)
    gross_profit = sum(value for value in sequence if value > 0)
    gross_loss = -sum(value for value in sequence if value < 0)
    if gross_loss <= 0:
        return MAX_FINITE_PROFIT_FACTOR if gross_profit > 0 else 0.0
    return gross_profit / gross_loss


def _max_drawdown_percent(values: Iterable[float]) -> float:
    equity = 100.0
    peak = equity
    maximum = 0.0
    for value in values:
        equity += value
        peak = max(peak, equity)
        if peak > 0:
            maximum = max(maximum, (peak - equity) / peak * 100.0)
    return maximum


def _bootstrap_lower_bound(
    values: tuple[float, ...],
    *,
    seed: int,
    resamples: int,
) -> tuple[float, str]:
    if not values:
        return 0.0, _hash_payload({"seed": seed, "resamples": resamples, "means": []})
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise TypeError("bootstrap_seed must be an integer")
    if isinstance(resamples, bool) or not isinstance(resamples, int) or resamples < MIN_BOOTSTRAP_RESAMPLES:
        raise ValueError(f"bootstrap_resamples must be at least {MIN_BOOTSTRAP_RESAMPLES}")
    generator = random.Random(seed)
    count = len(values)
    means = sorted(
        sum(values[generator.randrange(count)] for _ in range(count)) / count
        for _ in range(resamples)
    )
    index = int(math.floor(0.025 * (resamples - 1)))
    receipt_payload = {
        "schema_version": "promotion-bootstrap-v1",
        "seed": seed,
        "resamples": resamples,
        "sample_sha256": hashlib.sha256(
            _canonical_json({"values": list(values)})
        ).hexdigest(),
        "lower_bound": means[index],
    }
    return means[index], _hash_payload(receipt_payload)


def evaluate_promotion_corpus(
    corpus: PromotionCorpus,
    *,
    bootstrap_seed: int,
    bootstrap_resamples: int = MIN_BOOTSTRAP_RESAMPLES,
) -> IndependentPromotionAssessment:
    if not isinstance(corpus, PromotionCorpus):
        raise TypeError("corpus must be PromotionCorpus")
    oos_values = _adjusted(corpus.oos_trades, 1.0)
    forward_values = _adjusted(corpus.forward_trades, 1.0)
    combined = tuple(oos_values + forward_values)
    lower_bound, bootstrap_hash = _bootstrap_lower_bound(
        combined,
        seed=bootstrap_seed,
        resamples=bootstrap_resamples,
    )
    if len(corpus.forward_trades) >= 2:
        first = min(item.closed_at_utc for item in corpus.forward_trades)
        last = max(item.closed_at_utc for item in corpus.forward_trades)
        forward_weeks = (last - first).total_seconds() / (7 * 24 * 60 * 60)
    else:
        forward_weeks = 0.0
    matching = sum(item.matching_leaf_count for item in corpus.parity_reports)
    total = sum(item.total_leaf_count for item in corpus.parity_reports)
    parity_percent = 100.0 * matching / total
    parity_corpus_hash = _hash_payload(
        {
            "schema_version": "independent-parity-corpus-v1",
            "fixtures": [
                {
                    "fixture_id": item.fixture_id,
                    "matching_leaf_count": item.matching_leaf_count,
                    "total_leaf_count": item.total_leaf_count,
                    "full_parity": item.full_parity,
                }
                for item in sorted(
                    corpus.parity_reports, key=lambda report: report.fixture_id
                )
            ],
        }
    )
    verified = corpus.validation_receipt.verified
    evidence = LaneEvidence(
        symbol=corpus.symbol,
        strategy=corpus.strategy,
        config_sha256=corpus.config_sha256,
        oos_closed_trades=len(corpus.oos_trades),
        broker_forward_closed_trades=len(corpus.forward_trades),
        broker_forward_weeks=forward_weeks,
        positive_rolling_folds=sum(
            fold.expectancy_r > 0 for fold in corpus.rolling_folds
        ),
        total_rolling_folds=len(corpus.rolling_folds),
        oos_profit_factor=_profit_factor(oos_values),
        broker_forward_profit_factor=_profit_factor(forward_values),
        cost_adjusted_expectancy_ci95_low=lower_bound,
        max_validation_drawdown_percent=_max_drawdown_percent(combined),
        stressed_cost_1_5x_expectancy=(
            sum(_adjusted(corpus.oos_trades + corpus.forward_trades, 1.5))
            / len(combined)
            if combined
            else 0.0
        ),
        stressed_cost_2x_expectancy=(
            sum(_adjusted(corpus.oos_trades + corpus.forward_trades, 2.0))
            / len(combined)
            if combined
            else 0.0
        ),
        deterministic_runtime_parity_percent=parity_percent,
        immutable_snapshot_verified=(
            verified and corpus.validation_receipt.immutable_snapshot_verified
        ),
        forward_contract_verified=(
            verified and corpus.validation_receipt.forward_contract_verified
        ),
        broker_source_aligned=(
            verified and corpus.validation_receipt.broker_source_aligned
        ),
        ruleset_drift_detected=(
            not verified or corpus.validation_receipt.ruleset_drift_detected
        ),
    )
    readiness = evaluate_lane(evidence)
    return IndependentPromotionAssessment(
        lane_evidence=evidence,
        readiness=readiness,
        validation_receipt_sha256=corpus.validation_receipt.receipt_sha256,
        bootstrap_receipt_sha256=bootstrap_hash,
        parity_corpus_sha256=parity_corpus_hash,
    )


def validation_receipt_from_verification(
    verification: Mapping[str, Any],
) -> ValidationReceiptObservation:
    """Map the secure evidence verifier output into the issuer port.

    This function deliberately ignores any performance field in the receipt.
    Only verifier status and immutable provenance/coverage facts are mapped.
    """

    if not isinstance(verification, Mapping):
        raise TypeError("verification must be a mapping")
    receipt = verification.get("receipt")
    if not isinstance(receipt, Mapping):
        return ValidationReceiptObservation(
            receipt_sha256="0" * 64,
            verified=False,
            immutable_snapshot_verified=False,
            forward_contract_verified=False,
            broker_source_aligned=False,
            ruleset_drift_detected=True,
            _seal=_VALIDATION_RECEIPT_OBSERVATION_SEAL,
        )
    receipt_sha256 = str(receipt.get("receipt_payload_sha256") or "0" * 64)
    evidence = receipt.get("evidence_verification")
    evidence = evidence if isinstance(evidence, Mapping) else {}
    failures = tuple(str(item).upper() for item in verification.get("failures", ()))
    verified = verification.get("valid") is True
    live_grade = receipt.get("validation_profile") == "LIVE_GRADE"
    coverage_complete = evidence.get("coverage_complete") is True
    return ValidationReceiptObservation(
        receipt_sha256=receipt_sha256,
        verified=verified,
        immutable_snapshot_verified=verified and evidence.get("valid") is True,
        forward_contract_verified=verified and bool(receipt.get("contract_hmac_sha256")),
        broker_source_aligned=verified and live_grade and coverage_complete,
        ruleset_drift_detected=(
            not verified
            or any("RULESET" in item or "BUILD_IDENTITY" in item for item in failures)
        ),
        _seal=_VALIDATION_RECEIPT_OBSERVATION_SEAL,
    )


def issue_independent_promotion_evidence_receipt(
    corpus: PromotionCorpus,
    *,
    bootstrap_seed: int,
    bootstrap_resamples: int = MIN_BOOTSTRAP_RESAMPLES,
    mode: str,
    account_alias: str,
    server: str,
    journal_sha256: str,
    commit_sha: str,
    model_artifact_sha256: str,
    build_manifest_sha256: str,
    issued_at: datetime,
    expires_at: datetime,
    signer_key_id: str,
    nonce: str,
    secret: str | bytes,
) -> tuple[IndependentPromotionAssessment, PromotionEvidenceReceipt]:
    """Recalculate raw evidence and sign the existing bounded receipt.

    The signed receipt is still only one input to a separate PromotionPermit
    and does not alter any execution lock or provide manual ship approval.
    """

    assessment = evaluate_promotion_corpus(
        corpus,
        bootstrap_seed=bootstrap_seed,
        bootstrap_resamples=bootstrap_resamples,
    )
    receipt = issue_promotion_evidence_receipt(
        assessment.readiness,
        mode=mode,
        account_alias=account_alias,
        server=server,
        journal_sha256=journal_sha256,
        commit_sha=commit_sha,
        model_artifact_sha256=model_artifact_sha256,
        evidence_store_receipt_sha256=assessment.validation_receipt_sha256,
        runtime_parity_receipt_sha256=assessment.parity_corpus_sha256,
        build_manifest_sha256=build_manifest_sha256,
        issued_at=issued_at,
        expires_at=expires_at,
        signer_key_id=signer_key_id,
        nonce=nonce,
        secret=secret,
    )
    return assessment, receipt


__all__ = [
    "ClosedTradeObservation",
    "IndependentPromotionAssessment",
    "MIN_BOOTSTRAP_RESAMPLES",
    "ParityObservation",
    "PromotionCorpus",
    "PromotionCorpusError",
    "RollingFoldObservation",
    "ValidationReceiptObservation",
    "evaluate_promotion_corpus",
    "issue_independent_promotion_evidence_receipt",
    "validation_receipt_from_verification",
]
