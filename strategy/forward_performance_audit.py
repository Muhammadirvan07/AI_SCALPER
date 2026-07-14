"""Diagnostic-only audit of historical paper-forward performance.

This module deliberately does not import or modify the Phase 4 quality guard.
It treats the existing paper-order file as an immutable observation source,
then reports a separate cohort that matches the *current* execution policy and
symbol strategy profiles.  Official status outcomes and economic PnL signs are
kept separate so, for example, a profitable timeout remains a timeout.

No result from this report can grant live or demo-auto-order permission.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from execution_policy import (
    EXECUTION_APPROVED_SYMBOLS,
    EXECUTION_BLOCKED_SYMBOLS,
    EXECUTION_MAX_LOT,
    EXECUTION_MIN_LOT,
    LIVE_ALLOWED as POLICY_LIVE_ALLOWED,
    SAFE_TO_DEMO_AUTO_ORDER as POLICY_SAFE_TO_DEMO_AUTO_ORDER,
    SHADOW_ONLY_SYMBOLS,
    validate_execution_lot,
    validate_execution_symbol,
)
from executor_config import DEFAULT_SYMBOL_RISK_PROFILE, SYMBOL_RISK_PROFILES
from strategy.strategy_profiles import get_strategy_profile, normalize_symbol


SCHEMA_VERSION = "1.0"
REPORT_TYPE = "FORWARD_PERFORMANCE_COHORT_AUDIT"
DEFAULT_SOURCE = Path(__file__).resolve().parents[1] / "paper_orders.json"
DEFAULT_OUTPUT = Path("forward_performance_audit_report.json")
DEFAULT_BOOTSTRAP_ITERATIONS = 20_000
DEFAULT_BOOTSTRAP_SEED = 42
FX_STANDARD_CONTRACT_SIZE = 100_000.0
FX_PIP_VALUE_USD_PER_001_LOT = 0.10
FX_REFERENCE_LOT = 0.01
CURRENT_MODEL_REQUIRED_FIELDS = (
    "experiment_id",
    "model_version",
    "config_hash",
    "fill_model",
    "timeframe",
)

# Independent fail-closed locks.  These are intentionally not derived from a
# quality metric or CLI option.
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
PROMOTION_ELIGIBLE = False

OFFICIAL_STATUS_KEYS = {
    "PAPER_WIN": "wins",
    "PAPER_LOSS": "losses",
    "PAPER_TIMEOUT": "timeouts",
}


def _finite_float(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _round(value: float | None, digits: int = 8) -> float | None:
    if value is None:
        return None
    return round(float(value), digits)


def _profit_factor(profits: Sequence[float]) -> tuple[float | None, bool]:
    gross_profit = sum(value for value in profits if value > 0.0)
    gross_loss = abs(sum(value for value in profits if value < 0.0))
    if gross_loss == 0.0:
        return None, gross_profit > 0.0
    return gross_profit / gross_loss, False


def official_status_metrics(records: Iterable[Mapping[str, object]]) -> dict:
    """Count outcomes only from the official ``status`` field."""

    records = list(records)
    outcome_counts = Counter(
        OFFICIAL_STATUS_KEYS.get(
            str(record.get("status") or "").strip().upper(), "other"
        )
        for record in records
    )
    wins = outcome_counts["wins"]
    losses = outcome_counts["losses"]
    timeouts = outcome_counts["timeouts"]
    closed = wins + losses + timeouts

    return {
        "records": len(records),
        "closed_status_records": closed,
        "wins": wins,
        "losses": losses,
        "timeouts": timeouts,
        "other_status_records": outcome_counts["other"],
        "status_win_rate_percent": _round(wins / closed * 100.0, 4)
        if closed
        else None,
        "classification_source": "status_field_only",
    }


def economic_metrics(profits: Iterable[object]) -> dict:
    """Summarize economic signs without reclassifying official statuses."""

    raw_values = list(profits)
    values = [value for item in raw_values if (value := _finite_float(item)) is not None]
    positive = [value for value in values if value > 0.0]
    negative = [value for value in values if value < 0.0]
    flat_count = sum(value == 0.0 for value in values)
    profit_factor, infinite_profit_factor = _profit_factor(values)

    return {
        "records_with_finite_pnl": len(values),
        "records_without_finite_pnl": len(raw_values) - len(values),
        "positive_pnl_records": len(positive),
        "negative_pnl_records": len(negative),
        "flat_pnl_records": flat_count,
        "gross_profit_usd": _round(sum(positive)),
        "gross_loss_usd": _round(abs(sum(negative))),
        "net_profit_usd": _round(sum(values)),
        "expectancy_usd_per_record": _round(sum(values) / len(values))
        if values
        else None,
        "profit_factor": _round(profit_factor),
        "profit_factor_is_infinite": infinite_profit_factor,
        "classification_source": "profit_usd_sign_only",
    }


def status_economic_crosstab(
    records: Iterable[Mapping[str, object]],
) -> dict[str, dict[str, int]]:
    """Expose status/PnL disagreements instead of silently merging them."""

    table: dict[str, Counter] = {}
    for record in records:
        status = str(record.get("status") or "UNKNOWN").strip().upper() or "UNKNOWN"
        profit = _finite_float(record.get("profit_usd"))
        if profit is None:
            sign = "non_finite_or_missing"
        elif profit > 0.0:
            sign = "positive"
        elif profit < 0.0:
            sign = "negative"
        else:
            sign = "flat"
        table.setdefault(status, Counter())[sign] += 1

    columns = ("positive", "negative", "flat", "non_finite_or_missing")
    return {
        status: {column: counts[column] for column in columns}
        for status, counts in sorted(table.items())
    }


def _fx_notional_usd(symbol: str, entry: float, lot: float) -> float | None:
    """Estimate USD notional for a standard FX contract.

    Only USD-base and USD-quote pairs have an unambiguous USD conversion using
    the order entry alone.  Crosses fail closed because a conversion quote is
    not present in the paper-order record.
    """

    if len(symbol) != 6 or entry <= 0.0 or lot <= 0.0:
        return None
    base_notional = FX_STANDARD_CONTRACT_SIZE * lot
    if symbol.endswith("USD"):
        return base_notional * entry
    if symbol.startswith("USD"):
        return base_notional
    return None


def estimate_fx_round_trip_cost(
    record: Mapping[str, object],
) -> dict[str, float] | None:
    """Return the profile-based FX round-trip cost derived from notional."""

    symbol = normalize_symbol(record.get("symbol"))
    profile = get_strategy_profile(symbol)
    if profile.asset_class != "FOREX":
        return None

    entry = _finite_float(record.get("entry"))
    lot = _finite_float(record.get("lot"))
    if entry is None or lot is None:
        return None
    notional_usd = _fx_notional_usd(symbol, entry, lot)
    if notional_usd is None:
        return None

    cost_bps = float(profile.estimated_round_trip_cost_bps)
    return {
        "notional_usd": notional_usd,
        "round_trip_cost_bps": cost_bps,
        "estimated_round_trip_cost_usd": notional_usd * cost_bps / 10_000.0,
    }


def estimate_recorded_fx_stop_risk_usd(
    record: Mapping[str, object],
) -> float | None:
    """Estimate stop exposure using the same EURUSD pip-value safety model.

    This is still not broker contract verification. It exists to ensure a
    historical row cannot be called current-policy compatible when its final
    0.01 lot would breach the configured dollar risk cap.
    """

    symbol = normalize_symbol(record.get("symbol"))
    profile = get_strategy_profile(symbol)
    if profile.asset_class != "FOREX":
        return None

    entry = _finite_float(record.get("entry"))
    stop = _finite_float(record.get("sl"))
    lot = _finite_float(record.get("lot"))
    if entry is None or stop is None or lot is None or lot <= 0.0:
        return None

    action = str(
        record.get("type", record.get("action", record.get("order_type", "")))
        or ""
    ).upper()
    if action == "BUY" and stop >= entry:
        return None
    if action == "SELL" and stop <= entry:
        return None
    if action not in {"BUY", "SELL"} or stop == entry:
        return None

    pip_size = 0.01 if symbol.endswith("JPY") else 0.0001
    stop_pips = abs(entry - stop) / pip_size
    return stop_pips * FX_PIP_VALUE_USD_PER_001_LOT * (lot / FX_REFERENCE_LOT)


def _policy_symbol_exclusion_reason(symbol: str) -> str:
    if not symbol or symbol == "UNKNOWN":
        return "symbol_missing"
    if symbol in EXECUTION_BLOCKED_SYMBOLS:
        return "symbol_blocked_by_execution_policy"
    if symbol in SHADOW_ONLY_SYMBOLS:
        return "symbol_shadow_only"
    return "symbol_not_execution_approved"


def _percentile(sorted_values: Sequence[float], probability: float) -> float:
    if not sorted_values:
        raise ValueError("percentile requires at least one value")
    position = (len(sorted_values) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    weight = position - lower
    return sorted_values[lower] * (1.0 - weight) + sorted_values[upper] * weight


def bootstrap_expectancy(
    profits: Sequence[float],
    *,
    iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
    seed: int = DEFAULT_BOOTSTRAP_SEED,
    confidence: float = 0.95,
) -> dict:
    """Deterministically bootstrap the mean cost-adjusted PnL."""

    if iterations <= 0:
        raise ValueError("bootstrap iterations must be positive")
    if not 0.0 < confidence < 1.0:
        raise ValueError("bootstrap confidence must be between zero and one")

    values = [value for item in profits if (value := _finite_float(item)) is not None]
    if not values:
        return {
            "sample_count": 0,
            "iterations": iterations,
            "seed": seed,
            "confidence_level": confidence,
            "expectancy_ci_low_usd": None,
            "expectancy_ci_high_usd": None,
            "probability_expectancy_gt_zero": None,
        }

    rng = random.Random(seed)
    sample_count = len(values)
    means = [
        sum(values[rng.randrange(sample_count)] for _ in range(sample_count))
        / sample_count
        for _ in range(iterations)
    ]
    means.sort()
    alpha = (1.0 - confidence) / 2.0

    return {
        "sample_count": sample_count,
        "iterations": iterations,
        "seed": seed,
        "confidence_level": confidence,
        "expectancy_ci_low_usd": _round(_percentile(means, alpha)),
        "expectancy_ci_high_usd": _round(_percentile(means, 1.0 - alpha)),
        "probability_expectancy_gt_zero": _round(
            sum(value > 0.0 for value in means) / iterations,
            6,
        ),
        "method": "iid_nonparametric_bootstrap_of_mean_with_replacement",
    }


def _strategy_profile_snapshot(symbols: Iterable[str]) -> dict[str, dict]:
    snapshot = {}
    for symbol in sorted(set(symbols)):
        profile = get_strategy_profile(symbol)
        snapshot[symbol] = {
            "asset_class": profile.asset_class,
            "allowed_strategies": sorted(profile.allowed_strategies),
            "preferred_strategy": profile.preferred_strategy,
            "min_strategy_score": profile.min_strategy_score,
            "estimated_round_trip_cost_bps": profile.estimated_round_trip_cost_bps,
        }
    return snapshot


def _transaction_cost_summary(cost_rows: Sequence[dict]) -> dict:
    total_notional = sum(row["notional_usd"] for row in cost_rows)
    total_cost = sum(row["estimated_round_trip_cost_usd"] for row in cost_rows)
    by_symbol: dict[str, dict] = {}
    for row in cost_rows:
        symbol = row["symbol"]
        bucket = by_symbol.setdefault(
            symbol,
            {
                "records": 0,
                "notional_usd": 0.0,
                "estimated_round_trip_cost_usd": 0.0,
                "round_trip_cost_bps": row["round_trip_cost_bps"],
            },
        )
        bucket["records"] += 1
        bucket["notional_usd"] += row["notional_usd"]
        bucket["estimated_round_trip_cost_usd"] += row[
            "estimated_round_trip_cost_usd"
        ]

    for bucket in by_symbol.values():
        bucket["notional_usd"] = _round(bucket["notional_usd"])
        bucket["estimated_round_trip_cost_usd"] = _round(
            bucket["estimated_round_trip_cost_usd"]
        )

    return {
        "costed_records": len(cost_rows),
        "fx_standard_contract_size_base_units": FX_STANDARD_CONTRACT_SIZE,
        "formula": (
            "notional_usd * profile.estimated_round_trip_cost_bps / 10000"
        ),
        "usd_notional_method": (
            "XXXUSD=entry*lot*100000; USDXXX=lot*100000; FX crosses unavailable"
        ),
        "total_notional_usd": _round(total_notional),
        "total_estimated_round_trip_cost_usd": _round(total_cost),
        "average_estimated_round_trip_cost_usd": _round(
            total_cost / len(cost_rows)
        )
        if cost_rows
        else None,
        "by_symbol": by_symbol,
    }


def build_forward_performance_audit(
    records: Sequence[Mapping[str, object]],
    *,
    source_file: str,
    source_sha256: str,
    source_size_bytes: int,
    generated_at: str | None = None,
    bootstrap_iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
    bootstrap_seed: int = DEFAULT_BOOTSTRAP_SEED,
) -> dict:
    """Build a separate current-policy cohort from immutable source records."""

    records = list(records)
    if not all(isinstance(record, Mapping) for record in records):
        raise TypeError("every paper-order record must be a JSON object")
    if (
        not source_sha256
        or len(source_sha256) != 64
        or any(character not in "0123456789abcdefABCDEF" for character in source_sha256)
    ):
        raise ValueError("source_sha256 must be a 64-character SHA256 hex digest")

    legacy_policy_shape_records: list[Mapping[str, object]] = []
    legacy_policy_shape_cost_rows: list[dict] = []
    legacy_policy_shape_adjusted_profits: list[float] = []
    eligible_records: list[Mapping[str, object]] = []
    eligible_cost_rows: list[dict] = []
    adjusted_profits: list[float] = []
    current_model_records: list[Mapping[str, object]] = []
    current_model_cost_rows: list[dict] = []
    current_model_adjusted_profits: list[float] = []
    current_model_signatures: Counter = Counter()
    missing_current_model_metadata: Counter = Counter()
    primary_exclusions: Counter = Counter()
    all_exclusions: Counter = Counter()
    excluded_symbols: Counter = Counter()
    excluded_strategies: Counter = Counter()

    for record in records:
        status = str(record.get("status") or "").strip().upper()
        symbol = normalize_symbol(record.get("symbol"))
        strategy = str(record.get("strategy") or "").strip().upper()
        profile = get_strategy_profile(symbol)
        reasons: list[str] = []

        if status not in OFFICIAL_STATUS_KEYS:
            reasons.append("status_not_officially_closed")
        profit = _finite_float(record.get("profit_usd"))
        if profit is None:
            reasons.append("profit_usd_missing_or_non_finite")

        symbol_allowed, _ = validate_execution_symbol(symbol)
        if not symbol_allowed:
            reasons.append(_policy_symbol_exclusion_reason(symbol))

        lot_allowed, _ = validate_execution_lot(record.get("lot"))
        if not lot_allowed:
            reasons.append("lot_outside_execution_policy")

        if strategy not in profile.allowed_strategies:
            reasons.append("strategy_not_allowed_by_symbol_profile")

        score = _finite_float(record.get("score"))
        if score is None or score < profile.min_strategy_score:
            reasons.append("score_below_or_missing_profile_minimum")

        cost = None
        if not reasons:
            cost = estimate_fx_round_trip_cost(record)
            if cost is None:
                reasons.append("fx_notional_cost_unavailable")

        if reasons:
            primary_exclusions[reasons[0]] += 1
            all_exclusions.update(reasons)
            excluded_symbols[symbol] += 1
            excluded_strategies[strategy or "UNKNOWN"] += 1
            continue

        assert profit is not None and cost is not None
        cost_row = {"symbol": symbol, **cost}
        legacy_policy_shape_records.append(record)
        legacy_policy_shape_cost_rows.append(cost_row)
        legacy_policy_shape_adjusted_profits.append(
            profit - cost["estimated_round_trip_cost_usd"]
        )

        actual_stop_risk = estimate_recorded_fx_stop_risk_usd(record)
        risk_profile = SYMBOL_RISK_PROFILES.get(symbol, DEFAULT_SYMBOL_RISK_PROFILE)
        max_risk_usd = float(
            risk_profile.get(
                "max_risk_usd",
                DEFAULT_SYMBOL_RISK_PROFILE["max_risk_usd"],
            )
        )
        if actual_stop_risk is None:
            reasons.append("actual_stop_risk_unavailable")
        elif actual_stop_risk > max_risk_usd:
            reasons.append("actual_stop_risk_exceeds_symbol_profile")

        if reasons:
            primary_exclusions[reasons[0]] += 1
            all_exclusions.update(reasons)
            excluded_symbols[symbol] += 1
            excluded_strategies[strategy or "UNKNOWN"] += 1
            continue

        eligible_records.append(record)
        eligible_cost_rows.append(cost_row)
        adjusted_profits.append(profit - cost["estimated_round_trip_cost_usd"])

        missing_metadata = [
            field
            for field in CURRENT_MODEL_REQUIRED_FIELDS
            if not str(record.get(field) or "").strip()
        ]
        if missing_metadata:
            missing_current_model_metadata.update(missing_metadata)
        else:
            signature = tuple(
                str(record.get(field)).strip()
                for field in CURRENT_MODEL_REQUIRED_FIELDS
            )
            current_model_signatures[signature] += 1
            current_model_records.append(record)
            current_model_cost_rows.append(cost_row)
            current_model_adjusted_profits.append(
                profit - cost["estimated_round_trip_cost_usd"]
            )

    all_profits = [record.get("profit_usd") for record in records]
    eligible_profits = [record.get("profit_usd") for record in eligible_records]
    symbols = [normalize_symbol(record.get("symbol")) for record in records]
    legacy_policy_shape_bootstrap = bootstrap_expectancy(
        legacy_policy_shape_adjusted_profits,
        iterations=bootstrap_iterations,
        seed=bootstrap_seed,
    )
    legacy_policy_shape_ci_low = legacy_policy_shape_bootstrap[
        "expectancy_ci_low_usd"
    ]
    legacy_policy_shape_status = (
        "LEGACY_POLICY_SHAPE_EXPECTANCY_CI_ABOVE_ZERO_DIAGNOSTIC_ONLY"
        if legacy_policy_shape_ci_low is not None and legacy_policy_shape_ci_low > 0.0
        else "LEGACY_POLICY_SHAPE_POSITIVE_EXPECTANCY_NOT_PROVEN"
    )

    cost_adjusted = economic_metrics(adjusted_profits)
    bootstrap = bootstrap_expectancy(
        adjusted_profits,
        iterations=bootstrap_iterations,
        seed=bootstrap_seed,
    )
    ci_low = bootstrap["expectancy_ci_low_usd"]
    evidence_status = (
        "CURRENT_POLICY_EXPECTANCY_CI_ABOVE_ZERO_DIAGNOSTIC_ONLY"
        if ci_low is not None and ci_low > 0.0
        else "CURRENT_POLICY_POSITIVE_EXPECTANCY_NOT_PROVEN"
    )

    homogeneous_current_model = len(current_model_signatures) == 1
    homogeneous_current_model_records = (
        current_model_records if homogeneous_current_model else []
    )
    homogeneous_current_model_cost_rows = (
        current_model_cost_rows if homogeneous_current_model else []
    )
    homogeneous_current_model_adjusted = (
        current_model_adjusted_profits if homogeneous_current_model else []
    )
    current_model_bootstrap = bootstrap_expectancy(
        homogeneous_current_model_adjusted,
        iterations=bootstrap_iterations,
        seed=bootstrap_seed,
    )
    current_model_ci_low = current_model_bootstrap["expectancy_ci_low_usd"]
    if not current_model_records:
        current_model_status = "NO_HOMOGENEOUS_TAGGED_MODEL_COHORT"
    elif not homogeneous_current_model:
        current_model_status = "MIXED_TAGGED_MODEL_SIGNATURES_REJECTED"
    elif current_model_ci_low is not None and current_model_ci_low > 0.0:
        current_model_status = "TAGGED_MODEL_POSITIVE_EXPECTANCY_DIAGNOSTIC_ONLY"
    else:
        current_model_status = "TAGGED_MODEL_POSITIVE_EXPECTANCY_NOT_PROVEN"

    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": REPORT_TYPE,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "diagnostic_only": True,
        "live_allowed": LIVE_ALLOWED,
        "safe_to_demo_auto_order": SAFE_TO_DEMO_AUTO_ORDER,
        "promotion_eligible": PROMOTION_ELIGIBLE,
        "safety_locks": {
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "promotion_eligible": False,
            "mutates_phase4_quality_formula": False,
            "mutates_paper_orders": False,
        },
        "source": {
            "file": source_file,
            "sha256": source_sha256,
            "size_bytes": source_size_bytes,
            "records": len(records),
            "read_only_observation": True,
        },
        "current_execution_policy": {
            "approved_symbols": sorted(EXECUTION_APPROVED_SYMBOLS),
            "blocked_symbols": sorted(EXECUTION_BLOCKED_SYMBOLS),
            "shadow_only_symbols": sorted(SHADOW_ONLY_SYMBOLS),
            "min_lot": EXECUTION_MIN_LOT,
            "max_lot": EXECUTION_MAX_LOT,
            "policy_live_allowed": bool(POLICY_LIVE_ALLOWED),
            "policy_safe_to_demo_auto_order": bool(
                POLICY_SAFE_TO_DEMO_AUTO_ORDER
            ),
        },
        "strategy_profiles_observed": _strategy_profile_snapshot(symbols),
        "all_history_observed": {
            "official_status_outcomes": official_status_metrics(records),
            "economic_pnl": economic_metrics(all_profits),
            "status_vs_economic_pnl": status_economic_crosstab(records),
        },
        "legacy_policy_shape_cohort": {
            "records": len(legacy_policy_shape_records),
            "cohort_type": "LEGACY_POLICY_SHAPE_ONLY",
            "not_current_policy_evidence": True,
            "reason": (
                "Rows match current symbol/lot/strategy/score shape but have not "
                "passed the current actual-stop-risk or model-signature gates."
            ),
            "official_status_outcomes": official_status_metrics(
                legacy_policy_shape_records
            ),
            "gross_economic_pnl": economic_metrics(
                [record.get("profit_usd") for record in legacy_policy_shape_records]
            ),
            "transaction_cost_estimate": _transaction_cost_summary(
                legacy_policy_shape_cost_rows
            ),
            "cost_adjusted_economic_pnl": economic_metrics(
                legacy_policy_shape_adjusted_profits
            ),
            "bootstrap_cost_adjusted_expectancy": legacy_policy_shape_bootstrap,
            "evidence_status": legacy_policy_shape_status,
        },
        "current_policy_execution_cohort": {
            "records": len(eligible_records),
            "cohort_type": "CURRENT_POLICY_INCLUDING_ACTUAL_STOP_RISK",
            "not_current_model_evidence": True,
            "criteria": [
                "officially closed PAPER_WIN/PAPER_LOSS/PAPER_TIMEOUT status",
                "finite profit_usd",
                "symbol passes execution_policy.validate_execution_symbol",
                "lot passes execution_policy.validate_execution_lot",
                "strategy is allowed by the current symbol profile",
                "score meets the current symbol profile minimum",
                "USD FX notional and profile round-trip cost are available",
                "actual stop exposure is available and within symbol max_risk_usd",
            ],
            "official_status_outcomes": official_status_metrics(eligible_records),
            "gross_economic_pnl": economic_metrics(eligible_profits),
            "transaction_cost_estimate": _transaction_cost_summary(
                eligible_cost_rows
            ),
            "cost_adjusted_economic_pnl": cost_adjusted,
            "bootstrap_cost_adjusted_expectancy": bootstrap,
            "evidence_status": evidence_status,
        },
        "homogeneous_tagged_model_cohort": {
            "records": len(homogeneous_current_model_records),
            "status": current_model_status,
            "required_metadata_fields": list(CURRENT_MODEL_REQUIRED_FIELDS),
            "policy_compatible_records_considered": len(eligible_records),
            "records_with_complete_model_metadata": len(current_model_records),
            "missing_metadata_field_counts": dict(
                sorted(missing_current_model_metadata.items())
            ),
            "homogeneous_signature_count": len(current_model_signatures),
            "homogeneous_signature_required": True,
            "official_status_outcomes": official_status_metrics(
                homogeneous_current_model_records
            ),
            "gross_economic_pnl": economic_metrics(
                [record.get("profit_usd") for record in homogeneous_current_model_records]
            ),
            "transaction_cost_estimate": _transaction_cost_summary(
                homogeneous_current_model_cost_rows
            ),
            "cost_adjusted_economic_pnl": economic_metrics(
                homogeneous_current_model_adjusted
            ),
            "bootstrap_cost_adjusted_expectancy": current_model_bootstrap,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "promotion_eligible": False,
        },
        "current_model_evidence": {
            "records": 0,
            "evidence_available": False,
            "status": "EXPECTED_CURRENT_MODEL_SIGNATURE_NOT_CONFIGURED",
            "reason": (
                "Homogeneous metadata alone cannot prove that a row came from "
                "the current code/config. An independently supplied expected "
                "model and config signature is required."
            ),
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "promotion_eligible": False,
        },
        "exclusions": {
            "excluded_records": len(records) - len(eligible_records),
            "primary_reason_counts": dict(sorted(primary_exclusions.items())),
            "all_reason_counts": dict(sorted(all_exclusions.items())),
            "excluded_symbol_counts": dict(sorted(excluded_symbols.items())),
            "excluded_strategy_counts": dict(sorted(excluded_strategies.items())),
            "reason_precedence": [
                "status_not_officially_closed",
                "profit_usd_missing_or_non_finite",
                "execution symbol policy",
                "execution lot policy",
                "symbol strategy profile",
                "symbol profile minimum score",
                "FX notional cost availability",
                "actual stop risk availability and profile cap",
            ],
        },
        "limitations": [
            "Historical paper PnL is observational and is not a randomized sample.",
            "The bootstrap assumes iid records and does not remove regime dependence.",
            "Cost is an estimate from recorded entry, lot, FX contract size, and profile bps.",
            (
                "Profile gates that require historical indicator context cannot be "
                "reconstructed from paper orders."
            ),
            "This audit does not model latency, spread spikes, partial fills, or broker rejection.",
            "No metric in this report changes official Phase 4 quality or execution locks.",
        ],
    }


def load_and_build_report(
    source_path: str | Path = DEFAULT_SOURCE,
    *,
    bootstrap_iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
    bootstrap_seed: int = DEFAULT_BOOTSTRAP_SEED,
    generated_at: str | None = None,
) -> dict:
    """Hash and parse one immutable byte snapshot of the paper-order source."""

    path = Path(source_path)
    raw = path.read_bytes()
    parsed = json.loads(raw)
    if not isinstance(parsed, list):
        raise TypeError("paper-order source must contain a JSON array")

    return build_forward_performance_audit(
        parsed,
        source_file=path.name,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        source_size_bytes=len(raw),
        generated_at=generated_at,
        bootstrap_iterations=bootstrap_iterations,
        bootstrap_seed=bootstrap_seed,
    )


def write_report(report: Mapping[str, object], output_path: str | Path) -> Path:
    """Write only the dedicated diagnostic output, never the source orders."""

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    temporary.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(output)
    return output


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a diagnostic-only current-policy paper-forward audit."
    )
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--bootstrap-iterations",
        type=int,
        default=DEFAULT_BOOTSTRAP_ITERATIONS,
    )
    parser.add_argument("--bootstrap-seed", type=int, default=DEFAULT_BOOTSTRAP_SEED)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    report = load_and_build_report(
        args.source,
        bootstrap_iterations=args.bootstrap_iterations,
        bootstrap_seed=args.bootstrap_seed,
    )
    output = write_report(report, args.output)
    cohort = report["current_policy_execution_cohort"]
    print(
        f"Wrote diagnostic forward audit to {output}: "
        f"records={cohort['records']}, evidence={cohort['evidence_status']}, "
        "live_allowed=False, safe_to_demo_auto_order=False"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
