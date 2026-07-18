"""Read-only performance reporting for the broker diagnostic journal.

The report is deliberately non-promotional.  It summarizes R-multiple paper
outcomes from the append-only realtime diagnostic journal without opening the
SQLite database for mutation or importing any broker execution capability.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import sqlite3
from statistics import median
from typing import Mapping, Sequence

from .contracts import canonical_sha256


UTC = timezone.utc
REPORT_SCHEMA_VERSION = "REALTIME_DIAGNOSTIC_PERFORMANCE_V1"
REQUIRED_SYMBOLS = ("XAUUSD", "EURUSD", "USDJPY", "AUDUSD")
ZERO_HASH = "0" * 64
ALLOWED_EVENT_TYPES = frozenset({"BAR_DECISION", "PAPER_CLOSE", "CYCLE"})
ALLOWED_EXIT_REASONS = frozenset(
    {"STOP_LOSS", "TAKE_PROFIT", "TIMEOUT", "LEGACY_UNSPECIFIED"}
)
REQUIRED_COLUMNS = frozenset(
    {
        "sequence",
        "event_id",
        "event_type",
        "decision_key",
        "symbol",
        "observed_at_utc",
        "payload_json",
        "payload_sha256",
        "previous_sha256",
    }
)


class DiagnosticReportError(RuntimeError):
    """Raised when a diagnostic journal cannot support a trusted report."""


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DiagnosticReportError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise DiagnosticReportError(f"non-finite JSON constant: {value}")


def _strict_json(raw: str) -> dict[str, object]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise DiagnosticReportError("journal contains invalid JSON") from exc
    if not isinstance(value, dict):
        raise DiagnosticReportError("journal event envelope must be an object")
    return value


def _utc_datetime(value: object, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise DiagnosticReportError(f"{field} is not valid UTC") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise DiagnosticReportError(f"{field} must be timezone-aware UTC")
    return parsed.astimezone(UTC)


def _utc_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _text(value: object, field: str, *, upper: bool = False) -> str:
    result = str(value or "").strip()
    if not result:
        raise DiagnosticReportError(f"{field} is required")
    return result.upper() if upper else result


def _finite(value: object, field: str) -> float:
    if isinstance(value, bool):
        raise DiagnosticReportError(f"{field} must be finite")
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise DiagnosticReportError(f"{field} must be finite") from exc
    if not math.isfinite(result):
        raise DiagnosticReportError(f"{field} must be finite")
    return result


def _integer(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise DiagnosticReportError(f"{field} must be an integer >= {minimum}")
    return value


def _round(value: float | None, digits: int = 6) -> float | None:
    return None if value is None else round(float(value), digits)


def _read_verified_events(
    database: Path,
) -> tuple[list[dict[str, object]], str]:
    if not database.exists():
        raise DiagnosticReportError(f"diagnostic database does not exist: {database}")
    if not database.is_file() or database.is_symlink():
        raise DiagnosticReportError("diagnostic database must be a regular file")

    uri = f"{database.resolve().as_uri()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(diagnostic_events)"
            ).fetchall()
        }
        if not REQUIRED_COLUMNS.issubset(columns):
            raise DiagnosticReportError("diagnostic journal schema is invalid")
        rows = connection.execute(
            """SELECT sequence, event_id, event_type, decision_key, symbol,
            observed_at_utc, payload_json, payload_sha256, previous_sha256
            FROM diagnostic_events ORDER BY sequence"""
        ).fetchall()
    except sqlite3.Error as exc:
        raise DiagnosticReportError("diagnostic database cannot be read") from exc
    finally:
        if "connection" in locals():
            connection.close()

    events: list[dict[str, object]] = []
    previous_hash = ZERO_HASH
    for expected_sequence, row in enumerate(rows, start=1):
        if row["sequence"] != expected_sequence:
            raise DiagnosticReportError("diagnostic journal sequence is not contiguous")
        envelope = _strict_json(str(row["payload_json"]))
        event_type = _text(row["event_type"], "event_type", upper=True)
        if event_type not in ALLOWED_EVENT_TYPES:
            raise DiagnosticReportError("diagnostic journal event type is invalid")
        if row["previous_sha256"] != previous_hash:
            raise DiagnosticReportError("diagnostic journal hash chain is invalid")
        if envelope.get("previous_sha256") != previous_hash:
            raise DiagnosticReportError("diagnostic journal hash chain is invalid")
        if canonical_sha256(envelope) != row["payload_sha256"]:
            raise DiagnosticReportError("diagnostic journal hash chain is invalid")
        comparisons = {
            "event_id": row["event_id"],
            "event_type": event_type,
            "decision_key": row["decision_key"],
            "symbol": row["symbol"],
            "observed_at_utc": row["observed_at_utc"],
        }
        if any(envelope.get(key) != value for key, value in comparisons.items()):
            raise DiagnosticReportError("journal row does not match its event envelope")
        safety = envelope.get("safety")
        if not isinstance(safety, Mapping):
            raise DiagnosticReportError("journal safety payload is unavailable")
        if any(
            safety.get(key) is not False
            for key in (
                "live_allowed",
                "safe_to_demo_auto_order",
                "promotion_eligible",
                "validation_evidence",
                "legal_gate_bypassed",
            )
        ) or safety.get("order_capability") != "DISABLED":
            raise DiagnosticReportError("journal safety lock is not diagnostic-only")
        _utc_datetime(row["observed_at_utc"], "observed_at_utc")
        payload = envelope.get("payload")
        if not isinstance(payload, Mapping):
            raise DiagnosticReportError("journal event payload must be an object")
        envelope["payload"] = dict(payload)
        events.append(envelope)
        previous_hash = str(row["payload_sha256"])
    return events, previous_hash


def _trade_metrics(trades: Sequence[Mapping[str, object]]) -> dict[str, object]:
    ordered = sorted(
        trades,
        key=lambda item: (str(item["closed_at_utc"]), str(item["decision_id"])),
    )
    values = [float(item["r_multiple"]) for item in ordered]
    wins = sum(item["outcome"] == "WIN" for item in ordered)
    losses = sum(item["outcome"] == "LOSS" for item in ordered)
    positive = [value for value in values if value > 0.0]
    negative = [value for value in values if value < 0.0]
    gross_profit = sum(positive)
    gross_loss = abs(sum(negative))
    equity = 0.0
    peak = 0.0
    max_drawdown = 0.0
    loss_streak = 0
    max_loss_streak = 0
    for item, value in zip(ordered, values):
        equity += value
        peak = max(peak, equity)
        max_drawdown = max(max_drawdown, peak - equity)
        if item["outcome"] == "LOSS":
            loss_streak += 1
            max_loss_streak = max(max_loss_streak, loss_streak)
        else:
            loss_streak = 0
    holding_seconds = [float(item["holding_seconds"]) for item in ordered]
    holding_bars = [float(item["holding_horizon_m15_bars"]) for item in ordered]
    return {
        "closed_trades": len(ordered),
        "wins": wins,
        "losses": losses,
        "timeouts": sum(item["exit_reason"] == "TIMEOUT" for item in ordered),
        "win_rate_percent": _round(wins / len(ordered) * 100.0)
        if ordered
        else None,
        "gross_profit_r": _round(gross_profit),
        "gross_loss_r": _round(gross_loss),
        "net_r": _round(sum(values)),
        "expectancy_r": _round(sum(values) / len(values)) if values else None,
        "median_r": _round(median(values)) if values else None,
        "profit_factor_r": _round(gross_profit / gross_loss)
        if gross_loss > 0.0
        else None,
        "profit_factor_undefined_no_losses": bool(positive and not negative),
        "max_drawdown_r": _round(max_drawdown),
        "max_consecutive_losses": max_loss_streak,
        "average_holding_seconds": _round(
            sum(holding_seconds) / len(holding_seconds)
        )
        if holding_seconds
        else None,
        "average_holding_horizon_m15_bars": _round(
            sum(holding_bars) / len(holding_bars)
        )
        if holding_bars
        else None,
        "exit_reason_counts": dict(
            sorted(Counter(str(item["exit_reason"]) for item in ordered).items())
        ),
        "strategy_counts": dict(
            sorted(Counter(str(item["strategy"]) for item in ordered).items())
        ),
        "side_counts": dict(
            sorted(Counter(str(item["side"]) for item in ordered).items())
        ),
    }


def _sample_assessment(closed_trades: int) -> dict[str, object]:
    if closed_trades == 0:
        status = "NO_CLOSED_TRADES"
    elif closed_trades < 30:
        status = "VERY_LOW_SAMPLE"
    elif closed_trades < 50:
        status = "LOW_SAMPLE"
    elif closed_trades < 100:
        status = "COUNT_REACHES_FORWARD_MINIMUM_ONLY"
    else:
        status = "COUNT_REACHES_OOS_MINIMUM_ONLY"
    warnings = ["DIAGNOSTIC_ONLY", "NOT_PROMOTION_EVIDENCE"]
    if closed_trades == 0:
        warnings.append("NO_CLOSED_TRADES")
    elif closed_trades < 30:
        warnings.append("WIN_RATE_AND_EXPECTANCY_UNSTABLE")
    warnings.append("EIGHT_WEEK_DURATION_NOT_ASSESSED")
    warnings.append("COST_AND_BOOTSTRAP_GATES_NOT_ASSESSED")
    return {
        "status": status,
        "closed_trades": closed_trades,
        "roadmap_reference_counts": {
            "minimum_broker_forward_closed_trades": 50,
            "minimum_oos_closed_trades": 100,
        },
        "observed_count_reaches_forward_reference": closed_trades >= 50,
        "observed_count_reaches_oos_reference": closed_trades >= 100,
        "promotion_eligible": False,
        "warnings": warnings,
    }


def build_diagnostic_report(
    database: str | Path,
    *,
    generated_at: datetime | None = None,
) -> dict[str, object]:
    """Build a verified, non-promotional report without mutating SQLite."""

    generated = generated_at or datetime.now(UTC)
    if generated.tzinfo is None or generated.utcoffset() != UTC.utcoffset(generated):
        raise DiagnosticReportError("generated_at must be timezone-aware UTC")
    generated = generated.astimezone(UTC)
    database_path = Path(database)
    events, chain_head = _read_verified_events(database_path)

    decisions: dict[str, dict[str, object]] = {}
    closes: dict[str, dict[str, object]] = {}
    decision_counts = {symbol: 0 for symbol in REQUIRED_SYMBOLS}
    paper_opened_counts = {symbol: 0 for symbol in REQUIRED_SYMBOLS}
    action_counts: dict[str, Counter[str]] = {
        symbol: Counter() for symbol in REQUIRED_SYMBOLS
    }
    event_times: list[datetime] = []

    for envelope in events:
        event_times.append(
            _utc_datetime(envelope["observed_at_utc"], "observed_at_utc")
        )
        payload = envelope["payload"]
        if not isinstance(payload, Mapping):
            raise DiagnosticReportError("journal event payload is invalid")
        event_type = envelope["event_type"]
        if event_type == "BAR_DECISION":
            symbol = _text(
                payload.get("canonical_symbol") or envelope.get("symbol"),
                "decision symbol",
                upper=True,
            )
            if symbol not in REQUIRED_SYMBOLS:
                raise DiagnosticReportError("decision symbol is unsupported")
            decision_counts[symbol] += 1
            snapshot = payload.get("snapshot")
            action = "NO_SNAPSHOT"
            if isinstance(snapshot, Mapping):
                action = _text(snapshot.get("side"), "decision side", upper=True)
            action_counts[symbol][action] += 1
            if payload.get("paper_opened") is not True:
                continue
            if not isinstance(snapshot, Mapping):
                raise DiagnosticReportError("opened paper position has no snapshot")
            decision_id = _text(payload.get("decision_id"), "decision_id")
            if decision_id in decisions:
                raise DiagnosticReportError("paper decision id is duplicated")
            side = _text(snapshot.get("side"), "side", upper=True)
            if side not in {"BUY", "SELL"}:
                raise DiagnosticReportError("paper position side is invalid")
            score = _integer(snapshot.get("score"), "score")
            max_holding = payload.get("max_holding_bars")
            if max_holding is None:
                max_holding = 32
            max_holding = _integer(max_holding, "max_holding_bars", minimum=1)
            decisions[decision_id] = {
                "decision_id": decision_id,
                "symbol": symbol,
                "broker_symbol": _text(
                    payload.get("broker_symbol"), "broker_symbol"
                ),
                "side": side,
                "strategy": _text(snapshot.get("strategy"), "strategy", upper=True),
                "score": score,
                "bar_closed_at": _utc_datetime(
                    payload.get("bar_closed_at_utc"), "bar_closed_at_utc"
                ),
                "opened_at": _utc_datetime(snapshot.get("created_at"), "created_at"),
                "max_holding_bars": max_holding,
            }
            paper_opened_counts[symbol] += 1
        elif event_type == "PAPER_CLOSE":
            decision_id = _text(payload.get("decision_id"), "decision_id")
            if decision_id in closes:
                raise DiagnosticReportError("paper close decision id is duplicated")
            closes[decision_id] = dict(payload)

    trades: list[dict[str, object]] = []
    for decision_id, payload in closes.items():
        decision = decisions.get(decision_id)
        if decision is None:
            raise DiagnosticReportError("paper close has no matching open decision")
        side = _text(payload.get("side"), "close side", upper=True)
        if side != decision["side"]:
            raise DiagnosticReportError("paper close side does not match decision")
        opened_at = _utc_datetime(payload.get("opened_at_utc"), "opened_at_utc")
        if opened_at != decision["opened_at"]:
            raise DiagnosticReportError("paper close opening timestamp does not match")
        closed_at = _utc_datetime(payload.get("closed_at_utc"), "closed_at_utc")
        if closed_at < opened_at:
            raise DiagnosticReportError("paper close predates its open")
        outcome = _text(payload.get("outcome"), "outcome", upper=True)
        if outcome not in {"WIN", "LOSS"}:
            raise DiagnosticReportError("paper outcome is invalid")
        r_multiple = _finite(payload.get("r_multiple"), "r_multiple")
        if (outcome == "WIN" and r_multiple <= 0.0) or (
            outcome == "LOSS" and r_multiple > 0.0
        ):
            raise DiagnosticReportError("paper outcome and R multiple disagree")
        exit_reason = _text(
            payload.get("exit_reason") or "LEGACY_UNSPECIFIED",
            "exit_reason",
            upper=True,
        )
        if exit_reason not in ALLOWED_EXIT_REASONS:
            raise DiagnosticReportError("paper exit reason is invalid")
        bar_closed_at = decision["bar_closed_at"]
        if not isinstance(bar_closed_at, datetime):
            raise DiagnosticReportError("decision bar timestamp is invalid")
        trade = {
            "decision_id": decision_id,
            "symbol": decision["symbol"],
            "broker_symbol": decision["broker_symbol"],
            "side": side,
            "strategy": decision["strategy"],
            "score": decision["score"],
            "bar_closed_at_utc": _utc_text(bar_closed_at),
            "opened_at_utc": _utc_text(opened_at),
            "closed_at_utc": _utc_text(closed_at),
            "exit_reason": exit_reason,
            "outcome": outcome,
            "r_multiple": _round(r_multiple),
            "holding_seconds": _round((closed_at - opened_at).total_seconds()),
            "holding_horizon_m15_bars": _round(
                (closed_at - bar_closed_at).total_seconds() / (15 * 60)
            ),
            "configured_max_holding_bars": decision["max_holding_bars"],
        }
        trades.append(trade)
    trades.sort(key=lambda item: (str(item["closed_at_utc"]), str(item["decision_id"])))

    open_positions = [
        {
            "decision_id": decision_id,
            "symbol": decision["symbol"],
            "side": decision["side"],
            "strategy": decision["strategy"],
            "score": decision["score"],
            "opened_at_utc": _utc_text(decision["opened_at"]),
            "bar_closed_at_utc": _utc_text(decision["bar_closed_at"]),
            "configured_max_holding_bars": decision["max_holding_bars"],
        }
        for decision_id, decision in sorted(decisions.items())
        if decision_id not in closes
    ]

    per_symbol: dict[str, dict[str, object]] = {}
    for symbol in REQUIRED_SYMBOLS:
        metrics = _trade_metrics(
            [trade for trade in trades if trade["symbol"] == symbol]
        )
        metrics.update(
            {
                "decisions": decision_counts[symbol],
                "paper_opened": paper_opened_counts[symbol],
                "paper_open": sum(
                    position["symbol"] == symbol for position in open_positions
                ),
                "action_counts": dict(sorted(action_counts[symbol].items())),
                "sample_assessment": _sample_assessment(
                    int(metrics["closed_trades"])
                ),
            }
        )
        per_symbol[symbol] = metrics

    overall = _trade_metrics(trades)
    report: dict[str, object] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_type": "BROKER_REALTIME_DIAGNOSTIC_PERFORMANCE",
        "generated_at_utc": _utc_text(generated),
        "source": {
            "database_name": database_path.name,
            "event_count": len(events),
            "journal_chain_head_sha256": chain_head,
            "journal_sha256_chain_valid": True,
            "database_access": "SQLITE_READ_ONLY_QUERY_ONLY",
        },
        "safety": {
            "diagnostic_only": True,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "promotion_eligible": False,
            "validation_evidence": False,
            "legal_gate_bypassed": False,
            "order_capability": "DISABLED",
            "max_lot": 0.01,
        },
        "observation": {
            "first_event_at_utc": _utc_text(min(event_times)) if event_times else None,
            "last_event_at_utc": _utc_text(max(event_times)) if event_times else None,
            "elapsed_hours": _round(
                (max(event_times) - min(event_times)).total_seconds() / 3600.0
            )
            if event_times
            else None,
        },
        "overall": overall,
        "per_symbol": per_symbol,
        "open_positions": {
            "count": len(open_positions),
            "positions": open_positions,
        },
        "trades": trades,
        "sample_assessment": _sample_assessment(int(overall["closed_trades"])),
        "limitations": (
            "R-multiple paper outcomes only",
            "commission, swap, account-currency conversion, and margin are excluded",
            "diagnostic journal is not broker-forward promotion evidence",
            "confidence intervals and cost stress are not calculated",
        ),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


__all__ = [
    "DiagnosticReportError",
    "REPORT_SCHEMA_VERSION",
    "build_diagnostic_report",
]
