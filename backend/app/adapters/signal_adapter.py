from __future__ import annotations

from typing import Any

from app.schemas.signals import SignalStatus, TradingSignal
from app.utils.datetime import parse_datetime
from app.utils.serialization import as_dict, as_list, safe_float, stable_id


def _first(raw: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in raw and raw[key] is not None:
            return raw[key]
    return None


def _status(value: Any, reason: str | None) -> SignalStatus:
    text = str(value or "").strip().upper().replace("-", "_")
    aliases = {
        "READY": "APPROVED",
        "OPEN": "PAPER_OPEN",
        "PAPER_TRADE_OPEN": "PAPER_OPEN",
        "PAPER_WIN": "CLOSED",
        "PAPER_LOSS": "CLOSED",
        "REJECTED_OR_SKIPPED": "REJECTED",
        "NO_TRADE": "WAIT",
        "SIDEWAYS": "WAIT",
    }
    text = aliases.get(text, text)
    if text not in {item.value for item in SignalStatus}:
        reason_upper = (reason or "").upper()
        if "EXPIRED" in reason_upper:
            text = "EXPIRED"
        elif "BLOCK" in reason_upper or "LOCK" in reason_upper:
            text = "BLOCKED"
        else:
            text = "UNKNOWN"
    return SignalStatus(text)


class SignalAdapter:
    def normalize(self, raw: dict[str, Any], *, source: str) -> TradingSignal:
        reason = _first(raw, "reason", "message", "decision_reason")
        symbol_raw = _first(raw, "symbol", "pair", "instrument")
        symbol = str(symbol_raw).strip().upper() if symbol_raw else None
        side_raw = _first(raw, "side", "type", "order_type", "signal", "direction")
        side = str(side_raw).strip().upper() if side_raw else None
        if side not in {"BUY", "SELL"}:
            side = None
        strategy = _first(raw, "selected_strategy", "strategy", "original_selected_strategy")
        timestamp_raw = _first(raw, "timestamp", "time", "created_at", "generated_at", "rejected_at")
        original_score = safe_float(_first(raw, "original_score", "strategy_original_score", "score", "strategy_score"))
        adaptive = as_dict(raw.get("phase5a_adaptive_score"))
        adaptive_score = safe_float(_first(raw, "adaptive_score", "adjusted_score", "strategy_score"))
        if adaptive_score is None:
            adaptive_score = safe_float(adaptive.get("adaptive_score") or adaptive.get("boosted_score"))
        entry = safe_float(_first(raw, "entry", "entry_price", "price"))
        stop = safe_float(_first(raw, "sl", "stop_loss"))
        target = safe_float(_first(raw, "tp", "take_profit"))
        rr = safe_float(_first(raw, "risk_reward_ratio", "rr", "r_ratio"))
        if rr is None and entry is not None and stop is not None and target is not None and abs(entry - stop) > 0:
            rr = abs(target - entry) / abs(entry - stop)
        pair_guard = as_dict(_first(raw, "phase5e_pair_rotation_guard", "pair_guard"))
        quality_guard = as_dict(_first(raw, "phase4r_pair_loss_recovery", "quality_guard"))
        session_guard = as_dict(_first(raw, "phase5j_market_session_guard", "session_guard"))
        blockers = [str(item) for item in as_list(_first(raw, "blocking_reasons", "blockers", "still_blocked_by"))]
        if not blockers and str(_first(raw, "status", "decision") or "").upper() in {"BLOCKED", "WAIT"} and reason:
            blockers = [str(reason)]
        signal_id = str(
            _first(raw, "signal_id", "id") or stable_id("signal", timestamp_raw, symbol, side, strategy, reason)
        )
        return TradingSignal(
            signal_id=signal_id,
            timestamp=parse_datetime(timestamp_raw),
            symbol=symbol,
            side=side,
            strategy=str(strategy).strip().upper() if strategy else None,
            original_score=original_score,
            adaptive_score=adaptive_score,
            confidence=safe_float(_first(raw, "confidence", "confidence_score")),
            entry=entry,
            stop_loss=stop,
            take_profit=target,
            risk_reward_ratio=rr,
            calculated_lot=safe_float(_first(raw, "calculated_lot", "lot", "volume")),
            risk_percent=safe_float(_first(raw, "risk_percent", "risk_pct")),
            status=_status(_first(raw, "status", "decision", "final_decision"), str(reason) if reason else None),
            reason=str(reason) if reason else None,
            blocking_reasons=blockers,
            quality_guard=str(quality_guard.get("status")) if quality_guard.get("status") else None,
            pair_guard=str(pair_guard.get("status")) if pair_guard.get("status") else None,
            session_guard=str(session_guard.get("status")) if session_guard.get("status") else None,
            expiry=parse_datetime(_first(raw, "expiry", "expires_at", "expired_at")),
            source=source,
            mode="PAPER" if str(_first(raw, "mode", "execution_mode") or "PAPER").upper() != "LIVE" else "DRY_RUN",
        )

    def normalize_source(self, raw: Any, *, source: str) -> list[TradingSignal]:
        rows: list[Any]
        if isinstance(raw, list):
            rows = raw
        elif isinstance(raw, dict):
            rows = [
                *as_list(raw.get("signals")),
                *as_list(raw.get("all_decisions")),
                *as_list(raw.get("orders")),
                *as_list(raw.get("history")),
            ]
            generated_at = raw.get("generated_at") or raw.get("last_updated")
            rows = [
                {**row, "generated_at": row.get("generated_at") or generated_at} if isinstance(row, dict) else row
                for row in rows
            ]
        else:
            rows = []
        normalized: list[TradingSignal] = []
        seen: set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            item = self.normalize(row, source=source)
            if item.signal_id not in seen:
                seen.add(item.signal_id)
                normalized.append(item)
        return normalized
