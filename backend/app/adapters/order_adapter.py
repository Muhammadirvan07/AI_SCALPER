from __future__ import annotations

from typing import Any

from app.schemas.orders import PaperOrder
from app.utils.datetime import parse_datetime
from app.utils.serialization import safe_float, stable_id


def _first(raw: dict[str, Any], *keys: str) -> Any:
    return next((raw[key] for key in keys if key in raw and raw[key] is not None), None)


class OrderAdapter:
    def normalize(self, raw: dict[str, Any]) -> PaperOrder:
        open_time = parse_datetime(_first(raw, "open_time", "opened_at", "created_at", "timestamp"))
        close_time = parse_datetime(_first(raw, "close_time", "closed_at", "updated_at"))
        entry = safe_float(_first(raw, "entry", "entry_price", "open_price"))
        exit_price = safe_float(_first(raw, "exit", "exit_price", "close_price"))
        pnl = safe_float(_first(raw, "pnl", "profit", "profit_usd", "net_profit"))
        risk = safe_float(_first(raw, "risk_usd", "risk_amount"))
        result = _first(raw, "result", "outcome")
        status_raw = str(_first(raw, "status", "state") or "UNKNOWN").upper()
        if status_raw in {"PAPER_WIN", "PAPER_LOSS", "PAPER_TIMEOUT", "CLOSED", "WIN", "LOSS", "TIMEOUT"}:
            status = "CLOSED"
        elif "OPEN" in status_raw:
            status = "PAPER_OPEN"
        else:
            status = status_raw
        order_id = str(
            _first(raw, "paper_order_id", "order_id", "id") or stable_id("order", open_time, raw.get("symbol"), entry)
        )
        duration = (
            (close_time - open_time).total_seconds()
            if close_time and open_time
            else safe_float(raw.get("duration_seconds"))
        )
        pnl_percent = safe_float(_first(raw, "pnl_percent", "profit_percent"))
        r_multiple = safe_float(_first(raw, "r_multiple", "r"))
        if r_multiple is None and pnl is not None and risk and risk != 0:
            r_multiple = pnl / abs(risk)
        return PaperOrder(
            order_id=order_id,
            signal_id=str(raw.get("signal_id")) if raw.get("signal_id") else None,
            symbol=str(_first(raw, "symbol", "pair", "instrument")).strip().upper()
            if _first(raw, "symbol", "pair", "instrument")
            else None,
            side=str(_first(raw, "side", "type", "order_type")).strip().upper()
            if _first(raw, "side", "type", "order_type")
            else None,
            strategy=str(_first(raw, "strategy", "selected_strategy")).strip().upper()
            if _first(raw, "strategy", "selected_strategy")
            else None,
            entry=entry,
            exit=exit_price,
            stop_loss=safe_float(_first(raw, "sl", "stop_loss")),
            take_profit=safe_float(_first(raw, "tp", "take_profit")),
            lot=safe_float(_first(raw, "lot", "volume", "calculated_lot")),
            open_time=open_time,
            close_time=close_time,
            duration_seconds=duration,
            pnl=pnl,
            pnl_percent=pnl_percent,
            r_multiple=r_multiple,
            exit_reason=str(_first(raw, "exit_reason", "close_reason", "monitor_note"))
            if _first(raw, "exit_reason", "close_reason", "monitor_note")
            else None,
            result=str(result).upper() if result else None,
            status=status,
            mode="PAPER",
            source=str(raw.get("source")) if raw.get("source") else "paper_orders.json",
        )

    def normalize_source(self, raw: Any) -> list[PaperOrder]:
        rows = raw if isinstance(raw, list) else raw.get("orders", []) if isinstance(raw, dict) else []
        return [self.normalize(row) for row in rows if isinstance(row, dict)]
