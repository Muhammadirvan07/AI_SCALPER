import json
import os
from datetime import datetime, timezone

from execution_policy import (
    EXECUTION_APPROVED_SYMBOLS,
    EXECUTION_BLOCKED_SYMBOLS,
    EXECUTION_MAX_LOT,
    LIVE_ALLOWED as POLICY_LIVE_ALLOWED,
    SAFE_TO_DEMO_AUTO_ORDER as POLICY_SAFE_TO_DEMO_AUTO_ORDER,
    SHADOW_ONLY_SYMBOLS,
    to_finite_float,
    validate_execution_lot,
    validate_execution_symbol,
)


# =========================
# DEMO MT5 EXTERNAL FILE BRIDGE
# =========================
# Demo-only outbox. This does not enable live trading.
ENABLE_DEMO_MT5_FILE_BRIDGE = True
DEMO_MT5_FILE_BRIDGE_OUTPUT = "mt5_demo_bridge_outbox.json"
DEMO_MT5_FILE_BRIDGE_MODE = "DEMO_ONLY_FILE_BRIDGE"
DEMO_MT5_FILE_BRIDGE_LIVE_ALLOWED = False
DEMO_MT5_FILE_BRIDGE_MAX_LOT = EXECUTION_MAX_LOT
SAFE_TO_DEMO_AUTO_ORDER = POLICY_SAFE_TO_DEMO_AUTO_ORDER

MT5_SIGNAL_FILE = "mt5_trade_signals.json"
EXECUTED_SIGNAL_LOG = "executed_signals.json"
BRIDGE_REJECTED_SIGNAL_LOG = "bridge_rejected_signals.json"
BRIDGE_STATUS_FILE = "bridge_status.json"
PAPER_REPLAY_CANDIDATES_FILE = "paper_replay_candidates.json"
MAX_EXECUTED_HISTORY = 500
MAX_REJECTED_HISTORY = 500

USE_REPLAY_CANDIDATE_FINAL_GUARD = True
REPLAY_FINAL_GUARD_REQUIRE_GLOBAL_CANDIDATES = True
LIVE_ALLOWED = POLICY_LIVE_ALLOWED
MAX_ALLOWED_LOT = EXECUTION_MAX_LOT

# =========================
# BRIDGE APPROVED LABEL CLEANUP
# =========================
# Diagnostic/status cleanup only. Does not unlock trading or create orders.
ENABLE_BRIDGE_APPROVED_LABEL_CLEANUP = True
BRIDGE_EXECUTION_APPROVED_SYMBOLS = EXECUTION_APPROVED_SYMBOLS
BRIDGE_EXECUTION_BLOCKED_SYMBOLS = EXECUTION_BLOCKED_SYMBOLS
BRIDGE_SHADOW_SYMBOLS = SHADOW_ONLY_SYMBOLS
BRIDGE_LABEL_CLEANUP_MODE = "SEPARATE_REPLAY_CANDIDATES_FROM_EXECUTION_APPROVED"
BRIDGE_LABEL_CLEANUP_LIVE_ALLOWED = False
BRIDGE_LABEL_CLEANUP_MAX_LOT = EXECUTION_MAX_LOT



def load_json_file(file_path, default_value):
    if not os.path.exists(file_path):
        return default_value

    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except json.JSONDecodeError:
        print(f"⚠️ Failed to parse {file_path}. Using safe default.")
        return default_value


def save_json_file(file_path, payload):
    with open(file_path, "w") as file:
        json.dump(payload, file, indent=4)


def normalize_signal_id(order):
    signal_id = order.get("signal_id")
    if signal_id:
        return signal_id

    symbol = str(order.get("symbol") or order.get("symbol_mt5") or "UNKNOWN").upper()
    order_type = str(order.get("order_type") or "UNKNOWN").upper()
    generated_at = str(order.get("generated_at") or order.get("created_at") or "NO_TIME")
    return f"{symbol}_{order_type}_{generated_at}"


def load_mt5_signals():
    return load_json_file(
        MT5_SIGNAL_FILE,
        {
            "generated_at": None,
            "order_count": 0,
            "orders": [],
        },
    )


def load_executed_signals():
    return load_json_file(
        EXECUTED_SIGNAL_LOG,
        {
            "executed_signal_ids": [],
            "history": [],
        },
    )


def load_rejected_signals():
    return load_json_file(
        BRIDGE_REJECTED_SIGNAL_LOG,
        {
            "rejected_signal_ids": [],
            "history": [],
        },
    )


def load_replay_candidate_final_guard():
    if not USE_REPLAY_CANDIDATE_FINAL_GUARD:
        return {
            "enabled": False,
            "global_status": "DISABLED",
            "approved_symbols": set(),
            "blocked_symbols": set(),
            "reason": "Replay candidate final guard is disabled.",
        }

    candidate_data = load_json_file(PAPER_REPLAY_CANDIDATES_FILE, {})

    if not isinstance(candidate_data, dict):
        return {
            "enabled": True,
            "global_status": "MISSING_OR_INVALID",
            "approved_symbols": set(),
            "blocked_symbols": set(),
            "reason": "Replay candidate file is missing or invalid.",
        }

    approved_items = candidate_data.get("approved_symbols", [])
    blocked_items = candidate_data.get("blocked_symbols", [])
    global_status = candidate_data.get("global_status", "UNKNOWN")

    approved_symbols = {
        str(item.get("symbol", "")).upper()
        for item in approved_items
        if isinstance(item, dict) and str(item.get("symbol", "")).strip()
    }

    blocked_symbols = {
        str(item.get("symbol", "")).upper()
        for item in blocked_items
        if isinstance(item, dict) and str(item.get("symbol", "")).strip()
    }

    approved_symbols = approved_symbols - blocked_symbols

    return {
        "enabled": True,
        "global_status": global_status,
        "approved_symbols": approved_symbols,
        "blocked_symbols": blocked_symbols,
        "reason": candidate_data.get("global_action", "Replay candidate final guard loaded."),
    }


def is_order_symbol_allowed_by_final_guard(order, final_guard):
    symbol = str(order.get("symbol") or "").strip().upper()
    symbol_mt5 = str(order.get("symbol_mt5") or "").strip().upper()

    policy_allowed, policy_reason = validate_execution_symbol(
        symbol,
        symbol_mt5,
        require_mt5_match=True,
    )
    if not policy_allowed:
        return False, policy_reason

    if not final_guard.get("enabled", False):
        return True, "Replay candidate final guard is disabled."

    blocked_symbols = final_guard.get("blocked_symbols", set())
    approved_symbols = final_guard.get("approved_symbols", set())
    global_status = final_guard.get("global_status", "UNKNOWN")

    if symbol in blocked_symbols:
        return False, f"{symbol} is blocked by replay candidate final guard."

    if REPLAY_FINAL_GUARD_REQUIRE_GLOBAL_CANDIDATES and global_status != "CANDIDATES_AVAILABLE":
        return False, f"Replay global status is {global_status}; MT5 bridge execution is blocked."

    if symbol not in approved_symbols:
        return False, f"{symbol} is not in approved replay candidate symbols."

    return True, "Symbol passed replay candidate final guard."


def is_live_trading_allowed():
    return LIVE_ALLOWED is True


def parse_datetime(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def is_signal_expired(order):
    expires_at = parse_datetime(order.get("expires_at"))

    if expires_at is None:
        return True

    current_time = datetime.now(timezone.utc) if expires_at.tzinfo else datetime.now()
    return current_time > expires_at


def is_signal_already_executed(order, executed_payload):
    signal_id = normalize_signal_id(order)
    executed_ids = executed_payload.get("executed_signal_ids", [])

    return signal_id in executed_ids


def validate_order(order, executed_payload, final_guard):
    if order.get("status") != "PENDING_EXECUTION":
        return False, "Signal status is not PENDING_EXECUTION."

    symbol_allowed, symbol_reason = is_order_symbol_allowed_by_final_guard(order, final_guard)
    if not symbol_allowed:
        return False, symbol_reason

    if is_signal_expired(order):
        return False, "Signal is expired."

    if is_signal_already_executed(order, executed_payload):
        return False, "Signal was already executed."

    order_type = str(order.get("order_type") or "").upper()
    if order_type not in ["BUY", "SELL"]:
        return False, "Order type is not BUY or SELL."

    lot_allowed, lot_reason = validate_execution_lot(order.get("lot"))
    if not lot_allowed:
        return False, lot_reason

    entry_price = to_finite_float(order.get("entry_price"))
    stop_loss = to_finite_float(order.get("stop_loss"))
    take_profit = to_finite_float(order.get("take_profit"))
    if entry_price is None or stop_loss is None or take_profit is None:
        return False, "Entry, SL, and TP must be finite numbers."

    if order_type == "BUY" and not stop_loss < entry_price < take_profit:
        return False, "BUY price structure is invalid; expected SL < Entry < TP."

    if order_type == "SELL" and not take_profit < entry_price < stop_loss:
        return False, "SELL price structure is invalid; expected TP < Entry < SL."

    if not is_live_trading_allowed():
        return True, "Order is valid for DRY_RUN simulated MT5 execution. Live trading is locked."

    return True, "Order is valid for live MT5 execution."


def build_rejected_record(order, reason):
    return {
        "signal_id": normalize_signal_id(order),
        "rejected_at": datetime.now().isoformat(timespec="seconds"),
        "symbol": order.get("symbol"),
        "symbol_mt5": order.get("symbol_mt5"),
        "order_type": order.get("order_type"),
        "lot": order.get("lot"),
        "entry_price": order.get("entry_price"),
        "stop_loss": order.get("stop_loss"),
        "take_profit": order.get("take_profit"),
        "selected_strategy": order.get("selected_strategy"),
        "strategy_score": order.get("strategy_score"),
        "reason": reason,
        "live_allowed": is_live_trading_allowed(),
        "status": "REJECTED_OR_SKIPPED",
    }


def save_rejected_orders(rejected_orders):
    if not rejected_orders:
        return

    rejected_payload = load_rejected_signals()
    rejected_ids = rejected_payload.get("rejected_signal_ids", [])
    history = rejected_payload.get("history", [])

    for item in rejected_orders:
        signal_id = item.get("signal_id")
        reason = item.get("reason")
        duplicate_key = f"{signal_id}|{reason}"

        if duplicate_key in rejected_ids:
            continue

        rejected_ids.append(duplicate_key)
        history.append(item)

    if len(history) > MAX_REJECTED_HISTORY:
        history = history[-MAX_REJECTED_HISTORY:]
        rejected_ids = [
            f"{item.get('signal_id')}|{item.get('reason')}"
            for item in history
            if item.get("signal_id")
        ]

    rejected_payload["rejected_signal_ids"] = rejected_ids
    rejected_payload["history"] = history
    rejected_payload["last_updated"] = datetime.now().isoformat(timespec="seconds")

    save_json_file(BRIDGE_REJECTED_SIGNAL_LOG, rejected_payload)



def build_bridge_label_cleanup_status(existing_status=None):
    """Separate candidate/source symbols from true execution-approved symbols.

    Diagnostic only. Does not unlock live trading, does not create orders,
    and does not override bridge guards.
    """
    if not ENABLE_BRIDGE_APPROVED_LABEL_CLEANUP:
        return {}

    if not isinstance(existing_status, dict):
        existing_status = {}

    source_approved = existing_status.get("approved_symbols", []) or []
    source_blocked = existing_status.get("blocked_symbols", []) or []

    if not isinstance(source_approved, list):
        source_approved = []
    if not isinstance(source_blocked, list):
        source_blocked = []

    return {
        "bridge_label_cleanup_enabled": True,
        "bridge_label_cleanup_mode": BRIDGE_LABEL_CLEANUP_MODE,
        "approved_symbols_label_note": "approved_symbols is a legacy/source/candidate label, not final execution approval.",
        "source_approved_symbols": sorted({str(x).upper() for x in source_approved if x}),
        "source_blocked_symbols": sorted({str(x).upper() for x in source_blocked if x}),
        "execution_approved_symbols": sorted(BRIDGE_EXECUTION_APPROVED_SYMBOLS),
        "execution_blocked_symbols": sorted(BRIDGE_EXECUTION_BLOCKED_SYMBOLS),
        "shadow_symbols": sorted(BRIDGE_SHADOW_SYMBOLS),
        "execution_label_safety": {
            "live_allowed": BRIDGE_LABEL_CLEANUP_LIVE_ALLOWED,
            "max_lot": BRIDGE_LABEL_CLEANUP_MAX_LOT,
            "creates_order": False,
            "does_not_override_existing_guards": True,
            "does_not_modify_replay_candidates": True,
            "does_not_modify_active_pairs": True,
        },
    }


def save_bridge_status(valid_orders, rejected_orders, final_guard):
    status_payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "mode": "DRY_RUN_SIMULATOR" if not is_live_trading_allowed() else "LIVE_EXECUTION",
        "live_allowed": is_live_trading_allowed(),
        "max_allowed_lot": MAX_ALLOWED_LOT,
        "guard_enabled": final_guard.get("enabled", False),
        "guard_global_status": final_guard.get("global_status", "UNKNOWN"),
        "approved_symbols": sorted(final_guard.get("approved_symbols", [])),
        "blocked_symbols": sorted(final_guard.get("blocked_symbols", [])),
        "valid_order_count": len(valid_orders),
        "rejected_order_count": len(rejected_orders),
        "valid_orders": valid_orders,
        "rejected_orders": rejected_orders,
    }

    if ENABLE_BRIDGE_APPROVED_LABEL_CLEANUP:
        status_payload.update(build_bridge_label_cleanup_status(status_payload))

    save_json_file(BRIDGE_STATUS_FILE, status_payload)
    return status_payload


def get_valid_orders():
    signal_payload = load_mt5_signals()
    executed_payload = load_executed_signals()
    final_guard = load_replay_candidate_final_guard()

    valid_orders = []
    rejected_orders = []

    for order in signal_payload.get("orders", []):
        is_valid, reason = validate_order(order, executed_payload, final_guard)

        if is_valid:
            order["bridge_validation_reason"] = reason
            order["live_allowed"] = is_live_trading_allowed()
            valid_orders.append(order)
        else:
            rejected_orders.append(build_rejected_record(order, reason))

    return valid_orders, rejected_orders, final_guard


def mark_orders_as_simulated_executed(valid_orders):
    executed_payload = load_executed_signals()
    executed_ids = executed_payload.get("executed_signal_ids", [])
    history = executed_payload.get("history", [])

    for order in valid_orders:
        signal_id = normalize_signal_id(order)

        if signal_id in executed_ids:
            continue

        executed_ids.append(signal_id)
        history.append(
            {
                "signal_id": signal_id,
                "executed_at": datetime.now().isoformat(timespec="seconds"),
                "execution_source": "MT5_BRIDGE_FINAL_GUARD",
                "symbol": order.get("symbol"),
                "symbol_mt5": order.get("symbol_mt5"),
                "order_type": order.get("order_type"),
                "lot": order.get("lot"),
                "entry_price": order.get("entry_price"),
                "stop_loss": order.get("stop_loss"),
                "take_profit": order.get("take_profit"),
                "selected_strategy": order.get("selected_strategy"),
                "strategy_score": order.get("strategy_score"),
                "bridge_validation_reason": order.get("bridge_validation_reason"),
                "live_allowed": order.get("live_allowed", False),
                "status": "SIMULATED_EXECUTED",
            }
        )

    if len(history) > MAX_EXECUTED_HISTORY:
        history = history[-MAX_EXECUTED_HISTORY:]
        executed_ids = [
            item["signal_id"]
            for item in history
            if item.get("signal_id")
        ]

    executed_payload["executed_signal_ids"] = executed_ids
    executed_payload["history"] = history
    save_json_file(EXECUTED_SIGNAL_LOG, executed_payload)


def print_bridge_report(valid_orders, rejected_orders, final_guard):
    print("\n=== MT5 BRIDGE READER SIMULATOR ===")
    print("\n=== FINAL BRIDGE GUARD ===")
    print(f"Live allowed  : {is_live_trading_allowed()}")
    print(f"Max lot       : {MAX_ALLOWED_LOT}")
    print(f"Guard enabled : {final_guard.get('enabled')}")
    print(f"Global status : {final_guard.get('global_status')}")
    candidate_src = ', '.join(sorted(final_guard.get('approved_symbols', []))) or 'none'
    blocked_src = ', '.join(sorted(final_guard.get('blocked_symbols', []))) or 'none'
    print(f"Candidate src : {candidate_src}")
    print(f"Blocked src   : {blocked_src}")

    if ENABLE_BRIDGE_APPROVED_LABEL_CLEANUP:
        print(f"Exec approved : {', '.join(sorted(BRIDGE_EXECUTION_APPROVED_SYMBOLS)) or 'none'}")
        print(f"Exec blocked  : {', '.join(sorted(BRIDGE_EXECUTION_BLOCKED_SYMBOLS)) or 'none'}")
        print(f"Shadow        : {', '.join(sorted(BRIDGE_SHADOW_SYMBOLS)) or 'none'}")

    if not valid_orders:
        print("No valid order is ready for simulated MT5 execution.")
    else:
        print("\n=== VALID ORDERS READY FOR MT5 ===")
        print(
            f"{'SYMBOL':<10} {'TYPE':>6} {'LOT':>6} {'ENTRY':>12} "
            f"{'SL':>12} {'TP':>12} {'STRATEGY':>18} {'SCORE':>7}"
        )
        print("-" * 95)

        for order in valid_orders:
            print(
                f"{order['symbol_mt5']:<10} "
                f"{order['order_type']:>6} "
                f"{order['lot']:>6.2f} "
                f"{order['entry_price']:>12.5f} "
                f"{order['stop_loss']:>12.5f} "
                f"{order['take_profit']:>12.5f} "
                f"{order.get('selected_strategy', 'UNKNOWN'):>18} "
                f"{order.get('strategy_score', 0):>7}"
            )
            print(
                f"  Signal ID: {order['signal_id']} | "
                f"Expires: {order['expires_at']} | "
                f"Comment: {order.get('comment', '-')}"
            )
            print(f"  Guard: {order.get('bridge_validation_reason', '-')}")

    print("\n=== REJECTED / SKIPPED ORDERS ===")

    if not rejected_orders:
        print("No rejected order.")
    else:
        for item in rejected_orders:
            print(
                f"❌ {item.get('symbol')} {item.get('order_type')} | "
                f"Signal: {item.get('signal_id')} | "
                f"Reason: {item.get('reason')}"
            )
        print(f"\nRejected/skipped order log will be saved to: {BRIDGE_REJECTED_SIGNAL_LOG}")


def export_demo_mt5_file_bridge_outbox(valid_orders=None, bridge_status=None):
    """Export demo-only MT5 file bridge outbox.

    File ini bisa dibaca oleh EA MT5 demo. Fungsi ini tidak mengirim order real,
    tidak unlock live trading, dan lot tetap capped 0.01.
    """
    if not ENABLE_DEMO_MT5_FILE_BRIDGE:
        return {
            "enabled": False,
            "status": "DISABLED",
            "reason": "Demo MT5 file bridge is disabled.",
        }

    if valid_orders is None:
        valid_orders = []
    if bridge_status is None:
        bridge_status = {}

    if not isinstance(valid_orders, list):
        valid_orders = []
    if not isinstance(bridge_status, dict):
        bridge_status = {}

    demo_orders = []
    demo_auto_order_allowed = SAFE_TO_DEMO_AUTO_ORDER is True

    for order in valid_orders if demo_auto_order_allowed else []:
        if not isinstance(order, dict):
            continue

        safe_order = dict(order)
        safe_order["demo_only"] = True
        safe_order["paper_only"] = True
        safe_order["live_allowed"] = False
        safe_order["max_lot"] = DEMO_MT5_FILE_BRIDGE_MAX_LOT

        try:
            lot = float(safe_order.get("lot", 0) or 0)
        except Exception:
            lot = 0.0

        safe_order["lot"] = min(lot, DEMO_MT5_FILE_BRIDGE_MAX_LOT) if lot > 0 else 0.0
        demo_orders.append(safe_order)

    payload = {
        "generated_at": datetime.now().isoformat(),
        "mode": DEMO_MT5_FILE_BRIDGE_MODE,
        "enabled": True,
        "status": (
            "DEMO_OUTBOX_EXPORTED"
            if demo_auto_order_allowed
            else "BLOCKED_BY_DEMO_AUTO_ORDER_LOCK"
        ),
        "demo_only": True,
        "paper_only": True,
        "live_allowed": DEMO_MT5_FILE_BRIDGE_LIVE_ALLOWED,
        "safe_to_demo_auto_order": demo_auto_order_allowed,
        "max_lot": DEMO_MT5_FILE_BRIDGE_MAX_LOT,
        "order_count": len(demo_orders),
        "orders": demo_orders,
        "bridge_status_snapshot": bridge_status,
        "safety_notes": [
            "This outbox is for MT5 demo account testing only.",
            "This exporter does not unlock live trading.",
            "Demo auto-order remains blocked unless SAFE_TO_DEMO_AUTO_ORDER is explicitly reviewed and enabled.",
            "Orders remain blocked when the main bridge has no valid order.",
            "Lot is capped at 0.01."
        ],
    }

    with open(DEMO_MT5_FILE_BRIDGE_OUTPUT, "w") as file:
        json.dump(payload, file, indent=2)

    return payload



def main():
    valid_orders, rejected_orders, final_guard = get_valid_orders()
    print_bridge_report(valid_orders, rejected_orders, final_guard)

    if valid_orders:
        mark_orders_as_simulated_executed(valid_orders)
        print(f"\nSimulated execution logged to: {EXECUTED_SIGNAL_LOG}")

    save_rejected_orders(rejected_orders)
    bridge_status = save_bridge_status(valid_orders, rejected_orders, final_guard)
    print(f"Bridge rejected/skipped log saved to: {BRIDGE_REJECTED_SIGNAL_LOG}")
    print(f"Bridge status saved to: {BRIDGE_STATUS_FILE}")

    demo_outbox = export_demo_mt5_file_bridge_outbox(valid_orders, bridge_status)
    if isinstance(demo_outbox, dict) and demo_outbox.get("enabled"):
        print(
            "Demo MT5 file bridge outbox saved to: "
            f"{DEMO_MT5_FILE_BRIDGE_OUTPUT} | "
            f"orders={demo_outbox.get('order_count', 0)} | "
            f"live_allowed={demo_outbox.get('live_allowed')} | "
            f"max_lot={demo_outbox.get('max_lot')}"
        )





if __name__ == "__main__":
    main()
