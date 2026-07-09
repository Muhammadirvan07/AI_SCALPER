import json
import os
from datetime import datetime

MT5_SIGNAL_FILE = "mt5_trade_signals.json"
DRY_RUN_LOG_FILE = "mt5_dry_run_orders.json"
MAX_DRY_RUN_HISTORY = 500

ALLOWED_ORDER_TYPES = ["BUY", "SELL"]
MIN_LOT = 0.01
MAX_LOT = 0.10
MAX_SPREAD_POINTS_SIMULATION = 300
STOP_DISTANCE_TOLERANCE_POINTS = 0.1


def load_json_file(file_path, default_value):
    if not os.path.exists(file_path):
        return default_value

    with open(file_path, "r") as file:
        return json.load(file)


def save_json_file(file_path, payload):
    with open(file_path, "w") as file:
        json.dump(payload, file, indent=4)


def parse_datetime(value):
    if not value:
        return None

    return datetime.fromisoformat(value)


def load_mt5_orders():
    payload = load_json_file(
        MT5_SIGNAL_FILE,
        {
            "generated_at": None,
            "engine_mode": "UNKNOWN",
            "order_count": 0,
            "orders": [],
        },
    )

    return payload.get("orders", [])


def load_dry_run_log():
    return load_json_file(
        DRY_RUN_LOG_FILE,
        {
            "dry_run_signal_ids": [],
            "history": [],
        },
    )


def get_symbol_execution_profile(symbol):
    symbol = symbol.upper()

    if symbol in ["XAUUSD", "GOLD"]:
        return {
            "symbol": symbol,
            "digits": 2,
            "point": 0.01,
            "min_stop_points": 150,
            "max_spread_points": 500,
        }

    if symbol in ["BTCUSD", "BTC"]:
        return {
            "symbol": symbol,
            "digits": 2,
            "point": 1.0,
            "min_stop_points": 300,
            "max_spread_points": 2000,
        }

    if "JPY" in symbol:
        return {
            "symbol": symbol,
            "digits": 3,
            "point": 0.001,
            "min_stop_points": 30,
            "max_spread_points": 300,
        }

    return {
        "symbol": symbol,
        "digits": 5,
        "point": 0.00001,
        "min_stop_points": 30,
        "max_spread_points": MAX_SPREAD_POINTS_SIMULATION,
    }


def calculate_stop_points(order, profile):
    entry_price = order.get("entry_price")
    stop_loss = order.get("stop_loss")

    if entry_price is None or stop_loss is None:
        return None

    return abs(entry_price - stop_loss) / profile["point"]


def validate_order_structure(order):
    required_fields = [
        "signal_id",
        "symbol",
        "symbol_mt5",
        "order_type",
        "lot",
        "entry_price",
        "stop_loss",
        "take_profit",
        "expires_at",
        "magic_number",
    ]

    missing_fields = [
        field for field in required_fields
        if field not in order or order.get(field) is None
    ]

    if missing_fields:
        return False, f"Missing required fields: {', '.join(missing_fields)}"

    return True, "Order structure is valid."


def validate_order_expiry(order):
    expires_at = parse_datetime(order.get("expires_at"))

    if expires_at is None:
        return False, "Order expiry is missing or invalid."

    if datetime.now() > expires_at:
        return False, "Order signal is expired."

    return True, "Order signal is still valid."


def validate_duplicate(order, dry_run_log):
    signal_id = order.get("signal_id")
    dry_run_signal_ids = dry_run_log.get("dry_run_signal_ids", [])

    if signal_id in dry_run_signal_ids:
        return False, "Order was already processed by dry run executor."

    return True, "Order is not duplicated."


def validate_order_values(order):
    order_type = order.get("order_type")

    if order_type not in ALLOWED_ORDER_TYPES:
        return False, "Order type must be BUY or SELL."

    lot = order.get("lot", 0)

    if lot < MIN_LOT or lot > MAX_LOT:
        return False, f"Lot is outside allowed range: {lot}."

    entry_price = order.get("entry_price")
    stop_loss = order.get("stop_loss")
    take_profit = order.get("take_profit")

    if order_type == "BUY":
        if not stop_loss < entry_price < take_profit:
            return False, "BUY order price structure is invalid. Expected SL < Entry < TP."

    if order_type == "SELL":
        if not take_profit < entry_price < stop_loss:
            return False, "SELL order price structure is invalid. Expected TP < Entry < SL."

    return True, "Order values are valid."


def validate_stop_distance(order, profile):
    stop_points = calculate_stop_points(order, profile)

    if stop_points is None:
        return False, "Cannot calculate stop distance."

    minimum_allowed_points = profile["min_stop_points"] - STOP_DISTANCE_TOLERANCE_POINTS

    if stop_points < minimum_allowed_points:
        return (
            False,
            f"Stop distance is too small: {stop_points:.1f} points "
            f"(min: {profile['min_stop_points']} points).",
        )

    return True, f"Stop distance is valid: {stop_points:.1f} points."


def build_dry_run_order(order, profile):
    return {
        "signal_id": order.get("signal_id"),
        "dry_run_at": datetime.now().isoformat(timespec="seconds"),
        "execution_mode": "DRY_RUN",
        "symbol": order.get("symbol"),
        "symbol_mt5": order.get("symbol_mt5"),
        "order_type": order.get("order_type"),
        "volume": order.get("lot"),
        "entry_reference_price": round(order.get("entry_price"), profile["digits"]),
        "stop_loss": round(order.get("stop_loss"), profile["digits"]),
        "take_profit": round(order.get("take_profit"), profile["digits"]),
        "magic_number": order.get("magic_number"),
        "comment": order.get("comment"),
        "selected_strategy": order.get("selected_strategy"),
        "strategy_score": order.get("strategy_score"),
        "risk_amount": order.get("risk_amount"),
        "risk_percent": order.get("risk_percent"),
        "risk_reward_ratio": order.get("risk_reward_ratio"),
        "symbol_profile": profile,
        "status": "DRY_RUN_READY",
        "note": "This is a dry-run order only. No real MT5 trade was sent.",
    }


def validate_order(order, dry_run_log):
    structure_ok, structure_reason = validate_order_structure(order)

    if not structure_ok:
        return False, structure_reason, None

    expiry_ok, expiry_reason = validate_order_expiry(order)

    if not expiry_ok:
        return False, expiry_reason, None

    duplicate_ok, duplicate_reason = validate_duplicate(order, dry_run_log)

    if not duplicate_ok:
        return False, duplicate_reason, None

    values_ok, values_reason = validate_order_values(order)

    if not values_ok:
        return False, values_reason, None

    profile = get_symbol_execution_profile(order.get("symbol_mt5"))
    stop_ok, stop_reason = validate_stop_distance(order, profile)

    if not stop_ok:
        return False, stop_reason, profile

    return True, "Order passed all dry-run execution checks.", profile


def save_dry_run_results(valid_dry_run_orders):
    dry_run_log = load_dry_run_log()
    dry_run_signal_ids = dry_run_log.get("dry_run_signal_ids", [])
    history = dry_run_log.get("history", [])

    for order in valid_dry_run_orders:
        signal_id = order.get("signal_id")

        if signal_id in dry_run_signal_ids:
            continue

        dry_run_signal_ids.append(signal_id)
        history.append(order)

    if len(history) > MAX_DRY_RUN_HISTORY:
        history = history[-MAX_DRY_RUN_HISTORY:]
        dry_run_signal_ids = [
            item["signal_id"]
            for item in history
            if item.get("signal_id")
        ]

    dry_run_log["dry_run_signal_ids"] = dry_run_signal_ids
    dry_run_log["history"] = history

    save_json_file(DRY_RUN_LOG_FILE, dry_run_log)


def print_dry_run_report(valid_dry_run_orders, rejected_orders):
    print("\n=== MT5 EXECUTOR DRY RUN ===")

    if valid_dry_run_orders:
        print("\n=== DRY-RUN ORDERS READY ===")
        print(
            f"{'SYMBOL':<10} "
            f"{'TYPE':>6} "
            f"{'LOT':>6} "
            f"{'ENTRY':>12} "
            f"{'SL':>12} "
            f"{'TP':>12} "
            f"{'STRATEGY':>18} "
            f"{'SCORE':>7}"
        )
        print("-" * 95)

        for order in valid_dry_run_orders:
            print(
                f"{order['symbol_mt5']:<10} "
                f"{order['order_type']:>6} "
                f"{order['volume']:>6.2f} "
                f"{order['entry_reference_price']:>12} "
                f"{order['stop_loss']:>12} "
                f"{order['take_profit']:>12} "
                f"{order.get('selected_strategy', 'UNKNOWN'):>18} "
                f"{order.get('strategy_score', 0):>7}"
            )
            print(f"  Signal ID: {order['signal_id']}")
            print("  Status: DRY_RUN_READY, no real order sent.")
    else:
        print("No order passed dry-run execution checks.")

    print("\n=== DRY-RUN REJECTED ORDERS ===")

    if not rejected_orders:
        print("No rejected order.")
        return

    for item in rejected_orders:
        print(
            f"❌ {item.get('symbol')} {item.get('order_type')} | "
            f"Signal: {item.get('signal_id')} | "
            f"Reason: {item.get('reason')}"
        )


def main():
    orders = load_mt5_orders()
    dry_run_log = load_dry_run_log()

    valid_dry_run_orders = []
    rejected_orders = []

    for order in orders:
        is_valid, reason, profile = validate_order(order, dry_run_log)

        if is_valid:
            dry_run_order = build_dry_run_order(order, profile)
            valid_dry_run_orders.append(dry_run_order)
        else:
            rejected_orders.append(
                {
                    "signal_id": order.get("signal_id"),
                    "symbol": order.get("symbol"),
                    "order_type": order.get("order_type"),
                    "reason": reason,
                }
            )

    print_dry_run_report(valid_dry_run_orders, rejected_orders)

    if valid_dry_run_orders:
        save_dry_run_results(valid_dry_run_orders)
        print(f"\nDry-run order log saved to: {DRY_RUN_LOG_FILE}")


if __name__ == "__main__":
    main()