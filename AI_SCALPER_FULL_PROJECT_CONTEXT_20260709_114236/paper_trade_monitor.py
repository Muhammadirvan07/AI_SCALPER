import json
import os
from datetime import datetime, timezone

import pandas as pd

PAPER_ORDERS_FILE = "paper_orders.json"
PAPER_REPORT_FILE = "paper_report.json"
DATA_DIR = "data"

DEFAULT_WIN_USD = 0.50
DEFAULT_LOSS_USD = -0.25

# =========================
# PAPER TIME STOP CONFIG
# =========================

 # Phase 4 paper validation timeout.
# M1 data: 48 candles ≈ 48 minutes.
# This only affects paper order monitoring, not live trading.
MAX_HOLDING_CANDLES = 48
TIMEOUT_RESULT = "TIMEOUT"
TIMEOUT_STATUS = "PAPER_TIMEOUT"

# If market data stops updating after an order is created, the paper runner can look stuck.
# This safe timeout prevents one stale PAPER_OPEN order from blocking the whole forward loop forever.
STALE_ORDER_SAFE_TIMEOUT_MINUTES = 90
STALE_DATA_WARNING_MINUTES = 30


# =========================
# BASIC FILE HELPERS
# =========================

def load_json(path, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Failed to read {path}: {e}")
        return default


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def parse_datetime(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def utc_now():
    return datetime.now(timezone.utc)


def to_utc_timestamp(value):
    parsed = parse_datetime(value)

    if parsed is None:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return pd.Timestamp(parsed).tz_convert("UTC")


def minutes_since(value):
    ts = to_utc_timestamp(value)

    if ts is None:
        return None

    delta = utc_now() - ts.to_pydatetime()
    return max(0.0, delta.total_seconds() / 60)


def get_latest_market_snapshot(df):
    if df is None or df.empty:
        return {
            "last_market_candle_at": None,
            "last_market_close": None,
        }

    latest_row = df.iloc[-1]
    return {
        "last_market_candle_at": latest_row["Datetime"].isoformat(),
        "last_market_close": float(latest_row["Close"]),
    }


def build_result_info(
    status,
    result,
    close_price,
    closed_at,
    note,
    holding_candles=0,
    last_market_candle_at=None,
    last_market_close=None,
):
    return {
        "status": status,
        "result": result,
        "close_price": close_price,
        "closed_at": closed_at,
        "note": note,
        "holding_candles": int(holding_candles or 0),
        "last_checked_at": utc_now().isoformat(),
        "last_market_candle_at": last_market_candle_at,
        "last_market_close": last_market_close,
    }


# =========================
# MARKET DATA HELPERS
# =========================

def symbol_to_data_path(symbol):
    filename = f"{str(symbol).lower()}.csv"
    return os.path.join(DATA_DIR, filename)


def load_price_data(symbol):
    path = symbol_to_data_path(symbol)

    if not os.path.exists(path):
        print(f"Data file not found for {symbol}: {path}")
        return None

    try:
        df = pd.read_csv(path)
    except Exception as e:
        print(f"Failed to read price data for {symbol}: {e}")
        return None

    if df.empty:
        print(f"Price data is empty for {symbol}.")
        return None

    required_columns = {"Datetime", "Open", "High", "Low", "Close"}
    missing_columns = required_columns - set(df.columns)

    if missing_columns:
        print(f"Missing columns for {symbol}: {missing_columns}")
        return None

    df["Datetime"] = pd.to_datetime(df["Datetime"], errors="coerce", utc=True)
    df = df.dropna(subset=["Datetime"])

    for col in ["Open", "High", "Low", "Close"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.dropna(subset=["Open", "High", "Low", "Close"])
    df = df.sort_values("Datetime")

    if df.empty:
        print(f"No valid OHLC rows for {symbol}.")
        return None

    return df


def get_rows_after_order(df, created_at):
    order_time = to_utc_timestamp(created_at)
    latest_snapshot = get_latest_market_snapshot(df)

    if order_time is None:
        return df, "Order created_at is missing or invalid; checking all available rows.", latest_snapshot

    rows = df[df["Datetime"] > order_time]

    if rows.empty:
        last_market_candle_at = latest_snapshot.get("last_market_candle_at")
        last_market_close = latest_snapshot.get("last_market_close")
        age_minutes = minutes_since(created_at)

        if age_minutes is None:
            age_note = "order age unknown"
        else:
            age_note = f"order age {age_minutes:.1f} minutes"

        note = (
            "No new candle after order creation; order remains open. "
            f"Latest market candle: {last_market_candle_at}, "
            f"latest close: {last_market_close}, {age_note}."
        )
        return None, note, latest_snapshot

    return rows, "New candles found after order creation.", latest_snapshot


# =========================
# ORDER MONITORING LOGIC
# =========================

def calculate_actual_rr(order):
    order_type = str(order.get("type", "")).upper()
    entry = float(order.get("entry", 0) or 0)
    sl = float(order.get("sl", 0) or 0)
    tp = float(order.get("tp", 0) or 0)

    if order_type == "BUY":
        risk_distance = entry - sl
        reward_distance = tp - entry
    elif order_type == "SELL":
        risk_distance = sl - entry
        reward_distance = entry - tp
    else:
        return 0.0

    if risk_distance <= 0 or reward_distance <= 0:
        return 0.0

    return reward_distance / risk_distance


def calculate_timeout_profit(order, close_price):
    order_type = str(order.get("type", "")).upper()
    entry = float(order.get("entry", 0) or 0)
    sl = float(order.get("sl", 0) or 0)
    close_price = float(close_price or 0)
    risk_usd = abs(float(order.get("risk_usd", 0.25) or 0.25))

    if entry <= 0 or sl <= 0 or close_price <= 0:
        return 0.0

    if order_type == "BUY":
        risk_distance = entry - sl
        price_r = (close_price - entry) / risk_distance if risk_distance > 0 else 0.0
    elif order_type == "SELL":
        risk_distance = sl - entry
        price_r = (entry - close_price) / risk_distance if risk_distance > 0 else 0.0
    else:
        return 0.0

    return round(risk_usd * price_r, 4)


def calculate_profit(order, result, close_price=None):
    risk_usd = abs(float(order.get("risk_usd", 0.25) or 0.25))

    if result == "WIN":
        rr = calculate_actual_rr(order)
        if rr <= 0:
            return 0.0
        return round(risk_usd * rr, 4)

    if result == "LOSS":
        return -risk_usd

    if result == TIMEOUT_RESULT:
        return calculate_timeout_profit(order, close_price)

    return 0.0


def check_order_result(order, df):
    order_type = str(order.get("type", "")).upper()
    entry = float(order.get("entry", 0) or 0)
    sl = float(order.get("sl", 0) or 0)
    tp = float(order.get("tp", 0) or 0)

    if order_type not in ["BUY", "SELL"]:
        return None

    if entry <= 0 or sl <= 0 or tp <= 0:
        return None

    rows, row_note, latest_snapshot = get_rows_after_order(df, order.get("created_at"))
    last_market_candle_at = latest_snapshot.get("last_market_candle_at")
    last_market_close = latest_snapshot.get("last_market_close")

    if rows is None:
        order_age_minutes = minutes_since(order.get("created_at"))

        if order_age_minutes is not None and order_age_minutes >= STALE_ORDER_SAFE_TIMEOUT_MINUTES:
            return build_result_info(
                status=TIMEOUT_STATUS,
                result=TIMEOUT_RESULT,
                close_price=last_market_close,
                closed_at=last_market_candle_at or utc_now().isoformat(),
                note=(
                    f"Safe stale-data timeout reached after {order_age_minutes:.1f} minutes. "
                    "No candle newer than order creation was available, so the order was closed "
                    "to prevent the paper forward runner from being blocked forever."
                ),
                holding_candles=0,
                last_market_candle_at=last_market_candle_at,
                last_market_close=last_market_close,
            )

        warning = ""
        if order_age_minutes is not None and order_age_minutes >= STALE_DATA_WARNING_MINUTES:
            warning = " Data is stale; run data_collector.py before the next monitor check."

        return build_result_info(
            status="PAPER_OPEN",
            result=None,
            close_price=None,
            closed_at=None,
            note=row_note + warning,
            holding_candles=0,
            last_market_candle_at=last_market_candle_at,
            last_market_close=last_market_close,
        )

    total_rows_after_order = len(rows)
    rows_to_check = rows.head(MAX_HOLDING_CANDLES)
    last_checked_row = rows.iloc[-1]
    last_market_candle_at = last_checked_row["Datetime"].isoformat()
    last_market_close = float(last_checked_row["Close"])

    for _, row in rows_to_check.iterrows():
        high = float(row["High"])
        low = float(row["Low"])
        close_time = row["Datetime"].isoformat()

        if order_type == "BUY":
            hit_sl = low <= sl
            hit_tp = high >= tp

            if hit_sl and hit_tp:
                return build_result_info(
                    status="PAPER_LOSS",
                    result="LOSS",
                    close_price=sl,
                    closed_at=close_time,
                    note="Both TP and SL touched in same candle; conservative result = LOSS.",
                    holding_candles=total_rows_after_order,
                    last_market_candle_at=last_market_candle_at,
                    last_market_close=last_market_close,
                )

            if hit_sl:
                return build_result_info(
                    status="PAPER_LOSS",
                    result="LOSS",
                    close_price=sl,
                    closed_at=close_time,
                    note="SL touched.",
                    holding_candles=total_rows_after_order,
                    last_market_candle_at=last_market_candle_at,
                    last_market_close=last_market_close,
                )

            if hit_tp:
                return build_result_info(
                    status="PAPER_WIN",
                    result="WIN",
                    close_price=tp,
                    closed_at=close_time,
                    note="TP touched.",
                    holding_candles=total_rows_after_order,
                    last_market_candle_at=last_market_candle_at,
                    last_market_close=last_market_close,
                )

        if order_type == "SELL":
            hit_sl = high >= sl
            hit_tp = low <= tp

            if hit_sl and hit_tp:
                return build_result_info(
                    status="PAPER_LOSS",
                    result="LOSS",
                    close_price=sl,
                    closed_at=close_time,
                    note="Both TP and SL touched in same candle; conservative result = LOSS.",
                    holding_candles=total_rows_after_order,
                    last_market_candle_at=last_market_candle_at,
                    last_market_close=last_market_close,
                )

            if hit_sl:
                return build_result_info(
                    status="PAPER_LOSS",
                    result="LOSS",
                    close_price=sl,
                    closed_at=close_time,
                    note="SL touched.",
                    holding_candles=total_rows_after_order,
                    last_market_candle_at=last_market_candle_at,
                    last_market_close=last_market_close,
                )

            if hit_tp:
                return build_result_info(
                    status="PAPER_WIN",
                    result="WIN",
                    close_price=tp,
                    closed_at=close_time,
                    note="TP touched.",
                    holding_candles=total_rows_after_order,
                    last_market_candle_at=last_market_candle_at,
                    last_market_close=last_market_close,
                )

    if total_rows_after_order >= MAX_HOLDING_CANDLES:
        timeout_row = rows_to_check.iloc[-1]
        timeout_close = float(timeout_row["Close"])
        timeout_time = timeout_row["Datetime"].isoformat()

        return build_result_info(
            status=TIMEOUT_STATUS,
            result=TIMEOUT_RESULT,
            close_price=timeout_close,
            closed_at=timeout_time,
            note=f"Time stop reached after {MAX_HOLDING_CANDLES} candles; closed at last available close.",
            holding_candles=total_rows_after_order,
            last_market_candle_at=last_market_candle_at,
            last_market_close=last_market_close,
        )

    return build_result_info(
        status="PAPER_OPEN",
        result=None,
        close_price=None,
        closed_at=None,
        note=f"Still open; TP/SL not touched yet. Holding candles: {total_rows_after_order}/{MAX_HOLDING_CANDLES}.",
        holding_candles=total_rows_after_order,
        last_market_candle_at=last_market_candle_at,
        last_market_close=last_market_close,
    )


def update_order(order, result_info):
    if result_info is None:
        order["monitor_note"] = "Invalid order or insufficient data."
        return order

    if result_info["status"] == "PAPER_OPEN":
        order["monitor_note"] = result_info["note"]
        order["holding_candles"] = result_info.get("holding_candles", order.get("holding_candles", 0))
        order["last_checked_at"] = result_info.get("last_checked_at")
        order["last_market_candle_at"] = result_info.get("last_market_candle_at")
        order["last_market_close"] = result_info.get("last_market_close")
        return order

    order["status"] = result_info["status"]
    order["result"] = result_info["result"]
    order["close_price"] = result_info["close_price"]
    order["closed_at"] = result_info["closed_at"]
    order["actual_rr"] = round(calculate_actual_rr(order), 4)
    order["profit_usd"] = calculate_profit(order, result_info["result"], result_info["close_price"])
    order["monitor_note"] = result_info["note"]
    order["holding_candles"] = result_info.get("holding_candles", order.get("holding_candles", 0))
    order["last_checked_at"] = result_info.get("last_checked_at")
    order["last_market_candle_at"] = result_info.get("last_market_candle_at")
    order["last_market_close"] = result_info.get("last_market_close")

    return order


# =========================
# REPORTING
# =========================

def build_report(orders):
    total = len(orders)
    wins = sum(1 for order in orders if order.get("result") == "WIN")
    losses = sum(1 for order in orders if order.get("result") == "LOSS")
    timeouts = sum(1 for order in orders if order.get("result") == TIMEOUT_RESULT)
    open_orders = sum(1 for order in orders if order.get("status") == "PAPER_OPEN")
    stale_open_orders = sum(
        1
        for order in orders
        if order.get("status") == "PAPER_OPEN"
        and "No new candle after order creation" in str(order.get("monitor_note", ""))
    )
    closed = wins + losses + timeouts

    gross_profit = sum(float(order.get("profit_usd", 0) or 0) for order in orders if float(order.get("profit_usd", 0) or 0) > 0)
    gross_loss = abs(sum(float(order.get("profit_usd", 0) or 0) for order in orders if float(order.get("profit_usd", 0) or 0) < 0))
    net_profit = gross_profit - gross_loss

    winrate = (wins / closed * 100) if closed > 0 else 0.0
    profit_factor = (gross_profit / gross_loss) if gross_loss > 0 else None
    expectancy = (net_profit / closed) if closed > 0 else 0.0

    by_symbol = {}
    by_strategy = {}

    for order in orders:
        symbol = order.get("symbol", "UNKNOWN")
        strategy = order.get("strategy", "UNKNOWN")

        by_symbol.setdefault(symbol, {"total": 0, "wins": 0, "losses": 0, "profit_usd": 0.0})
        by_strategy.setdefault(strategy, {"total": 0, "wins": 0, "losses": 0, "profit_usd": 0.0})

        for bucket in [by_symbol[symbol], by_strategy[strategy]]:
            bucket["total"] += 1
            bucket["profit_usd"] += float(order.get("profit_usd", 0) or 0)

            if order.get("result") == "WIN":
                bucket["wins"] += 1
            elif order.get("result") == "LOSS":
                bucket["losses"] += 1
            elif order.get("result") == TIMEOUT_RESULT:
                bucket.setdefault("timeouts", 0)
                bucket["timeouts"] += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_orders": total,
        "closed_orders": closed,
        "open_orders": open_orders,
        "stale_open_orders": stale_open_orders,
        "wins": wins,
        "losses": losses,
        "timeouts": timeouts,
        "winrate_percent": round(winrate, 2),
        "gross_profit_usd": round(gross_profit, 2),
        "gross_loss_usd": round(gross_loss, 2),
        "net_profit_usd": round(net_profit, 2),
        "profit_factor": round(profit_factor, 2) if profit_factor is not None else None,
        "expectancy_usd": round(expectancy, 4),
        "by_symbol": by_symbol,
        "by_strategy": by_strategy,
    }


def print_report(report):
    print("\n=== PAPER TRADING REPORT ===")
    print(f"Total orders : {report['total_orders']}")
    print(f"Closed orders: {report['closed_orders']}")
    print(f"Open orders  : {report['open_orders']}")
    print(f"Stale opens  : {report.get('stale_open_orders', 0)}")
    print(f"Wins         : {report['wins']}")
    print(f"Losses       : {report['losses']}")
    print(f"Timeouts     : {report.get('timeouts', 0)}")
    print(f"Time stop    : {MAX_HOLDING_CANDLES} candles")
    print(f"Safe timeout : {STALE_ORDER_SAFE_TIMEOUT_MINUTES} minutes")
    print(f"Winrate      : {report['winrate_percent']}%")
    print(f"Net profit   : ${report['net_profit_usd']}")
    print(f"Profit factor: {report['profit_factor']}")
    print(f"Expectancy   : ${report['expectancy_usd']}")


# =========================
# MAIN
# =========================

def main():
    print("\n=== AI_SCALPER PAPER TRADE MONITOR ===")

    orders = load_json(PAPER_ORDERS_FILE, [])

    if not orders:
        print("No paper orders found.")
        return

    updated_orders = []

    for order in orders:
        symbol = order.get("symbol", "UNKNOWN")
        status = order.get("status", "UNKNOWN")

        if status != "PAPER_OPEN":
            updated_orders.append(order)
            continue

        df = load_price_data(symbol)

        if df is None:
            order["monitor_note"] = "No price data available."
            updated_orders.append(order)
            continue

        result_info = check_order_result(order, df)
        order = update_order(order, result_info)
        updated_orders.append(order)

        print(
            f"{symbol} {order.get('type')} | "
            f"Entry: {order.get('entry')} | "
            f"SL: {order.get('sl')} | "
            f"TP: {order.get('tp')} | "
            f"Status: {order.get('status')} | "
            f"Result: {order.get('result')}"
        )

    save_json(PAPER_ORDERS_FILE, updated_orders)

    report = build_report(updated_orders)
    save_json(PAPER_REPORT_FILE, report)
    print_report(report)

    print(f"\nUpdated paper orders saved to: {PAPER_ORDERS_FILE}")
    print(f"Paper report saved to: {PAPER_REPORT_FILE}")


if __name__ == "__main__":
    main()