import json
import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pandas as pd

DATA_DIR = "data"
PAPER_REPLAY_ORDERS_FILE = "paper_replay_orders.json"
PAPER_REPLAY_REPORT_FILE = "paper_replay_report.json"
PAPER_REPLAY_CANDIDATES_FILE = "paper_replay_candidates.json"
OFFLINE_DASHBOARD_REPORT_FILE = "offline_dashboard_report.json"
ACTIVE_PAIRS_FILE = "active_pairs.json"

LOCAL_TIMEZONE = "Asia/Tokyo"
TEST_MODE_AUTO = "AUTO"
TEST_MODE_WEEKDAY = "WEEKDAY_MARKET_TEST"
TEST_MODE_WEEKEND = "WEEKEND_OFFLINE_TEST"

STARTING_BALANCE = 50.0
RISK_PER_TRADE_USD = 0.25
MAX_REPLAY_TRADES = 100
MAX_OPEN_REPLAY_ORDERS = 1
MAX_HOLDING_CANDLES = 96

MIN_SCORE_TO_TRADE = 5
MIN_ATR_PERCENT = 0.00025
MIN_BREAKOUT_ATR_MULT = 0.10
MIN_BODY_TO_RANGE_RATIO = 0.40
MIN_EMA_DISTANCE_ATR_MULT = 0.15

EMA_FAST = 20
EMA_SLOW = 50
ATR_PERIOD = 14

SL_ATR_MULT = 1.5
TP_ATR_MULT = 2.5

REPLAY_GUARD_MIN_CLOSED_ORDERS = 10
REPLAY_GUARD_MIN_WINRATE_PERCENT = 40.0
REPLAY_GUARD_REQUIRE_POSITIVE_NET = True

REPLAY_CANDIDATE_MIN_CLOSED_ORDERS = 5
REPLAY_CANDIDATE_MIN_WINRATE_PERCENT = 45.0
REPLAY_CANDIDATE_MIN_PROFIT_FACTOR = 1.10
REPLAY_CANDIDATE_MIN_EXPECTANCY_USD = 0.01


def load_json(path, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def normalize_symbol_from_filename(filename):
    name = filename.replace(".csv", "")
    return name.upper()


def get_current_test_mode():
    if TEST_MODE_AUTO != "AUTO":
        return TEST_MODE_AUTO

    now_local = datetime.now(ZoneInfo(LOCAL_TIMEZONE))
    now_utc = datetime.now(timezone.utc)

    local_weekday = now_local.weekday()  # Monday=0, Sunday=6
    utc_weekday = now_utc.weekday()
    utc_hour = now_utc.hour

    # Forex market is normally closed from Friday late UTC until Sunday late UTC.
    # This keeps weekday/live-session testing efficient and sends weekends to offline testing.
    if utc_weekday == 5:
        return TEST_MODE_WEEKEND

    if utc_weekday == 6 and utc_hour < 22:
        return TEST_MODE_WEEKEND

    if utc_weekday == 4 and utc_hour >= 22:
        return TEST_MODE_WEEKEND

    if local_weekday in {5, 6}:
        return TEST_MODE_WEEKEND

    return TEST_MODE_WEEKDAY


def load_market_data(symbol):
    possible_files = [
        os.path.join(DATA_DIR, f"{symbol.lower()}.csv"),
        os.path.join(DATA_DIR, f"{symbol.upper()}.csv"),
        os.path.join(DATA_DIR, f"{symbol}.csv"),
    ]

    path = None
    for file_path in possible_files:
        if os.path.exists(file_path):
            path = file_path
            break

    if path is None:
        return None

    df = pd.read_csv(path)

    if "Datetime" in df.columns:
        df["Datetime"] = pd.to_datetime(df["Datetime"], errors="coerce")
    elif "Date" in df.columns:
        df["Datetime"] = pd.to_datetime(df["Date"], errors="coerce")
    else:
        df["Datetime"] = pd.to_datetime(df.index, errors="coerce")

    required = ["Open", "High", "Low", "Close"]
    for col in required:
        if col not in df.columns:
            return None

    df = df.dropna(subset=["Datetime", "Open", "High", "Low", "Close"]).copy()
    df = df.sort_values("Datetime").reset_index(drop=True)

    for col in required:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.dropna(subset=required).reset_index(drop=True)

    return df


def add_indicators(df):
    df = df.copy()

    df["ema_fast"] = df["Close"].ewm(span=EMA_FAST, adjust=False).mean()
    df["ema_slow"] = df["Close"].ewm(span=EMA_SLOW, adjust=False).mean()

    high_low = df["High"] - df["Low"]
    high_close = (df["High"] - df["Close"].shift(1)).abs()
    low_close = (df["Low"] - df["Close"].shift(1)).abs()

    true_range = pd.concat([high_low, high_close, low_close], axis=1).max(axis=1)
    df["atr"] = true_range.rolling(ATR_PERIOD).mean()
    df["atr_percent"] = df["atr"] / df["Close"]

    return df


def get_symbols_from_active_pairs_file():
    active_pairs_data = load_json(ACTIVE_PAIRS_FILE, {})

    if isinstance(active_pairs_data, list):
        return [str(symbol).upper() for symbol in active_pairs_data]

    if isinstance(active_pairs_data, dict):
        pairs = active_pairs_data.get("active_pairs", [])
        if isinstance(pairs, list):
            return [str(symbol).upper() for symbol in pairs]

    return []


def get_symbols_from_replay_candidates_file():
    candidate_data = load_json(PAPER_REPLAY_CANDIDATES_FILE, {})

    if not isinstance(candidate_data, dict):
        return []

    approved = candidate_data.get("approved_symbols", [])
    blocked = candidate_data.get("blocked_symbols", [])

    blocked_symbols = {
        str(item.get("symbol", "")).upper()
        for item in blocked
        if isinstance(item, dict)
    }

    symbols = []
    for item in approved:
        if not isinstance(item, dict):
            continue

        symbol = str(item.get("symbol", "")).upper()
        if symbol and symbol not in blocked_symbols:
            symbols.append(symbol)

    return symbols


# New function to get blocked symbols from replay candidates file
def get_blocked_symbols_from_replay_candidates_file():
    candidate_data = load_json(PAPER_REPLAY_CANDIDATES_FILE, {})

    if not isinstance(candidate_data, dict):
        return set()

    blocked = candidate_data.get("blocked_symbols", [])

    return {
        str(item.get("symbol", "")).upper()
        for item in blocked
        if isinstance(item, dict) and str(item.get("symbol", "")).strip()
    }


def get_active_pairs_from_offline_report():
    report = load_json(OFFLINE_DASHBOARD_REPORT_FILE, {})
    symbol_performance = report.get("symbol_performance", {}) if isinstance(report, dict) else {}

    if not isinstance(symbol_performance, dict) or not symbol_performance:
        return []

    symbols = []
    for symbol, item in symbol_performance.items():
        net = safe_float(item.get("net_profit_usd", 0))
        closed = int(item.get("closed_orders", 0) or 0)
        winrate = safe_float(item.get("winrate_percent", 0))

        if closed >= 3 and net >= 0 and winrate >= 40:
            symbols.append(symbol.upper())

    return symbols


def get_available_symbols(test_mode):
    if not os.path.exists(DATA_DIR):
        return []

    symbols = []

    for filename in os.listdir(DATA_DIR):
        if filename.endswith(".csv"):
            symbols.append(normalize_symbol_from_filename(filename))

    blocked_symbols = get_blocked_symbols_from_replay_candidates_file()
    if blocked_symbols:
        symbols = [symbol for symbol in symbols if symbol not in blocked_symbols]

    if test_mode == TEST_MODE_WEEKDAY:
        active_pairs = get_symbols_from_active_pairs_file()
        if active_pairs:
            filtered = [symbol for symbol in active_pairs if symbol in symbols]
            if filtered:
                return filtered

        preferred = get_active_pairs_from_offline_report()
        if preferred:
            filtered = [symbol for symbol in preferred if symbol in symbols]
            if filtered:
                return filtered

    if test_mode == TEST_MODE_WEEKEND:
        replay_candidates = get_symbols_from_replay_candidates_file()
        if replay_candidates:
            filtered = [symbol for symbol in replay_candidates if symbol in symbols]
            if filtered:
                return filtered

        preferred = get_active_pairs_from_offline_report()
        if preferred:
            filtered = [symbol for symbol in preferred if symbol in symbols]
            if filtered:
                return filtered

    return symbols


def calculate_score(row, previous_row):
    score = 0
    reasons = []

    atr = safe_float(row.get("atr"), 0.0)
    close = safe_float(row.get("Close"), 0.0)
    open_price = safe_float(row.get("Open"), 0.0)
    high = safe_float(row.get("High"), 0.0)
    low = safe_float(row.get("Low"), 0.0)
    ema_fast = safe_float(row.get("ema_fast"), 0.0)
    ema_slow = safe_float(row.get("ema_slow"), 0.0)

    candle_range = high - low
    candle_body = abs(close - open_price)
    body_ratio = candle_body / candle_range if candle_range > 0 else 0.0
    ema_distance = abs(ema_fast - ema_slow)

    if row["atr_percent"] >= MIN_ATR_PERCENT:
        score += 1
        reasons.append("ATR ok")
    else:
        reasons.append("ATR low")

    if ema_distance >= atr * MIN_EMA_DISTANCE_ATR_MULT:
        score += 1
        reasons.append("EMA distance ok")
    else:
        reasons.append("EMA distance weak")

    if body_ratio >= MIN_BODY_TO_RANGE_RATIO:
        score += 1
        reasons.append("Candle body ok")
    else:
        reasons.append("Candle body weak")

    breakout_buffer = atr * MIN_BREAKOUT_ATR_MULT

    if ema_fast > ema_slow:
        trend = "BUY"
        score += 1
        reasons.append("Bullish EMA")
    elif ema_fast < ema_slow:
        trend = "SELL"
        score += 1
        reasons.append("Bearish EMA")
    else:
        trend = "WAIT"
        reasons.append("EMA flat")

    if trend == "BUY" and close > safe_float(previous_row["High"]) + breakout_buffer:
        score += 2
        reasons.append("Bullish breakout with ATR buffer")
    elif trend == "SELL" and close < safe_float(previous_row["Low"]) - breakout_buffer:
        score += 2
        reasons.append("Bearish breakout with ATR buffer")
    else:
        reasons.append("No valid breakout")

    return score, trend, reasons


def create_replay_order(symbol, df, index, action, score, reasons):
    row = df.iloc[index]
    entry = safe_float(row["Close"])
    atr = safe_float(row["atr"])

    if atr <= 0:
        return None

    if action == "BUY":
        sl = entry - (atr * SL_ATR_MULT)
        tp = entry + (atr * TP_ATR_MULT)
    elif action == "SELL":
        sl = entry + (atr * SL_ATR_MULT)
        tp = entry - (atr * TP_ATR_MULT)
    else:
        return None

    return {
        "order_id": f"REPLAY_{symbol}_{index}_{int(datetime.now(timezone.utc).timestamp())}",
        "symbol": symbol,
        "type": action,
        "strategy": "REPLAY_EMA_BREAKOUT",
        "score": score,
        "entry": entry,
        "sl": round(sl, 8),
        "tp": round(tp, 8),
        "risk_usd": RISK_PER_TRADE_USD,
        "open_index": index,
        "open_time": str(row["Datetime"]),
        "close_index": None,
        "closed_at": None,
        "status": "REPLAY_OPEN",
        "result": None,
        "profit_usd": 0.0,
        "reasons": reasons,
    }


def close_replay_order(order, df, current_index):
    row = df.iloc[current_index]
    high = safe_float(row["High"])
    low = safe_float(row["Low"])
    close = safe_float(row["Close"])

    entry = safe_float(order["entry"])
    sl = safe_float(order["sl"])
    tp = safe_float(order["tp"])
    action = order["type"]

    bars_held = current_index - int(order["open_index"])

    result = None
    profit = 0.0

    if action == "BUY":
        hit_sl = low <= sl
        hit_tp = high >= tp

        if hit_sl and hit_tp:
            result = "LOSS"
            profit = -RISK_PER_TRADE_USD
        elif hit_sl:
            result = "LOSS"
            profit = -RISK_PER_TRADE_USD
        elif hit_tp:
            result = "WIN"
            rr = abs(tp - entry) / abs(entry - sl)
            profit = RISK_PER_TRADE_USD * rr

    elif action == "SELL":
        hit_sl = high >= sl
        hit_tp = low <= tp

        if hit_sl and hit_tp:
            result = "LOSS"
            profit = -RISK_PER_TRADE_USD
        elif hit_sl:
            result = "LOSS"
            profit = -RISK_PER_TRADE_USD
        elif hit_tp:
            result = "WIN"
            rr = abs(entry - tp) / abs(sl - entry)
            profit = RISK_PER_TRADE_USD * rr

    if result is None and bars_held >= MAX_HOLDING_CANDLES:
        result = "TIMEOUT"

        if action == "BUY":
            raw_rr = (close - entry) / abs(entry - sl)
        else:
            raw_rr = (entry - close) / abs(sl - entry)

        profit = RISK_PER_TRADE_USD * raw_rr

    if result is None:
        return order

    order["close_index"] = current_index
    order["closed_at"] = str(row["Datetime"])
    order["status"] = f"REPLAY_{result}"
    order["result"] = result
    order["profit_usd"] = round(profit, 4)

    return order


def summarize_orders_by_key(orders, key):
    groups = {}

    for order in orders:
        if order.get("result") not in {"WIN", "LOSS", "TIMEOUT"}:
            continue

        name = str(order.get(key, "UNKNOWN") or "UNKNOWN").upper()
        groups.setdefault(name, {
            "closed_orders": 0,
            "wins": 0,
            "losses": 0,
            "timeouts": 0,
            "net_profit_usd": 0.0,
        })

        bucket = groups[name]
        bucket["closed_orders"] += 1
        bucket["net_profit_usd"] += safe_float(order.get("profit_usd"), 0.0)

        if order.get("result") == "WIN":
            bucket["wins"] += 1
        elif order.get("result") == "LOSS":
            bucket["losses"] += 1
        elif order.get("result") == "TIMEOUT":
            bucket["timeouts"] += 1

    for bucket in groups.values():
        closed = bucket["closed_orders"]
        wins = bucket["wins"]
        bucket["winrate_percent"] = round((wins / closed) * 100, 2) if closed > 0 else 0.0
        bucket["net_profit_usd"] = round(bucket["net_profit_usd"], 4)

    return groups


def build_replay_guard_recommendations(orders):
    symbol_performance = summarize_orders_by_key(orders, "symbol")
    strategy_performance = summarize_orders_by_key(orders, "strategy")
    recommendations = []

    for symbol, item in symbol_performance.items():
        closed = int(item.get("closed_orders", 0) or 0)
        winrate = safe_float(item.get("winrate_percent", 0))
        net_profit = safe_float(item.get("net_profit_usd", 0))

        weak_sample = closed >= REPLAY_GUARD_MIN_CLOSED_ORDERS
        weak_winrate = winrate < REPLAY_GUARD_MIN_WINRATE_PERCENT
        weak_net = net_profit < 0 if REPLAY_GUARD_REQUIRE_POSITIVE_NET else False

        if weak_sample and weak_winrate and weak_net:
            recommendations.append({
                "level": "HIGH",
                "type": "REPLAY_WEAK_SYMBOL",
                "target": symbol,
                "closed_orders": closed,
                "winrate_percent": round(winrate, 2),
                "net_profit_usd": round(net_profit, 4),
                "recommendation": "Require higher score, add stricter filter, or exclude this symbol from replay candidate until performance improves.",
            })
        elif weak_sample and weak_winrate:
            recommendations.append({
                "level": "MEDIUM",
                "type": "REPLAY_SYMBOL_WATCH",
                "target": symbol,
                "closed_orders": closed,
                "winrate_percent": round(winrate, 2),
                "net_profit_usd": round(net_profit, 4),
                "recommendation": "Watch this symbol. Winrate is weak, but net is not negative yet.",
            })

    for strategy, item in strategy_performance.items():
        closed = int(item.get("closed_orders", 0) or 0)
        winrate = safe_float(item.get("winrate_percent", 0))
        net_profit = safe_float(item.get("net_profit_usd", 0))

        weak_sample = closed >= REPLAY_GUARD_MIN_CLOSED_ORDERS
        weak_winrate = winrate < REPLAY_GUARD_MIN_WINRATE_PERCENT
        weak_net = net_profit < 0 if REPLAY_GUARD_REQUIRE_POSITIVE_NET else False

        if weak_sample and weak_winrate and weak_net:
            recommendations.append({
                "level": "HIGH",
                "type": "REPLAY_WEAK_STRATEGY",
                "target": strategy,
                "closed_orders": closed,
                "winrate_percent": round(winrate, 2),
                "net_profit_usd": round(net_profit, 4),
                "recommendation": "Require higher score or add stricter confirmation before using this strategy.",
            })
        elif weak_sample and weak_winrate:
            recommendations.append({
                "level": "MEDIUM",
                "type": "REPLAY_STRATEGY_WATCH",
                "target": strategy,
                "closed_orders": closed,
                "winrate_percent": round(winrate, 2),
                "net_profit_usd": round(net_profit, 4),
                "recommendation": "Watch this strategy. Winrate is weak, but net is not negative yet.",
            })

    if not recommendations:
        recommendations.append({
            "level": "INFO",
            "type": "REPLAY_NO_WEAKNESS_DETECTED",
            "target": "ALL",
            "closed_orders": 0,
            "winrate_percent": 0.0,
            "net_profit_usd": 0.0,
            "recommendation": "No replay guard action required from current sample.",
        })

    return recommendations

def build_replay_candidates(report):
    symbol_performance = report.get("symbol_performance", {})
    candidate_symbols = []
    watch_symbols = []
    blocked_symbols = []

    total_profit_factor = safe_float(report.get("profit_factor", 0.0))
    total_expectancy = safe_float(report.get("expectancy_usd", 0.0))

    for symbol, item in symbol_performance.items():
        closed = int(item.get("closed_orders", 0) or 0)
        winrate = safe_float(item.get("winrate_percent", 0.0))
        net_profit = safe_float(item.get("net_profit_usd", 0.0))

        symbol_status = {
            "symbol": symbol,
            "closed_orders": closed,
            "winrate_percent": round(winrate, 2),
            "net_profit_usd": round(net_profit, 4),
        }

        if closed < REPLAY_CANDIDATE_MIN_CLOSED_ORDERS:
            symbol_status["status"] = "WATCH_LOW_SAMPLE"
            symbol_status["reason"] = "Sample is still too small for candidate approval."
            watch_symbols.append(symbol_status)

        elif winrate >= REPLAY_CANDIDATE_MIN_WINRATE_PERCENT and net_profit > 0:
            symbol_status["status"] = "APPROVED_REPLAY_CANDIDATE"
            symbol_status["reason"] = "Symbol passed replay winrate and net profit requirements."
            candidate_symbols.append(symbol_status)

        elif net_profit < 0:
            symbol_status["status"] = "BLOCKED_WEAK_REPLAY_SYMBOL"
            symbol_status["reason"] = "Symbol has negative replay net profit and should be excluded from next replay candidate set."
            blocked_symbols.append(symbol_status)

        else:
            symbol_status["status"] = "WATCH_WEAK_WINRATE"
            symbol_status["reason"] = "Symbol is not negative, but winrate is still below candidate threshold."
            watch_symbols.append(symbol_status)

    if total_profit_factor < REPLAY_CANDIDATE_MIN_PROFIT_FACTOR or total_expectancy < REPLAY_CANDIDATE_MIN_EXPECTANCY_USD:
        global_status = "NOT_READY"
        global_action = "Keep replay in research mode. Do not promote candidates yet."
    elif not candidate_symbols:
        global_status = "WATCH_BUILDING"
        global_action = "Global replay quality is acceptable, but no symbol has enough clean confirmation yet."
    else:
        global_status = "CANDIDATES_AVAILABLE"
        global_action = "Use approved replay candidates for the next paper-only decision filter. Keep DRY_RUN locked."

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "PAPER_REPLAY_ONLY",
        "live_allowed": False,
        "global_status": global_status,
        "global_action": global_action,
        "requirements": {
            "min_closed_orders_per_symbol": REPLAY_CANDIDATE_MIN_CLOSED_ORDERS,
            "min_winrate_percent": REPLAY_CANDIDATE_MIN_WINRATE_PERCENT,
            "min_profit_factor": REPLAY_CANDIDATE_MIN_PROFIT_FACTOR,
            "min_expectancy_usd": REPLAY_CANDIDATE_MIN_EXPECTANCY_USD,
        },
        "approved_symbols": candidate_symbols,
        "watch_symbols": watch_symbols,
        "blocked_symbols": blocked_symbols,
    }


def summarize_orders(orders, test_mode):
    closed = [
        order for order in orders
        if order.get("result") in {"WIN", "LOSS", "TIMEOUT"}
    ]

    wins = sum(1 for order in closed if order.get("result") == "WIN")
    losses = sum(1 for order in closed if order.get("result") == "LOSS")
    timeouts = sum(1 for order in closed if order.get("result") == "TIMEOUT")

    gross_profit = sum(
        safe_float(order.get("profit_usd"))
        for order in closed
        if safe_float(order.get("profit_usd")) > 0
    )

    gross_loss = abs(sum(
        safe_float(order.get("profit_usd"))
        for order in closed
        if safe_float(order.get("profit_usd")) < 0
    ))

    net_profit = sum(safe_float(order.get("profit_usd")) for order in closed)
    profit_factor = gross_profit / gross_loss if gross_loss > 0 else 999.0 if gross_profit > 0 else 0.0
    winrate = (wins / len(closed)) * 100 if closed else 0.0
    expectancy = net_profit / len(closed) if closed else 0.0

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "test_mode": test_mode,
        "starting_balance": STARTING_BALANCE,
        "ending_balance": round(STARTING_BALANCE + net_profit, 4),
        "total_orders": len(orders),
        "closed_orders": len(closed),
        "wins": wins,
        "losses": losses,
        "timeouts": timeouts,
        "winrate_percent": round(winrate, 2),
        "gross_profit_usd": round(gross_profit, 4),
        "gross_loss_usd": round(gross_loss, 4),
        "net_profit_usd": round(net_profit, 4),
        "profit_factor": round(profit_factor, 4),
        "expectancy_usd": round(expectancy, 4),
        "symbol_performance": summarize_orders_by_key(orders, "symbol"),
        "strategy_performance": summarize_orders_by_key(orders, "strategy"),
        "replay_guard_recommendations": build_replay_guard_recommendations(orders),
    }


def run_symbol_replay(symbol):
    df = load_market_data(symbol)

    if df is None or len(df) < EMA_SLOW + ATR_PERIOD + MAX_HOLDING_CANDLES:
        return []

    df = add_indicators(df)
    df = df.dropna().reset_index(drop=True)

    orders = []
    open_order = None

    for index in range(EMA_SLOW + ATR_PERIOD + 1, len(df)):
        if len([order for order in orders if order.get("result")]) >= MAX_REPLAY_TRADES:
            break

        if open_order is not None:
            open_order = close_replay_order(open_order, df, index)

            if open_order.get("result") is not None:
                orders.append(open_order)
                open_order = None

            continue

        previous_row = df.iloc[index - 1]
        row = df.iloc[index]

        score, action, reasons = calculate_score(row, previous_row)

        if action in {"BUY", "SELL"} and score >= MIN_SCORE_TO_TRADE:
            open_order = create_replay_order(symbol, df, index, action, score, reasons)

    if open_order is not None:
        orders.append(open_order)

    return orders


def main():
    test_mode = get_current_test_mode()
    symbols = get_available_symbols(test_mode)

    if not symbols:
        print("No CSV data found in data/*.csv")
        return

    print("=" * 72)
    print("AI_SCALPER PAPER REPLAY RUNNER")
    print("=" * 72)
    print(f"Test mode: {test_mode}")
    print(f"Symbols: {', '.join(symbols)}")
    print(f"Max replay trades: {MAX_REPLAY_TRADES}")
    print(f"Min score: {MIN_SCORE_TO_TRADE}")
    print(f"Risk/order: ${RISK_PER_TRADE_USD}")
    print("=" * 72)

    all_orders = []

    for symbol in symbols:
        print(f"Running replay for {symbol}...")
        symbol_orders = run_symbol_replay(symbol)
        closed_count = len([order for order in symbol_orders if order.get("result")])
        print(f"- {symbol}: {closed_count} closed replay orders")
        all_orders.extend(symbol_orders)

    report = summarize_orders(all_orders, test_mode)
    candidates = build_replay_candidates(report)

    save_json(PAPER_REPLAY_ORDERS_FILE, all_orders)
    save_json(PAPER_REPLAY_REPORT_FILE, report)
    save_json(PAPER_REPLAY_CANDIDATES_FILE, candidates)

    print("\n" + "=" * 72)
    print("PAPER REPLAY REPORT")
    print("=" * 72)
    print(f"Test mode     : {report['test_mode']}")
    print(f"Total orders  : {report['total_orders']}")
    print(f"Closed orders : {report['closed_orders']}")
    print(f"Wins          : {report['wins']}")
    print(f"Losses        : {report['losses']}")
    print(f"Timeouts      : {report['timeouts']}")
    print(f"Winrate       : {report['winrate_percent']}%")
    print(f"Net profit    : ${report['net_profit_usd']}")
    print(f"Profit factor : {report['profit_factor']}")
    print(f"Expectancy    : ${report['expectancy_usd']}")

    print("\nSYMBOL PERFORMANCE")
    for symbol, item in report.get("symbol_performance", {}).items():
        print(
            f"- {symbol}: Closed {item['closed_orders']} | "
            f"W/L/T {item['wins']}/{item['losses']}/{item['timeouts']} | "
            f"Winrate {item['winrate_percent']}% | Net ${item['net_profit_usd']}"
        )

    print("\nSTRATEGY PERFORMANCE")
    for strategy, item in report.get("strategy_performance", {}).items():
        print(
            f"- {strategy}: Closed {item['closed_orders']} | "
            f"W/L/T {item['wins']}/{item['losses']}/{item['timeouts']} | "
            f"Winrate {item['winrate_percent']}% | Net ${item['net_profit_usd']}"
        )

    print("\nREPLAY CANDIDATE FILTER")
    print(f"Status        : {candidates['global_status']}")
    print(f"Action        : {candidates['global_action']}")

    approved = candidates.get("approved_symbols", [])
    watch = candidates.get("watch_symbols", [])
    blocked = candidates.get("blocked_symbols", [])

    if approved:
        print("Approved symbols:")
        for item in approved:
            print(
                f"- {item['symbol']}: Closed {item['closed_orders']} | "
                f"Winrate {item['winrate_percent']}% | Net ${item['net_profit_usd']}"
            )
    else:
        print("Approved symbols: none")

    if watch:
        print("Watch symbols:")
        for item in watch:
            print(
                f"- {item['symbol']}: {item['status']} | Closed {item['closed_orders']} | "
                f"Winrate {item['winrate_percent']}% | Net ${item['net_profit_usd']}"
            )

    if blocked:
        print("Blocked symbols:")
        for item in blocked:
            print(
                f"- {item['symbol']}: Closed {item['closed_orders']} | "
                f"Winrate {item['winrate_percent']}% | Net ${item['net_profit_usd']}"
            )

    print("=" * 72)
    print(f"Saved orders     : {PAPER_REPLAY_ORDERS_FILE}")
    print(f"Saved report     : {PAPER_REPLAY_REPORT_FILE}")
    print(f"Saved candidates : {PAPER_REPLAY_CANDIDATES_FILE}")


if __name__ == "__main__":
    main()