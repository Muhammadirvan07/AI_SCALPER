import json
import pandas as pd

from strategy.trend_analyzer import analyze_trend
from agents.volatility_agent import get_atr
from agents.supervisor_agent import SupervisorAgent

INITIAL_BALANCE = 50.0
RISK_PER_TRADE = 0.5
COOLDOWN_CANDLES = 10
MAX_HOLD_CANDLES = 50

SYMBOLS = [
    "eurusd",
    "gbpusd",
    "usdjpy",
    "usdchf",
    "audusd",
    "nzdusd",
    "usdcad",
    "eurjpy",
    "gbpjpy",
    "eurgbp",
    "audjpy",
    "cadjpy",
    "chfjpy",
    "xauusd",
    "btcusd",
]


ACTIVE_SYMBOL = "xauusd"  # ubah ke: eurusd, gbpusd, usdjpy, xauusd, btcusd, dll

MIN_TRADES_FOR_ACTIVE_PAIR = 20

# =========================
# SYMBOL-SPECIFIC ACTIVE PAIR FILTER
# =========================

DEFAULT_MIN_PROFIT_FACTOR_FOR_ACTIVE_PAIR = 1.10

SYMBOL_MIN_PROFIT_FACTOR_FOR_ACTIVE_PAIR = {
    "XAUUSD": 1.20,
    "BTCUSD": 1.25,
}

MIN_PROFIT_FACTOR_FOR_ACTIVE_PAIR = DEFAULT_MIN_PROFIT_FACTOR_FOR_ACTIVE_PAIR
MIN_EXPECTANCY_FOR_ACTIVE_PAIR = 0.0
MIN_NET_PROFIT_FOR_ACTIVE_PAIR = 0.0
MAX_ACTIVE_PAIRS = 4
ACTIVE_PAIRS_OUTPUT = "active_pairs.json"
PAPER_REPLAY_CANDIDATES_FILE = "paper_replay_candidates.json"

USE_REPLAY_FILTER_FOR_ACTIVE_PAIRS = True
REPLAY_FILTER_REQUIRE_GLOBAL_CANDIDATES = True


def get_min_profit_factor_for_active_pair(symbol):
    symbol = str(symbol or "").upper()
    return SYMBOL_MIN_PROFIT_FACTOR_FOR_ACTIVE_PAIR.get(
        symbol,
        DEFAULT_MIN_PROFIT_FACTOR_FOR_ACTIVE_PAIR,
    )


# =========================
# REPLAY CANDIDATE FILTER FOR ACTIVE PAIRS
# =========================

def load_json_file(filename, default_value):
    try:
        with open(filename, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return default_value
    except json.JSONDecodeError:
        print(f"⚠️ Failed to parse {filename}. Using safe default.")
        return default_value


def load_replay_candidate_filter():
    if not USE_REPLAY_FILTER_FOR_ACTIVE_PAIRS:
        return {
            "enabled": False,
            "global_status": "DISABLED",
            "approved_symbols": set(),
            "blocked_symbols": set(),
            "reason": "Replay filter disabled for active pair selection.",
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
        "reason": candidate_data.get("global_action", "Replay candidate filter loaded."),
    }


def apply_replay_filter_to_backtest_results(results, replay_filter):
    if not replay_filter.get("enabled", False):
        return results

    global_status = replay_filter.get("global_status", "UNKNOWN")
    approved_symbols = replay_filter.get("approved_symbols", set())
    blocked_symbols = replay_filter.get("blocked_symbols", set())
    filtered_results = []

    for item in results:
        symbol = str(item.get("symbol", "")).upper()
        item["replay_filter_status"] = "ACCEPTED"
        item["replay_filter_reason"] = "Symbol passed replay filter."

        if symbol in blocked_symbols:
            item["replay_filter_status"] = "REJECTED"
            item["replay_filter_reason"] = f"{symbol} is blocked by replay candidate filter."
            continue

        if REPLAY_FILTER_REQUIRE_GLOBAL_CANDIDATES and global_status != "CANDIDATES_AVAILABLE":
            item["replay_filter_status"] = "REJECTED"
            item["replay_filter_reason"] = f"Replay global status is {global_status}; active pair promotion is blocked."
            continue

        if approved_symbols and symbol not in approved_symbols:
            item["replay_filter_status"] = "REJECTED"
            item["replay_filter_reason"] = f"{symbol} is not in approved replay candidate symbols."
            continue

        filtered_results.append(item)

    return filtered_results


def print_replay_filter_summary(replay_filter):
    print("\n=== REPLAY FILTER FOR ACTIVE PAIRS ===")
    print(f"Enabled       : {replay_filter.get('enabled')}")
    print(f"Global status : {replay_filter.get('global_status')}")
    print(f"Approved      : {', '.join(sorted(replay_filter.get('approved_symbols', []))) or 'none'}")
    print(f"Blocked       : {', '.join(sorted(replay_filter.get('blocked_symbols', []))) or 'none'}")
    print(f"Reason        : {replay_filter.get('reason')}")


def print_replay_filter_rejections(results):
    rejected = [
        item for item in results
        if item.get("replay_filter_status") == "REJECTED"
    ]

    if not rejected:
        return

    print("\n=== REPLAY FILTER REJECTIONS ===")
    for item in rejected:
        print(
            f"🚫 {item['symbol']} | "
            f"Reason: {item.get('replay_filter_reason', 'Rejected by replay filter.')}"
        )

def classify_market_by_percent(atr, price):
    volatility_percent = (atr / price) * 100

    # Forex pairs have much smaller M1 percent volatility than XAUUSD/BTCUSD.
    if price < 300:
        high_threshold = 0.05
        normal_threshold = 0.006
    elif price < 10000:
        high_threshold = 0.35
        normal_threshold = 0.05
    else:
        high_threshold = 0.50
        normal_threshold = 0.03

    if volatility_percent > high_threshold:
        return "HIGH", volatility_percent

    if volatility_percent > normal_threshold:
        return "NORMAL", volatility_percent

    return "LOW", volatility_percent


def get_risk_model(atr, volatility_percent):
    if volatility_percent > 1.0:
        return {
            "market_mode": "HIGH_VOL",
            "sl_distance": atr * 2.0,
            "tp_distance": atr * 4.0,
            "reward_multiplier": 2.0,
            "trail_start_atr": 2.0,
            "trail_step_atr": 1.0,
        }

    if volatility_percent > 0.35:
        return {
            "market_mode": "NORMAL_VOL",
            "sl_distance": atr * 1.5,
            "tp_distance": atr * 3.0,
            "reward_multiplier": 2.0,
            "trail_start_atr": 2.5,
            "trail_step_atr": 1.25,
        }

    return {
        "market_mode": "LOW_VOL",
        "sl_distance": atr * 1.5,
        "tp_distance": atr * 2.5,
        "reward_multiplier": 1.67,
        "trail_start_atr": 3.0,
        "trail_step_atr": 1.5,
    }


def update_trailing_stop(decision, entry, atr, current_close, stop_loss, risk_model):
    trail_start_atr = risk_model["trail_start_atr"]
    trail_step_atr = risk_model["trail_step_atr"]

    if decision == "BUY":
        profit_atr = (current_close - entry) / atr

        if profit_atr >= trail_start_atr:
            locked_atr = max(0, profit_atr - trail_step_atr)
            new_stop = entry + (locked_atr * atr)
            return max(stop_loss, new_stop)

        return stop_loss

    profit_atr = (entry - current_close) / atr

    if profit_atr >= trail_start_atr:
        locked_atr = max(0, profit_atr - trail_step_atr)
        new_stop = entry - (locked_atr * atr)
        return min(stop_loss, new_stop)

    return stop_loss


def calculate_trade_result(decision, entry, stop_loss, take_profit, high, low):
    if decision == "BUY":
        if low <= stop_loss:
            if stop_loss > entry:
                return "TRAIL_WIN"
            if stop_loss == entry:
                return "BREAKEVEN"
            return "LOSS"

        if high >= take_profit:
            return "WIN"

    if decision == "SELL":
        if high >= stop_loss:
            if stop_loss < entry:
                return "TRAIL_WIN"
            if stop_loss == entry:
                return "BREAKEVEN"
            return "LOSS"

        if low <= take_profit:
            return "WIN"

    return None


def run_backtest(symbol, verbose=True):
    data_path = f"data/{symbol}.csv"
    df = pd.read_csv(data_path)

    balance = INITIAL_BALANCE
    supervisor = SupervisorAgent()
    last_trade_index = -999

    stats = {
        "symbol": symbol.upper(),
        "skipped_sideways": 0,
        "skipped_low_vol": 0,
        "skipped_wait": 0,
        "high_vol_count": 0,
        "low_vol_count": 0,
        "buy_count": 0,
        "sell_count": 0,
        "breakout_rejected": 0,
        "buy_wins": 0,
        "buy_losses": 0,
        "sell_wins": 0,
        "sell_losses": 0,
        "timeout_trades": 0,
        "trailing_stop_hits": 0,
        "gross_profit": 0.0,
        "gross_loss": 0.0,
        "total_win_amount": 0.0,
        "total_loss_amount": 0.0,
        "wins": 0,
        "losses": 0,
        "trades": 0,
    }

    if verbose:
        print(f"Backtest started for {symbol.upper()}...")

    for i in range(250, len(df) - 20):
        if i - last_trade_index < COOLDOWN_CANDLES:
            continue

        if verbose and i % 500 == 0:
            print(f"Processing candle {i}/{len(df)}")

        window = df.iloc[:i].copy()

        if len(window) < 250:
            continue

        signal = analyze_trend(window)
        current_close = window["Close"].iloc[-1]

        breakout_high = window["High"].iloc[-21:-1].max()
        breakout_low = window["Low"].iloc[-21:-1].min()

        atr = get_atr(window)

        market_status, current_volatility_percent = classify_market_by_percent(
            atr,
            current_close,
        )

        decision = supervisor.make_decision(
            signal,
            market_status,
        )

        if signal == "SIDEWAYS":
            stats["skipped_sideways"] += 1
            continue

        if signal == "BUY" and current_close <= breakout_high:
            stats["breakout_rejected"] += 1
            continue

        if signal == "SELL" and current_close >= breakout_low:
            stats["breakout_rejected"] += 1
            continue

        if market_status == "LOW":
            stats["skipped_low_vol"] += 1
            continue

        if decision == "WAIT":
            stats["skipped_wait"] += 1
            continue

        entry = df.iloc[i]["Close"]
        volatility_percent = (atr / entry) * 100
        risk_model = get_risk_model(atr, volatility_percent)

        if risk_model["market_mode"] == "HIGH_VOL":
            stats["high_vol_count"] += 1
        else:
            stats["low_vol_count"] += 1

        if decision == "BUY":
            stats["buy_count"] += 1
            stop_loss = entry - risk_model["sl_distance"]
            take_profit = entry + risk_model["tp_distance"]
        else:
            stats["sell_count"] += 1
            stop_loss = entry + risk_model["sl_distance"]
            take_profit = entry - risk_model["tp_distance"]

        trade_result = None

        for j in range(i + 1, min(i + MAX_HOLD_CANDLES, len(df))):
            current_close_forward = df.iloc[j]["Close"]

            stop_loss = update_trailing_stop(
                decision,
                entry,
                atr,
                current_close_forward,
                stop_loss,
                risk_model,
            )

            high = df.iloc[j]["High"]
            low = df.iloc[j]["Low"]

            trade_result = calculate_trade_result(
                decision,
                entry,
                stop_loss,
                take_profit,
                high,
                low,
            )

            if trade_result is not None:
                break

        if trade_result is None:
            stats["timeout_trades"] += 1
            continue

        stats["trades"] += 1
        last_trade_index = i

        if trade_result == "WIN":
            stats["wins"] += 1

            if decision == "BUY":
                stats["buy_wins"] += 1
            else:
                stats["sell_wins"] += 1

            profit_amount = RISK_PER_TRADE * risk_model["reward_multiplier"]

            stats["gross_profit"] += profit_amount
            stats["total_win_amount"] += profit_amount
            balance += profit_amount

        elif trade_result == "TRAIL_WIN":
            stats["wins"] += 1
            stats["trailing_stop_hits"] += 1

            if decision == "BUY":
                stats["buy_wins"] += 1
            else:
                stats["sell_wins"] += 1

            profit_amount = RISK_PER_TRADE

            stats["gross_profit"] += profit_amount
            stats["total_win_amount"] += profit_amount
            balance += profit_amount

        elif trade_result == "BREAKEVEN":
            stats["trailing_stop_hits"] += 1

        else:
            stats["losses"] += 1

            if decision == "BUY":
                stats["buy_losses"] += 1
            else:
                stats["sell_losses"] += 1

            loss_amount = RISK_PER_TRADE

            stats["gross_loss"] += loss_amount
            stats["total_loss_amount"] += loss_amount
            balance -= loss_amount

    stats["ending_balance"] = balance
    stats["net_profit"] = balance - INITIAL_BALANCE
    stats["win_rate"] = (
        stats["wins"] / stats["trades"] * 100
        if stats["trades"] > 0 else 0
    )
    stats["average_win"] = (
        stats["total_win_amount"] / stats["wins"]
        if stats["wins"] > 0 else 0
    )
    stats["average_loss"] = (
        stats["total_loss_amount"] / stats["losses"]
        if stats["losses"] > 0 else 0
    )
    stats["profit_factor"] = (
        stats["gross_profit"] / stats["gross_loss"]
        if stats["gross_loss"] > 0 else 0
    )

    win_rate_decimal = (
        stats["wins"] / stats["trades"]
        if stats["trades"] > 0 else 0
    )
    loss_rate_decimal = (
        stats["losses"] / stats["trades"]
        if stats["trades"] > 0 else 0
    )

    stats["expectancy"] = (
        (win_rate_decimal * stats["average_win"])
        - (loss_rate_decimal * stats["average_loss"])
    )

    if verbose:
        print_report(stats)

    return stats



def get_profitable_pairs(results):
    valid_pairs = []

    for item in results:
        symbol = item["symbol"]
        min_pf = get_min_profit_factor_for_active_pair(symbol)

        item["min_profit_factor_required"] = min_pf
        item["active_pair_filter_status"] = "REJECTED"
        item["active_pair_filter_reasons"] = []

        if item["trades"] < MIN_TRADES_FOR_ACTIVE_PAIR:
            item["active_pair_filter_reasons"].append(
                f"Trades {item['trades']} below minimum {MIN_TRADES_FOR_ACTIVE_PAIR}."
            )

        if item["profit_factor"] < min_pf:
            item["active_pair_filter_reasons"].append(
                f"PF {item['profit_factor']:.2f} below symbol-specific minimum {min_pf:.2f}."
            )

        if item["expectancy"] <= MIN_EXPECTANCY_FOR_ACTIVE_PAIR:
            item["active_pair_filter_reasons"].append(
                f"Expectancy {item['expectancy']:.4f} below or equal minimum {MIN_EXPECTANCY_FOR_ACTIVE_PAIR:.4f}."
            )

        if item["net_profit"] <= MIN_NET_PROFIT_FOR_ACTIVE_PAIR:
            item["active_pair_filter_reasons"].append(
                f"Net profit ${item['net_profit']:.2f} below or equal minimum ${MIN_NET_PROFIT_FOR_ACTIVE_PAIR:.2f}."
            )

        if not item["active_pair_filter_reasons"]:
            item["active_pair_filter_status"] = "ACCEPTED"
            valid_pairs.append(item)

    sorted_pairs = sorted(
        valid_pairs,
        key=lambda item: (
            item["profit_factor"],
            item["expectancy"],
            item["net_profit"],
        ),
        reverse=True,
    )

    return sorted_pairs[:MAX_ACTIVE_PAIRS]

def print_active_pair_source(active_pairs):
    print("\n=== ACTIVE PAIR SOURCE ===")

    if not active_pairs:
        print("ACTIVE_PAIRS = []")
        print("No pair passed the profitability filter.")
        return

    pair_names = [
        item["symbol"].lower()
        for item in active_pairs
    ]

    print(f"ACTIVE_PAIRS = {pair_names}")
    print("\nUse only these pairs for the AI trading focus.")

    print("\n=== ACTIVE PAIR DETAILS ===")
    for item in active_pairs:
        min_pf = item.get(
            "min_profit_factor_required",
            get_min_profit_factor_for_active_pair(item["symbol"]),
        )
        print(
            f"✅ {item['symbol']} | "
            f"Trades: {item['trades']} | "
            f"PF: {item['profit_factor']:.2f} / MinPF: {min_pf:.2f} | "
            f"Expectancy: {item['expectancy']:.4f} | "
            f"Net: ${item['net_profit']:.2f}"
        )

# Save active pairs and their details to a JSON file
def save_active_pairs(active_pairs):
    pair_names = [
        item["symbol"].lower()
        for item in active_pairs
    ]

    payload = {
        "active_pairs": pair_names,
        "criteria": {
            "min_trades": MIN_TRADES_FOR_ACTIVE_PAIR,
            "default_min_profit_factor": DEFAULT_MIN_PROFIT_FACTOR_FOR_ACTIVE_PAIR,
            "symbol_min_profit_factor": SYMBOL_MIN_PROFIT_FACTOR_FOR_ACTIVE_PAIR,
            "min_expectancy": MIN_EXPECTANCY_FOR_ACTIVE_PAIR,
            "min_net_profit": MIN_NET_PROFIT_FOR_ACTIVE_PAIR,
            "max_active_pairs": MAX_ACTIVE_PAIRS,
            "use_replay_filter_for_active_pairs": USE_REPLAY_FILTER_FOR_ACTIVE_PAIRS,
            "replay_filter_require_global_candidates": REPLAY_FILTER_REQUIRE_GLOBAL_CANDIDATES,
        },
            "details": active_pairs,
    }

    with open(ACTIVE_PAIRS_OUTPUT, "w") as file:
        json.dump(payload, file, indent=4)

    print(f"\nSaved active pair source to: {ACTIVE_PAIRS_OUTPUT}")


def print_multi_report(results):
    replay_filter = load_replay_candidate_filter()
    print_replay_filter_summary(replay_filter)

    sorted_results = sorted(
        results,
        key=lambda item: item["profit_factor"],
        reverse=True,
    )

    print("\n=== MULTI PAIR BACKTEST RANKING ===")
    print(
        f"{'PAIR':<8} "
        f"{'TRADES':>7} "
        f"{'WINRATE':>9} "
        f"{'PF':>6} "
        f"{'EXP':>8} "
        f"{'NET':>8} "
        f"{'SIDE':>7} "
        f"{'LOW':>6} "
        f"{'BO_REJ':>7}"
    )
    print("-" * 80)

    for item in sorted_results:
        print(
            f"{item['symbol']:<8} "
            f"{item['trades']:>7} "
            f"{item['win_rate']:>8.2f}% "
            f"{item['profit_factor']:>6.2f} "
            f"{item['expectancy']:>8.4f} "
            f"{item['net_profit']:>8.2f} "
            f"{item['skipped_sideways']:>7} "
            f"{item['skipped_low_vol']:>6} "
            f"{item['breakout_rejected']:>7}"
        )

    replay_filtered_results = apply_replay_filter_to_backtest_results(
        sorted_results,
        replay_filter,
    )
    print_replay_filter_rejections(sorted_results)

    profitable_pairs = get_profitable_pairs(replay_filtered_results)

    print("\n=== BEST PAIRS ===")

    if not profitable_pairs:
        print("No profitable pair found with current settings.")
        return

    for item in profitable_pairs:
        min_pf = item.get(
            "min_profit_factor_required",
            get_min_profit_factor_for_active_pair(item["symbol"]),
        )
        print(
            f"✅ {item['symbol']} | "
            f"PF: {item['profit_factor']:.2f} / MinPF: {min_pf:.2f} | "
            f"Net: ${item['net_profit']:.2f} | "
            f"WinRate: {item['win_rate']:.2f}%"
        )

    rejected_active_pairs = [
        item for item in sorted_results
        if item.get("active_pair_filter_status") == "REJECTED"
    ]

    if rejected_active_pairs:
        print("\n=== ACTIVE PAIR FILTER REJECTIONS ===")
        for item in rejected_active_pairs:
            min_pf = item.get(
                "min_profit_factor_required",
                get_min_profit_factor_for_active_pair(item["symbol"]),
            )
            reasons = " | ".join(item.get("active_pair_filter_reasons", []))
            print(
                f"❌ {item['symbol']} | "
                f"PF: {item['profit_factor']:.2f} / MinPF: {min_pf:.2f} | "
                f"Reason: {reasons}"
            )

    print_active_pair_source(profitable_pairs)
    save_active_pairs(profitable_pairs)

    print("\n=== WARNING NOTES ===")
    print("Pairs with trades < 20 are not statistically reliable yet.")
    print("High SIDE means trend filter is blocking most candles.")
    print("High LOW means volatility filter is too strict or market is quiet.")
    print("High BO_REJ means breakout confirmation is rejecting many signals.")
print("ACTIVE_PAIRS is generated from symbol-specific PF, expectancy, net profit, and minimum trade count.")

def run_multi_backtest():
    results = []

    for symbol in SYMBOLS:
        try:
            print(f"\nRunning {symbol.upper()}...")
            result = run_backtest(symbol, verbose=False)
            results.append(result)
        except FileNotFoundError:
            print(f"⚠️ Data file not found for {symbol.upper()}")
        except Exception as error:
            print(f"❌ Error on {symbol.upper()}: {error}")

    print_multi_report(results)

    replay_filter = load_replay_candidate_filter()
    replay_filtered_results = apply_replay_filter_to_backtest_results(
        results,
        replay_filter,
    )

    return get_profitable_pairs(replay_filtered_results)


def print_report(stats):
    print("\n=== DEBUG INFO ===")
    print(f"Skipped Sideways: {stats['skipped_sideways']}")
    print(f"Skipped Low Volatility: {stats['skipped_low_vol']}")
    print(f"Skipped WAIT Decision: {stats['skipped_wait']}")
    print(f"Executed Trades: {stats['trades']}")
    print(f"BUY Signals Executed: {stats['buy_count']}")
    print(f"SELL Signals Executed: {stats['sell_count']}")
    print(f"Breakout Rejected Signals: {stats['breakout_rejected']}")
    print(f"High Volatility Trades: {stats['high_vol_count']}")
    print(f"Low/Normal Volatility Trades: {stats['low_vol_count']}")
    print(f"BUY Wins: {stats['buy_wins']}")
    print(f"BUY Losses: {stats['buy_losses']}")
    print(f"SELL Wins: {stats['sell_wins']}")
    print(f"SELL Losses: {stats['sell_losses']}")
    print(f"Timeout Trades: {stats['timeout_trades']}")
    print(f"Trailing Stop Hits: {stats['trailing_stop_hits']}")
    print("Adaptive ATR Trailing Stop: ON")
    print("Adaptive Mode: ON")
    print("RSI Filter: ON")
    print("Breakout Confirmation: ON")
    print("Adaptive ATR Risk Model: ON")
    print("Pair-Adaptive Volatility Filter: ON")
    print("Risk Reward: Dynamic")

    print(f"Symbol: {stats['symbol']}")

    print("\n=== BACKTEST V1 RESULT ===")
    print(f"Trades: {stats['trades']}")
    print(f"Wins: {stats['wins']}")
    print(f"Losses: {stats['losses']}")
    print(f"Win Rate: {stats['win_rate']:.2f}%")
    print(f"Starting Balance: ${INITIAL_BALANCE:.2f}")
    print(f"Ending Balance: ${stats['ending_balance']:.2f}")
    print(f"Net Profit: ${stats['net_profit']:.2f}")

    print("\n=== ADVANCED STATS ===")
    print(f"Gross Profit: ${stats['gross_profit']:.2f}")
    print(f"Gross Loss: ${stats['gross_loss']:.2f}")
    print(f"Average Win: ${stats['average_win']:.2f}")
    print(f"Average Loss: ${stats['average_loss']:.2f}")
    print(f"Profit Factor: {stats['profit_factor']:.2f}")
    print(f"Expectancy: {stats['expectancy']:.4f}")


if __name__ == "__main__":
    run_multi_backtest()

    # Untuk test satu pair saja, matikan run_multi_backtest() lalu aktifkan baris ini.
    # run_backtest(ACTIVE_SYMBOL)