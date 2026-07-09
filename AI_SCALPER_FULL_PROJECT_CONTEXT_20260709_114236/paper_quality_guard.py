import json
import os
from collections import defaultdict
from datetime import datetime, timezone


# =========================
# FILES
# =========================

PAPER_REPORT_FILE = "paper_report.json"
PAPER_ORDERS_FILE = "paper_orders.json"
QUALITY_REPORT_FILE = "paper_quality_report.json"
QUALITY_RULES_FILE = "paper_quality_rules.json"


# =========================
# PHASE 4 QUALITY THRESHOLDS
# =========================

MIN_CLOSED_ORDERS_FOR_WATCH = 10
MIN_CLOSED_ORDERS_FOR_READY = 30
QUALITY_SAMPLE_WINDOW = 30
NEXT_VALIDATION_TARGET_CLOSED_ORDERS = 50

MIN_WINRATE_FOR_WATCH = 40.0
MIN_WINRATE_FOR_READY = 45.0

MIN_PROFIT_FACTOR_FOR_WATCH = 1.05
MIN_PROFIT_FACTOR_FOR_READY = 1.20

MIN_EXPECTANCY_FOR_WATCH = 0.01
MIN_EXPECTANCY_FOR_READY = 0.03

MAX_DRAWDOWN_PERCENT_FOR_WATCH = 5.0
MAX_DRAWDOWN_PERCENT_FOR_READY = 3.0

RECENT_WINDOW_SIZE = 5
RECENT_MIN_NET_PROFIT_USD_FOR_READY = 0.0
RECENT_MAX_LOSS_STREAK_FOR_READY = 2
MAX_RECENT_LOSS_STREAK = 3

MIN_GROUP_CLOSED_TO_GUARD = 5
MIN_GROUP_CLOSED_TO_BLOCK = 6
GROUP_PRIORITY_MIN_WINRATE = 45.0
GROUP_WATCH_MIN_WINRATE = 35.0
GROUP_RESTRICT_MIN_WINRATE = 25.0

BASE_MIN_SCORE = 4
WATCH_MIN_SCORE = 4
RESTRICT_MIN_SCORE = 5
BLOCK_MIN_SCORE = 99

STATUS_PRIORITY = "PRIORITY"
STATUS_WATCH = "WATCH"
STATUS_RESTRICT = "RESTRICT"
STATUS_BLOCK = "BLOCK"
STATUS_INSUFFICIENT = "INSUFFICIENT_SAMPLE"

# =========================
# PHASE 4B HARD REFINEMENT
# =========================
# Phase 4 target has been reached, but winrate is still below READY.
# These overrides are paper-only guard refinements to improve entry quality.
# Live trading remains locked by design.
PHASE4B_HARD_REFINEMENT_ENABLED = True
PHASE4B_FORCE_BLOCK_STRATEGIES = {"TREND_FOLLOWING"}
PHASE4B_FORCE_SYMBOL_MIN_SCORE = {
    "GBPUSD": 6,
}
PHASE4B_PRIORITY_SYMBOLS = {"EURUSD"}


# =========================
# BASIC HELPERS
# =========================


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()



def load_json(path, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as exc:
        print(f"Failed to read {path}: {exc}")
        return default



def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)



def safe_float(value, default=0.0):
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default



def safe_int(value, default=0):
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default



def get_closed_orders(orders):
    if not isinstance(orders, list):
        return []

    closed_statuses = {"PAPER_WIN", "PAPER_LOSS", "PAPER_TIMEOUT"}
    closed_results = {"WIN", "LOSS", "TIMEOUT"}

    return [
        order
        for order in orders
        if order.get("status") in closed_statuses
        or order.get("result") in closed_results
    ]



def get_quality_sample_orders(closed_orders, window_size=QUALITY_SAMPLE_WINDOW):
    if not isinstance(closed_orders, list):
        return []

    if window_size <= 0:
        return closed_orders

    return closed_orders[-window_size:]


def get_open_orders(orders):
    if not isinstance(orders, list):
        return []

    return [order for order in orders if order.get("status") == "PAPER_OPEN"]



def is_win(order):
    return order.get("result") == "WIN" or order.get("status") == "PAPER_WIN"



def is_loss(order):
    return order.get("result") == "LOSS" or order.get("status") == "PAPER_LOSS"



def is_timeout(order):
    return order.get("result") == "TIMEOUT" or order.get("status") == "PAPER_TIMEOUT"


# =========================
# METRIC HELPERS
# =========================



def calculate_profit_factor(closed_orders):
    gross_profit = sum(
        safe_float(order.get("profit_usd"))
        for order in closed_orders
        if safe_float(order.get("profit_usd")) > 0
    )
    gross_loss = abs(
        sum(
            safe_float(order.get("profit_usd"))
            for order in closed_orders
            if safe_float(order.get("profit_usd")) < 0
        )
    )

    if gross_loss == 0:
        return 999.0 if gross_profit > 0 else 0.0

    return gross_profit / gross_loss



def calculate_expectancy(closed_orders):
    if not closed_orders:
        return 0.0

    net_profit = sum(safe_float(order.get("profit_usd")) for order in closed_orders)
    return net_profit / len(closed_orders)



def calculate_winrate(wins, closed):
    if closed <= 0:
        return 0.0

    return (wins / closed) * 100.0



def get_recent_loss_streak(closed_orders):
    streak = 0

    for order in reversed(closed_orders):
        if is_loss(order):
            streak += 1
        elif is_win(order):
            break

    return streak



def summarize_recent_orders(closed_orders, limit=RECENT_WINDOW_SIZE):
    recent = closed_orders[-limit:]
    wins = sum(1 for order in recent if is_win(order))
    losses = sum(1 for order in recent if is_loss(order))
    timeouts = sum(1 for order in recent if is_timeout(order))
    net_profit = sum(safe_float(order.get("profit_usd")) for order in recent)

    current_loss_streak = 0
    max_loss_streak = 0

    for order in recent:
        if is_loss(order):
            current_loss_streak += 1
            max_loss_streak = max(max_loss_streak, current_loss_streak)
        else:
            current_loss_streak = 0

    return {
        "window_size": limit,
        "sample_size": len(recent),
        "wins": wins,
        "losses": losses,
        "timeouts": timeouts,
        "net_profit_usd": round(net_profit, 4),
        "max_loss_streak": max_loss_streak,
    }



def build_equity_curve_and_drawdown(closed_orders, starting_balance=50.0):
    equity = starting_balance
    peak = starting_balance
    max_drawdown_usd = 0.0
    max_drawdown_percent = 0.0
    curve = []

    for index, order in enumerate(closed_orders, start=1):
        profit = safe_float(order.get("profit_usd"))
        equity += profit
        peak = max(peak, equity)

        drawdown_usd = peak - equity
        drawdown_percent = (drawdown_usd / peak * 100.0) if peak > 0 else 0.0
        max_drawdown_usd = max(max_drawdown_usd, drawdown_usd)
        max_drawdown_percent = max(max_drawdown_percent, drawdown_percent)

        curve.append({
            "index": index,
            "paper_order_id": order.get("paper_order_id"),
            "symbol": order.get("symbol"),
            "strategy": order.get("strategy"),
            "result": order.get("result"),
            "profit_usd": round(profit, 4),
            "equity": round(equity, 4),
            "drawdown_usd": round(drawdown_usd, 4),
            "drawdown_percent": round(drawdown_percent, 2),
        })

    return {
        "starting_balance": starting_balance,
        "ending_balance": round(equity, 4),
        "max_drawdown_usd": round(max_drawdown_usd, 4),
        "max_drawdown_percent": round(max_drawdown_percent, 2),
        "curve": curve[-50:],
    }



def calculate_metrics_from_orders(orders, open_orders_count=None, total_orders_count=None):
    closed_orders = get_closed_orders(orders)
    open_orders = get_open_orders(orders)
    wins = sum(1 for order in closed_orders if is_win(order))
    losses = sum(1 for order in closed_orders if is_loss(order))
    timeouts = sum(1 for order in closed_orders if is_timeout(order))
    closed = len(closed_orders)
    gross_profit = sum(
        safe_float(order.get("profit_usd"))
        for order in closed_orders
        if safe_float(order.get("profit_usd")) > 0
    )
    gross_loss = abs(
        sum(
            safe_float(order.get("profit_usd"))
            for order in closed_orders
            if safe_float(order.get("profit_usd")) < 0
        )
    )
    net_profit = gross_profit - gross_loss

    if open_orders_count is None:
        open_orders_count = len(open_orders)

    if total_orders_count is None:
        total_orders_count = len(orders) if isinstance(orders, list) else 0

    return {
        "total_orders": total_orders_count,
        "closed_orders": closed,
        "open_orders": open_orders_count,
        "wins": wins,
        "losses": losses,
        "timeouts": timeouts,
        "winrate_percent": round(calculate_winrate(wins, closed), 2),
        "gross_profit_usd": round(gross_profit, 4),
        "gross_loss_usd": round(gross_loss, 4),
        "net_profit_usd": round(net_profit, 4),
        "profit_factor": round(calculate_profit_factor(closed_orders), 4),
        "expectancy_usd": round(calculate_expectancy(closed_orders), 4),
    }



def build_group_quality(orders, key):
    result = defaultdict(lambda: {
        "closed_orders": 0,
        "wins": 0,
        "losses": 0,
        "timeouts": 0,
        "net_profit_usd": 0.0,
    })

    for order in get_closed_orders(orders):
        name = str(order.get(key, "UNKNOWN") or "UNKNOWN").upper()
        bucket = result[name]
        bucket["closed_orders"] += 1
        bucket["net_profit_usd"] += safe_float(order.get("profit_usd"))

        if is_win(order):
            bucket["wins"] += 1
        elif is_loss(order):
            bucket["losses"] += 1
        elif is_timeout(order):
            bucket["timeouts"] += 1

    formatted = {}

    for name, bucket in result.items():
        closed = bucket["closed_orders"]
        closed_subset = [
            order for order in get_closed_orders(orders)
            if str(order.get(key, "UNKNOWN") or "UNKNOWN").upper() == name
        ]
        bucket["winrate_percent"] = round(calculate_winrate(bucket["wins"], closed), 2)
        bucket["profit_factor"] = round(calculate_profit_factor(closed_subset), 4)
        bucket["expectancy_usd"] = round(calculate_expectancy(closed_subset), 4)
        bucket["net_profit_usd"] = round(bucket["net_profit_usd"], 4)
        formatted[name] = dict(bucket)

    return dict(sorted(formatted.items()))


# =========================
# PHASE 4 GROUP GUARD RULES
# =========================



def classify_group(bucket):
    closed = safe_int(bucket.get("closed_orders"))
    winrate = safe_float(bucket.get("winrate_percent"))
    net_profit = safe_float(bucket.get("net_profit_usd"))
    pf = safe_float(bucket.get("profit_factor"))
    exp = safe_float(bucket.get("expectancy_usd"))

    if closed < MIN_GROUP_CLOSED_TO_GUARD:
        return {
            "guard_status": STATUS_INSUFFICIENT,
            "min_score_required": BASE_MIN_SCORE,
            "allow_new_entries": True,
            "reason": f"Sample kecil: {closed} closed orders. Belum cukup untuk strict guard.",
        }

    if closed >= MIN_GROUP_CLOSED_TO_BLOCK and winrate < GROUP_RESTRICT_MIN_WINRATE and net_profit < 0:
        return {
            "guard_status": STATUS_BLOCK,
            "min_score_required": BLOCK_MIN_SCORE,
            "allow_new_entries": False,
            "reason": f"BLOCK: closed={closed}, winrate={winrate:.2f}%, net=${net_profit:.4f}.",
        }

    if winrate < GROUP_WATCH_MIN_WINRATE or net_profit < 0:
        return {
            "guard_status": STATUS_RESTRICT,
            "min_score_required": RESTRICT_MIN_SCORE,
            "allow_new_entries": True,
            "reason": f"RESTRICT: closed={closed}, winrate={winrate:.2f}%, net=${net_profit:.4f}. Require score >= 5.",
        }

    if winrate >= GROUP_PRIORITY_MIN_WINRATE and net_profit >= 0 and pf >= MIN_PROFIT_FACTOR_FOR_READY and exp >= 0:
        return {
            "guard_status": STATUS_PRIORITY,
            "min_score_required": BASE_MIN_SCORE,
            "allow_new_entries": True,
            "reason": f"PRIORITY: closed={closed}, winrate={winrate:.2f}%, PF={pf:.4f}, net=${net_profit:.4f}.",
        }

    return {
        "guard_status": STATUS_WATCH,
        "min_score_required": WATCH_MIN_SCORE,
        "allow_new_entries": True,
        "reason": f"WATCH: closed={closed}, winrate={winrate:.2f}%, net=${net_profit:.4f}. Require score >= 4.",
    }



def apply_phase4b_hard_refinement(name, group_type, rule):
    if not PHASE4B_HARD_REFINEMENT_ENABLED:
        return rule

    name_upper = str(name or "UNKNOWN").upper()
    group_type_upper = str(group_type or "").upper()
    refined = dict(rule)
    refinement_reasons = list(refined.get("phase4b_refinement_reasons", []))

    if group_type_upper == "STRATEGY" and name_upper in PHASE4B_FORCE_BLOCK_STRATEGIES:
        refined["guard_status"] = STATUS_BLOCK
        refined["min_score_required"] = BLOCK_MIN_SCORE
        refined["allow_new_entries"] = False
        refinement_reasons.append(
            "PHASE4B_FORCE_BLOCK: Strategy is temporarily blocked after Phase 4 review because winrate/quality is not READY."
        )

    if group_type_upper == "SYMBOL" and name_upper in PHASE4B_FORCE_SYMBOL_MIN_SCORE:
        forced_min_score = safe_int(PHASE4B_FORCE_SYMBOL_MIN_SCORE[name_upper], RESTRICT_MIN_SCORE)
        refined["guard_status"] = STATUS_RESTRICT
        refined["min_score_required"] = max(
            safe_int(refined.get("min_score_required"), BASE_MIN_SCORE),
            forced_min_score,
        )
        refined["allow_new_entries"] = True
        refinement_reasons.append(
            f"PHASE4B_SYMBOL_RESTRICT: {name_upper} requires score >= {refined['min_score_required']} after Phase 4 review."
        )

    if group_type_upper == "SYMBOL" and name_upper in PHASE4B_PRIORITY_SYMBOLS:
        if refined.get("guard_status") not in {STATUS_BLOCK, STATUS_RESTRICT}:
            refined["guard_status"] = STATUS_PRIORITY
            refined["min_score_required"] = max(
                safe_int(refined.get("min_score_required"), BASE_MIN_SCORE),
                BASE_MIN_SCORE,
            )
            refined["allow_new_entries"] = True
            refinement_reasons.append(
                f"PHASE4B_PRIORITY_SYMBOL: {name_upper} remains the preferred paper-validation symbol."
            )

    if refinement_reasons:
        base_reason = refined.get("reason", "")
        refined["phase4b_refinement"] = True
        refined["phase4b_refinement_reasons"] = refinement_reasons
        refined["reason"] = (base_reason + " | " if base_reason else "") + " | ".join(refinement_reasons)

    return refined


def build_group_rules(group_quality, group_type):
    rules = {}

    for name, bucket in group_quality.items():
        classification = classify_group(bucket)
        rule = {
            "type": group_type,
            "name": name,
            **bucket,
            **classification,
        }
        rules[name] = apply_phase4b_hard_refinement(name, group_type, rule)

    return rules


def build_recommendations(symbol_rules, strategy_rules):
    recommendations = []

    def add_recommendation(rule, item_type):
        name = rule["name"]
        status = rule["guard_status"]

        if status == STATUS_BLOCK:
            recommendations.append({
                "priority": "HIGH",
                "type": f"{item_type}_BLOCK",
                "name": name,
                "action": "Block until future paper data improves.",
                "min_score_required": rule["min_score_required"],
                "reason": rule["reason"],
            })
        elif status == STATUS_RESTRICT:
            min_score = safe_int(rule.get("min_score_required"), RESTRICT_MIN_SCORE)
            recommendations.append({
                "priority": "HIGH",
                "type": f"{item_type}_RESTRICT",
                "name": name,
                "action": f"Require score >= {min_score} before execution.",
                "min_score_required": min_score,
                "reason": rule["reason"],
            })
        elif status == STATUS_WATCH:
            recommendations.append({
                "priority": "MEDIUM",
                "type": f"{item_type}_WATCH",
                "name": name,
                "action": "Require score >= 4 and avoid score 3 entries.",
                "min_score_required": rule["min_score_required"],
                "reason": rule["reason"],
            })
        elif status == STATUS_PRIORITY:
            recommendations.append({
                "priority": "LOW",
                "type": f"{item_type}_PRIORITY",
                "name": name,
                "action": "Best current profile. Keep allowed in paper mode with score >= 4.",
                "min_score_required": rule["min_score_required"],
                "reason": rule["reason"],
            })

    for rule in symbol_rules.values():
        add_recommendation(rule, "SYMBOL")

    for rule in strategy_rules.values():
        add_recommendation(rule, "STRATEGY")

    priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    recommendations.sort(key=lambda item: (priority_order.get(item["priority"], 9), item["type"], item["name"]))
    return recommendations


# =========================
# QUALITY STATUS
# =========================



def evaluate_status(metrics, drawdown, recent_performance, recent_loss_streak):
    closed_orders = safe_int(metrics.get("closed_orders"))
    winrate = safe_float(metrics.get("winrate_percent"))
    profit_factor = safe_float(metrics.get("profit_factor"))
    expectancy = safe_float(metrics.get("expectancy_usd"))
    max_dd = safe_float(drawdown.get("max_drawdown_percent"))

    blocking_reasons = []
    warnings = []
    strengths = []

    if closed_orders < MIN_CLOSED_ORDERS_FOR_WATCH:
        blocking_reasons.append(
            f"Closed orders masih {closed_orders}. Minimal {MIN_CLOSED_ORDERS_FOR_WATCH} untuk WATCH."
        )

    if closed_orders < MIN_CLOSED_ORDERS_FOR_READY:
        warnings.append(
            f"Belum cukup data untuk READY. Butuh minimal {MIN_CLOSED_ORDERS_FOR_READY} closed orders."
        )
    else:
        strengths.append("Sample size is sufficient for READY evaluation.")

    if recent_loss_streak >= MAX_RECENT_LOSS_STREAK:
        blocking_reasons.append(
            f"Loss streak terakhir {recent_loss_streak}. Maksimal aman {MAX_RECENT_LOSS_STREAK - 1}."
        )
    else:
        strengths.append("Loss streak aman.")

    if max_dd > MAX_DRAWDOWN_PERCENT_FOR_WATCH:
        blocking_reasons.append(
            f"Max drawdown {max_dd:.2f}% exceeds WATCH limit {MAX_DRAWDOWN_PERCENT_FOR_WATCH:.2f}%."
        )
    elif max_dd > MAX_DRAWDOWN_PERCENT_FOR_READY:
        warnings.append(
            f"Max drawdown {max_dd:.2f}% exceeds READY target {MAX_DRAWDOWN_PERCENT_FOR_READY:.2f}%."
        )
    else:
        strengths.append("Drawdown is controlled.")

    if recent_performance["sample_size"] >= RECENT_WINDOW_SIZE:
        if recent_performance["net_profit_usd"] < RECENT_MIN_NET_PROFIT_USD_FOR_READY:
            warnings.append(
                f"Recent {RECENT_WINDOW_SIZE} orders net ${recent_performance['net_profit_usd']:.4f} below READY target."
            )
        else:
            strengths.append("Recent performance is acceptable.")

        if recent_performance["max_loss_streak"] > RECENT_MAX_LOSS_STREAK_FOR_READY:
            warnings.append(
                f"Recent max loss streak {recent_performance['max_loss_streak']} exceeds READY target {RECENT_MAX_LOSS_STREAK_FOR_READY}."
            )

    if profit_factor >= MIN_PROFIT_FACTOR_FOR_READY:
        strengths.append(f"Profit factor {profit_factor} sudah di atas target READY {MIN_PROFIT_FACTOR_FOR_READY}.")
    elif profit_factor >= MIN_PROFIT_FACTOR_FOR_WATCH:
        strengths.append(f"Profit factor {profit_factor} sudah masuk area WATCH.")
    else:
        warnings.append(f"Profit factor {profit_factor} masih di bawah WATCH {MIN_PROFIT_FACTOR_FOR_WATCH}.")

    if winrate >= MIN_WINRATE_FOR_READY:
        strengths.append(f"Winrate {winrate}% sudah di atas target READY {MIN_WINRATE_FOR_READY}%.")
    elif winrate >= MIN_WINRATE_FOR_WATCH:
        strengths.append(f"Winrate {winrate}% sudah masuk area WATCH.")
    else:
        warnings.append(f"Winrate {winrate}% masih di bawah WATCH {MIN_WINRATE_FOR_WATCH}%.")

    if expectancy >= MIN_EXPECTANCY_FOR_READY:
        strengths.append(f"Expectancy ${expectancy} sudah di atas target READY ${MIN_EXPECTANCY_FOR_READY}.")
    elif expectancy >= MIN_EXPECTANCY_FOR_WATCH:
        strengths.append(f"Expectancy ${expectancy} sudah masuk area WATCH.")
    else:
        warnings.append(f"Expectancy ${expectancy} masih di bawah WATCH ${MIN_EXPECTANCY_FOR_WATCH}.")

    ready_conditions = [
        closed_orders >= MIN_CLOSED_ORDERS_FOR_READY,
        winrate >= MIN_WINRATE_FOR_READY,
        profit_factor >= MIN_PROFIT_FACTOR_FOR_READY,
        expectancy >= MIN_EXPECTANCY_FOR_READY,
        recent_loss_streak < MAX_RECENT_LOSS_STREAK,
        max_dd <= MAX_DRAWDOWN_PERCENT_FOR_READY,
        recent_performance["sample_size"] >= RECENT_WINDOW_SIZE,
        recent_performance["net_profit_usd"] >= RECENT_MIN_NET_PROFIT_USD_FOR_READY,
        recent_performance["max_loss_streak"] <= RECENT_MAX_LOSS_STREAK_FOR_READY,
    ]

    watch_conditions = [
        closed_orders >= MIN_CLOSED_ORDERS_FOR_WATCH,
        winrate >= MIN_WINRATE_FOR_WATCH,
        profit_factor >= MIN_PROFIT_FACTOR_FOR_WATCH,
        expectancy >= MIN_EXPECTANCY_FOR_WATCH,
        recent_loss_streak < MAX_RECENT_LOSS_STREAK,
        max_dd <= MAX_DRAWDOWN_PERCENT_FOR_WATCH,
    ]

    if all(ready_conditions):
        return (
            "READY_CANDIDATE",
            "Continue DRY_RUN validation to 50 closed orders before any semi-live discussion.",
            blocking_reasons,
            warnings,
            strengths,
        )

    if all(watch_conditions):
        return (
            "WATCH",
            "Phase 4 guard refinement. Continue DRY_RUN/paper-only to 50 closed orders.",
            blocking_reasons,
            warnings,
            strengths,
        )

    return (
        "NOT_READY",
        "Keep DRY_RUN/paper-only. Do not loosen guards.",
        blocking_reasons,
        warnings,
        strengths,
    )


# =========================
# REPORT BUILDERS
# =========================



def build_quality_report():
    paper_report = load_json(PAPER_REPORT_FILE, {})
    orders = load_json(PAPER_ORDERS_FILE, [])

    if not isinstance(orders, list):
        orders = []

    all_closed_orders = get_closed_orders(orders)
    open_orders = get_open_orders(orders)
    quality_sample_orders = get_quality_sample_orders(all_closed_orders, QUALITY_SAMPLE_WINDOW)

    all_time_metrics = calculate_metrics_from_orders(
        orders,
        open_orders_count=len(open_orders),
        total_orders_count=len(orders),
    )
    quality_sample_metrics = calculate_metrics_from_orders(
        quality_sample_orders,
        open_orders_count=len(open_orders),
        total_orders_count=len(orders),
    )

    sample_drawdown = build_equity_curve_and_drawdown(quality_sample_orders, starting_balance=50.0)
    all_time_drawdown = build_equity_curve_and_drawdown(all_closed_orders, starting_balance=50.0)
    recent_performance = summarize_recent_orders(quality_sample_orders, limit=RECENT_WINDOW_SIZE)
    recent_loss_streak = get_recent_loss_streak(quality_sample_orders)

    symbol_quality = build_group_quality(quality_sample_orders, "symbol")
    strategy_quality = build_group_quality(quality_sample_orders, "strategy")
    symbol_rules = build_group_rules(symbol_quality, "symbol")
    strategy_rules = build_group_rules(strategy_quality, "strategy")
    recommendations = build_recommendations(symbol_rules, strategy_rules)

    status, recommendation, blocking_reasons, warnings, strengths = evaluate_status(
        quality_sample_metrics,
        sample_drawdown,
        recent_performance,
        recent_loss_streak,
    )

    quality_sample_info = {
        "mode": "ROLLING_LAST_N_CLOSED_ORDERS",
        "window_size": QUALITY_SAMPLE_WINDOW,
        "sample_closed_orders": len(quality_sample_orders),
        "total_closed_orders": len(all_closed_orders),
        "uses_all_available_until_window_filled": len(all_closed_orders) < QUALITY_SAMPLE_WINDOW,
        "description": f"Quality status and Phase 4 rules use the last {QUALITY_SAMPLE_WINDOW} closed paper orders. Total closed orders are still used for validation progress toward {NEXT_VALIDATION_TARGET_CLOSED_ORDERS}.",
    }

    quality = {
        "generated_at": utc_now_iso(),
        "phase": "PHASE_4_QUALITY_GUARD_REFINEMENT",
        "quality_status": status,
        "live_allowed": False,
        "execution_mode": "PAPER_ONLY",
        "recommendation": recommendation,
        "quality_action": recommendation,
        "next_validation_target_closed_orders": NEXT_VALIDATION_TARGET_CLOSED_ORDERS,
        "quality_sample": quality_sample_info,
        "metrics": {
            **all_time_metrics,
            "recent_loss_streak": get_recent_loss_streak(all_closed_orders),
        },
        "quality_sample_metrics": {
            **quality_sample_metrics,
            "recent_loss_streak": recent_loss_streak,
        },
        "drawdown": all_time_drawdown,
        "quality_sample_drawdown": sample_drawdown,
        "recent_performance": recent_performance,
        "source_check": {
            "metrics_source": "paper_orders.json recalculated",
            "quality_rules_source": f"rolling last {QUALITY_SAMPLE_WINDOW} closed orders",
            "paper_report_reference": paper_report,
        },
        "blocking_reasons": blocking_reasons,
        "warnings": warnings,
        "strengths": strengths,
        "recent_10_closed_orders": summarize_recent_orders(all_closed_orders, limit=10),
        "open_order_risk_audit": [],
        "open_order_risk_violations": [],
        "by_symbol": symbol_quality,
        "by_strategy": strategy_quality,
        "symbol_rules": symbol_rules,
        "strategy_rules": strategy_rules,
        "recommendations": recommendations,
        "phase4_rules_file": QUALITY_RULES_FILE,
    }

    rules = {
        "generated_at": quality["generated_at"],
        "phase": quality["phase"],
        "quality_status": quality["quality_status"],
        "quality_action": quality["quality_action"],
        "live_allowed": False,
        "execution_mode": "PAPER_ONLY",
        "base_min_score": BASE_MIN_SCORE,
        "next_validation_target_closed_orders": NEXT_VALIDATION_TARGET_CLOSED_ORDERS,
        "quality_sample": quality_sample_info,
        "quality_sample_metrics": quality["quality_sample_metrics"],
        "symbol_rules": symbol_rules,
        "strategy_rules": strategy_rules,
        "recommendations": recommendations,
    }

    return quality, rules



def print_quality_report(quality):
    print("\n=== PAPER QUALITY GUARD — PHASE 4 ===")
    print(f"Status        : {quality['quality_status']}")
    print(f"Live allowed  : {quality['live_allowed']}")
    print(f"Mode          : {quality['execution_mode']}")
    print(f"Recommendation: {quality['recommendation']}")

    quality_sample = quality.get("quality_sample", {})
    print("\nQuality Sample:")
    print(f"Mode          : {quality_sample.get('mode', '-')}")
    print(f"Window        : {quality_sample.get('window_size', QUALITY_SAMPLE_WINDOW)} closed orders")
    print(f"Sample closed : {quality_sample.get('sample_closed_orders', 0)}")
    print(f"Total closed  : {quality_sample.get('total_closed_orders', 0)}")

    metrics = quality["metrics"]
    sample_metrics = quality.get("quality_sample_metrics", metrics)
    print("\nAll-time Metrics:")
    print(f"Closed orders : {metrics['closed_orders']}")
    print(f"Open orders   : {metrics['open_orders']}")
    print(f"Winrate       : {metrics['winrate_percent']}%")
    print(f"Profit factor : {metrics['profit_factor']}")
    print(f"Expectancy    : ${metrics['expectancy_usd']}")
    print(f"Net profit    : ${metrics['net_profit_usd']}")
    print(f"Loss streak   : {metrics['recent_loss_streak']}")
    print(f"Timeouts      : {metrics.get('timeouts', 0)}")

    print("\nRolling Quality Metrics:")
    print(f"Closed orders : {sample_metrics['closed_orders']}")
    print(f"Winrate       : {sample_metrics['winrate_percent']}%")
    print(f"Profit factor : {sample_metrics['profit_factor']}")
    print(f"Expectancy    : ${sample_metrics['expectancy_usd']}")
    print(f"Net profit    : ${sample_metrics['net_profit_usd']}")
    print(f"Loss streak   : {sample_metrics['recent_loss_streak']}")
    print(f"Timeouts      : {sample_metrics.get('timeouts', 0)}")

    drawdown = quality.get("drawdown", {})
    sample_drawdown = quality.get("quality_sample_drawdown", {})
    print("\nAll-time Drawdown:")
    print(f"Start balance : ${drawdown.get('starting_balance', 50.0)}")
    print(f"End balance   : ${drawdown.get('ending_balance', 50.0)}")
    print(f"Max DD USD    : ${drawdown.get('max_drawdown_usd', 0.0)}")
    print(f"Max DD %      : {drawdown.get('max_drawdown_percent', 0.0)}%")

    print("\nRolling Quality Drawdown:")
    print(f"Start balance : ${sample_drawdown.get('starting_balance', 50.0)}")
    print(f"End balance   : ${sample_drawdown.get('ending_balance', 50.0)}")
    print(f"Max DD USD    : ${sample_drawdown.get('max_drawdown_usd', 0.0)}")
    print(f"Max DD %      : {sample_drawdown.get('max_drawdown_percent', 0.0)}%")

    recent = quality.get("recent_performance", {})
    print("\nRecent Performance:")
    print(f"Window        : {recent.get('sample_size', 0)}/{recent.get('window_size', RECENT_WINDOW_SIZE)} closed orders")
    print(f"Wins          : {recent.get('wins', 0)}")
    print(f"Losses        : {recent.get('losses', 0)}")
    print(f"Timeouts      : {recent.get('timeouts', 0)}")
    print(f"Recent net    : ${recent.get('net_profit_usd', 0)}")
    print(f"Recent streak : {recent.get('max_loss_streak', 0)}")

    print("\nSymbol Rules:")
    for name, rule in quality.get("symbol_rules", {}).items():
        print(
            f"- {name} | {rule['guard_status']} | "
            f"Closed={rule['closed_orders']} | Winrate={rule['winrate_percent']}% | "
            f"Net=${rule['net_profit_usd']} | MinScore={rule['min_score_required']}"
        )

    print("\nStrategy Rules:")
    for name, rule in quality.get("strategy_rules", {}).items():
        print(
            f"- {name} | {rule['guard_status']} | "
            f"Closed={rule['closed_orders']} | Winrate={rule['winrate_percent']}% | "
            f"Net=${rule['net_profit_usd']} | MinScore={rule['min_score_required']}"
        )

    print("\nRecommendations:")
    if quality.get("recommendations"):
        for item in quality["recommendations"]:
            print(
                f"[{item['priority']}] {item['type']} | {item['name']} | "
                f"MinScore={item['min_score_required']} | {item['action']}"
            )
            print(f"  Reason: {item['reason']}")
    else:
        print("none")

    if quality["blocking_reasons"]:
        print("\nBlocking reasons:")
        for reason in quality["blocking_reasons"]:
            print(f"- {reason}")

    if quality["warnings"]:
        print("\nWarnings:")
        for warning in quality["warnings"]:
            print(f"- {warning}")

    if quality["strengths"]:
        print("\nStrengths:")
        for strength in quality["strengths"]:
            print(f"- {strength}")

    print(f"\nQuality report saved to: {QUALITY_REPORT_FILE}")
    print(f"Quality rules saved to : {QUALITY_RULES_FILE}")



def main():
    quality, rules = build_quality_report()
    save_json(QUALITY_REPORT_FILE, quality)
    save_json(QUALITY_RULES_FILE, rules)
    print_quality_report(quality)


if __name__ == "__main__":
    main()