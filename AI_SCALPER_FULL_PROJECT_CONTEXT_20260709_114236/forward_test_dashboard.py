import json
import os
from datetime import datetime, timezone

PAPER_ORDERS_FILE = "paper_orders.json"
PAPER_REPORT_FILE = "paper_report.json"
QUALITY_REPORT_FILE = "paper_quality_report.json"
PAPER_QUALITY_RULES_FILE = "paper_quality_rules.json"
ACTIVE_PAIRS_FILE = "active_pairs.json"
FORWARD_RUNS_FILE = "paper_forward_runs.json"
TRADE_SIGNALS_FILE = "trade_signals.json"
MT5_SIGNALS_FILE = "mt5_trade_signals.json"
EXECUTED_SIGNALS_FILE = "executed_signals.json"
BRIDGE_REJECTED_SIGNALS_FILE = "bridge_rejected_signals.json"
BRIDGE_STATUS_FILE = "bridge_status.json"
PAPER_REPLAY_CANDIDATES_FILE = "paper_replay_candidates.json"
OFFLINE_DASHBOARD_REPORT_FILE = "offline_dashboard_report.json"


def load_json(path, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as exc:
        print(f"Failed to save {path}: {exc}")


def safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def money(value):
    return f"${safe_float(value):.4f}".rstrip("0").rstrip(".")


def pct(value):
    return f"{safe_float(value):.2f}%"


def print_header(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def print_kv(label, value):
    print(f"{label:<24}: {value}")


def print_status_badge(quality_status):
    status = str(quality_status or "UNKNOWN").upper()

    if status == "READY_CANDIDATE":
        return "🟢 READY_CANDIDATE"
    if status == "WATCH":
        return "🟡 WATCH"
    if status == "NOT_READY":
        return "🔴 NOT_READY"

    return f"⚪ {status}"


def get_closed_orders(orders):
    closed_statuses = {"PAPER_WIN", "PAPER_LOSS", "PAPER_TIMEOUT"}
    closed_results = {"WIN", "LOSS", "TIMEOUT"}

    return [
        order for order in orders
        if order.get("status") in closed_statuses
        or order.get("result") in closed_results
    ]


def get_open_orders(orders):
    return [
        order for order in orders
        if order.get("status") == "PAPER_OPEN"
    ]


def get_active_pairs(active_pairs_data):
    if isinstance(active_pairs_data, list):
        return active_pairs_data

    if isinstance(active_pairs_data, dict):
        pairs = active_pairs_data.get("active_pairs", [])
        if isinstance(pairs, list):
            return pairs

    return []


def get_signal_orders(mt5_data):
    if isinstance(mt5_data, list):
        return mt5_data

    if not isinstance(mt5_data, dict):
        return []

    for key in [
        "orders",
        "signals",
        "mt5_signals",
        "valid_orders",
        "ready_orders",
        "trade_signals",
    ]:
        value = mt5_data.get(key)
        if isinstance(value, list):
            return value

    return []


def summarize_group(orders, group_key):
    grouped = {}

    for order in get_closed_orders(orders):
        key = str(order.get(group_key, "UNKNOWN") or "UNKNOWN").upper()

        grouped.setdefault(key, {
            "closed_orders": 0,
            "wins": 0,
            "losses": 0,
            "timeouts": 0,
            "net_profit_usd": 0.0,
        })

        bucket = grouped[key]
        bucket["closed_orders"] += 1
        bucket["net_profit_usd"] += safe_float(order.get("profit_usd"), 0.0)

        result = str(order.get("result", "")).upper()

        if result == "WIN":
            bucket["wins"] += 1
        elif result == "LOSS":
            bucket["losses"] += 1
        elif result == "TIMEOUT":
            bucket["timeouts"] += 1

    for bucket in grouped.values():
        closed = bucket["closed_orders"]
        wins = bucket["wins"]
        bucket["winrate_percent"] = round((wins / closed) * 100, 2) if closed > 0 else 0.0
        bucket["net_profit_usd"] = round(bucket["net_profit_usd"], 4)

    return grouped


def sort_grouped(grouped):
    return sorted(
        grouped.items(),
        key=lambda item: (
            item[1].get("net_profit_usd", 0),
            item[1].get("winrate_percent", 0),
            item[1].get("closed_orders", 0),
        ),
        reverse=True,
    )


def print_quality_section(quality, paper_report):
    metrics = quality.get("metrics", {}) if isinstance(quality, dict) else {}
    drawdown = quality.get("drawdown", {}) if isinstance(quality, dict) else {}
    recent = quality.get("recent_performance", {}) if isinstance(quality, dict) else {}

    print_header("AI_SCALPER FORWARD TEST DASHBOARD")
    print_kv("Generated at", datetime.now(timezone.utc).isoformat())
    print_kv("Quality status", print_status_badge(quality.get("quality_status", "UNKNOWN")))
    print_kv("Live allowed", quality.get("live_allowed", False))
    print_kv("Recommendation", quality.get("recommendation", "-"))

    print_header("QUALITY METRICS")
    print_kv("Closed orders", metrics.get("closed_orders", paper_report.get("closed_orders", 0)))
    print_kv("Open orders", paper_report.get("open_orders", 0))
    print_kv(
        "Wins / Losses",
        f"{metrics.get('wins', paper_report.get('wins', 0))} / "
        f"{metrics.get('losses', paper_report.get('losses', 0))}",
    )
    print_kv("Timeouts", metrics.get("timeouts", paper_report.get("timeouts", 0)))
    print_kv("Winrate", pct(metrics.get("winrate_percent", paper_report.get("winrate_percent", 0))))
    print_kv("Profit factor", metrics.get("profit_factor", paper_report.get("profit_factor", 0)))
    print_kv("Expectancy", money(metrics.get("expectancy_usd", paper_report.get("expectancy_usd", 0))))
    print_kv("Net profit", money(paper_report.get("net_profit_usd", metrics.get("net_profit_usd", 0))))
    print_kv("Loss streak", metrics.get("recent_loss_streak", "-"))

    print_header("DRAWDOWN")
    print_kv("Start balance", money(drawdown.get("starting_balance", 50.0)))
    print_kv("End balance", money(drawdown.get("ending_balance", 50.0)))
    print_kv("Max DD USD", money(drawdown.get("max_drawdown_usd", 0.0)))
    print_kv("Max DD %", pct(drawdown.get("max_drawdown_percent", 0.0)))

    print_header("RECENT PERFORMANCE")
    if recent:
        print_kv("Window", f"{recent.get('sample_size', 0)}/{recent.get('window_size', 0)} closed orders")
        print_kv("Wins / Losses", f"{recent.get('wins', 0)} / {recent.get('losses', 0)}")
        print_kv("Timeouts", recent.get("timeouts", 0))
        print_kv("Recent net", money(recent.get("net_profit_usd", 0)))
        print_kv("Recent loss streak", recent.get("max_loss_streak", 0))
    else:
        print("No recent performance data yet.")


def print_orders_section(orders):
    open_orders = get_open_orders(orders)
    closed_orders = get_closed_orders(orders)

    print_header("OPEN ORDERS")
    if not open_orders:
        print("No open paper orders.")
    else:
        for order in open_orders:
            print(
                f"{order.get('symbol')} {order.get('type')} | "
                f"Strategy: {order.get('strategy')} | "
                f"Score: {order.get('score')} | "
                f"Entry: {order.get('entry')} | "
                f"SL: {order.get('sl')} | "
                f"TP: {order.get('tp')} | "
                f"Risk: {money(order.get('risk_usd', 0))} | "
                f"Status: {order.get('status')}"
            )

    print_header("LATEST CLOSED ORDERS")
    if not closed_orders:
        print("No closed orders yet.")
    else:
        for order in closed_orders[-5:]:
            print(
                f"{order.get('symbol')} {order.get('type')} | "
                f"Strategy: {order.get('strategy')} | "
                f"Score: {order.get('score')} | "
                f"Result: {order.get('result')} | "
                f"Profit: {money(order.get('profit_usd', 0))} | "
                f"Closed at: {order.get('closed_at')}"
            )


def print_group_section(title, grouped):
    print_header(title)
    sorted_items = sort_grouped(grouped)

    if not sorted_items:
        print("No closed order data yet.")
        return

    for name, item in sorted_items:
        print(
            f"{name:<22} | "
            f"Closed: {item['closed_orders']:<3} | "
            f"W/L/T: {item['wins']}/{item['losses']}/{item['timeouts']} | "
            f"Winrate: {pct(item['winrate_percent'])} | "
            f"Net: {money(item['net_profit_usd'])}"
        )


def print_active_pairs_section(active_pairs_data, mt5_data):
    active_pairs = get_active_pairs(active_pairs_data)
    signal_orders = get_signal_orders(mt5_data)

    print_header("ACTIVE PAIRS & MT5 READY SIGNALS")
    print_kv(
        "Active pairs",
        ", ".join(str(pair).upper() for pair in active_pairs) if active_pairs else "-",
    )
    print_kv("MT5 order count", len(signal_orders))
    print_kv(
        "MT5 replay filter",
        mt5_data.get("replay_candidate_filter_enabled", "-") if isinstance(mt5_data, dict) else "-",
    )

    if not signal_orders:
        print("Ready MT5 signal orders: none")
        return

    print("Ready MT5 signal orders:")
    for order in signal_orders:
        print(
            f"- {order.get('symbol')} {order.get('order_type', order.get('type', order.get('action')))} | "
            f"Status: {order.get('status', '-')} | "
            f"Score: {order.get('score', order.get('strategy_score'))} | "
            f"Lot: {order.get('lot', '-')} | "
            f"Entry: {order.get('entry_price', order.get('entry'))} | "
            f"SL: {order.get('stop_loss', order.get('sl'))} | "
            f"TP: {order.get('take_profit', order.get('tp'))} | "
            f"Risk: {money(order.get('risk_usd', order.get('risk_amount', 0)))}"
        )


def get_trade_decisions(trade_data):
    if not isinstance(trade_data, dict):
        return []

    decisions = trade_data.get("all_decisions", [])
    if isinstance(decisions, list):
        return decisions

    return []


def get_executed_history(executed_data):
    if not isinstance(executed_data, dict):
        return []

    history = executed_data.get("history", [])
    if isinstance(history, list):
        return history

    return []


def get_rejected_history(rejected_data):
    if not isinstance(rejected_data, dict):
        return []

    history = rejected_data.get("history", [])
    if isinstance(history, list):
        return history

    return []


def get_guard_symbols(candidate_data, key):
    if not isinstance(candidate_data, dict):
        return []

    items = candidate_data.get(key, [])
    symbols = []

    if not isinstance(items, list):
        return symbols

    for item in items:
        if isinstance(item, dict):
            symbol = str(item.get("symbol", "")).upper()
            if symbol:
                symbols.append(symbol)

    return symbols


def get_candidate_items(candidate_data, key):
    if not isinstance(candidate_data, dict):
        return []

    items = candidate_data.get(key, [])
    return items if isinstance(items, list) else []


def classify_execution_history(executed_history, candidate_data):
    approved_symbols = set(get_guard_symbols(candidate_data, "approved_symbols"))
    blocked_symbols = set(get_guard_symbols(candidate_data, "blocked_symbols"))

    guarded = []
    legacy = []
    currently_not_approved = []
    currently_blocked = []

    for order in executed_history:
        if not isinstance(order, dict):
            continue

        symbol = str(order.get("symbol", "") or "").upper()
        guard_reason = str(order.get("bridge_validation_reason", "") or "")

        if guard_reason.strip():
            guarded.append(order)
        else:
            legacy.append(order)

        if symbol in blocked_symbols:
            currently_blocked.append(order)
        elif approved_symbols and symbol not in approved_symbols:
            currently_not_approved.append(order)

    return {
        "guarded": guarded,
        "legacy": legacy,
        "currently_not_approved": currently_not_approved,
        "currently_blocked": currently_blocked,
    }


def print_replay_candidate_section(candidate_data):
    print_header("REPLAY CANDIDATE GUARD")

    if not isinstance(candidate_data, dict) or not candidate_data:
        print("No paper replay candidate data yet.")
        return

    approved = get_candidate_items(candidate_data, "approved_symbols")
    watch = get_candidate_items(candidate_data, "watch_symbols")
    blocked = get_candidate_items(candidate_data, "blocked_symbols")

    print_kv("Mode", candidate_data.get("mode", "-"))
    print_kv("Live allowed", candidate_data.get("live_allowed", False))
    print_kv("Global status", candidate_data.get("global_status", "UNKNOWN"))
    print_kv("Global action", candidate_data.get("global_action", "-"))
    print_kv("Approved count", len(approved))
    print_kv("Watch count", len(watch))
    print_kv("Blocked count", len(blocked))

    def print_items(title, items):
        print(f"\n{title}:")
        if not items:
            print("- none")
            return

        for item in items:
            if not isinstance(item, dict):
                continue

            print(
                f"- {item.get('symbol')} | "
                f"Status: {item.get('status', '-')} | "
                f"Closed: {item.get('closed_orders', 0)} | "
                f"Winrate: {pct(item.get('winrate_percent', 0))} | "
                f"Net: {money(item.get('net_profit_usd', 0))} | "
                f"Reason: {item.get('reason', '-')}"
            )

    print_items("Approved symbols", approved)
    print_items("Watch symbols", watch)
    print_items("Blocked symbols", blocked)


def print_decision_engine_section(trade_data):
    print_header("DECISION ENGINE SUMMARY")

    if not isinstance(trade_data, dict) or not trade_data:
        print("No trade_signals.json data yet.")
        return

    decisions = get_trade_decisions(trade_data)
    ready = trade_data.get("signals", []) if isinstance(trade_data.get("signals", []), list) else []
    wait_count = len([item for item in decisions if item.get("status") == "WAIT"])

    print_kv("Generated at", trade_data.get("generated_at", "-"))
    print_kv("Replay filter", trade_data.get("replay_candidate_filter_enabled", "-"))
    print_kv("Ready trades", trade_data.get("ready_trade_count", len(ready)))
    print_kv("Wait decisions", wait_count)
    print_kv("All decisions", len(decisions))

    if not decisions:
        print("No decision detail yet.")
        return

    print("Latest decisions:")
    for item in decisions[-8:]:
        print(
            f"- {item.get('symbol')} | "
            f"Status: {item.get('status')} | "
            f"Signal: {item.get('signal', item.get('action', '-'))} | "
            f"Strategy: {item.get('selected_strategy', '-')} | "
            f"Score: {item.get('strategy_score', '-')} | "
            f"Reason: {item.get('reason', '-')}"
        )


def print_bridge_execution_section(mt5_data, executed_data, candidate_data=None, bridge_status=None, rejected_data=None):
    print_header("MT5 BRIDGE / EXECUTION LOG")

    candidate_data = candidate_data if isinstance(candidate_data, dict) else {}
    bridge_status = bridge_status if isinstance(bridge_status, dict) else {}
    rejected_data = rejected_data if isinstance(rejected_data, dict) else {}

    mt5_orders = get_signal_orders(mt5_data)
    executed_history = get_executed_history(executed_data)
    rejected_history = get_rejected_history(rejected_data)
    execution_classes = classify_execution_history(executed_history, candidate_data)

    print_kv("MT5 generated at", mt5_data.get("generated_at", "-") if isinstance(mt5_data, dict) else "-")
    print_kv("Bridge generated", bridge_status.get("generated_at", "-"))
    print_kv("Bridge mode", bridge_status.get("mode", "-"))
    print_kv("Bridge live allowed", bridge_status.get("live_allowed", False))
    print_kv("Bridge max lot", bridge_status.get("max_allowed_lot", "-"))
    print_kv("Bridge guard", bridge_status.get("guard_enabled", "-"))
    print_kv("Bridge guard status", bridge_status.get("guard_global_status", "-"))
    print_kv("Bridge valid orders", bridge_status.get("valid_order_count", "-"))
    print_kv("Bridge rejected orders", bridge_status.get("rejected_order_count", "-"))
    print_kv("Rejected history", len(rejected_history))
    print_kv("MT5 order count", len(mt5_orders))
    print_kv("Executed history", len(executed_history))
    print_kv("Guarded executions", len(execution_classes["guarded"]))
    print_kv("Legacy executions", len(execution_classes["legacy"]))
    print_kv("Now not approved", len(execution_classes["currently_not_approved"]))
    print_kv("Now blocked", len(execution_classes["currently_blocked"]))

    if mt5_orders:
        print("Current MT5 orders:")
        for order in mt5_orders:
            print(
                f"- {order.get('symbol')} {order.get('order_type', order.get('type', '-'))} | "
                f"Status: {order.get('status', '-')} | "
                f"Signal ID: {order.get('signal_id', '-')} | "
                f"Expires: {order.get('expires_at', '-')}"
            )
    else:
        print("Current MT5 orders: none")

    if rejected_history:
        print("\nLatest rejected/skipped bridge orders:")
        for item in rejected_history[-5:]:
            print(
                f"- {item.get('symbol')} {item.get('order_type', '-')} | "
                f"Status: {item.get('status', '-')} | "
                f"Signal ID: {item.get('signal_id', '-')} | "
                f"Reason: {item.get('reason', '-')}"
            )
    else:
        print("Rejected/skipped bridge history: none")

    if execution_classes["legacy"]:
        print("\nLegacy executions before final guard:")
        for order in execution_classes["legacy"][-5:]:
            print(
                f"- {order.get('symbol')} {order.get('order_type', order.get('type', '-'))} | "
                f"Status: {order.get('status', '-')} | "
                f"Signal ID: {order.get('signal_id', '-')} | "
                f"Guard: LEGACY_NO_FINAL_GUARD"
            )

    if execution_classes["guarded"]:
        print("\nLatest guarded executions:")
        for order in execution_classes["guarded"][-5:]:
            print(
                f"- {order.get('symbol')} {order.get('order_type', order.get('type', '-'))} | "
                f"Status: {order.get('status', '-')} | "
                f"Live allowed: {order.get('live_allowed', False)} | "
                f"Signal ID: {order.get('signal_id', '-')} | "
                f"Guard: {order.get('bridge_validation_reason', '-')}"
            )

    if not execution_classes["legacy"] and not execution_classes["guarded"]:
        print("Executed/simulated history: none")

    if execution_classes["currently_not_approved"] or execution_classes["currently_blocked"]:
        print("\nExecution history caution:")
        print("- Some old simulated executions are no longer approved by the current replay guard.")
        print("- This is historical only; new orders are protected by decision_engine.py and mt5_bridge_reader.py final guard.")


def print_runner_section(runs):
    print_header("LATEST RUN")

    if not isinstance(runs, list) or not runs:
        print("No forward run log yet.")
        return

    latest = runs[-1]

    print_kv("Run ID", latest.get("run_id", "-"))
    print_kv("Pipeline success", latest.get("pipeline_success", latest.get("success", False)))
    print_kv("New order added", latest.get("new_order_added", False))
    print_kv("New order count", latest.get("new_order_count", 0))
    print_kv("Monitor updated", latest.get("monitor_updated", False))
    print_kv("Order book changed", latest.get("order_book_changed", False))
    print_kv("Quality status", latest.get("quality_status", "UNKNOWN"))

    skipped = [
        step for step in latest.get("steps", [])
        if isinstance(step, dict) and step.get("skipped")
    ]

    if skipped:
        print("Skipped steps:")
        for step in skipped:
            print(f"- {step.get('name')}: {step.get('skip_reason')}")


def print_warnings_section(quality):
    print_header("WARNINGS / STRENGTHS")

    blocking = quality.get("blocking_reasons", []) if isinstance(quality, dict) else []
    warnings = quality.get("warnings", []) if isinstance(quality, dict) else []
    strengths = quality.get("strengths", []) if isinstance(quality, dict) else []

    if blocking:
        print("Blocking reasons:")
        for item in blocking:
            print(f"- {item}")

    if warnings:
        print("Warnings:")
        for item in warnings:
            print(f"- {item}")

    if strengths:
        print("Strengths:")
        for item in strengths:
            print(f"- {item}")

    if not blocking and not warnings and not strengths:
        print("No warnings, blocking reasons, or strengths yet.")


def build_guard_recommendations(orders):
    symbol_groups = summarize_group(orders, "symbol")
    strategy_groups = summarize_group(orders, "strategy")
    recommendations = []

    for symbol, item in sort_grouped(symbol_groups):
        closed = safe_int(item.get("closed_orders", 0))
        winrate = safe_float(item.get("winrate_percent", 0))
        net_profit = safe_float(item.get("net_profit_usd", 0))

        if closed >= 5 and winrate < 40 and net_profit < 0:
            recommendations.append({
                "level": "HIGH",
                "type": "SYMBOL_GUARD",
                "target": symbol,
                "reason": f"Closed={closed}, Winrate={winrate:.2f}%, Net={money(net_profit)}",
                "action": "Keep symbol performance guard active. Require score >= 4 before execution.",
            })
        elif closed >= 5 and winrate < 40:
            recommendations.append({
                "level": "MEDIUM",
                "type": "SYMBOL_WATCH",
                "target": symbol,
                "reason": f"Closed={closed}, Winrate={winrate:.2f}%, Net={money(net_profit)}",
                "action": "Watch this symbol. Avoid score 3 entries unless quality improves.",
            })

    for strategy, item in sort_grouped(strategy_groups):
        closed = safe_int(item.get("closed_orders", 0))
        winrate = safe_float(item.get("winrate_percent", 0))

        if closed >= 5 and winrate < 40:
            recommendations.append({
                "level": "MEDIUM",
                "type": "STRATEGY_GUARD",
                "target": strategy,
                "reason": f"Closed={closed}, Winrate={winrate:.2f}%, Net={money(item.get('net_profit_usd', 0))}",
                "action": "Keep strategy performance guard active. Require score >= 4 before execution.",
            })

    if not recommendations:
        recommendations.append({
            "level": "INFO",
            "type": "NO_GUARD_ACTION",
            "target": "ALL",
            "reason": "No symbol or strategy currently meets weak-performance guard criteria.",
            "action": "Continue paper forward testing until at least 30 closed orders.",
        })

    return recommendations



def print_guard_recommendation_section(orders):
    print_header("OFFLINE GUARD RECOMMENDATIONS")
    recommendations = build_guard_recommendations(orders)

    for item in recommendations:
        print(
            f"[{item['level']}] {item['type']} | {item['target']} | "
            f"{item['reason']} | Action: {item['action']}"
        )


def print_phase4_quality_rules_section(phase4_rules):
    print_header("PHASE 4 QUALITY RULES")

    if not isinstance(phase4_rules, dict) or not phase4_rules:
        print("No paper_quality_rules.json data yet. Run python paper_quality_guard.py first.")
        return

    symbol_rules = phase4_rules.get("symbol_rules", {})
    strategy_rules = phase4_rules.get("strategy_rules", {})
    recommendations = phase4_rules.get("recommendations", [])

    print_kv("Quality status", print_status_badge(phase4_rules.get("quality_status", "UNKNOWN")))
    print_kv("Execution mode", phase4_rules.get("execution_mode", "-"))
    print_kv("Live allowed", phase4_rules.get("live_allowed", False))
    print_kv("Base min score", phase4_rules.get("base_min_score", "-"))
    print_kv("Next target", f"{phase4_rules.get('next_validation_target_closed_orders', 50)} closed orders")
    print_kv("Quality action", phase4_rules.get("quality_action", "-"))

    print("\nSymbol Rules:")
    if isinstance(symbol_rules, dict) and symbol_rules:
        for name, rule in sorted(symbol_rules.items()):
            print(
                f"- {name:<10} | "
                f"{rule.get('guard_status', 'UNKNOWN'):<19} | "
                f"MinScore: {rule.get('min_score_required', '-'):>2} | "
                f"Closed: {rule.get('closed_orders', 0):>3} | "
                f"WR: {pct(rule.get('winrate_percent', 0)):<7} | "
                f"PF: {safe_float(rule.get('profit_factor', 0)):.4f} | "
                f"Net: {money(rule.get('net_profit_usd', 0))}"
            )
    else:
        print("- none")

    print("\nStrategy Rules:")
    if isinstance(strategy_rules, dict) and strategy_rules:
        for name, rule in sorted(strategy_rules.items()):
            print(
                f"- {name:<20} | "
                f"{rule.get('guard_status', 'UNKNOWN'):<19} | "
                f"MinScore: {rule.get('min_score_required', '-'):>2} | "
                f"Closed: {rule.get('closed_orders', 0):>3} | "
                f"WR: {pct(rule.get('winrate_percent', 0)):<7} | "
                f"PF: {safe_float(rule.get('profit_factor', 0)):.4f} | "
                f"Net: {money(rule.get('net_profit_usd', 0))}"
            )
    else:
        print("- none")

    print("\nPhase 4 Recommendations:")
    if isinstance(recommendations, list) and recommendations:
        for item in recommendations:
            if not isinstance(item, dict):
                continue
            print(
                f"[{item.get('priority', '-')}] {item.get('type', '-')} | "
                f"{item.get('name', '-')} | "
                f"MinScore={item.get('min_score_required', '-')} | "
                f"Action: {item.get('action', '-')}"
            )
            print(f"  Reason: {item.get('reason', '-')}")
    else:
        print("- none")

    print("\nRule meaning:")
    print("- PRIORITY: best current profile; allowed in paper mode with required score.")
    print("- WATCH: allowed, but avoid weak score entries.")
    print("- RESTRICT: only allowed with stricter score requirement.")
    print("- BLOCK: do not allow new entries for now.")
    print("- INSUFFICIENT_SAMPLE: allowed only in paper mode while collecting more data.")


def calculate_offline_readiness_score(quality, orders):
    metrics = quality.get("metrics", {}) if isinstance(quality, dict) else {}
    drawdown = quality.get("drawdown", {}) if isinstance(quality, dict) else {}
    recent = quality.get("recent_performance", {}) if isinstance(quality, dict) else {}

    closed_orders = safe_int(metrics.get("closed_orders", len(get_closed_orders(orders))))
    winrate = safe_float(metrics.get("winrate_percent", 0))
    profit_factor = safe_float(metrics.get("profit_factor", 0))
    expectancy = safe_float(metrics.get("expectancy_usd", 0))
    max_dd = safe_float(drawdown.get("max_drawdown_percent", 0))
    recent_net = safe_float(recent.get("net_profit_usd", 0))
    recent_loss_streak = safe_int(recent.get("max_loss_streak", 0))

    score = 0
    notes = []

    if closed_orders >= 30:
        score += 2
        notes.append("Sample size is sufficient for READY evaluation.")
    else:
        notes.append(f"Sample size is still small: {closed_orders}/30 closed orders.")

    if winrate >= 45:
        score += 2
        notes.append("Winrate is READY-level.")
    elif winrate >= 40:
        score += 1
        notes.append("Winrate is WATCH-level.")
    else:
        notes.append("Winrate is still below WATCH-level.")

    if profit_factor >= 1.2:
        score += 2
        notes.append("Profit factor is READY-level.")
    elif profit_factor >= 1.05:
        score += 1
        notes.append("Profit factor is WATCH-level.")
    else:
        notes.append("Profit factor is still weak.")

    if expectancy >= 0.03:
        score += 2
        notes.append("Expectancy is READY-level.")
    elif expectancy >= 0.01:
        score += 1
        notes.append("Expectancy is WATCH-level.")
    else:
        notes.append("Expectancy is still weak.")

    if max_dd <= 3:
        score += 1
        notes.append("Drawdown is controlled.")
    else:
        notes.append("Drawdown is above preferred READY limit.")

    if recent_net >= 0 and recent_loss_streak <= 2:
        score += 1
        notes.append("Recent performance is acceptable.")
    else:
        notes.append("Recent performance needs caution.")

    if score >= 8 and closed_orders >= 30 and winrate >= 45:
        label = "READY_CANDIDATE_CHECK"
    elif score >= 5:
        label = "WATCH_BUILDING"
    else:
        label = "NOT_READY_BUILDING"

    return {
        "score": score,
        "max_score": 10,
        "label": label,
        "notes": notes,
    }


def print_offline_readiness_section(quality, orders):
    print_header("PHASE 4C OFFLINE READINESS CHECK")
    result = calculate_offline_readiness_score(quality, orders)

    print_kv("Offline score", f"{result['score']}/{result['max_score']}")
    print_kv("Offline label", result["label"])

    for note in result["notes"]:
        print(f"- {note}")


def print_next_stage_section(quality, orders):
    summary = build_next_stage_summary(quality, orders)

    print_header("NEXT STAGE PLAN")
    print_kv("Current stage", summary["current_stage"])
    print_kv("Action", summary["action"])
    print_kv("Quality status", print_status_badge(summary["quality_status"]))
    print_kv(
        "Phase 4 progress",
        f"{summary['closed_orders']}/{summary['phase4_target_closed_orders']} closed orders "
        f"({summary['phase4_progress_percent']}%)",
    )
    print_kv("Remaining", f"{summary['remaining_to_phase4_target']} closed orders")
    print_kv("Winrate target", f"{summary['winrate_percent']:.2f}% / 45.00% READY target")
    print_kv("PF target", f"{summary['profit_factor']:.4f} / 1.20 READY target")
    print_kv("Expectancy target", f"${summary['expectancy_usd']:.4f} / $0.03 READY target")

    for note in summary["notes"]:
        print(f"- {note}")


def build_next_stage_summary(quality, orders):
    metrics = quality.get("metrics", {}) if isinstance(quality, dict) else {}
    closed_orders = safe_int(metrics.get("closed_orders"), len(get_closed_orders(orders)))
    winrate = safe_float(metrics.get("winrate_percent", 0.0))
    profit_factor = safe_float(metrics.get("profit_factor", 0.0))
    expectancy = safe_float(metrics.get("expectancy_usd", 0.0))
    quality_status = str(quality.get("quality_status", "UNKNOWN")).upper() if isinstance(quality, dict) else "UNKNOWN"

    phase4_rules = load_json(PAPER_QUALITY_RULES_FILE, {})
    if not isinstance(phase4_rules, dict):
        phase4_rules = {}

    phase4_target = safe_int(phase4_rules.get("next_validation_target_closed_orders"), 50)
    remaining_to_phase4_target = max(phase4_target - closed_orders, 0)
    phase4_progress_percent = (closed_orders / phase4_target * 100.0) if phase4_target > 0 else 0.0

    if closed_orders >= phase4_target:
        current_stage = "Phase 4 validation target reached"
        action = "STOP_AND_REVIEW_PHASE_4"
    elif quality_status == "READY_CANDIDATE":
        current_stage = "Phase 4 READY_CANDIDATE validation"
        action = "CONTINUE_TO_50_THEN_REVIEW"
    elif quality_status == "WATCH":
        current_stage = "Phase 4 WATCH validation"
        action = "CONTINUE_PAPER_VALIDATION_TO_50"
    else:
        current_stage = "Phase 4 guarded paper validation"
        action = "CONTINUE_WITH_STRICT_GUARDS"

    notes = []

    if closed_orders < phase4_target:
        notes.append(
            f"Phase 4 target belum selesai: {closed_orders}/{phase4_target}. "
            f"Butuh {remaining_to_phase4_target} closed order lagi sebelum review besar."
        )
    else:
        notes.append(
            f"Phase 4 target tercapai: {closed_orders}/{phase4_target}. Stop loop dan review kualitas sebelum lanjut."
        )

    if winrate >= 45.0:
        notes.append("Winrate sudah READY-level. Jaga stabil sampai target 50 closed orders.")
    elif winrate >= 40.0:
        notes.append("Winrate sudah WATCH-level, tetapi belum READY-level. Fokus menaikkan stabilitas winrate.")
    else:
        notes.append("Winrate turun di bawah WATCH. Jangan longgarkan guard.")

    if profit_factor >= 1.20 and expectancy >= 0.03:
        notes.append("Strength: PF dan expectancy sudah READY-level. Fokus utama sekarang sample size dan winrate.")
    elif profit_factor >= 1.20:
        notes.append("PF sudah READY-level, tetapi expectancy belum cukup kuat.")
    elif expectancy >= 0.03:
        notes.append("Expectancy sudah READY-level, tetapi PF belum cukup kuat.")
    else:
        notes.append("PF dan expectancy belum cukup kuat. Lanjut paper-only dengan guard ketat.")

    notes.append("Live trading remains locked. Continue DRY_RUN/paper mode only.")

    return {
        "current_stage": current_stage,
        "action": action,
        "quality_status": quality_status,
        "closed_orders": closed_orders,
        "phase4_target_closed_orders": phase4_target,
        "remaining_to_phase4_target": remaining_to_phase4_target,
        "phase4_progress_percent": round(phase4_progress_percent, 2),
        "winrate_percent": round(winrate, 2),
        "profit_factor": round(profit_factor, 4),
        "expectancy_usd": round(expectancy, 4),
        "notes": notes,
    }


def build_offline_dashboard_report(
    quality,
    orders,
    active_pairs_data=None,
    candidate_data=None,
    trade_data=None,
    mt5_data=None,
    executed_data=None,
    bridge_status=None,
    rejected_data=None,
    phase4_rules=None,
):
    active_pairs_data = active_pairs_data if isinstance(active_pairs_data, dict) or isinstance(active_pairs_data, list) else {}
    candidate_data = candidate_data if isinstance(candidate_data, dict) else {}
    trade_data = trade_data if isinstance(trade_data, dict) else {}
    mt5_data = mt5_data if isinstance(mt5_data, dict) else {}
    executed_data = executed_data if isinstance(executed_data, dict) else {}
    bridge_status = bridge_status if isinstance(bridge_status, dict) else {}
    rejected_data = rejected_data if isinstance(rejected_data, dict) else {}
    phase4_rules = phase4_rules if isinstance(phase4_rules, dict) else {}

    executed_history = get_executed_history(executed_data)
    rejected_history = get_rejected_history(rejected_data)
    execution_classes = classify_execution_history(executed_history, candidate_data)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "quality_status": quality.get("quality_status", "UNKNOWN") if isinstance(quality, dict) else "UNKNOWN",
        "live_allowed": quality.get("live_allowed", False) if isinstance(quality, dict) else False,
        "active_pairs": get_active_pairs(active_pairs_data),
        "replay_candidate_guard": {
            "global_status": candidate_data.get("global_status", "UNKNOWN"),
            "global_action": candidate_data.get("global_action", "-"),
            "live_allowed": candidate_data.get("live_allowed", False),
            "approved_symbols": get_guard_symbols(candidate_data, "approved_symbols"),
            "watch_symbols": get_guard_symbols(candidate_data, "watch_symbols"),
            "blocked_symbols": get_guard_symbols(candidate_data, "blocked_symbols"),
        },
        "decision_engine": {
            "generated_at": trade_data.get("generated_at", "-"),
            "replay_candidate_filter_enabled": trade_data.get("replay_candidate_filter_enabled", False),
            "ready_trade_count": trade_data.get("ready_trade_count", 0),
            "decision_count": len(get_trade_decisions(trade_data)),
        },
        "mt5_bridge": {
            "generated_at": mt5_data.get("generated_at", "-"),
            "bridge_status_generated_at": bridge_status.get("generated_at", "-"),
            "bridge_mode": bridge_status.get("mode", "-"),
            "live_allowed": bridge_status.get("live_allowed", False),
            "max_allowed_lot": bridge_status.get("max_allowed_lot", "-"),
            "guard_enabled": bridge_status.get("guard_enabled", "-"),
            "guard_global_status": bridge_status.get("guard_global_status", "-"),
            "replay_candidate_filter_enabled": mt5_data.get("replay_candidate_filter_enabled", False),
            "order_count": len(get_signal_orders(mt5_data)),
            "bridge_valid_order_count": bridge_status.get("valid_order_count", 0),
            "bridge_rejected_order_count": bridge_status.get("rejected_order_count", 0),
            "rejected_history_count": len(rejected_history),
            "executed_history_count": len(executed_history),
            "guarded_execution_count": len(execution_classes["guarded"]),
            "legacy_execution_count": len(execution_classes["legacy"]),
            "currently_not_approved_history_count": len(execution_classes["currently_not_approved"]),
            "currently_blocked_history_count": len(execution_classes["currently_blocked"]),
            "latest_rejected": rejected_history[-5:],
            "latest_guarded_executed": execution_classes["guarded"][-5:],
            "latest_legacy_executed": execution_classes["legacy"][-5:],
        },
        "phase4_quality_rules": {
            "quality_status": phase4_rules.get("quality_status", "UNKNOWN"),
            "quality_action": phase4_rules.get("quality_action", "-"),
            "live_allowed": phase4_rules.get("live_allowed", False),
            "execution_mode": phase4_rules.get("execution_mode", "-"),
            "base_min_score": phase4_rules.get("base_min_score", "-"),
            "next_validation_target_closed_orders": phase4_rules.get("next_validation_target_closed_orders", 50),
            "symbol_rules": phase4_rules.get("symbol_rules", {}),
            "strategy_rules": phase4_rules.get("strategy_rules", {}),
            "recommendations": phase4_rules.get("recommendations", []),
        },
        "legacy_offline_guard_recommendations": build_guard_recommendations(orders),
        "guard_recommendations": phase4_rules.get("recommendations", build_guard_recommendations(orders)),
        "offline_readiness": calculate_offline_readiness_score(quality, orders),
        "next_stage": build_next_stage_summary(quality, orders),
        "symbol_performance": summarize_group(orders, "symbol"),
        "strategy_performance": summarize_group(orders, "strategy"),
    }


def main():
    orders = load_json(PAPER_ORDERS_FILE, [])
    paper_report = load_json(PAPER_REPORT_FILE, {})
    quality = load_json(QUALITY_REPORT_FILE, {})
    phase4_rules = load_json(PAPER_QUALITY_RULES_FILE, {})
    active_pairs_data = load_json(ACTIVE_PAIRS_FILE, {})
    runs = load_json(FORWARD_RUNS_FILE, [])
    candidate_data = load_json(PAPER_REPLAY_CANDIDATES_FILE, {})
    trade_data = load_json(TRADE_SIGNALS_FILE, {})
    mt5_data = load_json(MT5_SIGNALS_FILE, {})
    executed_data = load_json(EXECUTED_SIGNALS_FILE, {})
    bridge_status = load_json(BRIDGE_STATUS_FILE, {})
    rejected_data = load_json(BRIDGE_REJECTED_SIGNALS_FILE, {})

    if not isinstance(orders, list):
        orders = []
    if not isinstance(paper_report, dict):
        paper_report = {}
    if not isinstance(quality, dict):
        quality = {}
    if not isinstance(phase4_rules, dict):
        phase4_rules = {}

    print_quality_section(quality, paper_report)
    print_orders_section(orders)
    print_group_section("SYMBOL PERFORMANCE", summarize_group(orders, "symbol"))
    print_group_section("STRATEGY PERFORMANCE", summarize_group(orders, "strategy"))
    print_replay_candidate_section(candidate_data)
    print_active_pairs_section(active_pairs_data, mt5_data)
    print_decision_engine_section(trade_data)
    print_bridge_execution_section(mt5_data, executed_data, candidate_data, bridge_status, rejected_data)
    print_runner_section(runs)
    print_warnings_section(quality)
    print_phase4_quality_rules_section(phase4_rules)
    print_guard_recommendation_section(orders)
    print_offline_readiness_section(quality, orders)
    print_next_stage_section(quality, orders)

    offline_report = build_offline_dashboard_report(
        quality,
        orders,
        active_pairs_data=active_pairs_data,
        candidate_data=candidate_data,
        trade_data=trade_data,
        mt5_data=mt5_data,
        executed_data=executed_data,
        bridge_status=bridge_status,
        rejected_data=rejected_data,
        phase4_rules=phase4_rules,
    )

    save_json(OFFLINE_DASHBOARD_REPORT_FILE, offline_report)
    print(f"\nOffline dashboard report saved to: {OFFLINE_DASHBOARD_REPORT_FILE}")
    print("Dashboard command: python forward_test_dashboard.py")


if __name__ == "__main__":
    main()