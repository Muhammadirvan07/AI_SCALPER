import csv
import json
import os
from datetime import datetime, timezone

from executor_config import (
    EXECUTION_MODE,
    MAX_RISK_PER_TRADE_USD,
    MAX_LOT,
    MIN_SCORE_TO_EXECUTE,
    ALLOWED_SYMBOLS,
    DEFAULT_SYMBOL_RISK_PROFILE,
    SYMBOL_RISK_PROFILES,
    ALLOW_LIVE_TRADING,
    MAX_ORDERS_PER_RUN,
    MAX_OPEN_PAPER_ORDERS_GLOBAL,
    MAX_OPEN_PAPER_ORDERS_PER_SYMBOL,
    BLOCK_IF_SIGNAL_EXPIRED,
    BLOCK_DUPLICATE_SIGNAL,
)

SIGNAL_FILE = "mt5_trade_signals.json"
TRADE_SIGNAL_OUTPUT = "trade_signals.json"
PAPER_OBSERVATION_ONLY_STATUS = "PAPER_OBSERVATION_ONLY"
PAPER_ENTRY_ALLOWED_STATUSES = {"READY_TO_TRADE", PAPER_OBSERVATION_ONLY_STATUS}
PAPER_LOG_FILE = "paper_orders.json"
SHADOW_PROBE_LOG_FILE = "paper_probe_orders.json"
SHADOW_PROBE_EXECUTED_IDS_FILE = "paper_probe_executed_signal_ids.json"
ENABLE_SHADOW_PROBE_ORDERS = True
MAX_SHADOW_PROBE_ORDERS_PER_RUN = 1
SHADOW_PROBE_ALLOWED_SYMBOLS = {"EURUSD"}
SHADOW_PROBE_ALLOWED_STATUSES = {"WAIT"}
SHADOW_PROBE_EXCLUDED_FROM_PHASE4_QUALITY = True
SHADOW_PROBE_DEFAULT_LOT = 0.01
SHADOW_PROBE_DEFAULT_RISK_USD = 0.10
SHADOW_PROBE_EURUSD_SL_PIPS = 10
SHADOW_PROBE_EURUSD_TP_PIPS = 15
SHADOW_PROBE_EURUSD_PIP_SIZE = 0.0001
SHADOW_PROBE_PRICE_FILES = [
    "data/EURUSD_M15.csv",
    "data/EURUSD.csv",
    "EURUSD_M15.csv",
    "EURUSD.csv",
]
EXECUTED_IDS_FILE = "executed_signal_ids.json"
QUALITY_REPORT_FILE = "paper_quality_report.json"
PAPER_QUALITY_RULES_FILE = "paper_quality_rules.json"
PAPER_EXECUTOR_REPORT_FILE = "paper_executor_report.json"

# =========================
# QUALITY-AWARE EXECUTION GUARD
# =========================

QUALITY_GUARD_ENABLED = True
QUALITY_GUARD_STATUS_TO_RESTRICT = "NOT_READY"
QUALITY_GUARD_MIN_WINRATE_PERCENT = 40.0
QUALITY_GUARD_MIN_SCORE_WHEN_WEAK = 4

# =========================
# PHASE 4 RULES EXECUTION GUARD
# =========================

PHASE4_RULES_GUARD_ENABLED = True
PHASE4_BLOCK_STATUSES = {"BLOCK"}
PHASE4_RESTRICT_STATUSES = {"RESTRICT"}

# =========================
# SYMBOL PERFORMANCE GUARD
# =========================

SYMBOL_PERFORMANCE_GUARD_ENABLED = True
SYMBOL_PERFORMANCE_MIN_CLOSED_ORDERS = 5
SYMBOL_PERFORMANCE_MIN_WINRATE_PERCENT = 40.0
SYMBOL_PERFORMANCE_REQUIRE_POSITIVE_NET = True
SYMBOL_PERFORMANCE_MIN_SCORE_WHEN_WEAK = 4

# =========================
# STRATEGY PERFORMANCE GUARD
# =========================

STRATEGY_PERFORMANCE_GUARD_ENABLED = True
STRATEGY_PERFORMANCE_MIN_CLOSED_ORDERS = 5
STRATEGY_PERFORMANCE_MIN_WINRATE_PERCENT = 40.0
STRATEGY_PERFORMANCE_REQUIRE_NEGATIVE_NET_TO_RESTRICT = False
STRATEGY_PERFORMANCE_MIN_SCORE_WHEN_WEAK = 4

# =========================
# PAPER SIGNAL CLEANUP
# =========================

# In Phase 3 we allow only limited paper exposure. After the executor accepts one
# paper order, any remaining MT5-ready signals must not keep showing as pending.
# They are cleared and summarized so dashboard/runner status stays synchronized.
CLEAR_SIGNALS_AFTER_PAPER_EXECUTION = True
CLEAR_SIGNALS_WHEN_OPEN_ORDER_BLOCKS_EXECUTION = True


def load_json(path, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default



def load_phase4r_paper_observation_signals():
    """Load Phase4R paper-observation-only decisions from trade_signals.json.

    Safety contract:
    - Does not read from MT5-ready export.
    - Does not create live/demo-auto permission.
    - Only returns strict PAPER_OBSERVATION_ONLY decisions.
    """
    payload = load_json(TRADE_SIGNAL_OUTPUT, {})
    decisions = payload.get("all_decisions", [])

    if not isinstance(decisions, list):
        return []

    allowed = []
    for item in decisions:
        if not isinstance(item, dict):
            continue
        if item.get("status") != PAPER_OBSERVATION_ONLY_STATUS:
            continue
        if item.get("paper_observation_only") is not True:
            continue
        if item.get("mt5_ready") is True:
            continue
        if item.get("live_allowed") is True:
            continue
        if item.get("safe_to_demo_auto_order") is True:
            continue

        safe_item = dict(item)
        safe_item["paper_observation_only"] = True
        safe_item["phase4r_paper_observation_allowed"] = True
        safe_item["live_allowed"] = False
        safe_item["safe_to_demo_auto_order"] = False
        safe_item["mt5_ready"] = False
        allowed.append(safe_item)

    return allowed


def merge_phase4r_paper_observation_signals(signals):
    """Append PAPER_OBSERVATION_ONLY decisions to paper executor input only.

    These signals must never be written to mt5_trade_signals.json.
    """
    merged = list(signals or [])
    existing_ids = {
        str(item.get("signal_id") or item.get("id") or "")
        for item in merged
        if isinstance(item, dict)
    }

    for item in load_phase4r_paper_observation_signals():
        signal_id = str(item.get("signal_id") or item.get("id") or "")
        if signal_id and signal_id in existing_ids:
            continue
        merged.append(item)
        if signal_id:
            existing_ids.add(signal_id)

    return merged


# =========================
# SHADOW PROBE ORDER HELPERS
# =========================


# Helper: Best-effort latest close price for diagnostic-only shadow probe entries
def get_latest_shadow_probe_price(symbol):
    """Best-effort latest close price for diagnostic-only shadow probe entries."""
    symbol = str(symbol or "").upper()
    if symbol != "EURUSD":
        return 0.0

    for path in SHADOW_PROBE_PRICE_FILES:
        if not os.path.exists(path):
            continue

        try:
            with open(path, "r", newline="") as f:
                rows = list(csv.DictReader(f))
        except Exception:
            continue

        if not rows:
            continue

        latest = rows[-1]
        for key in ["close", "Close", "CLOSE", "bid", "Bid", "price", "Price"]:
            try:
                value = float(latest.get(key, 0) or 0)
            except Exception:
                value = 0.0
            if value > 0:
                return value

    return 0.0


# Helper: Add synthetic diagnostic-only execution fields for shadow probe signals
def enrich_shadow_probe_signal(item):
    """Add synthetic diagnostic-only execution fields when blocked WAIT lacks entry/SL/TP.

    This does not make the signal official, live, demo-auto, or MT5-ready.
    It only enables a separate paper_probe_orders.json diagnostic track.
    """
    safe_item = dict(item)
    symbol = str(safe_item.get("symbol", "") or "").upper()
    action = str(get_first_value(safe_item, ["type", "action", "order_type", "signal"], "") or "").upper()

    if action not in {"BUY", "SELL"}:
        return None

    entry = get_signal_entry(safe_item)
    if entry <= 0:
        entry = get_latest_shadow_probe_price(symbol)

    if entry <= 0:
        return None

    lot = float(safe_item.get("lot", 0) or 0)
    if lot <= 0:
        lot = min(SHADOW_PROBE_DEFAULT_LOT, MAX_LOT)

    if lot <= 0 or lot > MAX_LOT:
        return None

    sl = get_signal_sl(safe_item)
    tp = get_signal_tp(safe_item)

    sl_distance = SHADOW_PROBE_EURUSD_SL_PIPS * SHADOW_PROBE_EURUSD_PIP_SIZE
    tp_distance = SHADOW_PROBE_EURUSD_TP_PIPS * SHADOW_PROBE_EURUSD_PIP_SIZE

    if sl <= 0 or tp <= 0:
        if action == "BUY":
            sl = round(entry - sl_distance, 5)
            tp = round(entry + tp_distance, 5)
        else:
            sl = round(entry + sl_distance, 5)
            tp = round(entry - tp_distance, 5)

    if action == "BUY" and not (sl < entry < tp):
        return None
    if action == "SELL" and not (tp < entry < sl):
        return None

    safe_item["type"] = action
    safe_item["action"] = action
    safe_item["lot"] = lot
    safe_item["entry"] = round(entry, 5)
    safe_item["sl"] = sl
    safe_item["tp"] = tp
    safe_item["risk_usd"] = float(safe_item.get("risk_usd", 0) or SHADOW_PROBE_DEFAULT_RISK_USD)
    safe_item["shadow_probe_synthetic_execution"] = True
    safe_item["shadow_probe_synthetic_reason"] = (
        "Blocked WAIT decision had no executable entry/SL/TP/lot; synthetic diagnostic-only probe fields were generated."
    )
    return safe_item


def load_shadow_probe_signals():
    """Load diagnostic-only blocked WAIT decisions for separate shadow probe tracking.

    Safety contract:
    - Does not write to mt5_trade_signals.json.
    - Does not create official paper_orders.json entries.
    - Excluded from Phase 4 quality/winrate calculations.
    - EURUSD only by default.
    """
    if not ENABLE_SHADOW_PROBE_ORDERS:
        return []

    payload = load_json(TRADE_SIGNAL_OUTPUT, {})
    decisions = payload.get("all_decisions", [])

    if not isinstance(decisions, list):
        return []

    allowed = []
    for item in decisions:
        if not isinstance(item, dict):
            continue

        symbol = str(item.get("symbol", "") or "").upper()
        status = str(item.get("status", "") or "").upper()
        strategy = str(item.get("selected_strategy", item.get("strategy", "")) or "").upper()

        if symbol not in SHADOW_PROBE_ALLOWED_SYMBOLS:
            continue
        if status not in SHADOW_PROBE_ALLOWED_STATUSES:
            continue
        if item.get("mt5_ready") is True:
            continue
        if item.get("live_allowed") is True:
            continue
        if item.get("safe_to_demo_auto_order") is True:
            continue
        if strategy in {"NO_STRATEGY", "NO_ALLOWED_STRATEGY"}:
            # No clean executable strategy lane; keep this as diagnostic only.
            pass

        safe_item = enrich_shadow_probe_signal(item)
        if safe_item is None:
            continue

        safe_item["shadow_probe_only"] = True
        safe_item["excluded_from_phase4_quality"] = SHADOW_PROBE_EXCLUDED_FROM_PHASE4_QUALITY
        safe_item["paper_observation_only"] = False
        safe_item["live_allowed"] = False
        safe_item["safe_to_demo_auto_order"] = False
        safe_item["mt5_ready"] = False
        allowed.append(safe_item)

    return allowed


def get_open_shadow_probe_orders(shadow_orders):
    if not isinstance(shadow_orders, list):
        return []

    return [
        order for order in shadow_orders
        if order.get("status") == "SHADOW_PROBE_OPEN"
    ]



def calculate_shadow_probe_profit_usd(order, close_price):
    """Approximate diagnostic-only probe P/L in USD for EURUSD micro-lot probes."""
    try:
        entry = float(order.get("entry", 0) or 0)
        lot = float(order.get("lot", 0) or 0)
        action = str(order.get("type", "") or "").upper()
        close_price = float(close_price or 0)
    except Exception:
        return 0.0

    if entry <= 0 or lot <= 0 or close_price <= 0:
        return 0.0

    pip_value = 10.0 * lot
    if action == "BUY":
        pips = (close_price - entry) / SHADOW_PROBE_EURUSD_PIP_SIZE
    elif action == "SELL":
        pips = (entry - close_price) / SHADOW_PROBE_EURUSD_PIP_SIZE
    else:
        return 0.0

    return round(pips * pip_value, 4)


def monitor_shadow_probe_orders(shadow_orders):
    """Close SHADOW_PROBE_OPEN orders when diagnostic TP/SL is reached."""
    if not isinstance(shadow_orders, list):
        return []

    closed = []
    for order in shadow_orders:
        if order.get("status") != "SHADOW_PROBE_OPEN":
            continue

        symbol = str(order.get("symbol", "") or "").upper()
        action = str(order.get("type", "") or "").upper()
        latest_price = get_latest_shadow_probe_price(symbol)

        if latest_price <= 0:
            continue

        try:
            sl = float(order.get("sl", 0) or 0)
            tp = float(order.get("tp", 0) or 0)
        except Exception:
            continue

        if sl <= 0 or tp <= 0:
            continue

        result = None
        if action == "BUY":
            if latest_price <= sl:
                result = "LOSS"
            elif latest_price >= tp:
                result = "WIN"
        elif action == "SELL":
            if latest_price >= sl:
                result = "LOSS"
            elif latest_price <= tp:
                result = "WIN"

        if result is None:
            continue

        order["result"] = result
        order["status"] = "SHADOW_PROBE_WIN" if result == "WIN" else "SHADOW_PROBE_LOSS"
        order["close_price"] = round(latest_price, 5)
        order["closed_at"] = utc_now_iso()
        order["profit_usd"] = calculate_shadow_probe_profit_usd(order, latest_price)
        order["excluded_from_phase4_quality"] = True
        order["live_allowed"] = False
        order["safe_to_demo_auto_order"] = False
        order["mt5_ready"] = False
        closed.append(order)

    return closed



def create_shadow_probe_order(signal):
    symbol = str(signal.get("symbol", "") or "").upper()
    action = get_signal_action(signal)
    strategy = get_signal_strategy(signal)
    signal_id = signal.get("signal_id") or f"{symbol}_{action}_{strategy}_{utc_now_iso()}"

    return {
        "paper_probe_order_id": f"PROBE_{signal_id}",
        "signal_id": signal_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "symbol": symbol,
        "type": action,
        "lot": float(signal.get("lot", 0) or 0),
        "entry": get_signal_entry(signal),
        "sl": get_signal_sl(signal),
        "tp": get_signal_tp(signal),
        "strategy": strategy,
        "score": get_signal_score(signal),
        "risk_usd": get_signal_risk_usd(signal),
        "status": "SHADOW_PROBE_OPEN",
        "result": None,
        "close_price": None,
        "closed_at": None,
        "profit_usd": 0.0,
        "shadow_probe_only": True,
        "excluded_from_phase4_quality": SHADOW_PROBE_EXCLUDED_FROM_PHASE4_QUALITY,
        "source_status": signal.get("status"),
        "source_reason": signal.get("reason"),
        "shadow_probe_synthetic_execution": bool(signal.get("shadow_probe_synthetic_execution")),
        "shadow_probe_synthetic_reason": signal.get("shadow_probe_synthetic_reason"),
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "mt5_ready": False,
        "executor_created_at": utc_now_iso(),
        "executor_mode": EXECUTION_MODE,
        "source": "AI_SCALPER_SHADOW_PROBE",
    }

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def build_executor_report(accepted, rejected, raw_signal_count, cleanup_applied, cleanup_reason):
    return {
        "generated_at": utc_now_iso(),
        "execution_mode": EXECUTION_MODE,
        "live_allowed": ALLOW_LIVE_TRADING,
        "raw_signal_count": raw_signal_count,
        "accepted_count": len(accepted),
        "rejected_count": len(rejected),
        "cleanup_applied": cleanup_applied,
        "cleanup_reason": cleanup_reason,
        "accepted_orders": accepted,
        "rejected_orders": rejected,
    }


def build_signal_cleanup_payload(accepted, rejected, cleanup_reason):
    return {
        "generated_at": utc_now_iso(),
        "status": "PAPER_EXECUTOR_CONSUMED",
        "execution_mode": EXECUTION_MODE,
        "live_allowed": ALLOW_LIVE_TRADING,
        "orders": [],
        "valid_orders": [],
        "ready_orders": [],
        "signals": [],
        "paper_executor_summary": {
            "accepted_count": len(accepted),
            "rejected_count": len(rejected),
            "cleanup_reason": cleanup_reason,
            "accepted_signal_ids": [order.get("signal_id") for order in accepted],
            "rejected_signal_ids": [
                item.get("signal", {}).get("signal_id")
                for item in rejected
                if isinstance(item, dict)
            ],
        },
    }


def should_cleanup_signals_after_run(accepted, rejected):
    if accepted and CLEAR_SIGNALS_AFTER_PAPER_EXECUTION:
        return True, "Accepted paper order(s); clearing remaining MT5-ready signals to prevent stale pending execution."

    if not CLEAR_SIGNALS_WHEN_OPEN_ORDER_BLOCKS_EXECUTION:
        return False, "Signal cleanup disabled when open order blocks execution."

    for item in rejected:
        reasons = item.get("reasons", []) if isinstance(item, dict) else []
        reason_text = " ".join(str(reason) for reason in reasons).lower()
        if "open paper order limit reached" in reason_text:
            return True, "Open paper order guard blocked execution; clearing MT5-ready signals to keep paper-only state synchronized."

    return False, "No cleanup condition met."


def get_quality_guard_min_score():
    if not QUALITY_GUARD_ENABLED:
        return MIN_SCORE_TO_EXECUTE

    quality_report = load_json(QUALITY_REPORT_FILE, {})
    if not isinstance(quality_report, dict):
        return MIN_SCORE_TO_EXECUTE

    status = str(quality_report.get("quality_status", "")).upper()
    metrics = quality_report.get("metrics", {})

    if not isinstance(metrics, dict):
        metrics = {}

    winrate = float(metrics.get("winrate_percent", 0) or 0)

    if (
        status == QUALITY_GUARD_STATUS_TO_RESTRICT
        and winrate < QUALITY_GUARD_MIN_WINRATE_PERCENT
    ):
        return max(MIN_SCORE_TO_EXECUTE, QUALITY_GUARD_MIN_SCORE_WHEN_WEAK)

    return MIN_SCORE_TO_EXECUTE


# =========================
# PHASE 4 RULES GUARD HELPERS
# =========================

def load_phase4_quality_rules():
    if not PHASE4_RULES_GUARD_ENABLED:
        return {
            "enabled": False,
            "source": PAPER_QUALITY_RULES_FILE,
            "reason": "Phase 4 rules guard disabled in paper executor.",
            "quality_status": "DISABLED",
            "symbol_rules": {},
            "strategy_rules": {},
        }

    rules = load_json(PAPER_QUALITY_RULES_FILE, {})

    if not isinstance(rules, dict) or not rules:
        return {
            "enabled": False,
            "source": PAPER_QUALITY_RULES_FILE,
            "reason": "Phase 4 quality rules file missing or invalid.",
            "quality_status": "UNKNOWN",
            "symbol_rules": {},
            "strategy_rules": {},
        }

    return {
        "enabled": True,
        "source": PAPER_QUALITY_RULES_FILE,
        "reason": "Phase 4 quality rules loaded for executor final gate.",
        "quality_status": str(rules.get("quality_status", "UNKNOWN")).upper(),
        "quality_action": rules.get("quality_action", ""),
        "base_min_score": int(rules.get("base_min_score", MIN_SCORE_TO_EXECUTE) or MIN_SCORE_TO_EXECUTE),
        "symbol_rules": rules.get("symbol_rules", {}) if isinstance(rules.get("symbol_rules", {}), dict) else {},
        "strategy_rules": rules.get("strategy_rules", {}) if isinstance(rules.get("strategy_rules", {}), dict) else {},
    }


def get_phase4_rule(phase4_rules, rule_type, name):
    if not phase4_rules or not phase4_rules.get("enabled"):
        return None

    name = str(name or "UNKNOWN").upper()
    collection_key = "symbol_rules" if rule_type == "symbol" else "strategy_rules"
    collection = phase4_rules.get(collection_key, {})

    if not isinstance(collection, dict):
        return None

    return collection.get(name)


def validate_phase4_executor_guard(signal, phase4_rules):
    if not phase4_rules or not phase4_rules.get("enabled"):
        return [], {
            "enabled": False,
            "status": "NOT_LOADED",
            "required_score": MIN_SCORE_TO_EXECUTE,
            "reason": "Phase 4 rules are not loaded in executor.",
            "symbol_rule": None,
            "strategy_rule": None,
        }

    symbol = str(signal.get("symbol", "") or "").upper()
    strategy = str(get_signal_strategy(signal) or "UNKNOWN").upper()
    score = get_signal_score(signal)

    symbol_rule = get_phase4_rule(phase4_rules, "symbol", symbol)
    strategy_rule = get_phase4_rule(phase4_rules, "strategy", strategy)

    reasons = []
    required_score = MIN_SCORE_TO_EXECUTE
    rule_notes = []

    for label, rule in [("symbol", symbol_rule), ("strategy", strategy_rule)]:
        if not isinstance(rule, dict):
            continue

        rule_name = str(rule.get("name", "UNKNOWN") or "UNKNOWN").upper()
        guard_status = str(rule.get("guard_status", "UNKNOWN") or "UNKNOWN").upper()
        allow_new_entries = bool(rule.get("allow_new_entries", True))
        min_score_required = int(rule.get("min_score_required", MIN_SCORE_TO_EXECUTE) or MIN_SCORE_TO_EXECUTE)
        rule_reason = rule.get("reason", "")

        required_score = max(required_score, min_score_required)
        rule_notes.append(
            f"{label} {rule_name}: status={guard_status}, min_score={min_score_required}, allow={allow_new_entries}"
        )

        if guard_status in PHASE4_BLOCK_STATUSES or not allow_new_entries:
            reasons.append(
                f"Phase 4 {label} guard blocks new entries for {rule_name}: {rule_reason}"
            )

    if score < required_score:
        reasons.append(
            f"Score {score} below Phase 4 executor minimum {required_score}. "
            + " | ".join(rule_notes)
        )

    if reasons:
        guard_status = "BLOCKED"
        guard_reason = " | ".join(reasons)
    else:
        guard_status = "PASSED"
        guard_reason = (
            f"Phase 4 executor guard passed with score {score} >= required {required_score}. "
            + (" | ".join(rule_notes) if rule_notes else "No specific Phase 4 rule found.")
        )

    return reasons, {
        "enabled": True,
        "status": guard_status,
        "required_score": required_score,
        "reason": guard_reason,
        "symbol_rule": symbol_rule,
        "strategy_rule": strategy_rule,
    }


def get_closed_paper_orders_by_symbol(symbol):
    symbol = str(symbol or "").upper()
    paper_orders = load_json(PAPER_LOG_FILE, [])

    if not isinstance(paper_orders, list):
        return []

    closed_statuses = {"PAPER_WIN", "PAPER_LOSS", "PAPER_TIMEOUT"}
    closed_results = {"WIN", "LOSS", "TIMEOUT"}

    return [
        order for order in paper_orders
        if str(order.get("symbol", "")).upper() == symbol
        and (
            order.get("status") in closed_statuses
            or order.get("result") in closed_results
        )
    ]


def get_symbol_performance_summary(symbol):
    closed_orders = get_closed_paper_orders_by_symbol(symbol)
    closed_count = len(closed_orders)
    wins = sum(1 for order in closed_orders if order.get("result") == "WIN")
    losses = sum(1 for order in closed_orders if order.get("result") == "LOSS")
    timeouts = sum(1 for order in closed_orders if order.get("result") == "TIMEOUT")
    net_profit = round(
        sum(float(order.get("profit_usd", 0) or 0) for order in closed_orders),
        4,
    )
    winrate = round((wins / closed_count) * 100, 2) if closed_count > 0 else 0.0

    return {
        "symbol": str(symbol or "").upper(),
        "closed_orders": closed_count,
        "wins": wins,
        "losses": losses,
        "timeouts": timeouts,
        "winrate_percent": winrate,
        "net_profit_usd": net_profit,
    }


def get_symbol_performance_min_score(symbol):
    if not SYMBOL_PERFORMANCE_GUARD_ENABLED:
        return MIN_SCORE_TO_EXECUTE

    summary = get_symbol_performance_summary(symbol)

    if summary["closed_orders"] < SYMBOL_PERFORMANCE_MIN_CLOSED_ORDERS:
        return MIN_SCORE_TO_EXECUTE

    weak_winrate = summary["winrate_percent"] < SYMBOL_PERFORMANCE_MIN_WINRATE_PERCENT
    weak_net = summary["net_profit_usd"] < 0 if SYMBOL_PERFORMANCE_REQUIRE_POSITIVE_NET else False

    if weak_winrate and weak_net:
        return max(MIN_SCORE_TO_EXECUTE, SYMBOL_PERFORMANCE_MIN_SCORE_WHEN_WEAK)

    return MIN_SCORE_TO_EXECUTE


def get_closed_paper_orders_by_strategy(strategy):
    strategy = str(strategy or "UNKNOWN").upper()
    paper_orders = load_json(PAPER_LOG_FILE, [])

    if not isinstance(paper_orders, list):
        return []

    closed_statuses = {"PAPER_WIN", "PAPER_LOSS", "PAPER_TIMEOUT"}
    closed_results = {"WIN", "LOSS", "TIMEOUT"}

    return [
        order for order in paper_orders
        if str(order.get("strategy", "UNKNOWN") or "UNKNOWN").upper() == strategy
        and (
            order.get("status") in closed_statuses
            or order.get("result") in closed_results
        )
    ]


def get_strategy_performance_summary(strategy):
    closed_orders = get_closed_paper_orders_by_strategy(strategy)
    closed_count = len(closed_orders)
    wins = sum(1 for order in closed_orders if order.get("result") == "WIN")
    losses = sum(1 for order in closed_orders if order.get("result") == "LOSS")
    timeouts = sum(1 for order in closed_orders if order.get("result") == "TIMEOUT")
    net_profit = round(
        sum(float(order.get("profit_usd", 0) or 0) for order in closed_orders),
        4,
    )
    winrate = round((wins / closed_count) * 100, 2) if closed_count > 0 else 0.0

    return {
        "strategy": str(strategy or "UNKNOWN").upper(),
        "closed_orders": closed_count,
        "wins": wins,
        "losses": losses,
        "timeouts": timeouts,
        "winrate_percent": winrate,
        "net_profit_usd": net_profit,
    }


def get_strategy_performance_min_score(strategy):
    if not STRATEGY_PERFORMANCE_GUARD_ENABLED:
        return MIN_SCORE_TO_EXECUTE

    summary = get_strategy_performance_summary(strategy)

    if summary["closed_orders"] < STRATEGY_PERFORMANCE_MIN_CLOSED_ORDERS:
        return MIN_SCORE_TO_EXECUTE

    weak_winrate = summary["winrate_percent"] < STRATEGY_PERFORMANCE_MIN_WINRATE_PERCENT
    weak_net = summary["net_profit_usd"] < 0

    if STRATEGY_PERFORMANCE_REQUIRE_NEGATIVE_NET_TO_RESTRICT:
        should_restrict = weak_winrate and weak_net
    else:
        should_restrict = weak_winrate

    if should_restrict:
        return max(MIN_SCORE_TO_EXECUTE, STRATEGY_PERFORMANCE_MIN_SCORE_WHEN_WEAK)

    return MIN_SCORE_TO_EXECUTE


def normalize_signals(raw_signals):
    """Convert mt5_trade_signals.json into a clean list of signal dictionaries."""
    if isinstance(raw_signals, list):
        return raw_signals

    if isinstance(raw_signals, dict):
        possible_keys = [
            "signals",
            "mt5_signals",
            "orders",
            "valid_orders",
            "ready_orders",
            "trade_signals",
        ]

        for key in possible_keys:
            value = raw_signals.get(key)
            if isinstance(value, list):
                return value

        # If the file contains one single signal as a dictionary.
        required_signal_fields = {"symbol", "entry", "sl", "tp"}
        if required_signal_fields.issubset(set(raw_signals.keys())):
            return [raw_signals]

    return []


def get_open_paper_orders(paper_orders):
    if not isinstance(paper_orders, list):
        return []

    return [
        order for order in paper_orders
        if order.get("status") == "PAPER_OPEN"
    ]


def get_open_orders_for_symbol(paper_orders, symbol):
    symbol = str(symbol or "").upper()

    return [
        order for order in get_open_paper_orders(paper_orders)
        if str(order.get("symbol", "")).upper() == symbol
    ]


def get_symbol_risk_profile(symbol):
    symbol = str(symbol or "").upper()
    profile = SYMBOL_RISK_PROFILES.get(symbol, DEFAULT_SYMBOL_RISK_PROFILE)

    return {
        "max_risk_usd": float(profile.get("max_risk_usd", DEFAULT_SYMBOL_RISK_PROFILE["max_risk_usd"])),
        "max_lot": float(profile.get("max_lot", DEFAULT_SYMBOL_RISK_PROFILE["max_lot"])),
        "min_score": int(profile.get("min_score", DEFAULT_SYMBOL_RISK_PROFILE["min_score"])),
    }


def parse_time(value):
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def is_expired(signal):
    expires_at = signal.get("expires_at")

    if not expires_at:
        return False

    expiry_time = parse_time(expires_at)

    if expiry_time is None:
        return True

    now = datetime.now(timezone.utc)

    if expiry_time.tzinfo is None:
        expiry_time = expiry_time.replace(tzinfo=timezone.utc)

    return now > expiry_time


def get_first_value(signal, keys, default=None):
    for key in keys:
        value = signal.get(key)
        if value is not None:
            return value
    return default


def get_signal_entry(signal):
    return float(get_first_value(signal, ["entry", "entry_price", "price"], 0) or 0)


def get_signal_sl(signal):
    return float(get_first_value(signal, ["sl", "stop_loss", "stoploss"], 0) or 0)


def get_signal_tp(signal):
    return float(get_first_value(signal, ["tp", "take_profit", "takeprofit"], 0) or 0)


def get_signal_score(signal):
    return int(get_first_value(signal, ["score", "strategy_score"], 0) or 0)


def get_signal_risk_usd(signal):
    return float(get_first_value(signal, ["risk_usd", "risk_amount"], 0) or 0)


def get_signal_strategy(signal):
    return str(get_first_value(signal, ["strategy", "selected_strategy"], "UNKNOWN") or "UNKNOWN")


def get_signal_action(signal):
    action = get_first_value(signal, ["type", "action", "order_type"], "")
    return str(action or "").upper()


def validate_signal(signal, executed_ids, paper_orders, phase4_rules=None):
    reasons = []

    symbol = str(signal.get("symbol", "")).upper()
    open_orders = get_open_paper_orders(paper_orders)
    symbol_profile = get_symbol_risk_profile(symbol)
    quality_min_score = get_quality_guard_min_score()
    symbol_performance_min_score = get_symbol_performance_min_score(symbol)
    strategy = get_signal_strategy(signal)
    strategy_performance_min_score = get_strategy_performance_min_score(strategy)
    action = get_signal_action(signal)
    phase4_reasons, phase4_guard_info = validate_phase4_executor_guard(signal, phase4_rules)
    lot = float(signal.get("lot", 0) or 0)
    score = get_signal_score(signal)
    risk_usd = get_signal_risk_usd(signal)
    signal_id = signal.get("signal_id")

    entry = get_signal_entry(signal)
    sl = get_signal_sl(signal)
    tp = get_signal_tp(signal)

    if not signal_id:
        reasons.append("Missing signal_id.")

    if BLOCK_DUPLICATE_SIGNAL and signal_id in executed_ids:
        reasons.append("Duplicate signal_id already processed.")

    if len(open_orders) >= MAX_OPEN_PAPER_ORDERS_GLOBAL:
        reasons.append(
            f"Open paper order limit reached: {len(open_orders)}/{MAX_OPEN_PAPER_ORDERS_GLOBAL} global."
        )

    symbol_open_orders = get_open_orders_for_symbol(paper_orders, symbol)
    if len(symbol_open_orders) >= MAX_OPEN_PAPER_ORDERS_PER_SYMBOL:
        reasons.append(
            f"Open paper order limit reached for {symbol}: {len(symbol_open_orders)}/{MAX_OPEN_PAPER_ORDERS_PER_SYMBOL}."
        )

    if symbol not in ALLOWED_SYMBOLS:
        reasons.append(f"Symbol {symbol} is not allowed.")

    if action not in ["BUY", "SELL"]:
        reasons.append(f"Invalid action/type: {action}")

    if lot <= 0:
        reasons.append("Lot must be greater than 0.")

    if lot > MAX_LOT:
        reasons.append(f"Lot {lot} exceeds global MAX_LOT {MAX_LOT}.")

    if lot > symbol_profile["max_lot"]:
        reasons.append(
            f"Lot {lot} exceeds {symbol} profile max lot {symbol_profile['max_lot']}."
        )

    if score < MIN_SCORE_TO_EXECUTE:
        reasons.append(f"Score {score} below global minimum {MIN_SCORE_TO_EXECUTE}.")

    if score < quality_min_score:
        reasons.append(
            f"Score {score} below quality-aware minimum {quality_min_score} because quality status is weak."
        )

    if score < symbol_performance_min_score:
        summary = get_symbol_performance_summary(symbol)
        reasons.append(
            f"Score {score} below symbol-performance minimum {symbol_performance_min_score} because {symbol} performance is weak: "
            f"closed={summary['closed_orders']}, winrate={summary['winrate_percent']}%, net=${summary['net_profit_usd']}."
        )

    if score < strategy_performance_min_score:
        summary = get_strategy_performance_summary(strategy)
        reasons.append(
            f"Score {score} below strategy-performance minimum {strategy_performance_min_score} because {strategy} performance is weak: "
            f"closed={summary['closed_orders']}, winrate={summary['winrate_percent']}%, net=${summary['net_profit_usd']}."
        )

    if phase4_reasons:
        reasons.extend(phase4_reasons)

    if score < symbol_profile["min_score"]:
        reasons.append(
            f"Score {score} below {symbol} profile minimum {symbol_profile['min_score']}."
        )

    if risk_usd > MAX_RISK_PER_TRADE_USD:
        reasons.append(f"Risk ${risk_usd} exceeds global max ${MAX_RISK_PER_TRADE_USD}.")

    if risk_usd > symbol_profile["max_risk_usd"]:
        reasons.append(
            f"Risk ${risk_usd} exceeds {symbol} profile max ${symbol_profile['max_risk_usd']}."
        )

    if BLOCK_IF_SIGNAL_EXPIRED and is_expired(signal):
        reasons.append("Signal expired.")

    if entry <= 0 or sl <= 0 or tp <= 0:
        reasons.append("Entry, SL, or TP is invalid.")

    if action == "BUY":
        if not (sl < entry < tp):
            reasons.append("Invalid BUY structure: SL must be below entry and TP above entry.")

    if action == "SELL":
        if not (tp < entry < sl):
            reasons.append("Invalid SELL structure: TP must be below entry and SL above entry.")

    return reasons, phase4_guard_info


def create_paper_order(signal, phase4_guard_info=None):
    symbol = str(signal.get("symbol", "")).upper()
    action = get_signal_action(signal)
    symbol_profile = get_symbol_risk_profile(symbol)

    return {
        "paper_order_id": f"PAPER_{signal.get('signal_id')}",
        "signal_id": signal.get("signal_id"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "symbol": symbol,
        "type": action,
        "lot": float(signal.get("lot", 0) or 0),
        "entry": get_signal_entry(signal),
        "sl": get_signal_sl(signal),
        "tp": get_signal_tp(signal),
        "strategy": get_signal_strategy(signal),
        "score": get_signal_score(signal),
        "strategy_original_score": signal.get("strategy_original_score", signal.get("score", get_signal_score(signal))),
        "score_boost": signal.get("score_boost", {}),
        "phase4_quality_guard": signal.get("phase4_quality_guard", phase4_guard_info or {}),
        "executor_phase4_quality_guard": phase4_guard_info or {},
        "risk_usd": get_signal_risk_usd(signal),
        "symbol_risk_profile": symbol_profile,
        "status": "PAPER_OPEN",
        "paper_observation_only": signal.get("status") == PAPER_OBSERVATION_ONLY_STATUS,
        "phase4r_review_lock": "LOCKED" if signal.get("status") == PAPER_OBSERVATION_ONLY_STATUS else signal.get("phase4r_review_lock"),
        "phase4r_paper_observation_allowed": bool(signal.get("status") == PAPER_OBSERVATION_ONLY_STATUS or signal.get("phase4r_paper_observation_allowed")),
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "mt5_ready": False,
        "result": None,
        "close_price": None,
        "closed_at": None,
        "profit_usd": 0.0,
        "executor_created_at": utc_now_iso(),
        "executor_mode": EXECUTION_MODE,
        "source": "AI_SCALPER",
    }


def main():
    print("\n=== AI_SCALPER PAPER EXECUTOR ===")
    print(f"Execution mode: {EXECUTION_MODE}")

    quality_min_score = get_quality_guard_min_score()
    if quality_min_score > MIN_SCORE_TO_EXECUTE:
        print(
            f"Quality guard: active | Effective min score: {quality_min_score} "
            f"because quality status is weak."
        )
    else:
        print(f"Quality guard: normal | Effective min score: {quality_min_score}")

    if SYMBOL_PERFORMANCE_GUARD_ENABLED:
        print(
            "Symbol performance guard: active | "
            f"Min closed: {SYMBOL_PERFORMANCE_MIN_CLOSED_ORDERS}, "
            f"Min winrate: {SYMBOL_PERFORMANCE_MIN_WINRATE_PERCENT}%, "
            f"Require positive net: {SYMBOL_PERFORMANCE_REQUIRE_POSITIVE_NET}"
        )

    if STRATEGY_PERFORMANCE_GUARD_ENABLED:
        print(
            "Strategy performance guard: active | "
            f"Min closed: {STRATEGY_PERFORMANCE_MIN_CLOSED_ORDERS}, "
            f"Min winrate: {STRATEGY_PERFORMANCE_MIN_WINRATE_PERCENT}%, "
            f"Require negative net: {STRATEGY_PERFORMANCE_REQUIRE_NEGATIVE_NET_TO_RESTRICT}"
        )

    phase4_rules = load_phase4_quality_rules()
    print(
        "Phase 4 rules guard: "
        f"enabled={phase4_rules.get('enabled')} | "
        f"quality_status={phase4_rules.get('quality_status')} | "
        f"source={phase4_rules.get('source')}"
    )
    print(f"Phase 4 rules reason: {phase4_rules.get('reason')}")

    if EXECUTION_MODE == "LIVE" and not ALLOW_LIVE_TRADING:
        raise RuntimeError("LIVE trading is blocked. Set ALLOW_LIVE_TRADING=True only when fully ready.")

    raw_signals = load_json(SIGNAL_FILE, [])
    signals = normalize_signals(raw_signals)
    signals = merge_phase4r_paper_observation_signals(signals)
    paper_orders = load_json(PAPER_LOG_FILE, [])
    executed_ids = load_json(EXECUTED_IDS_FILE, [])
    shadow_probe_orders = load_json(SHADOW_PROBE_LOG_FILE, [])
    shadow_probe_executed_ids = load_json(SHADOW_PROBE_EXECUTED_IDS_FILE, [])
    shadow_probe_closed = monitor_shadow_probe_orders(shadow_probe_orders)

    shadow_probe_accepted = []
    shadow_probe_rejected = []
    open_shadow_probe_orders = get_open_shadow_probe_orders(shadow_probe_orders)

    if ENABLE_SHADOW_PROBE_ORDERS and not open_shadow_probe_orders:
        for probe_signal in load_shadow_probe_signals():
            if len(shadow_probe_accepted) >= MAX_SHADOW_PROBE_ORDERS_PER_RUN:
                break

            probe_signal_id = probe_signal.get("signal_id")
            if probe_signal_id and probe_signal_id in shadow_probe_executed_ids:
                shadow_probe_rejected.append({
                    "signal": probe_signal,
                    "reasons": ["Duplicate shadow probe signal_id already processed."],
                })
                continue

            probe_order = create_shadow_probe_order(probe_signal)
            shadow_probe_accepted.append(probe_order)
            shadow_probe_orders.append(probe_order)
            if probe_signal_id:
                shadow_probe_executed_ids.append(probe_signal_id)

    save_json(SHADOW_PROBE_LOG_FILE, shadow_probe_orders)
    save_json(SHADOW_PROBE_EXECUTED_IDS_FILE, shadow_probe_executed_ids)

    if not signals:
        if isinstance(raw_signals, dict):
            status = str(raw_signals.get("status", "UNKNOWN")).upper()
            orders = raw_signals.get("orders")

            if status in ["NO_TRADE", "WAIT"] or orders == []:
                print("No ready trade signal found. Market condition is WAIT or no order passed filters.")
                print(f"Shadow probe order log saved to: {SHADOW_PROBE_LOG_FILE}")
                if shadow_probe_accepted:
                    print("Accepted shadow probe order(s):")
                    for order in shadow_probe_accepted:
                        print(
                            f"{order['symbol']} {order['type']} | "
                            f"Lot: {order['lot']} | "
                            f"Entry: {order['entry']} | "
                            f"SL: {order['sl']} | "
                            f"TP: {order['tp']} | "
                            f"Strategy: {order['strategy']} | "
                            f"Score: {order['score']} | "
                            f"Status: {order['status']} | "
                            f"Excluded from Phase4 quality: {order['excluded_from_phase4_quality']}"
                        )
                else:
                    print("No accepted shadow probe order.")

                if shadow_probe_closed:
                    print("Closed shadow probe order(s):")
                    for order in shadow_probe_closed:
                        print(
                            f"{order['symbol']} {order['type']} | "
                            f"Close: {order['close_price']} | "
                            f"Result: {order['result']} | "
                            f"Profit: ${order['profit_usd']} | "
                            f"Status: {order['status']} | "
                            f"Excluded from Phase4 quality: {order['excluded_from_phase4_quality']}"
                        )
                return

        print("No valid signal found in mt5_trade_signals.json or PAPER_OBSERVATION_ONLY in trade_signals.json.")
        print("Supported MT5 formats: list of signals, or dict with key: signals/orders/valid_orders/ready_orders/trade_signals.")
        print(f"Shadow probe order log saved to: {SHADOW_PROBE_LOG_FILE}")
        if shadow_probe_accepted:
            print("Accepted shadow probe order(s):")
            for order in shadow_probe_accepted:
                print(
                    f"{order['symbol']} {order['type']} | "
                    f"Lot: {order['lot']} | "
                    f"Entry: {order['entry']} | "
                    f"SL: {order['sl']} | "
                    f"TP: {order['tp']} | "
                    f"Strategy: {order['strategy']} | "
                    f"Score: {order['score']} | "
                    f"Status: {order['status']} | "
                    f"Excluded from Phase4 quality: {order['excluded_from_phase4_quality']}"
                )
        else:
            print("No accepted shadow probe order.")

        if shadow_probe_closed:
            print("Closed shadow probe order(s):")
            for order in shadow_probe_closed:
                print(
                    f"{order['symbol']} {order['type']} | "
                    f"Close: {order['close_price']} | "
                    f"Result: {order['result']} | "
                    f"Profit: ${order['profit_usd']} | "
                    f"Status: {order['status']} | "
                    f"Excluded from Phase4 quality: {order['excluded_from_phase4_quality']}"
                )
        return

    accepted = []
    rejected = []
    raw_signal_count = len(signals)

    for signal in signals:
        if len(accepted) >= MAX_ORDERS_PER_RUN:
            rejected.append({
                "signal": signal,
                "reasons": [
                    f"Accepted order limit reached for this run: {len(accepted)}/{MAX_ORDERS_PER_RUN}."
                ],
            })
            continue

        reasons, phase4_guard_info = validate_signal(signal, executed_ids, paper_orders, phase4_rules)

        if reasons:
            rejected.append({
                "signal": signal,
                "reasons": reasons,
                "phase4_quality_guard": phase4_guard_info,
            })
            continue

        order = create_paper_order(signal, phase4_guard_info)

        accepted.append(order)
        paper_orders.append(order)
        executed_ids.append(signal.get("signal_id"))

    save_json(PAPER_LOG_FILE, paper_orders)
    save_json(EXECUTED_IDS_FILE, executed_ids)

    cleanup_applied, cleanup_reason = should_cleanup_signals_after_run(accepted, rejected)
    if cleanup_applied:
        save_json(SIGNAL_FILE, build_signal_cleanup_payload(accepted, rejected, cleanup_reason))

    executor_report = build_executor_report(
        accepted=accepted,
        rejected=rejected,
        raw_signal_count=raw_signal_count,
        cleanup_applied=cleanup_applied,
        cleanup_reason=cleanup_reason,
    )
    save_json(PAPER_EXECUTOR_REPORT_FILE, executor_report)

    print("\n=== ACCEPTED PAPER ORDERS ===")
    if accepted:
        for order in accepted:
            phase4_guard = order.get("executor_phase4_quality_guard", {})
            print(
                f"{order['symbol']} {order['type']} | "
                f"Lot: {order['lot']} | "
                f"Entry: {order['entry']} | "
                f"SL: {order['sl']} | "
                f"TP: {order['tp']} | "
                f"Strategy: {order['strategy']} | "
                f"Score: {order['score']} | "
                f"Risk: ${order['risk_usd']} | "
                f"Phase4: {phase4_guard.get('status', 'UNKNOWN')} required={phase4_guard.get('required_score', '-')} | "
                f"Profile: {order['symbol_risk_profile']} | "
                f"Status: {order['status']}"
            )
    else:
        print("No accepted paper order.")

    print("\n=== CLOSED SHADOW PROBE ORDERS ===")
    if shadow_probe_closed:
        for order in shadow_probe_closed:
            print(
                f"{order['symbol']} {order['type']} | "
                f"Close: {order['close_price']} | "
                f"Result: {order['result']} | "
                f"Profit: ${order['profit_usd']} | "
                f"Status: {order['status']} | "
                f"Excluded from Phase4 quality: {order['excluded_from_phase4_quality']}"
            )
    else:
        print("No closed shadow probe order.")

    print("\n=== ACCEPTED SHADOW PROBE ORDERS ===")
    if shadow_probe_accepted:
        for order in shadow_probe_accepted:
            print(
                f"{order['symbol']} {order['type']} | "
                f"Lot: {order['lot']} | "
                f"Entry: {order['entry']} | "
                f"SL: {order['sl']} | "
                f"TP: {order['tp']} | "
                f"Strategy: {order['strategy']} | "
                f"Score: {order['score']} | "
                f"Risk: ${order['risk_usd']} | "
                f"Status: {order['status']} | "
                f"Excluded from Phase4 quality: {order['excluded_from_phase4_quality']}"
            )
    else:
        print("No accepted shadow probe order.")

    print("\n=== REJECTED ORDERS ===")
    if rejected:
        for item in rejected:
            signal = item["signal"]
            symbol = signal.get("symbol")
            action = get_signal_action(signal)

            print(f"{symbol} {action} rejected:")
            phase4_guard = item.get("phase4_quality_guard", {})
            if phase4_guard:
                print(
                    "  Phase4 guard: "
                    f"status={phase4_guard.get('status')} | "
                    f"required={phase4_guard.get('required_score')} | "
                    f"reason={phase4_guard.get('reason', '-')}"
                )
            for reason in item["reasons"]:
                print(f"  - {reason}")
    else:
        print("No rejected order.")

    print(f"\nSignal cleanup applied: {cleanup_applied}")
    print(f"Signal cleanup reason : {cleanup_reason}")
    print(f"Paper order log saved to: {PAPER_LOG_FILE}")
    print(f"Shadow probe order log saved to: {SHADOW_PROBE_LOG_FILE}")
    print(f"Executed signal IDs saved to: {EXECUTED_IDS_FILE}")
    print(f"Paper executor report saved to: {PAPER_EXECUTOR_REPORT_FILE}")


if __name__ == "__main__":
    main()