import json
from datetime import datetime
from pathlib import Path

from execution_policy import (
    EXECUTION_APPROVED_SYMBOLS,
    EXECUTION_BLOCKED_SYMBOLS,
    EXECUTION_MAX_LOT,
    SHADOW_ONLY_SYMBOLS,
)

OUTPUT = "demo_readiness_evaluator.json"

MIN_READY_WINRATE = 45.0
NEAR_READY_WINRATE = 42.0
MIN_PROFIT_FACTOR = 1.20
MIN_CLEAN_SAMPLES = 20
MAX_LOSS_STREAK = 2
MAX_LOT = EXECUTION_MAX_LOT

PRIMARY_SYMBOLS = EXECUTION_APPROVED_SYMBOLS
BLOCKED_SYMBOLS = EXECUTION_BLOCKED_SYMBOLS
SHADOW_SYMBOLS = SHADOW_ONLY_SYMBOLS


def first_not_none(*values):
    for value in values:
        if value is not None:
            return value
    return None


def load_json(path, default=None):
    if default is None:
        default = {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


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


def get_dashboard_metrics(dashboard, quality_report=None):
    ns = dashboard.get("next_stage", {}) if isinstance(dashboard, dict) else {}
    if not isinstance(ns, dict):
        ns = {}
    quality_report = quality_report if isinstance(quality_report, dict) else {}
    quality_metrics = quality_report.get("metrics", {})
    if not isinstance(quality_metrics, dict):
        quality_metrics = {}

    return {
        "quality_status": first_not_none(
            quality_report.get("status"), ns.get("quality_status"), dashboard.get("quality_status")
        ),
        "phase4_action": first_not_none(ns.get("action"), dashboard.get("phase4_action")),
        "closed_orders": first_not_none(
            quality_metrics.get("closed_orders"), ns.get("closed_orders"), dashboard.get("closed_orders")
        ),
        "winrate_percent": first_not_none(
            quality_metrics.get("winrate_percent"), ns.get("winrate_percent"), dashboard.get("winrate_percent")
        ),
        "profit_factor": first_not_none(
            quality_metrics.get("profit_factor"), ns.get("profit_factor"), dashboard.get("profit_factor")
        ),
        "expectancy": first_not_none(
            quality_metrics.get("expectancy_usd"),
            ns.get("expectancy"),
            dashboard.get("expectancy"),
            dashboard.get("expectancy_usd"),
        ),
        "current_loss_streak": first_not_none(
            quality_metrics.get("recent_loss_streak"),
            ns.get("current_loss_streak"),
            dashboard.get("current_loss_streak"),
            dashboard.get("loss_streak"),
        ),
    }


def main():
    gate = load_json("phase4_clean_sample_gate.json")
    monitor = load_json("phase4_recovery_monitor.json")
    advisor = load_json("phase4_winrate_repair_advisor.json")
    recovery_plan = load_json("phase4_recovery_plan.json")
    final_summary = load_json("phase4_final_cleanup_summary.json")
    dashboard = load_json("offline_dashboard_report.json")
    quality_report = load_json("paper_quality_report.json")
    bridge = load_json("bridge_status.json")
    outbox = load_json("mt5_demo_bridge_outbox.json")
    trade_signals = load_json("trade_signals.json")
    mt5_signals = load_json("mt5_trade_signals.json")

    metrics = get_dashboard_metrics(dashboard, quality_report)

    quality_status = metrics.get("quality_status") or monitor.get("quality_status")
    phase4_action = metrics.get("phase4_action") or monitor.get("phase4_action")
    winrate = safe_float(metrics.get("winrate_percent"), safe_float(monitor.get("winrate_percent"), 0.0))
    pf = safe_float(metrics.get("profit_factor"), safe_float(monitor.get("profit_factor"), 0.0))
    closed_orders = safe_int(metrics.get("closed_orders"), safe_int(monitor.get("closed_orders"), 0))
    expectancy = first_not_none(metrics.get("expectancy"), monitor.get("expectancy"))
    loss_streak = first_not_none(metrics.get("current_loss_streak"), monitor.get("current_loss_streak"))

    clean_count = safe_int(gate.get("clean_sample_count"), 0)
    blocked_count = safe_int(gate.get("blocked_sample_count"), 0)

    if isinstance(mt5_signals, dict):
        mt5_order_count = safe_int(mt5_signals.get("order_count"), 0)
    elif isinstance(mt5_signals, list):
        mt5_order_count = len(mt5_signals)
    else:
        mt5_order_count = 0

    if isinstance(trade_signals, dict):
        ready_trade_count = safe_int(trade_signals.get("ready_trade_count"), 0)
    elif isinstance(trade_signals, list):
        ready_trade_count = len([
            x for x in trade_signals
            if isinstance(x, dict) and str(x.get("status", "")).upper() in {"READY", "READY_TO_TRADE"}
        ])
    else:
        ready_trade_count = 0

    exec_approved = bridge.get("execution_approved_symbols") or []
    exec_blocked = bridge.get("execution_blocked_symbols") or []
    shadow = bridge.get("shadow_symbols") or []

    checks = {
        "quality_not_ready_lock_active": str(quality_status).upper() == "NOT_READY",
        "phase4_stop_and_review_active": str(phase4_action).upper() == "STOP_AND_REVIEW_PHASE_4",
        "winrate_ready": winrate >= MIN_READY_WINRATE,
        "winrate_near_ready": winrate >= NEAR_READY_WINRATE,
        "profit_factor_ready": pf >= MIN_PROFIT_FACTOR,
        "clean_sample_target_met": clean_count >= MIN_CLEAN_SAMPLES,
        "loss_streak_safe": loss_streak is not None and safe_int(loss_streak, 99) <= MAX_LOSS_STREAK,
        "bridge_demo_safe": (
            bridge.get("live_allowed") is False
            and outbox.get("live_allowed") is False
            and outbox.get("safe_to_demo_auto_order") is False
            and safe_float(bridge.get("max_allowed_lot"), MAX_LOT) <= MAX_LOT
            and safe_float(outbox.get("max_lot"), MAX_LOT) <= MAX_LOT
        ),
        "no_orders_pending": (
            ready_trade_count == 0
            and mt5_order_count == 0
            and safe_int(outbox.get("order_count"), 0) == 0
            and safe_int(bridge.get("valid_order_count"), 0) == 0
        ),
        "eurusd_only_execution_approved": exec_approved == ["EURUSD"],
        "gbpusd_blocked": "GBPUSD" in exec_blocked,
        "btcusd_shadow_only": "BTCUSD" in shadow,
    }

    passed_checks = [k for k, v in checks.items() if v]
    failed_checks = [k for k, v in checks.items() if not v]

    readiness_score = int(round((len(passed_checks) / len(checks)) * 100)) if checks else 0

    bridge_safe = (
        checks["bridge_demo_safe"]
        and checks["no_orders_pending"]
        and checks["eurusd_only_execution_approved"]
        and checks["gbpusd_blocked"]
        and checks["btcusd_shadow_only"]
    )

    auto_order_ready = False

    if bridge_safe and not checks["winrate_ready"]:
        status = "DEMO_OBSERVATION_ONLY_READY"
    else:
        status = "DEMO_AUTO_ORDER_NOT_READY"

    missing_logic_to_improve = []

    if not checks["winrate_near_ready"]:
        missing_logic_to_improve.append({
            "area": "WINRATE_RECOVERY",
            "current": winrate,
            "target_near_ready": NEAR_READY_WINRATE,
            "target_ready": MIN_READY_WINRATE,
            "action": "Collect clean EURUSD M15 samples only; do not loosen guards.",
        })

    if not checks["clean_sample_target_met"]:
        missing_logic_to_improve.append({
            "area": "CLEAN_SAMPLE_ACCUMULATION",
            "current": clean_count,
            "target": MIN_CLEAN_SAMPLES,
            "action": "Count only EURUSD setups with valid strategy, score >= 5, confirmations >= 3, replay restored, and market usable.",
        })

    if not checks["loss_streak_safe"]:
        missing_logic_to_improve.append({
            "area": "LOSS_STREAK_RECOVERY",
            "current": loss_streak,
            "max_allowed": MAX_LOSS_STREAK,
            "action": "Keep Phase4R locked until loss streak recovers through closed paper results.",
        })

    if gate.get("blocked_samples"):
        missing_logic_to_improve.append({
            "area": "MARKET_AND_STRATEGY_READINESS",
            "blocked_samples": blocked_count,
            "action": "Improve market freshness detection, avoid force-blocked TREND_FOLLOWING, and require allowed strategy before sample counting.",
        })

    payload = {
        "generated_at": datetime.now().isoformat(),
        "enabled": True,
        "mode": "EVALUATE_DEMO_READINESS_REVIEW_ONLY",
        "status": status,
        "review_only": True,
        "do_not_unlock_phase4r": True,
        "readiness_score": readiness_score,
        "safe_to_demo_auto_order": auto_order_ready,
        "safe_to_demo_observe": bridge_safe,
        "passed_checks": passed_checks,
        "failed_checks": failed_checks,
        "metrics": {
            "quality_status": quality_status,
            "phase4_action": phase4_action,
            "closed_orders": closed_orders,
            "winrate_percent": winrate,
            "profit_factor": pf,
            "expectancy": expectancy,
            "current_loss_streak": loss_streak,
            "clean_sample_count": clean_count,
            "blocked_sample_count": blocked_count,
        },
        "source_state": {
            "clean_sample_status": gate.get("status"),
            "clean_sample_source": gate.get("decision_source_used"),
            "decision_count": gate.get("decision_count"),
            "decision_symbols_seen": gate.get("decision_symbols_seen"),
            "recovery_monitor_status": monitor.get("status"),
            "winrate_repair_status": advisor.get("status"),
            "recovery_plan_status": recovery_plan.get("status"),
            "final_cleanup_status": final_summary.get("status"),
            "bridge_execution_approved_symbols": exec_approved,
            "bridge_execution_blocked_symbols": exec_blocked,
            "bridge_shadow_symbols": shadow,
        },
        "safety": {
            "live_allowed": False,
            "max_lot": MAX_LOT,
            "creates_order": False,
            "ready_trade_count": ready_trade_count,
            "mt5_order_count": mt5_order_count,
            "demo_outbox_order_count": outbox.get("order_count"),
            "bridge_valid_order_count": bridge.get("valid_order_count"),
            "modifies_active_pairs": False,
            "modifies_replay_candidates": False,
            "modifies_quality_rules": False,
        },
        "missing_logic_to_improve": missing_logic_to_improve,
        "recommended_next_improvements": [
            "Keep M15 recovery observation as the main test mode.",
            "Improve/monitor market freshness before counting any clean sample.",
            "Reject force-blocked TREND_FOLLOWING; only allow BREAKOUT, MEAN_REVERSION, or MOMENTUM_PULLBACK when confirmations pass.",
            "Require positive confirmations >= 3 before recovery sample counting.",
            "Accumulate at least 20 clean EURUSD samples before demo auto-order discussion.",
            "Keep GBPUSD blocked and BTCUSD shadow-only.",
            "Add spread/session/news checks before any future demo micro-order unlock.",
            "Keep live_allowed=False and max_lot=0.01 until a separate manual demo unlock plan is created.",
        ],
    }

    Path(OUTPUT).write_text(json.dumps(payload, indent=2))
    print(f"Demo readiness evaluator exported: {OUTPUT}")
    print(f"status={status}")
    print(f"readiness_score={readiness_score}")
    print(f"safe_to_demo_observe={bridge_safe}")
    print(f"safe_to_demo_auto_order={auto_order_ready}")
    print(f"failed_checks={failed_checks}")


if __name__ == "__main__":
    main()
