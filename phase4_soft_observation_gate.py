import json
from datetime import datetime
from pathlib import Path

OUTPUT = "phase4_soft_observation_gate.json"

PRIMARY_SYMBOLS = {"EURUSD"}
BLOCKED_SYMBOLS = {"GBPUSD"}
SHADOW_SYMBOLS = {"BTCUSD"}

ALLOWED_STRATEGIES = {"BREAKOUT", "MEAN_REVERSION", "MOMENTUM_PULLBACK"}

SOFT_MIN_SCORE = 4
EXECUTION_MIN_SCORE = 5
MAX_LOT = 0.01


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


def first_non_empty(*values):
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return None


def extract_symbol(item):
    return str(first_non_empty(
        item.get("symbol"),
        item.get("pair"),
        item.get("final_symbol"),
        item.get("display_symbol"),
    ) or "").upper()


def extract_strategy(item):
    strategy_value = first_non_empty(
        item.get("final_strategy"),
        item.get("display_strategy"),
        item.get("selected_strategy_final"),
        item.get("selected_strategy"),
        item.get("strategy"),
        item.get("strategy_name"),
    )

    final_sanitizer = item.get("final_strategy_sanitizer")
    if isinstance(final_sanitizer, dict):
        strategy_value = first_non_empty(
            final_sanitizer.get("sanitized"),
            final_sanitizer.get("strategy"),
            final_sanitizer.get("original"),
            strategy_value,
        )

    return str(strategy_value or "").upper()


def extract_score(item):
    score_value = first_non_empty(
        item.get("final_score"),
        item.get("display_score"),
        item.get("committed_score"),
        item.get("adaptive_score"),
        item.get("strategy_score"),
        item.get("score"),
    )

    phase5p = item.get("phase5p_controlled_score_commit")
    if isinstance(phase5p, dict):
        score_value = first_non_empty(
            phase5p.get("committed"),
            phase5p.get("committed_score"),
            score_value,
        )

    phase5a = item.get("phase5a_adaptive_score")
    if isinstance(phase5a, dict):
        score_value = first_non_empty(
            phase5a.get("adaptive"),
            phase5a.get("adaptive_score"),
            score_value,
        )

    return safe_float(score_value, 0.0)


def get_decisions(snapshot, trade_signals):
    if isinstance(snapshot, dict):
        for key in ("items", "decisions", "latest_decisions", "signals", "latest_signals", "rows", "data"):
            value = snapshot.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)], "decision_health_snapshot.json", key

        for key, value in snapshot.items():
            if isinstance(value, list):
                rows = [x for x in value if isinstance(x, dict)]
                if rows:
                    return rows, "decision_health_snapshot.json", key

    if isinstance(trade_signals, list):
        return [x for x in trade_signals if isinstance(x, dict)], "trade_signals.json", "root"

    return [], "NONE", None


def main():
    snapshot = load_json("decision_health_snapshot.json")
    trade_signals = load_json("trade_signals.json")
    bridge = load_json("bridge_status.json")
    outbox = load_json("mt5_demo_bridge_outbox.json")
    clean_gate = load_json("phase4_clean_sample_gate.json")
    dashboard = load_json("offline_dashboard_report.json")

    decisions, source_used, source_key = get_decisions(snapshot, trade_signals)

    soft_samples = []
    blocked_samples = []

    for item in decisions:
        symbol = extract_symbol(item)
        strategy = extract_strategy(item)
        score = extract_score(item)
        blob = json.dumps(item, default=str).upper()

        requirements = {
            "primary_symbol": symbol in PRIMARY_SYMBOLS,
            "not_blocked_symbol": symbol not in BLOCKED_SYMBOLS,
            "not_shadow_symbol": symbol not in SHADOW_SYMBOLS,
            "valid_strategy": strategy in ALLOWED_STRATEGIES,
            "soft_score_passed": score >= SOFT_MIN_SCORE,
            "execution_score_not_required_here": True,
            "replay_restored_or_not_required_for_soft_observation": (
                "REPLAY_VALIDATION_RECOVERY_AVAILABLE" in blob
                or '"RESTORED": TRUE' in blob
                or "'RESTORED': TRUE" in blob
                or symbol in PRIMARY_SYMBOLS
            ),
            "not_force_blocked_strategy": "FORCE_BLOCKED_STRATEGY" not in blob,
        }

        passed = all(requirements.values())

        sample = {
            "symbol": symbol,
            "strategy": strategy,
            "score": score,
            "passed_soft_observation": passed,
            "requirements": requirements,
            "scope": "OBSERVATION_ONLY_NO_ORDER",
            "creates_order": False,
            "live_allowed": False,
            "max_lot": MAX_LOT,
        }

        if passed:
            soft_samples.append(sample)
        else:
            sample["missing_requirements"] = [k for k, v in requirements.items() if not v]
            blocked_samples.append(sample)

    bridge_live_allowed = bridge.get("live_allowed")
    outbox_live_allowed = outbox.get("live_allowed")
    bridge_valid_orders = int(bridge.get("valid_order_count", 0) or 0)
    outbox_orders = int(outbox.get("order_count", 0) or 0)

    status = "SOFT_OBSERVATION_SAMPLE_AVAILABLE" if soft_samples else "NO_SOFT_OBSERVATION_SAMPLE"

    payload = {
        "generated_at": datetime.now().isoformat(),
        "enabled": True,
        "mode": "PHASE4_SOFT_OBSERVATION_GATE",
        "status": status,
        "scope": "OBSERVATION_ONLY_NO_ORDER",
        "soft_sample_count": len(soft_samples),
        "blocked_sample_count": len(blocked_samples),
        "decision_source_used": source_used,
        "decision_source_key": source_key,
        "decision_count": len(decisions),
        "soft_policy": {
            "primary_symbols": sorted(PRIMARY_SYMBOLS),
            "blocked_symbols": sorted(BLOCKED_SYMBOLS),
            "shadow_symbols": sorted(SHADOW_SYMBOLS),
            "allowed_strategies": sorted(ALLOWED_STRATEGIES),
            "soft_min_score": SOFT_MIN_SCORE,
            "execution_min_score_still_required": EXECUTION_MIN_SCORE,
            "creates_order": False,
            "safe_to_demo_auto_order": False,
            "live_allowed": False,
            "max_lot": MAX_LOT,
        },
        "soft_samples": soft_samples,
        "blocked_samples": blocked_samples,
        "source_state": {
            "clean_gate_status": clean_gate.get("status"),
            "clean_sample_count": clean_gate.get("clean_sample_count"),
            "quality_status": (dashboard.get("next_stage", {}) if isinstance(dashboard, dict) else {}).get("quality_status"),
            "phase4_action": (dashboard.get("next_stage", {}) if isinstance(dashboard, dict) else {}).get("action"),
            "bridge_execution_approved_symbols": bridge.get("execution_approved_symbols"),
            "bridge_execution_blocked_symbols": bridge.get("execution_blocked_symbols"),
            "bridge_shadow_symbols": bridge.get("shadow_symbols"),
        },
        "safety": {
            "live_allowed": False,
            "bridge_live_allowed": bridge_live_allowed,
            "outbox_live_allowed": outbox_live_allowed,
            "max_lot": MAX_LOT,
            "creates_order": False,
            "safe_to_demo_auto_order": False,
            "bridge_valid_order_count": bridge_valid_orders,
            "demo_outbox_order_count": outbox_orders,
            "modifies_active_pairs": False,
            "modifies_replay_candidates": False,
            "modifies_quality_rules": False,
        },
        "next_steps": [
            "Use soft samples only for observation and analysis.",
            "Do not send soft samples to MT5 bridge or demo outbox.",
            "Keep execution clean sample gate stricter: score >= 5, confirmations >= 3, market usable.",
            "Keep demo auto-order disabled until clean sample target and readiness checks pass.",
        ],
    }

    Path(OUTPUT).write_text(json.dumps(payload, indent=2))

    print(f"Soft observation gate exported: {OUTPUT}")
    print(f"status={status}")
    print(f"soft_samples={len(soft_samples)}")
    print(f"blocked_samples={len(blocked_samples)}")
    print(f"source={source_used}")
    print("safe_to_demo_auto_order=False")
    print("creates_order=False")


if __name__ == "__main__":
    main()
