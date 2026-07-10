"""
AI Background Review Runner

Read-only handoff generator for ChatGPT/Claude.
Does not create orders.
Does not touch MT5 bridge/outbox.
Does not unlock live/demo auto-order.
Writes only files under ai_handoff/.
"""

import json
from datetime import datetime
from pathlib import Path

OUT_DIR = Path("ai_handoff")
OUT_DIR.mkdir(exist_ok=True)

SUMMARY_FILE = OUT_DIR / "ai_background_review_summary.json"
PACKET_FILE = OUT_DIR / "AI_REVIEW_PACKET.md"
WORK_QUEUE_FILE = OUT_DIR / "AI_WORK_QUEUE.md"
CHATGPT_TASK_FILE = OUT_DIR / "CHATGPT_NEXT_TASK.md"
CLAUDE_TASK_FILE = OUT_DIR / "CLAUDE_NEXT_TASK.md"

INPUTS = {
    "readiness": "demo_readiness_evaluator.json",
    "bridge": "bridge_status.json",
    "outbox": "mt5_demo_bridge_outbox.json",
    "soft": "phase4_soft_observation_gate.json",
    "clean": "phase4_clean_sample_gate.json",
    "dashboard": "offline_dashboard_report.json",
    "health": "decision_health_snapshot.json",
    "phase5k_diag": "phase5k_zero_volume_diagnostic.json",
}


def load_json(path):
    try:
        p = Path(path)
        if not p.exists():
            return {}
        with p.open() as f:
            return json.load(f)
    except Exception as exc:
        return {"_load_error": str(exc)}


def find_symbol(items, symbol):
    symbol = symbol.upper()
    if not isinstance(items, list):
        return {}
    for item in items:
        if str(item.get("symbol", "")).upper() == symbol:
            return item
    return {}


def extract_decisions(health):
    if not isinstance(health, dict):
        return []
    for key in ("decisions", "latest_decisions", "items", "symbols"):
        value = health.get(key)
        if isinstance(value, list):
            return value
    return []


def recommend_focus(summary):
    safety = summary["safety"]
    eurusd = summary["symbols"]["EURUSD"]
    samples = summary["samples"]

    if safety["safe_to_demo_auto_order"] is not False:
        return "STOP: safe_to_demo_auto_order is not False."
    if safety["bridge_live_allowed"] is not False:
        return "STOP: bridge live_allowed is not False."
    if safety["outbox_live_allowed"] is not False:
        return "STOP: outbox live_allowed is not False."
    if safety["bridge_orders"] not in (0, None):
        return "STOP: bridge has orders."
    if safety["outbox_orders"] not in (0, None):
        return "STOP: outbox has orders."

    missing = (
        eurusd.get("diagnostic", {})
        .get("phase5h", {})
        .get("missing_components", [])
    )

    if "replay_validation" in missing:
        return "Review Phase5Z replay_validation mapping for EURUSD. Diagnostic only."
    if "volatility_quality" in missing:
        return "Review Phase5H volatility_quality mapping. Diagnostic only."
    if samples["soft_sample_count"] == 0:
        return "Review EURUSD score and positive confirmation gap for soft observation."
    if samples["clean_sample_count"] == 0:
        return "Review clean sample gate blockers."

    return "Continue M15 observation and collect more samples."


def build_summary():
    data = {name: load_json(path) for name, path in INPUTS.items()}

    readiness = data["readiness"]
    bridge = data["bridge"]
    outbox = data["outbox"]
    soft = data["soft"]
    clean = data["clean"]
    dashboard = data["dashboard"]
    health = data["health"]
    diag = data["phase5k_diag"]

    next_stage = dashboard.get("next_stage", {}) if isinstance(dashboard, dict) else {}
    decisions = extract_decisions(health)
    diag_symbols = diag.get("symbols", []) if isinstance(diag, dict) else []

    summary = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "mode": "AI_BACKGROUND_REVIEW_ONLY",
        "read_only": True,
        "creates_order": False,
        "safety": {
            "safe_to_demo_auto_order": readiness.get("safe_to_demo_auto_order"),
            "safe_to_demo_observe": readiness.get("safe_to_demo_observe"),
            "bridge_live_allowed": bridge.get("live_allowed"),
            "outbox_live_allowed": outbox.get("live_allowed"),
            "bridge_orders": bridge.get("valid_order_count"),
            "outbox_orders": outbox.get("order_count"),
            "bridge_max_lot": bridge.get("max_allowed_lot"),
            "outbox_max_lot": outbox.get("max_lot"),
            "soft_creates_order": soft.get("soft_policy", {}).get("creates_order"),
        },
        "readiness": {
            "status": readiness.get("status"),
            "readiness_score": readiness.get("readiness_score"),
            "failed_checks": readiness.get("failed_checks"),
        },
        "quality": {
            "quality_status": next_stage.get("quality_status"),
            "action": next_stage.get("action"),
            "winrate_percent": next_stage.get("winrate_percent"),
            "profit_factor": next_stage.get("profit_factor"),
            "expectancy": next_stage.get("expectancy"),
        },
        "samples": {
            "soft_status": soft.get("status"),
            "soft_sample_count": soft.get("soft_sample_count"),
            "soft_blocked_count": soft.get("blocked_sample_count"),
            "clean_status": clean.get("status"),
            "clean_sample_count": clean.get("clean_sample_count"),
            "clean_blocked_count": clean.get("blocked_sample_count"),
        },
        "symbols": {
            "EURUSD": {
                "decision": find_symbol(decisions, "EURUSD"),
                "diagnostic": find_symbol(diag_symbols, "EURUSD"),
            },
            "GBPUSD": {
                "decision": find_symbol(decisions, "GBPUSD"),
                "diagnostic": find_symbol(diag_symbols, "GBPUSD"),
            },
            "BTCUSD": {
                "decision": find_symbol(decisions, "BTCUSD"),
                "diagnostic": find_symbol(diag_symbols, "BTCUSD"),
            },
        },
    }

    summary["recommended_next_focus"] = recommend_focus(summary)
    return summary


def write_outputs(summary):
    SUMMARY_FILE.write_text(json.dumps(summary, indent=2, default=str))

    safety = summary["safety"]
    readiness = summary["readiness"]
    quality = summary["quality"]
    samples = summary["samples"]
    focus = summary["recommended_next_focus"]

    packet = f"""# AI_SCALPER Background Review Packet

Generated: {summary["generated_at"]}
Mode: {summary["mode"]}
Read-only: {summary["read_only"]}
Creates order: {summary["creates_order"]}

## Safety
- safe_to_demo_auto_order: {safety["safe_to_demo_auto_order"]}
- bridge_live_allowed: {safety["bridge_live_allowed"]}
- outbox_live_allowed: {safety["outbox_live_allowed"]}
- bridge_orders: {safety["bridge_orders"]}
- outbox_orders: {safety["outbox_orders"]}
- bridge_max_lot: {safety["bridge_max_lot"]}
- outbox_max_lot: {safety["outbox_max_lot"]}
- soft_creates_order: {safety["soft_creates_order"]}

## Readiness
- status: {readiness["status"]}
- readiness_score: {readiness["readiness_score"]}
- failed_checks: {readiness["failed_checks"]}

## Quality
- quality_status: {quality["quality_status"]}
- action: {quality["action"]}
- winrate_percent: {quality["winrate_percent"]}
- profit_factor: {quality["profit_factor"]}
- expectancy: {quality["expectancy"]}

## Samples
- soft_status: {samples["soft_status"]}
- soft_sample_count: {samples["soft_sample_count"]}
- clean_status: {samples["clean_status"]}
- clean_sample_count: {samples["clean_sample_count"]}

## Recommended Next Focus
{focus}

## Hard Rules
- Do not enable live trading.
- Do not enable demo auto-order.
- Do not raise max lot.
- Do not create MT5 orders.
- Do not write outbox orders.
- Do not unlock Phase4R.
- Do not promote GBPUSD.
- Do not promote BTCUSD from shadow.
- Do not lower execution score gates.
"""
    PACKET_FILE.write_text(packet)

    WORK_QUEUE_FILE.write_text(f"""# AI Work Queue

Generated: {summary["generated_at"]}

1. {focus}

Safety must remain locked:
- live_allowed=False
- safe_to_demo_auto_order=False
- max_lot=0.01
- orders=0
""")

    CHATGPT_TASK_FILE.write_text(f"""# ChatGPT Next Task

Use skill checklist:
code-reviewer, pr-review-expert, senior-backend, senior-architect, focused-fix,
ship-gate, adversarial-reviewer, ai-security, financial-analyst,
tech-debt-tracker, runbook-generator.

Task:
{focus}

Constraints:
- Diagnostic/review only unless user explicitly asks for patch.
- Do not unlock order/live/demo auto-order.
- Preserve GBPUSD block and BTCUSD shadow.
- Keep max lot 0.01.
""")

    CLAUDE_TASK_FILE.write_text(f"""# Claude Next Task

Use skill checklist:
code-reviewer, pr-review-expert, senior-backend, senior-architect, focused-fix,
ship-gate, adversarial-reviewer, ai-security, financial-analyst,
tech-debt-tracker, runbook-generator.

Current task:
{focus}

Read:
- AI_REVIEW_PACKET.md
- ai_background_review_summary.json
- decision_engine.py

Output format:
PROPOSED CHANGE
Problem:
Root cause:
Files touched:
Patch summary:
Safety impact:
Trading/financial risk impact:
Test command:
Rollback command:
Ship / No-Ship decision:

Do not:
- enable live trading
- enable demo auto-order
- raise max_lot
- create MT5 orders
- write outbox orders
- unlock Phase4R
- promote GBPUSD
- promote BTCUSD
- lower score gates
""")


def main():
    summary = build_summary()
    write_outputs(summary)

    print("AI background review exported:")
    print(f"- {SUMMARY_FILE}")
    print(f"- {PACKET_FILE}")
    print(f"- {WORK_QUEUE_FILE}")
    print(f"- {CHATGPT_TASK_FILE}")
    print(f"- {CLAUDE_TASK_FILE}")
    print("")
    print("Recommended next focus:", summary["recommended_next_focus"])


if __name__ == "__main__":
    main()
