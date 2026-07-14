import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

RUN_LOG_FILE = "paper_forward_runs.json"
DEFAULT_STEP_TIMEOUT_SECONDS = 300
DEFAULT_MAX_RUN_LOG_ENTRIES = 2000
STEP_TIMEOUT_ENV = "AI_SCALPER_FORWARD_STEP_TIMEOUT_SECONDS"
RUN_LOG_MAX_ENTRIES_ENV = "AI_SCALPER_FORWARD_LOG_MAX_ENTRIES"
COMPACT_OUTPUT_TAIL_CHARS = 500

PAPER_REPORT_FILE = "paper_report.json"
PAPER_ORDERS_FILE = "paper_orders.json"
QUALITY_REPORT_FILE = "paper_quality_report.json"
PAPER_QUALITY_RULES_FILE = "paper_quality_rules.json"
MT5_SIGNAL_OUTPUT = "mt5_trade_signals.json"
CLEAR_MT5_SIGNALS_WHEN_PAPER_ORDER_OPEN = True
RUN_DATA_COLLECTOR_BEFORE_MONITOR = True

PHASE4_VALIDATION_TARGET_CLOSED_ORDERS = 50
PHASE4_WARNING_LOSS_STREAK = 3
PHASE4_STOP_REVIEW_STATUSES = {"READY_CANDIDATE"}
PHASE4_CAUTION_STATUSES = {"NOT_READY"}

STEPS = [
    {
        "name": "Data Collector",
        "command": [sys.executable, "data_collector.py"],
        "optional": True,
    },
    {
        "name": "Paper Trade Monitor - Pre",
        "command": [sys.executable, "paper_trade_monitor.py"],
    },
    {
        "name": "Decision Engine",
        "command": [sys.executable, "decision_engine.py"],
    },
    {
        "name": "Paper Trade Monitor - Mid",
        "command": [sys.executable, "paper_trade_monitor.py"],
    },
    {
        "name": "Paper Executor",
        "command": [sys.executable, "paper_executor.py"],
    },
    {
        "name": "Paper Trade Monitor - Post",
        "command": [sys.executable, "paper_trade_monitor.py"],
    },
    {
        "name": "Paper Quality Guard",
        "command": [sys.executable, "paper_quality_guard.py"],
    },
]


def load_json(path, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    """Atomically replace a JSON file so readers never observe partial content."""
    destination = os.path.abspath(path)
    directory = os.path.dirname(destination)
    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=directory,
            prefix=f".{os.path.basename(destination)}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = temporary_file.name
            json.dump(data, temporary_file, indent=4)
            temporary_file.write("\n")
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)


def positive_int_from_env(name, default):
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default

    return value if value > 0 else default


def get_step_timeout_seconds(step):
    configured_default = positive_int_from_env(
        STEP_TIMEOUT_ENV,
        DEFAULT_STEP_TIMEOUT_SECONDS,
    )
    try:
        timeout = int(step.get("timeout_seconds", configured_default))
    except (TypeError, ValueError):
        return configured_default

    return timeout if timeout > 0 else configured_default


def normalize_process_output(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def clear_mt5_signals(reason, force=False):
    if not force and not CLEAR_MT5_SIGNALS_WHEN_PAPER_ORDER_OPEN:
        return

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "order_count": 0,
        "orders": [],
        "status": "NO_READY_ORDERS",
        "paper_order_guard": "BLOCKED",
        "reason": reason,
    }
    save_json(MT5_SIGNAL_OUTPUT, payload)
    print(f"Cleared MT5-ready signals: {reason}")


def run_step(step):
    print(f"\n=== RUNNING: {step['name']} ===")
    print("Command:", " ".join(step["command"]))

    started_at = datetime.now(timezone.utc).isoformat()

    timeout_seconds = get_step_timeout_seconds(step)

    try:
        result = subprocess.run(
            step["command"],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
        stdout = normalize_process_output(result.stdout)
        stderr = normalize_process_output(result.stderr)
        returncode = result.returncode
        timed_out = False
        error_type = None
    except subprocess.TimeoutExpired as exc:
        stdout = normalize_process_output(exc.stdout)
        stderr = normalize_process_output(exc.stderr)
        timeout_message = f"Step timed out after {timeout_seconds} seconds."
        stderr = f"{stderr}\n{timeout_message}".strip()
        returncode = 124
        timed_out = True
        error_type = "TIMEOUT"
    except OSError as exc:
        stdout = ""
        stderr = f"Unable to start step: {exc}"
        returncode = 127
        timed_out = False
        error_type = "SPAWN_ERROR"

    finished_at = datetime.now(timezone.utc).isoformat()

    if stdout:
        print(stdout)

    if stderr:
        print("--- STDERR ---")
        print(stderr)

    success = returncode == 0

    return {
        "name": step["name"],
        "command": " ".join(step["command"]),
        "started_at": started_at,
        "finished_at": finished_at,
        "success": success,
        "returncode": returncode,
        "timeout_seconds": timeout_seconds,
        "timed_out": timed_out,
        "error_type": error_type,
        "stdout_tail": stdout[-3000:],
        "stderr_tail": stderr[-3000:],
    }


def build_skipped_step_result(name, reason):
    timestamp = datetime.now(timezone.utc).isoformat()
    print(f"\n=== SKIPPING: {name} ===")
    print(f"Reason: {reason}")

    return {
        "name": name,
        "command": "SKIPPED",
        "started_at": timestamp,
        "finished_at": timestamp,
        "success": True,
        "skipped": True,
        "skip_reason": reason,
        "returncode": 0,
        "stdout_tail": "",
        "stderr_tail": "",
    }


def get_order_ids():
    orders = load_json(PAPER_ORDERS_FILE, [])

    if not isinstance(orders, list):
        return set()

    return set(
        str(order.get("paper_order_id"))
        for order in orders
        if order.get("paper_order_id")
    )


def get_open_order_details():
    orders = load_json(PAPER_ORDERS_FILE, [])

    if not isinstance(orders, list):
        return []

    return [
        {
            "paper_order_id": order.get("paper_order_id"),
            "symbol": order.get("symbol"),
            "type": order.get("type"),
            "strategy": order.get("strategy"),
            "status": order.get("status"),
            "created_at": order.get("created_at"),
            "holding_candles": order.get("holding_candles", 0),
            "last_checked_at": order.get("last_checked_at"),
            "last_market_candle_at": order.get("last_market_candle_at"),
            "last_market_close": order.get("last_market_close"),
            "monitor_note": order.get("monitor_note"),
        }
        for order in orders
        if order.get("status") == "PAPER_OPEN"
    ]


def detect_new_order(before_ids, after_ids):
    new_ids = sorted(list(after_ids - before_ids))
    return {
        "new_order_added": len(new_ids) > 0,
        "new_order_ids": new_ids,
        "new_order_count": len(new_ids),
    }


def detect_monitor_update(before_snapshot, after_snapshot):
    before_closed = before_snapshot.get("closed_orders", 0)
    after_closed = after_snapshot.get("closed_orders", 0)
    before_open = before_snapshot.get("open_orders", 0)
    after_open = after_snapshot.get("open_orders", 0)
    before_total = before_snapshot.get("total_orders", 0)
    after_total = after_snapshot.get("total_orders", 0)
    before_timeout = before_snapshot.get("timeout_orders", 0)
    after_timeout = after_snapshot.get("timeout_orders", 0)
    before_open_details = before_snapshot.get("open_order_details", []) or []
    after_open_details = after_snapshot.get("open_order_details", []) or []

    before_monitor_state = json.dumps(before_open_details, sort_keys=True, default=str)
    after_monitor_state = json.dumps(after_open_details, sort_keys=True, default=str)

    closed_changed = after_closed != before_closed
    open_changed = after_open != before_open
    total_changed = after_total != before_total
    timeout_changed = after_timeout != before_timeout
    open_monitor_changed = before_monitor_state != after_monitor_state

    return {
        "monitor_updated": closed_changed or open_changed or timeout_changed or open_monitor_changed,
        "order_book_changed": closed_changed or open_changed or total_changed or timeout_changed,
        "open_monitor_changed": open_monitor_changed,
        "closed_orders_before": before_closed,
        "closed_orders_after": after_closed,
        "open_orders_before": before_open,
        "open_orders_after": after_open,
        "total_orders_before": before_total,
        "total_orders_after": after_total,
        "timeout_orders_before": before_timeout,
        "timeout_orders_after": after_timeout,
        "open_order_details_before": before_open_details,
        "open_order_details_after": after_open_details,
    }


def get_latest_quality_report():
    return load_json(QUALITY_REPORT_FILE, {})

def get_latest_phase4_rules():
    return load_json(PAPER_QUALITY_RULES_FILE, {})


def get_latest_report():
    return load_json(PAPER_REPORT_FILE, {})


def get_order_snapshot():
    orders = load_json(PAPER_ORDERS_FILE, [])

    if not isinstance(orders, list):
        return {
            "total_orders": 0,
            "open_orders": 0,
            "closed_orders": 0,
            "timeout_orders": 0,
            "latest_order": None,
            "open_order_details": [],
        }

    closed_statuses = ["PAPER_WIN", "PAPER_LOSS", "PAPER_TIMEOUT"]

    open_orders = sum(1 for order in orders if order.get("status") == "PAPER_OPEN")
    closed_orders = sum(
        1 for order in orders if order.get("status") in closed_statuses
    )
    timeout_orders = sum(1 for order in orders if order.get("status") == "PAPER_TIMEOUT")
    latest_order = orders[-1] if orders else None
    open_order_details = get_open_order_details()

    return {
        "total_orders": len(orders),
        "open_orders": open_orders,
        "closed_orders": closed_orders,
        "timeout_orders": timeout_orders,
        "latest_order": latest_order,
        "open_order_details": open_order_details,
    }


# ==============================
# PHASE 4 VALIDATION HELPERS
# ==============================

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


def extract_phase4_validation_state(quality_report, phase4_rules, order_snapshot):
    if not isinstance(quality_report, dict):
        quality_report = {}
    if not isinstance(phase4_rules, dict):
        phase4_rules = {}
    if not isinstance(order_snapshot, dict):
        order_snapshot = {}

    metrics = quality_report.get("metrics", {})
    if not isinstance(metrics, dict):
        metrics = {}

    closed_orders = safe_int(
        metrics.get("closed_orders"),
        safe_int(order_snapshot.get("closed_orders"), 0),
    )
    open_orders = safe_int(
        metrics.get("open_orders"),
        safe_int(order_snapshot.get("open_orders"), 0),
    )
    target = safe_int(
        phase4_rules.get("next_validation_target_closed_orders"),
        PHASE4_VALIDATION_TARGET_CLOSED_ORDERS,
    )
    quality_status = str(
        phase4_rules.get("quality_status")
        or quality_report.get("quality_status")
        or "UNKNOWN"
    ).upper()
    execution_mode = phase4_rules.get("execution_mode", "PAPER_ONLY")
    live_allowed = bool(
        phase4_rules.get("live_allowed", quality_report.get("live_allowed", False))
    )
    loss_streak = safe_int(metrics.get("recent_loss_streak"), 0)
    winrate = safe_float(metrics.get("winrate_percent"), 0.0)
    profit_factor = safe_float(metrics.get("profit_factor"), 0.0)
    expectancy = safe_float(metrics.get("expectancy_usd"), 0.0)
    net_profit = safe_float(metrics.get("net_profit_usd"), 0.0)
    remaining = max(target - closed_orders, 0)
    progress_percent = (closed_orders / target * 100.0) if target > 0 else 0.0

    warnings = []
    action = "CONTINUE_PAPER_VALIDATION"

    if live_allowed:
        warnings.append("Live allowed is True in Phase 4 rules/quality report. This must stay False.")
        action = "SAFETY_REVIEW_REQUIRED"

    if quality_status in PHASE4_CAUTION_STATUSES:
        warnings.append(f"Quality status is {quality_status}. Do not loosen guards.")
        action = "CAUTION_CONTINUE_WITH_GUARDS"

    if loss_streak >= PHASE4_WARNING_LOSS_STREAK:
        warnings.append(f"Loss streak {loss_streak} reached warning threshold {PHASE4_WARNING_LOSS_STREAK}.")
        action = "CAUTION_LOSS_STREAK"

    if closed_orders >= target:
        action = "STOP_AND_REVIEW_PHASE_4"
        warnings.append(f"Phase 4 validation target reached: {closed_orders}/{target}. Review before continuing.")

    if quality_status in PHASE4_STOP_REVIEW_STATUSES and closed_orders >= target:
        action = "READY_REVIEW_REQUIRED"

    return {
        "target_closed_orders": target,
        "closed_orders": closed_orders,
        "open_orders": open_orders,
        "remaining_closed_orders": remaining,
        "progress_percent": round(progress_percent, 2),
        "quality_status": quality_status,
        "execution_mode": execution_mode,
        "live_allowed": live_allowed,
        "loss_streak": loss_streak,
        "winrate_percent": round(winrate, 2),
        "profit_factor": round(profit_factor, 4),
        "expectancy_usd": round(expectancy, 4),
        "net_profit_usd": round(net_profit, 4),
        "action": action,
        "warnings": warnings,
    }


def select_fields(source, field_names):
    if not isinstance(source, dict):
        return {}
    return {name: source.get(name) for name in field_names if name in source}


def compact_run_entry(run_entry):
    """Keep operational evidence without copying large runtime snapshots per run."""
    if not isinstance(run_entry, dict):
        return {}

    compact_steps = []
    for step in run_entry.get("steps", []) or []:
        compact_step = select_fields(
            step,
            (
                "name",
                "command",
                "started_at",
                "finished_at",
                "success",
                "skipped",
                "skip_reason",
                "returncode",
                "timeout_seconds",
                "timed_out",
                "error_type",
            ),
        )
        if not step.get("success"):
            compact_step["stderr_tail"] = normalize_process_output(
                step.get("stderr_tail")
            )[-COMPACT_OUTPUT_TAIL_CHARS:]
        compact_steps.append(compact_step)

    monitor_info = select_fields(
        run_entry.get("monitor_info", {}),
        (
            "monitor_updated",
            "order_book_changed",
            "open_monitor_changed",
            "closed_orders_before",
            "closed_orders_after",
            "open_orders_before",
            "open_orders_after",
            "total_orders_before",
            "total_orders_after",
            "timeout_orders_before",
            "timeout_orders_after",
        ),
    )
    paper_report = select_fields(
        run_entry.get("paper_report", {}),
        (
            "total_orders",
            "closed_orders",
            "open_orders",
            "wins",
            "losses",
            "timeouts",
            "winrate_percent",
            "net_profit_usd",
            "profit_factor",
            "expectancy_usd",
        ),
    )
    quality_metrics = run_entry.get("quality_metrics", {})
    if not isinstance(quality_metrics, dict) or not quality_metrics:
        quality_report = run_entry.get("quality_report", {})
        if isinstance(quality_report, dict):
            quality_metrics = quality_report.get("metrics", {})
    quality_metrics = select_fields(
        quality_metrics,
        (
            "closed_orders",
            "open_orders",
            "wins",
            "losses",
            "timeouts",
            "winrate_percent",
            "net_profit_usd",
            "profit_factor",
            "expectancy_usd",
            "recent_loss_streak",
        ),
    )

    order_snapshot = run_entry.get("order_snapshot", {})
    compact_order_snapshot = select_fields(
        order_snapshot,
        ("total_orders", "open_orders", "closed_orders", "timeout_orders"),
    )
    if isinstance(order_snapshot, dict) and order_snapshot.get("latest_order"):
        compact_order_snapshot["latest_order"] = select_fields(
            order_snapshot.get("latest_order"),
            (
                "paper_order_id",
                "symbol",
                "type",
                "strategy",
                "status",
                "result",
                "profit_usd",
                "created_at",
                "closed_at",
            ),
        )

    return {
        "log_schema_version": 2,
        **select_fields(
            run_entry,
            (
                "run_id",
                "started_at",
                "finished_at",
                "success",
                "pipeline_success",
                "execution_blocked",
                "execution_block_reason",
                "new_order_added",
                "new_order_count",
                "monitor_updated",
                "order_book_changed",
                "quality_status",
            ),
        ),
        "new_order_ids": list(run_entry.get("new_order_ids", []) or [])[-10:],
        "monitor_info": monitor_info,
        "phase4_validation": run_entry.get("phase4_validation", {}),
        "steps": compact_steps,
        "paper_report": paper_report,
        "quality_metrics": quality_metrics,
        "order_snapshot": compact_order_snapshot,
    }


def append_run_log(run_entry, max_entries=None):
    logs = load_json(RUN_LOG_FILE, [])

    if not isinstance(logs, list):
        logs = []

    if max_entries is None:
        max_entries = positive_int_from_env(
            RUN_LOG_MAX_ENTRIES_ENV,
            DEFAULT_MAX_RUN_LOG_ENTRIES,
        )
    else:
        try:
            max_entries = max(int(max_entries), 1)
        except (TypeError, ValueError):
            max_entries = DEFAULT_MAX_RUN_LOG_ENTRIES

    compact_logs = [
        compact_run_entry(log_entry)
        for log_entry in logs
        if isinstance(log_entry, dict)
    ]
    compact_logs.append(compact_run_entry(run_entry))
    compact_logs = compact_logs[-max_entries:]
    save_json(RUN_LOG_FILE, compact_logs)


def print_final_summary(run_entry):
    report = run_entry.get("paper_report", {}) or {}
    order_snapshot = run_entry.get("order_snapshot", {}) or {}
    latest_order = order_snapshot.get("latest_order")

    print("\n=== PAPER FORWARD RUN SUMMARY ===")
    print(f"Pipeline success : {run_entry.get('pipeline_success')}")
    print(f"New order added  : {run_entry.get('new_order_added')}")
    print(f"New order count  : {run_entry.get('new_order_count')}")
    print(f"Monitor updated  : {run_entry.get('monitor_updated')}")
    print(f"Open monitor chg : {run_entry.get('monitor_info', {}).get('open_monitor_changed')}")
    print(f"Order book change: {run_entry.get('order_book_changed')}")
    print(f"Quality status   : {run_entry.get('quality_status')}")
    print(f"Execution blocked: {run_entry.get('execution_blocked')}")
    if run_entry.get("execution_block_reason"):
        print(f"Block reason     : {run_entry.get('execution_block_reason')}")

    phase4_state = run_entry.get("phase4_validation", {}) or {}
    if phase4_state:
        print("\n=== PHASE 4 VALIDATION TARGET ===")
        print(f"Closed progress : {phase4_state.get('closed_orders')}/{phase4_state.get('target_closed_orders')}")
        print(f"Remaining       : {phase4_state.get('remaining_closed_orders')}")
        print(f"Progress        : {phase4_state.get('progress_percent')}%")
        print(f"Open orders     : {phase4_state.get('open_orders')}")
        print(f"Quality status  : {phase4_state.get('quality_status')}")
        print(f"Execution mode  : {phase4_state.get('execution_mode')}")
        print(f"Live allowed    : {phase4_state.get('live_allowed')}")
        print(f"Winrate         : {phase4_state.get('winrate_percent')}%")
        print(f"Profit factor   : {phase4_state.get('profit_factor')}")
        print(f"Expectancy      : ${phase4_state.get('expectancy_usd')}")
        print(f"Net profit      : ${phase4_state.get('net_profit_usd')}")
        print(f"Loss streak     : {phase4_state.get('loss_streak')}")
        print(f"Action          : {phase4_state.get('action')}")
        if phase4_state.get("warnings"):
            print("Phase 4 warnings:")
            for warning in phase4_state.get("warnings", []):
                print(f"- {warning}")
    skipped_steps = [
        step for step in run_entry.get("steps", [])
        if step.get("skipped")
    ]
    if skipped_steps:
        print("Skipped steps   :")
        for step in skipped_steps:
            print(f"- {step.get('name')}: {step.get('skip_reason')}")

    print(f"Total orders  : {report.get('total_orders', order_snapshot.get('total_orders', 0))}")
    print(f"Closed orders : {report.get('closed_orders', order_snapshot.get('closed_orders', 0))}")
    print(f"Open orders   : {report.get('open_orders', order_snapshot.get('open_orders', 0))}")
    print(f"Wins          : {report.get('wins', 0)}")
    print(f"Losses        : {report.get('losses', 0)}")
    print(f"Timeouts      : {report.get('timeouts', order_snapshot.get('timeout_orders', 0))}")
    print(f"Winrate       : {report.get('winrate_percent', 0)}%")
    print(f"Net profit    : ${report.get('net_profit_usd', 0)}")
    print(f"Profit factor : {report.get('profit_factor')}")
    print(f"Expectancy    : ${report.get('expectancy_usd', 0)}")

    if latest_order:
        print("\nLatest order:")
        print(
            f"{latest_order.get('symbol')} {latest_order.get('type')} | "
            f"Strategy: {latest_order.get('strategy')} | "
            f"Score: {latest_order.get('score')} | "
            f"Status: {latest_order.get('status')} | "
            f"Result: {latest_order.get('result')} | "
            f"Profit: ${latest_order.get('profit_usd')}"
        )
        if latest_order.get("status") == "PAPER_OPEN":
            print(f"  Holding candles : {latest_order.get('holding_candles', 0)}")
            print(f"  Last checked    : {latest_order.get('last_checked_at')}")
            print(f"  Last market     : {latest_order.get('last_market_candle_at')} | Close: {latest_order.get('last_market_close')}")
            print(f"  Monitor note    : {latest_order.get('monitor_note')}")

    print(f"\nRun log saved to: {RUN_LOG_FILE}")


def main():
    print("\n=== AI_SCALPER PAPER FORWARD RUNNER ===")
    print("Runner: data_collector.py -> pre-monitor -> optional decision_engine.py -> mid-monitor -> optional paper_executor.py -> post-monitor -> paper_quality_guard.py")

    run_started_at = datetime.now(timezone.utc).isoformat()
    before_order_ids = get_order_ids()
    before_snapshot = get_order_snapshot()
    step_results = []
    pipeline_success = True
    decision_completed_successfully = False
    decision_block_reason = None
    execution_block_reason = None

    for step in STEPS:
        if step["name"] == "Data Collector" and not RUN_DATA_COLLECTOR_BEFORE_MONITOR:
            reason = "Skipped because RUN_DATA_COLLECTOR_BEFORE_MONITOR is disabled."
            step_results.append(build_skipped_step_result(step["name"], reason))
            continue

        if step["name"] == "Decision Engine":
            if decision_block_reason:
                execution_block_reason = decision_block_reason
                clear_mt5_signals(decision_block_reason, force=True)
                step_results.append(
                    build_skipped_step_result(step["name"], decision_block_reason)
                )
                continue

            pre_decision_snapshot = get_order_snapshot()
            open_orders_before_decision = pre_decision_snapshot.get("open_orders", 0)

            if open_orders_before_decision > 0:
                reason = (
                    f"Skipped because {open_orders_before_decision} paper order(s) are still open before Decision Engine. "
                    "Runner will wait until TP, SL, or timeout closes the open order before generating new signals."
                )
                clear_mt5_signals(reason)
                execution_block_reason = reason
                step_results.append(build_skipped_step_result(step["name"], reason))
                continue

        if step["name"] == "Paper Executor":
            if execution_block_reason or not decision_completed_successfully:
                reason = execution_block_reason or (
                    "Skipped because Decision Engine did not complete successfully "
                    "during this runner cycle."
                )
                execution_block_reason = reason
                clear_mt5_signals(reason, force=True)
                step_results.append(build_skipped_step_result(step["name"], reason))
                continue

            mid_snapshot = get_order_snapshot()
            open_orders_after_mid = mid_snapshot.get("open_orders", 0)

            if open_orders_after_mid > 0:
                reason = (
                    f"Skipped because {open_orders_after_mid} paper order(s) are still open after Mid-monitor. "
                    "Executor will wait until TP, SL, or timeout closes the open order."
                )
                clear_mt5_signals(reason)
                execution_block_reason = reason
                step_results.append(build_skipped_step_result(step["name"], reason))
                continue

        result = run_step(step)
        step_results.append(result)

        if result["success"]:
            if step["name"] == "Decision Engine":
                decision_completed_successfully = True
            continue

        pipeline_success = False
        failure_kind = "timed out" if result.get("timed_out") else "failed"
        failure_reason = (
            f"{step['name']} {failure_kind} (return code {result.get('returncode')})."
        )

        if step["name"] == "Data Collector":
            decision_block_reason = (
                f"{failure_reason} Decision Engine and Paper Executor are blocked "
                "because fresh market data was not confirmed."
            )
            execution_block_reason = decision_block_reason
            clear_mt5_signals(decision_block_reason, force=True)
        elif step["name"] == "Paper Trade Monitor - Pre":
            decision_block_reason = (
                f"{failure_reason} Decision Engine and Paper Executor are blocked "
                "because the open-order state was not confirmed."
            )
            execution_block_reason = decision_block_reason
            clear_mt5_signals(decision_block_reason, force=True)
        elif step["name"] == "Decision Engine":
            execution_block_reason = (
                f"{failure_reason} Paper Executor is blocked because no successful "
                "decision was produced in this cycle."
            )
            clear_mt5_signals(execution_block_reason, force=True)
        elif step["name"] == "Paper Trade Monitor - Mid":
            execution_block_reason = (
                f"{failure_reason} Paper Executor is blocked because the latest "
                "open-order state was not confirmed."
            )
            clear_mt5_signals(execution_block_reason, force=True)
        elif step["name"] == "Paper Executor":
            execution_block_reason = (
                f"{failure_reason} MT5-ready signals were cleared to prevent an "
                "uncontrolled retry."
            )
            clear_mt5_signals(execution_block_reason, force=True)

        if step.get("optional"):
            print(f"\nOptional step failed; continuing safe monitor/quality steps: {step['name']}")
        else:
            print(f"\nStep failed; continuing safe monitor/quality steps: {step['name']}")

    run_finished_at = datetime.now(timezone.utc).isoformat()
    after_order_ids = get_order_ids()
    after_snapshot = get_order_snapshot()
    new_order_info = detect_new_order(before_order_ids, after_order_ids)
    monitor_info = detect_monitor_update(before_snapshot, after_snapshot)
    quality_report = get_latest_quality_report()
    quality_status = quality_report.get("quality_status", "UNKNOWN")

    phase4_rules = get_latest_phase4_rules()
    phase4_validation = extract_phase4_validation_state(
        quality_report,
        phase4_rules,
        after_snapshot,
    )

    run_entry = {
        "run_id": f"PAPER_RUN_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "started_at": run_started_at,
        "finished_at": run_finished_at,
        "success": pipeline_success,
        "pipeline_success": pipeline_success,
        "execution_blocked": bool(execution_block_reason),
        "execution_block_reason": execution_block_reason,
        "new_order_added": new_order_info["new_order_added"],
        "new_order_count": new_order_info["new_order_count"],
        "new_order_ids": new_order_info["new_order_ids"],
        "monitor_updated": monitor_info["monitor_updated"],
        "order_book_changed": monitor_info["order_book_changed"],
        "monitor_info": monitor_info,
        "quality_status": quality_status,
        "phase4_validation": phase4_validation,
        "steps": step_results,
        "paper_report": get_latest_report(),
        "quality_report": quality_report,
        "phase4_rules": phase4_rules,
        "order_snapshot": after_snapshot,
    }

    append_run_log(run_entry)
    print_final_summary(run_entry)
    return run_entry


def cli_main():
    run_entry = main()
    return 0 if run_entry.get("pipeline_success") is True else 1


if __name__ == "__main__":
    raise SystemExit(cli_main())
