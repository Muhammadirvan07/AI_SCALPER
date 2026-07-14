import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import paper_forward_runner as runner


def step_result(name, success=True, timed_out=False):
    return {
        "name": name,
        "command": f"python {name}",
        "started_at": "2026-07-15T00:00:00+00:00",
        "finished_at": "2026-07-15T00:00:01+00:00",
        "success": success,
        "returncode": 0 if success else (124 if timed_out else 1),
        "timeout_seconds": 2,
        "timed_out": timed_out,
        "error_type": "TIMEOUT" if timed_out else None,
        "stdout_tail": "x" * 3000,
        "stderr_tail": "failure " + ("y" * 3000) if not success else "",
    }


def empty_order_snapshot():
    return {
        "total_orders": 0,
        "open_orders": 0,
        "closed_orders": 0,
        "timeout_orders": 0,
        "latest_order": None,
        "open_order_details": [],
    }


class PaperForwardRunnerTests(unittest.TestCase):
    def test_cli_exit_code_reflects_pipeline_failure(self):
        with patch.object(
            runner,
            "main",
            return_value={"pipeline_success": False},
        ):
            self.assertEqual(runner.cli_main(), 1)

        with patch.object(
            runner,
            "main",
            return_value={"pipeline_success": True},
        ):
            self.assertEqual(runner.cli_main(), 0)

    def test_run_step_converts_timeout_to_bounded_failure(self):
        timeout = subprocess.TimeoutExpired(
            cmd=["python", "decision_engine.py"],
            timeout=2,
            output=b"partial output",
            stderr=b"hung process",
        )
        step = {
            "name": "Decision Engine",
            "command": ["python", "decision_engine.py"],
            "timeout_seconds": 2,
        }

        with patch.object(runner.subprocess, "run", side_effect=timeout) as run_mock:
            with patch("builtins.print"):
                result = runner.run_step(step)

        self.assertFalse(result["success"])
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["error_type"], "TIMEOUT")
        self.assertEqual(result["returncode"], 124)
        self.assertIn("timed out after 2 seconds", result["stderr_tail"])
        self.assertEqual(run_mock.call_args.kwargs["timeout"], 2)

    def test_collector_or_decision_failure_never_reaches_executor(self):
        for failing_step in ("Data Collector", "Decision Engine"):
            with self.subTest(failing_step=failing_step):
                executed_steps = []

                def fake_run_step(step):
                    name = step["name"]
                    executed_steps.append(name)
                    return step_result(name, success=name != failing_step)

                with patch.object(runner, "run_step", side_effect=fake_run_step), \
                        patch.object(runner, "get_order_ids", return_value=set()), \
                        patch.object(runner, "get_order_snapshot", side_effect=empty_order_snapshot), \
                        patch.object(runner, "get_latest_quality_report", return_value={}), \
                        patch.object(runner, "get_latest_phase4_rules", return_value={}), \
                        patch.object(runner, "get_latest_report", return_value={}), \
                        patch.object(runner, "clear_mt5_signals") as clear_signals, \
                        patch.object(runner, "append_run_log"), \
                        patch.object(runner, "print_final_summary"), \
                        patch("builtins.print"):
                    run_entry = runner.main()

                self.assertNotIn("Paper Executor", executed_steps)
                self.assertIn("Paper Trade Monitor - Mid", executed_steps)
                self.assertIn("Paper Trade Monitor - Post", executed_steps)
                self.assertIn("Paper Quality Guard", executed_steps)
                self.assertFalse(run_entry["pipeline_success"])
                self.assertTrue(run_entry["execution_blocked"])
                clear_signals.assert_called()

                executor_step = next(
                    step
                    for step in run_entry["steps"]
                    if step["name"] == "Paper Executor"
                )
                self.assertTrue(executor_step["skipped"])

                if failing_step == "Data Collector":
                    self.assertNotIn("Decision Engine", executed_steps)

    def test_run_log_is_compacted_and_capped(self):
        def full_entry(run_id):
            return {
                "run_id": run_id,
                "started_at": "2026-07-15T00:00:00+00:00",
                "finished_at": "2026-07-15T00:00:01+00:00",
                "success": False,
                "pipeline_success": False,
                "new_order_ids": ["one"],
                "steps": [step_result("Decision Engine", success=False)],
                "quality_report": {
                    "metrics": {"closed_orders": 53, "profit_factor": 1.33},
                    "large_snapshot": "z" * 10000,
                },
                "phase4_rules": {"large_snapshot": "z" * 10000},
                "paper_report": {"closed_orders": 53, "extra": "z" * 10000},
                "order_snapshot": empty_order_snapshot(),
            }

        with tempfile.TemporaryDirectory() as temporary_directory:
            log_path = Path(temporary_directory) / "runs.json"
            runner.save_json(log_path, [full_entry("run-1"), full_entry("run-2")])

            with patch.object(runner, "RUN_LOG_FILE", str(log_path)):
                runner.append_run_log(full_entry("run-3"), max_entries=2)

            with log_path.open("r", encoding="utf-8") as log_file:
                logs = json.load(log_file)

            self.assertEqual([entry["run_id"] for entry in logs], ["run-2", "run-3"])
            self.assertTrue(all(entry["log_schema_version"] == 2 for entry in logs))
            self.assertTrue(all("quality_report" not in entry for entry in logs))
            self.assertTrue(all("phase4_rules" not in entry for entry in logs))
            self.assertEqual(logs[-1]["quality_metrics"]["closed_orders"], 53)
            self.assertNotIn("stdout_tail", logs[-1]["steps"][0])
            self.assertLessEqual(
                len(logs[-1]["steps"][0]["stderr_tail"]),
                runner.COMPACT_OUTPUT_TAIL_CHARS,
            )
            self.assertEqual(list(Path(temporary_directory).glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
