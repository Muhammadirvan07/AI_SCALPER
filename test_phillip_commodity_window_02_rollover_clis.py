from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import prepare_phillip_commodity_window_02_rollover_review as prepare_cli
import verify_phillip_commodity_window_02_rollover_review as verify_cli


ROOT = Path(__file__).resolve().parent


class PhillipCommodityWindow02RolloverCLITests(unittest.TestCase):
    def test_help_exposes_no_secret_or_mutation_controls(self) -> None:
        for filename in (
            "prepare_phillip_commodity_window_02_rollover_review.py",
            "verify_phillip_commodity_window_02_rollover_review.py",
        ):
            completed = subprocess.run(
                (sys.executable, "-B", filename, "--help"),
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            help_text = completed.stdout.lower()
            for forbidden in (
                "--password",
                "--login",
                "--account",
                "--order",
                "--lot",
                "--live",
                "--apply",
                "--patch",
                "--commit",
                "--register-contract",
                "--install-task",
                "--signing-key",
                "--raw-secret",
                "--key-export",
            ):
                self.assertNotIn(forbidden, help_text)

    def test_success_uses_vault_and_reports_non_mutating_boundary(self) -> None:
        output = io.StringIO()
        identity = {
            "clean": True,
            "commit_sha": "a" * 40,
            "tree_sha": "b" * 40,
        }
        profile = SimpleNamespace(
            candidate_id="phillip-commodity",
            key_name="phillip-commodity-window-01-v1",
        )
        pack = {
            "proposal_sha256": "c" * 64,
            "source_git_commit": "a" * 40,
            "current_contract_id": "phillip-commodity-window-01-diagnostic-v5",
            "proposed_contract_id": "phillip-commodity-window-02-diagnostic-v1",
        }
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "review.json"
            with (
                patch.object(
                    prepare_cli,
                    "current_git_identity",
                    side_effect=[identity, identity],
                ),
                patch.object(
                    prepare_cli,
                    "load_broker_evidence_profile",
                    return_value=profile,
                ),
                patch.object(
                    prepare_cli,
                    "load_json_object_strict",
                    side_effect=[{}, {}, {}, {}, {}],
                ),
                patch.object(
                    prepare_cli,
                    "load_regulatory_observation",
                    return_value={},
                ),
                patch.object(
                    prepare_cli,
                    "load_prewindow_calendar_review",
                    return_value={},
                ),
                patch.object(prepare_cli, "WindowsEvidenceKeyStore") as store,
                patch.object(
                    prepare_cli,
                    "build_phillip_commodity_window_02_rollover_review",
                    return_value=pack,
                ) as build,
                patch.object(
                    prepare_cli,
                    "write_phillip_commodity_window_02_rollover_review_exclusive",
                    return_value=destination,
                ),
                patch.object(Path, "exists", return_value=False),
                redirect_stdout(output),
            ):
                store.return_value.load.return_value = b"k" * 32
                result = prepare_cli.main(
                    [
                        "--candidate",
                        "phillip-commodity",
                        "--discovery",
                        str(Path(directory) / "discovery.json"),
                        "--regulatory-observation",
                        str(Path(directory) / "regulatory.json"),
                        "--calendar-review",
                        str(Path(directory) / "calendar.json"),
                        "--output",
                        str(destination),
                    ]
                )

        self.assertEqual(0, result)
        store.return_value.load.assert_called_once_with(profile.key_name)
        kwargs = build.call_args.kwargs
        self.assertIs(kwargs["regulatory_key_provider"], store.return_value.load)
        self.assertIs(kwargs["calendar_key_provider"], store.return_value.load)
        rendered = output.getvalue()
        self.assertIn("Manual rollover required: true", rendered)
        self.assertIn("Configuration mutated: false", rendered)
        self.assertIn("Registration enabled: true", rendered)
        self.assertIn("Contract registration: NOT_PERFORMED", rendered)
        self.assertIn("Scheduler mutation: NOT_PERFORMED", rendered)
        self.assertIn("Order capability: DISABLED", rendered)

    def test_repository_output_is_rejected_before_key_access(self) -> None:
        output = io.StringIO()
        with (
            patch.object(prepare_cli, "WindowsEvidenceKeyStore") as store,
            redirect_stdout(output),
        ):
            result = prepare_cli.main(
                [
                    "--candidate",
                    "phillip-commodity",
                    "--discovery",
                    "missing.json",
                    "--regulatory-observation",
                    "missing.json",
                    "--calendar-review",
                    "missing.json",
                    "--output",
                    "window-02-rollover-review.json",
                ]
            )
        self.assertEqual(2, result)
        store.assert_not_called()
        self.assertIn("outside the repository", output.getvalue())
        self.assertIn("no configuration or broker order changed", output.getvalue())

    def test_existing_signed_template_is_rejected_before_key_access(self) -> None:
        output = io.StringIO()
        with (
            patch.object(prepare_cli, "_signed_template_destination_exists", return_value=True),
            patch.object(prepare_cli, "WindowsEvidenceKeyStore") as store,
            patch.object(
                prepare_cli,
                "current_git_identity",
                return_value={
                    "clean": True,
                    "commit_sha": "a" * 40,
                    "tree_sha": "b" * 40,
                },
            ),
            redirect_stdout(output),
        ):
            with tempfile.TemporaryDirectory() as directory:
                result = prepare_cli.main(
                    [
                        "--candidate",
                        "phillip-commodity",
                        "--discovery",
                        "missing.json",
                        "--regulatory-observation",
                        "missing.json",
                        "--calendar-review",
                        "missing.json",
                        "--output",
                        str(Path(directory) / "review.json"),
                    ]
                )
        self.assertEqual(2, result)
        store.assert_not_called()
        self.assertIn("signed Window 02 template destination already exists", output.getvalue())

    def test_static_verifier_never_loads_credentials(self) -> None:
        output = io.StringIO()
        pack = {
            "candidate_id": "phillip-commodity",
            "proposal_sha256": "a" * 64,
            "current_contract_id": "phillip-commodity-window-01-diagnostic-v5",
            "proposed_contract_id": "phillip-commodity-window-02-diagnostic-v1",
        }
        with (
            patch.object(verify_cli, "load_json_object_strict", return_value=pack),
            patch.object(
                verify_cli,
                "verify_phillip_commodity_window_02_rollover_review",
            ) as verify,
            redirect_stdout(output),
        ):
            result = verify_cli.main(["--input", "review.json"])
        self.assertEqual(0, result)
        verify.assert_called_once_with(pack)
        rendered = output.getvalue()
        self.assertIn("PHILLIP_COMMODITY_WINDOW_02_ROLLOVER_REVIEW_VALID", rendered)
        self.assertIn("Contract registration: NOT_PERFORMED", rendered)
        self.assertIn("Scheduler mutation: NOT_PERFORMED", rendered)
        self.assertIn("Order capability: DISABLED", rendered)

    def test_ordinary_windows_release_inventory_includes_rollover_tools(self) -> None:
        payload = json.loads(
            (ROOT / "config/windows_release_allowlist.v1.json").read_text(
                encoding="utf-8"
            )
        )
        files = set(payload["files"])
        self.assertTrue(
            {
                "live_runtime/phillip_commodity_window_02_rollover.py",
                "prepare_phillip_commodity_window_02_rollover_review.py",
                "verify_phillip_commodity_window_02_rollover_review.py",
            }
            <= files
        )


if __name__ == "__main__":
    unittest.main()
