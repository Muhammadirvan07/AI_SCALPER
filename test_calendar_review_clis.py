from __future__ import annotations

from contextlib import redirect_stdout
import io
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import assemble_prewindow_calendar_review as assemble_cli
import prepare_prewindow_calendar_review as prepare_cli
import setup_calendar_review_key as setup_cli
import sign_prewindow_calendar_review as sign_cli
from live_runtime.calendar_review import calendar_review_key_name


ROOT = Path(__file__).resolve().parent


class CalendarReviewCLITests(unittest.TestCase):
    def test_commands_expose_no_execution_or_secret_arguments(self) -> None:
        for filename in (
            "setup_calendar_review_key.py",
            "prepare_prewindow_calendar_review.py",
            "sign_prewindow_calendar_review.py",
            "assemble_prewindow_calendar_review.py",
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
                "--password", "--login", "--account", "--order", "--lot",
                "--volume", "--live", "--private-key", "--secret",
                "--signing-key", "--export-key",
            ):
                self.assertNotIn(forbidden, help_text)

    def test_key_setup_uses_candidate_scoped_windows_vault_key(self) -> None:
        profile = SimpleNamespace(candidate_id="phillip-fx")
        output = io.StringIO()
        with (
            patch.object(setup_cli, "load_broker_evidence_profile", return_value=profile),
            patch.object(setup_cli, "WindowsEvidenceKeyStore") as store,
            redirect_stdout(output),
        ):
            store.return_value.ensure.return_value = (b"k" * 32, True)
            result = setup_cli.main(["--candidate", "phillip-fx"])
        self.assertEqual(0, result)
        store.return_value.ensure.assert_called_once_with(
            calendar_review_key_name("phillip-fx")
        )
        self.assertIn("Secret material: NOT_EXPORTED", output.getvalue())
        self.assertIn("Registration enabled: false", output.getvalue())
        self.assertIn("Order capability: DISABLED", output.getvalue())

    def test_prepare_cli_writes_only_immutable_evidence(self) -> None:
        profile = SimpleNamespace(
            candidate_id="phillip-fx",
            template_path="config/phillip_fx_calendar_window_01.template.json",
        )
        evidence = {
            "candidate_id": "phillip-fx",
            "evidence_bundle_sha256": "a" * 64,
        }
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text("{}", encoding="utf-8")
            destination = root / "evidence.json"
            with (
                patch.object(prepare_cli, "load_broker_evidence_profile", return_value=profile),
                patch.object(prepare_cli, "read_json_object", side_effect=[{}, {}]),
                patch.object(prepare_cli, "load_calendar_source_manifest", return_value={}),
                patch.object(prepare_cli, "prepare_calendar_review_evidence", return_value=evidence),
                patch.object(
                    prepare_cli, "write_calendar_review_artifact_exclusive",
                    return_value=destination,
                ) as writer,
                redirect_stdout(output),
            ):
                result = prepare_cli.main(
                    [
                        "--candidate", "phillip-fx",
                        "--source-manifest", str(manifest),
                        "--source-root", str(root),
                        "--output", str(destination),
                    ]
                )
        self.assertEqual(0, result)
        writer.assert_called_once_with(destination, evidence)
        self.assertIn("Future exception completeness: false", output.getvalue())
        self.assertIn("Order capability: DISABLED", output.getvalue())

    def test_sign_cli_loads_only_derived_calendar_key(self) -> None:
        approval = {
            "candidate_id": "phillip-fx",
            "signature_hmac_sha256": "b" * 64,
        }
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_path = root / "evidence.json"
            evidence_path.write_text("{}", encoding="utf-8")
            destination = root / "approval.json"
            with (
                patch.object(sign_cli, "load_calendar_review_evidence", return_value={"candidate_id": "phillip-fx"}),
                patch.object(sign_cli, "WindowsEvidenceKeyStore") as store,
                patch.object(sign_cli, "sign_calendar_review_approval", return_value=approval),
                patch.object(
                    sign_cli, "write_calendar_review_artifact_exclusive",
                    return_value=destination,
                ),
                redirect_stdout(output),
            ):
                store.return_value.load.return_value = b"k" * 32
                result = sign_cli.main(
                    [
                        "--candidate", "phillip-fx",
                        "--reviewer-id", "calendar-reviewer",
                        "--evidence", str(evidence_path),
                        "--output", str(destination),
                    ]
                )
        self.assertEqual(0, result)
        store.return_value.load.assert_called_once_with(
            calendar_review_key_name("phillip-fx")
        )
        self.assertIn("Reviewer role: CALENDAR_REVIEW", output.getvalue())
        self.assertIn("Secret material: NOT_EXPORTED", output.getvalue())

    def test_assemble_cli_uses_vault_provider_without_patching_template(self) -> None:
        profile = SimpleNamespace(
            candidate_id="phillip-fx",
            template_path="config/phillip_fx_calendar_window_01.template.json",
            registration_enabled=False,
        )
        review = {
            "candidate_id": "phillip-fx",
            "review_artifact_sha256": "c" * 64,
        }
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_path = root / "evidence.json"
            approval_path = root / "approval.json"
            evidence_path.write_text("{}", encoding="utf-8")
            approval_path.write_text("{}", encoding="utf-8")
            destination = root / "review.json"
            with (
                patch.object(assemble_cli, "load_broker_evidence_profile", return_value=profile),
                patch.object(assemble_cli, "read_json_object", return_value={}),
                patch.object(assemble_cli, "load_calendar_review_evidence", return_value={"candidate_id": "phillip-fx"}),
                patch.object(assemble_cli, "load_calendar_review_approval", return_value={"candidate_id": "phillip-fx"}),
                patch.object(assemble_cli, "WindowsEvidenceKeyStore") as store,
                patch.object(
                    assemble_cli, "assemble_prewindow_calendar_review",
                    return_value=review,
                ) as assemble,
                patch.object(
                    assemble_cli, "write_calendar_review_artifact_exclusive",
                    return_value=destination,
                ),
                redirect_stdout(output),
            ):
                result = assemble_cli.main(
                    [
                        "--candidate", "phillip-fx",
                        "--evidence", str(evidence_path),
                        "--approval", str(approval_path),
                        "--output", str(destination),
                    ]
                )
        self.assertEqual(0, result)
        self.assertIs(
            assemble.call_args.kwargs["approval_key_provider"],
            store.return_value.load,
        )
        self.assertIn("Template patched: false", output.getvalue())
        self.assertIn("Registration enabled: false", output.getvalue())
        self.assertIn("Order capability: DISABLED", output.getvalue())


if __name__ == "__main__":
    unittest.main()
