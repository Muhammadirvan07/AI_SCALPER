from __future__ import annotations

from contextlib import redirect_stdout
import io
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import prepare_broker_registration_activation_review as activation_cli
import verify_broker_registration_activation_review as verify_cli
from live_runtime.registration_activation import (
    RegistrationActivationError,
    current_git_identity,
    load_json_object_strict,
)


class RegistrationActivationCLITests(unittest.TestCase):
    def test_help_exposes_no_secret_or_mutation_controls(self) -> None:
        for filename in (
            "prepare_broker_registration_activation_review.py",
            "verify_broker_registration_activation_review.py",
        ):
            completed = subprocess.run(
                (sys.executable, "-B", filename, "--help"),
                cwd=Path(__file__).resolve().parent,
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
                "--signing-key",
                "--raw-secret",
                "--key-export",
            ):
                self.assertNotIn(forbidden, help_text)

    def test_success_uses_vault_and_reports_every_safety_lock(self) -> None:
        output = io.StringIO()
        identity = {
            "clean": True,
            "commit_sha": "a" * 40,
            "tree_sha": "b" * 40,
        }
        profile = SimpleNamespace(
            candidate_id="phillip-fx",
            key_name="phillip-fx-window-01-v1",
            template_path="config/phillip_fx_calendar_window_01.template.json",
        )
        pack = {
            "proposal_sha256": "c" * 64,
            "source_git_commit": "a" * 40,
        }
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "review.json"
            with (
                patch.object(
                    activation_cli,
                    "current_git_identity",
                    side_effect=[identity, identity],
                ),
                patch.object(
                    activation_cli,
                    "load_broker_evidence_profile",
                    return_value=profile,
                ),
                patch.object(
                    activation_cli,
                    "load_json_object_strict",
                    side_effect=[{}, {}, {}, {}],
                ),
                patch.object(
                    activation_cli,
                    "load_regulatory_observation",
                    return_value={},
                ),
                patch.object(
                    activation_cli,
                    "load_prewindow_calendar_review",
                    return_value={},
                ),
                patch.object(
                    activation_cli,
                    "WindowsEvidenceKeyStore",
                ) as store,
                patch.object(
                    activation_cli,
                    "build_registration_activation_review_pack",
                    return_value=pack,
                ) as build,
                patch.object(
                    activation_cli,
                    "write_registration_activation_review_pack_exclusive",
                    return_value=destination,
                ),
                redirect_stdout(output),
            ):
                store.return_value.load.return_value = b"k" * 32
                result = activation_cli.main(
                    [
                        "--candidate",
                        "phillip-fx",
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
        self.assertIn("Manual activation review required: true", rendered)
        self.assertIn("Configuration mutated: false", rendered)
        self.assertIn("Registration enabled: false", rendered)
        self.assertIn("Apply capability: DISABLED", rendered)
        self.assertIn("Order capability: DISABLED", rendered)

    def test_repository_output_is_rejected_before_key_access(self) -> None:
        output = io.StringIO()
        with (
            patch.object(
                activation_cli,
                "WindowsEvidenceKeyStore",
            ) as store,
            redirect_stdout(output),
        ):
            result = activation_cli.main(
                [
                    "--candidate",
                    "phillip-fx",
                    "--discovery",
                    "missing.json",
                    "--regulatory-observation",
                    "missing.json",
                    "--calendar-review",
                    "missing.json",
                    "--output",
                    "activation-review.json",
                ]
            )
        self.assertEqual(2, result)
        store.assert_not_called()
        self.assertIn("outside the repository", output.getvalue())
        self.assertIn("no configuration or broker order changed", output.getvalue())

    def test_static_verifier_cli_never_loads_credentials(self) -> None:
        output = io.StringIO()
        pack = {"candidate_id": "phillip-fx", "proposal_sha256": "a" * 64}
        with (
            patch.object(verify_cli, "load_json_object_strict", return_value=pack),
            patch.object(
                verify_cli,
                "verify_registration_activation_review_pack",
            ) as verify,
            redirect_stdout(output),
        ):
            result = verify_cli.main(["--input", "review.json"])
        self.assertEqual(0, result)
        verify.assert_called_once_with(pack)
        self.assertIn("REGISTRATION_ACTIVATION_REVIEW_VALID", output.getvalue())
        self.assertIn("Registration enabled: false", output.getvalue())
        self.assertIn("Order capability: DISABLED", output.getvalue())

    def test_git_identity_rejects_dirty_or_unstable_captures(self) -> None:
        shown = str(Path(__file__).resolve().parent)
        clean = [
            shown,
            "",
            "a" * 40,
            "b" * 40,
            "",
            "a" * 40,
            "b" * 40,
        ]
        with patch(
            "live_runtime.registration_activation._git_command",
            side_effect=clean,
        ):
            identity = current_git_identity(shown)
        self.assertTrue(identity["clean"])

        dirty = [
            shown,
            " M config/file.json",
            "a" * 40,
            "b" * 40,
            " M config/file.json",
            "a" * 40,
            "b" * 40,
        ]
        with (
            patch(
                "live_runtime.registration_activation._git_command",
                side_effect=dirty,
            ),
            self.assertRaisesRegex(RegistrationActivationError, "clean"),
        ):
            current_git_identity(shown)

        unstable = [
            shown,
            "",
            "a" * 40,
            "b" * 40,
            "",
            "c" * 40,
            "b" * 40,
        ]
        with (
            patch(
                "live_runtime.registration_activation._git_command",
                side_effect=unstable,
            ),
            self.assertRaisesRegex(RegistrationActivationError, "changed"),
        ):
            current_git_identity(shown)

    def test_strict_json_loader_rejects_duplicate_nonfinite_and_symlink_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.json"
            source.write_text('{"value":1,"value":2}', encoding="utf-8")
            with self.assertRaisesRegex(RegistrationActivationError, "duplicate"):
                load_json_object_strict(source)

            source.write_text('{"value":NaN}', encoding="utf-8")
            with self.assertRaisesRegex(RegistrationActivationError, "non-finite"):
                load_json_object_strict(source)

            source.write_text('{"value":1}', encoding="utf-8")
            link = root / "linked.json"
            try:
                link.symlink_to(source)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            with self.assertRaisesRegex(RegistrationActivationError, "regular file"):
                load_json_object_strict(link)


if __name__ == "__main__":
    unittest.main()
