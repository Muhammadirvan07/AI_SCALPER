from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import assemble_broker_registration_review as assemble_cli
import prepare_broker_registration_review as prepare_cli
import prepare_broker_window
import register_broker_forward_contract
import setup_regulatory_review_key as setup_cli
import sign_broker_registration_review as sign_cli
from live_runtime.registration_review import regulatory_review_key_name


ROOT = Path(__file__).resolve().parent


class RegistrationReviewCLITests(unittest.TestCase):
    def test_review_commands_expose_no_execution_or_secret_arguments(self) -> None:
        for filename in (
            "setup_regulatory_review_key.py",
            "prepare_broker_registration_review.py",
            "sign_broker_registration_review.py",
            "assemble_broker_registration_review.py",
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
                "--order",
                "--lot",
                "--live",
                "--private-key",
                "--secret",
                "--signing-key",
            ):
                self.assertNotIn(forbidden, help_text)

    def test_review_key_name_is_lane_and_role_namespaced(self) -> None:
        self.assertEqual(
            "phillip-fx-compliance-review-v1",
            regulatory_review_key_name("phillip-fx", "COMPLIANCE_REVIEW"),
        )
        self.assertNotEqual(
            regulatory_review_key_name("phillip-fx", "LEGAL_REVIEW"),
            regulatory_review_key_name("phillip-commodity", "LEGAL_REVIEW"),
        )

    def test_key_setup_uses_windows_vault_without_exporting_secret(self) -> None:
        output = io.StringIO()
        with (
            patch.object(setup_cli, "WindowsEvidenceKeyStore") as store,
            redirect_stdout(output),
        ):
            store.return_value.ensure.return_value = (b"k" * 32, True)
            result = setup_cli.main(
                [
                    "--candidate",
                    "phillip-fx",
                    "--role",
                    "COMPLIANCE_REVIEW",
                ]
            )
        self.assertEqual(0, result)
        store.return_value.ensure.assert_called_once_with(
            "phillip-fx-compliance-review-v1"
        )
        self.assertIn("Secret material: NOT_EXPORTED", output.getvalue())
        self.assertIn("Order capability: DISABLED", output.getvalue())

    def test_prepare_cli_writes_only_review_evidence(self) -> None:
        output = io.StringIO()
        evidence = {
            "candidate_id": "phillip-fx",
            "evidence_bundle_sha256": "a" * 64,
        }
        profile = SimpleNamespace(
            candidate_id="phillip-fx",
            template_path="config/phillip_fx_calendar_window_01.template.json",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            destination = root / "evidence.json"
            manifest.write_text("{}", encoding="utf-8")
            with (
                patch.object(prepare_cli, "load_broker_evidence_profile", return_value=profile),
                patch.object(prepare_cli, "read_json_object", side_effect=[{}, {}]),
                patch.object(prepare_cli, "load_regulatory_source_manifest", return_value={}),
                patch.object(prepare_cli, "prepare_regulatory_evidence", return_value=evidence),
                patch.object(
                    prepare_cli,
                    "write_regulatory_artifact_exclusive",
                    return_value=destination,
                ) as writer,
                redirect_stdout(output),
            ):
                result = prepare_cli.main(
                    [
                        "--candidate",
                        "phillip-fx",
                        "--source-manifest",
                        str(manifest),
                        "--source-root",
                        str(root),
                        "--output",
                        str(destination),
                    ]
                )
        self.assertEqual(0, result)
        writer.assert_called_once_with(destination, evidence)
        self.assertIn("Registration enabled: false", output.getvalue())
        self.assertIn("Order capability: DISABLED", output.getvalue())

    def test_sign_cli_loads_only_derived_role_key(self) -> None:
        output = io.StringIO()
        approval = {
            "candidate_id": "phillip-fx",
            "approver_role": "LEGAL_REVIEW",
            "signature_hmac_sha256": "b" * 64,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_path = root / "evidence.json"
            output_path = root / "approval.json"
            evidence_path.write_text("{}", encoding="utf-8")
            with (
                patch.object(sign_cli, "load_regulatory_evidence", return_value={"candidate_id": "phillip-fx"}),
                patch.object(sign_cli, "WindowsEvidenceKeyStore") as store,
                patch.object(sign_cli, "sign_regulatory_approval", return_value=approval),
                patch.object(
                    sign_cli,
                    "write_regulatory_artifact_exclusive",
                    return_value=output_path,
                ),
                redirect_stdout(output),
            ):
                store.return_value.load.return_value = b"l" * 32
                result = sign_cli.main(
                    [
                        "--candidate",
                        "phillip-fx",
                        "--role",
                        "LEGAL_REVIEW",
                        "--approver-id",
                        "legal-reviewer",
                        "--evidence",
                        str(evidence_path),
                        "--output",
                        str(output_path),
                    ]
                )
        self.assertEqual(0, result)
        store.return_value.load.assert_called_once_with(
            "phillip-fx-legal-review-v1"
        )
        self.assertIn("Order capability: DISABLED", output.getvalue())

    def test_assembly_cli_uses_vault_provider_and_does_not_activate_profile(self) -> None:
        output = io.StringIO()
        observation = {
            "candidate_id": "phillip-fx",
            "regulatory_approvals": [{}, {}],
        }
        profile = SimpleNamespace(
            candidate_id="phillip-fx",
            template_path="config/phillip_fx_calendar_window_01.template.json",
            registration_enabled=False,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [root / name for name in ("evidence.json", "compliance.json", "legal.json")]
            for path in paths:
                path.write_text("{}", encoding="utf-8")
            destination = root / "observation.json"
            with (
                patch.object(assemble_cli, "load_broker_evidence_profile", return_value=profile),
                patch.object(assemble_cli, "read_json_object", side_effect=[{}, {}]),
                patch.object(assemble_cli, "load_regulatory_evidence", return_value={"candidate_id": "phillip-fx"}),
                patch.object(
                    assemble_cli,
                    "load_regulatory_approval",
                    side_effect=[
                        {"approver_role": "COMPLIANCE_REVIEW"},
                        {"approver_role": "LEGAL_REVIEW"},
                    ],
                ),
                patch.object(assemble_cli, "WindowsEvidenceKeyStore") as store,
                patch.object(
                    assemble_cli,
                    "assemble_regulatory_observation",
                    return_value=observation,
                ) as assemble,
                patch.object(
                    assemble_cli,
                    "write_regulatory_artifact_exclusive",
                    return_value=destination,
                ),
                redirect_stdout(output),
            ):
                result = assemble_cli.main(
                    [
                        "--candidate",
                        "phillip-fx",
                        "--evidence",
                        str(paths[0]),
                        "--compliance-approval",
                        str(paths[1]),
                        "--legal-approval",
                        str(paths[2]),
                        "--output",
                        str(destination),
                    ]
                )
        self.assertEqual(0, result)
        self.assertIs(assemble.call_args.kwargs["approval_key_provider"], store.return_value.load)
        self.assertIn("Registration enabled: false", output.getvalue())
        self.assertIn("Order capability: DISABLED", output.getvalue())

    def test_plan_and_contract_pass_vault_provider_to_downstream_verifiers(self) -> None:
        profile = SimpleNamespace(
            candidate_id="phillip-fx",
            key_name="phillip-fx-window-01-v1",
            template_path="config/phillip_fx_calendar_window_01.template.json",
            registration_enabled=True,
            contract_id="phillip-fx-window-01-diagnostic-v1",
        )
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch.object(prepare_broker_window, "load_broker_evidence_profile", return_value=profile),
                patch.object(prepare_broker_window, "read_json_object", side_effect=[{}, {}, {}]),
                patch.object(prepare_broker_window, "WindowsEvidenceKeyStore") as plan_store,
                patch.object(
                    prepare_broker_window,
                    "prepare_broker_calendar_plan",
                    return_value={"plan_payload_sha256": "a" * 64},
                ) as prepare,
                patch.object(
                    prepare_broker_window,
                    "write_broker_calendar_plan_exclusive",
                    return_value=root / "plan.json",
                ),
                redirect_stdout(output),
            ):
                plan_store.return_value.load.return_value = b"k" * 32
                result = prepare_broker_window.main(
                    [
                        "--candidate", "phillip-fx",
                        "--discovery", str(root / "discovery.json"),
                        "--output", str(root / "plan.json"),
                    ]
                )
            self.assertEqual(0, result)
            self.assertIs(
                prepare.call_args.kwargs["regulatory_approval_key_provider"],
                plan_store.return_value.load,
            )

            with (
                patch.object(register_broker_forward_contract, "load_broker_evidence_profile", return_value=profile),
                patch.object(register_broker_forward_contract, "WindowsEvidenceKeyStore") as contract_store,
                patch.object(
                    register_broker_forward_contract,
                    "register_broker_diagnostic_contract",
                    return_value={
                        "contract_id": profile.contract_id,
                        "contract_payload_sha256": "b" * 64,
                        "signing_key_id": "wincred-fixture",
                    },
                ) as register,
                redirect_stdout(io.StringIO()),
            ):
                contract_store.return_value.load.return_value = b"k" * 32
                result = register_broker_forward_contract.main(
                    [
                        "--candidate", "phillip-fx",
                        "--discovery", str(root / "discovery.json"),
                        "--plan", str(root / "plan.json"),
                        "--calendar", str(root / "calendar.json"),
                    ]
                )
            self.assertEqual(0, result)
            self.assertIs(
                register.call_args.kwargs["regulatory_approval_key_provider"],
                contract_store.return_value.load,
            )


if __name__ == "__main__":
    unittest.main()
