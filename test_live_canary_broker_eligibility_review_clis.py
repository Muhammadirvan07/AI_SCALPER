from __future__ import annotations

from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import assemble_live_canary_broker_eligibility_review as assemble_cli
import prepare_live_canary_broker_eligibility_review as prepare_cli
import setup_live_canary_broker_eligibility_review_key as setup_cli
import sign_live_canary_broker_eligibility_review as sign_cli
import verify_live_canary_broker_eligibility_review as verify_cli
from live_runtime.live_canary_broker_eligibility_review import (
    LiveCanaryBrokerEligibilityReviewError,
    live_canary_broker_eligibility_key_name,
)


ROOT = Path(__file__).resolve().parent
UTC = timezone.utc


class LiveCanaryBrokerEligibilityReviewCLITests(unittest.TestCase):
    def test_commands_expose_no_secret_or_execution_arguments(self) -> None:
        for filename in (
            "setup_live_canary_broker_eligibility_review_key.py",
            "prepare_live_canary_broker_eligibility_review.py",
            "sign_live_canary_broker_eligibility_review.py",
            "assemble_live_canary_broker_eligibility_review.py",
            "verify_live_canary_broker_eligibility_review.py",
        ):
            completed = subprocess.run(
                (sys.executable, "-B", filename, "--help"),
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            help_text = completed.stdout.casefold()
            for forbidden in (
                "--password",
                "--login",
                "--account",
                "--order",
                "--lot",
                "--volume",
                "--private-key",
                "--secret",
                "--signing-key",
                "--export-key",
                "--activate",
                "--enable-execution",
            ):
                self.assertNotIn(forbidden, help_text)

    def test_key_setup_uses_exact_role_scoped_windows_key(self) -> None:
        output = io.StringIO()
        profile = SimpleNamespace(candidate_id="phillip-commodity")
        with (
            patch.object(
                setup_cli,
                "load_broker_evidence_profile",
                return_value=profile,
            ),
            patch.object(setup_cli, "WindowsEvidenceKeyStore") as store,
            redirect_stdout(output),
        ):
            store.return_value.ensure.return_value = (b"k" * 32, True)
            result = setup_cli.main(
                [
                    "--candidate",
                    "phillip-commodity",
                    "--role",
                    "LIVE_CANARY_LEGAL_REVIEW",
                ]
            )
        self.assertEqual(0, result)
        store.return_value.ensure.assert_called_once_with(
            live_canary_broker_eligibility_key_name(
                "phillip-commodity", "LIVE_CANARY_LEGAL_REVIEW"
            )
        )
        rendered = output.getvalue()
        self.assertIn("Secret material: NOT_EXPORTED", rendered)
        self.assertIn("Live allowed: false", rendered)
        self.assertIn("Order capability: DISABLED", rendered)

    def test_prepare_uses_profile_source_and_diagnostic_vault_provider(self) -> None:
        output = io.StringIO()
        profile = SimpleNamespace(
            candidate_id="phillip-commodity",
            template_path="config/phillip_commodity_calendar_window_01.template.json",
        )
        body = {
            "candidate_id": "phillip-commodity",
            "broker_id": "phillip-jp",
            "content_sha256": "a" * 64,
            "expires_at_utc": "2026-08-12T12:00:00.000000Z",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            observation_path = root / "observation.json"
            destination = root / "body.json"
            observation_path.write_text("{}", encoding="utf-8")
            with (
                patch.object(
                    prepare_cli,
                    "load_broker_evidence_profile",
                    return_value=profile,
                ),
                patch.object(
                    prepare_cli,
                    "read_json_object",
                    side_effect=[{}, {}],
                ),
                patch.object(
                    prepare_cli,
                    "load_regulatory_observation",
                    return_value={},
                ),
                patch.object(prepare_cli, "WindowsEvidenceKeyStore") as store,
                patch.object(
                    prepare_cli,
                    "prepare_live_canary_broker_eligibility_review_body",
                    return_value=body,
                ) as prepare,
                patch.object(
                    prepare_cli,
                    "write_live_canary_broker_eligibility_artifact_exclusive",
                    return_value=destination,
                ) as writer,
                redirect_stdout(output),
            ):
                result = prepare_cli.main(
                    [
                        "--candidate",
                        "phillip-commodity",
                        "--broker-id",
                        "phillip-jp",
                        "--live-server",
                        "PhillipSecuritiesJP-LIVE",
                        "--registration-authority",
                        "JAPAN-FSA",
                        "--registration-identifier",
                        "KANTO-KINSHO-127",
                        "--expires-at-utc",
                        "2026-08-12T12:00:00Z",
                        "--regulatory-observation",
                        str(observation_path),
                        "--output",
                        str(destination),
                    ]
                )
        self.assertEqual(0, result)
        self.assertIs(
            prepare.call_args.kwargs["diagnostic_key_provider"],
            store.return_value.load,
        )
        self.assertEqual(
            datetime(2026, 8, 12, 12, 0, tzinfo=UTC),
            prepare.call_args.kwargs["expires_at"],
        )
        writer.assert_called_once_with(destination, body)
        self.assertIn("Order capability: DISABLED", output.getvalue())

    def test_sign_loads_only_derived_live_key_and_uses_vault_for_diagnostics(self) -> None:
        output = io.StringIO()
        role = "LIVE_CANARY_COMPLIANCE_REVIEW"
        key_id = live_canary_broker_eligibility_key_name(
            "phillip-commodity", role
        )
        approval = {
            "candidate_id": "phillip-commodity",
            "approver_role": role,
            "key_id": key_id,
            "signature_hmac_sha256": "b" * 64,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            body_path = root / "body.json"
            observation_path = root / "observation.json"
            destination = root / "approval.json"
            body_path.write_text("{}", encoding="utf-8")
            observation_path.write_text("{}", encoding="utf-8")
            with (
                patch.object(
                    sign_cli,
                    "load_broker_evidence_profile",
                    return_value=SimpleNamespace(
                        candidate_id="phillip-commodity",
                        template_path=(
                            "config/"
                            "phillip_commodity_calendar_window_01.template.json"
                        ),
                    ),
                ),
                patch.object(
                    sign_cli, "read_json_object", side_effect=[{}, {}]
                ),
                patch.object(
                    sign_cli,
                    "load_live_canary_broker_eligibility_review_body",
                    return_value={"candidate_id": "phillip-commodity"},
                ),
                patch.object(
                    sign_cli, "load_regulatory_observation", return_value={}
                ),
                patch.object(sign_cli, "WindowsEvidenceKeyStore") as store,
                patch.object(
                    sign_cli,
                    "sign_live_canary_broker_eligibility_approval",
                    return_value=approval,
                ) as sign,
                patch.object(
                    sign_cli,
                    "write_live_canary_broker_eligibility_artifact_exclusive",
                    return_value=destination,
                ),
                redirect_stdout(output),
            ):
                store.return_value.load.return_value = b"l" * 32
                result = sign_cli.main(
                    [
                        "--candidate",
                        "phillip-commodity",
                        "--role",
                        role,
                        "--approver-id",
                        "live-compliance-reviewer",
                        "--review-body",
                        str(body_path),
                        "--regulatory-observation",
                        str(observation_path),
                        "--output",
                        str(destination),
                    ]
                )
        self.assertEqual(0, result)
        store.return_value.load.assert_any_call(key_id)
        self.assertEqual(b"l" * 32, sign.call_args.kwargs["signing_key"])
        self.assertIs(
            sign.call_args.kwargs["diagnostic_key_provider"],
            store.return_value.load,
        )
        self.assertIn("Secret material: NOT_EXPORTED", output.getvalue())

    def test_assemble_and_verify_use_vault_without_enabling_execution(self) -> None:
        profile = SimpleNamespace(
            candidate_id="phillip-commodity",
            template_path="config/phillip_commodity_calendar_window_01.template.json",
        )
        review = {
            "content_sha256": "c" * 64,
            "eligibility_evidence": SimpleNamespace(content_sha256="d" * 64),
        }
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                name: root / f"{name}.json"
                for name in (
                    "body",
                    "observation",
                    "compliance",
                    "legal",
                    "review",
                )
            }
            for path in paths.values():
                path.write_text("{}", encoding="utf-8")
            with (
                patch.object(
                    assemble_cli,
                    "load_broker_evidence_profile",
                    return_value=profile,
                ),
                patch.object(
                    assemble_cli, "read_json_object", side_effect=[{}, {}]
                ),
                patch.object(
                    assemble_cli,
                    "load_live_canary_broker_eligibility_review_body",
                    return_value={"candidate_id": "phillip-commodity"},
                ),
                patch.object(
                    assemble_cli,
                    "load_live_canary_broker_eligibility_approval",
                    side_effect=[
                        {"approver_role": "LIVE_CANARY_COMPLIANCE_REVIEW"},
                        {"approver_role": "LIVE_CANARY_LEGAL_REVIEW"},
                    ],
                ),
                patch.object(
                    assemble_cli, "load_regulatory_observation", return_value={}
                ),
                patch.object(assemble_cli, "WindowsEvidenceKeyStore") as store,
                patch.object(
                    assemble_cli,
                    "assemble_live_canary_broker_eligibility_review",
                    return_value=review,
                ) as assemble,
                patch.object(
                    assemble_cli,
                    "write_live_canary_broker_eligibility_artifact_exclusive",
                    return_value=paths["review"],
                ),
                redirect_stdout(output),
            ):
                result = assemble_cli.main(
                    [
                        "--candidate",
                        "phillip-commodity",
                        "--review-body",
                        str(paths["body"]),
                        "--regulatory-observation",
                        str(paths["observation"]),
                        "--compliance-approval",
                        str(paths["compliance"]),
                        "--legal-approval",
                        str(paths["legal"]),
                        "--output",
                        str(paths["review"]),
                    ]
                )
            self.assertEqual(0, result)
            self.assertIs(
                assemble.call_args.kwargs["diagnostic_key_provider"],
                store.return_value.load,
            )
            self.assertIs(
                assemble.call_args.kwargs["live_key_provider"],
                store.return_value.load,
            )

            evidence = SimpleNamespace(
                broker_id="phillip-jp", content_sha256="e" * 64
            )
            with (
                patch.object(
                    verify_cli,
                    "load_broker_evidence_profile",
                    return_value=profile,
                ),
                patch.object(
                    verify_cli, "read_json_object", side_effect=[{}, {}]
                ),
                patch.object(
                    verify_cli,
                    "load_live_canary_broker_eligibility_review",
                    return_value={},
                ),
                patch.object(
                    verify_cli, "load_regulatory_observation", return_value={}
                ),
                patch.object(verify_cli, "WindowsEvidenceKeyStore") as verify_store,
                patch.object(
                    verify_cli,
                    "verify_live_canary_broker_eligibility_review",
                    return_value=evidence,
                ) as verify,
                redirect_stdout(output),
            ):
                result = verify_cli.main(
                    [
                        "--candidate",
                        "phillip-commodity",
                        "--review",
                        str(paths["review"]),
                        "--regulatory-observation",
                        str(paths["observation"]),
                    ]
                )
            self.assertEqual(0, result)
            self.assertIs(
                verify.call_args.kwargs["diagnostic_key_provider"],
                verify_store.return_value.load,
            )
            self.assertIs(
                verify.call_args.kwargs["live_key_provider"],
                verify_store.return_value.load,
            )
        rendered = output.getvalue()
        self.assertIn("Live allowed: false", rendered)
        self.assertIn("Order capability: DISABLED", rendered)

    def test_failure_is_exit_two_and_explicitly_deny_only(self) -> None:
        output = io.StringIO()
        profile = SimpleNamespace(
            candidate_id="phillip-commodity",
            template_path="config/phillip_commodity_calendar_window_01.template.json",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            observation = root / "observation.json"
            observation.write_text("{}", encoding="utf-8")
            with (
                patch.object(
                    prepare_cli,
                    "load_broker_evidence_profile",
                    return_value=profile,
                ),
                patch.object(
                    prepare_cli, "read_json_object", side_effect=[{}, {}]
                ),
                patch.object(
                    prepare_cli,
                    "load_regulatory_observation",
                    return_value={},
                ),
                patch.object(prepare_cli, "WindowsEvidenceKeyStore"),
                patch.object(
                    prepare_cli,
                    "prepare_live_canary_broker_eligibility_review_body",
                    side_effect=LiveCanaryBrokerEligibilityReviewError(
                        "LIVE_CANARY_ELIGIBILITY_SOURCE_INVALID"
                    ),
                ),
                redirect_stdout(output),
            ):
                result = prepare_cli.main(
                    [
                        "--candidate",
                        "phillip-commodity",
                        "--broker-id",
                        "phillip-jp",
                        "--live-server",
                        "PhillipSecuritiesJP-LIVE",
                        "--registration-authority",
                        "JAPAN-FSA",
                        "--registration-identifier",
                        "KANTO-KINSHO-127",
                        "--expires-at-utc",
                        "2026-08-12T12:00:00Z",
                        "--regulatory-observation",
                        str(observation),
                        "--output",
                        str(root / "body.json"),
                    ]
                )
        self.assertEqual(2, result)
        rendered = output.getvalue()
        self.assertIn("LIVE_CANARY_BROKER_ELIGIBILITY_PREPARE_BLOCKED", rendered)
        self.assertIn("no broker order was submitted", rendered)
        self.assertIn("Order capability: DISABLED", rendered)


if __name__ == "__main__":
    unittest.main()
