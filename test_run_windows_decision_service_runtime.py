from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from live_runtime.asymmetric_release_trust import (
    DECISION_RELEASE_PROFILE,
    VerifiedExternalLauncherAttestation,
)
from live_runtime.windows_decision_service_entrypoint import (
    DecisionServiceRuntimeError,
)
import run_windows_decision_service as decision_cli


UTC = timezone.utc
IDENTITY = "a" * 64


class RunWindowsDecisionServiceRuntimeTests(unittest.TestCase):
    def _args(self, *extra: str) -> list[str]:
        return [
            "--factory-manifest",
            "config/factory.json",
            "--release-root",
            "release-root",
            "--expected-release-identity-sha256",
            IDENTITY,
            *extra,
        ]

    def test_validate_only_is_import_trust_and_provider_free(self) -> None:
        manifest = SimpleNamespace(
            release_profile=DECISION_RELEASE_PROFILE,
            factory_contract_sha256="b" * 64,
            bootstrap_binding_sha256="c" * 64,
        )
        config = SimpleNamespace(service_id="decision-service")
        stdout = io.StringIO()
        with (
            patch.object(
                decision_cli,
                "validate_reviewed_windows_decision_service_factory_manifest",
                return_value=(manifest, config, object()),
            ) as validate,
            patch.object(
                decision_cli,
                "_verify_external_release_trust",
                side_effect=AssertionError("trust must not be read"),
            ),
            patch.object(
                decision_cli,
                "load_reviewed_windows_decision_service_factory",
                side_effect=AssertionError("factory must not import"),
            ),
            redirect_stdout(stdout),
        ):
            status = decision_cli.main(self._args("--validate-only"))
        self.assertEqual(0, status)
        validate.assert_called_once()
        report = json.loads(stdout.getvalue())
        self.assertEqual(
            "STATIC_CONFIGURED_FACTORY_AND_CONFIG_VERIFIED",
            report["status"],
        )
        self.assertFalse(report["factory_imported"])
        self.assertFalse(report["provider_materialized"])
        self.assertFalse(report["live_allowed"])
        self.assertFalse(report["safe_to_demo_auto_order"])

    def test_operational_launch_without_external_trust_fails_before_import(
        self,
    ) -> None:
        stderr = io.StringIO()
        with (
            patch.object(
                decision_cli,
                "load_reviewed_windows_decision_service_factory",
                side_effect=AssertionError("factory must not import"),
            ),
            redirect_stderr(stderr),
        ):
            status = decision_cli.main(self._args())
        self.assertEqual(2, status)
        self.assertIn(
            "EXTERNAL_RSA_LAUNCHER_ATTESTATION_REQUIRED",
            stderr.getvalue(),
        )

    def test_operational_launch_verifies_trust_before_factory_and_rechecks(
        self,
    ) -> None:
        calls: list[str] = []
        verified = Mock(spec=VerifiedExternalLauncherAttestation)

        def trust(_args):
            calls.append("trust")
            return verified

        manifest = SimpleNamespace(factory_contract_sha256="b" * 64)
        config = SimpleNamespace(
            service_id="decision-service",
            max_cycles=1,
            poll_seconds=0.0,
            cycle_deadline_seconds=1.0,
        )
        factory_result = object()

        def load(**_kwargs):
            calls.append("factory")
            return manifest, config, factory_result

        runner = Mock()
        runner.run.return_value = (
            SimpleNamespace(
                lanes=(
                    SimpleNamespace(symbol="XAUUSD", status="NO_INPUT"),
                )
            ),
        )
        stdout = io.StringIO()
        with (
            patch.object(
                decision_cli,
                "_verify_external_release_trust",
                side_effect=trust,
            ),
            patch.object(
                decision_cli,
                "load_reviewed_windows_decision_service_factory",
                side_effect=load,
            ),
            patch.object(
                decision_cli,
                "WindowsDecisionServiceRunner",
                return_value=runner,
            ) as runner_type,
            patch.object(
                decision_cli,
                "install_decision_signal_handlers",
            ) as install_signals,
            redirect_stdout(stdout),
        ):
            status = decision_cli.main(
                self._args(
                    "--release-trust-policy",
                    "policy.json",
                    "--expected-release-trust-policy-sha256",
                    "d" * 64,
                    "--release-attestation",
                    "attestation.json",
                )
            )
        self.assertEqual(0, status)
        self.assertEqual(["trust", "factory"], calls)
        verified.assert_current.assert_called_once_with(
            now=unittest.mock.ANY,
            expected_release_identity_sha256=IDENTITY,
            expected_release_profile=DECISION_RELEASE_PROFILE,
        )
        runner_type.assert_called_once_with(
            factory_result,
            runtime_config=config,
        )
        install_signals.assert_called_once_with(runner)
        runner.run.assert_called_once_with()
        report = json.loads(stdout.getvalue())
        self.assertEqual("BOUNDED_DECISION_RUN_COMPLETE", report["status"])
        self.assertEqual(1, report["cycles"])
        self.assertEqual({"NO_INPUT": 1}, report["lane_status_counts"])
        self.assertEqual("DISABLED", report["order_capability"])

    def test_trust_verifier_is_pinned_to_decision_profile(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            base = Path(raw)
            release_root = base / "release"
            release_root.mkdir()
            policy = base / "policy.json"
            attestation = base / "attestation.json"
            policy.write_text("{}\n", encoding="utf-8")
            attestation.write_text("{}\n", encoding="utf-8")
            args = SimpleNamespace(
                release_root=str(release_root),
                release_trust_policy=str(policy),
                expected_release_trust_policy_sha256="e" * 64,
                release_attestation=str(attestation),
                expected_release_identity_sha256=IDENTITY,
            )
            verified = object.__new__(VerifiedExternalLauncherAttestation)
            with patch.object(
                decision_cli,
                "verify_external_launcher_attestation",
                return_value=verified,
            ) as verify:
                result = decision_cli._verify_external_release_trust(args)
        self.assertIs(verified, result)
        self.assertEqual(
            DECISION_RELEASE_PROFILE,
            verify.call_args.kwargs["expected_release_profile"],
        )

    def test_external_trust_documents_inside_release_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            root = Path(raw)
            document = root / "policy.json"
            document.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(
                DecisionServiceRuntimeError,
                "MUST_BE_EXTERNAL",
            ):
                decision_cli._read_external_trust_document(
                    str(document),
                    release_root=str(root),
                    label="release_trust_policy",
                )


if __name__ == "__main__":
    unittest.main()
