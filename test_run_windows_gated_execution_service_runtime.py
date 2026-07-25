from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from live_runtime.asymmetric_release_trust import (
    EXECUTION_RELEASE_PROFILE,
    VerifiedExternalLauncherAttestation,
)
import run_windows_gated_execution_service as execution_cli


IDENTITY = "a" * 64
FACTORY_HASH = "b" * 64
BOOTSTRAP_HASH = "c" * 64
CONFIG_HASH = "d" * 64


class RunWindowsGatedExecutionServiceRuntimeTests(unittest.TestCase):
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

    def _trusted_args(self, *extra: str) -> list[str]:
        return self._args(
            "--release-trust-policy",
            "policy.json",
            "--expected-release-trust-policy-sha256",
            "e" * 64,
            "--release-attestation",
            "attestation.json",
            *extra,
        )

    @staticmethod
    def _factory_result(*, mt5_module=None):
        materialize = Mock(name="bootstrap_materialize")
        bootstrap = SimpleNamespace(
            ports=SimpleNamespace(mt5_module=mt5_module),
            config=SimpleNamespace(safe_binding_sha256=BOOTSTRAP_HASH),
            materialize=materialize,
        )
        return SimpleNamespace(
            bootstrap=bootstrap,
            factory_contract_sha256=FACTORY_HASH,
            service_config_file_sha256=CONFIG_HASH,
        )

    def test_validate_and_materialize_modes_are_mutually_exclusive(self) -> None:
        with self.assertRaises(SystemExit):
            execution_cli.parse_args(
                self._args("--validate-only", "--materialize-only")
            )

    def test_materialize_only_requires_external_trust_before_factory(self) -> None:
        stderr = io.StringIO()
        with (
            patch.object(
                execution_cli,
                "load_reviewed_windows_service_factory",
                side_effect=AssertionError("factory must not import"),
            ),
            redirect_stderr(stderr),
        ):
            status = execution_cli.main(
                self._args("--materialize-only")
            )
        self.assertEqual(2, status)
        self.assertIn(
            "EXTERNAL_RSA_LAUNCHER_ATTESTATION_REQUIRED",
            stderr.getvalue(),
        )

    def test_materialize_only_loads_provider_but_never_bootstrap_or_runner(
        self,
    ) -> None:
        events: list[str] = []
        verified = Mock(spec=VerifiedExternalLauncherAttestation)
        manifest = SimpleNamespace(
            release_profile=EXECUTION_RELEASE_PROFILE,
            factory_contract_sha256=FACTORY_HASH,
            bootstrap_binding_sha256=BOOTSTRAP_HASH,
        )
        result = self._factory_result()

        def trust(_args):
            events.append("trust")
            return verified

        def load(**_kwargs):
            events.append("factory")
            return manifest, {}, result

        stdout = io.StringIO()
        with (
            patch.object(
                execution_cli,
                "_verify_external_release_trust",
                side_effect=trust,
            ),
            patch.object(
                execution_cli,
                "load_reviewed_windows_service_factory",
                side_effect=load,
            ),
            patch.object(
                execution_cli,
                "WindowsGatedServiceRunner",
                side_effect=AssertionError("runner must not be constructed"),
            ),
            patch.object(
                execution_cli,
                "install_signal_handlers",
                side_effect=AssertionError("signals must not be installed"),
            ),
            redirect_stdout(stdout),
        ):
            status = execution_cli.main(
                self._trusted_args("--materialize-only")
            )
        self.assertEqual(0, status)
        self.assertEqual(["trust", "factory"], events)
        verified.assert_current.assert_called_once_with(
            now=unittest.mock.ANY,
            expected_release_identity_sha256=IDENTITY,
            expected_release_profile=EXECUTION_RELEASE_PROFILE,
        )
        result.bootstrap.materialize.assert_not_called()
        report = json.loads(stdout.getvalue())
        self.assertEqual(
            "FACTORY_MATERIALIZED_BROKER_NOT_INITIALIZED",
            report["status"],
        )
        self.assertTrue(report["factory_imported"])
        self.assertTrue(report["provider_materialized"])
        self.assertFalse(report["production_bootstrap_materialized"])
        self.assertFalse(report["mt5_module_injected"])
        self.assertFalse(report["mt5_import_or_initialize_performed"])
        self.assertFalse(report["broker_mutation_performed"])
        self.assertFalse(report["production_execution_ready"])
        self.assertEqual("DISABLED", report["order_capability"])
        self.assertFalse(report["live_allowed"])
        self.assertFalse(report["safe_to_demo_auto_order"])
        self.assertEqual(0.01, report["max_lot"])

    def test_materialize_only_rejects_mt5_injection_before_runner(self) -> None:
        verified = Mock(spec=VerifiedExternalLauncherAttestation)
        manifest = SimpleNamespace(
            release_profile=EXECUTION_RELEASE_PROFILE,
            factory_contract_sha256=FACTORY_HASH,
            bootstrap_binding_sha256=BOOTSTRAP_HASH,
        )
        result = self._factory_result(mt5_module=object())
        stderr = io.StringIO()
        with (
            patch.object(
                execution_cli,
                "_verify_external_release_trust",
                return_value=verified,
            ),
            patch.object(
                execution_cli,
                "load_reviewed_windows_service_factory",
                return_value=(manifest, {}, result),
            ),
            patch.object(
                execution_cli,
                "WindowsGatedServiceRunner",
                side_effect=AssertionError("runner must not be constructed"),
            ),
            redirect_stderr(stderr),
        ):
            status = execution_cli.main(
                self._trusted_args("--materialize-only")
            )
        self.assertEqual(2, status)
        self.assertIn(
            "SERVICE_FACTORY_MT5_INJECTION_FORBIDDEN",
            stderr.getvalue(),
        )
        result.bootstrap.materialize.assert_not_called()

    def test_trust_verifier_is_pinned_to_execution_profile(self) -> None:
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
            verified = object.__new__(
                VerifiedExternalLauncherAttestation
            )
            with patch.object(
                execution_cli,
                "verify_external_launcher_attestation",
                return_value=verified,
            ) as verify:
                result = execution_cli._verify_external_release_trust(args)
        self.assertIs(verified, result)
        self.assertEqual(
            EXECUTION_RELEASE_PROFILE,
            verify.call_args.kwargs["expected_release_profile"],
        )


if __name__ == "__main__":
    unittest.main()
