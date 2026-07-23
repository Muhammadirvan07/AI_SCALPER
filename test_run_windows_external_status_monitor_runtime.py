from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from live_runtime.windows_external_status_monitor_entrypoint import (
    WindowsExternalStatusMonitorFactoryContext,
    seal_windows_external_status_monitor_factory_result,
)
from run_windows_external_status_monitor import main as run_monitor
import test_live_runtime_windows_external_status_monitor_loader as monitor_loader_fixtures


class WindowsExternalStatusMonitorRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.fixture = (
            monitor_loader_fixtures
            .WindowsExternalStatusMonitorLoaderTests()
        )
        self.fixture.setUp()

    def tearDown(self) -> None:
        self.fixture.tearDown()
        self.temporary.cleanup()

    def test_validate_only_is_static_and_side_effect_free(self):
        root, manifest_path, result = self.fixture._configured_release(
            factory_source=b"raise RuntimeError('must not import')\n"
        )
        stdout = io.StringIO()
        with patch(
            "run_windows_external_status_monitor."
            "_verify_external_release_trust",
            side_effect=AssertionError("trust must not be read"),
        ), patch(
            "run_windows_external_status_monitor."
            "load_reviewed_windows_external_status_monitor_factory",
            side_effect=AssertionError("factory must not import"),
        ), redirect_stdout(stdout):
            status = run_monitor(
                [
                    "--factory-manifest",
                    str(manifest_path),
                    "--release-root",
                    str(root),
                    "--expected-release-identity-sha256",
                    result["release_identity_sha256"],
                    "--validate-only",
                ]
            )
        self.assertEqual(0, status)
        report = json.loads(stdout.getvalue())
        self.assertEqual(
            "STATIC_CONFIGURED_FACTORY_AND_CONFIG_VERIFIED",
            report["status"],
        )
        self.assertFalse(report["factory_imported"])
        self.assertFalse(report["provider_materialized"])
        self.assertFalse(report["offhost_delivery_performed"])
        self.assertFalse(report["broker_mutation_performed"])

    def test_operational_mode_requires_external_trust_first(self):
        events: list[str] = []

        def reject_trust(_args):
            events.append("trust")
            raise RuntimeError("trust rejected")

        def forbidden_factory(**_kwargs):
            events.append("factory")
            raise AssertionError("factory must not load before trust")

        stderr = io.StringIO()
        with patch(
            "run_windows_external_status_monitor."
            "_verify_external_release_trust",
            side_effect=reject_trust,
        ), patch(
            "run_windows_external_status_monitor."
            "load_reviewed_windows_external_status_monitor_factory",
            side_effect=forbidden_factory,
        ), redirect_stderr(stderr):
            status = run_monitor(
                [
                    "--factory-manifest",
                    "not-used.json",
                    "--release-root",
                    "not-used",
                    "--expected-release-identity-sha256",
                    "a" * 64,
                ]
            )
        self.assertEqual(3, status)
        self.assertEqual(["trust"], events)

    def test_missing_external_trust_fails_closed(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            status = run_monitor(
                [
                    "--factory-manifest",
                    "not-used.json",
                    "--release-root",
                    "not-used",
                    "--expected-release-identity-sha256",
                    "a" * 64,
                ]
            )
        self.assertEqual(2, status)
        self.assertIn(
            "EXTERNAL_RSA_MONITOR_LAUNCHER_ATTESTATION_REQUIRED",
            stderr.getvalue(),
        )

    def test_operational_run_uses_exact_bound_monitor(self):
        root, manifest_path, release = self.fixture._configured_release()
        manifest, runtime_config, context = (
            monitor_loader_fixtures
            .validate_reviewed_windows_external_status_monitor_factory_manifest(
                release_root=root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=release[
                    "release_identity_sha256"
                ],
            )
        )
        provider_template = runtime_config.factory_template(
            release_identity_sha256=context.release_identity_sha256,
            factory_implementation_sha256=context.factory_file_sha256,
            factory_configuration_sha256=(
                context.service_config_file_sha256
            ),
        )
        factory_result = (
            seal_windows_external_status_monitor_factory_result(
                runtime_config=runtime_config,
                provider_template=provider_template,
                context=WindowsExternalStatusMonitorFactoryContext(
                    **context.to_canonical_dict()
                ),
                dependencies=self.fixture.fixture._dependencies(
                    Path(self.temporary.name)
                ),
            )
        )
        trust = SimpleNamespace(assert_current=lambda **_kwargs: True)
        stdout = io.StringIO()
        with patch(
            "run_windows_external_status_monitor."
            "_verify_external_release_trust",
            return_value=trust,
        ), patch(
            "run_windows_external_status_monitor."
            "load_reviewed_windows_external_status_monitor_factory",
            return_value=(manifest, runtime_config, factory_result),
        ), patch(
            "run_windows_external_status_monitor."
            "install_monitor_signal_handlers",
        ), patch.object(
            factory_result.monitor,
            "run",
            return_value=(),
        ), redirect_stdout(stdout):
            status = run_monitor(
                [
                    "--factory-manifest",
                    str(manifest_path),
                    "--release-root",
                    str(root),
                    "--expected-release-identity-sha256",
                    release["release_identity_sha256"],
                    "--release-trust-policy",
                    "policy.json",
                    "--expected-release-trust-policy-sha256",
                    "b" * 64,
                    "--release-attestation",
                    "attestation.json",
                ]
            )
        self.assertEqual(0, status)
        report = json.loads(stdout.getvalue())
        self.assertEqual(
            "BOUNDED_STATUS_MONITOR_RUN_COMPLETE",
            report["status"],
        )
        self.assertEqual(0, report["cycles"])
        self.assertEqual("DISABLED", report["order_capability"])


if __name__ == "__main__":
    unittest.main()
