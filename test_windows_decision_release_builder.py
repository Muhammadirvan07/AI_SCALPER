from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from build_windows_decision_release import (
    APPROVED_SOURCE_PATHS,
    READINESS_BLOCKERS,
    RELEASE_PROFILE,
    REPO_ROOT,
    REQUIRED_SAFETY,
    ReleaseBuildError,
    _read_decision_sources,
    _validate_decision_source_security,
    _validate_dependency_lock_set,
    build_decision_release,
    load_decision_allowlist,
)
from build_windows_release import MANIFEST_MEMBER, _verify_local_import_closure
from live_runtime.windows_decision_service_factory_template import (
    PROVIDER_ROLES,
    provider_contracts,
    validate_windows_decision_service_factory_template,
    windows_decision_service_factory_contract,
)
from run_windows_decision_service import main as run_decision_service
from validate_windows_decision_service import validate_windows_decision_service


class WindowsDecisionReleaseBuilderTests(unittest.TestCase):
    def _git(self, root: Path, *args: str) -> None:
        subprocess.run(("git", *args), cwd=root, check=True, capture_output=True)

    def _repo(
        self,
        base: Path,
        *,
        overrides: dict[str, bytes | str] | None = None,
        extra_files: dict[str, bytes | str] | None = None,
    ) -> tuple[Path, Path]:
        root = base / "repo"
        root.mkdir()
        for relative in sorted(APPROVED_SOURCE_PATHS):
            source = REPO_ROOT / relative
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        for relative, content in (overrides or {}).items():
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                destination.write_bytes(content)
            else:
                destination.write_text(content, encoding="utf-8")
        for relative, content in (extra_files or {}).items():
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                destination.write_bytes(content)
            else:
                destination.write_text(content, encoding="utf-8")
        self._git(root, "init", "-q")
        self._git(root, "config", "user.name", "Decision Release Test")
        self._git(root, "config", "user.email", "decision@example.invalid")
        self._git(root, "add", ".")
        self._git(root, "commit", "-qm", "fixture")
        return root, root / "config/windows_decision_service_allowlist.v1.json"

    @staticmethod
    def _factory_payload(release_identity: str) -> dict[str, object]:
        contracts = provider_contracts()
        custody = windows_decision_service_factory_contract()[
            "provider_custody_modes"
        ]
        return {
            "service_id": "decision-service-jp-demo",
            "release_identity_sha256": release_identity,
            "factory_implementation_sha256": "1" * 64,
            "factory_configuration_sha256": "2" * 64,
            "providers": [
                {
                    "role": role,
                    "contract_sha256": contracts[role],
                    "implementation_sha256": "3" * 64,
                    "configuration_sha256": "4" * 64,
                    "custody_mode": custody[role],
                }
                for role in PROVIDER_ROLES
            ],
            "release_profile": RELEASE_PROFILE,
            "materialization_enabled": False,
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "schema_version": "windows-decision-service-factory-template-v1",
        }

    def test_release_is_exact_deterministic_and_non_executable(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(base)
            first = base / "first.zip"
            second = base / "second.zip"
            first_result = build_decision_release(root, allowlist, first)
            second_result = build_decision_release(root, allowlist, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(
                first_result["release_identity_sha256"],
                second_result["release_identity_sha256"],
            )
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(
                    set(APPROVED_SOURCE_PATHS) | {MANIFEST_MEMBER},
                    set(archive.namelist()),
                )
                manifest = json.loads(archive.read(MANIFEST_MEMBER))
            self.assertEqual(RELEASE_PROFILE, manifest["release_profile"])
            self.assertEqual(REQUIRED_SAFETY, manifest["safety"])
            self.assertEqual(
                "SIGNED_EXACT_CLOSURE_RECEIPTS_ONLY",
                manifest["usage_policy"]["session_calendar_capability"],
            )
            self.assertEqual(
                "EXACT_IMPLEMENTATION_AND_CONFIGURATION_HASH_REQUIRED",
                manifest["usage_policy"][
                    "session_calendar_verifier_provider"
                ],
            )
            self.assertIn(
                "SESSION_CALENDAR_VERIFIER",
                manifest["required_factory_provider_contracts"],
            )
            self.assertEqual(
                "BINDING_PINNED_HMAC_VERIFIER_PORT",
                manifest["usage_policy"][
                    "cursor_cas_acknowledgement_authentication"
                ],
            )
            self.assertFalse(manifest["production_execution_ready"])
            self.assertEqual(list(READINESS_BLOCKERS), manifest["readiness_blockers"])
            self.assertEqual("EXTERNAL_NOT_BUNDLED", manifest["runtime_factory"])
            self.assertEqual(
                "SEALED_BINDING_PINNED_HMAC_VERIFIER_PORT",
                manifest["trust_boundaries"][
                    "producer_cursor_cas_acknowledgement"
                ],
            )
            self.assertEqual("DISABLED", first_result["order_capability"])
            paths = {item["path"] for item in manifest["source_files"]}
            self.assertIn("live_runtime/brokerless_decision_producer.py", paths)
            for forbidden in (
                "execution_policy.py",
                "live_runtime/executor.py",
                "live_runtime/mt5_adapter.py",
                "live_runtime/permit.py",
                "live_runtime/reconciliation.py",
                "live_runtime/risk.py",
            ):
                self.assertNotIn(forbidden, paths)

    def test_dirty_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(base)
            (root / "runtime_state").mkdir()
            (root / "runtime_state/new.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseBuildError, "dirty"):
                build_decision_release(root, allowlist, base / "release.zip")

    def test_allowlist_is_exact_and_rejects_execution_path(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(base)
            payload = json.loads(allowlist.read_text(encoding="utf-8"))
            payload["files"].append("live_runtime/executor.py")
            allowlist.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ReleaseBuildError, "exact source allowlist"):
                load_decision_allowlist(allowlist)

    def test_forbidden_import_member_and_dynamic_loading_are_rejected(self):
        cases = (
            ("import MetaTrader5\n", "forbidden decision-service import"),
            ("import live_runtime.risk\n", "forbidden decision-service import"),
            ("def f(client):\n    return client.order_send({})\n", "order-capability"),
            ("value = __import__('helper')\n", "dynamic code loading"),
        )
        for index, (source, message) in enumerate(cases):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as raw:
                base = Path(raw) / str(index)
                base.mkdir()
                root, allowlist = self._repo(
                    base,
                    overrides={"agents/supervisor_agent.py": source},
                )
                with self.assertRaisesRegex(ReleaseBuildError, message):
                    build_decision_release(root, allowlist, base / "release.zip")

    def test_undeclared_local_import_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(
                base,
                overrides={
                    "agents/supervisor_agent.py": "from helper import VALUE\n"
                },
                extra_files={"helper.py": "VALUE = 1\n"},
            )
            with self.assertRaisesRegex(ReleaseBuildError, "local import is absent"):
                build_decision_release(root, allowlist, base / "release.zip")

    def test_dependency_drift_and_broker_sdk_are_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            lock = (
                REPO_ROOT / "requirements-decision-windows-cp312.lock.txt"
            ).read_text(encoding="utf-8")
            lock += "metatrader5==5.0.5735 --hash=sha256:" + "a" * 64 + "\n"
            root, allowlist = self._repo(
                base,
                overrides={
                    "requirements-decision-windows-cp312.lock.txt": lock
                },
            )
            with self.assertRaisesRegex(ReleaseBuildError, "dependency closure drift"):
                build_decision_release(root, allowlist, base / "release.zip")

    def test_project_allowlist_has_exact_import_closure_and_dependency_lock(self):
        allowlist = load_decision_allowlist(
            REPO_ROOT / "config/windows_decision_service_allowlist.v1.json"
        )
        sources = {
            path: (REPO_ROOT / path).read_bytes() for path in allowlist["files"]
        }
        _verify_local_import_closure(REPO_ROOT, sources)
        _validate_decision_source_security(sources)
        _validate_dependency_lock_set(sources)
        self.assertEqual(APPROVED_SOURCE_PATHS, set(sources))
        self.assertNotIn("live_runtime/executor.py", sources)

    def test_factory_template_is_exact_non_materializing_and_secret_free(self):
        payload = self._factory_payload("a" * 64)
        template = validate_windows_decision_service_factory_template(
            payload,
            expected_release_identity_sha256="a" * 64,
        )
        self.assertFalse(template.materialization_enabled)
        self.assertEqual("DISABLED", template.order_capability)
        self.assertFalse(template.live_allowed)
        self.assertFalse(template.safe_to_demo_auto_order)
        self.assertIn("SESSION_CALENDAR_VERIFIER", PROVIDER_ROLES)
        self.assertIn("SESSION_CALENDAR_VERIFIER", provider_contracts())
        drifted = dict(payload)
        drifted["password"] = "forbidden"
        with self.assertRaisesRegex(ValueError, "root fields drift"):
            validate_windows_decision_service_factory_template(drifted)

        missing_calendar = dict(payload)
        missing_calendar["providers"] = [
            item
            for item in payload["providers"]
            if item["role"] != "SESSION_CALENDAR_VERIFIER"
        ]
        with self.assertRaisesRegex(ValueError, "provider set is incomplete"):
            validate_windows_decision_service_factory_template(missing_calendar)
        report = validate_windows_decision_service(
            factory_payload=missing_calendar,
            expected_release_identity_sha256="a" * 64,
        )
        self.assertEqual("FAIL", report["port_validation"])
        self.assertIn("EXTERNAL_FACTORY_TEMPLATE:VALID", report["missing_ports"])

    def test_validator_is_fail_closed_and_never_materializes(self):
        payload = self._factory_payload("a" * 64)
        with patch(
            "live_runtime.brokerless_decision_producer.BrokerlessDecisionProducerService.run_cycle",
            side_effect=AssertionError("decision runtime must not run"),
        ), patch(
            "live_runtime.decision_ipc.DecisionIPCProducer.publish",
            side_effect=AssertionError("IPC must not mutate"),
        ):
            report = validate_windows_decision_service(
                factory_payload=payload,
                expected_release_identity_sha256="a" * 64,
            )
        self.assertEqual("PASS", report["port_validation"])
        self.assertEqual("PASS_NON_MATERIALIZING", report["factory_template_validation"])
        self.assertFalse(report["production_execution_ready"])
        self.assertIn(
            "EXTERNAL_SIGNED_SESSION_CALENDAR_VERIFIER_REQUIRED",
            report["readiness_blockers"],
        )
        self.assertEqual("DISABLED", report["safety"]["order_capability"])
        self.assertFalse(any(report["effects"].values()))
        self.assertIn(
            "SESSION_CALENDAR_VERIFIER",
            report["required_factory_provider_contracts"],
        )
        self.assertEqual(
            "EXACT_SIGNED_CLOSURE_RECEIPTS_BOUND_TO_LANE_HASH",
            report["trust_boundaries"]["session_calendar_continuity"],
        )

    def test_runner_validate_only_checks_release_without_runtime_effects(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(base)
            archive = base / "release.zip"
            result = build_decision_release(root, allowlist, archive)
            extracted = base / "extracted"
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(extracted)
            factory_path = base / "factory.json"
            factory_path.write_text(
                json.dumps(self._factory_payload(result["release_identity_sha256"])),
                encoding="utf-8",
            )
            with patch(
                "live_runtime.brokerless_decision_producer.BrokerlessDecisionProducerService.run_cycle",
                side_effect=AssertionError("market data must not be fetched"),
            ), patch(
                "live_runtime.decision_ipc.DecisionIPCProducer.publish",
                side_effect=AssertionError("IPC must not mutate"),
            ):
                status = run_decision_service(
                    [
                        "--factory-manifest",
                        str(factory_path),
                        "--release-root",
                        str(extracted),
                        "--expected-release-identity-sha256",
                        result["release_identity_sha256"],
                        "--validate-only",
                    ]
                )
            self.assertEqual(0, status)

            source = extracted / "agents/supervisor_agent.py"
            source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            self.assertEqual(
                2,
                run_decision_service(
                    [
                        "--factory-manifest",
                        str(factory_path),
                        "--release-root",
                        str(extracted),
                        "--expected-release-identity-sha256",
                        result["release_identity_sha256"],
                        "--validate-only",
                    ]
                ),
            )

    def test_runner_rejects_non_validate_mode_before_materialization(self):
        self.assertEqual(
            2,
            run_decision_service(
                [
                    "--factory-manifest",
                    "not-used.json",
                    "--release-root",
                    "not-used",
                    "--expected-release-identity-sha256",
                    "a" * 64,
                ]
            ),
        )

    def test_validator_fails_closed_when_safety_constant_drifts(self):
        with patch(
            "live_runtime.brokerless_decision_producer.ORDER_CAPABILITY",
            "PRESENT",
        ):
            report = validate_windows_decision_service()
        self.assertEqual("FAIL", report["port_validation"])
        self.assertFalse(report["production_execution_ready"])


if __name__ == "__main__":
    unittest.main()
