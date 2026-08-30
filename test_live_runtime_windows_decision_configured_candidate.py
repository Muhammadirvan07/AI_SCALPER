from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from live_runtime.configured_service_release import (
    verify_configured_service_release,
)
from live_runtime.windows_decision_configured_candidate import (
    CANDIDATE_RECEIPT_NAME,
    DecisionConfiguredCandidateError,
    assemble_windows_decision_configured_candidate,
    validate_windows_decision_configured_candidate,
)
from live_runtime.windows_decision_provider_pack_generator import (
    validate_windows_decision_provider_pack,
)
from live_runtime.windows_decision_service_factory_template import (
    validate_windows_decision_service_factory_template,
)
from live_runtime.windows_decision_service_entrypoint import (
    parse_windows_decision_service_runtime_config,
    validate_reviewed_windows_decision_service_factory_manifest,
)
from assemble_windows_decision_configured_candidate import (
    _parser as assemble_parser,
    main as assemble_main,
)
import test_live_runtime_windows_decision_provider_pack_generator as provider_fixture_module
from validate_windows_decision_configured_candidate import (
    _parser as validate_parser,
    main as validate_main,
)


EXPECTED_RELATIVE_FILES = {
    "DECISION_CONFIGURED_CANDIDATE.json",
    "configured-overlay.json",
    "configured-overlay/config/windows_factory_manifest.json",
    "configured-overlay/config/windows_service_config.json",
    "configured-overlay/configured_providers/__init__.py",
    "configured-overlay/configured_providers/decision_provider.py",
    "configured-overlay/reviewed_windows_factory.py",
    "decision-configured-v1.zip",
    "decision-configured-v1.zip.manifest.json",
    "decision-factory-template.json",
    "provider-pack/config/windows_service_config.json",
    "provider-pack/configured_providers/__init__.py",
    "provider-pack/configured_providers/decision_provider.py",
    "provider-pack/reviewed_windows_factory.py",
    "reviewed-task-definition.xml",
}


class WindowsDecisionConfiguredCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = (
            provider_fixture_module.WindowsDecisionProviderPackGeneratorTests(
            methodName="runTest"
            )
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self._provider_fixture = fixture
        self.root = fixture.root
        self.suite_root = fixture.suite_root
        self.decision_base = fixture.decision_base

    def _prepare(self, name: str):
        return self._provider_fixture._prepare(name)

    def _candidate(
        self,
        name: str,
        *,
        pack_name: str | None = None,
    ):
        pack = self._prepare(pack_name or f"{name}-provider-pack")
        pack_root = Path(pack.output_root)
        before = {
            item.relative_to(pack_root).as_posix(): item.read_bytes()
            for item in pack_root.rglob("*")
            if item.is_file()
        }
        task = self.root / f"{name}-task.xml"
        task.write_bytes(
            b"<Task><Enabled>false</Enabled>"
            b"<Principal>decision-service</Principal></Task>\n"
        )
        output = self.root / name
        result = assemble_windows_decision_configured_candidate(
            base_suite_root=self.suite_root,
            decision_base_release=self.decision_base,
            provider_pack_root=pack_root,
            task_definition_path=task,
            candidate_id="decision-demo-auto-window-01",
            output_root=output,
        )
        after = {
            item.relative_to(pack_root).as_posix(): item.read_bytes()
            for item in pack_root.rglob("*")
            if item.is_file()
        }
        self.assertEqual(before, after)
        original = validate_windows_decision_provider_pack(
            base_suite_root=self.suite_root,
            decision_base_release=self.decision_base,
            pack_root=pack_root,
        )
        self.assertEqual(
            pack.pack_identity_sha256,
            original.pack_identity_sha256,
        )
        return result, output, pack_root, task

    def test_exact_candidate_is_deterministic_and_fully_validated(self):
        first, first_root, _first_pack, _first_task = self._candidate(
            "candidate-first"
        )
        second, second_root, _second_pack, _second_task = self._candidate(
            "candidate-second"
        )
        first_files = {
            item.relative_to(first_root).as_posix(): item.read_bytes()
            for item in first_root.rglob("*")
            if item.is_file()
        }
        second_files = {
            item.relative_to(second_root).as_posix(): item.read_bytes()
            for item in second_root.rglob("*")
            if item.is_file()
        }
        self.assertEqual(EXPECTED_RELATIVE_FILES, set(first_files))
        self.assertEqual(first_files, second_files)
        self.assertEqual(
            first.content_sha256,
            second.content_sha256,
        )
        validated = validate_windows_decision_configured_candidate(
            base_suite_root=self.suite_root,
            decision_base_release=self.decision_base,
            candidate_root=first_root,
        )
        self.assertEqual(first.content_sha256, validated.content_sha256)
        self.assertEqual(
            "EXTERNAL_PROVIDER_CONFORMANCE_REQUIRED",
            validated.status,
        )
        self.assertEqual(7, validated.provider_count)
        self.assertFalse(validated.provider_accepted)
        self.assertFalse(validated.production_execution_ready)
        self.assertFalse(validated.live_allowed)
        self.assertFalse(validated.safe_to_demo_auto_order)
        self.assertEqual(0.01, validated.max_lot)

    def test_bootstrap_template_and_suite_binding_are_derived(self):
        result, root, _pack, _task = self._candidate(
            "derived-bindings"
        )
        runtime = parse_windows_decision_service_runtime_config(json.loads(
            (
                root
                / "provider-pack/config/windows_service_config.json"
            ).read_text("utf-8")
        ))
        self.assertEqual(
            runtime.decision_producer_binding.content_sha256,
            result.bootstrap_binding_sha256,
        )
        template_payload = json.loads(
            (root / "decision-factory-template.json").read_text(
                "utf-8"
            )
        )
        template = validate_windows_decision_service_factory_template(
            template_payload,
            expected_release_identity_sha256=(
                result.configured_release_identity_sha256
            ),
        )
        self.assertEqual(7, len(template.providers))
        configured = verify_configured_service_release(
            root / "decision-configured-v1.zip",
            expected_release_identity_sha256=(
                result.configured_release_identity_sha256
            ),
        )
        self.assertTrue(configured.base_release_suite_bound)
        self.assertEqual("DECISION", configured.base_release_suite_role)
        self.assertEqual(
            result.base_suite_identity_sha256,
            configured.base_release_suite_identity_sha256,
        )
        extracted = self.root / "suite-bound-runtime-extracted"
        with zipfile.ZipFile(root / "decision-configured-v1.zip") as archive:
            archive.extractall(extracted)
        manifest, _runtime, context = (
            validate_reviewed_windows_decision_service_factory_manifest(
                release_root=extracted,
                manifest_path=(
                    extracted / "config/windows_factory_manifest.json"
                ),
                expected_release_identity_sha256=(
                    result.configured_release_identity_sha256
                ),
            )
        )
        self.assertEqual("WINDOWS_DECISION_SERVICE_V1", manifest.release_profile)
        self.assertEqual(
            result.configured_release_identity_sha256,
            context.release_identity_sha256,
        )

    def test_existing_destination_and_mid_assembly_failure_preserve_inputs(
        self,
    ):
        pack = self._prepare("failure-pack")
        pack_root = Path(pack.output_root)
        before = {
            item.relative_to(pack_root).as_posix(): item.read_bytes()
            for item in pack_root.rglob("*")
            if item.is_file()
        }
        task = self.root / "failure-task.xml"
        task.write_bytes(b"<Task><Enabled>false</Enabled></Task>\n")
        existing = self.root / "existing-candidate"
        existing.mkdir()
        marker = existing / "marker"
        marker.write_bytes(b"preserve")
        with self.assertRaises(DecisionConfiguredCandidateError) as raised:
            assemble_windows_decision_configured_candidate(
                base_suite_root=self.suite_root,
                decision_base_release=self.decision_base,
                provider_pack_root=pack_root,
                task_definition_path=task,
                candidate_id="decision-demo-auto-window-01",
                output_root=existing,
            )
        self.assertEqual(
            "CANDIDATE_OUTPUT_ALREADY_EXISTS",
            raised.exception.reason_code,
        )
        self.assertEqual(b"preserve", marker.read_bytes())

        overlapped = pack_root / "candidate"
        with self.assertRaises(DecisionConfiguredCandidateError) as raised:
            assemble_windows_decision_configured_candidate(
                base_suite_root=self.suite_root,
                decision_base_release=self.decision_base,
                provider_pack_root=pack_root,
                task_definition_path=task,
                candidate_id="decision-demo-auto-window-01",
                output_root=overlapped,
            )
        self.assertEqual(
            "CANDIDATE_OUTPUT_INPUT_OVERLAP",
            raised.exception.reason_code,
        )
        self.assertFalse(overlapped.exists())

        secret_task = self.root / "secret-task.xml"
        secret_task.write_bytes(
            b"<Task>-----BEGIN PRIVATE KEY-----</Task>\n"
        )
        secret_output = self.root / "secret-candidate"
        with self.assertRaises(DecisionConfiguredCandidateError) as raised:
            assemble_windows_decision_configured_candidate(
                base_suite_root=self.suite_root,
                decision_base_release=self.decision_base,
                provider_pack_root=pack_root,
                task_definition_path=secret_task,
                candidate_id="decision-demo-auto-window-01",
                output_root=secret_output,
            )
        self.assertEqual(
            "TASK_DEFINITION_SECRET_MATERIAL_FORBIDDEN",
            raised.exception.reason_code,
        )
        self.assertFalse(secret_output.exists())

        failed = self.root / "failed-candidate"
        with patch(
            "live_runtime.windows_decision_configured_candidate."
            "build_configured_service_release",
            side_effect=RuntimeError("injected"),
        ):
            with self.assertRaises(RuntimeError):
                assemble_windows_decision_configured_candidate(
                    base_suite_root=self.suite_root,
                    decision_base_release=self.decision_base,
                    provider_pack_root=pack_root,
                    task_definition_path=task,
                    candidate_id="decision-demo-auto-window-01",
                    output_root=failed,
                )
        self.assertFalse(failed.exists())
        after = {
            item.relative_to(pack_root).as_posix(): item.read_bytes()
            for item in pack_root.rglob("*")
            if item.is_file()
        }
        self.assertEqual(before, after)
        validate_windows_decision_provider_pack(
            base_suite_root=self.suite_root,
            decision_base_release=self.decision_base,
            pack_root=pack_root,
        )

    def test_tamper_extra_missing_and_symlink_fail_closed(self):
        _result, root, _pack, _task = self._candidate("tamper")
        target = root / "decision-factory-template.json"
        original = target.read_bytes()
        target.write_bytes(original + b" ")
        with self.assertRaises(DecisionConfiguredCandidateError):
            validate_windows_decision_configured_candidate(
                base_suite_root=self.suite_root,
                decision_base_release=self.decision_base,
                candidate_root=root,
            )
        target.write_bytes(original)

        extra = root / "extra.txt"
        extra.write_bytes(b"extra")
        with self.assertRaises(DecisionConfiguredCandidateError):
            validate_windows_decision_configured_candidate(
                base_suite_root=self.suite_root,
                decision_base_release=self.decision_base,
                candidate_root=root,
            )
        extra.unlink()

        receipt = root / CANDIDATE_RECEIPT_NAME
        receipt_bytes = receipt.read_bytes()
        receipt.unlink()
        with self.assertRaises(DecisionConfiguredCandidateError):
            validate_windows_decision_configured_candidate(
                base_suite_root=self.suite_root,
                decision_base_release=self.decision_base,
                candidate_root=root,
            )
        receipt.write_bytes(receipt_bytes)

        provider = (
            root / "provider-pack/configured_providers/decision_provider.py"
        )
        provider_bytes = provider.read_bytes()
        provider.unlink()
        try:
            provider.symlink_to(
                root
                / "configured-overlay/configured_providers/"
                "decision_provider.py"
            )
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unavailable")
        with self.assertRaises(DecisionConfiguredCandidateError):
            validate_windows_decision_configured_candidate(
                base_suite_root=self.suite_root,
                decision_base_release=self.decision_base,
                candidate_root=root,
            )
        provider.unlink()
        provider.write_bytes(provider_bytes)

    def test_candidate_receipt_cannot_self_attest_or_relax_safety(self):
        _result, root, _pack, _task = self._candidate("receipt-tamper")
        receipt = root / CANDIDATE_RECEIPT_NAME
        payload = json.loads(receipt.read_text("utf-8"))
        payload["provider_accepted"] = True
        unsigned = dict(payload)
        unsigned.pop("content_sha256")
        import hashlib

        unsigned_bytes = json.dumps(
            unsigned,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        payload["content_sha256"] = hashlib.sha256(
            unsigned_bytes
        ).hexdigest()
        receipt.write_text(
            json.dumps(
                payload,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(DecisionConfiguredCandidateError):
            validate_windows_decision_configured_candidate(
                base_suite_root=self.suite_root,
                decision_base_release=self.decision_base,
                candidate_root=root,
            )

    def test_no_provider_or_credential_materialization_occurs(self):
        from live_runtime.windows_decision_provider_pack import (
            _WindowsNativeCredentialBackend,
        )

        with patch.object(
            _WindowsNativeCredentialBackend,
            "read_blob",
            side_effect=AssertionError("credential access forbidden"),
        ):
            result, root, _pack, _task = self._candidate(
                "no-materialization"
            )
            validate_windows_decision_configured_candidate(
                base_suite_root=self.suite_root,
                decision_base_release=self.decision_base,
                candidate_root=root,
            )
        self.assertFalse(result.credential_access_performed)
        self.assertFalse(result.provider_imported)
        self.assertFalse(result.provider_materialized)
        self.assertFalse(result.task_installation_performed)
        self.assertFalse(result.broker_mutation_performed)

    def test_cli_surface_is_exact_and_deny_only(self):
        assemble_args = {
            item.dest
            for item in assemble_parser()._actions
            if item.dest != "help"
        }
        self.assertEqual(
            {
                "base_suite_root",
                "decision_base_release",
                "provider_pack_root",
                "task_definition",
                "candidate_id",
                "output_root",
            },
            assemble_args,
        )
        validate_args = {
            item.dest
            for item in validate_parser()._actions
            if item.dest != "help"
        }
        self.assertEqual(
            {
                "base_suite_root",
                "decision_base_release",
                "candidate_root",
            },
            validate_args,
        )
        forbidden = {
            "password",
            "login",
            "secret",
            "private_key",
            "permit",
            "arm",
            "order",
            "activation",
            "bootstrap_binding_sha256",
        }
        self.assertTrue(assemble_args.isdisjoint(forbidden))
        self.assertTrue(validate_args.isdisjoint(forbidden))

        pack = self._prepare("cli-input-pack")
        task = self.root / "cli-task.xml"
        task.write_bytes(b"<Task><Enabled>false</Enabled></Task>\n")
        output = self.root / "cli-candidate"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = assemble_main(
                [
                    "--base-suite-root",
                    str(self.suite_root),
                    "--decision-base-release",
                    str(self.decision_base),
                    "--provider-pack-root",
                    str(pack.output_root),
                    "--task-definition",
                    str(task),
                    "--candidate-id",
                    "decision-demo-auto-window-01",
                    "--output-root",
                    str(output),
                ]
            )
        self.assertEqual(0, status, stderr.getvalue())
        self.assertIn(
            "EXTERNAL_PROVIDER_CONFORMANCE_REQUIRED",
            stdout.getvalue(),
        )
        self.assertIn("Order capability: DISABLED", stdout.getvalue())
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = validate_main(
                [
                    "--base-suite-root",
                    str(self.suite_root),
                    "--decision-base-release",
                    str(self.decision_base),
                    "--candidate-root",
                    str(output),
                ]
            )
        self.assertEqual(0, status, stderr.getvalue())
        self.assertIn(
            "WINDOWS_DECISION_CONFIGURED_CANDIDATE_VALID",
            stdout.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
