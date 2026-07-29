from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
import warnings
import zipfile

from live_runtime.windows_execution_provider_pack_generator import (
    prepare_windows_live_canary_execution_provider_pack,
)
from live_runtime.windows_live_canary_execution_configured_candidate import (
    assemble_windows_live_canary_execution_configured_candidate,
)
from live_runtime.windows_live_canary_execution_source_bound_candidate import (
    ARCHIVE_MEMBERS,
    FIXED_ZIP_MODE,
    FIXED_ZIP_TIMESTAMP,
    MANIFEST_MEMBER,
    SAFETY,
    WindowsLiveCanaryExecutionSourceBoundCandidateError,
    WindowsLiveCanaryExecutionSourceBoundCandidateVerification,
    prepare_windows_live_canary_execution_source_bound_candidate,
    verify_windows_live_canary_execution_source_bound_candidate,
)
from prepare_windows_live_canary_execution_source_bound_candidate import (
    _parser as prepare_parser,
    main as prepare_main,
)
import test_live_runtime_windows_execution_source_bound_candidate as source_fixture
from test_live_runtime_windows_live_canary_execution_configured_candidate import (
    EXPECTED_FILES as LIVE_CANDIDATE_FILES,
)
import test_live_runtime_windows_live_canary_execution_provider_pack_generator as live_pack_fixture
from validate_windows_live_canary_execution_source_bound_candidate import (
    _parser as verify_parser,
    main as verify_main,
)


def rewrite_archive(
    data: bytes,
    *,
    replacements: dict[str, bytes] | None = None,
    extra: tuple[str, bytes] | None = None,
    duplicate: tuple[str, bytes] | None = None,
    timestamp: tuple[int, int, int, int, int, int] = FIXED_ZIP_TIMESTAMP,
) -> bytes:
    replacements = replacements or {}
    with zipfile.ZipFile(io.BytesIO(data), "r") as original:
        members = {name: original.read(name) for name in original.namelist()}
    members.update(replacements)
    if extra is not None:
        members[extra[0]] = extra[1]
    destination = io.BytesIO()
    with zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, timestamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = FIXED_ZIP_MODE << 16
            archive.writestr(info, members[name])
        if duplicate is not None:
            info = zipfile.ZipInfo(duplicate[0], timestamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = FIXED_ZIP_MODE << 16
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr(info, duplicate[1])
    return destination.getvalue()


class WindowsLiveCanaryExecutionSourceBoundCandidateTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        live_fixture = (
            live_pack_fixture.WindowsLiveCanaryExecutionProviderPackGeneratorTests(
                methodName="runTest"
            )
        )
        live_fixture.setUp()
        self.addCleanup(live_fixture.doCleanups)
        fixture = source_fixture.WindowsExecutionSourceBoundCandidateTests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.suite_root = live_fixture.suite_root
        fixture.execution_base = live_fixture.execution_base
        fixture.suite_identity = str(
            live_fixture.suite_manifest["suite_identity_sha256"]
        )
        fixture.pack_root, fixture.candidate_root, fixture.candidate = (
            fixture._candidate("shared-live-suite-demo")
        )
        self.fixture = fixture
        self.root = fixture.root
        self.suite_root = fixture.suite_root
        self.execution_base = fixture.execution_base
        self.source_bound_path = self.root / "demo-source-bound.zip"
        self.source_bound = fixture.prepare(self.source_bound_path)
        self.live_candidate_root = self._live_candidate(
            "live-valid",
            source_sha256=fixture.source_report.archive_sha256,
            bootstrap_sha256=fixture.source_report.bootstrap_binding_sha256,
        )

    def source_pins(self) -> dict[str, str]:
        return {
            "expected_source_bound_archive_sha256": (
                self.source_bound.archive_sha256
            ),
            **self.fixture.verification_pins(),
        }

    def _live_pack_input(self, name: str, source_sha256: str) -> Path:
        live_fixture = (
            live_pack_fixture.WindowsLiveCanaryExecutionProviderPackGeneratorTests(
                methodName="runTest"
            )
        )
        payload = live_fixture._pack_payload()
        payload["provider_configuration"]["production_config_sha256"] = (
            source_sha256
        )
        path = self.root / f"{name}-live-pack-input.json"
        path.write_bytes(source_fixture.canonical_file(payload))
        return path

    def _live_candidate_input(self, name: str, bootstrap_sha256: str) -> Path:
        path = self.root / f"{name}-live-candidate-input.json"
        path.write_bytes(
            source_fixture.canonical_file(
                {
                    "bootstrap_binding_sha256": bootstrap_sha256,
                    "schema_version": (
                        "windows-live-canary-execution-"
                        "configured-candidate-input-v1"
                    ),
                    "task_scheduler": {
                        "acl_policy_sha256": live_pack_fixture.digest(
                            "live-task-acl"
                        ),
                        "host_identity_sha256": live_pack_fixture.digest(
                            "live-host"
                        ),
                        "launcher_path_sha256": live_pack_fixture.digest(
                            "live-launcher"
                        ),
                        "logon_type": "SERVICE_ACCOUNT",
                        "multiple_instances_policy": "IGNORE_NEW",
                        "release_root_path_sha256": live_pack_fixture.digest(
                            "live-release-root"
                        ),
                        "run_level": "LIMITED",
                        "service_account_principal_sha256": live_pack_fixture.digest(
                            "live-service-principal"
                        ),
                        "service_account_sid_sha256": live_pack_fixture.digest(
                            "live-service-sid"
                        ),
                        "task_path": (
                            r"\AI_SCALPER\ExecutionLiveCanaryWindow01"
                        ),
                    },
                }
            )
        )
        return path

    def _live_candidate(
        self,
        name: str,
        *,
        source_sha256: str,
        bootstrap_sha256: str,
    ) -> Path:
        pack_root = self.root / f"{name}-pack"
        prepare_windows_live_canary_execution_provider_pack(
            base_suite_root=self.suite_root,
            execution_base_release=self.execution_base,
            pack_input_path=self._live_pack_input(name, source_sha256),
            output_root=pack_root,
        )
        task = self.root / f"{name}-task.xml"
        task.write_bytes(
            b"<Task><Enabled>false</Enabled>"
            b"<Principal>live-execution-service</Principal></Task>\n"
        )
        candidate_root = self.root / f"{name}-candidate"
        assemble_windows_live_canary_execution_configured_candidate(
            base_suite_root=self.suite_root,
            execution_base_release=self.execution_base,
            provider_pack_root=pack_root,
            task_definition_path=task,
            candidate_input_path=self._live_candidate_input(
                name,
                bootstrap_sha256,
            ),
            candidate_id="xm-live-canary-window-01",
            output_root=candidate_root,
        )
        return candidate_root

    def prepare(self, output: Path):
        return prepare_windows_live_canary_execution_source_bound_candidate(
            base_suite_root=self.suite_root,
            execution_base_release=self.execution_base,
            demo_source_bound_archive=self.source_bound_path,
            live_configured_candidate_root=self.live_candidate_root,
            output=output,
            **self.source_pins(),
        )

    def test_ac1_exact_deterministic_archive_is_deny_only(self):
        first_path = self.root / "live-source-bound-first.zip"
        second_path = self.root / "live-source-bound-second.zip"
        first = self.prepare(first_path)
        second = self.prepare(second_path)
        self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
        self.assertEqual(first, second)
        self.assertEqual(SAFETY, first.safety)
        self.assertEqual(first.runtime_mode, "LIVE")
        self.assertEqual(first.provider_count, 49)
        self.assertEqual(first.credential_reference_count, 12)
        self.assertFalse(first.provider_accepted)
        self.assertFalse(first.production_execution_ready)
        self.assertFalse(first.live_allowed)
        self.assertEqual(first.order_capability, "DISABLED")
        with zipfile.ZipFile(first_path, "r") as archive:
            self.assertEqual(ARCHIVE_MEMBERS, tuple(archive.namelist()))
            manifest = json.loads(archive.read(MANIFEST_MEMBER))
        self.assertEqual(17, len(ARCHIVE_MEMBERS))
        self.assertEqual(SAFETY, manifest["safety"])
        self.assertEqual(
            {f"candidate/{path}" for path in LIVE_CANDIDATE_FILES},
            {
                name
                for name in ARCHIVE_MEMBERS
                if name.startswith("candidate/")
            },
        )

    def test_ac2_ten_pin_verifier_reconstructs_cross_bindings(self):
        output = self.root / "live-source-bound.zip"
        prepared = self.prepare(output)
        verified = verify_windows_live_canary_execution_source_bound_candidate(
            output,
            base_suite_root=self.suite_root,
            execution_base_release=self.execution_base,
            expected_live_bound_archive_sha256=prepared.archive_sha256,
            **self.source_pins(),
        )
        self.assertEqual(prepared, verified)
        self.assertEqual(
            self.fixture.source_report.archive_sha256,
            verified.production_config_sha256,
        )
        self.assertEqual(
            self.fixture.source_report.bootstrap_binding_sha256,
            verified.bootstrap_binding_sha256,
        )
        self.assertEqual(
            self.source_bound.binding_identity_sha256,
            verified.source_bound_binding_identity_sha256,
        )
        with self.assertRaises(TypeError):
            WindowsLiveCanaryExecutionSourceBoundCandidateVerification(
                archive_path=output,
                archive_sha256="1" * 64,
                archive_size_bytes=1,
                binding_identity_sha256="2" * 64,
                source_bound_archive_sha256="3" * 64,
                source_bound_binding_identity_sha256="4" * 64,
                source_archive_sha256="5" * 64,
                bootstrap_binding_sha256="6" * 64,
                candidate_id="candidate",
                candidate_content_sha256="7" * 64,
                production_config_sha256="8" * 64,
                provider_pack_identity_sha256="9" * 64,
                provider_configuration_sha256="a" * 64,
                live_provider_contract_set_sha256="b" * 64,
                configured_release_identity_sha256="c" * 64,
                configured_archive_sha256="d" * 64,
                execution_factory_template_sha256="e" * 64,
                task_definition_sha256="f" * 64,
                suite_identity_sha256="1" * 64,
                execution_base_archive_sha256="2" * 64,
                execution_base_release_identity_sha256="3" * 64,
                git_commit="4" * 40,
                git_tree="5" * 40,
                provider_count=49,
                credential_reference_count=12,
            )

    def test_ac3_source_and_bootstrap_mismatch_reject_before_output(self):
        cases = (
            (
                "source",
                live_pack_fixture.digest("unrelated-live-source"),
                self.fixture.source_report.bootstrap_binding_sha256,
                "LIVE_BOUND_SOURCE_PROVIDER_MISMATCH",
            ),
            (
                "bootstrap",
                self.fixture.source_report.archive_sha256,
                live_pack_fixture.digest("unrelated-live-bootstrap"),
                "LIVE_BOUND_SOURCE_BOOTSTRAP_MISMATCH",
            ),
        )
        for name, source, bootstrap, reason in cases:
            with self.subTest(name=name):
                candidate = self._live_candidate(
                    f"mismatch-{name}",
                    source_sha256=source,
                    bootstrap_sha256=bootstrap,
                )
                output = self.root / f"mismatch-{name}.zip"
                with self.assertRaisesRegex(
                    WindowsLiveCanaryExecutionSourceBoundCandidateError,
                    reason,
                ):
                    prepare_windows_live_canary_execution_source_bound_candidate(
                        base_suite_root=self.suite_root,
                        execution_base_release=self.execution_base,
                        demo_source_bound_archive=self.source_bound_path,
                        live_configured_candidate_root=candidate,
                        output=output,
                        **self.source_pins(),
                    )
                self.assertFalse(output.exists())

    def test_ac4_existing_output_wrong_pin_and_symlink_are_preserved(self):
        existing = self.root / "existing.zip"
        existing.write_bytes(b"preserve")
        with self.assertRaisesRegex(
            WindowsLiveCanaryExecutionSourceBoundCandidateError,
            "LIVE_BOUND_DESTINATION_INVALID",
        ):
            self.prepare(existing)
        self.assertEqual(b"preserve", existing.read_bytes())
        with self.assertRaisesRegex(
            WindowsLiveCanaryExecutionSourceBoundCandidateError,
            "LIVE_BOUND_EXTERNAL_PIN_INVALID",
        ):
            prepare_windows_live_canary_execution_source_bound_candidate(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                demo_source_bound_archive=self.source_bound_path,
                live_configured_candidate_root=self.live_candidate_root,
                output=self.root / "wrong-pin.zip",
                **{
                    **self.source_pins(),
                    "expected_suite_identity_sha256": "0" * 64,
                },
            )
        linked = self.root / "linked-source-bound.zip"
        try:
            linked.symlink_to(self.source_bound_path)
        except OSError:
            self.skipTest("symlink creation is unavailable")
        with self.assertRaisesRegex(
            WindowsLiveCanaryExecutionSourceBoundCandidateError,
            "LIVE_BOUND_INPUT_INVALID",
        ):
            prepare_windows_live_canary_execution_source_bound_candidate(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                demo_source_bound_archive=linked,
                live_configured_candidate_root=self.live_candidate_root,
                output=self.root / "linked-output.zip",
                **self.source_pins(),
            )

    def test_ac5_adversarial_outer_archive_rejects_with_updated_pin(self):
        output = self.root / "valid-live-source-bound.zip"
        self.prepare(output)
        original = output.read_bytes()
        with zipfile.ZipFile(io.BytesIO(original), "r") as archive:
            manifest = archive.read(MANIFEST_MEMBER)
        wrong_safety = json.loads(manifest)
        wrong_safety["safety"]["provider_accepted"] = 0
        unsigned = dict(wrong_safety)
        unsigned.pop("binding_identity_sha256")
        wrong_safety["binding_identity_sha256"] = hashlib.sha256(
            json.dumps(
                unsigned,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        candidate_member = f"candidate/{sorted(LIVE_CANDIDATE_FILES)[0]}"
        cases = {
            "trailer": original + b"trailer",
            "extra": rewrite_archive(original, extra=("extra.txt", b"x")),
            "traversal": rewrite_archive(
                original,
                extra=("../outside.txt", b"x"),
            ),
            "casefold": rewrite_archive(
                original,
                extra=(candidate_member.upper(), b"x"),
            ),
            "duplicate": rewrite_archive(
                original,
                duplicate=(candidate_member, b"x"),
            ),
            "timestamp": rewrite_archive(
                original,
                timestamp=(1980, 1, 2, 0, 0, 0),
            ),
            "noncanonical-manifest": rewrite_archive(
                original,
                replacements={
                    MANIFEST_MEMBER: json.dumps(json.loads(manifest)).encode()
                },
            ),
            "safety-type": rewrite_archive(
                original,
                replacements={
                    MANIFEST_MEMBER: source_fixture.canonical_file(
                        wrong_safety
                    )
                },
            ),
        }
        for name, data in cases.items():
            with self.subTest(name=name):
                path = self.root / f"adversarial-{name}.zip"
                path.write_bytes(data)
                with self.assertRaises(
                    WindowsLiveCanaryExecutionSourceBoundCandidateError
                ):
                    verify_windows_live_canary_execution_source_bound_candidate(
                        path,
                        base_suite_root=self.suite_root,
                        execution_base_release=self.execution_base,
                        expected_live_bound_archive_sha256=hashlib.sha256(
                            data
                        ).hexdigest(),
                        **self.source_pins(),
                    )

    def test_ac6_cli_surface_is_isolated_and_deny_only(self):
        forbidden = {
            "--account-login",
            "--arm",
            "--central-unlock",
            "--credential",
            "--order",
            "--password",
            "--permit",
            "--provider-accepted",
        }
        prepare_options = {
            option
            for action in prepare_parser()._actions
            for option in action.option_strings
        }
        verify_options = {
            option
            for action in verify_parser()._actions
            for option in action.option_strings
        }
        self.assertTrue(forbidden.isdisjoint(prepare_options))
        self.assertTrue(forbidden.isdisjoint(verify_options))
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(2, prepare_main([]))
            self.assertEqual(2, verify_main([]))

        repository = Path(__file__).resolve().parent
        output = self.root / "cli-live-source-bound.zip"
        common = (
            "--base-suite-root",
            str(self.suite_root),
            "--execution-base-release",
            str(self.execution_base),
            "--expected-source-bound-archive-sha256",
            self.source_bound.archive_sha256,
            "--expected-source-archive-sha256",
            self.fixture.source_report.archive_sha256,
            "--expected-champion-archive-sha256",
            str(self.fixture.champion["archive_sha256"]),
            "--expected-model-artifact-sha256",
            str(self.fixture.champion["model_artifact_sha256"]),
            "--expected-training-snapshot-sha256",
            str(self.fixture.champion["training_snapshot_sha256"]),
            "--expected-config-sha256",
            str(self.fixture.champion["config_sha256"]),
            "--expected-git-commit",
            source_fixture.COMMIT,
            "--expected-git-tree",
            source_fixture.TREE,
            "--expected-suite-identity-sha256",
            self.fixture.suite_identity,
        )
        prepared = subprocess.run(
            (
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(
                    repository
                    / "prepare_windows_live_canary_execution_source_bound_candidate.py"
                ),
                *common,
                "--demo-source-bound-archive",
                str(self.source_bound_path),
                "--live-configured-candidate-root",
                str(self.live_candidate_root),
                "--output",
                str(output),
            ),
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(0, prepared.returncode, prepared.stderr)
        self.assertIn(
            "WINDOWS_LIVE_CANARY_EXECUTION_SOURCE_BOUND_CANDIDATE_READY",
            prepared.stdout,
        )
        verified = subprocess.run(
            (
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(
                    repository
                    / "validate_windows_live_canary_execution_source_bound_candidate.py"
                ),
                *common,
                "--archive",
                str(output),
                "--expected-live-bound-archive-sha256",
                hashlib.sha256(output.read_bytes()).hexdigest(),
            ),
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(0, verified.returncode, verified.stderr)
        self.assertIn(
            "WINDOWS_LIVE_CANARY_EXECUTION_SOURCE_BOUND_CANDIDATE_VERIFIED",
            verified.stdout,
        )
        self.assertIn("Order capability: DISABLED", verified.stdout)


if __name__ == "__main__":
    unittest.main()
