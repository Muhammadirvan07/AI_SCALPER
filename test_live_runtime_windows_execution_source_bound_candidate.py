from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile

from live_runtime.windows_execution_configured_candidate import (
    assemble_windows_execution_configured_candidate,
)
from live_runtime.windows_execution_production_config_source import (
    canonical_source_file,
    prepare_windows_execution_production_config_source,
)
from live_runtime.windows_execution_provider_pack_generator import (
    prepare_windows_execution_provider_pack,
)
from live_runtime.windows_execution_source_bound_candidate import (
    ARCHIVE_MEMBERS,
    FIXED_ZIP_MODE,
    FIXED_ZIP_TIMESTAMP,
    MANIFEST_MEMBER,
    SAFETY,
    WindowsExecutionSourceBoundCandidateError,
    WindowsExecutionSourceBoundCandidateVerification,
    prepare_windows_execution_source_bound_candidate,
    verify_windows_execution_source_bound_candidate,
)
import test_live_runtime_windows_execution_provider_pack_generator as provider_fixture
from test_live_runtime_windows_execution_configured_candidate import (
    EXPECTED_FILES as CONFIGURED_CANDIDATE_FILES,
)
from test_live_runtime_windows_execution_production_config_source import (
    champion_fixture,
    config_fixture,
    stage_document,
    stage_fixture,
)


COMMIT = "1" * 40
TREE = "2" * 40


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_file(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"


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


class WindowsExecutionSourceBoundCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = provider_fixture.WindowsExecutionProviderPackGeneratorTests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.root
        self.suite_root = fixture.suite_root
        self.execution_base = fixture.execution_base
        self.suite_identity = str(
            fixture.suite_manifest["suite_identity_sha256"]
        )
        self.champion_bytes, self.champion = champion_fixture(
            commit=COMMIT,
            tree=TREE,
        )
        self.stage = stage_fixture(
            self.champion,
            commit=COMMIT,
            tree=TREE,
        )
        self.config = config_fixture(self.root, self.stage)
        self.config_path = self.root / "production-config.json"
        self.stage_path = self.root / "stage-binding.json"
        self.champion_path = self.root / "champion.zip"
        self.source_path = self.root / "production-source.zip"
        self.config_path.write_bytes(
            canonical_source_file(self.config.reviewed_configuration_payload)
        )
        self.stage_path.write_bytes(
            canonical_source_file(stage_document(self.stage))
        )
        self.champion_path.write_bytes(self.champion_bytes)
        self.source_report = (
            prepare_windows_execution_production_config_source(
                production_config_path=self.config_path,
                stage_binding_path=self.stage_path,
                champion_artifact_path=self.champion_path,
                output=self.source_path,
                **self.source_prepare_pins(),
            )
        )
        self.pack_root, self.candidate_root, self.candidate = (
            self._candidate("valid")
        )

    def source_prepare_pins(self) -> dict[str, str]:
        return {
            "expected_champion_archive_sha256": str(
                self.champion["archive_sha256"]
            ),
            "expected_model_artifact_sha256": str(
                self.champion["model_artifact_sha256"]
            ),
            "expected_training_snapshot_sha256": str(
                self.champion["training_snapshot_sha256"]
            ),
            "expected_config_sha256": str(self.champion["config_sha256"]),
            "expected_git_commit": COMMIT,
            "expected_git_tree": TREE,
        }

    def verification_pins(self) -> dict[str, str]:
        return {
            "expected_source_archive_sha256": (
                self.source_report.archive_sha256
            ),
            **self.source_prepare_pins(),
            "expected_suite_identity_sha256": self.suite_identity,
        }

    def _candidate_input(self, name: str, bootstrap: str) -> Path:
        path = self.root / f"{name}-candidate-input.json"
        path.write_bytes(
            canonical_file(
                {
                    "bootstrap_binding_sha256": bootstrap,
                    "schema_version": (
                        "windows-execution-configured-candidate-input-v1"
                    ),
                    "task_scheduler": {
                        "acl_policy_sha256": digest("task-acl"),
                        "host_identity_sha256": digest("windows-host"),
                        "launcher_path_sha256": digest("launcher-path"),
                        "logon_type": "SERVICE_ACCOUNT",
                        "multiple_instances_policy": "IGNORE_NEW",
                        "release_root_path_sha256": digest(
                            "release-root-path"
                        ),
                        "run_level": "LIMITED",
                        "service_account_principal_sha256": digest(
                            "service-account-principal"
                        ),
                        "service_account_sid_sha256": digest(
                            "service-account-sid"
                        ),
                        "task_path": r"\AI_SCALPER\ExecutionDemoWindow01",
                    },
                }
            )
        )
        return path

    def _pack_input(self, name: str, source_sha256: str) -> Path:
        payload = json.loads(self.fixture.pack_input.read_text("utf-8"))
        payload["provider_configuration"]["production_config_sha256"] = (
            source_sha256
        )
        path = self.root / f"{name}-pack-input.json"
        path.write_bytes(canonical_file(payload))
        return path

    def _candidate(
        self,
        name: str,
        *,
        source_sha256: str | None = None,
        bootstrap_sha256: str | None = None,
    ):
        source_sha256 = (
            self.source_report.archive_sha256
            if source_sha256 is None
            else source_sha256
        )
        bootstrap_sha256 = (
            self.source_report.bootstrap_binding_sha256
            if bootstrap_sha256 is None
            else bootstrap_sha256
        )
        pack_root = self.root / f"{name}-pack"
        prepare_windows_execution_provider_pack(
            base_suite_root=self.suite_root,
            execution_base_release=self.execution_base,
            pack_input_path=self._pack_input(name, source_sha256),
            output_root=pack_root,
        )
        task = self.root / f"{name}-task.xml"
        task.write_bytes(
            b"<Task><Enabled>false</Enabled>"
            b"<Principal>execution-service</Principal></Task>\n"
        )
        candidate_root = self.root / f"{name}-candidate"
        candidate = assemble_windows_execution_configured_candidate(
            base_suite_root=self.suite_root,
            execution_base_release=self.execution_base,
            provider_pack_root=pack_root,
            task_definition_path=task,
            candidate_input_path=self._candidate_input(
                name,
                bootstrap_sha256,
            ),
            candidate_id="execution-demo-window-01",
            output_root=candidate_root,
        )
        return pack_root, candidate_root, candidate

    def prepare(self, output: Path):
        return prepare_windows_execution_source_bound_candidate(
            base_suite_root=self.suite_root,
            execution_base_release=self.execution_base,
            production_config_source_archive=self.source_path,
            configured_candidate_root=self.candidate_root,
            output=output,
            **self.verification_pins(),
        )

    def test_deterministic_exact_inventory_and_deny_only_result(self):
        first = self.root / "bound-first.zip"
        second = self.root / "bound-second.zip"
        first_result = self.prepare(first)
        second_result = self.prepare(second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first_result, second_result)
        self.assertEqual(SAFETY, first_result.safety)
        self.assertFalse(first_result.provider_accepted)
        self.assertFalse(first_result.production_execution_ready)
        self.assertEqual("DISABLED", first_result.order_capability)
        with zipfile.ZipFile(first, "r") as archive:
            self.assertEqual(ARCHIVE_MEMBERS, tuple(archive.namelist()))
            manifest = json.loads(archive.read(MANIFEST_MEMBER))
        expected_candidate = {
            f"candidate/{path}" for path in CONFIGURED_CANDIDATE_FILES
        }
        self.assertEqual(
            {MANIFEST_MEMBER, "source/windows-execution-production-config-source-v1.zip", *expected_candidate},
            set(ARCHIVE_MEMBERS),
        )
        self.assertEqual(SAFETY, manifest["safety"])

    def test_nine_pin_verifier_reconstructs_all_cross_bindings(self):
        output = self.root / "bound.zip"
        prepared = self.prepare(output)
        verified = verify_windows_execution_source_bound_candidate(
            output,
            base_suite_root=self.suite_root,
            execution_base_release=self.execution_base,
            expected_bound_archive_sha256=prepared.archive_sha256,
            **self.verification_pins(),
        )
        self.assertEqual(prepared, verified)
        self.assertEqual(
            self.source_report.archive_sha256,
            verified.production_config_sha256,
        )
        self.assertEqual(
            self.source_report.bootstrap_binding_sha256,
            verified.bootstrap_binding_sha256,
        )
        self.assertEqual(
            self.candidate.content_sha256,
            verified.candidate_content_sha256,
        )
        with self.assertRaises(TypeError):
            WindowsExecutionSourceBoundCandidateVerification(
                archive_path=output,
                archive_sha256="1" * 64,
                archive_size_bytes=1,
                binding_identity_sha256="2" * 64,
                source_archive_sha256="3" * 64,
                source_identity_sha256="4" * 64,
                bootstrap_binding_sha256="5" * 64,
                stage_binding_sha256="6" * 64,
                production_config_sha256="7" * 64,
                candidate_id="candidate",
                candidate_content_sha256="8" * 64,
                provider_pack_identity_sha256="9" * 64,
                provider_configuration_sha256="a" * 64,
                configured_release_identity_sha256="b" * 64,
                configured_archive_sha256="c" * 64,
                task_definition_sha256="d" * 64,
                suite_identity_sha256="e" * 64,
                execution_base_archive_sha256="f" * 64,
                execution_base_release_identity_sha256="1" * 64,
                git_commit="2" * 40,
                git_tree="3" * 40,
            )

    def test_provider_and_bootstrap_mismatch_reject_before_output(self):
        cases = (
            {
                "name": "provider",
                "source_sha256": digest("unrelated-source"),
                "bootstrap_sha256": self.source_report.bootstrap_binding_sha256,
                "reason": "BOUND_SOURCE_PROVIDER_MISMATCH",
            },
            {
                "name": "bootstrap",
                "source_sha256": self.source_report.archive_sha256,
                "bootstrap_sha256": digest("unrelated-bootstrap"),
                "reason": "BOUND_SOURCE_BOOTSTRAP_MISMATCH",
            },
        )
        for case in cases:
            with self.subTest(name=case["name"]):
                _pack, candidate_root, _candidate = self._candidate(
                    str(case["name"]),
                    source_sha256=str(case["source_sha256"]),
                    bootstrap_sha256=str(case["bootstrap_sha256"]),
                )
                output = self.root / f"mismatch-{case['name']}.zip"
                with self.assertRaisesRegex(
                    WindowsExecutionSourceBoundCandidateError,
                    str(case["reason"]),
                ):
                    prepare_windows_execution_source_bound_candidate(
                        base_suite_root=self.suite_root,
                        execution_base_release=self.execution_base,
                        production_config_source_archive=self.source_path,
                        configured_candidate_root=candidate_root,
                        output=output,
                        **self.verification_pins(),
                    )
                self.assertFalse(output.exists())

    def test_wrong_suite_pin_existing_output_and_symlink_are_preserved(self):
        existing = self.root / "existing.zip"
        existing.write_bytes(b"preserve")
        with self.assertRaisesRegex(
            WindowsExecutionSourceBoundCandidateError,
            "BOUND_DESTINATION_INVALID",
        ):
            self.prepare(existing)
        self.assertEqual(b"preserve", existing.read_bytes())

        with self.assertRaisesRegex(
            WindowsExecutionSourceBoundCandidateError,
            "BOUND_EXTERNAL_PIN_INVALID",
        ):
            prepare_windows_execution_source_bound_candidate(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                production_config_source_archive=self.source_path,
                configured_candidate_root=self.candidate_root,
                output=self.root / "wrong-suite.zip",
                **{
                    **self.verification_pins(),
                    "expected_suite_identity_sha256": "0" * 64,
                },
            )
        linked = self.root / "linked-source.zip"
        try:
            linked.symlink_to(self.source_path)
        except OSError:
            self.skipTest("symlink creation is unavailable")
        with self.assertRaisesRegex(
            WindowsExecutionSourceBoundCandidateError,
            "BOUND_INPUT_INVALID",
        ):
            prepare_windows_execution_source_bound_candidate(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                production_config_source_archive=linked,
                configured_candidate_root=self.candidate_root,
                output=self.root / "linked-output.zip",
                **self.verification_pins(),
            )

    def test_adversarial_outer_archive_rejects_with_updated_outer_pin(self):
        output = self.root / "valid-bound.zip"
        self.prepare(output)
        original = output.read_bytes()
        with zipfile.ZipFile(io.BytesIO(original), "r") as archive:
            manifest = archive.read(MANIFEST_MEMBER)
        noncanonical = json.dumps(json.loads(manifest)).encode("utf-8")
        wrong_safety_type = json.loads(manifest)
        wrong_safety_type["safety"]["provider_accepted"] = 0
        unsigned = dict(wrong_safety_type)
        unsigned.pop("binding_identity_sha256")
        wrong_safety_type["binding_identity_sha256"] = hashlib.sha256(
            json.dumps(
                unsigned,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        candidate_member = f"candidate/{sorted(CONFIGURED_CANDIDATE_FILES)[0]}"
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
            "manifest": rewrite_archive(
                original,
                replacements={MANIFEST_MEMBER: noncanonical},
            ),
            "safety-type": rewrite_archive(
                original,
                replacements={
                    MANIFEST_MEMBER: canonical_file(wrong_safety_type)
                },
            ),
        }
        for name, data in cases.items():
            with self.subTest(name=name):
                path = self.root / f"adversarial-{name}.zip"
                path.write_bytes(data)
                with self.assertRaises(
                    WindowsExecutionSourceBoundCandidateError
                ):
                    verify_windows_execution_source_bound_candidate(
                        path,
                        base_suite_root=self.suite_root,
                        execution_base_release=self.execution_base,
                        expected_bound_archive_sha256=hashlib.sha256(
                            data
                        ).hexdigest(),
                        **self.verification_pins(),
                    )

    def test_isolated_clis_prepare_and_verify(self):
        repository = Path(__file__).resolve().parent
        output = self.root / "cli-bound.zip"
        common = (
            "--base-suite-root",
            str(self.suite_root),
            "--execution-base-release",
            str(self.execution_base),
            "--expected-source-archive-sha256",
            self.source_report.archive_sha256,
            "--expected-champion-archive-sha256",
            str(self.champion["archive_sha256"]),
            "--expected-model-artifact-sha256",
            str(self.champion["model_artifact_sha256"]),
            "--expected-training-snapshot-sha256",
            str(self.champion["training_snapshot_sha256"]),
            "--expected-config-sha256",
            str(self.champion["config_sha256"]),
            "--expected-git-commit",
            COMMIT,
            "--expected-git-tree",
            TREE,
            "--expected-suite-identity-sha256",
            self.suite_identity,
        )
        prepared = subprocess.run(
            (
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(
                    repository
                    / "prepare_windows_execution_source_bound_candidate.py"
                ),
                *common,
                "--production-config-source-archive",
                str(self.source_path),
                "--configured-candidate-root",
                str(self.candidate_root),
                "--output",
                str(output),
            ),
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(0, prepared.returncode, prepared.stderr)
        self.assertIn(
            "WINDOWS_EXECUTION_SOURCE_BOUND_CANDIDATE_READY",
            prepared.stdout,
        )
        archive_sha = hashlib.sha256(output.read_bytes()).hexdigest()
        verified = subprocess.run(
            (
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(
                    repository
                    / "verify_windows_execution_source_bound_candidate.py"
                ),
                *common,
                "--archive",
                str(output),
                "--expected-bound-archive-sha256",
                archive_sha,
            ),
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(0, verified.returncode, verified.stderr)
        self.assertIn(
            "WINDOWS_EXECUTION_SOURCE_BOUND_CANDIDATE_VERIFIED",
            verified.stdout,
        )
        self.assertIn("Order capability: DISABLED", verified.stdout)


if __name__ == "__main__":
    unittest.main()
