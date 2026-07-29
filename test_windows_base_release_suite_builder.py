from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import build_windows_base_release_suite as suite


COMMIT = "1" * 40
TREE = "2" * 40
OTHER_COMMIT = "3" * 40
PROVIDER_BOUND_RUNTIME_CLOSURE_PATHS = (
    "execution_policy.py",
    "live_runtime/contracts.py",
    "live_runtime/live_canary_provider_bound_runtime_session.py",
    "live_runtime/live_canary_runtime_authority.py",
    "live_runtime/live_canary_runtime_candidate.py",
    "live_runtime/production_bootstrap.py",
    "live_runtime/windows_live_canary_execution_provider.py",
)
PROVIDER_BOUND_RUNTIME_CLOSURE_SCHEMA = (
    "windows-execution-live-canary-provider-bound-runtime-closure-v1"
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _provider_bound_runtime_closure() -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": PROVIDER_BOUND_RUNTIME_CLOSURE_SCHEMA,
        "files": [
            {
                "path": path,
                "size_bytes": 1,
                "sha256": _sha256(path.encode("utf-8")),
            }
            for path in PROVIDER_BOUND_RUNTIME_CLOSURE_PATHS
        ],
        "file_count": len(PROVIDER_BOUND_RUNTIME_CLOSURE_PATHS),
        "live_allowed": False,
        "order_capability": "DISABLED",
        "production_execution_ready": False,
    }
    return {
        **body,
        "closure_identity_sha256": _sha256(suite._canonical_json(body)),
    }


def _reseal_closure(closure: dict[str, object]) -> None:
    body = dict(closure)
    body.pop("closure_identity_sha256", None)
    closure["closure_identity_sha256"] = _sha256(
        suite._canonical_json(body)
    )


class WindowsBaseReleaseSuiteBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name).resolve()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / ".git").mkdir()
        self.release_parent = self.root / "releases"
        self.release_parent.mkdir()
        self.fail_role: str | None = None
        self.manifest_mutators: dict[str, object] = {}
        self.result_mutators: dict[str, object] = {}
        self.raw_sidecars: dict[str, bytes] = {}
        self.external_result_paths: dict[str, tuple[Path, Path]] = {}

    @staticmethod
    def _base_manifest(policy: suite.BaseReleaseRolePolicy) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": policy.manifest_schema,
            "release_profile": policy.release_profile,
            "git_commit": COMMIT,
            "git_tree": TREE,
            "allowlist_sha256": "4" * 64,
            "safety": {
                "live_allowed": False,
                "safe_to_demo_auto_order": False,
                "max_lot": 0.01,
                "order_capability": policy.order_capability,
            },
            "usage_policy": {},
            "source_files": [
                {
                    "path": f"{policy.role.lower()}.py",
                    "size_bytes": 1,
                    "sha256": "5" * 64,
                }
            ],
        }
        defaults: dict[str, object] = {
            "activation_requires": [],
            "decision_process": {},
            "demo_auto_gate_semantics": {},
            "dependency_lock_summary": {},
            "effects_during_build": {},
            "effects_during_validation": {},
            "foundation_status": {},
            "full_pending_gate_catalog": {},
            "live_canary_provider_bound_runtime_closure": (
                _provider_bound_runtime_closure()
            ),
            "order_primitive_inventory": {},
            "production_execution_ready": False,
            "readiness_blockers": [],
            "readiness_blockers_by_category": {},
            "required_factory_provider_contracts": {},
            "runtime_factory": "CONFIGURED_RELEASE_OVERLAY_REQUIRED",
            "runtime_loader": "RELEASE_LOCAL_CONFIGURED_ONLY",
            "stdlib_only": True,
            "trust_boundaries": {},
        }
        for key in policy.manifest_keys:
            if key not in payload and key != "release_identity_sha256":
                payload[key] = defaults[key]
        if policy.role == "EXECUTION":
            payload["source_files"].extend(
                {
                    "path": path,
                    "size_bytes": 1,
                    "sha256": _sha256(path.encode("utf-8")),
                }
                for path in PROVIDER_BOUND_RUNTIME_CLOSURE_PATHS
            )
            payload["source_files"] = sorted(
                payload["source_files"],
                key=lambda item: item["path"],
            )
            payload["live_canary_provider_bound_runtime_closure"] = (
                _provider_bound_runtime_closure()
            )
        identity = _sha256(suite._canonical_json(payload))
        return {**payload, "release_identity_sha256": identity}

    def _fake_builder(self, policy: suite.BaseReleaseRolePolicy):
        def build(
            root: Path,
            allowlist: Path,
            output: Path,
            *,
            manifest_output_path: Path | None = None,
        ) -> dict[str, object]:
            self.assertEqual(self.repo.resolve(), root.resolve())
            self.assertEqual(
                (self.repo / policy.allowlist_relative).resolve(),
                allowlist.resolve(),
            )
            if self.fail_role == policy.role:
                raise RuntimeError("internal builder detail must be redacted")
            assert manifest_output_path is not None
            manifest = self._base_manifest(policy)
            mutator = self.manifest_mutators.get(policy.role)
            if callable(mutator):
                mutator(manifest)
                body = dict(manifest)
                body.pop("release_identity_sha256", None)
                manifest["release_identity_sha256"] = _sha256(
                    suite._canonical_json(body)
                )
            archive_bytes = f"archive:{policy.role}\n".encode("ascii")
            output.write_bytes(archive_bytes)
            sidecar_bytes = self.raw_sidecars.get(
                policy.role,
                suite._canonical_json(manifest) + b"\n",
            )
            manifest_output_path.write_bytes(sidecar_bytes)
            result: dict[str, object] = {
                "archive": str(output.resolve()),
                "archive_sha256": _sha256(archive_bytes),
                "manifest": str(manifest_output_path.resolve()),
                "release_identity_sha256": manifest[
                    "release_identity_sha256"
                ],
                "file_count": len(manifest["source_files"]),
            }
            if policy.role == "READ_ONLY_SHADOW":
                result.update(
                    {
                        "bundle_class": "READ_ONLY_SHADOW_SERVICE",
                        "execution_context": (
                            "WINDOWS_TASK_SCHEDULER_SERVICE_ACCOUNT"
                        ),
                    }
                )
            else:
                result.update(
                    {
                        "order_capability": policy.order_capability,
                        "production_execution_ready": False,
                    }
                )
            external = self.external_result_paths.get(policy.role)
            if external is not None:
                result["archive"] = str(external[0])
                result["manifest"] = str(external[1])
            result_mutator = self.result_mutators.get(policy.role)
            if callable(result_mutator):
                result_mutator(result)
            return result

        return build

    def _patched_builders(self) -> ExitStack:
        stack = ExitStack()
        for policy in suite.ROLE_POLICIES:
            stack.enter_context(
                patch.object(
                    suite,
                    policy.builder_name,
                    side_effect=self._fake_builder(policy),
                )
            )
        return stack

    def _build(
        self,
        name: str = "candidate",
        *,
        states: list[tuple[str, str]] | None = None,
    ) -> dict[str, object]:
        source_states = states or [(COMMIT, TREE), (COMMIT, TREE)]
        with (
            patch.object(
                suite,
                "_clean_source_state",
                side_effect=source_states,
            ),
            self._patched_builders(),
        ):
            return suite.build_base_release_suite(
                self.repo,
                self.release_parent / name,
            )

    def test_ac1_complete_same_commit_five_role_suite(self) -> None:
        result = self._build()
        output = Path(result["output_root"])
        expected = {
            suite.SUITE_MANIFEST_NAME,
            *(
                name
                for policy in suite.ROLE_POLICIES
                for name in (
                    policy.archive_name,
                    f"{policy.archive_name}.manifest.json",
                )
            ),
        }
        self.assertEqual(expected, {item.name for item in output.iterdir()})
        manifest = json.loads(
            (output / suite.SUITE_MANIFEST_NAME).read_text("utf-8")
        )
        self.assertEqual(COMMIT, manifest["git_commit"])
        self.assertEqual(TREE, manifest["git_tree"])
        self.assertEqual(
            [item.role for item in suite.ROLE_POLICIES],
            [item["role"] for item in manifest["roles"]],
        )
        self.assertEqual(
            "GATED_PRESENT",
            next(
                item["order_capability"]
                for item in manifest["roles"]
                if item["role"] == "EXECUTION"
            ),
        )
        self.assertTrue(
            all(
                item["production_execution_ready"] is False
                for item in manifest["roles"]
            )
        )
        self.assertEqual(0.01, manifest["safety"]["max_lot"])
        self.assertFalse(manifest["safety"]["live_allowed"])
        self.assertFalse(manifest["safety"]["safe_to_demo_auto_order"])

    def test_ac2_atomic_publication_removes_staging(self) -> None:
        result = self._build()
        output = Path(result["output_root"])
        self.assertTrue(output.is_dir())
        self.assertEqual(
            [],
            list(
                self.release_parent.glob(
                    f".{output.name}.staging-*"
                )
            ),
        )

    def test_ac3_dirty_source_denied_before_role_builder(self) -> None:
        output = self.release_parent / "dirty"
        first_policy = suite.ROLE_POLICIES[0]
        with (
            patch.object(
                suite,
                "_clean_source_state",
                side_effect=suite.BaseReleaseSuiteError(
                    "BASE_RELEASE_SUITE_SOURCE_NOT_CLEAN"
                ),
            ),
            patch.object(
                suite,
                first_policy.builder_name,
            ) as builder,
        ):
            with self.assertRaisesRegex(
                suite.BaseReleaseSuiteError,
                "^BASE_RELEASE_SUITE_SOURCE_NOT_CLEAN$",
            ):
                suite.build_base_release_suite(self.repo, output)
        builder.assert_not_called()
        self.assertFalse(output.exists())

    def test_clean_source_state_rejects_untracked_content(self) -> None:
        with patch.object(
            suite,
            "_git",
            side_effect=[COMMIT, TREE, b"?? frontend-dashboard/\x00"],
        ):
            with self.assertRaisesRegex(
                suite.BaseReleaseSuiteError,
                "^BASE_RELEASE_SUITE_SOURCE_NOT_CLEAN$",
            ):
                suite._clean_source_state(self.repo)

    def test_ac4_later_role_failure_leaves_no_partial_suite(self) -> None:
        self.fail_role = "STATUS_MONITOR"
        output = self.release_parent / "failed"
        with self.assertRaisesRegex(
            suite.BaseReleaseSuiteError,
            "^BASE_RELEASE_SUITE_ROLE_BUILD_FAILED$",
        ):
            self._build(output.name)
        self.assertFalse(output.exists())
        self.assertEqual(
            [],
            list(self.release_parent.glob(f".{output.name}.staging-*")),
        )

    def test_ac5_wrong_profile_or_commit_is_denied(self) -> None:
        for field, value in (
            ("release_profile", "WRONG_PROFILE"),
            ("git_commit", OTHER_COMMIT),
        ):
            with self.subTest(field=field):
                self.manifest_mutators = {
                    "STATUS_MONITOR": (
                        lambda payload, key=field, replacement=value: (
                            payload.__setitem__(key, replacement)
                        )
                    )
                }
                output = self.release_parent / f"wrong-{field}"
                with self.assertRaisesRegex(
                    suite.BaseReleaseSuiteError,
                    "^BASE_RELEASE_SUITE_ROLE_MISMATCH$",
                ):
                    self._build(output.name)
                self.assertFalse(output.exists())

    def test_ac6_safety_invariant_mismatch_is_denied(self) -> None:
        def unlock(payload: dict[str, object]) -> None:
            payload["safety"] = {
                **payload["safety"],
                "safe_to_demo_auto_order": True,
            }

        self.manifest_mutators["EXECUTION"] = unlock
        output = self.release_parent / "unsafe"
        with self.assertRaisesRegex(
            suite.BaseReleaseSuiteError,
            "^BASE_RELEASE_SUITE_SAFETY_MISMATCH$",
        ):
            self._build(output.name)
        self.assertFalse(output.exists())

    def test_ac7_existing_inside_or_symlink_destination_is_denied(self) -> None:
        existing = self.release_parent / "existing"
        existing.mkdir()
        inside = self.repo / "inside"
        real_parent = self.root / "real-parent"
        real_parent.mkdir()
        symlink_parent = self.root / "symlink-parent"
        symlink_parent.symlink_to(real_parent, target_is_directory=True)
        for output in (
            existing,
            inside,
            symlink_parent / "suite",
        ):
            with self.subTest(output=output):
                with self.assertRaisesRegex(
                    suite.BaseReleaseSuiteError,
                    "^BASE_RELEASE_SUITE_DESTINATION_INVALID$",
                ):
                    with patch.object(
                        suite,
                        "_clean_source_state",
                    ) as source:
                        suite.build_base_release_suite(self.repo, output)
                source.assert_not_called()
        self.assertTrue(existing.is_dir())
        self.assertTrue(real_parent.is_dir())

    def test_ac8_source_change_before_publish_is_denied(self) -> None:
        output = self.release_parent / "source-changed"
        with self.assertRaisesRegex(
            suite.BaseReleaseSuiteError,
            "^BASE_RELEASE_SUITE_SOURCE_CHANGED$",
        ):
            self._build(
                output.name,
                states=[(COMMIT, TREE), (OTHER_COMMIT, TREE)],
            )
        self.assertFalse(output.exists())

    def test_ac9_two_builds_are_byte_identical(self) -> None:
        first = Path(self._build("first")["output_root"])
        second = Path(self._build("second")["output_root"])
        self.assertEqual(
            [item.name for item in sorted(first.iterdir())],
            [item.name for item in sorted(second.iterdir())],
        )
        for item in first.iterdir():
            self.assertEqual(item.read_bytes(), (second / item.name).read_bytes())

    def test_ac10_no_operational_effects_or_enable_option(self) -> None:
        result = self._build()
        manifest = json.loads(
            Path(result["manifest_path"]).read_text("utf-8")
        )
        self.assertEqual(suite.SUITE_EFFECTS, manifest["effects"])
        self.assertTrue(manifest["effects"]["git_subprocess"])
        self.assertTrue(
            all(
                value is False
                for key, value in manifest["effects"].items()
                if key != "git_subprocess"
            )
        )
        flags = {
            option
            for action in suite._parser()._actions
            for option in action.option_strings
        }
        forbidden = {
            "--enable-orders",
            "--arm",
            "--credential",
            "--permit",
            "--install-task",
            "--initialize-mt5",
        }
        self.assertTrue(flags.isdisjoint(forbidden))

    def test_ac11_builder_result_to_byte_mismatch_is_denied(self) -> None:
        self.result_mutators["DECISION"] = lambda result: result.__setitem__(
            "archive_sha256",
            "f" * 64,
        )
        output = self.release_parent / "result-mismatch"
        with self.assertRaisesRegex(
            suite.BaseReleaseSuiteError,
            "^BASE_RELEASE_SUITE_ROLE_RESULT_MISMATCH$",
        ):
            self._build(output.name)
        self.assertFalse(output.exists())

    def test_ac12_duplicate_key_sidecar_is_denied(self) -> None:
        self.raw_sidecars["DECISION"] = (
            b'{"release_profile":"A","release_profile":"B"}\n'
        )
        output = self.release_parent / "duplicate"
        with self.assertRaisesRegex(
            suite.BaseReleaseSuiteError,
            "^BASE_RELEASE_SUITE_MANIFEST_INVALID$",
        ):
            self._build(output.name)
        self.assertFalse(output.exists())

    def test_ac12_suite_manifest_fixed_paths_are_enforced(self) -> None:
        result = self._build("valid-for-suite-validation")
        manifest_path = Path(result["manifest_path"])
        payload = json.loads(manifest_path.read_text("utf-8"))
        payload["roles"][0]["archive_path"] = "substitute.zip"
        body = dict(payload)
        body.pop("suite_identity_sha256")
        payload["suite_identity_sha256"] = _sha256(
            suite._canonical_json(body)
        )
        with self.assertRaisesRegex(
            suite.BaseReleaseSuiteError,
            "^BASE_RELEASE_SUITE_MANIFEST_INVALID$",
        ):
            suite._validate_suite_manifest_bytes(
                suite._canonical_json(payload) + b"\n"
            )

    def test_ac13_exact_provider_bound_runtime_closure_is_accepted(self) -> None:
        result = self._build("provider-bound-closure")
        output = Path(result["output_root"])
        execution = next(
            policy
            for policy in suite.ROLE_POLICIES
            if policy.role == "EXECUTION"
        )
        manifest = json.loads(
            (
                output
                / f"{execution.archive_name}.manifest.json"
            ).read_text("utf-8")
        )
        closure = manifest[
            "live_canary_provider_bound_runtime_closure"
        ]
        self.assertEqual(
            PROVIDER_BOUND_RUNTIME_CLOSURE_SCHEMA,
            closure["schema_version"],
        )
        self.assertEqual(
            list(PROVIDER_BOUND_RUNTIME_CLOSURE_PATHS),
            [item["path"] for item in closure["files"]],
        )
        self.assertEqual(7, closure["file_count"])
        self.assertFalse(closure["live_allowed"])
        self.assertFalse(closure["production_execution_ready"])
        self.assertEqual("DISABLED", closure["order_capability"])

    def test_ac13_missing_provider_bound_runtime_closure_is_denied(self) -> None:
        self.manifest_mutators["EXECUTION"] = lambda payload: payload.pop(
            "live_canary_provider_bound_runtime_closure"
        )
        output = self.release_parent / "provider-bound-closure-missing"
        with self.assertRaisesRegex(
            suite.BaseReleaseSuiteError,
            "^BASE_RELEASE_SUITE_MANIFEST_INVALID$",
        ):
            self._build(output.name)
        self.assertFalse(output.exists())

    def test_ec15_malformed_provider_bound_runtime_closure_is_denied(
        self,
    ) -> None:
        def wrong_path(payload: dict[str, object]) -> None:
            closure = payload[
                "live_canary_provider_bound_runtime_closure"
            ]
            closure["files"][0]["path"] = "substitute.py"
            _reseal_closure(closure)

        def zero_size(payload: dict[str, object]) -> None:
            closure = payload[
                "live_canary_provider_bound_runtime_closure"
            ]
            closure["files"][0]["size_bytes"] = 0
            _reseal_closure(closure)

        def unlocked(payload: dict[str, object]) -> None:
            closure = payload[
                "live_canary_provider_bound_runtime_closure"
            ]
            closure["live_allowed"] = True
            _reseal_closure(closure)

        def forged_identity(payload: dict[str, object]) -> None:
            closure = payload[
                "live_canary_provider_bound_runtime_closure"
            ]
            closure["closure_identity_sha256"] = "f" * 64

        for name, mutation in (
            ("wrong-path", wrong_path),
            ("zero-size", zero_size),
            ("unlocked", unlocked),
            ("forged-identity", forged_identity),
        ):
            with self.subTest(name=name):
                self.manifest_mutators = {"EXECUTION": mutation}
                output = self.release_parent / f"closure-{name}"
                with self.assertRaisesRegex(
                    suite.BaseReleaseSuiteError,
                    "^BASE_RELEASE_SUITE_ROLE_MISMATCH$",
                ):
                    self._build(output.name)
                self.assertFalse(output.exists())

    def test_ec5_post_validation_artifact_change_is_denied(self) -> None:
        original = suite._validate_suite_manifest_bytes

        def mutate_after_manifest_validation(data: bytes) -> dict[str, object]:
            payload = original(data)
            staging = next(
                self.release_parent.glob(".artifact-changed.staging-*")
            )
            (staging / suite.ROLE_POLICIES[0].archive_name).write_bytes(
                b"changed-after-first-stable-read"
            )
            return payload

        output = self.release_parent / "artifact-changed"
        with patch.object(
            suite,
            "_validate_suite_manifest_bytes",
            side_effect=mutate_after_manifest_validation,
        ):
            with self.assertRaisesRegex(
                suite.BaseReleaseSuiteError,
                "^BASE_RELEASE_SUITE_ROLE_RESULT_MISMATCH$",
            ):
                self._build(output.name)
        self.assertFalse(output.exists())

    def test_ec7_external_builder_result_path_is_never_deleted(self) -> None:
        external_archive = self.root / "external.zip"
        external_sidecar = self.root / "external.json"
        external_archive.write_bytes(b"caller-owned")
        external_sidecar.write_bytes(b"caller-owned")
        self.external_result_paths["DECISION"] = (
            external_archive,
            external_sidecar,
        )
        output = self.release_parent / "external-result"
        with self.assertRaisesRegex(
            suite.BaseReleaseSuiteError,
            "^BASE_RELEASE_SUITE_ROLE_RESULT_MISMATCH$",
        ):
            self._build(output.name)
        self.assertEqual(b"caller-owned", external_archive.read_bytes())
        self.assertEqual(b"caller-owned", external_sidecar.read_bytes())
        self.assertFalse(output.exists())

    def test_ec10_concurrent_destination_is_preserved(self) -> None:
        output = self.release_parent / "concurrent"

        def conflict(staging: Path, destination: Path) -> None:
            destination.mkdir()
            (destination / "caller-owned.txt").write_text(
                "preserve",
                encoding="utf-8",
            )
            raise suite.BaseReleaseSuiteError(
                "BASE_RELEASE_SUITE_PUBLICATION_FAILED"
            )

        with patch.object(suite, "_atomic_publish", side_effect=conflict):
            with self.assertRaisesRegex(
                suite.BaseReleaseSuiteError,
                "^BASE_RELEASE_SUITE_PUBLICATION_FAILED$",
            ):
                self._build(output.name)
        self.assertEqual(
            "preserve",
            (output / "caller-owned.txt").read_text("utf-8"),
        )

    def test_ec10_atomic_publish_never_replaces_empty_racing_root(self) -> None:
        staging = self.release_parent / "staging-for-race"
        staging.mkdir()
        (staging / "suite.txt").write_text("suite", encoding="utf-8")
        output = self.release_parent / "empty-racing-root"
        original = suite._rename_no_replace

        def create_destination_then_rename(
            source: Path,
            destination: Path,
        ) -> None:
            destination.mkdir()
            original(source, destination)

        with patch.object(
            suite,
            "_rename_no_replace",
            side_effect=create_destination_then_rename,
        ):
            with self.assertRaisesRegex(
                suite.BaseReleaseSuiteError,
                "^BASE_RELEASE_SUITE_PUBLICATION_FAILED$",
            ):
                suite._atomic_publish(staging, output)
        self.assertTrue(output.is_dir())
        self.assertEqual([], list(output.iterdir()))
        self.assertTrue(staging.is_dir())
        self.assertFalse(
            (self.release_parent / f".{output.name}.publish.lock").exists()
        )

    def test_atomic_publish_preserves_replaced_lock_path(self) -> None:
        staging = self.release_parent / "staging-for-lock-race"
        staging.mkdir()
        output = self.release_parent / "lock-race-output"
        lock = self.release_parent / f".{output.name}.publish.lock"
        replacement = self.release_parent / "replacement-lock"

        def replace_lock_then_fail(
            _source: Path,
            _destination: Path,
        ) -> None:
            lock.unlink()
            lock.symlink_to(replacement.name)
            raise OSError("simulated publish failure after lock swap")

        try:
            with patch.object(
                suite,
                "_rename_no_replace",
                side_effect=replace_lock_then_fail,
            ):
                with self.assertRaisesRegex(
                    suite.BaseReleaseSuiteError,
                    "BASE_RELEASE_SUITE_PUBLICATION_FAILED",
                ):
                    suite._atomic_publish(staging, output)
        except (NotImplementedError, OSError):
            self.skipTest("symlinks are unavailable on this platform")

        self.assertTrue(lock.is_symlink())
        self.assertEqual(Path(replacement.name), lock.readlink())
        self.assertFalse(replacement.exists())

    def test_build_cleanup_preserves_replaced_staging_root(self) -> None:
        output = self.release_parent / "staging-race-output"
        replacement = self.release_parent / "replacement-staging"
        displaced: Path | None = None

        def replace_staging_then_fail(
            staging: Path,
            _destination: Path,
        ) -> None:
            nonlocal displaced
            displaced = staging.with_name(staging.name + "-displaced")
            staging.rename(displaced)
            staging.symlink_to(replacement.name, target_is_directory=True)
            raise suite.BaseReleaseSuiteError(
                "BASE_RELEASE_SUITE_PUBLICATION_FAILED"
            )

        try:
            with patch.object(
                suite,
                "_atomic_publish",
                side_effect=replace_staging_then_fail,
            ):
                with self.assertRaisesRegex(
                    suite.BaseReleaseSuiteError,
                    "BASE_RELEASE_SUITE_PUBLICATION_FAILED",
                ):
                    self._build(output.name)
        except (NotImplementedError, OSError):
            self.skipTest("symlinks are unavailable on this platform")

        staging_links = list(
            self.release_parent.glob(f".{output.name}.staging-*")
        )
        self.assertEqual(2, len(staging_links))
        self.assertEqual(1, sum(path.is_symlink() for path in staging_links))
        self.assertIsNotNone(displaced)
        self.assertTrue(displaced.is_dir())

    def test_cli_redacts_internal_failure(self) -> None:
        output = io.StringIO()
        with (
            patch.object(
                suite,
                "build_base_release_suite",
                side_effect=suite.BaseReleaseSuiteError(
                    "BASE_RELEASE_SUITE_ROLE_BUILD_FAILED"
                ),
            ),
            redirect_stdout(output),
        ):
            status = suite.main(
                [
                    "--output-root",
                    str(self.release_parent / "cli"),
                ]
            )
        self.assertEqual(2, status)
        self.assertEqual(
            "BASE_RELEASE_SUITE_REJECTED: "
            "BASE_RELEASE_SUITE_ROLE_BUILD_FAILED\n",
            output.getvalue(),
        )
        self.assertNotIn("internal", output.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
