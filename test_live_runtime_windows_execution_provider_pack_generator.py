from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import live_runtime.windows_execution_provider_pack_generator as execution_pack_module
from build_windows_release import _canonical_json, _create_archive
from live_runtime.windows_execution_provider_pack_generator import (
    GENERATED_PATHS,
    ExecutionProviderPackError,
    prepare_windows_execution_provider_pack,
    validate_windows_execution_provider_pack,
)
from test_live_runtime_windows_base_release_suite import (
    write_suite_from_role_bases,
)
from prepare_windows_execution_provider_pack import (
    _parser as prepare_parser,
    main as prepare_main,
)
from validate_windows_execution_provider_pack import (
    _parser as validate_parser,
    main as validate_main,
)
import test_live_runtime_windows_execution_provider_pack as foundation_fixture


def canonical_file(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"


class WindowsExecutionProviderPackGeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.suite_root, self.execution_base, self.suite_manifest = (
            self._base_suite()
        )
        self.pack_input = self.root / "execution-provider-input.json"
        self.pack_input.write_bytes(canonical_file(self._pack_payload()))

    def _base_suite(
        self,
        *,
        root: Path | None = None,
        omit: str | None = None,
        foundation_suffix: bytes = b"",
    ):
        target = self.root if root is None else root
        target.mkdir(parents=True, exist_ok=True)
        source = Path(__file__).resolve().parent
        foundation_paths = (
            "live_runtime/windows_execution_provider_pack.py",
            "live_runtime/windows_provider_primitives.py",
        )
        sources = {
            "live_runtime/__init__.py": b"",
            "live_runtime/contracts.py": (
                source / "live_runtime/contracts.py"
            ).read_bytes(),
            "live_runtime/windows_service_factory_template.py": (
                source
                / "live_runtime/windows_service_factory_template.py"
            ).read_bytes(),
        }
        for path in foundation_paths:
            if path == omit:
                continue
            data = (source / path).read_bytes()
            if path.endswith("windows_execution_provider_pack.py"):
                data += foundation_suffix
            sources[path] = data
        unsigned = {
            "schema_version": (
                "ai-scalper-windows-execution-service-manifest-v1"
            ),
            "release_profile": (
                "WINDOWS_GATED_EXECUTION_SERVICE_V1"
            ),
            "git_commit": "1" * 40,
            "git_tree": "2" * 40,
            "safety": {
                "live_allowed": False,
                "safe_to_demo_auto_order": False,
                "max_lot": 0.01,
                "order_capability": "GATED_PRESENT",
            },
            "production_execution_ready": False,
            "readiness_blockers": [
                "EXTERNAL_FACTORY_PROVIDER_CONFIGURATION_REQUIRED"
            ],
            "source_files": [
                {
                    "path": path,
                    "size_bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
                for path, data in sorted(sources.items())
            ],
        }
        manifest = {
            **unsigned,
            "release_identity_sha256": hashlib.sha256(
                _canonical_json(unsigned)
            ).hexdigest(),
        }
        archive = target / "execution-base-source.zip"
        archive.write_bytes(
            _create_archive(
                sources,
                _canonical_json(manifest) + b"\n",
            )
        )
        suite, suite_manifest, _manifests = (
            write_suite_from_role_bases(
                target,
                {"EXECUTION": (archive, manifest)},
            )
        )
        return (
            suite,
            suite / "execution-base-v1.zip",
            suite_manifest,
        )

    def _pack_payload(self) -> dict[str, object]:
        case = foundation_fixture.WindowsExecutionProviderPackTests(
            methodName="runTest"
        )
        case.setUp()
        try:
            provider = case._payload()
        finally:
            case.doCleanups()
        provider_core = {
            key: value
            for key, value in provider.items()
            if key
            not in {
                "base_suite_identity_sha256",
                "execution_base_release_identity_sha256",
                "provider_bindings",
                "service_config_file_sha256",
            }
        }
        return {
            "provider_configuration": provider_core,
            "schema_version": (
                "windows-execution-provider-pack-input-v1"
            ),
            "service_config": {
                "cycle_deadline_seconds": 10.0,
                "cycle_interval_seconds": 1.0,
                "heartbeat_ttl_seconds": 30,
                "lease_seconds": 30,
                "max_cycles": 100,
                "owner_id": "execution-service-account-v1",
                "service_id": "ai-scalper-execution-v1",
            },
        }

    def _prepare(self, name: str, *, input_path: Path | None = None):
        target = self.root / name
        return prepare_windows_execution_provider_pack(
            base_suite_root=self.suite_root,
            execution_base_release=self.execution_base,
            pack_input_path=input_path or self.pack_input,
            output_root=target,
        ), target

    def test_pack_is_exact_deterministic_and_deny_only(self):
        first, first_root = self._prepare("first")
        second, second_root = self._prepare("second")
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
        self.assertEqual(tuple(sorted(first_files)), GENERATED_PATHS)
        self.assertEqual(first_files, second_files)
        self.assertEqual(
            first.pack_identity_sha256,
            second.pack_identity_sha256,
        )
        self.assertEqual(first.provider_count, 46)
        self.assertFalse(first.provider_accepted)
        self.assertFalse(first.production_execution_ready)
        self.assertFalse(first.provider_materialized)
        self.assertFalse(first.credential_access_performed)
        self.assertFalse(first.mt5_initialized)
        self.assertFalse(first.broker_mutation_performed)
        self.assertEqual(first.order_capability, "DISABLED")
        self.assertEqual(
            validate_windows_execution_provider_pack(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                pack_root=first_root,
            ),
            first,
        )

    def test_tamper_extra_and_partial_output_fail_closed(self):
        result, root = self._prepare("tamper")
        self.assertFalse(result.provider_accepted)
        provider = (
            root
            / "configured_providers/execution_provider.py"
        )
        provider.write_bytes(provider.read_bytes() + b" ")
        with self.assertRaises(ExecutionProviderPackError):
            validate_windows_execution_provider_pack(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                pack_root=root,
            )
        provider.write_bytes(provider.read_bytes()[:-1])
        (root / "extra.py").write_bytes(b"raise SystemExit\n")
        with self.assertRaises(ExecutionProviderPackError):
            validate_windows_execution_provider_pack(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                pack_root=root,
            )

    def test_foundation_missing_or_drifted_fails_before_output(self):
        for name, omit, suffix in (
            (
                "missing",
                "live_runtime/windows_execution_provider_pack.py",
                b"",
            ),
            ("drift", None, b"\n# drift\n"),
        ):
            alternate = self.root / name
            suite, execution, _manifest = self._base_suite(
                root=alternate,
                omit=omit,
                foundation_suffix=suffix,
            )
            output = self.root / f"{name}-output"
            with self.subTest(name=name):
                with self.assertRaises(ExecutionProviderPackError):
                    prepare_windows_execution_provider_pack(
                        base_suite_root=suite,
                        execution_base_release=execution,
                        pack_input_path=self.pack_input,
                        output_root=output,
                    )
                self.assertFalse(output.exists())

    def test_secret_safety_and_noncanonical_input_fail_before_output(self):
        payload = self._pack_payload()
        mutations = (
            {
                **payload,
                "password": "secret-is-forbidden",
            },
            {
                **payload,
                "provider_configuration": {
                    **payload["provider_configuration"],
                    "live_allowed": True,
                },
            },
            {
                **payload,
                "service_config": {
                    **payload["service_config"],
                    "cycle_interval_seconds": 20.0,
                },
            },
        )
        for index, changed in enumerate(mutations):
            input_path = self.root / f"bad-{index}.json"
            input_path.write_bytes(canonical_file(changed))
            output = self.root / f"bad-output-{index}"
            with self.subTest(index=index):
                with self.assertRaises(ExecutionProviderPackError):
                    prepare_windows_execution_provider_pack(
                        base_suite_root=self.suite_root,
                        execution_base_release=self.execution_base,
                        pack_input_path=input_path,
                        output_root=output,
                    )
                self.assertFalse(output.exists())

        duplicate = (
            b'{"provider_configuration":{},'
            b'"provider_configuration":{},'
            b'"schema_version":"windows-execution-provider-pack-input-v1",'
            b'"service_config":{}}\n'
        )
        duplicate_path = self.root / "duplicate.json"
        duplicate_path.write_bytes(duplicate)
        with self.assertRaises(ExecutionProviderPackError):
            prepare_windows_execution_provider_pack(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                pack_input_path=duplicate_path,
                output_root=self.root / "duplicate-output",
            )

    def test_pack_validation_never_imports_generated_provider(self):
        _result, root = self._prepare("no-import")
        source = (
            root / "configured_providers/execution_provider.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "build_windows_execution_factory_result",
            source,
        )
        self.assertNotIn("MetaTrader5", source)
        self.assertNotIn("order_send", source)
        self.assertNotIn("order_check", source)
        validate_windows_execution_provider_pack(
            base_suite_root=self.suite_root,
            execution_base_release=self.execution_base,
            pack_root=root,
        )

    def test_cli_prepare_and_validate_are_deny_only(self):
        self.assertEqual(
            {
                "base_suite_root",
                "execution_base_release",
                "pack_input",
                "output_root",
            },
            {
                action.dest
                for action in prepare_parser()._actions
                if action.dest != "help"
            },
        )
        self.assertEqual(
            {
                "base_suite_root",
                "execution_base_release",
                "pack_root",
            },
            {
                action.dest
                for action in validate_parser()._actions
                if action.dest != "help"
            },
        )
        output = self.root / "cli-pack"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = prepare_main(
                [
                    "--base-suite-root",
                    str(self.suite_root),
                    "--execution-base-release",
                    str(self.execution_base),
                    "--pack-input",
                    str(self.pack_input),
                    "--output-root",
                    str(output),
                ]
            )
        self.assertEqual(0, code, stderr.getvalue())
        prepared = stdout.getvalue()
        self.assertIn(
            "WINDOWS_EXECUTION_PROVIDER_PACK_PREPARED",
            prepared,
        )
        self.assertIn("PROVIDER_ACCEPTANCE_REQUIRED", prepared)
        self.assertIn("Provider count: 46", prepared)
        self.assertIn("Credential access: NOT_PERFORMED", prepared)
        self.assertIn("MT5 initialization: NOT_PERFORMED", prepared)
        self.assertIn("Order capability: DISABLED", prepared)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = validate_main(
                [
                    "--base-suite-root",
                    str(self.suite_root),
                    "--execution-base-release",
                    str(self.execution_base),
                    "--pack-root",
                    str(output),
                ]
            )
        self.assertEqual(0, code, stderr.getvalue())
        validated = stdout.getvalue()
        self.assertIn(
            "WINDOWS_EXECUTION_PROVIDER_PACK_VALID",
            validated,
        )
        self.assertIn("Provider materialization: NOT_PERFORMED", validated)
        self.assertIn("Broker mutation: NOT_PERFORMED", validated)
        self.assertIn("Production execution ready: false", validated)


    def test_cleanup_preserves_replaced_pack_root(self):
        pack_root = self.root / "owned-pack"
        displaced = self.root / "displaced-pack"
        replacement = self.root / "replacement-pack"
        pack_root.mkdir()
        identity = execution_pack_module._directory_identity(
            pack_root.lstat()
        )
        pack_root.rename(displaced)
        try:
            pack_root.symlink_to(
                replacement.name,
                target_is_directory=True,
            )
        except (NotImplementedError, OSError):
            self.skipTest("symlinks are unavailable on this platform")

        execution_pack_module._cleanup(pack_root, identity, [])

        self.assertTrue(pack_root.is_symlink())
        self.assertEqual(Path(replacement.name), pack_root.readlink())
        self.assertTrue(displaced.is_dir())


if __name__ == "__main__":
    unittest.main()
