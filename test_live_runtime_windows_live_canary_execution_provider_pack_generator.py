from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import live_runtime.windows_execution_provider_pack_generator as pack_module
from build_windows_release import _canonical_json, _create_archive
from live_runtime.windows_execution_provider_pack_generator import (
    GENERATED_PATHS,
    LIVE_EXECUTION_CREDENTIAL_PURPOSES,
    LIVE_EXECUTION_PROVIDER_ROLES,
    LIVE_FOUNDATION_PATHS,
    ExecutionProviderPackError,
    extract_windows_live_canary_execution_provider_configuration,
    prepare_windows_live_canary_execution_provider_pack,
    static_windows_live_canary_execution_provider_configuration_from_dict,
    validate_windows_live_canary_execution_provider_pack,
)
from live_runtime.windows_live_canary_execution_provider import (
    LIVE_WINDOWS_FACTORY_PROVIDER_CONTRACT_SET_SHA256,
    live_provider_contracts,
)
from live_runtime.windows_service_factory_template import (
    WINDOWS_FACTORY_PROVIDER_CONTRACT_SET_SHA256,
)
from prepare_windows_live_canary_execution_provider_pack import (
    _parser as prepare_parser,
    main as prepare_main,
)
from test_live_runtime_windows_base_release_suite import (
    write_suite_from_role_bases,
)
from validate_windows_live_canary_execution_provider_pack import (
    _parser as validate_parser,
    main as validate_main,
)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_file(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"


class WindowsLiveCanaryExecutionProviderPackGeneratorTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.suite_root, self.execution_base, self.suite_manifest = (
            self._base_suite()
        )
        self.pack_input = self.root / "live-execution-provider-input.json"
        self.pack_input.write_bytes(canonical_file(self._pack_payload()))

    def _base_suite(
        self,
        *,
        root: Path | None = None,
        omit: str | None = None,
        drift: str | None = None,
    ):
        target = self.root if root is None else root
        target.mkdir(parents=True, exist_ok=True)
        source = Path(__file__).resolve().parent
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
        for path in LIVE_FOUNDATION_PATHS:
            if path == omit:
                continue
            data = (source / path).read_bytes()
            if path == drift:
                data += b"\n# reviewed-byte-drift\n"
            sources[path] = data
        unsigned = {
            "schema_version": (
                "ai-scalper-windows-execution-service-manifest-v1"
            ),
            "release_profile": "WINDOWS_GATED_EXECUTION_SERVICE_V1",
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
            _create_archive(sources, _canonical_json(manifest) + b"\n")
        )
        suite, suite_manifest, _manifests = write_suite_from_role_bases(
            target,
            {"EXECUTION": (archive, manifest)},
        )
        return suite, suite / "execution-base-v1.zip", suite_manifest

    @staticmethod
    def _provider_core() -> dict[str, object]:
        contracts = live_provider_contracts()
        prefix = "AI_SCALPER/WINDOWS_SERVICE/LIVE_EXECUTION"
        credential_contracts = tuple(
            item for item in contracts if item.credential_purpose is not None
        )
        credentials = [
            {
                "fingerprint_sha256": digest(
                    f"live-secret-material:{item.credential_purpose}"
                ),
                "key_id": f"live-execution-key-{index:02d}",
                "purpose": item.credential_purpose,
                "reference_id": f"live-execution-credential-{index:02d}",
                "target_name": (
                    f"{prefix}/live-execution-key-{index:02d}"
                ),
            }
            for index, item in enumerate(credential_contracts, start=1)
        ]
        return {
            "clock_attestation_path": (
                r"C:\AI_SCALPER_STATE\live-execution\clock.json"
            ),
            "clock_binding": {
                "authority_issuer_id": "live-clock-authority-v1",
                "authority_key_fingerprint_sha256": digest(
                    "live-clock-key-material"
                ),
                "authority_key_id": "live-clock-key-v1",
                "host_identity_sha256": digest("live-host-v1"),
                "maximum_absolute_drift_ms": 1000,
                "maximum_attestation_age_ms": 10000,
                "provider_id": "live-clock-provider-v1",
                "schema_version": "windows-clock-binding-v1",
            },
            "credential_references": credentials,
            "credential_target_prefix": prefix,
            "live_allowed": False,
            "max_lot": 0.01,
            "order_capability": "DISABLED",
            "pack_id": "xm-live-canary-provider-window-01",
            "production_config_sha256": digest("live-production-source"),
            "production_execution_ready": False,
            "promotion_eligible": False,
            "runtime_mode": "LIVE",
            "safe_to_demo_auto_order": False,
            "schema_version": (
                "windows-live-canary-execution-provider-configuration-v1"
            ),
        }

    def _pack_payload(self) -> dict[str, object]:
        return {
            "provider_configuration": self._provider_core(),
            "schema_version": (
                "windows-live-canary-execution-provider-pack-input-v1"
            ),
            "service_config": {
                "cycle_deadline_seconds": 10.0,
                "cycle_interval_seconds": 1.0,
                "heartbeat_ttl_seconds": 30,
                "lease_seconds": 30,
                "max_cycles": 100,
                "owner_id": "xm-live-execution-owner-v1",
                "service_id": "ai-scalper-xm-live-execution-v1",
            },
        }

    def _prepare(self, name: str, *, input_path: Path | None = None):
        target = self.root / name
        result = prepare_windows_live_canary_execution_provider_pack(
            base_suite_root=self.suite_root,
            execution_base_release=self.execution_base,
            pack_input_path=input_path or self.pack_input,
            output_root=target,
        )
        return result, target

    def test_ac1_pack_is_exact_deterministic_and_deny_only(self):
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
            first.pack_identity_sha256, second.pack_identity_sha256
        )
        self.assertEqual(first.provider_count, 49)
        self.assertEqual(first.credential_reference_count, 12)
        self.assertEqual(
            first.status, "EXTERNAL_LIVE_PROVIDER_ACCEPTANCE_REQUIRED"
        )
        self.assertFalse(first.provider_accepted)
        self.assertFalse(first.provider_materialized)
        self.assertFalse(first.credential_access_performed)
        self.assertFalse(first.production_execution_ready)
        self.assertFalse(first.live_allowed)
        self.assertFalse(first.broker_mutation_performed)
        self.assertEqual(first.order_capability, "DISABLED")
        self.assertEqual(
            first,
            validate_windows_live_canary_execution_provider_pack(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                pack_root=first_root,
            ),
        )

    def test_ac2_embedded_configuration_is_exact_live_inventory(self):
        _result, root = self._prepare("inventory")
        source = (
            root / "configured_providers/execution_provider.py"
        ).read_bytes()
        raw = extract_windows_live_canary_execution_provider_configuration(
            source
        )
        config = (
            static_windows_live_canary_execution_provider_configuration_from_dict(
                raw
            )
        )
        self.assertEqual(
            tuple(item.port_name for item in config.provider_bindings),
            LIVE_EXECUTION_PROVIDER_ROLES,
        )
        self.assertEqual(
            tuple(item.purpose for item in config.credential_references),
            LIVE_EXECUTION_CREDENTIAL_PURPOSES,
        )
        self.assertEqual(
            LIVE_EXECUTION_CREDENTIAL_PURPOSES[0], "MT5_LIVE_SESSION"
        )
        text = source.decode("utf-8")
        self.assertIn(
            "build_windows_live_canary_execution_factory_result", text
        )
        self.assertNotIn("MetaTrader5", text)
        self.assertNotIn("order_send", text)
        self.assertNotIn("order_check", text)

    def test_ac3_foundation_missing_or_drifted_fails_before_output(self):
        cases = (
            ("missing", LIVE_FOUNDATION_PATHS[0], None),
            ("drift", None, LIVE_FOUNDATION_PATHS[0]),
        )
        for name, omit, drift in cases:
            alternate = self.root / name
            suite, execution, _manifest = self._base_suite(
                root=alternate,
                omit=omit,
                drift=drift,
            )
            output = self.root / f"{name}-output"
            with self.subTest(name=name):
                with self.assertRaises(ExecutionProviderPackError):
                    prepare_windows_live_canary_execution_provider_pack(
                        base_suite_root=suite,
                        execution_base_release=execution,
                        pack_input_path=self.pack_input,
                        output_root=output,
                    )
                self.assertFalse(output.exists())

    def test_ac5_tamper_extra_schema_and_derived_input_fail_closed(self):
        _result, root = self._prepare("tamper")
        provider = root / "configured_providers/execution_provider.py"
        original = provider.read_bytes()
        provider.write_bytes(original + b" ")
        with self.assertRaises(ExecutionProviderPackError):
            validate_windows_live_canary_execution_provider_pack(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                pack_root=root,
            )
        provider.write_bytes(original)
        (root / "extra.py").write_bytes(b"raise SystemExit\n")
        with self.assertRaises(ExecutionProviderPackError):
            validate_windows_live_canary_execution_provider_pack(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                pack_root=root,
            )

        mutations = []
        payload = self._pack_payload()
        mutations.append({**payload, "password": "forbidden"})
        mutations.append(
            {
                **payload,
                "provider_configuration": {
                    **payload["provider_configuration"],
                    "runtime_mode": "DEMO",
                },
            }
        )
        mutations.append(
            {
                **payload,
                "provider_configuration": {
                    **payload["provider_configuration"],
                    "base_suite_identity_sha256": digest("caller-derived"),
                },
            }
        )
        for index, changed in enumerate(mutations):
            source = self.root / f"bad-{index}.json"
            source.write_bytes(canonical_file(changed))
            output = self.root / f"bad-output-{index}"
            with self.subTest(index=index):
                with self.assertRaises(ExecutionProviderPackError):
                    prepare_windows_live_canary_execution_provider_pack(
                        base_suite_root=self.suite_root,
                        execution_base_release=self.execution_base,
                        pack_input_path=source,
                        output_root=output,
                    )
                self.assertFalse(output.exists())

        duplicate = (
            b'{"provider_configuration":{},'
            b'"provider_configuration":{},'
            b'"schema_version":'
            b'"windows-live-canary-execution-provider-pack-input-v1",'
            b'"service_config":{}}\n'
        )
        duplicate_path = self.root / "duplicate.json"
        duplicate_path.write_bytes(duplicate)
        with self.assertRaises(ExecutionProviderPackError):
            prepare_windows_live_canary_execution_provider_pack(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                pack_input_path=duplicate_path,
                output_root=self.root / "duplicate-output",
            )

    def test_ac6_cleanup_preserves_replaced_pack_root(self):
        pack_root = self.root / "owned-pack"
        displaced = self.root / "displaced-pack"
        replacement = self.root / "replacement-pack"
        pack_root.mkdir()
        identity = pack_module._directory_identity(pack_root.lstat())
        pack_root.rename(displaced)
        try:
            pack_root.symlink_to(replacement.name, target_is_directory=True)
        except (NotImplementedError, OSError):
            self.skipTest("symlinks are unavailable on this platform")
        pack_module._cleanup(pack_root, identity, [])
        self.assertTrue(pack_root.is_symlink())
        self.assertEqual(Path(replacement.name), pack_root.readlink())
        self.assertTrue(displaced.is_dir())

    def test_ac7_v1_contract_and_generated_profile_remain_unchanged(self):
        self.assertEqual(
            WINDOWS_FACTORY_PROVIDER_CONTRACT_SET_SHA256,
            "0003087efd10ade71255d6e05db45060febac9f98b50a0d29c1a7212d55db148",
        )
        self.assertNotEqual(
            WINDOWS_FACTORY_PROVIDER_CONTRACT_SET_SHA256,
            LIVE_WINDOWS_FACTORY_PROVIDER_CONTRACT_SET_SHA256,
        )
        self.assertEqual(
            live_provider_contracts(),
            pack_module._LIVE_CONTRACTS,
        )
        self.assertEqual(len(LIVE_EXECUTION_PROVIDER_ROLES), 49)

    def test_ac8_prepare_and_validate_cli_are_deny_only(self):
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
            {"base_suite_root", "execution_base_release", "pack_root"},
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
        self.assertIn("WINDOWS_LIVE_EXECUTION_PROVIDER_PACK_PREPARED", prepared)
        self.assertIn("EXTERNAL_LIVE_PROVIDER_ACCEPTANCE_REQUIRED", prepared)
        self.assertIn("Provider count: 49", prepared)
        self.assertIn("Credential reference count: 12", prepared)
        self.assertIn("Credential access: NOT_PERFORMED", prepared)
        self.assertIn("Broker mutation: NOT_PERFORMED", prepared)
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
        self.assertIn("WINDOWS_LIVE_EXECUTION_PROVIDER_PACK_VALID", validated)
        self.assertIn("Provider materialization: NOT_PERFORMED", validated)
        self.assertIn("Production execution ready: false", validated)

    def test_ac9_release_allowlists_close_live_pack_sources(self):
        execution = json.loads(
            Path("config/windows_execution_service_allowlist.v1.json")
            .read_text(encoding="utf-8")
        )
        tooling = json.loads(
            Path("config/windows_configured_release_tooling_allowlist.v1.json")
            .read_text(encoding="utf-8")
        )
        self.assertIn(
            "live_runtime/windows_live_canary_execution_provider.py",
            execution["files"],
        )
        self.assertIn(
            "prepare_windows_live_canary_execution_provider_pack.py",
            tooling["files"],
        )
        self.assertIn(
            "validate_windows_live_canary_execution_provider_pack.py",
            tooling["files"],
        )
        self.assertEqual(execution["safety"]["live_allowed"], False)
        self.assertEqual(tooling["safety"]["order_capability"], "DISABLED")


if __name__ == "__main__":
    unittest.main()
