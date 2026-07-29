from __future__ import annotations

from contextlib import nullcontext
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import execution_policy
from live_runtime.windows_live_canary_execution_provider import (
    WindowsLiveCanaryProviderMaterializationHooks,
)
from live_runtime.windows_service_entrypoint import (
    WindowsLiveCanaryExternalRuntimeContext,
    WindowsServiceError,
    WindowsServiceFactoryContext,
    load_reviewed_windows_live_runtime_hooks,
    validate_windows_live_runtime_provider_source,
)


UTC = timezone.utc


def digest(value: bytes | str) -> str:
    payload = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


VALID_SOURCE = b'''\
"""Exact reviewed test runtime provider."""

from live_runtime.windows_live_canary_execution_provider import (
    WindowsLiveCanaryProviderMaterializationHooks,
)


def build_live_canary_materialization_hooks(context):
    def unavailable(*args, **kwargs):
        raise RuntimeError("provider state not provisioned")

    return WindowsLiveCanaryProviderMaterializationHooks(
        runtime_source_reader=unavailable,
        credential_backend_factory=unavailable,
        clock_attestation_reader=unavailable,
        provider_state_reader=unavailable,
        sqlite_opener=unavailable,
        mt5_importer=unavailable,
        network_sender=unavailable,
    )
'''


class WindowsLiveCanaryExternalRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.release_root = Path(__file__).resolve().parent
        self.provider = self.root / "reviewed-live-runtime.py"
        self.provider.write_bytes(VALID_SOURCE)
        self.factory_context = WindowsServiceFactoryContext(
            release_root_sha256=digest(str(self.release_root)),
            factory_contract_sha256=digest("factory-contract"),
            factory_file_sha256=digest("factory-file"),
            service_config_file_sha256=digest("service-config"),
            bootstrap_binding_sha256=digest("bootstrap"),
        )

    def test_static_source_validator_accepts_exact_builder_without_execution(self):
        calls: list[str] = []
        report = validate_windows_live_runtime_provider_source(
            VALID_SOURCE,
            effect_probe=calls.append,
        )
        self.assertEqual([], calls)
        self.assertEqual(
            "build_live_canary_materialization_hooks",
            report.builder_name,
        )
        self.assertEqual(digest(VALID_SOURCE), report.source_sha256)

    def test_static_source_validator_rejects_order_process_and_top_level_effects(self):
        invalid = (
            b"def build_live_canary_materialization_hooks(context):\n"
            b"    return broker.order_send({})\n",
            b"import subprocess\n"
            b"def build_live_canary_materialization_hooks(context):\n"
            b"    return subprocess.run(['x'])\n",
            b"touch()\n"
            b"def build_live_canary_materialization_hooks(context):\n"
            b"    return None\n",
            b"from importlib import import_module\n"
            b"def build_live_canary_materialization_hooks(context):\n"
            b"    return import_module('x')\n",
            b"target.attribute = 1\n"
            b"def build_live_canary_materialization_hooks(context):\n"
            b"    return None\n",
            b"@touch()\n"
            b"def helper():\n"
            b"    return None\n"
            b"def build_live_canary_materialization_hooks(context):\n"
            b"    return None\n",
            b"def helper(value=touch()):\n"
            b"    return value\n"
            b"def build_live_canary_materialization_hooks(context):\n"
            b"    return None\n",
            b"class Provider:\n"
            b"    touch()\n"
            b"def build_live_canary_materialization_hooks(context):\n"
            b"    return None\n",
            b"import sys\n"
            b"def build_live_canary_materialization_hooks(context):\n"
            b"    sys.modules['unreviewed_runtime'] = object()\n"
            b"    return None\n",
        )
        for source in invalid:
            with self.subTest(source=source[:30]):
                with self.assertRaises(WindowsServiceError):
                    validate_windows_live_runtime_provider_source(source)

    def test_static_source_validator_requires_declarative_hook_builder(self):
        invalid = (
            VALID_SOURCE.replace(
                b"    def unavailable(*args, **kwargs):\n",
                b"    touch()\n\n    def unavailable(*args, **kwargs):\n",
            ),
            VALID_SOURCE.replace(
                b"    return WindowsLiveCanaryProviderMaterializationHooks(\n",
                b"    return build_hooks_dynamically(\n",
            ),
            VALID_SOURCE.replace(
                b"        runtime_source_reader=unavailable,\n",
                b"        runtime_source_reader=make_hook(),\n",
            ),
        )
        for source in invalid:
            with self.subTest(source=source[-120:]):
                with self.assertRaises(WindowsServiceError):
                    validate_windows_live_runtime_provider_source(source)

    def test_static_source_validator_rejects_forbidden_import_aliases(self):
        invalid = (
            b"from os import system as harmless\n\n" + VALID_SOURCE,
            b"from builtins import __import__ as load_module\n\n"
            + VALID_SOURCE,
            b"from sys import modules as cache\n\n" + VALID_SOURCE,
        )
        for source in invalid:
            with self.subTest(source=source[:60]):
                with self.assertRaises(WindowsServiceError):
                    validate_windows_live_runtime_provider_source(source)

    def test_loader_returns_exact_hooks_and_sealed_non_secret_context(self):
        observed = datetime(2026, 7, 30, 0, 0, tzinfo=UTC)
        with (
            mock.patch.object(execution_policy, "LIVE_ALLOWED", True),
            mock.patch(
                "live_runtime.windows_service_entrypoint._verify_execution_release_manifest",
                return_value=({}, {}),
            ),
            mock.patch(
                "live_runtime.windows_service_entrypoint._reviewed_import_scope",
                return_value=nullcontext(),
            ),
        ):
            context, hooks = load_reviewed_windows_live_runtime_hooks(
                release_root=self.release_root,
                expected_release_identity_sha256=digest("release"),
                factory_context=self.factory_context,
                runtime_provider_path=self.provider,
                expected_runtime_provider_sha256=digest(VALID_SOURCE),
                clock_provider=lambda: observed,
                platform="win32",
            )
        self.assertIs(type(context), WindowsLiveCanaryExternalRuntimeContext)
        self.assertIs(type(hooks), WindowsLiveCanaryProviderMaterializationHooks)
        self.assertEqual(digest(VALID_SOURCE), context.runtime_provider_sha256)
        self.assertEqual(observed, context.observed_at_utc)
        canonical = context.to_canonical_dict()
        self.assertNotIn("hooks", canonical)
        self.assertFalse(canonical["live_allowed"])
        self.assertEqual("DISABLED", canonical["order_capability"])

    def test_loader_rejects_hash_drift_before_module_execution(self):
        with (
            mock.patch.object(execution_policy, "LIVE_ALLOWED", True),
            mock.patch(
                "live_runtime.windows_service_entrypoint._verify_execution_release_manifest",
                return_value=({}, {}),
            ),
            mock.patch(
                "live_runtime.windows_service_entrypoint.validate_windows_live_runtime_provider_source",
                side_effect=AssertionError("source must not parse"),
            ),
            self.assertRaisesRegex(
                WindowsServiceError,
                "LIVE_RUNTIME_PROVIDER_HASH_MISMATCH",
            ),
        ):
            load_reviewed_windows_live_runtime_hooks(
                release_root=self.release_root,
                expected_release_identity_sha256=digest("release"),
                factory_context=self.factory_context,
                runtime_provider_path=self.provider,
                expected_runtime_provider_sha256=digest("wrong"),
                clock_provider=lambda: datetime.now(UTC),
                platform="win32",
            )

    def test_loader_rejects_disabled_policy_before_file_read(self):
        with (
            mock.patch.object(execution_policy, "LIVE_ALLOWED", False),
            mock.patch.object(
                Path,
                "open",
                side_effect=AssertionError("file must not be read"),
            ),
            self.assertRaisesRegex(
                WindowsServiceError,
                "CENTRAL_LIVE_LOCK_NOT_ENABLED",
            ),
        ):
            load_reviewed_windows_live_runtime_hooks(
                release_root=self.release_root,
                expected_release_identity_sha256=digest("release"),
                factory_context=self.factory_context,
                runtime_provider_path=self.provider,
                expected_runtime_provider_sha256=digest(VALID_SOURCE),
                clock_provider=lambda: datetime.now(UTC),
                platform="win32",
            )


if __name__ == "__main__":
    unittest.main()
