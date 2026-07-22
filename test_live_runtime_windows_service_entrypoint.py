from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
import importlib.util
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from live_runtime.offhost_delivery import (
    DeliveryAcknowledgement,
    DeliveryOutbox,
)
from live_runtime.production_bootstrap import (
    ProductionRuntimeBootstrap,
    ProductionRuntimeComposition,
)
from live_runtime.windows_service_entrypoint import (
    WindowsGatedServiceRunner,
    WindowsServiceError,
    WindowsServiceFactoryContext,
    canonical_service_factory_contract_sha256,
    load_reviewed_windows_service_factory,
    seal_windows_service_factory_result,
    validate_reviewed_windows_service_factory_manifest,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 23, 1, 0, tzinfo=UTC)
SENDER_KEY = b"s" * 32
REMOTE_KEY = b"r" * 32
BOOTSTRAP_HASH = "b" * 64
RUN_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


class AckTransport:
    def __init__(self) -> None:
        self.envelopes = []

    def deliver(self, envelope):
        self.envelopes.append(envelope)
        return DeliveryAcknowledgement.create(
            envelope_id=envelope.envelope_id,
            destination_id=envelope.destination_id,
            payload_sha256=envelope.payload_sha256,
            acknowledged_at_utc=NOW,
            remote_key_id="remote-key",
            secret=REMOTE_KEY,
        )


class FailOnceAckTransport(AckTransport):
    def __init__(self) -> None:
        super().__init__()
        self.failed_once = False

    def deliver(self, envelope):
        self.envelopes.append(envelope)
        if not self.failed_once:
            self.failed_once = True
            raise TimeoutError("transient heartbeat outage")
        return DeliveryAcknowledgement.create(
            envelope_id=envelope.envelope_id,
            destination_id=envelope.destination_id,
            payload_sha256=envelope.payload_sha256,
            acknowledged_at_utc=NOW,
            remote_key_id="remote-key",
            secret=REMOTE_KEY,
        )


class StopOnWait:
    def __init__(self) -> None:
        self.waits = []
        self.stopped = False

    def is_set(self):
        return self.stopped

    def set(self):
        self.stopped = True

    def wait(self, timeout):
        self.waits.append(timeout)
        self.stopped = True
        return True


class WindowsServiceEntrypointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def _service_config(self):
        return {
            "service_id": "ai-scalper-gated",
            "owner_id": "windows-service",
            "max_cycles": 2,
            "lease_seconds": 30,
            "heartbeat_ttl_seconds": 30,
            "cycle_interval_seconds": 0.25,
            "cycle_deadline_seconds": 20.0,
        }

    def _release(self, *, factory_source: str | None = None, config=None):
        source = factory_source or "def build(config, context):\n    return object()\n"
        factory = self.root / "reviewed_factory.py"
        service_config = self.root / "service.json"
        factory_manifest = self.root / "factory_manifest.json"
        factory.write_text(source, encoding="utf-8")
        service_config.write_text(
            json.dumps(config or self._service_config(), sort_keys=True),
            encoding="utf-8",
        )
        factory_hash = _sha(factory.read_bytes())
        config_hash = _sha(service_config.read_bytes())
        contract_hash = canonical_service_factory_contract_sha256(
            release_profile="WINDOWS_GATED_EXECUTION_SERVICE_V1",
            factory_module="reviewed_factory",
            factory_attribute="build",
            factory_relative_path="reviewed_factory.py",
            factory_file_sha256=factory_hash,
            service_config_relative_path="service.json",
            service_config_file_sha256=config_hash,
            bootstrap_binding_sha256=BOOTSTRAP_HASH,
        )
        factory_manifest.write_text(
            json.dumps(
                {
                    "release_profile": "WINDOWS_GATED_EXECUTION_SERVICE_V1",
                    "factory_module": "reviewed_factory",
                    "factory_attribute": "build",
                    "factory_relative_path": "reviewed_factory.py",
                    "factory_file_sha256": factory_hash,
                    "service_config_relative_path": "service.json",
                    "service_config_file_sha256": config_hash,
                    "bootstrap_binding_sha256": BOOTSTRAP_HASH,
                    "factory_contract_sha256": contract_hash,
                    "schema_version": "windows-service-factory-manifest-v1",
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        members = []
        for path in (factory_manifest, factory, service_config):
            payload = path.read_bytes()
            members.append(
                {
                    "path": path.name,
                    "size_bytes": len(payload),
                    "sha256": _sha(payload),
                }
            )
        release_base = {
            "schema_version": "ai-scalper-windows-execution-service-manifest-v1",
            "release_profile": "WINDOWS_GATED_EXECUTION_SERVICE_V1",
            "git_commit": "a" * 40,
            "git_tree": "c" * 40,
            "safety": {
                "live_allowed": False,
                "safe_to_demo_auto_order": False,
                "max_lot": 0.01,
                "order_capability": "GATED_PRESENT",
            },
            "source_files": members,
        }
        identity = _sha(_canonical(release_base))
        (self.root / "RELEASE_MANIFEST.json").write_bytes(
            _canonical({**release_base, "release_identity_sha256": identity})
        )
        return factory_manifest, identity

    def test_static_validation_is_import_and_provider_free(self):
        manifest_path, identity = self._release()
        self.assertNotIn("reviewed_factory", sys.modules)
        manifest, config, context = validate_reviewed_windows_service_factory_manifest(
            release_root=self.root,
            manifest_path=manifest_path,
            expected_release_identity_sha256=identity,
        )
        self.assertEqual(manifest.factory_module, "reviewed_factory")
        self.assertEqual(config, self._service_config())
        self.assertEqual(context.bootstrap_binding_sha256, BOOTSTRAP_HASH)
        self.assertNotIn("reviewed_factory", sys.modules)

    def test_static_validation_rejects_unpinned_or_tampered_release(self):
        manifest_path, identity = self._release()
        with self.assertRaisesRegex(WindowsServiceError, "RELEASE_IDENTITY_MISMATCH"):
            validate_reviewed_windows_service_factory_manifest(
                release_root=self.root,
                manifest_path=manifest_path,
                expected_release_identity_sha256="f" * 64,
            )
        (self.root / "service.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(WindowsServiceError, "MEMBER_HASH_MISMATCH"):
            validate_reviewed_windows_service_factory_manifest(
                release_root=self.root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=identity,
            )

    def test_static_validation_rejects_extra_secret_like_config_field(self):
        config = self._service_config() | {"payload": "base64-secret-material"}
        manifest_path, identity = self._release(config=config)
        with self.assertRaisesRegex(WindowsServiceError, "CONFIG_SCHEMA_INVALID"):
            validate_reviewed_windows_service_factory_manifest(
                release_root=self.root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=identity,
            )

    def test_release_root_rejects_unlisted_executable_member(self):
        manifest_path, identity = self._release()
        (self.root / "poisoned_helper.py").write_text(
            "raise RuntimeError('must never import')\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(WindowsServiceError, "EXTRA_MEMBER"):
            validate_reviewed_windows_service_factory_manifest(
                release_root=self.root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=identity,
            )

    def test_factory_rejects_preloaded_site_package_import_origin(self):
        dependency_root = self.root.parent / "site-packages"
        dependency_root.mkdir(exist_ok=True)
        dependency_file = dependency_root / "poisoned_dep.py"
        dependency_file.write_text("VALUE = 'poisoned'\n", encoding="utf-8")
        poisoned = ModuleType("poisoned_dep")
        poisoned.__spec__ = importlib.util.spec_from_file_location(
            "poisoned_dep", dependency_file
        )
        sys.modules["poisoned_dep"] = poisoned
        self.addCleanup(sys.modules.pop, "poisoned_dep", None)
        manifest_path, identity = self._release(
            factory_source=(
                "import poisoned_dep\n"
                "def build(config, context):\n"
                "    return object()\n"
            )
        )
        with self.assertRaisesRegex(WindowsServiceError, "IMPORT_ORIGIN_DENIED"):
            load_reviewed_windows_service_factory(
                release_root=self.root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=identity,
            )

    def test_factory_invocation_rejects_local_preloaded_site_package_import(self):
        dependency_root = self.root.parent / "site-packages"
        dependency_root.mkdir(exist_ok=True)
        dependency_file = dependency_root / "poisoned_local_dep.py"
        dependency_file.write_text("VALUE = 'poisoned'\n", encoding="utf-8")
        poisoned = ModuleType("poisoned_local_dep")
        poisoned.__spec__ = importlib.util.spec_from_file_location(
            "poisoned_local_dep", dependency_file
        )
        sys.modules["poisoned_local_dep"] = poisoned
        self.addCleanup(sys.modules.pop, "poisoned_local_dep", None)
        manifest_path, identity = self._release(
            factory_source=(
                "def build(config, context):\n"
                "    import poisoned_local_dep\n"
                "    return object()\n"
            )
        )
        with self.assertRaisesRegex(WindowsServiceError, "IMPORT_ORIGIN_DENIED"):
            load_reviewed_windows_service_factory(
                release_root=self.root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=identity,
            )

    def test_factory_invocation_rejects_importlib_preloaded_site_package(self):
        dependency_root = self.root.parent / "site-packages"
        dependency_root.mkdir(exist_ok=True)
        dependency_file = dependency_root / "poisoned_importlib_dep.py"
        dependency_file.write_text("VALUE = 'poisoned'\n", encoding="utf-8")
        poisoned = ModuleType("poisoned_importlib_dep")
        poisoned.__spec__ = importlib.util.spec_from_file_location(
            "poisoned_importlib_dep", dependency_file
        )
        sys.modules["poisoned_importlib_dep"] = poisoned
        self.addCleanup(sys.modules.pop, "poisoned_importlib_dep", None)
        manifest_path, identity = self._release(
            factory_source=(
                "import importlib\n"
                "def build(config, context):\n"
                "    importlib.import_module('poisoned_importlib_dep')\n"
                "    return object()\n"
            )
        )
        with self.assertRaisesRegex(WindowsServiceError, "IMPORT_ORIGIN_DENIED"):
            load_reviewed_windows_service_factory(
                release_root=self.root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=identity,
            )

    def test_factory_invocation_rejects_bound_import_module_site_package(self):
        dependency_root = self.root.parent / "site-packages"
        dependency_root.mkdir(exist_ok=True)
        dependency_file = dependency_root / "poisoned_bound_dep.py"
        dependency_file.write_text("VALUE = 'poisoned'\n", encoding="utf-8")
        poisoned = ModuleType("poisoned_bound_dep")
        poisoned.__spec__ = importlib.util.spec_from_file_location(
            "poisoned_bound_dep", dependency_file
        )
        sys.modules["poisoned_bound_dep"] = poisoned
        self.addCleanup(sys.modules.pop, "poisoned_bound_dep", None)
        manifest_path, identity = self._release(
            factory_source=(
                "def build(config, context):\n"
                "    from importlib import import_module\n"
                "    import_module('poisoned_bound_dep')\n"
                "    return object()\n"
            )
        )
        with self.assertRaisesRegex(WindowsServiceError, "IMPORT_ORIGIN_DENIED"):
            load_reviewed_windows_service_factory(
                release_root=self.root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=identity,
            )

    def test_factory_importlib_allows_attested_stdlib_import(self):
        manifest_path, identity = self._release(
            factory_source=(
                "import importlib\n"
                "def build(config, context):\n"
                "    assert importlib.import_module('json').dumps is not None\n"
                "    return object()\n"
            )
        )
        with self.assertRaisesRegex(WindowsServiceError, "RESULT_NOT_SEALED"):
            load_reviewed_windows_service_factory(
                release_root=self.root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=identity,
            )

    def test_factory_importlib_dynamic_file_loader_is_denied(self):
        manifest_path, identity = self._release(
            factory_source=(
                "import importlib\n"
                "def build(config, context):\n"
                "    importlib.util.spec_from_file_location('x', __file__)\n"
                "    return object()\n"
            )
        )
        with self.assertRaisesRegex(WindowsServiceError, "DYNAMIC_LOADER_DENIED"):
            load_reviewed_windows_service_factory(
                release_root=self.root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=identity,
            )

    def test_factory_reattests_preloaded_module_after_invocation(self):
        dependency_root = self.root.parent / "site-packages"
        dependency_root.mkdir(exist_ok=True)
        poisoned_origin = dependency_root / "mutated_origin.py"
        poisoned_origin.write_text("VALUE = 1\n", encoding="utf-8")
        mutable = ModuleType("mutable_preloaded_dep")
        mutable.__spec__ = importlib.util.spec_from_file_location(
            "mutable_preloaded_dep", Path(json.__file__).resolve()
        )
        sys.modules["mutable_preloaded_dep"] = mutable
        self.addCleanup(sys.modules.pop, "mutable_preloaded_dep", None)
        manifest_path, identity = self._release(
            factory_source=(
                "import importlib\n"
                "def build(config, context):\n"
                "    dependency = importlib.import_module('mutable_preloaded_dep')\n"
                f"    dependency.__spec__.origin = {str(poisoned_origin)!r}\n"
                "    return object()\n"
            )
        )
        with self.assertRaisesRegex(WindowsServiceError, "IMPORT_ORIGIN_DENIED"):
            load_reviewed_windows_service_factory(
                release_root=self.root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=identity,
            )

    def test_every_path_component_indirection_is_rejected(self):
        manifest_path, identity = self._release()
        link = self.root / "manifest-link.json"
        try:
            link.symlink_to(manifest_path)
        except OSError:
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(WindowsServiceError, "INDIRECTION_DENIED"):
            validate_reviewed_windows_service_factory_manifest(
                release_root=self.root,
                manifest_path=link,
                expected_release_identity_sha256=identity,
            )

    def test_preloaded_module_cannot_redirect_exact_factory_file(self):
        manifest_path, identity = self._release()
        poisoned = ModuleType("reviewed_factory")
        poisoned.build = lambda *_args: "POISONED"
        sys.modules["reviewed_factory"] = poisoned
        self.addCleanup(sys.modules.pop, "reviewed_factory", None)
        with self.assertRaisesRegex(WindowsServiceError, "RESULT_NOT_SEALED"):
            load_reviewed_windows_service_factory(
                release_root=self.root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=identity,
            )
        self.assertIs(sys.modules["reviewed_factory"], poisoned)

    def _factory_result(self):
        bootstrap = object.__new__(ProductionRuntimeBootstrap)
        bootstrap.config = SimpleNamespace(safe_binding_sha256=BOOTSTRAP_HASH)
        outbox = DeliveryOutbox(self.root / "heartbeat.sqlite3")
        transport = AckTransport()
        context = WindowsServiceFactoryContext(
            release_root_sha256="1" * 64,
            factory_contract_sha256="2" * 64,
            factory_file_sha256="3" * 64,
            service_config_file_sha256="4" * 64,
            bootstrap_binding_sha256=BOOTSTRAP_HASH,
        )
        result = seal_windows_service_factory_result(
            bootstrap=bootstrap,
            context=context,
            heartbeat_outbox=outbox,
            heartbeat_transport=transport,
            heartbeat_destination_id="ops-offhost",
            heartbeat_sender_key_id="sender-key",
            heartbeat_sender_key_fingerprint_sha256=_sha(SENDER_KEY),
            heartbeat_remote_key_id="remote-key",
            heartbeat_remote_key_fingerprint_sha256=_sha(REMOTE_KEY),
            heartbeat_sender_key_provider=lambda _key_id: SENDER_KEY,
            heartbeat_remote_key_provider=lambda _key_id: REMOTE_KEY,
            clock_provider=lambda: NOW,
        )
        return result, transport

    def test_clean_run_has_sealed_shutdown_receipt_and_chained_heartbeats(self):
        result, transport = self._factory_result()
        composition = object.__new__(ProductionRuntimeComposition)
        cycle = SimpleNamespace(content_sha256="6" * 64)
        shutdown = SimpleNamespace(content_sha256="7" * 64)
        runner = WindowsGatedServiceRunner(
            result,
            service_id="ai-scalper-gated",
            owner_id="windows-service",
            heartbeat_ttl_seconds=30,
            service_run_id=RUN_ID,
        )
        with (
            patch.object(
                ProductionRuntimeBootstrap, "materialize", return_value=composition
            ),
            patch.object(ProductionRuntimeComposition, "initialize") as initialize,
            patch.object(
                ProductionRuntimeComposition,
                "start",
                return_value=SimpleNamespace(content_sha256="5" * 64),
            ) as start,
            patch.object(
                ProductionRuntimeComposition, "run_cycle", return_value=cycle
            ) as run_cycle,
            patch.object(
                ProductionRuntimeComposition, "stop", return_value=shutdown
            ) as stop,
            patch.object(ProductionRuntimeComposition, "shutdown") as shutdown_call,
        ):
            receipts = runner.run(
                max_cycles=1,
                cycle_interval_seconds=0.25,
                cycle_deadline_seconds=20,
            )
        self.assertEqual(receipts, (cycle,))
        initialize.assert_called_once_with()
        start.assert_called_once()
        run_cycle.assert_called_once_with()
        stop.assert_called_once_with()
        shutdown_call.assert_called_once_with()
        payloads = [json.loads(item.payload_json) for item in transport.envelopes]
        self.assertEqual(
            [item["phase"] for item in payloads],
            ["STARTING", "INITIALIZED", "RUNNING", "RUNNING", "STOPPING", "STOPPED"],
        )
        self.assertTrue(all(item["service_run_id"] == RUN_ID for item in payloads))
        self.assertEqual(payloads[0]["previous_status_sha256"], "0" * 64)
        for previous, current in zip(payloads, payloads[1:]):
            previous_sha = hashlib.sha256(
                json.dumps(
                    previous,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()
            self.assertEqual(current["previous_status_sha256"], previous_sha)

    def test_composition_cycle_failure_is_not_fail_closed_twice(self):
        result, _transport = self._factory_result()
        composition = object.__new__(ProductionRuntimeComposition)
        composition.supervisor = SimpleNamespace(fail_closed=Mock())

        def already_owned_failure():
            composition.supervisor.fail_closed("OWNED_BY_COMPOSITION")
            raise RuntimeError("cycle failed")

        runner = WindowsGatedServiceRunner(
            result,
            service_id="ai-scalper-gated",
            owner_id="windows-service",
            service_run_id=RUN_ID,
        )
        with (
            patch.object(
                ProductionRuntimeBootstrap, "materialize", return_value=composition
            ),
            patch.object(ProductionRuntimeComposition, "initialize"),
            patch.object(
                ProductionRuntimeComposition,
                "start",
                return_value=SimpleNamespace(content_sha256="5" * 64),
            ),
            patch.object(
                ProductionRuntimeComposition,
                "run_cycle",
                side_effect=already_owned_failure,
            ),
            patch.object(ProductionRuntimeComposition, "shutdown"),
        ):
            with self.assertRaisesRegex(RuntimeError, "cycle failed"):
                runner.run(
                    max_cycles=1,
                    cycle_interval_seconds=0.25,
                    cycle_deadline_seconds=20,
                )
        composition.supervisor.fail_closed.assert_called_once_with(
            "OWNED_BY_COMPOSITION"
        )

    def test_cycle_interval_wait_is_interruptible_and_stops_once(self):
        result, _transport = self._factory_result()
        composition = object.__new__(ProductionRuntimeComposition)
        runner = WindowsGatedServiceRunner(
            result,
            service_id="ai-scalper-gated",
            owner_id="windows-service",
            service_run_id=RUN_ID,
        )
        event = StopOnWait()
        runner.stop_event = event
        with (
            patch.object(
                ProductionRuntimeBootstrap, "materialize", return_value=composition
            ),
            patch.object(ProductionRuntimeComposition, "initialize"),
            patch.object(
                ProductionRuntimeComposition,
                "start",
                return_value=SimpleNamespace(content_sha256="5" * 64),
            ),
            patch.object(
                ProductionRuntimeComposition,
                "run_cycle",
                return_value=SimpleNamespace(content_sha256="6" * 64),
            ) as run_cycle,
            patch.object(
                ProductionRuntimeComposition,
                "stop",
                return_value=SimpleNamespace(content_sha256="7" * 64),
            ) as stop,
            patch.object(ProductionRuntimeComposition, "shutdown"),
        ):
            receipts = runner.run(
                max_cycles=2,
                cycle_interval_seconds=0.25,
                cycle_deadline_seconds=20,
            )
        self.assertEqual(len(receipts), 1)
        self.assertEqual(run_cycle.call_count, 1)
        stop.assert_called_once_with()
        self.assertEqual(len(event.waits), 1)
        self.assertGreater(event.waits[0], 0)
        self.assertLessEqual(event.waits[0], 0.25)

    def test_transient_delivery_recovery_keeps_one_durable_chain(self):
        result, _transport = self._factory_result()
        transport = FailOnceAckTransport()
        object.__setattr__(result, "heartbeat_transport", transport)
        runner = WindowsGatedServiceRunner(
            result,
            service_id="ai-scalper-gated",
            owner_id="windows-service",
            service_run_id=RUN_ID,
        )
        with self.assertRaisesRegex(WindowsServiceError, "NOT_ACKNOWLEDGED"):
            runner._heartbeat("STARTING")
        recovered = runner._heartbeat("FAILED", reason_code="TRANSIENT_FAILURE")
        records = result.heartbeat_outbox.records()
        payloads = [
            json.loads(item["envelope"].payload_json)
            for item in records
            if json.loads(item["envelope"].payload_json).get("service_run_id")
            == RUN_ID
        ]
        self.assertEqual([1, 2], [item["sequence"] for item in payloads])
        self.assertTrue(all(item["state"] == "ACKNOWLEDGED" for item in records))
        predecessor = hashlib.sha256(
            json.dumps(
                payloads[0],
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(payloads[1]["previous_status_sha256"], predecessor)
        self.assertEqual(recovered.sequence, 2)

    def test_cycle_deadline_aborts_then_hard_terminates_worker(self):
        result, _transport = self._factory_result()
        runner = WindowsGatedServiceRunner(
            result,
            service_id="ai-scalper-gated",
            owner_id="windows-service",
            service_run_id=RUN_ID,
        )
        release_worker = threading.Event()
        composition = SimpleNamespace(
            run_cycle=lambda: release_worker.wait(5),
            abort_fail_closed=Mock(side_effect=RuntimeError("latched")),
        )
        try:
            with patch(
                "live_runtime.windows_service_entrypoint._hard_terminate_process",
                side_effect=SystemExit(70),
            ) as terminate:
                with self.assertRaises(SystemExit):
                    runner._run_cycle_with_deadline(
                        composition=composition,
                        deadline_seconds=0.02,
                        prior_receipt_sha256="5" * 64,
                    )
        finally:
            release_worker.set()
        composition.abort_fail_closed.assert_called_once()
        terminate.assert_called_with(70)
        self.assertTrue(runner._lifecycle_abort_handled)


if __name__ == "__main__":
    unittest.main()
