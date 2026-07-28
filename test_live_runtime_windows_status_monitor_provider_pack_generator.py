from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import live_runtime.windows_status_monitor_provider_pack_generator as status_pack_module
from build_windows_release import _canonical_json, _create_archive
from live_runtime.windows_external_status_monitor_entrypoint import (
    parse_windows_external_status_monitor_config,
)
from live_runtime.windows_provider_primitives import (
    CredentialReference,
    WindowsClockBinding,
)
from live_runtime.windows_status_monitor_provider_pack import (
    WindowsStatusMonitorProviderError,
    build_windows_status_monitor_dependencies,
    windows_status_monitor_provider_configuration_from_dict,
)
from live_runtime.windows_status_monitor_provider_pack_generator import (
    GENERATED_PATHS,
    StatusMonitorProviderPackError,
    _extract_provider_configuration,
    prepare_windows_status_monitor_provider_pack,
    validate_windows_status_monitor_provider_pack,
)
from test_live_runtime_windows_base_release_suite import (
    write_suite_from_role_bases,
)


def canonical_file(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"


class WindowsStatusMonitorProviderPackGeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.suite_root, self.status_base, self.suite_manifest = (
            self._base_suite()
        )
        self.pack_input = self.root / "status-provider-input.json"
        self.pack_input.write_bytes(canonical_file(self._pack_payload()))

    def _base_suite(
        self,
        *,
        root: Path | None = None,
        omit: str | None = None,
        primitive_suffix: bytes = b"",
    ):
        target = self.root if root is None else root
        target.mkdir(parents=True, exist_ok=True)
        source = Path(__file__).resolve().parent
        paths = (
            "live_runtime/windows_status_monitor_provider_pack.py",
            "live_runtime/windows_provider_primitives.py",
            "live_runtime/offhost_delivery.py",
        )
        sources = {
            "live_runtime/__init__.py": b"",
            "live_runtime/windows_external_status_monitor_entrypoint.py": (
                source
                / "live_runtime/windows_external_status_monitor_entrypoint.py"
            ).read_bytes(),
            (
                "live_runtime/windows_external_status_monitor_factory_template.py"
            ): (
                source
                / "live_runtime/windows_external_status_monitor_factory_template.py"
            ).read_bytes(),
        }
        for path in paths:
            if path == omit:
                continue
            data = (source / path).read_bytes()
            if path == "live_runtime/windows_provider_primitives.py":
                data += primitive_suffix
            sources[path] = data
        unsigned = {
            "schema_version": (
                "ai-scalper-windows-status-monitor-manifest-v1"
            ),
            "release_profile": "WINDOWS_EXTERNAL_STATUS_MONITOR_V1",
            "git_commit": "1" * 40,
            "git_tree": "2" * 40,
            "safety": {
                "live_allowed": False,
                "safe_to_demo_auto_order": False,
                "max_lot": 0.01,
                "order_capability": "DISABLED",
            },
            "production_execution_ready": False,
            "readiness_blockers": [
                "EXTERNAL_MONITOR_PROVIDER_CONFIGURATION_REQUIRED"
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
        archive = target / "status-monitor-base-source.zip"
        archive.write_bytes(
            _create_archive(
                sources,
                _canonical_json(manifest) + b"\n",
            )
        )
        suite, suite_manifest, _manifests = write_suite_from_role_bases(
            target,
            {"STATUS_MONITOR": (archive, manifest)},
        )
        return (
            suite,
            suite / "status-monitor-base-v1.zip",
            suite_manifest,
        )

    @staticmethod
    def _clock_and_references():
        keys = {
            "monitor-clock-key": b"clock-key-material-for-status-monitor",
            "monitor-snapshot-key": b"snapshot-key-material-for-monitor-v1",
            "monitor-checkpoint-key": b"checkpoint-key-material-monitor-v1",
            "monitor-incident-key": b"incident-key-material-for-monitor-v1",
            "monitor-heartbeat-key": b"heartbeat-key-material-monitor-v1",
            "monitor-alert-key": b"alert-key-material-for-status-monitor",
            "monitor-remote-ack-key": b"remote-ack-key-material-monitor-v1",
        }
        clock = WindowsClockBinding(
            provider_id="monitor-clock-v1",
            host_identity_sha256="a" * 64,
            authority_issuer_id="monitor-clock-authority-v1",
            authority_key_id="monitor-clock-key",
            authority_key_fingerprint_sha256=hashlib.sha256(
                keys["monitor-clock-key"]
            ).hexdigest(),
            maximum_attestation_age_ms=10_000,
            maximum_absolute_drift_ms=1_000,
        )
        prefix = "AI_SCALPER/STATUS_MONITOR"
        references = tuple(
            CredentialReference(
                key_id=key_id,
                target_name=f"{prefix}/{key_id}",
                fingerprint_sha256=hashlib.sha256(value).hexdigest(),
            )
            for key_id, value in sorted(keys.items())
        )
        return clock, references

    def _pack_payload(self) -> dict[str, object]:
        clock, references = self._clock_and_references()
        return {
            "schema_version": (
                "windows-status-monitor-provider-pack-input-v1"
            ),
            "pack_id": "reviewed-monitor-provider-v1",
            "runtime": {
                "monitor_service_id": "ai-scalper-monitor-v1",
                "monitor_provider_id": "reviewed-monitor-provider-v1",
                "monitor_service_account_id": "svc-ai-scalper-monitor",
                "decision_service_id": "ai-scalper-decision-v1",
                "execution_service_id": "ai-scalper-execution-v1",
                "decision_service_account_id": "svc-ai-scalper-decision",
                "execution_service_account_id": "svc-ai-scalper-execution",
                "decision_release_identity_sha256": "1" * 64,
                "execution_release_identity_sha256": "2" * 64,
                "decision_task_definition_sha256": "3" * 64,
                "execution_task_definition_sha256": "4" * 64,
                "decision_ipc_binding_sha256": "5" * 64,
                "snapshot_checkpoint_provider_id": (
                    "monitor-checkpoint-cas-v1"
                ),
                "incident_latch_provider_id": (
                    "monitor-incident-latch-v1"
                ),
                "heartbeat_destination_id": (
                    "offhost-monitor-heartbeat-v1"
                ),
                "alert_destination_id": "offhost-monitor-alert-v1",
                "thresholds": {
                    "max_clock_drift_seconds": 1.0,
                    "minimum_free_disk_gib": 10.0,
                    "max_service_status_age_seconds": 30,
                    "max_audit_export_age_seconds": 300,
                    "max_backup_anchor_age_seconds": 86_400,
                    "max_snapshot_age_seconds": 30,
                    "schema_version": (
                        "windows-external-status-monitor-thresholds-v1"
                    ),
                },
                "max_cycles": 100,
                "poll_seconds": 5.0,
                "cycle_deadline_seconds": 10.0,
            },
            "clock_binding": clock.to_canonical_dict(),
            "credential_target_prefix": "AI_SCALPER/STATUS_MONITOR",
            "credential_references": [
                item.to_canonical_dict() for item in references
            ],
            "keys": {
                "snapshot_key_id": "monitor-snapshot-key",
                "checkpoint_key_id": "monitor-checkpoint-key",
                "incident_key_id": "monitor-incident-key",
                "heartbeat_sender_key_id": "monitor-heartbeat-key",
                "alert_sender_key_id": "monitor-alert-key",
                "remote_ack_key_id": "monitor-remote-ack-key",
            },
            "storage": {
                "clock_attestation_path": (
                    r"C:\AI_SCALPER_STATE\monitor\clock.json"
                ),
                "snapshot_directory": (
                    r"C:\AI_SCALPER_STATE\monitor\snapshots"
                ),
                "checkpoint_current_path": (
                    r"C:\AI_SCALPER_STATE\monitor\checkpoint.json"
                ),
                "heartbeat_outbox_database": (
                    r"C:\AI_SCALPER_STATE\monitor\heartbeat.sqlite3"
                ),
                "alert_outbox_database": (
                    r"C:\AI_SCALPER_STATE\monitor\alert.sqlite3"
                ),
            },
            "checkpoint": {
                "provider_id": "monitor-checkpoint-cas-v1",
                "request_directory": (
                    r"C:\AI_SCALPER_STATE\monitor\checkpoint-requests"
                ),
                "response_directory": (
                    r"C:\AI_SCALPER_STATE\monitor\checkpoint-responses"
                ),
            },
            "incident": {
                "provider_id": "monitor-incident-latch-v1",
                "request_directory": (
                    r"C:\AI_SCALPER_STATE\monitor\incident-requests"
                ),
                "response_directory": (
                    r"C:\AI_SCALPER_STATE\monitor\incident-responses"
                ),
            },
            "delivery": {
                "heartbeat_outbound_directory": (
                    r"C:\AI_SCALPER_STATE\monitor\heartbeat-out"
                ),
                "heartbeat_acknowledgement_directory": (
                    r"C:\AI_SCALPER_STATE\monitor\heartbeat-acks"
                ),
                "alert_outbound_directory": (
                    r"C:\AI_SCALPER_STATE\monitor\alert-out"
                ),
                "alert_acknowledgement_directory": (
                    r"C:\AI_SCALPER_STATE\monitor\alert-acks"
                ),
            },
            "provider_timeout_seconds": 1.0,
            "safety": {
                "status_only": True,
                "order_capability": "DISABLED",
                "live_allowed": False,
                "safe_to_demo_auto_order": False,
                "max_lot": 0.01,
                "promotion_eligible": False,
                "production_execution_ready": False,
            },
        }

    def test_ac1_ac11_prepare_and_validate_exact_deterministic_pack(self):
        first = self.root / "pack-first"
        second = self.root / "pack-second"
        first_result = prepare_windows_status_monitor_provider_pack(
            base_suite_root=self.suite_root,
            status_monitor_base_release=self.status_base,
            pack_input_path=self.pack_input,
            output_root=first,
        )
        second_result = prepare_windows_status_monitor_provider_pack(
            base_suite_root=self.suite_root,
            status_monitor_base_release=self.status_base,
            pack_input_path=self.pack_input,
            output_root=second,
        )
        self.assertEqual(first_result.status, "EXTERNAL_PROVIDER_ACCEPTANCE_REQUIRED")
        self.assertFalse(first_result.production_execution_ready)
        self.assertFalse(first_result.credential_access_performed)
        self.assertEqual(
            {
                path.relative_to(first).as_posix()
                for path in first.rglob("*")
                if path.is_file()
            },
            set(GENERATED_PATHS),
        )
        for path in GENERATED_PATHS:
            self.assertEqual(
                (first / path).read_bytes(),
                (second / path).read_bytes(),
            )
        validated = validate_windows_status_monitor_provider_pack(
            base_suite_root=self.suite_root,
            status_monitor_base_release=self.status_base,
            pack_root=first,
        )
        self.assertEqual(
            validated.pack_identity_sha256,
            first_result.pack_identity_sha256,
        )
        config = parse_windows_external_status_monitor_config(
            json.loads(
                (first / "config/windows_service_config.json")
                .read_text(encoding="utf-8")
            )
        )
        self.assertEqual(len(config.providers), 12)
        self.assertFalse(config.live_allowed)
        self.assertFalse(config.safe_to_demo_auto_order)
        provider_config = (
            windows_status_monitor_provider_configuration_from_dict(
                _extract_provider_configuration(
                    (
                        first
                        / "configured_providers/status_monitor_provider.py"
                    ).read_bytes()
                )
            )
        )
        effects: list[str] = []

        class Backend:
            def read_blob(self, _target):
                effects.append("CREDENTIAL")
                return None

        with self.assertRaisesRegex(
            WindowsStatusMonitorProviderError,
            "WINDOWS_PLATFORM_REQUIRED",
        ):
            build_windows_status_monitor_dependencies(
                runtime_config=config,
                provider_config=provider_config,
                platform="darwin",
                credential_backend=Backend(),
                path_resolver=lambda _value: effects.append("PATH"),
            )
        self.assertEqual(effects, [])

    def test_ac13_missing_foundation_member_rejects_before_output(self):
        missing_root = self.root / "missing-suite"
        suite, status_base, _manifest = self._base_suite(
            root=missing_root,
            omit="live_runtime/offhost_delivery.py",
        )
        output = self.root / "missing-output"
        with self.assertRaisesRegex(
            StatusMonitorProviderPackError,
            "STATUS_MONITOR_PROVIDER_FOUNDATION_MISSING",
        ):
            prepare_windows_status_monitor_provider_pack(
                base_suite_root=suite,
                status_monitor_base_release=status_base,
                pack_input_path=self.pack_input,
                output_root=output,
            )
        self.assertFalse(output.exists())

    def test_ac13_shared_primitive_change_changes_role_hashes(self):
        first = self.root / "hash-first"
        prepare_windows_status_monitor_provider_pack(
            base_suite_root=self.suite_root,
            status_monitor_base_release=self.status_base,
            pack_input_path=self.pack_input,
            output_root=first,
        )
        changed_root = self.root / "changed-suite"
        suite, status_base, _manifest = self._base_suite(
            root=changed_root,
            primitive_suffix=b"\n# reviewed-test-byte\n",
        )
        second = self.root / "hash-second"
        prepare_windows_status_monitor_provider_pack(
            base_suite_root=suite,
            status_monitor_base_release=status_base,
            pack_input_path=self.pack_input,
            output_root=second,
        )
        first_config = json.loads(
            (first / "config/windows_service_config.json").read_text()
        )
        second_config = json.loads(
            (second / "config/windows_service_config.json").read_text()
        )
        self.assertNotEqual(
            [item["implementation_sha256"] for item in first_config["providers"]],
            [item["implementation_sha256"] for item in second_config["providers"]],
        )

    def test_ac12_secret_and_noncanonical_input_fail_transactionally(self):
        payload = self._pack_payload()
        payload["password"] = "must-never-exist"
        self.pack_input.write_bytes(canonical_file(payload))
        output = self.root / "unsafe-output"
        with self.assertRaises(StatusMonitorProviderPackError):
            prepare_windows_status_monitor_provider_pack(
                base_suite_root=self.suite_root,
                status_monitor_base_release=self.status_base,
                pack_input_path=self.pack_input,
                output_root=output,
            )
        self.assertFalse(output.exists())


    def test_cleanup_preserves_replaced_pack_root(self):
        pack_root = self.root / "owned-pack"
        displaced = self.root / "displaced-pack"
        replacement = self.root / "replacement-pack"
        pack_root.mkdir()
        identity = status_pack_module._directory_identity(
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

        status_pack_module._cleanup(pack_root, identity, [])

        self.assertTrue(pack_root.is_symlink())
        self.assertEqual(Path(replacement.name), pack_root.readlink())
        self.assertTrue(displaced.is_dir())


if __name__ == "__main__":
    unittest.main()
