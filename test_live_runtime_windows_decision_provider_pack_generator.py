from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import live_runtime.windows_decision_provider_pack_generator as decision_pack_module
from build_windows_release import _canonical_json, _create_archive
from live_runtime.brokerless_decision_producer import (
    DecisionProducerBinding,
    DecisionProducerLaneConfig,
    decision_producer_key_fingerprint,
)
from live_runtime.decision_feed import (
    DecisionFeedBinding,
    DecisionFeedLaneBinding,
    decision_feed_key_fingerprint,
)
from live_runtime.decision_ipc import (
    DecisionIPCBinding,
    decision_ipc_key_fingerprint,
)
from live_runtime.windows_decision_provider_pack import (
    CredentialReference,
    WindowsClockBinding,
    parse_windows_decision_provider_configuration,
    validate_windows_decision_provider_bindings,
)
from live_runtime.windows_decision_provider_pack_generator import (
    GENERATED_PATHS,
    DecisionProviderPackError,
    _extract_provider_configuration,
    _implementation_hashes,
    prepare_windows_decision_provider_pack,
    validate_windows_decision_provider_pack,
)
from live_runtime.configured_service_release import (
    build_configured_service_release,
    prepare_configured_overlay_candidate,
)
from live_runtime.windows_decision_service_entrypoint import (
    parse_windows_decision_service_runtime_config,
)
from prepare_windows_decision_provider_pack import (
    _parser as prepare_parser,
    main as prepare_main,
)
from test_live_runtime_windows_base_release_suite import (
    write_suite_from_role_bases,
)
from validate_windows_decision_provider_pack import (
    _parser as validate_parser,
    main as validate_main,
)


HASH_A = hashlib.sha256(b"a").hexdigest()
HASH_B = hashlib.sha256(b"b").hexdigest()
HASH_C = hashlib.sha256(b"c").hexdigest()
COMMIT = hashlib.sha1(b"commit").hexdigest()
DECISION_KEY = b"generator-decision-signing-key-material-minimum"
IPC_KEY = b"generator-ipc-custody-key-material-minimum"
CURSOR_KEY = b"generator-cursor-custody-key-material-minimum"
FEED_KEY = b"generator-feed-key-material-minimum"
CALENDAR_KEY = b"generator-calendar-key-material-minimum"
CLOCK_KEY = b"generator-clock-key-material-minimum"


def canonical_file(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"


class WindowsDecisionProviderPackGeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.suite_root, self.decision_base, self.suite_manifest = (
            self._base_suite()
        )
        self.pack_input = self.root / "provider-pack-input.json"
        self.pack_input.write_bytes(canonical_file(self._pack_payload()))

    def _base_suite(
        self,
        *,
        root: Path | None = None,
        include_primitives: bool = True,
    ) -> tuple[Path, Path, dict[str, object]]:
        target_root = self.root if root is None else root
        target_root.mkdir(parents=True, exist_ok=True)
        source_root = Path(__file__).resolve().parent
        foundation = (
            source_root / "live_runtime/windows_decision_provider_pack.py"
        ).read_bytes()
        sources = {
            "live_runtime/__init__.py": b"",
            "live_runtime/windows_decision_service_entrypoint.py": (
                source_root
                / "live_runtime/windows_decision_service_entrypoint.py"
            ).read_bytes(),
            "live_runtime/windows_decision_service_factory_template.py": (
                source_root
                / "live_runtime/windows_decision_service_factory_template.py"
            ).read_bytes(),
            "live_runtime/windows_decision_provider_pack.py": foundation,
        }
        if include_primitives:
            sources["live_runtime/windows_provider_primitives.py"] = (
                source_root / "live_runtime/windows_provider_primitives.py"
            ).read_bytes()
        unsigned = {
            "schema_version": (
                "ai-scalper-windows-decision-service-manifest-v1"
            ),
            "release_profile": "WINDOWS_DECISION_SERVICE_V1",
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
        archive = target_root / "decision-base-source.zip"
        archive.write_bytes(
            _create_archive(
                sources,
                _canonical_json(manifest) + b"\n",
            )
        )
        suite, suite_manifest, _manifests = write_suite_from_role_bases(
            target_root,
            {"DECISION": (archive, manifest)},
        )
        return (
            suite,
            suite / "decision-base-v1.zip",
            suite_manifest,
        )

    @staticmethod
    def _bindings() -> tuple[
        DecisionProducerBinding,
        DecisionFeedBinding,
        DecisionIPCBinding,
        WindowsClockBinding,
        tuple[CredentialReference, ...],
    ]:
        lane = DecisionProducerLaneConfig(
            lane_id="xauusd-m15-primary",
            symbol="XAUUSD",
            source_name="broker-signed-feed",
            data_contract_sha256=HASH_A,
            model_version="champion-v1",
            model_artifact_sha256=HASH_B,
            commit_sha=COMMIT,
            config_sha256=HASH_C,
            session_calendar_sha256=HASH_B,
            session_calendar_issuer_id="calendar-v1",
            session_calendar_key_id="calendar-key-v1",
            session_calendar_key_fingerprint_sha256=(
                decision_producer_key_fingerprint(CALENDAR_KEY)
            ),
        )
        producer = DecisionProducerBinding(
            service_id="decision-service-v1",
            lanes=(lane,),
            custody_issuer_id="cursor-custody-v1",
            custody_key_id="cursor-key-v1",
            custody_key_fingerprint_sha256=(
                decision_producer_key_fingerprint(CURSOR_KEY)
            ),
        )
        feed = DecisionFeedBinding(
            feed_id="decision-feed-v1",
            broker_server="Reviewed-Demo-Server",
            broker_account_identity_sha256=HASH_A,
            publisher_issuer_id="feed-publisher-v1",
            publisher_key_id="feed-key-v1",
            publisher_key_fingerprint_sha256=(
                decision_feed_key_fingerprint(FEED_KEY)
            ),
            lanes=(
                DecisionFeedLaneBinding(
                    lane_id=lane.lane_id,
                    symbol=lane.symbol,
                    broker_symbol="XAUUSD",
                    source_name=lane.source_name,
                    data_contract_sha256=lane.data_contract_sha256,
                    session_calendar_sha256=(
                        lane.session_calendar_sha256
                    ),
                ),
            ),
        )
        ipc = DecisionIPCBinding(
            queue_id="decision-queue-v1",
            account_id_sha256=HASH_A,
            server=feed.broker_server,
            environment="DEMO",
            journal_sha256=HASH_C,
            commit_sha=COMMIT,
            config_sha256=HASH_C,
            model_artifact_sha256=HASH_B,
            data_contract_sha256=HASH_A,
            decision_issuer_id=producer.service_id,
            decision_key_id="decision-key-v1",
            decision_key_fingerprint_sha256=(
                decision_ipc_key_fingerprint(DECISION_KEY)
            ),
            custody_issuer_id="ipc-custody-v1",
            custody_key_id="ipc-key-v1",
            custody_key_fingerprint_sha256=(
                decision_ipc_key_fingerprint(IPC_KEY)
            ),
            permit_key_id="downstream-permit-key-v1",
            permit_key_fingerprint_sha256=HASH_C,
        )
        clock = WindowsClockBinding(
            provider_id="decision-clock-v1",
            host_identity_sha256=HASH_C,
            authority_issuer_id="clock-authority-v1",
            authority_key_id="clock-key-v1",
            authority_key_fingerprint_sha256=hashlib.sha256(
                CLOCK_KEY
            ).hexdigest(),
            maximum_attestation_age_ms=10_000,
            maximum_absolute_drift_ms=1_000,
        )
        keys = {
            ipc.decision_key_id: (
                ipc.decision_key_fingerprint_sha256
            ),
            ipc.custody_key_id: (
                ipc.custody_key_fingerprint_sha256
            ),
            producer.custody_key_id: (
                producer.custody_key_fingerprint_sha256
            ),
            feed.publisher_key_id: (
                feed.publisher_key_fingerprint_sha256
            ),
            lane.session_calendar_key_id: (
                lane.session_calendar_key_fingerprint_sha256
            ),
            clock.authority_key_id: (
                clock.authority_key_fingerprint_sha256
            ),
        }
        prefix = "AI_SCALPER/DECISION"
        references = tuple(
            CredentialReference(
                key_id=key_id,
                target_name=f"{prefix}/{key_id}",
                fingerprint_sha256=fingerprint,
            )
            for key_id, fingerprint in sorted(keys.items())
        )
        return producer, feed, ipc, clock, references

    def _pack_payload(self) -> dict[str, object]:
        producer, feed, ipc, clock, references = self._bindings()
        return {
            "cas_timeout_seconds": 1.0,
            "clock_binding": clock.to_canonical_dict(),
            "credential_references": [
                item.to_canonical_dict() for item in references
            ],
            "credential_target_prefix": "AI_SCALPER/DECISION",
            "decision_feed_binding": feed.to_canonical_dict(),
            "decision_ipc_binding": ipc.to_canonical_dict(),
            "external_cas": {
                "ipc": {
                    "provider_id": "ipc-directory-cas-v1",
                    "request_directory": (
                        r"C:\AI_SCALPER_STATE\decision\ipc-requests"
                    ),
                    "response_directory": (
                        r"C:\AI_SCALPER_STATE\decision\ipc-responses"
                    ),
                },
                "producer": {
                    "provider_id": "cursor-directory-cas-v1",
                    "request_directory": (
                        r"C:\AI_SCALPER_STATE\decision\cursor-requests"
                    ),
                    "response_directory": (
                        r"C:\AI_SCALPER_STATE\decision\cursor-responses"
                    ),
                },
            },
            "pack_id": "decision-provider-pack-v1",
            "runtime": {
                "cycle_deadline_seconds": 5.0,
                "decision_producer_binding": (
                    producer.to_canonical_dict()
                ),
                "max_cycles": 10_000,
                "poll_seconds": 0.25,
                "service_id": producer.service_id,
            },
            "safety": {
                "live_allowed": False,
                "max_lot": 0.01,
                "order_capability": "DISABLED",
                "production_execution_ready": False,
                "promotion_eligible": False,
                "safe_to_demo_auto_order": False,
            },
            "schema_version": (
                "windows-decision-provider-pack-input-v1"
            ),
            "storage": {
                "clock_attestation_path": (
                    r"C:\AI_SCALPER_STATE\decision\clock-attestation.json"
                ),
                "decision_ipc_database": (
                    r"C:\AI_SCALPER_STATE\decision\decision-ipc.sqlite3"
                ),
                "finalized_m15_directory": (
                    r"C:\AI_SCALPER_STATE\decision\feed"
                ),
                "producer_cursor_database": (
                    r"C:\AI_SCALPER_STATE\decision\producer-cursor.sqlite3"
                ),
            },
        }

    def _prepare(self, name: str):
        return prepare_windows_decision_provider_pack(
            base_suite_root=self.suite_root,
            decision_base_release=self.decision_base,
            pack_input_path=self.pack_input,
            output_root=self.root / name,
        )

    def test_deterministic_exact_four_file_pack_and_validation(self) -> None:
        first = self._prepare("first")
        second = self._prepare("second")
        first_root = Path(first.output_root)
        second_root = Path(second.output_root)
        self.assertEqual(
            set(GENERATED_PATHS),
            {
                item.relative_to(first_root).as_posix()
                for item in first_root.rglob("*")
                if item.is_file()
            },
        )
        for relative in GENERATED_PATHS:
            self.assertEqual(
                (first_root / relative).read_bytes(),
                (second_root / relative).read_bytes(),
            )
        self.assertEqual(
            "EXTERNAL_PROVIDER_ACCEPTANCE_REQUIRED",
            first.status,
        )
        self.assertFalse(first.production_execution_ready)
        self.assertFalse(first.credential_access_performed)
        self.assertFalse(first.provider_materialization_performed)
        self.assertFalse(first.broker_mutation_performed)
        self.assertFalse(first.live_allowed)
        self.assertFalse(first.safe_to_demo_auto_order)
        self.assertEqual(0.01, first.max_lot)
        self.assertEqual(
            self.suite_manifest["suite_identity_sha256"],
            first.base_suite_identity_sha256,
        )
        validated = validate_windows_decision_provider_pack(
            base_suite_root=self.suite_root,
            decision_base_release=self.decision_base,
            pack_root=first_root,
        )
        self.assertEqual(first.pack_identity_sha256, validated.pack_identity_sha256)
        runtime_payload = json.loads(
            (first_root / "config/windows_service_config.json").read_text(
                "utf-8"
            )
        )
        runtime = parse_windows_decision_service_runtime_config(runtime_payload)
        self.assertEqual(7, len(runtime.providers))
        self.assertTrue(
            all(
                item.implementation_sha256 != "0" * 64
                and item.configuration_sha256 != "0" * 64
                for item in runtime.providers
            )
        )
        provider_payload = _extract_provider_configuration(
            (
                first_root
                / "configured_providers/decision_provider.py"
            ).read_bytes()
        )
        provider = parse_windows_decision_provider_configuration(
            provider_payload
        )
        validate_windows_decision_provider_bindings(
            runtime_config=runtime,
            provider_config=provider,
        )
        self.assertEqual(
            provider.provider_configuration_hashes(),
            {
                item.role: item.configuration_sha256
                for item in runtime.providers
            },
        )

    def test_implementation_hashes_bind_all_transitive_foundation_bytes(
        self,
    ) -> None:
        provider_module = b"generated decision provider\n"
        foundation_files = {
            "live_runtime/windows_decision_provider_pack.py": (
                b"decision foundation\n"
            ),
            "live_runtime/windows_provider_primitives.py": (
                b"shared primitives v1\n"
            ),
        }
        baseline = _implementation_hashes(
            foundation_files=foundation_files,
            provider_module_bytes=provider_module,
        )
        changed = _implementation_hashes(
            foundation_files={
                **foundation_files,
                "live_runtime/windows_provider_primitives.py": (
                    b"shared primitives changed\n"
                ),
            },
            provider_module_bytes=provider_module,
        )
        self.assertEqual(set(baseline), set(changed))
        self.assertTrue(
            all(
                baseline[role] != changed[role]
                for role in baseline
            )
        )

    def test_missing_shared_primitive_in_base_fails_before_output(
        self,
    ) -> None:
        alternate = self.root / "missing-primitives"
        suite, decision_base, _manifest = self._base_suite(
            root=alternate,
            include_primitives=False,
        )
        output = self.root / "must-not-exist"
        with self.assertRaises(DecisionProviderPackError) as raised:
            prepare_windows_decision_provider_pack(
                base_suite_root=suite,
                decision_base_release=decision_base,
                pack_input_path=self.pack_input,
                output_root=output,
            )
        self.assertEqual(
            "DECISION_PROVIDER_FOUNDATION_MISSING",
            raised.exception.reason_code,
        )
        self.assertFalse(output.exists())

    def test_stable_read_preserves_binary_archive_bytes(self) -> None:
        payload = b"PK\x03\x04binary\r\nmember\x1a\x00tail"
        archive = self.root / "binary-archive.zip"
        archive.write_bytes(payload)
        self.assertEqual(
            payload,
            decision_pack_module._stable_read(
                archive,
                maximum_bytes=len(payload),
                reason_code="BINARY_ARCHIVE_INVALID",
            ),
        )

    def test_input_and_output_are_secret_free_and_closed(self) -> None:
        payload = self._pack_payload()
        payload["password"] = "do-not-accept"
        self.pack_input.write_bytes(canonical_file(payload))
        output = self.root / "unknown-field"
        with self.assertRaises(DecisionProviderPackError) as raised:
            self._prepare(output.name)
        self.assertEqual(
            "PACK_SENSITIVE_FIELD_FORBIDDEN",
            raised.exception.reason_code,
        )
        self.assertFalse(output.exists())

        payload = self._pack_payload()
        payload["unexpected"] = False
        self.pack_input.write_bytes(canonical_file(payload))
        with self.assertRaises(DecisionProviderPackError) as raised:
            self._prepare("unknown-field")
        self.assertEqual(
            "PACK_INPUT_FIELDS_INVALID",
            raised.exception.reason_code,
        )

        payload = self._pack_payload()
        payload["credential_references"][0]["target_name"] = (
            "AI_SCALPER/DECISION/wrong-target"
        )
        self.pack_input.write_bytes(canonical_file(payload))
        with self.assertRaises(DecisionProviderPackError) as raised:
            self._prepare("wrong-target")
        self.assertEqual(
            "CREDENTIAL_TARGET_BINDING_INVALID",
            raised.exception.reason_code,
        )

        payload = self._pack_payload()
        first = payload["credential_references"][0]
        second = payload["credential_references"][1]
        second["key_id"] = first["key_id"].upper()
        second["target_name"] = (
            payload["credential_target_prefix"]
            + "/"
            + second["key_id"]
        )
        self.pack_input.write_bytes(canonical_file(payload))
        with self.assertRaises(DecisionProviderPackError) as raised:
            self._prepare("case-colliding-key")
        self.assertEqual(
            "CREDENTIAL_REFERENCE_SET_INVALID",
            raised.exception.reason_code,
        )

    def test_noncanonical_and_unsafe_paths_fail_before_output(self) -> None:
        payload = self._pack_payload()
        self.pack_input.write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
        )
        with self.assertRaises(DecisionProviderPackError) as raised:
            self._prepare("noncanonical")
        self.assertEqual(
            "PACK_JSON_NOT_CANONICAL",
            raised.exception.reason_code,
        )
        self.assertFalse((self.root / "noncanonical").exists())

        payload = self._pack_payload()
        payload["storage"]["finalized_m15_directory"] = (
            r"C:\AI_SCALPER_STATE\decision\..\escape"
        )
        self.pack_input.write_bytes(canonical_file(payload))
        with self.assertRaises(DecisionProviderPackError) as raised:
            self._prepare("traversal")
        self.assertEqual(
            "WINDOWS_PATH_INVALID",
            raised.exception.reason_code,
        )
        self.assertFalse((self.root / "traversal").exists())

        payload = self._pack_payload()
        payload["external_cas"]["ipc"]["request_directory"] = (
            payload["storage"]["finalized_m15_directory"]
        )
        self.pack_input.write_bytes(canonical_file(payload))
        with self.assertRaises(DecisionProviderPackError) as raised:
            self._prepare("path-collision")
        self.assertEqual(
            "PROVIDER_PATH_COLLISION",
            raised.exception.reason_code,
        )
        self.assertFalse((self.root / "path-collision").exists())

    def test_validator_rejects_tamper_without_importing_generated_code(
        self,
    ) -> None:
        generated = self._prepare("tampered")
        root = Path(generated.output_root)
        generated_module_names = {
            "reviewed_windows_factory",
            "configured_providers",
            "configured_providers.decision_provider",
        }
        before = generated_module_names.intersection(sys.modules)
        provider_path = (
            root / "configured_providers/decision_provider.py"
        )
        provider_path.write_bytes(provider_path.read_bytes() + b"# drift\n")
        with self.assertRaises(DecisionProviderPackError) as raised:
            validate_windows_decision_provider_pack(
                base_suite_root=self.suite_root,
                decision_base_release=self.decision_base,
                pack_root=root,
            )
        self.assertEqual(
            "GENERATED_PROVIDER_SOURCE_DRIFT",
            raised.exception.reason_code,
        )
        self.assertEqual(
            before,
            generated_module_names.intersection(sys.modules),
        )

        generated = self._prepare("factory-tampered")
        root = Path(generated.output_root)
        factory_path = root / "reviewed_windows_factory.py"
        factory_path.write_bytes(factory_path.read_bytes() + b"# drift\n")
        with self.assertRaises(DecisionProviderPackError) as raised:
            validate_windows_decision_provider_pack(
                base_suite_root=self.suite_root,
                decision_base_release=self.decision_base,
                pack_root=root,
            )
        self.assertEqual(
            "GENERATED_SOURCE_DRIFT",
            raised.exception.reason_code,
        )
        self.assertEqual(
            before,
            generated_module_names.intersection(sys.modules),
        )

    def test_validator_rejects_symlink_in_pack(self) -> None:
        generated = self._prepare("symlink-pack")
        root = Path(generated.output_root)
        provider_path = root / "configured_providers/decision_provider.py"
        target = self.root / "provider-target.py"
        target.write_bytes(provider_path.read_bytes())
        provider_path.unlink()
        try:
            provider_path.symlink_to(target)
        except (NotImplementedError, OSError):
            self.skipTest("symlink creation is unavailable")
        with self.assertRaises(DecisionProviderPackError) as raised:
            validate_windows_decision_provider_pack(
                base_suite_root=self.suite_root,
                decision_base_release=self.decision_base,
                pack_root=root,
            )
        self.assertEqual(
            "PACK_FILE_SET_INVALID",
            raised.exception.reason_code,
        )

    def test_wrong_base_and_existing_destination_fail_without_mutation(self) -> None:
        wrong_base = self.suite_root / "execution-base-v1.zip"
        with self.assertRaises(DecisionProviderPackError) as raised:
            prepare_windows_decision_provider_pack(
                base_suite_root=self.suite_root,
                decision_base_release=wrong_base,
                pack_input_path=self.pack_input,
                output_root=self.root / "wrong-base",
            )
        self.assertEqual(
            "DECISION_BASE_SUITE_BINDING_MISMATCH",
            raised.exception.reason_code,
        )
        existing = self.root / "existing"
        existing.mkdir()
        marker = existing / "keep.txt"
        marker.write_text("KEEP", encoding="utf-8")
        with self.assertRaises(DecisionProviderPackError) as raised:
            prepare_windows_decision_provider_pack(
                base_suite_root=self.suite_root,
                decision_base_release=self.decision_base,
                pack_input_path=self.pack_input,
                output_root=existing,
            )
        self.assertEqual(
            "PACK_OUTPUT_ALREADY_EXISTS",
            raised.exception.reason_code,
        )
        self.assertEqual("KEEP", marker.read_text("utf-8"))

    def test_partial_generation_removes_only_new_output(self) -> None:
        from live_runtime import windows_decision_provider_pack_generator as target

        output = self.root / "partial"
        original = target._write_exclusive
        writes = 0

        def fail_second(path: Path, payload: bytes) -> tuple[int, ...]:
            nonlocal writes
            writes += 1
            if writes == 2:
                raise DecisionProviderPackError("PACK_OUTPUT_WRITE_FAILED")
            return original(path, payload)

        with (
            patch.object(target, "_write_exclusive", side_effect=fail_second),
            self.assertRaises(DecisionProviderPackError),
        ):
            self._prepare(output.name)
        self.assertFalse(output.exists())

    def test_cli_prepare_and_validate_are_deny_only(self) -> None:
        prepare_destinations = {
            action.dest
            for action in prepare_parser()._actions
            if action.dest != "help"
        }
        self.assertEqual(
            {
                "base_suite_root",
                "decision_base_release",
                "pack_input",
                "output_root",
            },
            prepare_destinations,
        )
        validate_destinations = {
            action.dest
            for action in validate_parser()._actions
            if action.dest != "help"
        }
        self.assertEqual(
            {
                "base_suite_root",
                "decision_base_release",
                "pack_root",
            },
            validate_destinations,
        )
        output = self.root / "cli-pack"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = prepare_main(
                [
                    "--base-suite-root",
                    str(self.suite_root),
                    "--decision-base-release",
                    str(self.decision_base),
                    "--pack-input",
                    str(self.pack_input),
                    "--output-root",
                    str(output),
                ]
            )
        self.assertEqual(0, code, stderr.getvalue())
        self.assertIn("EXTERNAL_PROVIDER_ACCEPTANCE_REQUIRED", stdout.getvalue())
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = validate_main(
                [
                    "--base-suite-root",
                    str(self.suite_root),
                    "--decision-base-release",
                    str(self.decision_base),
                    "--pack-root",
                    str(output),
                ]
            )
        self.assertEqual(0, code, stderr.getvalue())
        self.assertIn("WINDOWS_DECISION_PROVIDER_PACK_VALID", stdout.getvalue())

    def test_pack_flows_into_exact_configured_release_builder(self) -> None:
        generated = self._prepare("configured-overlay")
        overlay = Path(generated.output_root)
        task = self.root / "decision-task.xml"
        task.write_bytes(b"<Task><Enabled>false</Enabled></Task>\n")
        descriptor = self.root / "decision-overlay-descriptor.json"
        producer, _feed, _ipc, _clock, _references = self._bindings()
        prepared = prepare_configured_overlay_candidate(
            base_archive=self.decision_base,
            overlay_root=overlay,
            task_definition_path=task,
            overlay_id="decision-provider-pack-v1",
            bootstrap_binding_sha256=producer.content_sha256,
            runtime_mode="DEMO_AUTO",
            descriptor_output_path=descriptor,
        )
        self.assertEqual(5, prepared.file_count)
        configured_archive = self.root / "decision-configured.zip"
        built = build_configured_service_release(
            self.decision_base,
            overlay,
            descriptor,
            configured_archive,
            base_release_suite_root=self.suite_root,
        )
        self.assertEqual(
            "WINDOWS_DECISION_SERVICE_V1",
            built["release_profile"],
        )
        self.assertEqual(
            self.suite_manifest["suite_identity_sha256"],
            built["base_release_suite_identity_sha256"],
        )


    def test_cleanup_preserves_replaced_pack_root(self):
        pack_root = self.root / "owned-pack"
        displaced = self.root / "displaced-pack"
        replacement = self.root / "replacement-pack"
        pack_root.mkdir()
        identity = decision_pack_module._directory_identity(
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

        decision_pack_module._cleanup_created(
            pack_root,
            identity,
            [],
        )

        self.assertTrue(pack_root.is_symlink())
        self.assertEqual(Path(replacement.name), pack_root.readlink())
        self.assertTrue(displaced.is_dir())


if __name__ == "__main__":
    unittest.main()
