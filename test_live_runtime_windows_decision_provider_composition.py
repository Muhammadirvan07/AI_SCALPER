from __future__ import annotations

from datetime import datetime, timedelta, timezone
from dataclasses import replace
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from live_runtime.brokerless_decision_producer import (
    BrokerlessDecisionProducerService,
    DecisionProducerBinding,
    DecisionProducerCheckpoint,
    DecisionProducerCursorStore,
    DecisionProducerLaneConfig,
    decision_producer_key_fingerprint,
    issue_decision_producer_cas_acknowledgement,
    make_decision_producer_cas_verifier,
)
from live_runtime.contracts import canonical_json, canonical_sha256
from live_runtime.decision_feed import (
    DecisionFeedBinding,
    DecisionFeedLaneBinding,
)
from live_runtime.decision_ipc import (
    ZERO_SHA256,
    DecisionIPCBinding,
    DurableDecisionIPCQueue,
    decision_ipc_key_fingerprint,
    issue_decision_ipc_cas_acknowledgement,
)
from live_runtime.windows_decision_provider_pack import (
    CredentialReference,
    DecisionIPCExternalCAS,
    DecisionProducerExternalCAS,
    WindowsClockAttestationFile,
    WindowsClockBinding,
    WindowsDecisionProviderConfiguration,
    WindowsDecisionProviderConfigurationV2,
    WindowsDecisionProviderError,
    WindowsEd25519ClockBinding,
    WindowsEd25519ClockEnvelopeFile,
    WindowsEd25519TrustedUTCContinuity,
    WindowsTrustedUTCContinuityCASBinding,
    WindowsTrustedUTCContinuityAcceptanceBinding,
    TrustedUTCContinuityExternalCAS,
    build_windows_decision_provider_service,
    build_windows_decision_provider_service_v2,
    issue_trusted_utc_continuity_cas_acknowledgement,
    issue_windows_clock_attestation,
    parse_windows_decision_provider_configuration_v2,
)
from live_runtime.windows_ed25519_trusted_clock import (
    ENVELOPE_SCHEMA,
    WindowsEd25519TrustedUTCAttestation,
    WindowsEd25519TrustedUTCError,
    ed25519_public_key_sha256,
)
from live_runtime.windows_decision_service_entrypoint import (
    WindowsDecisionServiceRuntimeConfig,
)
from live_runtime.windows_decision_service_factory_template import (
    DecisionServiceProviderBinding,
    provider_contracts,
)


UTC = timezone.utc
DECISION_KEY = b"composition-decision-signing-key-material-minimum"
IPC_KEY = b"composition-ipc-custody-key-material-minimum"
CURSOR_KEY = b"composition-cursor-custody-key-material-minimum"
FEED_KEY = b"composition-feed-key-material-minimum"
CALENDAR_KEY = b"composition-calendar-key-material-minimum"
CLOCK_KEY = b"composition-clock-key-material-minimum"
HASH_A = hashlib.sha256(b"a").hexdigest()
HASH_B = hashlib.sha256(b"b").hexdigest()
HASH_C = hashlib.sha256(b"c").hexdigest()
COMMIT = hashlib.sha1(b"commit").hexdigest()

_CUSTODY = {
    "FINALIZED_M15_DATA": "EXTERNAL_READ_ONLY",
    "IPC_CHECKPOINT_CAS": "EXTERNAL_CAS_CUSTODY",
    "IPC_SIGNING_KEY_CUSTODY": "EXTERNAL_KEY_CUSTODY",
    "PRODUCER_CURSOR_ACK_VERIFIER": "EXTERNAL_ATTESTATION_VERIFIER",
    "PRODUCER_CURSOR_CAS": "EXTERNAL_CAS_CUSTODY",
    "SESSION_CALENDAR_VERIFIER": "EXTERNAL_KEY_CUSTODY",
    "TRUSTED_CLOCK": "EXTERNAL_READ_ONLY",
}


class FakeNativeBackend:
    def __init__(self, keys: dict[str, bytes]) -> None:
        self.keys = keys
        self.reads: list[str] = []

    def read_blob(self, target_name: str) -> bytes | None:
        self.reads.append(target_name)
        key = self.keys.get(target_name)
        return None if key is None else b"hex:" + key.hex().encode("ascii")


class WindowsDecisionProviderCompositionTests(unittest.TestCase):
    def setUp(self) -> None:
        acl_patch = patch(
            "live_runtime.windows_decision_provider_pack.validate_restricted_path_acl",
            lambda _path: None,
        )
        acl_patch.start()
        self.addCleanup(acl_patch.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.now = datetime.now(UTC)
        self.feed_directory = self.root / "feed"
        self.ipc_requests = self.root / "ipc-requests"
        self.ipc_responses = self.root / "ipc-responses"
        self.cursor_requests = self.root / "cursor-requests"
        self.cursor_responses = self.root / "cursor-responses"
        for directory in (
            self.feed_directory,
            self.ipc_requests,
            self.ipc_responses,
            self.cursor_requests,
            self.cursor_responses,
        ):
            directory.mkdir()

        self.lane = DecisionProducerLaneConfig(
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
            session_calendar_key_fingerprint_sha256=hashlib.sha256(
                CALENDAR_KEY
            ).hexdigest(),
        )
        self.producer_binding = DecisionProducerBinding(
            service_id="decision-service-v1",
            lanes=(self.lane,),
            custody_issuer_id="cursor-custody-v1",
            custody_key_id="cursor-key-v1",
            custody_key_fingerprint_sha256=hashlib.sha256(
                CURSOR_KEY
            ).hexdigest(),
        )
        self.feed_binding = DecisionFeedBinding(
            feed_id="decision-feed-v1",
            broker_server="Reviewed-Demo-Server",
            broker_account_identity_sha256=HASH_A,
            publisher_issuer_id="feed-publisher-v1",
            publisher_key_id="feed-key-v1",
            publisher_key_fingerprint_sha256=hashlib.sha256(
                FEED_KEY
            ).hexdigest(),
            lanes=(
                DecisionFeedLaneBinding(
                    lane_id=self.lane.lane_id,
                    symbol=self.lane.symbol,
                    broker_symbol="XAUUSD",
                    source_name=self.lane.source_name,
                    data_contract_sha256=self.lane.data_contract_sha256,
                    session_calendar_sha256=(
                        self.lane.session_calendar_sha256
                    ),
                ),
            ),
        )
        self.ipc_binding = DecisionIPCBinding(
            queue_id="decision-queue-v1",
            account_id_sha256=HASH_A,
            server=self.feed_binding.broker_server,
            environment="DEMO",
            journal_sha256=HASH_C,
            commit_sha=COMMIT,
            config_sha256=HASH_C,
            model_artifact_sha256=HASH_B,
            data_contract_sha256=HASH_A,
            decision_issuer_id=self.producer_binding.service_id,
            decision_key_id="decision-key-v1",
            decision_key_fingerprint_sha256=hashlib.sha256(
                DECISION_KEY
            ).hexdigest(),
            custody_issuer_id="ipc-custody-v1",
            custody_key_id="ipc-key-v1",
            custody_key_fingerprint_sha256=hashlib.sha256(
                IPC_KEY
            ).hexdigest(),
            permit_key_id="downstream-permit-key-v1",
            permit_key_fingerprint_sha256=HASH_C,
        )
        self.clock_binding = WindowsClockBinding(
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
        self.clock_path = self.root / "clock-attestation.json"
        attestation = issue_windows_clock_attestation(
            binding=self.clock_binding,
            authority_utc=self.now,
            observed_system_utc=self.now,
            issued_at_utc=self.now - timedelta(milliseconds=50),
            expires_at_utc=self.now + timedelta(seconds=5),
            authority_key=CLOCK_KEY,
        )
        self.clock_path.write_bytes(
            canonical_json(attestation).encode("utf-8")
        )

        local_ipc_head = None

        def ipc_provider():
            return local_ipc_head

        def ipc_exporter(expected, checkpoint):
            nonlocal local_ipc_head
            observed = (
                ZERO_SHA256
                if local_ipc_head is None
                else local_ipc_head.content_sha256
            )
            accepted = observed == expected
            if accepted:
                local_ipc_head = checkpoint
            return issue_decision_ipc_cas_acknowledgement(
                queue_id=self.ipc_binding.queue_id,
                expected_previous_checkpoint_sha256=expected,
                accepted_checkpoint_sha256=checkpoint.content_sha256,
                observed_previous_checkpoint_sha256=observed,
                accepted=accepted,
                issued_at_utc=checkpoint.issued_at_utc,
                custody_issuer_id=self.ipc_binding.custody_issuer_id,
                custody_key_id=self.ipc_binding.custody_key_id,
                custody_key=IPC_KEY,
            )

        self.ipc_database = self.root / "decision-ipc.sqlite3"
        queue = DurableDecisionIPCQueue.provision(
            self.ipc_database,
            binding=self.ipc_binding,
            decision_key_provider=lambda _: DECISION_KEY,
            custody_key_provider=lambda _: IPC_KEY,
            external_checkpoint_provider=ipc_provider,
            checkpoint_exporter=ipc_exporter,
            clock_provider=lambda: self.now,
        )
        self.ipc_checkpoint = queue.current_checkpoint()

        cursor_head = None

        def cursor_provider():
            return cursor_head

        def cursor_cas(expected, checkpoint):
            nonlocal cursor_head
            observed = (
                ZERO_SHA256
                if cursor_head is None
                else cursor_head.content_sha256
            )
            accepted = observed == expected
            if accepted:
                cursor_head = checkpoint
            return issue_decision_producer_cas_acknowledgement(
                service_id=self.producer_binding.service_id,
                binding_sha256=self.producer_binding.content_sha256,
                expected_previous_checkpoint_sha256=expected,
                accepted_checkpoint_sha256=checkpoint.content_sha256,
                observed_previous_checkpoint_sha256=observed,
                accepted=accepted,
                issued_at_utc=checkpoint.issued_at_utc,
                custody_issuer_id=self.producer_binding.custody_issuer_id,
                custody_key_id=self.producer_binding.custody_key_id,
                custody_key=CURSOR_KEY,
            )

        self.cursor_database = self.root / "producer-cursor.sqlite3"
        cursor_store = DecisionProducerCursorStore.provision(
            self.cursor_database,
            binding=self.producer_binding,
            external_checkpoint_provider=cursor_provider,
            checkpoint_cas=cursor_cas,
            acknowledgement_verifier=make_decision_producer_cas_verifier(
                self.producer_binding,
                lambda _: CURSOR_KEY,
            ),
            clock_provider=lambda: self.now,
        )
        self.cursor_checkpoint = cursor_store.current_checkpoint()
        self._seed_external_custody()

        self.keys_by_id = {
            "decision-key-v1": DECISION_KEY,
            "ipc-key-v1": IPC_KEY,
            "cursor-key-v1": CURSOR_KEY,
            "feed-key-v1": FEED_KEY,
            "calendar-key-v1": CALENDAR_KEY,
            "clock-key-v1": CLOCK_KEY,
        }
        self.targets_by_id = {
            key_id: f"AI_SCALPER/DECISION/{key_id}"
            for key_id in self.keys_by_id
        }
        self.backend = FakeNativeBackend(
            {
                self.targets_by_id[key_id]: value
                for key_id, value in self.keys_by_id.items()
            }
        )
        references = tuple(
            CredentialReference(
                key_id=key_id,
                target_name=self.targets_by_id[key_id],
                fingerprint_sha256=hashlib.sha256(value).hexdigest(),
            )
            for key_id, value in sorted(self.keys_by_id.items())
        )
        self.configuration = WindowsDecisionProviderConfiguration(
            pack_id="decision-provider-pack-v1",
            base_suite_identity_sha256=HASH_A,
            decision_base_release_identity_sha256=HASH_B,
            decision_feed_binding=self.feed_binding,
            decision_ipc_binding=self.ipc_binding,
            decision_producer_binding=self.producer_binding,
            clock_binding=self.clock_binding,
            credential_target_prefix="AI_SCALPER/DECISION",
            credential_references=references,
            finalized_m15_directory=str(self.feed_directory),
            decision_ipc_database=str(self.ipc_database),
            producer_cursor_database=str(self.cursor_database),
            ipc_cas_provider_id="ipc-directory-cas-v1",
            ipc_cas_request_directory=str(self.ipc_requests),
            ipc_cas_response_directory=str(self.ipc_responses),
            producer_cas_provider_id="cursor-directory-cas-v1",
            producer_cas_request_directory=str(self.cursor_requests),
            producer_cas_response_directory=str(self.cursor_responses),
            clock_attestation_path=str(self.clock_path),
            cas_timeout_seconds=1.0,
        )
        contracts = provider_contracts()
        configuration_hashes = (
            self.configuration.provider_configuration_hashes()
        )
        providers = tuple(
            DecisionServiceProviderBinding(
                role=role,
                contract_sha256=contracts[role],
                implementation_sha256=hashlib.sha256(
                    f"implementation:{role}".encode()
                ).hexdigest(),
                configuration_sha256=configuration_hashes[role],
                custody_mode=_CUSTODY[role],
            )
            for role in sorted(contracts)
        )
        self.runtime = WindowsDecisionServiceRuntimeConfig(
            service_id=self.producer_binding.service_id,
            max_cycles=1,
            poll_seconds=0.0,
            cycle_deadline_seconds=5.0,
            decision_producer_binding=self.producer_binding,
            providers=providers,
        )

    @staticmethod
    def _write_response(
        request_directory: Path,
        response_directory: Path,
        acknowledgement_factory,
    ) -> tuple[threading.Thread, list[BaseException]]:
        failures: list[BaseException] = []

        def respond() -> None:
            try:
                deadline = time.monotonic() + 2
                request_path = None
                while time.monotonic() < deadline:
                    paths = tuple(
                        request_directory.glob("*.request.json")
                    )
                    if paths:
                        request_path = paths[0]
                        break
                    time.sleep(0.005)
                if request_path is None:
                    raise AssertionError("request was not written")
                request = json.loads(request_path.read_text("utf-8"))
                acknowledgement = acknowledgement_factory(request)
                response = {
                    "schema_version": "external-cas-response-v1",
                    "request_id": request["request_id"],
                    "request_sha256": canonical_sha256(request),
                    "provider_id": request["provider_id"],
                    "state_domain": request["state_domain"],
                    "identity_sha256": request["identity_sha256"],
                    "acknowledgement": acknowledgement.to_canonical_dict(),
                    "current_object": request["proposed_object"],
                    "responded_at_utc": request["issued_at_utc"],
                }
                payload = canonical_json(response).encode("utf-8")
                response_path = (
                    response_directory
                    / f"{request['request_id']}.response.json"
                )
                response_temporary = response_path.with_suffix(".tmp")
                response_temporary.write_bytes(payload)
                response_temporary.replace(response_path)
                head_path = (
                    response_directory / "current.response.json"
                )
                head_temporary = head_path.with_suffix(".tmp")
                head_temporary.write_bytes(payload)
                head_temporary.replace(head_path)
            except BaseException as exc:
                failures.append(exc)

        thread = threading.Thread(target=respond, daemon=True)
        thread.start()
        return thread, failures

    def _seed_external_custody(self) -> None:
        ipc = DecisionIPCExternalCAS(
            provider_id="ipc-directory-cas-v1",
            binding=self.ipc_binding,
            request_directory=self.ipc_requests,
            response_directory=self.ipc_responses,
            custody_key_provider=lambda _: IPC_KEY,
            clock_provider=lambda: self.now,
            timeout_seconds=1.0,
        )
        ipc_thread, ipc_failures = self._write_response(
            self.ipc_requests,
            self.ipc_responses,
            lambda request: issue_decision_ipc_cas_acknowledgement(
                queue_id=self.ipc_binding.queue_id,
                expected_previous_checkpoint_sha256=ZERO_SHA256,
                accepted_checkpoint_sha256=request["proposed_sha256"],
                observed_previous_checkpoint_sha256=ZERO_SHA256,
                accepted=True,
                issued_at_utc=self.ipc_checkpoint.issued_at_utc,
                custody_issuer_id=self.ipc_binding.custody_issuer_id,
                custody_key_id=self.ipc_binding.custody_key_id,
                custody_key=IPC_KEY,
            ),
        )
        ipc.compare_and_swap(ZERO_SHA256, self.ipc_checkpoint)
        ipc_thread.join(timeout=2)
        self.assertEqual([], ipc_failures)

        cursor = DecisionProducerExternalCAS(
            provider_id="cursor-directory-cas-v1",
            binding=self.producer_binding,
            request_directory=self.cursor_requests,
            response_directory=self.cursor_responses,
            custody_key_provider=lambda _: CURSOR_KEY,
            clock_provider=lambda: self.now,
            timeout_seconds=1.0,
        )
        cursor_thread, cursor_failures = self._write_response(
            self.cursor_requests,
            self.cursor_responses,
            lambda request: issue_decision_producer_cas_acknowledgement(
                service_id=self.producer_binding.service_id,
                binding_sha256=self.producer_binding.content_sha256,
                expected_previous_checkpoint_sha256=ZERO_SHA256,
                accepted_checkpoint_sha256=request["proposed_sha256"],
                observed_previous_checkpoint_sha256=ZERO_SHA256,
                accepted=True,
                issued_at_utc=self.cursor_checkpoint.issued_at_utc,
                custody_issuer_id=self.producer_binding.custody_issuer_id,
                custody_key_id=self.producer_binding.custody_key_id,
                custody_key=CURSOR_KEY,
            ),
        )
        cursor.compare_and_swap(ZERO_SHA256, self.cursor_checkpoint)
        cursor_thread.join(timeout=2)
        self.assertEqual([], cursor_failures)

    def test_clock_attestation_file_is_strict_and_uncached(self) -> None:
        provider = WindowsClockAttestationFile(self.clock_path)
        first = provider()
        second = provider()
        self.assertEqual(first, second)
        self.clock_path.write_bytes(b'{"provider_id":"duplicate","provider_id":"x"}')
        with self.assertRaises(WindowsDecisionProviderError) as raised:
            provider()
        self.assertEqual(
            "CLOCK_ATTESTATION_FILE_INVALID",
            raised.exception.reason_code,
        )

    def test_exact_preprovisioned_composition_runs_no_input(self) -> None:
        with (
            patch(
                "live_runtime.windows_decision_provider_pack.sys.platform",
                "win32",
            ),
            patch(
                "live_runtime.windows_decision_provider_pack."
                "_WindowsNativeCredentialBackend",
                return_value=self.backend,
            ),
        ):
            service = build_windows_decision_provider_service(
                runtime_config=self.runtime,
                provider_config=self.configuration,
            )
            self.assertIs(type(service), BrokerlessDecisionProducerService)
            self.assertEqual(self.producer_binding, service.binding)
            cycle = service.run_cycle()
        self.assertEqual("NO_INPUT", cycle.lanes[0].status)
        self.assertGreater(len(self.backend.reads), 0)

    def test_binding_or_provider_hash_drift_fails_before_credential_access(self) -> None:
        providers = list(self.runtime.providers)
        providers[0] = DecisionServiceProviderBinding(
            role=providers[0].role,
            contract_sha256=providers[0].contract_sha256,
            implementation_sha256=providers[0].implementation_sha256,
            configuration_sha256="f" * 64,
            custody_mode=providers[0].custody_mode,
        )
        drifted = WindowsDecisionServiceRuntimeConfig(
            service_id=self.runtime.service_id,
            max_cycles=self.runtime.max_cycles,
            poll_seconds=self.runtime.poll_seconds,
            cycle_deadline_seconds=self.runtime.cycle_deadline_seconds,
            decision_producer_binding=self.runtime.decision_producer_binding,
            providers=tuple(providers),
        )
        with (
            patch(
                "live_runtime.windows_decision_provider_pack.sys.platform",
                "win32",
            ),
            patch(
                "live_runtime.windows_decision_provider_pack."
                "_WindowsNativeCredentialBackend",
                return_value=self.backend,
            ),
            self.assertRaises(WindowsDecisionProviderError) as raised,
        ):
            build_windows_decision_provider_service(
                runtime_config=drifted,
                provider_config=self.configuration,
            )
        self.assertEqual(
            "PROVIDER_CONFIGURATION_BINDING_MISMATCH",
            raised.exception.reason_code,
        )
        self.assertEqual([], self.backend.reads)

    def test_any_provider_path_overlap_fails_before_credential_access(
        self,
    ) -> None:
        drifted = replace(
            self.configuration,
            clock_attestation_path=str(self.ipc_database),
        )
        configuration_hashes = drifted.provider_configuration_hashes()
        providers = tuple(
            replace(
                item,
                configuration_sha256=configuration_hashes[item.role],
            )
            for item in self.runtime.providers
        )
        runtime = replace(self.runtime, providers=providers)
        with (
            patch(
                "live_runtime.windows_decision_provider_pack.sys.platform",
                "win32",
            ),
            patch(
                "live_runtime.windows_decision_provider_pack."
                "_WindowsNativeCredentialBackend",
                return_value=self.backend,
            ),
            self.assertRaises(WindowsDecisionProviderError) as raised,
        ):
            build_windows_decision_provider_service(
                runtime_config=runtime,
                provider_config=drifted,
            )
        self.assertEqual(
            "DECISION_PROVIDER_PATH_COLLISION",
            raised.exception.reason_code,
        )
        self.assertEqual([], self.backend.reads)

    def _v2_configuration(self):
        algorithm = b"ssh-ed25519"
        key = b"k" * 32
        blob = (
            len(algorithm).to_bytes(4, "big")
            + algorithm
            + len(key).to_bytes(4, "big")
            + key
        )
        public_key = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii")
        executable = self.root / "ssh-keygen.exe"
        executable.write_bytes(b"pinned-test-executable")
        clock = WindowsEd25519ClockBinding(
            provider_id="decision-ed25519-clock-v1",
            source_host_identity_sha256=HASH_A,
            consumer_host_identity_sha256=HASH_C,
            authority_issuer_id="offhost-clock-authority-v1",
            signer_identity="offhost-clock-signer-v1",
            authority_public_key=public_key,
            authority_public_key_sha256=ed25519_public_key_sha256(public_key),
            ssh_keygen_path=str(executable.resolve()),
            ssh_keygen_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            maximum_attestation_age_ms=10_000,
            maximum_delivery_delay_ms=3_000,
            maximum_bootstrap_drift_ms=1_000,
        )
        attestation = WindowsEd25519TrustedUTCAttestation(
            binding_sha256=clock.content_sha256,
            source_host_identity_sha256=HASH_A,
            consumer_host_identity_sha256=HASH_C,
            authority_issuer_id=clock.authority_issuer_id,
            signer_identity=clock.signer_identity,
            authority_public_key_sha256=clock.authority_public_key_sha256,
            sequence=1,
            previous_attestation_sha256="0" * 64,
            authority_utc=self.now,
            issued_at_utc=self.now - timedelta(milliseconds=50),
            expires_at_utc=self.now + timedelta(seconds=5),
        )
        payload = attestation.signing_payload
        envelope_path = self.root / "clock-envelope.json"
        envelope_path.write_bytes(
            (
                canonical_json(
                    {
                        "payload_base64": base64.b64encode(payload).decode("ascii"),
                        "schema_version": ENVELOPE_SCHEMA,
                        "signature_base64": base64.b64encode(b"signature").decode("ascii"),
                    }
                )
                + "\n"
            ).encode("utf-8")
        )
        clock_requests = self.root / "clock-continuity-requests"
        clock_responses = self.root / "clock-continuity-responses"
        clock_requests.mkdir()
        clock_responses.mkdir()
        custody_key = b"clock-continuity-custody-key-material"
        custody_binding = WindowsTrustedUTCContinuityCASBinding(
            provider_id="clock-continuity-directory-cas-v1",
            clock_binding_sha256=clock.content_sha256,
            custody_issuer_id="clock-continuity-custody-v1",
            custody_key_id="clock-continuity-key-v1",
            custody_key_fingerprint_sha256=hashlib.sha256(custody_key).hexdigest(),
        )
        acceptance_public_path = self.root / "continuity-acceptance.pub"
        acceptance_public_path.write_text(public_key + " acceptance-test\n", encoding="ascii")
        acceptance_binding = WindowsTrustedUTCContinuityAcceptanceBinding(
            provider_id=custody_binding.provider_id,
            clock_binding_sha256=clock.content_sha256,
            source_host_identity_sha256=HASH_A,
            consumer_host_identity_sha256=HASH_C,
            custody_issuer_id="continuity-acceptance-issuer-v1",
            custody_key_id="continuity-acceptance-key-v1",
            custody_public_key_sha256=hashlib.sha256(public_key.encode("ascii")).hexdigest(),
            public_key_file_sha256=hashlib.sha256(
                acceptance_public_path.read_bytes()
            ).hexdigest(),
        )
        target = "AI_SCALPER/DECISION/clock-continuity-key-v1"
        self.backend.keys[target] = custody_key
        references = tuple(
            item
            for item in self.configuration.credential_references
            if item.key_id != "clock-key-v1"
        ) + (
            CredentialReference(
                key_id="clock-continuity-key-v1",
                target_name=target,
                fingerprint_sha256=hashlib.sha256(custody_key).hexdigest(),
            ),
        )
        configuration = WindowsDecisionProviderConfigurationV2(
            pack_id="decision-provider-pack-v2",
            base_suite_identity_sha256=HASH_A,
            decision_base_release_identity_sha256=HASH_B,
            decision_feed_binding=self.feed_binding,
            decision_ipc_binding=self.ipc_binding,
            decision_producer_binding=self.producer_binding,
            clock_binding=clock,
            clock_continuity_binding=custody_binding,
            clock_continuity_acceptance_binding=acceptance_binding,
            credential_target_prefix="AI_SCALPER/DECISION",
            credential_references=references,
            finalized_m15_directory=str(self.feed_directory),
            decision_ipc_database=str(self.ipc_database),
            producer_cursor_database=str(self.cursor_database),
            ipc_cas_provider_id="ipc-directory-cas-v1",
            ipc_cas_request_directory=str(self.ipc_requests),
            ipc_cas_response_directory=str(self.ipc_responses),
            producer_cas_provider_id="cursor-directory-cas-v1",
            producer_cas_request_directory=str(self.cursor_requests),
            producer_cas_response_directory=str(self.cursor_responses),
            clock_attestation_path=str(envelope_path),
            clock_continuity_request_directory=str(clock_requests),
            clock_continuity_response_directory=str(clock_responses),
            clock_continuity_acceptance_public_key_path=str(
                acceptance_public_path
            ),
            cas_timeout_seconds=1.0,
        )
        hashes = configuration.provider_configuration_hashes()
        runtime = replace(
            self.runtime,
            providers=tuple(
                replace(item, configuration_sha256=hashes[item.role])
                for item in self.runtime.providers
            ),
        )
        return configuration, runtime, custody_key

    def test_v2_continuity_acknowledgement_is_domain_authenticated(self) -> None:
        configuration, _runtime, custody_key = self._v2_configuration()
        self.assertEqual(
            configuration,
            parse_windows_decision_provider_configuration_v2(
                configuration.to_canonical_dict()
            ),
        )
        continuity = WindowsEd25519TrustedUTCContinuity(
            binding_sha256=configuration.clock_binding.content_sha256,
            source_host_identity_sha256=HASH_A,
            consumer_host_identity_sha256=HASH_C,
            sequence=1,
            attestation_sha256=HASH_B,
            last_authority_utc=self.now,
            last_trusted_utc=self.now,
        )
        adapter = TrustedUTCContinuityExternalCAS(
            binding=configuration.clock_continuity_binding,
            request_directory=configuration.clock_continuity_request_directory,
            response_directory=configuration.clock_continuity_response_directory,
            custody_key_provider=lambda _: custody_key,
            system_clock=lambda: self.now,
            timeout_seconds=1.0,
        )
        request = adapter._build_request(
            expected_previous="0" * 64,
            proposed=continuity,
        )
        acknowledgement = issue_trusted_utc_continuity_cas_acknowledgement(
            binding=configuration.clock_continuity_binding,
            expected_previous_continuity_sha256="0" * 64,
            accepted_continuity_sha256=continuity.content_sha256,
            observed_previous_continuity_sha256="0" * 64,
            accepted=True,
            issued_at_utc=self.now,
            custody_key=custody_key,
        )
        observed, current = adapter._verify_typed_response(
            request=request,
            acknowledgement=acknowledgement.to_canonical_dict(),
            current_object=continuity.to_canonical_dict(),
        )
        self.assertTrue(observed.accepted)
        self.assertEqual(continuity, current)
        forged = replace(acknowledgement, hmac_sha256="f" * 64)
        with self.assertRaises(WindowsDecisionProviderError) as raised:
            adapter._verify_typed_response(
                request=request,
                acknowledgement=forged.to_canonical_dict(),
                current_object=continuity.to_canonical_dict(),
            )
        self.assertEqual("EXTERNAL_CAS_ACK_INVALID", raised.exception.reason_code)

    def test_v2_continuity_requires_hmac_and_bound_ed25519_acceptance(self) -> None:
        configuration, _runtime, custody_key = self._v2_configuration()
        continuity = WindowsEd25519TrustedUTCContinuity(
            binding_sha256=configuration.clock_binding.content_sha256,
            source_host_identity_sha256=HASH_A,
            consumer_host_identity_sha256=HASH_C,
            sequence=1,
            attestation_sha256=HASH_B,
            last_authority_utc=self.now,
            last_trusted_utc=self.now,
        )
        adapter = TrustedUTCContinuityExternalCAS(
            binding=configuration.clock_continuity_binding,
            request_directory=configuration.clock_continuity_request_directory,
            response_directory=configuration.clock_continuity_response_directory,
            custody_key_provider=lambda _: custody_key,
            system_clock=lambda: self.now,
            timeout_seconds=1.0,
            acceptance_binding=configuration.clock_continuity_acceptance_binding,
            acceptance_public_key_path=(
                configuration.clock_continuity_acceptance_public_key_path
            ),
            ssh_keygen_path=configuration.clock_binding.ssh_keygen_path,
            ssh_keygen_sha256=configuration.clock_binding.ssh_keygen_sha256,
        )
        request = adapter._build_request(
            expected_previous="0" * 64, proposed=continuity
        )
        acknowledgement = issue_trusted_utc_continuity_cas_acknowledgement(
            binding=configuration.clock_continuity_binding,
            expected_previous_continuity_sha256="0" * 64,
            accepted_continuity_sha256=continuity.content_sha256,
            observed_previous_continuity_sha256="0" * 64,
            accepted=True,
            issued_at_utc=self.now,
            custody_key=custody_key,
        )
        acceptance = b"canonical-signed-acceptance"
        response_root = Path(configuration.clock_continuity_response_directory)
        (response_root / f"{request.request_id}.acceptance.json").write_bytes(acceptance)
        (response_root / "current.acceptance.json").write_bytes(acceptance)
        binding = configuration.clock_continuity_acceptance_binding
        receipt = unittest.mock.Mock(
            provider_id=binding.provider_id,
            clock_binding_sha256=binding.clock_binding_sha256,
            source_host_identity_sha256=HASH_A,
            consumer_host_identity_sha256=HASH_C,
            sequence=1,
            predecessor_attestation_sha256="0" * 64,
            candidate_attestation_sha256=continuity.attestation_sha256,
            cas_request_id=request.request_id,
            expected_previous_continuity_sha256="0" * 64,
            committed_continuity_sha256=continuity.content_sha256,
            accepted_at_utc=self.now,
            custody_issuer_id=binding.custody_issuer_id,
            custody_key_id=binding.custody_key_id,
            custody_public_key_sha256=binding.custody_public_key_sha256,
        )
        with patch(
            "live_runtime.windows_decision_provider_pack.verify_acceptance_envelope",
            return_value=receipt,
        ) as verifier:
            observed, current = adapter._verify_typed_response(
                request=request,
                acknowledgement=acknowledgement.to_canonical_dict(),
                current_object=continuity.to_canonical_dict(),
            )
        self.assertTrue(observed.accepted)
        self.assertEqual(continuity, current)
        verifier.assert_called_once()

        forged_hmac = replace(acknowledgement, hmac_sha256="f" * 64)
        with patch(
            "live_runtime.windows_decision_provider_pack.verify_acceptance_envelope"
        ) as verifier, self.assertRaises(WindowsDecisionProviderError):
            adapter._verify_typed_response(
                request=request,
                acknowledgement=forged_hmac.to_canonical_dict(),
                current_object=continuity.to_canonical_dict(),
            )
        verifier.assert_not_called()

        with patch(
            "live_runtime.windows_decision_provider_pack.verify_acceptance_envelope",
            side_effect=ValueError("wrong key/domain/signature"),
        ), self.assertRaisesRegex(
            WindowsDecisionProviderError, "CONTINUITY_ACCEPTANCE_INVALID"
        ):
            adapter._verify_typed_response(
                request=request,
                acknowledgement=acknowledgement.to_canonical_dict(),
                current_object=continuity.to_canonical_dict(),
            )

    def test_v2_acceptance_reconstructs_signed_predecessor_after_restart(self) -> None:
        configuration, _runtime, custody_key = self._v2_configuration()
        binding = configuration.clock_continuity_acceptance_binding
        adapter = TrustedUTCContinuityExternalCAS(
            binding=configuration.clock_continuity_binding,
            request_directory=configuration.clock_continuity_request_directory,
            response_directory=configuration.clock_continuity_response_directory,
            custody_key_provider=lambda _: custody_key,
            system_clock=lambda: self.now,
            timeout_seconds=1.0,
            acceptance_binding=binding,
            acceptance_public_key_path=(
                configuration.clock_continuity_acceptance_public_key_path
            ),
            ssh_keygen_path=configuration.clock_binding.ssh_keygen_path,
            ssh_keygen_sha256=configuration.clock_binding.ssh_keygen_sha256,
        )
        previous = WindowsEd25519TrustedUTCContinuity(
            binding_sha256=configuration.clock_binding.content_sha256,
            source_host_identity_sha256=HASH_A,
            consumer_host_identity_sha256=HASH_C,
            sequence=1,
            attestation_sha256=HASH_B,
            last_authority_utc=self.now,
            last_trusted_utc=self.now,
        )
        proposed = replace(
            previous, sequence=2, attestation_sha256=HASH_C
        )
        request = adapter._build_request(
            expected_previous=previous.content_sha256, proposed=proposed
        )
        historical_id = "a" * 64
        root = Path(configuration.clock_continuity_response_directory)
        (root / f"{historical_id}.acceptance.json").write_bytes(b"historical")
        (root / f"{request.request_id}.acceptance.json").write_bytes(b"current")
        (root / "current.acceptance.json").write_bytes(b"current")

        common = dict(
            provider_id=binding.provider_id,
            clock_binding_sha256=binding.clock_binding_sha256,
            source_host_identity_sha256=HASH_A,
            consumer_host_identity_sha256=HASH_C,
            custody_issuer_id=binding.custody_issuer_id,
            custody_key_id=binding.custody_key_id,
            custody_public_key_sha256=binding.custody_public_key_sha256,
            accepted_at_utc=self.now,
        )
        historical = unittest.mock.Mock(
            **common,
            sequence=1,
            predecessor_attestation_sha256="0" * 64,
            candidate_attestation_sha256=previous.attestation_sha256,
            cas_request_id=historical_id,
            expected_previous_continuity_sha256="0" * 64,
            committed_continuity_sha256=previous.content_sha256,
        )
        current = unittest.mock.Mock(
            **common,
            sequence=2,
            predecessor_attestation_sha256=previous.attestation_sha256,
            candidate_attestation_sha256=proposed.attestation_sha256,
            cas_request_id=request.request_id,
            expected_previous_continuity_sha256=previous.content_sha256,
            committed_continuity_sha256=proposed.content_sha256,
        )
        with patch(
            "live_runtime.windows_decision_provider_pack.verify_acceptance_envelope",
            side_effect=lambda data, **_kwargs: (
                historical if data == b"historical" else current
            ),
        ):
            adapter._verify_acceptance(request=request, proposed=proposed)
        self.assertEqual(
            previous.attestation_sha256,
            adapter._known_continuity_attestations[previous.content_sha256],
        )

    def test_v2_clock_preflight_failure_precedes_sqlite(self) -> None:
        configuration, runtime, _ = self._v2_configuration()
        preflight = unittest.mock.Mock(side_effect=RuntimeError("clock blocked"))
        with (
            patch("live_runtime.windows_decision_provider_pack.sys.platform", "win32"),
            patch(
                "live_runtime.windows_decision_provider_pack._WindowsNativeCredentialBackend",
                return_value=self.backend,
            ),
            patch(
                "live_runtime.windows_decision_provider_pack.Ed25519AttestedTrustedUTCProvider",
                return_value=preflight,
            ),
            patch(
                "live_runtime.windows_decision_provider_pack.DurableDecisionIPCQueue"
            ) as queue,
            patch(
                "live_runtime.windows_decision_provider_pack.DecisionProducerCursorStore"
            ) as cursor,
            self.assertRaises(WindowsDecisionProviderError) as raised,
        ):
            build_windows_decision_provider_service_v2(
                runtime_config=runtime,
                provider_config=configuration,
            )
        self.assertEqual("TRUSTED_UTC_PREFLIGHT_FAILED", raised.exception.reason_code)
        preflight.assert_called_once_with()
        queue.assert_not_called()
        cursor.assert_not_called()

    def test_v2_clock_preflight_preserves_classified_reason(self) -> None:
        configuration, runtime, _ = self._v2_configuration()
        classified = unittest.mock.Mock(
            side_effect=WindowsEd25519TrustedUTCError(
                "TRUSTED_UTC_SIGNATURE_INVALID"
            )
        )
        with (
            patch("live_runtime.windows_decision_provider_pack.sys.platform", "win32"),
            patch(
                "live_runtime.windows_decision_provider_pack._WindowsNativeCredentialBackend",
                return_value=self.backend,
            ),
            patch(
                "live_runtime.windows_decision_provider_pack.Ed25519AttestedTrustedUTCProvider",
                return_value=classified,
            ),
            patch(
                "live_runtime.windows_decision_provider_pack.DurableDecisionIPCQueue"
            ) as queue,
            self.assertRaises(WindowsDecisionProviderError) as raised,
        ):
            build_windows_decision_provider_service_v2(
                runtime_config=runtime,
                provider_config=configuration,
            )
        self.assertEqual(
            "TRUSTED_UTC_SIGNATURE_INVALID", raised.exception.reason_code
        )
        queue.assert_not_called()

    def _continuity_case(self):
        configuration, _runtime, custody_key = self._v2_configuration()
        continuity = WindowsEd25519TrustedUTCContinuity(
            binding_sha256=configuration.clock_binding.content_sha256,
            source_host_identity_sha256=HASH_A,
            consumer_host_identity_sha256=HASH_C,
            sequence=1,
            attestation_sha256=HASH_B,
            last_authority_utc=self.now,
            last_trusted_utc=self.now,
        )
        adapter = TrustedUTCContinuityExternalCAS(
            binding=configuration.clock_continuity_binding,
            request_directory=configuration.clock_continuity_request_directory,
            response_directory=configuration.clock_continuity_response_directory,
            custody_key_provider=lambda _: custody_key,
            system_clock=lambda: self.now,
            timeout_seconds=1.0,
        )
        request = adapter._build_request(
            expected_previous="0" * 64, proposed=continuity
        )
        acknowledgement = issue_trusted_utc_continuity_cas_acknowledgement(
            binding=configuration.clock_continuity_binding,
            expected_previous_continuity_sha256="0" * 64,
            accepted_continuity_sha256=continuity.content_sha256,
            observed_previous_continuity_sha256="0" * 64,
            accepted=True,
            issued_at_utc=self.now,
            custody_key=custody_key,
        )
        return configuration, custody_key, continuity, adapter, request, acknowledgement

    def test_v2_continuity_rejects_identity_and_chain_tampering(self) -> None:
        configuration, custody_key, continuity, adapter, request, acknowledgement = (
            self._continuity_case()
        )
        tampered = (
            replace(acknowledgement, provider_id="wrong-provider-v1"),
            replace(acknowledgement, clock_binding_sha256="d" * 64),
            replace(acknowledgement, custody_issuer_id="wrong-issuer-v1"),
            replace(acknowledgement, custody_key_id="wrong-key-v1"),
            replace(
                acknowledgement,
                custody_key_fingerprint_sha256="e" * 64,
            ),
        )
        for forged in tampered:
            with self.subTest(field=forged), self.assertRaises(
                WindowsDecisionProviderError
            ) as raised:
                adapter._verify_typed_response(
                    request=request,
                    acknowledgement=forged.to_canonical_dict(),
                    current_object=continuity.to_canonical_dict(),
                )
            self.assertEqual("EXTERNAL_CAS_ACK_INVALID", raised.exception.reason_code)
        for expected, proposed in (("f" * 64, continuity.content_sha256), ("0" * 64, "f" * 64)):
            forged = issue_trusted_utc_continuity_cas_acknowledgement(
                binding=configuration.clock_continuity_binding,
                expected_previous_continuity_sha256=expected,
                accepted_continuity_sha256=proposed,
                observed_previous_continuity_sha256="0" * 64,
                accepted=True,
                issued_at_utc=self.now,
                custody_key=custody_key,
            )
            with self.assertRaises(WindowsDecisionProviderError) as raised:
                adapter._verify_typed_response(
                    request=request,
                    acknowledgement=forged.to_canonical_dict(),
                    current_object=continuity.to_canonical_dict(),
                )
            self.assertEqual("EXTERNAL_CAS_ACK_INVALID", raised.exception.reason_code)

    def test_v2_continuity_rejects_negative_ack_readback_and_callback_failures(self) -> None:
        configuration, custody_key, continuity, adapter, request, _ = self._continuity_case()
        rejected = issue_trusted_utc_continuity_cas_acknowledgement(
            binding=configuration.clock_continuity_binding,
            expected_previous_continuity_sha256="0" * 64,
            accepted_continuity_sha256=continuity.content_sha256,
            observed_previous_continuity_sha256="f" * 64,
            accepted=False,
            issued_at_utc=self.now,
            custody_key=custody_key,
        )
        with self.assertRaises(WindowsDecisionProviderError) as raised:
            adapter._verify_typed_response(
                request=request,
                acknowledgement=rejected.to_canonical_dict(),
                current_object=continuity.to_canonical_dict(),
            )
        self.assertEqual("EXTERNAL_CAS_READBACK_MISMATCH", raised.exception.reason_code)
        key_failure = TrustedUTCContinuityExternalCAS(
            binding=configuration.clock_continuity_binding,
            request_directory=configuration.clock_continuity_request_directory,
            response_directory=configuration.clock_continuity_response_directory,
            custody_key_provider=lambda _: (_ for _ in ()).throw(OSError()),
            system_clock=lambda: self.now,
            timeout_seconds=1.0,
        )
        with self.assertRaises(WindowsDecisionProviderError) as raised:
            key_failure._verify_typed_response(
                request=request,
                acknowledgement=rejected.to_canonical_dict(),
                current_object=continuity.to_canonical_dict(),
            )
        self.assertEqual("EXTERNAL_CAS_KEY_UNAVAILABLE", raised.exception.reason_code)
        clock_failure = TrustedUTCContinuityExternalCAS(
            binding=configuration.clock_continuity_binding,
            request_directory=configuration.clock_continuity_request_directory,
            response_directory=configuration.clock_continuity_response_directory,
            custody_key_provider=lambda _: custody_key,
            system_clock=lambda: (_ for _ in ()).throw(OSError()),
            timeout_seconds=1.0,
        )
        with self.assertRaises(WindowsDecisionProviderError) as raised:
            clock_failure._clock()
        self.assertEqual("EXTERNAL_CAS_CLOCK_INVALID", raised.exception.reason_code)

    def test_v2_continuity_rejects_cross_domain_and_stale_response(self) -> None:
        _configuration, _key, continuity, adapter, request, acknowledgement = (
            self._continuity_case()
        )
        request_path = Path(adapter._request_directory) / f"{request.request_id}.request.json"
        request_path.write_bytes(canonical_json(request).encode("utf-8"))

        def timestamp(value):
            return value.isoformat(timespec="microseconds").replace("+00:00", "Z")

        response = {
            "schema_version": "external-cas-response-v1",
            "request_id": request.request_id,
            "request_sha256": request.content_sha256,
            "provider_id": request.provider_id,
            "state_domain": request.state_domain,
            "identity_sha256": request.identity_sha256,
            "acknowledgement": acknowledgement.to_canonical_dict(),
            "current_object": continuity.to_canonical_dict(),
            "responded_at_utc": timestamp(request.expires_at_utc),
        }
        with self.assertRaises(WindowsDecisionProviderError) as raised:
            adapter._parse_response(
                canonical_json(response).encode("utf-8"),
                expected_request=request,
                require_live_observation=False,
            )
        self.assertEqual("EXTERNAL_CAS_RESPONSE_EXPIRED", raised.exception.reason_code)
        response["responded_at_utc"] = timestamp(self.now)
        response["state_domain"] = "DECISION_IPC"
        with self.assertRaises(WindowsDecisionProviderError) as raised:
            adapter._parse_response(
                canonical_json(response).encode("utf-8"),
                expected_request=request,
                require_live_observation=False,
            )
        self.assertEqual("EXTERNAL_CAS_RESPONSE_INVALID", raised.exception.reason_code)

    def test_v2_envelope_replacement_is_rejected(self) -> None:
        configuration, _runtime, _ = self._v2_configuration()
        path = Path(configuration.clock_attestation_path)
        replacement = path.with_name("replacement-envelope.json")
        replacement.write_bytes(path.read_bytes())
        reader = WindowsEd25519ClockEnvelopeFile(path)
        original = Path.read_bytes

        def replace_during_read(observed):
            payload = original(observed)
            if observed == path:
                os.replace(replacement, path)
            return payload

        with patch.object(Path, "read_bytes", replace_during_read), self.assertRaises(
            WindowsDecisionProviderError
        ) as raised:
            reader()
        self.assertEqual("TRUSTED_UTC_ENVELOPE_UNSTABLE", raised.exception.reason_code)

    def test_v2_direct_and_ancestor_alias_paths_fail_before_credentials(self) -> None:
        configuration, _runtime, _ = self._v2_configuration()

        def runtime_for(config):
            hashes = config.provider_configuration_hashes()
            return replace(
                self.runtime,
                providers=tuple(
                    replace(item, configuration_sha256=hashes[item.role])
                    for item in self.runtime.providers
                ),
            )

        direct = replace(
            configuration,
            clock_continuity_request_directory=configuration.ipc_cas_request_directory,
        )
        with self.assertRaises(WindowsDecisionProviderError) as raised:
            build_windows_decision_provider_service_v2(
                runtime_config=runtime_for(direct), provider_config=direct
            )
        self.assertEqual("DECISION_PROVIDER_PATH_COLLISION", raised.exception.reason_code)
        alias = self.root / "clock-request-alias"
        try:
            alias.symlink_to(
                Path(configuration.clock_continuity_request_directory),
                target_is_directory=True,
            )
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"directory symlink unavailable: {exc}")
        aliased = replace(
            configuration,
            clock_continuity_request_directory=str(alias),
        )
        with self.assertRaises(WindowsDecisionProviderError) as raised:
            build_windows_decision_provider_service_v2(
                runtime_config=runtime_for(aliased), provider_config=aliased
            )
        self.assertEqual("DECISION_PROVIDER_V2_PATH_INVALID", raised.exception.reason_code)
        self.assertEqual([], self.backend.reads)

    @unittest.skipUnless(os.name == "nt", "Windows junction semantics only")
    def test_v2_ancestor_junction_is_rejected(self) -> None:
        configuration, _runtime, _ = self._v2_configuration()
        junction = self.root / "clock-request-junction"
        completed = subprocess.run(
            [
                "cmd",
                "/c",
                "mklink",
                "/J",
                str(junction),
                configuration.clock_continuity_request_directory,
            ],
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            self.skipTest("junction creation unavailable")
        drifted = replace(
            configuration,
            clock_continuity_request_directory=str(junction),
        )
        hashes = drifted.provider_configuration_hashes()
        runtime = replace(
            self.runtime,
            providers=tuple(
                replace(item, configuration_sha256=hashes[item.role])
                for item in self.runtime.providers
            ),
        )
        with self.assertRaises(WindowsDecisionProviderError) as raised:
            build_windows_decision_provider_service_v2(
                runtime_config=runtime, provider_config=drifted
            )
        self.assertEqual("DECISION_PROVIDER_V2_PATH_INVALID", raised.exception.reason_code)

    def test_successful_v2_composition_with_approved_clock_port(self) -> None:
        configuration, runtime, _ = self._v2_configuration()
        trusted_clock = unittest.mock.Mock(return_value=self.now)
        with (
            patch("live_runtime.windows_decision_provider_pack.sys.platform", "win32"),
            patch(
                "live_runtime.windows_decision_provider_pack._WindowsNativeCredentialBackend",
                return_value=self.backend,
            ),
            patch(
                "live_runtime.windows_decision_provider_pack.Ed25519AttestedTrustedUTCProvider",
                return_value=trusted_clock,
            ),
        ):
            service = build_windows_decision_provider_service_v2(
                runtime_config=runtime, provider_config=configuration
            )
            cycle = service.run_cycle()
        self.assertIs(type(service), BrokerlessDecisionProducerService)
        self.assertEqual("NO_INPUT", cycle.lanes[0].status)
        self.assertGreaterEqual(trusted_clock.call_count, 1)


if __name__ == "__main__":
    unittest.main()
