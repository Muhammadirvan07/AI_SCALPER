from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from live_runtime.brokerless_decision_producer import (
    DecisionProducerBinding,
    DecisionProducerCheckpoint,
    DecisionProducerLaneConfig,
    decision_producer_key_fingerprint,
    issue_decision_producer_cas_acknowledgement,
)
from live_runtime.contracts import canonical_json, canonical_sha256
from live_runtime.decision_ipc import (
    ZERO_SHA256,
    DecisionIPCBinding,
    DurableDecisionIPCQueue,
    decision_ipc_key_fingerprint,
    issue_decision_ipc_cas_acknowledgement,
)
from live_runtime.windows_decision_provider_pack import (
    DecisionIPCExternalCAS,
    DecisionProducerExternalCAS,
    WindowsDecisionProviderError,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 25, 4, 0, tzinfo=UTC)
IPC_DECISION_KEY = b"external-cas-ipc-decision-key-material-minimum"
IPC_CUSTODY_KEY = b"external-cas-ipc-custody-key-material-minimum"
CURSOR_CUSTODY_KEY = b"external-cas-cursor-custody-key-material-minimum"
HASH_A = hashlib.sha256(b"a").hexdigest()
HASH_B = hashlib.sha256(b"b").hexdigest()
HASH_C = hashlib.sha256(b"c").hexdigest()
COMMIT = hashlib.sha1(b"commit").hexdigest()


class WindowsDecisionExternalCASTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.ipc_requests = self.root / "ipc-requests"
        self.ipc_responses = self.root / "ipc-responses"
        self.cursor_requests = self.root / "cursor-requests"
        self.cursor_responses = self.root / "cursor-responses"
        for directory in (
            self.ipc_requests,
            self.ipc_responses,
            self.cursor_requests,
            self.cursor_responses,
        ):
            directory.mkdir()

        self.ipc_binding = DecisionIPCBinding(
            queue_id="decision-queue-v1",
            account_id_sha256=HASH_A,
            server="Reviewed-Demo-Server",
            environment="DEMO",
            journal_sha256=HASH_B,
            commit_sha=COMMIT,
            config_sha256=HASH_C,
            model_artifact_sha256=HASH_A,
            data_contract_sha256=HASH_B,
            decision_issuer_id="decision-service-v1",
            decision_key_id="decision-key-v1",
            decision_key_fingerprint_sha256=decision_ipc_key_fingerprint(
                IPC_DECISION_KEY
            ),
            custody_issuer_id="ipc-custody-v1",
            custody_key_id="ipc-custody-key-v1",
            custody_key_fingerprint_sha256=decision_ipc_key_fingerprint(
                IPC_CUSTODY_KEY
            ),
            permit_key_id="permit-key-v1",
            permit_key_fingerprint_sha256=HASH_C,
        )
        local_head = None

        def local_provider():
            return local_head

        def local_exporter(expected, checkpoint):
            nonlocal local_head
            observed = (
                ZERO_SHA256
                if local_head is None
                else local_head.content_sha256
            )
            accepted = observed == expected
            if accepted:
                local_head = checkpoint
            return issue_decision_ipc_cas_acknowledgement(
                queue_id=self.ipc_binding.queue_id,
                expected_previous_checkpoint_sha256=expected,
                accepted_checkpoint_sha256=checkpoint.content_sha256,
                observed_previous_checkpoint_sha256=observed,
                accepted=accepted,
                issued_at_utc=checkpoint.issued_at_utc,
                custody_issuer_id=self.ipc_binding.custody_issuer_id,
                custody_key_id=self.ipc_binding.custody_key_id,
                custody_key=IPC_CUSTODY_KEY,
            )

        self.queue = DurableDecisionIPCQueue.provision(
            self.root / "decision-ipc.sqlite3",
            binding=self.ipc_binding,
            decision_key_provider=lambda _: IPC_DECISION_KEY,
            custody_key_provider=lambda _: IPC_CUSTODY_KEY,
            external_checkpoint_provider=local_provider,
            checkpoint_exporter=local_exporter,
            clock_provider=lambda: NOW,
        )
        self.ipc_checkpoint = self.queue.current_checkpoint()

        lane = DecisionProducerLaneConfig(
            lane_id="xauusd-m15-primary",
            symbol="XAUUSD",
            source_name="broker-signed-feed",
            data_contract_sha256=HASH_A,
            model_version="champion-v1",
            model_artifact_sha256=HASH_A,
            commit_sha=COMMIT,
            config_sha256=HASH_C,
            session_calendar_sha256=HASH_B,
            session_calendar_issuer_id="calendar-v1",
            session_calendar_key_id="calendar-key-v1",
            session_calendar_key_fingerprint_sha256=HASH_C,
        )
        self.producer_binding = DecisionProducerBinding(
            service_id="decision-service-v1",
            lanes=(lane,),
            custody_issuer_id="cursor-custody-v1",
            custody_key_id="cursor-custody-key-v1",
            custody_key_fingerprint_sha256=decision_producer_key_fingerprint(
                CURSOR_CUSTODY_KEY
            ),
        )
        self.producer_checkpoint = DecisionProducerCheckpoint(
            service_id=self.producer_binding.service_id,
            binding_sha256=self.producer_binding.content_sha256,
            sequence=0,
            previous_checkpoint_sha256=ZERO_SHA256,
            lane_cursors=(),
            issued_at_utc=NOW,
            custody_issuer_id=self.producer_binding.custody_issuer_id,
        )

    @staticmethod
    def _write_exact(path: Path, payload: dict[str, object]) -> None:
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_bytes(canonical_json(payload).encode("utf-8"))
        temporary.replace(path)

    def _start_responder(
        self,
        *,
        request_directory: Path,
        response_directory: Path,
        state_domain: str,
        acknowledgement_factory,
        mutate_response=None,
        mutate_head=None,
    ) -> tuple[threading.Thread, list[BaseException]]:
        failures: list[BaseException] = []

        def respond() -> None:
            try:
                deadline = time.monotonic() + 2
                request_path = None
                while time.monotonic() < deadline:
                    matches = tuple(
                        request_directory.glob("*.request.json")
                    )
                    if matches:
                        request_path = matches[0]
                        break
                    time.sleep(0.005)
                if request_path is None:
                    raise AssertionError("CAS request was not published")
                request = json.loads(request_path.read_text(encoding="utf-8"))
                acknowledgement = acknowledgement_factory(request)
                response = {
                    "schema_version": "external-cas-response-v1",
                    "request_id": request["request_id"],
                    "request_sha256": canonical_sha256(request),
                    "provider_id": request["provider_id"],
                    "state_domain": state_domain,
                    "identity_sha256": request["identity_sha256"],
                    "acknowledgement": acknowledgement.to_canonical_dict(),
                    "current_object": request["proposed_object"],
                    "responded_at_utc": NOW,
                }
                if mutate_response is not None:
                    response = mutate_response(response)
                response_path = response_directory / (
                    f"{request['request_id']}.response.json"
                )
                self._write_exact(response_path, response)
                head = response
                if mutate_head is not None:
                    head = mutate_head(dict(response))
                self._write_exact(
                    response_directory / "current.response.json",
                    head,
                )
            except BaseException as exc:
                failures.append(exc)

        thread = threading.Thread(target=respond, daemon=True)
        thread.start()
        return thread, failures

    def _ipc_cas(self) -> DecisionIPCExternalCAS:
        return DecisionIPCExternalCAS(
            provider_id="ipc-directory-cas-v1",
            binding=self.ipc_binding,
            request_directory=self.ipc_requests,
            response_directory=self.ipc_responses,
            custody_key_provider=lambda _: IPC_CUSTODY_KEY,
            clock_provider=lambda: NOW,
            timeout_seconds=1.0,
        )

    def _producer_cas(self) -> DecisionProducerExternalCAS:
        return DecisionProducerExternalCAS(
            provider_id="cursor-directory-cas-v1",
            binding=self.producer_binding,
            request_directory=self.cursor_requests,
            response_directory=self.cursor_responses,
            custody_key_provider=lambda _: CURSOR_CUSTODY_KEY,
            clock_provider=lambda: NOW,
            timeout_seconds=1.0,
        )

    def test_ipc_compare_and_swap_is_signed_exact_and_idempotent(self) -> None:
        cas = self._ipc_cas()
        self.assertIsNone(cas.current())

        def acknowledgement(request):
            return issue_decision_ipc_cas_acknowledgement(
                queue_id=self.ipc_binding.queue_id,
                expected_previous_checkpoint_sha256=(
                    request["expected_previous_sha256"]
                ),
                accepted_checkpoint_sha256=request["proposed_sha256"],
                observed_previous_checkpoint_sha256=(
                    request["expected_previous_sha256"]
                ),
                accepted=True,
                issued_at_utc=NOW,
                custody_issuer_id=self.ipc_binding.custody_issuer_id,
                custody_key_id=self.ipc_binding.custody_key_id,
                custody_key=IPC_CUSTODY_KEY,
            )

        thread, failures = self._start_responder(
            request_directory=self.ipc_requests,
            response_directory=self.ipc_responses,
            state_domain="DECISION_IPC",
            acknowledgement_factory=acknowledgement,
        )
        observed = cas.compare_and_swap(ZERO_SHA256, self.ipc_checkpoint)
        thread.join(timeout=2)
        self.assertEqual([], failures)
        self.assertTrue(observed.accepted)
        self.assertEqual(self.ipc_checkpoint, cas.current())

        request_path = next(self.ipc_requests.glob("*.request.json"))
        original = request_path.read_bytes()
        retried = cas.compare_and_swap(ZERO_SHA256, self.ipc_checkpoint)
        self.assertEqual(observed, retried)
        self.assertEqual(original, request_path.read_bytes())

    def test_producer_compare_and_swap_is_domain_separated(self) -> None:
        cas = self._producer_cas()
        self.assertIsNone(cas.current())

        def acknowledgement(request):
            return issue_decision_producer_cas_acknowledgement(
                service_id=self.producer_binding.service_id,
                binding_sha256=self.producer_binding.content_sha256,
                expected_previous_checkpoint_sha256=(
                    request["expected_previous_sha256"]
                ),
                accepted_checkpoint_sha256=request["proposed_sha256"],
                observed_previous_checkpoint_sha256=(
                    request["expected_previous_sha256"]
                ),
                accepted=True,
                issued_at_utc=NOW,
                custody_issuer_id=self.producer_binding.custody_issuer_id,
                custody_key_id=self.producer_binding.custody_key_id,
                custody_key=CURSOR_CUSTODY_KEY,
            )

        thread, failures = self._start_responder(
            request_directory=self.cursor_requests,
            response_directory=self.cursor_responses,
            state_domain="PRODUCER_CURSOR",
            acknowledgement_factory=acknowledgement,
        )
        observed = cas.compare_and_swap(
            ZERO_SHA256,
            self.producer_checkpoint,
        )
        thread.join(timeout=2)
        self.assertEqual([], failures)
        self.assertTrue(observed.accepted)
        self.assertEqual(self.producer_checkpoint, cas.current())

        request = json.loads(
            next(self.cursor_requests.glob("*.request.json")).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("PRODUCER_CURSOR", request["state_domain"])
        self.assertEqual(
            self.producer_binding.content_sha256,
            request["identity_sha256"],
        )

    def test_forged_ack_and_readback_mismatch_fail_closed(self) -> None:
        cas = self._ipc_cas()

        # A public constructor cannot mint the forged sealed type, so mutate
        # only its canonical response after a valid acknowledgement is built.
        def valid_ack(request):
            return issue_decision_ipc_cas_acknowledgement(
                queue_id=self.ipc_binding.queue_id,
                expected_previous_checkpoint_sha256=ZERO_SHA256,
                accepted_checkpoint_sha256=request["proposed_sha256"],
                observed_previous_checkpoint_sha256=ZERO_SHA256,
                accepted=True,
                issued_at_utc=NOW,
                custody_issuer_id=self.ipc_binding.custody_issuer_id,
                custody_key_id=self.ipc_binding.custody_key_id,
                custody_key=IPC_CUSTODY_KEY,
            )

        def mutate_signature(response):
            response = dict(response)
            acknowledgement = dict(response["acknowledgement"])
            acknowledgement["signature_hmac_sha256"] = "f" * 64
            response["acknowledgement"] = acknowledgement
            return response

        thread, failures = self._start_responder(
            request_directory=self.ipc_requests,
            response_directory=self.ipc_responses,
            state_domain="DECISION_IPC",
            acknowledgement_factory=valid_ack,
            mutate_response=mutate_signature,
        )
        with self.assertRaises(WindowsDecisionProviderError) as raised:
            cas.compare_and_swap(ZERO_SHA256, self.ipc_checkpoint)
        thread.join(timeout=2)
        self.assertEqual([], failures)
        self.assertEqual(
            "EXTERNAL_CAS_ACK_INVALID",
            raised.exception.reason_code,
        )

    def test_conflicting_retry_and_symlinked_head_are_rejected(self) -> None:
        cas = self._producer_cas()

        def acknowledgement(request):
            return issue_decision_producer_cas_acknowledgement(
                service_id=self.producer_binding.service_id,
                binding_sha256=self.producer_binding.content_sha256,
                expected_previous_checkpoint_sha256=ZERO_SHA256,
                accepted_checkpoint_sha256=request["proposed_sha256"],
                observed_previous_checkpoint_sha256=ZERO_SHA256,
                accepted=True,
                issued_at_utc=NOW,
                custody_issuer_id=self.producer_binding.custody_issuer_id,
                custody_key_id=self.producer_binding.custody_key_id,
                custody_key=CURSOR_CUSTODY_KEY,
            )

        thread, failures = self._start_responder(
            request_directory=self.cursor_requests,
            response_directory=self.cursor_responses,
            state_domain="PRODUCER_CURSOR",
            acknowledgement_factory=acknowledgement,
        )
        cas.compare_and_swap(ZERO_SHA256, self.producer_checkpoint)
        thread.join(timeout=2)
        self.assertEqual([], failures)
        request_path = next(self.cursor_requests.glob("*.request.json"))
        request_path.write_text("{}", encoding="utf-8")
        with self.assertRaises(WindowsDecisionProviderError) as conflict:
            cas.compare_and_swap(ZERO_SHA256, self.producer_checkpoint)
        self.assertEqual(
            "EXTERNAL_CAS_REQUEST_CONFLICT",
            conflict.exception.reason_code,
        )

        head = self.cursor_responses / "current.response.json"
        head.unlink()
        head.symlink_to(next(self.cursor_responses.glob("*.response.json")))
        with self.assertRaises(WindowsDecisionProviderError) as unsafe:
            cas.current()
        self.assertEqual(
            "EXTERNAL_CAS_PATH_INVALID",
            unsafe.exception.reason_code,
        )


if __name__ == "__main__":
    unittest.main()
