from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from live_runtime.brokerless_decision_producer import (
    DecisionProducerBinding,
    DecisionProducerLaneConfig,
    DecisionProducerCheckpoint,
    decision_producer_key_fingerprint,
    issue_decision_producer_cas_acknowledgement,
    parse_decision_producer_cas_acknowledgement,
    parse_decision_producer_checkpoint,
)
from live_runtime.contracts import canonical_json
from live_runtime.decision_ipc import (
    ZERO_SHA256,
    DecisionIPCBinding,
    DecisionIPCCASAcknowledgement,
    DecisionIPCCheckpoint,
    DurableDecisionIPCQueue,
    decision_ipc_key_fingerprint,
    issue_decision_ipc_cas_acknowledgement,
    parse_decision_ipc_cas_acknowledgement,
    parse_decision_ipc_checkpoint,
)
from live_runtime.windows_decision_provider_pack import (
    AttestedTrustedUTCProvider,
    CredentialReference,
    WindowsClockBinding,
    WindowsCredentialManagerKeyProvider,
    WindowsDecisionProviderError,
    issue_windows_clock_attestation,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 25, 3, 0, tzinfo=UTC)
KEY = b"decision-provider-pack-key-material-32bytes-minimum"
OTHER_KEY = b"decision-provider-pack-other-key-material-minimum"
HASH_A = hashlib.sha256(b"a").hexdigest()
HASH_B = hashlib.sha256(b"b").hexdigest()
HASH_C = hashlib.sha256(b"c").hexdigest()
COMMIT = hashlib.sha1(b"commit").hexdigest()


class FakeCredentialBackend:
    def __init__(self, values: dict[str, bytes] | None = None) -> None:
        self.values = dict(values or {})
        self.reads: list[str] = []

    def read_blob(self, target_name: str) -> bytes | None:
        self.reads.append(target_name)
        return self.values.get(target_name)


class CredentialProviderTests(unittest.TestCase):
    def reference(self, *, fingerprint: str | None = None) -> CredentialReference:
        return CredentialReference(
            key_id="decision-key-v1",
            target_name="AI_SCALPER/DECISION/decision-key-v1",
            fingerprint_sha256=fingerprint or hashlib.sha256(KEY).hexdigest(),
        )

    def test_exact_ascii_hex_credential_is_read_only_and_not_cached(self) -> None:
        target = self.reference().target_name
        backend = FakeCredentialBackend({target: b"hex:" + KEY.hex().encode("ascii")})
        provider = WindowsCredentialManagerKeyProvider(
            target_prefix="AI_SCALPER/DECISION",
            references=(self.reference(),),
            backend=backend,
            platform="win32",
        )

        self.assertEqual(KEY, provider("decision-key-v1"))
        self.assertEqual(KEY, provider("decision-key-v1"))
        self.assertEqual([target, target], backend.reads)
        self.assertFalse(hasattr(provider, "__dict__"))
        for forbidden in ("ensure", "write", "delete", "enumerate", "backend"):
            self.assertFalse(hasattr(provider, forbidden), forbidden)

    def test_exact_utf16_hex_credential_is_supported(self) -> None:
        target = self.reference().target_name
        encoded = ("hex:" + KEY.hex()).encode("utf-16-le")
        provider = WindowsCredentialManagerKeyProvider(
            target_prefix="AI_SCALPER/DECISION",
            references=(self.reference(),),
            backend=FakeCredentialBackend({target: encoded}),
            platform="win32",
        )
        self.assertEqual(KEY, provider("decision-key-v1"))

    def test_non_windows_unknown_missing_malformed_short_and_mismatch_fail(self) -> None:
        reference = self.reference()
        target = reference.target_name
        cases = (
            (
                WindowsCredentialManagerKeyProvider(
                    target_prefix="AI_SCALPER/DECISION",
                    references=(reference,),
                    backend=FakeCredentialBackend({target: b"hex:" + KEY.hex().encode()}),
                    platform="darwin",
                ),
                "decision-key-v1",
                "WINDOWS_PLATFORM_REQUIRED",
            ),
            (
                WindowsCredentialManagerKeyProvider(
                    target_prefix="AI_SCALPER/DECISION",
                    references=(reference,),
                    backend=FakeCredentialBackend(),
                    platform="win32",
                ),
                "unknown-key",
                "CREDENTIAL_KEY_ID_NOT_ALLOWED",
            ),
            (
                WindowsCredentialManagerKeyProvider(
                    target_prefix="AI_SCALPER/DECISION",
                    references=(reference,),
                    backend=FakeCredentialBackend(),
                    platform="win32",
                ),
                "decision-key-v1",
                "CREDENTIAL_NOT_PROVISIONED",
            ),
            (
                WindowsCredentialManagerKeyProvider(
                    target_prefix="AI_SCALPER/DECISION",
                    references=(reference,),
                    backend=FakeCredentialBackend({target: b"plaintext"}),
                    platform="win32",
                ),
                "decision-key-v1",
                "CREDENTIAL_BLOB_INVALID",
            ),
            (
                WindowsCredentialManagerKeyProvider(
                    target_prefix="AI_SCALPER/DECISION",
                    references=(reference,),
                    backend=FakeCredentialBackend({target: b"hex:" + b"00" * 16}),
                    platform="win32",
                ),
                "decision-key-v1",
                "CREDENTIAL_KEY_TOO_SHORT",
            ),
            (
                WindowsCredentialManagerKeyProvider(
                    target_prefix="AI_SCALPER/DECISION",
                    references=(self.reference(fingerprint=hashlib.sha256(OTHER_KEY).hexdigest()),),
                    backend=FakeCredentialBackend({target: b"hex:" + KEY.hex().encode()}),
                    platform="win32",
                ),
                "decision-key-v1",
                "CREDENTIAL_FINGERPRINT_MISMATCH",
            ),
        )
        for provider, key_id, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(WindowsDecisionProviderError) as raised:
                    provider(key_id)
                self.assertEqual(reason, raised.exception.reason_code)
                self.assertNotIn(KEY.hex(), str(raised.exception))

    def test_reference_set_is_closed_unique_and_case_exact(self) -> None:
        duplicate = self.reference()
        with self.assertRaisesRegex(ValueError, "unique"):
            WindowsCredentialManagerKeyProvider(
                target_prefix="AI_SCALPER/DECISION",
                references=(duplicate, duplicate),
                backend=FakeCredentialBackend(),
                platform="win32",
            )
        provider = WindowsCredentialManagerKeyProvider(
            target_prefix="AI_SCALPER/DECISION",
            references=(duplicate,),
            backend=FakeCredentialBackend(),
            platform="win32",
        )
        with self.assertRaises(WindowsDecisionProviderError) as raised:
            provider("DECISION-KEY-V1")
        self.assertEqual(
            "CREDENTIAL_KEY_ID_NOT_ALLOWED",
            raised.exception.reason_code,
        )
        wrong_target = CredentialReference(
            key_id="decision-key-v1",
            target_name="AI_SCALPER/OTHER/decision-key-v1",
            fingerprint_sha256=hashlib.sha256(KEY).hexdigest(),
        )
        with self.assertRaisesRegex(ValueError, "prefix-bound"):
            WindowsCredentialManagerKeyProvider(
                target_prefix="AI_SCALPER/DECISION",
                references=(wrong_target,),
                backend=FakeCredentialBackend(),
                platform="win32",
            )


class TrustedClockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.system_now = NOW
        self.key_provider = lambda key_id: KEY
        self.binding = WindowsClockBinding(
            provider_id="decision-clock-v1",
            host_identity_sha256=HASH_A,
            authority_issuer_id="offhost-clock-authority-v1",
            authority_key_id="clock-key-v1",
            authority_key_fingerprint_sha256=hashlib.sha256(KEY).hexdigest(),
            maximum_attestation_age_ms=5_000,
            maximum_absolute_drift_ms=1_000,
        )

    def attestation(self, **overrides: object):
        values = {
            "binding": self.binding,
            "authority_utc": NOW - timedelta(milliseconds=150),
            "observed_system_utc": NOW,
            "issued_at_utc": NOW - timedelta(milliseconds=200),
            "expires_at_utc": NOW + timedelta(seconds=2),
            "authority_key": KEY,
        }
        values.update(overrides)
        return issue_windows_clock_attestation(**values)

    def provider(self, attestation=None) -> AttestedTrustedUTCProvider:
        current = self.attestation() if attestation is None else attestation
        return AttestedTrustedUTCProvider(
            binding=self.binding,
            attestation_provider=lambda: current,
            key_provider=self.key_provider,
            system_clock=lambda: self.system_now,
        )

    def test_fresh_signed_attestation_returns_aware_utc(self) -> None:
        observed = self.provider()()
        self.assertEqual(NOW, observed)
        self.assertIs(UTC, observed.tzinfo)

    def test_forged_stale_future_drift_naive_and_binding_mismatch_fail(self) -> None:
        valid = self.attestation()
        cases = (
            (
                replace(valid, hmac_sha256="f" * 64),
                "CLOCK_ATTESTATION_SIGNATURE_INVALID",
            ),
            (
                self.attestation(
                    issued_at_utc=NOW - timedelta(seconds=6),
                    expires_at_utc=NOW + timedelta(seconds=1),
                ),
                "CLOCK_ATTESTATION_STALE",
            ),
            (
                self.attestation(
                    issued_at_utc=NOW + timedelta(seconds=2),
                    expires_at_utc=NOW + timedelta(seconds=3),
                ),
                "CLOCK_ATTESTATION_FUTURE",
            ),
            (
                self.attestation(
                    authority_utc=NOW - timedelta(seconds=2),
                ),
                "CLOCK_DRIFT_EXCEEDED",
            ),
            (
                self.attestation(
                    binding=replace(self.binding, provider_id="other-clock"),
                ),
                "CLOCK_BINDING_MISMATCH",
            ),
        )
        for attestation, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(WindowsDecisionProviderError) as raised:
                    self.provider(attestation)()
                self.assertEqual(reason, raised.exception.reason_code)

        naive_provider = AttestedTrustedUTCProvider(
            binding=self.binding,
            attestation_provider=lambda: valid,
            key_provider=self.key_provider,
            system_clock=lambda: NOW.replace(tzinfo=None),
        )
        with self.assertRaises(WindowsDecisionProviderError) as raised:
            naive_provider()
        self.assertEqual("TRUSTED_CLOCK_INVALID", raised.exception.reason_code)

    def test_clock_regression_is_rejected_after_first_success(self) -> None:
        provider = self.provider()
        self.assertEqual(NOW, provider())
        self.system_now = NOW - timedelta(microseconds=1)
        with self.assertRaises(WindowsDecisionProviderError) as raised:
            provider()
        self.assertEqual("TRUSTED_CLOCK_REGRESSION", raised.exception.reason_code)

    def test_key_failure_and_fingerprint_mismatch_do_not_leak_key(self) -> None:
        for key_provider, reason in (
            (
                lambda _: (_ for _ in ()).throw(RuntimeError(KEY.hex())),
                "CLOCK_KEY_UNAVAILABLE",
            ),
            (
                lambda _: OTHER_KEY,
                "CLOCK_KEY_FINGERPRINT_MISMATCH",
            ),
        ):
            with self.subTest(reason=reason):
                provider = AttestedTrustedUTCProvider(
                    binding=self.binding,
                    attestation_provider=self.attestation,
                    key_provider=key_provider,
                    system_clock=lambda: NOW,
                )
                with self.assertRaises(WindowsDecisionProviderError) as raised:
                    provider()
                self.assertEqual(reason, raised.exception.reason_code)
                self.assertNotIn(KEY.hex(), str(raised.exception))


class StrictCheckpointParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ipc_current = None
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
            decision_key_fingerprint_sha256=decision_ipc_key_fingerprint(KEY),
            custody_issuer_id="ipc-custody-v1",
            custody_key_id="ipc-custody-key-v1",
            custody_key_fingerprint_sha256=decision_ipc_key_fingerprint(OTHER_KEY),
            permit_key_id="permit-key-v1",
            permit_key_fingerprint_sha256=HASH_C,
        )

        def ipc_exporter(expected, checkpoint):
            observed = (
                ZERO_SHA256
                if self.ipc_current is None
                else self.ipc_current.content_sha256
            )
            accepted = observed == expected
            if accepted:
                self.ipc_current = checkpoint
            return issue_decision_ipc_cas_acknowledgement(
                queue_id=self.ipc_binding.queue_id,
                expected_previous_checkpoint_sha256=expected,
                accepted_checkpoint_sha256=checkpoint.content_sha256,
                observed_previous_checkpoint_sha256=observed,
                accepted=accepted,
                issued_at_utc=checkpoint.issued_at_utc,
                custody_issuer_id=self.ipc_binding.custody_issuer_id,
                custody_key_id=self.ipc_binding.custody_key_id,
                custody_key=OTHER_KEY,
            )

        self.queue = DurableDecisionIPCQueue.provision(
            self.root / "decision-ipc.sqlite3",
            binding=self.ipc_binding,
            decision_key_provider=lambda _: KEY,
            custody_key_provider=lambda _: OTHER_KEY,
            external_checkpoint_provider=lambda: self.ipc_current,
            checkpoint_exporter=ipc_exporter,
            clock_provider=lambda: NOW,
        )
        self.lane = DecisionProducerLaneConfig(
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
            lanes=(self.lane,),
            custody_issuer_id="cursor-custody-v1",
            custody_key_id="cursor-key-v1",
            custody_key_fingerprint_sha256=decision_producer_key_fingerprint(KEY),
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

    def test_exact_ipc_checkpoint_and_ack_round_trip(self) -> None:
        checkpoint = self.queue.current_checkpoint()
        parsed_checkpoint = parse_decision_ipc_checkpoint(
            checkpoint.to_canonical_dict()
        )
        self.assertIs(type(parsed_checkpoint), DecisionIPCCheckpoint)
        self.assertEqual(checkpoint, parsed_checkpoint)

        ack = issue_decision_ipc_cas_acknowledgement(
            queue_id=self.ipc_binding.queue_id,
            expected_previous_checkpoint_sha256=checkpoint.content_sha256,
            accepted_checkpoint_sha256=checkpoint.content_sha256,
            observed_previous_checkpoint_sha256=checkpoint.content_sha256,
            accepted=True,
            issued_at_utc=NOW,
            custody_issuer_id=self.ipc_binding.custody_issuer_id,
            custody_key_id=self.ipc_binding.custody_key_id,
            custody_key=OTHER_KEY,
        )
        parsed_ack = parse_decision_ipc_cas_acknowledgement(
            ack.to_canonical_dict()
        )
        self.assertIs(type(parsed_ack), DecisionIPCCASAcknowledgement)
        self.assertEqual(ack, parsed_ack)

    def test_exact_producer_checkpoint_and_ack_round_trip(self) -> None:
        parsed_checkpoint = parse_decision_producer_checkpoint(
            self.producer_checkpoint.to_canonical_dict()
        )
        self.assertIs(type(parsed_checkpoint), DecisionProducerCheckpoint)
        self.assertEqual(self.producer_checkpoint, parsed_checkpoint)

        ack = issue_decision_producer_cas_acknowledgement(
            service_id=self.producer_binding.service_id,
            binding_sha256=self.producer_binding.content_sha256,
            expected_previous_checkpoint_sha256=ZERO_SHA256,
            accepted_checkpoint_sha256=self.producer_checkpoint.content_sha256,
            observed_previous_checkpoint_sha256=ZERO_SHA256,
            accepted=True,
            issued_at_utc=NOW,
            custody_issuer_id=self.producer_binding.custody_issuer_id,
            custody_key_id=self.producer_binding.custody_key_id,
            custody_key=KEY,
        )
        parsed_ack = parse_decision_producer_cas_acknowledgement(
            ack.to_canonical_dict()
        )
        self.assertIs(type(parsed_ack), type(ack))
        self.assertEqual(ack, parsed_ack)

    def test_parsers_reject_unknown_missing_duplicate_and_naive_fields(self) -> None:
        ipc_payload = self.queue.current_checkpoint().to_canonical_dict()
        producer_payload = self.producer_checkpoint.to_canonical_dict()
        cases = (
            (
                parse_decision_ipc_checkpoint,
                {**ipc_payload, "unknown": True},
            ),
            (
                parse_decision_ipc_checkpoint,
                {key: value for key, value in ipc_payload.items() if key != "queue_id"},
            ),
            (
                parse_decision_ipc_checkpoint,
                {**ipc_payload, "issued_at_utc": "2026-07-25T03:00:00"},
            ),
            (
                parse_decision_producer_checkpoint,
                {**producer_payload, "unknown": True},
            ),
            (
                parse_decision_producer_checkpoint,
                {
                    key: value
                    for key, value in producer_payload.items()
                    if key != "service_id"
                },
            ),
            (
                parse_decision_producer_checkpoint,
                {**producer_payload, "issued_at_utc": "2026-07-25T03:00:00"},
            ),
        )
        for parser, payload in cases:
            with self.subTest(parser=parser.__name__, payload=payload):
                with self.assertRaises((TypeError, ValueError)):
                    parser(payload)

        duplicate = (
            '{"queue_id":"one","queue_id":"two",'
            + ",".join(
                json.dumps(key) + ":" + json.dumps(value)
                for key, value in ipc_payload.items()
                if key != "queue_id"
            )
            + "}"
        )
        with self.assertRaises((TypeError, ValueError)):
            parse_decision_ipc_checkpoint(duplicate)


if __name__ == "__main__":
    unittest.main()
