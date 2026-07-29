from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

import execution_policy
from build_windows_execution_release import (
    REQUIRED_LIVE_CANARY_PROVIDER_BOUND_RUNTIME_CLOSURE,
)
from live_runtime.asymmetric_release_trust import (
    SIGNATURE_ALGORITHM,
    rsa_public_key_fingerprint_sha256,
)
from live_runtime.live_canary_provider_bound_runtime_session import (
    LiveCanaryProviderBoundRuntimeLaunchSession,
    is_live_canary_provider_bound_runtime_launch_session,
)
from live_runtime.live_canary_provider_bound_runtime_session_handoff import (
    HANDOFF_DOCUMENT_SCHEMA,
    HANDOFF_POLICY_SCHEMA,
    REPLAY_RECEIPT_SCHEMA,
    LiveCanaryProviderBoundRuntimeSessionHandoffError,
    decode_live_canary_provider_bound_runtime_session_handoff_policy,
    load_live_canary_provider_bound_runtime_session_handoff,
    provider_bound_runtime_session_consumption_receipt_signing_message,
    provider_bound_runtime_session_handoff_signing_message,
)
from live_runtime.live_canary_runtime_candidate import (
    LiveCanaryRuntimeCandidate,
)
import test_live_runtime_live_canary_portable_launch_custody as rsa_support
import test_live_runtime_live_canary_provider_bound_runtime_launch_session as session_support


UTC = timezone.utc
REPO_ROOT = Path(__file__).resolve().parent
HANDOFF_CONSUMER = (
    "live_runtime/"
    "live_canary_provider_bound_runtime_session_handoff.py"
)
HANDOFF_N = rsa_support.LAUNCHER_N
HANDOFF_D = rsa_support.LAUNCHER_D
REPLAY_N = rsa_support.CUSTODY_N
REPLAY_D = rsa_support.CUSTODY_D
HANDOFF_FINGERPRINT = rsa_public_key_fingerprint_sha256(HANDOFF_N, 65537)
REPLAY_FINGERPRINT = rsa_public_key_fingerprint_sha256(REPLAY_N, 65537)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def canonical_document(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def canonical_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def rsa_sign(message: bytes, *, modulus_hex: str, private_hex: str) -> str:
    return rsa_support.rsa_sign(
        message,
        modulus_hex=modulus_hex,
        private_hex=private_hex,
    )


class SignedReplayLedger:
    def __init__(self) -> None:
        self.calls = 0
        self.requests: list[dict[str, object]] = []
        self.seen_handoffs: set[str] = set()
        self.cached_receipt: bytes | None = None
        self.replay_cached_receipt = False

    def __call__(self, request_payload: bytes) -> bytes:
        self.calls += 1
        request = json.loads(request_payload)
        self.requests.append(request)
        if self.replay_cached_receipt and self.cached_receipt is not None:
            return self.cached_receipt
        handoff_sha256 = str(request["handoff_sha256"])
        if handoff_sha256 in self.seen_handoffs:
            raise RuntimeError("private atomic replay conflict detail")
        self.seen_handoffs.add(handoff_sha256)
        requested = datetime.fromisoformat(
            str(request["requested_at_utc"])[:-1] + "+00:00"
        )
        receipt: dict[str, object] = {
            "schema_version": REPLAY_RECEIPT_SCHEMA,
            "consumption_id": f"consume-{self.calls}",
            "consumption_sequence": self.calls,
            "request_sha256": hashlib.sha256(request_payload).hexdigest(),
            "handoff_id": request["handoff_id"],
            "handoff_policy_sha256": request["handoff_policy_sha256"],
            "handoff_sha256": request["handoff_sha256"],
            "candidate_sha256": request["candidate_sha256"],
            "session_sha256": request["session_sha256"],
            "handoff_nonce_sha256": request["handoff_nonce_sha256"],
            "challenge_sha256": request["challenge_sha256"],
            "replay_ledger_alias_sha256": request[
                "replay_ledger_alias_sha256"
            ],
            "execution_release_identity_sha256": request[
                "execution_release_identity_sha256"
            ],
            "target_host_identity_sha256": request[
                "target_host_identity_sha256"
            ],
            "installed_environment_sha256": request[
                "installed_environment_sha256"
            ],
            "deployment_host_alias_sha256": request[
                "deployment_host_alias_sha256"
            ],
            "service_account_alias_sha256": request[
                "service_account_alias_sha256"
            ],
            "launcher_task_definition_sha256": request[
                "launcher_task_definition_sha256"
            ],
            "live_execution_task_definition_sha256": request[
                "live_execution_task_definition_sha256"
            ],
            "consumed_at_utc": canonical_utc(
                requested + timedelta(milliseconds=250)
            ),
            "expires_at_utc": request["expires_at_utc"],
            "replay_issuer_id": "runtime-session-replay-ledger",
            "replay_key_id": "runtime-session-replay-rsa-v1",
            "replay_public_key_fingerprint_sha256": REPLAY_FINGERPRINT,
            "consumed_once": True,
            "central_unlock_required": True,
            "session_reconstruction_authorized": True,
            "direct_execution_authorized": False,
            "broker_mutation_authorized": False,
            "order_capability": "GATED_PRESENT",
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "signature_rsa_pkcs1v15_sha256_hex": "",
        }
        unsigned = canonical_document(receipt)
        receipt["signature_rsa_pkcs1v15_sha256_hex"] = rsa_sign(
            provider_bound_runtime_session_consumption_receipt_signing_message(
                unsigned
            ),
            modulus_hex=REPLAY_N,
            private_hex=REPLAY_D,
        )
        self.cached_receipt = canonical_document(receipt)
        return self.cached_receipt


class WindowsLiveCanaryProviderBoundRuntimeSessionHandoffTests(
    unittest.TestCase
):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        fixture_type = (
            session_support.LiveCanaryProviderBoundRuntimeLaunchSessionTests
        )
        fixture_type.setUpClass()
        fixture = fixture_type(methodName="runTest")
        fixture.setUp()
        cls.fixture = fixture
        cls.candidate: LiveCanaryRuntimeCandidate = fixture.candidate
        cls.session: LiveCanaryProviderBoundRuntimeLaunchSession = (
            fixture._activate()
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture.doCleanups()
        session_support.LiveCanaryProviderBoundRuntimeLaunchSessionTests.tearDownClass()
        super().tearDownClass()

    def setUp(self) -> None:
        self.policy = self._policy()
        self.policy_payload = canonical_document(self.policy)
        self.policy_sha256 = hashlib.sha256(self.policy_payload).hexdigest()
        self.handoff = self._handoff()
        self.handoff_payload = self._signed_handoff(self.handoff)
        self.handoff_sha256 = hashlib.sha256(
            self.handoff_payload
        ).hexdigest()
        self.ledger = SignedReplayLedger()

    def _policy(self) -> dict[str, object]:
        reserved_ids = sorted(
            set(self.candidate.runtime_key_ids)
            | {"launcher-rsa-v1", "custody-rsa-v1"}
        )
        reserved_fingerprints = sorted(
            set(self.candidate.runtime_key_fingerprints)
            | {digest("launcher-fingerprint"), digest("custody-fingerprint")}
        )
        self.assertNotIn("runtime-session-handoff-rsa-v1", reserved_ids)
        self.assertNotIn("runtime-session-replay-rsa-v1", reserved_ids)
        self.assertNotIn(HANDOFF_FINGERPRINT, reserved_fingerprints)
        self.assertNotIn(REPLAY_FINGERPRINT, reserved_fingerprints)
        return {
            "schema_version": HANDOFF_POLICY_SCHEMA,
            "policy_id": "provider-bound-runtime-session-handoff-policy-v1",
            "handoff_issuer_id": "runtime-session-handoff-authority",
            "handoff_key_id": "runtime-session-handoff-rsa-v1",
            "handoff_rsa_modulus_hex": HANDOFF_N,
            "handoff_rsa_exponent": 65537,
            "handoff_public_key_fingerprint_sha256": HANDOFF_FINGERPRINT,
            "replay_issuer_id": "runtime-session-replay-ledger",
            "replay_key_id": "runtime-session-replay-rsa-v1",
            "replay_rsa_modulus_hex": REPLAY_N,
            "replay_rsa_exponent": 65537,
            "replay_public_key_fingerprint_sha256": REPLAY_FINGERPRINT,
            "replay_ledger_alias_sha256": digest("runtime-replay-ledger"),
            "execution_release_identity_sha256": (
                self.session.live_execution_release_identity_sha256
            ),
            "target_host_identity_sha256": (
                self.session.target_host_identity_sha256
            ),
            "installed_environment_sha256": (
                self.session.installed_environment_sha256
            ),
            "deployment_host_alias_sha256": (
                self.session.deployment_host_alias_sha256
            ),
            "service_account_alias_sha256": (
                self.session.service_account_alias_sha256
            ),
            "launcher_task_definition_sha256": (
                self.session.task_definition_sha256
            ),
            "live_execution_task_definition_sha256": (
                self.session.live_execution_task_definition_sha256
            ),
            "reserved_authority_key_ids": reserved_ids,
            "reserved_authority_fingerprints_sha256": reserved_fingerprints,
            "maximum_handoff_ttl_seconds": 60,
            "maximum_replay_request_ttl_seconds": 3,
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "central_unlock_required": True,
            "session_reconstruction_authorized": True,
            "direct_execution_authorized": False,
            "broker_mutation_authorized": False,
            "order_capability": "GATED_PRESENT",
        }

    def _handoff(self) -> dict[str, object]:
        return {
            "schema_version": HANDOFF_DOCUMENT_SCHEMA,
            "handoff_id": "provider-bound-runtime-session-handoff-1",
            "handoff_policy_sha256": self.policy_sha256,
            "candidate_sha256": self.candidate.content_sha256,
            "session_sha256": self.session.content_sha256,
            "session": self.session.to_canonical_dict(),
            "handoff_nonce_sha256": digest("runtime-handoff-nonce-1"),
            "issued_at_utc": canonical_utc(self.session.activated_at_utc),
            "not_before_utc": canonical_utc(self.session.activated_at_utc),
            "expires_at_utc": canonical_utc(self.session.valid_until_utc),
            "execution_release_identity_sha256": (
                self.session.live_execution_release_identity_sha256
            ),
            "target_host_identity_sha256": (
                self.session.target_host_identity_sha256
            ),
            "installed_environment_sha256": (
                self.session.installed_environment_sha256
            ),
            "deployment_host_alias_sha256": (
                self.session.deployment_host_alias_sha256
            ),
            "service_account_alias_sha256": (
                self.session.service_account_alias_sha256
            ),
            "launcher_task_definition_sha256": (
                self.session.task_definition_sha256
            ),
            "live_execution_task_definition_sha256": (
                self.session.live_execution_task_definition_sha256
            ),
            "handoff_issuer_id": "runtime-session-handoff-authority",
            "handoff_key_id": "runtime-session-handoff-rsa-v1",
            "handoff_public_key_fingerprint_sha256": HANDOFF_FINGERPRINT,
            "central_unlock_required": True,
            "session_reconstruction_authorized": True,
            "direct_execution_authorized": False,
            "broker_mutation_authorized": False,
            "order_capability": "GATED_PRESENT",
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "signature_rsa_pkcs1v15_sha256_hex": "",
        }

    def _signed_handoff(self, value: dict[str, object]) -> bytes:
        unsigned = canonical_document(value)
        signed = dict(value)
        signed["signature_rsa_pkcs1v15_sha256_hex"] = rsa_sign(
            provider_bound_runtime_session_handoff_signing_message(unsigned),
            modulus_hex=HANDOFF_N,
            private_hex=HANDOFF_D,
        )
        return canonical_document(signed)

    def _clock(self):
        return iter(
            (
                self.session.activated_at_utc + timedelta(seconds=1),
                self.session.activated_at_utc + timedelta(seconds=2),
                self.session.activated_at_utc + timedelta(seconds=3),
            )
        ).__next__

    def _kwargs(self) -> dict[str, object]:
        return {
            "policy_payload": self.policy_payload,
            "handoff_payload": self.handoff_payload,
            "candidate": self.candidate,
            "expected_policy_sha256": self.policy_sha256,
            "expected_handoff_sha256": self.handoff_sha256,
            "expected_candidate_sha256": self.candidate.content_sha256,
            "expected_session_sha256": self.session.content_sha256,
            "expected_handoff_nonce_sha256": self.handoff[
                "handoff_nonce_sha256"
            ],
            "expected_execution_release_identity_sha256": (
                self.session.live_execution_release_identity_sha256
            ),
            "expected_target_host_identity_sha256": (
                self.session.target_host_identity_sha256
            ),
            "expected_installed_environment_sha256": (
                self.session.installed_environment_sha256
            ),
            "expected_deployment_host_alias_sha256": (
                self.session.deployment_host_alias_sha256
            ),
            "expected_service_account_alias_sha256": (
                self.session.service_account_alias_sha256
            ),
            "expected_launcher_task_definition_sha256": (
                self.session.task_definition_sha256
            ),
            "expected_live_execution_task_definition_sha256": (
                self.session.live_execution_task_definition_sha256
            ),
            "external_replay_consumer": self.ledger,
            "clock_provider": self._clock(),
        }

    def _load(self, **changes: object):
        values = self._kwargs()
        values.update(changes)
        with (
            mock.patch.object(execution_policy, "LIVE_ALLOWED", True),
            mock.patch(
                "live_runtime.live_canary_provider_bound_runtime_session_handoff.secrets.token_bytes",
                return_value=b"A" * 32,
            ),
        ):
            return load_live_canary_provider_bound_runtime_session_handoff(
                **values
            )

    def test_ac1_policy_and_handoff_are_exact_and_independently_pinned(self) -> None:
        policy = decode_live_canary_provider_bound_runtime_session_handoff_policy(
            self.policy_payload,
            expected_policy_sha256=self.policy_sha256,
        )
        self.assertEqual(self.policy_sha256, policy.content_sha256)
        self.assertEqual(HANDOFF_FINGERPRINT, policy.handoff_public_key_fingerprint_sha256)
        self.assertEqual(REPLAY_FINGERPRINT, policy.replay_public_key_fingerprint_sha256)

        for name, value in {
            "expected_policy_sha256": digest("wrong-policy"),
            "expected_handoff_sha256": digest("wrong-handoff"),
            "expected_candidate_sha256": digest("wrong-candidate"),
            "expected_session_sha256": digest("wrong-session"),
            "expected_target_host_identity_sha256": digest("wrong-host"),
        }.items():
            with self.subTest(name=name), self.assertRaises(
                LiveCanaryProviderBoundRuntimeSessionHandoffError
            ):
                self._load(**{name: value})
        self.assertEqual(0, self.ledger.calls)

        same_authority = dict(self.policy)
        same_authority["replay_key_id"] = same_authority["handoff_key_id"]
        payload = canonical_document(same_authority)
        with self.assertRaises(
            LiveCanaryProviderBoundRuntimeSessionHandoffError
        ):
            decode_live_canary_provider_bound_runtime_session_handoff_policy(
                payload,
                expected_policy_sha256=hashlib.sha256(payload).hexdigest(),
            )

    def test_ac2_fresh_challenge_and_atomic_replay_consumption(self) -> None:
        with mock.patch(
            "live_runtime.live_canary_provider_bound_runtime_session_handoff.secrets.token_bytes",
            side_effect=(b"A" * 32, b"B" * 32),
        ), mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            first = load_live_canary_provider_bound_runtime_session_handoff(
                **self._kwargs()
            )
            self.assertTrue(
                is_live_canary_provider_bound_runtime_launch_session(first)
            )
            with self.assertRaises(
                LiveCanaryProviderBoundRuntimeSessionHandoffError
            ) as caught:
                load_live_canary_provider_bound_runtime_session_handoff(
                    **self._kwargs()
                )
        self.assertEqual(2, self.ledger.calls)
        self.assertNotEqual(
            self.ledger.requests[0]["challenge_sha256"],
            self.ledger.requests[1]["challenge_sha256"],
        )
        self.assertEqual(
            "RUNTIME_SESSION_REPLAY_CONSUMPTION_FAILED",
            caught.exception.reason_code,
        )
        self.assertNotIn("private", str(caught.exception))

    def test_ac2_prior_receipt_cannot_satisfy_a_new_challenge(self) -> None:
        self._load()
        replaying = SignedReplayLedger()
        replaying.cached_receipt = self.ledger.cached_receipt
        replaying.replay_cached_receipt = True
        with mock.patch(
            "live_runtime.live_canary_provider_bound_runtime_session_handoff.secrets.token_bytes",
            return_value=b"B" * 32,
        ), mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            with self.assertRaisesRegex(
                LiveCanaryProviderBoundRuntimeSessionHandoffError,
                "RECEIPT_BINDING_MISMATCH",
            ):
                load_live_canary_provider_bound_runtime_session_handoff(
                    **{
                        **self._kwargs(),
                        "external_replay_consumer": replaying,
                    }
                )

    def test_ac3_exact_sealed_session_round_trip_is_launch_only(self) -> None:
        loaded = self._load()
        self.assertIs(type(loaded), LiveCanaryProviderBoundRuntimeLaunchSession)
        self.assertTrue(
            is_live_canary_provider_bound_runtime_launch_session(loaded)
        )
        self.assertEqual(self.session, loaded)
        self.assertEqual(self.session.canonical_json(), loaded.canonical_json())
        self.assertEqual(self.session.content_sha256, loaded.content_sha256)
        self.assertTrue(loaded.bootstrap_authorized)
        self.assertTrue(loaded.process_launch_authorized)
        self.assertFalse(loaded.execution_authorized)
        self.assertFalse(loaded.broker_mutation_authorized)
        self.assertTrue(loaded.independent_per_order_authorization_required)
        self.assertTrue(loaded.signed_promotion_evidence_required)
        self.assertTrue(loaded.risk_and_news_guards_required)
        self.assertTrue(loaded.durable_journal_lease_required)
        self.assertTrue(loaded.final_mt5_submission_guard_required)

    def test_ac4_central_lock_and_static_failures_precede_replay(self) -> None:
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundRuntimeSessionHandoffError,
            "CENTRAL_LIVE_LOCK_NOT_ENABLED",
        ):
            load_live_canary_provider_bound_runtime_session_handoff(
                **self._kwargs()
            )
        self.assertEqual(0, self.ledger.calls)

        malformed_cases = (
            b"{}",
            b"{}\n\n",
            b"\xff\n",
            self.handoff_payload[:-1] + b" ",
            self.handoff_payload.replace(
                b'"signature_rsa_pkcs1v15_sha256_hex":"',
                b'"signature_rsa_pkcs1v15_sha256_hex":"00',
                1,
            ),
        )
        for payload in malformed_cases:
            with self.subTest(size=len(payload)), self.assertRaises(
                LiveCanaryProviderBoundRuntimeSessionHandoffError
            ):
                self._load(
                    handoff_payload=payload,
                    expected_handoff_sha256=hashlib.sha256(payload).hexdigest(),
                )
        self.assertEqual(0, self.ledger.calls)

        forged = object.__new__(LiveCanaryRuntimeCandidate)
        with self.assertRaises(
            LiveCanaryProviderBoundRuntimeSessionHandoffError
        ):
            self._load(candidate=forged)
        self.assertEqual(0, self.ledger.calls)

    def test_ac5_release_closure_is_minimal_and_operator_producers_absent(self) -> None:
        self.assertIn(
            HANDOFF_CONSUMER,
            REQUIRED_LIVE_CANARY_PROVIDER_BOUND_RUNTIME_CLOSURE,
        )
        allowlist = json.loads(
            (
                REPO_ROOT
                / "config/windows_execution_service_allowlist.v1.json"
            ).read_text(encoding="utf-8")
        )
        self.assertIn(HANDOFF_CONSUMER, allowlist["files"])
        forbidden = {
            "live_runtime/live_canary_provider_bound_runtime_launch_session.py",
            "live_runtime/live_canary_provider_bound_prebootstrap_admission.py",
            "live_runtime/live_canary_provider_bound_portable_custody.py",
            "live_runtime/live_canary_portable_launch_custody.py",
        }
        self.assertTrue(forbidden.isdisjoint(allowlist["files"]))

    def test_ac6_tamper_expiry_randomness_and_callback_fail_closed(self) -> None:
        tampered = dict(self.handoff)
        tampered["session_sha256"] = digest("tampered-session")
        tampered_payload = self._signed_handoff(tampered)
        with self.assertRaises(
            LiveCanaryProviderBoundRuntimeSessionHandoffError
        ):
            self._load(
                handoff_payload=tampered_payload,
                expected_handoff_sha256=hashlib.sha256(
                    tampered_payload
                ).hexdigest(),
            )
        self.assertEqual(0, self.ledger.calls)

        def private_failure(_request: bytes) -> bytes:
            raise RuntimeError("secret replay service response")

        with self.assertRaises(
            LiveCanaryProviderBoundRuntimeSessionHandoffError
        ) as caught:
            self._load(external_replay_consumer=private_failure)
        self.assertEqual(
            "RUNTIME_SESSION_REPLAY_CONSUMPTION_FAILED",
            caught.exception.reason_code,
        )
        self.assertNotIn("secret", str(caught.exception))

        for random_value in (b"short", bytearray(b"A" * 32)):
            with mock.patch.object(
                execution_policy, "LIVE_ALLOWED", True
            ), mock.patch(
                "live_runtime.live_canary_provider_bound_runtime_session_handoff.secrets.token_bytes",
                return_value=random_value,
            ), self.assertRaisesRegex(
                LiveCanaryProviderBoundRuntimeSessionHandoffError,
                "RANDOM_CHALLENGE_INVALID",
            ):
                load_live_canary_provider_bound_runtime_session_handoff(
                    **self._kwargs()
                )

    def test_ac6_signature_window_clock_and_receipt_tamper_fail_closed(
        self,
    ) -> None:
        forged_signature = json.loads(self.handoff_payload)
        signature = forged_signature[
            "signature_rsa_pkcs1v15_sha256_hex"
        ]
        forged_signature["signature_rsa_pkcs1v15_sha256_hex"] = (
            ("0" if signature[0] != "0" else "1") + signature[1:]
        )
        forged_payload = canonical_document(forged_signature)
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundRuntimeSessionHandoffError,
            "HANDOFF_SIGNATURE_INVALID",
        ):
            self._load(
                handoff_payload=forged_payload,
                expected_handoff_sha256=hashlib.sha256(
                    forged_payload
                ).hexdigest(),
            )
        self.assertEqual(0, self.ledger.calls)

        overlong = dict(self.handoff)
        overlong["expires_at_utc"] = canonical_utc(
            self.session.valid_until_utc + timedelta(microseconds=1)
        )
        overlong_payload = self._signed_handoff(overlong)
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundRuntimeSessionHandoffError,
            "RUNTIME_SESSION_HANDOFF_WINDOW_INVALID",
        ):
            self._load(
                handoff_payload=overlong_payload,
                expected_handoff_sha256=hashlib.sha256(
                    overlong_payload
                ).hexdigest(),
            )
        self.assertEqual(0, self.ledger.calls)

        regressing_clock = iter(
            (
                self.session.activated_at_utc + timedelta(seconds=2),
                self.session.activated_at_utc + timedelta(seconds=1),
            )
        ).__next__
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundRuntimeSessionHandoffError,
            "TRUSTED_CLOCK_REGRESSION",
        ):
            self._load(clock_provider=regressing_clock)
        self.assertEqual(0, self.ledger.calls)

        def tampered_receipt(request_payload: bytes) -> bytes:
            payload = json.loads(self.ledger(request_payload))
            payload["signature_rsa_pkcs1v15_sha256_hex"] = (
                "00" + payload["signature_rsa_pkcs1v15_sha256_hex"][2:]
            )
            return canonical_document(payload)

        with self.assertRaisesRegex(
            LiveCanaryProviderBoundRuntimeSessionHandoffError,
            "REPLAY_RECEIPT_SIGNATURE_INVALID",
        ):
            self._load(external_replay_consumer=tampered_receipt)
        self.assertEqual(1, self.ledger.calls)

    def test_ac4_policy_flip_and_nonbytes_replay_never_return_authority(
        self,
    ) -> None:
        clock_calls = 0

        def relocking_clock() -> datetime:
            nonlocal clock_calls
            clock_calls += 1
            execution_policy.LIVE_ALLOWED = False
            return self.session.activated_at_utc + timedelta(seconds=1)

        with self.assertRaisesRegex(
            LiveCanaryProviderBoundRuntimeSessionHandoffError,
            "CENTRAL_LIVE_LOCK_NOT_ENABLED",
        ):
            self._load(clock_provider=relocking_clock)
        self.assertEqual(1, clock_calls)
        self.assertEqual(0, self.ledger.calls)

        with self.assertRaisesRegex(
            LiveCanaryProviderBoundRuntimeSessionHandoffError,
            "REPLAY_RECEIPT_BYTES_INVALID",
        ):
            self._load(
                external_replay_consumer=lambda _request: bytearray(b"x")
            )

    def test_ac7_consumer_source_has_no_private_or_broker_effect_surface(self) -> None:
        source = (REPO_ROOT / HANDOFF_CONSUMER).read_text(encoding="utf-8")
        for forbidden in (
            "private_exponent",
            "MetaTrader5",
            "order_check",
            "order_send",
            "subprocess",
            "requests",
            "sqlite3",
            "win32cred",
            "win32com",
            "Start-ScheduledTask",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
