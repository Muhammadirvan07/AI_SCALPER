from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from live_runtime.signed_release_trust import (
    HMAC_RELEASE_TRUST_PRODUCTION_READY,
    PRODUCTION_RELEASE_TRUST_REQUIREMENT,
    RELEASE_TRUST_PROFILE,
    SIGNED_RELEASE_TRUST_ENABLED,
    ZERO_SHA256,
    ReleaseTrustBinding,
    ReleaseTrustError,
    ReleaseTrustPolicy,
    SignedReleaseTrustVerifier,
    decode_signed_release_trust_receipt,
    deployment_alias_sha256,
    issue_release_trust_custody_commit,
    issue_signed_release_trust_receipt,
    release_trust_key_fingerprint,
    release_trust_nonce_sha256,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 23, 1, 0, tzinfo=UTC)
ISSUER_KEY = b"independent-release-authority-key-0000000001"
CUSTODY_KEY = b"independent-offhost-custody-key-0000000002"
ATTACKER_KEY = b"release-local-self-asserted-key-00000000003"


class IndependentCustody:
    """Test double for a nonce registry and signed external compare-and-swap."""

    def __init__(self, policy: ReleaseTrustPolicy) -> None:
        self.policy = policy
        self.head = None
        self.read_override = None
        self.nonces: set[str] = set()
        self.now = NOW

    def provider(self):
        return self.read_override if self.read_override is not None else self.head

    def nonce_seen(self, nonce_sha256):
        return nonce_sha256 in self.nonces

    def cas(self, expected_predecessor, proposal):
        current = self.head.content_sha256 if self.head is not None else ZERO_SHA256
        if expected_predecessor != current:
            raise RuntimeError("custody compare-and-swap rejected")
        if proposal.accepted_nonce_sha256 in self.nonces:
            raise RuntimeError("custody nonce registry rejected replay")
        commit = issue_release_trust_custody_commit(
            proposal,
            policy=self.policy,
            custody_secret=CUSTODY_KEY,
            acknowledged_at=self.now,
        )
        self.nonces.add(proposal.accepted_nonce_sha256)
        self.head = commit.checkpoint
        return commit


class HeadOnlyCASCustody(IndependentCustody):
    """CAS protects only the head; nonce history remains a separate registry."""

    def __init__(self, policy: ReleaseTrustPolicy) -> None:
        super().__init__(policy)
        self.cas_calls = 0

    def cas(self, expected_predecessor, proposal):
        self.cas_calls += 1
        current = self.head.content_sha256 if self.head is not None else ZERO_SHA256
        if expected_predecessor != current:
            raise RuntimeError("custody compare-and-swap rejected")
        commit = issue_release_trust_custody_commit(
            proposal,
            policy=self.policy,
            custody_secret=CUSTODY_KEY,
            acknowledged_at=self.now,
        )
        # Deliberately do not reject duplicates here. The all-history nonce
        # registry is queried independently before and after this head-only CAS.
        self.nonces.add(proposal.accepted_nonce_sha256)
        self.head = commit.checkpoint
        return commit


class SignedReleaseTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = ReleaseTrustPolicy(
            policy_id="windows-release-authority-v1",
            release_profile=RELEASE_TRUST_PROFILE,
            issuer_id="release-review-board",
            issuer_key_id="release-authority-key-v1",
            issuer_key_fingerprint_sha256=release_trust_key_fingerprint(ISSUER_KEY),
            custody_issuer_id="offhost-custody",
            custody_key_id="release-custody-key-v1",
            custody_key_fingerprint_sha256=release_trust_key_fingerprint(CUSTODY_KEY),
            maximum_ttl_seconds=120,
        )
        self.binding = ReleaseTrustBinding(
            release_identity_sha256="1" * 64,
            git_commit="2" * 40,
            git_tree="3" * 40,
            release_profile=RELEASE_TRUST_PROFILE,
            deployment_host_alias_sha256=deployment_alias_sha256("win-vps-canary-01"),
            service_account_alias_sha256=deployment_alias_sha256(
                "svc-ai-scalper-demo"
            ),
        )
        self.custody = IndependentCustody(self.policy)
        self.verifier = self._verifier()

    def _verifier(self, **changes):
        values = {
            "policy": self.policy,
            "expected_policy_sha256": self.policy.content_sha256,
            "issuer_key_provider": lambda key_id: (
                ISSUER_KEY if key_id == self.policy.issuer_key_id else None
            ),
            "custody_key_provider": lambda key_id: (
                CUSTODY_KEY if key_id == self.policy.custody_key_id else None
            ),
            "external_checkpoint_provider": self.custody.provider,
            "external_checkpoint_cas": self.custody.cas,
            "external_nonce_seen_provider": self.custody.nonce_seen,
            "clock_provider": lambda: NOW,
        }
        values.update(changes)
        return SignedReleaseTrustVerifier(**values)

    def _receipt(
        self,
        *,
        binding=None,
        policy=None,
        sequence=1,
        predecessor=ZERO_SHA256,
        nonce="release-authority-nonce-00000001",
        issued=NOW - timedelta(seconds=5),
        not_before=NOW - timedelta(seconds=4),
        expires=NOW + timedelta(seconds=55),
        key=ISSUER_KEY,
    ):
        return issue_signed_release_trust_receipt(
            binding=binding or self.binding,
            policy=policy or self.policy,
            sequence=sequence,
            predecessor_checkpoint_sha256=predecessor,
            nonce=nonce,
            issued_at=issued,
            not_before=not_before,
            expires_at=expires,
            issuer_secret=key,
        )

    def test_exact_receipt_is_consumed_once_without_arming_execution(self):
        self.assertFalse(SIGNED_RELEASE_TRUST_ENABLED)
        self.assertFalse(HMAC_RELEASE_TRUST_PRODUCTION_READY)
        self.assertIn("ASYMMETRIC", PRODUCTION_RELEASE_TRUST_REQUIREMENT)
        receipt = self._receipt()
        verified = self.verifier.verify_and_consume(receipt, expected_binding=self.binding)
        self.assertTrue(verified.release_trust_verified)
        self.assertFalse(verified.execution_authority_granted)
        self.assertFalse(verified.stage_authority_granted)
        self.assertFalse(verified.safe_to_demo_auto_order)
        self.assertFalse(verified.live_allowed)
        self.assertFalse(verified.promotion_eligible)
        self.assertEqual(verified.max_lot, 0.01)
        self.assertEqual(verified.sequence, 1)
        self.assertEqual(verified.binding, self.binding)
        self.assertEqual(verified.nonce_sha256, receipt.nonce_sha256)
        self.assertEqual(verified.expires_at_utc, receipt.expires_at_utc)
        self.assertEqual(verified.verified_at_utc, NOW)
        self.assertEqual(verified.custody_checkpoint_sha256, self.custody.head.content_sha256)
        self.assertTrue(
            verified.validate_freshness(
                checked_at=NOW + timedelta(seconds=30),
                expected_binding=self.binding,
                expected_nonce_sha256=receipt.nonce_sha256,
            )
        )
        with self.assertRaisesRegex(
            ReleaseTrustError, "VERIFIED_RELEASE_TRUST_EXPIRED"
        ):
            verified.validate_freshness(
                checked_at=receipt.expires_at_utc,
                expected_binding=self.binding,
                expected_nonce_sha256=receipt.nonce_sha256,
            )
        with self.assertRaisesRegex(
            ReleaseTrustError, "VERIFIED_RELEASE_NONCE_MISMATCH"
        ):
            verified.validate_freshness(
                checked_at=NOW + timedelta(seconds=1),
                expected_binding=self.binding,
                expected_nonce_sha256=release_trust_nonce_sha256(
                    "different-verified-nonce-0001"
                ),
            )

    def test_external_receipt_decoder_requires_exact_canonical_schema(self):
        receipt = self._receipt()
        decoded = decode_signed_release_trust_receipt(receipt.canonical_json())
        self.assertEqual(decoded, receipt)
        noncanonical = receipt.canonical_json().replace(",", ", ", 1)
        with self.assertRaisesRegex(ReleaseTrustError, "RECEIPT_JSON_NOT_CANONICAL"):
            decode_signed_release_trust_receipt(noncanonical)
        duplicate = receipt.canonical_json().replace(
            '{"binding":', '{"binding":null,"binding":', 1
        )
        with self.assertRaisesRegex(ReleaseTrustError, "RECEIPT_JSON_DUPLICATE_KEY"):
            decode_signed_release_trust_receipt(duplicate)

    def test_tamper_and_wrong_independent_key_fail_closed(self):
        receipt = self._receipt()
        object.__setattr__(receipt, "signature_hmac_sha256", "f" * 64)
        with self.assertRaisesRegex(ReleaseTrustError, "RECEIPT_SIGNATURE_INVALID"):
            self.verifier.verify_and_consume(receipt, expected_binding=self.binding)
        wrong_provider = self._verifier(
            issuer_key_provider=lambda _key_id: ATTACKER_KEY
        )
        with self.assertRaisesRegex(ReleaseTrustError, "ISSUER_KEY_FINGERPRINT_MISMATCH"):
            wrong_provider.verify_and_consume(
                self._receipt(nonce="release-authority-nonce-00000002"),
                expected_binding=self.binding,
            )

    def test_expired_future_and_not_yet_valid_receipts_are_rejected(self):
        cases = (
            (
                self._receipt(
                    nonce="expired-release-nonce-00001",
                    issued=NOW - timedelta(minutes=1),
                    not_before=NOW - timedelta(minutes=1),
                    expires=NOW - timedelta(seconds=1),
                ),
                "RECEIPT_EXPIRED",
            ),
            (
                self._receipt(
                    nonce="future-issued-release-nonce-01",
                    issued=NOW + timedelta(seconds=1),
                    not_before=NOW + timedelta(seconds=1),
                    expires=NOW + timedelta(seconds=31),
                ),
                "RECEIPT_ISSUED_IN_FUTURE",
            ),
            (
                self._receipt(
                    nonce="not-before-release-nonce-001",
                    issued=NOW - timedelta(seconds=1),
                    not_before=NOW + timedelta(seconds=1),
                    expires=NOW + timedelta(seconds=31),
                ),
                "RECEIPT_NOT_YET_VALID",
            ),
        )
        for receipt, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(ReleaseTrustError, reason):
                    self.verifier.verify_and_consume(
                        receipt, expected_binding=self.binding
                    )

    def test_release_git_host_and_account_mismatches_are_rejected(self):
        mismatches = (
            replace(self.binding, release_identity_sha256="4" * 64),
            replace(self.binding, git_commit="5" * 40),
            replace(self.binding, git_tree="6" * 40),
            replace(
                self.binding,
                deployment_host_alias_sha256=deployment_alias_sha256("other-host"),
            ),
            replace(
                self.binding,
                service_account_alias_sha256=deployment_alias_sha256("other-account"),
            ),
        )
        receipt = self._receipt()
        for expected in mismatches:
            with self.subTest(expected=expected.content_sha256):
                with self.assertRaisesRegex(
                    ReleaseTrustError, "RELEASE_BINDING_MISMATCH"
                ):
                    self.verifier.verify_and_consume(
                        receipt, expected_binding=expected
                    )

    def test_self_asserted_policy_and_key_are_not_trusted(self):
        attacker_policy = replace(
            self.policy,
            policy_id="release-local-policy",
            issuer_id="release-itself",
            issuer_key_id="release-local-key",
            issuer_key_fingerprint_sha256=release_trust_key_fingerprint(ATTACKER_KEY),
        )
        receipt = self._receipt(
            policy=attacker_policy,
            key=ATTACKER_KEY,
            nonce="self-asserted-release-nonce-01",
        )
        with self.assertRaisesRegex(
            ReleaseTrustError, "SELF_ASSERTED_OR_UNTRUSTED_ISSUER"
        ):
            self.verifier.verify_and_consume(receipt, expected_binding=self.binding)
        with self.assertRaisesRegex(ReleaseTrustError, "EXTERNAL_POLICY_PIN_MISMATCH"):
            SignedReleaseTrustVerifier(
                policy=attacker_policy,
                expected_policy_sha256=self.policy.content_sha256,
                issuer_key_provider=lambda _key_id: ATTACKER_KEY,
                custody_key_provider=lambda _key_id: CUSTODY_KEY,
                external_checkpoint_provider=self.custody.provider,
                external_checkpoint_cas=self.custody.cas,
                external_nonce_seen_provider=self.custody.nonce_seen,
                clock_provider=lambda: NOW,
            )

    def test_replay_fork_rollback_and_historical_nonce_reuse_are_rejected(self):
        first = self._receipt()
        self.verifier.verify_and_consume(first, expected_binding=self.binding)
        first_checkpoint = self.custody.head
        with self.assertRaisesRegex(
            ReleaseTrustError, "RECEIPT_NONCE_REPLAY|RECEIPT_REPLAY_ROLLBACK_OR_FORK"
        ):
            self.verifier.verify_and_consume(first, expected_binding=self.binding)

        second = self._receipt(
            sequence=2,
            predecessor=first_checkpoint.content_sha256,
            nonce="release-authority-nonce-00000002",
        )
        self.verifier.verify_and_consume(second, expected_binding=self.binding)
        second_checkpoint = self.custody.head

        fork = self._receipt(
            sequence=2,
            predecessor=first_checkpoint.content_sha256,
            nonce="release-authority-fork-nonce-0001",
        )
        with self.assertRaisesRegex(
            ReleaseTrustError, "RECEIPT_REPLAY_ROLLBACK_OR_FORK"
        ):
            self.verifier.verify_and_consume(fork, expected_binding=self.binding)

        self.custody.read_override = first_checkpoint
        rollback_target = self._receipt(
            sequence=3,
            predecessor=second_checkpoint.content_sha256,
            nonce="release-authority-rollback-nonce-01",
        )
        with self.assertRaisesRegex(
            ReleaseTrustError, "RECEIPT_REPLAY_ROLLBACK_OR_FORK"
        ):
            self.verifier.verify_and_consume(
                rollback_target, expected_binding=self.binding
            )
        self.custody.read_override = None

        historical_nonce = self._receipt(
            sequence=3,
            predecessor=second_checkpoint.content_sha256,
            nonce="release-authority-nonce-00000001",
        )
        with self.assertRaisesRegex(
            ReleaseTrustError, "RECEIPT_NONCE_REPLAY"
        ):
            self.verifier.verify_and_consume(
                historical_nonce, expected_binding=self.binding
            )

    def test_head_only_cas_cannot_accept_sequence_three_historical_nonce(self):
        self.custody = HeadOnlyCASCustody(self.policy)
        verifier = self._verifier()
        first = self._receipt(nonce="head-only-sequence-one-nonce-01")
        verifier.verify_and_consume(first, expected_binding=self.binding)
        first_head = self.custody.head
        second = self._receipt(
            sequence=2,
            predecessor=first_head.content_sha256,
            nonce="head-only-sequence-two-nonce-02",
        )
        verifier.verify_and_consume(second, expected_binding=self.binding)
        second_head = self.custody.head
        replay = self._receipt(
            sequence=3,
            predecessor=second_head.content_sha256,
            nonce="head-only-sequence-one-nonce-01",
        )
        with self.assertRaisesRegex(ReleaseTrustError, "RECEIPT_NONCE_REPLAY"):
            verifier.verify_and_consume(replay, expected_binding=self.binding)
        self.assertEqual(self.custody.cas_calls, 2)

    def test_slow_custody_expiry_and_clock_regression_fail_after_readback(self):
        slow_clock = iter((NOW, NOW + timedelta(seconds=56)))
        verifier = self._verifier(clock_provider=lambda: next(slow_clock))
        receipt = self._receipt()
        with self.assertRaisesRegex(
            ReleaseTrustError, "RECEIPT_EXPIRED_DURING_CUSTODY"
        ):
            verifier.verify_and_consume(receipt, expected_binding=self.binding)
        self.assertTrue(self.custody.nonce_seen(receipt.nonce_sha256))

        self.custody = IndependentCustody(self.policy)
        regressing_clock = iter((NOW, NOW - timedelta(microseconds=1)))
        verifier = self._verifier(clock_provider=lambda: next(regressing_clock))
        with self.assertRaisesRegex(
            ReleaseTrustError, "TRUSTED_CLOCK_REGRESSION_DURING_CUSTODY"
        ):
            verifier.verify_and_consume(
                self._receipt(nonce="regressing-clock-release-nonce-01"),
                expected_binding=self.binding,
            )

    def test_external_nonce_registry_is_mandatory_and_read_back(self):
        verifier = self._verifier(external_nonce_seen_provider=lambda _nonce: False)
        with self.assertRaisesRegex(
            ReleaseTrustError, "EXTERNAL_NONCE_RESERVATION_READBACK_MISSING"
        ):
            verifier.verify_and_consume(
                self._receipt(nonce="nonce-readback-missing-000001"),
                expected_binding=self.binding,
            )
        self.custody = IndependentCustody(self.policy)
        verifier = self._verifier(
            external_nonce_seen_provider=lambda _nonce: "false"
        )
        with self.assertRaisesRegex(
            ReleaseTrustError, "EXTERNAL_NONCE_REGISTRY_RESULT_INVALID"
        ):
            verifier.verify_and_consume(
                self._receipt(nonce="nonce-registry-type-invalid-001"),
                expected_binding=self.binding,
            )
        with self.assertRaises(TypeError):
            self._verifier(external_nonce_seen_provider=None)

    def test_custody_write_readback_and_ack_tamper_fail_closed(self):
        receipt = self._receipt()

        def no_readback(expected, proposal):
            return issue_release_trust_custody_commit(
                proposal,
                policy=self.policy,
                custody_secret=CUSTODY_KEY,
                acknowledged_at=NOW,
            )

        verifier = self._verifier(external_checkpoint_cas=no_readback)
        with self.assertRaisesRegex(
            ReleaseTrustError, "EXTERNAL_CHECKPOINT_READBACK_MISMATCH"
        ):
            verifier.verify_and_consume(receipt, expected_binding=self.binding)

        def tampered_ack(expected, proposal):
            commit = self.custody.cas(expected, proposal)
            object.__setattr__(
                commit.acknowledgement, "signature_hmac_sha256", "f" * 64
            )
            return commit

        verifier = self._verifier(external_checkpoint_cas=tampered_ack)
        with self.assertRaisesRegex(
            ReleaseTrustError, "EXTERNAL_CHECKPOINT_ACK_SIGNATURE_INVALID"
        ):
            verifier.verify_and_consume(
                self._receipt(nonce="tampered-custody-ack-nonce-001"),
                expected_binding=self.binding,
            )


if __name__ == "__main__":
    unittest.main()
