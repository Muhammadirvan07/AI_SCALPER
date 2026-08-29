from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from live_runtime.release_trust_custody import ReleaseTrustCustodyStore
from live_runtime.signed_release_trust import (
    RELEASE_TRUST_PROFILE,
    ZERO_SHA256,
    ReleaseTrustBinding,
    ReleaseTrustError,
    ReleaseTrustPolicy,
    SignedReleaseTrustVerifier,
    decode_release_trust_checkpoint,
    deployment_alias_sha256,
    issue_signed_release_trust_receipt,
    release_trust_key_fingerprint,
)


NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
ISSUER_KEY = b"release-trust-custody-test-issuer-key-0001"
CUSTODY_KEY = b"release-trust-custody-test-store-key-0002"


class ReleaseTrustCustodyStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = ReleaseTrustPolicy(
            policy_id="finex-release-policy-v1",
            release_profile=RELEASE_TRUST_PROFILE,
            issuer_id="finex-release-review-board",
            issuer_key_id="finex-release-issuer-v1",
            issuer_key_fingerprint_sha256=release_trust_key_fingerprint(ISSUER_KEY),
            custody_issuer_id="finex-independent-custody",
            custody_key_id="finex-release-custody-v1",
            custody_key_fingerprint_sha256=release_trust_key_fingerprint(CUSTODY_KEY),
            maximum_ttl_seconds=120,
        )
        self.binding = ReleaseTrustBinding(
            release_identity_sha256="1" * 64,
            git_commit="2" * 40,
            git_tree="3" * 40,
            release_profile=RELEASE_TRUST_PROFILE,
            deployment_host_alias_sha256=deployment_alias_sha256("finex-demo-host"),
            service_account_alias_sha256=deployment_alias_sha256("finex-demo-service"),
        )

    def _receipt(self, *, sequence=1, predecessor=ZERO_SHA256, nonce="nonce-0000000000000001"):
        return issue_signed_release_trust_receipt(
            binding=self.binding,
            policy=self.policy,
            sequence=sequence,
            predecessor_checkpoint_sha256=predecessor,
            nonce=nonce,
            issued_at=NOW - timedelta(seconds=2),
            not_before=NOW - timedelta(seconds=1),
            expires_at=NOW + timedelta(seconds=60),
            issuer_secret=ISSUER_KEY,
        )

    def _verifier(self, store):
        return SignedReleaseTrustVerifier(
            policy=self.policy,
            expected_policy_sha256=self.policy.content_sha256,
            issuer_key_provider=lambda _: ISSUER_KEY,
            custody_key_provider=lambda _: CUSTODY_KEY,
            external_checkpoint_provider=store.checkpoint_provider,
            external_checkpoint_cas=store.compare_and_swap,
            external_nonce_seen_provider=store.nonce_seen,
            clock_provider=lambda: NOW,
        )

    def test_checkpoint_and_nonce_survive_reopen_and_replay_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release-trust.sqlite3"
            with ReleaseTrustCustodyStore(
                path,
                policy=self.policy,
                custody_key_provider=lambda _: CUSTODY_KEY,
                clock_provider=lambda: NOW,
            ) as store:
                first = self._receipt()
                verified = self._verifier(store).verify_and_consume(
                    first, expected_binding=self.binding
                )
                head_hash = verified.custody_checkpoint_sha256
            with ReleaseTrustCustodyStore(
                path,
                policy=self.policy,
                custody_key_provider=lambda _: CUSTODY_KEY,
                clock_provider=lambda: NOW,
            ) as reopened:
                head = reopened.checkpoint_provider()
                self.assertEqual(head_hash, head.content_sha256)
                self.assertTrue(reopened.nonce_seen(first.nonce_sha256))
                with self.assertRaisesRegex(
                    ReleaseTrustError,
                    "RECEIPT_NONCE_REPLAY|RECEIPT_REPLAY_ROLLBACK_OR_FORK",
                ):
                    self._verifier(reopened).verify_and_consume(
                        first, expected_binding=self.binding
                    )
                second = self._receipt(
                    sequence=2,
                    predecessor=head.content_sha256,
                    nonce="nonce-0000000000000002",
                )
                accepted = self._verifier(reopened).verify_and_consume(
                    second, expected_binding=self.binding
                )
                self.assertEqual(2, accepted.sequence)

    def test_checkpoint_decoder_round_trip_and_store_rejects_row_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            with ReleaseTrustCustodyStore(
                Path(directory) / "release-trust.sqlite3",
                policy=self.policy,
                custody_key_provider=lambda _: CUSTODY_KEY,
                clock_provider=lambda: NOW,
            ) as store:
                self._verifier(store).verify_and_consume(
                    self._receipt(), expected_binding=self.binding
                )
                payload = store.checkpoint_provider().canonical_json()
                self.assertEqual(
                    store.checkpoint_provider(), decode_release_trust_checkpoint(payload)
                )
                with self.assertRaisesRegex(
                    ReleaseTrustError, "CHECKPOINT_JSON_NOT_CANONICAL"
                ):
                    decode_release_trust_checkpoint(payload + "\n")
                store._connection.execute(
                    "UPDATE release_trust_head SET sequence = 2 WHERE singleton = 1"
                )
                with self.assertRaisesRegex(
                    ReleaseTrustError, "CUSTODY_CHECKPOINT_ROW_MISMATCH"
                ):
                    store.checkpoint_provider()


if __name__ == "__main__":
    unittest.main()
