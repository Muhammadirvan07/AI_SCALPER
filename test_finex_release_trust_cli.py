from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from finex_release_trust import issue_from_reviewed_request
from live_runtime.release_trust_custody import ReleaseTrustCustodyStore
from live_runtime.signed_release_trust import (
    RELEASE_TRUST_PROFILE,
    ReleaseTrustBinding,
    ReleaseTrustPolicy,
    SignedReleaseTrustVerifier,
    release_trust_key_fingerprint,
)


NOW = datetime(2026, 8, 28, 14, 0, tzinfo=timezone.utc)
ISSUER_KEY = b"finex-release-trust-cli-issuer-key-0001"
CUSTODY_KEY = b"finex-release-trust-cli-custody-key-002"


def _policy():
    return ReleaseTrustPolicy(
        policy_id="finex-release-trust-v1",
        release_profile=RELEASE_TRUST_PROFILE,
        issuer_id="finex-release-board",
        issuer_key_id="finex-release-issuer-v1",
        issuer_key_fingerprint_sha256=release_trust_key_fingerprint(ISSUER_KEY),
        custody_issuer_id="finex-release-custody",
        custody_key_id="finex-release-custody-v1",
        custody_key_fingerprint_sha256=release_trust_key_fingerprint(CUSTODY_KEY),
        maximum_ttl_seconds=120,
    )


def _binding():
    return ReleaseTrustBinding(
        release_identity_sha256="1" * 64,
        git_commit="2" * 40,
        git_tree="3" * 40,
        release_profile=RELEASE_TRUST_PROFILE,
        deployment_host_alias_sha256="4" * 64,
        service_account_alias_sha256="5" * 64,
    )


def _request(policy, binding, nonce, at):
    return {
        "policy": policy.to_canonical_dict(),
        "binding": binding.to_canonical_dict(),
        "nonce": nonce,
        "issued_at_utc": (at - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "not_before_utc": (at - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "expires_at_utc": (at + timedelta(seconds=60)).isoformat().replace("+00:00", "Z"),
    }


class FinexReleaseTrustCLITests(unittest.TestCase):
    def test_sequence_is_derived_from_authenticated_custody_head(self):
        policy, binding = _policy(), _binding()
        keys = {policy.issuer_key_id: ISSUER_KEY, policy.custody_key_id: CUSTODY_KEY}
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "custody.sqlite3"
            first = issue_from_reviewed_request(
                _request(policy, binding, "release-nonce-000000000001", NOW),
                expected_policy_sha256=policy.content_sha256,
                expected_binding_sha256=binding.content_sha256,
                custody_database=database,
                key_provider=keys.__getitem__,
                now=NOW,
            )
            self.assertEqual(1, first.sequence)
            with ReleaseTrustCustodyStore(
                database,
                policy=policy,
                custody_key_provider=keys.__getitem__,
                clock_provider=lambda: NOW,
            ) as custody:
                SignedReleaseTrustVerifier(
                    policy=policy,
                    expected_policy_sha256=policy.content_sha256,
                    issuer_key_provider=keys.__getitem__,
                    custody_key_provider=keys.__getitem__,
                    external_checkpoint_provider=custody.checkpoint_provider,
                    external_checkpoint_cas=custody.compare_and_swap,
                    external_nonce_seen_provider=custody.nonce_seen,
                    clock_provider=lambda: NOW,
                ).verify_and_consume(first, expected_binding=binding)
                head = custody.checkpoint_provider()
            second = issue_from_reviewed_request(
                _request(policy, binding, "release-nonce-000000000002", NOW),
                expected_policy_sha256=policy.content_sha256,
                expected_binding_sha256=binding.content_sha256,
                custody_database=database,
                key_provider=keys.__getitem__,
                now=NOW,
            )
            self.assertEqual(2, second.sequence)
            self.assertEqual(head.content_sha256, second.predecessor_checkpoint_sha256)
            self.assertFalse(second.execution_authority_granted)

    def test_external_binding_pin_is_mandatory(self):
        policy, binding = _policy(), _binding()
        keys = {policy.issuer_key_id: ISSUER_KEY, policy.custody_key_id: CUSTODY_KEY}
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(Exception, "EXTERNAL_BINDING_MISMATCH"):
                issue_from_reviewed_request(
                    _request(policy, binding, "release-nonce-000000000003", NOW),
                    expected_policy_sha256=policy.content_sha256,
                    expected_binding_sha256="0" * 64,
                    custody_database=Path(directory) / "custody.sqlite3",
                    key_provider=keys.__getitem__,
                    now=NOW,
                )


if __name__ == "__main__":
    unittest.main()
