from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from finex_release_reproducibility import (
    FinexReleaseReproducibilityCLIError,
    POLICY_SCHEMA,
    issue_from_reviewed_request,
)
from live_runtime.contracts import canonical_sha256
from live_runtime.release_reproducibility import verify_reproducibility_receipt


NOW = datetime(2026, 8, 28, 13, 0, tzinfo=timezone.utc)
KEY = b"finex-release-reproducibility-test-key-01"


def _observation(build, host):
    return {
        "build_id": build,
        "host_alias_sha256": host,
        "os_name": "WINDOWS",
        "python_version": "3.12.10",
        "clean_checkout": True,
        "git_commit": "1" * 40,
        "git_tree": "2" * 40,
        "archive_sha256": "3" * 64,
        "manifest_sha256": "4" * 64,
        "release_identity_sha256": "5" * 64,
        "observed_at_utc": (NOW - timedelta(seconds=2)).isoformat().replace("+00:00", "Z"),
    }


def _request():
    policy = {
        "schema_version": POLICY_SCHEMA,
        "signer_key_id": "finex-release-reproducibility-v1",
        "first_host_alias_sha256": "a" * 64,
        "second_host_alias_sha256": "b" * 64,
        "git_commit": "1" * 40,
        "git_tree": "2" * 40,
        "archive_sha256": "3" * 64,
        "manifest_sha256": "4" * 64,
        "release_identity_sha256": "5" * 64,
    }
    return {
        "trust_policy": policy,
        "first_observation": _observation("build-a", "a" * 64),
        "second_observation": _observation("build-b", "b" * 64),
        "issued_at_utc": (NOW - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
    }


class FinexReleaseReproducibilityCLITests(unittest.TestCase):
    def test_two_pinned_hosts_issue_deny_only_receipt(self):
        request = _request()
        receipt = issue_from_reviewed_request(
            request,
            expected_trust_policy_sha256=canonical_sha256(request["trust_policy"]),
            key_provider=lambda _: KEY,
            now=NOW,
        )
        self.assertTrue(
            verify_reproducibility_receipt(
                receipt, key_provider=lambda _: KEY, checked_at=NOW
            )
        )
        self.assertNotEqual(
            receipt.first_host_alias_sha256, receipt.second_host_alias_sha256
        )
        self.assertFalse(receipt.safe_to_demo_auto_order)

    def test_same_host_and_self_asserted_policy_fail_closed(self):
        request = _request()
        request["second_observation"]["host_alias_sha256"] = "a" * 64
        request["trust_policy"]["second_host_alias_sha256"] = "a" * 64
        with self.assertRaisesRegex(
            FinexReleaseReproducibilityCLIError,
            "REPRODUCIBILITY_ISSUANCE_FAILED",
        ):
            issue_from_reviewed_request(
                request,
                expected_trust_policy_sha256=canonical_sha256(request["trust_policy"]),
                key_provider=lambda _: KEY,
                now=NOW,
            )
        with self.assertRaisesRegex(
            FinexReleaseReproducibilityCLIError, "EXTERNAL_TRUST_MISMATCH"
        ):
            issue_from_reviewed_request(
                _request(),
                expected_trust_policy_sha256="0" * 64,
                key_provider=lambda _: KEY,
                now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
