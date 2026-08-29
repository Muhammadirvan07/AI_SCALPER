from __future__ import annotations

from datetime import timedelta
import unittest

from finex_stage_human_approval import (
    FinexStageHumanApprovalError,
    sign_reviewed_stage_request,
)
from live_runtime.stage_authorization import (
    human_approval_attestation_from_mapping,
    stage_readiness_request_from_mapping,
)
from test_live_runtime_stage_authorization import StageAuthorizationTestCase


class FinexStageHumanApprovalTests(StageAuthorizationTestCase):
    def test_request_and_approval_round_trip_without_raw_identity(self):
        request = self._request()
        rebuilt_request = stage_readiness_request_from_mapping(
            request.to_canonical_dict()
        )
        self.assertEqual(request, rebuilt_request)
        approval = sign_reviewed_stage_request(
            rebuilt_request,
            expected_request_sha256=request.request_sha256,
            role="RISK_OWNER",
            human_identity="putra-independent-risk-owner",
            signer_key_id="finex-risk-owner-audusd-v1",
            signing_secret=b"finex-risk-owner-test-secret-material-32-bytes",
            approved_at=self.t0 + timedelta(seconds=1),
            approval_nonce="finex-risk-owner-audusd-review-001",
        )
        rebuilt = human_approval_attestation_from_mapping(
            approval.to_canonical_dict()
        )
        self.assertEqual(approval, rebuilt)
        self.assertTrue(
            rebuilt.verify_signature(
                b"finex-risk-owner-test-secret-material-32-bytes"
            )
        )
        self.assertNotIn("putra-independent-risk-owner", rebuilt.canonical_json())
        self.assertFalse(rebuilt.safe_to_demo_auto_order)

    def test_out_of_band_hash_mismatch_blocks_signing(self):
        with self.assertRaisesRegex(
            FinexStageHumanApprovalError, "out-of-band"
        ):
            sign_reviewed_stage_request(
                self._request(),
                expected_request_sha256="f" * 64,
                role="OPERATIONS_OWNER",
                human_identity="operator",
                signer_key_id="finex-ops-owner-audusd-v1",
                signing_secret=b"finex-ops-owner-test-secret-material-32-bytes",
                approved_at=self.t0 + timedelta(seconds=1),
                approval_nonce="finex-ops-owner-audusd-review-001",
            )


if __name__ == "__main__":
    unittest.main()
