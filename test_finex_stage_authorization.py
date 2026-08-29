from __future__ import annotations

from datetime import timedelta
import unittest

from finex_stage_authorization import (
    FinexStageAuthorizationError,
    assemble_reviewed_stage_authorization,
)
from live_runtime.stage_authorization import (
    acceptance_authority_policy_from_mapping,
    manual_demo_aggregate_receipt_from_mapping,
    manual_demo_readiness_receipt_from_mapping,
)
from test_live_runtime_stage_authorization import StageAuthorizationTestCase


class FinexStageAuthorizationTests(StageAuthorizationTestCase):
    def test_exact_persisted_evidence_assembles_deny_only_authorization(self):
        request = self._request()
        approvals = self._approvals(request)
        readiness = manual_demo_readiness_receipt_from_mapping(
            self.readiness.to_canonical_dict()
        )
        aggregate = manual_demo_aggregate_receipt_from_mapping(
            self.manual_aggregate.to_canonical_dict()
        )
        policy = acceptance_authority_policy_from_mapping(
            self.acceptance_policy.to_canonical_dict()
        )
        keys = {
            "manual-readiness-v1": self.manual_readiness_secret,
            "manual-aggregate-v1": self.manual_secret,
            "promotion-v1": self.promotion_secret,
            "approval-risk-v1": self.approver_secrets["approval-risk-v1"],
            "approval-ops-v1": self.approver_secrets["approval-ops-v1"],
            "stage-authority-v1": self.stage_secret,
            **self.acceptance_authority_secrets,
        }
        authorization = assemble_reviewed_stage_authorization(
            request=request,
            expected_request_sha256=request.request_sha256,
            manual_readiness=readiness,
            expected_manual_readiness_key_id="manual-readiness-v1",
            manual_aggregate=aggregate,
            expected_manual_aggregate_key_id="manual-aggregate-v1",
            promotion_receipt=self.promotion,
            expected_promotion_key_id="promotion-v1",
            acceptance_policy=policy,
            expected_acceptance_policy_sha256=policy.policy_sha256,
            approvals=approvals,
            expected_risk_approval_key_id="approval-risk-v1",
            expected_operations_approval_key_id="approval-ops-v1",
            stage_signer_key_id="stage-authority-v1",
            key_provider=keys.__getitem__,
            issued_at=self.t0 + timedelta(minutes=2),
        )
        self.assertTrue(authorization.verify_signature(self.stage_secret))
        self.assertFalse(authorization.execution_authorized)
        self.assertFalse(authorization.activation_authorized)
        self.assertEqual("DISABLED", authorization.order_capability)

    def test_out_of_band_key_mismatch_blocks_before_issuance(self):
        request = self._request()
        with self.assertRaisesRegex(FinexStageAuthorizationError, "promotion key"):
            assemble_reviewed_stage_authorization(
                request=request,
                expected_request_sha256=request.request_sha256,
                manual_readiness=self.readiness,
                expected_manual_readiness_key_id="manual-readiness-v1",
                manual_aggregate=self.manual_aggregate,
                expected_manual_aggregate_key_id="manual-aggregate-v1",
                promotion_receipt=self.promotion,
                expected_promotion_key_id="wrong-promotion-key",
                acceptance_policy=self.acceptance_policy,
                expected_acceptance_policy_sha256=self.acceptance_policy.policy_sha256,
                approvals=self._approvals(request),
                expected_risk_approval_key_id="approval-risk-v1",
                expected_operations_approval_key_id="approval-ops-v1",
                stage_signer_key_id="stage-authority-v1",
                key_provider=lambda _: b"x" * 32,
                issued_at=self.t0 + timedelta(seconds=1),
            )


if __name__ == "__main__":
    unittest.main()
