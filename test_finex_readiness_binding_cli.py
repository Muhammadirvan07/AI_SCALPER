from __future__ import annotations

from datetime import timedelta
import unittest

from finex_readiness_binding import (
    FinexReadinessBindingCLIError,
    REQUEST_FIELDS,
    issue_from_reviewed_request,
)
from live_runtime.finex_readiness_binding import verify_finex_readiness_binding
from test_finex_readiness_binding import KEY, NOW, _issue


class FinexReadinessBindingCLITests(unittest.TestCase):
    def _request(self):
        canonical = _issue().to_canonical_dict()
        request = {name: canonical[name] for name in REQUEST_FIELDS}
        for name in (
            "terminal_spec_observation_sha256_by_symbol",
            "broker_spec_sha256_by_symbol",
            "strategy_config_sha256_by_symbol",
            "model_artifact_sha256_by_symbol",
            "stage_binding_sha256_by_symbol",
            "risk_key_id_by_symbol",
            "risk_source_issuer_id_by_symbol",
            "risk_source_key_id_by_symbol",
            "promotion_signer_key_id_by_symbol",
            "stage_signer_key_id_by_symbol",
            "risk_approval_key_id_by_symbol",
            "operations_approval_key_id_by_symbol",
        ):
            request[name] = dict(request[name])
        return request

    def test_reviewed_request_round_trip_is_deny_only(self):
        request = self._request()
        binding = issue_from_reviewed_request(
            request,
            expected_trust_policy_sha256=request["trust_policy_sha256"],
            expected_issuer_id=request["issuer_id"],
            expected_key_id=request["key_id"],
            signing_key=KEY,
        )
        verified = verify_finex_readiness_binding(
            binding,
            expected_trust_policy_sha256=request["trust_policy_sha256"],
            expected_issuer_id=request["issuer_id"],
            expected_key_id=request["key_id"],
            key_provider=lambda _: KEY,
            now=NOW + timedelta(seconds=1),
        )
        self.assertFalse(verified.authorization_granted)
        self.assertFalse(verified.safe_to_demo_auto_order)
        self.assertEqual("DISABLED", verified.order_capability)

    def test_external_trust_and_exact_shape_are_mandatory(self):
        request = self._request()
        with self.assertRaisesRegex(
            FinexReadinessBindingCLIError, "EXTERNAL_TRUST_MISMATCH"
        ):
            issue_from_reviewed_request(
                request,
                expected_trust_policy_sha256="f" * 64,
                expected_issuer_id=request["issuer_id"],
                expected_key_id=request["key_id"],
                signing_key=KEY,
            )
        request["unexpected"] = True
        with self.assertRaisesRegex(
            FinexReadinessBindingCLIError, "REQUEST_SHAPE_INVALID"
        ):
            issue_from_reviewed_request(
                request,
                expected_trust_policy_sha256=request["trust_policy_sha256"],
                expected_issuer_id=request["issuer_id"],
                expected_key_id=request["key_id"],
                signing_key=KEY,
            )


if __name__ == "__main__":
    unittest.main()
