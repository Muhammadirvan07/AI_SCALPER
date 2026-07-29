from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from live_runtime.live_canary_activation import LIVE_CANARY_APPROVAL_ROLES
from live_runtime.live_canary_activation_artifacts import (
    LiveCanaryActivationArtifactError,
    assemble_live_canary_activation_authorization_artifact,
    assemble_live_canary_activation_request_artifact,
    issue_live_canary_human_approval_artifact,
    load_demo_auto_soak_cohort_binding_artifact,
    load_demo_auto_soak_cohort_receipt_artifact,
    load_live_canary_activation_authorization_artifact,
    load_live_canary_activation_request_artifact,
    load_live_canary_human_approval_artifact,
    load_promotion_evidence_receipt_artifact,
    verify_live_canary_activation_authorization_artifact,
    verify_live_canary_activation_request_artifact,
    verify_live_canary_human_approval_artifact,
    write_live_canary_activation_artifact_exclusive,
)
from live_runtime.live_canary_gate_contracts import LIVE_CANARY_GATE_DOMAINS
from live_runtime.live_canary_gate_receipt_artifacts import (
    assemble_live_canary_gate_receipt_set,
    write_live_canary_gate_artifact_exclusive,
)
from live_runtime.secure_files import write_json_exclusive
from test_live_runtime_demo_auto_soak_cohort import NOW
import test_live_runtime_live_canary_activation as activation_fixture


class LiveCanaryActivationArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.base = Path(self.root.name)
        self.core = activation_fixture.LiveCanaryActivationTests(
            methodName="test_ac1_exact_eligible_request_is_canonical_and_deny_only"
        )
        self.core.setUp()
        self.addCleanup(self.core.doCleanups)

        self.binding_path = self._write(
            "binding.json", self.core.binding.to_canonical_dict()
        )
        self.policy_path = self._write(
            "trust-policy.json", self.core.policy.to_canonical_dict()
        )
        self.soak_binding_path = self._write(
            "soak-binding.json", self.core.soak.binding.to_canonical_dict()
        )
        self.soak_receipt_path = self._write(
            "soak-receipt.json", self.core.soak_receipt.to_canonical_dict()
        )
        self.promotion_path = self._write(
            "promotion.json", self.core.promotion.to_canonical_dict()
        )
        self.evidence_paths = {}
        for domain in sorted(LIVE_CANARY_GATE_DOMAINS - {"LEGAL_COMPLIANCE"}):
            path = self.base / f"{domain.lower()}-evidence.bin"
            path.write_bytes(f"external-gate:{domain}".encode("utf-8"))
            self.evidence_paths[domain] = path
        gate_set = assemble_live_canary_gate_receipt_set(
            self.core.binding,
            self.core.policy,
            receipts=self.core.gate_receipts,
            evidence_paths_by_domain=self.evidence_paths,
            eligibility_evidence=self.core.eligibility,
            key_provider=self.core._gate_key,
            assembled_at=NOW,
            required_until=NOW + timedelta(minutes=3),
            clock_provider=lambda: NOW,
        )
        self.gate_set_path = self.base / "gate-set.json"
        write_live_canary_gate_artifact_exclusive(self.gate_set_path, gate_set)

    def _write(self, name: str, payload: dict[str, object]) -> Path:
        path = self.base / name
        write_json_exclusive(path, payload)
        return path

    def _request(self):
        return assemble_live_canary_activation_request_artifact(
            binding=self.core.binding,
            trust_policy=self.core.policy,
            soak_binding=self.core.soak.binding,
            soak_receipt=self.core.soak_receipt,
            soak_key_provider=self.core.soak.aggregator_key,
            promotion_evidence=self.core.promotion,
            promotion_key_provider=lambda _key_id: self.core.promotion_secret,
            live_account_alias="phillip-live-account-alias",
            broker_eligibility_evidence=self.core.eligibility,
            gate_receipt_set_path=self.gate_set_path,
            gate_evidence_paths_by_domain=self.evidence_paths,
            gate_key_provider=self.core._gate_key,
            expires_at=NOW + timedelta(minutes=3),
            nonce="activation-operator-request-nonce-v1",
            clock_provider=lambda: NOW,
        )

    def _request_inputs(self) -> dict[str, object]:
        return {
            "binding": self.core.binding,
            "soak_binding": self.core.soak.binding,
            "soak_receipt": self.core.soak_receipt,
            "soak_key_provider": self.core.soak.aggregator_key,
            "promotion_evidence": self.core.promotion,
            "promotion_key_provider": lambda _key_id: self.core.promotion_secret,
            "live_account_alias": "phillip-live-account-alias",
            "broker_eligibility_evidence": self.core.eligibility,
            "gate_receipt_set_path": self.gate_set_path,
            "gate_evidence_paths_by_domain": self.evidence_paths,
            "gate_key_provider": self.core._gate_key,
            "clock_provider": lambda: NOW,
        }

    def _approvals(self, request):
        return tuple(
            issue_live_canary_human_approval_artifact(
                request,
                trust_policy=self.core.policy,
                role=role,
                approver_identity=self.core.approver_identities[role],
                key_provider=self.core._approval_key,
                clock_provider=lambda: NOW,
            )
            for role in sorted(LIVE_CANARY_APPROVAL_ROLES)
        )

    def test_ac1_strict_loaders_round_trip_exact_contracts(self) -> None:
        soak_binding = load_demo_auto_soak_cohort_binding_artifact(
            self.soak_binding_path
        )
        soak_receipt = load_demo_auto_soak_cohort_receipt_artifact(
            self.soak_receipt_path
        )
        promotion = load_promotion_evidence_receipt_artifact(self.promotion_path)
        self.assertEqual(self.core.soak.binding, soak_binding)
        self.assertEqual(self.core.soak_receipt, soak_receipt)
        self.assertEqual(self.core.promotion, promotion)

        malformed = self.base / "duplicate.json"
        malformed.write_text('{"mode":"LIVE","mode":"DEMO_AUTO"}\n', encoding="utf-8")
        with self.assertRaises(LiveCanaryActivationArtifactError):
            load_promotion_evidence_receipt_artifact(malformed)

    def test_ac1_strict_loaders_reject_byte_and_nested_schema_drift(self) -> None:
        malformed_payloads = {
            "bom.json": b"\xef\xbb\xbf" + self.promotion_path.read_bytes(),
            "nan.json": b'{"value": NaN}\n',
            "noncanonical.json": b'{"value":1}\n',
        }
        for name, payload in malformed_payloads.items():
            path = self.base / name
            path.write_bytes(payload)
            with self.subTest(name=name), self.assertRaises(
                LiveCanaryActivationArtifactError
            ):
                load_promotion_evidence_receipt_artifact(path)

        request_payload = self._request().to_canonical_dict()
        request_payload["binding"]["unexpected"] = "field"
        nested = self._write("nested-extra.json", request_payload)
        with self.assertRaises(LiveCanaryActivationArtifactError):
            load_live_canary_activation_request_artifact(nested)

    def test_ac1_strict_loader_rejects_symlink(self) -> None:
        link = self.base / "promotion-link.json"
        try:
            link.symlink_to(self.promotion_path)
        except (NotImplementedError, OSError):
            self.skipTest("symlinks are unavailable on this platform")
        with self.assertRaises(LiveCanaryActivationArtifactError):
            load_promotion_evidence_receipt_artifact(link)

    def test_ac2_ac3_request_assembly_and_independent_rebuild(self) -> None:
        request = self._request()
        destination = self.base / "request.json"
        write_live_canary_activation_artifact_exclusive(
            destination, request.to_canonical_dict()
        )
        loaded = load_live_canary_activation_request_artifact(destination)
        verified = verify_live_canary_activation_request_artifact(
            loaded,
            trust_policy=self.core.policy,
            **self._request_inputs(),
        )
        self.assertEqual(request, loaded)
        self.assertEqual(request, verified)
        self.assertFalse(verified.live_allowed)
        self.assertFalse(verified.execution_authorized)
        self.assertEqual("DISABLED", verified.order_capability)

        changed = self.evidence_paths["SECURITY"]
        changed.write_bytes(b"changed-security-source")
        with self.assertRaises(LiveCanaryActivationArtifactError):
            verify_live_canary_activation_request_artifact(
                loaded,
                trust_policy=self.core.policy,
                **self._request_inputs(),
            )

    def test_ac4_role_bound_approval_round_trip_and_tamper_denial(self) -> None:
        request = self._request()
        approval = issue_live_canary_human_approval_artifact(
            request,
            trust_policy=self.core.policy,
            role="RISK_OWNER",
            approver_identity=self.core.approver_identities["RISK_OWNER"],
            key_provider=self.core._approval_key,
            clock_provider=lambda: NOW,
        )
        path = self._write("risk-approval.json", approval.to_canonical_dict())
        loaded = load_live_canary_human_approval_artifact(path)
        self.assertEqual(
            approval,
            verify_live_canary_human_approval_artifact(
                loaded,
                request=request,
                trust_policy=self.core.policy,
                key_provider=self.core._approval_key,
                clock_provider=lambda: NOW,
            ),
        )
        forged = replace(loaded, signature_hmac_sha256="f" * 64)
        with self.assertRaises(LiveCanaryActivationArtifactError):
            verify_live_canary_human_approval_artifact(
                forged,
                request=request,
                trust_policy=self.core.policy,
                key_provider=self.core._approval_key,
                clock_provider=lambda: NOW,
            )

    def test_ac4_untrusted_or_stale_approval_fails_before_key_access(self) -> None:
        request = self._request()
        approval = self._approvals(request)[0]
        provider = mock.Mock(side_effect=AssertionError("credential accessed"))

        forged = replace(approval, key_id="attacker-selected-key-v1")
        with self.assertRaises(LiveCanaryActivationArtifactError):
            verify_live_canary_human_approval_artifact(
                forged,
                request=request,
                trust_policy=self.core.policy,
                key_provider=provider,
                clock_provider=lambda: NOW,
            )
        provider.assert_not_called()

        with self.assertRaises(LiveCanaryActivationArtifactError):
            verify_live_canary_human_approval_artifact(
                approval,
                request=request,
                trust_policy=self.core.policy,
                key_provider=provider,
                clock_provider=lambda: request.expires_at,
            )
        provider.assert_not_called()

    def test_ac5_ac6_authorization_requires_three_distinct_approvals(self) -> None:
        request = self._request()
        approvals = self._approvals(request)
        authorization = assemble_live_canary_activation_authorization_artifact(
            request,
            approvals=approvals,
            trust_policy=self.core.policy,
            approval_key_provider=self.core._approval_key,
            deployment_key_provider=lambda _key_id: self.core.deployment_secret,
            clock_provider=lambda: NOW,
        )
        path = self._write(
            "authorization.json", authorization.to_canonical_dict()
        )
        loaded = load_live_canary_activation_authorization_artifact(path)
        verified = verify_live_canary_activation_authorization_artifact(
            loaded,
            request=request,
            approvals=approvals,
            trust_policy=self.core.policy,
            approval_key_provider=self.core._approval_key,
            deployment_key_provider=lambda _key_id: self.core.deployment_secret,
            clock_provider=lambda: NOW,
        )
        self.assertEqual(authorization, verified)
        self.assertFalse(verified.activation_authorized)
        self.assertEqual("DISABLED", verified.order_capability)

        with self.assertRaises(LiveCanaryActivationArtifactError):
            assemble_live_canary_activation_authorization_artifact(
                request,
                approvals=(approvals[0], approvals[0], approvals[2]),
                trust_policy=self.core.policy,
                approval_key_provider=self.core._approval_key,
                deployment_key_provider=lambda _key_id: self.core.deployment_secret,
                clock_provider=lambda: NOW,
            )

    def test_ac5_invalid_approvals_fail_before_deployment_key_access(self) -> None:
        request = self._request()
        approvals = self._approvals(request)
        deployment_provider = mock.Mock(
            side_effect=AssertionError("deployment key accessed")
        )
        with self.assertRaises(LiveCanaryActivationArtifactError):
            assemble_live_canary_activation_authorization_artifact(
                request,
                approvals=(approvals[0], approvals[0], approvals[2]),
                trust_policy=self.core.policy,
                approval_key_provider=self.core._approval_key,
                deployment_key_provider=deployment_provider,
                clock_provider=lambda: NOW,
            )
        deployment_provider.assert_not_called()

    def test_ac6_authorization_verifier_rejects_source_substitution(self) -> None:
        request = self._request()
        approvals = self._approvals(request)
        authorization = assemble_live_canary_activation_authorization_artifact(
            request,
            approvals=approvals,
            trust_policy=self.core.policy,
            approval_key_provider=self.core._approval_key,
            deployment_key_provider=lambda _key_id: self.core.deployment_secret,
            clock_provider=lambda: NOW,
        )
        substituted = replace(request, nonce="substituted-request-nonce-v1")
        deployment_provider = mock.Mock(
            side_effect=AssertionError("deployment key accessed")
        )
        with self.assertRaises(LiveCanaryActivationArtifactError):
            verify_live_canary_activation_authorization_artifact(
                authorization,
                request=substituted,
                approvals=approvals,
                trust_policy=self.core.policy,
                approval_key_provider=self.core._approval_key,
                deployment_key_provider=deployment_provider,
                clock_provider=lambda: NOW,
            )
        deployment_provider.assert_not_called()

    def test_ac7_existing_output_is_never_replaced(self) -> None:
        path = self.base / "existing.json"
        path.write_bytes(b"owner-evidence")
        with self.assertRaises(FileExistsError):
            write_live_canary_activation_artifact_exclusive(path, {"x": 1})
        self.assertEqual(b"owner-evidence", path.read_bytes())

    def test_ac9_bounded_approval_and_authorization_latency(self) -> None:
        request = self._request()
        started = time.perf_counter()
        for _ in range(25):
            approvals = self._approvals(request)
            authorization = assemble_live_canary_activation_authorization_artifact(
                request,
                approvals=approvals,
                trust_policy=self.core.policy,
                approval_key_provider=self.core._approval_key,
                deployment_key_provider=lambda _key_id: self.core.deployment_secret,
                clock_provider=lambda: NOW,
            )
            verify_live_canary_activation_authorization_artifact(
                authorization,
                request=request,
                approvals=approvals,
                trust_policy=self.core.policy,
                approval_key_provider=self.core._approval_key,
                deployment_key_provider=lambda _key_id: self.core.deployment_secret,
                clock_provider=lambda: NOW,
            )
        elapsed_ms = (time.perf_counter() - started) * 1000 / 25
        self.assertLess(elapsed_ms, 100.0)


if __name__ == "__main__":
    unittest.main()
