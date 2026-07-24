from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from live_runtime.promotion_evidence import PromotionEvidenceReceipt
from live_runtime.stage_authorization import (
    AcceptanceAuthorityReceipt,
    AcceptanceAuthorityTrustPolicy,
    HumanApprovalAttestation,
    ManualDemoAggregateReceipt,
    ManualDemoReadinessReceipt,
    StageAuthorizationError,
    StageAuthorizationIntegrityError,
    StageAuthorizationReplayRegistry,
    StageAuthorizationValidation,
    StageBinding,
    StageReadinessAuthorization,
    StageReadinessRequest,
    StageReplayCheckpoint,
    account_alias_sha256,
    issue_acceptance_authority_receipt,
    issue_human_approval,
    issue_stage_readiness_authorization,
    validate_and_consume_stage_readiness_authorization,
)


UTC = timezone.utc
PRE_MANUAL_COMPLETE_STATUS = (
    "PRE_MANUAL_DEMO_EXTERNAL_PRECONDITIONS_COMPLETE_"
    "ACTIVATION_REVIEW_REQUIRED"
)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class StageAuthorizationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.t0 = datetime(2026, 7, 22, 10, 0, tzinfo=UTC)
        self.account_alias = "private-demo-alias-001"
        self.manual_readiness_secret = b"r" * 32
        self.manual_secret = b"m" * 32
        self.promotion_secret = b"p" * 32
        self.approver_secrets = {
            "approval-risk-v1": b"a" * 32,
            "approval-ops-v1": b"b" * 32,
        }
        self.stage_secret = b"s" * 32
        self.replay_secret = b"x" * 32
        self.pre_manual_entry_review_sha256 = digest(
            "complete-pre-manual-entry-review"
        )
        self.acceptance_authority_secrets = {
            "runtime-authority-v1": b"u" * 32,
            "parity-authority-v1": b"v" * 32,
            "security-authority-v1": b"w" * 32,
            "failure-drill-authority-v1": b"y" * 32,
        }
        self.acceptance_policy = AcceptanceAuthorityTrustPolicy(
            policy_id="stage-acceptance-authorities-v1",
            domain_key_allowlist=tuple(
                (
                    domain,
                    (
                        (
                            key_id,
                            hashlib.sha256(
                                self.acceptance_authority_secrets[key_id]
                            ).hexdigest(),
                        ),
                    ),
                )
                for domain, key_id in (
                    ("RUNTIME", "runtime-authority-v1"),
                    ("PARITY", "parity-authority-v1"),
                    ("SECURITY", "security-authority-v1"),
                    ("FAILURE_DRILL", "failure-drill-authority-v1"),
                )
            ),
        )
        self.binding = StageBinding(
            broker_id="phillip-demo",
            account_alias_sha256=account_alias_sha256(self.account_alias),
            server="Phillip-Demo-Reviewed",
            environment="DEMO",
            symbol="EURUSD",
            strategy="BREAKOUT",
            lane_id=f"EURUSD:BREAKOUT:{digest('config')}",
            journal_sha256=digest("journal"),
            commit_sha="abcdef1234567",
            config_sha256=digest("config"),
            dependency_lock_sha256=digest("dependencies"),
            broker_spec_sha256=digest("broker-spec"),
            session_calendar_sha256=digest("session-calendar"),
            evidence_contract_sha256=digest("evidence-contract"),
            broker_profile_sha256=digest("broker-profile"),
            runtime_profile_sha256=digest("runtime-profile"),
            model_artifact_sha256=digest("model"),
            acceptance_authority_policy_sha256=(
                self.acceptance_policy.policy_sha256
            ),
            manual_demo_custodian_trust_sha256=digest(
                "manual-custodian-trust-policy"
            ),
        )
        self.readiness = self._readiness_receipt()
        self.manual_aggregate = self._manual_aggregate_receipt()
        self.promotion = self._promotion_receipt()

    def _readiness_receipt(self, **changes: object) -> ManualDemoReadinessReceipt:
        values: dict[str, object] = {
            "binding_sha256": self.binding.binding_sha256,
            "gate_receipts": {
                "LEGAL": digest("legal"),
                "CLEAN_RELEASE": digest("release"),
                "NEWS": digest("news"),
                "WINDOWS": digest("windows"),
                "FAILURE_DRILL": digest("failure-drill"),
                "SECURITY": digest("security"),
                "RISK": digest("risk"),
                "RECONCILIATION": digest("reconciliation"),
            },
            "source_validation_receipt_sha256": digest("global-validation"),
            "pre_manual_entry_review_sha256": (
                self.pre_manual_entry_review_sha256
            ),
            "pre_manual_entry_review_checked_at": (
                self.t0 - timedelta(minutes=1)
            ),
            "pre_manual_entry_review_status": PRE_MANUAL_COMPLETE_STATUS,
            "issued_at": self.t0 - timedelta(minutes=1),
            "expires_at": self.t0 + timedelta(minutes=4),
            "signer_key_id": "manual-readiness-v1",
            "nonce": "manual-readiness-nonce-001",
        }
        values.update(changes)
        return ManualDemoReadinessReceipt(**values).sign(  # type: ignore[arg-type]
            self.manual_readiness_secret
        )

    def _manual_aggregate_receipt(self, **changes: object) -> ManualDemoAggregateReceipt:
        values: dict[str, object] = {
            "binding_sha256": digest("manual-tracker-binding"),
            "account_alias_sha256": self.binding.account_alias_sha256,
            "broker_server": self.binding.server,
            "journal_sha256": self.binding.journal_sha256,
            "commit_sha": self.binding.commit_sha,
            "config_sha256": self.binding.config_sha256,
            "lane_id": self.binding.lane_id,
            "tracker_head_sha256": digest("manual-tracker-head"),
            "external_custody_checkpoint_sha256": digest(
                "manual-tracker-external-custody"
            ),
            "custodian_trust_sha256": digest("manual-custodian-trust-policy"),
            "tracker_head_sequence": 40,
            "total_events": 40,
            "clean_completed_orders": 10,
            "critical_incidents": 0,
            "orphan_positions": 0,
            "orphan_orders": 0,
            "unexplained_positions": 0,
            "assessment_sha256": digest("manual-assessment"),
            "assessed_at": self.t0 - timedelta(minutes=2),
            "issued_at": self.t0 - timedelta(minutes=1),
            "expires_at": self.t0 + timedelta(minutes=4),
            "signer_key_id": "manual-aggregate-v1",
            "nonce": "manual-aggregate-nonce-001",
        }
        values.update(changes)
        return ManualDemoAggregateReceipt(**values).sign(  # type: ignore[arg-type]
            self.manual_secret
        )

    def _promotion_receipt(self, **changes: object) -> PromotionEvidenceReceipt:
        values: dict[str, object] = {
            "mode": "DEMO_AUTO",
            "lane_id": self.binding.lane_id,
            "symbol": self.binding.symbol,
            "strategy": self.binding.strategy,
            "account_alias_sha256": self.binding.account_alias_sha256,
            "server": self.binding.server,
            "journal_sha256": self.binding.journal_sha256,
            "commit_sha": self.binding.commit_sha,
            "config_sha256": self.binding.config_sha256,
            "model_artifact_sha256": self.binding.model_artifact_sha256,
            "lane_readiness_sha256": digest("lane-readiness"),
            "lane_evidence_sha256": digest("lane-evidence"),
            "evidence_store_receipt_sha256": digest("evidence-store"),
            "runtime_parity_receipt_sha256": digest("parity-receipt"),
            "build_manifest_sha256": digest("build-manifest"),
            "issued_at": self.t0 - timedelta(minutes=1),
            "expires_at": self.t0 + timedelta(minutes=4),
            "signer_key_id": "promotion-v1",
            "nonce": "promotion-nonce-001",
        }
        values.update(changes)
        return PromotionEvidenceReceipt(**values).sign(  # type: ignore[arg-type]
            self.promotion_secret
        )

    def _acceptance_receipts(
        self, **receipt_changes: str
    ) -> tuple[AcceptanceAuthorityReceipt, ...]:
        receipts = {
            "RUNTIME": digest("runtime-acceptance"),
            "PARITY": self.promotion.runtime_parity_receipt_sha256,
            "SECURITY": digest("security-acceptance"),
            "FAILURE_DRILL": digest("failure-acceptance"),
        }
        receipts.update(receipt_changes)
        return tuple(
            issue_acceptance_authority_receipt(
                domain=domain,
                binding=self.binding,
                evidence_receipt_sha256=receipt,
                validation_receipt_sha256=digest(f"{domain}-validation"),
                accepted_at=self.t0 - timedelta(minutes=2),
                expires_at=self.t0 + timedelta(minutes=5),
                authority_key_id={
                    "RUNTIME": "runtime-authority-v1",
                    "PARITY": "parity-authority-v1",
                    "SECURITY": "security-authority-v1",
                    "FAILURE_DRILL": "failure-drill-authority-v1",
                }[domain],
                authority_secret=self.acceptance_authority_secrets[
                    {
                        "RUNTIME": "runtime-authority-v1",
                        "PARITY": "parity-authority-v1",
                        "SECURITY": "security-authority-v1",
                        "FAILURE_DRILL": "failure-drill-authority-v1",
                    }[domain]
                ],
                trust_policy=self.acceptance_policy,
            )
            for domain, receipt in receipts.items()
        )

    def _request(self, mode: str = "DEMO_AUTO", **changes: object) -> StageReadinessRequest:
        values: dict[str, object] = {
            "binding": self.binding,
            "manual_readiness_receipt_sha256": self.readiness.content_sha256,
            "pre_manual_entry_review_sha256": (
                self.pre_manual_entry_review_sha256
            ),
            "acceptance_receipts": (
                self._acceptance_receipts() if mode == "DEMO_AUTO" else ()
            ),
            "issued_at": self.t0,
            "expires_at": self.t0 + timedelta(minutes=4),
            "nonce": f"{mode.lower()}-stage-nonce-001",
            "mode": mode,
            "manual_demo_aggregate_receipt_sha256": (
                self.manual_aggregate.content_sha256 if mode == "DEMO_AUTO" else None
            ),
            "promotion_evidence_receipt_sha256": (
                self.promotion.content_sha256 if mode == "DEMO_AUTO" else None
            ),
            "evidence_store_receipt_sha256": (
                self.promotion.evidence_store_receipt_sha256
                if mode == "DEMO_AUTO"
                else None
            ),
        }
        values.update(changes)
        return StageReadinessRequest(**values)  # type: ignore[arg-type]

    def _approvals(
        self,
        request: StageReadinessRequest,
        *,
        same_identity: bool = False,
    ) -> tuple[HumanApprovalAttestation, HumanApprovalAttestation]:
        identities = ("risk-owner@example.invalid", "ops-owner@example.invalid")
        if same_identity:
            identities = (identities[0], identities[0])
        risk = issue_human_approval(
            request,
            human_identity=identities[0],
            role="RISK_OWNER",
            approved_at=self.t0 + timedelta(minutes=1),
            approval_nonce="risk-approval-nonce-001",
            signer_key_id="approval-risk-v1",
            secret=self.approver_secrets["approval-risk-v1"],
        )
        ops = issue_human_approval(
            request,
            human_identity=identities[1],
            role="OPERATIONS_OWNER",
            approved_at=self.t0 + timedelta(minutes=1),
            approval_nonce="ops-approval-nonce-001",
            signer_key_id="approval-ops-v1",
            secret=self.approver_secrets["approval-ops-v1"],
        )
        return risk, ops

    def _issue(self, request: StageReadinessRequest) -> StageReadinessAuthorization:
        return issue_stage_readiness_authorization(
            request,
            manual_readiness_receipt=self.readiness,
            manual_readiness_key_provider=lambda _key_id: self.manual_readiness_secret,
            manual_demo_receipt=(
                self.manual_aggregate if request.mode == "DEMO_AUTO" else None
            ),
            manual_demo_key_provider=(
                (lambda _key_id: self.manual_secret)
                if request.mode == "DEMO_AUTO"
                else None
            ),
            promotion_evidence_receipt=(
                self.promotion if request.mode == "DEMO_AUTO" else None
            ),
            promotion_evidence_key_provider=(
                (lambda _key_id: self.promotion_secret)
                if request.mode == "DEMO_AUTO"
                else None
            ),
            acceptance_authority_policy=(
                self.acceptance_policy if request.mode == "DEMO_AUTO" else None
            ),
            acceptance_authority_key_provider=(
                (lambda key_id: self.acceptance_authority_secrets[key_id])
                if request.mode == "DEMO_AUTO"
                else None
            ),
            approvals=self._approvals(request),
            approval_key_provider=lambda key_id: self.approver_secrets[key_id],
            issued_at=self.t0 + timedelta(minutes=2),
            stage_signer_key_id="stage-authority-v1",
            stage_signing_secret=self.stage_secret,
        )

    def _validate(
        self,
        authorization: StageReadinessAuthorization,
        registry: StageAuthorizationReplayRegistry,
        **changes: object,
    ) -> StageAuthorizationValidation:
        values: dict[str, object] = {
            "manual_readiness_receipt": self.readiness,
            "manual_readiness_key_provider": lambda _key_id: self.manual_readiness_secret,
            "manual_demo_receipt": (
                self.manual_aggregate
                if authorization.request.mode == "DEMO_AUTO"
                else None
            ),
            "manual_demo_key_provider": (
                (lambda _key_id: self.manual_secret)
                if authorization.request.mode == "DEMO_AUTO"
                else None
            ),
            "promotion_evidence_receipt": (
                self.promotion if authorization.request.mode == "DEMO_AUTO" else None
            ),
            "promotion_evidence_key_provider": (
                (lambda _key_id: self.promotion_secret)
                if authorization.request.mode == "DEMO_AUTO"
                else None
            ),
            "acceptance_authority_policy": (
                self.acceptance_policy
                if authorization.request.mode == "DEMO_AUTO"
                else None
            ),
            "acceptance_authority_key_provider": (
                (lambda key_id: self.acceptance_authority_secrets[key_id])
                if authorization.request.mode == "DEMO_AUTO"
                else None
            ),
            "approval_key_provider": lambda key_id: self.approver_secrets[key_id],
            "stage_key_provider": lambda _key_id: self.stage_secret,
            "expected_binding": self.binding,
            "expected_mode": authorization.request.mode,
            "now": self.t0 + timedelta(minutes=3),
            "replay_registry": registry,
        }
        values.update(changes)
        return validate_and_consume_stage_readiness_authorization(  # type: ignore[arg-type]
            authorization,
            **values,
        )

    def _registry(self, root: Path, name: str = "replay.sqlite3") -> StageAuthorizationReplayRegistry:
        return StageAuthorizationReplayRegistry(
            root / name,
            registry_id="stage-replay-phillip-eurusd-v1",
            registry_key_id="replay-key-v1",
            hmac_secret=self.replay_secret,
        )

    def test_manual_demo_global_readiness_is_valid_but_deny_only(self) -> None:
        request = self._request("MANUAL_DEMO")
        authorization = self._issue(request)
        with tempfile.TemporaryDirectory() as directory:
            validation = self._validate(authorization, self._registry(Path(directory)))
        self.assertTrue(validation.valid)
        self.assertTrue(validation.evidence_eligible_for_review)
        self.assertFalse(validation.execution_authorized)
        self.assertFalse(validation.activation_authorized)
        self.assertFalse(validation.safe_to_demo_auto_order)
        self.assertFalse(validation.live_allowed)
        self.assertEqual(validation.order_capability, "DISABLED")
        self.assertEqual(
            self.pre_manual_entry_review_sha256,
            validation.pre_manual_entry_review_sha256,
        )
        self.assertFalse(authorization.execution_authorized)
        self.assertEqual(authorization.order_capability, "DISABLED")

    def test_pre_manual_review_status_and_freshness_are_mandatory(self) -> None:
        self.assertEqual(
            self.pre_manual_entry_review_sha256,
            self.readiness.pre_manual_entry_review_sha256,
        )
        self.assertEqual(
            PRE_MANUAL_COMPLETE_STATUS,
            self.readiness.pre_manual_entry_review_status,
        )
        with self.assertRaises(ValueError):
            self._readiness_receipt(
                pre_manual_entry_review_status=(
                    "BLOCKED_PRE_MANUAL_DEMO_EXTERNAL_PRECONDITIONS"
                )
            )
        with self.assertRaises(ValueError):
            self._readiness_receipt(
                issued_at=self.t0 - timedelta(minutes=1, microseconds=1)
            )
        with self.assertRaises(ValueError):
            self._readiness_receipt(
                expires_at=self.t0
                + timedelta(minutes=4, microseconds=1)
            )

    def test_request_cannot_substitute_a_different_pre_manual_review(
        self,
    ) -> None:
        request = self._request(
            "MANUAL_DEMO",
            pre_manual_entry_review_sha256=digest("other-entry-review"),
        )
        with self.assertRaisesRegex(
            StageAuthorizationError,
            "MANUAL_READINESS_PRE_MANUAL_REVIEW_MISMATCH",
        ):
            self._issue(request)

    def test_demo_auto_requires_all_evidence_and_remains_deny_only(self) -> None:
        authorization = self._issue(self._request())
        with tempfile.TemporaryDirectory() as directory:
            validation = self._validate(authorization, self._registry(Path(directory)))
        self.assertTrue(validation.valid)
        self.assertTrue(validation.consumed_once)
        self.assertFalse(validation.execution_authorized)
        self.assertFalse(validation.activation_authorized)
        self.assertFalse(validation.safe_to_demo_auto_order)
        self.assertFalse(validation.live_allowed)
        self.assertEqual(validation.order_capability, "DISABLED")

    def test_replay_is_rejected_across_registry_restart(self) -> None:
        authorization = self._issue(self._request())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self._validate(authorization, self._registry(root))
            restarted = self._registry(root)
            second = self._validate(authorization, restarted)
            self.assertTrue(restarted.verify_integrity())
        self.assertTrue(first.valid)
        self.assertFalse(second.valid)
        self.assertEqual(second.reason_codes, ("STAGE_AUTHORIZATION_REPLAYED",))

    def test_signature_tamper_fails_without_consuming_nonce(self) -> None:
        authorization = self._issue(self._request())
        object.__setattr__(authorization, "signature_hmac_sha256", digest("tampered"))
        with tempfile.TemporaryDirectory() as directory:
            registry = self._registry(Path(directory))
            result = self._validate(authorization, registry)
            self.assertTrue(registry.verify_integrity())
        self.assertFalse(result.valid)
        self.assertFalse(result.consumed_once)
        self.assertIn("STAGE_AUTHORIZATION_SIGNATURE_INVALID", result.reason_codes)

    def test_exact_binding_mismatch_fails_closed(self) -> None:
        authorization = self._issue(self._request())
        other = replace(self.binding, runtime_profile_sha256=digest("other-runtime"))
        with tempfile.TemporaryDirectory() as directory:
            result = self._validate(
                authorization,
                self._registry(Path(directory)),
                expected_binding=other,
            )
        self.assertFalse(result.valid)
        self.assertIn("STAGE_BINDING_MISMATCH", result.reason_codes)

    def test_expected_stage_mode_mismatch_fails_closed(self) -> None:
        authorization = self._issue(self._request("MANUAL_DEMO"))
        with tempfile.TemporaryDirectory() as directory:
            result = self._validate(
                authorization,
                self._registry(Path(directory)),
                expected_mode="DEMO_AUTO",
            )
        self.assertFalse(result.valid)
        self.assertEqual(result.mode, "MANUAL_DEMO")
        self.assertIn("STAGE_MODE_MISMATCH", result.reason_codes)

    def test_missing_manual_readiness_receipt_is_rejected(self) -> None:
        authorization = self._issue(self._request("MANUAL_DEMO"))
        with tempfile.TemporaryDirectory() as directory:
            result = self._validate(
                authorization,
                self._registry(Path(directory)),
                manual_readiness_receipt=None,
            )
        self.assertFalse(result.valid)
        self.assertIn("MANUAL_READINESS_RECEIPT_MISSING", result.reason_codes)

    def test_tampered_manual_readiness_signature_is_rejected(self) -> None:
        authorization = self._issue(self._request("MANUAL_DEMO"))
        object.__setattr__(self.readiness, "signature_hmac_sha256", digest("bad-readiness"))
        with tempfile.TemporaryDirectory() as directory:
            result = self._validate(authorization, self._registry(Path(directory)))
        self.assertFalse(result.valid)
        self.assertIn("MANUAL_READINESS_SIGNATURE_INVALID", result.reason_codes)
        self.assertIn("MANUAL_READINESS_REFERENCE_MISMATCH", result.reason_codes)

    def test_demo_auto_missing_tracker_receipt_is_rejected(self) -> None:
        authorization = self._issue(self._request())
        with tempfile.TemporaryDirectory() as directory:
            result = self._validate(
                authorization,
                self._registry(Path(directory)),
                manual_demo_receipt=None,
            )
        self.assertFalse(result.valid)
        self.assertIn("MANUAL_DEMO_AGGREGATE_MISSING", result.reason_codes)

    def test_demo_auto_missing_promotion_receipt_is_rejected(self) -> None:
        authorization = self._issue(self._request())
        with tempfile.TemporaryDirectory() as directory:
            result = self._validate(
                authorization,
                self._registry(Path(directory)),
                promotion_evidence_receipt=None,
            )
        self.assertFalse(result.valid)
        self.assertIn("PROMOTION_EVIDENCE_MISSING", result.reason_codes)

    def test_tampered_manual_aggregate_is_rejected(self) -> None:
        authorization = self._issue(self._request())
        object.__setattr__(self.manual_aggregate, "clean_completed_orders", 11)
        with tempfile.TemporaryDirectory() as directory:
            result = self._validate(authorization, self._registry(Path(directory)))
        self.assertFalse(result.valid)
        self.assertIn("MANUAL_DEMO_AGGREGATE_SIGNATURE_INVALID", result.reason_codes)
        self.assertIn("MANUAL_DEMO_AGGREGATE_REFERENCE_MISMATCH", result.reason_codes)

    def test_manual_demo_custodian_trust_policy_must_match_stage_binding(self) -> None:
        self.manual_aggregate = self._manual_aggregate_receipt(
            custodian_trust_sha256=digest("unreviewed-custodian-policy")
        )
        request = self._request()
        with self.assertRaisesRegex(
            StageAuthorizationError,
            "MANUAL_DEMO_CUSTODIAN_TRUST_MISMATCH",
        ):
            self._issue(request)

    def test_promotion_parity_reference_mismatch_rejected_at_issuance(self) -> None:
        request = self._request(
            acceptance_receipts=self._acceptance_receipts(
                PARITY=digest("wrong-parity")
            )
        )
        with self.assertRaisesRegex(StageAuthorizationError, "PARITY_REFERENCE_MISMATCH"):
            self._issue(request)

    def test_duplicate_human_identity_is_rejected(self) -> None:
        request = self._request("MANUAL_DEMO")
        with self.assertRaisesRegex(ValueError, "identities must be distinct"):
            issue_stage_readiness_authorization(
                request,
                manual_readiness_receipt=self.readiness,
                manual_readiness_key_provider=lambda _key_id: self.manual_readiness_secret,
                approvals=self._approvals(request, same_identity=True),
                approval_key_provider=lambda key_id: self.approver_secrets[key_id],
                issued_at=self.t0 + timedelta(minutes=2),
                stage_signer_key_id="stage-authority-v1",
                stage_signing_secret=self.stage_secret,
            )

    def test_tampered_human_approval_is_rejected_at_issuance(self) -> None:
        request = self._request("MANUAL_DEMO")
        approvals = list(self._approvals(request))
        object.__setattr__(approvals[0], "signature_hmac_sha256", digest("bad-approval"))
        with self.assertRaisesRegex(StageAuthorizationError, "HUMAN_APPROVAL_SIGNATURE_INVALID"):
            issue_stage_readiness_authorization(
                request,
                manual_readiness_receipt=self.readiness,
                manual_readiness_key_provider=lambda _key_id: self.manual_readiness_secret,
                approvals=approvals,
                approval_key_provider=lambda key_id: self.approver_secrets[key_id],
                issued_at=self.t0 + timedelta(minutes=2),
                stage_signer_key_id="stage-authority-v1",
                stage_signing_secret=self.stage_secret,
            )

    def test_distinct_key_ids_cannot_alias_the_same_key_material(self) -> None:
        request = self._request("MANUAL_DEMO")
        shared = b"q" * 32
        approvals = (
            issue_human_approval(
                request,
                human_identity="risk-owner@example.invalid",
                role="RISK_OWNER",
                approved_at=self.t0 + timedelta(minutes=1),
                approval_nonce="risk-shared-key-nonce",
                signer_key_id="approval-risk-shared-v1",
                secret=shared,
            ),
            issue_human_approval(
                request,
                human_identity="ops-owner@example.invalid",
                role="OPERATIONS_OWNER",
                approved_at=self.t0 + timedelta(minutes=1),
                approval_nonce="ops-shared-key-nonce",
                signer_key_id="approval-ops-shared-v1",
                secret=shared,
            ),
        )
        with self.assertRaisesRegex(
            StageAuthorizationError,
            "HUMAN_APPROVER_KEY_MATERIAL_NOT_DISTINCT",
        ):
            issue_stage_readiness_authorization(
                request,
                manual_readiness_receipt=self.readiness,
                manual_readiness_key_provider=lambda _key_id: self.manual_readiness_secret,
                approvals=approvals,
                approval_key_provider=lambda _key_id: shared,
                issued_at=self.t0 + timedelta(minutes=2),
                stage_signer_key_id="stage-authority-v1",
                stage_signing_secret=self.stage_secret,
            )

    def test_stage_ttl_is_capped_at_five_minutes(self) -> None:
        with self.assertRaisesRegex(ValueError, "validity window exceeds"):
            self._request(expires_at=self.t0 + timedelta(minutes=5, seconds=1))

    def test_non_demo_environment_is_impossible(self) -> None:
        with self.assertRaisesRegex(ValueError, "restricted to DEMO"):
            replace(self.binding, environment="LIVE")

    def test_missing_acceptance_domain_is_rejected(self) -> None:
        receipts = tuple(
            item
            for item in self._acceptance_receipts()
            if item.domain != "SECURITY"
        )
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self._request(acceptance_receipts=receipts)

    def test_random_hashes_cannot_forge_an_acceptance_authority_receipt(self) -> None:
        with self.assertRaisesRegex(TypeError, "only be created by its authority issuer"):
            AcceptanceAuthorityReceipt(
                domain="RUNTIME",
                binding_sha256=self.binding.binding_sha256,
                evidence_receipt_sha256=digest("random-evidence"),
                validation_receipt_sha256=digest("random-validation"),
                accepted_at=self.t0 - timedelta(minutes=2),
                expires_at=self.t0 + timedelta(minutes=5),
                authority_key_id="runtime-authority-v1",
                signature_hmac_sha256=digest("random-signature"),
            )

    def test_authority_issuer_rejects_wrong_domain_key_and_policy_binding(self) -> None:
        with self.assertRaisesRegex(
            StageAuthorizationIntegrityError,
            "authority key is not trusted",
        ):
            issue_acceptance_authority_receipt(
                domain="RUNTIME",
                binding=self.binding,
                evidence_receipt_sha256=digest("runtime-evidence"),
                validation_receipt_sha256=digest("runtime-validation"),
                accepted_at=self.t0 - timedelta(minutes=2),
                expires_at=self.t0 + timedelta(minutes=5),
                authority_key_id="security-authority-v1",
                authority_secret=self.acceptance_authority_secrets[
                    "security-authority-v1"
                ],
                trust_policy=self.acceptance_policy,
            )

        with self.assertRaisesRegex(
            StageAuthorizationIntegrityError,
            "key material is not trusted",
        ):
            issue_acceptance_authority_receipt(
                domain="RUNTIME",
                binding=self.binding,
                evidence_receipt_sha256=digest("runtime-evidence"),
                validation_receipt_sha256=digest("runtime-validation"),
                accepted_at=self.t0 - timedelta(minutes=2),
                expires_at=self.t0 + timedelta(minutes=5),
                authority_key_id="runtime-authority-v1",
                authority_secret=b"q" * 32,
                trust_policy=self.acceptance_policy,
            )

        other_policy = AcceptanceAuthorityTrustPolicy(
            policy_id="unbound-acceptance-authorities-v1",
            domain_key_allowlist=tuple(
                (
                    domain,
                    (
                        (
                            f"unbound-{domain.lower()}-authority-v1",
                            digest(f"unbound-{domain}-authority-material"),
                        ),
                    ),
                )
                for domain in ("RUNTIME", "PARITY", "SECURITY", "FAILURE_DRILL")
            ),
        )
        with self.assertRaisesRegex(
            StageAuthorizationIntegrityError,
            "policy does not match stage binding",
        ):
            issue_acceptance_authority_receipt(
                domain="RUNTIME",
                binding=self.binding,
                evidence_receipt_sha256=digest("runtime-evidence"),
                validation_receipt_sha256=digest("runtime-validation"),
                accepted_at=self.t0 - timedelta(minutes=2),
                expires_at=self.t0 + timedelta(minutes=5),
                authority_key_id="unbound-runtime-authority-v1",
                authority_secret=b"z" * 32,
                trust_policy=other_policy,
            )

    def test_wrong_binding_authority_receipt_is_rejected_before_stage_issuance(self) -> None:
        other_binding = replace(
            self.binding,
            runtime_profile_sha256=digest("different-runtime-profile"),
        )
        wrong_receipt = issue_acceptance_authority_receipt(
            domain="RUNTIME",
            binding=other_binding,
            evidence_receipt_sha256=digest("other-runtime-evidence"),
            validation_receipt_sha256=digest("other-runtime-validation"),
            accepted_at=self.t0 - timedelta(minutes=2),
            expires_at=self.t0 + timedelta(minutes=5),
            authority_key_id="runtime-authority-v1",
            authority_secret=self.acceptance_authority_secrets[
                "runtime-authority-v1"
            ],
            trust_policy=self.acceptance_policy,
        )
        receipts = tuple(
            wrong_receipt if item.domain == "RUNTIME" else item
            for item in self._acceptance_receipts()
        )
        with self.assertRaisesRegex(ValueError, "RUNTIME acceptance binding mismatch"):
            self._request(acceptance_receipts=receipts)

    def test_tampered_authority_receipt_is_rejected_at_issuance_and_consumption(self) -> None:
        request = self._request()
        runtime_receipt = next(
            item for item in request.acceptance_receipts if item.domain == "RUNTIME"
        )
        object.__setattr__(
            runtime_receipt,
            "evidence_receipt_sha256",
            digest("tampered-runtime-evidence"),
        )
        with self.assertRaisesRegex(
            StageAuthorizationError,
            "RUNTIME_ACCEPTANCE_AUTHORITY_SIGNATURE_INVALID",
        ):
            self._issue(request)

        request = self._request(nonce="demo_auto-stage-consumption-tamper-002")
        authorization = self._issue(request)
        runtime_receipt = next(
            item for item in request.acceptance_receipts if item.domain == "RUNTIME"
        )
        object.__setattr__(
            runtime_receipt,
            "validation_receipt_sha256",
            digest("tampered-runtime-validation"),
        )
        authorization = StageReadinessAuthorization(
            request=request,
            approvals=self._approvals(request),
            stage_signer_key_id="stage-authority-v1",
        ).sign(self.stage_secret)
        with tempfile.TemporaryDirectory() as directory:
            result = self._validate(
                authorization,
                self._registry(Path(directory)),
            )
        self.assertFalse(result.valid)
        self.assertIn(
            "RUNTIME_ACCEPTANCE_AUTHORITY_SIGNATURE_INVALID",
            result.reason_codes,
        )

    def test_wrong_authority_key_at_consumption_fails_closed(self) -> None:
        authorization = self._issue(self._request())

        def wrong_runtime_key(key_id: str) -> bytes:
            if key_id == "runtime-authority-v1":
                return b"q" * 32
            return self.acceptance_authority_secrets[key_id]

        with tempfile.TemporaryDirectory() as directory:
            result = self._validate(
                authorization,
                self._registry(Path(directory)),
                acceptance_authority_key_provider=wrong_runtime_key,
            )
        self.assertFalse(result.valid)
        self.assertIn(
            "RUNTIME_ACCEPTANCE_AUTHORITY_SIGNATURE_INVALID",
            result.reason_codes,
        )

    def test_manual_readiness_requires_every_global_gate(self) -> None:
        gates = {
            "LEGAL": digest("legal"),
            "CLEAN_RELEASE": digest("release"),
            "NEWS": digest("news"),
        }
        with self.assertRaisesRegex(ValueError, "gate set is incomplete"):
            self._readiness_receipt(gate_receipts=gates)

    def test_manual_aggregate_cannot_claim_fewer_than_ten_clean_orders(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least ten"):
            self._manual_aggregate_receipt(clean_completed_orders=9)

    def test_manual_aggregate_cannot_hide_critical_incident(self) -> None:
        with self.assertRaisesRegex(ValueError, "critical condition"):
            self._manual_aggregate_receipt(critical_incidents=1)

    def test_expired_authorization_and_receipts_fail_closed(self) -> None:
        authorization = self._issue(self._request())
        with tempfile.TemporaryDirectory() as directory:
            result = self._validate(
                authorization,
                self._registry(Path(directory)),
                now=self.t0 + timedelta(minutes=4),
            )
        self.assertFalse(result.valid)
        self.assertIn("STAGE_AUTHORIZATION_EXPIRED", result.reason_codes)
        self.assertIn("MANUAL_DEMO_AGGREGATE_EXPIRED", result.reason_codes)
        self.assertIn("PROMOTION_EVIDENCE_EXPIRED", result.reason_codes)

    def test_stale_acceptance_authority_receipt_is_rejected(self) -> None:
        authorization = self._issue(self._request())
        with tempfile.TemporaryDirectory() as directory:
            result = self._validate(
                authorization,
                self._registry(Path(directory)),
                now=self.t0 + timedelta(minutes=5),
            )
        self.assertFalse(result.valid)
        self.assertIn("RUNTIME_ACCEPTANCE_STALE", result.reason_codes)

    def test_raw_account_alias_and_human_identities_are_not_serialized(self) -> None:
        request = self._request()
        authorization = self._issue(request)
        payload = authorization.canonical_json()
        self.assertNotIn(self.account_alias, payload)
        self.assertNotIn("risk-owner@example.invalid", payload)
        self.assertNotIn("ops-owner@example.invalid", payload)
        self.assertIn(self.binding.account_alias_sha256, payload)

    def test_validation_constructor_is_sealed(self) -> None:
        with self.assertRaisesRegex(TypeError, "only be created by its verifier"):
            StageAuthorizationValidation(
                valid=False,
                reason_codes=("REJECTED",),
                checked_at=self.t0,
                mode="MANUAL_DEMO",
                authorization_id="manual_demo_stage_123",
                authorization_sha256=digest("auth"),
                request_sha256=digest("request"),
                binding_sha256=digest("binding"),
                pre_manual_entry_review_sha256=digest("entry-review"),
                nonce_sha256=digest("nonce"),
                evidence_eligible_for_review=False,
                consumed_once=False,
            )

    def test_naive_timestamps_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "timezone-aware UTC"):
            self._request(issued_at=self.t0.replace(tzinfo=None))

    def test_replay_registry_detects_schema_tamper(self) -> None:
        authorization = self._issue(self._request("MANUAL_DEMO"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = self._registry(root)
            self._validate(authorization, registry)
            connection = sqlite3.connect(root / "replay.sqlite3")
            connection.execute("DROP TRIGGER stage_replay_events_no_delete")
            connection.commit()
            connection.close()
            with self.assertRaisesRegex(StageAuthorizationIntegrityError, "triggers changed"):
                self._registry(root)

    def test_replay_registry_wrong_hmac_key_fails_closed_after_consumption(self) -> None:
        authorization = self._issue(self._request("MANUAL_DEMO"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._validate(authorization, self._registry(root))
            with self.assertRaisesRegex(StageAuthorizationIntegrityError, "binding mismatch"):
                StageAuthorizationReplayRegistry(
                    root / "replay.sqlite3",
                    registry_id="stage-replay-phillip-eurusd-v1",
                    registry_key_id="replay-key-v1",
                    hmac_secret=b"z" * 32,
                )

    def test_signed_replay_checkpoint_allows_exact_restart_and_extension(self) -> None:
        first_authorization = self._issue(self._request("MANUAL_DEMO"))
        second_request = self._request(
            "MANUAL_DEMO",
            nonce="manual-demo-stage-nonce-002",
        )
        second_authorization = self._issue(second_request)
        checkpoint_secret = b"c" * 32
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = self._registry(root)
            self._validate(first_authorization, registry)
            checkpoint = registry.create_checkpoint(
                issued_at=self.t0 + timedelta(minutes=3),
                checkpoint_key_id="replay-checkpoint-v1",
                checkpoint_secret=checkpoint_secret,
            )
            self._validate(second_authorization, registry)
            restarted = StageAuthorizationReplayRegistry(
                root / "replay.sqlite3",
                registry_id="stage-replay-phillip-eurusd-v1",
                registry_key_id="replay-key-v1",
                hmac_secret=self.replay_secret,
                expected_checkpoint=checkpoint,
                checkpoint_key_provider=lambda _key_id: checkpoint_secret,
            )
            self.assertTrue(restarted.verify_integrity())
            self.assertEqual(checkpoint.event_count, 1)
            self.assertEqual(checkpoint.registry_id, "stage-replay-phillip-eurusd-v1")
            self.assertEqual(
                checkpoint.registry_key_fingerprint_sha256,
                hashlib.sha256(self.replay_secret).hexdigest(),
            )

    def test_production_checkpoint_verification_rejects_valid_historical_prefix(self) -> None:
        first_authorization = self._issue(self._request("MANUAL_DEMO"))
        second_authorization = self._issue(
            self._request(
                "MANUAL_DEMO",
                nonce="manual-demo-stage-current-head-002",
            )
        )
        checkpoint_secret = b"c" * 32
        with tempfile.TemporaryDirectory() as directory:
            registry = self._registry(Path(directory))
            self._validate(first_authorization, registry)
            historical = registry.create_checkpoint(
                issued_at=self.t0 + timedelta(minutes=3),
                checkpoint_key_id="replay-checkpoint-v1",
                checkpoint_secret=checkpoint_secret,
            )
            self._validate(second_authorization, registry)

            with self.assertRaisesRegex(
                StageAuthorizationIntegrityError,
                "not the current high-water mark",
            ):
                registry.verify_checkpoint(
                    historical,
                    key_provider=lambda _key_id: checkpoint_secret,
                    require_current=True,
                )

    def test_expected_checkpoint_detects_full_database_rollback(self) -> None:
        authorization = self._issue(self._request("MANUAL_DEMO"))
        checkpoint_secret = b"c" * 32
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "replay.sqlite3"
            empty_backup = root / "empty.sqlite3"
            registry = self._registry(root)
            source = sqlite3.connect(database)
            destination = sqlite3.connect(empty_backup)
            source.backup(destination)
            source.close()
            destination.close()
            self._validate(authorization, registry)
            checkpoint = registry.create_checkpoint(
                issued_at=self.t0 + timedelta(minutes=3),
                checkpoint_key_id="replay-checkpoint-v1",
                checkpoint_secret=checkpoint_secret,
            )
            connection = sqlite3.connect(database)
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            connection.close()
            shutil.copy2(empty_backup, database)
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(database) + suffix)
                if sidecar.exists():
                    sidecar.unlink()
            with self.assertRaisesRegex(
                StageAuthorizationIntegrityError,
                "rollback detected",
            ):
                StageAuthorizationReplayRegistry(
                    database,
                    registry_id="stage-replay-phillip-eurusd-v1",
                    registry_key_id="replay-key-v1",
                    hmac_secret=self.replay_secret,
                    expected_checkpoint=checkpoint,
                    checkpoint_key_provider=lambda _key_id: checkpoint_secret,
                )

    def test_expected_checkpoint_detects_equal_height_fork(self) -> None:
        first_authorization = self._issue(self._request("MANUAL_DEMO"))
        second_authorization = self._issue(
            self._request(
                "MANUAL_DEMO",
                nonce="manual-demo-stage-fork-nonce-002",
            )
        )
        checkpoint_secret = b"c" * 32
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_registry = self._registry(root, "first.sqlite3")
            self._validate(first_authorization, first_registry)
            checkpoint = first_registry.create_checkpoint(
                issued_at=self.t0 + timedelta(minutes=3),
                checkpoint_key_id="replay-checkpoint-v1",
                checkpoint_secret=checkpoint_secret,
            )
            fork_registry = self._registry(root, "fork.sqlite3")
            self._validate(second_authorization, fork_registry)
            with self.assertRaisesRegex(
                StageAuthorizationIntegrityError,
                "fork or prefix rewrite",
            ):
                StageAuthorizationReplayRegistry(
                    root / "fork.sqlite3",
                    registry_id="stage-replay-phillip-eurusd-v1",
                    registry_key_id="replay-key-v1",
                    hmac_secret=self.replay_secret,
                    expected_checkpoint=checkpoint,
                    checkpoint_key_provider=lambda _key_id: checkpoint_secret,
                )

    def test_expected_checkpoint_signature_and_binding_are_authenticated(self) -> None:
        authorization = self._issue(self._request("MANUAL_DEMO"))
        checkpoint_secret = b"c" * 32
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = self._registry(root)
            self._validate(authorization, registry)
            checkpoint = registry.create_checkpoint(
                issued_at=self.t0 + timedelta(minutes=3),
                checkpoint_key_id="replay-checkpoint-v1",
                checkpoint_secret=checkpoint_secret,
            )
            tampered = replace(
                checkpoint,
                signature_hmac_sha256=digest("bad-checkpoint-signature"),
            )
            with self.assertRaisesRegex(
                StageAuthorizationIntegrityError,
                "checkpoint signature is invalid",
            ):
                StageAuthorizationReplayRegistry(
                    root / "replay.sqlite3",
                    registry_id="stage-replay-phillip-eurusd-v1",
                    registry_key_id="replay-key-v1",
                    hmac_secret=self.replay_secret,
                    expected_checkpoint=tampered,
                    checkpoint_key_provider=lambda _key_id: checkpoint_secret,
                )
            wrong_binding = replace(
                checkpoint,
                registry_id="different-stage-replay-registry",
            ).sign(checkpoint_secret)
            with self.assertRaisesRegex(
                StageAuthorizationIntegrityError,
                "checkpoint binding mismatch",
            ):
                StageAuthorizationReplayRegistry(
                    root / "replay.sqlite3",
                    registry_id="stage-replay-phillip-eurusd-v1",
                    registry_key_id="replay-key-v1",
                    hmac_secret=self.replay_secret,
                    expected_checkpoint=wrong_binding,
                    checkpoint_key_provider=lambda _key_id: checkpoint_secret,
                )

    def test_signed_genesis_checkpoint_anchors_first_production_startup(self) -> None:
        checkpoint_secret = b"c" * 32
        with tempfile.TemporaryDirectory() as directory:
            registry = self._registry(Path(directory))
            checkpoint = registry.create_checkpoint(
                issued_at=self.t0,
                checkpoint_key_id="checkpoint-key-v1",
                checkpoint_secret=checkpoint_secret,
            )
            self.assertEqual(0, checkpoint.event_count)
            self.assertEqual("GENESIS", checkpoint.last_authorization_id)
            self.assertEqual("0" * 64, checkpoint.head_sha256)
            self.assertIs(
                checkpoint,
                registry.verify_checkpoint(
                    checkpoint,
                    key_provider=lambda _key_id: checkpoint_secret,
                    require_current=True,
                ),
            )

    def test_genesis_checkpoint_rejects_non_genesis_facts(self) -> None:
        with self.assertRaisesRegex(ValueError, "genesis replay checkpoint facts"):
            StageReplayCheckpoint(
                registry_id="stage-replay-phillip-eurusd-v1",
                registry_key_id="replay-key-v1",
                registry_key_fingerprint_sha256=digest("registry-key"),
                event_count=0,
                head_sha256=digest("head"),
                authorization_ids_sha256=digest("auths"),
                nonce_hashes_sha256=digest("nonces"),
                last_authorization_id="manual_demo_stage_last",
                last_nonce_sha256=digest("last-nonce"),
                issued_at=self.t0,
                checkpoint_key_id="checkpoint-key-v1",
            )


if __name__ == "__main__":
    unittest.main()
