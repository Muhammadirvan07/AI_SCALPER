from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import hashlib
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import execution_policy
from live_runtime.live_canary_activation import (
    LIVE_CANARY_GATE_DOMAINS,
    LiveCanaryActivationBindingError,
    LiveCanaryActivationError,
    LiveCanaryActivationIntegrityError,
    LiveCanaryBinding,
    LiveCanaryBrokerEligibilityEvidence,
    LiveCanaryReplayRegistry,
    LiveCanaryTrustPolicy,
    build_live_canary_activation_request,
    issue_live_canary_activation_authorization,
    issue_live_canary_gate_receipt,
    issue_live_canary_human_approval,
    validate_and_consume_live_canary_activation,
)
from live_runtime.promotion_evidence import PromotionEvidenceReceipt
from test_live_runtime_demo_auto_soak_cohort import (
    Fixture as SoakFixture,
    MODEL,
    NOW,
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class LiveCanaryActivationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.gate_secrets = {
            domain: f"live-canary-gate-{domain}-secret-material-padding-32".encode()
            for domain in LIVE_CANARY_GATE_DOMAINS
        }
        self.gate_key_ids = {
            domain: f"live-canary-{domain.lower().replace('_', '-')}-key-v1"
            for domain in LIVE_CANARY_GATE_DOMAINS
        }
        self.promotion_secret = b"live-promotion-authority-secret-material-v1"
        self.approval_secrets = {
            "RISK_OWNER": b"risk-owner-live-canary-secret-material-v1",
            "OPERATIONS_OWNER": b"operations-owner-live-secret-material-v1",
            "COMPLIANCE_OWNER": b"compliance-owner-live-secret-material-v1",
        }
        self.approver_identities = {
            role: f"reviewer:{role.lower()}" for role in self.approval_secrets
        }
        self.deployment_secret = b"live-deployment-authority-secret-material-v1"
        self.checkpoint_secret = b"live-replay-checkpoint-secret-material-v1"
        self.policy = LiveCanaryTrustPolicy(
            policy_id="phillip-xauusd-live-canary-policy-v1",
            domain_key_allowlist=tuple(
                (
                    domain,
                    self.gate_key_ids[domain],
                    hashlib.sha256(self.gate_secrets[domain]).hexdigest(),
                )
                for domain in sorted(LIVE_CANARY_GATE_DOMAINS)
            ),
            promotion_key_id="live-promotion-key-v1",
            promotion_key_fingerprint_sha256=hashlib.sha256(
                self.promotion_secret
            ).hexdigest(),
            approval_key_allowlist=tuple(
                (
                    role,
                    digest(self.approver_identities[role]),
                    f"{role.lower().replace('_', '-')}-approval-key-v1",
                    hashlib.sha256(self.approval_secrets[role]).hexdigest(),
                )
                for role in sorted(self.approval_secrets)
            ),
            deployment_key_id="live-deployment-authority-key-v1",
            deployment_key_fingerprint_sha256=hashlib.sha256(
                self.deployment_secret
            ).hexdigest(),
            replay_checkpoint_key_id="live-replay-checkpoint-key-v1",
            replay_checkpoint_key_fingerprint_sha256=hashlib.sha256(
                self.checkpoint_secret
            ).hexdigest(),
        )
        self.soak = SoakFixture()
        self.soak_receipt = self.soak.aggregate()
        demo = self.soak.binding
        self.binding = LiveCanaryBinding(
            broker_id=demo.broker_id,
            demo_account_alias_sha256=demo.account_alias_sha256,
            demo_server=demo.broker_server,
            demo_journal_sha256=demo.journal_sha256,
            demo_commit_sha=demo.commit_sha,
            demo_config_sha256=demo.config_sha256,
            demo_dependency_lock_sha256=demo.dependency_lock_sha256,
            demo_runtime_profile_sha256=demo.runtime_profile_sha256,
            demo_release_manifest_sha256=demo.release_manifest_sha256,
            demo_session_calendar_sha256=demo.session_calendar_sha256,
            demo_broker_spec_set_sha256=demo.broker_spec_set_sha256,
            soak_cohort_binding_sha256=demo.binding_sha256,
            live_account_alias_sha256=digest("phillip-live-account-alias"),
            live_server="PhillipSecuritiesJP-LIVE",
            live_journal_sha256=digest("phillip-live-journal"),
            live_commit_sha="e" * 40,
            live_config_sha256=digest("phillip-live-config"),
            live_dependency_lock_sha256=digest("phillip-live-dependency-lock"),
            live_broker_spec_sha256=digest("phillip-live-xau-spec"),
            live_session_calendar_sha256=digest("phillip-live-calendar"),
            live_runtime_profile_sha256=digest("phillip-live-runtime-profile"),
            live_release_manifest_sha256=digest("phillip-live-release-manifest"),
            model_artifact_sha256=MODEL,
            champion_archive_sha256=digest("champion-archive"),
            champion_package_identity_sha256=digest("champion-package"),
            champion_training_snapshot_sha256=digest("champion-snapshot"),
            champion_git_tree="a" * 40,
            champion_runtime_binding_sha256=digest("champion-runtime"),
            acceptance_policy_sha256=self.policy.policy_sha256,
            symbol="XAUUSD",
            strategy="BREAKOUT",
            lane_id=f"XAUUSD:BREAKOUT:{digest('phillip-live-config')}",
        )
        self.eligibility = LiveCanaryBrokerEligibilityEvidence(
            broker_id=self.binding.broker_id,
            broker_legal_name="Phillip Securities Japan, Ltd.",
            operating_jurisdiction="JP",
            registration_authority="JAPAN-FSA",
            registration_identifier="KANTO-KINSHO-127",
            live_server=self.binding.live_server,
            symbol=self.binding.symbol,
            regulatory_evidence_sha256=digest("phillip-regulatory-evidence"),
            compliance_approval_sha256=digest("phillip-compliance-approval"),
            legal_approval_sha256=digest("phillip-legal-approval"),
            reviewed_at=NOW - timedelta(days=1),
            expires_at=NOW + timedelta(days=14),
        )
        self.promotion = self._promotion()
        self.gate_receipts = self._gate_receipts()
        self.request = self._request()
        self.approvals = tuple(
            issue_live_canary_human_approval(
                self.request,
                trust_policy=self.policy,
                role=role,
                approver_identity=self.approver_identities[role],
                key_id=f"{role.lower().replace('_', '-')}-approval-key-v1",
                approved_at=NOW,
                secret=secret,
            )
            for role, secret in sorted(self.approval_secrets.items())
        )
        self.authorization = issue_live_canary_activation_authorization(
            self.request,
            approvals=self.approvals,
            trust_policy=self.policy,
            approval_key_provider=self._approval_key,
            deployment_signer_key_id="live-deployment-authority-key-v1",
            deployment_signing_secret=self.deployment_secret,
            issued_at=NOW,
            clock_provider=lambda: NOW,
        )
        self.replay_secret = b"live-canary-replay-registry-secret-material-v1"

    def _promotion(self, **overrides: object) -> PromotionEvidenceReceipt:
        values: dict[str, object] = {
            "mode": "LIVE",
            "lane_id": self.binding.lane_id,
            "symbol": self.binding.symbol,
            "strategy": self.binding.strategy,
            "account_alias_sha256": self.binding.live_account_alias_sha256,
            "server": self.binding.live_server,
            "journal_sha256": self.binding.live_journal_sha256,
            "commit_sha": self.binding.live_commit_sha,
            "config_sha256": self.binding.live_config_sha256,
            "model_artifact_sha256": self.binding.model_artifact_sha256,
            "champion_archive_sha256": self.binding.champion_archive_sha256,
            "champion_package_identity_sha256": (
                self.binding.champion_package_identity_sha256
            ),
            "champion_training_snapshot_sha256": (
                self.binding.champion_training_snapshot_sha256
            ),
            "champion_git_tree": self.binding.champion_git_tree,
            "champion_runtime_binding_sha256": (
                self.binding.champion_runtime_binding_sha256
            ),
            "quality_corpus_sha256": digest("live-quality-corpus"),
            "bootstrap_receipt_sha256": digest("live-bootstrap-receipt"),
            "lane_readiness_sha256": digest("live-lane-readiness"),
            "lane_evidence_sha256": digest("live-lane-evidence"),
            "evidence_store_receipt_sha256": digest("live-evidence-store"),
            "runtime_parity_receipt_sha256": digest("live-runtime-parity"),
            "build_manifest_sha256": self.binding.live_release_manifest_sha256,
            "issued_at": NOW - timedelta(seconds=1),
            "expires_at": NOW + timedelta(minutes=4),
            "signer_key_id": "live-promotion-key-v1",
            "nonce": "live-promotion-nonce-v1",
        }
        values.update(overrides)
        return PromotionEvidenceReceipt(**values).sign(self.promotion_secret)

    def _gate_receipts(self, *, legal_evidence_sha256: str | None = None):
        legal_hash = legal_evidence_sha256 or self.eligibility.content_sha256
        return tuple(
            issue_live_canary_gate_receipt(
                self.binding,
                self.policy,
                domain=domain,
                evidence_sha256=(
                    legal_hash
                    if domain == "LEGAL_COMPLIANCE"
                    else digest(f"external-gate:{domain}")
                ),
                issued_at=NOW - timedelta(minutes=1),
                expires_at=NOW + timedelta(minutes=4),
                issuer_id=f"issuer:{domain.lower()}",
                key_id=self.gate_key_ids[domain],
                secret=self.gate_secrets[domain],
            )
            for domain in sorted(LIVE_CANARY_GATE_DOMAINS)
        )

    def _gate_key(self, key_id: str) -> bytes:
        for domain, expected in self.gate_key_ids.items():
            if key_id == expected:
                return self.gate_secrets[domain]
        raise KeyError(key_id)

    def _approval_key(self, key_id: str) -> bytes:
        for role, secret in self.approval_secrets.items():
            if key_id == f"{role.lower().replace('_', '-')}-approval-key-v1":
                return secret
        raise KeyError(key_id)

    def _request(self, **overrides: object):
        values: dict[str, object] = {
            "binding": self.binding,
            "trust_policy": self.policy,
            "soak_receipt": self.soak_receipt,
            "soak_binding": self.soak.binding,
            "soak_key_provider": self.soak.aggregator_key,
            "promotion_evidence": self.promotion,
            "promotion_key_provider": lambda _key_id: self.promotion_secret,
            "live_account_alias": "phillip-live-account-alias",
            "broker_eligibility_evidence": self.eligibility,
            "gate_receipts": self.gate_receipts,
            "gate_key_provider": self._gate_key,
            "issued_at": NOW,
            "expires_at": NOW + timedelta(minutes=3),
            "nonce": "phillip-live-canary-request-nonce-v1",
            "clock_provider": lambda: NOW,
        }
        values.update(overrides)
        return build_live_canary_activation_request(**values)

    def _registry(
        self,
        name: str = "live-canary-replay.sqlite3",
        **overrides: object,
    ):
        values: dict[str, object] = {
            "binding": self.binding,
            "trust_policy": self.policy,
            "registry_id": "phillip-live-canary-replay-v1",
            "key_id": "phillip-live-canary-replay-key-v1",
            "key_fingerprint_sha256": hashlib.sha256(
                self.replay_secret
            ).hexdigest(),
            "key_provider": lambda _key_id: self.replay_secret,
        }
        values.update(overrides)
        return LiveCanaryReplayRegistry(
            Path(self.root.name) / name,
            **values,
        )

    def _validate(self, registry, **overrides: object):
        values: dict[str, object] = {
            "authorization": self.authorization,
            "trust_policy": self.policy,
            "soak_receipt": self.soak_receipt,
            "soak_binding": self.soak.binding,
            "soak_key_provider": self.soak.aggregator_key,
            "promotion_evidence": self.promotion,
            "promotion_key_provider": lambda _key_id: self.promotion_secret,
            "live_account_alias": "phillip-live-account-alias",
            "broker_eligibility_evidence": self.eligibility,
            "gate_receipts": self.gate_receipts,
            "gate_key_provider": self._gate_key,
            "approval_key_provider": self._approval_key,
            "deployment_key_provider": lambda _key_id: self.deployment_secret,
            "replay_registry": registry,
            "now": NOW,
            "clock_provider": lambda: NOW,
        }
        values.update(overrides)
        return validate_and_consume_live_canary_activation(**values)

    def test_ac1_exact_eligible_request_is_canonical_and_deny_only(self):
        request = self.request
        self.assertEqual(self.binding.binding_sha256, request.binding.binding_sha256)
        self.assertEqual(
            self.soak_receipt.content_sha256,
            request.soak_cohort_receipt_sha256,
        )
        self.assertEqual(
            self.eligibility.content_sha256,
            request.broker_eligibility_evidence_sha256,
        )
        self.assertEqual("live-canary-activation-request-v2", request.schema_version)
        self.assertEqual(tuple(sorted(LIVE_CANARY_GATE_DOMAINS)), tuple(
            domain for domain, _receipt_hash in request.gate_receipt_sha256_by_domain
        ))
        self.assertFalse(request.live_allowed)
        self.assertFalse(request.execution_authorized)
        self.assertFalse(request.activation_authorized)
        self.assertEqual("DISABLED", request.order_capability)
        self.assertEqual(0.01, request.max_lot)
        self.assertEqual(1, request.max_concurrent_positions)

    def test_ac2_incomplete_stale_or_mismatched_soak_is_rejected(self):
        incomplete = SoakFixture(counts={"AUDUSD": 1, "EURUSD": 1, "USDJPY": 1, "XAUUSD": 1})
        with self.assertRaisesRegex(LiveCanaryActivationError, "SOAK"):
            self._request(
                soak_receipt=incomplete.aggregate(),
                soak_binding=incomplete.binding,
                soak_key_provider=incomplete.aggregator_key,
            )
        with self.assertRaisesRegex(LiveCanaryActivationError, "SOAK"):
            self._request(
                issued_at=NOW + timedelta(minutes=6),
                expires_at=NOW + timedelta(minutes=9),
                clock_provider=lambda: NOW + timedelta(minutes=6),
            )
        swapped = replace(
            self.binding,
            demo_journal_sha256=digest("swapped-demo-journal"),
        )
        with self.assertRaisesRegex(LiveCanaryActivationBindingError, "SOAK"):
            self._request(binding=swapped)

    def test_ac3_live_promotion_must_match_every_live_and_champion_pin(self):
        for field, value in (
            ("mode", "DEMO_AUTO"),
            ("server", "Other-Live-Server"),
            ("journal_sha256", digest("other-live-journal")),
            ("champion_archive_sha256", digest("other-champion")),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(
                LiveCanaryActivationError, "PROMOTION"
            ):
                self._request(promotion_evidence=self._promotion(**{field: value}))
        rogue_secret = b"rogue-live-promotion-secret-material-padding-v1"
        rogue = replace(
            self.promotion,
            signature_hmac_sha256="",
        ).sign(rogue_secret)
        with self.assertRaisesRegex(LiveCanaryActivationError, "PROMOTION"):
            self._request(
                promotion_evidence=rogue,
                promotion_key_provider=lambda _key_id: rogue_secret,
            )

    def test_ac4_gate_policy_is_exact_and_all_receipts_are_authenticated(self):
        with self.assertRaisesRegex(LiveCanaryActivationError, "GATE"):
            self._request(gate_receipts=self.gate_receipts[:-1])
        tampered = replace(
            self.gate_receipts[0],
            evidence_sha256=digest("tampered-gate-evidence"),
        )
        with self.assertRaisesRegex(LiveCanaryActivationError, "GATE"):
            self._request(gate_receipts=(tampered,) + self.gate_receipts[1:])
        entries = list(self.policy.domain_key_allowlist)
        entries[1] = (entries[1][0], entries[0][1], entries[0][2])
        with self.assertRaises(ValueError):
            replace(
                self.policy,
                policy_id="invalid-reused-key-policy",
                domain_key_allowlist=tuple(entries),
            )

    def test_ac5_human_roles_and_deployment_authority_are_distinct(self):
        self.assertFalse(self.authorization.live_allowed)
        self.assertFalse(self.authorization.execution_authorized)
        self.assertEqual("DISABLED", self.authorization.order_capability)
        duplicate = (self.approvals[0], self.approvals[0], self.approvals[2])
        with self.assertRaisesRegex(LiveCanaryActivationError, "APPROVAL"):
            issue_live_canary_activation_authorization(
                self.request,
                approvals=duplicate,
                trust_policy=self.policy,
                approval_key_provider=self._approval_key,
                deployment_signer_key_id="live-deployment-authority-key-v1",
                deployment_signing_secret=self.deployment_secret,
                issued_at=NOW,
                clock_provider=lambda: NOW,
            )
        with self.assertRaisesRegex(LiveCanaryActivationError, "APPROVAL"):
            issue_live_canary_human_approval(
                self.request,
                trust_policy=self.policy,
                role="RISK_OWNER",
                approver_identity="untrusted:risk-owner",
                key_id="untrusted-risk-owner-key-v1",
                approved_at=NOW,
                secret=b"untrusted-risk-owner-secret-material-padding-v1",
            )
        with self.assertRaisesRegex(LiveCanaryActivationError, "DEPLOYMENT"):
            issue_live_canary_activation_authorization(
                self.request,
                approvals=self.approvals,
                trust_policy=self.policy,
                approval_key_provider=self._approval_key,
                deployment_signer_key_id=self.approvals[0].key_id,
                deployment_signing_secret=self.approval_secrets["RISK_OWNER"],
                issued_at=NOW,
                clock_provider=lambda: NOW,
            )

    def test_ac6_authorization_is_consumed_exactly_once(self):
        registry = self._registry()
        first = self._validate(registry)
        second = self._validate(registry)
        self.assertTrue(first.valid)
        self.assertTrue(first.consumed_once)
        self.assertFalse(second.valid)
        self.assertFalse(second.consumed_once)
        self.assertEqual(
            ("LIVE_CANARY_AUTHORIZATION_REPLAYED",), second.reason_codes
        )
        self.assertFalse(first.live_allowed)
        self.assertFalse(first.execution_authorized)

    def test_ac6_authorization_remains_valid_after_issuance_clock_instant(self):
        registry = self._registry("delayed.sqlite3")
        checked = NOW + timedelta(minutes=1)
        result = self._validate(
            registry,
            now=checked,
            clock_provider=lambda: checked,
        )
        self.assertTrue(result.valid)
        self.assertTrue(result.consumed_once)

    def test_ac6_untrusted_deployment_authority_is_rejected_at_validation(self):
        rogue_secret = b"rogue-live-deployment-secret-material-padding-v1"
        forged = replace(
            self.authorization,
            deployment_signer_key_id="rogue-deployment-authority-key-v1",
            deployment_signer_key_fingerprint_sha256=hashlib.sha256(
                rogue_secret
            ).hexdigest(),
            signature_hmac_sha256="",
        ).sign(rogue_secret)
        result = self._validate(
            self._registry("rogue-deployment.sqlite3"),
            authorization=forged,
            deployment_key_provider=lambda _key_id: rogue_secret,
        )
        self.assertFalse(result.valid)
        self.assertIn(
            "LIVE_CANARY_DEPLOYMENT_SIGNATURE_INVALID",
            result.reason_codes,
        )

    def test_ac6_concurrent_consumers_produce_one_success(self):
        registry = self._registry("concurrent.sqlite3")
        barrier = threading.Barrier(2)
        results = []

        def worker() -> None:
            barrier.wait()
            results.append(self._validate(registry))

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(2, len(results))
        self.assertEqual(1, sum(result.valid for result in results))
        self.assertEqual(1, registry.event_count)

    def test_ac7_registry_tamper_fails_closed(self):
        registry = self._registry("tamper.sqlite3")
        connection = sqlite3.connect(registry.path)
        try:
            connection.execute("DROP TRIGGER live_canary_events_no_update")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(LiveCanaryActivationIntegrityError):
            self._validate(registry)

    def test_ac7_same_name_noop_trigger_and_reopen_fail_closed(self):
        name = "noop-trigger.sqlite3"
        registry = self._registry(name)
        connection = sqlite3.connect(registry.path)
        try:
            connection.execute("DROP TRIGGER live_canary_events_no_update")
            connection.execute(
                """
                CREATE TRIGGER live_canary_events_no_update
                BEFORE UPDATE ON live_canary_events BEGIN SELECT 1; END
                """
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(LiveCanaryActivationIntegrityError):
            self._validate(registry)
        with self.assertRaises(LiveCanaryActivationIntegrityError):
            self._registry(name)

    def test_ac7_offhost_checkpoint_detects_registry_rollback(self):
        registry = self._registry("checkpoint-source.sqlite3")
        self.assertTrue(self._validate(registry).valid)
        checkpoint = registry.create_checkpoint(
            issued_at=NOW + timedelta(seconds=1),
            checkpoint_secret=self.checkpoint_secret,
        )
        registry.verify_checkpoint(
            checkpoint,
            key_provider=lambda _key_id: self.checkpoint_secret,
            require_current=True,
        )
        self._registry(
            "checkpoint-source.sqlite3",
            expected_checkpoint=checkpoint,
            checkpoint_key_provider=lambda _key_id: self.checkpoint_secret,
        )
        rolled_back = self._registry("checkpoint-rollback.sqlite3")
        with self.assertRaises(LiveCanaryActivationIntegrityError):
            rolled_back.verify_checkpoint(
                checkpoint,
                key_provider=lambda _key_id: self.checkpoint_secret,
            )

    def test_ac8_module_is_static_and_checked_in_live_lock_remains_false(self):
        source = Path("live_runtime/live_canary_activation.py").read_text(
            encoding="utf-8"
        )
        forbidden = (
            "MetaTrader5",
            "order_send",
            "mt5_adapter",
            "evidence_credentials",
            "subprocess",
            "socket",
            "requests",
            "urllib",
        )
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, source)
        self.assertIs(False, execution_policy.LIVE_ALLOWED)

    def test_ac9_in_memory_signature_validation_is_bounded(self):
        started = time.perf_counter()
        iterations = 10
        for index in range(iterations):
            request = self._request(nonce=f"bounded-request-nonce-{index}")
            self.assertEqual(self.binding.binding_sha256, request.binding.binding_sha256)
            self.assertTrue(
                self.authorization.verify_signature(self.deployment_secret)
            )
            for receipt in self.gate_receipts:
                self.assertTrue(receipt.verify_signature(self._gate_key(receipt.key_id)))
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed / iterations, 0.1)

    def test_ac10_broker_eligibility_identity_scope_and_time_are_exact(self):
        for changes in (
            {"broker_id": "other-broker"},
            {"live_server": "Other-Live-Server"},
            {
                "reviewed_at": NOW - timedelta(days=3),
                "expires_at": NOW - timedelta(days=2),
            },
            {
                "reviewed_at": NOW + timedelta(seconds=1),
                "expires_at": NOW + timedelta(days=1),
            },
        ):
            with self.subTest(changes=changes), self.assertRaisesRegex(
                LiveCanaryActivationError,
                "ELIGIBILITY",
            ):
                self._request(
                    broker_eligibility_evidence=replace(
                        self.eligibility,
                        **changes,
                    )
                )

    def test_ac10_legal_compliance_gate_must_bind_eligibility_hash(self):
        mismatched = self._gate_receipts(
            legal_evidence_sha256=digest("other-eligibility-evidence")
        )
        with self.assertRaisesRegex(
            LiveCanaryActivationBindingError,
            "ELIGIBILITY_GATE_MISMATCH",
        ):
            self._request(gate_receipts=mismatched)

    def test_ac10_ineligible_or_ambiguous_evidence_is_rejected(self):
        with self.assertRaisesRegex(TypeError, "eligibility"):
            self._request(broker_eligibility_evidence=None)
        for changes in (
            {"registration_status": "UNREGISTERED"},
            {"registration_status": "registered"},
            {"eligibility_decision": "DIAGNOSTIC_ONLY"},
            {"eligibility_decision": "eligible_for_live_canary"},
            {"operating_jurisdiction": "jp"},
            {"operating_jurisdiction": "japan"},
            {
                "legal_approval_sha256": (
                    self.eligibility.compliance_approval_sha256
                )
            },
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(self.eligibility, **changes)

    def test_edge_contract_and_provider_inputs_fail_closed(self):
        for changes in (
            {"symbol": "EURUSD"},
            {"live_config_sha256": "0" * 64},
            {"live_account_alias_sha256": self.binding.demo_account_alias_sha256},
            {"live_server": self.binding.demo_server},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(self.binding, **changes)
        with self.assertRaisesRegex(
            LiveCanaryActivationIntegrityError,
            "TRUSTED_CLOCK_MISMATCH",
        ):
            self._request(
                clock_provider=lambda: NOW + timedelta(milliseconds=51)
            )
        with self.assertRaisesRegex(LiveCanaryActivationError, "GATE"):
            self._request(
                gate_key_provider=lambda _key_id: b"wrong-gate-key-material-padding-32"
            )
        with self.assertRaisesRegex(LiveCanaryActivationError, "PROMOTION"):
            self._request(expires_at=NOW + timedelta(minutes=4, seconds=1))

    def test_optimized_focused_suite_runs(self):
        if sys.flags.optimize:
            self.skipTest("already running under optimized mode")
        completed = subprocess.run(
            [
                sys.executable,
                "-O",
                "-B",
                "-m",
                "unittest",
                (
                    "test_live_runtime_live_canary_activation."
                    "LiveCanaryActivationTests."
                    "test_ac1_exact_eligible_request_is_canonical_and_deny_only"
                ),
            ],
            cwd=Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
