from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import live_runtime.live_canary_activation_consumption as consumption_module
from live_runtime.live_canary_activation import (
    LiveCanaryActivationIntegrityError,
    LiveCanaryActivationReplayError,
    LiveCanaryReplayRegistry,
    issue_live_canary_activation_authorization,
    issue_live_canary_human_approval,
    verify_consumed_live_canary_activation,
)
from live_runtime.live_canary_activation_consumption import (
    LiveCanaryActivationConsumptionError,
    build_live_canary_replay_registry_profile,
    consume_live_canary_activation_artifact,
    initialize_live_canary_replay_registry,
    load_live_canary_activation_consumption_receipt,
    load_live_canary_replay_registry_initialization_receipt,
    load_live_canary_replay_registry_profile,
    recover_live_canary_activation_consumption_artifact,
    verify_live_canary_activation_consumption_artifact,
    write_live_canary_activation_consumption_artifact_exclusive,
)
from test_live_runtime_demo_auto_soak_cohort import NOW
import test_live_runtime_live_canary_activation as activation_fixture


class LiveCanaryActivationConsumptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root_context = tempfile.TemporaryDirectory()
        self.addCleanup(self.root_context.cleanup)
        self.root = Path(self.root_context.name)
        self.fixture = activation_fixture.LiveCanaryActivationTests(
            "test_ac1_exact_eligible_request_is_canonical_and_deny_only"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.registry_path = self.root / "live-canary-replay.sqlite3"
        self.profile = build_live_canary_replay_registry_profile(
            profile_id="phillip-live-canary-replay-profile-v1",
            binding=self.fixture.binding,
            trust_policy=self.fixture.policy,
            registry_path=self.registry_path,
            registry_id="phillip-live-canary-replay-v1",
            registry_key_id="phillip-live-canary-replay-key-v1",
            expected_registry_key_fingerprint_sha256=hashlib.sha256(
                self.fixture.replay_secret
            ).hexdigest(),
            key_provider=self._key,
        )

    def _key(self, key_id: str) -> bytes:
        providers = (
            self.fixture._gate_key,
            self.fixture.soak.aggregator_key,
            self.fixture._approval_key,
        )
        for provider in providers:
            try:
                return provider(key_id)
            except KeyError:
                pass
        if key_id == self.fixture.policy.promotion_key_id:
            return self.fixture.promotion_secret
        if key_id == self.fixture.policy.deployment_key_id:
            return self.fixture.deployment_secret
        if key_id == self.fixture.policy.replay_checkpoint_key_id:
            return self.fixture.checkpoint_secret
        registry_key_id = (
            self.profile.registry_key_id
            if hasattr(self, "profile")
            else "phillip-live-canary-replay-key-v1"
        )
        if key_id == registry_key_id:
            return self.fixture.replay_secret
        raise KeyError(key_id)

    def _initialize(self):
        return initialize_live_canary_replay_registry(
            profile=self.profile,
            expected_profile_sha256=self.profile.content_sha256,
            registry_path=self.registry_path,
            binding=self.fixture.binding,
            trust_policy=self.fixture.policy,
            key_provider=self._key,
            clock_provider=lambda: NOW,
        )

    def _evidence(self) -> dict[str, object]:
        return {
            "authorization": self.fixture.authorization,
            "trust_policy": self.fixture.policy,
            "soak_receipt": self.fixture.soak_receipt,
            "soak_binding": self.fixture.soak.binding,
            "soak_key_provider": self.fixture.soak.aggregator_key,
            "promotion_evidence": self.fixture.promotion,
            "promotion_key_provider": lambda _key_id: self.fixture.promotion_secret,
            "live_account_alias": "phillip-live-account-alias",
            "broker_eligibility_evidence": self.fixture.eligibility,
            "gate_receipts": self.fixture.gate_receipts,
            "gate_key_provider": self.fixture._gate_key,
            "approval_key_provider": self.fixture._approval_key,
            "deployment_key_provider": lambda _key_id: self.fixture.deployment_secret,
        }

    def _consume(self, predecessor, **overrides):
        values = {
            "profile": self.profile,
            "expected_profile_sha256": self.profile.content_sha256,
            "registry_path": self.registry_path,
            "binding": self.fixture.binding,
            "predecessor_checkpoint": predecessor.checkpoint,
            "registry_key_provider": self._key,
            "checkpoint_key_provider": self._key,
            "clock_provider": lambda: NOW,
            **self._evidence(),
        }
        values.update(overrides)
        return consume_live_canary_activation_artifact(**values)

    def _verify(self, receipt, predecessor, **overrides):
        values = {
            "receipt": receipt,
            "profile": self.profile,
            "expected_profile_sha256": self.profile.content_sha256,
            "registry_path": self.registry_path,
            "binding": self.fixture.binding,
            "predecessor_checkpoint": predecessor.checkpoint,
            "registry_key_provider": self._key,
            "checkpoint_key_provider": self._key,
            "clock_provider": lambda: NOW,
            **self._evidence(),
        }
        values.update(overrides)
        return verify_live_canary_activation_consumption_artifact(**values)

    def test_ac1_profile_is_exact_path_and_authority_bound(self) -> None:
        self.assertEqual(
            self.fixture.binding.binding_sha256,
            self.profile.binding_sha256,
        )
        self.assertEqual(
            self.fixture.policy.policy_sha256,
            self.profile.trust_policy_sha256,
        )
        self.assertFalse(self.profile.live_allowed)
        self.assertEqual("DISABLED", self.profile.order_capability)

        path = self.root / "profile.json"
        write_live_canary_activation_consumption_artifact_exclusive(
            path, self.profile.to_canonical_dict()
        )
        self.assertEqual(self.profile, load_live_canary_replay_registry_profile(path))

        with self.assertRaises(LiveCanaryActivationConsumptionError):
            build_live_canary_replay_registry_profile(
                profile_id="reused-authority-profile-v1",
                binding=self.fixture.binding,
                trust_policy=self.fixture.policy,
                registry_path=self.root / "other.sqlite3",
                registry_id="other-registry-v1",
                registry_key_id=self.fixture.policy.deployment_key_id,
                expected_registry_key_fingerprint_sha256=hashlib.sha256(
                    self.fixture.deployment_secret
                ).hexdigest(),
                key_provider=self._key,
            )

    def test_ac1_strict_profile_loader_rejects_noncanonical_and_extra(self) -> None:
        payload = self.profile.to_canonical_dict()
        payload["unexpected"] = "field"
        extra = self.root / "extra-profile.json"
        extra.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(LiveCanaryActivationConsumptionError):
            load_live_canary_replay_registry_profile(extra)

        duplicate = self.root / "duplicate-profile.json"
        duplicate.write_text('{"schema_version":"x","schema_version":"y"}\n')
        with self.assertRaises(LiveCanaryActivationConsumptionError):
            load_live_canary_replay_registry_profile(duplicate)

    def test_ac1_registry_path_traversal_is_rejected_before_credentials(self) -> None:
        provider = mock.Mock(side_effect=AssertionError("credential accessed"))
        traversal_path = self.root / "intermediate" / ".." / "traversal.sqlite3"

        with self.assertRaises(LiveCanaryActivationConsumptionError) as raised:
            build_live_canary_replay_registry_profile(
                profile_id="traversal-profile-v1",
                binding=self.fixture.binding,
                trust_policy=self.fixture.policy,
                registry_path=traversal_path,
                registry_id="traversal-registry-v1",
                registry_key_id="traversal-registry-key-v1",
                expected_registry_key_fingerprint_sha256="f" * 64,
                key_provider=provider,
            )

        self.assertEqual(
            "REPLAY_REGISTRY_PATH_TRAVERSAL",
            raised.exception.reason_code,
        )
        provider.assert_not_called()

    def test_nfr_s1_authority_fingerprints_use_constant_time_comparison(self) -> None:
        registry_fingerprint = hashlib.sha256(self.fixture.replay_secret).hexdigest()
        original = consumption_module.hmac.compare_digest

        with mock.patch.object(
            consumption_module.hmac,
            "compare_digest",
            wraps=original,
        ) as compared:
            build_live_canary_replay_registry_profile(
                profile_id="constant-time-profile-v1",
                binding=self.fixture.binding,
                trust_policy=self.fixture.policy,
                registry_path=self.root / "constant-time.sqlite3",
                registry_id="constant-time-registry-v1",
                registry_key_id=self.profile.registry_key_id,
                expected_registry_key_fingerprint_sha256=registry_fingerprint,
                key_provider=self._key,
            )

        compared_pairs = {call.args[:2] for call in compared.call_args_list}
        for authority_fingerprint in self.fixture.policy.authority_key_fingerprints:
            self.assertIn(
                (registry_fingerprint, authority_fingerprint),
                compared_pairs,
            )

    def test_ac2_initialization_creates_signed_genesis_and_is_exclusive(self) -> None:
        receipt = self._initialize()
        self.assertTrue(self.registry_path.is_file())
        self.assertEqual(0, receipt.checkpoint.event_count)
        self.assertTrue(
            receipt.checkpoint.verify_signature(self.fixture.checkpoint_secret)
        )
        self.assertFalse(receipt.activation_authorized)
        with self.assertRaises(LiveCanaryActivationConsumptionError):
            self._initialize()

        path = self.root / "initialization.json"
        write_live_canary_activation_consumption_artifact_exclusive(
            path, receipt.to_canonical_dict()
        )
        self.assertEqual(
            receipt,
            load_live_canary_replay_registry_initialization_receipt(path),
        )

    def test_ac3_one_use_consumption_and_receipt_round_trip(self) -> None:
        predecessor = self._initialize()
        receipt = self._consume(predecessor)
        self.assertTrue(receipt.validation.valid)
        self.assertTrue(receipt.validation.consumed_once)
        self.assertEqual(1, receipt.checkpoint.event_count)
        self.assertEqual(
            predecessor.checkpoint.content_sha256,
            receipt.predecessor_checkpoint_sha256,
        )
        self.assertEqual("DISABLED", receipt.order_capability)

        path = self.root / "consumption.json"
        write_live_canary_activation_consumption_artifact_exclusive(
            path, receipt.to_canonical_dict()
        )
        self.assertEqual(
            receipt,
            load_live_canary_activation_consumption_receipt(path),
        )
        with self.assertRaises(LiveCanaryActivationConsumptionError):
            self._consume(predecessor)

    def test_ac4_predecessor_must_be_current_before_mutation(self) -> None:
        predecessor = self._initialize()
        receipt = self._consume(predecessor)
        second_fixture = activation_fixture.LiveCanaryActivationTests(
            "test_ac1_exact_eligible_request_is_canonical_and_deny_only"
        )
        second_fixture.setUp()
        self.addCleanup(second_fixture.doCleanups)
        with self.assertRaises(LiveCanaryActivationConsumptionError):
            self._consume(
                predecessor,
                authorization=replace(
                    second_fixture.authorization,
                    request=replace(
                        second_fixture.authorization.request,
                        nonce="second-live-canary-authorization-nonce-v1",
                    ),
                ),
            )
        registry = LiveCanaryReplayRegistry(
            self.registry_path,
            binding=self.fixture.binding,
            trust_policy=self.fixture.policy,
            registry_id=self.profile.registry_id,
            key_id=self.profile.registry_key_id,
            key_fingerprint_sha256=self.profile.registry_key_fingerprint_sha256,
            key_provider=self._key,
        )
        self.assertEqual(receipt.checkpoint.event_count, registry.event_count)

    def test_ac4_competing_authorization_cannot_append_from_stale_predecessor(
        self,
    ) -> None:
        predecessor = self._initialize()
        racing_request = self.fixture._request(
            nonce="phillip-live-canary-competing-request-nonce-v1"
        )
        racing_approvals = tuple(
            issue_live_canary_human_approval(
                racing_request,
                trust_policy=self.fixture.policy,
                role=role,
                approver_identity=self.fixture.approver_identities[role],
                key_id=f"{role.lower().replace('_', '-')}-approval-key-v1",
                approved_at=NOW,
                secret=secret,
            )
            for role, secret in sorted(self.fixture.approval_secrets.items())
        )
        racing_authorization = issue_live_canary_activation_authorization(
            racing_request,
            approvals=racing_approvals,
            trust_policy=self.fixture.policy,
            approval_key_provider=self.fixture._approval_key,
            deployment_signer_key_id=self.fixture.policy.deployment_key_id,
            deployment_signing_secret=self.fixture.deployment_secret,
            issued_at=NOW,
            clock_provider=lambda: NOW,
        )
        original = consumption_module.validate_and_consume_live_canary_activation
        raced = False

        def race_then_consume(**kwargs: object):
            nonlocal raced
            if not raced:
                raced = True
                competing = dict(kwargs)
                competing["authorization"] = racing_authorization
                competing_result = original(**competing)
                self.assertTrue(competing_result.valid)
                self.assertTrue(competing_result.consumed_once)
            return original(**kwargs)

        with mock.patch.object(
            consumption_module,
            "validate_and_consume_live_canary_activation",
            side_effect=race_then_consume,
        ):
            with self.assertRaises(LiveCanaryActivationConsumptionError):
                self._consume(predecessor)

        registry = LiveCanaryReplayRegistry(
            self.registry_path,
            binding=self.fixture.binding,
            trust_policy=self.fixture.policy,
            registry_id=self.profile.registry_id,
            key_id=self.profile.registry_key_id,
            key_fingerprint_sha256=self.profile.registry_key_fingerprint_sha256,
            key_provider=self._key,
        )
        self.assertEqual(1, registry.event_count)

    def test_ac5_independent_verify_is_read_only_and_exact(self) -> None:
        predecessor = self._initialize()
        receipt = self._consume(predecessor)
        before = receipt.checkpoint.event_count
        verified = self._verify(receipt, predecessor)
        self.assertEqual(receipt, verified)
        registry = LiveCanaryReplayRegistry(
            self.registry_path,
            binding=self.fixture.binding,
            trust_policy=self.fixture.policy,
            registry_id=self.profile.registry_id,
            key_id=self.profile.registry_key_id,
            key_fingerprint_sha256=self.profile.registry_key_fingerprint_sha256,
            key_provider=self._key,
        )
        self.assertEqual(before, registry.event_count)

        tampered_payload = receipt.to_canonical_dict()
        tampered_payload["predecessor_checkpoint_sha256"] = "f" * 64
        tampered_path = self.root / "tampered-consumption.json"
        write_live_canary_activation_consumption_artifact_exclusive(
            tampered_path, tampered_payload
        )
        tampered = load_live_canary_activation_consumption_receipt(tampered_path)
        with self.assertRaises(LiveCanaryActivationConsumptionError):
            self._verify(tampered, predecessor)

    def test_ac6_recovery_after_publication_failure_is_deterministic(self) -> None:
        predecessor = self._initialize()
        expected = self._consume(predecessor)
        recovered = recover_live_canary_activation_consumption_artifact(
            profile=self.profile,
            expected_profile_sha256=self.profile.content_sha256,
            registry_path=self.registry_path,
            binding=self.fixture.binding,
            predecessor_checkpoint=predecessor.checkpoint,
            registry_key_provider=self._key,
            checkpoint_key_provider=self._key,
            clock_provider=lambda: NOW,
            **self._evidence(),
        )
        self.assertEqual(expected, recovered)
        self.assertEqual(expected.content_sha256, recovered.content_sha256)

        after_expiry = recover_live_canary_activation_consumption_artifact(
            profile=self.profile,
            expected_profile_sha256=self.profile.content_sha256,
            registry_path=self.registry_path,
            binding=self.fixture.binding,
            predecessor_checkpoint=predecessor.checkpoint,
            registry_key_provider=self._key,
            checkpoint_key_provider=self._key,
            clock_provider=lambda: NOW + timedelta(hours=1),
            **self._evidence(),
        )
        self.assertEqual(expected, after_expiry)

    def test_ac6_recovery_rejects_missing_or_non_head_event(self) -> None:
        predecessor = self._initialize()
        with self.assertRaises(LiveCanaryActivationConsumptionError):
            recover_live_canary_activation_consumption_artifact(
                profile=self.profile,
                expected_profile_sha256=self.profile.content_sha256,
                registry_path=self.registry_path,
                binding=self.fixture.binding,
                predecessor_checkpoint=predecessor.checkpoint,
                registry_key_provider=self._key,
                checkpoint_key_provider=self._key,
                clock_provider=lambda: NOW,
                **self._evidence(),
            )

    def test_ac7_existing_output_is_preserved(self) -> None:
        path = self.root / "existing.json"
        path.write_bytes(b"owner-evidence")
        with self.assertRaises(FileExistsError):
            write_live_canary_activation_consumption_artifact_exclusive(
                path, self.profile.to_canonical_dict()
            )
        self.assertEqual(b"owner-evidence", path.read_bytes())

    def test_ac5_verification_latency_is_bounded(self) -> None:
        predecessor = self._initialize()
        receipt = self._consume(predecessor)
        started = time.perf_counter()
        for _ in range(10):
            self._verify(receipt, predecessor)
        elapsed_ms = (time.perf_counter() - started) * 1000 / 10
        self.assertLess(elapsed_ms, 100.0)

    def test_core_consumed_validation_recovery_is_sealed_and_read_only(self) -> None:
        registry = self.fixture._registry("core-verification.sqlite3")
        validation = self.fixture._validate(registry)
        event_count = registry.event_count
        recovered = verify_consumed_live_canary_activation(
            replay_registry=registry,
            now=NOW,
            clock_provider=lambda: NOW,
            **self._evidence(),
        )
        self.assertEqual(validation, recovered)
        self.assertEqual(event_count, registry.event_count)

        empty = self.fixture._registry("core-empty.sqlite3")
        with self.assertRaises(LiveCanaryActivationReplayError):
            verify_consumed_live_canary_activation(
                replay_registry=empty,
                now=NOW,
                clock_provider=lambda: NOW,
                **self._evidence(),
            )

    def test_profile_failure_precedes_credential_access(self) -> None:
        provider = mock.Mock(side_effect=AssertionError("credential accessed"))
        with self.assertRaises(LiveCanaryActivationConsumptionError):
            initialize_live_canary_replay_registry(
                profile=self.profile,
                expected_profile_sha256="f" * 64,
                registry_path=self.registry_path,
                binding=self.fixture.binding,
                trust_policy=self.fixture.policy,
                key_provider=provider,
                clock_provider=lambda: NOW,
            )
        provider.assert_not_called()

    def test_initialization_validates_both_keys_before_creating_registry(self) -> None:
        def missing_checkpoint(key_id: str) -> bytes:
            if key_id == self.profile.registry_key_id:
                return self.fixture.replay_secret
            raise KeyError(key_id)

        with self.assertRaises(LiveCanaryActivationConsumptionError):
            initialize_live_canary_replay_registry(
                profile=self.profile,
                expected_profile_sha256=self.profile.content_sha256,
                registry_path=self.registry_path,
                binding=self.fixture.binding,
                trust_policy=self.fixture.policy,
                key_provider=missing_checkpoint,
                clock_provider=lambda: NOW,
            )
        self.assertFalse(self.registry_path.exists())


if __name__ == "__main__":
    unittest.main()
