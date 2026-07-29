from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import hashlib
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import execution_policy
from live_runtime.live_canary_activation import (
    LiveCanaryBinding,
    issue_live_canary_activation_authorization,
    issue_live_canary_human_approval,
)
from live_runtime.live_canary_prebootstrap_admission import (
    ADMISSION_STATUS,
    LiveCanaryPrebootstrapAdmission,
    LiveCanaryPrebootstrapAdmissionError,
    LiveCanaryRuntimeCandidate,
    assess_live_canary_prebootstrap_admission,
)
from live_runtime.windows_execution_source_bound_candidate import (
    verify_windows_execution_source_bound_candidate,
)
import test_live_runtime_demo_auto_soak_cohort as soak_fixture_module
import test_live_runtime_live_canary_activation as activation_fixture_module
import test_live_runtime_windows_execution_source_bound_candidate as source_fixture_module


SoakFixture = soak_fixture_module.Fixture
NOW = activation_fixture_module.NOW


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class LiveCanaryPrebootstrapAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        fixture = source_fixture_module.WindowsExecutionSourceBoundCandidateTests(
            methodName="runTest"
        )
        fixture.setUp()
        cls.source_fixture = fixture
        output = fixture.root / "prebootstrap-source-bound.zip"
        prepared = fixture.prepare(output)
        cls.source = verify_windows_execution_source_bound_candidate(
            output,
            base_suite_root=fixture.suite_root,
            execution_base_release=fixture.execution_base,
            expected_bound_archive_sha256=prepared.archive_sha256,
            **fixture.verification_pins(),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.source_fixture.doCleanups()
        super().tearDownClass()

    def setUp(self) -> None:
        activation = activation_fixture_module.LiveCanaryActivationTests(
            methodName="runTest"
        )
        activation.setUp()
        self.addCleanup(activation.doCleanups)
        self.activation = activation

        with mock.patch.multiple(
            soak_fixture_module,
            ACCOUNT=digest("phillip-demo-account-alias"),
            JOURNAL=digest("phillip-demo-journal"),
            COMMIT=self.source.git_commit,
            CONFIG=self.source.production_config_sha256,
            MODEL=self.source.champion_model_artifact_sha256,
        ):
            soak = SoakFixture()
            soak.binding = replace(
                soak.binding,
                broker_id="phillip-jp",
                broker_server="PhillipSecuritiesJP-PROD",
                dependency_lock_sha256=digest("phillip-demo-dependency-lock"),
                runtime_profile_sha256=digest("phillip-demo-runtime-profile"),
                release_manifest_sha256=(
                    self.source.configured_release_identity_sha256
                ),
                session_calendar_sha256=digest("phillip-demo-session-calendar"),
            )
            soak.next_source_sequence = 1
            soak.evidence = [
                soak._lane_evidence(
                    member,
                    count=soak._member_count(member),
                )
                for member in soak.members
            ]
            soak.evidence.sort(key=lambda item: item.lane_id)
            activation.soak_receipt = soak.aggregate()
        activation.soak = soak

        self.candidate = self._candidate(activation)
        demo = soak.binding
        activation.binding = LiveCanaryBinding(
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
            live_account_alias_sha256=self.candidate.account_alias_sha256,
            live_server=self.candidate.server,
            live_journal_sha256=self.candidate.journal_sha256,
            live_commit_sha=self.candidate.commit_sha,
            live_config_sha256=self.candidate.content_sha256,
            live_dependency_lock_sha256=(
                self.candidate.dependency_lock_sha256
            ),
            live_broker_spec_sha256=self.candidate.broker_spec_sha256,
            live_session_calendar_sha256=(
                self.candidate.session_calendar_sha256
            ),
            live_runtime_profile_sha256=(
                self.candidate.runtime_profile_sha256
            ),
            live_release_manifest_sha256=(
                self.candidate.release_manifest_sha256
            ),
            model_artifact_sha256=self.candidate.model_artifact_sha256,
            champion_archive_sha256=(
                self.candidate.champion_archive_sha256
            ),
            champion_package_identity_sha256=(
                self.candidate.champion_package_identity_sha256
            ),
            champion_training_snapshot_sha256=(
                self.candidate.champion_training_snapshot_sha256
            ),
            champion_git_tree=self.candidate.champion_git_tree,
            champion_runtime_binding_sha256=(
                self.candidate.champion_runtime_binding_sha256
            ),
            acceptance_policy_sha256=activation.policy.policy_sha256,
            symbol="XAUUSD",
            strategy="BREAKOUT",
            lane_id=(
                f"XAUUSD:BREAKOUT:{self.candidate.content_sha256}"
            ),
        )
        activation.eligibility = replace(
            activation.eligibility,
            broker_id=activation.binding.broker_id,
            broker_legal_name="Phillip Securities Japan, Ltd.",
            live_server=activation.binding.live_server,
        )
        activation.promotion = activation._promotion()
        activation.gate_receipts = activation._gate_receipts()
        activation.request = activation._request()
        activation.approvals = tuple(
            issue_live_canary_human_approval(
                activation.request,
                trust_policy=activation.policy,
                role=role,
                approver_identity=activation.approver_identities[role],
                key_id=(
                    f"{role.lower().replace('_', '-')}-approval-key-v1"
                ),
                approved_at=NOW,
                secret=secret,
            )
            for role, secret in sorted(activation.approval_secrets.items())
        )
        activation.authorization = issue_live_canary_activation_authorization(
            activation.request,
            approvals=activation.approvals,
            trust_policy=activation.policy,
            approval_key_provider=activation._approval_key,
            deployment_signer_key_id=(
                "live-deployment-authority-key-v1"
            ),
            deployment_signing_secret=activation.deployment_secret,
            issued_at=NOW,
            clock_provider=lambda: NOW,
        )
        self.registry = activation._registry("prebootstrap.sqlite3")
        self.validation = activation._validate(self.registry)

    def _candidate(
        self,
        activation: activation_fixture_module.LiveCanaryActivationTests,
    ) -> LiveCanaryRuntimeCandidate:
        source = self.source
        root = r"C:\AI_SCALPER_PRIVATE\phillip-commodity-live-canary"
        return LiveCanaryRuntimeCandidate(
            candidate_id="phillip-commodity-live-canary-window-01",
            broker_id="phillip-jp",
            broker_legal_name="Phillip Securities Japan, Ltd.",
            server="PhillipSecuritiesJP-LIVE",
            account_alias_sha256=digest("phillip-live-account-alias"),
            account_currency="JPY",
            journal_database=root + r"\journal.sqlite3",
            supervisor_database=root + r"\supervisor.sqlite3",
            dependency_lock_file=(
                r"C:\AI_SCALPER\pylock.windows-cp312.toml"
            ),
            symbol_map=(("XAUUSD", "XAUUSD.ps01"),),
            usd_account_currency_symbols=(("USDJPY", "USDJPY.ps01"),),
            journal_sha256=digest("phillip-live-journal-prebootstrap"),
            commit_sha=source.git_commit,
            dependency_lock_sha256=digest("phillip-live-dependency-lock"),
            installed_environment_sha256=digest("phillip-installed-environment"),
            mt5_site_packages_sha256=digest("phillip-mt5-site-packages"),
            mt5_site_packages_tree_sha256=digest("phillip-mt5-site-tree"),
            mt5_distribution_record_sha256=digest("phillip-mt5-record"),
            mt5_module_file_sha256=digest("phillip-mt5-module"),
            mt5_module_relative_path_sha256=digest("phillip-mt5-relative-path"),
            runtime_profile_sha256=digest("phillip-live-runtime-profile"),
            release_manifest_sha256=digest("phillip-live-release-manifest"),
            session_calendar_sha256=digest("phillip-live-session-calendar"),
            broker_spec_sha256=digest("phillip-live-xauusd-broker-spec"),
            live_stage_binding_sha256=digest("phillip-live-stage-binding"),
            activation_policy_sha256=activation.policy.policy_sha256,
            model_artifact_sha256=source.champion_model_artifact_sha256,
            champion_archive_sha256=source.champion_archive_sha256,
            champion_package_identity_sha256=(
                source.champion_package_identity_sha256
            ),
            champion_training_snapshot_sha256=(
                source.champion_training_snapshot_sha256
            ),
            champion_config_sha256=source.champion_config_sha256,
            champion_git_tree=source.git_tree,
            champion_runtime_binding_sha256=(
                source.champion_runtime_binding_sha256
            ),
            demo_source_bound_archive_sha256=source.archive_sha256,
            demo_source_bound_binding_identity_sha256=(
                source.binding_identity_sha256
            ),
            demo_source_archive_sha256=source.source_archive_sha256,
            demo_source_identity_sha256=source.source_identity_sha256,
            demo_production_config_sha256=source.production_config_sha256,
            demo_bootstrap_binding_sha256=source.bootstrap_binding_sha256,
            demo_stage_binding_sha256=source.stage_binding_sha256,
            demo_configured_release_identity_sha256=(
                source.configured_release_identity_sha256
            ),
            demo_configured_archive_sha256=(
                source.configured_archive_sha256
            ),
            demo_execution_factory_template_sha256=(
                source.execution_factory_template_sha256
            ),
            demo_execution_candidate_id=source.candidate_id,
            demo_execution_candidate_content_sha256=(
                source.candidate_content_sha256
            ),
            demo_provider_pack_identity_sha256=(
                source.provider_pack_identity_sha256
            ),
            demo_provider_configuration_sha256=(
                source.provider_configuration_sha256
            ),
            demo_task_definition_sha256=source.task_definition_sha256,
            demo_base_suite_identity_sha256=source.suite_identity_sha256,
            demo_execution_base_archive_sha256=(
                source.execution_base_archive_sha256
            ),
            demo_execution_base_release_identity_sha256=(
                source.execution_base_release_identity_sha256
            ),
            demo_git_commit=source.git_commit,
            demo_git_tree=source.git_tree,
            manual_demo_custodian_trust_sha256=digest(
                "manual-demo-custodian-trust"
            ),
            news_guard_provider_id="phillip-live-news-guard-v1",
            news_guard_key_id="runtime-news-guard-key-v1",
            news_guard_key_fingerprint_sha256=digest("runtime-news-key"),
            news_guard_ruleset_sha256=digest("phillip-news-ruleset"),
            news_guard_blackout_window_sha256=digest("phillip-blackout-window"),
            supervisor_key_id="runtime-supervisor-key-v1",
            supervisor_key_fingerprint_sha256=digest("runtime-supervisor-key"),
            supervisor_checkpoint_key_id=(
                "runtime-supervisor-checkpoint-key-v1"
            ),
            supervisor_checkpoint_key_fingerprint_sha256=digest(
                "runtime-supervisor-checkpoint-key"
            ),
            credential_session_key_id="runtime-credential-session-key-v1",
            credential_session_key_fingerprint_sha256=digest(
                "runtime-credential-session-key"
            ),
            journal_provisioning_key_id=(
                "runtime-journal-provisioning-key-v1"
            ),
            journal_provisioning_key_fingerprint_sha256=digest(
                "runtime-journal-provisioning-key"
            ),
            worm_audit_key_id="runtime-worm-audit-key-v1",
            worm_audit_key_fingerprint_sha256=digest("runtime-worm-key"),
            risk_ledger_id="phillip-live-risk-ledger-v1",
            risk_ledger_key_id="runtime-risk-ledger-key-v1",
            risk_ledger_key_fingerprint_sha256=digest("runtime-risk-key"),
            journal_checkpoint_key_id=(
                "runtime-journal-checkpoint-key-v1"
            ),
            journal_checkpoint_key_fingerprint_sha256=digest(
                "runtime-journal-checkpoint-key"
            ),
            permit_secret_fingerprint_sha256=digest("runtime-permit-secret"),
            magic_number=260729,
            deviation_points=30,
            max_tick_age_seconds=10,
            intent_ttl_seconds=0.5,
        )

    def _assess(self, **overrides: object):
        values: dict[str, object] = {
            "candidate": self.candidate,
            "source_bound_verification": self.source,
            "trust_policy": self.activation.policy,
            "authorization": self.activation.authorization,
            "validation": self.validation,
            "clock_provider": lambda: NOW,
        }
        values.update(overrides)
        return assess_live_canary_prebootstrap_admission(**values)

    def test_ac1_candidate_is_canonical_xau_only_and_deny_only(self):
        self.assertEqual((("XAUUSD", "XAUUSD.ps01"),), self.candidate.symbol_map)
        self.assertEqual(
            (("USDJPY", "USDJPY.ps01"),),
            self.candidate.usd_account_currency_symbols,
        )
        self.assertEqual(0.01, self.candidate.max_lot)
        self.assertEqual(1, self.candidate.max_concurrent_positions)
        self.assertFalse(self.candidate.live_allowed)
        self.assertFalse(self.candidate.execution_authorized)
        self.assertEqual("DISABLED", self.candidate.order_capability)
        self.assertEqual(
            self.candidate.content_sha256,
            self.activation.binding.live_config_sha256,
        )

    def test_ac2_exact_sealed_source_ancestry_is_required(self):
        report = self._assess()
        self.assertEqual(self.source.archive_sha256, report.source_bound_archive_sha256)
        with self.assertRaisesRegex(
            LiveCanaryPrebootstrapAdmissionError,
            "DEMO_SOURCE_BOUND_VERIFICATION_UNSEALED",
        ):
            self._assess(source_bound_verification=object())
        changed = replace(
            self.candidate,
            demo_source_identity_sha256=digest("substituted-source"),
        )
        with self.assertRaisesRegex(
            LiveCanaryPrebootstrapAdmissionError,
            "DEMO_SOURCE_BOUND_MISMATCH",
        ):
            self._assess(candidate=changed)

    def test_ac3_consumed_validation_is_bound_to_exact_authorization(self):
        self.assertTrue(self.validation.valid)
        self.assertTrue(self.validation.consumed_once)
        replayed = self.activation._validate(self.registry)
        self.assertFalse(replayed.valid)
        with self.assertRaisesRegex(
            LiveCanaryPrebootstrapAdmissionError,
            "VALIDATION_NOT_CONSUMED",
        ):
            self._assess(validation=replayed)
        wrong_authorization = replace(
            self.activation.authorization,
            signature_hmac_sha256="1" * 64,
        )
        with self.assertRaisesRegex(
            LiveCanaryPrebootstrapAdmissionError,
            "VALIDATION_BINDING_MISMATCH",
        ):
            self._assess(authorization=wrong_authorization)

    def test_ac4_live_candidate_substitution_fails_closed(self):
        for field_name, value in (
            ("server", "PhillipSecuritiesJP-OTHER"),
            ("journal_sha256", digest("other-live-journal")),
            ("release_manifest_sha256", digest("other-live-release")),
            ("runtime_profile_sha256", digest("other-live-runtime")),
        ):
            with self.subTest(field=field_name), self.assertRaisesRegex(
                LiveCanaryPrebootstrapAdmissionError,
                "RUNTIME_ACTIVATION_BINDING_MISMATCH",
            ):
                self._assess(
                    candidate=replace(
                        self.candidate,
                        **{field_name: value},
                    )
                )

    def test_ac5_runtime_and_activation_authority_keys_are_disjoint(self):
        reused = replace(
            self.candidate,
            news_guard_key_id=self.activation.policy.deployment_key_id,
        )
        with self.assertRaisesRegex(
            LiveCanaryPrebootstrapAdmissionError,
            "AUTHORITY_KEY_REUSE",
        ):
            self._assess(candidate=reused)

    def test_ac6_trusted_clock_must_remain_inside_request_window(self):
        with self.assertRaisesRegex(
            LiveCanaryPrebootstrapAdmissionError,
            "PREBOOTSTRAP_TIME_INVALID",
        ):
            self._assess(
                clock_provider=lambda: (
                    self.activation.request.expires_at
                )
            )
        readings = iter((NOW, NOW - timedelta(microseconds=1)))
        with self.assertRaisesRegex(
            LiveCanaryPrebootstrapAdmissionError,
            "CLOCK_WINDOW_INVALID",
        ):
            self._assess(clock_provider=lambda: next(readings))

    def test_ac7_central_live_lock_must_still_be_false(self):
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            with self.assertRaisesRegex(
                LiveCanaryPrebootstrapAdmissionError,
                "CENTRAL_LIVE_LOCK_NOT_FALSE",
            ):
                self._assess()
        self.assertIs(False, execution_policy.LIVE_ALLOWED)

    def test_ac8_success_report_is_sealed_and_non_authoritative(self):
        report = self._assess()
        self.assertEqual(ADMISSION_STATUS, report.status)
        self.assertTrue(report.central_unlock_required)
        self.assertFalse(report.bootstrap_authorized)
        self.assertFalse(report.live_allowed)
        self.assertFalse(report.execution_authorized)
        self.assertFalse(report.activation_authorized)
        self.assertEqual("DISABLED", report.order_capability)
        with self.assertRaises(TypeError):
            LiveCanaryPrebootstrapAdmission(
                checked_at=NOW,
                candidate_sha256="1" * 64,
                source_bound_verification_sha256="2" * 64,
                source_bound_archive_sha256="3" * 64,
                source_bound_binding_identity_sha256="4" * 64,
                trust_policy_sha256="5" * 64,
                authorization_id="authorization-id",
                authorization_sha256="6" * 64,
                request_sha256="7" * 64,
                activation_binding_sha256="8" * 64,
                validation_sha256="9" * 64,
                live_commit_sha="a" * 40,
                champion_git_tree="b" * 40,
                symbol="XAUUSD",
                max_lot=0.01,
                max_concurrent_positions=1,
            )

    def test_edge_candidate_inputs_fail_closed(self):
        cases = (
            {"symbol_map": (("EURUSD", "EURUSD"),)},
            {"journal_database": "relative.sqlite3"},
            {"dependency_lock_file": r"C:\AI_SCALPER\wrong.lock"},
            {"commit_sha": "A" * 40},
            {"max_tick_age_seconds": True},
            {
                "journal_checkpoint_key_id": (
                    self.candidate.risk_ledger_key_id
                )
            },
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(
                LiveCanaryPrebootstrapAdmissionError
            ):
                replace(self.candidate, **changes)

    def test_ac9_static_surface_and_optimized_mode(self):
        source = Path(
            "live_runtime/live_canary_prebootstrap_admission.py"
        ).read_text(encoding="utf-8")
        forbidden = (
            "order_send",
            "subprocess",
            "socket",
            "requests",
            "urllib",
            "sqlite3",
            "CredentialManager",
            "Popen",
            "create_subprocess",
        )
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, source)
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
                    "test_live_runtime_live_canary_prebootstrap_admission."
                    "LiveCanaryPrebootstrapAdmissionTests."
                    "test_ac8_success_report_is_sealed_and_non_authoritative"
                ),
            ],
            cwd=Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(
            0,
            completed.returncode,
            completed.stdout + completed.stderr,
        )


if __name__ == "__main__":
    unittest.main()
