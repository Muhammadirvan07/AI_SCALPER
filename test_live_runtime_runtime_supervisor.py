from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import sqlite3
from pathlib import Path
import tempfile
import unittest

from live_runtime.contracts import (
    BrokerSpec,
    ExecutionReceipt,
    _mint_execution_receipt,
    _mint_submission_consumption_proof,
    canonical_json,
    canonical_sha256,
)
from live_runtime.controls import (
    ManualDemoApproval,
    manual_demo_account_sha256,
    validate_manual_demo_approval,
)
from live_runtime.health import (
    MIN_FREE_DISK_BYTES,
    RuntimeHealthFacts,
    evaluate_runtime_health,
)
from live_runtime.journal import ExecutionJournal
from live_runtime.journal_integrity import (
    ExecutionJournalCheckpointCASAcknowledgement,
    create_execution_journal_checkpoint,
    verify_execution_journal_checkpoint,
)
from live_runtime.reconciliation import (
    BrokerClosedTradeReceipt,
    BrokerDealReceipt,
    BrokerReconciliationReceipt,
    ReconciliationResult,
    issue_broker_reconciliation_receipt,
    issue_broker_deal_receipt,
    issue_broker_closed_trade_receipt,
    verify_broker_closed_trade_receipt,
    verify_broker_deal_receipt,
    verify_broker_reconciliation_receipt,
)
from live_runtime.risk_ledger import (
    AccountRiskSnapshot,
    ClosedTradeRiskEvent,
    EntryRiskEvent,
    RiskLedgerBinding,
    RiskStateCheckpointCASAcknowledgement,
    verify_risk_source_receipt,
)
from test_fixtures.risk_source import (
    SOURCE_ISSUER,
    SOURCE_KEY,
    SOURCE_KEY_ID,
    TrustedRiskLedgerFixture,
    upstream_verifier,
)
from live_runtime.runtime_fact_collector import (
    RUNTIME_FACT_HMAC_DOMAIN,
    RuntimeAccountFact,
    RuntimeFactReceipt,
    RuntimeTickFact,
    verify_runtime_fact_receipt,
)
from live_runtime.runtime_supervisor import (
    RuntimeAccountSnapshotRiskEvidence,
    RuntimeClosedTradeRiskEvidence,
    RuntimeManualDemoExecutionResult,
    RuntimeNewsGuard,
    RuntimeNewsGuardReceipt,
    RuntimeStageAuthorizationPorts,
    RuntimeSupervisor,
    RuntimeSupervisorBinding,
    RuntimeSupervisorBindingError,
    RuntimeSupervisorCheckpoint,
    RuntimeSupervisorCheckpointCASAcknowledgement,
    RuntimeSupervisorCriticalError,
    RuntimeSupervisorCycleReceipt,
    RuntimeSupervisorLeaseError,
    RuntimeSupervisorDecision,
    issue_runtime_news_guard_receipt,
    runtime_news_guard_trust_sha256,
    seal_runtime_manual_demo_execution_result,
    seal_runtime_reconciliation_risk_result,
    verify_runtime_news_guard_receipt,
)
from live_runtime.stage_authorization import (
    AcceptanceAuthorityTrustPolicy,
    ManualDemoAggregateReceipt,
    ManualDemoReadinessReceipt,
    StageAuthorizationReplayRegistry,
    StageBinding,
    StageReadinessRequest,
    account_alias_sha256,
    issue_acceptance_authority_receipt,
    issue_human_approval,
    issue_stage_readiness_authorization,
    validate_and_consume_stage_readiness_authorization,
)
from live_runtime.promotion_evidence import PromotionEvidenceReceipt


UTC = timezone.utc
NOW = datetime(2026, 7, 22, 4, 0, tzinfo=UTC)
ACCOUNT_ID = "phillip-fx-demo"
SERVER = "PhillipSecuritiesJP-PROD"
CURRENCY = "JPY"
SYMBOL = "EURUSD"
BROKER_SYMBOL = "EURUSD.ps01"
IDENTITY_SHA256 = "a" * 64
COMMIT_SHA = "b" * 40
CONFIG_SHA256 = "c" * 64
SUPERVISOR_KEY_ID = "runtime-supervisor-key-v1"
SUPERVISOR_KEY = b"runtime-supervisor-hmac-key-material-32-bytes"
SUPERVISOR_CHECKPOINT_KEY_ID = "runtime-supervisor-checkpoint-key-v1"
SUPERVISOR_CHECKPOINT_KEY = b"runtime-supervisor-checkpoint-key-material-32-bytes"
RISK_KEY_ID = "risk-ledger-key-v1"
RISK_KEY = b"durable-risk-ledger-hmac-key-material-32-bytes"
FACT_KEY_ID = "runtime-fact-key-v1"
FACT_KEY = b"runtime-fact-hmac-key-material-at-least-32-bytes"
JOURNAL_CHECKPOINT_KEY_ID = "execution-journal-checkpoint-key-v1"
JOURNAL_CHECKPOINT_KEY = b"execution-journal-checkpoint-hmac-key-32-bytes"
APPROVAL_KEY_ID = "manual-demo-key-v1"
APPROVAL_KEY = b"manual-demo-approval-secret-32-bytes-minimum"
NEWS_KEY_ID = "trusted-news-provider-key-v1"
NEWS_KEY = b"trusted-news-provider-hmac-key-material-32-bytes"
NEWS_PROVIDER_ID = "reviewed-economic-calendar-v1"
BROKER_RECONCILIATION_PROVIDER_ID = "trusted-mt5-reconciler-v1"
BROKER_RECONCILIATION_KEY_ID = "trusted-mt5-reconciler-key-v1"
BROKER_RECONCILIATION_KEY = (
    b"trusted-mt5-reconciler-hmac-key-material-32-bytes"
)
NEWS_RULESET_SHA256 = hashlib.sha256(b"news-ruleset-v1").hexdigest()
NEWS_WINDOW_SHA256 = hashlib.sha256(b"blackout-window-v1").hexdigest()
PRE_MANUAL_COMPLETE_STATUS = (
    "PRE_MANUAL_DEMO_EXTERNAL_PRECONDITIONS_COMPLETE_"
    "ACTIVATION_REVIEW_REQUIRED"
)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class StagePortFixture:
    def __init__(self, root: Path, *, journal_sha256: str) -> None:
        self.root = root
        self.t0 = NOW - timedelta(minutes=3)
        self.readiness_secret = b"r" * 32
        self.approval_secrets = {
            "approval-risk-v1": b"a" * 32,
            "approval-ops-v1": b"b" * 32,
        }
        self.stage_secret = b"s" * 32
        self.manual_secret = b"m" * 32
        self.promotion_secret = b"p" * 32
        self.acceptance_authority_secrets = {
            "runtime-authority-v1": b"u" * 32,
            "parity-authority-v1": b"v" * 32,
            "security-authority-v1": b"w" * 32,
            "failure_drill-authority-v1": b"y" * 32,
        }
        self.acceptance_authority_policy = AcceptanceAuthorityTrustPolicy(
            policy_id="supervisor-acceptance-authorities-v1",
            domain_key_allowlist=tuple(
                (
                    domain,
                    (
                        (
                            f"{domain.lower()}-authority-v1",
                            hashlib.sha256(
                                self.acceptance_authority_secrets[
                                    f"{domain.lower()}-authority-v1"
                                ]
                            ).hexdigest(),
                        ),
                    ),
                )
                for domain in ("RUNTIME", "PARITY", "SECURITY", "FAILURE_DRILL")
            ),
        )
        self.replay_secret = b"x" * 32
        self.checkpoint_secret = b"c" * 32
        self.pre_manual_entry_review_sha256 = digest(
            "supervisor-complete-pre-manual-entry-review"
        )
        self.binding = StageBinding(
            broker_id="phillip-demo",
            account_alias_sha256=account_alias_sha256(ACCOUNT_ID),
            server=SERVER,
            environment="DEMO",
            symbol=SYMBOL,
            strategy="BREAKOUT",
            lane_id=f"{SYMBOL}:BREAKOUT:{CONFIG_SHA256}",
            journal_sha256=journal_sha256,
            commit_sha=COMMIT_SHA,
            config_sha256=CONFIG_SHA256,
            dependency_lock_sha256=digest("dependencies"),
            broker_spec_sha256=digest("broker-spec"),
            session_calendar_sha256=digest("session-calendar"),
            evidence_contract_sha256=digest("evidence-contract"),
            broker_profile_sha256=digest("broker-profile"),
            runtime_profile_sha256=digest("runtime-profile"),
            model_artifact_sha256=digest("model"),
            acceptance_authority_policy_sha256=(
                self.acceptance_authority_policy.policy_sha256
            ),
            manual_demo_custodian_trust_sha256=digest(
                "manual-custodian-trust-policy"
            ),
        )
        self.readiness = ManualDemoReadinessReceipt(
            binding_sha256=self.binding.binding_sha256,
            gate_receipts={
                name: digest(name.lower())
                for name in (
                    "LEGAL",
                    "CLEAN_RELEASE",
                    "NEWS",
                    "WINDOWS",
                    "FAILURE_DRILL",
                    "SECURITY",
                    "RISK",
                    "RECONCILIATION",
                )
            },
            source_validation_receipt_sha256=digest("global-validation"),
            pre_manual_entry_review_sha256=(
                self.pre_manual_entry_review_sha256
            ),
            pre_manual_entry_review_checked_at=(
                self.t0 - timedelta(minutes=1)
            ),
            pre_manual_entry_review_status=PRE_MANUAL_COMPLETE_STATUS,
            issued_at=self.t0 - timedelta(minutes=1),
            expires_at=self.t0 + timedelta(minutes=4),
            signer_key_id="manual-readiness-v1",
            nonce="manual-readiness-supervisor-v1",
        ).sign(self.readiness_secret)
        self.registry = StageAuthorizationReplayRegistry(
            root / "stage-replay.sqlite3",
            registry_id="supervisor-stage-replay-v1",
            registry_key_id="supervisor-stage-replay-key-v1",
            hmac_secret=self.replay_secret,
        )
        self.generation = 0
        self.validation_calls = 0

    def ports(self, mode: str = "MANUAL_DEMO") -> RuntimeStageAuthorizationPorts:
        self.generation += 1
        manual_aggregate = None
        promotion = None
        references = ()
        if mode == "DEMO_AUTO":
            manual_aggregate = ManualDemoAggregateReceipt(
                binding_sha256=digest("manual-tracker-binding"),
                account_alias_sha256=self.binding.account_alias_sha256,
                broker_server=self.binding.server,
                journal_sha256=self.binding.journal_sha256,
                commit_sha=self.binding.commit_sha,
                config_sha256=self.binding.config_sha256,
                lane_id=self.binding.lane_id,
                tracker_head_sha256=digest("manual-tracker-head"),
                external_custody_checkpoint_sha256=digest(
                    "manual-tracker-external-custody"
                ),
                custodian_trust_sha256=digest(
                    "manual-custodian-trust-policy"
                ),
                tracker_head_sequence=40,
                total_events=40,
                clean_completed_orders=10,
                critical_incidents=0,
                orphan_positions=0,
                orphan_orders=0,
                unexplained_positions=0,
                assessment_sha256=digest("manual-assessment"),
                assessed_at=self.t0,
                issued_at=self.t0,
                expires_at=self.t0 + timedelta(minutes=5),
                signer_key_id="manual-aggregate-v1",
                nonce=f"manual-aggregate-{self.generation:03d}",
            ).sign(self.manual_secret)
            promotion = PromotionEvidenceReceipt(
                mode="DEMO_AUTO",
                lane_id=self.binding.lane_id,
                symbol=self.binding.symbol,
                strategy=self.binding.strategy,
                account_alias_sha256=self.binding.account_alias_sha256,
                server=self.binding.server,
                journal_sha256=self.binding.journal_sha256,
                commit_sha=self.binding.commit_sha,
                config_sha256=self.binding.config_sha256,
                model_artifact_sha256=self.binding.model_artifact_sha256,
                lane_readiness_sha256=digest("lane-readiness"),
                lane_evidence_sha256=digest("lane-evidence"),
                evidence_store_receipt_sha256=digest("evidence-store"),
                runtime_parity_receipt_sha256=digest("parity-receipt"),
                build_manifest_sha256=digest("build-manifest"),
                issued_at=self.t0,
                expires_at=self.t0 + timedelta(minutes=5),
                signer_key_id="promotion-v1",
                nonce=f"promotion-{self.generation:03d}",
            ).sign(self.promotion_secret)
            references = tuple(
                issue_acceptance_authority_receipt(
                    domain=domain,
                    binding=self.binding,
                    evidence_receipt_sha256=(
                        promotion.runtime_parity_receipt_sha256
                        if domain == "PARITY"
                        else digest(f"{domain}-acceptance")
                    ),
                    validation_receipt_sha256=digest(f"{domain}-validation"),
                    accepted_at=self.t0,
                    expires_at=self.t0 + timedelta(minutes=5),
                    authority_key_id=f"{domain.lower()}-authority-v1",
                    authority_secret=self.acceptance_authority_secrets[
                        f"{domain.lower()}-authority-v1"
                    ],
                    trust_policy=self.acceptance_authority_policy,
                )
                for domain in ("RUNTIME", "PARITY", "SECURITY", "FAILURE_DRILL")
            )
        request = StageReadinessRequest(
            binding=self.binding,
            manual_readiness_receipt_sha256=self.readiness.content_sha256,
            pre_manual_entry_review_sha256=(
                self.pre_manual_entry_review_sha256
            ),
            acceptance_receipts=references,
            issued_at=self.t0,
            expires_at=self.t0 + timedelta(minutes=4),
            nonce=f"supervisor-stage-nonce-{self.generation:03d}",
            mode=mode,
            manual_demo_aggregate_receipt_sha256=(
                None if manual_aggregate is None else manual_aggregate.content_sha256
            ),
            promotion_evidence_receipt_sha256=(
                None if promotion is None else promotion.content_sha256
            ),
            evidence_store_receipt_sha256=(
                None if promotion is None else promotion.evidence_store_receipt_sha256
            ),
        )
        approvals = (
            issue_human_approval(
                request,
                human_identity=f"risk-{self.generation}@example.invalid",
                role="RISK_OWNER",
                approved_at=self.t0 + timedelta(minutes=1),
                approval_nonce=f"risk-approval-{self.generation:03d}",
                signer_key_id="approval-risk-v1",
                secret=self.approval_secrets["approval-risk-v1"],
            ),
            issue_human_approval(
                request,
                human_identity=f"ops-{self.generation}@example.invalid",
                role="OPERATIONS_OWNER",
                approved_at=self.t0 + timedelta(minutes=1),
                approval_nonce=f"ops-approval-{self.generation:03d}",
                signer_key_id="approval-ops-v1",
                secret=self.approval_secrets["approval-ops-v1"],
            ),
        )
        authorization = issue_stage_readiness_authorization(
            request,
            manual_readiness_receipt=self.readiness,
            manual_readiness_key_provider=lambda _key_id: self.readiness_secret,
            manual_demo_receipt=manual_aggregate,
            manual_demo_key_provider=(
                None if manual_aggregate is None else lambda _key_id: self.manual_secret
            ),
            promotion_evidence_receipt=promotion,
            promotion_evidence_key_provider=(
                None if promotion is None else lambda _key_id: self.promotion_secret
            ),
            acceptance_authority_policy=(
                None if promotion is None else self.acceptance_authority_policy
            ),
            acceptance_authority_key_provider=(
                None
                if promotion is None
                else lambda key_id: self.acceptance_authority_secrets[key_id]
            ),
            approvals=approvals,
            approval_key_provider=lambda key_id: self.approval_secrets[key_id],
            issued_at=self.t0 + timedelta(minutes=2),
            stage_signer_key_id="stage-authority-v1",
            stage_signing_secret=self.stage_secret,
        )
        external = self.registry.create_checkpoint(
            issued_at=NOW - timedelta(seconds=1),
            checkpoint_key_id="stage-checkpoint-key-v1",
            checkpoint_secret=self.checkpoint_secret,
        )

        def validator(now: datetime, expected_mode: str):
            self.validation_calls += 1
            return validate_and_consume_stage_readiness_authorization(
                authorization,
                manual_readiness_receipt=self.readiness,
                manual_readiness_key_provider=lambda _key_id: self.readiness_secret,
                manual_demo_receipt=manual_aggregate,
                manual_demo_key_provider=(
                    None if manual_aggregate is None else lambda _key_id: self.manual_secret
                ),
                promotion_evidence_receipt=promotion,
                promotion_evidence_key_provider=(
                    None if promotion is None else lambda _key_id: self.promotion_secret
                ),
                acceptance_authority_policy=(
                    None if promotion is None else self.acceptance_authority_policy
                ),
                acceptance_authority_key_provider=(
                    None
                    if promotion is None
                    else lambda key_id: self.acceptance_authority_secrets[key_id]
                ),
                approval_key_provider=lambda key_id: self.approval_secrets[key_id],
                stage_key_provider=lambda _key_id: self.stage_secret,
                expected_binding=self.binding,
                expected_mode=expected_mode,
                now=now,
                replay_registry=self.registry,
            )

        return RuntimeStageAuthorizationPorts(
            authorization=authorization,
            expected_binding=self.binding,
            external_replay_checkpoint=external,
            authorization_validator=validator,
            replay_registry=self.registry,
            checkpoint_key_id="stage-checkpoint-key-v1",
            checkpoint_key_provider=lambda _key_id: self.checkpoint_secret,
        )


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class FakeAdapter:
    def __init__(self, clock: MutableClock) -> None:
        self.clock = clock

    def assert_account_binding(self):
        return {"account_alias": ACCOUNT_ID, "server": SERVER}

    def execution_fence_identity(self):
        return IDENTITY_SHA256

    def get_broker_spec(self, symbol, broker_symbol, *, now):
        return BrokerSpec(
            account_id=ACCOUNT_ID,
            broker_legal_name="Phillip Securities Japan, Ltd.",
            server=SERVER,
            environment="DEMO",
            symbol=symbol,
            broker_symbol=broker_symbol,
            account_currency=CURRENCY,
            digits=5,
            point=0.00001,
            tick_size=0.00001,
            tick_value=100.0,
            contract_size=100_000.0,
            volume_min=0.01,
            volume_max=50.0,
            volume_step=0.01,
            stops_level_points=0,
            freeze_level_points=0,
            margin_per_lot=4_000.0,
            session_calendar_sha256="d" * 64,
            captured_at=now,
        )

    def current_tick(self, broker_symbol, *, now):
        return {
            "bid": 1.17,
            "ask": 1.17002,
            "time_utc": now - timedelta(milliseconds=100),
            "age_seconds": 0.1,
        }


def clean_reconciliation() -> ReconciliationResult:
    return ReconciliationResult(
        status="RECONCILIATION_COMPLETE",
        matched_intents=(),
        uncertain_intents=(),
        closed_intents=(),
        orphan_position_tickets=(),
        orphan_order_tickets=(),
        protection_failures=(),
        volume_failures=(),
        binding_failures=(),
        kill_switch_latched=False,
    )


class SupervisorFixture:
    def __init__(
        self,
        root: Path,
        *,
        mode: str = "SHADOW",
        signed_news: bool | None = None,
    ) -> None:
        self.root = root
        self.mode = mode
        self.clock = MutableClock(NOW)
        self.journal = ExecutionJournal(
            root / "execution.sqlite3", clock_provider=self.clock
        )
        self.signed_news = mode != "SHADOW" if signed_news is None else signed_news
        self.stage = StagePortFixture(root, journal_sha256=self.journal.journal_sha256)
        self.stage_ports = (
            self.stage.ports(
                "MANUAL_DEMO" if mode == "DEMO" else "DEMO_AUTO"
            )
            if mode in {"DEMO", "DEMO_AUTO"}
            else None
        )
        self.binding = RuntimeSupervisorBinding(
            account_id_sha256=manual_demo_account_sha256(ACCOUNT_ID),
            server=SERVER,
            environment="DEMO",
            account_currency=CURRENCY,
            journal_sha256=self.journal.journal_sha256,
            commit_sha=COMMIT_SHA,
            config_sha256=CONFIG_SHA256,
            mode=mode,
            stage_binding_sha256=(
                self.stage.binding.binding_sha256
                if mode in {"DEMO", "DEMO_AUTO"}
                else None
            ),
            news_guard_trust_sha256=(
                runtime_news_guard_trust_sha256(
                    provider_id=NEWS_PROVIDER_ID,
                    key_id=NEWS_KEY_ID,
                    ruleset_sha256=NEWS_RULESET_SHA256,
                    blackout_window_sha256=NEWS_WINDOW_SHA256,
                )
                if self.signed_news
                else None
            ),
        )
        risk_binding = RiskLedgerBinding(
            account_id_sha256=manual_demo_account_sha256(ACCOUNT_ID),
            server=SERVER,
            environment="DEMO",
            journal_sha256=self.journal.journal_sha256,
            broker_spec_sha256=digest("risk-broker-spec"),
            account_currency=CURRENCY,
        )
        self.risk_ledger = TrustedRiskLedgerFixture(
            root / "risk.sqlite3",
            binding=risk_binding,
            key_id=RISK_KEY_ID,
            key_provider=lambda key_id: RISK_KEY,
            source_key_provider=lambda _key_id: SOURCE_KEY,
            trusted_source_issuer_keys={SOURCE_ISSUER: (SOURCE_KEY_ID,)},
            upstream_receipt_verifier=self._verify_risk_upstream,
            clock_provider=self.clock,
        )
        initial_snapshot = AccountRiskSnapshot(
            snapshot_id="snapshot-1",
            binding=risk_binding,
            observed_at_utc=NOW,
            daily_baseline_id="day-2026-07-22",
            weekly_baseline_id="week-2026-W30",
            equity=100_000.0,
        )
        self.current_risk_source, initial_upstream = self.risk_ledger._provenance(
            initial_snapshot,
            "ACCOUNT_SNAPSHOT",
        )
        self.risk_ledger.append_account_snapshot(
            initial_snapshot,
            source_receipt=self.current_risk_source,
            upstream_receipt=initial_upstream,
        )
        self.checkpoint = self.risk_ledger.current_receipt()
        self.adapter = FakeAdapter(self.clock)
        self.trace: list[str] = []
        self.decisions = 0
        self.executions = 0
        self.account_equity = 100_000.0
        self.fact_observed_lag_seconds = 0.0
        self.fact_validity_seconds = 1.0
        self.extra_pending_fact: RuntimeFactReceipt | None = None
        self.static_fact = None
        self.pending_reconciliation_fact = None
        self.risk_refresh_sequence = 0
        self.broker_reconciliation_previous: BrokerReconciliationReceipt | None = None
        self.verified_broker_reconciliation_previous: (
            BrokerReconciliationReceipt | None
        ) = None
        self.news_sequence = 0
        self.news_previous = "0" * 64
        self.last_news_receipt: RuntimeNewsGuardReceipt | None = None
        self.news_feed_fresh = True
        self.news_blackout_active = False
        self.rollover_blackout_active = False
        self.external_supervisor_checkpoint: RuntimeSupervisorCheckpoint | None = None
        self.external_journal_checkpoint = (
            create_execution_journal_checkpoint(
                self.journal,
                account_id_sha256=manual_demo_account_sha256(ACCOUNT_ID),
                server=SERVER,
                environment="DEMO",
                commit_sha=COMMIT_SHA,
                config_sha256=CONFIG_SHA256,
                key_id=JOURNAL_CHECKPOINT_KEY_ID,
                key_provider=lambda _key_id: JOURNAL_CHECKPOINT_KEY,
                clock_provider=self.clock,
                execution_mode="SHADOW",
            )
            if mode != "SHADOW"
            else None
        )

    @staticmethod
    def _verify_risk_upstream(receipt_type: str, receipt: object) -> object:
        if receipt_type == "EXECUTION_RECEIPT" and type(receipt) is ExecutionReceipt:
            return receipt
        if receipt_type == "RUNTIME_FACT_RECEIPT" and type(receipt) is RuntimeFactReceipt:
            return receipt
        if (
            receipt_type == "BROKER_CLOSED_TRADE_RECEIPT"
            and type(receipt) is BrokerClosedTradeReceipt
        ):
            return receipt
        return upstream_verifier(receipt_type, receipt)

    def manual_execution_result(
        self,
        intent_id: str,
    ) -> RuntimeManualDemoExecutionResult:
        proof = _mint_submission_consumption_proof(
            journal_sha256=self.journal.journal_sha256,
            intent_id=intent_id,
            execution_gate_sha256=digest(f"gate:{intent_id}"),
            authorization_sha256=digest(f"authorization:{intent_id}"),
            broker_request_sha256=digest(f"request:{intent_id}"),
            consumed_at=self.clock.value,
        )
        execution_receipt = _mint_execution_receipt(
            submission_proof=proof,
            intent_id=intent_id,
            state="FILLED",
            account_id=ACCOUNT_ID,
            server=SERVER,
            symbol=SYMBOL,
            requested_volume=0.01,
            filled_volume=0.01,
            received_at=self.clock.value,
            broker_retcode="10009",
            message="filled",
            order_ticket=f"order-{intent_id}",
            deal_ticket=f"deal-{intent_id}",
            requested_price=1.17,
            fill_price=1.17002,
        )
        before = self.risk_ledger.current_receipt()
        entry = EntryRiskEvent(
            entry_id=intent_id,
            binding=self.risk_ledger.binding,
            occurred_at_utc=execution_receipt.received_at,
            daily_baseline_id=before.daily_baseline_id,
            weekly_baseline_id=before.weekly_baseline_id,
            symbol=SYMBOL,
        )
        unsigned = {
            "source_receipt_id": f"source-entry-{entry.content_sha256[:32]}",
            "source_kind": "ENTRY",
            "issuer_id": SOURCE_ISSUER,
            "key_id": SOURCE_KEY_ID,
            "binding": self.risk_ledger.binding.to_canonical_dict(),
            "event_sha256": entry.content_sha256,
            "upstream_receipt_type": "EXECUTION_RECEIPT",
            "upstream_receipt_sha256": execution_receipt.content_sha256,
            "observed_at_utc": self.clock.value,
            "valid_until_utc": self.clock.value + timedelta(seconds=5),
            "schema_version": "durable-risk-source-receipt-v1",
        }
        signature = hmac.new(
            SOURCE_KEY,
            b"AI_SCALPER_DURABLE_RISK_SOURCE_V1\x00"
            + canonical_json(unsigned).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        source = verify_risk_source_receipt(
            {**unsigned, "signature_hmac_sha256": signature},
            expected_event=entry,
            expected_binding=self.risk_ledger.binding,
            key_provider=lambda _key_id: SOURCE_KEY,
            trusted_issuer_keys={SOURCE_ISSUER: (SOURCE_KEY_ID,)},
            clock_provider=self.clock,
        )
        self.current_risk_source = source
        return seal_runtime_manual_demo_execution_result(
            execution_receipt=execution_receipt,
            entry_event=entry,
            entry_source_receipt=source,
        )

    def fact_provider(self):
        self.trace.append("facts")
        if self.pending_reconciliation_fact is not None:
            receipt = self.pending_reconciliation_fact
            self.pending_reconciliation_fact = None
            extra = self.extra_pending_fact
            self.extra_pending_fact = None
            return (receipt,) if extra is None else (receipt, extra)
        if self.static_fact is not None:
            return (self.static_fact,)
        observed = self.clock.value - timedelta(
            seconds=self.fact_observed_lag_seconds
        )
        spec = self.adapter.get_broker_spec(SYMBOL, BROKER_SYMBOL, now=observed)
        account_fact = RuntimeAccountFact(
            account_id=ACCOUNT_ID,
            server=SERVER,
            currency=CURRENCY,
            balance=100_000.0,
            equity=self.account_equity,
            margin=0.0,
            margin_free=self.account_equity,
            margin_level=0.0,
            trade_allowed=False,
            trade_expert=True,
            captured_at_utc=observed,
        )
        tick = RuntimeTickFact(
            broker_symbol=BROKER_SYMBOL,
            bid=1.17,
            ask=1.17002,
            time_utc=observed - timedelta(milliseconds=100),
            age_seconds=0.1,
            collected_at_utc=observed,
        )
        health = RuntimeHealthFacts(
            observed_at=observed,
            heartbeat_at=observed - timedelta(seconds=1),
            clock_drift_seconds=0.1,
            free_disk_bytes=MIN_FREE_DISK_BYTES + 1,
            database_integrity_ok=True,
            broker_connected=True,
            data_feed_fresh=True,
            audit_export_healthy=True,
            backup_recent=True,
            kill_switch_latched=False,
        )
        health_decision = evaluate_runtime_health(health)
        account_binding = canonical_sha256(
            {
                "account_id": ACCOUNT_ID,
                "server": SERVER,
                "environment": "DEMO",
                "account_runtime_identity_sha256": IDENTITY_SHA256,
            }
        )
        unsigned = RuntimeFactReceipt(
            account_id=ACCOUNT_ID,
            server=SERVER,
            environment="DEMO",
            symbol=SYMBOL,
            broker_symbol=BROKER_SYMBOL,
            account_runtime_identity_sha256=IDENTITY_SHA256,
            account_binding_sha256=account_binding,
            account_fact=account_fact,
            account_fact_sha256=account_fact.content_sha256,
            broker_spec=spec,
            broker_spec_sha256=spec.content_sha256,
            tick=tick,
            tick_sha256=tick.content_sha256,
            health_facts=health,
            health_facts_sha256=health.content_sha256,
            health_decision=health_decision,
            health_decision_sha256=health_decision.content_sha256,
            journal_sha256=self.journal.journal_sha256,
            key_id=FACT_KEY_ID,
            observed_at_utc=observed,
            valid_until_utc=observed
            + timedelta(seconds=self.fact_validity_seconds),
        )
        signature = hmac.new(
            FACT_KEY,
            RUNTIME_FACT_HMAC_DOMAIN + unsigned.signing_payload,
            hashlib.sha256,
        ).hexdigest()
        return (replace(unsigned, signature=signature),)

    @staticmethod
    def _resign_fact(
        receipt: RuntimeFactReceipt,
        *,
        symbol: str,
        broker_symbol: str,
        equity: float,
    ) -> RuntimeFactReceipt:
        account = replace(
            receipt.account_fact,
            equity=equity,
            margin_free=equity,
        )
        broker_spec = replace(
            receipt.broker_spec,
            symbol=symbol,
            broker_symbol=broker_symbol,
        )
        tick = replace(receipt.tick, broker_symbol=broker_symbol)
        unsigned = replace(
            receipt,
            symbol=symbol,
            broker_symbol=broker_symbol,
            account_fact=account,
            account_fact_sha256=account.content_sha256,
            broker_spec=broker_spec,
            broker_spec_sha256=broker_spec.content_sha256,
            tick=tick,
            tick_sha256=tick.content_sha256,
            signature="",
        )
        signature = hmac.new(
            FACT_KEY,
            RUNTIME_FACT_HMAC_DOMAIN + unsigned.signing_payload,
            hashlib.sha256,
        ).hexdigest()
        return replace(unsigned, signature=signature)

    def fact_verifier(self, receipt):
        self.trace.append("fact_verify")
        return verify_runtime_fact_receipt(
            receipt,
            expected_account_id=ACCOUNT_ID,
            expected_server=SERVER,
            expected_environment="DEMO",
            expected_symbol=receipt.symbol,
            expected_broker_symbol=receipt.broker_symbol,
            expected_account_runtime_identity_sha256=IDENTITY_SHA256,
            expected_broker_spec_sha256=receipt.broker_spec.content_sha256,
            expected_journal_sha256=self.journal.journal_sha256,
            expected_key_id=FACT_KEY_ID,
            key_provider=lambda key_id: FACT_KEY,
            clock_provider=self.clock,
        )

    def reconciliation(self):
        self.trace.append("reconcile")
        if self.mode == "SHADOW":
            return clean_reconciliation()
        self.risk_refresh_sequence += 1
        self.clock.value += timedelta(microseconds=1)
        upstream = self.fact_provider()[0]
        self.trace.pop()
        self.pending_reconciliation_fact = upstream
        snapshot = AccountRiskSnapshot(
            snapshot_id=f"snapshot-reconciliation-{self.risk_refresh_sequence}",
            binding=self.risk_ledger.binding,
            observed_at_utc=upstream.observed_at_utc,
            daily_baseline_id="day-2026-07-22",
            weekly_baseline_id="week-2026-W30",
            equity=upstream.account_fact.equity,
        )
        unsigned = {
            "source_receipt_id": f"source-snapshot-{snapshot.content_sha256[:32]}",
            "source_kind": "ACCOUNT_SNAPSHOT",
            "issuer_id": SOURCE_ISSUER,
            "key_id": SOURCE_KEY_ID,
            "binding": self.risk_ledger.binding.to_canonical_dict(),
            "event_sha256": snapshot.content_sha256,
            "upstream_receipt_type": "RUNTIME_FACT_RECEIPT",
            "upstream_receipt_sha256": upstream.content_sha256,
            "observed_at_utc": upstream.observed_at_utc,
            "valid_until_utc": upstream.observed_at_utc + timedelta(seconds=5),
            "schema_version": "durable-risk-source-receipt-v1",
        }
        signature = hmac.new(
            SOURCE_KEY,
            b"AI_SCALPER_DURABLE_RISK_SOURCE_V1\x00"
            + canonical_json(unsigned).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        source = verify_risk_source_receipt(
            {**unsigned, "signature_hmac_sha256": signature},
            expected_event=snapshot,
            expected_binding=self.risk_ledger.binding,
            key_provider=lambda _key_id: SOURCE_KEY,
            trusted_issuer_keys={SOURCE_ISSUER: (SOURCE_KEY_ID,)},
            clock_provider=self.clock,
        )
        self.current_risk_source = source
        result = clean_reconciliation()
        broker_receipt = issue_broker_reconciliation_receipt(
            result=result,
            account_id_sha256=self.binding.account_id_sha256,
            server=self.binding.server,
            environment=self.binding.environment,
            journal_sha256=self.binding.journal_sha256,
            query_from_utc=self.clock.value - timedelta(minutes=1),
            query_to_utc=self.clock.value,
            source_time_utc=self.clock.value,
            observed_at_utc=self.clock.value,
            source_sequence=self.risk_refresh_sequence,
            previous_receipt_sha256=(
                "0" * 64
                if self.broker_reconciliation_previous is None
                else self.broker_reconciliation_previous.content_sha256
            ),
            order_tickets=(),
            position_tickets=(),
            deal_tickets=(),
            closed_intent_deal_tickets={},
            raw_payload_sha256=digest(
                f"broker-payload:{self.risk_refresh_sequence}"
            ),
            provider_id=BROKER_RECONCILIATION_PROVIDER_ID,
            key_id=BROKER_RECONCILIATION_KEY_ID,
            key=BROKER_RECONCILIATION_KEY,
        )
        self.broker_reconciliation_previous = broker_receipt
        return seal_runtime_reconciliation_risk_result(
            result,
            broker_reconciliation_receipt=broker_receipt,
            account_snapshot_evidence=RuntimeAccountSnapshotRiskEvidence(
                event=snapshot,
                source_receipt=source,
                upstream_receipt=upstream,
            ),
        )

    def verify_broker_reconciliation(self, receipt, result):
        checked = verify_broker_reconciliation_receipt(
            receipt,
            expected_result=result,
            expected_account_id_sha256=self.binding.account_id_sha256,
            expected_server=self.binding.server,
            expected_environment=self.binding.environment,
            expected_journal_sha256=self.binding.journal_sha256,
            expected_provider_id=BROKER_RECONCILIATION_PROVIDER_ID,
            expected_key_id=BROKER_RECONCILIATION_KEY_ID,
            key_provider=lambda _key_id: BROKER_RECONCILIATION_KEY,
            now=self.clock.value,
            prior_receipt=self.verified_broker_reconciliation_previous,
        )
        self.verified_broker_reconciliation_previous = checked
        return checked

    @staticmethod
    def verify_broker_deal(receipt, reconciliation_receipt):
        return verify_broker_deal_receipt(
            receipt,
            reconciliation_receipt=reconciliation_receipt,
            expected_intent_id=receipt.intent_id,
            key_provider=lambda _key_id: BROKER_RECONCILIATION_KEY,
        )

    @staticmethod
    def verify_broker_closed_trade(receipt, reconciliation_receipt):
        return verify_broker_closed_trade_receipt(
            receipt,
            reconciliation_receipt=reconciliation_receipt,
            expected_intent_id=receipt.intent_id,
            key_provider=lambda _key_id: BROKER_RECONCILIATION_KEY,
        )

    def checkpoint_provider(self):
        self.trace.append("risk")
        return self.checkpoint

    def export_risk_checkpoint(self, expected_current_sha256, checkpoint):
        if self.checkpoint.content_sha256 != expected_current_sha256:
            raise RuntimeError("risk checkpoint compare-and-swap conflict")
        self.checkpoint = checkpoint
        return RiskStateCheckpointCASAcknowledgement(
            expected_current_checkpoint_sha256=expected_current_sha256,
            written_checkpoint_sha256=checkpoint.content_sha256,
        )

    def journal_checkpoint_provider(self):
        self.trace.append("journal_checkpoint")
        return create_execution_journal_checkpoint(
            self.journal,
            account_id_sha256=manual_demo_account_sha256(ACCOUNT_ID),
            server=SERVER,
            environment="DEMO",
            commit_sha=COMMIT_SHA,
            config_sha256=CONFIG_SHA256,
            key_id=JOURNAL_CHECKPOINT_KEY_ID,
            key_provider=lambda key_id: JOURNAL_CHECKPOINT_KEY,
            clock_provider=self.clock,
            prior_checkpoint=self.external_journal_checkpoint,
            execution_mode=self.mode,
        )

    def journal_checkpoint_verifier(self, checkpoint, prior_checkpoint):
        self.trace.append("checkpoint_verify")
        return verify_execution_journal_checkpoint(
            self.journal,
            checkpoint,
            expected_account_id_sha256=manual_demo_account_sha256(ACCOUNT_ID),
            expected_server=SERVER,
            expected_environment="DEMO",
            expected_commit_sha=COMMIT_SHA,
            expected_config_sha256=CONFIG_SHA256,
            key_provider=lambda key_id: JOURNAL_CHECKPOINT_KEY,
            now=self.clock.value,
            prior_checkpoint=prior_checkpoint,
            execution_mode=self.mode,
        )

    def export_journal_checkpoint(self, expected_current_sha256, checkpoint):
        current_sha256 = (
            "0" * 64
            if self.external_journal_checkpoint is None
            else self.external_journal_checkpoint.content_sha256
        )
        if current_sha256 != expected_current_sha256:
            raise RuntimeError("journal checkpoint compare-and-swap conflict")
        self.external_journal_checkpoint = checkpoint
        return ExecutionJournalCheckpointCASAcknowledgement(
            expected_current_checkpoint_sha256=expected_current_sha256,
            written_checkpoint_sha256=checkpoint.content_sha256,
        )

    def export_supervisor_checkpoint(self, expected_current_sha256, checkpoint):
        current_sha256 = (
            "0" * 64
            if self.external_supervisor_checkpoint is None
            else self.external_supervisor_checkpoint.content_sha256
        )
        if current_sha256 != expected_current_sha256:
            raise RuntimeError("off-host checkpoint compare-and-swap conflict")
        self.external_supervisor_checkpoint = checkpoint
        return RuntimeSupervisorCheckpointCASAcknowledgement(
            expected_current_checkpoint_sha256=expected_current_sha256,
            written_checkpoint_sha256=checkpoint.content_sha256,
        )

    def news(self):
        self.trace.append("news")
        if self.signed_news:
            self.news_sequence += 1
            receipt = issue_runtime_news_guard_receipt(
                provider_id=NEWS_PROVIDER_ID,
                key_id=NEWS_KEY_ID,
                key=NEWS_KEY,
                account_id_sha256=self.binding.account_id_sha256,
                server=SERVER,
                environment="DEMO",
                observed_at_utc=self.clock.value,
                valid_until_utc=self.clock.value + timedelta(seconds=30),
                feed_sequence=self.news_sequence,
                feed_payload_sha256=digest(f"feed-{self.news_sequence}"),
                previous_receipt_sha256=self.news_previous,
                news_feed_fresh=self.news_feed_fresh,
                news_blackout_active=self.news_blackout_active,
                rollover_blackout_active=self.rollover_blackout_active,
                blackout_window_sha256=NEWS_WINDOW_SHA256,
                ruleset_sha256=NEWS_RULESET_SHA256,
                config_sha256=CONFIG_SHA256,
            )
            self.news_previous = receipt.content_sha256
            self.last_news_receipt = receipt
            return receipt
        return RuntimeNewsGuard(
            observed_at_utc=self.clock.value,
            news_feed_fresh=True,
            news_blackout_active=False,
            rollover_blackout_active=False,
        )

    def decision(self, facts, risk):
        self.trace.append("decision")
        self.decisions += 1
        return RuntimeSupervisorDecision(
            decision_id=f"decision-{self.decisions}",
            action="NO_ACTION",
            decided_at_utc=self.clock.value,
            decision_payload_sha256="e" * 64,
        )

    def supervisor(self, *, path: Path | None = None, **changes) -> RuntimeSupervisor:
        values = {
            "binding": self.binding,
            "journal": self.journal,
            "risk_ledger": self.risk_ledger,
            "journal_checkpoint_provider": self.journal_checkpoint_provider,
            "journal_checkpoint_verifier": self.journal_checkpoint_verifier,
            "risk_checkpoint_provider": self.checkpoint_provider,
            "risk_source_provider": lambda: self.current_risk_source,
            "risk_checkpoint_exporter": (
                self.export_risk_checkpoint
                if self.mode != "SHADOW"
                else None
            ),
            "reconciliation_provider": self.reconciliation,
            "runtime_fact_provider": self.fact_provider,
            "runtime_fact_verifier": self.fact_verifier,
            "news_guard_provider": self.news,
            "decision_provider": self.decision,
            "key_id": SUPERVISOR_KEY_ID,
            "key_provider": lambda key_id: SUPERVISOR_KEY,
            "supervisor_checkpoint_provider": (
                lambda: self.external_supervisor_checkpoint
            ),
            "supervisor_checkpoint_exporter": self.export_supervisor_checkpoint,
            "supervisor_checkpoint_key_id": SUPERVISOR_CHECKPOINT_KEY_ID,
            "supervisor_checkpoint_key_provider": (
                lambda _key_id: SUPERVISOR_CHECKPOINT_KEY
            ),
            "allow_checkpoint_bootstrap": (
                self.external_supervisor_checkpoint is None
            ),
            "external_journal_checkpoint_provider": (
                (lambda: self.external_journal_checkpoint)
                if self.mode != "SHADOW"
                else None
            ),
            "journal_checkpoint_exporter": (
                self.export_journal_checkpoint
                if self.mode != "SHADOW"
                else None
            ),
            "clock_provider": self.clock,
            "stage_authorization_ports": self.stage_ports,
            "broker_reconciliation_receipt_verifier": (
                self.verify_broker_reconciliation
            ),
            "broker_deal_receipt_verifier": self.verify_broker_deal,
            "broker_closed_trade_receipt_verifier": (
                self.verify_broker_closed_trade
            ),
        }
        if self.signed_news:
            values.update(
                {
                    "news_guard_verifier": lambda receipt: verify_runtime_news_guard_receipt(
                        receipt,
                        expected_provider_id=NEWS_PROVIDER_ID,
                        expected_key_id=NEWS_KEY_ID,
                        expected_account_id_sha256=self.binding.account_id_sha256,
                        expected_server=SERVER,
                        expected_environment="DEMO",
                        expected_config_sha256=CONFIG_SHA256,
                        key_provider=lambda _key_id: NEWS_KEY,
                        now=self.clock.value,
                    ),
                    "news_guard_provider_id": NEWS_PROVIDER_ID,
                    "news_guard_key_id": NEWS_KEY_ID,
                    "news_guard_ruleset_sha256": NEWS_RULESET_SHA256,
                    "news_guard_blackout_window_sha256": NEWS_WINDOW_SHA256,
                    "allow_legacy_shadow_news_guard": False,
                }
            )
        else:
            values["allow_legacy_shadow_news_guard"] = True
        values.update(changes)
        return RuntimeSupervisor(
            path or self.root / "supervisor.sqlite3", **values
        )


class RuntimeSupervisorTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.fixture = SupervisorFixture(self.root)

    def _manual_demo_supervisor(
        self,
        fixture: SupervisorFixture,
        *,
        intent_id: str,
        execution_service,
    ) -> RuntimeSupervisor:
        approval = ManualDemoApproval(
            intent_id=intent_id,
            account_id_sha256=manual_demo_account_sha256(ACCOUNT_ID),
            server=SERVER,
            approver_id="operator-1",
            key_id=APPROVAL_KEY_ID,
            issued_at_utc=fixture.clock.value,
            expires_at_utc=fixture.clock.value + timedelta(minutes=1),
            nonce=f"review-{intent_id}",
            journal_sha256=fixture.journal.journal_sha256,
        ).sign(APPROVAL_KEY)

        def approval_provider(runtime_decision):
            return validate_manual_demo_approval(
                approval,
                expected_intent_id=runtime_decision.intent_id,
                expected_account_id=ACCOUNT_ID,
                expected_server=SERVER,
                expected_approver_id="operator-1",
                expected_key_id=APPROVAL_KEY_ID,
                expected_journal_sha256=fixture.journal.journal_sha256,
                key_provider=lambda _key_id: APPROVAL_KEY,
                clock_provider=fixture.clock,
            )

        return fixture.supervisor(
            decision_provider=lambda facts, risk: RuntimeSupervisorDecision(
                decision_id=f"decision-{intent_id}",
                action="MANUAL_DEMO_EXECUTE",
                intent_id=intent_id,
                decided_at_utc=fixture.clock.value,
                decision_payload_sha256=digest(f"decision:{intent_id}"),
            ),
            manual_approval_provider=approval_provider,
            manual_demo_policy_callback=lambda decision, validation: True,
            execution_service=execution_service,
        )

    def test_startup_verifies_all_receipts_and_reconciles_without_decision(self):
        supervisor = self.fixture.supervisor()
        receipt = supervisor.start(owner_id="runtime-a")

        self.assertEqual("READY", receipt.status)
        self.assertEqual(0, self.fixture.decisions)
        self.assertEqual(
            [
                "journal_checkpoint",
                "checkpoint_verify",
                "risk",
                "reconcile",
                "facts",
                "fact_verify",
                "news",
            ],
            self.fixture.trace,
        )
        self.assertEqual(
            {"journal_mode": "WAL", "synchronous": "FULL"},
            dict(supervisor.storage_settings()),
        )
        with self.assertRaises(FrozenInstanceError):
            receipt.status = "FORGED"  # type: ignore[misc]

    def test_cycle_reconciliation_precedes_facts_and_decision(self):
        supervisor = self.fixture.supervisor()
        supervisor.start(owner_id="runtime-a")
        self.fixture.trace.clear()

        receipt = supervisor.run_cycle()

        self.assertEqual("COMPLETE", receipt.status)
        self.assertLess(
            self.fixture.trace.index("reconcile"), self.fixture.trace.index("facts")
        )
        self.assertLess(
            self.fixture.trace.index("fact_verify"),
            self.fixture.trace.index("decision"),
        )

    def test_reconciliation_failure_never_calls_decision_and_latches_kill_switch(self):
        supervisor = self.fixture.supervisor()
        supervisor.start(owner_id="runtime-a")
        calls_before = self.fixture.decisions

        def critical_reconciliation():
            self.fixture.trace.append("reconcile")
            value = clean_reconciliation()
            return ReconciliationResult(
                **{
                    **value.__dict__,
                    "status": "RECONCILIATION_CRITICAL_HOLD",
                    "orphan_position_tickets": ("99",),
                }
            )

        supervisor.reconciliation_provider = critical_reconciliation
        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError, "RECONCILIATION_NOT_CLEAN"
        ):
            supervisor.run_cycle()
        self.assertEqual(calls_before, self.fixture.decisions)
        self.assertTrue(self.fixture.journal.kill_switch_status()["latched"])
        self.assertTrue(supervisor.status().stopped)

    def test_singleton_lease_rejects_second_owner_without_latching(self):
        first = self.fixture.supervisor()
        second = self.fixture.supervisor()
        first.start(owner_id="runtime-a")

        with self.assertRaises(RuntimeSupervisorLeaseError):
            second.start(owner_id="runtime-b")

        self.assertFalse(self.fixture.journal.kill_switch_status()["latched"])
        first.stop()

    def test_graceful_restart_continues_chain_and_increments_fence(self):
        first = self.fixture.supervisor()
        initial_checkpoint = self.fixture.external_supervisor_checkpoint
        assert initial_checkpoint is not None
        self.assertEqual("0" * 64, initial_checkpoint.predecessor_checkpoint_sha256)
        start_one = first.start(owner_id="runtime-a")
        startup_checkpoint = self.fixture.external_supervisor_checkpoint
        assert startup_checkpoint is not None
        self.assertEqual(
            initial_checkpoint.content_sha256,
            startup_checkpoint.predecessor_checkpoint_sha256,
        )
        first.run_cycle()
        first.stop()

        second = self.fixture.supervisor()
        start_two = second.start(owner_id="runtime-b")

        self.assertGreater(start_two.sequence, start_one.sequence)
        self.assertGreater(start_two.fence_token, start_one.fence_token)
        self.assertTrue(second.verify_integrity())

    def test_critical_latch_survives_journal_latch_failure_and_blocks_restart(self):
        supervisor = self.fixture.supervisor()
        supervisor.start(owner_id="runtime-a")

        def journal_latch_failure(*args, **kwargs):
            raise OSError("injected journal write failure")

        self.fixture.journal.latch_kill_switch = journal_latch_failure  # type: ignore[method-assign]
        supervisor.reconciliation_provider = lambda: ReconciliationResult(
            **{
                **clean_reconciliation().__dict__,
                "status": "RECONCILIATION_CRITICAL_HOLD",
                "orphan_position_tickets": ("orphan-1",),
            }
        )
        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "RECONCILIATION_NOT_CLEAN",
        ):
            supervisor.run_cycle()

        self.assertFalse(self.fixture.journal.kill_switch_status()["latched"])
        checkpoint = self.fixture.external_supervisor_checkpoint
        assert checkpoint is not None
        self.assertTrue(checkpoint.critical_latched)
        self.assertEqual("RECONCILIATION_NOT_CLEAN", checkpoint.critical_reason)
        with sqlite3.connect(self.root / "supervisor.sqlite3") as connection:
            critical = connection.execute(
                "SELECT critical_latched, critical_reason FROM supervisor_critical_state"
            ).fetchone()
        self.assertEqual((1, "RECONCILIATION_NOT_CLEAN"), critical)

        restarted = self.fixture.supervisor()
        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "SUPERVISOR_CRITICAL_LATCHED",
        ):
            restarted.start(owner_id="runtime-restart")
        self.assertEqual(0, self.fixture.decisions)

    def test_checkpoint_export_failure_latches_locally_without_regressing_custody(self):
        supervisor = self.fixture.supervisor()
        supervisor.start(owner_id="runtime-a")
        external_before = self.fixture.external_supervisor_checkpoint
        assert external_before is not None

        def export_failure(expected_current_sha256, checkpoint):
            raise OSError("injected off-host outage")

        supervisor.supervisor_checkpoint_exporter = export_failure
        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "RUNTIME_CYCLE_FAILED",
        ):
            supervisor.run_cycle()

        external_after = self.fixture.external_supervisor_checkpoint
        assert external_after is not None
        self.assertEqual(
            external_before.content_sha256,
            external_after.content_sha256,
        )
        with sqlite3.connect(self.root / "supervisor.sqlite3") as connection:
            critical = connection.execute(
                "SELECT critical_latched FROM supervisor_critical_state"
            ).fetchone()[0]
        self.assertEqual(1, critical)
        with self.assertRaises(RuntimeSupervisorCriticalError):
            self.fixture.supervisor()
        self.assertEqual(
            external_before.content_sha256,
            self.fixture.external_supervisor_checkpoint.content_sha256,
        )

    def test_checkpoint_cas_rejects_head_change_during_export(self):
        supervisor = self.fixture.supervisor()
        supervisor.start(owner_id="runtime-a")
        external_before = self.fixture.external_supervisor_checkpoint
        assert external_before is not None
        competing_head = replace(
            external_before,
            issued_at_utc=external_before.issued_at_utc + timedelta(microseconds=1),
            signature_hmac_sha256="",
        ).sign(SUPERVISOR_CHECKPOINT_KEY)

        def racing_exporter(expected_current_sha256, checkpoint):
            self.fixture.external_supervisor_checkpoint = competing_head
            return self.fixture.export_supervisor_checkpoint(
                expected_current_sha256,
                checkpoint,
            )

        supervisor.supervisor_checkpoint_exporter = racing_exporter
        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "RUNTIME_CYCLE_FAILED",
        ):
            supervisor.run_cycle()

        self.assertEqual(
            competing_head.content_sha256,
            self.fixture.external_supervisor_checkpoint.content_sha256,
        )
        with sqlite3.connect(self.root / "supervisor.sqlite3") as connection:
            critical = connection.execute(
                "SELECT critical_latched FROM supervisor_critical_state"
            ).fetchone()[0]
        self.assertEqual(1, critical)

    def test_journal_checkpoint_cas_rejects_head_change_during_export(self):
        root = self.root / "journal-cas-race"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        supervisor = fixture.supervisor()
        supervisor.start(owner_id="runtime-journal-cas")
        external_before = fixture.external_journal_checkpoint
        assert external_before is not None
        competing_head = create_execution_journal_checkpoint(
            fixture.journal,
            account_id_sha256=manual_demo_account_sha256(ACCOUNT_ID),
            server=SERVER,
            environment="DEMO",
            commit_sha=COMMIT_SHA,
            config_sha256=CONFIG_SHA256,
            key_id=JOURNAL_CHECKPOINT_KEY_ID,
            key_provider=lambda _key_id: JOURNAL_CHECKPOINT_KEY,
            clock_provider=lambda: fixture.clock.value + timedelta(microseconds=1),
            prior_checkpoint=external_before,
            execution_mode="DEMO",
        )

        def racing_journal_exporter(expected_current_sha256, checkpoint):
            fixture.external_journal_checkpoint = competing_head
            return fixture.export_journal_checkpoint(
                expected_current_sha256,
                checkpoint,
            )

        supervisor.journal_checkpoint_exporter = racing_journal_exporter
        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "RUNTIME_CYCLE_FAILED",
        ):
            supervisor.run_cycle()
        self.assertEqual(
            True,
            fixture.journal.kill_switch_status()["latched"],
        )
        self.assertGreaterEqual(
            sum(
                item.row_count
                for item in fixture.external_journal_checkpoint.append_heads
            ),
            sum(item.row_count for item in competing_head.append_heads),
        )
        with sqlite3.connect(root / "supervisor.sqlite3") as connection:
            critical = connection.execute(
                "SELECT critical_latched FROM supervisor_critical_state"
            ).fetchone()[0]
        self.assertEqual(1, critical)

    def test_restored_old_execution_journal_is_rejected_by_external_high_water(self):
        root = self.root / "journal-rollback"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        supervisor = fixture.supervisor()
        supervisor.start(owner_id="runtime-journal-rollback")
        journal_database = root / "execution.sqlite3"
        old_database = root / "execution-old.sqlite3"
        with sqlite3.connect(journal_database) as source, sqlite3.connect(
            old_database
        ) as target:
            source.backup(target)

        fixture.journal.create_intent(
            intent_id="journal-seq2-intent",
            decision_id="journal-seq2-decision",
            symbol=SYMBOL,
            payload={"source": "rollback-adversarial-test"},
            created_at=fixture.clock.value,
        )
        supervisor.run_cycle()
        external_high_water = fixture.external_journal_checkpoint
        assert external_high_water is not None
        self.assertGreater(external_high_water.append_heads[0].row_count, 0)
        decisions_before = fixture.decisions

        for candidate in (
            journal_database,
            Path(f"{journal_database}-wal"),
            Path(f"{journal_database}-shm"),
        ):
            candidate.unlink(missing_ok=True)
        with sqlite3.connect(old_database) as source, sqlite3.connect(
            journal_database
        ) as target:
            source.backup(target)

        with self.assertRaises(RuntimeSupervisorCriticalError):
            supervisor.run_cycle()
        self.assertEqual(decisions_before, fixture.decisions)
        self.assertEqual(
            external_high_water.content_sha256,
            fixture.external_journal_checkpoint.content_sha256,
        )

    def test_risk_checkpoint_cas_rejects_head_change_during_export(self):
        root = self.root / "risk-cas-race"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        supervisor = fixture.supervisor()
        supervisor.start(owner_id="runtime-risk-cas")
        competing_risk_head = fixture.risk_ledger.append_entry(
            EntryRiskEvent(
                entry_id="risk-entry-race-1",
                binding=fixture.risk_ledger.binding,
                occurred_at_utc=fixture.clock.value,
                daily_baseline_id="day-2026-07-22",
                weekly_baseline_id="week-2026-W30",
                symbol=SYMBOL,
            )
        )

        def racing_risk_exporter(expected_current_sha256, checkpoint):
            fixture.checkpoint = checkpoint
            return fixture.export_risk_checkpoint(
                expected_current_sha256,
                checkpoint,
            )

        supervisor.risk_checkpoint_exporter = racing_risk_exporter
        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "RUNTIME_CYCLE_FAILED",
        ):
            supervisor.run_cycle()
        self.assertEqual(
            competing_risk_head.event_sequence,
            fixture.checkpoint.event_sequence,
        )
        with sqlite3.connect(root / "supervisor.sqlite3") as connection:
            critical = connection.execute(
                "SELECT critical_latched FROM supervisor_critical_state"
            ).fetchone()[0]
        self.assertEqual(1, critical)

    def test_risk_seq2_to_seq1_restore_is_rejected_by_external_high_water(self):
        root = self.root / "risk-rollback"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        supervisor = fixture.supervisor()
        supervisor.start(owner_id="runtime-risk-rollback")
        restored_sequence = fixture.checkpoint.event_sequence
        risk_database = root / "risk.sqlite3"
        old_database = root / "risk-seq1.sqlite3"
        with sqlite3.connect(risk_database) as source, sqlite3.connect(
            old_database
        ) as target:
            source.backup(target)

        fixture.risk_ledger.append_entry(
            EntryRiskEvent(
                entry_id="risk-entry-2",
                binding=fixture.risk_ledger.binding,
                occurred_at_utc=fixture.clock.value,
                daily_baseline_id="day-2026-07-22",
                weekly_baseline_id="week-2026-W30",
                symbol=SYMBOL,
            )
        )
        supervisor.run_cycle()
        external_high_water = fixture.checkpoint
        self.assertGreater(external_high_water.event_sequence, restored_sequence)
        decisions_before = fixture.decisions

        for candidate in (
            risk_database,
            Path(f"{risk_database}-wal"),
            Path(f"{risk_database}-shm"),
        ):
            candidate.unlink(missing_ok=True)
        with sqlite3.connect(old_database) as source, sqlite3.connect(
            risk_database
        ) as target:
            source.backup(target)

        with self.assertRaises(RuntimeSupervisorCriticalError):
            supervisor.run_cycle()
        self.assertEqual(decisions_before, fixture.decisions)
        self.assertEqual(
            external_high_water.content_sha256,
            fixture.checkpoint.content_sha256,
        )
        self.assertTrue(fixture.journal.kill_switch_status()["latched"])

    def test_restored_old_supervisor_database_is_rejected_without_head_overwrite(self):
        database = self.root / "supervisor.sqlite3"
        backup = self.root / "supervisor-old.sqlite3"
        supervisor = self.fixture.supervisor()
        with sqlite3.connect(database) as source, sqlite3.connect(backup) as target:
            source.backup(target)
        supervisor.start(owner_id="runtime-a")
        supervisor.stop()
        external_high_water = self.fixture.external_supervisor_checkpoint
        assert external_high_water is not None

        for candidate in (
            database,
            Path(f"{database}-wal"),
            Path(f"{database}-shm"),
        ):
            candidate.unlink(missing_ok=True)
        with sqlite3.connect(backup) as source, sqlite3.connect(database) as target:
            source.backup(target)

        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "SUPERVISOR_STORE_INITIALIZATION_FAILED",
        ):
            self.fixture.supervisor()
        self.assertEqual(
            external_high_water.content_sha256,
            self.fixture.external_supervisor_checkpoint.content_sha256,
        )
        with sqlite3.connect(database) as connection:
            critical = connection.execute(
                "SELECT critical_latched FROM supervisor_critical_state"
            ).fetchone()[0]
        self.assertEqual(1, critical)

    def test_deleted_and_recreated_supervisor_database_has_wrong_incarnation(self):
        database = self.root / "supervisor.sqlite3"
        supervisor = self.fixture.supervisor()
        supervisor.start(owner_id="runtime-a")
        supervisor.stop()
        external_high_water = self.fixture.external_supervisor_checkpoint
        assert external_high_water is not None

        for candidate in (
            database,
            Path(f"{database}-wal"),
            Path(f"{database}-shm"),
        ):
            candidate.unlink(missing_ok=True)

        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "SUPERVISOR_STORE_INITIALIZATION_FAILED",
        ):
            self.fixture.supervisor()
        self.assertEqual(
            external_high_water.content_sha256,
            self.fixture.external_supervisor_checkpoint.content_sha256,
        )

    def test_critical_state_trigger_forbids_reset(self):
        supervisor = self.fixture.supervisor()
        supervisor.start(owner_id="runtime-a")
        supervisor.reconciliation_provider = lambda: ReconciliationResult(
            **{
                **clean_reconciliation().__dict__,
                "status": "RECONCILIATION_CRITICAL_HOLD",
                "orphan_order_tickets": ("orphan-order-1",),
            }
        )
        with self.assertRaises(RuntimeSupervisorCriticalError):
            supervisor.run_cycle()

        with sqlite3.connect(self.root / "supervisor.sqlite3") as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    UPDATE supervisor_critical_state
                    SET critical_latched=0,
                        critical_reason=NULL,
                        critical_latched_at_utc=NULL
                    WHERE singleton=1
                    """
                )

    def test_tampered_receipt_chain_is_rejected_and_kill_switch_latched(self):
        supervisor = self.fixture.supervisor()
        supervisor.start(owner_id="runtime-a")
        supervisor.stop()
        with sqlite3.connect(self.root / "supervisor.sqlite3") as connection:
            connection.execute("DROP TRIGGER supervisor_receipts_no_update")
            connection.execute(
                "UPDATE supervisor_cycle_receipts SET payload_json='{}' WHERE sequence=1"
            )

        with self.assertRaises(RuntimeSupervisorCriticalError):
            supervisor.start(owner_id="runtime-b")

        self.assertTrue(self.fixture.journal.kill_switch_status()["latched"])

    def test_stale_runtime_fact_is_fail_closed(self):
        self.fixture.static_fact = self.fixture.fact_provider()[0]
        self.fixture.clock.value += timedelta(seconds=2)
        supervisor = self.fixture.supervisor()

        with self.assertRaises(RuntimeSupervisorCriticalError):
            supervisor.start(owner_id="runtime-a")

        self.assertTrue(self.fixture.journal.kill_switch_status()["latched"])
        self.assertEqual(0, self.fixture.decisions)

    def test_signed_journal_checkpoint_verification_failure_latches_before_decision(self):
        def reject_checkpoint(checkpoint, prior_checkpoint):
            raise RuntimeError("checkpoint rejected")

        supervisor = self.fixture.supervisor(
            journal_checkpoint_verifier=reject_checkpoint
        )

        with self.assertRaises(RuntimeSupervisorCriticalError):
            supervisor.start(owner_id="runtime-a")

        self.assertEqual(0, self.fixture.decisions)
        self.assertTrue(self.fixture.journal.kill_switch_status()["latched"])

    def test_lease_expiry_latches_and_stops_without_reconciliation_or_decision(self):
        supervisor = self.fixture.supervisor()
        supervisor.start(owner_id="runtime-a", lease_seconds=1)
        self.fixture.trace.clear()
        decisions_before = self.fixture.decisions
        self.fixture.clock.value += timedelta(seconds=2)

        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError, "SUPERVISOR_LEASE_LOST"
        ):
            supervisor.run_cycle()

        self.assertNotIn("reconcile", self.fixture.trace)
        self.assertEqual(decisions_before, self.fixture.decisions)
        self.assertTrue(self.fixture.journal.kill_switch_status()["latched"])

    def test_external_kill_switch_stops_before_decision(self):
        supervisor = self.fixture.supervisor()
        supervisor.start(owner_id="runtime-a")
        decisions_before = self.fixture.decisions
        self.fixture.journal.latch_kill_switch(
            "operator emergency stop", source="TEST"
        )

        with self.assertRaisesRegex(RuntimeSupervisorCriticalError, "KILL_SWITCH_LATCHED"):
            supervisor.run_cycle()

        self.assertEqual(decisions_before, self.fixture.decisions)
        self.assertTrue(supervisor.status().stopped)

    def test_unhealthy_news_guard_stops_before_decision(self):
        supervisor = self.fixture.supervisor()
        supervisor.start(owner_id="runtime-a")
        calls_before = self.fixture.decisions
        supervisor.news_guard_provider = lambda: RuntimeNewsGuard(
            observed_at_utc=self.fixture.clock.value,
            news_feed_fresh=False,
            news_blackout_active=False,
            rollover_blackout_active=False,
        )

        with self.assertRaisesRegex(RuntimeSupervisorCriticalError, "NEWS_FEED_STALE"):
            supervisor.run_cycle()

        self.assertEqual(calls_before, self.fixture.decisions)
        self.assertTrue(self.fixture.journal.kill_switch_status()["latched"])

    def test_evidence_expiring_inside_decision_call_stops_before_receipt(self):
        supervisor = self.fixture.supervisor()
        supervisor.start(owner_id="runtime-a")

        def delayed_decision(facts, risk):
            self.fixture.clock.value += timedelta(seconds=2)
            return RuntimeSupervisorDecision(
                decision_id="decision-after-evidence-expiry",
                action="NO_ACTION",
                decided_at_utc=self.fixture.clock.value,
                decision_payload_sha256="e" * 64,
            )

        supervisor.decision_provider = delayed_decision
        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "JOURNAL_CHECKPOINT_EXPIRED_DURING_CYCLE",
        ):
            supervisor.run_cycle()

        self.assertTrue(self.fixture.journal.kill_switch_status()["latched"])

    def test_demo_auto_and_live_modes_are_hard_denied(self):
        for mode in ("DEMO_AUTO", "LIVE"):
            with self.subTest(mode=mode):
                nested = self.root / mode.lower()
                nested.mkdir()
                fixture = SupervisorFixture(nested, mode=mode)
                executions: list[str] = []
                supervisor = fixture.supervisor(
                    execution_service=lambda decision, approval: executions.append(
                        decision.decision_id
                    )
                )
                with self.assertRaisesRegex(
                    RuntimeSupervisorCriticalError, "MODE_POLICY_LOCKED"
                ):
                    supervisor.start(owner_id=f"runtime-{mode.lower()}")
                self.assertEqual([], executions)
                self.assertTrue(fixture.journal.kill_switch_status()["latched"])

    def test_shadow_manual_execution_request_never_reaches_approval_or_service(self):
        calls: list[str] = []
        supervisor = self.fixture.supervisor(
            decision_provider=lambda facts, risk: RuntimeSupervisorDecision(
                decision_id="shadow-forged-execution",
                action="MANUAL_DEMO_EXECUTE",
                intent_id="intent-shadow-denied",
                decided_at_utc=self.fixture.clock.value,
                decision_payload_sha256="f" * 64,
            ),
            manual_approval_provider=lambda decision: calls.append("approval"),
            manual_demo_policy_callback=lambda decision, validation: calls.append(
                "policy"
            ),
            execution_service=lambda decision, validation: calls.append("service"),
        )
        supervisor.start(owner_id="runtime-shadow")

        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError, "MANUAL_EXECUTION_MODE_DENIED"
        ):
            supervisor.run_cycle()

        self.assertEqual([], calls)
        self.assertTrue(self.fixture.journal.kill_switch_status()["latched"])

    def test_manual_demo_requires_sealed_per_intent_approval_and_policy(self):
        manual_root = self.root / "manual"
        manual_root.mkdir()
        fixture = SupervisorFixture(manual_root, mode="DEMO")
        intent_id = "intent-manual-demo-1"

        def decision(facts, risk):
            fixture.decisions += 1
            return RuntimeSupervisorDecision(
                decision_id="decision-manual-1",
                action="MANUAL_DEMO_EXECUTE",
                intent_id=intent_id,
                decided_at_utc=fixture.clock.value,
                decision_payload_sha256="f" * 64,
            )

        approval = ManualDemoApproval(
            intent_id=intent_id,
            account_id_sha256=manual_demo_account_sha256(ACCOUNT_ID),
            server=SERVER,
            approver_id="operator-1",
            key_id=APPROVAL_KEY_ID,
            issued_at_utc=fixture.clock.value,
            expires_at_utc=fixture.clock.value + timedelta(minutes=1),
            nonce="review-1",
            journal_sha256=fixture.journal.journal_sha256,
        ).sign(APPROVAL_KEY)

        def approval_provider(runtime_decision):
            return validate_manual_demo_approval(
                approval,
                expected_intent_id=runtime_decision.intent_id,
                expected_account_id=ACCOUNT_ID,
                expected_server=SERVER,
                expected_approver_id="operator-1",
                expected_key_id=APPROVAL_KEY_ID,
                expected_journal_sha256=fixture.journal.journal_sha256,
                key_provider=lambda key_id: APPROVAL_KEY,
                clock_provider=fixture.clock,
            )

        calls: list[str] = []
        supervisor = fixture.supervisor(
            decision_provider=decision,
            manual_approval_provider=approval_provider,
            manual_demo_policy_callback=lambda runtime_decision, validation: True,
            execution_service=lambda runtime_decision, validation: (
                calls.append(runtime_decision.intent_id)
                or fixture.manual_execution_result(runtime_decision.intent_id)
            ),
        )
        supervisor.start(owner_id="runtime-demo")
        sequence_before_cycle = fixture.checkpoint.event_sequence

        receipt = supervisor.run_cycle()

        self.assertEqual([intent_id], calls)
        self.assertTrue(receipt.execution_service_called)
        self.assertIsNotNone(receipt.execution_result_sha256)
        self.assertEqual(3, receipt.sequence)
        self.assertEqual(3, fixture.news_sequence)
        self.assertIsNotNone(fixture.last_news_receipt)
        self.assertEqual(
            fixture.last_news_receipt.content_sha256,
            receipt.news_guard_sha256,
        )
        self.assertEqual(
            fixture.last_news_receipt.previous_receipt_sha256,
            receipt.news_guard_previous_sha256,
        )
        with sqlite3.connect(manual_root / "supervisor.sqlite3") as connection:
            predispatch_payload = json.loads(
                connection.execute(
                    "SELECT payload_json FROM supervisor_cycle_receipts WHERE sequence=2"
                ).fetchone()[0]
            )
        self.assertEqual("PRE_DISPATCH", predispatch_payload["phase"])
        self.assertEqual(
            predispatch_payload["news_guard_sha256"],
            receipt.news_guard_previous_sha256,
        )
        self.assertTrue(supervisor.store.verify_integrity())
        # One exact account snapshot is ingested during reconciliation and one
        # exact ENTRY is appended after the broker fill.
        self.assertEqual(
            sequence_before_cycle + 2,
            fixture.checkpoint.event_sequence,
        )
        self.assertEqual(1, fixture.checkpoint.entries_today)
        self.assertEqual(
            fixture.current_risk_source.content_sha256,
            fixture.risk_ledger.current_receipt().latest_source_receipt_sha256,
        )
        self.assertFalse(supervisor.status().manual_demo_enabled)

    def test_slow_manual_approval_expires_decision_before_dispatch(self):
        root = self.root / "slow-approval"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        calls: list[str] = []
        supervisor = self._manual_demo_supervisor(
            fixture,
            intent_id="intent-slow-approval",
            execution_service=lambda decision, validation: calls.append("called"),
        )
        original_approval = supervisor.manual_approval_provider
        assert original_approval is not None

        def slow_approval(decision):
            fixture.clock.value += timedelta(seconds=1.1)
            return original_approval(decision)

        supervisor.manual_approval_provider = slow_approval
        supervisor.start(owner_id="runtime-slow-approval")

        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "DECISION_EXPIRED_DURING_DISPATCH",
        ):
            supervisor.run_cycle()

        self.assertEqual([], calls)
        self.assertTrue(fixture.journal.kill_switch_status()["latched"])
        self.assertTrue(supervisor.store.critical_state()["critical_latched"])

    def test_slow_manual_policy_expires_decision_before_dispatch(self):
        root = self.root / "slow-policy"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        calls: list[str] = []
        supervisor = self._manual_demo_supervisor(
            fixture,
            intent_id="intent-slow-policy",
            execution_service=lambda decision, validation: calls.append("called"),
        )

        def slow_policy(decision, validation):
            fixture.clock.value += timedelta(seconds=1.1)
            return True

        supervisor.manual_demo_policy_callback = slow_policy
        supervisor.start(owner_id="runtime-slow-policy")

        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "DECISION_EXPIRED_DURING_DISPATCH",
        ):
            supervisor.run_cycle()

        self.assertEqual([], calls)
        self.assertTrue(fixture.journal.kill_switch_status()["latched"])
        self.assertTrue(supervisor.store.critical_state()["critical_latched"])

    def test_news_blackout_change_after_policy_denies_dispatch(self):
        root = self.root / "news-blackout-after-policy"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        calls: list[str] = []
        supervisor = self._manual_demo_supervisor(
            fixture,
            intent_id="intent-news-blackout",
            execution_service=lambda decision, validation: calls.append("called"),
        )

        def activate_blackout(decision, validation):
            fixture.news_blackout_active = True
            return True

        supervisor.manual_demo_policy_callback = activate_blackout
        supervisor.start(owner_id="runtime-news-blackout")

        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "NEWS_BLACKOUT_ACTIVE",
        ):
            supervisor.run_cycle()

        self.assertEqual([], calls)
        self.assertEqual(3, fixture.news_sequence)
        self.assertTrue(fixture.journal.kill_switch_status()["latched"])
        self.assertTrue(supervisor.store.critical_state()["critical_latched"])

    def test_news_feed_stales_after_policy_denies_dispatch(self):
        root = self.root / "news-stale-after-policy"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        calls: list[str] = []
        supervisor = self._manual_demo_supervisor(
            fixture,
            intent_id="intent-news-stale",
            execution_service=lambda decision, validation: calls.append("called"),
        )

        def stale_feed(decision, validation):
            fixture.news_feed_fresh = False
            return True

        supervisor.manual_demo_policy_callback = stale_feed
        supervisor.start(owner_id="runtime-news-stale")

        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "NEWS_FEED_STALE",
        ):
            supervisor.run_cycle()

        self.assertEqual([], calls)
        self.assertEqual(3, fixture.news_sequence)
        self.assertTrue(fixture.journal.kill_switch_status()["latched"])
        self.assertTrue(supervisor.store.critical_state()["critical_latched"])

    def test_final_news_receipt_must_extend_predispatch_predecessor(self):
        root = self.root / "news-final-predecessor-fork"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        calls: list[str] = []
        supervisor = self._manual_demo_supervisor(
            fixture,
            intent_id="intent-news-final-fork",
            execution_service=lambda decision, validation: calls.append("called"),
        )
        supervisor.start(owner_id="runtime-news-final-fork")
        normal_news = supervisor.news_guard_provider

        def fork_final_news():
            if fixture.news_sequence == 1:
                return normal_news()
            return issue_runtime_news_guard_receipt(
                provider_id=NEWS_PROVIDER_ID,
                key_id=NEWS_KEY_ID,
                key=NEWS_KEY,
                account_id_sha256=fixture.binding.account_id_sha256,
                server=SERVER,
                environment="DEMO",
                observed_at_utc=fixture.clock.value,
                valid_until_utc=fixture.clock.value + timedelta(seconds=30),
                feed_sequence=fixture.news_sequence + 1,
                feed_payload_sha256=digest("forked-final-feed"),
                previous_receipt_sha256="0" * 64,
                news_feed_fresh=True,
                news_blackout_active=False,
                rollover_blackout_active=False,
                blackout_window_sha256=NEWS_WINDOW_SHA256,
                ruleset_sha256=NEWS_RULESET_SHA256,
                config_sha256=CONFIG_SHA256,
            )

        supervisor.news_guard_provider = fork_final_news

        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "NEWS_GUARD_REPLAY_ROLLBACK_OR_FORK",
        ):
            supervisor.run_cycle()

        self.assertEqual([], calls)
        self.assertTrue(fixture.journal.kill_switch_status()["latched"])
        self.assertTrue(supervisor.store.critical_state()["critical_latched"])

    def test_successful_manual_execution_without_entry_evidence_latches(self):
        root = self.root / "missing-entry"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        supervisor = self._manual_demo_supervisor(
            fixture,
            intent_id="intent-missing-entry",
            execution_service=lambda decision, validation: {"status": "FILLED"},
        )
        supervisor.start(owner_id="runtime-missing-entry")
        sequence_before_cycle = fixture.risk_ledger.current_receipt().event_sequence

        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "MANUAL_EXECUTION_RESULT_EVIDENCE_INVALID",
        ):
            supervisor.run_cycle()

        # Reconciliation still ingests its exact account snapshot; the missing
        # execution evidence must not add an ENTRY.
        self.assertEqual(
            sequence_before_cycle + 1,
            fixture.risk_ledger.current_receipt().event_sequence,
        )
        self.assertTrue(fixture.journal.kill_switch_status()["latched"])

    def test_manual_execution_rejects_stale_account_snapshot(self):
        root = self.root / "stale-account-snapshot"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        calls: list[str] = []
        supervisor = self._manual_demo_supervisor(
            fixture,
            intent_id="intent-stale-snapshot",
            execution_service=lambda decision, validation: calls.append("called"),
        )
        supervisor.start(owner_id="runtime-stale-snapshot")
        fixture.clock.value += timedelta(seconds=0.6)
        fixture.fact_observed_lag_seconds = 0.55
        fixture.fact_validity_seconds = 1.0

        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "FRESH_ACCOUNT_RISK_SNAPSHOT_REQUIRED",
        ):
            supervisor.run_cycle()

        self.assertEqual([], calls)
        self.assertTrue(fixture.journal.kill_switch_status()["latched"])

    def test_manual_execution_rejects_runtime_equity_mismatch(self):
        root = self.root / "equity-mismatch"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        calls: list[str] = []
        supervisor = self._manual_demo_supervisor(
            fixture,
            intent_id="intent-equity-mismatch",
            execution_service=lambda decision, validation: calls.append("called"),
        )
        supervisor.start(owner_id="runtime-equity-mismatch")
        original_reconciliation = supervisor.reconciliation_provider

        def mismatched_reconciliation():
            result = original_reconciliation()
            evidence = result.account_snapshot_evidence
            assert evidence is not None
            fixture.extra_pending_fact = fixture._resign_fact(
                evidence.upstream_receipt,
                symbol="USDJPY",
                broker_symbol="USDJPY.ps01",
                equity=evidence.event.equity - 1.0,
            )
            return result

        supervisor.reconciliation_provider = mismatched_reconciliation

        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "RISK_EQUITY_RUNTIME_FACT_MISMATCH",
        ):
            supervisor.run_cycle()

        self.assertEqual([], calls)
        self.assertTrue(fixture.journal.kill_switch_status()["latched"])

    def test_demo_reconciliation_missing_closed_trade_receipt_latches(self):
        root = self.root / "missing-close"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        supervisor = fixture.supervisor()
        supervisor.start(owner_id="runtime-missing-close")
        clean = clean_reconciliation()
        supervisor.reconciliation_provider = lambda: ReconciliationResult(
            **{**clean.__dict__, "closed_intents": ("intent-without-close-risk",)}
        )

        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "RECONCILIATION_RISK_RESULT_REQUIRED",
        ):
            supervisor.run_cycle()

        self.assertTrue(fixture.journal.kill_switch_status()["latched"])

    def test_demo_reconciliation_ingests_exact_closed_trade_once(self):
        root = self.root / "exact-close"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        intent_id = "intent-exact-close"
        entry = EntryRiskEvent(
            entry_id=intent_id,
            binding=fixture.risk_ledger.binding,
            occurred_at_utc=fixture.clock.value,
            daily_baseline_id="day-2026-07-22",
            weekly_baseline_id="week-2026-W30",
            symbol=SYMBOL,
        )
        entry_source, entry_upstream = fixture.risk_ledger._provenance(
            entry, "ENTRY"
        )
        fixture.checkpoint = fixture.risk_ledger.append_entry(
            entry,
            source_receipt=entry_source,
            upstream_receipt=entry_upstream,
        )
        fixture.current_risk_source = entry_source
        supervisor = fixture.supervisor()
        supervisor.start(owner_id="runtime-exact-close")
        sequence_before = fixture.checkpoint.event_sequence
        original_reconciliation = supervisor.reconciliation_provider

        def exact_closed_reconciliation():
            base = original_reconciliation()
            snapshot = base.account_snapshot_evidence
            assert snapshot is not None
            prior = fixture.verified_broker_reconciliation_previous
            closed = ReconciliationResult(
                **{
                    **clean_reconciliation().__dict__,
                    "closed_intents": (intent_id,),
                }
            )
            broker = issue_broker_reconciliation_receipt(
                result=closed,
                account_id_sha256=fixture.binding.account_id_sha256,
                server=fixture.binding.server,
                environment=fixture.binding.environment,
                journal_sha256=fixture.binding.journal_sha256,
                query_from_utc=fixture.clock.value - timedelta(minutes=1),
                query_to_utc=fixture.clock.value,
                source_time_utc=fixture.clock.value,
                observed_at_utc=fixture.clock.value,
                source_sequence=fixture.risk_refresh_sequence,
                previous_receipt_sha256=(
                    "0" * 64 if prior is None else prior.content_sha256
                ),
                order_tickets=("order-close-1",),
                position_tickets=("position-close-1",),
                deal_tickets=("deal-close-1",),
                closed_intent_deal_tickets={
                    intent_id: ("deal-close-1",)
                },
                raw_payload_sha256=digest("exact-close-broker-payload"),
                provider_id=BROKER_RECONCILIATION_PROVIDER_ID,
                key_id=BROKER_RECONCILIATION_KEY_ID,
                key=BROKER_RECONCILIATION_KEY,
            )
            fixture.broker_reconciliation_previous = broker
            deal = issue_broker_deal_receipt(
                reconciliation_receipt=broker,
                intent_id=intent_id,
                deal_sequence=1,
                deal_ticket="deal-close-1",
                order_ticket="order-close-1",
                position_ticket="position-close-1",
                canonical_symbol=SYMBOL,
                broker_symbol=BROKER_SYMBOL,
                account_currency=CURRENCY,
                entry_side="BUY",
                exit_side="SELL",
                volume=0.01,
                fill_price=1.18,
                profit_account_currency=1_000.0,
                commission_account_currency=-10.0,
                swap_account_currency=-2.0,
                fee_account_currency=-1.0,
                source_time_utc=fixture.clock.value,
                raw_payload_sha256=digest("exact-close-deal-payload"),
                key=BROKER_RECONCILIATION_KEY,
            )
            aggregate = issue_broker_closed_trade_receipt(
                reconciliation_receipt=broker,
                intent_id=intent_id,
                deal_receipts=(deal,),
                expected_closed_volume=0.01,
                key=BROKER_RECONCILIATION_KEY,
            )
            close_event = ClosedTradeRiskEvent(
                trade_id=aggregate.trade_id,
                entry_id=intent_id,
                binding=fixture.risk_ledger.binding,
                occurred_at_utc=aggregate.closed_at_utc,
                daily_baseline_id="day-2026-07-22",
                weekly_baseline_id="week-2026-W30",
                symbol=SYMBOL,
                outcome="WIN",
                realized_pnl_account_currency=(
                    aggregate.realized_net_pnl_account_currency
                ),
            )
            unsigned = {
                "source_receipt_id": f"source-close-{close_event.content_sha256[:24]}",
                "source_kind": "CLOSED_TRADE",
                "issuer_id": SOURCE_ISSUER,
                "key_id": SOURCE_KEY_ID,
                "binding": fixture.risk_ledger.binding.to_canonical_dict(),
                "event_sha256": close_event.content_sha256,
                "upstream_receipt_type": "BROKER_CLOSED_TRADE_RECEIPT",
                "upstream_receipt_sha256": aggregate.content_sha256,
                "observed_at_utc": fixture.clock.value,
                "valid_until_utc": fixture.clock.value + timedelta(seconds=5),
                "schema_version": "durable-risk-source-receipt-v1",
            }
            signature = hmac.new(
                SOURCE_KEY,
                b"AI_SCALPER_DURABLE_RISK_SOURCE_V1\x00"
                + canonical_json(unsigned).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            close_source = verify_risk_source_receipt(
                {**unsigned, "signature_hmac_sha256": signature},
                expected_event=close_event,
                expected_binding=fixture.risk_ledger.binding,
                key_provider=lambda _key_id: SOURCE_KEY,
                trusted_issuer_keys={SOURCE_ISSUER: (SOURCE_KEY_ID,)},
                clock_provider=fixture.clock,
            )
            return seal_runtime_reconciliation_risk_result(
                closed,
                broker_reconciliation_receipt=broker,
                closed_trade_evidence=(
                    RuntimeClosedTradeRiskEvidence(
                        event=close_event,
                        source_receipt=close_source,
                        upstream_receipt=aggregate,
                    ),
                ),
                account_snapshot_evidence=snapshot,
            )

        fixture.account_equity = 100_987.0
        supervisor.reconciliation_provider = exact_closed_reconciliation
        supervisor.run_cycle()

        # Exactly one CLOSED_TRADE and one ACCOUNT_SNAPSHOT advance the ledger.
        self.assertEqual(sequence_before + 2, fixture.checkpoint.event_sequence)
        self.assertEqual(100_987.0, fixture.checkpoint.current_equity)
        self.assertEqual(0, fixture.checkpoint.consecutive_losses)

    def test_policy_denial_prevents_manual_demo_execution_and_latches(self):
        deny_root = self.root / "deny"
        deny_root.mkdir()
        fixture = SupervisorFixture(deny_root, mode="DEMO")
        intent_id = "intent-denied-1"
        approval = ManualDemoApproval(
            intent_id=intent_id,
            account_id_sha256=manual_demo_account_sha256(ACCOUNT_ID),
            server=SERVER,
            approver_id="operator-1",
            key_id=APPROVAL_KEY_ID,
            issued_at_utc=fixture.clock.value,
            expires_at_utc=fixture.clock.value + timedelta(minutes=1),
            nonce="review-deny-1",
            journal_sha256=fixture.journal.journal_sha256,
        ).sign(APPROVAL_KEY)
        decision = lambda facts, risk: RuntimeSupervisorDecision(
            decision_id="decision-denied-1",
            action="MANUAL_DEMO_EXECUTE",
            intent_id=intent_id,
            decided_at_utc=fixture.clock.value,
            decision_payload_sha256="f" * 64,
        )
        validation = lambda runtime_decision: validate_manual_demo_approval(
            approval,
            expected_intent_id=intent_id,
            expected_account_id=ACCOUNT_ID,
            expected_server=SERVER,
            expected_approver_id="operator-1",
            expected_key_id=APPROVAL_KEY_ID,
            expected_journal_sha256=fixture.journal.journal_sha256,
            key_provider=lambda key_id: APPROVAL_KEY,
            clock_provider=fixture.clock,
        )
        calls: list[str] = []
        supervisor = fixture.supervisor(
            decision_provider=decision,
            manual_approval_provider=validation,
            manual_demo_policy_callback=lambda runtime_decision, approval: False,
            execution_service=lambda runtime_decision, approval: calls.append("called"),
        )
        supervisor.start(owner_id="runtime-demo")

        with self.assertRaisesRegex(RuntimeSupervisorCriticalError, "MANUAL_POLICY_DENIED"):
            supervisor.run_cycle()

        self.assertEqual([], calls)
        self.assertTrue(fixture.journal.kill_switch_status()["latched"])

    def test_manual_stage_authorization_is_consumed_once_at_startup_and_hashed(self):
        root = self.root / "stage-once"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        supervisor = fixture.supervisor()

        startup = supervisor.start(owner_id="runtime-demo-stage")
        supervisor.run_cycle()

        self.assertEqual(1, fixture.stage.validation_calls)
        self.assertEqual("MANUAL_DEMO", startup.stage_mode)
        self.assertEqual(
            fixture.stage_ports.authorization.content_sha256,
            startup.stage_authorization_sha256,
        )
        self.assertEqual(
            fixture.stage.pre_manual_entry_review_sha256,
            startup.stage_pre_manual_entry_review_sha256,
        )
        self.assertIsNotNone(startup.stage_validation_sha256)
        self.assertEqual(
            fixture.stage_ports.external_replay_checkpoint.content_sha256,
            startup.stage_external_checkpoint_sha256,
        )
        self.assertIsNotNone(startup.stage_replay_checkpoint_sha256)

    def test_stage_validation_review_hash_mismatch_fails_before_ready(self):
        root = self.root / "stage-review-mismatch"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        assert fixture.stage_ports is not None
        original_validator = fixture.stage_ports.authorization_validator

        def mismatched_validator(now, expected_mode):
            validation = original_validator(now, expected_mode)
            object.__setattr__(
                validation,
                "pre_manual_entry_review_sha256",
                digest("forged-pre-manual-review"),
            )
            return validation

        bad_ports = replace(
            fixture.stage_ports,
            authorization_validator=mismatched_validator,
        )
        supervisor = fixture.supervisor(stage_authorization_ports=bad_ports)

        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "STAGE_AUTHORIZATION_VALIDATION_FAILED",
        ):
            supervisor.start(owner_id="runtime-review-mismatch")

        self.assertEqual(1, fixture.stage.validation_calls)
        with sqlite3.connect(root / "supervisor.sqlite3") as connection:
            statuses = tuple(
                json.loads(row[0])["status"]
                for row in connection.execute(
                    """
                    SELECT payload_json
                    FROM supervisor_cycle_receipts
                    ORDER BY sequence
                    """
                ).fetchall()
            )
        self.assertEqual(("STOPPED",), statuses)
        self.assertNotIn("READY", statuses)
        self.assertTrue(fixture.journal.kill_switch_status()["latched"])

    def test_incomplete_stage_receipt_rolls_back_before_append(self):
        root = self.root / "incomplete-stage-receipt"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        supervisor = fixture.supervisor()
        owner = "runtime-incomplete-stage"
        token = supervisor.store.claim(
            owner,
            lease_seconds=30,
            now=fixture.clock.value,
        )
        assert fixture.stage_ports is not None
        authorization = fixture.stage_ports.authorization

        with self.assertRaisesRegex(
            ValueError,
            "stage startup receipt fields must be complete",
        ):
            supervisor.store.append(
                owner_id=owner,
                fence_token=token,
                cycle_id="startup-incomplete-stage",
                phase="STARTUP",
                status="READY",
                occurred_at=fixture.clock.value,
                news_guard_sha256=digest("news-guard"),
                news_guard_provider_id=NEWS_PROVIDER_ID,
                news_guard_feed_sequence=1,
                news_guard_previous_sha256="0" * 64,
                stage_mode="MANUAL_DEMO",
                stage_authorization_id=authorization.authorization_id,
                stage_authorization_sha256=authorization.content_sha256,
                stage_validation_sha256=digest("stage-validation"),
                stage_external_checkpoint_sha256=digest(
                    "stage-external-checkpoint"
                ),
                stage_replay_checkpoint_sha256=digest(
                    "stage-replay-checkpoint"
                ),
            )

        self.assertEqual(0, supervisor.store.receipt_count())

    def test_manual_demo_restart_requires_a_new_stage_authorization(self):
        root = self.root / "stage-restart"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        first = fixture.supervisor()
        first_start = first.start(owner_id="runtime-demo-a")
        first.stop()

        fixture.stage_ports = fixture.stage.ports("MANUAL_DEMO")
        second = fixture.supervisor()
        second_start = second.start(owner_id="runtime-demo-b")

        self.assertNotEqual(
            first_start.stage_authorization_id,
            second_start.stage_authorization_id,
        )
        self.assertEqual(2, fixture.stage.validation_calls)
        self.assertGreater(second_start.fence_token, first_start.fence_token)

    def test_manual_demo_restart_rejects_reused_stage_authorization(self):
        root = self.root / "stage-replay"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        reused_ports = fixture.stage_ports
        first = fixture.supervisor()
        first.start(owner_id="runtime-demo-a")
        first.stop()

        second = fixture.supervisor(stage_authorization_ports=reused_ports)
        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError, "STAGE_AUTHORIZATION_REPLAYED"
        ):
            second.start(owner_id="runtime-demo-b")

        self.assertEqual(1, fixture.stage.validation_calls)
        self.assertTrue(fixture.journal.kill_switch_status()["latched"])

    def test_stage_binding_mismatch_fails_before_consumption(self):
        root = self.root / "stage-binding"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        assert fixture.stage_ports is not None
        wrong_binding = replace(
            fixture.stage.binding,
            runtime_profile_sha256=digest("other-runtime-profile"),
        )
        wrong_ports = replace(
            fixture.stage_ports,
            expected_binding=wrong_binding,
        )
        supervisor = fixture.supervisor(stage_authorization_ports=wrong_ports)

        with self.assertRaises(RuntimeSupervisorCriticalError):
            supervisor.start(owner_id="runtime-wrong-stage-binding")

        self.assertEqual(0, fixture.stage.validation_calls)

    def test_invalid_external_stage_checkpoint_fails_closed(self):
        root = self.root / "stage-checkpoint"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        assert fixture.stage_ports is not None
        bad_checkpoint = replace(
            fixture.stage_ports.external_replay_checkpoint,
            signature_hmac_sha256=digest("bad-stage-checkpoint"),
        )
        bad_ports = replace(
            fixture.stage_ports,
            external_replay_checkpoint=bad_checkpoint,
        )
        supervisor = fixture.supervisor(stage_authorization_ports=bad_ports)

        with self.assertRaises(RuntimeSupervisorCriticalError):
            supervisor.start(owner_id="runtime-bad-stage-checkpoint")

        self.assertEqual(0, fixture.stage.validation_calls)

    def test_execution_mode_rejects_raw_caller_constructed_news_guard(self):
        root = self.root / "raw-news"
        root.mkdir()
        fixture = SupervisorFixture(root, mode="DEMO")
        supervisor = fixture.supervisor(
            news_guard_provider=lambda: RuntimeNewsGuard(
                observed_at_utc=fixture.clock.value,
                news_feed_fresh=True,
                news_blackout_active=False,
                rollover_blackout_active=False,
            )
        )

        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError, "SIGNED_NEWS_GUARD_REQUIRED"
        ):
            supervisor.start(owner_id="runtime-raw-news")

        self.assertEqual(0, fixture.stage.validation_calls)

    def test_signed_news_guard_replay_inside_ttl_is_rejected(self):
        root = self.root / "news-replay"
        root.mkdir()
        fixture = SupervisorFixture(root, signed_news=True)
        supervisor = fixture.supervisor()
        supervisor.start(owner_id="runtime-signed-news")
        replayed = fixture.last_news_receipt
        assert replayed is not None
        supervisor.news_guard_provider = lambda: replayed

        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError, "NEWS_GUARD_REPLAY_ROLLBACK_OR_FORK"
        ):
            supervisor.run_cycle()

        self.assertTrue(fixture.journal.kill_switch_status()["latched"])

    def test_signed_news_guard_predecessor_fork_is_rejected(self):
        root = self.root / "news-fork"
        root.mkdir()
        fixture = SupervisorFixture(root, signed_news=True)
        supervisor = fixture.supervisor()
        supervisor.start(owner_id="runtime-signed-news")
        fork = issue_runtime_news_guard_receipt(
            provider_id=NEWS_PROVIDER_ID,
            key_id=NEWS_KEY_ID,
            key=NEWS_KEY,
            account_id_sha256=fixture.binding.account_id_sha256,
            server=SERVER,
            environment="DEMO",
            observed_at_utc=fixture.clock.value,
            valid_until_utc=fixture.clock.value + timedelta(seconds=30),
            feed_sequence=fixture.news_sequence + 1,
            feed_payload_sha256=digest("forked-feed"),
            previous_receipt_sha256="0" * 64,
            news_feed_fresh=True,
            news_blackout_active=False,
            rollover_blackout_active=False,
            blackout_window_sha256=NEWS_WINDOW_SHA256,
            ruleset_sha256=NEWS_RULESET_SHA256,
            config_sha256=CONFIG_SHA256,
        )
        supervisor.news_guard_provider = lambda: fork

        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError, "NEWS_GUARD_REPLAY_ROLLBACK_OR_FORK"
        ):
            supervisor.run_cycle()

    def test_signed_news_guard_signature_tamper_is_rejected(self):
        root = self.root / "news-signature"
        root.mkdir()
        fixture = SupervisorFixture(root, signed_news=True)
        forged = fixture.news()
        assert type(forged) is RuntimeNewsGuardReceipt
        object.__setattr__(forged, "signature_hmac_sha256", digest("forged-news"))
        supervisor = fixture.supervisor(news_guard_provider=lambda: forged)

        with self.assertRaises(RuntimeSupervisorCriticalError):
            supervisor.start(owner_id="runtime-forged-news")

    def test_signed_news_verifier_must_return_exact_receipt(self):
        root = self.root / "news-exact-verifier"
        root.mkdir()
        fixture = SupervisorFixture(root, signed_news=True)
        supplied = fixture.news()
        assert type(supplied) is RuntimeNewsGuardReceipt
        other = issue_runtime_news_guard_receipt(
            provider_id=NEWS_PROVIDER_ID,
            key_id=NEWS_KEY_ID,
            key=NEWS_KEY,
            account_id_sha256=fixture.binding.account_id_sha256,
            server=SERVER,
            environment="DEMO",
            observed_at_utc=fixture.clock.value,
            valid_until_utc=fixture.clock.value + timedelta(seconds=30),
            feed_sequence=supplied.feed_sequence,
            feed_payload_sha256=digest("different-sealed-feed"),
            previous_receipt_sha256=supplied.previous_receipt_sha256,
            news_feed_fresh=True,
            news_blackout_active=False,
            rollover_blackout_active=False,
            blackout_window_sha256=NEWS_WINDOW_SHA256,
            ruleset_sha256=NEWS_RULESET_SHA256,
            config_sha256=CONFIG_SHA256,
        )
        supervisor = fixture.supervisor(
            news_guard_provider=lambda: supplied,
            news_guard_verifier=lambda _receipt: other,
        )

        with self.assertRaises(RuntimeSupervisorCriticalError):
            supervisor.start(owner_id="runtime-non-exact-news-verifier")

    def test_news_guard_provider_binding_mismatch_is_rejected(self):
        root = self.root / "news-provider"
        root.mkdir()
        fixture = SupervisorFixture(root, signed_news=True)
        wrong = issue_runtime_news_guard_receipt(
            provider_id="unreviewed-provider",
            key_id=NEWS_KEY_ID,
            key=NEWS_KEY,
            account_id_sha256=fixture.binding.account_id_sha256,
            server=SERVER,
            environment="DEMO",
            observed_at_utc=fixture.clock.value,
            valid_until_utc=fixture.clock.value + timedelta(seconds=30),
            feed_sequence=1,
            feed_payload_sha256=digest("wrong-provider-feed"),
            previous_receipt_sha256="0" * 64,
            news_feed_fresh=True,
            news_blackout_active=False,
            rollover_blackout_active=False,
            blackout_window_sha256=NEWS_WINDOW_SHA256,
            ruleset_sha256=NEWS_RULESET_SHA256,
            config_sha256=CONFIG_SHA256,
        )
        supervisor = fixture.supervisor(news_guard_provider=lambda: wrong)

        with self.assertRaises(RuntimeSupervisorCriticalError):
            supervisor.start(owner_id="runtime-wrong-news-provider")

    def test_signed_news_trust_profile_drift_is_rejected_by_store_binding(self):
        root = self.root / "news-trust-drift"
        root.mkdir()
        fixture = SupervisorFixture(root, signed_news=True)

        with self.assertRaisesRegex(
            RuntimeSupervisorBindingError, "trust profile"
        ):
            fixture.supervisor(news_guard_ruleset_sha256=digest("other-ruleset"))

    def test_supervisor_store_never_serializes_raw_account_alias(self):
        supervisor = self.fixture.supervisor()
        supervisor.start(owner_id="runtime-private-binding")
        supervisor.stop()

        with sqlite3.connect(self.root / "supervisor.sqlite3") as connection:
            identity = connection.execute(
                "SELECT binding_json FROM supervisor_identity"
            ).fetchone()[0]
            payloads = "\n".join(
                row[0]
                for row in connection.execute(
                    "SELECT payload_json FROM supervisor_cycle_receipts"
                ).fetchall()
            )
        self.assertNotIn(ACCOUNT_ID, identity)
        self.assertNotIn(ACCOUNT_ID, payloads)
        self.assertIn(manual_demo_account_sha256(ACCOUNT_ID), identity)

    def test_bounded_run_stops_gracefully_and_status_never_unlocks(self):
        supervisor = self.fixture.supervisor()
        supervisor.start(owner_id="runtime-a")

        receipts = supervisor.run_bounded(max_cycles=2)
        status = supervisor.status()

        self.assertEqual(2, len(receipts))
        self.assertTrue(status.stopped)
        self.assertEqual("DISABLED", status.order_capability)
        self.assertFalse(status.execution_enabled)
        self.assertFalse(status.manual_demo_enabled)
        self.assertFalse(status.live_allowed)
        self.assertFalse(status.safe_to_demo_auto_order)
        self.assertEqual(4, status.receipts)  # startup + two cycles + shutdown

    def test_stop_cannot_overwrite_an_existing_critical_state(self):
        supervisor = self.fixture.supervisor()
        supervisor.start(owner_id="runtime-critical-stop")
        with self.assertRaises(RuntimeSupervisorCriticalError):
            supervisor.fail_closed("SERVICE_CYCLE_DEADLINE_EXCEEDED")
        before = supervisor.status()
        self.assertEqual("STOPPED_CRITICAL", before.state)
        self.assertTrue(supervisor.store.critical_state()["critical_latched"])
        self.assertIsNone(supervisor.stop())
        after = supervisor.status()
        self.assertEqual("STOPPED_CRITICAL", after.state)
        self.assertTrue(supervisor.store.critical_state()["critical_latched"])


if __name__ == "__main__":
    unittest.main()
