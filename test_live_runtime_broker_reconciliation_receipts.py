from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import unittest

from live_runtime.contracts import canonical_json
from live_runtime.reconciliation import (
    BrokerDealReceipt,
    BrokerClosedTradeReceipt,
    BrokerReconciliationReceipt,
    ReconciliationResult,
    issue_broker_deal_receipt,
    issue_broker_closed_trade_receipt,
    issue_broker_reconciliation_receipt,
    verify_broker_deal_receipt,
    verify_broker_reconciliation_receipt,
)
from live_runtime.runtime_supervisor import (
    RuntimeClosedTradeRiskEvidence,
    seal_runtime_reconciliation_risk_result,
)
from live_runtime.risk_ledger import (
    ClosedTradeRiskEvent,
    RiskLedgerBinding,
    verify_risk_source_receipt,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 22, 5, 0, tzinfo=UTC)
ACCOUNT_SHA = hashlib.sha256(b"demo-account").hexdigest()
JOURNAL_SHA = hashlib.sha256(b"journal").hexdigest()
KEY = b"broker-reconciliation-test-key-material-32-bytes"
KEY_ID = "broker-reconciliation-key-v1"
PROVIDER_ID = "trusted-mt5-reconciler-v1"
SERVER = "PhillipSecuritiesJP-PROD"
SOURCE_KEY = b"broker-risk-source-test-key-material-32-bytes"
SOURCE_KEY_ID = "broker-risk-source-key-v1"
SOURCE_ISSUER = "trusted-broker-risk-source-v1"
SOURCE_DOMAIN = b"AI_SCALPER_DURABLE_RISK_SOURCE_V1\x00"


def result(*, closed: tuple[str, ...] = ()) -> ReconciliationResult:
    return ReconciliationResult(
        status="RECONCILIATION_COMPLETE",
        matched_intents=(),
        uncertain_intents=(),
        closed_intents=closed,
        orphan_position_tickets=(),
        orphan_order_tickets=(),
        protection_failures=(),
        volume_failures=(),
        binding_failures=(),
        kill_switch_latched=False,
    )


def issue_reconciliation(
    reconciled: ReconciliationResult,
    *,
    sequence: int = 1,
    previous: BrokerReconciliationReceipt | None = None,
    deal_tickets: tuple[str, ...] = ("deal-1",),
) -> BrokerReconciliationReceipt:
    return issue_broker_reconciliation_receipt(
        result=reconciled,
        account_id_sha256=ACCOUNT_SHA,
        server=SERVER,
        environment="DEMO",
        journal_sha256=JOURNAL_SHA,
        query_from_utc=NOW - timedelta(hours=1),
        query_to_utc=NOW,
        source_time_utc=NOW - timedelta(seconds=1),
        observed_at_utc=NOW,
        source_sequence=sequence,
        previous_receipt_sha256=(
            "0" * 64 if previous is None else previous.content_sha256
        ),
        order_tickets=("order-1",),
        position_tickets=("position-1",),
        deal_tickets=deal_tickets,
        closed_intent_deal_tickets={
            intent_id: deal_tickets for intent_id in reconciled.closed_intents
        },
        raw_payload_sha256=hashlib.sha256(
            f"payload:{sequence}".encode("utf-8")
        ).hexdigest(),
        provider_id=PROVIDER_ID,
        key_id=KEY_ID,
        key=KEY,
    )


def issue_deal(
    observation: BrokerReconciliationReceipt,
    *,
    intent_id: str = "intent-1",
    deal_sequence: int = 1,
    deal_ticket: str = "deal-1",
    volume: float = 0.01,
    profit: float = 1_000.0,
    commission: float = -10.0,
    swap: float = -2.0,
    fee: float = -1.0,
) -> BrokerDealReceipt:
    return issue_broker_deal_receipt(
        reconciliation_receipt=observation,
        intent_id=intent_id,
        deal_sequence=deal_sequence,
        deal_ticket=deal_ticket,
        order_ticket="order-1",
        position_ticket="position-1",
        canonical_symbol="EURUSD",
        broker_symbol="EURUSD.ps01",
        account_currency="JPY",
        entry_side="BUY",
        exit_side="SELL",
        volume=volume,
        fill_price=1.17,
        profit_account_currency=profit,
        commission_account_currency=commission,
        swap_account_currency=swap,
        fee_account_currency=fee,
        source_time_utc=NOW - timedelta(seconds=1),
        raw_payload_sha256=hashlib.sha256(b"deal-payload").hexdigest(),
        key=KEY,
    )


def issue_risk_source(event, deal, binding):
    unsigned = {
        "source_receipt_id": f"source-{event.content_sha256[:32]}",
        "source_kind": "CLOSED_TRADE",
        "issuer_id": SOURCE_ISSUER,
        "key_id": SOURCE_KEY_ID,
        "binding": binding.to_canonical_dict(),
        "event_sha256": event.content_sha256,
        "upstream_receipt_type": "BROKER_CLOSED_TRADE_RECEIPT",
        "upstream_receipt_sha256": deal.content_sha256,
        "observed_at_utc": NOW,
        "valid_until_utc": NOW + timedelta(seconds=5),
        "schema_version": "durable-risk-source-receipt-v1",
    }
    signature = hmac.new(
        SOURCE_KEY,
        SOURCE_DOMAIN + canonical_json(unsigned).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return verify_risk_source_receipt(
        {**unsigned, "signature_hmac_sha256": signature},
        expected_event=event,
        expected_binding=binding,
        key_provider=lambda _key_id: SOURCE_KEY,
        trusted_issuer_keys={SOURCE_ISSUER: (SOURCE_KEY_ID,)},
        clock_provider=lambda: NOW,
    )


class BrokerReconciliationReceiptTests(unittest.TestCase):
    def verify_reconciliation(self, receipt, reconciled, *, prior=None, now=NOW):
        return verify_broker_reconciliation_receipt(
            receipt,
            expected_result=reconciled,
            expected_account_id_sha256=ACCOUNT_SHA,
            expected_server=SERVER,
            expected_environment="DEMO",
            expected_journal_sha256=JOURNAL_SHA,
            expected_provider_id=PROVIDER_ID,
            expected_key_id=KEY_ID,
            key_provider=lambda _key_id: KEY,
            now=now,
            prior_receipt=prior,
        )

    def test_signed_reconciliation_and_deal_receipts_verify_exactly(self):
        reconciled = result(closed=("intent-1",))
        observation = issue_reconciliation(reconciled)
        self.assertIs(observation, self.verify_reconciliation(observation, reconciled))

        deal = issue_deal(observation)
        aggregate = issue_broker_closed_trade_receipt(
            reconciliation_receipt=observation,
            intent_id="intent-1",
            deal_receipts=(deal,),
            expected_closed_volume=0.01,
            key=KEY,
        )
        checked = verify_broker_deal_receipt(
            deal,
            reconciliation_receipt=observation,
            expected_intent_id="intent-1",
            key_provider=lambda _key_id: KEY,
        )
        self.assertIs(deal, checked)
        self.assertIs(type(deal), BrokerDealReceipt)

    def test_constructor_and_dataclass_replace_cannot_forge_receipt(self):
        reconciled = result()
        observation = issue_reconciliation(reconciled, deal_tickets=())
        with self.assertRaises(TypeError):
            BrokerReconciliationReceipt(
                **{
                    **observation.__dict__,
                    "signature_hmac_sha256": "0" * 64,
                }
            )
        with self.assertRaises(TypeError):
            replace(observation, raw_payload_sha256="1" * 64)

    def test_payload_tamper_is_rejected_by_signature(self):
        reconciled = result()
        observation = issue_reconciliation(reconciled, deal_tickets=())
        object.__setattr__(observation, "raw_payload_sha256", "1" * 64)
        with self.assertRaisesRegex(ValueError, "signature mismatch"):
            self.verify_reconciliation(observation, reconciled)

    def test_reconciliation_replay_is_rejected_by_exact_chain(self):
        reconciled = result()
        first = issue_reconciliation(reconciled, deal_tickets=())
        self.verify_reconciliation(first, reconciled)
        with self.assertRaisesRegex(ValueError, "binding/replay"):
            self.verify_reconciliation(first, reconciled, prior=first)

    def test_deal_swapped_between_observation_receipts_is_rejected(self):
        reconciled = result(closed=("intent-1",))
        first = issue_reconciliation(reconciled)
        deal = issue_deal(first)
        second = issue_reconciliation(
            reconciled,
            sequence=2,
            previous=first,
        )
        with self.assertRaisesRegex(ValueError, "binding mismatch"):
            verify_broker_deal_receipt(
                deal,
                reconciliation_receipt=second,
                expected_intent_id="intent-1",
                key_provider=lambda _key_id: KEY,
            )

    def test_closed_intent_omission_cannot_be_sealed(self):
        reconciled = result(closed=("intent-1",))
        observation = issue_reconciliation(reconciled)
        with self.assertRaisesRegex(ValueError, "exactly one risk receipt"):
            seal_runtime_reconciliation_risk_result(
                reconciled,
                broker_reconciliation_receipt=observation,
                closed_trade_evidence=(),
            )

    def test_close_risk_event_requires_exact_net_pnl_and_semantics(self):
        reconciled = result(closed=("intent-1",))
        observation = issue_reconciliation(reconciled)
        deal = issue_deal(observation)
        aggregate = issue_broker_closed_trade_receipt(
            reconciliation_receipt=observation,
            intent_id="intent-1",
            deal_receipts=(deal,),
            expected_closed_volume=0.01,
            key=KEY,
        )
        binding = RiskLedgerBinding(
            account_id_sha256=ACCOUNT_SHA,
            server=SERVER,
            environment="DEMO",
            journal_sha256=JOURNAL_SHA,
            broker_spec_sha256=hashlib.sha256(b"broker-spec").hexdigest(),
            account_currency="JPY",
        )
        exact_event = ClosedTradeRiskEvent(
            trade_id=aggregate.trade_id,
            entry_id=aggregate.intent_id,
            binding=binding,
            occurred_at_utc=aggregate.closed_at_utc,
            daily_baseline_id="day-2026-07-22",
            weekly_baseline_id="week-2026-W30",
            symbol=aggregate.canonical_symbol,
            outcome="WIN",
            realized_pnl_account_currency=(
                aggregate.realized_net_pnl_account_currency
            ),
        )
        exact_source = issue_risk_source(exact_event, aggregate, binding)
        evidence = RuntimeClosedTradeRiskEvidence(
            event=exact_event,
            source_receipt=exact_source,
            upstream_receipt=aggregate,
        )
        self.assertEqual(
            aggregate.content_sha256,
            evidence.upstream_receipt.content_sha256,
        )

        swapped_positive = replace(
            exact_event,
            trade_id="trade-swapped-positive-pnl",
            realized_pnl_account_currency=500.0,
        )
        swapped_source = issue_risk_source(swapped_positive, aggregate, binding)
        with self.assertRaisesRegex(ValueError, "not exact"):
            RuntimeClosedTradeRiskEvidence(
                event=swapped_positive,
                source_receipt=swapped_source,
                upstream_receipt=aggregate,
            )

    def test_deal_fee_is_required_and_hmac_bound(self):
        reconciled = result(closed=("intent-1",))
        observation = issue_reconciliation(reconciled)
        required = {
            "reconciliation_receipt": observation,
            "intent_id": "intent-1",
            "deal_sequence": 1,
            "deal_ticket": "deal-1",
            "order_ticket": "order-1",
            "position_ticket": "position-1",
            "canonical_symbol": "EURUSD",
            "broker_symbol": "EURUSD.ps01",
            "account_currency": "JPY",
            "entry_side": "BUY",
            "exit_side": "SELL",
            "volume": 0.01,
            "fill_price": 1.17,
            "profit_account_currency": 1_000.0,
            "commission_account_currency": -10.0,
            "swap_account_currency": -2.0,
            "source_time_utc": NOW - timedelta(seconds=1),
            "raw_payload_sha256": hashlib.sha256(b"deal-payload").hexdigest(),
            "key": KEY,
        }
        with self.assertRaises(TypeError):
            issue_broker_deal_receipt(**required)

        deal = issue_deal(observation)
        object.__setattr__(deal, "fee_account_currency", 0.0)
        with self.assertRaisesRegex(ValueError, "signature mismatch"):
            verify_broker_deal_receipt(
                deal,
                reconciliation_receipt=observation,
                expected_intent_id="intent-1",
                key_provider=lambda _key_id: KEY,
            )

    def test_two_part_close_is_canonical_complete_and_rejects_bad_sets(self):
        reconciled = result(closed=("intent-1",))
        observation = issue_reconciliation(
            reconciled,
            deal_tickets=("deal-1", "deal-2"),
        )
        first = issue_deal(
            observation,
            deal_sequence=1,
            deal_ticket="deal-1",
            volume=0.004,
            profit=400.0,
            commission=-4.0,
            swap=-1.0,
            fee=-0.5,
        )
        second = issue_deal(
            observation,
            deal_sequence=2,
            deal_ticket="deal-2",
            volume=0.006,
            profit=600.0,
            commission=-6.0,
            swap=-1.0,
            fee=-0.5,
        )
        aggregate = issue_broker_closed_trade_receipt(
            reconciliation_receipt=observation,
            intent_id="intent-1",
            deal_receipts=(second, first),
            expected_closed_volume=0.01,
            key=KEY,
        )
        self.assertEqual((first, second), aggregate.deal_receipts)
        self.assertEqual(("deal-1", "deal-2"), aggregate.deal_tickets)
        self.assertEqual(0.01, aggregate.final_closed_volume)
        self.assertEqual(987.0, aggregate.realized_net_pnl_account_currency)

        with self.assertRaisesRegex(ValueError, "omitted, duplicated, or unrelated"):
            issue_broker_closed_trade_receipt(
                reconciliation_receipt=observation,
                intent_id="intent-1",
                deal_receipts=(first,),
                expected_closed_volume=0.004,
                key=KEY,
            )
        with self.assertRaisesRegex(ValueError, "omitted, duplicated, or unrelated"):
            issue_broker_closed_trade_receipt(
                reconciliation_receipt=observation,
                intent_id="intent-1",
                deal_receipts=(first, first),
                expected_closed_volume=0.008,
                key=KEY,
            )
        with self.assertRaisesRegex(ValueError, "absent from reconciliation"):
            issue_deal(
                observation,
                deal_sequence=3,
                deal_ticket="deal-unrelated",
                volume=0.001,
            )
        duplicate_sequence = issue_deal(
            observation,
            deal_sequence=1,
            deal_ticket="deal-2",
            volume=0.006,
        )
        with self.assertRaisesRegex(ValueError, "canonical unique sequence"):
            issue_broker_closed_trade_receipt(
                reconciliation_receipt=observation,
                intent_id="intent-1",
                deal_receipts=(first, duplicate_sequence),
                expected_closed_volume=0.01,
                key=KEY,
            )


if __name__ == "__main__":
    unittest.main()
