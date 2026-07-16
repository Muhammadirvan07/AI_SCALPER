from __future__ import annotations

from dataclasses import FrozenInstanceError, asdict
from datetime import datetime, timedelta, timezone
import unittest

from live_runtime.contracts import (
    BrokerSpec,
    DecisionSnapshot,
    ExecutionReceipt,
    TradeIntent,
    _mint_decision_snapshot,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 15, 1, 0, 1, tzinfo=UTC)
COMMIT = "a" * 40
CONFIG = "b" * 64
DATA = "c" * 64


def broker_spec(**changes: object) -> BrokerSpec:
    values: dict[str, object] = {
        "account_id": "acct-01",
        "broker_legal_name": "Example Broker Ltd",
        "server": "broker-demo",
        "environment": "DEMO",
        "symbol": "EURUSD",
        "broker_symbol": "EURUSD.a",
        "account_currency": "USD",
        "digits": 5,
        "point": 0.00001,
        "tick_size": 0.00001,
        "tick_value": 1.0,
        "contract_size": 100_000.0,
        "volume_min": 0.001,
        "volume_max": 100.0,
        "volume_step": 0.001,
        "stops_level_points": 20,
        "freeze_level_points": 10,
        "margin_per_lot": 1_000.0,
        "session_calendar_sha256": "d" * 64,
        "captured_at": NOW,
    }
    values.update(changes)
    return BrokerSpec(**values)  # type: ignore[arg-type]


def decision(**changes: object) -> DecisionSnapshot:
    values: dict[str, object] = {
        "decision_run_id": "run-01",
        "symbol": "EURUSD",
        "side": "BUY",
        "strategy": "momentum_pullback",
        "score": 5,
        "score_components": {"trend": 3, "pullback": 2},
        "entry_reference": 1.10000,
        "stop_loss": 1.09900,
        "take_profit": 1.10200,
        "model_version": "rules-1",
        "model_artifact_sha256": "f" * 64,
        "commit_sha": COMMIT,
        "config_sha256": CONFIG,
        "data_sha256": DATA,
        "source_name": "broker_m1",
        "source_aligned": True,
        "data_fresh": True,
        "bar_closed_at": NOW - timedelta(seconds=1),
        "created_at": NOW,
    }
    values.update(changes)
    return _mint_decision_snapshot(**values)  # type: ignore[arg-type]


def trade_intent(**changes: object) -> TradeIntent:
    values: dict[str, object] = {
        "mode": "DRY_RUN",
        "account_id": "acct-01",
        "server": "broker-demo",
        "symbol": "EURUSD",
        "side": "BUY",
        "requested_lot": 0.01,
        "entry_reference": 1.10000,
        "stop_loss": 1.09900,
        "take_profit": 1.10200,
        "created_at": NOW,
        "expires_at": NOW + timedelta(seconds=5),
        "decision": decision(),
        "permit_id": "permit_test",
    }
    values.update(changes)
    return TradeIntent(**values)  # type: ignore[arg-type]


class ContractTests(unittest.TestCase):
    def test_contracts_are_frozen_and_normalized(self) -> None:
        spec = broker_spec(symbol="eurusd", broker_symbol="eurusd.a")
        self.assertEqual(spec.symbol, "EURUSD")
        with self.assertRaises(FrozenInstanceError):
            spec.symbol = "XAUUSD"  # type: ignore[misc]

    def test_nonfinite_numbers_and_non_utc_timestamps_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            broker_spec(point=float("nan"))
        with self.assertRaises(ValueError):
            broker_spec(captured_at=NOW.replace(tzinfo=None))
        with self.assertRaises(ValueError):
            broker_spec(captured_at=NOW.astimezone(timezone(timedelta(hours=9))))

    def test_decision_has_stable_canonical_serialization_and_id(self) -> None:
        first = decision(score_components={"pullback": 2, "trend": 3})
        second = decision(score_components={"trend": 3, "pullback": 2})
        self.assertEqual(first.canonical_json(), second.canonical_json())
        self.assertEqual(first.snapshot_id, second.snapshot_id)
        self.assertEqual(first.content_sha256, second.content_sha256)
        self.assertNotEqual(first.snapshot_id, decision(model_version="rules-2").snapshot_id)

    def test_decision_snapshot_cannot_bypass_the_shared_core_boundary(self) -> None:
        with self.assertRaises(TypeError):
            DecisionSnapshot(**asdict(decision()))

    def test_score_must_equal_component_sum(self) -> None:
        with self.assertRaises(ValueError):
            decision(score=6)

    def test_trade_intent_idempotency_and_price_geometry(self) -> None:
        first = trade_intent()
        second = trade_intent()
        self.assertEqual(first.intent_id, second.intent_id)
        self.assertEqual(first.idempotency_id, second.idempotency_id)
        self.assertAlmostEqual(first.stop_distance, 0.001)
        with self.assertRaises(ValueError):
            trade_intent(stop_loss=1.101)
        with self.assertRaises(ValueError):
            trade_intent(entry_reference=1.10001)
        with self.assertRaises(ValueError):
            trade_intent(expires_at=NOW + timedelta(seconds=10))
        with self.assertRaises(ValueError):
            trade_intent(symbol="XAUUSD")

    def test_execution_receipt_requires_fill_evidence(self) -> None:
        common = {
            "intent_id": trade_intent().intent_id,
            "account_id": "acct-01",
            "server": "broker-demo",
            "symbol": "EURUSD",
            "requested_volume": 0.002,
            "received_at": NOW,
            "broker_retcode": "10009",
            "message": "ok",
        }
        with self.assertRaises(ValueError):
            ExecutionReceipt(state="FILLED", filled_volume=0.0, **common)
        partial = ExecutionReceipt(
            state="PARTIAL",
            filled_volume=0.001,
            fill_price=1.10001,
            order_ticket="42",
            **common,
        )
        self.assertEqual(partial.state, "PARTIAL")
        acknowledged = ExecutionReceipt(
            state="ACKNOWLEDGED",
            filled_volume=0.0,
            order_ticket="42",
            **common,
        )
        self.assertTrue(acknowledged.receipt_id.startswith("receipt_"))
        for state in ("PREFLIGHT_PASSED", "UNCERTAIN", "CLOSED"):
            receipt = ExecutionReceipt(state=state, filled_volume=0.0, **common)
            self.assertEqual(receipt.state, state)


if __name__ == "__main__":
    unittest.main()
