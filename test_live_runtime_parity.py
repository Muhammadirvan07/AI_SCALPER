from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import unittest

from live_runtime.contracts import (
    BrokerSpec,
    DecisionSnapshot,
    TradeIntent,
    _mint_decision_snapshot,
)
from live_runtime.parity import ParityFixture, compare_parity
from live_runtime.risk import RiskContext, evaluate_risk


UTC = timezone.utc


def fixture(symbol: str, base: float) -> ParityFixture:
    now = datetime(2026, 7, 15, 1, 0, 1, tzinfo=UTC)
    stop_distance = max(base * 0.001, 0.0001)
    decision = _mint_decision_snapshot(
        decision_run_id=f"run-{symbol}",
        symbol=symbol,
        side="BUY",
        strategy="MOMENTUM_PULLBACK",
        score=3,
        score_components=(("momentum", 2), ("trend", 1)),
        entry_reference=base,
        stop_loss=base - stop_distance,
        take_profit=base + 2 * stop_distance,
        model_version="champion-1",
        model_artifact_sha256="f" * 64,
        commit_sha="abcdef1",
        config_sha256="a" * 64,
        data_sha256="b" * 64,
        source_name="broker-mt5",
        source_aligned=True,
        data_fresh=True,
        bar_closed_at=now - timedelta(seconds=1),
        created_at=now,
    )
    intent = TradeIntent(
        mode="PAPER",
        account_id="demo-alias",
        server="Broker-Demo",
        symbol=symbol,
        side="BUY",
        requested_lot=0.01,
        entry_reference=base,
        stop_loss=base - stop_distance,
        take_profit=base + 2 * stop_distance,
        created_at=now,
        expires_at=now + timedelta(seconds=9),
        decision=decision,
        permit_id="permit-test",
    )
    point = 0.01 if base >= 10 else 0.00001
    broker = BrokerSpec(
        account_id="demo-alias",
        broker_legal_name="Example Broker Ltd",
        server="Broker-Demo",
        environment="DEMO",
        symbol=symbol,
        broker_symbol=f"{symbol}.a",
        account_currency="USD",
        digits=2 if point == 0.01 else 5,
        point=point,
        tick_size=point,
        tick_value=0.001,
        contract_size=100_000.0,
        volume_min=0.01,
        volume_max=100.0,
        volume_step=0.01,
        stops_level_points=1,
        freeze_level_points=0,
        margin_per_lot=10.0,
        session_calendar_sha256="d" * 64,
        captured_at=now,
    )
    context = RiskContext(
        evaluated_at=now,
        mode="PAPER",
        account_id="demo-alias",
        server="Broker-Demo",
        equity=100.0,
        daily_start_equity=100.0,
        weekly_start_equity=100.0,
        high_water_equity=100.0,
        daily_pnl_cash=0.0,
        weekly_pnl_cash=0.0,
        open_position_count=0,
        entries_today=0,
        consecutive_losses=0,
        loss_latch_active=False,
        reserved_symbols=(),
        current_spread_points=1.0,
        median_spread_points=1.0,
        p95_spread_points=2.0,
        estimated_slippage_points=0.0,
        p95_slippage_points=0.0,
        news_clear=True,
        rollover_clear=True,
        data_fresh=True,
        source_aligned=True,
        permit_valid=True,
    )
    risk = evaluate_risk(intent, broker, context)
    return ParityFixture(
        lane_id=f"{symbol}:MOMENTUM_PULLBACK:config-a",
        decision=decision,
        intent=intent,
        risk_decision=risk,
        outbound_payload_sha256="c" * 64,
        captured_at=now,
    )


class ParityTests(unittest.TestCase):
    def test_golden_parity_is_exact_for_all_v1_symbols(self) -> None:
        now = datetime(2026, 7, 15, 1, 1, tzinfo=UTC)
        for symbol, base in (
            ("XAUUSD", 3300.0),
            ("EURUSD", 1.20),
            ("USDJPY", 150.0),
            ("AUDUSD", 0.70),
        ):
            with self.subTest(symbol=symbol):
                reference = fixture(symbol, base)
                report = compare_parity(reference, reference, compared_at=now)
                self.assertTrue(report.full_parity)
                self.assertEqual(1.0, report.parity_ratio)
                self.assertFalse(report.promotion_eligible)
                self.assertFalse(report.live_allowed)

    def test_payload_hash_mismatch_is_explicit_and_blocks_full_parity(self) -> None:
        reference = fixture("XAUUSD", 3300.0)
        runtime = replace(reference, outbound_payload_sha256="d" * 64)
        report = compare_parity(
            reference,
            runtime,
            compared_at=reference.captured_at + timedelta(seconds=1),
        )
        self.assertFalse(report.full_parity)
        self.assertIn("outbound_payload_sha256", report.mismatch_paths)

    def test_score_mismatch_reports_precise_path(self) -> None:
        reference = fixture("EURUSD", 1.20)
        decision_values = asdict(reference.decision)
        decision_values.update(
            score=4,
            score_components=(("momentum", 2), ("trend", 2)),
        )
        changed_decision = _mint_decision_snapshot(**decision_values)
        changed_intent = replace(reference.intent, decision=changed_decision)
        runtime = replace(
            reference,
            decision=changed_decision,
            intent=changed_intent,
        )
        report = compare_parity(
            reference,
            runtime,
            compared_at=reference.captured_at + timedelta(seconds=1),
        )
        self.assertFalse(report.full_parity)
        self.assertIn("decision.score", report.mismatch_paths)
        self.assertIn("intent.decision.score", report.mismatch_paths)

    def test_different_lanes_cannot_be_aggregated(self) -> None:
        with self.assertRaises(ValueError):
            compare_parity(
                fixture("XAUUSD", 3300.0),
                fixture("EURUSD", 1.20),
                compared_at=datetime(2026, 7, 15, 1, 1, tzinfo=UTC),
            )


if __name__ == "__main__":
    unittest.main()
