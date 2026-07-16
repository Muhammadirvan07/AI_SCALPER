from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest

import numpy as np
import pandas as pd

import live_runtime.decision_core as decision_core
from live_runtime.decision_core import (
    DecisionProvenance,
    build_runtime_decision_snapshot,
    evaluate_decision_core,
)
import strategy.replay_validator as replay_validator
from strategy.replay_validator import build_replay_decision_snapshot
from strategy.strategy_profiles import get_strategy_profile


UTC = timezone.utc
GOLDEN_PATH = Path(__file__).parent / "test_fixtures/decision_core_golden_v1.json"
START = datetime(2026, 1, 1, tzinfo=UTC)
SIGNAL_INDEX = 259

CASES = {
    "XAUUSD": {"base": 3300.0, "direction": 1, "spread": 0.02},
    "EURUSD": {"base": 1.2, "direction": 1, "spread": 0.00002},
    "USDJPY": {"base": 150.0, "direction": -1, "spread": 0.002},
    "AUDUSD": {"base": 0.7, "direction": -1, "spread": 0.00002},
}


def broker_frame(symbol: str) -> pd.DataFrame:
    case = CASES[symbol]
    rows = SIGNAL_INDEX + 2
    index = np.arange(rows, dtype=float)
    base = case["base"]
    direction = case["direction"]
    close = base + direction * (
        base * 0.0002 * 0.2 * index
        + base * 0.005 * 0.2 * np.sin(index / 7.0)
    )
    candle_body = base * 0.0003
    open_price = close - direction * candle_body
    high = np.maximum(open_price, close) + candle_body * 0.2
    low = np.minimum(open_price, close) - candle_body * 0.2
    timestamps = pd.date_range(
        start=START,
        periods=rows,
        freq="15min",
        tz="UTC",
    )
    first_time_msc = (timestamps.asi8 // 1_000_000 + 1_000).astype("int64")
    half_spread = case["spread"] / 2.0
    return pd.DataFrame(
        {
            "open_time_utc": timestamps,
            "Open": open_price,
            "High": high,
            "Low": low,
            "Close": close,
            "is_final": [True] * rows,
            "bid_open": open_price - half_spread,
            "ask_open": open_price + half_spread,
            "first_time_msc": first_time_msc,
        }
    )


def provenance(symbol: str, frame: pd.DataFrame) -> DecisionProvenance:
    entry_row = frame.iloc[SIGNAL_INDEX + 1]
    bar_closed_at = pd.Timestamp(entry_row["open_time_utc"]).to_pydatetime()
    created_at = pd.to_datetime(
        int(entry_row["first_time_msc"]),
        unit="ms",
        utc=True,
    ).to_pydatetime()
    return DecisionProvenance(
        decision_run_id=f"golden-{symbol}",
        model_version="champion-locked-v1",
        model_artifact_sha256="f" * 64,
        commit_sha="a" * 40,
        config_sha256="c" * 64,
        data_sha256="d" * 64,
        source_name="broker-mt5-m15",
        source_aligned=True,
        data_fresh=True,
        bar_closed_at=bar_closed_at,
        created_at=created_at,
    )


class DecisionCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))

    def test_replay_and_runtime_share_one_core_and_match_four_golden_lanes(
        self,
    ) -> None:
        self.assertIs(
            replay_validator.build_decision_snapshot,
            decision_core.build_decision_snapshot,
        )
        self.assertEqual("decision-core-golden-v1", self.golden["schema_version"])

        for symbol in CASES:
            with self.subTest(symbol=symbol):
                frame = broker_frame(symbol)
                binding = provenance(symbol, frame)
                entry_row = frame.iloc[SIGNAL_INDEX + 1]
                replay = build_replay_decision_snapshot(
                    frame,
                    symbol,
                    SIGNAL_INDEX,
                    provenance=binding,
                )
                runtime = build_runtime_decision_snapshot(
                    frame.iloc[: SIGNAL_INDEX + 1],
                    symbol=symbol,
                    first_eligible_bid=entry_row["bid_open"],
                    first_eligible_ask=entry_row["ask_open"],
                    first_eligible_tick_at=binding.created_at,
                    provenance=binding,
                )

                self.assertEqual(replay, runtime)
                expected = self.golden["cases"][symbol]
                actual = {
                    "side": runtime.side,
                    "strategy": runtime.strategy,
                    "score": runtime.score,
                    "score_components": [
                        list(component) for component in runtime.score_components
                    ],
                    "entry_reference": runtime.entry_reference,
                    "stop_loss": runtime.stop_loss,
                    "take_profit": runtime.take_profit,
                    "snapshot_id": runtime.snapshot_id,
                    "content_sha256": runtime.content_sha256,
                }
                self.assertEqual(expected, actual)
                expected_entry = (
                    entry_row["ask_open"]
                    if runtime.side == "BUY"
                    else entry_row["bid_open"]
                )
                self.assertEqual(expected_entry, runtime.entry_reference)
                self.assertFalse(hasattr(runtime, "live_allowed"))

    def test_core_is_deterministic_and_preserves_locked_strategy_thresholds(
        self,
    ) -> None:
        for symbol in CASES:
            with self.subTest(symbol=symbol):
                frame = broker_frame(symbol).iloc[: SIGNAL_INDEX + 1]
                first = evaluate_decision_core(frame, symbol)
                second = evaluate_decision_core(frame.copy(deep=True), symbol)
                self.assertEqual(first, second)
                self.assertEqual("MOMENTUM_PULLBACK", first.strategy)
                self.assertEqual(6, first.score)
                self.assertEqual(
                    5 if symbol == "XAUUSD" else 4,
                    get_strategy_profile(symbol).min_strategy_score,
                )

    def test_snapshot_adapter_rejects_unfinalized_naive_or_drifted_time(self) -> None:
        frame = broker_frame("XAUUSD")
        binding = provenance("XAUUSD", frame)
        entry = frame.iloc[SIGNAL_INDEX + 1]

        unfinalized = frame.iloc[: SIGNAL_INDEX + 1].copy()
        unfinalized.loc[SIGNAL_INDEX, "is_final"] = False
        with self.assertRaisesRegex(ValueError, "explicitly finalized"):
            build_runtime_decision_snapshot(
                unfinalized,
                symbol="XAUUSD",
                first_eligible_bid=entry["bid_open"],
                first_eligible_ask=entry["ask_open"],
                first_eligible_tick_at=binding.created_at,
                provenance=binding,
            )

        naive = frame.iloc[: SIGNAL_INDEX + 1].copy()
        naive["open_time_utc"] = naive["open_time_utc"].dt.tz_localize(None)
        with self.assertRaisesRegex(ValueError, "timezone-aware UTC"):
            build_runtime_decision_snapshot(
                naive,
                symbol="XAUUSD",
                first_eligible_bid=entry["bid_open"],
                first_eligible_ask=entry["ask_open"],
                first_eligible_tick_at=binding.created_at,
                provenance=binding,
            )

        with self.assertRaisesRegex(ValueError, "first-tick entry window"):
            replace(
                binding,
                created_at=binding.bar_closed_at + timedelta(seconds=11),
            )
        with self.assertRaisesRegex(ValueError, "bind the first eligible quote"):
            build_runtime_decision_snapshot(
                frame.iloc[: SIGNAL_INDEX + 1],
                symbol="XAUUSD",
                first_eligible_bid=entry["bid_open"],
                first_eligible_ask=entry["ask_open"],
                first_eligible_tick_at=binding.created_at + timedelta(seconds=1),
                provenance=binding,
            )

    def test_snapshot_adapter_rejects_bad_quotes_and_proxy_replay_data(self) -> None:
        frame = broker_frame("EURUSD")
        binding = provenance("EURUSD", frame)
        entry = frame.iloc[SIGNAL_INDEX + 1]
        with self.assertRaisesRegex(ValueError, "ask cannot be below bid"):
            build_runtime_decision_snapshot(
                frame.iloc[: SIGNAL_INDEX + 1],
                symbol="EURUSD",
                first_eligible_bid=entry["ask_open"],
                first_eligible_ask=entry["bid_open"],
                first_eligible_tick_at=binding.created_at,
                provenance=binding,
            )

        proxy_only = frame.drop(columns=["bid_open", "ask_open", "first_time_msc"])
        with self.assertRaisesRegex(ValueError, "first-tick bid/ask"):
            build_replay_decision_snapshot(
                proxy_only,
                "EURUSD",
                SIGNAL_INDEX,
                provenance=binding,
            )


if __name__ == "__main__":
    unittest.main()
