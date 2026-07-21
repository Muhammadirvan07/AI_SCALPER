from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from live_runtime.account_identity import ACCOUNT_IDENTITY_SCHEME
from live_runtime.broker_exporter import BrokerExportResult
from live_runtime.evidence_bootstrap import CONTRACT_ID
from live_runtime.mt5_readonly import (
    MT5ReadOnlyAttestationError,
    attest_mt5_read_only,
)
from live_runtime.session_calendar import build_calendar_bundle
from live_runtime.shadow_collector import (
    ReadOnlyMT5Facade,
    ShadowCollectorError,
    ShadowCycleStore,
    plan_next_bar,
    run_shadow_cycle,
    session_boundary_flags,
)
import json


UTC = timezone.utc
SYMBOLS = ("XAUUSD", "EURUSD", "USDJPY", "AUDUSD")


def contract_fixture():
    plan = json.loads(Path("config/xm_calendar_window_01.json").read_text(encoding="utf-8"))
    bundle = build_calendar_bundle(plan)
    return {
        "symbols": list(SYMBOLS),
        "timeframe_seconds": 900,
        "finalization_lag_seconds": 900,
        "max_append_lag_seconds": 60,
        "session_calendars": bundle["calendars"],
    }


def export_result(
    symbol: str,
    *,
    contract_id: str = CONTRACT_ID,
) -> BrokerExportResult:
    result = object.__new__(BrokerExportResult)
    for key, value in {
        "contract_id": contract_id,
        "symbol": symbol,
        "raw_tick_partition": {"rows": 1, "partition_payload_sha256": "a" * 64},
        "finalized_bar_segment": {"rows": 1, "segment_payload_sha256": "b" * 64},
        "exported_at": datetime(2026, 7, 19, 21, 30, tzinfo=UTC),
        "coverage_metadata": {"fixture": True},
        "broker_binding_sha256": "c" * 64,
        "status": "FINALIZED_EVIDENCE_APPENDED",
        "paired_commit_receipt": None,
    }.items():
        object.__setattr__(result, key, value)
    return result


class FakeMT5:
    COPY_TICKS_ALL = 1
    ACCOUNT_TRADE_MODE_DEMO = 0
    ACCOUNT_TRADE_MODE_REAL = 2
    ACCOUNT_MARGIN_MODE_RETAIL_NETTING = 0
    ACCOUNT_MARGIN_MODE_EXCHANGE = 1
    ACCOUNT_MARGIN_MODE_RETAIL_HEDGING = 2

    def account_info(self):
        return {
            "trade_allowed": False,
            "trade_expert": False,
        }

    def terminal_info(self):
        return {
            "trade_allowed": False,
            "tradeapi_disabled": True,
        }

    def symbol_info(self, symbol):
        return {}

    def copy_ticks_range(self, symbol, start, end, flags):
        return []

    def order_send(self, request):
        raise AssertionError("must never be reachable")


class ShadowCollectorTests(unittest.TestCase):
    def test_fx_and_gold_follow_exact_registered_open_grid(self):
        contract = contract_fixture()
        fx_due = datetime(2026, 7, 19, 21, 30, tzinfo=UTC)
        self.assertEqual(
            "DUE",
            plan_next_bar(contract, "EURUSD", last_open_at=None, now=fx_due).status,
        )
        self.assertEqual(
            "NOT_DUE",
            plan_next_bar(contract, "XAUUSD", last_open_at=None, now=fx_due).status,
        )
        gold = plan_next_bar(
            contract,
            "XAUUSD",
            last_open_at=None,
            now=datetime(2026, 7, 19, 22, 30, tzinfo=UTC),
        )
        self.assertEqual("DUE", gold.status)
        self.assertEqual(datetime(2026, 7, 19, 22, 0, tzinfo=UTC), gold.open_at)

    def test_missed_append_deadline_fails_closed(self):
        contract = contract_fixture()
        plan = plan_next_bar(
            contract,
            "EURUSD",
            last_open_at=None,
            now=datetime(2026, 7, 19, 21, 31, 1, tzinfo=UTC),
        )
        self.assertEqual("HOLD", plan.status)
        self.assertEqual("APPEND_DEADLINE_MISSED", plan.reason_code)

    def test_last_bar_advances_without_crossing_registered_closures(self):
        contract = contract_fixture()
        first = datetime(2026, 7, 19, 21, 0, tzinfo=UTC)
        plan = plan_next_bar(
            contract,
            "EURUSD",
            last_open_at=first,
            now=first + timedelta(minutes=45),
        )
        self.assertEqual(first + timedelta(minutes=15), plan.open_at)

    def test_session_boundary_flags_come_only_from_exact_registered_interval(self):
        calendar = contract_fixture()["session_calendars"]["EURUSD"]
        interval = calendar["market_open_intervals"][0]
        interval_open = datetime.fromisoformat(
            interval["open_at_utc"].replace("Z", "+00:00")
        )
        interval_close = datetime.fromisoformat(
            interval["close_at_utc"].replace("Z", "+00:00")
        )
        self.assertEqual(
            (True, False),
            session_boundary_flags(
                calendar,
                open_at=interval_open,
                close_at=interval_open + timedelta(minutes=15),
            ),
        )
        self.assertEqual(
            (False, True),
            session_boundary_flags(
                calendar,
                open_at=interval_close - timedelta(minutes=15),
                close_at=interval_close,
            ),
        )
        self.assertEqual(
            (False, False),
            session_boundary_flags(
                calendar,
                open_at=interval_open + timedelta(minutes=15),
                close_at=interval_open + timedelta(minutes=30),
            ),
        )
        with self.assertRaisesRegex(
            ShadowCollectorError,
            "exactly one",
        ):
            session_boundary_flags(
                calendar,
                open_at=interval_open - timedelta(minutes=15),
                close_at=interval_open,
            )

    def test_facade_exposes_no_order_capability(self):
        facade = ReadOnlyMT5Facade(FakeMT5())
        self.assertFalse(hasattr(facade, "order_send"))
        self.assertFalse(hasattr(facade, "positions_get"))
        self.assertFalse(hasattr(facade, "_mt5"))
        self.assertFalse(hasattr(facade, "__dict__"))
        self.assertEqual(
            {
                "account_trade_allowed": False,
                "account_trade_expert": False,
                "terminal_trade_allowed": False,
                "terminal_tradeapi_disabled": True,
            },
            dict(attest_mt5_read_only(facade)),
        )

    def test_read_only_attestation_rejects_any_enabled_or_missing_flag(self):
        for field in (
            "account_trade_allowed",
            "account_trade_expert",
            "terminal_trade_allowed",
            "terminal_tradeapi_disabled",
        ):
            with self.subTest(field=field):
                class UnsafeMT5(FakeMT5):
                    def account_info(self):
                        facts = dict(super().account_info())
                        if field == "account_trade_allowed":
                            facts["trade_allowed"] = True
                        if field == "account_trade_expert":
                            facts["trade_expert"] = True
                        return facts

                    def terminal_info(self):
                        facts = dict(super().terminal_info())
                        if field == "terminal_trade_allowed":
                            facts["trade_allowed"] = True
                        if field == "terminal_tradeapi_disabled":
                            facts.pop("tradeapi_disabled")
                        return facts

                with self.assertRaises(MT5ReadOnlyAttestationError):
                    attest_mt5_read_only(ReadOnlyMT5Facade(UnsafeMT5()))

    def test_cycle_receipt_is_durable_and_reconciles_results(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ShadowCycleStore(Path(directory) / "cycles.sqlite3")
            self.addCleanup(store.close)
            statuses = {symbol: "NOT_DUE" for symbol in SYMBOLS}
            statuses["EURUSD"] = "APPENDED"
            results = {"EURUSD": export_result("EURUSD")}
            now = datetime(2026, 7, 19, 21, 30, tzinfo=UTC)
            first = store.record(
                cycle_id="cycle-1",
                observed_at=now,
                symbol_status=statuses,
                results=results,
                failures=(),
            )
            second = store.record(
                cycle_id="cycle-1",
                observed_at=now,
                symbol_status=statuses,
                results=results,
                failures=(),
            )
            self.assertEqual("APPENDED", first.status)
            self.assertEqual(first.payload_sha256, second.payload_sha256)
            self.assertFalse(first.live_allowed)
            self.assertFalse(first.safe_to_demo_auto_order)
            bad = dict(statuses, USDJPY="APPENDED")
            with self.assertRaisesRegex(ShadowCollectorError, "reconcile"):
                store.record(
                    cycle_id="cycle-2",
                    observed_at=now,
                    symbol_status=bad,
                    results=results,
                    failures=(),
                )

    def test_cycle_receipt_supports_exact_registered_symbol_subset(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ShadowCycleStore(
                Path(directory) / "cycles.sqlite3",
                contract_id="phillip-commodity-window-01-diagnostic-v1",
            )
            self.addCleanup(store.close)
            receipt = store.record(
                cycle_id="phillip-commodity-cycle-1",
                observed_at=datetime(2026, 7, 21, 12, 0, tzinfo=UTC),
                symbol_status={"XAUUSD": "NOT_DUE"},
                results={},
                failures=(),
                required_symbols=("XAUUSD",),
            )
            self.assertEqual({"XAUUSD"}, set(receipt.symbol_status))

    def test_shadow_cycle_iterates_only_registered_contract_subset(self):
        contract = contract_fixture()
        contract["symbols"] = ["XAUUSD"]
        contract["session_calendars"] = {
            "XAUUSD": contract["session_calendars"]["XAUUSD"]
        }
        contract["broker_sources"] = {
            "XAUUSD": {
                "account_identity_sha256": "e" * 64,
                "account_identity_scheme": ACCOUNT_IDENTITY_SCHEME,
                "account_identity_key_id": "test-key",
                "source_instance_id": "phillip-commodity-test",
                "broker_legal_name": "Phillip Securities Japan, Ltd.",
                "broker_server": "PhillipSecuritiesJP-PROD",
                "environment": "DEMO",
                "account_currency": "JPY",
                "account_trade_allowed": False,
                "account_trade_expert": True,
                "terminal_trade_allowed": False,
                "terminal_tradeapi_disabled": True,
                "broker_symbol": "XAUUSD.ps01",
            }
        }
        contract["instrument_specs"] = {"XAUUSD": {}}

        class FakeExporter:
            def __init__(self, *_args, **_kwargs):
                pass

            def export(self, **kwargs):
                return export_result(kwargs["canonical_symbol"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            forward = root / "artifacts" / "forward" / CONTRACT_ID
            (forward / "heads" / "segments").mkdir(parents=True)
            (forward / "contract.json").write_text(
                json.dumps(contract),
                encoding="utf-8",
            )
            (forward / "heads" / "segments" / "XAUUSD.json").write_text(
                '{"last_at_utc":null}',
                encoding="utf-8",
            )
            store = ShadowCycleStore(root / "cycles.sqlite3")
            self.addCleanup(store.close)
            with (
                patch(
                    "live_runtime.shadow_collector.verify_forward_evidence",
                    return_value={"valid": True, "failures": []},
                ),
                patch(
                    "live_runtime.shadow_collector.BrokerExportBinding",
                    return_value=object(),
                ),
                patch(
                    "live_runtime.shadow_collector.MT5EvidenceExporter",
                    FakeExporter,
                ),
            ):
                receipt = run_shadow_cycle(
                    FakeMT5(),
                    repo_root=root,
                    artifact_root=root / "artifacts",
                    signing_key=b"collector-test-signing-key-32bytes-minimum",
                    store=store,
                    now_provider=lambda: datetime(2026, 7, 19, 22, 30, tzinfo=UTC),
                )
            self.assertEqual({"XAUUSD"}, set(receipt.symbol_status))
            self.assertEqual("APPENDED", receipt.symbol_status["XAUUSD"])

    def test_cycle_store_rejects_export_from_another_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ShadowCycleStore(
                Path(directory) / "cycles.sqlite3",
                contract_id="fbs-window-01-diagnostic-v1",
            )
            self.addCleanup(store.close)
            statuses = {symbol: "NOT_DUE" for symbol in SYMBOLS}
            statuses["EURUSD"] = "APPENDED"
            with self.assertRaisesRegex(ShadowCollectorError, "contract-bound"):
                store.record(
                    cycle_id="fbs-cycle-1",
                    observed_at=datetime(2026, 7, 21, 12, 0, tzinfo=UTC),
                    symbol_status=statuses,
                    results={"EURUSD": export_result("EURUSD")},
                    failures=(),
                )

    def test_runner_rejects_store_bound_to_another_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ShadowCycleStore(
                Path(directory) / "cycles.sqlite3",
                contract_id="fbs-window-01-diagnostic-v1",
            )
            self.addCleanup(store.close)
            with self.assertRaisesRegex(
                ShadowCollectorError,
                "cycle store contract binding mismatch",
            ):
                run_shadow_cycle(
                    FakeMT5(),
                    repo_root=directory,
                    artifact_root=Path(directory) / "artifacts",
                    signing_key=b"collector-test-signing-key-32bytes-minimum",
                    store=store,
                    contract_id=CONTRACT_ID,
                )

    def test_read_only_cycle_exports_due_fx_and_leaves_closed_gold_idle(self):
        contract = contract_fixture()
        broker_symbols = {
            "XAUUSD": "GOLD.",
            "EURUSD": "EURUSD.",
            "USDJPY": "USDJPY.",
            "AUDUSD": "AUDUSD.",
        }
        identities = {
            "XAUUSD": ("XAU", "USD", "SPOT_METAL_CFD", 2, 0.01, 100.0, "USD"),
            "EURUSD": ("EUR", "USD", "FOREX_SPOT_CFD", 5, 0.00001, 100000.0, "EUR"),
            "USDJPY": ("USD", "JPY", "FOREX_SPOT_CFD", 3, 0.001, 100000.0, "USD"),
            "AUDUSD": ("AUD", "USD", "FOREX_SPOT_CFD", 5, 0.00001, 100000.0, "AUD"),
        }
        contract["broker_sources"] = {}
        contract["instrument_specs"] = {}
        for symbol, broker_symbol in broker_symbols.items():
            base, quote, kind, digits, point, size, margin = identities[symbol]
            contract["broker_sources"][symbol] = {
                "provider_kind": "BROKER_EXPORT",
                "broker_legal_name": "Tradexfin Limited",
                "broker_server": "XMTrading-MT5 3",
                "environment": "DEMO",
                "account_identity_sha256": "e" * 64,
                "account_identity_scheme": ACCOUNT_IDENTITY_SCHEME,
                "account_identity_key_id": "test-key",
                "account_currency": "JPY",
                "account_trade_allowed": False,
                "account_trade_expert": False,
                "terminal_trade_allowed": False,
                "terminal_tradeapi_disabled": True,
                "canonical_symbol": symbol,
                "broker_symbol": broker_symbol,
                "source_instance_id": "xm-test-terminal-window-01",
                "quote_mode": "FINALIZED_BID_ASK_BARS",
                "exporter_version": "test",
                "exporter_signing_key_id": "test-key",
                "feed_grade": "DEMO_BROKER_ALIGNED_ONLY",
            }
            contract["instrument_specs"][symbol] = {
                "canonical_symbol": symbol,
                "instrument_kind": kind,
                "base_currency": base,
                "quote_currency": quote,
                "digits": digits,
                "point": str(point),
                "tick_size": str(point),
                "contract_size": str(size),
                "tick_value": "1",
                "volume_min": "0.01",
                "volume_max": "50",
                "volume_step": "0.01",
                "stops_level_points": 0,
                "freeze_level_points": 0,
                "profit_currency": quote,
                "margin_currency": margin,
                "margin_mode": "RETAIL_HEDGING",
                "session_calendar_sha256": "d" * 64,
            }

        class ConnectedMT5(FakeMT5):
            def account_info(self):
                return {
                    "login": 123456,
                    "currency": "JPY",
                    "trade_allowed": False,
                    "trade_expert": False,
                }

        calls = []
        events = []
        guard_calls = []

        class FakeExporter:
            def __init__(self, mt5, *, binding, **kwargs):
                self.binding = binding

            def export(self, **kwargs):
                events.append("export:" + kwargs["canonical_symbol"])
                calls.append(dict(kwargs))
                return export_result(kwargs["canonical_symbol"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            forward = root / "validation_artifacts" / "forward" / CONTRACT_ID
            (forward / "heads" / "segments").mkdir(parents=True)
            (forward / "contract.json").write_text(json.dumps(contract), encoding="utf-8")
            for symbol in SYMBOLS:
                (forward / "heads" / "segments" / f"{symbol}.json").write_text(
                    '{"last_at_utc":null}', encoding="utf-8"
                )
            store = ShadowCycleStore(root / "cycles.sqlite3")
            self.addCleanup(store.close)
            now = datetime(2026, 7, 19, 21, 30, tzinfo=UTC)
            with (
                patch(
                    "live_runtime.shadow_collector.verify_forward_evidence",
                    return_value={"valid": True, "failures": []},
                ),
                patch(
                    "live_runtime.shadow_collector.build_current_identity",
                    return_value={"test": "identity"},
                ),
                patch("live_runtime.shadow_collector.MT5EvidenceExporter", FakeExporter),
            ):
                receipt = run_shadow_cycle(
                    ConnectedMT5(),
                    repo_root=root,
                    artifact_root=root / "validation_artifacts",
                    signing_key=b"collector-test-signing-key-32bytes-minimum",
                    store=store,
                    now_provider=lambda: now,
                    stage_reporter=lambda stage, outcome, reason: events.append(
                        f"{stage}:{outcome}:{reason}"
                    ),
                    pre_evidence_mutation_check=lambda: (
                        guard_calls.append("disk"),
                        events.append("disk"),
                    ),
                )
            self.assertEqual("APPENDED", receipt.status)
            self.assertEqual(
                {"AUDUSD", "EURUSD", "USDJPY"},
                {call["canonical_symbol"] for call in calls},
            )
            self.assertTrue(
                all("exported_at" not in call for call in calls),
                "shadow collector must let the exporter mint a post-collection timestamp",
            )
            self.assertTrue(
                all(call["session_open_boundary"] is True for call in calls)
            )
            self.assertTrue(
                all(call["session_close_boundary"] is False for call in calls)
            )
            self.assertEqual("NOT_DUE", receipt.symbol_status["XAUUSD"])
            self.assertEqual(
                [
                    "CONTRACT_VERIFICATION:STARTED:"
                    "CONTRACT_VERIFICATION_STARTED",
                    "CONTRACT_VERIFICATION:PASS:CONTRACT_EVIDENCE_VERIFIED",
                ],
                events[:2],
            )
            self.assertEqual(3, len(guard_calls))
            for index, value in enumerate(events):
                if value.startswith("export:"):
                    self.assertEqual("disk", events[index - 1])

    def test_contract_verification_failure_is_reported_before_raise(self):
        events = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract = root / "artifacts" / "forward" / CONTRACT_ID
            contract.mkdir(parents=True)
            store = ShadowCycleStore(root / "cycles.sqlite3")
            self.addCleanup(store.close)
            with patch(
                "live_runtime.shadow_collector.verify_forward_evidence",
                return_value={"valid": False, "failures": ["SYNTHETIC"]},
            ):
                with self.assertRaisesRegex(
                    ShadowCollectorError,
                    "verification failed",
                ):
                    run_shadow_cycle(
                        FakeMT5(),
                        repo_root=root,
                        artifact_root=root / "artifacts",
                        signing_key=b"collector-test-signing-key-32bytes-minimum",
                        store=store,
                        now_provider=lambda: datetime(
                            2026, 7, 19, 21, 30, tzinfo=UTC
                        ),
                        stage_reporter=lambda stage, outcome, reason: events.append(
                            (stage, outcome, reason)
                        ),
                    )
        self.assertEqual(
            [
                (
                    "CONTRACT_VERIFICATION",
                    "STARTED",
                    "CONTRACT_VERIFICATION_STARTED",
                ),
                (
                    "CONTRACT_VERIFICATION",
                    "HOLD",
                    "CONTRACT_EVIDENCE_INVALID",
                ),
            ],
            events,
        )

    def test_pre_mutation_guard_failure_prevents_export_and_holds_cycle(self):
        contract = contract_fixture()
        contract["broker_sources"] = {}
        contract["instrument_specs"] = {}
        for symbol, broker_symbol in {
            "XAUUSD": "GOLD.",
            "EURUSD": "EURUSD.",
            "USDJPY": "USDJPY.",
            "AUDUSD": "AUDUSD.",
        }.items():
            contract["broker_sources"][symbol] = {
                "broker_legal_name": "Tradexfin Limited",
                "broker_server": "XMTrading-MT5 3",
                "environment": "DEMO",
                "account_identity_sha256": "e" * 64,
                "account_identity_scheme": ACCOUNT_IDENTITY_SCHEME,
                "account_identity_key_id": "test-key",
                "account_currency": "JPY",
                "account_trade_allowed": False,
                "account_trade_expert": False,
                "terminal_trade_allowed": False,
                "terminal_tradeapi_disabled": True,
                "broker_symbol": broker_symbol,
                "source_instance_id": "xm-test-terminal-window-01",
            }
            contract["instrument_specs"][symbol] = {}

        class MustNotExport:
            def __init__(self, *args, **kwargs):
                raise AssertionError("exporter must not be constructed")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            forward = root / "artifacts" / "forward" / CONTRACT_ID
            (forward / "heads" / "segments").mkdir(parents=True)
            (forward / "contract.json").write_text(
                json.dumps(contract),
                encoding="utf-8",
            )
            for symbol in SYMBOLS:
                (forward / "heads" / "segments" / f"{symbol}.json").write_text(
                    '{"last_at_utc":null}',
                    encoding="utf-8",
                )
            store = ShadowCycleStore(root / "cycles.sqlite3")
            self.addCleanup(store.close)
            now = datetime(2026, 7, 19, 21, 30, tzinfo=UTC)
            with (
                patch(
                    "live_runtime.shadow_collector.verify_forward_evidence",
                    return_value={"valid": True, "failures": []},
                ),
                patch(
                    "live_runtime.shadow_collector.MT5EvidenceExporter",
                    MustNotExport,
                ),
                patch(
                    "live_runtime.shadow_collector.BrokerExportBinding",
                    return_value=object(),
                ),
            ):
                receipt = run_shadow_cycle(
                    FakeMT5(),
                    repo_root=root,
                    artifact_root=root / "artifacts",
                    signing_key=b"collector-test-signing-key-32bytes-minimum",
                    store=store,
                    now_provider=lambda: now,
                    pre_evidence_mutation_check=lambda: (_ for _ in ()).throw(
                        RuntimeError("synthetic low disk")
                    ),
                )
        self.assertEqual("HOLD", receipt.status)
        self.assertEqual("NOT_DUE", receipt.symbol_status["XAUUSD"])
        self.assertTrue(
            all(
                receipt.symbol_status[symbol] == "HOLD"
                for symbol in ("AUDUSD", "EURUSD", "USDJPY")
            )
        )
        self.assertTrue(
            all(
                failure.startswith("PRE_EVIDENCE_MUTATION_GUARD_FAILED:")
                for failure in receipt.failures
            )
        )


if __name__ == "__main__":
    unittest.main()
