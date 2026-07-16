from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from live_runtime.broker_exporter import (
    BrokerExportBinding,
    BrokerExportBindingError,
    EvidenceInstrumentIdentity,
    MT5EvidenceExporter,
    PairedAppendRecoveryRequired,
    aggregate_m15_bid_ask_bars,
    broker_export_binding_from_spec,
    finalized_m15_bid_ask_bars,
    normalize_mt5_ticks,
    paired_append_recovery_status,
)
from live_runtime.contracts import BrokerSpec
from validation_evidence import (
    EvidenceValidationError,
    canonical_evidence_payload_sha256,
)


UTC = timezone.utc


class FakeMT5:
    COPY_TICKS_ALL = 15
    ACCOUNT_TRADE_MODE_DEMO = 0
    ACCOUNT_TRADE_MODE_REAL = 2
    ACCOUNT_MARGIN_MODE_RETAIL_NETTING = 0
    ACCOUNT_MARGIN_MODE_EXCHANGE = 1
    ACCOUNT_MARGIN_MODE_RETAIL_HEDGING = 2

    def __init__(self, rows, *, account=None, symbol=None):
        self.rows = rows
        self.calls = []
        self.account = account or {}
        self.symbol = symbol or {}

    def copy_ticks_range(self, symbol, start, end, mode):
        self.calls.append((symbol, start, end, mode))
        start_msc = int(start.timestamp() * 1000)
        end_msc = int(end.timestamp() * 1000)
        return [
            row
            for row in self.rows
            if start_msc <= int(row["time_msc"]) <= end_msc
        ]

    def account_info(self):
        return self.account

    def symbol_info(self, symbol):
        return self.symbol


class BrokerExporterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.start = datetime(2026, 1, 2, 0, 0, tzinfo=UTC)
        self.end = datetime(2026, 1, 2, 0, 30, tzinfo=UTC)
        timestamps = (
            "2026-01-02T00:00:01Z",
            "2026-01-02T00:00:02Z",
            "2026-01-02T00:15:01Z",
            "2026-01-02T00:15:02Z",
        )
        self.rows = []
        for index, value in enumerate(timestamps):
            milliseconds = int(
                datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
                * 1000
            )
            self.rows.append(
                {
                    "time_msc": milliseconds,
                    "bid": 100.0 + index * 0.01,
                    "ask": 100.02 + index * 0.01,
                    "last": 0.0,
                    "volume": 1.0,
                    "volume_real": 0.0,
                    "flags": 6,
                }
            )
        self.broker_rows = [
            self.tick("2026-01-01T23:59:59Z", bid=99.99, ask=100.01),
            *self.rows,
            self.tick("2026-01-02T00:30:00Z", bid=100.04, ask=100.06),
        ]
        self.broker_spec = BrokerSpec(
            account_id="canary-demo",
            broker_legal_name="Regulated Broker Ltd",
            server="Broker-Demo",
            environment="DEMO",
            symbol="XAUUSD",
            broker_symbol="GOLD.a",
            account_currency="USD",
            digits=2,
            point=0.01,
            tick_size=0.01,
            tick_value=1.0,
            contract_size=100.0,
            volume_min=0.01,
            volume_max=100.0,
            volume_step=0.01,
            stops_level_points=10,
            freeze_level_points=5,
            margin_per_lot=1_000.0,
            session_calendar_sha256="c" * 64,
            captured_at=self.start,
        )
        self.evidence_identity = EvidenceInstrumentIdentity(
            instrument_kind="SPOT_METAL_CFD",
            base_currency="XAU",
            quote_currency="USD",
            profit_currency="USD",
            margin_currency="USD",
            margin_mode="RETAIL_HEDGING",
        )
        self.account = {
            "login": 123456,
            "company": "Regulated Broker Ltd",
            "server": "Broker-Demo",
            "trade_mode": FakeMT5.ACCOUNT_TRADE_MODE_DEMO,
            "currency": "USD",
            "margin_mode": FakeMT5.ACCOUNT_MARGIN_MODE_RETAIL_HEDGING,
        }
        self.symbol = {
            "digits": 2,
            "point": 0.01,
            "trade_tick_size": 0.01,
            "trade_contract_size": 100.0,
            "trade_tick_value": 1.0,
            "volume_min": 0.01,
            "volume_max": 100.0,
            "volume_step": 0.01,
            "trade_stops_level": 10,
            "trade_freeze_level": 5,
            "currency_profit": "USD",
            "currency_margin": "USD",
        }
        self.binding = broker_export_binding_from_spec(
            self.broker_spec,
            expected_login=123456,
            evidence_identity=self.evidence_identity,
        )
        self.instrument_spec = dict(self.binding.instrument_spec)

    @staticmethod
    def tick(value, *, bid, ask):
        milliseconds = int(
            datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000
        )
        return {
            "time_msc": milliseconds,
            "bid": bid,
            "ask": ask,
            "last": 0.0,
            "volume": 1.0,
            "volume_real": 0.0,
            "flags": 6,
        }

    def fake(self, rows=None, *, account=None, symbol=None):
        return FakeMT5(
            self.broker_rows if rows is None else rows,
            account=self.account if account is None else account,
            symbol=self.symbol if symbol is None else symbol,
        )

    def exporter(self, fake=None, *, binding=None, max_gap=900):
        return MT5EvidenceExporter(
            fake or self.fake(),
            binding=binding or self.binding,
            max_observed_tick_gap_seconds=max_gap,
        )

    def test_broker_spec_bridge_matches_real_evidence_schema(self) -> None:
        from validation_evidence.secure_core import _validate_instrument_spec

        validated = _validate_instrument_spec(
            "XAUUSD",
            self.binding.instrument_spec,
        )
        self.assertEqual(validated, dict(self.binding.instrument_spec))
        self.assertEqual(self.broker_spec.account_id, self.binding.account_alias)
        self.assertEqual(
            self.broker_spec.broker_legal_name,
            self.binding.broker_legal_name,
        )
        self.assertEqual(self.broker_spec.server, self.binding.server)
        self.assertEqual(self.broker_spec.environment, self.binding.environment)
        self.assertEqual(
            self.broker_spec.account_currency,
            self.binding.account_currency,
        )
        self.assertEqual(self.broker_spec.symbol, self.binding.canonical_symbol)
        self.assertEqual(self.broker_spec.broker_symbol, self.binding.broker_symbol)
        self.assertEqual(
            self.broker_spec.symbol,
            self.binding.instrument_spec["canonical_symbol"],
        )
        self.assertEqual(
            self.broker_spec.digits,
            self.binding.instrument_spec["digits"],
        )
        for field in (
            "point",
            "tick_size",
            "tick_value",
            "contract_size",
            "volume_min",
            "volume_max",
            "volume_step",
        ):
            self.assertEqual(
                Decimal(str(getattr(self.broker_spec, field))),
                Decimal(str(self.binding.instrument_spec[field])),
                field,
            )
        for field in ("stops_level_points", "freeze_level_points"):
            self.assertEqual(
                getattr(self.broker_spec, field),
                self.binding.instrument_spec[field],
                field,
            )
        self.assertEqual(
            self.broker_spec.session_calendar_sha256,
            self.binding.instrument_spec["session_calendar_sha256"],
        )

        fake = self.fake()
        ticks = self.exporter(fake).collect(
            self.broker_spec.broker_symbol,
            start_utc=self.start,
            end_utc=self.end,
        )
        self.assertEqual(len(self.rows), len(ticks))
        self.assertEqual(1, len(fake.calls))

    def test_broker_spec_bridge_fails_closed_on_contract_or_schema_drift(self) -> None:
        cases = (
            (
                replace(self.broker_spec, schema_version="2.0"),
                self.evidence_identity,
            ),
            (
                replace(self.broker_spec, point=0.1),
                self.evidence_identity,
            ),
            (
                self.broker_spec,
                replace(self.evidence_identity, base_currency="EUR"),
            ),
            (
                replace(self.broker_spec, environment="LIVE"),
                self.evidence_identity,
            ),
        )
        for broker_spec, evidence_identity in cases:
            with self.subTest(
                schema_version=broker_spec.schema_version,
                point=broker_spec.point,
                environment=broker_spec.environment,
                base_currency=evidence_identity.base_currency,
            ):
                with self.assertRaises(ValueError):
                    broker_export_binding_from_spec(
                        broker_spec,
                        expected_login=123456,
                        evidence_identity=evidence_identity,
                    )

        with self.assertRaises(ValueError):
            broker_export_binding_from_spec(
                self.broker_spec,
                expected_login=0,
                evidence_identity=self.evidence_identity,
            )

    def test_broker_spec_bridge_accepts_all_locked_v1_instrument_identities(
        self,
    ) -> None:
        cases = (
            ("XAUUSD", "XAU", "USD", "SPOT_METAL_CFD", 2, 0.01, 100.0),
            ("EURUSD", "EUR", "USD", "FOREX_SPOT_CFD", 5, 0.00001, 100_000.0),
            ("USDJPY", "USD", "JPY", "FOREX_SPOT_CFD", 3, 0.001, 100_000.0),
            ("AUDUSD", "AUD", "USD", "FOREX_SPOT_CFD", 5, 0.00001, 100_000.0),
        )
        for symbol, base, quote, kind, digits, point, contract_size in cases:
            with self.subTest(symbol=symbol):
                broker_spec = replace(
                    self.broker_spec,
                    symbol=symbol,
                    broker_symbol=f"{symbol}.a",
                    digits=digits,
                    point=point,
                    tick_size=point,
                    contract_size=contract_size,
                )
                evidence_identity = replace(
                    self.evidence_identity,
                    instrument_kind=kind,
                    base_currency=base,
                    quote_currency=quote,
                )
                binding = broker_export_binding_from_spec(
                    broker_spec,
                    expected_login=123456,
                    evidence_identity=evidence_identity,
                )
                self.assertEqual(symbol, binding.canonical_symbol)
                self.assertEqual(symbol, binding.instrument_spec["canonical_symbol"])

    def source(self):
        return {
            "provider_kind": "BROKER_EXPORT",
            "broker_legal_name": "Regulated Broker Ltd",
            "broker_server": "Broker-Demo",
            "environment": "DEMO",
            "canonical_symbol": "XAUUSD",
            "broker_symbol": "GOLD.a",
            "source_instance_id": "exporter-1",
            "quote_mode": "FINALIZED_BID_ASK_BARS",
            "exporter_version": "v2",
            "exporter_signing_key_id": "evidence-key-v1",
        }

    def test_collect_is_read_only_and_builds_finalized_bid_ask_bars(self) -> None:
        fake = self.fake()
        exporter = self.exporter(fake)
        ticks = exporter.collect("GOLD.a", start_utc=self.start, end_utc=self.end)
        bars = finalized_m15_bid_ask_bars(
            ticks,
            exported_at=datetime(2026, 1, 2, 0, 46, tzinfo=UTC),
        )
        self.assertEqual(2, len(bars))
        self.assertEqual(100.0, bars.iloc[0]["bid_open"])
        self.assertEqual(100.03, bars.iloc[1]["bid_close"])
        self.assertTrue(bars["is_final"].all())
        self.assertEqual(1, len(fake.calls))

    def test_naive_boundary_is_rejected_before_broker_call(self) -> None:
        fake = self.fake()
        with self.assertRaises(ValueError):
            self.exporter(fake).collect(
                "GOLD.a",
                start_utc=datetime(2026, 1, 2, 0, 0),
                end_utc=self.end,
            )
        self.assertEqual([], fake.calls)

    def test_partial_window_cannot_be_misrepresented_as_a_final_m15_bar(self) -> None:
        rows = [
            *self.broker_rows,
            self.tick("2026-01-02T00:04:59Z", bid=100.0, ask=100.02),
        ]
        ticks = self.exporter(self.fake(rows)).collect(
            "GOLD.a",
            start_utc=datetime(2026, 1, 2, 0, 5, tzinfo=UTC),
            end_utc=self.end,
        )
        with self.assertRaisesRegex(ValueError, "align to an M15 boundary"):
            finalized_m15_bid_ask_bars(
                ticks,
                exported_at=datetime(2026, 1, 2, 0, 46, tzinfo=UTC),
            )

        ticks.attrs.clear()
        with self.assertRaisesRegex(ValueError, "coverage metadata is required"):
            finalized_m15_bid_ask_bars(
                ticks,
                exported_at=datetime(2026, 1, 2, 0, 46, tzinfo=UTC),
            )

    def test_collect_rejects_account_server_environment_and_spec_drift(self) -> None:
        drift_cases = (
            (dict(self.account, login=999999), self.symbol, "ACCOUNT_LOGIN"),
            (dict(self.account, server="Wrong-Demo"), self.symbol, "ACCOUNT_SERVER"),
            (
                dict(self.account, trade_mode=FakeMT5.ACCOUNT_TRADE_MODE_REAL),
                self.symbol,
                "ACCOUNT_ENVIRONMENT",
            ),
            (dict(self.account, company="Unknown Broker"), self.symbol, "ACCOUNT_BROKER"),
            (self.account, dict(self.symbol, point=0.1), "POINT"),
        )
        for account, symbol, reason in drift_cases:
            with self.subTest(reason=reason):
                fake = self.fake(account=account, symbol=symbol)
                with self.assertRaisesRegex(BrokerExportBindingError, reason):
                    self.exporter(fake).collect(
                        "GOLD.a", start_utc=self.start, end_utc=self.end
                    )
                self.assertEqual([], fake.calls)

        other_login_binding = replace(self.binding, expected_login=999999)
        self.assertNotEqual(
            self.binding.public_binding_sha256,
            other_login_binding.public_binding_sha256,
        )

    def test_collect_rejects_account_switch_during_tick_copy(self) -> None:
        fake = self.fake()
        copy_ticks_range = fake.copy_ticks_range

        def copy_then_switch_account(symbol, start, end, mode):
            rows = copy_ticks_range(symbol, start, end, mode)
            fake.account = dict(fake.account, login=999999)
            return rows

        fake.copy_ticks_range = copy_then_switch_account
        with self.assertRaisesRegex(BrokerExportBindingError, "ACCOUNT_LOGIN"):
            self.exporter(fake).collect(
                "GOLD.a",
                start_utc=self.start,
                end_utc=self.end,
            )
        self.assertEqual(1, len(fake.calls))

    def test_dynamic_account_currency_tick_value_is_not_identity_drift(self) -> None:
        dynamic = dict(self.symbol, trade_tick_value=1.234567)
        ticks = self.exporter(self.fake(symbol=dynamic)).collect(
            "GOLD.a", start_utc=self.start, end_utc=self.end
        )
        self.assertFalse(ticks.empty)

        unavailable = dict(self.symbol, trade_tick_value=0.0)
        with self.assertRaisesRegex(
            BrokerExportBindingError, "TICK_VALUE_UNAVAILABLE"
        ):
            self.exporter(self.fake(symbol=unavailable)).collect(
                "GOLD.a", start_utc=self.start, end_utc=self.end
            )

    def test_collect_requires_observed_boundaries_and_bounded_continuity(self) -> None:
        with self.assertRaisesRegex(ValueError, "left/right boundary"):
            self.exporter(self.fake(self.rows)).collect(
                "GOLD.a", start_utc=self.start, end_utc=self.end
            )

        discontinuous = [
            self.tick("2026-01-01T23:59:59Z", bid=99.99, ask=100.01),
            self.rows[0],
            self.tick("2026-01-02T00:30:00Z", bid=100.04, ask=100.06),
        ]
        with self.assertRaisesRegex(ValueError, "bounded observed tick continuity"):
            self.exporter(self.fake(discontinuous)).collect(
                "GOLD.a", start_utc=self.start, end_utc=self.end
            )

    def test_aggregation_rejects_self_attested_requested_range(self) -> None:
        ticks = normalize_mt5_ticks(self.rows)
        ticks.attrs["coverage_start_at_utc"] = self.start
        ticks.attrs["coverage_end_at_utc"] = self.end
        with self.assertRaisesRegex(ValueError, "boundary and continuity proof"):
            aggregate_m15_bid_ask_bars(
                ticks,
                exported_at=datetime(2026, 1, 2, 0, 46, tzinfo=UTC),
            )

    def test_aggregation_splits_finalized_evidence_from_requery_tail(self) -> None:
        ticks = self.exporter().collect(
            "GOLD.a", start_utc=self.start, end_utc=self.end
        )
        result = aggregate_m15_bid_ask_bars(
            ticks,
            exported_at=datetime(2026, 1, 2, 0, 31, tzinfo=UTC),
        )
        self.assertEqual(1, len(result.finalized_bars))
        self.assertEqual(2, len(result.evidence_ticks))
        self.assertEqual(2, len(result.tail_ticks))
        self.assertEqual(
            datetime(2026, 1, 2, 0, 15, tzinfo=UTC),
            result.tail_requery_from_at,
        )
        metadata = result.coverage_metadata()
        self.assertEqual(2, metadata["archived_tick_rows"])
        self.assertEqual(2, metadata["tail_tick_rows"])
        self.assertEqual(1, len(metadata["bar_tick_ranges"]))

    def test_tick_schema_rejects_quote_time_and_integer_corruption(self) -> None:
        mismatched_time = dict(self.rows[0])
        mismatched_time["time_utc"] = datetime(2026, 1, 2, 0, 5, tzinfo=UTC)
        with self.assertRaisesRegex(ValueError, "does not match time_msc"):
            normalize_mt5_ticks([mismatched_time])

        crossed_quote = dict(self.rows[0], ask=99.0)
        with self.assertRaisesRegex(ValueError, "ask cannot be below bid"):
            normalize_mt5_ticks([crossed_quote])

        fractional_flags = dict(self.rows[0], flags=1.5)
        with self.assertRaisesRegex(ValueError, "flags must contain integers"):
            normalize_mt5_ticks([fractional_flags])

    @patch("live_runtime.broker_exporter.append_paired_forward_evidence")
    def test_export_archives_raw_ticks_and_bars(
        self,
        append_pair,
    ) -> None:
        append_pair.return_value = {
            "raw_tick_partition": {
                "contract_id": "contract-1",
                "symbol": "XAUUSD",
                "rows": 4,
                "partition_payload_sha256": "a" * 64,
            },
            "forward_segment": {
                "contract_id": "contract-1",
                "symbol": "XAUUSD",
                "rows": 2,
                "segment_payload_sha256": "b" * 64,
            },
            "paired_commit": {
                "export_id": "export_" + "0" * 32,
                "sequence": 1,
                "broker_binding_sha256": self.binding.public_binding_sha256,
                "coverage_metadata_sha256": "0" * 64,
                "raw_partition_payload_sha256": "a" * 64,
                "bar_segment_payload_sha256": "b" * 64,
                "paired_commit_payload_sha256": "c" * 64,
                "paired_commit_hmac_sha256": "d" * 64,
            },
        }
        arguments = {
            "artifact_root": self.tempdir.name,
            "contract_id": "contract-1",
            "canonical_symbol": "XAUUSD",
            "broker_symbol": "GOLD.a",
            "source": self.source(),
            "instrument_spec": self.instrument_spec,
            "start_utc": self.start,
            "end_utc": self.end,
            "exported_at": datetime(2026, 1, 2, 0, 46, tzinfo=UTC),
        }
        identity_provider = lambda: {"test": "identity"}
        clock_provider = lambda: arguments["exported_at"]
        exporter = MT5EvidenceExporter(
            self.fake(),
            binding=self.binding,
            max_observed_tick_gap_seconds=900,
            signing_key=b"exporter-injected-test-key-32bytes-minimum",
            build_identity_provider=identity_provider,
            clock_provider=clock_provider,
        )
        # The export and coverage hashes are deterministic but only known once
        # aggregation runs; bind the fake result at call time.
        def paired_result(*args, **kwargs):
            if append_pair.call_count > 1:
                raise EvidenceValidationError(
                    "PAIRED_EXPORT_ID_REPLAY",
                    kwargs["export_id"],
                )
            value = dict(append_pair.return_value)
            value["paired_commit"] = {
                **value["paired_commit"],
                "export_id": kwargs["export_id"],
                "broker_binding_sha256": kwargs["broker_binding_sha256"],
                "coverage_metadata_sha256": kwargs["coverage_metadata_sha256"],
            }
            return value

        append_pair.side_effect = paired_result
        result = exporter.export(**arguments)
        self.assertEqual("XAUUSD", result.symbol)
        self.assertEqual("FINALIZED_EVIDENCE_APPENDED", result.status)
        self.assertIsNotNone(result.paired_commit_receipt)
        self.assertEqual(
            self.binding.public_binding_sha256,
            result.broker_binding_sha256,
        )
        self.assertFalse(
            paired_append_recovery_status(
                self.tempdir.name, "contract-1", "XAUUSD"
            )["blocked"]
        )
        self.assertFalse(
            (Path(self.tempdir.name) / "export_commits").exists()
        )
        coverage = append_pair.call_args.kwargs["coverage_metadata"]
        observed_facts = coverage["broker_binding_observed_facts"]
        observed_hash = canonical_evidence_payload_sha256(observed_facts)
        self.assertEqual(observed_hash, coverage["observed_facts_sha256"])
        self.assertEqual(
            observed_hash,
            coverage["broker_binding_pre_observed_facts_sha256"],
        )
        self.assertEqual(
            observed_hash,
            coverage["broker_binding_post_observed_facts_sha256"],
        )
        append_pair.assert_called_once()
        self.assertEqual(
            b"exporter-injected-test-key-32bytes-minimum",
            append_pair.call_args.kwargs["signing_key"],
        )
        self.assertIs(
            identity_provider,
            append_pair.call_args.kwargs["build_identity_provider"],
        )
        self.assertIs(clock_provider, append_pair.call_args.kwargs["clock_provider"])
        with self.assertRaisesRegex(
            PairedAppendRecoveryRequired, "duplicate append is blocked"
        ):
            exporter.export(**arguments)
        self.assertEqual(2, append_pair.call_count)

    @patch("live_runtime.broker_exporter.append_paired_forward_evidence")
    def test_interrupted_paired_append_blocks_subsequent_evidence(
        self,
        append_pair,
    ) -> None:
        def leave_authoritative_pending_marker(*args, **kwargs):
            marker = (
                Path(self.tempdir.name)
                / "forward"
                / "contract-1"
                / "paired_pending"
                / "XAUUSD.json"
            )
            marker.parent.mkdir(parents=True)
            marker.write_text(
                '{"status":"INCOMPLETE_RECOVERY_REQUIRED"}\n',
                encoding="utf-8",
            )
            raise RuntimeError("simulated paired append failure")

        append_pair.side_effect = leave_authoritative_pending_marker
        arguments = {
            "artifact_root": self.tempdir.name,
            "contract_id": "contract-1",
            "canonical_symbol": "XAUUSD",
            "broker_symbol": "GOLD.a",
            "source": self.source(),
            "instrument_spec": self.instrument_spec,
            "start_utc": self.start,
            "end_utc": self.end,
            "exported_at": datetime(2026, 1, 2, 0, 31, tzinfo=UTC),
        }
        with self.assertRaisesRegex(
            PairedAppendRecoveryRequired, "recovery marker blocks evidence"
        ):
            self.exporter().export(**arguments)

        recovery = paired_append_recovery_status(
            self.tempdir.name, "contract-1", "XAUUSD"
        )
        self.assertTrue(recovery["blocked"])
        self.assertEqual(
            "INCOMPLETE_RECOVERY_REQUIRED",
            recovery["pending_exports"][0]["status"],
        )
        with self.assertRaisesRegex(
            PairedAppendRecoveryRequired, "prior paired append is incomplete"
        ):
            self.exporter().export(**arguments)
        self.assertEqual(1, append_pair.call_count)

    @patch("live_runtime.broker_exporter.append_paired_forward_evidence")
    def test_crash_after_inner_commit_creates_no_outer_recovery_blocker(
        self,
        append_pair,
    ) -> None:
        def paired_result(*args, **kwargs):
            return {
                "raw_tick_partition": {
                    "contract_id": "contract-1",
                    "symbol": "XAUUSD",
                    "rows": 4,
                    "partition_payload_sha256": "a" * 64,
                },
                "forward_segment": {
                    "contract_id": "contract-1",
                    "symbol": "XAUUSD",
                    "rows": 2,
                    "segment_payload_sha256": "b" * 64,
                },
                "paired_commit": {
                    "export_id": kwargs["export_id"],
                    "sequence": 1,
                    "broker_binding_sha256": kwargs["broker_binding_sha256"],
                    "coverage_metadata_sha256": kwargs[
                        "coverage_metadata_sha256"
                    ],
                    "raw_partition_payload_sha256": "a" * 64,
                    "bar_segment_payload_sha256": "b" * 64,
                    "paired_commit_payload_sha256": "c" * 64,
                    "paired_commit_hmac_sha256": "d" * 64,
                },
            }

        append_pair.side_effect = paired_result
        arguments = {
            "artifact_root": self.tempdir.name,
            "contract_id": "contract-1",
            "canonical_symbol": "XAUUSD",
            "broker_symbol": "GOLD.a",
            "source": self.source(),
            "instrument_spec": self.instrument_spec,
            "start_utc": self.start,
            "end_utc": self.end,
            "exported_at": datetime(2026, 1, 2, 0, 46, tzinfo=UTC),
        }
        exporter = self.exporter()
        with patch(
            "live_runtime.broker_exporter.PairedAppendCommitReceipt",
            side_effect=RuntimeError("simulated crash after inner commit"),
        ):
            with self.assertRaisesRegex(RuntimeError, "after inner commit"):
                exporter.export(**arguments)

        self.assertFalse(
            paired_append_recovery_status(
                self.tempdir.name,
                "contract-1",
                "XAUUSD",
            )["blocked"]
        )
        self.assertFalse((Path(self.tempdir.name) / "export_commits").exists())
        recovered = exporter.export(**arguments)
        self.assertEqual("FINALIZED_EVIDENCE_APPENDED", recovered.status)
        self.assertEqual(2, append_pair.call_count)

    @patch("live_runtime.broker_exporter.append_paired_forward_evidence")
    def test_export_archives_only_ticks_behind_finalized_boundary(
        self,
        append_pair,
    ) -> None:
        def paired_result(*args, **kwargs):
            return {
                "raw_tick_partition": {
                    "contract_id": "contract-1",
                    "symbol": "XAUUSD",
                    "rows": 2,
                    "partition_payload_sha256": "a" * 64,
                },
                "forward_segment": {
                    "contract_id": "contract-1",
                    "symbol": "XAUUSD",
                    "rows": 1,
                    "segment_payload_sha256": "b" * 64,
                },
                "paired_commit": {
                    "export_id": kwargs["export_id"],
                    "sequence": 1,
                    "broker_binding_sha256": kwargs["broker_binding_sha256"],
                    "coverage_metadata_sha256": kwargs[
                        "coverage_metadata_sha256"
                    ],
                    "raw_partition_payload_sha256": "a" * 64,
                    "bar_segment_payload_sha256": "b" * 64,
                    "paired_commit_payload_sha256": "c" * 64,
                    "paired_commit_hmac_sha256": "d" * 64,
                },
            }

        append_pair.side_effect = paired_result
        result = self.exporter().export(
            artifact_root=self.tempdir.name,
            contract_id="contract-1",
            canonical_symbol="XAUUSD",
            broker_symbol="GOLD.a",
            source=self.source(),
            instrument_spec=self.instrument_spec,
            start_utc=self.start,
            end_utc=self.end,
            exported_at=datetime(2026, 1, 2, 0, 31, tzinfo=UTC),
        )
        raw_frame = append_pair.call_args.args[3]
        bar_frame = append_pair.call_args.args[4]
        self.assertEqual(2, len(raw_frame))
        self.assertEqual(1, len(bar_frame))
        self.assertEqual(2, result.coverage_metadata["tail_tick_rows"])
        self.assertEqual(
            datetime(2026, 1, 2, 0, 15, tzinfo=UTC),
            result.coverage_metadata["tail_requery_from_at_utc"],
        )
        self.assertEqual(64, len(result.content_sha256))
        tampered_metadata = dict(result.coverage_metadata)
        tampered_metadata["tail_tick_rows"] = 3
        with self.assertRaisesRegex(ValueError, "do not reconcile"):
            replace(result, coverage_metadata=tampered_metadata)

    @patch("live_runtime.broker_exporter.append_paired_forward_evidence")
    def test_no_finalized_bar_retains_tail_without_appending_evidence(
        self,
        append_pair,
    ) -> None:
        rows = [
            self.broker_rows[0],
            *self.rows[:2],
            self.tick("2026-01-02T00:15:00Z", bid=100.02, ask=100.04),
        ]
        result = self.exporter(self.fake(rows)).export(
            artifact_root=self.tempdir.name,
            contract_id="contract-1",
            canonical_symbol="XAUUSD",
            broker_symbol="GOLD.a",
            source=self.source(),
            instrument_spec=self.instrument_spec,
            start_utc=self.start,
            end_utc=datetime(2026, 1, 2, 0, 15, tzinfo=UTC),
            exported_at=datetime(2026, 1, 2, 0, 20, tzinfo=UTC),
        )
        self.assertEqual("TAIL_RETAINED_NO_FINALIZED_BAR", result.status)
        self.assertIsNone(result.raw_tick_partition)
        self.assertIsNone(result.finalized_bar_segment)
        self.assertEqual(2, result.coverage_metadata["tail_tick_rows"])
        self.assertEqual(self.start, result.coverage_metadata["tail_requery_from_at_utc"])
        append_pair.assert_not_called()


if __name__ == "__main__":
    unittest.main()
