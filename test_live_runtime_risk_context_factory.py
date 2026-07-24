from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from live_runtime.contracts import BrokerSpec
from live_runtime.health import MIN_FREE_DISK_BYTES
from live_runtime.journal import ExecutionJournal
from live_runtime.market_guard import (
    NEWS_FEED_SCHEMA_VERSION,
    NewsEvent,
    NewsFeed,
    evaluate_market_guards,
)
from live_runtime.permit import (
    NO_PROMOTION_EVIDENCE_SHA256,
    PromotionPermit,
    account_alias_sha256,
    validate_permit,
)
from live_runtime.risk import _mint_usd_risk_cap_conversion
from live_runtime.risk_context_factory import (
    BrokerExposure,
    ExposureReceipt,
    RiskCalibrationReceipt,
    RiskContextVerificationError,
    VerifiedRiskContext,
    create_verified_risk_context,
    require_verified_risk_context,
)
from live_runtime.risk_ledger import (
    AccountRiskSnapshot,
    RiskLedgerBinding,
)
from live_runtime.runtime_fact_collector import RuntimeFactCollector
from test_fixtures.risk_source import (
    SOURCE_ISSUER,
    SOURCE_KEY,
    SOURCE_KEY_ID,
    TrustedRiskLedgerFixture,
    upstream_verifier,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 22, 4, 0, 0, tzinfo=UTC)
VERIFY_AT = NOW + timedelta(milliseconds=500)
ACCOUNT_ID = "phillip-fx-demo"
SERVER = "PhillipSecuritiesJP-PROD"
ENVIRONMENT = "DEMO"
SYMBOL = "EURUSD"
BROKER_SYMBOL = "EURUSD.ps01"
IDENTITY_SHA256 = "1" * 64
CONFIG_SHA256 = "2" * 64
MODEL_SHA256 = "3" * 64
COMMIT_SHA = "4" * 40
DATA_WINDOW_SHA256 = "5" * 64
RUNTIME_KEY_ID = "runtime-key-v1"
RISK_KEY_ID = "risk-key-v1"
EXPOSURE_KEY_ID = "exposure-key-v1"
CALIBRATION_KEY_ID = "calibration-key-v1"
PERMIT_KEY = b"permit-key-material-at-least-32-bytes-long"
RUNTIME_KEY = b"runtime-key-material-at-least-32-bytes-long"
RISK_KEY = b"risk-key-material-at-least-32-bytes-long"
EXPOSURE_KEY = b"exposure-key-material-at-least-32-bytes-long"
CALIBRATION_KEY = b"calibration-key-material-at-least-32-bytes"
NEWS_KEY = b"news-key-material-at-least-32-bytes-long"


class FakeAdapter:
    max_tick_age_seconds = 1.0

    def __init__(self, spec: BrokerSpec) -> None:
        self.spec = spec

    def assert_account_binding(self):
        return {
            "account_alias": ACCOUNT_ID,
            "server": SERVER,
            "currency": "JPY",
            "balance": 1_000_000.0,
            "equity": 1_000_000.0,
            "margin": 0.0,
            "margin_free": 1_000_000.0,
            "margin_level": 0.0,
            "trade_allowed": False,
            "trade_expert": True,
            "captured_at_utc": NOW,
        }

    def execution_fence_identity(self):
        return IDENTITY_SHA256

    def get_broker_spec(self, symbol, broker_symbol, *, now):
        if (symbol, broker_symbol, now) != (SYMBOL, BROKER_SYMBOL, NOW):
            raise AssertionError("unexpected broker specification request")
        return self.spec

    def current_tick(self, broker_symbol, *, now):
        if (broker_symbol, now) != (BROKER_SYMBOL, NOW):
            raise AssertionError("unexpected tick request")
        return {
            "bid": 1.17234,
            "ask": 1.17236,
            "time_utc": NOW - timedelta(milliseconds=100),
            "age_seconds": 0.1,
        }


class TrustedRiskContextFactoryTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.journal = ExecutionJournal(
            self.root / "execution.sqlite3", clock_provider=lambda: NOW
        )
        self.spec = BrokerSpec(
            account_id=ACCOUNT_ID,
            broker_legal_name="Phillip Securities Japan, Ltd.",
            server=SERVER,
            environment=ENVIRONMENT,
            symbol=SYMBOL,
            broker_symbol=BROKER_SYMBOL,
            account_currency="JPY",
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
            session_calendar_sha256="6" * 64,
            captured_at=NOW,
        )
        collector = RuntimeFactCollector(
            adapter=FakeAdapter(self.spec),
            journal=self.journal,
            key_id=RUNTIME_KEY_ID,
            key_provider=lambda key_id: self._key(key_id),
            clock_provider=lambda: NOW,
            clock_drift_provider=lambda: 0.1,
            heartbeat_provider=lambda: NOW - timedelta(seconds=2),
            audit_export_status_provider=lambda: True,
            backup_status_provider=lambda: True,
            disk_free_provider=lambda _path: MIN_FREE_DISK_BYTES + 1,
        )
        self.runtime_receipt = collector.collect(
            symbol=SYMBOL, broker_symbol=BROKER_SYMBOL
        )
        self.risk_receipt = self._risk_receipt(equity=1_000_000.0)
        self.exposure_receipt = ExposureReceipt(
            account_id=ACCOUNT_ID,
            server=SERVER,
            environment=ENVIRONMENT,
            account_runtime_identity_sha256=IDENTITY_SHA256,
            journal_sha256=self.journal.journal_sha256,
            active_orders=(),
            active_positions=(),
            active_order_count=0,
            active_position_count=0,
            reserved_canonical_symbols=(),
            reconciliation_clean=True,
            key_id=EXPOSURE_KEY_ID,
            observed_at_utc=NOW,
            valid_until_utc=NOW + timedelta(seconds=1),
        ).sign(EXPOSURE_KEY)
        self.calibration_receipt = RiskCalibrationReceipt(
            account_id=ACCOUNT_ID,
            server=SERVER,
            environment=ENVIRONMENT,
            symbol=SYMBOL,
            broker_symbol=BROKER_SYMBOL,
            account_runtime_identity_sha256=IDENTITY_SHA256,
            broker_spec_sha256=self.spec.content_sha256,
            config_sha256=CONFIG_SHA256,
            data_window_sha256=DATA_WINDOW_SHA256,
            data_window_start_utc=NOW - timedelta(days=20),
            data_window_end_utc=NOW - timedelta(minutes=1),
            session_count=20,
            sample_count=2_000,
            median_spread_points=2.0,
            p95_spread_points=4.0,
            p95_slippage_points=1.0,
            key_id=CALIBRATION_KEY_ID,
            issued_at_utc=NOW,
            valid_until_utc=NOW + timedelta(hours=24),
        ).sign(CALIBRATION_KEY)
        feed = NewsFeed(
            fetched_at=NOW,
            events=(
                NewsEvent(
                    event_id="coverage-sentinel",
                    currency="AUD",
                    impact="LOW",
                    scheduled_at=NOW,
                ),
            ),
            provider_name="regulated-calendar-provider",
            provider_healthy=True,
            schema_version=NEWS_FEED_SCHEMA_VERSION,
            coverage_start_at=NOW - timedelta(hours=1),
            coverage_end_at=NOW + timedelta(hours=2),
            signing_key_id="news-key-v1",
        ).sign(NEWS_KEY)
        self.market_guard = evaluate_market_guards(
            symbol=SYMBOL,
            now=NOW,
            news_feed=feed,
            broker_rollover_at=NOW + timedelta(hours=5),
            news_signing_key_provider=lambda _key_id: NEWS_KEY,
        )
        permit = PromotionPermit(
            mode="DEMO",
            account_alias_sha256=account_alias_sha256(ACCOUNT_ID),
            server=SERVER,
            symbols=(SYMBOL,),
            commit_sha=COMMIT_SHA,
            config_sha256=CONFIG_SHA256,
            model_artifact_sha256=MODEL_SHA256,
            issued_at=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=4),
            nonce="manual-demo-test-1",
            journal_sha256=self.journal.journal_sha256,
        ).sign(PERMIT_KEY)
        self.permit_validation = validate_permit(
            permit,
            PERMIT_KEY,
            now=NOW,
            expected_mode="DEMO",
            expected_account_alias=ACCOUNT_ID,
            expected_server=SERVER,
            expected_symbols=(SYMBOL,),
            expected_commit_sha=COMMIT_SHA,
            expected_config_sha256=CONFIG_SHA256,
            expected_model_artifact_sha256=MODEL_SHA256,
            expected_journal_sha256=self.journal.journal_sha256,
        )
        self.conversion = _mint_usd_risk_cap_conversion(
            account_id=ACCOUNT_ID,
            server=SERVER,
            account_currency="JPY",
            account_currency_per_usd=150.0,
            source="MT5_BID_ASK",
            broker_symbol="USDJPY.ps01",
            direction="DIRECT",
            bid=150.0,
            ask=150.02,
            captured_at_utc=NOW,
        )

    def _key(self, key_id: str) -> bytes:
        return {
            RUNTIME_KEY_ID: RUNTIME_KEY,
            RISK_KEY_ID: RISK_KEY,
            EXPOSURE_KEY_ID: EXPOSURE_KEY,
            CALIBRATION_KEY_ID: CALIBRATION_KEY,
        }[key_id]

    def _risk_receipt(self, *, equity: float):
        binding = RiskLedgerBinding(
            account_id_sha256=account_alias_sha256(ACCOUNT_ID),
            server=SERVER,
            environment=ENVIRONMENT,
            journal_sha256=self.journal.journal_sha256,
            broker_spec_sha256=self.spec.content_sha256,
            account_currency="JPY",
        )
        path = self.root / f"risk-{int(equity)}.sqlite3"
        ledger = TrustedRiskLedgerFixture(
            path,
            binding=binding,
            key_id=RISK_KEY_ID,
            key_provider=lambda key_id: self._key(key_id),
            source_key_provider=lambda _key_id: SOURCE_KEY,
            trusted_source_issuer_keys={SOURCE_ISSUER: (SOURCE_KEY_ID,)},
            upstream_receipt_verifier=upstream_verifier,
            clock_provider=lambda: NOW,
        )
        return ledger.append_account_snapshot(
            AccountRiskSnapshot(
                snapshot_id=f"snapshot-{int(equity)}",
                binding=binding,
                observed_at_utc=NOW,
                daily_baseline_id="day-2026-07-22",
                weekly_baseline_id="week-2026-W30",
                equity=equity,
            )
        )

    def create(self, **changes):
        values = {
            "risk_state_receipt": self.risk_receipt,
            "runtime_fact_receipt": self.runtime_receipt,
            "exposure_receipt": self.exposure_receipt,
            "calibration_receipt": self.calibration_receipt,
            "market_guard_decision": self.market_guard,
            "permit_validation": self.permit_validation,
            "usd_risk_cap_conversion": self.conversion,
            "expected_account_id": ACCOUNT_ID,
            "expected_server": SERVER,
            "expected_environment": ENVIRONMENT,
            "expected_symbol": SYMBOL,
            "expected_broker_symbol": BROKER_SYMBOL,
            "expected_mode": "DEMO",
            "expected_permit_symbols": (SYMBOL,),
            "expected_account_runtime_identity_sha256": IDENTITY_SHA256,
            "expected_broker_spec_sha256": self.spec.content_sha256,
            "expected_journal_sha256": self.journal.journal_sha256,
            "expected_commit_sha": COMMIT_SHA,
            "expected_config_sha256": CONFIG_SHA256,
            "expected_model_artifact_sha256": MODEL_SHA256,
            "expected_promotion_evidence_sha256": NO_PROMOTION_EVIDENCE_SHA256,
            "expected_calibration_data_window_sha256": DATA_WINDOW_SHA256,
            "expected_runtime_fact_key_id": RUNTIME_KEY_ID,
            "expected_exposure_key_id": EXPOSURE_KEY_ID,
            "expected_calibration_key_id": CALIBRATION_KEY_ID,
            "risk_state_key_provider": lambda key_id: self._key(key_id),
            "runtime_fact_key_provider": lambda key_id: self._key(key_id),
            "exposure_key_provider": lambda key_id: self._key(key_id),
            "calibration_key_provider": lambda key_id: self._key(key_id),
            "clock_provider": lambda: VERIFY_AT,
        }
        values.update(changes)
        return create_verified_risk_context(**values)

    def assert_rejected(self, expected_reason: str, **changes) -> None:
        with self.assertRaises(RiskContextVerificationError) as caught:
            self.create(**changes)
        self.assertIn(expected_reason, caught.exception.reason_codes)

    def test_successful_synthetic_manual_demo_context_is_sealed_and_deny_only(self):
        verified = self.create()
        self.assertEqual("DEMO", verified.context.mode)
        self.assertEqual(1_000_000.0, verified.context.equity)
        self.assertAlmostEqual(2.0, verified.context.current_spread_points)
        self.assertEqual(0, verified.context.open_position_count)
        self.assertTrue(verified.context.permit_valid)
        self.assertFalse(verified.live_allowed)
        self.assertFalse(verified.safe_to_demo_auto_order)
        self.assertGreater(verified.valid_until_utc, verified.evaluated_at_utc)
        with self.assertRaises(TypeError):
            VerifiedRiskContext(
                context=verified.context,
                account_id=ACCOUNT_ID,
                server=SERVER,
                environment=ENVIRONMENT,
                symbol=SYMBOL,
                mode="DEMO",
                evaluated_at_utc=VERIFY_AT,
                valid_until_utc=NOW + timedelta(seconds=1),
                risk_state_receipt_sha256="a" * 64,
                runtime_fact_receipt_sha256="b" * 64,
                exposure_receipt_sha256="c" * 64,
                calibration_receipt_sha256="d" * 64,
                market_guard_decision_sha256="e" * 64,
                permit_validation_sha256="f" * 64,
                conversion_sha256="0" * 64,
            )

    def test_use_boundary_rechecks_every_runtime_binding_and_expiry(self):
        verified = self.create()
        substituted_feed = NewsFeed(
            fetched_at=NOW,
            events=(
                NewsEvent(
                    event_id="different-coverage-sentinel",
                    currency="AUD",
                    impact="LOW",
                    scheduled_at=NOW,
                ),
            ),
            provider_name="regulated-calendar-provider",
            provider_healthy=True,
            schema_version=NEWS_FEED_SCHEMA_VERSION,
            coverage_start_at=NOW - timedelta(hours=1),
            coverage_end_at=NOW + timedelta(hours=2),
            signing_key_id="news-key-v1",
        ).sign(NEWS_KEY)
        substituted_guard = evaluate_market_guards(
            symbol=SYMBOL,
            now=NOW,
            news_feed=substituted_feed,
            broker_rollover_at=NOW + timedelta(hours=5),
            news_signing_key_provider=lambda _key_id: NEWS_KEY,
        )
        values = {
            "now": VERIFY_AT,
            "expected_account_id": ACCOUNT_ID,
            "expected_server": SERVER,
            "expected_environment": ENVIRONMENT,
            "expected_mode": "DEMO",
            "expected_symbol": SYMBOL,
            "expected_broker_symbol": BROKER_SYMBOL,
            "expected_account_runtime_identity_sha256": IDENTITY_SHA256,
            "expected_journal_sha256": self.journal.journal_sha256,
            "broker_spec": self.spec,
            "health_facts": self.runtime_receipt.health_facts,
            "market_guard_decision": self.market_guard,
            "expected_permit_id": self.permit_validation.permit_id,
        }
        self.assertIs(
            verified.context,
            require_verified_risk_context(verified, **values),
        )
        cases = (
            (
                {"expected_journal_sha256": "9" * 64},
                "VERIFIED_RISK_CONTEXT_JOURNAL_MISMATCH",
            ),
            (
                {"broker_spec": replace(self.spec, tick_value=101.0)},
                "VERIFIED_RISK_CONTEXT_BROKER_SPEC_MISMATCH",
            ),
            (
                {"expected_permit_id": "permit-substitution"},
                "VERIFIED_RISK_CONTEXT_PERMIT_MISMATCH",
            ),
            (
                {
                    "health_facts": replace(
                        self.runtime_receipt.health_facts,
                        backup_recent=False,
                    )
                },
                "VERIFIED_RISK_CONTEXT_HEALTH_MISMATCH",
            ),
            (
                {"market_guard_decision": substituted_guard},
                "VERIFIED_RISK_CONTEXT_MARKET_GUARD_MISMATCH",
            ),
            (
                {"now": verified.valid_until_utc},
                "VERIFIED_RISK_CONTEXT_EXPIRED",
            ),
        )
        for changes, expected_reason in cases:
            with self.subTest(expected_reason=expected_reason):
                with self.assertRaises(RiskContextVerificationError) as caught:
                    require_verified_risk_context(
                        verified,
                        **{**values, **changes},
                    )
                self.assertIn(expected_reason, caught.exception.reason_codes)
        with self.assertRaises(TypeError):
            require_verified_risk_context(  # type: ignore[arg-type]
                verified.context,
                **values,
            )

    def test_missing_and_wrong_types_fail_before_context_construction(self):
        self.assert_rejected(
            "EXPOSURE_RECEIPT_TYPE_INVALID", exposure_receipt=None
        )
        self.assert_rejected(
            "USD_CONVERSION_TYPE_INVALID", usd_risk_cap_conversion=object()
        )

    def test_tampered_receipt_signatures_fail_closed(self):
        self.assert_rejected(
            "EXPOSURE_SIGNATURE_INVALID",
            exposure_receipt=replace(self.exposure_receipt, signature="0" * 64),
        )
        self.assert_rejected(
            "CALIBRATION_SIGNATURE_INVALID",
            calibration_receipt=replace(
                self.calibration_receipt, signature="0" * 64
            ),
        )
        self.assert_rejected(
            "RUNTIME_FACT_INVALID_SIGNATURE",
            runtime_fact_receipt=replace(self.runtime_receipt, signature="0" * 64),
        )
        self.assert_rejected(
            "RISK_STATE_SIGNATURE_INVALID",
            risk_state_key_provider=lambda _key_id: b"wrong-key-material-at-least-32-bytes-long",
        )

    def test_replay_and_future_proofs_are_rejected(self):
        self.assert_rejected(
            "RISK_STATE_RECEIPT_STALE",
            clock_provider=lambda: NOW + timedelta(seconds=2),
        )
        future = ExposureReceipt(
            account_id=ACCOUNT_ID,
            server=SERVER,
            environment=ENVIRONMENT,
            account_runtime_identity_sha256=IDENTITY_SHA256,
            journal_sha256=self.journal.journal_sha256,
            active_orders=(),
            active_positions=(),
            active_order_count=0,
            active_position_count=0,
            reserved_canonical_symbols=(),
            reconciliation_clean=True,
            key_id=EXPOSURE_KEY_ID,
            observed_at_utc=NOW + timedelta(milliseconds=750),
            valid_until_utc=NOW + timedelta(seconds=1, milliseconds=750),
        ).sign(EXPOSURE_KEY)
        self.assert_rejected(
            "EXPOSURE_RECEIPT_STALE_OR_FUTURE", exposure_receipt=future
        )

    def test_exact_account_server_symbol_and_permit_bindings_are_required(self):
        self.assert_rejected(
            "RISK_STATE_BINDING_MISMATCH", expected_account_id="other-account"
        )
        self.assert_rejected(
            "RUNTIME_FACT_SERVER_BINDING_MISMATCH", expected_server="Other-Server"
        )
        self.assert_rejected(
            "CALIBRATION_BINDING_MISMATCH",
            expected_calibration_data_window_sha256="9" * 64,
        )
        self.assert_rejected(
            "PERMIT_VALIDATION_BINDING_INVALID", expected_mode="PAPER"
        )

    def test_risk_ledger_and_runtime_equity_must_match_exactly(self):
        self.assert_rejected(
            "RISK_STATE_RUNTIME_EQUITY_MISMATCH",
            risk_state_receipt=self._risk_receipt(equity=999_999.0),
        )

    def test_exposure_requires_clean_reconciliation_and_consistent_reservations(self):
        dirty = replace(
            self.exposure_receipt,
            reconciliation_clean=False,
            signature="",
        ).sign(EXPOSURE_KEY)
        self.assert_rejected(
            "EXPOSURE_RECONCILIATION_NOT_CLEAN", exposure_receipt=dirty
        )
        position = BrokerExposure(
            exposure_id="position-1",
            kind="POSITION",
            canonical_symbol=SYMBOL,
            broker_symbol="WRONG.ps01",
            side="BUY",
            volume=0.01,
        )
        mismatched = ExposureReceipt(
            account_id=ACCOUNT_ID,
            server=SERVER,
            environment=ENVIRONMENT,
            account_runtime_identity_sha256=IDENTITY_SHA256,
            journal_sha256=self.journal.journal_sha256,
            active_orders=(),
            active_positions=(position,),
            active_order_count=0,
            active_position_count=1,
            reserved_canonical_symbols=(SYMBOL,),
            reconciliation_clean=True,
            key_id=EXPOSURE_KEY_ID,
            observed_at_utc=NOW,
            valid_until_utc=NOW + timedelta(seconds=1),
        ).sign(EXPOSURE_KEY)
        self.assert_rejected(
            "EXPOSURE_BROKER_SYMBOL_MISMATCH", exposure_receipt=mismatched
        )
        with self.assertRaises(ValueError):
            replace(mismatched, active_position_count=0)
        with self.assertRaises(ValueError):
            replace(mismatched, reserved_canonical_symbols=())

    def test_inadequate_calibration_and_stale_conversion_fail_closed(self):
        inadequate = replace(
            self.calibration_receipt,
            session_count=19,
            signature="",
        ).sign(CALIBRATION_KEY)
        self.assert_rejected(
            "CALIBRATION_SESSIONS_INSUFFICIENT",
            calibration_receipt=inadequate,
        )
        stale_conversion = _mint_usd_risk_cap_conversion(
            account_id=ACCOUNT_ID,
            server=SERVER,
            account_currency="JPY",
            account_currency_per_usd=150.0,
            source="MT5_BID_ASK",
            broker_symbol="USDJPY.ps01",
            direction="DIRECT",
            bid=150.0,
            ask=150.02,
            captured_at_utc=NOW - timedelta(seconds=2),
        )
        self.assert_rejected(
            "USD_CONVERSION_STALE", usd_risk_cap_conversion=stale_conversion
        )


if __name__ == "__main__":
    unittest.main()
