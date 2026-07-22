"""Build legitimate factory-sealed risk contexts for executable-boundary tests."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
import tempfile

from live_runtime.contracts import BrokerSpec
from live_runtime.health import MIN_FREE_DISK_BYTES, RuntimeHealthFacts
from live_runtime.journal import ExecutionJournal
from live_runtime.market_guard import MarketGuardDecision
from live_runtime.permit import PromotionPermit, validate_permit
from live_runtime.risk import RiskContext
from live_runtime.risk_context_factory import (
    BrokerExposure,
    ExposureReceipt,
    RiskCalibrationReceipt,
    VerifiedRiskContext,
    create_verified_risk_context,
)
from live_runtime.risk_ledger import (
    AccountRiskSnapshot,
    ClosedTradeRiskEvent,
    EntryRiskEvent,
    RiskLedgerBinding,
)
from live_runtime.runtime_fact_collector import RuntimeFactCollector
from live_runtime.permit import account_alias_sha256
from test_fixtures.risk_source import (
    SOURCE_ISSUER,
    SOURCE_KEY,
    SOURCE_KEY_ID,
    TrustedRiskLedgerFixture,
    upstream_verifier,
)


_RUNTIME_KEY_ID = "fixture-runtime-key-v1"
_RISK_KEY_ID = "fixture-risk-key-v1"
_EXPOSURE_KEY_ID = "fixture-exposure-key-v1"
_CALIBRATION_KEY_ID = "fixture-calibration-key-v1"
_RUNTIME_KEY = b"fixture-runtime-key-material-at-least-32-bytes"
_RISK_KEY = b"fixture-risk-key-material-at-least-32-bytes"
_EXPOSURE_KEY = b"fixture-exposure-key-material-at-least-32-bytes"
_CALIBRATION_KEY = b"fixture-calibration-key-material-at-least-32-bytes"
_DATA_WINDOW_SHA256 = "7" * 64


class _FactAdapter:
    max_tick_age_seconds = 1.0

    def __init__(
        self,
        *,
        spec: BrokerSpec,
        identity_sha256: str,
        equity: float,
        observed_at: datetime,
        spread_points: float,
    ) -> None:
        self.spec = spec
        self.identity_sha256 = identity_sha256
        self.equity = equity
        self.observed_at = observed_at
        self.spread_points = spread_points

    def assert_account_binding(self):
        return {
            "account_alias": self.spec.account_id,
            "server": self.spec.server,
            "currency": self.spec.account_currency,
            "balance": self.equity,
            "equity": self.equity,
            "margin": 0.0,
            "margin_free": self.equity,
            "margin_level": 0.0,
            "trade_allowed": False,
            "trade_expert": True,
            "captured_at_utc": self.observed_at,
        }

    def execution_fence_identity(self):
        return self.identity_sha256

    def get_broker_spec(self, symbol, broker_symbol, *, now):
        if (symbol, broker_symbol) != (self.spec.symbol, self.spec.broker_symbol):
            raise AssertionError("unexpected fixture broker specification request")
        return self.spec

    def current_tick(self, broker_symbol, *, now):
        if broker_symbol != self.spec.broker_symbol:
            raise AssertionError("unexpected fixture broker tick request")
        bid = 100.0
        return {
            "bid": bid,
            "ask": bid + self.spread_points * self.spec.point,
            "time_utc": self.observed_at,
            "age_seconds": 0.0,
        }


def _key(key_id: str) -> bytes:
    return {
        _RUNTIME_KEY_ID: _RUNTIME_KEY,
        _RISK_KEY_ID: _RISK_KEY,
        _EXPOSURE_KEY_ID: _EXPOSURE_KEY,
        _CALIBRATION_KEY_ID: _CALIBRATION_KEY,
    }[key_id]


def build_verified_risk_context(
    *,
    journal: ExecutionJournal,
    broker_spec: BrokerSpec,
    health_facts: RuntimeHealthFacts,
    market_guard: MarketGuardDecision,
    permit: PromotionPermit,
    permit_secret: str | bytes,
    account_runtime_identity_sha256: str,
    now: datetime,
    template: RiskContext,
) -> VerifiedRiskContext:
    """Create all signed proofs and pass them through the real context factory."""

    root = Path(tempfile.mkdtemp(prefix="verified-risk-context-fixture-"))
    binding = RiskLedgerBinding(
        account_id_sha256=account_alias_sha256(broker_spec.account_id),
        server=broker_spec.server,
        environment=broker_spec.environment,
        journal_sha256=journal.journal_sha256,
        broker_spec_sha256=broker_spec.content_sha256,
        account_currency=broker_spec.account_currency,
    )
    ledger = TrustedRiskLedgerFixture(
        root / "risk.sqlite3",
        binding=binding,
        key_id=_RISK_KEY_ID,
        key_provider=_key,
        source_key_provider=lambda _key_id: SOURCE_KEY,
        trusted_source_issuer_keys={SOURCE_ISSUER: (SOURCE_KEY_ID,)},
        upstream_receipt_verifier=upstream_verifier,
        clock_provider=lambda: now,
    )
    base = now - timedelta(milliseconds=400)
    weekly_id = "fixture-week"
    old_daily_id = "fixture-day-prior"
    daily_id = "fixture-day-current"
    weekly_baseline_equity = template.equity - template.weekly_pnl_cash
    daily_baseline_equity = template.equity - template.daily_pnl_cash
    high_water_equity = max(
        template.high_water_equity,
        weekly_baseline_equity,
        daily_baseline_equity,
        template.equity,
    )
    ledger.append_account_snapshot(
        AccountRiskSnapshot(
            snapshot_id="fixture-weekly-baseline",
            binding=binding,
            observed_at_utc=base,
            daily_baseline_id=old_daily_id,
            weekly_baseline_id=weekly_id,
            equity=weekly_baseline_equity,
        )
    )
    if high_water_equity != weekly_baseline_equity:
        ledger.append_account_snapshot(
            AccountRiskSnapshot(
                snapshot_id="fixture-high-water",
                binding=binding,
                observed_at_utc=base + timedelta(milliseconds=25),
                daily_baseline_id=old_daily_id,
                weekly_baseline_id=weekly_id,
                equity=high_water_equity,
            )
        )
    ledger.append_account_snapshot(
        AccountRiskSnapshot(
            snapshot_id="fixture-daily-baseline",
            binding=binding,
            observed_at_utc=base + timedelta(milliseconds=50),
            daily_baseline_id=daily_id,
            weekly_baseline_id=weekly_id,
            equity=daily_baseline_equity,
        )
    )
    event_time = base + timedelta(milliseconds=75)
    entry_count = max(template.entries_today, template.consecutive_losses)
    for index in range(entry_count):
        entry_id = f"fixture-entry-{index}"
        ledger.append_entry(
            EntryRiskEvent(
                entry_id=entry_id,
                binding=binding,
                occurred_at_utc=event_time + timedelta(milliseconds=index * 2),
                daily_baseline_id=daily_id,
                weekly_baseline_id=weekly_id,
                symbol=broker_spec.symbol,
            )
        )
        if index >= entry_count - template.consecutive_losses:
            ledger.append_closed_trade(
                ClosedTradeRiskEvent(
                    trade_id=f"fixture-loss-{index}",
                    entry_id=entry_id,
                    binding=binding,
                    occurred_at_utc=(
                        event_time + timedelta(milliseconds=index * 2 + 1)
                    ),
                    daily_baseline_id=daily_id,
                    weekly_baseline_id=weekly_id,
                    symbol=broker_spec.symbol,
                    outcome="LOSS",
                    realized_pnl_account_currency=-0.01,
                )
            )
    risk_receipt = ledger.append_account_snapshot(
        AccountRiskSnapshot(
            snapshot_id="fixture-current",
            binding=binding,
            observed_at_utc=now - timedelta(milliseconds=100),
            daily_baseline_id=daily_id,
            weekly_baseline_id=weekly_id,
            equity=template.equity,
        )
    )

    collector = RuntimeFactCollector(
        adapter=_FactAdapter(
            spec=broker_spec,
            identity_sha256=account_runtime_identity_sha256,
            equity=template.equity,
            observed_at=health_facts.observed_at,
            spread_points=template.current_spread_points,
        ),
        journal=journal,
        key_id=_RUNTIME_KEY_ID,
        key_provider=_key,
        clock_provider=lambda: health_facts.observed_at,
        clock_drift_provider=lambda: health_facts.clock_drift_seconds,
        heartbeat_provider=lambda: health_facts.heartbeat_at,
        audit_export_status_provider=lambda: health_facts.audit_export_healthy,
        backup_status_provider=lambda: health_facts.backup_recent,
        disk_free_provider=lambda _path: max(
            health_facts.free_disk_bytes, MIN_FREE_DISK_BYTES + 1
        ),
    )
    runtime_receipt = collector.collect(
        symbol=broker_spec.symbol,
        broker_symbol=broker_spec.broker_symbol,
    )
    if runtime_receipt.health_facts != health_facts:
        raise ValueError("fixture health facts are not collector-coherent")

    positions = tuple(
        BrokerExposure(
            exposure_id=f"fixture-position-{index}",
            kind="POSITION",
            canonical_symbol=broker_spec.symbol,
            broker_symbol=broker_spec.broker_symbol,
            side="BUY",
            volume=broker_spec.volume_min,
        )
        for index in range(template.open_position_count)
    )
    reserved = set(template.reserved_symbols)
    if positions:
        reserved.add(broker_spec.symbol)
    exposure_receipt = ExposureReceipt(
        account_id=broker_spec.account_id,
        server=broker_spec.server,
        environment=broker_spec.environment,
        account_runtime_identity_sha256=account_runtime_identity_sha256,
        journal_sha256=journal.journal_sha256,
        active_orders=(),
        active_positions=positions,
        active_order_count=0,
        active_position_count=len(positions),
        reserved_canonical_symbols=tuple(reserved),
        reconciliation_clean=True,
        key_id=_EXPOSURE_KEY_ID,
        observed_at_utc=now,
        valid_until_utc=now + timedelta(seconds=1),
    ).sign(_EXPOSURE_KEY)
    calibration_receipt = RiskCalibrationReceipt(
        account_id=broker_spec.account_id,
        server=broker_spec.server,
        environment=broker_spec.environment,
        symbol=broker_spec.symbol,
        broker_symbol=broker_spec.broker_symbol,
        account_runtime_identity_sha256=account_runtime_identity_sha256,
        broker_spec_sha256=broker_spec.content_sha256,
        config_sha256=permit.config_sha256,
        data_window_sha256=_DATA_WINDOW_SHA256,
        data_window_start_utc=now - timedelta(days=20),
        data_window_end_utc=now - timedelta(minutes=1),
        session_count=20,
        sample_count=2_000,
        median_spread_points=max(template.median_spread_points, 1e-9),
        p95_spread_points=max(
            template.p95_spread_points,
            template.median_spread_points,
            1e-9,
        ),
        p95_slippage_points=template.p95_slippage_points,
        key_id=_CALIBRATION_KEY_ID,
        issued_at_utc=now,
        valid_until_utc=now + timedelta(hours=24),
    ).sign(_CALIBRATION_KEY)
    validation_kwargs = {}
    if permit.mode in {"DEMO_AUTO", "LIVE"}:
        validation_kwargs["expected_promotion_evidence_sha256"] = (
            permit.promotion_evidence_sha256
        )
    permit_validation = validate_permit(
        permit,
        permit_secret,
        now=now,
        expected_mode=permit.mode,
        expected_account_alias=broker_spec.account_id,
        expected_server=broker_spec.server,
        expected_symbols=permit.symbols,
        expected_commit_sha=permit.commit_sha,
        expected_config_sha256=permit.config_sha256,
        expected_model_artifact_sha256=permit.model_artifact_sha256,
        expected_journal_sha256=journal.journal_sha256,
        **validation_kwargs,
    )
    return create_verified_risk_context(
        risk_state_receipt=risk_receipt,
        runtime_fact_receipt=runtime_receipt,
        exposure_receipt=exposure_receipt,
        calibration_receipt=calibration_receipt,
        market_guard_decision=market_guard,
        permit_validation=permit_validation,
        usd_risk_cap_conversion=template.usd_risk_cap_conversion,
        expected_account_id=broker_spec.account_id,
        expected_server=broker_spec.server,
        expected_environment=broker_spec.environment,
        expected_symbol=broker_spec.symbol,
        expected_broker_symbol=broker_spec.broker_symbol,
        expected_mode=permit.mode,
        expected_permit_symbols=permit.symbols,
        expected_account_runtime_identity_sha256=(
            account_runtime_identity_sha256
        ),
        expected_broker_spec_sha256=broker_spec.content_sha256,
        expected_journal_sha256=journal.journal_sha256,
        expected_commit_sha=permit.commit_sha,
        expected_config_sha256=permit.config_sha256,
        expected_model_artifact_sha256=permit.model_artifact_sha256,
        expected_promotion_evidence_sha256=permit.promotion_evidence_sha256,
        expected_calibration_data_window_sha256=_DATA_WINDOW_SHA256,
        expected_runtime_fact_key_id=_RUNTIME_KEY_ID,
        expected_exposure_key_id=_EXPOSURE_KEY_ID,
        expected_calibration_key_id=_CALIBRATION_KEY_ID,
        risk_state_key_provider=_key,
        runtime_fact_key_provider=_key,
        exposure_key_provider=_key,
        calibration_key_provider=_key,
        clock_provider=lambda: now,
    )


__all__ = ["build_verified_risk_context"]
