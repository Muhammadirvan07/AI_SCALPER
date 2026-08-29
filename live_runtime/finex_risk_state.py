"""FINEX account-risk snapshot ingestion from verified runtime facts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from .finex_readiness_binding import FinexReadinessBinding, REQUIRED_SYMBOLS
from .risk_ledger import (
    AccountRiskSnapshot,
    DurableRiskLedger,
    RiskLedgerBinding,
    RiskStateReceipt,
    RiskSourceReceipt,
    issue_risk_source_receipt,
)
from .runtime_fact_collector import RuntimeFactReceipt, verify_runtime_fact_receipt


UTC = timezone.utc


class FinexRiskStateError(RuntimeError):
    pass


@dataclass(frozen=True)
class FinexRiskStateEvidence:
    source_receipt: RiskSourceReceipt
    risk_receipt: RiskStateReceipt


def _risk_binding(binding: FinexReadinessBinding, symbol: str) -> RiskLedgerBinding:
    specs = dict(binding.broker_spec_sha256_by_symbol)
    return RiskLedgerBinding(
        account_id_sha256=binding.account_id_sha256,
        server=binding.server,
        environment="DEMO",
        journal_sha256=binding.journal_sha256,
        broker_spec_sha256=specs[symbol],
        account_currency=binding.account_currency,
    )


def produce_finex_account_risk_state(
    *,
    binding: FinexReadinessBinding,
    symbol: str,
    runtime_fact_receipt: RuntimeFactReceipt,
    ledger_path: str | Path,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
    expected_receipt: RiskStateReceipt | None = None,
) -> FinexRiskStateEvidence:
    """Consume one exact runtime fact and append one broker-derived snapshot."""

    if type(binding) is not FinexReadinessBinding:
        raise FinexRiskStateError("exact verified FINEX readiness binding is required")
    canonical_symbol = str(symbol or "").strip().upper()
    if canonical_symbol not in REQUIRED_SYMBOLS:
        raise FinexRiskStateError("FINEX risk symbol is unsupported")
    if type(runtime_fact_receipt) is not RuntimeFactReceipt:
        raise FinexRiskStateError("exact runtime fact receipt is required")
    if not callable(key_provider):
        raise FinexRiskStateError("risk key provider is required")
    if now.tzinfo is None:
        raise FinexRiskStateError("trusted risk clock must be timezone-aware")
    trusted_now = now.astimezone(UTC)
    specs = dict(binding.broker_spec_sha256_by_symbol)
    source_issuers = dict(binding.risk_source_issuer_id_by_symbol)
    source_keys = dict(binding.risk_source_key_id_by_symbol)
    ledger_keys = dict(binding.risk_key_id_by_symbol)
    if runtime_fact_receipt.health_trust_policy_sha256 != binding.trust_policy_sha256:
        raise FinexRiskStateError("runtime health trust policy binding mismatch")
    verified_fact = verify_runtime_fact_receipt(
        runtime_fact_receipt,
        expected_account_id=binding.account_alias_sha256,
        expected_server=binding.server,
        expected_environment="DEMO",
        expected_symbol=canonical_symbol,
        expected_broker_symbol=runtime_fact_receipt.broker_symbol,
        expected_account_runtime_identity_sha256=binding.account_id_sha256,
        expected_broker_spec_sha256=specs[canonical_symbol],
        expected_journal_sha256=binding.journal_sha256,
        expected_key_id=source_keys[canonical_symbol],
        key_provider=key_provider,
        clock_provider=lambda: trusted_now,
    )
    if verified_fact is not runtime_fact_receipt:
        raise FinexRiskStateError("runtime fact verifier changed object identity")
    if verified_fact.health_decision.healthy is not True:
        raise FinexRiskStateError("unhealthy runtime facts cannot update risk state")
    risk_binding = _risk_binding(binding, canonical_symbol)
    observed = verified_fact.observed_at_utc
    iso_week = observed.isocalendar()
    snapshot = AccountRiskSnapshot(
        snapshot_id=(
            f"finex-{canonical_symbol.lower()}-{verified_fact.content_sha256[:32]}"
        ),
        binding=risk_binding,
        observed_at_utc=observed,
        daily_baseline_id=f"day-{observed.date().isoformat()}",
        weekly_baseline_id=f"week-{iso_week.year}-W{iso_week.week:02d}",
        equity=verified_fact.account_fact.equity,
    )
    source = issue_risk_source_receipt(
        event=snapshot,
        binding=risk_binding,
        upstream_receipt_type="RUNTIME_FACT_RECEIPT",
        upstream_receipt=verified_fact,
        issuer_id=source_issuers[canonical_symbol],
        key_id=source_keys[canonical_symbol],
        key=key_provider(source_keys[canonical_symbol]),
        observed_at_utc=trusted_now,
        valid_until_utc=trusted_now + timedelta(seconds=5),
    )

    def verify_upstream(receipt_type: str, receipt: object) -> object:
        if receipt_type != "RUNTIME_FACT_RECEIPT" or receipt is not verified_fact:
            raise FinexRiskStateError("risk upstream receipt identity mismatch")
        return verify_runtime_fact_receipt(
            receipt,
            expected_account_id=binding.account_alias_sha256,
            expected_server=binding.server,
            expected_environment="DEMO",
            expected_symbol=canonical_symbol,
            expected_broker_symbol=verified_fact.broker_symbol,
            expected_account_runtime_identity_sha256=binding.account_id_sha256,
            expected_broker_spec_sha256=specs[canonical_symbol],
            expected_journal_sha256=binding.journal_sha256,
            expected_key_id=source_keys[canonical_symbol],
            key_provider=key_provider,
            clock_provider=lambda: trusted_now,
        )

    ledger = DurableRiskLedger(
        ledger_path,
        binding=risk_binding,
        key_id=ledger_keys[canonical_symbol],
        key_provider=key_provider,
        source_key_provider=key_provider,
        trusted_source_issuer_keys={
            source_issuers[canonical_symbol]: (source_keys[canonical_symbol],)
        },
        upstream_receipt_verifier=verify_upstream,
        clock_provider=lambda: trusted_now,
        expected_receipt=expected_receipt,
    )
    risk_receipt = ledger.append_account_snapshot(
        snapshot,
        source_receipt=source,
        upstream_receipt=verified_fact,
    )
    if (
        risk_receipt.key_id != ledger_keys[canonical_symbol]
        or risk_receipt.latest_source_issuer_id != source_issuers[canonical_symbol]
        or risk_receipt.latest_source_key_id != source_keys[canonical_symbol]
    ):
        raise FinexRiskStateError("risk receipt signer binding mismatch")
    return FinexRiskStateEvidence(source_receipt=source, risk_receipt=risk_receipt)


__all__ = [
    "FinexRiskStateError",
    "FinexRiskStateEvidence",
    "produce_finex_account_risk_state",
]
