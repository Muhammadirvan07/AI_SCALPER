"""Execution-trusted risk-source fixtures for integration tests."""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from datetime import timedelta
import hashlib
import hmac

from live_runtime.contracts import CanonicalContract, canonical_json
from live_runtime.risk_ledger import (
    DurableRiskLedger,
    verify_risk_source_receipt,
)


SOURCE_KEY_ID = "fixture-risk-source-key-v1"
SOURCE_KEY = b"fixture-risk-source-key-material-at-least-32-bytes"
SOURCE_ISSUER = "fixture-broker-evidence-issuer"
SOURCE_DOMAIN = b"AI_SCALPER_DURABLE_RISK_SOURCE_V1\x00"
_UPSTREAM_SEAL = object()


@dataclass(frozen=True)
class TestRiskUpstreamReceipt(CanonicalContract):
    receipt_type: str
    receipt_id: str
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _UPSTREAM_SEAL:
            raise TypeError("test risk upstream receipt is sealed")


def upstream_verifier(receipt_type: str, receipt: object) -> object:
    if type(receipt) is not TestRiskUpstreamReceipt:
        raise TypeError("risk upstream receipt type is not exact")
    if receipt.receipt_type != receipt_type:
        raise ValueError("risk upstream receipt kind does not match")
    return receipt


class TrustedRiskLedgerFixture(DurableRiskLedger):
    """Test-only issuer that still crosses the real signed source boundary."""

    def _provenance(self, event: CanonicalContract, source_kind: str):
        upstream_type = {
            "ACCOUNT_SNAPSHOT": "RUNTIME_FACT_RECEIPT",
            "ENTRY": "EXECUTION_RECEIPT",
            "CLOSED_TRADE": "BROKER_DEAL_RECEIPT",
        }[source_kind]
        upstream = TestRiskUpstreamReceipt(
            receipt_type=upstream_type,
            receipt_id=f"upstream-{source_kind.lower()}-{event.content_sha256[:20]}",
            _seal=_UPSTREAM_SEAL,
        )
        event_time = getattr(event, "observed_at_utc", None) or getattr(
            event, "occurred_at_utc"
        )
        unsigned = {
            "source_receipt_id": f"source-{event.content_sha256[:32]}",
            "source_kind": source_kind,
            "issuer_id": SOURCE_ISSUER,
            "key_id": SOURCE_KEY_ID,
            "binding": self.binding.to_canonical_dict(),
            "event_sha256": event.content_sha256,
            "upstream_receipt_type": upstream_type,
            "upstream_receipt_sha256": upstream.content_sha256,
            "observed_at_utc": event_time,
            "valid_until_utc": event_time + timedelta(seconds=5),
            "schema_version": "durable-risk-source-receipt-v1",
        }
        signature = hmac.new(
            SOURCE_KEY,
            SOURCE_DOMAIN + canonical_json(unsigned).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        source = verify_risk_source_receipt(
            {**unsigned, "signature_hmac_sha256": signature},
            expected_event=event,
            expected_binding=self.binding,
            key_provider=lambda _key_id: SOURCE_KEY,
            trusted_issuer_keys={SOURCE_ISSUER: (SOURCE_KEY_ID,)},
            clock_provider=self._clock_provider,
        )
        return source, upstream

    def append_account_snapshot(self, snapshot, **kwargs):
        if kwargs:
            return super().append_account_snapshot(snapshot, **kwargs)
        source, upstream = self._provenance(snapshot, "ACCOUNT_SNAPSHOT")
        return super().append_account_snapshot(
            snapshot,
            source_receipt=source,
            upstream_receipt=upstream,
        )

    def append_entry(self, event, **kwargs):
        if kwargs:
            return super().append_entry(event, **kwargs)
        source, upstream = self._provenance(event, "ENTRY")
        return super().append_entry(
            event,
            source_receipt=source,
            upstream_receipt=upstream,
        )

    def append_closed_trade(self, event, **kwargs):
        if kwargs:
            return super().append_closed_trade(event, **kwargs)
        source, upstream = self._provenance(event, "CLOSED_TRADE")
        return super().append_closed_trade(
            event,
            source_receipt=source,
            upstream_receipt=upstream,
        )
