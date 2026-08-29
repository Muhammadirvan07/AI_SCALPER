"""FINEX-only, read-only producer for one-second RuntimeFactReceipt values."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hmac
import math
from typing import Callable, Mapping

from .account_identity import account_identity_sha256
from .contracts import BrokerSpec, require_finite, require_hash, require_text, require_utc
from .finex_readiness_binding import (
    FinexReadinessBinding,
    verify_finex_readiness_binding,
)
from .finex_runtime_health_evidence import (
    FinexRuntimeHealthEvidence,
    verify_finex_runtime_health_evidence,
)
from .finex_runtime_health_trust_policy import FinexRuntimeHealthTrustPolicy
from .mt5_readonly import ReadOnlyMT5Facade, attest_mt5_read_only
from .runtime_fact_collector import (
    RuntimeFactCollector,
    RuntimeFactReceipt,
    verify_runtime_fact_receipt,
)


LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_TICK_AGE_SECONDS = 1.0


class FinexRuntimeFactError(RuntimeError):
    pass


def _mapping(value: object, field: str) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    method = getattr(value, "_asdict", None)
    if callable(method):
        mapped = method()
        if isinstance(mapped, Mapping):
            return dict(mapped)
    raise FinexRuntimeFactError(f"{field} is unavailable")


def _same_number(actual: object, expected: float, field: str) -> bool:
    try:
        observed = require_finite(field, actual, positive=True)
    except (TypeError, ValueError):
        return False
    return math.isclose(observed, expected, rel_tol=1e-12, abs_tol=1e-12)


class FinexReadOnlyRuntimeAdapter:
    """Capability-reduced adapter exposing only RuntimeFactCollector reads."""

    __slots__ = (
        "_facade",
        "_template",
        "_account_identity_key",
        "_expected_account_identity_sha256",
        "_clock_provider",
        "_observed_identity",
        "max_tick_age_seconds",
    )

    def __init__(
        self,
        *,
        facade: ReadOnlyMT5Facade,
        broker_spec_template: BrokerSpec,
        account_identity_key: bytes,
        expected_account_identity_sha256: str,
        clock_provider: Callable[[], datetime],
    ) -> None:
        if type(facade) is not ReadOnlyMT5Facade:
            raise TypeError("facade must be exact ReadOnlyMT5Facade")
        if type(broker_spec_template) is not BrokerSpec:
            raise TypeError("broker_spec_template must be exact BrokerSpec")
        if not isinstance(account_identity_key, bytes) or len(account_identity_key) < 32:
            raise FinexRuntimeFactError("account identity key must be 256-bit")
        if not callable(clock_provider):
            raise TypeError("clock_provider is required")
        self._facade = facade
        self._template = broker_spec_template
        self._account_identity_key = account_identity_key
        self._expected_account_identity_sha256 = require_hash(
            "expected_account_identity_sha256",
            expected_account_identity_sha256,
        )
        self._clock_provider = clock_provider
        self._observed_identity: str | None = None
        self.max_tick_age_seconds = MAX_TICK_AGE_SECONDS

    def assert_account_binding(self) -> dict[str, object]:
        attest_mt5_read_only(self._facade, require_account_expert_disabled=False)
        account = _mapping(self._facade.account_info(), "FINEX account")
        observed = account_identity_sha256(
            account,
            self._account_identity_key,
            environment="DEMO",
        )
        if not hmac.compare_digest(observed, self._expected_account_identity_sha256):
            raise FinexRuntimeFactError("FINEX account identity mismatch")
        if (
            account.get("server") != self._template.server
            or account.get("currency") != self._template.account_currency
            or account.get("trade_mode") != self._facade.ACCOUNT_TRADE_MODE_DEMO
            or account.get("trade_allowed") is not False
        ):
            raise FinexRuntimeFactError("FINEX account binding mismatch")
        captured_at = require_utc(
            "account captured_at", self._clock_provider()
        ).astimezone(timezone.utc)
        self._observed_identity = observed
        return {
            "account_alias": self._template.account_id,
            "server": self._template.server,
            "currency": account.get("currency"),
            "balance": account.get("balance"),
            "equity": account.get("equity"),
            "margin": account.get("margin"),
            "margin_free": account.get("margin_free"),
            "margin_level": account.get("margin_level"),
            "trade_allowed": account.get("trade_allowed"),
            "trade_expert": account.get("trade_expert"),
            "captured_at_utc": captured_at,
        }

    def execution_fence_identity(self) -> str:
        if self._observed_identity is None:
            raise FinexRuntimeFactError("account identity was not observed")
        return self._observed_identity

    def get_broker_spec(
        self,
        symbol: str,
        broker_symbol: str,
        *,
        now: datetime,
    ) -> BrokerSpec:
        canonical = require_text("symbol", symbol, upper=True)
        exact = require_text("broker_symbol", broker_symbol)
        if canonical != self._template.symbol or exact != self._template.broker_symbol:
            raise FinexRuntimeFactError("FINEX broker symbol binding mismatch")
        info = _mapping(self._facade.symbol_info(exact), "FINEX symbol info")
        integer_fields = {
            "digits": "digits",
            "stops_level_points": "trade_stops_level",
            "freeze_level_points": "trade_freeze_level",
        }
        number_fields = {
            "point": "point",
            "tick_size": "trade_tick_size",
            "tick_value": "trade_tick_value",
            "contract_size": "trade_contract_size",
            "volume_min": "volume_min",
            "volume_max": "volume_max",
            "volume_step": "volume_step",
        }
        if any(
            isinstance(info.get(observed), bool)
            or not isinstance(info.get(observed), int)
            or int(info[observed]) != int(getattr(self._template, contract))
            for contract, observed in integer_fields.items()
        ) or any(
            not _same_number(info.get(observed), getattr(self._template, contract), observed)
            for contract, observed in number_fields.items()
        ):
            raise FinexRuntimeFactError("FINEX terminal broker specification drift")
        captured = require_utc("broker spec captured_at", now).astimezone(timezone.utc)
        return replace(self._template, captured_at=captured)

    def current_tick(
        self,
        broker_symbol: str,
        *,
        now: datetime,
    ) -> dict[str, object]:
        exact = require_text("broker_symbol", broker_symbol)
        if exact != self._template.broker_symbol:
            raise FinexRuntimeFactError("FINEX tick symbol binding mismatch")
        info = _mapping(self._facade.symbol_info(exact), "FINEX symbol tick")
        bid = require_finite("bid", info.get("bid"), positive=True)
        ask = require_finite("ask", info.get("ask"), positive=True)
        if ask <= bid:
            raise FinexRuntimeFactError("FINEX tick spread is invalid")
        milliseconds = info.get("time_msc")
        seconds = info.get("time")
        if isinstance(milliseconds, int) and not isinstance(milliseconds, bool):
            timestamp = milliseconds / 1000.0
        elif isinstance(seconds, int) and not isinstance(seconds, bool):
            timestamp = float(seconds)
        else:
            raise FinexRuntimeFactError("FINEX tick timestamp is unavailable")
        tick_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        observed = require_utc("tick collection time", now).astimezone(timezone.utc)
        return {
            "bid": bid,
            "ask": ask,
            "time_utc": tick_time,
            "age_seconds": (observed - tick_time).total_seconds(),
        }


def collect_bound_finex_runtime_fact(
    *,
    binding: FinexReadinessBinding,
    expected_binding_issuer_id: str,
    expected_binding_key_id: str,
    readiness_key_provider: Callable[[str], str | bytes],
    health_policy: FinexRuntimeHealthTrustPolicy,
    health_evidence: FinexRuntimeHealthEvidence,
    health_public_key_text: str,
    facade: ReadOnlyMT5Facade,
    broker_spec_template: BrokerSpec,
    journal: object,
    account_identity_key: bytes,
    runtime_key_provider: Callable[[str], str | bytes],
    symbol: str,
    clock_provider: Callable[[], datetime],
) -> RuntimeFactReceipt:
    """Verify every trust root, collect reads, and mint one deny-only receipt."""

    if type(binding) is not FinexReadinessBinding:
        raise TypeError("binding must be exact FinexReadinessBinding")
    if type(health_policy) is not FinexRuntimeHealthTrustPolicy:
        raise TypeError("health_policy must be exact FinexRuntimeHealthTrustPolicy")
    if type(health_evidence) is not FinexRuntimeHealthEvidence:
        raise TypeError("health_evidence must be exact FinexRuntimeHealthEvidence")
    if type(broker_spec_template) is not BrokerSpec:
        raise TypeError("broker_spec_template must be exact BrokerSpec")
    if not callable(clock_provider):
        raise TypeError("clock_provider is required")
    started_at = require_utc("trusted clock", clock_provider()).astimezone(timezone.utc)
    verified_binding = verify_finex_readiness_binding(
        binding,
        expected_trust_policy_sha256=health_policy.content_sha256,
        expected_issuer_id=expected_binding_issuer_id,
        expected_key_id=expected_binding_key_id,
        key_provider=readiness_key_provider,
        now=started_at,
    )
    if verified_binding is not binding:
        raise FinexRuntimeFactError("readiness verifier changed binding identity")
    canonical_symbol = require_text("symbol", symbol, upper=True)
    expected_specs = dict(binding.broker_spec_sha256_by_symbol)
    source_keys = dict(binding.risk_source_key_id_by_symbol)
    if (
        canonical_symbol not in expected_specs
        or canonical_symbol not in source_keys
        or broker_spec_template.symbol != canonical_symbol
        or broker_spec_template.server != binding.server
        or broker_spec_template.environment != "DEMO"
        or broker_spec_template.account_id != binding.account_alias_sha256
        or broker_spec_template.account_currency != binding.account_currency
        or broker_spec_template.content_sha256 != expected_specs[canonical_symbol]
    ):
        raise FinexRuntimeFactError("broker specification readiness binding mismatch")
    projection = verify_finex_runtime_health_evidence(
        health_evidence,
        policy=health_policy,
        expected_policy_sha256=binding.trust_policy_sha256,
        public_key_text=health_public_key_text,
        now=started_at,
    )
    adapter = FinexReadOnlyRuntimeAdapter(
        facade=facade,
        broker_spec_template=broker_spec_template,
        account_identity_key=account_identity_key,
        expected_account_identity_sha256=binding.account_id_sha256,
        clock_provider=clock_provider,
    )
    runtime_key_id = source_keys[canonical_symbol]
    collector = RuntimeFactCollector(
        adapter=adapter,
        journal=journal,
        key_id=runtime_key_id,
        key_provider=runtime_key_provider,
        clock_provider=clock_provider,
        clock_drift_provider=lambda: projection.clock_drift_seconds,
        heartbeat_provider=lambda: projection.heartbeat_at_utc,
        audit_export_status_provider=lambda: projection.audit_export_healthy,
        backup_status_provider=lambda: projection.backup_recent,
        health_source_evidence_sha256=health_evidence.content_sha256,
        health_trust_policy_sha256=health_policy.content_sha256,
    )
    receipt = collector.collect(
        symbol=canonical_symbol,
        broker_symbol=broker_spec_template.broker_symbol,
    )
    checked_at = require_utc("trusted clock", clock_provider()).astimezone(timezone.utc)
    verified = verify_runtime_fact_receipt(
        receipt,
        expected_account_id=binding.account_alias_sha256,
        expected_server=binding.server,
        expected_environment="DEMO",
        expected_symbol=canonical_symbol,
        expected_broker_symbol=broker_spec_template.broker_symbol,
        expected_account_runtime_identity_sha256=binding.account_id_sha256,
        expected_broker_spec_sha256=expected_specs[canonical_symbol],
        expected_journal_sha256=journal.journal_sha256,
        expected_key_id=runtime_key_id,
        key_provider=runtime_key_provider,
        clock_provider=lambda: checked_at,
    )
    if (
        verified is not receipt
        or receipt.health_source_evidence_sha256 != health_evidence.content_sha256
        or receipt.health_trust_policy_sha256 != binding.trust_policy_sha256
        or receipt.health_decision.healthy is not True
        or receipt.live_allowed
        or receipt.safe_to_demo_auto_order
    ):
        raise FinexRuntimeFactError("FINEX runtime fact postcondition failed")
    return receipt


__all__ = [
    "FinexReadOnlyRuntimeAdapter",
    "FinexRuntimeFactError",
    "collect_bound_finex_runtime_fact",
]
