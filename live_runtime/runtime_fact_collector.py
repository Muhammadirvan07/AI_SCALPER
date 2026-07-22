"""Production-oriented, deny-only runtime health fact collection.

The collector reads broker, journal, host, and off-host observations and mints
one short-lived HMAC receipt.  It never creates risk facts, permits, intents, or
order capabilities.  If a required observation cannot be obtained, collection
raises and no receipt exists for an executor to trust.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
import hashlib
import hmac
from pathlib import Path
import shutil
from typing import Any, Callable, Mapping

from .contracts import (
    BrokerSpec,
    CanonicalContract,
    canonical_json,
    canonical_sha256,
    require_finite,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from .health import (
    RuntimeHealthDecision,
    RuntimeHealthFacts,
    evaluate_runtime_health,
)


RUNTIME_FACT_RECEIPT_SCHEMA_VERSION = "runtime-fact-receipt-v1"
RUNTIME_TICK_FACT_SCHEMA_VERSION = "runtime-tick-fact-v1"
RUNTIME_FACT_RECEIPT_MAX_AGE_SECONDS = 1.0
RUNTIME_FACT_RECEIPT_MAX_AGE = timedelta(
    seconds=RUNTIME_FACT_RECEIPT_MAX_AGE_SECONDS
)
RUNTIME_FACT_HMAC_DOMAIN = b"AI_SCALPER_RUNTIME_FACT_RECEIPT_V1\x00"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False


class RuntimeFactCollectionError(RuntimeError):
    """A required runtime observation could not be collected safely."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = require_text("reason_code", reason_code, upper=True)
        super().__init__(self.reason_code)


class RuntimeFactVerificationError(RuntimeError):
    """A runtime fact receipt failed signature, freshness, or binding checks."""

    def __init__(self, reason_codes: tuple[str, ...] | list[str]) -> None:
        normalized = tuple(
            sorted(
                {
                    require_text("reason_code", reason, upper=True)
                    for reason in reason_codes
                }
            )
        )
        if not normalized:
            raise ValueError("verification failure requires at least one reason")
        self.reason_codes = normalized
        super().__init__(",".join(normalized))


def _require_bool(name: str, value: object) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{name} must be bool")
    return value


def _secret_bytes(secret: str | bytes) -> bytes:
    if isinstance(secret, str):
        normalized = secret.encode("utf-8")
    elif isinstance(secret, bytes):
        normalized = secret
    else:
        raise TypeError("runtime fact HMAC secret must be str or bytes")
    if len(normalized) < 32:
        raise ValueError("runtime fact HMAC secret must contain at least 32 bytes")
    return normalized


def _require_provider(name: str, provider: object) -> Callable[..., object]:
    if not callable(provider):
        raise TypeError(f"{name} must be callable; missing providers fail closed")
    return provider


def _call_required(reason_code: str, operation: Callable[[], Any]) -> Any:
    try:
        return operation()
    except RuntimeFactCollectionError:
        raise
    except Exception as exc:
        raise RuntimeFactCollectionError(reason_code) from exc


def _default_disk_free(path: Path) -> int:
    return int(shutil.disk_usage(path).free)


def _account_binding_sha256(
    *,
    account_id: str,
    server: str,
    environment: str,
    account_runtime_identity_sha256: str,
) -> str:
    return canonical_sha256(
        {
            "account_id": require_text("account_id", account_id),
            "server": require_text("server", server),
            "environment": require_text("environment", environment, upper=True),
            "account_runtime_identity_sha256": require_hash(
                "account_runtime_identity_sha256",
                account_runtime_identity_sha256,
            ),
        }
    )


@dataclass(frozen=True)
class RuntimeTickFact(CanonicalContract):
    """Exact broker tick returned by the bound adapter for one collection."""

    broker_symbol: str
    bid: float
    ask: float
    time_utc: datetime
    age_seconds: float
    collected_at_utc: datetime
    schema_version: str = RUNTIME_TICK_FACT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "broker_symbol",
            require_text("broker_symbol", self.broker_symbol),
        )
        object.__setattr__(
            self,
            "bid",
            require_finite("bid", self.bid, positive=True),
        )
        object.__setattr__(
            self,
            "ask",
            require_finite("ask", self.ask, positive=True),
        )
        if self.ask < self.bid:
            raise ValueError("tick ask cannot be below bid")
        require_utc("time_utc", self.time_utc)
        require_utc("collected_at_utc", self.collected_at_utc)
        object.__setattr__(
            self,
            "age_seconds",
            require_finite("age_seconds", self.age_seconds),
        )
        if self.age_seconds < -1.0:
            raise ValueError("tick is too far in the future")
        observed_age = (self.collected_at_utc - self.time_utc).total_seconds()
        if abs(observed_age - self.age_seconds) > 0.1:
            raise ValueError("tick age is inconsistent with collection time")
        object.__setattr__(
            self,
            "schema_version",
            require_text("schema_version", self.schema_version),
        )
        if self.schema_version != RUNTIME_TICK_FACT_SCHEMA_VERSION:
            raise ValueError("unsupported runtime tick fact schema")


@dataclass(frozen=True)
class RuntimeAccountFact(CanonicalContract):
    """Exact account values observed from the bound broker adapter."""

    account_id: str
    server: str
    currency: str
    balance: float
    equity: float
    margin: float
    margin_free: float
    margin_level: float
    trade_allowed: bool
    trade_expert: bool
    captured_at_utc: datetime

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "account_id",
            require_text("account_id", self.account_id),
        )
        object.__setattr__(self, "server", require_text("server", self.server))
        currency = require_text("currency", self.currency, upper=True)
        if len(currency) != 3 or not currency.isalpha():
            raise ValueError("account currency must be a three-letter code")
        object.__setattr__(self, "currency", currency)
        object.__setattr__(
            self,
            "balance",
            require_finite("balance", self.balance),
        )
        object.__setattr__(
            self,
            "equity",
            require_finite("equity", self.equity, positive=True),
        )
        object.__setattr__(
            self,
            "margin",
            require_finite("margin", self.margin, nonnegative=True),
        )
        object.__setattr__(
            self,
            "margin_free",
            require_finite("margin_free", self.margin_free),
        )
        object.__setattr__(
            self,
            "margin_level",
            require_finite("margin_level", self.margin_level, nonnegative=True),
        )
        _require_bool("trade_allowed", self.trade_allowed)
        _require_bool("trade_expert", self.trade_expert)
        require_utc("captured_at_utc", self.captured_at_utc)


@dataclass(frozen=True)
class RuntimeFactReceipt(CanonicalContract):
    """Signed immutable binding of all facts used by the health deny gate."""

    account_id: str
    server: str
    environment: str
    symbol: str
    broker_symbol: str
    account_runtime_identity_sha256: str
    account_binding_sha256: str
    account_fact: RuntimeAccountFact
    account_fact_sha256: str
    broker_spec: BrokerSpec
    broker_spec_sha256: str
    tick: RuntimeTickFact
    tick_sha256: str
    health_facts: RuntimeHealthFacts
    health_facts_sha256: str
    health_decision: RuntimeHealthDecision
    health_decision_sha256: str
    journal_sha256: str
    key_id: str
    observed_at_utc: datetime
    valid_until_utc: datetime
    signature: str = ""
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    schema_version: str = RUNTIME_FACT_RECEIPT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        account_id = require_text("account_id", self.account_id)
        server = require_text("server", self.server)
        environment = require_text("environment", self.environment, upper=True)
        symbol = require_text("symbol", self.symbol, upper=True)
        broker_symbol = require_text("broker_symbol", self.broker_symbol)
        if environment not in {"DEMO", "LIVE", "LIVE_READ_ONLY"}:
            raise ValueError("unsupported runtime fact environment")
        object.__setattr__(self, "account_id", account_id)
        object.__setattr__(self, "server", server)
        object.__setattr__(self, "environment", environment)
        object.__setattr__(self, "symbol", symbol)
        object.__setattr__(self, "broker_symbol", broker_symbol)
        for name in (
            "account_runtime_identity_sha256",
            "account_binding_sha256",
            "account_fact_sha256",
            "broker_spec_sha256",
            "tick_sha256",
            "health_facts_sha256",
            "health_decision_sha256",
            "journal_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(self, "key_id", require_text("key_id", self.key_id))
        require_utc("observed_at_utc", self.observed_at_utc)
        require_utc("valid_until_utc", self.valid_until_utc)
        lifetime = self.valid_until_utc - self.observed_at_utc
        if not timedelta(0) < lifetime <= RUNTIME_FACT_RECEIPT_MAX_AGE:
            raise ValueError("runtime fact receipt lifetime exceeds one second")
        if not isinstance(self.account_fact, RuntimeAccountFact):
            raise TypeError("account_fact must be RuntimeAccountFact")
        if not isinstance(self.broker_spec, BrokerSpec):
            raise TypeError("broker_spec must be BrokerSpec")
        if not isinstance(self.tick, RuntimeTickFact):
            raise TypeError("tick must be RuntimeTickFact")
        if not isinstance(self.health_facts, RuntimeHealthFacts):
            raise TypeError("health_facts must be RuntimeHealthFacts")
        if not isinstance(self.health_decision, RuntimeHealthDecision):
            raise TypeError("health_decision must be RuntimeHealthDecision")
        expected_decision = evaluate_runtime_health(self.health_facts)
        if expected_decision != self.health_decision:
            raise ValueError("health decision does not match runtime health facts")
        bindings = (
            self.broker_spec.account_id == account_id,
            self.broker_spec.server == server,
            self.broker_spec.environment == environment,
            self.broker_spec.symbol == symbol,
            self.broker_spec.broker_symbol == broker_symbol,
            self.account_fact.account_id == account_id,
            self.account_fact.server == server,
            self.account_fact.currency == self.broker_spec.account_currency,
            self.account_fact_sha256 == self.account_fact.content_sha256,
            self.tick.broker_symbol == broker_symbol,
            self.tick.collected_at_utc == self.observed_at_utc,
            self.health_facts.observed_at == self.observed_at_utc,
            self.health_decision.observed_at == self.observed_at_utc,
            timedelta(0)
            <= self.observed_at_utc - self.account_fact.captured_at_utc
            <= RUNTIME_FACT_RECEIPT_MAX_AGE,
            timedelta(0)
            <= self.observed_at_utc - self.broker_spec.captured_at
            <= RUNTIME_FACT_RECEIPT_MAX_AGE,
            self.account_binding_sha256
            == _account_binding_sha256(
                account_id=account_id,
                server=server,
                environment=environment,
                account_runtime_identity_sha256=(
                    self.account_runtime_identity_sha256
                ),
            ),
            self.broker_spec_sha256 == self.broker_spec.content_sha256,
            self.tick_sha256 == self.tick.content_sha256,
            self.health_facts_sha256 == self.health_facts.content_sha256,
            self.health_decision_sha256 == self.health_decision.content_sha256,
        )
        if not all(bindings):
            raise ValueError("runtime fact receipt binding mismatch")
        signature = str(self.signature or "").strip().lower()
        if signature:
            signature = require_hash("signature", signature)
        object.__setattr__(self, "signature", signature)
        _require_bool("live_allowed", self.live_allowed)
        _require_bool("safe_to_demo_auto_order", self.safe_to_demo_auto_order)
        if self.live_allowed or self.safe_to_demo_auto_order:
            raise ValueError("runtime fact receipts can only deny execution")
        object.__setattr__(
            self,
            "schema_version",
            require_text("schema_version", self.schema_version),
        )
        if self.schema_version != RUNTIME_FACT_RECEIPT_SCHEMA_VERSION:
            raise ValueError("unsupported runtime fact receipt schema")

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature")
        return payload

    @property
    def signing_payload(self) -> bytes:
        return canonical_json(self.signing_dict()).encode("utf-8")

    @property
    def receipt_id(self) -> str:
        digest = hashlib.sha256(self.signing_payload).hexdigest()
        return f"runtime_fact_{digest[:32]}"

    def verify_signature(self, secret: str | bytes) -> bool:
        if not self.signature:
            return False
        expected = hmac.new(
            _secret_bytes(secret),
            RUNTIME_FACT_HMAC_DOMAIN + self.signing_payload,
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(self.signature, expected)


class RuntimeFactCollector:
    """Collect exact observations and mint a one-second deny-only receipt."""

    def __init__(
        self,
        *,
        adapter: object,
        journal: object,
        key_id: str,
        key_provider: Callable[[str], str | bytes],
        clock_provider: Callable[[], datetime],
        clock_drift_provider: Callable[[], float],
        heartbeat_provider: Callable[[], datetime],
        audit_export_status_provider: Callable[[], bool],
        backup_status_provider: Callable[[], bool],
        disk_free_provider: Callable[[Path], int] | None = None,
    ) -> None:
        if adapter is None or journal is None:
            raise TypeError("adapter and journal are required")
        self.adapter = adapter
        self.journal = journal
        self.key_id = require_text("key_id", key_id)
        self.key_provider = _require_provider("key_provider", key_provider)
        self.clock_provider = _require_provider("clock_provider", clock_provider)
        self.clock_drift_provider = _require_provider(
            "clock_drift_provider",
            clock_drift_provider,
        )
        self.heartbeat_provider = _require_provider(
            "heartbeat_provider",
            heartbeat_provider,
        )
        self.audit_export_status_provider = _require_provider(
            "audit_export_status_provider",
            audit_export_status_provider,
        )
        self.backup_status_provider = _require_provider(
            "backup_status_provider",
            backup_status_provider,
        )
        self.disk_free_provider = (
            _default_disk_free
            if disk_free_provider is None
            else _require_provider("disk_free_provider", disk_free_provider)
        )

    def collect(self, *, symbol: str, broker_symbol: str) -> RuntimeFactReceipt:
        canonical_symbol = require_text("symbol", symbol, upper=True)
        exact_broker_symbol = require_text("broker_symbol", broker_symbol)
        started_at = _call_required(
            "TRUSTED_CLOCK_PROVIDER_UNAVAILABLE",
            lambda: require_utc("trusted clock", self.clock_provider()),
        )
        account = _call_required(
            "ADAPTER_ACCOUNT_BINDING_UNAVAILABLE",
            self.adapter.assert_account_binding,
        )
        if not isinstance(account, Mapping):
            raise RuntimeFactCollectionError("ADAPTER_ACCOUNT_BINDING_INVALID")
        spec = _call_required(
            "ADAPTER_BROKER_SPEC_UNAVAILABLE",
            lambda: self.adapter.get_broker_spec(
                canonical_symbol,
                exact_broker_symbol,
                now=started_at,
            ),
        )
        if not isinstance(spec, BrokerSpec):
            raise RuntimeFactCollectionError("ADAPTER_BROKER_SPEC_INVALID")
        tick_payload = _call_required(
            "ADAPTER_CURRENT_TICK_UNAVAILABLE",
            lambda: self.adapter.current_tick(
                exact_broker_symbol,
                now=started_at,
            ),
        )
        if not isinstance(tick_payload, Mapping):
            raise RuntimeFactCollectionError("ADAPTER_CURRENT_TICK_INVALID")
        identity = _call_required(
            "ADAPTER_ACCOUNT_IDENTITY_UNAVAILABLE",
            lambda: require_hash(
                "account runtime identity",
                self.adapter.execution_fence_identity(),
            ),
        )
        account_id = _call_required(
            "ADAPTER_ACCOUNT_BINDING_INVALID",
            lambda: require_text("account alias", account.get("account_alias")),
        )
        server = _call_required(
            "ADAPTER_ACCOUNT_BINDING_INVALID",
            lambda: require_text("account server", account.get("server")),
        )
        if (
            account_id != spec.account_id
            or server != spec.server
            or spec.symbol != canonical_symbol
            or spec.broker_symbol != exact_broker_symbol
        ):
            raise RuntimeFactCollectionError("ADAPTER_ACCOUNT_BINDING_MISMATCH")
        account_fact = _call_required(
            "ADAPTER_ACCOUNT_FACT_INVALID",
            lambda: RuntimeAccountFact(
                account_id=account_id,
                server=server,
                currency=account.get("currency"),
                balance=account.get("balance"),
                equity=account.get("equity"),
                margin=account.get("margin"),
                margin_free=account.get("margin_free"),
                margin_level=account.get("margin_level"),
                trade_allowed=account.get("trade_allowed"),
                trade_expert=account.get("trade_expert"),
                captured_at_utc=account.get("captured_at_utc"),
            ),
        )
        database_integrity_ok = _call_required(
            "JOURNAL_INTEGRITY_PROVIDER_UNAVAILABLE",
            lambda: _require_bool(
                "journal integrity",
                self.journal.integrity_check(),
            ),
        )
        kill_switch = _call_required(
            "KILL_SWITCH_PROVIDER_UNAVAILABLE",
            self.journal.kill_switch_status,
        )
        if not isinstance(kill_switch, Mapping) or "latched" not in kill_switch:
            raise RuntimeFactCollectionError("KILL_SWITCH_STATUS_INVALID")
        kill_switch_latched = _call_required(
            "KILL_SWITCH_STATUS_INVALID",
            lambda: _require_bool("kill switch latched", kill_switch["latched"]),
        )
        journal_sha256 = _call_required(
            "JOURNAL_IDENTITY_UNAVAILABLE",
            lambda: require_hash("journal_sha256", self.journal.journal_sha256),
        )
        journal_path = _call_required(
            "JOURNAL_PATH_UNAVAILABLE",
            lambda: Path(self.journal.path).resolve().parent,
        )
        free_disk_bytes = _call_required(
            "DISK_FREE_PROVIDER_UNAVAILABLE",
            lambda: require_int(
                "free_disk_bytes",
                self.disk_free_provider(journal_path),
                minimum=0,
            ),
        )
        clock_drift_seconds = _call_required(
            "CLOCK_DRIFT_PROVIDER_UNAVAILABLE",
            lambda: require_finite(
                "clock_drift_seconds",
                self.clock_drift_provider(),
                nonnegative=True,
            ),
        )
        heartbeat_at = _call_required(
            "OFF_HOST_HEARTBEAT_PROVIDER_UNAVAILABLE",
            lambda: require_utc("off-host heartbeat", self.heartbeat_provider()),
        )
        audit_export_healthy = _call_required(
            "AUDIT_EXPORT_PROVIDER_UNAVAILABLE",
            lambda: _require_bool(
                "audit_export_healthy",
                self.audit_export_status_provider(),
            ),
        )
        backup_recent = _call_required(
            "BACKUP_STATUS_PROVIDER_UNAVAILABLE",
            lambda: _require_bool(
                "backup_recent",
                self.backup_status_provider(),
            ),
        )
        observed_at = _call_required(
            "TRUSTED_CLOCK_PROVIDER_UNAVAILABLE",
            lambda: require_utc("trusted clock", self.clock_provider()),
        )
        collection_age = (observed_at - started_at).total_seconds()
        if collection_age < 0 or collection_age > RUNTIME_FACT_RECEIPT_MAX_AGE_SECONDS:
            raise RuntimeFactCollectionError("BROKER_FACT_COLLECTION_EXPIRED")
        tick_time = _call_required(
            "ADAPTER_CURRENT_TICK_INVALID",
            lambda: require_utc("tick time", tick_payload.get("time_utc")),
        )
        tick_age = (observed_at - tick_time).total_seconds()
        tick = _call_required(
            "ADAPTER_CURRENT_TICK_INVALID",
            lambda: RuntimeTickFact(
                broker_symbol=exact_broker_symbol,
                bid=tick_payload.get("bid"),
                ask=tick_payload.get("ask"),
                time_utc=tick_time,
                age_seconds=tick_age,
                collected_at_utc=observed_at,
            ),
        )
        maximum_tick_age = _call_required(
            "ADAPTER_TICK_AGE_POLICY_INVALID",
            lambda: require_finite(
                "max_tick_age_seconds",
                getattr(self.adapter, "max_tick_age_seconds", 1.0),
                positive=True,
            ),
        )
        broker_facts_fresh = (
            0 <= tick_age <= maximum_tick_age
            and timedelta(0)
            <= observed_at - account_fact.captured_at_utc
            <= RUNTIME_FACT_RECEIPT_MAX_AGE
            and timedelta(0)
            <= observed_at - spec.captured_at
            <= RUNTIME_FACT_RECEIPT_MAX_AGE
        )
        health_facts = _call_required(
            "RUNTIME_HEALTH_FACTS_INVALID",
            lambda: RuntimeHealthFacts(
                observed_at=observed_at,
                heartbeat_at=heartbeat_at,
                clock_drift_seconds=clock_drift_seconds,
                free_disk_bytes=free_disk_bytes,
                database_integrity_ok=database_integrity_ok,
                broker_connected=True,
                data_feed_fresh=broker_facts_fresh,
                audit_export_healthy=audit_export_healthy,
                backup_recent=backup_recent,
                kill_switch_latched=kill_switch_latched,
            ),
        )
        health_decision = evaluate_runtime_health(health_facts)
        account_binding_sha = _account_binding_sha256(
            account_id=account_id,
            server=server,
            environment=spec.environment,
            account_runtime_identity_sha256=identity,
        )
        unsigned = RuntimeFactReceipt(
            account_id=account_id,
            server=server,
            environment=spec.environment,
            symbol=canonical_symbol,
            broker_symbol=exact_broker_symbol,
            account_runtime_identity_sha256=identity,
            account_binding_sha256=account_binding_sha,
            account_fact=account_fact,
            account_fact_sha256=account_fact.content_sha256,
            broker_spec=spec,
            broker_spec_sha256=spec.content_sha256,
            tick=tick,
            tick_sha256=tick.content_sha256,
            health_facts=health_facts,
            health_facts_sha256=health_facts.content_sha256,
            health_decision=health_decision,
            health_decision_sha256=health_decision.content_sha256,
            journal_sha256=journal_sha256,
            key_id=self.key_id,
            observed_at_utc=observed_at,
            valid_until_utc=observed_at + RUNTIME_FACT_RECEIPT_MAX_AGE,
        )
        secret = _call_required(
            "SIGNING_KEY_UNAVAILABLE",
            lambda: _secret_bytes(self.key_provider(self.key_id)),
        )
        signature = hmac.new(
            secret,
            RUNTIME_FACT_HMAC_DOMAIN + unsigned.signing_payload,
            hashlib.sha256,
        ).hexdigest()
        return replace(unsigned, signature=signature)


def verify_runtime_fact_receipt(
    receipt: RuntimeFactReceipt,
    *,
    expected_account_id: str,
    expected_server: str,
    expected_environment: str,
    expected_symbol: str,
    expected_broker_symbol: str,
    expected_account_runtime_identity_sha256: str,
    expected_broker_spec_sha256: str,
    expected_journal_sha256: str,
    expected_key_id: str,
    key_provider: Callable[[str], str | bytes],
    clock_provider: Callable[[], datetime],
) -> RuntimeFactReceipt:
    """Return the receipt only when HMAC, freshness, and all bindings match."""

    if not isinstance(receipt, RuntimeFactReceipt):
        raise TypeError("receipt must be RuntimeFactReceipt")
    if not callable(key_provider):
        raise RuntimeFactVerificationError(["VERIFICATION_KEY_PROVIDER_INVALID"])
    if not callable(clock_provider):
        raise RuntimeFactVerificationError(["TRUSTED_CLOCK_PROVIDER_INVALID"])
    try:
        checked_at = require_utc("trusted verification clock", clock_provider())
    except Exception as exc:
        raise RuntimeFactVerificationError(
            ["TRUSTED_CLOCK_PROVIDER_UNAVAILABLE"]
        ) from exc

    account_id = require_text("expected_account_id", expected_account_id)
    server = require_text("expected_server", expected_server)
    environment = require_text(
        "expected_environment",
        expected_environment,
        upper=True,
    )
    symbol = require_text("expected_symbol", expected_symbol, upper=True)
    broker_symbol = require_text("expected_broker_symbol", expected_broker_symbol)
    identity = require_hash(
        "expected_account_runtime_identity_sha256",
        expected_account_runtime_identity_sha256,
    )
    broker_spec_sha = require_hash(
        "expected_broker_spec_sha256",
        expected_broker_spec_sha256,
    )
    journal_sha = require_hash(
        "expected_journal_sha256",
        expected_journal_sha256,
    )
    key_id = require_text("expected_key_id", expected_key_id)
    expected_account_binding_sha = _account_binding_sha256(
        account_id=account_id,
        server=server,
        environment=environment,
        account_runtime_identity_sha256=identity,
    )

    reasons: list[str] = []
    binding_checks = (
        (receipt.account_id == account_id, "ACCOUNT_BINDING_MISMATCH"),
        (receipt.server == server, "SERVER_BINDING_MISMATCH"),
        (receipt.environment == environment, "ENVIRONMENT_BINDING_MISMATCH"),
        (receipt.symbol == symbol, "SYMBOL_BINDING_MISMATCH"),
        (receipt.broker_symbol == broker_symbol, "BROKER_SYMBOL_BINDING_MISMATCH"),
        (
            receipt.account_runtime_identity_sha256 == identity,
            "ACCOUNT_RUNTIME_IDENTITY_MISMATCH",
        ),
        (
            receipt.account_binding_sha256 == expected_account_binding_sha,
            "ACCOUNT_BINDING_HASH_MISMATCH",
        ),
        (
            receipt.broker_spec_sha256 == broker_spec_sha,
            "BROKER_SPEC_BINDING_MISMATCH",
        ),
        (receipt.journal_sha256 == journal_sha, "JOURNAL_BINDING_MISMATCH"),
        (receipt.key_id == key_id, "KEY_ID_MISMATCH"),
    )
    for matched, reason in binding_checks:
        if not matched:
            reasons.append(reason)

    lifetime = receipt.valid_until_utc - receipt.observed_at_utc
    if not timedelta(0) < lifetime <= RUNTIME_FACT_RECEIPT_MAX_AGE:
        reasons.append("RUNTIME_FACT_RECEIPT_TTL_INVALID")
    if checked_at < receipt.observed_at_utc:
        reasons.append("RUNTIME_FACT_RECEIPT_NOT_YET_VALID")
    if checked_at >= receipt.valid_until_utc:
        reasons.append("RUNTIME_FACT_RECEIPT_STALE")
    if receipt.live_allowed or receipt.safe_to_demo_auto_order:
        reasons.append("RUNTIME_FACT_RECEIPT_UNLOCK_ATTEMPT")
    if receipt.schema_version != RUNTIME_FACT_RECEIPT_SCHEMA_VERSION:
        reasons.append("RUNTIME_FACT_RECEIPT_SCHEMA_MISMATCH")

    if receipt.broker_spec_sha256 != receipt.broker_spec.content_sha256:
        reasons.append("BROKER_SPEC_CONTENT_MISMATCH")
    if receipt.account_fact_sha256 != receipt.account_fact.content_sha256:
        reasons.append("ACCOUNT_FACT_CONTENT_MISMATCH")
    if receipt.tick_sha256 != receipt.tick.content_sha256:
        reasons.append("TICK_CONTENT_MISMATCH")
    if receipt.health_facts_sha256 != receipt.health_facts.content_sha256:
        reasons.append("HEALTH_FACTS_CONTENT_MISMATCH")
    if receipt.health_decision_sha256 != receipt.health_decision.content_sha256:
        reasons.append("HEALTH_DECISION_CONTENT_MISMATCH")
    expected_health_decision = evaluate_runtime_health(receipt.health_facts)
    if expected_health_decision != receipt.health_decision:
        reasons.append("HEALTH_DECISION_RECOMPUTE_MISMATCH")

    secret: bytes | None = None
    try:
        secret = _secret_bytes(key_provider(key_id))
    except Exception:
        reasons.append("VERIFICATION_KEY_UNAVAILABLE")
    if secret is not None and not receipt.verify_signature(secret):
        reasons.append("INVALID_SIGNATURE")
    if reasons:
        raise RuntimeFactVerificationError(reasons)
    return receipt


__all__ = [
    "LIVE_ALLOWED",
    "RUNTIME_FACT_RECEIPT_MAX_AGE_SECONDS",
    "RUNTIME_FACT_RECEIPT_SCHEMA_VERSION",
    "RuntimeFactCollectionError",
    "RuntimeFactCollector",
    "RuntimeFactReceipt",
    "RuntimeAccountFact",
    "RuntimeFactVerificationError",
    "RuntimeTickFact",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "verify_runtime_fact_receipt",
]
