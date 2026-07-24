"""Concrete fail-closed composition root for the Windows GATED bundle.

Importing, constructing, or statically validating this module never connects to
MetaTrader and never submits an order.  Filesystem materialization, credential
resolution, MT5 initialization, supervisor startup, and bounded execution are
separate explicit phases.  The checked-in release accepts only controlled
manual ``DEMO`` mode.  A complete ``DEMO_AUTO`` composition exists behind the
single reviewed execution-policy lock; live mode remains unsupported.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field
from datetime import datetime, timedelta
import hashlib
import hmac
from pathlib import Path
import sqlite3
import threading
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

import execution_policy
from execution_policy import LIVE_ALLOWED, SAFE_TO_DEMO_AUTO_ORDER

from .contracts import (
    CanonicalContract,
    canonical_json,
    canonical_sha256,
    require_currency,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from .controls import manual_demo_account_sha256
from .executor import ExecutionCoordinator
from .journal import ExecutionJournal
from .journal_integrity import (
    ExecutionJournalCheckpoint,
    ExecutionJournalCheckpointCASAcknowledgement,
    verify_execution_journal_checkpoint,
)
from .mt5_adapter import MT5Adapter
from .mt5_module_attestation import (
    MT5_DISTRIBUTION_VERSION,
    VerifiedMT5Installation,
    VerifiedMT5ModuleAttestation,
    verify_mt5_installed_environment,
)
from .dependency_lock import MT5_WHEEL_SHA256
from .risk_ledger import (
    RiskLedgerBinding,
    RiskSourceReceipt,
    RiskStateCheckpointCASAcknowledgement,
    RiskStateReceipt,
    verify_risk_state_receipt,
)
from .reconciliation import (
    BrokerClosedTradeReceipt,
    BrokerDealReceipt,
    BrokerReconciliationReceipt,
    ReconciliationResult,
)
from .runtime_service import LiveRuntimeService
from .runtime_supervisor import (
    RuntimeDemoAutoExecutionResult,
    RuntimeManualDemoExecutionResult,
    RuntimeNewsGuardReceipt,
    RuntimeStageAuthorizationPorts,
    RuntimeSupervisor,
    RuntimeSupervisorBinding,
    RuntimeSupervisorCheckpoint,
    RuntimeSupervisorCheckpointCASAcknowledgement,
    RuntimeSupervisorCycleReceipt,
    RuntimeSupervisorDecision,
    RuntimeReconciliationRiskResult,
    runtime_news_guard_trust_sha256,
    verify_runtime_news_guard_receipt,
    verify_runtime_supervisor_checkpoint_signature,
)
from .stage_authorization import StageBinding


BOOTSTRAP_SCHEMA_VERSION = "windows-production-bootstrap-v1"
EXTERNAL_RECEIPT_SCHEMA_VERSION = "windows-bootstrap-external-receipt-v1"
WORM_AUDIT_ROOT_SCHEMA_VERSION = "windows-bootstrap-worm-audit-root-v1"
EXTERNAL_RECEIPT_MAX_TTL = timedelta(minutes=1)
ORDER_CAPABILITY = "DISABLED"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False

_EXTERNAL_RECEIPT_DOMAIN = b"AI_SCALPER_WINDOWS_BOOTSTRAP_EXTERNAL_V1\x00"
_EXTERNAL_RECEIPT_SEAL = object()
_EXTERNAL_PURPOSES = frozenset(
    {"CREDENTIAL_SESSION", "JOURNAL_PROVISIONING", "WORM_AUDIT"}
)


class ProductionBootstrapError(RuntimeError):
    """A required binding, provider, receipt, or lifecycle gate failed closed."""


def _callable(name: str, value: object) -> Callable[..., Any]:
    if not callable(value):
        raise TypeError(f"{name} must be callable")
    return value


def _secret(value: object, *, label: str) -> bytes:
    if isinstance(value, str):
        result = value.encode("utf-8")
    elif isinstance(value, bytes):
        result = value
    else:
        raise ProductionBootstrapError(f"{label.upper()}_KEY_UNAVAILABLE")
    if len(result) < 32:
        raise ProductionBootstrapError(f"{label.upper()}_KEY_TOO_SHORT")
    return result


def _pairs(name: str, values: Sequence[tuple[str, str]]) -> tuple[tuple[str, str], ...]:
    normalized = tuple(
        sorted(
            (
                require_text(f"{name} canonical symbol", canonical, upper=True),
                require_text(f"{name} broker symbol", broker),
            )
            for canonical, broker in tuple(values)
        )
    )
    if not normalized or len({item[0] for item in normalized}) != len(normalized):
        raise ValueError(f"{name} requires unique canonical symbols")
    if len({item[1] for item in normalized}) != len(normalized):
        raise ValueError(f"{name} cannot alias broker symbols")
    return normalized


@dataclass(frozen=True)
class ProductionRuntimeConfig:
    """Immutable, non-secret production composition configuration."""

    journal_database: Path
    supervisor_database: Path
    dependency_lock_file: Path
    account_alias_sha256: str
    broker_legal_name: str
    server: str
    environment: str
    account_currency: str
    session_calendar_sha256: str
    symbol_map: tuple[tuple[str, str], ...]
    journal_sha256: str
    broker_spec_sha256: str
    commit_sha: str
    config_sha256: str
    stage_binding_sha256: str
    manual_demo_custodian_trust_sha256: str
    news_guard_provider_id: str
    news_guard_key_id: str
    news_guard_ruleset_sha256: str
    news_guard_blackout_window_sha256: str
    supervisor_key_id: str
    supervisor_checkpoint_key_id: str
    risk_ledger_id: str
    risk_ledger_key_id: str
    risk_ledger_key_fingerprint_sha256: str
    journal_checkpoint_key_id: str
    journal_checkpoint_key_fingerprint_sha256: str
    news_guard_key_fingerprint_sha256: str
    permit_secret_fingerprint_sha256: str
    dependency_lock_sha256: str
    installed_environment_sha256: str
    mt5_site_packages_sha256: str
    mt5_site_packages_tree_sha256: str
    mt5_distribution_record_sha256: str
    mt5_module_file_sha256: str
    mt5_module_relative_path_sha256: str
    supervisor_key_fingerprint_sha256: str = "4" * 64
    supervisor_checkpoint_key_fingerprint_sha256: str = "5" * 64
    credential_session_key_id: str = "credential-session-key-v1"
    credential_session_key_fingerprint_sha256: str = "1" * 64
    journal_provisioning_key_id: str = "journal-provisioning-key-v1"
    journal_provisioning_key_fingerprint_sha256: str = "3" * 64
    worm_audit_key_id: str = "worm-audit-key-v1"
    worm_audit_key_fingerprint_sha256: str = "2" * 64
    mt5_distribution_version: str = MT5_DISTRIBUTION_VERSION
    mt5_wheel_sha256: str = MT5_WHEEL_SHA256
    usd_account_currency_symbols: tuple[tuple[str, str], ...] = ()
    mode: str = "DEMO"
    magic_number: int = 260615
    deviation_points: int = 30
    max_tick_age_seconds: int = 10
    intent_ttl_seconds: float = 1.0
    expected_manual_approver_id: str | None = None
    expected_manual_approval_key_id: str | None = None
    manual_approval_key_fingerprint_sha256: str | None = None
    demo_auto_session_binding_sha256: str | None = None
    demo_auto_session_ledger_id: str | None = None
    demo_auto_session_custody_key_id: str | None = None
    demo_auto_session_custody_key_fingerprint_sha256: str | None = None
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    order_capability: str = ORDER_CAPABILITY
    schema_version: str = BOOTSTRAP_SCHEMA_VERSION

    def __post_init__(self) -> None:
        journal = Path(self.journal_database).expanduser().resolve(strict=False)
        supervisor = Path(self.supervisor_database).expanduser().resolve(strict=False)
        dependency_lock = Path(self.dependency_lock_file).expanduser().resolve(
            strict=False
        )
        if journal == supervisor:
            raise ValueError("journal and supervisor databases must be distinct")
        object.__setattr__(self, "journal_database", journal)
        object.__setattr__(self, "supervisor_database", supervisor)
        if dependency_lock.name != "pylock.windows-cp312.toml":
            raise ValueError("production dependency lock filename drift")
        object.__setattr__(self, "dependency_lock_file", dependency_lock)
        object.__setattr__(
            self,
            "broker_legal_name",
            require_text("broker_legal_name", self.broker_legal_name),
        )
        object.__setattr__(self, "server", require_text("server", self.server))
        environment = require_text("environment", self.environment, upper=True)
        mode = require_text("mode", self.mode, upper=True)
        if environment != "DEMO" or mode not in {"DEMO", "DEMO_AUTO"}:
            raise ValueError(
                "GATED v1 production bootstrap is restricted to DEMO stages"
            )
        if (
            mode == "DEMO_AUTO"
            and not execution_policy.demo_auto_execution_policy_enabled()
        ):
            raise ValueError("DEMO_AUTO_MODE_POLICY_LOCKED")
        object.__setattr__(self, "environment", environment)
        object.__setattr__(self, "mode", mode)
        object.__setattr__(
            self,
            "account_currency",
            require_currency("account_currency", self.account_currency),
        )
        for name in (
            "session_calendar_sha256",
            "account_alias_sha256",
            "journal_sha256",
            "broker_spec_sha256",
            "config_sha256",
            "stage_binding_sha256",
            "manual_demo_custodian_trust_sha256",
            "news_guard_ruleset_sha256",
            "news_guard_blackout_window_sha256",
            "credential_session_key_fingerprint_sha256",
            "journal_provisioning_key_fingerprint_sha256",
            "worm_audit_key_fingerprint_sha256",
            "supervisor_key_fingerprint_sha256",
            "supervisor_checkpoint_key_fingerprint_sha256",
            "risk_ledger_key_fingerprint_sha256",
            "journal_checkpoint_key_fingerprint_sha256",
            "news_guard_key_fingerprint_sha256",
            "permit_secret_fingerprint_sha256",
            "dependency_lock_sha256",
            "installed_environment_sha256",
            "mt5_site_packages_sha256",
            "mt5_site_packages_tree_sha256",
            "mt5_distribution_record_sha256",
            "mt5_module_file_sha256",
            "mt5_module_relative_path_sha256",
            "mt5_wheel_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "commit_sha",
            require_hash("commit_sha", self.commit_sha, minimum_length=7),
        )
        object.__setattr__(self, "symbol_map", _pairs("symbol_map", self.symbol_map))
        conversions = tuple(self.usd_account_currency_symbols)
        if conversions:
            conversions = _pairs("usd_account_currency_symbols", conversions)
        object.__setattr__(self, "usd_account_currency_symbols", conversions)
        for name in (
            "news_guard_provider_id",
            "news_guard_key_id",
            "supervisor_key_id",
            "supervisor_checkpoint_key_id",
            "credential_session_key_id",
            "journal_provisioning_key_id",
            "worm_audit_key_id",
            "risk_ledger_id",
            "risk_ledger_key_id",
            "journal_checkpoint_key_id",
        ):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        trust_key_ids = (
            self.credential_session_key_id,
            self.journal_provisioning_key_id,
            self.worm_audit_key_id,
            self.supervisor_key_id,
            self.supervisor_checkpoint_key_id,
            self.news_guard_key_id,
            self.risk_ledger_key_id,
            self.journal_checkpoint_key_id,
        )
        if len(set(trust_key_ids)) != len(trust_key_ids):
            raise ValueError("trust-domain key IDs must be distinct")
        trust_fingerprints = (
            self.credential_session_key_fingerprint_sha256,
            self.journal_provisioning_key_fingerprint_sha256,
            self.worm_audit_key_fingerprint_sha256,
            self.supervisor_key_fingerprint_sha256,
            self.supervisor_checkpoint_key_fingerprint_sha256,
            self.risk_ledger_key_fingerprint_sha256,
            self.journal_checkpoint_key_fingerprint_sha256,
            self.news_guard_key_fingerprint_sha256,
            self.permit_secret_fingerprint_sha256,
        )
        if len(set(trust_fingerprints)) != len(trust_fingerprints):
            raise ValueError("trust-domain key fingerprints must be distinct")
        require_int("magic_number", self.magic_number, minimum=1)
        require_int("deviation_points", self.deviation_points, minimum=0)
        require_int("max_tick_age_seconds", self.max_tick_age_seconds, minimum=1)
        if isinstance(self.intent_ttl_seconds, bool):
            raise TypeError("intent_ttl_seconds must be numeric")
        ttl = float(self.intent_ttl_seconds)
        if not 0 < ttl <= 1:
            raise ValueError("intent_ttl_seconds must be in (0, 1]")
        object.__setattr__(self, "intent_ttl_seconds", ttl)
        if self.expected_manual_approver_id is not None:
            object.__setattr__(
                self,
                "expected_manual_approver_id",
                require_text(
                    "expected_manual_approver_id", self.expected_manual_approver_id
                ),
            )
        if self.expected_manual_approval_key_id is not None:
            object.__setattr__(
                self,
                "expected_manual_approval_key_id",
                require_text(
                    "expected_manual_approval_key_id",
                    self.expected_manual_approval_key_id,
                ),
            )
        if self.manual_approval_key_fingerprint_sha256 is not None:
            object.__setattr__(
                self,
                "manual_approval_key_fingerprint_sha256",
                require_hash(
                    "manual_approval_key_fingerprint_sha256",
                    self.manual_approval_key_fingerprint_sha256,
                ),
            )
        manual_trust = (
            self.expected_manual_approver_id,
            self.expected_manual_approval_key_id,
            self.manual_approval_key_fingerprint_sha256,
        )
        if any(value is not None for value in manual_trust) and not all(
            value is not None for value in manual_trust
        ):
            raise ValueError("manual approval trust fields must be complete")
        if all(value is not None for value in manual_trust):
            if self.expected_manual_approval_key_id in trust_key_ids:
                raise ValueError("manual approval key ID must be trust-domain distinct")
            if self.manual_approval_key_fingerprint_sha256 in trust_fingerprints:
                raise ValueError(
                    "manual approval key fingerprint must be trust-domain distinct"
                )
        session_trust = (
            self.demo_auto_session_binding_sha256,
            self.demo_auto_session_ledger_id,
            self.demo_auto_session_custody_key_id,
            self.demo_auto_session_custody_key_fingerprint_sha256,
        )
        if self.mode == "DEMO_AUTO":
            if not all(value is not None for value in session_trust):
                raise ValueError(
                    "DEMO_AUTO session trust fields must be complete"
                )
            object.__setattr__(
                self,
                "demo_auto_session_binding_sha256",
                require_hash(
                    "demo_auto_session_binding_sha256",
                    self.demo_auto_session_binding_sha256,
                ),
            )
            object.__setattr__(
                self,
                "demo_auto_session_ledger_id",
                require_text(
                    "demo_auto_session_ledger_id",
                    self.demo_auto_session_ledger_id,
                ),
            )
            object.__setattr__(
                self,
                "demo_auto_session_custody_key_id",
                require_text(
                    "demo_auto_session_custody_key_id",
                    self.demo_auto_session_custody_key_id,
                ),
            )
            object.__setattr__(
                self,
                "demo_auto_session_custody_key_fingerprint_sha256",
                require_hash(
                    "demo_auto_session_custody_key_fingerprint_sha256",
                    self.demo_auto_session_custody_key_fingerprint_sha256,
                ),
            )
            if self.demo_auto_session_custody_key_id in trust_key_ids:
                raise ValueError(
                    "DEMO_AUTO session custody key ID must be trust-domain distinct"
                )
            if (
                self.demo_auto_session_custody_key_fingerprint_sha256
                in trust_fingerprints
            ):
                raise ValueError(
                    "DEMO_AUTO session custody fingerprint must be trust-domain distinct"
                )
        elif any(value is not None for value in session_trust):
            raise ValueError("DEMO config cannot carry DEMO_AUTO session trust")
        if type(self.live_allowed) is not bool or type(
            self.safe_to_demo_auto_order
        ) is not bool:
            raise TypeError("execution locks must be bool")
        if (
            self.live_allowed
            or self.safe_to_demo_auto_order
            or self.order_capability != ORDER_CAPABILITY
            or self.schema_version != BOOTSTRAP_SCHEMA_VERSION
        ):
            raise ValueError("production bootstrap cannot change execution locks")
        if self.mt5_distribution_version != MT5_DISTRIBUTION_VERSION:
            raise ValueError("production MT5 distribution version drift")
        if self.mt5_wheel_sha256 != MT5_WHEEL_SHA256:
            raise ValueError("production MT5 wheel SHA-256 drift")

    @property
    def safe_binding_sha256(self) -> str:
        return canonical_sha256(self.reviewed_configuration_payload)

    @property
    def reviewed_configuration_payload(self) -> dict[str, object]:
        """Complete non-secret behavior and trust payload bound by receipts."""

        return {
            "journal_database": str(self.journal_database),
            "supervisor_database": str(self.supervisor_database),
            "dependency_lock_file": str(self.dependency_lock_file),
            "account_alias_sha256": self.account_alias_sha256,
            "broker_legal_name": self.broker_legal_name,
            "server": self.server,
            "environment": self.environment,
            "account_currency": self.account_currency,
            "session_calendar_sha256": self.session_calendar_sha256,
            "symbol_map": self.symbol_map,
            "journal_sha256": self.journal_sha256,
            "broker_spec_sha256": self.broker_spec_sha256,
            "commit_sha": self.commit_sha,
            "config_sha256": self.config_sha256,
            "stage_binding_sha256": self.stage_binding_sha256,
            "manual_demo_custodian_trust_sha256": (
                self.manual_demo_custodian_trust_sha256
            ),
            "news_guard_provider_id": self.news_guard_provider_id,
            "news_guard_key_id": self.news_guard_key_id,
            "news_guard_ruleset_sha256": self.news_guard_ruleset_sha256,
            "news_guard_blackout_window_sha256": (
                self.news_guard_blackout_window_sha256
            ),
            "supervisor_key_id": self.supervisor_key_id,
            "supervisor_key_fingerprint_sha256": (
                self.supervisor_key_fingerprint_sha256
            ),
            "supervisor_checkpoint_key_id": self.supervisor_checkpoint_key_id,
            "supervisor_checkpoint_key_fingerprint_sha256": (
                self.supervisor_checkpoint_key_fingerprint_sha256
            ),
            "risk_ledger_id": self.risk_ledger_id,
            "risk_ledger_key_id": self.risk_ledger_key_id,
            "risk_ledger_key_fingerprint_sha256": (
                self.risk_ledger_key_fingerprint_sha256
            ),
            "journal_checkpoint_key_id": self.journal_checkpoint_key_id,
            "journal_checkpoint_key_fingerprint_sha256": (
                self.journal_checkpoint_key_fingerprint_sha256
            ),
            "news_guard_key_fingerprint_sha256": (
                self.news_guard_key_fingerprint_sha256
            ),
            "permit_secret_fingerprint_sha256": (
                self.permit_secret_fingerprint_sha256
            ),
            "dependency_lock_sha256": self.dependency_lock_sha256,
            "installed_environment_sha256": self.installed_environment_sha256,
            "mt5_site_packages_sha256": self.mt5_site_packages_sha256,
            "mt5_site_packages_tree_sha256": (
                self.mt5_site_packages_tree_sha256
            ),
            "mt5_distribution_record_sha256": (
                self.mt5_distribution_record_sha256
            ),
            "mt5_module_file_sha256": self.mt5_module_file_sha256,
            "mt5_module_relative_path_sha256": (
                self.mt5_module_relative_path_sha256
            ),
            "credential_session_key_id": self.credential_session_key_id,
            "credential_session_key_fingerprint_sha256": (
                self.credential_session_key_fingerprint_sha256
            ),
            "journal_provisioning_key_id": self.journal_provisioning_key_id,
            "journal_provisioning_key_fingerprint_sha256": (
                self.journal_provisioning_key_fingerprint_sha256
            ),
            "worm_audit_key_id": self.worm_audit_key_id,
            "worm_audit_key_fingerprint_sha256": (
                self.worm_audit_key_fingerprint_sha256
            ),
            "mt5_distribution_version": self.mt5_distribution_version,
            "mt5_wheel_sha256": self.mt5_wheel_sha256,
            "usd_account_currency_symbols": self.usd_account_currency_symbols,
            "mode": self.mode,
            "magic_number": self.magic_number,
            "deviation_points": self.deviation_points,
            "max_tick_age_seconds": self.max_tick_age_seconds,
            "intent_ttl_seconds": self.intent_ttl_seconds,
            "expected_manual_approver_id": self.expected_manual_approver_id,
            "expected_manual_approval_key_id": (
                self.expected_manual_approval_key_id
            ),
            "manual_approval_key_fingerprint_sha256": (
                self.manual_approval_key_fingerprint_sha256
            ),
            "demo_auto_session_binding_sha256": (
                self.demo_auto_session_binding_sha256
            ),
            "demo_auto_session_ledger_id": self.demo_auto_session_ledger_id,
            "demo_auto_session_custody_key_id": (
                self.demo_auto_session_custody_key_id
            ),
            "demo_auto_session_custody_key_fingerprint_sha256": (
                self.demo_auto_session_custody_key_fingerprint_sha256
            ),
            "live_allowed": self.live_allowed,
            "safe_to_demo_auto_order": self.safe_to_demo_auto_order,
            "order_capability": self.order_capability,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True)
class VerifiedBootstrapExternalReceipt(CanonicalContract):
    """Short-lived signed receipt for credential/session or WORM custody."""

    purpose: str
    binding_sha256: str
    evidence_sha256: str
    observed_at_utc: datetime
    valid_until_utc: datetime
    key_id: str
    signature_hmac_sha256: str
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    order_capability: str = ORDER_CAPABILITY
    schema_version: str = EXTERNAL_RECEIPT_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _EXTERNAL_RECEIPT_SEAL:
            raise TypeError("external receipt must be created by its verifier")
        purpose = require_text("purpose", self.purpose, upper=True)
        if purpose not in _EXTERNAL_PURPOSES:
            raise ValueError("unsupported bootstrap external receipt purpose")
        object.__setattr__(self, "purpose", purpose)
        for name in ("binding_sha256", "evidence_sha256", "signature_hmac_sha256"):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        observed = require_utc("observed_at_utc", self.observed_at_utc)
        valid_until = require_utc("valid_until_utc", self.valid_until_utc)
        if not timedelta(0) < valid_until - observed <= EXTERNAL_RECEIPT_MAX_TTL:
            raise ValueError("external receipt lifetime is invalid")
        object.__setattr__(self, "key_id", require_text("key_id", self.key_id))
        if (
            self.live_allowed
            or self.safe_to_demo_auto_order
            or self.order_capability != ORDER_CAPABILITY
            or self.schema_version != EXTERNAL_RECEIPT_SCHEMA_VERSION
        ):
            raise ValueError("external receipt cannot change execution locks")

    @property
    def signing_payload(self) -> bytes:
        values = self.to_canonical_dict()
        values.pop("signature_hmac_sha256")
        return canonical_json(values).encode("utf-8")

    def verify_signature(self, key: str | bytes) -> bool:
        expected = hmac.new(
            _secret(key, label=self.purpose),
            _EXTERNAL_RECEIPT_DOMAIN + self.signing_payload,
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, self.signature_hmac_sha256)


def verify_bootstrap_external_receipt(
    payload: Mapping[str, object],
    *,
    key_provider: Callable[[str], str | bytes],
) -> VerifiedBootstrapExternalReceipt:
    """Verify an externally signed claim and seal the exact immutable receipt."""

    if not isinstance(payload, Mapping):
        raise TypeError("external receipt payload must be a mapping")
    expected_fields = {
        "purpose",
        "binding_sha256",
        "evidence_sha256",
        "observed_at_utc",
        "valid_until_utc",
        "key_id",
        "signature_hmac_sha256",
        "live_allowed",
        "safe_to_demo_auto_order",
        "order_capability",
        "schema_version",
    }
    if set(payload) != expected_fields:
        raise ProductionBootstrapError("EXTERNAL_RECEIPT_FIELDS_INVALID")
    receipt = VerifiedBootstrapExternalReceipt(
        **dict(payload),  # type: ignore[arg-type]
        _seal=_EXTERNAL_RECEIPT_SEAL,
    )
    try:
        key = key_provider(receipt.key_id)
    except Exception as exc:
        raise ProductionBootstrapError("EXTERNAL_RECEIPT_KEY_UNAVAILABLE") from exc
    if not receipt.verify_signature(key):
        raise ProductionBootstrapError("EXTERNAL_RECEIPT_SIGNATURE_INVALID")
    return receipt


def worm_audit_evidence_sha256(
    *,
    bootstrap_binding_sha256: str,
    journal_checkpoint_sha256: str,
    external_journal_checkpoint_sha256: str,
    risk_state_receipt_sha256: str,
    risk_source_receipt_sha256: str,
    supervisor_checkpoint_sha256: str,
    news_guard_receipt_sha256: str,
    stage_binding_sha256: str,
    stage_authorization_sha256: str,
    stage_external_checkpoint_sha256: str,
    mt5_module_attestation_sha256: str,
) -> str:
    """Bind one WORM attestation to every verified mutable audit head."""

    values = {
        "bootstrap_binding_sha256": bootstrap_binding_sha256,
        "journal_checkpoint_sha256": journal_checkpoint_sha256,
        "external_journal_checkpoint_sha256": external_journal_checkpoint_sha256,
        "risk_state_receipt_sha256": risk_state_receipt_sha256,
        "risk_source_receipt_sha256": risk_source_receipt_sha256,
        "supervisor_checkpoint_sha256": supervisor_checkpoint_sha256,
        "news_guard_receipt_sha256": news_guard_receipt_sha256,
        "stage_binding_sha256": stage_binding_sha256,
        "stage_authorization_sha256": stage_authorization_sha256,
        "stage_external_checkpoint_sha256": stage_external_checkpoint_sha256,
        "mt5_module_attestation_sha256": mt5_module_attestation_sha256,
    }
    return canonical_sha256(
        {
            name: require_hash(name, value)
            for name, value in values.items()
        }
        | {"schema_version": WORM_AUDIT_ROOT_SCHEMA_VERSION}
    )


def require_worm_audit_root(
    receipt: VerifiedBootstrapExternalReceipt,
    *,
    expected_evidence_sha256: str,
) -> VerifiedBootstrapExternalReceipt:
    """Reject a signed WORM receipt that attests any older/different root set."""

    if type(receipt) is not VerifiedBootstrapExternalReceipt:
        raise ProductionBootstrapError("WORM_AUDIT_RECEIPT_NOT_SEALED")
    expected = require_hash(
        "expected WORM evidence", expected_evidence_sha256
    )
    if receipt.purpose != "WORM_AUDIT" or not hmac.compare_digest(
        receipt.evidence_sha256, expected
    ):
        raise ProductionBootstrapError("WORM_AUDIT_ROOT_MISMATCH")
    return receipt


def credential_session_evidence_sha256(
    *,
    account_alias: str,
    expected_login: int,
    server: str,
    environment: str,
    credential_reference_sha256: str,
) -> str:
    """Hash only non-secret identity metadata for the signed session claim."""

    return canonical_sha256(
        {
            "account_alias_sha256": manual_demo_account_sha256(
                require_text("account_alias", account_alias)
            ),
            "expected_login": require_int(
                "expected_login", expected_login, minimum=1
            ),
            "server": require_text("server", server),
            "environment": require_text("environment", environment, upper=True),
            "credential_reference_sha256": require_hash(
                "credential_reference_sha256", credential_reference_sha256
            ),
            "credential_source": "WINDOWS_CREDENTIAL_MANAGER",
        }
    )


@dataclass(frozen=True, repr=False)
class VerifiedCredentialSession:
    """Verifier-sealed, in-memory credential/session material.

    Raw alias, login, and password-bearing initialization kwargs never enter the
    immutable release configuration or a canonical/audit serialization.
    """

    account_alias: str = field(repr=False)
    expected_login: int = field(repr=False)
    server: str
    environment: str
    credential_reference_sha256: str
    initialize_kwargs: Mapping[str, object] = field(repr=False, compare=False)
    receipt: VerifiedBootstrapExternalReceipt = field(repr=False)
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _CREDENTIAL_SESSION_SEAL:
            raise TypeError("credential session must be created by its verifier")
        alias = require_text("account_alias", self.account_alias)
        login = require_int("expected_login", self.expected_login, minimum=1)
        server = require_text("server", self.server)
        environment = require_text("environment", self.environment, upper=True)
        if environment != "DEMO":
            raise ValueError("GATED credential session must be DEMO")
        reference = require_hash(
            "credential_reference_sha256", self.credential_reference_sha256
        )
        if type(self.receipt) is not VerifiedBootstrapExternalReceipt:
            raise TypeError("credential receipt must be verifier-sealed")
        if self.receipt.purpose != "CREDENTIAL_SESSION":
            raise ValueError("credential receipt purpose is invalid")
        if not isinstance(self.initialize_kwargs, Mapping):
            raise TypeError("initialize_kwargs must be a mapping")
        kwargs = dict(self.initialize_kwargs)
        allowed = {"login", "password", "server", "path", "timeout", "portable"}
        if set(kwargs) - allowed:
            raise ValueError("initialize_kwargs contains an unreviewed MT5 field")
        if kwargs.get("login") != login or kwargs.get("server") != server:
            raise ValueError("initialize_kwargs login/server binding mismatch")
        password = kwargs.get("password")
        if not isinstance(password, str) or not password:
            raise ValueError("Credential Manager session requires a password")
        if self.receipt.evidence_sha256 != credential_session_evidence_sha256(
            account_alias=alias,
            expected_login=login,
            server=server,
            environment=environment,
            credential_reference_sha256=reference,
        ):
            raise ValueError("credential receipt evidence binding mismatch")
        object.__setattr__(self, "account_alias", alias)
        object.__setattr__(self, "expected_login", login)
        object.__setattr__(self, "server", server)
        object.__setattr__(self, "environment", environment)
        object.__setattr__(self, "credential_reference_sha256", reference)
        object.__setattr__(self, "initialize_kwargs", MappingProxyType(kwargs))


_CREDENTIAL_SESSION_SEAL = object()


def verify_credential_session(
    *,
    account_alias: str,
    expected_login: int,
    server: str,
    environment: str,
    credential_reference_sha256: str,
    initialize_kwargs: Mapping[str, object],
    receipt_payload: Mapping[str, object],
    key_provider: Callable[[str], str | bytes],
) -> VerifiedCredentialSession:
    """Verify and seal one ephemeral Windows Credential Manager session."""

    receipt = verify_bootstrap_external_receipt(
        receipt_payload,
        key_provider=key_provider,
    )
    return VerifiedCredentialSession(
        account_alias=account_alias,
        expected_login=expected_login,
        server=server,
        environment=environment,
        credential_reference_sha256=credential_reference_sha256,
        initialize_kwargs=initialize_kwargs,
        receipt=receipt,
        _seal=_CREDENTIAL_SESSION_SEAL,
    )


@dataclass(frozen=True)
class ProductionRuntimePorts:
    """All external authorities are explicit; construction invokes none of them."""

    mt5_module: object
    credential_session_provider: Callable[[], VerifiedCredentialSession]
    external_receipt_key_provider: Callable[[str], str | bytes]
    journal_provisioning_provider: Callable[[], VerifiedBootstrapExternalReceipt]
    worm_audit_provider: Callable[[], VerifiedBootstrapExternalReceipt]
    risk_ledger: object
    risk_ledger_key_provider: Callable[[str], str | bytes]
    risk_source_provider: Callable[[], RiskSourceReceipt]
    risk_checkpoint_provider: Callable[[], RiskStateReceipt]
    risk_checkpoint_exporter: Callable[
        [str, RiskStateReceipt],
        RiskStateCheckpointCASAcknowledgement,
    ]
    journal_checkpoint_provider: Callable[[], ExecutionJournalCheckpoint]
    journal_checkpoint_key_provider: Callable[[str], str | bytes]
    external_journal_checkpoint_provider: Callable[
        [], ExecutionJournalCheckpoint | None
    ]
    journal_checkpoint_exporter: Callable[
        [str, ExecutionJournalCheckpoint],
        ExecutionJournalCheckpointCASAcknowledgement,
    ]
    supervisor_checkpoint_provider: Callable[[], RuntimeSupervisorCheckpoint | None]
    supervisor_checkpoint_exporter: Callable[
        [str, RuntimeSupervisorCheckpoint],
        RuntimeSupervisorCheckpointCASAcknowledgement,
    ]
    supervisor_key_provider: Callable[[str], str | bytes]
    supervisor_checkpoint_key_provider: Callable[[str], str | bytes]
    reconciliation_provider: Callable[[], RuntimeReconciliationRiskResult]
    broker_reconciliation_receipt_verifier: Callable[
        [BrokerReconciliationReceipt, ReconciliationResult],
        BrokerReconciliationReceipt,
    ]
    broker_deal_receipt_verifier: Callable[
        [BrokerDealReceipt, BrokerReconciliationReceipt], BrokerDealReceipt
    ]
    broker_closed_trade_receipt_verifier: Callable[
        [BrokerClosedTradeReceipt, BrokerReconciliationReceipt],
        BrokerClosedTradeReceipt,
    ]
    runtime_fact_provider: Callable[[], Sequence[object]]
    runtime_fact_verifier: Callable[[object], object]
    news_guard_provider: Callable[[], RuntimeNewsGuardReceipt]
    news_guard_key_provider: Callable[[str], str | bytes]
    decision_provider: Callable[[tuple[object, ...], RiskStateReceipt], RuntimeSupervisorDecision]
    stage_binding: StageBinding
    stage_authorization_ports_provider: Callable[[], RuntimeStageAuthorizationPorts]
    permit_secret_provider: Callable[[], str | bytes]
    manual_approval_provider: Callable[[RuntimeSupervisorDecision], object]
    manual_demo_policy_callback: Callable[[RuntimeSupervisorDecision, object], bool]
    execution_cycle_provider: Callable[
        [LiveRuntimeService, RuntimeSupervisorDecision, object],
        RuntimeManualDemoExecutionResult,
    ]
    clock_provider: Callable[[], datetime]
    promotion_evidence_key_provider: Callable[[str], str | bytes] | None = None
    manual_approval_key_provider: Callable[[str], str | bytes] | None = None
    demo_auto_ipc_input_provider: Callable[[RuntimeSupervisorDecision], object] | None = None
    demo_auto_session_lease_provider: Callable[
        [RuntimeSupervisorDecision, object], object
    ] | None = None
    demo_auto_session_store: object | None = None
    demo_auto_permit_validation_provider: Callable[
        [RuntimeSupervisorDecision, object], object
    ] | None = None
    demo_auto_promotion_validation_provider: Callable[
        [RuntimeSupervisorDecision, object], object
    ] | None = None
    demo_auto_environment_arm_provider: Callable[
        [RuntimeSupervisorDecision, object], object
    ] | None = None
    demo_auto_execution_cycle_provider: Callable[..., RuntimeDemoAutoExecutionResult] | None = None

    def __post_init__(self) -> None:
        if self.mt5_module is not None:
            raise TypeError(
                "production ports forbid MT5 module injection; mt5_module must be None"
            )
        for name in (
            "credential_session_provider",
            "external_receipt_key_provider",
            "journal_provisioning_provider",
            "worm_audit_provider",
            "risk_source_provider",
            "risk_checkpoint_provider",
            "risk_checkpoint_exporter",
            "risk_ledger_key_provider",
            "journal_checkpoint_provider",
            "journal_checkpoint_key_provider",
            "external_journal_checkpoint_provider",
            "journal_checkpoint_exporter",
            "supervisor_checkpoint_provider",
            "supervisor_checkpoint_exporter",
            "supervisor_key_provider",
            "supervisor_checkpoint_key_provider",
            "reconciliation_provider",
            "broker_reconciliation_receipt_verifier",
            "broker_deal_receipt_verifier",
            "broker_closed_trade_receipt_verifier",
            "runtime_fact_provider",
            "runtime_fact_verifier",
            "news_guard_provider",
            "news_guard_key_provider",
            "decision_provider",
            "stage_authorization_ports_provider",
            "permit_secret_provider",
            "manual_approval_provider",
            "manual_demo_policy_callback",
            "execution_cycle_provider",
            "clock_provider",
        ):
            _callable(name, getattr(self, name))
        for name in (
            "promotion_evidence_key_provider",
            "manual_approval_key_provider",
            "demo_auto_ipc_input_provider",
            "demo_auto_session_lease_provider",
            "demo_auto_permit_validation_provider",
            "demo_auto_promotion_validation_provider",
            "demo_auto_environment_arm_provider",
            "demo_auto_execution_cycle_provider",
        ):
            value = getattr(self, name)
            if value is not None:
                _callable(name, value)
        if self.demo_auto_session_store is not None:
            from .demo_auto_session_capability import (
                DemoAutoSessionCapabilityStore,
            )

            if type(self.demo_auto_session_store) is not DemoAutoSessionCapabilityStore:
                raise TypeError(
                    "demo_auto_session_store must be exact "
                    "DemoAutoSessionCapabilityStore or None"
                )
        if type(self.stage_binding) is not StageBinding:
            raise TypeError("stage_binding must be exact StageBinding")


@dataclass(frozen=True)
class ProductionBootstrapContractReport(CanonicalContract):
    contract_valid: bool
    binding_sha256: str
    blockers: tuple[str, ...]
    production_execution_ready: bool = False
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    order_capability: str = ORDER_CAPABILITY
    broker_mutation_performed: bool = False
    schema_version: str = BOOTSTRAP_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self.contract_valid) is not bool:
            raise TypeError("contract_valid must be bool")
        object.__setattr__(
            self, "binding_sha256", require_hash("binding_sha256", self.binding_sha256)
        )
        object.__setattr__(
            self,
            "blockers",
            tuple(sorted(require_text("blocker", item, upper=True) for item in self.blockers)),
        )
        if (
            self.production_execution_ready
            or self.live_allowed
            or self.safe_to_demo_auto_order
            or self.order_capability != ORDER_CAPABILITY
            or self.broker_mutation_performed
        ):
            raise ValueError("contract report cannot claim execution readiness")


def _validate_bindings(
    config: ProductionRuntimeConfig,
    ports: ProductionRuntimePorts,
) -> None:
    if type(config) is not ProductionRuntimeConfig:
        raise TypeError("config must be exact ProductionRuntimeConfig")
    if type(ports) is not ProductionRuntimePorts:
        raise TypeError("ports must be exact ProductionRuntimePorts")
    stage = ports.stage_binding
    if (
        stage.binding_sha256 != config.stage_binding_sha256
        or stage.account_alias_sha256 != config.account_alias_sha256
        or stage.server != config.server
        or stage.environment != config.environment
        or stage.journal_sha256 != config.journal_sha256
        or stage.commit_sha != config.commit_sha
        or stage.config_sha256 != config.config_sha256
        or stage.dependency_lock_sha256 != config.dependency_lock_sha256
        or stage.session_calendar_sha256 != config.session_calendar_sha256
        or stage.broker_spec_sha256 != config.broker_spec_sha256
        or stage.manual_demo_custodian_trust_sha256
        != config.manual_demo_custodian_trust_sha256
        or stage.symbol not in dict(config.symbol_map)
    ):
        raise ProductionBootstrapError("STAGE_BINDING_MISMATCH")
    risk_binding = getattr(ports.risk_ledger, "binding", None)
    if type(risk_binding) is not RiskLedgerBinding:
        raise ProductionBootstrapError("RISK_LEDGER_BINDING_MISSING")
    if (
        getattr(ports.risk_ledger, "ledger_id", None) != config.risk_ledger_id
        or getattr(ports.risk_ledger, "key_id", None) != config.risk_ledger_key_id
        or risk_binding.account_id_sha256 != config.account_alias_sha256
        or risk_binding.server != config.server
        or risk_binding.environment != config.environment
        or risk_binding.journal_sha256 != config.journal_sha256
        or risk_binding.broker_spec_sha256 != config.broker_spec_sha256
        or risk_binding.account_currency != config.account_currency
    ):
        raise ProductionBootstrapError("RISK_LEDGER_BINDING_MISMATCH")
    if config.mode == "DEMO_AUTO":
        from .demo_auto_session_capability import (
            DemoAutoSessionBinding,
            DemoAutoSessionCapabilityStore,
        )

        symbol_allowed, _symbol_reason = execution_policy.validate_execution_symbol(
            stage.symbol,
            mode=config.mode,
        )
        if not symbol_allowed:
            raise ProductionBootstrapError("DEMO_AUTO_SYMBOL_POLICY_DENIED")
        required = (
            "demo_auto_ipc_input_provider",
            "demo_auto_session_lease_provider",
            "demo_auto_permit_validation_provider",
            "demo_auto_promotion_validation_provider",
            "demo_auto_environment_arm_provider",
            "demo_auto_execution_cycle_provider",
        )
        missing = tuple(name for name in required if not callable(getattr(ports, name)))
        if type(ports.demo_auto_session_store) is not DemoAutoSessionCapabilityStore:
            missing += ("demo_auto_session_store",)
        if missing:
            raise ProductionBootstrapError(
                "DEMO_AUTO_RUNTIME_PORTS_MISSING:" + ",".join(missing)
            )
        store = ports.demo_auto_session_store
        session_binding = store.binding
        if type(session_binding) is not DemoAutoSessionBinding:
            raise ProductionBootstrapError(
                "DEMO_AUTO_SESSION_STORE_BINDING_NOT_SEALED"
            )
        if (
            session_binding.content_sha256
            != config.demo_auto_session_binding_sha256
            or session_binding.ledger_id != config.demo_auto_session_ledger_id
            or session_binding.custody_key_id
            != config.demo_auto_session_custody_key_id
            or session_binding.custody_key_fingerprint_sha256
            != config.demo_auto_session_custody_key_fingerprint_sha256
            or session_binding.stage_binding != stage
            or session_binding.supervisor_binding.account_id_sha256
            != config.account_alias_sha256
            or session_binding.supervisor_binding.server != config.server
            or session_binding.supervisor_binding.environment != config.environment
            or session_binding.supervisor_binding.journal_sha256
            != config.journal_sha256
            or session_binding.supervisor_binding.commit_sha != config.commit_sha
            or session_binding.supervisor_binding.config_sha256
            != config.config_sha256
        ):
            raise ProductionBootstrapError("DEMO_AUTO_SESSION_STORE_BINDING_MISMATCH")


def _verify_mt5_installation_against_config(
    config: ProductionRuntimeConfig,
    installation: object,
) -> VerifiedMT5Installation:
    if type(installation) is not VerifiedMT5Installation:
        raise ProductionBootstrapError("MT5_INSTALLATION_NOT_SEALED")
    if (
        installation.dependency_lock_sha256 != config.dependency_lock_sha256
        or installation.installed_environment_sha256
        != config.installed_environment_sha256
        or installation.site_packages_sha256 != config.mt5_site_packages_sha256
        or installation.site_packages_tree_sha256
        != config.mt5_site_packages_tree_sha256
        or installation.record_sha256 != config.mt5_distribution_record_sha256
        or installation.distribution_version != config.mt5_distribution_version
        or installation.wheel_sha256 != config.mt5_wheel_sha256
    ):
        raise ProductionBootstrapError("MT5_INSTALLATION_BINDING_MISMATCH")
    return installation


def _verify_mt5_module_against_config(
    config: ProductionRuntimeConfig,
    attestation: object,
) -> VerifiedMT5ModuleAttestation:
    if type(attestation) is not VerifiedMT5ModuleAttestation:
        raise ProductionBootstrapError("MT5_MODULE_ATTESTATION_NOT_SEALED")
    if (
        attestation.dependency_lock_sha256 != config.dependency_lock_sha256
        or attestation.installed_environment_sha256
        != config.installed_environment_sha256
        or attestation.site_packages_tree_sha256
        != config.mt5_site_packages_tree_sha256
        or attestation.record_sha256 != config.mt5_distribution_record_sha256
        or attestation.distribution_version != config.mt5_distribution_version
        or attestation.wheel_sha256 != config.mt5_wheel_sha256
        or attestation.module_file_sha256 != config.mt5_module_file_sha256
        or attestation.module_relative_path_sha256
        != config.mt5_module_relative_path_sha256
    ):
        raise ProductionBootstrapError("MT5_MODULE_ATTESTATION_BINDING_MISMATCH")
    return attestation


def validate_production_bootstrap_contract(
    config: ProductionRuntimeConfig,
    ports: ProductionRuntimePorts,
) -> ProductionBootstrapContractReport:
    """Pure static validation: no provider, filesystem, credential, or broker call."""

    _validate_bindings(config, ports)
    blockers = [
        "EXTERNAL_CREDENTIAL_SESSION_RECEIPT_REQUIRED",
        "EXTERNAL_DECISION_DATA_PROVIDER_REQUIRED",
        "EXTERNAL_JOURNAL_CHECKPOINT_REQUIRED",
        "EXTERNAL_JOURNAL_CHECKPOINT_CAS_EXPORTER_REQUIRED",
        "EXTERNAL_JOURNAL_PROVISIONING_RECEIPT_REQUIRED",
        "EXACT_INSTALLED_MT5_MODULE_ATTESTATION_REQUIRED",
        "EXTERNAL_PERMIT_SECRET_PROVIDER_REQUIRED",
        "EXTERNAL_PROMOTION_EVIDENCE_TRUST_REQUIRED",
        "EXTERNAL_RECONCILIATION_PROVIDER_REQUIRED",
        "EXTERNAL_RISK_SOURCE_AND_STATE_RECEIPTS_REQUIRED",
        "EXTERNAL_RISK_CHECKPOINT_CAS_EXPORTER_REQUIRED",
        "EXTERNAL_RUNTIME_FACT_PROVIDER_REQUIRED",
        "EXTERNAL_SIGNED_NEWS_RECEIPT_REQUIRED",
        "EXTERNAL_STAGE_AUTHORIZATION_REQUIRED",
        "EXTERNAL_SUPERVISOR_CHECKPOINT_REQUIRED",
        "EXTERNAL_TRUSTED_CLOCK_PROVIDER_REQUIRED",
        "EXTERNAL_WORM_AUDIT_RECEIPT_REQUIRED",
    ]
    if config.mode == "DEMO":
        blockers.extend(
            (
                "EXTERNAL_EXECUTION_CYCLE_PROVIDER_REQUIRED",
                "EXTERNAL_MANUAL_APPROVAL_PROVIDER_REQUIRED",
            )
        )
    else:
        blockers.extend(
            (
                "DEMO_AUTO_REVIEWED_POLICY_RELEASE_REQUIRED",
                "DEMO_AUTO_ONE_USE_IPC_REQUIRED",
                "DEMO_AUTO_CURRENT_SESSION_LEASE_REQUIRED",
                "DEMO_AUTO_FRESH_PERMIT_PROMOTION_ARM_REQUIRED",
            )
        )
    return ProductionBootstrapContractReport(
        contract_valid=True,
        binding_sha256=config.safe_binding_sha256,
        blockers=tuple(blockers),
    )


def _receipt_trust(
    config: ProductionRuntimeConfig,
    purpose: str,
) -> tuple[str, str]:
    if purpose == "CREDENTIAL_SESSION":
        return (
            config.credential_session_key_id,
            config.credential_session_key_fingerprint_sha256,
        )
    if purpose == "JOURNAL_PROVISIONING":
        return (
            config.journal_provisioning_key_id,
            config.journal_provisioning_key_fingerprint_sha256,
        )
    if purpose == "WORM_AUDIT":
        return config.worm_audit_key_id, config.worm_audit_key_fingerprint_sha256
    raise ProductionBootstrapError("EXTERNAL_RECEIPT_PURPOSE_INVALID")


def _verify_external_receipt_against_config(
    *,
    config: ProductionRuntimeConfig,
    ports: ProductionRuntimePorts,
    receipt: object,
    purpose: str,
    now: datetime,
) -> VerifiedBootstrapExternalReceipt:
    if type(receipt) is not VerifiedBootstrapExternalReceipt:
        raise ProductionBootstrapError(f"{purpose}_RECEIPT_NOT_SEALED")
    expected_key_id, expected_fingerprint = _receipt_trust(config, purpose)
    try:
        key = ports.external_receipt_key_provider(receipt.key_id)
    except Exception as exc:
        raise ProductionBootstrapError(f"{purpose}_KEY_UNAVAILABLE") from exc
    material = _secret(key, label=purpose)
    if (
        receipt.purpose != purpose
        or receipt.binding_sha256 != config.safe_binding_sha256
        or receipt.key_id != expected_key_id
        or hashlib.sha256(material).hexdigest() != expected_fingerprint
        or not receipt.verify_signature(material)
        or not receipt.observed_at_utc <= now < receipt.valid_until_utc
    ):
        raise ProductionBootstrapError(f"{purpose}_RECEIPT_INVALID")
    return receipt


def _verify_credential_against_config(
    *,
    config: ProductionRuntimeConfig,
    ports: ProductionRuntimePorts,
    session: object,
    now: datetime,
) -> VerifiedCredentialSession:
    if type(session) is not VerifiedCredentialSession:
        raise ProductionBootstrapError("CREDENTIAL_SESSION_NOT_SEALED")
    _verify_external_receipt_against_config(
        config=config,
        ports=ports,
        receipt=session.receipt,
        purpose="CREDENTIAL_SESSION",
        now=now,
    )
    if (
        manual_demo_account_sha256(session.account_alias)
        != config.account_alias_sha256
        or session.server != config.server
        or session.environment != config.environment
    ):
        raise ProductionBootstrapError("CREDENTIAL_SESSION_BINDING_MISMATCH")
    return session


def _require_risk_source_checkpoint_binding(
    source: RiskSourceReceipt,
    checkpoint: RiskStateReceipt,
) -> None:
    """Bind the external source envelope to the exact risk high-water head."""

    if type(source) is not RiskSourceReceipt:
        raise ProductionBootstrapError("RISK_SOURCE_RECEIPT_NOT_SEALED")
    if type(checkpoint) is not RiskStateReceipt:
        raise ProductionBootstrapError("RISK_CHECKPOINT_NOT_SEALED")
    expected_upstream = {
        "ACCOUNT_SNAPSHOT": {"RUNTIME_FACT_RECEIPT"},
        "ENTRY": {"EXECUTION_RECEIPT"},
        "CLOSED_TRADE": {
            "BROKER_CLOSED_TRADE_RECEIPT",
        },
    }
    if (
        source.content_sha256 != checkpoint.latest_source_receipt_sha256
        or source.issuer_id != checkpoint.latest_source_issuer_id
        or source.key_id != checkpoint.latest_source_key_id
        or source.upstream_receipt_type
        not in expected_upstream.get(source.source_kind, set())
    ):
        raise ProductionBootstrapError("RISK_SOURCE_CHECKPOINT_BINDING_MISMATCH")


def _preflight_preprovisioned_journal(path: Path, expected_sha256: str) -> None:
    """Read the external journal identity without allowing SQLite creation."""

    if not path.exists() or not path.is_file() or path.is_symlink():
        raise ProductionBootstrapError("EXECUTION_JOURNAL_PREPROVISION_REQUIRED")
    uri = f"{path.resolve().as_uri()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=1.0)
        try:
            row = connection.execute(
                "SELECT instance_id FROM journal_identity WHERE singleton=1"
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise ProductionBootstrapError(
            "EXECUTION_JOURNAL_PREPROVISION_REQUIRED"
        ) from exc
    if row is None:
        raise ProductionBootstrapError("EXECUTION_JOURNAL_PREPROVISION_REQUIRED")
    instance_id = str(row[0] or "").strip().lower()
    if (
        len(instance_id) != 32
        or any(character not in "0123456789abcdef" for character in instance_id)
    ):
        raise ProductionBootstrapError("EXECUTION_JOURNAL_IDENTITY_INVALID")
    observed = hashlib.sha256(
        (str(path.resolve()) + "\x00" + instance_id).encode("utf-8")
    ).hexdigest()
    if not hmac.compare_digest(observed, expected_sha256):
        raise ProductionBootstrapError("EXECUTION_JOURNAL_BINDING_MISMATCH")


def _verify_configured_key_fingerprint(
    *,
    provider: Callable[[str], str | bytes],
    key_id: str,
    expected_fingerprint_sha256: str,
    label: str,
) -> bytes:
    try:
        material = _secret(provider(key_id), label=label)
    except Exception as exc:
        if isinstance(exc, ProductionBootstrapError):
            raise
        raise ProductionBootstrapError(f"{label}_KEY_UNAVAILABLE") from exc
    if not hmac.compare_digest(
        hashlib.sha256(material).hexdigest(), expected_fingerprint_sha256
    ):
        raise ProductionBootstrapError(f"{label}_KEY_FINGERPRINT_MISMATCH")
    return material


def _pinned_key_provider(
    *,
    provider: Callable[[str], str | bytes],
    expected_key_id: str,
    expected_fingerprint_sha256: str,
    label: str,
) -> Callable[[str], bytes]:
    def pinned(requested_key_id: str) -> bytes:
        if requested_key_id != expected_key_id:
            raise ProductionBootstrapError(f"{label}_KEY_ID_MISMATCH")
        return _verify_configured_key_fingerprint(
            provider=provider,
            key_id=expected_key_id,
            expected_fingerprint_sha256=expected_fingerprint_sha256,
            label=label,
        )

    return pinned


def _verify_journal_checkpoint_against_config(
    *,
    config: ProductionRuntimeConfig,
    ports: ProductionRuntimePorts,
    journal: ExecutionJournal,
    checkpoint: ExecutionJournalCheckpoint,
    prior_checkpoint: ExecutionJournalCheckpoint | None,
) -> None:
    if (
        type(checkpoint) is not ExecutionJournalCheckpoint
        or type(prior_checkpoint) is not ExecutionJournalCheckpoint
        or checkpoint.key_id != config.journal_checkpoint_key_id
        or prior_checkpoint.key_id != config.journal_checkpoint_key_id
    ):
        raise ProductionBootstrapError("JOURNAL_CHECKPOINT_SIGNER_MISMATCH")
    key_provider = _pinned_key_provider(
        provider=ports.journal_checkpoint_key_provider,
        expected_key_id=config.journal_checkpoint_key_id,
        expected_fingerprint_sha256=(
            config.journal_checkpoint_key_fingerprint_sha256
        ),
        label="JOURNAL_CHECKPOINT",
    )
    verify_execution_journal_checkpoint(
        journal,
        checkpoint,
        expected_account_id_sha256=config.account_alias_sha256,
        expected_server=config.server,
        expected_environment=config.environment,
        expected_commit_sha=config.commit_sha,
        expected_config_sha256=config.config_sha256,
        key_provider=key_provider,
        now=require_utc("trusted bootstrap clock", ports.clock_provider()),
        prior_checkpoint=prior_checkpoint,
        execution_mode=config.mode,
    )


def _verify_news_against_config(
    *,
    config: ProductionRuntimeConfig,
    ports: ProductionRuntimePorts,
    receipt: RuntimeNewsGuardReceipt,
) -> RuntimeNewsGuardReceipt:
    if type(receipt) is not RuntimeNewsGuardReceipt:
        raise ProductionBootstrapError("SIGNED_NEWS_RECEIPT_NOT_SEALED")
    key_provider = _pinned_key_provider(
        provider=ports.news_guard_key_provider,
        expected_key_id=config.news_guard_key_id,
        expected_fingerprint_sha256=config.news_guard_key_fingerprint_sha256,
        label="NEWS_GUARD",
    )
    return verify_runtime_news_guard_receipt(
        receipt,
        expected_provider_id=config.news_guard_provider_id,
        expected_key_id=config.news_guard_key_id,
        expected_account_id_sha256=config.account_alias_sha256,
        expected_server=config.server,
        expected_environment=config.environment,
        expected_config_sha256=config.config_sha256,
        key_provider=key_provider,
        now=require_utc("trusted bootstrap clock", ports.clock_provider()),
    )


class ProductionRuntimeComposition:
    """Materialized exact components with explicit initialization/run phases."""

    def __init__(
        self,
        *,
        config: ProductionRuntimeConfig,
        ports: ProductionRuntimePorts,
        journal: ExecutionJournal,
        adapter: MT5Adapter,
        coordinator: ExecutionCoordinator,
        runtime_service: LiveRuntimeService,
        supervisor: RuntimeSupervisor,
    ) -> None:
        exact = (
            type(journal) is ExecutionJournal,
            type(adapter) is MT5Adapter,
            type(coordinator) is ExecutionCoordinator,
            type(runtime_service) is LiveRuntimeService,
            type(supervisor) is RuntimeSupervisor,
        )
        if not all(exact):
            raise TypeError("production composition components must be exact reviewed types")
        self.config = config
        self.ports = ports
        self.journal = journal
        self.adapter = adapter
        self.coordinator = coordinator
        self.runtime_service = runtime_service
        self.supervisor = supervisor
        self._initialized = False
        self._started = False
        self._abort_initiated = False
        self._lifecycle_lock = threading.Lock()

    def _trusted_now(self) -> datetime:
        try:
            return require_utc("trusted bootstrap clock", self.ports.clock_provider())
        except Exception as exc:
            raise ProductionBootstrapError("TRUSTED_CLOCK_PROVIDER_FAILED") from exc

    def _external_receipt(
        self,
        purpose: str,
        provider: Callable[[], VerifiedBootstrapExternalReceipt],
    ) -> VerifiedBootstrapExternalReceipt:
        return _verify_external_receipt_against_config(
            config=self.config,
            ports=self.ports,
            receipt=provider(),
            purpose=purpose,
            now=self._trusted_now(),
        )

    def _credential_session(self) -> VerifiedCredentialSession:
        return _verify_credential_against_config(
            config=self.config,
            ports=self.ports,
            session=self.ports.credential_session_provider(),
            now=self._trusted_now(),
        )

    def verify_external_evidence(self) -> VerifiedCredentialSession:
        """Resolve every external proof without initializing the broker session."""

        try:
            mt5_attestation = _verify_mt5_module_against_config(
                self.config,
                self.adapter.verify_module_attestation(),
            )
        except ProductionBootstrapError:
            raise
        except Exception as exc:
            raise ProductionBootstrapError(
                "MT5_MODULE_ATTESTATION_VERIFICATION_FAILED"
            ) from exc
        credential = self._credential_session()
        provisioning = self._external_receipt(
            "JOURNAL_PROVISIONING",
            self.ports.journal_provisioning_provider,
        )
        if provisioning.evidence_sha256 != self.journal.journal_sha256:
            raise ProductionBootstrapError("JOURNAL_PROVISIONING_BINDING_MISMATCH")
        source = self.ports.risk_source_provider()
        if type(source) is not RiskSourceReceipt:
            raise ProductionBootstrapError("RISK_SOURCE_RECEIPT_NOT_SEALED")
        if source.binding != self.ports.risk_ledger.binding:
            raise ProductionBootstrapError("RISK_SOURCE_BINDING_MISMATCH")
        now = self._trusted_now()
        if not source.observed_at_utc <= now <= source.valid_until_utc:
            raise ProductionBootstrapError("RISK_SOURCE_RECEIPT_STALE")
        risk = self.ports.risk_checkpoint_provider()
        if type(risk) is not RiskStateReceipt:
            raise ProductionBootstrapError("RISK_CHECKPOINT_NOT_SEALED")
        risk_key_provider = _pinned_key_provider(
            provider=self.ports.risk_ledger_key_provider,
            expected_key_id=self.config.risk_ledger_key_id,
            expected_fingerprint_sha256=(
                self.config.risk_ledger_key_fingerprint_sha256
            ),
            label="RISK_LEDGER",
        )
        if (
            risk.ledger_id != self.config.risk_ledger_id
            or risk.key_id != self.config.risk_ledger_key_id
            or not verify_risk_state_receipt(
                risk, risk_key_provider
            )
            or self.ports.risk_ledger.verify_integrity(expected_receipt=risk)
            is not True
        ):
            raise ProductionBootstrapError("RISK_CHECKPOINT_VERIFICATION_FAILED")
        _require_risk_source_checkpoint_binding(source, risk)
        journal_checkpoint = self.ports.journal_checkpoint_provider()
        external_journal = self.ports.external_journal_checkpoint_provider()
        if (
            type(journal_checkpoint) is not ExecutionJournalCheckpoint
            or type(external_journal) is not ExecutionJournalCheckpoint
        ):
            raise ProductionBootstrapError("JOURNAL_CHECKPOINT_NOT_SEALED")
        _verify_journal_checkpoint_against_config(
            config=self.config,
            ports=self.ports,
            journal=self.journal,
            checkpoint=journal_checkpoint,
            prior_checkpoint=external_journal,
        )
        supervisor_checkpoint = self.ports.supervisor_checkpoint_provider()
        if type(supervisor_checkpoint) is not RuntimeSupervisorCheckpoint:
            raise ProductionBootstrapError("SUPERVISOR_CHECKPOINT_NOT_SEALED")
        checkpoint_key_provider = _pinned_key_provider(
            provider=self.ports.supervisor_checkpoint_key_provider,
            expected_key_id=self.config.supervisor_checkpoint_key_id,
            expected_fingerprint_sha256=(
                self.config.supervisor_checkpoint_key_fingerprint_sha256
            ),
            label="SUPERVISOR_CHECKPOINT",
        )
        checked_supervisor = verify_runtime_supervisor_checkpoint_signature(
            supervisor_checkpoint,
            expected_key_id=self.config.supervisor_checkpoint_key_id,
            key_provider=checkpoint_key_provider,
        )
        if (
            checked_supervisor is not supervisor_checkpoint
            or supervisor_checkpoint.binding_sha256
            != self.supervisor.binding.content_sha256
            or supervisor_checkpoint.issued_at_utc > now
        ):
            raise ProductionBootstrapError("SUPERVISOR_CHECKPOINT_BINDING_MISMATCH")
        news = _verify_news_against_config(
            config=self.config,
            ports=self.ports,
            receipt=self.ports.news_guard_provider(),
        )
        stage = self.ports.stage_authorization_ports_provider()
        if type(stage) is not RuntimeStageAuthorizationPorts:
            raise ProductionBootstrapError("STAGE_AUTHORIZATION_PORTS_NOT_SEALED")
        if (
            stage.expected_binding != self.ports.stage_binding
            or stage.authorization.request.binding != self.ports.stage_binding
        ):
            raise ProductionBootstrapError("STAGE_AUTHORIZATION_BINDING_MISMATCH")
        published_risk = self.ports.risk_checkpoint_provider()
        if (
            type(published_risk) is not RiskStateReceipt
            or published_risk.content_sha256 != risk.content_sha256
        ):
            raise ProductionBootstrapError(
                "RISK_CHECKPOINT_CHANGED_DURING_ATTESTATION"
            )
        worm_root = worm_audit_evidence_sha256(
            bootstrap_binding_sha256=self.config.safe_binding_sha256,
            journal_checkpoint_sha256=journal_checkpoint.content_sha256,
            external_journal_checkpoint_sha256=external_journal.content_sha256,
            # ``risk`` is the exact externally custodied high-water receipt;
            # bind its complete canonical contract, not only its inner HMAC.
            risk_state_receipt_sha256=published_risk.content_sha256,
            risk_source_receipt_sha256=source.content_sha256,
            supervisor_checkpoint_sha256=supervisor_checkpoint.content_sha256,
            news_guard_receipt_sha256=news.content_sha256,
            stage_binding_sha256=stage.expected_binding.binding_sha256,
            stage_authorization_sha256=stage.authorization.content_sha256,
            stage_external_checkpoint_sha256=(
                stage.external_replay_checkpoint.content_sha256
            ),
            mt5_module_attestation_sha256=mt5_attestation.content_sha256,
        )
        require_worm_audit_root(
            self._external_receipt("WORM_AUDIT", self.ports.worm_audit_provider),
            expected_evidence_sha256=worm_root,
        )
        return credential

    def initialize(self) -> None:
        if self._initialized:
            raise ProductionBootstrapError("COMPOSITION_ALREADY_INITIALIZED")
        try:
            mt5_attestation = self.adapter.load_and_attest_module()
            _verify_mt5_module_against_config(self.config, mt5_attestation)
            credential = self.verify_external_evidence()
            self.adapter.initialize(**dict(credential.initialize_kwargs))
            self.verify_external_evidence()
        except Exception:
            self.adapter.shutdown()
            raise
        self._initialized = True

    def start(self, *, owner_id: str, lease_seconds: int = 30):
        if not self._initialized:
            raise ProductionBootstrapError("COMPOSITION_NOT_INITIALIZED")
        self.verify_external_evidence()
        receipt = self.supervisor.start(owner_id=owner_id, lease_seconds=lease_seconds)
        with self._lifecycle_lock:
            self._started = True
            self._abort_initiated = False
        return receipt

    def abort_fail_closed(
        self,
        reason_code: str,
        *,
        cause: Exception | None = None,
    ) -> bool:
        """Own the composition's one critical-abort transition.

        ``RuntimeSupervisor`` operations can already have latched themselves
        before raising.  The composition therefore inspects the exact local
        supervisor state while holding its lifecycle lock, clears ``_started``
        before invoking any further abort, and never calls ``fail_closed`` a
        second time.  Returning ``False`` means the supervisor already owned
        the critical transition (or another caller won the abort race).
        """

        if not hasattr(self, "_lifecycle_lock"):
            self._lifecycle_lock = threading.Lock()
        if not hasattr(self, "_abort_initiated"):
            self._abort_initiated = False
        with self._lifecycle_lock:
            if self._abort_initiated or not self._started:
                self._started = False
                return False
            self._abort_initiated = True
            self._started = False
            if getattr(self.supervisor, "is_stopped_critical", False) is True:
                return False
        # ``fail_closed`` deliberately raises.  The lifecycle flags were
        # committed first so ``shutdown`` cannot issue a later clean stop.
        self.supervisor.fail_closed(reason_code, cause=cause)
        raise AssertionError("unreachable")

    def run_cycle(self):
        """Run one externally attested cycle without stopping the supervisor."""

        if not self._initialized or not self._started:
            raise ProductionBootstrapError("COMPOSITION_NOT_STARTED")
        try:
            self.verify_external_evidence()
            receipt = self.supervisor.run_cycle()
            self.verify_external_evidence()
            return receipt
        except Exception as exc:
            try:
                self.abort_fail_closed(
                    "PRODUCTION_BOOTSTRAP_EXTERNAL_EVIDENCE_FAILED",
                    cause=exc,
                )
            except Exception:
                pass
            self._started = False
            raise

    def stop(self):
        """Stop once and attest the final externally custodied supervisor head."""

        if not self._initialized or not self._started:
            raise ProductionBootstrapError("COMPOSITION_NOT_STARTED")
        try:
            receipt = self.supervisor.stop()
            if type(receipt) is not RuntimeSupervisorCycleReceipt:
                raise ProductionBootstrapError(
                    "SUPERVISOR_SHUTDOWN_RECEIPT_NOT_SEALED"
                )
            self._started = False
            # Stopping advances the checkpoint.  Never report a clean stop
            # until off-host evidence attests the resulting high-water mark.
            self.verify_external_evidence()
            return receipt
        except Exception as exc:
            try:
                self.abort_fail_closed(
                    "PRODUCTION_BOOTSTRAP_EXTERNAL_EVIDENCE_FAILED",
                    cause=exc,
                )
            except Exception:
                pass
            self._started = False
            raise

    def run_bounded(self, *, max_cycles: int):
        if not self._initialized or not self._started:
            raise ProductionBootstrapError("COMPOSITION_NOT_STARTED")
        count = require_int("max_cycles", max_cycles, minimum=1, maximum=100_000)
        receipts: list[object] = []
        for _ in range(count):
            receipts.append(self.run_cycle())
        self.stop()
        return tuple(receipts)

    def shutdown(self) -> None:
        try:
            if self._started:
                self.supervisor.stop()
        finally:
            self.coordinator.close()
            self.adapter.shutdown()
            self._started = False
            self._initialized = False


class ProductionRuntimeBootstrap:
    """Side-effect-free descriptor; ``materialize`` is the explicit I/O boundary."""

    def __init__(self, config: ProductionRuntimeConfig, ports: ProductionRuntimePorts):
        self.config = config
        self.ports = ports
        self.contract_report = validate_production_bootstrap_contract(config, ports)

    def materialize(self) -> ProductionRuntimeComposition:
        now = require_utc("trusted bootstrap clock", self.ports.clock_provider())
        credential = _verify_credential_against_config(
            config=self.config,
            ports=self.ports,
            session=self.ports.credential_session_provider(),
            now=now,
        )
        journal_path = self.config.journal_database
        _preflight_preprovisioned_journal(
            journal_path,
            self.config.journal_sha256,
        )
        provisioning = _verify_external_receipt_against_config(
            config=self.config,
            ports=self.ports,
            receipt=self.ports.journal_provisioning_provider(),
            purpose="JOURNAL_PROVISIONING",
            now=now,
        )
        if provisioning.evidence_sha256 != self.config.journal_sha256:
            raise ProductionBootstrapError("JOURNAL_PROVISIONING_BINDING_MISMATCH")
        stage_ports = self.ports.stage_authorization_ports_provider()
        if type(stage_ports) is not RuntimeStageAuthorizationPorts:
            raise ProductionBootstrapError("STAGE_AUTHORIZATION_PORTS_NOT_SEALED")
        if stage_ports.expected_binding != self.ports.stage_binding:
            raise ProductionBootstrapError("STAGE_AUTHORIZATION_BINDING_MISMATCH")
        _verify_configured_key_fingerprint(
            provider=self.ports.supervisor_key_provider,
            key_id=self.config.supervisor_key_id,
            expected_fingerprint_sha256=(
                self.config.supervisor_key_fingerprint_sha256
            ),
            label="SUPERVISOR",
        )
        _verify_configured_key_fingerprint(
            provider=self.ports.supervisor_checkpoint_key_provider,
            key_id=self.config.supervisor_checkpoint_key_id,
            expected_fingerprint_sha256=(
                self.config.supervisor_checkpoint_key_fingerprint_sha256
            ),
            label="SUPERVISOR_CHECKPOINT",
        )
        _verify_configured_key_fingerprint(
            provider=self.ports.risk_ledger_key_provider,
            key_id=self.config.risk_ledger_key_id,
            expected_fingerprint_sha256=(
                self.config.risk_ledger_key_fingerprint_sha256
            ),
            label="RISK_LEDGER",
        )
        _verify_configured_key_fingerprint(
            provider=self.ports.journal_checkpoint_key_provider,
            key_id=self.config.journal_checkpoint_key_id,
            expected_fingerprint_sha256=(
                self.config.journal_checkpoint_key_fingerprint_sha256
            ),
            label="JOURNAL_CHECKPOINT",
        )
        _verify_configured_key_fingerprint(
            provider=self.ports.news_guard_key_provider,
            key_id=self.config.news_guard_key_id,
            expected_fingerprint_sha256=(
                self.config.news_guard_key_fingerprint_sha256
            ),
            label="NEWS_GUARD",
        )
        _verify_configured_key_fingerprint(
            provider=lambda _key_id: self.ports.permit_secret_provider(),
            key_id="permit-secret",
            expected_fingerprint_sha256=(
                self.config.permit_secret_fingerprint_sha256
            ),
            label="PERMIT",
        )
        if self.config.expected_manual_approval_key_id is not None:
            assert self.config.manual_approval_key_fingerprint_sha256 is not None
            if self.ports.manual_approval_key_provider is None:
                raise ProductionBootstrapError(
                    "MANUAL_APPROVAL_KEY_PROVIDER_REQUIRED"
                )
            _verify_configured_key_fingerprint(
                provider=self.ports.manual_approval_key_provider,
                key_id=self.config.expected_manual_approval_key_id,
                expected_fingerprint_sha256=(
                    self.config.manual_approval_key_fingerprint_sha256
                ),
                label="MANUAL_APPROVAL",
            )
        journal = ExecutionJournal(
            self.config.journal_database,
            clock_provider=self.ports.clock_provider,
        )
        if journal.journal_sha256 != self.config.journal_sha256:
            raise ProductionBootstrapError("EXECUTION_JOURNAL_BINDING_MISMATCH")
        if self.config.mode == "DEMO_AUTO":
            from .demo_auto_session_capability import (
                DemoAutoSessionCapabilityStore,
            )

            store = self.ports.demo_auto_session_store
            if type(store) is not DemoAutoSessionCapabilityStore:
                raise ProductionBootstrapError(
                    "DEMO_AUTO_SESSION_STORE_REQUIRED"
                )
            try:
                store.recover_dispatch_reservations(journal)
            except Exception as exc:
                raise ProductionBootstrapError(
                    "DEMO_AUTO_DISPATCH_STARTUP_RECOVERY_FAILED"
                ) from exc
        try:
            mt5_installation = _verify_mt5_installation_against_config(
                self.config,
                verify_mt5_installed_environment(
                    self.config.dependency_lock_file
                ),
            )
        except ProductionBootstrapError:
            raise
        except Exception as exc:
            raise ProductionBootstrapError(
                "MT5_INSTALLED_ENVIRONMENT_VERIFICATION_FAILED"
            ) from exc
        adapter = MT5Adapter(
            account_alias=credential.account_alias,
            broker_legal_name=self.config.broker_legal_name,
            expected_login=credential.expected_login,
            expected_server=self.config.server,
            environment=self.config.environment,
            session_calendar_sha256=self.config.session_calendar_sha256,
            symbol_map=dict(self.config.symbol_map),
            usd_account_currency_symbols=dict(
                self.config.usd_account_currency_symbols
            ),
            mt5_module=self.ports.mt5_module,
            mt5_installation=mt5_installation,
            expected_installed_environment_sha256=(
                self.config.installed_environment_sha256
            ),
            expected_module_file_sha256=self.config.mt5_module_file_sha256,
            expected_module_relative_path_sha256=(
                self.config.mt5_module_relative_path_sha256
            ),
            max_tick_age_seconds=self.config.max_tick_age_seconds,
            magic_number=self.config.magic_number,
            deviation_points=self.config.deviation_points,
            clock_provider=self.ports.clock_provider,
        )
        def permit_secret() -> bytes:
            return _verify_configured_key_fingerprint(
                provider=lambda _key_id: self.ports.permit_secret_provider(),
                key_id="permit-secret",
                expected_fingerprint_sha256=(
                    self.config.permit_secret_fingerprint_sha256
                ),
                label="PERMIT",
            )

        def manual_approval_key(key_id: str) -> bytes:
            if (
                self.config.expected_manual_approval_key_id is None
                or self.config.manual_approval_key_fingerprint_sha256 is None
                or self.ports.manual_approval_key_provider is None
                or key_id != self.config.expected_manual_approval_key_id
            ):
                raise ProductionBootstrapError("MANUAL_APPROVAL_KEY_ID_MISMATCH")
            return _verify_configured_key_fingerprint(
                provider=self.ports.manual_approval_key_provider,
                key_id=key_id,
                expected_fingerprint_sha256=(
                    self.config.manual_approval_key_fingerprint_sha256
                ),
                label="MANUAL_APPROVAL",
            )

        coordinator = ExecutionCoordinator(
            journal,
            adapter,
            permit_secret_provider=permit_secret,
            promotion_evidence_key_provider=self.ports.promotion_evidence_key_provider,
            manual_approval_key_provider=(
                manual_approval_key
                if self.config.expected_manual_approval_key_id is not None
                else None
            ),
            expected_manual_approver_id=self.config.expected_manual_approver_id,
            expected_manual_approval_key_id=(
                self.config.expected_manual_approval_key_id
            ),
            clock_provider=self.ports.clock_provider,
        )
        runtime_service = LiveRuntimeService(
            adapter=adapter,
            coordinator=coordinator,
            journal=journal,
            magic_number=self.config.magic_number,
            clock_provider=self.ports.clock_provider,
            intent_ttl_seconds=self.config.intent_ttl_seconds,
        )
        supervisor_binding = RuntimeSupervisorBinding(
            account_id_sha256=self.config.account_alias_sha256,
            server=self.config.server,
            environment=self.config.environment,
            account_currency=self.config.account_currency,
            journal_sha256=journal.journal_sha256,
            commit_sha=self.config.commit_sha,
            config_sha256=self.config.config_sha256,
            mode=self.config.mode,
            stage_binding_sha256=self.config.stage_binding_sha256,
            news_guard_trust_sha256=runtime_news_guard_trust_sha256(
                provider_id=self.config.news_guard_provider_id,
                key_id=self.config.news_guard_key_id,
                ruleset_sha256=self.config.news_guard_ruleset_sha256,
                blackout_window_sha256=(
                    self.config.news_guard_blackout_window_sha256
                ),
            ),
        )

        def execute_cycle(
            decision: RuntimeSupervisorDecision,
            approval: object,
        ) -> RuntimeManualDemoExecutionResult:
            result = self.ports.execution_cycle_provider(
                runtime_service, decision, approval
            )
            if type(result) is not RuntimeManualDemoExecutionResult:
                raise ProductionBootstrapError(
                    "EXECUTION_CYCLE_RISK_EVIDENCE_INVALID"
                )
            return result

        def execute_demo_auto_cycle(
            decision: RuntimeSupervisorDecision,
            ipc_input: object,
            session_store: object,
            session_lease: object,
            session_checkpoint: object,
            session_dispatch_verification: object,
            permit_validation: object,
            promotion_validation: object,
            environment_arm: object,
            supervisor_checkpoint: RuntimeSupervisorCheckpoint,
            journal_checkpoint: ExecutionJournalCheckpoint,
            risk_receipt: RiskStateReceipt,
            reconciliation: RuntimeReconciliationRiskResult,
        ) -> RuntimeDemoAutoExecutionResult:
            provider = self.ports.demo_auto_execution_cycle_provider
            if not callable(provider):
                raise ProductionBootstrapError(
                    "DEMO_AUTO_EXECUTION_CYCLE_PROVIDER_REQUIRED"
                )
            result = provider(
                runtime_service,
                decision,
                ipc_input,
                session_store,
                session_lease,
                session_checkpoint,
                session_dispatch_verification,
                permit_validation,
                promotion_validation,
                environment_arm,
                supervisor_checkpoint,
                journal_checkpoint,
                risk_receipt,
                reconciliation,
            )
            if type(result) is not RuntimeDemoAutoExecutionResult:
                raise ProductionBootstrapError(
                    "DEMO_AUTO_EXECUTION_CYCLE_RISK_EVIDENCE_INVALID"
                )
            return result

        def journal_checkpoint_verifier(
            checkpoint: ExecutionJournalCheckpoint,
            prior_checkpoint: ExecutionJournalCheckpoint | None,
        ) -> None:
            _verify_journal_checkpoint_against_config(
                config=self.config,
                ports=self.ports,
                journal=journal,
                checkpoint=checkpoint,
                prior_checkpoint=prior_checkpoint,
            )

        def news_guard_verifier(
            receipt: RuntimeNewsGuardReceipt,
        ) -> RuntimeNewsGuardReceipt:
            return _verify_news_against_config(
                config=self.config,
                ports=self.ports,
                receipt=receipt,
            )

        supervisor_key_provider = _pinned_key_provider(
            provider=self.ports.supervisor_key_provider,
            expected_key_id=self.config.supervisor_key_id,
            expected_fingerprint_sha256=(
                self.config.supervisor_key_fingerprint_sha256
            ),
            label="SUPERVISOR",
        )
        supervisor_checkpoint_key_provider = _pinned_key_provider(
            provider=self.ports.supervisor_checkpoint_key_provider,
            expected_key_id=self.config.supervisor_checkpoint_key_id,
            expected_fingerprint_sha256=(
                self.config.supervisor_checkpoint_key_fingerprint_sha256
            ),
            label="SUPERVISOR_CHECKPOINT",
        )

        supervisor = RuntimeSupervisor(
            self.config.supervisor_database,
            binding=supervisor_binding,
            journal=journal,
            risk_ledger=self.ports.risk_ledger,
            journal_checkpoint_provider=self.ports.journal_checkpoint_provider,
            journal_checkpoint_verifier=journal_checkpoint_verifier,
            risk_checkpoint_provider=self.ports.risk_checkpoint_provider,
            risk_source_provider=self.ports.risk_source_provider,
            risk_checkpoint_exporter=self.ports.risk_checkpoint_exporter,
            reconciliation_provider=self.ports.reconciliation_provider,
            broker_reconciliation_receipt_verifier=(
                self.ports.broker_reconciliation_receipt_verifier
            ),
            broker_deal_receipt_verifier=(
                self.ports.broker_deal_receipt_verifier
            ),
            broker_closed_trade_receipt_verifier=(
                self.ports.broker_closed_trade_receipt_verifier
            ),
            runtime_fact_provider=self.ports.runtime_fact_provider,
            runtime_fact_verifier=self.ports.runtime_fact_verifier,
            news_guard_provider=self.ports.news_guard_provider,
            news_guard_verifier=news_guard_verifier,
            news_guard_provider_id=self.config.news_guard_provider_id,
            news_guard_key_id=self.config.news_guard_key_id,
            news_guard_ruleset_sha256=self.config.news_guard_ruleset_sha256,
            news_guard_blackout_window_sha256=(
                self.config.news_guard_blackout_window_sha256
            ),
            decision_provider=self.ports.decision_provider,
            manual_approval_provider=self.ports.manual_approval_provider,
            manual_demo_policy_callback=self.ports.manual_demo_policy_callback,
            execution_service=execute_cycle,
            demo_auto_ipc_input_provider=(
                self.ports.demo_auto_ipc_input_provider
            ),
            demo_auto_session_lease_provider=(
                self.ports.demo_auto_session_lease_provider
            ),
            demo_auto_session_store=self.ports.demo_auto_session_store,
            demo_auto_permit_validation_provider=(
                self.ports.demo_auto_permit_validation_provider
            ),
            demo_auto_promotion_validation_provider=(
                self.ports.demo_auto_promotion_validation_provider
            ),
            demo_auto_environment_arm_provider=(
                self.ports.demo_auto_environment_arm_provider
            ),
            demo_auto_execution_service=(
                execute_demo_auto_cycle if self.config.mode == "DEMO_AUTO" else None
            ),
            key_id=self.config.supervisor_key_id,
            key_provider=supervisor_key_provider,
            supervisor_checkpoint_provider=(
                self.ports.supervisor_checkpoint_provider
            ),
            supervisor_checkpoint_exporter=(
                self.ports.supervisor_checkpoint_exporter
            ),
            supervisor_checkpoint_key_id=(
                self.config.supervisor_checkpoint_key_id
            ),
            supervisor_checkpoint_key_provider=(
                supervisor_checkpoint_key_provider
            ),
            allow_checkpoint_bootstrap=False,
            external_journal_checkpoint_provider=(
                self.ports.external_journal_checkpoint_provider
            ),
            journal_checkpoint_exporter=self.ports.journal_checkpoint_exporter,
            clock_provider=self.ports.clock_provider,
            allow_legacy_shadow_news_guard=False,
            stage_authorization_ports=stage_ports,
        )
        return ProductionRuntimeComposition(
            config=self.config,
            ports=self.ports,
            journal=journal,
            adapter=adapter,
            coordinator=coordinator,
            runtime_service=runtime_service,
            supervisor=supervisor,
        )


__all__ = [
    "BOOTSTRAP_SCHEMA_VERSION",
    "EXTERNAL_RECEIPT_SCHEMA_VERSION",
    "ORDER_CAPABILITY",
    "ProductionBootstrapContractReport",
    "ProductionBootstrapError",
    "ProductionRuntimeBootstrap",
    "ProductionRuntimeComposition",
    "ProductionRuntimeConfig",
    "ProductionRuntimePorts",
    "VerifiedBootstrapExternalReceipt",
    "VerifiedCredentialSession",
    "WORM_AUDIT_ROOT_SCHEMA_VERSION",
    "credential_session_evidence_sha256",
    "require_worm_audit_root",
    "validate_production_bootstrap_contract",
    "verify_bootstrap_external_receipt",
    "verify_credential_session",
    "worm_audit_evidence_sha256",
]
