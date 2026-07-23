"""Build a deny-only operator kit for the controlled manual-demo stage.

The kit joins the tracked candidate readiness assessment with the reviewed
Windows composition-port inventory. It cannot initialize MetaTrader, read a
credential, create an approval, or submit an order.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Mapping, Sequence

from .contracts import CanonicalContract, require_text, require_utc
from .manual_demo_readiness import ManualDemoReadinessReport
from .windows_service_factory_template import ExternalProviderContract


SCHEMA_VERSION = "manual-demo-activation-kit-v1"
STATUS = "BLOCKED_EXTERNAL_INPUT_REQUIRED"
TARGET_CONTROLLED_ORDERS = 10
MAX_LOT = 0.01

_OPERATOR_SEQUENCE = (
    "VALIDATE_CLEAN_SIGNED_WINDOWS_RELEASE",
    "ATTEST_DISTINCT_MT5_TERMINAL_AND_DEMO_ACCOUNT_FENCE",
    "CONFIGURE_REQUIRED_EXTERNAL_PROVIDERS_AND_CREDENTIAL_REFERENCES",
    "RUN_FAILURE_AND_RECONCILIATION_DRILLS",
    "OBTAIN_INDEPENDENT_MANUAL_APPROVAL",
    "REASSESS_MANUAL_DEMO_READINESS",
    "EXECUTE_ONE_REVIEWED_MANUAL_DEMO_INTENT_AT_A_TIME",
    "RECONCILE_POSITION_AND_SERVER_SIDE_SL_TP_AFTER_EACH_ORDER",
    "REVIEW_ALL_TEN_CONTROLLED_ORDER_LIFECYCLES",
)
_PROHIBITED_ACTIONS = (
    "LIVE_ORDER",
    "DEMO_AUTO_ORDER",
    "BYPASS_READINESS_GATE",
    "EMBED_SECRET_IN_REPOSITORY",
    "REUSE_INTENT_AFTER_UNCERTAIN_SUBMISSION",
)


class ManualDemoActivationKitError(RuntimeError):
    """Raised when a source attempts to weaken the deny-only kit."""


def _provider_payload(
    contract: ExternalProviderContract,
) -> Mapping[str, object]:
    return MappingProxyType(
        {
            "port_name": contract.port_name,
            "provider_kind": contract.provider_kind,
            "call_contract": contract.call_contract,
            "credential_purpose": contract.credential_purpose,
            "contract_sha256": contract.contract_sha256,
        }
    )


@dataclass(frozen=True)
class ManualDemoActivationKit(CanonicalContract):
    candidate_id: str
    candidate_server: str
    account_currency: str
    prepared_at_utc: datetime
    status: str
    ready: bool
    readiness_report_sha256: str
    readiness_blocker_codes: tuple[str, ...]
    windows_port_validation: str
    required_external_providers: tuple[Mapping[str, object], ...]
    operator_sequence: tuple[str, ...]
    prohibited_actions: tuple[str, ...]
    target_controlled_orders: int
    safety: Mapping[str, object]
    broker_mutation_performed: bool
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        candidate_id = require_text("candidate_id", self.candidate_id).lower()
        server = require_text("candidate_server", self.candidate_server)
        currency = require_text(
            "account_currency", self.account_currency, upper=True
        )
        require_utc("prepared_at_utc", self.prepared_at_utc)
        if self.status != STATUS or self.ready is not False:
            raise ValueError("manual-demo activation kit must remain blocked")
        if self.windows_port_validation != "PASS":
            raise ValueError("Windows composition ports must pass before kit creation")
        if (
            not isinstance(self.readiness_report_sha256, str)
            or len(self.readiness_report_sha256) != 64
        ):
            raise ValueError("readiness report hash is invalid")
        blockers = tuple(sorted(set(self.readiness_blocker_codes)))
        if not blockers:
            raise ValueError("activation kit requires unresolved readiness blockers")
        providers = tuple(self.required_external_providers)
        if not providers:
            raise ValueError("activation kit requires external provider contracts")
        provider_names = tuple(
            str(provider.get("port_name", "")) for provider in providers
        )
        if (
            any(not name for name in provider_names)
            or len(provider_names) != len(set(provider_names))
        ):
            raise ValueError("external provider contract names are invalid")
        if tuple(self.operator_sequence) != _OPERATOR_SEQUENCE:
            raise ValueError("operator sequence is invalid")
        if tuple(self.prohibited_actions) != _PROHIBITED_ACTIONS:
            raise ValueError("prohibited actions are invalid")
        if self.target_controlled_orders != TARGET_CONTROLLED_ORDERS:
            raise ValueError("manual-demo target must remain exactly ten orders")
        expected_safety = {
            "manual_demo_enabled": False,
            "execution_enabled": False,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "order_capability": "DISABLED",
            "max_lot": MAX_LOT,
        }
        if dict(self.safety) != expected_safety:
            raise ValueError("activation kit safety locks are invalid")
        if self.broker_mutation_performed is not False:
            raise ValueError("activation kit cannot claim broker mutation")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("activation kit schema is invalid")
        object.__setattr__(self, "candidate_id", candidate_id)
        object.__setattr__(self, "candidate_server", server)
        object.__setattr__(self, "account_currency", currency)
        object.__setattr__(self, "readiness_blocker_codes", blockers)
        object.__setattr__(self, "required_external_providers", providers)
        object.__setattr__(self, "operator_sequence", _OPERATOR_SEQUENCE)
        object.__setattr__(self, "prohibited_actions", _PROHIBITED_ACTIONS)
        object.__setattr__(self, "safety", MappingProxyType(expected_safety))


def build_manual_demo_activation_kit(
    *,
    readiness: ManualDemoReadinessReport,
    windows_validation: Mapping[str, object],
    provider_contracts: Sequence[ExternalProviderContract],
    prepared_at_utc: datetime,
) -> ManualDemoActivationKit:
    """Join local readiness facts without creating execution authority."""

    require_utc("prepared_at_utc", prepared_at_utc)
    if readiness.ready is not False or readiness.status != "BLOCKED":
        raise ManualDemoActivationKitError(
            "readiness input must be the tracked blocked report"
        )
    if windows_validation.get("port_validation") != "PASS":
        raise ManualDemoActivationKitError(
            "Windows composition port validation did not pass"
        )
    if windows_validation.get("production_execution_ready") is not False:
        raise ManualDemoActivationKitError(
            "Windows validation must remain production-blocked"
        )
    required = tuple(
        _provider_payload(contract)
        for contract in sorted(provider_contracts, key=lambda item: item.port_name)
        if contract.required
    )
    return ManualDemoActivationKit(
        candidate_id=readiness.candidate_id,
        candidate_server=readiness.candidate_server,
        account_currency=readiness.account_currency,
        prepared_at_utc=prepared_at_utc,
        status=STATUS,
        ready=False,
        readiness_report_sha256=readiness.content_sha256,
        readiness_blocker_codes=readiness.blocker_codes,
        windows_port_validation="PASS",
        required_external_providers=required,
        operator_sequence=_OPERATOR_SEQUENCE,
        prohibited_actions=_PROHIBITED_ACTIONS,
        target_controlled_orders=TARGET_CONTROLLED_ORDERS,
        safety=readiness.safety,
        broker_mutation_performed=False,
    )


__all__ = [
    "ManualDemoActivationKit",
    "ManualDemoActivationKitError",
    "build_manual_demo_activation_kit",
]
