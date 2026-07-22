"""Canonical, deny-by-default catalog for live-grade readiness gates.

The catalog separates repository work from facts that code cannot manufacture.
It intentionally does not accept caller supplied booleans for external or
temporal gates and therefore cannot be used to promote a lane or arm execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping


SCHEMA_VERSION = "live-grade-readiness-gate-catalog-v1"
ORDER_CAPABILITY = "DISABLED"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_LOT = 0.01


class GateCatalogError(ValueError):
    """A malformed or unknown gate inventory was supplied."""


class GateCategory(str, Enum):
    LOCAL_FOUNDATION = "LOCAL_FOUNDATION"
    EXTERNAL_CONFIGURATION = "EXTERNAL_CONFIGURATION"
    TEMPORAL_EVIDENCE = "TEMPORAL_EVIDENCE"
    MANUAL_APPROVAL = "MANUAL_APPROVAL"


@dataclass(frozen=True, slots=True)
class GateDefinition:
    code: str
    category: GateCategory
    description: str

    def __post_init__(self) -> None:
        if not self.code or self.code != self.code.upper():
            raise GateCatalogError("gate code must be non-empty uppercase text")
        if not isinstance(self.category, GateCategory):
            raise GateCatalogError("gate category must be exact GateCategory")
        if not self.description or self.description.strip() != self.description:
            raise GateCatalogError("gate description must be normalized text")


def _gate(code: str, category: GateCategory, description: str) -> GateDefinition:
    return GateDefinition(code=code, category=category, description=description)


GATE_CATALOG = (
    _gate(
        "ASYMMETRIC_PUBLIC_VERIFICATION_OR_EXTERNAL_LAUNCHER_ATTESTATION_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "Release identity must be verified outside the local HMAC trust domain.",
    ),
    _gate(
        "EXTERNAL_FACTORY_PROVIDER_CONFIGURATION_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "Reviewed Windows service providers must be materialized and attested.",
    ),
    _gate(
        "EXTERNAL_DEMO_AUTO_IPC_CONFIGURATION_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "Decision and executor processes need independently configured IPC custody.",
    ),
    _gate(
        "EXTERNAL_DEMO_AUTO_SESSION_CUSTODY_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "Renewable demo-auto session checkpoints need independent CAS custody.",
    ),
    _gate(
        "EXTERNAL_CREDENTIAL_SESSION_RECEIPT_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "Windows credential use must be represented by a current signed session receipt.",
    ),
    _gate(
        "EXTERNAL_CROSS_ACCOUNT_PORTFOLIO_EXPOSURE_CUSTODY_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "Concurrent multi-account expansion requires one externally coordinated global exposure reservation and broker view.",
    ),
    _gate(
        "EXTERNAL_DECISION_DATA_PROVIDER_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "The brokerless decision service needs a reviewed finalized-data provider.",
    ),
    _gate(
        "EXTERNAL_EXECUTION_CYCLE_PROVIDER_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "The execution composition root needs a reviewed cycle provider.",
    ),
    _gate(
        "EXTERNAL_JOURNAL_CHECKPOINT_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "The local execution journal must match its off-host checkpoint.",
    ),
    _gate(
        "EXTERNAL_JOURNAL_CHECKPOINT_CAS_EXPORTER_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "Execution journal checkpoints require independent compare-and-swap export.",
    ),
    _gate(
        "EXTERNAL_JOURNAL_PROVISIONING_RECEIPT_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "The exact empty execution journal must be provisioned and attested.",
    ),
    _gate(
        "EXTERNAL_MANUAL_APPROVAL_PROVIDER_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "Runtime approval must come from a reviewed external provider.",
    ),
    _gate(
        "EXACT_INSTALLED_MT5_MODULE_ATTESTATION_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "The exact installed MetaTrader Python module and terminal must be attested.",
    ),
    _gate(
        "EXTERNAL_PERMIT_SECRET_PROVIDER_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "Promotion-permit signing material must remain outside the repository.",
    ),
    _gate(
        "EXTERNAL_PROMOTION_EVIDENCE_TRUST_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "Promotion evidence must be verified by an independent trust provider.",
    ),
    _gate(
        "EXTERNAL_RECONCILIATION_PROVIDER_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "The exact broker reconciliation provider must be wired and attested.",
    ),
    _gate(
        "EXTERNAL_RISK_SOURCE_AND_STATE_RECEIPTS_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "Risk state, account facts, market guards, and model state need signed receipts.",
    ),
    _gate(
        "EXTERNAL_RISK_CHECKPOINT_CAS_EXPORTER_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "Risk ledger checkpoints require independent compare-and-swap export.",
    ),
    _gate(
        "EXTERNAL_RUNTIME_FACT_PROVIDER_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "Fresh broker/account/runtime facts must come from a reviewed provider.",
    ),
    _gate(
        "EXTERNAL_SIGNED_NEWS_RECEIPT_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "A fresh signed high-impact news feed receipt is mandatory.",
    ),
    _gate(
        "EXTERNAL_STAGE_AUTHORIZATION_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "The requested runtime stage needs a consumed signed authorization.",
    ),
    _gate(
        "EXTERNAL_SUPERVISOR_CHECKPOINT_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "Runtime supervisor state must match a current off-host checkpoint.",
    ),
    _gate(
        "EXTERNAL_TRUSTED_CLOCK_PROVIDER_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "Runtime clock drift must be bounded by an independently trusted source.",
    ),
    _gate(
        "EXTERNAL_WORM_AUDIT_RECEIPT_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "Audit exports need immutable off-host retention acknowledgement.",
    ),
    _gate(
        "SIGNED_RUNTIME_RECEIPTS_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "All runtime providers must supply exact signed receipts.",
    ),
    _gate(
        "REGULATORY_AND_ACCOUNT_ELIGIBILITY_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "The exact broker, account type, resident status, and instruments need legal review.",
    ),
    _gate(
        "WINDOWS_VPS_HARDENING_AND_FAILURE_DRILLS_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "The exact Windows host must pass security hardening and all failure drills.",
    ),
    _gate(
        "XAUUSD_MINIMUM_LOT_RISK_FEASIBILITY_REQUIRED",
        GateCategory.EXTERNAL_CONFIGURATION,
        "Broker order-calc evidence must prove that minimum XAUUSD volume can fit the locked risk cap.",
    ),
    _gate(
        "BROKER_BENCHMARK_20_SESSIONS_REQUIRED",
        GateCategory.TEMPORAL_EVIDENCE,
        "Each broker candidate needs at least twenty observed sessions.",
    ),
    _gate(
        "BROKER_FORWARD_8_WEEKS_REQUIRED",
        GateCategory.TEMPORAL_EVIDENCE,
        "Each promoted lane needs at least eight weeks of broker-forward observation.",
    ),
    _gate(
        "MANUAL_DEMO_10_CONTROLLED_ORDERS_REQUIRED",
        GateCategory.TEMPORAL_EVIDENCE,
        "The reviewed executor must complete ten controlled manual demo orders.",
    ),
    _gate(
        "DEMO_AUTO_SOAK_30_DAYS_REQUIRED",
        GateCategory.TEMPORAL_EVIDENCE,
        "Demo-auto must run cleanly for at least thirty days.",
    ),
    _gate(
        "DEMO_AUTO_SOAK_50_CLOSED_FILLS_REQUIRED",
        GateCategory.TEMPORAL_EVIDENCE,
        "Demo-auto must reconcile at least fifty closed fills.",
    ),
    _gate(
        "DEMO_AUTO_SOAK_20_XAUUSD_CLOSED_FILLS_REQUIRED",
        GateCategory.TEMPORAL_EVIDENCE,
        "At least twenty reconciled demo-auto fills must be XAUUSD.",
    ),
    _gate(
        "OOS_100_CLOSED_TRADES_PER_LANE_REQUIRED",
        GateCategory.TEMPORAL_EVIDENCE,
        "Every lane needs at least one hundred closed out-of-sample trades.",
    ),
    _gate(
        "BROKER_FORWARD_50_CLOSED_TRADES_PER_LANE_REQUIRED",
        GateCategory.TEMPORAL_EVIDENCE,
        "Every lane needs at least fifty broker-forward closed trades.",
    ),
    _gate(
        "STATISTICAL_LANE_GATES_REQUIRED",
        GateCategory.TEMPORAL_EVIDENCE,
        "Each lane must pass folds, PF, expectancy CI, drawdown, cost stress, and parity gates.",
    ),
    _gate(
        "MANUAL_SHIP_APPROVAL_REQUIRED",
        GateCategory.MANUAL_APPROVAL,
        "A human ship decision is required after all technical evidence passes.",
    ),
    _gate(
        "XAUUSD_EXECUTION_POLICY_APPROVAL_REQUIRED",
        GateCategory.MANUAL_APPROVAL,
        "XAUUSD cannot enter demo-auto until its execution policy is separately reviewed.",
    ),
    _gate(
        "LIVE_CANARY_APPROVAL_REQUIRED",
        GateCategory.MANUAL_APPROVAL,
        "Live XAUUSD canary activation requires a new explicit approval.",
    ),
)

_BY_CODE = {gate.code: gate for gate in GATE_CATALOG}
if len(_BY_CODE) != len(GATE_CATALOG):  # pragma: no cover - import invariant
    raise RuntimeError("duplicate live-grade readiness gate code")


def classify_gate_codes(codes: Iterable[str]) -> Mapping[str, tuple[str, ...]]:
    """Return a deterministic category inventory or reject unknown codes."""

    normalized: set[str] = set()
    for raw_code in codes:
        if not isinstance(raw_code, str):
            raise GateCatalogError("gate code must be text")
        code = raw_code.strip().upper()
        if not code or code != raw_code:
            raise GateCatalogError("gate code must be normalized uppercase text")
        if code not in _BY_CODE:
            raise GateCatalogError(f"unknown readiness gate: {code}")
        normalized.add(code)
    return {
        category.value: tuple(
            sorted(
                code
                for code in normalized
                if _BY_CODE[code].category is category
            )
        )
        for category in GateCategory
    }


def pending_nonlocal_gate_codes() -> tuple[str, ...]:
    """Return every gate that repository code is forbidden to self-satisfy."""

    return tuple(
        sorted(
            gate.code
            for gate in GATE_CATALOG
            if gate.category is not GateCategory.LOCAL_FOUNDATION
        )
    )


def catalog_report() -> Mapping[str, object]:
    """Publish the static safety posture; this is never a promotion receipt."""

    pending = pending_nonlocal_gate_codes()
    return {
        "schema_version": SCHEMA_VERSION,
        "gate_count": len(GATE_CATALOG),
        "pending_gate_count": len(pending),
        "pending_gates": pending,
        "pending_by_category": classify_gate_codes(pending),
        "production_execution_ready": False,
        "promotion_eligible": False,
        "live_allowed": LIVE_ALLOWED,
        "safe_to_demo_auto_order": SAFE_TO_DEMO_AUTO_ORDER,
        "max_lot": MAX_LOT,
        "order_capability": ORDER_CAPABILITY,
    }


__all__ = [
    "GATE_CATALOG",
    "GateCatalogError",
    "GateCategory",
    "GateDefinition",
    "catalog_report",
    "classify_gate_codes",
    "pending_nonlocal_gate_codes",
]
