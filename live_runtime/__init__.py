"""Fail-closed building blocks for AI_SCALPER runtime validation."""

from .broker_exporter import (
    BrokerExportBinding,
    BrokerExportBindingError,
    BrokerExportResult,
    EvidenceInstrumentIdentity,
    MT5EvidenceExporter,
    PairedAppendCommitReceipt,
    PairedAppendRecoveryRequired,
    broker_export_binding_from_spec,
    paired_append_recovery_status,
)
from .contracts import (
    BrokerSpec,
    DecisionSnapshot,
    ExecutionReceipt,
    TradeIntent,
    canonical_json,
    canonical_sha256,
)
from .decision_core import (
    DECISION_CORE_VERSION,
    DecisionCoreResult,
    DecisionProvenance,
    FirstEligibleQuote,
    build_decision_snapshot,
    build_runtime_decision_snapshot,
    evaluate_decision_core,
)
from .executor import ExecutionCoordinator, ExecutionOutcome
from .health import RuntimeHealthDecision, RuntimeHealthFacts, evaluate_runtime_health
from .market_guard import MarketGuardDecision, NewsEvent, NewsFeed, evaluate_market_guards
from .model_governance import (
    ModelArtifactManifest,
    ModelBindingDecision,
    verify_decision_model,
)
from .mt5_discovery import (
    MT5DiscoveryError,
    discover_mt5_facts,
    write_discovery_exclusive,
)
from .parity import ParityFixture, ParityReport, compare_parity
from .permit import (
    KillSwitchResetAuthorization,
    KillSwitchResetPermit,
    PermitValidation,
    PromotionPermit,
    account_alias_sha256,
    authorize_kill_switch_reset,
    reset_reason_sha256,
    validate_permit,
)
from .risk import RiskContext, RiskDecision, RiskGovernor, evaluate_risk
from .shadow_phase import (
    BrokerCandidateRegistration,
    ReadOnlyShadowService,
    ShadowSessionReceipt,
    ShadowSessionStore,
)
from .session_calendar import (
    SessionCalendarError,
    build_calendar_bundle,
    write_calendar_bundle_exclusive,
)
from .shadow_collector import (
    BarPlan,
    ReadOnlyMT5Facade,
    ShadowCollectorError,
    ShadowCycleReceipt,
    ShadowCycleStore,
    expected_bar_opens,
    plan_next_bar,
    run_shadow_cycle,
)


__all__ = [
    "BrokerExportBinding",
    "BrokerExportBindingError",
    "BrokerExportResult",
    "BrokerCandidateRegistration",
    "BrokerSpec",
    "BarPlan",
    "DecisionSnapshot",
    "DecisionCoreResult",
    "DecisionProvenance",
    "DECISION_CORE_VERSION",
    "ExecutionReceipt",
    "ExecutionCoordinator",
    "ExecutionOutcome",
    "EvidenceInstrumentIdentity",
    "FirstEligibleQuote",
    "KillSwitchResetAuthorization",
    "KillSwitchResetPermit",
    "MT5EvidenceExporter",
    "MarketGuardDecision",
    "ModelArtifactManifest",
    "ModelBindingDecision",
    "MT5DiscoveryError",
    "NewsEvent",
    "NewsFeed",
    "PairedAppendCommitReceipt",
    "PairedAppendRecoveryRequired",
    "PermitValidation",
    "PromotionPermit",
    "RiskContext",
    "RiskDecision",
    "RiskGovernor",
    "ReadOnlyShadowService",
    "ReadOnlyMT5Facade",
    "RuntimeHealthDecision",
    "RuntimeHealthFacts",
    "ParityFixture",
    "ParityReport",
    "TradeIntent",
    "ShadowSessionReceipt",
    "ShadowSessionStore",
    "ShadowCollectorError",
    "ShadowCycleReceipt",
    "ShadowCycleStore",
    "SessionCalendarError",
    "canonical_json",
    "canonical_sha256",
    "account_alias_sha256",
    "authorize_kill_switch_reset",
    "broker_export_binding_from_spec",
    "build_decision_snapshot",
    "build_runtime_decision_snapshot",
    "build_calendar_bundle",
    "compare_parity",
    "evaluate_risk",
    "evaluate_runtime_health",
    "evaluate_market_guards",
    "discover_mt5_facts",
    "evaluate_decision_core",
    "expected_bar_opens",
    "paired_append_recovery_status",
    "plan_next_bar",
    "reset_reason_sha256",
    "run_shadow_cycle",
    "verify_decision_model",
    "validate_permit",
    "write_discovery_exclusive",
    "write_calendar_bundle_exclusive",
]
