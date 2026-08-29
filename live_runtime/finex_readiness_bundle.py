"""Single-entry FINEX readiness assembly bound to independently trusted evidence.

This module is deliberately deny-only.  It verifies the short-lived readiness
binding, cross-checks identities that span verifier domains, then delegates to
the sealed gate adapters.  It never activates execution or submits an order.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
from pathlib import Path
from typing import Callable, Iterable, Mapping

from .ai_advisory_receipt import AIAdvisoryReceipt
from .contracts import require_hash, require_utc
from .finex_demo_auto_readiness import (
    REQUIRED_SYMBOLS,
    build_readiness_report,
    verify_ai_news_gate,
    verify_broker_evidence_gate,
    verify_calendar_gate,
    verify_human_approval_gate,
    verify_kill_switch_gate,
    verify_reconciliation_gate,
    verify_regulatory_gate,
    verify_release_identity_gate,
    verify_risk_controls_gate,
    verify_soak_gate,
    verify_strategy_portfolio_gate,
    verify_terminal_gate,
)
from .finex_kill_switch_drill import FinexKillSwitchDrillReceipt
from .finex_readiness_binding import (
    FinexReadinessBinding,
    verify_finex_readiness_binding,
)
from .finex_soak_readiness import FinexSoakReadinessAssessment
from .finex_strategy_portfolio import FinexStrategyPortfolioReceipt
from .reconciliation import BrokerReconciliationReceipt, ReconciliationResult
from .release_reproducibility import WindowsReproducibilityReceipt
from .risk_ledger import RiskStateReceipt
from .runtime_supervisor import RuntimeNewsGuardReceipt
from .signed_release_trust import VerifiedReleaseTrustReceipt
from .stage_authorization import StageReadinessAuthorization


class FinexReadinessBundleError(RuntimeError):
    pass


KeyProvider = Callable[[str], str | bytes]


@dataclass(frozen=True)
class FinexReadinessEvidenceBundle:
    regulatory_observation: Mapping[str, object]
    calendar_contract: Mapping[str, object]
    calendar_report: Mapping[str, object]
    calendar_checkpoints: tuple[Mapping[str, object], ...]
    terminal_discovery: Mapping[str, object]
    terminal_fence: Mapping[str, object]
    terminal_report: Mapping[str, object]
    terminal_path: str
    advisory_receipts: tuple[AIAdvisoryReceipt, ...]
    news_guard_receipt: RuntimeNewsGuardReceipt
    soak_assessment: FinexSoakReadinessAssessment
    strategy_portfolio: FinexStrategyPortfolioReceipt
    reproducibility_receipt: WindowsReproducibilityReceipt
    release_trust_receipt: VerifiedReleaseTrustReceipt | None
    risk_receipts: tuple[RiskStateReceipt, ...]
    reconciliation_receipt: BrokerReconciliationReceipt
    reconciliation_result: ReconciliationResult
    kill_switch_receipt: FinexKillSwitchDrillReceipt
    kill_switch_journal_path: str
    stage_authorizations: tuple[StageReadinessAuthorization, ...]
    prior_reconciliation_receipt: BrokerReconciliationReceipt | None = None


def _fail(code: str) -> None:
    raise FinexReadinessBundleError(code)


def _symbol_map(name: str, rows: object) -> dict[str, str]:
    try:
        result = {str(symbol): str(value) for symbol, value in rows}  # type: ignore[union-attr]
    except (TypeError, ValueError) as exc:
        raise FinexReadinessBundleError(f"{name}_INVALID") from exc
    if tuple(result) != REQUIRED_SYMBOLS or len(result) != len(REQUIRED_SYMBOLS):
        _fail(f"{name}_INVALID")
    return result


def _file_sha256(path: str) -> str:
    resolved = Path(path).resolve(strict=True)
    digest = hashlib.sha256()
    with resolved.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_cross_bindings(
    binding: FinexReadinessBinding,
    evidence: FinexReadinessEvidenceBundle,
) -> None:
    terminal_specs = _symbol_map(
        "TERMINAL_SPEC_OBSERVATION_BINDING",
        binding.terminal_spec_observation_sha256_by_symbol,
    )
    specs = _symbol_map("BROKER_SPEC_BINDING", binding.broker_spec_sha256_by_symbol)
    configs = _symbol_map(
        "STRATEGY_CONFIG_BINDING", binding.strategy_config_sha256_by_symbol
    )
    models = _symbol_map(
        "MODEL_ARTIFACT_BINDING", binding.model_artifact_sha256_by_symbol
    )
    stages = _symbol_map("STAGE_BINDING", binding.stage_binding_sha256_by_symbol)
    risk_keys = _symbol_map("RISK_KEY_BINDING", binding.risk_key_id_by_symbol)
    risk_source_issuers = _symbol_map(
        "RISK_SOURCE_ISSUER_BINDING", binding.risk_source_issuer_id_by_symbol
    )
    risk_source_keys = _symbol_map(
        "RISK_SOURCE_KEY_BINDING", binding.risk_source_key_id_by_symbol
    )
    promotion_keys = _symbol_map(
        "PROMOTION_KEY_BINDING", binding.promotion_signer_key_id_by_symbol
    )
    stage_keys = _symbol_map("STAGE_KEY_BINDING", binding.stage_signer_key_id_by_symbol)
    risk_approvers = _symbol_map(
        "RISK_APPROVER_BINDING", binding.risk_approval_key_id_by_symbol
    )
    operations_approvers = _symbol_map(
        "OPERATIONS_APPROVER_BINDING", binding.operations_approval_key_id_by_symbol
    )

    if _file_sha256(evidence.terminal_path) != binding.terminal_executable_sha256:
        _fail("TERMINAL_EXECUTABLE_BINDING_MISMATCH")
    report_specs = evidence.terminal_report.get("terminal_spec_observation_hashes")
    if not isinstance(report_specs, Mapping) or {
        str(symbol): str(value) for symbol, value in report_specs.items()
    } != terminal_specs:
        _fail("TERMINAL_BROKER_SPEC_BINDING_MISMATCH")

    portfolio = evidence.strategy_portfolio
    if (
        portfolio.portfolio_id != binding.strategy_portfolio_id
        or portfolio.issuer_id != binding.strategy_portfolio_issuer_id
        or portfolio.key_id != binding.strategy_portfolio_key_id
        or portfolio.account_alias_sha256 != binding.account_alias_sha256
        or portfolio.journal_sha256 != binding.journal_sha256
        or portfolio.commit_sha != binding.git_commit
        or portfolio.build_manifest_sha256 != binding.release_manifest_sha256
        or portfolio.server != binding.server
        or portfolio.environment != binding.environment
    ):
        _fail("STRATEGY_PORTFOLIO_BINDING_MISMATCH")
    lanes = {str(lane.symbol): lane for lane in portfolio.lanes}
    if tuple(lanes) != REQUIRED_SYMBOLS or len(lanes) != len(REQUIRED_SYMBOLS):
        _fail("STRATEGY_LANE_SET_MISMATCH")
    for symbol in REQUIRED_SYMBOLS:
        lane = lanes[symbol]
        if (
            lane.config_sha256 != configs[symbol]
            or lane.model_artifact_sha256 != models[symbol]
            or lane.promotion_signer_key_id != promotion_keys[symbol]
        ):
            _fail(f"STRATEGY_LANE_BINDING_MISMATCH:{symbol}")

    authorizations = {
        str(authorization.request.binding.symbol): authorization
        for authorization in evidence.stage_authorizations
    }
    if tuple(authorizations) != REQUIRED_SYMBOLS or len(authorizations) != 4:
        _fail("STAGE_AUTHORIZATION_SET_MISMATCH")
    for symbol in REQUIRED_SYMBOLS:
        authorization = authorizations[symbol]
        stage = authorization.request.binding
        approvals = {str(item.role): item for item in authorization.approvals}
        if (
            stage.content_sha256 != stages[symbol]
            or stage.account_alias_sha256 != binding.account_alias_sha256
            or stage.server != binding.server
            or stage.environment != binding.environment
            or stage.journal_sha256 != binding.journal_sha256
            or stage.commit_sha != binding.git_commit
            or stage.config_sha256 != configs[symbol]
            or stage.model_artifact_sha256 != models[symbol]
            or stage.broker_spec_sha256 != specs[symbol]
            or stage.strategy != lanes[symbol].strategy
            or stage.lane_id != lanes[symbol].lane_id
            or authorization.stage_signer_key_id != stage_keys[symbol]
            or set(approvals) != {"RISK_OWNER", "OPERATIONS_OWNER"}
            or approvals["RISK_OWNER"].signer_key_id != risk_approvers[symbol]
            or approvals["OPERATIONS_OWNER"].signer_key_id
            != operations_approvers[symbol]
        ):
            _fail(f"STAGE_AUTHORIZATION_BINDING_MISMATCH:{symbol}")

    risk_by_spec = {
        receipt.binding.broker_spec_sha256: receipt for receipt in evidence.risk_receipts
    }
    if len(risk_by_spec) != 4 or set(risk_by_spec) != set(specs.values()):
        _fail("RISK_RECEIPT_SET_MISMATCH")
    for symbol in REQUIRED_SYMBOLS:
        receipt = risk_by_spec[specs[symbol]]
        if receipt.key_id != risk_keys[symbol]:
            _fail(f"RISK_KEY_BINDING_MISMATCH:{symbol}")
        if receipt.latest_source_issuer_id != risk_source_issuers[symbol]:
            _fail(f"RISK_SOURCE_ISSUER_BINDING_MISMATCH:{symbol}")
        if receipt.latest_source_key_id != risk_source_keys[symbol]:
            _fail(f"RISK_SOURCE_KEY_BINDING_MISMATCH:{symbol}")

    soak = evidence.soak_assessment
    if (
        soak.cohort_binding_sha256 != binding.soak_cohort_binding_sha256
        or soak.cohort_receipt_sha256 != binding.soak_cohort_receipt_sha256
        or soak.environment != binding.environment
        or soak.broker_server != binding.server
    ):
        _fail("SOAK_COHORT_BINDING_MISMATCH")
    if evidence.reproducibility_receipt.signer_key_id != binding.reproducibility_key_id:
        _fail("REPRODUCIBILITY_KEY_BINDING_MISMATCH")
    if (
        evidence.reconciliation_receipt.provider_id
        != binding.reconciliation_provider_id
        or evidence.reconciliation_receipt.key_id != binding.reconciliation_key_id
    ):
        _fail("RECONCILIATION_SIGNER_BINDING_MISMATCH")
    if evidence.kill_switch_receipt.key_id != binding.kill_switch_key_id:
        _fail("KILL_SWITCH_KEY_BINDING_MISMATCH")


def assemble_bound_readiness_report(
    manifest: Mapping[str, object],
    binding: FinexReadinessBinding,
    evidence: FinexReadinessEvidenceBundle,
    *,
    expected_trust_policy_sha256: str,
    expected_binding_issuer_id: str,
    expected_binding_key_id: str,
    key_provider: KeyProvider,
    readiness_signing_key: bytes,
    now: datetime,
) -> dict[str, object]:
    """Verify gates against one independently trusted binding.

    A ``None`` release trust receipt produces an eleven-gate preflight report
    with an explicit missing RELEASE_IDENTITY gate.  This allows callers to
    avoid consuming one-use release trust while any other prerequisite is HOLD.
    """

    trusted_now = require_utc("now", now)
    verified_binding = verify_finex_readiness_binding(
        binding,
        expected_trust_policy_sha256=require_hash(
            "expected_trust_policy_sha256", expected_trust_policy_sha256
        ),
        expected_issuer_id=expected_binding_issuer_id,
        expected_key_id=expected_binding_key_id,
        key_provider=key_provider,
        now=trusted_now,
    )
    _verify_cross_bindings(verified_binding, evidence)
    stage_bindings = dict(verified_binding.stage_binding_sha256_by_symbol)
    specs = dict(verified_binding.broker_spec_sha256_by_symbol)

    terminal = verify_terminal_gate(
        evidence.terminal_report,
        discovery=evidence.terminal_discovery,
        fence=evidence.terminal_fence,
        terminal_path=evidence.terminal_path,
        discovery_key=key_provider(verified_binding.terminal_discovery_key_id),
        fence_key=key_provider(verified_binding.terminal_fence_key_id),
        now=trusted_now,
    )
    gates = [
        verify_regulatory_gate(evidence.regulatory_observation, now=trusted_now),
        terminal,
        verify_broker_evidence_gate(terminal, evidence.terminal_report, now=trusted_now),
        verify_calendar_gate(
            evidence.calendar_contract,
            evidence.calendar_report,
            evidence.calendar_checkpoints,
            signing_key=key_provider(verified_binding.calendar_monitor_key_id),
            now=trusted_now,
        ),
        verify_ai_news_gate(
            evidence.advisory_receipts,
            evidence.news_guard_receipt,
            expected_news_provider_id=verified_binding.news_provider_id,
            expected_news_key_id=verified_binding.news_key_id,
            expected_advisory_issuer_id=verified_binding.advisory_issuer_id,
            expected_advisory_key_id=verified_binding.advisory_key_id,
            expected_account_id_sha256=verified_binding.account_id_sha256,
            expected_server=verified_binding.server,
            expected_config_sha256=verified_binding.news_config_sha256,
            expected_policy_sha256=verified_binding.advisory_policy_sha256,
            expected_stage_binding_sha256_by_symbol=stage_bindings,
            expected_model=verified_binding.advisory_model,
            news_key_provider=key_provider,
            advisory_key_provider=key_provider,
            now=trusted_now,
        ),
        verify_soak_gate(evidence.soak_assessment, now=trusted_now),
        verify_strategy_portfolio_gate(
            evidence.strategy_portfolio,
            expected_portfolio_id=verified_binding.strategy_portfolio_id,
            expected_account_alias_sha256=verified_binding.account_alias_sha256,
            expected_journal_sha256=verified_binding.journal_sha256,
            expected_commit_sha=verified_binding.git_commit,
            expected_build_manifest_sha256=verified_binding.release_manifest_sha256,
            expected_issuer_id=verified_binding.strategy_portfolio_issuer_id,
            expected_key_id=verified_binding.strategy_portfolio_key_id,
            key_provider=key_provider,
            now=trusted_now,
        ),
        *(
            ()
            if evidence.release_trust_receipt is None
            else (
                verify_release_identity_gate(
                    evidence.reproducibility_receipt,
                    evidence.release_trust_receipt,
                    expected_git_commit=verified_binding.git_commit,
                    expected_git_tree=verified_binding.git_tree,
                    expected_archive_sha256=verified_binding.archive_sha256,
                    expected_manifest_sha256=verified_binding.release_manifest_sha256,
                    expected_release_identity_sha256=verified_binding.release_identity_sha256,
                    expected_release_profile=verified_binding.release_profile,
                    reproducibility_key_provider=key_provider,
                    now=trusted_now,
                ),
            )
        ),
        verify_risk_controls_gate(
            evidence.risk_receipts,
            expected_account_id_sha256=verified_binding.account_id_sha256,
            expected_server=verified_binding.server,
            expected_journal_sha256=verified_binding.journal_sha256,
            expected_account_currency=verified_binding.account_currency,
            expected_broker_spec_sha256=specs,
            key_provider=key_provider,
            now=trusted_now,
        ),
        verify_reconciliation_gate(
            evidence.reconciliation_receipt,
            evidence.reconciliation_result,
            expected_account_id_sha256=verified_binding.account_id_sha256,
            expected_server=verified_binding.server,
            expected_journal_sha256=verified_binding.journal_sha256,
            expected_provider_id=verified_binding.reconciliation_provider_id,
            expected_key_id=verified_binding.reconciliation_key_id,
            key_provider=key_provider,
            now=trusted_now,
            prior_receipt=evidence.prior_reconciliation_receipt,
        ),
        verify_kill_switch_gate(
            evidence.kill_switch_receipt,
            journal_path=evidence.kill_switch_journal_path,
            expected_account_id_sha256=verified_binding.account_id_sha256,
            expected_server=verified_binding.server,
            expected_release_identity_sha256=verified_binding.release_identity_sha256,
            expected_release_manifest_sha256=verified_binding.release_manifest_sha256,
            expected_commit_sha=verified_binding.git_commit,
            key_provider=key_provider,
            now=trusted_now,
        ),
        verify_human_approval_gate(
            evidence.stage_authorizations,
            evidence.strategy_portfolio,
            approval_key_provider=key_provider,
            stage_key_provider=key_provider,
            now=trusted_now,
        ),
    ]
    return build_readiness_report(
        manifest, gates, signing_key=readiness_signing_key, now=trusted_now
    )


__all__ = [
    "FinexReadinessBundleError",
    "FinexReadinessEvidenceBundle",
    "assemble_bound_readiness_report",
]
