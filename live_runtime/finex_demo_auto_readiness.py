"""Content-addressed FINEX demo-auto readiness evidence aggregation.

Gate results can only be minted by concrete verifier adapters in this module.
The signed report is short-lived and deny-only: even complete evidence merely
permits an activation review, never trading or activation itself.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from datetime import datetime, timedelta, timezone
import hmac
import math
from typing import Callable, Iterable, Mapping

from .account_identity import payload_hmac_sha256
from .ai_advisory_receipt import AIAdvisoryReceipt, verify_ai_advisory_receipt
from .contracts import CanonicalContract, canonical_sha256, require_hash, require_utc
from .evidence_credentials import signing_key_fingerprint
from .finex_calendar_email_monitor import assemble_monitor_report
from .finex_kill_switch_drill import (
    FinexKillSwitchDrillReceipt,
    verify_kill_switch_drill_receipt,
)
from .finex_soak_readiness import FinexSoakReadinessAssessment
from .finex_strategy_portfolio import (
    FinexStrategyPortfolioReceipt,
    verify_finex_strategy_portfolio_receipt,
)
from .finex_terminal_fence import verify_terminal_fence
from .finex_terminal_monitor import verify_monitor_report
from .registration_review_ed25519 import verify_dual_observation
from .reconciliation import (
    BROKER_RECONCILIATION_RECEIPT_MAX_AGE,
    BrokerReconciliationReceipt,
    ReconciliationResult,
    verify_broker_reconciliation_receipt,
)
from .release_reproducibility import (
    WindowsReproducibilityReceipt,
    verify_reproducibility_receipt,
)
from .risk_ledger import RiskStateReceipt, verify_risk_state_receipt
from .runtime_supervisor import RuntimeNewsGuardReceipt, verify_runtime_news_guard_receipt
from .signed_release_trust import VerifiedReleaseTrustReceipt
from .stage_authorization import HumanApprovalAttestation, StageReadinessAuthorization


MANIFEST_SCHEMA = "finex-demo-auto-readiness-manifest-v1"
REPORT_SCHEMA = "finex-demo-auto-readiness-report-v1"
READINESS_KEY_NAME = "finex-demo-auto-readiness-v1"
REPORT_DOMAIN = b"AI_SCALPER/FINEX_DEMO_AUTO_READINESS/V1"
REPORT_MAX_AGE = timedelta(minutes=5)
REQUIRED_GATES = (
    "AI_NEWS_ADVISORY",
    "BROKER_EVIDENCE_FRESHNESS",
    "CALENDAR_MONITORING",
    "HUMAN_APPROVAL_PIPELINE",
    "KILL_SWITCH",
    "RECONCILIATION",
    "REGULATORY_DUAL_REVIEW",
    "RELEASE_IDENTITY",
    "RISK_CONTROLS",
    "SOAK_PORTFOLIO",
    "STRATEGY_PORTFOLIO",
    "TERMINAL_MONITOR",
)
REQUIRED_SYMBOLS = ("AUDUSD", "EURUSD", "USDJPY", "XAUUSD")
RELEASE_EVIDENCE_MAX_AGE = timedelta(hours=24)
RISK_STATE_MAX_AGE = timedelta(seconds=1)
_GATE_SEAL = object()


class FinexDemoAutoReadinessError(RuntimeError):
    pass


def _utc(value: object, name: str) -> datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise FinexDemoAutoReadinessError(f"{name} is invalid") from exc
    if parsed.tzinfo is None:
        raise FinexDemoAutoReadinessError(f"{name} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def validate_manifest(manifest: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(manifest, Mapping):
        raise FinexDemoAutoReadinessError("readiness manifest is required")
    expected = {
        "schema_version": MANIFEST_SCHEMA,
        "candidate_id": "finex",
        "operating_jurisdiction": "ID",
        "environment": "DEMO",
        "broker_server": "FinexBisnisSolusi-Demo",
        "required_symbols": list(REQUIRED_SYMBOLS),
        "required_gates": list(REQUIRED_GATES),
        "minimum_clean_days": 30,
        "minimum_total_closed_fills": 100,
        "minimum_closed_fills_per_symbol": 20,
        "authorization_granted": False,
        "activation_authorized": False,
        "execution_enabled": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
        "order_capability": "DISABLED",
    }
    if dict(manifest) != expected:
        raise FinexDemoAutoReadinessError("readiness manifest contract is invalid")
    return dict(manifest)


@dataclass(frozen=True)
class VerifiedGateResult(CanonicalContract):
    gate_id: str
    verifier_id: str
    status: str
    artifact_sha256: tuple[str, ...]
    blocker_codes: tuple[str, ...]
    observed_at_utc: datetime
    expires_at_utc: datetime | None
    complete: bool
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _GATE_SEAL:
            raise TypeError("gate results can only be created by readiness verifiers")
        if self.gate_id not in REQUIRED_GATES:
            raise ValueError("unknown FINEX readiness gate")
        if not self.verifier_id:
            raise ValueError("gate verifier id is required")
        hashes = tuple(require_hash("artifact_sha256", item) for item in self.artifact_sha256)
        if not hashes or hashes != tuple(sorted(set(hashes))):
            raise ValueError("gate artifact hashes must be unique and sorted")
        object.__setattr__(self, "artifact_sha256", hashes)
        blockers = tuple(sorted(set(self.blocker_codes)))
        if blockers != self.blocker_codes:
            raise ValueError("gate blockers must be unique and sorted")
        require_utc("observed_at_utc", self.observed_at_utc)
        if self.expires_at_utc is not None:
            require_utc("expires_at_utc", self.expires_at_utc)
            if self.expires_at_utc <= self.observed_at_utc:
                raise ValueError("gate expiry must follow observation")
        expected_status = "COMPLETE" if self.complete else "HOLD"
        if self.status != expected_status or self.complete == bool(blockers):
            raise ValueError("gate status and blockers are inconsistent")


def _gate(
    gate_id: str,
    verifier_id: str,
    artifacts: Iterable[str],
    blockers: Iterable[str],
    observed_at: datetime,
    expires_at: datetime | None = None,
) -> VerifiedGateResult:
    normalized = tuple(sorted(set(str(item).lower() for item in artifacts)))
    reasons = tuple(sorted(set(str(item) for item in blockers)))
    return VerifiedGateResult(
        gate_id=gate_id,
        verifier_id=verifier_id,
        status="COMPLETE" if not reasons else "HOLD",
        artifact_sha256=normalized,
        blocker_codes=reasons,
        observed_at_utc=require_utc("observed_at", observed_at),
        expires_at_utc=expires_at,
        complete=not reasons,
        _seal=_GATE_SEAL,
    )


def verify_regulatory_gate(
    observation: Mapping[str, object],
    *,
    now: datetime,
) -> VerifiedGateResult:
    trusted_now = require_utc("now", now)
    blockers: list[str] = []
    try:
        verified = verify_dual_observation(
            observation, now_provider=lambda: trusted_now
        )
        if (
            verified.get("candidate_id") != "finex"
            or verified.get("operating_jurisdiction") != "ID"
            or verified.get("environment") != "DEMO"
            or verified.get("broker_server") != "FinexBisnisSolusi-Demo"
            or verified.get("legal_eligible") is not True
            or verified.get("independent_registry_verification") is not True
            or verified.get("independent_reviewers_verified") is not True
        ):
            blockers.append("REGULATORY_BINDING_OR_ELIGIBILITY_INVALID")
        if (
            verified.get("authorization_granted") is not False
            or verified.get("order_capability") != "DISABLED"
        ):
            blockers.append("REGULATORY_REVIEW_SAFETY_CONTRACT_INVALID")
        observed = _utc(verified.get("verified_at_utc"), "regulatory verified_at")
    except Exception:
        blockers.append("REGULATORY_DUAL_REVIEW_INVALID")
        observed = trusted_now
    return _gate(
        "REGULATORY_DUAL_REVIEW",
        "registration_review_ed25519.verify_dual_observation",
        (canonical_sha256(observation),),
        blockers,
        observed,
    )


def verify_terminal_gate(
    report: Mapping[str, object],
    *,
    discovery: Mapping[str, object],
    fence: Mapping[str, object],
    terminal_path: str,
    discovery_key: bytes,
    fence_key: bytes,
    now: datetime,
) -> VerifiedGateResult:
    trusted_now = require_utc("now", now)
    artifacts = (
        canonical_sha256(discovery),
        canonical_sha256(fence),
        canonical_sha256(report),
    )
    blockers: list[str] = []
    try:
        verified_fence = verify_terminal_fence(
            fence,
            discovery,
            terminal_path=terminal_path,
            discovery_key=discovery_key,
            fence_key=fence_key,
            now_provider=lambda: trusted_now,
        )
        verified = verify_monitor_report(
            report,
            signing_key=fence_key,
            expected_account_identity_sha256=str(
                verified_fence["account_identity_sha256"]
            ),
            expected_terminal_fence_sha256=canonical_sha256(fence),
            now_provider=lambda: trusted_now,
        )
        observed = _utc(verified.get("last_observed_at"), "terminal observed_at")
        expires = _utc(verified.get("expires_at"), "terminal expires_at")
    except Exception:
        blockers.append("TERMINAL_MONITOR_INVALID_STALE_OR_HOLD")
        observed = trusted_now
        expires = trusted_now + timedelta(microseconds=1)
    return _gate(
        "TERMINAL_MONITOR",
        "finex_terminal_monitor.verify_monitor_report",
        artifacts,
        blockers,
        observed,
        expires,
    )


def verify_calendar_gate(
    contract: Mapping[str, object],
    report: Mapping[str, object],
    checkpoints: Iterable[Mapping[str, object]],
    *,
    signing_key: bytes,
    now: datetime,
) -> VerifiedGateResult:
    trusted_now = require_utc("now", now)
    blockers: list[str] = []
    checkpoint_list = list(checkpoints)
    try:
        generated_at = _utc(report.get("generated_at_utc"), "calendar generated_at")
        rebuilt = assemble_monitor_report(
            contract,
            checkpoint_list,
            signing_key=signing_key,
            now_provider=lambda: generated_at,
        )
        if dict(report) != rebuilt:
            raise FinexDemoAutoReadinessError("calendar report content mismatch")
        blind = _utc(rebuilt.get("blind_until_utc"), "calendar blind_until")
        observed = generated_at
        if trusted_now < blind:
            blockers.append("CALENDAR_OBSERVATION_WINDOW_INCOMPLETE")
        elif rebuilt.get("status") != "PENDING_INDEPENDENT_FINAL_REVIEW":
            blockers.append("CALENDAR_MONITORING_INCOMPLETE_OR_GAPPED")
        blockers.append("CALENDAR_FINAL_INDEPENDENT_REVIEW_REQUIRED")
    except Exception:
        blockers.append("CALENDAR_MONITOR_REPORT_INVALID")
        observed = trusted_now
    artifacts = [canonical_sha256(contract), canonical_sha256(report)]
    artifacts.extend(canonical_sha256(item) for item in checkpoint_list)
    return _gate(
        "CALENDAR_MONITORING",
        "finex_calendar_email_monitor.assemble_monitor_report",
        artifacts,
        blockers,
        observed,
    )


def verify_broker_evidence_gate(
    terminal_gate: VerifiedGateResult,
    terminal_report: Mapping[str, object],
    *,
    now: datetime,
) -> VerifiedGateResult:
    """Derive fresh broker facts only from a verified terminal-monitor result."""

    trusted_now = require_utc("now", now)
    if type(terminal_gate) is not VerifiedGateResult or terminal_gate.gate_id != "TERMINAL_MONITOR":
        raise FinexDemoAutoReadinessError("verified terminal gate is required")
    blockers: list[str] = []
    report_hash = canonical_sha256(terminal_report)
    if report_hash not in terminal_gate.artifact_sha256:
        blockers.append("BROKER_EVIDENCE_TERMINAL_REPORT_BINDING_INVALID")
    if not terminal_gate.complete or (
        terminal_gate.expires_at_utc is not None
        and trusted_now >= terminal_gate.expires_at_utc
    ):
        blockers.append("BROKER_EVIDENCE_REQUIRES_FRESH_TERMINAL_MONITOR")
    try:
        specs = terminal_report.get("terminal_spec_observation_hashes")
        receipts = terminal_report.get("receipts")
        if not isinstance(specs, Mapping) or set(specs) != set(REQUIRED_SYMBOLS):
            raise ValueError("broker spec symbol set is invalid")
        spec_hashes = tuple(
            require_hash("terminal_spec_observation_sha256", specs[s])
            for s in REQUIRED_SYMBOLS
        )
        if not isinstance(receipts, list) or not receipts:
            raise ValueError("terminal receipts are missing")
        samples = receipts[-1].get("symbol_samples")
        if not isinstance(samples, Mapping) or set(samples) != set(REQUIRED_SYMBOLS):
            raise ValueError("terminal sample symbol set is invalid")
        for symbol in REQUIRED_SYMBOLS:
            sample = samples[symbol]
            if not isinstance(sample, Mapping) or sample.get("status") != "READY_READ_ONLY":
                raise ValueError("terminal symbol sample is not ready")
            tick_value = sample.get("risk_tick_value")
            if (
                isinstance(tick_value, bool)
                or not isinstance(tick_value, (int, float))
                or not math.isfinite(float(tick_value))
                or float(tick_value) <= 0
            ):
                raise ValueError("broker tick value is invalid")
        observed = _utc(terminal_report.get("last_observed_at"), "broker observed_at")
        expires = _utc(terminal_report.get("expires_at"), "broker expires_at")
    except Exception:
        blockers.append("BROKER_EVIDENCE_SPEC_OR_RISK_VALUES_INVALID")
        spec_hashes = ()
        observed = trusted_now
        expires = None
    return _gate(
        "BROKER_EVIDENCE_FRESHNESS",
        "finex_demo_auto_readiness.verify_broker_evidence_gate",
        tuple(terminal_gate.artifact_sha256) + tuple(spec_hashes),
        blockers,
        observed,
        expires,
    )


def verify_ai_news_gate(
    advisory_receipts: Iterable[AIAdvisoryReceipt],
    news_guard_receipt: RuntimeNewsGuardReceipt,
    *,
    expected_news_provider_id: str,
    expected_news_key_id: str,
    expected_advisory_issuer_id: str,
    expected_advisory_key_id: str,
    expected_account_id_sha256: str,
    expected_server: str,
    expected_config_sha256: str,
    expected_policy_sha256: str,
    expected_stage_binding_sha256_by_symbol: Mapping[str, str],
    expected_model: str,
    news_key_provider: Callable[[str], str | bytes],
    advisory_key_provider: Callable[[str], str | bytes],
    now: datetime,
) -> VerifiedGateResult:
    """Verify current signed news guard and four demo-auto veto-only advisories."""

    trusted_now = require_utc("now", now)
    receipts = tuple(advisory_receipts)
    artifacts: list[str] = []
    blockers: list[str] = []
    try:
        if set(expected_stage_binding_sha256_by_symbol) != set(REQUIRED_SYMBOLS):
            raise ValueError("four exact stage bindings are required")
        stage_bindings = {
            symbol: require_hash(
                "expected_stage_binding_sha256",
                expected_stage_binding_sha256_by_symbol[symbol],
            )
            for symbol in REQUIRED_SYMBOLS
        }
    except Exception:
        blockers.append("AI_ADVISORY_STAGE_BINDING_SET_INVALID")
        stage_bindings = {symbol: "0" * 64 for symbol in REQUIRED_SYMBOLS}
    try:
        news = verify_runtime_news_guard_receipt(
            news_guard_receipt,
            expected_provider_id=expected_news_provider_id,
            expected_key_id=expected_news_key_id,
            expected_account_id_sha256=expected_account_id_sha256,
            expected_server=expected_server,
            expected_environment="DEMO",
            expected_config_sha256=expected_config_sha256,
            key_provider=news_key_provider,
            now=trusted_now,
        )
        artifacts.append(news.content_sha256)
        if not news.news_feed_fresh:
            blockers.append("LIVE_NEWS_UNAVAILABLE_OR_STALE")
        if news.news_blackout_active:
            blockers.append("NEWS_BLACKOUT_ACTIVE")
        if news.rollover_blackout_active:
            blockers.append("ROLLOVER_BLACKOUT_ACTIVE")
        news_hash = news.content_sha256
        expires = news.valid_until_utc
        observed = news.observed_at_utc
    except Exception:
        blockers.append("SIGNED_NEWS_GUARD_INVALID_OR_STALE")
        news_hash = "0" * 64
        expires = None
        observed = trusted_now
    by_symbol: dict[str, AIAdvisoryReceipt] = {}
    if len(receipts) != len(REQUIRED_SYMBOLS):
        blockers.append("AI_ADVISORY_FOUR_SYMBOL_COVERAGE_REQUIRED")
    for receipt in receipts:
        symbol = str(getattr(receipt, "symbol", "")).upper()
        if symbol in by_symbol:
            blockers.append("AI_ADVISORY_DUPLICATE_SYMBOL")
            continue
        by_symbol[symbol] = receipt
        try:
            if (
                getattr(receipt, "issuer_id", None) != expected_advisory_issuer_id
                or getattr(receipt, "key_id", None) != expected_advisory_key_id
            ):
                raise ValueError("unexpected advisory signer")
            verified = verify_ai_advisory_receipt(
                receipt,
                expected_account_id_sha256=expected_account_id_sha256,
                expected_server=expected_server,
                expected_environment="DEMO",
                expected_execution_scope="DEMO_AUTO_VETO_ONLY",
                expected_policy_sha256=expected_policy_sha256,
                expected_news_guard_receipt_sha256=news_hash,
                expected_stage_binding_sha256=stage_bindings.get(symbol, "0" * 64),
                key_provider=advisory_key_provider,
                now=trusted_now,
            )
            artifacts.append(verified.content_sha256)
            if verified.model != expected_model:
                blockers.append(f"AI_MODEL_BINDING_MISMATCH:{symbol}")
            if verified.status not in {"APPROVED", "VETOED"}:
                blockers.append(f"AI_ADVISORY_UNHEALTHY:{symbol}")
            observed = max(observed, verified.generated_at_utc)
            expires = (
                verified.valid_until_utc
                if expires is None
                else min(expires, verified.valid_until_utc)
            )
        except Exception:
            blockers.append(f"AI_ADVISORY_RECEIPT_INVALID:{symbol or 'UNKNOWN'}")
    if set(by_symbol) != set(REQUIRED_SYMBOLS):
        blockers.append("AI_ADVISORY_FOUR_SYMBOL_COVERAGE_REQUIRED")
    if not artifacts:
        artifacts.append(canonical_sha256({"gate": "AI_NEWS_ADVISORY", "state": "invalid"}))
    return _gate(
        "AI_NEWS_ADVISORY",
        "ai_advisory_receipt+runtime_supervisor_news_guard",
        artifacts,
        blockers,
        observed,
        expires,
    )


def verify_soak_gate(
    assessment: FinexSoakReadinessAssessment,
    *,
    now: datetime,
) -> VerifiedGateResult:
    trusted_now = require_utc("now", now)
    if type(assessment) is not FinexSoakReadinessAssessment:
        raise FinexDemoAutoReadinessError("exact FINEX soak assessment is required")
    blockers = list(assessment.blocker_codes)
    if trusted_now > assessment.receipt_valid_until_utc:
        blockers.append("SOAK_ASSESSMENT_SOURCE_EXPIRED")
    if not assessment.soak_criteria_met:
        blockers.append("SOAK_PORTFOLIO_CRITERIA_INCOMPLETE")
    return _gate(
        "SOAK_PORTFOLIO",
        "finex_soak_readiness.assess_finex_soak_readiness",
        (assessment.content_sha256,),
        blockers,
        assessment.assessed_at_utc,
        assessment.receipt_valid_until_utc,
    )


def verify_strategy_portfolio_gate(
    receipt: FinexStrategyPortfolioReceipt,
    *,
    expected_portfolio_id: str,
    expected_account_alias_sha256: str,
    expected_journal_sha256: str,
    expected_commit_sha: str,
    expected_build_manifest_sha256: str,
    expected_issuer_id: str,
    expected_key_id: str,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
) -> VerifiedGateResult:
    trusted_now = require_utc("now", now)
    blockers: list[str] = []
    try:
        verified = verify_finex_strategy_portfolio_receipt(
            receipt,
            expected_portfolio_id=expected_portfolio_id,
            expected_account_alias_sha256=expected_account_alias_sha256,
            expected_journal_sha256=expected_journal_sha256,
            expected_commit_sha=expected_commit_sha,
            expected_build_manifest_sha256=expected_build_manifest_sha256,
            expected_issuer_id=expected_issuer_id,
            expected_key_id=expected_key_id,
            key_provider=key_provider,
            now=trusted_now,
        )
        observed = verified.issued_at_utc
        expires = verified.valid_until_utc
    except Exception:
        blockers.append("STRATEGY_PORTFOLIO_RECEIPT_INVALID_OR_STALE")
        observed = trusted_now
        expires = None
    return _gate(
        "STRATEGY_PORTFOLIO",
        "finex_strategy_portfolio.verify_finex_strategy_portfolio_receipt",
        (receipt.content_sha256,),
        blockers,
        observed,
        expires,
    )


def verify_release_identity_gate(
    reproducibility_receipt: WindowsReproducibilityReceipt,
    release_trust_receipt: VerifiedReleaseTrustReceipt,
    *,
    expected_git_commit: str,
    expected_git_tree: str,
    expected_archive_sha256: str,
    expected_manifest_sha256: str,
    expected_release_identity_sha256: str,
    expected_release_profile: str,
    reproducibility_key_provider: Callable[[str], str | bytes],
    now: datetime,
) -> VerifiedGateResult:
    trusted_now = require_utc("now", now)
    blockers: list[str] = []
    try:
        if not verify_reproducibility_receipt(
            reproducibility_receipt,
            key_provider=reproducibility_key_provider,
            checked_at=trusted_now,
        ):
            raise ValueError("reproducibility signature is invalid")
        if type(release_trust_receipt) is not VerifiedReleaseTrustReceipt:
            raise TypeError("release trust receipt is not sealed")
        reproduction_bindings = (
            reproducibility_receipt.git_commit == expected_git_commit,
            reproducibility_receipt.git_tree == expected_git_tree,
            reproducibility_receipt.archive_sha256 == expected_archive_sha256,
            reproducibility_receipt.manifest_sha256 == expected_manifest_sha256,
            reproducibility_receipt.release_identity_sha256
            == expected_release_identity_sha256,
            reproducibility_receipt.first_host_alias_sha256
            != reproducibility_receipt.second_host_alias_sha256,
            reproducibility_receipt.live_allowed is False,
            reproducibility_receipt.safe_to_demo_auto_order is False,
            reproducibility_receipt.promotion_eligible is False,
            reproducibility_receipt.max_lot == 0.01,
        )
        binding = release_trust_receipt.binding
        trust_bindings = (
            release_trust_receipt.release_trust_verified is True,
            release_trust_receipt.release_binding_sha256 == binding.content_sha256,
            binding.release_identity_sha256 == expected_release_identity_sha256,
            binding.git_commit == expected_git_commit,
            binding.git_tree == expected_git_tree,
            binding.release_profile == expected_release_profile,
            release_trust_receipt.live_allowed is False,
            release_trust_receipt.safe_to_demo_auto_order is False,
            release_trust_receipt.promotion_eligible is False,
            release_trust_receipt.execution_authority_granted is False,
            release_trust_receipt.stage_authority_granted is False,
            release_trust_receipt.max_lot == 0.01,
            release_trust_receipt.verified_at_utc
            <= trusted_now
            < release_trust_receipt.expires_at_utc,
            reproducibility_receipt.issued_at_utc
            <= trusted_now
            <= reproducibility_receipt.issued_at_utc + RELEASE_EVIDENCE_MAX_AGE,
        )
        if not all(reproduction_bindings) or not all(trust_bindings):
            blockers.append("RELEASE_IDENTITY_BINDING_OR_CUSTODY_INVALID")
        observed = max(
            reproducibility_receipt.issued_at_utc,
            release_trust_receipt.verified_at_utc,
        )
        expires = min(
            reproducibility_receipt.issued_at_utc + RELEASE_EVIDENCE_MAX_AGE,
            release_trust_receipt.expires_at_utc,
        )
        artifacts = (
            reproducibility_receipt.content_sha256,
            release_trust_receipt.content_sha256,
        )
    except Exception:
        blockers.append("RELEASE_IDENTITY_RECEIPT_INVALID_OR_STALE")
        observed = trusted_now
        expires = None
        artifacts = (
            canonical_sha256({"gate": "RELEASE_IDENTITY", "state": "invalid"}),
        )
    return _gate(
        "RELEASE_IDENTITY",
        "release_reproducibility+signed_release_trust",
        artifacts,
        blockers,
        observed,
        expires,
    )


def verify_risk_controls_gate(
    receipts: Iterable[RiskStateReceipt],
    *,
    expected_account_id_sha256: str,
    expected_server: str,
    expected_journal_sha256: str,
    expected_account_currency: str,
    expected_broker_spec_sha256: Mapping[str, str],
    key_provider: Callable[[str], str | bytes],
    now: datetime,
) -> VerifiedGateResult:
    trusted_now = require_utc("now", now)
    rows = tuple(receipts)
    blockers: list[str] = []
    artifacts: list[str] = []
    if set(expected_broker_spec_sha256) != set(REQUIRED_SYMBOLS):
        raise FinexDemoAutoReadinessError("risk broker spec symbol set is incomplete")
    expected_specs = {
        require_hash("broker_spec_sha256", value)
        for value in expected_broker_spec_sha256.values()
    }
    if len(expected_specs) != len(REQUIRED_SYMBOLS) or len(rows) != len(REQUIRED_SYMBOLS):
        blockers.append("RISK_STATE_FOUR_SPEC_COVERAGE_REQUIRED")
    observed = trusted_now
    expires: datetime | None = None
    seen_specs: set[str] = set()
    for receipt in rows:
        try:
            if not verify_risk_state_receipt(receipt, key_provider):
                raise ValueError("risk state signature is invalid")
            binding = receipt.binding
            if (
                binding.account_id_sha256 != expected_account_id_sha256
                or binding.server != expected_server
                or binding.environment != "DEMO"
                or binding.journal_sha256 != expected_journal_sha256
                or binding.account_currency != expected_account_currency
                or binding.broker_spec_sha256 not in expected_specs
            ):
                raise ValueError("risk state binding mismatch")
            if (
                receipt.source_verified is not True
                or receipt.source_evidence_count <= 0
                or receipt.loss_latch_active
                or not receipt.issued_at_utc
                <= trusted_now
                < receipt.issued_at_utc + RISK_STATE_MAX_AGE
            ):
                raise ValueError("risk state is unsafe or stale")
            seen_specs.add(binding.broker_spec_sha256)
            artifacts.append(receipt.content_sha256)
            observed = min(observed, receipt.issued_at_utc)
            candidate_expiry = receipt.issued_at_utc + RISK_STATE_MAX_AGE
            expires = candidate_expiry if expires is None else min(expires, candidate_expiry)
        except Exception:
            blockers.append("RISK_STATE_RECEIPT_INVALID_UNSAFE_OR_STALE")
    if seen_specs != expected_specs:
        blockers.append("RISK_STATE_FOUR_SPEC_COVERAGE_REQUIRED")
    if not artifacts:
        artifacts.append(canonical_sha256({"gate": "RISK_CONTROLS", "state": "invalid"}))
    return _gate(
        "RISK_CONTROLS",
        "risk_ledger.verify_risk_state_receipt",
        artifacts,
        blockers,
        observed,
        expires,
    )


def verify_reconciliation_gate(
    receipt: BrokerReconciliationReceipt,
    result: ReconciliationResult,
    *,
    expected_account_id_sha256: str,
    expected_server: str,
    expected_journal_sha256: str,
    expected_provider_id: str,
    expected_key_id: str,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
    prior_receipt: BrokerReconciliationReceipt | None = None,
) -> VerifiedGateResult:
    trusted_now = require_utc("now", now)
    blockers: list[str] = []
    try:
        verified = verify_broker_reconciliation_receipt(
            receipt,
            expected_result=result,
            expected_account_id_sha256=expected_account_id_sha256,
            expected_server=expected_server,
            expected_environment="DEMO",
            expected_journal_sha256=expected_journal_sha256,
            expected_provider_id=expected_provider_id,
            expected_key_id=expected_key_id,
            key_provider=key_provider,
            now=trusted_now,
            prior_receipt=prior_receipt,
        )
        if (
            result.uncertain_intents
            or result.orphan_position_tickets
            or result.orphan_order_tickets
            or result.protection_failures
            or result.volume_failures
            or result.binding_failures
            or result.kill_switch_latched
        ):
            blockers.append("RECONCILIATION_NOT_CLEAN")
        observed = verified.observed_at_utc
        expires = verified.observed_at_utc + BROKER_RECONCILIATION_RECEIPT_MAX_AGE
        result_payload = (
            result
            if hasattr(result, "__dataclass_fields__")
            else vars(result)
        )
        artifacts = (verified.content_sha256, canonical_sha256(result_payload))
    except Exception:
        blockers.append("RECONCILIATION_RECEIPT_INVALID_OR_STALE")
        observed = trusted_now
        expires = None
        artifacts = (canonical_sha256({"gate": "RECONCILIATION", "state": "invalid"}),)
    return _gate(
        "RECONCILIATION",
        "reconciliation.verify_broker_reconciliation_receipt",
        artifacts,
        blockers,
        observed,
        expires,
    )


def verify_kill_switch_gate(
    receipt: FinexKillSwitchDrillReceipt,
    *,
    journal_path: str,
    expected_account_id_sha256: str,
    expected_server: str,
    expected_release_identity_sha256: str,
    expected_release_manifest_sha256: str,
    expected_commit_sha: str,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
) -> VerifiedGateResult:
    trusted_now = require_utc("now", now)
    blockers: list[str] = []
    try:
        verified = verify_kill_switch_drill_receipt(
            receipt,
            journal_path=journal_path,
            expected_account_id_sha256=expected_account_id_sha256,
            expected_server=expected_server,
            expected_release_identity_sha256=expected_release_identity_sha256,
            expected_release_manifest_sha256=expected_release_manifest_sha256,
            expected_commit_sha=expected_commit_sha,
            key_provider=key_provider,
            now=trusted_now,
        )
        observed = verified.completed_at_utc
        expires = verified.valid_until_utc
        artifacts = (verified.content_sha256, verified.journal_state_sha256)
    except Exception:
        blockers.append("KILL_SWITCH_DRILL_INVALID_UNSAFE_OR_STALE")
        observed = trusted_now
        expires = None
        artifacts = (
            canonical_sha256({"gate": "KILL_SWITCH", "state": "invalid"}),
        )
    return _gate(
        "KILL_SWITCH",
        "finex_kill_switch_drill.verify_kill_switch_drill_receipt",
        artifacts,
        blockers,
        observed,
        expires,
    )


def verify_human_approval_gate(
    authorizations: Iterable[StageReadinessAuthorization],
    strategy_portfolio: FinexStrategyPortfolioReceipt,
    *,
    approval_key_provider: Callable[[str], str | bytes],
    stage_key_provider: Callable[[str], str | bytes],
    now: datetime,
) -> VerifiedGateResult:
    trusted_now = require_utc("now", now)
    rows = tuple(authorizations)
    blockers: list[str] = []
    artifacts: list[str] = [strategy_portfolio.content_sha256]
    observed = trusted_now
    expires: datetime | None = strategy_portfolio.valid_until_utc
    if type(strategy_portfolio) is not FinexStrategyPortfolioReceipt:
        raise FinexDemoAutoReadinessError("sealed strategy portfolio is required")
    lanes = {lane.lane_id: lane for lane in strategy_portfolio.lanes}
    if len(rows) != len(REQUIRED_SYMBOLS):
        blockers.append("FOUR_LANE_STAGE_APPROVALS_REQUIRED")
    seen_lanes: set[str] = set()
    for authorization in rows:
        try:
            if type(authorization) is not StageReadinessAuthorization:
                raise TypeError("stage authorization is not exact")
            request = authorization.request
            binding = request.binding
            lane = lanes.get(binding.lane_id)
            if lane is None or binding.lane_id in seen_lanes:
                raise ValueError("stage lane binding is invalid")
            seen_lanes.add(binding.lane_id)
            if not authorization.verify_signature(
                stage_key_provider(authorization.stage_signer_key_id)
            ):
                raise ValueError("stage signature is invalid")
            if (
                request.mode != "DEMO_AUTO"
                or not request.issued_at <= trusted_now < request.expires_at
                or request.promotion_evidence_receipt_sha256
                != lane.promotion_receipt_sha256
                or binding.server != strategy_portfolio.server
                or binding.environment != "DEMO"
                or binding.symbol != lane.symbol
                or binding.strategy != lane.strategy
                or binding.config_sha256 != lane.config_sha256
                or binding.model_artifact_sha256 != lane.model_artifact_sha256
                or binding.account_alias_sha256
                != strategy_portfolio.account_alias_sha256
                or binding.journal_sha256 != strategy_portfolio.journal_sha256
                or binding.commit_sha != strategy_portfolio.commit_sha
            ):
                raise ValueError("stage request binding mismatch")
            approvals = tuple(authorization.approvals)
            by_role = {approval.role: approval for approval in approvals}
            if set(by_role) != {"RISK_OWNER", "OPERATIONS_OWNER"} or len(approvals) != 2:
                raise ValueError("dual human approval roles are invalid")
            if (
                len({approval.approver_identity_sha256 for approval in approvals}) != 2
                or len({approval.signer_key_id for approval in approvals}) != 2
                or authorization.stage_signer_key_id
                in {approval.signer_key_id for approval in approvals}
            ):
                raise ValueError("human/stage signer custody is not independent")
            for approval in approvals:
                if type(approval) is not HumanApprovalAttestation:
                    raise TypeError("human approval is not exact")
                if (
                    not approval.verify_signature(
                        approval_key_provider(approval.signer_key_id)
                    )
                    or approval.request_sha256 != request.request_sha256
                    or approval.decision != "APPROVE_STAGE_ELIGIBILITY_REVIEW"
                    or not request.issued_at <= approval.approved_at <= trusted_now
                ):
                    raise ValueError("human approval signature/binding is invalid")
            if (
                authorization.evidence_eligibility_claimed is not True
                or authorization.execution_authorized
                or authorization.activation_authorized
                or authorization.safe_to_demo_auto_order
                or authorization.live_allowed
                or authorization.order_capability != "DISABLED"
            ):
                raise ValueError("stage approval safety contract is invalid")
            artifacts.append(authorization.content_sha256)
            observed = min(observed, request.issued_at)
            expires = request.expires_at if expires is None else min(expires, request.expires_at)
        except Exception:
            blockers.append("HUMAN_APPROVAL_OR_STAGE_BINDING_INVALID")
    if seen_lanes != set(lanes):
        blockers.append("FOUR_LANE_STAGE_APPROVALS_REQUIRED")
    return _gate(
        "HUMAN_APPROVAL_PIPELINE",
        "stage_authorization.dual_human_approval_preflight",
        artifacts,
        blockers,
        observed,
        expires,
    )


def build_readiness_report(
    manifest: Mapping[str, object],
    gate_results: Iterable[VerifiedGateResult],
    *,
    signing_key: bytes,
    now: datetime,
) -> dict[str, object]:
    validated = validate_manifest(manifest)
    trusted_now = require_utc("now", now)
    supplied = tuple(gate_results)
    if any(type(item) is not VerifiedGateResult for item in supplied):
        raise FinexDemoAutoReadinessError("only verified gate results are accepted")
    by_gate = {item.gate_id: item for item in supplied}
    if len(by_gate) != len(supplied):
        raise FinexDemoAutoReadinessError("duplicate readiness gate result")
    normalized: list[VerifiedGateResult] = []
    for gate_id in REQUIRED_GATES:
        item = by_gate.get(gate_id)
        if item is None:
            item = _gate(
                gate_id,
                "missing-evidence",
                (canonical_sha256({"gate_id": gate_id, "state": "missing"}),),
                (f"GATE_EVIDENCE_MISSING:{gate_id}",),
                trusted_now,
            )
        elif item.expires_at_utc is not None and trusted_now >= item.expires_at_utc:
            item = _gate(
                gate_id,
                item.verifier_id,
                item.artifact_sha256,
                tuple(item.blocker_codes) + (f"GATE_EVIDENCE_EXPIRED:{gate_id}",),
                item.observed_at_utc,
                item.expires_at_utc,
            )
        normalized.append(item)
    activation_review_ready = all(item.complete for item in normalized)
    blockers = tuple(
        sorted(
            set(
                blocker
                for item in normalized
                for blocker in item.blocker_codes
            )
        )
    )
    body: dict[str, object] = {
        "schema_version": REPORT_SCHEMA,
        "candidate_id": "finex",
        "operating_jurisdiction": "ID",
        "environment": "DEMO",
        "broker_server": "FinexBisnisSolusi-Demo",
        "manifest_sha256": canonical_sha256(validated),
        "generated_at_utc": _utc_text(trusted_now),
        "expires_at_utc": _utc_text(trusted_now + REPORT_MAX_AGE),
        "gates": [item.to_canonical_dict() for item in normalized],
        "blocker_codes": list(blockers),
        "status": (
            "EVIDENCE_COMPLETE_FINAL_AUTHORIZATION_REQUIRED"
            if activation_review_ready
            else "HOLD"
        ),
        "activation_review_ready": activation_review_ready,
        "authorization_granted": False,
        "activation_authorized": False,
        "execution_enabled": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
        "order_capability": "DISABLED",
        "key_id": "wincred-" + signing_key_fingerprint(signing_key),
    }
    body["report_sha256"] = canonical_sha256(body)
    body["report_hmac_sha256"] = payload_hmac_sha256(
        body, signing_key, domain=REPORT_DOMAIN
    )
    return body


def verify_readiness_report(
    report: Mapping[str, object],
    manifest: Mapping[str, object],
    *,
    signing_key: bytes,
    now: datetime,
) -> dict[str, object]:
    validated = validate_manifest(manifest)
    trusted_now = require_utc("now", now)
    if not isinstance(report, Mapping) or report.get("schema_version") != REPORT_SCHEMA:
        raise FinexDemoAutoReadinessError("readiness report schema is invalid")
    body = dict(report)
    signature = str(body.pop("report_hmac_sha256", ""))
    if not hmac.compare_digest(
        signature, payload_hmac_sha256(body, signing_key, domain=REPORT_DOMAIN)
    ):
        raise FinexDemoAutoReadinessError("readiness report signature is invalid")
    report_hash = str(body.pop("report_sha256", ""))
    if not hmac.compare_digest(report_hash, canonical_sha256(body)):
        raise FinexDemoAutoReadinessError("readiness report hash is invalid")
    generated = _utc(report.get("generated_at_utc"), "readiness generated_at")
    expires = _utc(report.get("expires_at_utc"), "readiness expires_at")
    if expires - generated != REPORT_MAX_AGE or not generated <= trusted_now < expires:
        raise FinexDemoAutoReadinessError("readiness report is invalid or expired")
    if report.get("manifest_sha256") != canonical_sha256(validated):
        raise FinexDemoAutoReadinessError("readiness manifest binding is invalid")
    gates = report.get("gates")
    if not isinstance(gates, list) or tuple(item.get("gate_id") for item in gates) != REQUIRED_GATES:
        raise FinexDemoAutoReadinessError("readiness gate set is invalid")
    blockers = report.get("blocker_codes")
    complete = all(item.get("complete") is True for item in gates)
    if not isinstance(blockers, list) or bool(blockers) == complete:
        raise FinexDemoAutoReadinessError("readiness blockers are inconsistent")
    if report.get("activation_review_ready") is not complete:
        raise FinexDemoAutoReadinessError("readiness result is inconsistent")
    if any(
        report.get(name) is not False
        for name in (
            "authorization_granted",
            "activation_authorized",
            "execution_enabled",
            "safe_to_demo_auto_order",
            "live_allowed",
        )
    ) or report.get("order_capability") != "DISABLED":
        raise FinexDemoAutoReadinessError("readiness safety contract is invalid")
    return dict(report)


__all__ = [
    "FinexDemoAutoReadinessError",
    "MANIFEST_SCHEMA",
    "READINESS_KEY_NAME",
    "REPORT_SCHEMA",
    "REQUIRED_GATES",
    "VerifiedGateResult",
    "build_readiness_report",
    "validate_manifest",
    "verify_calendar_gate",
    "verify_broker_evidence_gate",
    "verify_ai_news_gate",
    "verify_readiness_report",
    "verify_regulatory_gate",
    "verify_soak_gate",
    "verify_strategy_portfolio_gate",
    "verify_release_identity_gate",
    "verify_risk_controls_gate",
    "verify_reconciliation_gate",
    "verify_kill_switch_gate",
    "verify_human_approval_gate",
    "verify_terminal_gate",
]
