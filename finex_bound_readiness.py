"""Assemble all persisted FINEX demo-auto evidence through one bound pipeline.

The command performs an eleven-gate preflight before consuming the one-use
signed release-trust receipt.  It only writes a deny-only readiness report and
never enables or submits broker orders.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from live_runtime.ai_advisory_receipt import ai_advisory_receipt_from_mapping
from live_runtime.demo_auto_soak_cohort_contracts import (
    demo_auto_soak_cohort_binding_from_mapping,
    demo_auto_soak_cohort_receipt_from_mapping,
)
from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.finex_demo_auto_readiness import READINESS_KEY_NAME
from live_runtime.finex_kill_switch_drill import kill_switch_drill_receipt_from_mapping
from live_runtime.finex_readiness_binding import finex_readiness_binding_from_mapping
from live_runtime.finex_readiness_bundle import (
    FinexReadinessEvidenceBundle,
    assemble_bound_readiness_report,
)
from live_runtime.finex_soak_readiness import assess_finex_soak_readiness
from live_runtime.finex_strategy_portfolio import (
    finex_strategy_portfolio_receipt_from_mapping,
)
from live_runtime.reconciliation import (
    broker_reconciliation_receipt_from_mapping,
    reconciliation_result_from_mapping,
)
from live_runtime.release_reproducibility import (
    windows_reproducibility_receipt_from_mapping,
)
from live_runtime.release_trust_custody import ReleaseTrustCustodyStore
from live_runtime.risk_ledger import risk_state_receipt_from_mapping
from live_runtime.runtime_supervisor import runtime_news_guard_receipt_from_mapping
from live_runtime.secure_files import write_json_exclusive
from live_runtime.signed_release_trust import (
    ReleaseTrustBinding,
    ReleaseTrustPolicy,
    SignedReleaseTrustVerifier,
    decode_signed_release_trust_receipt,
)
from live_runtime.stage_authorization import stage_readiness_authorization_from_mapping


RELEASE_ONLY_BLOCKER = "GATE_EVIDENCE_MISSING:RELEASE_IDENTITY"


def _load(path: str | Path) -> dict[str, object]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _load_release_policy(path: str) -> ReleaseTrustPolicy:
    try:
        return ReleaseTrustPolicy(**_load(path))
    except (TypeError, ValueError) as exc:
        raise ValueError("release trust policy is invalid") from exc


def _load_release_binding(path: str) -> ReleaseTrustBinding:
    try:
        return ReleaseTrustBinding(**_load(path))
    except (TypeError, ValueError) as exc:
        raise ValueError("release trust binding is invalid") from exc


def _print_report(report: dict[str, object], output: Path) -> None:
    print(f"FINEX bound readiness report written: {output.resolve()}")
    print(f"Status: {report['status']}")
    print(
        "Activation review ready: "
        + str(report["activation_review_ready"]).lower()
    )
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    for blocker in report["blocker_codes"]:
        print(f"BLOCKER: {blocker}")


def _status(args: argparse.Namespace) -> int:
    now = datetime.now(timezone.utc)
    store = WindowsEvidenceKeyStore()
    key_provider = store.load
    readiness_binding = finex_readiness_binding_from_mapping(_load(args.binding))
    cohort_binding = demo_auto_soak_cohort_binding_from_mapping(
        _load(args.soak_binding)
    )
    cohort_receipt = demo_auto_soak_cohort_receipt_from_mapping(
        _load(args.soak_receipt)
    )
    soak_assessment = assess_finex_soak_readiness(
        cohort_receipt,
        binding=cohort_binding,
        key_provider=key_provider,
        now=now,
    )
    prior_reconciliation = (
        broker_reconciliation_receipt_from_mapping(
            _load(args.prior_reconciliation_receipt)
        )
        if args.prior_reconciliation_receipt
        else None
    )
    evidence = FinexReadinessEvidenceBundle(
        regulatory_observation=_load(args.regulatory_observation),
        calendar_contract=_load(args.calendar_contract),
        calendar_report=_load(args.calendar_report),
        calendar_checkpoints=tuple(_load(path) for path in args.calendar_checkpoint),
        terminal_discovery=_load(args.terminal_discovery),
        terminal_fence=_load(args.terminal_fence),
        terminal_report=_load(args.terminal_report),
        terminal_path=args.terminal_path,
        advisory_receipts=tuple(
            ai_advisory_receipt_from_mapping(_load(path))
            for path in args.ai_advisory
        ),
        news_guard_receipt=runtime_news_guard_receipt_from_mapping(
            _load(args.news_guard)
        ),
        soak_assessment=soak_assessment,
        strategy_portfolio=finex_strategy_portfolio_receipt_from_mapping(
            _load(args.strategy_portfolio)
        ),
        reproducibility_receipt=windows_reproducibility_receipt_from_mapping(
            _load(args.reproducibility_receipt)
        ),
        release_trust_receipt=None,
        risk_receipts=tuple(
            risk_state_receipt_from_mapping(_load(path)) for path in args.risk_receipt
        ),
        reconciliation_receipt=broker_reconciliation_receipt_from_mapping(
            _load(args.reconciliation_receipt)
        ),
        reconciliation_result=reconciliation_result_from_mapping(
            _load(args.reconciliation_result)
        ),
        kill_switch_receipt=kill_switch_drill_receipt_from_mapping(
            _load(args.kill_switch_receipt)
        ),
        kill_switch_journal_path=args.kill_switch_journal,
        stage_authorizations=tuple(
            stage_readiness_authorization_from_mapping(_load(path))
            for path in args.stage_authorization
        ),
        prior_reconciliation_receipt=prior_reconciliation,
    )
    common = dict(
        expected_trust_policy_sha256=args.expected_binding_trust_policy_sha256,
        expected_binding_issuer_id=args.expected_binding_issuer_id,
        expected_binding_key_id=args.expected_binding_key_id,
        key_provider=key_provider,
        readiness_signing_key=store.load(READINESS_KEY_NAME),
        now=now,
    )
    manifest = _load(args.manifest)
    preflight = assemble_bound_readiness_report(
        manifest, readiness_binding, evidence, **common
    )
    if preflight["blocker_codes"] != [RELEASE_ONLY_BLOCKER]:
        output = write_json_exclusive(args.output, preflight)
        _print_report(preflight, output)
        return 2

    policy = _load_release_policy(args.release_trust_policy)
    release_binding = _load_release_binding(args.release_trust_binding)
    signed_receipt = decode_signed_release_trust_receipt(
        Path(args.signed_release_trust_receipt).read_text(encoding="utf-8")
    )
    with ReleaseTrustCustodyStore(
        args.release_trust_custody_db,
        policy=policy,
        custody_key_provider=key_provider,
        clock_provider=lambda: now,
    ) as custody:
        verified_release = SignedReleaseTrustVerifier(
            policy=policy,
            expected_policy_sha256=args.expected_release_trust_policy_sha256,
            issuer_key_provider=key_provider,
            custody_key_provider=key_provider,
            external_checkpoint_provider=custody.checkpoint_provider,
            external_checkpoint_cas=custody.compare_and_swap,
            external_nonce_seen_provider=custody.nonce_seen,
            clock_provider=lambda: now,
        ).verify_and_consume(signed_receipt, expected_binding=release_binding)
    final_report = assemble_bound_readiness_report(
        manifest,
        readiness_binding,
        replace(evidence, release_trust_receipt=verified_release),
        **common,
    )
    output = write_json_exclusive(args.output, final_report)
    _print_report(final_report, output)
    return 0 if final_report["activation_review_ready"] is True else 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--binding", required=True)
    parser.add_argument("--expected-binding-trust-policy-sha256", required=True)
    parser.add_argument("--expected-binding-issuer-id", required=True)
    parser.add_argument("--expected-binding-key-id", required=True)
    parser.add_argument("--regulatory-observation", required=True)
    parser.add_argument("--calendar-contract", required=True)
    parser.add_argument("--calendar-report", required=True)
    parser.add_argument("--calendar-checkpoint", action="append", required=True)
    parser.add_argument("--terminal-discovery", required=True)
    parser.add_argument("--terminal-fence", required=True)
    parser.add_argument("--terminal-report", required=True)
    parser.add_argument("--terminal-path", required=True)
    parser.add_argument("--ai-advisory", action="append", required=True)
    parser.add_argument("--news-guard", required=True)
    parser.add_argument("--soak-binding", required=True)
    parser.add_argument("--soak-receipt", required=True)
    parser.add_argument("--strategy-portfolio", required=True)
    parser.add_argument("--reproducibility-receipt", required=True)
    parser.add_argument("--release-trust-policy", required=True)
    parser.add_argument("--expected-release-trust-policy-sha256", required=True)
    parser.add_argument("--release-trust-binding", required=True)
    parser.add_argument("--signed-release-trust-receipt", required=True)
    parser.add_argument("--release-trust-custody-db", required=True)
    parser.add_argument("--risk-receipt", action="append", required=True)
    parser.add_argument("--reconciliation-receipt", required=True)
    parser.add_argument("--reconciliation-result", required=True)
    parser.add_argument("--prior-reconciliation-receipt")
    parser.add_argument("--kill-switch-receipt", required=True)
    parser.add_argument("--kill-switch-journal", required=True)
    parser.add_argument("--stage-authorization", action="append", required=True)
    parser.add_argument("--output", required=True)
    parser.set_defaults(handler=_status)
    return parser


def main() -> int:
    try:
        args = _parser().parse_args()
        return int(args.handler(args))
    except Exception as exc:
        print(f"FINEX_BOUND_READINESS_BLOCKED: {exc}", file=sys.stderr)
        print(
            "Safety lock remains active; no broker order was submitted.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
