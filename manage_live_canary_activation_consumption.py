"""Operate one target-bound, deny-only LIVE-canary replay registry.

The workflow consumes no broker capability and does not modify the central
LIVE lock.  Secrets are loaded only from Windows Credential Manager.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.live_canary_activation_artifacts import (
    load_live_canary_activation_authorization_artifact,
    verify_live_canary_activation_authorization_artifact,
    verify_live_canary_activation_request_artifact,
)
from live_runtime.live_canary_activation_cli_support import (
    DenyOnlyArgumentParser,
    LiveCanaryRequestSourceInputs,
    add_request_source_arguments,
    load_request_source_inputs,
    rooted,
)
from live_runtime.live_canary_activation_consumption import (
    LiveCanaryActivationConsumptionReceipt,
    LiveCanaryActivationConsumptionError,
    LiveCanaryReplayRegistryInitializationReceipt,
    LiveCanaryReplayRegistryProfile,
    build_live_canary_replay_registry_profile,
    consume_live_canary_activation_artifact,
    initialize_live_canary_replay_registry,
    inspect_consumed_live_canary_activation_event,
    load_live_canary_activation_consumption_receipt,
    load_live_canary_replay_checkpoint_receipt,
    load_live_canary_replay_registry_profile,
    preflight_live_canary_activation_consumption_output,
    recover_live_canary_activation_consumption_artifact,
    verify_live_canary_activation_consumption_artifact,
    write_live_canary_activation_consumption_artifact_exclusive,
)
from live_runtime.live_canary_activation import (
    LiveCanaryActivationAuthorization,
    LiveCanaryGateReceipt,
)
from live_runtime.live_canary_gate_receipt_artifacts import (
    load_live_canary_binding,
    load_live_canary_trust_policy,
    verify_live_canary_gate_receipt_set,
)


UTC = timezone.utc
REPO_ROOT = Path(__file__).resolve().parent


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _output(path: Path) -> Path:
    return preflight_live_canary_activation_consumption_output(
        rooted(REPO_ROOT, path)
    )


def _add_profile_use_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--expected-profile-sha256", required=True)
    parser.add_argument("--registry-path", type=Path, required=True)


def _add_consumption_arguments(
    parser: argparse.ArgumentParser,
    *,
    receipt: bool = False,
    output: bool = False,
) -> None:
    _add_profile_use_arguments(parser)
    parser.add_argument("--predecessor-receipt", type=Path, required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    add_request_source_arguments(parser)
    if receipt:
        parser.add_argument("--receipt", type=Path, required=True)
    if output:
        parser.add_argument("--output", type=Path, required=True)


def _parser() -> DenyOnlyArgumentParser:
    parser = DenyOnlyArgumentParser(
        description=(
            "Prepare, initialize, consume, verify, or recover one deny-only "
            "LIVE-canary activation replay registry"
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare-profile")
    prepare.add_argument("--binding", type=Path, required=True)
    prepare.add_argument("--trust-policy", type=Path, required=True)
    prepare.add_argument("--registry-path", type=Path, required=True)
    prepare.add_argument("--profile-id", required=True)
    prepare.add_argument("--registry-id", required=True)
    prepare.add_argument("--registry-key-id", required=True)
    prepare.add_argument("--registry-key-fingerprint-sha256", required=True)
    prepare.add_argument("--output", type=Path, required=True)

    initialize = commands.add_parser("initialize")
    _add_profile_use_arguments(initialize)
    initialize.add_argument("--binding", type=Path, required=True)
    initialize.add_argument("--trust-policy", type=Path, required=True)
    initialize.add_argument("--output", type=Path, required=True)

    consume = commands.add_parser("consume")
    _add_consumption_arguments(consume, output=True)

    verify = commands.add_parser("verify")
    _add_consumption_arguments(verify, receipt=True)

    recover = commands.add_parser("recover")
    _add_consumption_arguments(recover, output=True)
    return parser


def _load_verified_consumption_sources(
    args: argparse.Namespace,
    *,
    store: WindowsEvidenceKeyStore,
    authorization: LiveCanaryActivationAuthorization,
    verification_time: datetime,
) -> tuple[
    LiveCanaryActivationAuthorization,
    LiveCanaryRequestSourceInputs,
    tuple[LiveCanaryGateReceipt, ...],
]:
    sources = load_request_source_inputs(
        args,
        repo_root=REPO_ROOT,
        key_provider=store.load,
        now=verification_time,
    )
    verified_request = verify_live_canary_activation_request_artifact(
        authorization.request,
        **sources.verification_kwargs(store.load, lambda: verification_time),
    )
    verified_authorization = verify_live_canary_activation_authorization_artifact(
        authorization,
        request=verified_request,
        approvals=authorization.approvals,
        trust_policy=sources.trust_policy,
        approval_key_provider=store.load,
        deployment_key_provider=store.load,
        clock_provider=lambda: verification_time,
    )
    gate_receipts = verify_live_canary_gate_receipt_set(
        sources.gate_receipt_set_path,
        sources.binding,
        sources.trust_policy,
        evidence_paths_by_domain=sources.gate_evidence_paths_by_domain,
        eligibility_evidence=sources.broker_eligibility_evidence,
        key_provider=store.load,
        now=verification_time,
        required_until=verified_authorization.request.expires_at,
        clock_provider=lambda: verification_time,
        worm_custody_policy_sha256=sources.worm_custody_policy_sha256,
    )
    return verified_authorization, sources, gate_receipts


def _consumption_kwargs(
    args: argparse.Namespace,
    *,
    store: WindowsEvidenceKeyStore,
    now: datetime,
    historical: bool,
) -> dict[str, object]:
    profile = load_live_canary_replay_registry_profile(
        rooted(REPO_ROOT, args.profile)
    )
    predecessor = load_live_canary_replay_checkpoint_receipt(
        rooted(REPO_ROOT, args.predecessor_receipt)
    )
    authorization = load_live_canary_activation_authorization_artifact(
        rooted(REPO_ROOT, args.authorization)
    )
    verification_time = now
    if historical:
        binding = load_live_canary_binding(rooted(REPO_ROOT, args.binding))
        policy = load_live_canary_trust_policy(
            rooted(REPO_ROOT, args.trust_policy)
        )
        event = inspect_consumed_live_canary_activation_event(
            profile=profile,
            expected_profile_sha256=args.expected_profile_sha256,
            registry_path=args.registry_path,
            binding=binding,
            trust_policy=policy,
            predecessor_checkpoint=predecessor,
            registry_key_provider=store.load,
            checkpoint_key_provider=store.load,
            authorization=authorization,
            clock_provider=lambda: now,
        )
        verification_time = event.checked_at
    authorization, sources, gate_receipts = _load_verified_consumption_sources(
        args,
        store=store,
        authorization=authorization,
        verification_time=verification_time,
    )
    return {
        "profile": profile,
        "expected_profile_sha256": args.expected_profile_sha256,
        "registry_path": args.registry_path,
        "binding": sources.binding,
        "predecessor_checkpoint": predecessor,
        "registry_key_provider": store.load,
        "checkpoint_key_provider": store.load,
        "authorization": authorization,
        "trust_policy": sources.trust_policy,
        "soak_receipt": sources.soak_receipt,
        "soak_binding": sources.soak_binding,
        "soak_key_provider": store.load,
        "promotion_evidence": sources.promotion_evidence,
        "promotion_key_provider": store.load,
        "live_account_alias": sources.live_account_alias,
        "broker_eligibility_evidence": sources.broker_eligibility_evidence,
        "gate_receipts": gate_receipts,
        "gate_key_provider": store.load,
        "approval_key_provider": store.load,
        "deployment_key_provider": store.load,
        "clock_provider": lambda: now,
    }


def _prepare_profile(
    args: argparse.Namespace, now: datetime
) -> tuple[LiveCanaryReplayRegistryProfile, Path]:
    del now
    destination = _output(args.output)
    binding = load_live_canary_binding(rooted(REPO_ROOT, args.binding))
    policy = load_live_canary_trust_policy(rooted(REPO_ROOT, args.trust_policy))
    store = WindowsEvidenceKeyStore()
    profile = build_live_canary_replay_registry_profile(
        profile_id=args.profile_id,
        binding=binding,
        trust_policy=policy,
        registry_path=args.registry_path,
        registry_id=args.registry_id,
        registry_key_id=args.registry_key_id,
        expected_registry_key_fingerprint_sha256=(
            args.registry_key_fingerprint_sha256
        ),
        key_provider=store.load,
    )
    write_live_canary_activation_consumption_artifact_exclusive(
        destination, profile.to_canonical_dict()
    )
    return profile, destination


def _initialize(
    args: argparse.Namespace, now: datetime
) -> tuple[LiveCanaryReplayRegistryInitializationReceipt, Path]:
    destination = _output(args.output)
    profile = load_live_canary_replay_registry_profile(
        rooted(REPO_ROOT, args.profile)
    )
    binding = load_live_canary_binding(rooted(REPO_ROOT, args.binding))
    policy = load_live_canary_trust_policy(rooted(REPO_ROOT, args.trust_policy))
    store = WindowsEvidenceKeyStore()
    receipt = initialize_live_canary_replay_registry(
        profile=profile,
        expected_profile_sha256=args.expected_profile_sha256,
        registry_path=args.registry_path,
        binding=binding,
        trust_policy=policy,
        key_provider=store.load,
        clock_provider=lambda: now,
    )
    write_live_canary_activation_consumption_artifact_exclusive(
        destination, receipt.to_canonical_dict()
    )
    return receipt, destination


def _consume(
    args: argparse.Namespace, now: datetime
) -> tuple[LiveCanaryActivationConsumptionReceipt, Path]:
    destination = _output(args.output)
    store = WindowsEvidenceKeyStore()
    receipt = consume_live_canary_activation_artifact(
        **_consumption_kwargs(args, store=store, now=now, historical=False)
    )
    write_live_canary_activation_consumption_artifact_exclusive(
        destination, receipt.to_canonical_dict()
    )
    return receipt, destination


def _verify(
    args: argparse.Namespace, now: datetime
) -> LiveCanaryActivationConsumptionReceipt:
    receipt = load_live_canary_activation_consumption_receipt(
        rooted(REPO_ROOT, args.receipt)
    )
    store = WindowsEvidenceKeyStore()
    return verify_live_canary_activation_consumption_artifact(
        receipt=receipt,
        **_consumption_kwargs(args, store=store, now=now, historical=True),
    )


def _recover(
    args: argparse.Namespace, now: datetime
) -> tuple[LiveCanaryActivationConsumptionReceipt, Path]:
    destination = _output(args.output)
    store = WindowsEvidenceKeyStore()
    receipt = recover_live_canary_activation_consumption_artifact(
        **_consumption_kwargs(args, store=store, now=now, historical=True)
    )
    write_live_canary_activation_consumption_artifact_exclusive(
        destination, receipt.to_canonical_dict()
    )
    return receipt, destination


def _blocked_reason(exc: Exception) -> str:
    if type(exc) is LiveCanaryActivationConsumptionError:
        return exc.reason_code
    if isinstance(exc, FileExistsError):
        return "LIVE_CANARY_OUTPUT_ALREADY_EXISTS"
    if isinstance(exc, ValueError) and str(exc) == "command arguments are invalid":
        return "LIVE_CANARY_CONSUMPTION_ARGUMENTS_INVALID"
    return "LIVE_CANARY_ACTIVATION_CONSUMPTION_REJECTED"


def _locked_state() -> None:
    print("Live allowed: false")
    print("Activation authorized: false")
    print("Order capability: DISABLED")
    print("Broker mutation: NOT_PERFORMED")


def _receipt_success(
    label: str,
    receipt: (
        LiveCanaryReplayRegistryInitializationReceipt
        | LiveCanaryActivationConsumptionReceipt
    ),
    destination: Path | None,
) -> None:
    print(label)
    print("Profile SHA-256: " + receipt.profile_sha256)
    if hasattr(receipt, "authorization_id"):
        print("Authorization ID: " + receipt.authorization_id)
        print("Authorization SHA-256: " + receipt.authorization_sha256)
        print("Validation SHA-256: " + receipt.validation.content_sha256)
        print("Event count: " + str(receipt.event_count))
    print("Checkpoint SHA-256: " + receipt.checkpoint.content_sha256)
    print("Secret material: NOT_EXPORTED")
    _locked_state()
    if destination is not None:
        print("Output: " + str(destination))


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
        now = _utc_now()
        if args.command == "prepare-profile":
            profile, destination = _prepare_profile(args, now)
            print("LIVE_CANARY_REPLAY_PROFILE_PREPARED")
            print("Profile ID: " + profile.profile_id)
            print("Profile SHA-256: " + profile.content_sha256)
            print("Registry ID: " + profile.registry_id)
            print("Secret material: NOT_EXPORTED")
            _locked_state()
            print("Output: " + str(destination))
            return 0
        if args.command == "initialize":
            receipt, destination = _initialize(args, now)
            _receipt_success(
                "LIVE_CANARY_REPLAY_REGISTRY_INITIALIZED",
                receipt,
                destination,
            )
            return 0
        if args.command == "consume":
            receipt, destination = _consume(args, now)
            _receipt_success(
                "LIVE_CANARY_ACTIVATION_CONSUMED_ONCE", receipt, destination
            )
            return 0
        if args.command == "verify":
            receipt = _verify(args, now)
            _receipt_success(
                "LIVE_CANARY_ACTIVATION_CONSUMPTION_VERIFIED", receipt, None
            )
            return 0
        if args.command == "recover":
            receipt, destination = _recover(args, now)
            _receipt_success(
                "LIVE_CANARY_ACTIVATION_CONSUMPTION_RECOVERED",
                receipt,
                destination,
            )
            return 0
        raise ValueError("command arguments are invalid")
    except Exception as exc:
        print(
            "LIVE_CANARY_ACTIVATION_CONSUMPTION_BLOCKED: "
            + _blocked_reason(exc)
        )
        _locked_state()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
