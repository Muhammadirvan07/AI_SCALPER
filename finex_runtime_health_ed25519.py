"""Host-side FINEX runtime-health trust policy and evidence verifier."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

from live_runtime.contracts import canonical_json, require_hash
from live_runtime.finex_runtime_health_evidence import (
    ed25519_public_key_sha256,
    finex_runtime_health_evidence_from_mapping,
    normalize_ed25519_public_key,
    issue_finex_runtime_health_evidence,
    verify_finex_runtime_health_evidence,
)
from live_runtime.finex_runtime_health_trust_policy import (
    FinexRuntimeHealthTrustPolicy,
    finex_runtime_health_trust_policy_from_mapping,
)
from live_runtime.windows_external_status_monitor_persistence import (
    external_monitor_config_from_mapping,
    external_status_assessment_from_mapping,
    external_status_snapshot_from_mapping,
)


def _object(path: str | Path) -> dict[str, object]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _public_key(path: str | Path) -> str:
    return normalize_ed25519_public_key(Path(path).read_text(encoding="ascii"))


def _atomic_json(path: str | Path, value: object) -> Path:
    target = Path(path).expanduser().absolute()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + f".tmp-{os.getpid()}")
    try:
        temporary.write_text(canonical_json(value) + "\n", encoding="utf-8")
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return target


def _build_policy(args: argparse.Namespace) -> int:
    public_key = _public_key(args.public_key)
    policy = FinexRuntimeHealthTrustPolicy(
        monitor_service_id=args.monitor_service_id,
        monitor_provider_id=args.monitor_provider_id,
        heartbeat_destination_id=args.heartbeat_destination_id,
        signer_identity=args.signer_identity,
        public_key_sha256=ed25519_public_key_sha256(public_key),
    )
    output = _atomic_json(args.output, policy.to_canonical_dict())
    print(f"FINEX runtime-health trust policy written: {output}")
    print(f"Trust policy SHA-256: {policy.content_sha256}")
    print(f"Public key SHA-256: {policy.public_key_sha256}")
    print("Private key required on FINEX host: false")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0


def _verify(args: argparse.Namespace) -> int:
    policy = finex_runtime_health_trust_policy_from_mapping(_object(args.policy))
    expected = require_hash("expected_policy_sha256", args.expected_policy_sha256)
    evidence = finex_runtime_health_evidence_from_mapping(_object(args.evidence))
    projection = verify_finex_runtime_health_evidence(
        evidence,
        policy=policy,
        expected_policy_sha256=expected,
        public_key_text=_public_key(args.public_key),
        now=datetime.now(timezone.utc),
    )
    print("FINEX runtime-health evidence: VERIFIED")
    print(f"Trust policy SHA-256: {policy.content_sha256}")
    print(f"Evidence SHA-256: {projection.evidence_sha256}")
    print(f"Verified at UTC: {projection.verified_at_utc.isoformat()}")
    print("Private key loaded: false")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0


def _sign_evidence(args: argparse.Namespace) -> int:
    public_key = _public_key(args.public_key)
    config = external_monitor_config_from_mapping(_object(args.config))
    snapshot = external_status_snapshot_from_mapping(_object(args.snapshot))
    assessment = external_status_assessment_from_mapping(
        _object(args.assessment),
        config=config,
        snapshot=snapshot,
    )
    evidence = issue_finex_runtime_health_evidence(
        config=config,
        snapshot=snapshot,
        assessment=assessment,
        signer_identity=args.signer_identity,
        private_key_path=args.private_key,
        public_key_text=public_key,
    )
    output = _atomic_json(args.output, evidence.to_canonical_dict())
    print(f"FINEX runtime-health Ed25519 evidence written: {output}")
    print(f"Evidence SHA-256: {evidence.content_sha256}")
    print(f"Public key SHA-256: {evidence.public_key_sha256}")
    print("Private key exported: false")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="FINEX Ed25519 runtime-health policy and verification"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build-policy")
    build.add_argument("--public-key", required=True)
    build.add_argument("--output", required=True)
    build.add_argument(
        "--monitor-service-id", default="finex-offhost-monitor-v1"
    )
    build.add_argument(
        "--monitor-provider-id", default="finex-reviewed-monitor-provider-v1"
    )
    build.add_argument(
        "--heartbeat-destination-id", default="finex-offhost-heartbeat-v1"
    )
    build.add_argument("--signer-identity", default="finex-offhost-monitor-v1")
    build.set_defaults(handler=_build_policy)

    sign = sub.add_parser("sign-evidence")
    sign.add_argument("--config", required=True)
    sign.add_argument("--snapshot", required=True)
    sign.add_argument("--assessment", required=True)
    sign.add_argument("--private-key", required=True)
    sign.add_argument("--public-key", required=True)
    sign.add_argument("--signer-identity", default="finex-offhost-monitor-v1")
    sign.add_argument("--output", required=True)
    sign.set_defaults(handler=_sign_evidence)

    verify = sub.add_parser("verify-evidence")
    verify.add_argument("--policy", required=True)
    verify.add_argument("--expected-policy-sha256", required=True)
    verify.add_argument("--public-key", required=True)
    verify.add_argument("--evidence", required=True)
    verify.set_defaults(handler=_verify)
    return parser


def main() -> int:
    try:
        args = _parser().parse_args()
        return int(args.handler(args))
    except Exception as exc:
        print(f"FINEX_RUNTIME_HEALTH_BLOCKED: {exc}", file=sys.stderr)
        print(
            "Safety lock remains active; no broker order was submitted.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
