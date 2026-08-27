"""Cross-device Ed25519 broker regulatory review CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from live_runtime.registration_review_ed25519 import (
    ROLES,
    RegulatoryEd25519Error,
    assemble_dual_review,
    build_approved_attestation,
    build_role_request,
    canonical_bytes,
    derive_public_key,
    sign_attestation,
    verify_attestation,
)


REPO_ROOT = Path(__file__).resolve().parent


def _path(value: Path) -> Path:
    return value if value.is_absolute() else REPO_ROOT / value


def _load_json(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise RegulatoryEd25519Error("JSON input must be an object")
    return value


def _write_exclusive(path: Path, payload: bytes) -> Path:
    destination = _path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as handle:
        handle.write(payload)
        handle.flush()
    return destination


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="FINEX cross-device Ed25519 regulatory review"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    bind = commands.add_parser("bind-request")
    bind.add_argument("--candidate", required=True, choices=("finex",))
    bind.add_argument("--role", required=True, choices=tuple(sorted(ROLES)))
    bind.add_argument("--approver-id", required=True)
    bind.add_argument("--evidence", type=Path, required=True)
    bind.add_argument("--reviewer-public-key", type=Path, required=True)
    bind.add_argument("--output", type=Path, required=True)

    sign = commands.add_parser("sign")
    sign.add_argument("--request", type=Path, required=True)
    sign.add_argument("--evidence", type=Path, required=True)
    sign.add_argument("--private-key", type=Path, required=True)
    sign.add_argument("--attestation-output", type=Path, required=True)
    sign.add_argument("--signature-output", type=Path, required=True)
    sign.add_argument("--attest-independent", action="store_true")
    sign.add_argument("--attest-evidence-matches", action="store_true")
    sign.add_argument("--attest-license-record", action="store_true")

    verify = commands.add_parser("verify")
    verify.add_argument("--request", type=Path, required=True)
    verify.add_argument("--evidence", type=Path, required=True)
    verify.add_argument("--reviewer-public-key", type=Path, required=True)
    verify.add_argument("--attestation", type=Path, required=True)
    verify.add_argument("--signature", type=Path, required=True)
    verify.add_argument("--output", type=Path, required=True)

    assemble = commands.add_parser("assemble")
    assemble.add_argument("--evidence", type=Path, required=True)
    assemble.add_argument("--compliance-receipt", type=Path, required=True)
    assemble.add_argument("--legal-receipt", type=Path, required=True)
    assemble.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "bind-request":
            evidence = _load_json(_path(args.evidence))
            public_key = _path(args.reviewer_public_key).read_text(encoding="utf-8")
            payload = build_role_request(
                evidence,
                approver_role=args.role,
                approver_id=args.approver_id,
                public_key_text=public_key,
            )
            written = _write_exclusive(args.output, canonical_bytes(payload))
            print("Ed25519 regulatory request written: " + str(written))
            print("Role: " + args.role)
            print("Request SHA-256: " + str(payload["request_sha256"]))
        elif args.command == "sign":
            evidence = _load_json(_path(args.evidence))
            request = _load_json(_path(args.request))
            derived_key = derive_public_key(_path(args.private_key))
            if request.get("reviewer_public_key") != derived_key:
                raise RegulatoryEd25519Error("private key does not match request")
            attestation = build_approved_attestation(
                request,
                evidence,
                independence_attested=args.attest_independent,
                evidence_matches_sources_attested=args.attest_evidence_matches,
                license_record_verified_attested=args.attest_license_record,
            )
            attestation_bytes = canonical_bytes(attestation)
            signature = sign_attestation(attestation_bytes, _path(args.private_key))
            attestation_path = _write_exclusive(
                args.attestation_output, attestation_bytes
            )
            signature_path = _write_exclusive(args.signature_output, signature)
            print("Ed25519 regulatory attestation written: " + str(attestation_path))
            print("Detached signature written: " + str(signature_path))
        elif args.command == "verify":
            evidence = _load_json(_path(args.evidence))
            request = _load_json(_path(args.request))
            receipt = verify_attestation(
                request,
                evidence,
                _path(args.attestation).read_bytes(),
                _path(args.signature).read_bytes(),
                public_key_text=_path(args.reviewer_public_key).read_text(
                    encoding="utf-8"
                ),
            )
            written = _write_exclusive(args.output, canonical_bytes(receipt))
            print("Ed25519 regulatory receipt written: " + str(written))
            print("Role: " + str(receipt["approver_role"]))
            print("Cryptographic verification: true")
        else:
            evidence = _load_json(_path(args.evidence))
            observation = assemble_dual_review(
                evidence,
                _load_json(_path(args.compliance_receipt)),
                _load_json(_path(args.legal_receipt)),
            )
            written = _write_exclusive(args.output, canonical_bytes(observation))
            print("Ed25519 dual regulatory observation written: " + str(written))
            print("Independent approvals: 2")
            print("Activation eligible: false")
        print("Authorization granted: false")
        print("Order capability: DISABLED")
        return 0
    except (OSError, ValueError, RegulatoryEd25519Error) as exc:
        print("REGULATORY_ED25519_REVIEW_BLOCKED: " + str(exc))
        print("Authorization granted: false")
        print("Order capability: DISABLED")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
