"""Operate independent FINEX calendar review signatures with OpenSSH Ed25519."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess

from live_runtime.broker_window_plan import read_json_object
from live_runtime.calendar_review import load_calendar_review_evidence
from live_runtime.finex_calendar_review_ed25519 import (
    FinexCalendarReviewEd25519Error,
    assemble_incomplete_review,
    build_request,
    sign_incomplete_review,
    verify_detached_incomplete_attestation,
)
from live_runtime.secure_files import write_json_exclusive


REPO_ROOT = Path(__file__).resolve().parent


def _path(value: Path) -> Path:
    return value if value.is_absolute() else REPO_ROOT / value


def _outside_repo(value: Path) -> Path:
    target = value.expanduser().resolve(strict=False)
    try:
        target.relative_to(REPO_ROOT)
    except ValueError:
        return target
    raise FinexCalendarReviewEd25519Error("private key must remain outside the repository")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="FINEX Ed25519 calendar review")
    commands = parser.add_subparsers(dest="command", required=True)

    generate = commands.add_parser("generate-key")
    generate.add_argument("--private-key", type=Path, required=True)

    bind = commands.add_parser("bind-request")
    bind.add_argument("--base-request", type=Path, required=True)
    bind.add_argument("--reviewer-public-key", type=Path, required=True)
    bind.add_argument("--output", type=Path, required=True)

    sign = commands.add_parser("sign")
    sign.add_argument("--candidate", required=True)
    sign.add_argument("--reviewer-id", required=True)
    sign.add_argument("--request", type=Path, required=True)
    sign.add_argument("--evidence", type=Path, required=True)
    sign.add_argument("--reviewer-public-key", type=Path, required=True)
    sign.add_argument("--private-key", type=Path, required=True)
    sign.add_argument("--output", type=Path, required=True)
    sign.add_argument("--attest-independent", action="store_true")

    assemble = commands.add_parser("assemble")
    assemble.add_argument("--candidate", required=True)
    assemble.add_argument("--request", type=Path, required=True)
    assemble.add_argument("--evidence", type=Path, required=True)
    assemble.add_argument("--receipt", type=Path, required=True)
    assemble.add_argument("--reviewer-public-key", type=Path, required=True)
    assemble.add_argument("--output", type=Path, required=True)

    detached = commands.add_parser("verify-detached")
    detached.add_argument("--candidate", required=True)
    detached.add_argument("--request", type=Path, required=True)
    detached.add_argument("--evidence", type=Path, required=True)
    detached.add_argument("--attestation", type=Path, required=True)
    detached.add_argument("--signature", type=Path, required=True)
    detached.add_argument("--reviewer-public-key", type=Path, required=True)
    detached.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "generate-key":
            private_key = _outside_repo(args.private_key)
            if private_key.exists() or Path(str(private_key) + ".pub").exists():
                raise FinexCalendarReviewEd25519Error("reviewer key path already exists")
            private_key.parent.mkdir(parents=True, exist_ok=True)
            executable = shutil.which("ssh-keygen")
            if not executable:
                raise FinexCalendarReviewEd25519Error("ssh-keygen is unavailable")
            result = subprocess.run(
                [
                    executable,
                    "-t",
                    "ed25519",
                    "-a",
                    "100",
                    "-f",
                    str(private_key),
                    "-C",
                    "putra-finex-calendar-review-v3",
                ],
                check=False,
            )
            if result.returncode != 0:
                raise FinexCalendarReviewEd25519Error("reviewer key generation failed")
            print("Private key: reviewer custody only")
            print("Public key: " + str(private_key) + ".pub")
            print("Order capability: DISABLED")
            return 0

        if args.command == "bind-request":
            base = read_json_object(_path(args.base_request))
            public_key = _path(args.reviewer_public_key).read_text(encoding="ascii")
            request = build_request(base, public_key)
            destination = write_json_exclusive(_path(args.output), request)
            print("Ed25519-bound request written: " + str(destination))
            print("Request SHA-256: " + str(request["request_sha256"]))
            print("Reviewer public-key SHA-256: " + str(request["reviewer_public_key_sha256"]))
            print("Authorization granted: false")
            print("Order capability: DISABLED")
            return 0

        if str(args.candidate).strip().lower() != "finex":
            raise FinexCalendarReviewEd25519Error("candidate must be finex")
        request = read_json_object(_path(args.request))
        evidence = load_calendar_review_evidence(_path(args.evidence))
        public_key = _path(args.reviewer_public_key).read_text(encoding="ascii")

        if args.command == "verify-detached":
            validation = verify_detached_incomplete_attestation(
                request,
                evidence,
                _path(args.attestation).read_bytes(),
                _path(args.signature).read_bytes(),
                public_key_text=public_key,
            )
            destination = write_json_exclusive(_path(args.output), validation)
            print("Detached Ed25519 validation written: " + str(destination))
            print("Signature verified: true")
            print("Decision: " + str(validation["review_outcome"]))
            print("Authorization granted: false")
            print("Order capability: DISABLED")
            return 0

        if args.command == "sign":
            receipt = sign_incomplete_review(
                request,
                evidence,
                reviewer_id=args.reviewer_id,
                public_key_text=public_key,
                private_key_path=_outside_repo(args.private_key),
                independence_attested=args.attest_independent,
            )
            destination = write_json_exclusive(_path(args.output), receipt)
            print("Ed25519 review receipt written: " + str(destination))
            print("Decision: " + str(receipt["decision"]))
            print("Private key: NOT_EXPORTED")
            print("Authorization granted: false")
            print("Order capability: DISABLED")
            return 0

        receipt = read_json_object(_path(args.receipt))
        assembled = assemble_incomplete_review(
            request,
            evidence,
            receipt,
            public_key_text=public_key,
        )
        destination = write_json_exclusive(_path(args.output), assembled)
        print("Ed25519 review assembled: " + str(destination))
        print("Decision: " + str(assembled["review_outcome"]))
        print("Future exception completeness: false")
        print("Authorization granted: false")
        print("Order capability: DISABLED")
        return 0
    except Exception as exc:
        print("FINEX_CALENDAR_REVIEW_ED25519_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
