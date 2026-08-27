"""Operate the request-bound, deny-only FINEX calendar review v2 flow."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.broker_window_plan import read_json_object
from live_runtime.calendar_review import load_calendar_review_evidence
from live_runtime.evidence_credentials import (
    WindowsEvidenceKeyStore,
    signing_key_fingerprint,
)
from live_runtime.finex_calendar_review_v2 import (
    DECISION,
    FinexCalendarReviewV2Error,
    KEY_ID,
    assemble_incomplete_review,
    sign_incomplete_review,
    validate_request,
)
from live_runtime.secure_files import write_json_exclusive


REPO_ROOT = Path(__file__).resolve().parent


def _path(value: Path) -> Path:
    return value if value.is_absolute() else REPO_ROOT / value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="FINEX request-bound deny-only calendar review v2"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("setup-key", help="Provision the reviewer-owned v2 key")

    sign = commands.add_parser("sign", help="Sign an incomplete review receipt")
    sign.add_argument("--candidate", required=True)
    sign.add_argument("--reviewer-id", required=True)
    sign.add_argument("--request", type=Path, required=True)
    sign.add_argument("--evidence", type=Path, required=True)
    sign.add_argument("--output", type=Path, required=True)
    sign.add_argument(
        "--attest-independent",
        action="store_true",
        help="Reviewer attests they are not operator, developer, or evidence collector",
    )

    assemble = commands.add_parser("assemble", help="Verify and assemble the v2 review")
    assemble.add_argument("--candidate", required=True)
    assemble.add_argument("--request", type=Path, required=True)
    assemble.add_argument("--evidence", type=Path, required=True)
    assemble.add_argument("--receipt", type=Path, required=True)
    assemble.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "setup-key":
            key, created = WindowsEvidenceKeyStore().ensure(KEY_ID)
            print("Key status: " + ("CREATED" if created else "EXISTING"))
            print("Key ID: " + KEY_ID)
            print("Key fingerprint: wincred-" + signing_key_fingerprint(key))
            print("Secret material: NOT_EXPORTED")
            print("Order capability: DISABLED")
            return 0

        if str(args.candidate).strip().lower() != "finex":
            raise FinexCalendarReviewV2Error("candidate must be finex")
        request = validate_request(read_json_object(_path(args.request)))
        evidence = load_calendar_review_evidence(_path(args.evidence))
        store = WindowsEvidenceKeyStore()

        if args.command == "sign":
            key = store.load(KEY_ID)
            receipt = sign_incomplete_review(
                request,
                evidence,
                reviewer_id=args.reviewer_id,
                key_id=KEY_ID,
                signing_key=key,
                independence_attested=args.attest_independent,
            )
            destination = write_json_exclusive(_path(args.output), receipt)
            print("FINEX calendar review v2 receipt written: " + str(destination))
            print("Decision: " + DECISION)
            print("Request SHA-256: " + str(receipt["request_sha256"]))
            print("Key ID: " + KEY_ID)
            print("Reviewer independence attested: true")
            print("Authorization granted: false")
            print("Order capability: DISABLED")
            return 0

        receipt = read_json_object(_path(args.receipt))
        assembled = assemble_incomplete_review(
            request,
            evidence,
            receipt,
            key_provider=store.load,
        )
        destination = write_json_exclusive(_path(args.output), assembled)
        print("FINEX calendar review v2 assembled: " + str(destination))
        print("Decision: " + DECISION)
        print("Future exception completeness: false")
        print("Authorization granted: false")
        print("Order capability: DISABLED")
        return 0
    except Exception as exc:
        print("FINEX_CALENDAR_REVIEW_V2_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
