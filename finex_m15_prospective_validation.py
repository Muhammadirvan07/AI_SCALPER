from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
from typing import Any

import pandas as pd

from live_runtime.broker_evidence_profile import load_broker_evidence_profile
from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from strategy.replay_validator import (
    _data_fingerprint,
    normalize_ohlcv,
    validate_symbol_dataframe,
)
from validation_evidence import create_frozen_snapshot, verify_frozen_snapshot


SYMBOLS = ("XAUUSD", "EURUSD", "USDJPY", "AUDUSD")
SNAPSHOT_DOMAIN = b"AI_SCALPER/FINEX/M15_RESEARCH_SNAPSHOT/V1\x00"
BASELINE_DOMAIN = b"AI_SCALPER/FINEX/M15_PROSPECTIVE_BASELINE/V1\x00"


class ProspectiveValidationError(RuntimeError):
    pass


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ProspectiveValidationError(f"REGULAR_JSON_REQUIRED:{path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ProspectiveValidationError(f"JSON_OBJECT_REQUIRED:{path}")
    return value


def _key(profile_config: str) -> bytes:
    profile = load_broker_evidence_profile(
        Path(profile_config).resolve(strict=True), "finex"
    )
    return WindowsEvidenceKeyStore().load(profile.key_name)


def _verify_source_manifest(root: Path, key: bytes) -> dict[str, Any]:
    manifest = _load_object(root / "FINEX_M15_RESEARCH_SNAPSHOT.json")
    signature = manifest.pop("signature_hmac_sha256", None)
    content_hash = manifest.pop("content_sha256", None)
    unsigned_bytes = _canonical_bytes(manifest)
    if content_hash != _sha256(unsigned_bytes):
        raise ProspectiveValidationError("SOURCE_CONTENT_HASH_INVALID")
    expected = hmac.new(
        key,
        SNAPSHOT_DOMAIN + unsigned_bytes,
        hashlib.sha256,
    ).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
        raise ProspectiveValidationError("SOURCE_SIGNATURE_INVALID")
    if (
        manifest.get("evidence_class") != "HISTORICAL_RESEARCH_ONLY"
        or manifest.get("future_holdout") is not False
        or manifest.get("broker_forward_credit") is not False
        or manifest.get("order_capability") != "DISABLED"
    ):
        raise ProspectiveValidationError("SOURCE_SAFETY_INVALID")
    manifest["content_sha256"] = content_hash
    manifest["signature_hmac_sha256"] = signature
    return manifest


def freeze(args: argparse.Namespace) -> dict[str, Any]:
    source_root = Path(args.source_root).resolve(strict=True)
    artifact_root = Path(args.artifact_root).resolve()
    key = _key(args.profile_config)
    source_manifest = _verify_source_manifest(source_root, key)
    manifest_files = {
        str(item["symbol"]): item for item in source_manifest.get("files", [])
    }
    if set(manifest_files) != set(SYMBOLS):
        raise ProspectiveValidationError("SOURCE_SYMBOL_SET_INVALID")

    frames: dict[str, pd.DataFrame] = {}
    sources: dict[str, dict[str, object]] = {}
    boundaries: dict[str, dict[str, object]] = {}
    kinds = {
        "XAUUSD": "SPOT_METAL_CFD",
        "EURUSD": "FOREX_SPOT_CFD",
        "USDJPY": "FOREX_SPOT_CFD",
        "AUDUSD": "FOREX_SPOT_CFD",
    }
    for symbol in SYMBOLS:
        item = manifest_files[symbol]
        relative = Path(str(item["path"]))
        if relative.is_absolute() or ".." in relative.parts:
            raise ProspectiveValidationError("SOURCE_PATH_INVALID")
        path = source_root / relative
        payload = path.read_bytes()
        if item.get("sha256") != _sha256(payload):
            raise ProspectiveValidationError(f"SOURCE_FILE_HASH_INVALID:{symbol}")
        frame = pd.read_csv(path)
        frame = normalize_ohlcv(frame, timeframe="15min")
        if len(frame) < 300:
            raise ProspectiveValidationError(f"SOURCE_ROWS_INSUFFICIENT:{symbol}")
        frames[symbol] = frame
        boundaries[symbol] = {
            "development_end_at_utc": frame.iloc[-2]["Datetime"],
            "seen_legacy_end_at_utc": frame.iloc[-1]["Datetime"],
        }
        sources[symbol] = {
            "provider_kind": "BROKER_TERMINAL_READ_ONLY_SNAPSHOT",
            "candidate_id": source_manifest["candidate_id"],
            "broker_server": source_manifest["broker_server"],
            "environment": source_manifest["environment"],
            "account_identity_sha256": source_manifest["account_identity_sha256"],
            "canonical_symbol": symbol,
            "broker_symbol": str(item["broker_symbol"]),
            "source_discovery_payload_sha256": source_manifest[
                "source_discovery_payload_sha256"
            ],
            "fresh_discovery_payload_sha256": source_manifest[
                "fresh_discovery_payload_sha256"
            ],
            "captured_at_utc": source_manifest["captured_at_utc"],
            "read_only_attestation": source_manifest["read_only_attestation"],
            "evidence_role": "HISTORICAL_RESEARCH_ONLY",
        }

    created_at = datetime.now(timezone.utc)
    frozen = create_frozen_snapshot(
        artifact_root,
        frames,
        sources,
        boundaries,
        snapshot_id=args.snapshot_id,
        created_at=created_at,
        source_class="BROKER_HISTORICAL_RESEARCH",
    )
    verification = verify_frozen_snapshot(artifact_root, args.snapshot_id)
    if verification.get("valid") is not True:
        raise ProspectiveValidationError("FROZEN_SNAPSHOT_VERIFICATION_FAILED")

    contracts: dict[str, dict[str, object]] = {}
    snapshot_dir = artifact_root / "snapshots" / args.snapshot_id
    for symbol in SYMBOLS:
        item = frozen["symbols"][symbol]
        canonical_frame = normalize_ohlcv(
            pd.read_csv(snapshot_dir / str(item["file"])),
            timeframe="15min",
        )
        contracts[symbol] = {
            "development_end_at": item["development_end_at_utc"],
            "seen_legacy_holdout_end_at": item["seen_legacy_end_at_utc"],
            "snapshot_clean_rows": int(item["rows"]),
            "snapshot_data_sha256": _data_fingerprint(canonical_frame),
        }

    unsigned = {
        "schema_version": "finex-m15-prospective-validation-baseline-v1",
        "candidate_id": "finex",
        "snapshot_id": args.snapshot_id,
        "frozen_manifest_payload_sha256": frozen["manifest_payload_sha256"],
        "source_snapshot_content_sha256": source_manifest["content_sha256"],
        "created_at_utc": created_at.isoformat(),
        "contracts": contracts,
        "future_holdout_start_policy": "FIRST_FINALIZED_M15_AFTER_SEEN_LEGACY_END",
        "future_holdout_rows_at_registration": 0,
        "promotion_eligible": False,
        "authorization_granted": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
        "order_capability": "DISABLED",
    }
    unsigned_bytes = _canonical_bytes(unsigned)
    receipt = {
        **unsigned,
        "content_sha256": _sha256(unsigned_bytes),
        "signature_hmac_sha256": hmac.new(
            key,
            BASELINE_DOMAIN + unsigned_bytes,
            hashlib.sha256,
        ).hexdigest(),
    }
    receipt_root = artifact_root / "prospective-baselines"
    receipt_root.mkdir(parents=True, exist_ok=True)
    destination = receipt_root / f"{args.snapshot_id}.json"
    try:
        with destination.open("xb") as handle:
            handle.write(_canonical_bytes(receipt))
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise ProspectiveValidationError("BASELINE_RECEIPT_ALREADY_EXISTS") from exc
    receipt["receipt_path"] = str(destination)
    return receipt


def _verify_baseline(path: Path, key: bytes) -> dict[str, Any]:
    receipt = _load_object(path)
    signature = receipt.pop("signature_hmac_sha256", None)
    content_hash = receipt.pop("content_sha256", None)
    unsigned = _canonical_bytes(receipt)
    if content_hash != _sha256(unsigned):
        raise ProspectiveValidationError("BASELINE_CONTENT_HASH_INVALID")
    expected = hmac.new(
        key,
        BASELINE_DOMAIN + unsigned,
        hashlib.sha256,
    ).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
        raise ProspectiveValidationError("BASELINE_SIGNATURE_INVALID")
    receipt["content_sha256"] = content_hash
    receipt["signature_hmac_sha256"] = signature
    return receipt


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    key = _key(args.profile_config)
    baseline = _verify_baseline(Path(args.baseline).resolve(strict=True), key)
    data_root = Path(args.data_root).resolve(strict=True)
    source_manifest = _verify_source_manifest(data_root, key)
    manifest_files = {
        str(item["symbol"]): item for item in source_manifest.get("files", [])
    }
    if set(manifest_files) != set(SYMBOLS):
        raise ProspectiveValidationError("SOURCE_SYMBOL_SET_INVALID")
    reports = []
    for symbol in SYMBOLS:
        relative_path = Path(str(manifest_files[symbol]["path"]))
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ProspectiveValidationError("SOURCE_DATA_PATH_INVALID")
        frame = pd.read_csv(data_root / relative_path)
        reports.append(
            validate_symbol_dataframe(
                symbol,
                frame,
                validation_contract=baseline["contracts"][symbol],
                timeframe="15min",
            )
        )
    output = {
        "schema_version": "finex-m15-prospective-evaluation-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_content_sha256": baseline["content_sha256"],
        "symbol_reports": reports,
        "runtime_parity_verified": False,
        "broker_forward_credit": False,
        "promotion_eligible": False,
        "authorization_granted": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
        "order_capability": "DISABLED",
    }
    Path(args.output).write_bytes(_canonical_bytes(output))
    return output


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="FINEX prospective M15 validation")
    result.add_argument(
        "--profile-config",
        default="config/broker_evidence_profiles.v1.json",
    )
    sub = result.add_subparsers(dest="command", required=True)
    freeze_parser = sub.add_parser("freeze")
    freeze_parser.add_argument("--source-root", required=True)
    freeze_parser.add_argument("--artifact-root", required=True)
    freeze_parser.add_argument(
        "--snapshot-id", default="finex-m15-development-baseline-20260830-v1"
    )
    evaluate_parser = sub.add_parser("evaluate")
    evaluate_parser.add_argument("--baseline", required=True)
    evaluate_parser.add_argument("--data-root", required=True)
    evaluate_parser.add_argument("--output", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "freeze":
            receipt = freeze(args)
            print("FINEX_M15_PROSPECTIVE_BASELINE=FROZEN")
            print(f"Content SHA-256: {receipt['content_sha256']}")
            print(f"Baseline receipt: {receipt['receipt_path']}")
            print("Future holdout rows: 0")
        else:
            report = evaluate(args)
            print("FINEX_M15_PROSPECTIVE_EVALUATION=COMPLETE")
            for item in report["symbol_reports"]:
                boundary = item.get("validation_boundaries", {})
                print(
                    f"{item['symbol']}: {item['status']} "
                    f"future_rows={boundary.get('future_holdout_rows', 0)}"
                )
        print("Promotion eligible: false")
        print("Order capability: DISABLED")
        return 0
    except Exception as exc:
        print(f"FINEX_M15_PROSPECTIVE_VALIDATION_BLOCKED:{exc}", file=sys.stderr)
        print("Order capability remains DISABLED.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
