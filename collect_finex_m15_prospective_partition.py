"""Append one verified FINEX M15 snapshot to a prospective research chain.

This collector cannot connect to MT5 and cannot submit orders.  It consumes a
separately captured, HMAC-verified read-only snapshot and persists only rows
strictly newer than the frozen legacy boundary (and the previous chain head).
The chain is prospective research evidence, not broker-forward promotion
evidence; paired tick/bar and calendar-complete evidence remain separate gates.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Mapping

import pandas as pd

from finex_m15_prospective_validation import (
    SYMBOLS,
    ProspectiveValidationError,
    _canonical_bytes,
    _key,
    _sha256,
    _verify_baseline,
    _verify_source_manifest,
)
from strategy.replay_validator import normalize_ohlcv
from validation_evidence.secure_core import (
    _atomic_directory_commit,
    _atomic_replace,
    _canonical_csv_bytes,
)


PARTITION_DOMAIN = b"AI_SCALPER_FINEX_M15_PROSPECTIVE_PARTITION_V1\0"
HEAD_DOMAIN = b"AI_SCALPER_FINEX_M15_PROSPECTIVE_HEAD_V1\0"


def _utc(value: object, field: str) -> pd.Timestamp:
    try:
        timestamp = pd.Timestamp(value)
    except (TypeError, ValueError) as exc:
        raise ProspectiveValidationError(f"{field.upper()}_INVALID") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ProspectiveValidationError(f"{field.upper()}_UTC_REQUIRED")
    return timestamp.tz_convert("UTC")


def _signed(payload: Mapping[str, Any], key: bytes, domain: bytes) -> dict[str, Any]:
    unsigned = dict(payload)
    encoded = _canonical_bytes(unsigned)
    return {
        **unsigned,
        "content_sha256": _sha256(encoded),
        "signature_hmac_sha256": hmac.new(
            key, domain + encoded, hashlib.sha256
        ).hexdigest(),
    }


def _verify_signed(
    value: object,
    key: bytes,
    domain: bytes,
    *,
    error: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProspectiveValidationError(error)
    record = dict(value)
    signature = record.pop("signature_hmac_sha256", None)
    content_hash = record.pop("content_sha256", None)
    encoded = _canonical_bytes(record)
    if not isinstance(content_hash, str) or not hmac.compare_digest(
        content_hash, _sha256(encoded)
    ):
        raise ProspectiveValidationError(error)
    expected = hmac.new(key, domain + encoded, hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
        raise ProspectiveValidationError(error)
    record["content_sha256"] = content_hash
    record["signature_hmac_sha256"] = signature
    return record


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProspectiveValidationError(f"JSON_INVALID:{path.name}") from exc


def _safe_relative(value: object) -> Path:
    relative = Path(str(value or ""))
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ProspectiveValidationError("SOURCE_DATA_PATH_INVALID")
    return relative


def _initial_last_at(baseline: Mapping[str, Any]) -> dict[str, str]:
    contracts = baseline.get("contracts")
    if not isinstance(contracts, dict) or set(contracts) != set(SYMBOLS):
        raise ProspectiveValidationError("BASELINE_CONTRACTS_INVALID")
    return {
        symbol: str(contracts[symbol]["seen_legacy_holdout_end_at"])
        for symbol in SYMBOLS
    }


def _load_head(
    path: Path,
    baseline: Mapping[str, Any],
    key: bytes,
) -> dict[str, Any]:
    if not path.exists():
        return {
            "sequence": 0,
            "last_partition_content_sha256": baseline["content_sha256"],
            "last_source_snapshot_content_sha256": None,
            "last_source_captured_at_utc": None,
            "last_at_utc": _initial_last_at(baseline),
        }
    head = _verify_signed(_load_json(path), key, HEAD_DOMAIN, error="CHAIN_HEAD_INVALID")
    if (
        head.get("schema_version") != "finex-m15-prospective-head-v1"
        or head.get("baseline_content_sha256") != baseline["content_sha256"]
        or head.get("snapshot_id") != baseline["snapshot_id"]
        or not isinstance(head.get("sequence"), int)
        or head["sequence"] < 1
        or set(head.get("last_at_utc", {})) != set(SYMBOLS)
    ):
        raise ProspectiveValidationError("CHAIN_HEAD_BINDING_INVALID")
    if "last_source_captured_at_utc" not in head:
        partition_id = head.get("last_partition_id")
        if not isinstance(partition_id, str) or not partition_id:
            raise ProspectiveValidationError("CHAIN_HEAD_CAPTURE_TIME_MISSING")
        receipt_path = path.parent / "partitions" / partition_id / "receipt.json"
        receipt = _verify_signed(
            _load_json(receipt_path),
            key,
            PARTITION_DOMAIN,
            error="CHAIN_LAST_PARTITION_INVALID",
        )
        if (
            receipt.get("content_sha256")
            != head.get("last_partition_content_sha256")
            or receipt.get("partition_id") != partition_id
            or receipt.get("sequence") != head.get("sequence")
        ):
            raise ProspectiveValidationError("CHAIN_LAST_PARTITION_BINDING_INVALID")
        head["last_source_captured_at_utc"] = receipt.get("captured_at_utc")
    _utc(head.get("last_source_captured_at_utc"), "last_source_captured_at_utc")
    return head


def ingest(args: argparse.Namespace) -> dict[str, Any]:
    key = _key(args.profile_config)
    baseline = _verify_baseline(Path(args.baseline).resolve(strict=True), key)
    source_root = Path(args.source_root).resolve(strict=True)
    source = _verify_source_manifest(source_root, key)
    source_files = {str(item["symbol"]): item for item in source.get("files", [])}
    if set(source_files) != set(SYMBOLS):
        raise ProspectiveValidationError("SOURCE_SYMBOL_SET_INVALID")

    artifact_root = Path(args.artifact_root).resolve()
    chain_root = artifact_root / "prospective-chains" / str(baseline["snapshot_id"])
    partitions_root = chain_root / "partitions"
    partitions_root.mkdir(parents=True, exist_ok=True)
    head_path = chain_root / "head.json"
    head = _load_head(head_path, baseline, key)
    source_hash = str(source["content_sha256"])
    if head.get("last_source_snapshot_content_sha256") == source_hash:
        return {
            "status": "SOURCE_ALREADY_INGESTED",
            "sequence": head["sequence"],
            "new_rows": 0,
            "head_content_sha256": head.get("content_sha256"),
        }

    captured = _utc(source.get("captured_at_utc"), "captured_at_utc")
    previous_capture = head.get("last_source_captured_at_utc")
    if previous_capture is not None and captured <= _utc(
        previous_capture, "last_source_captured_at_utc"
    ):
        raise ProspectiveValidationError("SOURCE_CAPTURE_TIME_NOT_INCREASING")
    files: dict[str, bytes] = {}
    symbols: dict[str, dict[str, Any]] = {}
    next_last_at = dict(head["last_at_utc"])
    total_rows = 0
    for symbol in SYMBOLS:
        item = source_files[symbol]
        frame = normalize_ohlcv(
            pd.read_csv(source_root / _safe_relative(item.get("path"))),
            timeframe="15min",
        )
        previous = _utc(head["last_at_utc"][symbol], f"{symbol}_previous_last")
        future = frame.loc[frame["Datetime"] > previous].reset_index(drop=True)
        relative_name: str | None = None
        file_hash: str | None = None
        first_at: str | None = None
        last_at: str | None = None
        if not future.empty:
            relative_name = f"data/{symbol.lower()}.csv"
            csv_bytes = _canonical_csv_bytes(future)
            files[relative_name] = csv_bytes
            file_hash = _sha256(csv_bytes)
            first_at = future["Datetime"].iloc[0].isoformat().replace("+00:00", "Z")
            last_at = future["Datetime"].iloc[-1].isoformat().replace("+00:00", "Z")
            next_last_at[symbol] = last_at
            total_rows += len(future)
        symbols[symbol] = {
            "broker_symbol": item["broker_symbol"],
            "rows": len(future),
            "file": relative_name,
            "file_sha256": file_hash,
            "first_at_utc": first_at,
            "last_at_utc": last_at,
            "previous_last_at_utc": head["last_at_utc"][symbol],
        }

    sequence = int(head["sequence"]) + 1
    partition_id = (
        f"{sequence:06d}-"
        f"{captured.strftime('%Y%m%dT%H%M%S%fZ')}-"
        f"{source_hash[:12]}"
    )
    receipt = _signed(
        {
            "schema_version": "finex-m15-prospective-partition-v1",
            "partition_id": partition_id,
            "sequence": sequence,
            "snapshot_id": baseline["snapshot_id"],
            "baseline_content_sha256": baseline["content_sha256"],
            "previous_partition_content_sha256": head[
                "last_partition_content_sha256"
            ],
            "source_snapshot_content_sha256": source_hash,
            "source_discovery_payload_sha256": source[
                "source_discovery_payload_sha256"
            ],
            "captured_at_utc": source["captured_at_utc"],
            "ingested_at_utc": datetime.now(timezone.utc).isoformat(),
            "timeframe": "M15",
            "symbols": symbols,
            "new_rows": total_rows,
            "evidence_class": "PROSPECTIVE_RESEARCH_ONLY",
            "calendar_gap_assessment": "PENDING_VERIFIED_SESSION_CALENDAR",
            "broker_forward_credit": False,
            "runtime_parity_verified": False,
            "promotion_eligible": False,
            "authorization_granted": False,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "order_capability": "DISABLED",
        },
        key,
        PARTITION_DOMAIN,
    )
    files["receipt.json"] = _canonical_bytes(receipt)
    _atomic_directory_commit(partitions_root, partitions_root / partition_id, files)

    new_head = _signed(
        {
            "schema_version": "finex-m15-prospective-head-v1",
            "snapshot_id": baseline["snapshot_id"],
            "baseline_content_sha256": baseline["content_sha256"],
            "sequence": sequence,
            "last_partition_id": partition_id,
            "last_partition_content_sha256": receipt["content_sha256"],
            "last_source_snapshot_content_sha256": source_hash,
            "last_source_captured_at_utc": source["captured_at_utc"],
            "last_at_utc": next_last_at,
            "updated_at_utc": datetime.now(timezone.utc).isoformat(),
            "promotion_eligible": False,
            "authorization_granted": False,
            "order_capability": "DISABLED",
        },
        key,
        HEAD_DOMAIN,
    )
    _atomic_replace(head_path, _canonical_bytes(new_head))
    return {
        "status": "PARTITION_COMMITTED",
        "partition_id": partition_id,
        "sequence": sequence,
        "new_rows": total_rows,
        "partition_content_sha256": receipt["content_sha256"],
        "head_content_sha256": new_head["content_sha256"],
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Append verified FINEX M15 snapshots to a prospective chain"
    )
    result.add_argument("--baseline", required=True)
    result.add_argument("--source-root", required=True)
    result.add_argument("--artifact-root", required=True)
    result.add_argument(
        "--profile-config", default="config/broker_evidence_profiles.v1.json"
    )
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        result = ingest(parser().parse_args(argv))
        print(f"FINEX_M15_PROSPECTIVE_INGEST={result['status']}")
        print(f"Sequence: {result['sequence']}")
        print(f"New rows: {result['new_rows']}")
        print(f"Head SHA-256: {result.get('head_content_sha256')}")
        print("Broker-forward credit: false")
        print("Promotion eligible: false")
        print("Order capability: DISABLED")
        return 0
    except Exception as exc:
        print(f"FINEX_M15_PROSPECTIVE_INGEST_BLOCKED:{exc}")
        print("Order capability remains DISABLED.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
