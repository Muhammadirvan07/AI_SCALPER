from __future__ import annotations

from datetime import datetime, timedelta, timezone
import io
import json
import unittest
import zipfile

from live_runtime.model_governance import RULE_CORE_MODEL_SOURCE_PATHS
from live_runtime.rule_core_model_artifact import (
    CONFIG_PATH,
    EFFECTS,
    FIXED_ZIP_MODE,
    FIXED_ZIP_TIMESTAMP,
    MANIFEST_MEMBER,
    QUALITY_NON_CLAIMS,
    RuleCoreModelArtifactError,
    SAFETY,
    SNAPSHOT_MEMBER,
    build_archive_bytes,
    canonical_json_bytes,
    strict_json_object,
    validate_candidate_config,
    validate_snapshot_bytes,
    verify_archive_bytes,
    verify_archive_with_pins,
)


UTC = timezone.utc
START = datetime(2026, 7, 1, 0, 0, tzinfo=UTC)
REGISTERED = datetime(2026, 7, 3, 0, 0, tzinfo=UTC)
COMMIT = "a" * 40
TREE = "b" * 40


def source_members() -> dict[str, bytes]:
    return {
        path: f"# frozen {path}\n".encode("utf-8")
        for path in RULE_CORE_MODEL_SOURCE_PATHS
    }


def config_bytes(**candidate_overrides: object) -> bytes:
    candidate: dict[str, object] = {
        "candidate_id": "phillip-commodity",
        "environment": "DEMO",
        "binding_scope": "COMMODITY",
        "account_currency": "JPY",
        "server": "PhillipSecuritiesJP-PROD",
        "read_only_discovery_allowed": True,
        "broker_symbols_observed": {"XAUUSD": "XAUUSD.ps01"},
    }
    candidate.update(candidate_overrides)
    return canonical_json_bytes(
        {
            "schema_version": "broker-candidate-plan-v1",
            "execution_enabled": False,
            "credentials_allowed": False,
            "candidates": [candidate],
        }
    )


def snapshot_bytes(
    *,
    rows: int = 96,
    timestamps: list[datetime] | None = None,
    line_ending: str = "\n",
    header: str = "Datetime,Close,High,Low,Open,Volume",
    row_override: dict[int, str] | None = None,
) -> bytes:
    times = timestamps or [START + timedelta(minutes=15 * index) for index in range(rows)]
    lines = [header]
    for index, observed in enumerate(times):
        row = (
            f"{observed.isoformat()},2000.5,2001.0,1999.0,2000.0,{100 + index}"
        )
        if row_override and index in row_override:
            row = row_override[index]
        lines.append(row)
    return (line_ending.join(lines) + line_ending).encode("utf-8")


def artifact() -> tuple[bytes, dict[str, object]]:
    return build_archive_bytes(
        source_members=source_members(),
        config_bytes=config_bytes(),
        snapshot_bytes=snapshot_bytes(),
        branch="agent/live-grade-phase3",
        commit=COMMIT,
        tree=TREE,
        registered_at=REGISTERED,
    )


def rewrite_archive(
    data: bytes,
    *,
    replacements: dict[str, bytes] | None = None,
    extra: tuple[str, bytes] | None = None,
    timestamp: tuple[int, int, int, int, int, int] = FIXED_ZIP_TIMESTAMP,
) -> bytes:
    replacements = replacements or {}
    with zipfile.ZipFile(io.BytesIO(data), "r") as original:
        members = {name: original.read(name) for name in original.namelist()}
    members.update(replacements)
    if extra is not None:
        members[extra[0]] = extra[1]
    destination = io.BytesIO()
    with zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, timestamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = FIXED_ZIP_MODE << 16
            info.create_system = 3
            archive.writestr(info, members[name])
    return destination.getvalue()


class RuleCoreChampionArtifactTests(unittest.TestCase):
    def test_build_is_byte_deterministic_and_external_pins_are_mandatory(self):
        first, result = artifact()
        second, second_result = artifact()
        self.assertEqual(first, second)
        self.assertEqual(result, second_result)
        verified = verify_archive_with_pins(
            first,
            expected_archive_sha256=str(result["archive_sha256"]),
            expected_model_artifact_sha256=str(result["model_artifact_sha256"]),
            expected_training_snapshot_sha256=str(
                result["training_snapshot_sha256"]
            ),
            expected_config_sha256=str(result["config_sha256"]),
            expected_git_commit=COMMIT,
            expected_git_tree=TREE,
        )
        self.assertEqual("RULE_CORE_CHAMPION_ARTIFACT_VERIFIED", verified["status"])
        self.assertEqual(96, verified["snapshot_rows"])
        self.assertFalse(verified["quality_approved"])
        self.assertFalse(verified["promotion_eligible"])
        self.assertFalse(verified["live_allowed"])
        self.assertEqual("DISABLED", verified["order_capability"])
        self.assertEqual("NOT_PERFORMED", verified["broker_mutation"])
        with self.assertRaisesRegex(RuleCoreModelArtifactError, "PIN_MISMATCH"):
            verify_archive_with_pins(
                first,
                expected_archive_sha256="0" * 64,
                expected_model_artifact_sha256=str(
                    result["model_artifact_sha256"]
                ),
                expected_training_snapshot_sha256=str(
                    result["training_snapshot_sha256"]
                ),
                expected_config_sha256=str(result["config_sha256"]),
                expected_git_commit=COMMIT,
                expected_git_tree=TREE,
            )

    def test_manifest_contains_only_deny_only_claims(self):
        data, _ = artifact()
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            manifest = strict_json_object(
                archive.read(MANIFEST_MEMBER), reason="invalid"
            )
        self.assertEqual(SAFETY, manifest["safety"])
        self.assertEqual(EFFECTS, manifest["effects"])
        self.assertEqual(QUALITY_NON_CLAIMS, manifest["quality_claims"])
        self.assertEqual(CONFIG_PATH, manifest["config"]["archive_path"])
        self.assertEqual(SNAPSHOT_MEMBER, manifest["training_snapshot"]["archive_path"])

    def test_source_inventory_and_member_byte_drift_fail_closed(self):
        members = source_members()
        members.pop(RULE_CORE_MODEL_SOURCE_PATHS[0])
        with self.assertRaisesRegex(RuleCoreModelArtifactError, "INVENTORY"):
            build_archive_bytes(
                source_members=members,
                config_bytes=config_bytes(),
                snapshot_bytes=snapshot_bytes(),
                branch="agent/live-grade-phase3",
                commit=COMMIT,
                tree=TREE,
                registered_at=REGISTERED,
            )
        data, _ = artifact()
        tampered = rewrite_archive(
            data,
            replacements={
                f"model-source/{RULE_CORE_MODEL_SOURCE_PATHS[0]}": b"tampered\n"
            },
        )
        with self.assertRaises(RuleCoreModelArtifactError):
            verify_archive_bytes(tampered)

    def test_candidate_config_requires_exact_locked_candidate_identity(self):
        validate_candidate_config(config_bytes())
        for override in (
            {"environment": "LIVE"},
            {"server": "other"},
            {"read_only_discovery_allowed": False},
            {"broker_symbols_observed": {"XAUUSD": "wrong"}},
        ):
            with self.subTest(override=override):
                with self.assertRaisesRegex(
                    RuleCoreModelArtifactError, "CANDIDATE_CONFIG_INVALID"
                ):
                    validate_candidate_config(config_bytes(**override))

    def test_json_duplicate_keys_and_nonfinite_constants_are_rejected(self):
        with self.assertRaisesRegex(RuleCoreModelArtifactError, "DUPLICATE_KEY"):
            strict_json_object(b'{"a":1,"a":2}', reason="INVALID")
        with self.assertRaisesRegex(RuleCoreModelArtifactError, "NONFINITE"):
            strict_json_object(b'{"a":NaN}', reason="INVALID")

    def test_snapshot_contract_rejects_format_time_value_and_count_drift(self):
        duplicate_times = [START + timedelta(minutes=15 * index) for index in range(96)]
        duplicate_times[50] = duplicate_times[49]
        cases = {
            "too-short": snapshot_bytes(rows=95),
            "crlf": snapshot_bytes(line_ending="\r\n"),
            "header": snapshot_bytes(header="Datetime,Open,High,Low,Close,Volume"),
            "order": snapshot_bytes(timestamps=duplicate_times),
            "unaligned": snapshot_bytes(
                timestamps=[
                    START
                    + timedelta(
                        minutes=15 * index + (1 if index == 50 else 0)
                    )
                    for index in range(96)
                ]
            ),
            "nonfinite": snapshot_bytes(
                row_override={0: f"{START.isoformat()},NaN,2001,1999,2000,1"}
            ),
            "bad-candle": snapshot_bytes(
                row_override={0: f"{START.isoformat()},2000,1999,1998,2001,1"}
            ),
            "negative-volume": snapshot_bytes(
                row_override={0: f"{START.isoformat()},2000,2001,1999,2000,-1"}
            ),
        }
        for name, value in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(RuleCoreModelArtifactError):
                    validate_snapshot_bytes(value)

    def test_registration_must_follow_snapshot_cutoff(self):
        with self.assertRaisesRegex(
            RuleCoreModelArtifactError, "REGISTRATION_PRECEDES"
        ):
            build_archive_bytes(
                source_members=source_members(),
                config_bytes=config_bytes(),
                snapshot_bytes=snapshot_bytes(),
                branch="agent/live-grade-phase3",
                commit=COMMIT,
                tree=TREE,
                registered_at=START,
            )

    def test_archive_inventory_metadata_and_claim_drift_are_rejected(self):
        data, _ = artifact()
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            raw_manifest = archive.read(MANIFEST_MEMBER)
        manifest = json.loads(raw_manifest)
        manifest["safety"]["live_allowed"] = True
        cases = {
            "extra": rewrite_archive(data, extra=("extra.txt", b"x")),
            "trailing-data": data + b"trailer",
            "timestamp": rewrite_archive(
                data, timestamp=(1980, 1, 2, 0, 0, 0)
            ),
            "safety": rewrite_archive(
                data,
                replacements={MANIFEST_MEMBER: canonical_json_bytes(manifest)},
            ),
            "duplicate-json": rewrite_archive(
                data,
                replacements={
                    MANIFEST_MEMBER: raw_manifest.replace(
                        b"{", b'{"candidate_id":"forged",', 1
                    )
                },
            ),
        }
        for name, drifted in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(RuleCoreModelArtifactError):
                    verify_archive_bytes(drifted)


if __name__ == "__main__":
    unittest.main()
