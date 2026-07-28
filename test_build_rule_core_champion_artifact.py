from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import build_rule_core_champion_artifact as builder
from build_rule_core_champion_artifact import (
    RuleCoreChampionBuildError,
    build_champion_artifact,
)
from live_runtime.model_governance import RULE_CORE_MODEL_SOURCE_PATHS


UTC = timezone.utc
REGISTERED = datetime(2026, 7, 3, 0, 0, tzinfo=UTC)


def snapshot_bytes() -> bytes:
    start = datetime(2026, 7, 1, 0, 0, tzinfo=UTC)
    rows = ["Datetime,Close,High,Low,Open,Volume"]
    for index in range(96):
        observed = start + timedelta(minutes=15 * index)
        rows.append(
            f"{observed.isoformat()},2000.5,2001,1999,2000,{index + 1}"
        )
    return ("\n".join(rows) + "\n").encode("utf-8")


def config_bytes() -> bytes:
    return (
        json.dumps(
            {
                "schema_version": "broker-candidate-plan-v1",
                "execution_enabled": False,
                "credentials_allowed": False,
                "candidates": [
                    {
                        "candidate_id": "phillip-commodity",
                        "environment": "DEMO",
                        "binding_scope": "COMMODITY",
                        "account_currency": "JPY",
                        "server": "PhillipSecuritiesJP-PROD",
                        "read_only_discovery_allowed": True,
                        "broker_symbols_observed": {"XAUUSD": "XAUUSD.ps01"},
                    }
                ],
            },
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


class RuleCoreChampionBuilderTests(unittest.TestCase):
    @staticmethod
    def _git(root: Path, *args: str) -> str:
        completed = subprocess.run(
            ("git", *args),
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    def _repo(self, base: Path) -> tuple[Path, Path, str]:
        root = base / "repo"
        root.mkdir()
        for relative in RULE_CORE_MODEL_SOURCE_PATHS:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"# fixture {relative}\n".encode("utf-8"))
        config = root / "config/broker_candidates.phase3.json"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_bytes(config_bytes())
        snapshot = base / "xauusd.csv"
        snapshot.write_bytes(snapshot_bytes())
        self._git(root, "init", "-q")
        self._git(root, "config", "user.name", "Champion Builder Test")
        self._git(root, "config", "user.email", "champion@example.invalid")
        self._git(root, "checkout", "-qb", "agent/live-grade-phase3")
        self._git(root, "add", ".")
        self._git(root, "commit", "-qm", "fixture")
        return root, snapshot, self._git(root, "rev-parse", "HEAD")

    @staticmethod
    def _build(root: Path, snapshot: Path, output: Path) -> dict[str, object]:
        return build_champion_artifact(
            source_root=root,
            snapshot_path=snapshot,
            registered_at=REGISTERED,
            output=output,
        )

    def test_two_clean_builds_are_byte_identical_and_self_verified(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, snapshot, commit = self._repo(base)
            first_root = base / "first"
            second_root = base / "second"
            first_root.mkdir()
            second_root.mkdir()
            name = f"rule-core-phillip-commodity-champion-{commit[:8]}.zip"
            first = first_root / name
            second = second_root / name
            first_result = self._build(root, snapshot, first)
            second_result = self._build(root, snapshot, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(
                first_result["archive_sha256"], second_result["archive_sha256"]
            )
            self.assertEqual(commit, first_result["git_commit"])
            self.assertFalse(first_result["quality_approved"])
            self.assertEqual("DISABLED", first_result["order_capability"])

    def test_dirty_tracked_source_and_config_drift_are_rejected(self):
        for relative in (
            RULE_CORE_MODEL_SOURCE_PATHS[0],
            "config/broker_candidates.phase3.json",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as raw:
                base = Path(raw)
                root, snapshot, commit = self._repo(base)
                (root / relative).write_bytes((root / relative).read_bytes() + b"drift\n")
                output = base / f"rule-core-phillip-commodity-champion-{commit[:8]}.zip"
                with self.assertRaisesRegex(RuleCoreChampionBuildError, "dirty"):
                    self._build(root, snapshot, output)
                self.assertFalse(output.exists())

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, snapshot, commit = self._repo(base)
            output = base / f"rule-core-phillip-commodity-champion-{commit[:8]}.zip"
            output.write_bytes(b"preserve")
            with self.assertRaisesRegex(RuleCoreChampionBuildError, "already exists"):
                self._build(root, snapshot, output)
            self.assertEqual(b"preserve", output.read_bytes())

    def test_output_must_be_outside_repo_with_reviewed_name_and_existing_parent(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, snapshot, commit = self._repo(base)
            cases = (
                root / f"rule-core-phillip-commodity-champion-{commit[:8]}.zip",
                base / "wrong.zip",
                base / "missing" / f"rule-core-phillip-commodity-champion-{commit[:8]}.zip",
            )
            for output in cases:
                with self.subTest(output=output):
                    with self.assertRaises(RuleCoreChampionBuildError):
                        self._build(root, snapshot, output)

    def test_wrong_branch_or_commit_prefix_is_rejected_without_output(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, snapshot, commit = self._repo(base)
            wrong_prefix = base / "rule-core-phillip-commodity-champion-deadbeef.zip"
            with self.assertRaisesRegex(RuleCoreChampionBuildError, "Git identity"):
                self._build(root, snapshot, wrong_prefix)
            self.assertFalse(wrong_prefix.exists())
            self._git(root, "checkout", "-qb", "wrong-branch")
            correct = base / f"rule-core-phillip-commodity-champion-{commit[:8]}.zip"
            with self.assertRaisesRegex(RuleCoreChampionBuildError, "Git identity"):
                self._build(root, snapshot, correct)
            self.assertFalse(correct.exists())

    def test_early_registration_is_rejected_without_partial_output(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, snapshot, commit = self._repo(base)
            output = base / f"rule-core-phillip-commodity-champion-{commit[:8]}.zip"
            with self.assertRaisesRegex(RuleCoreChampionBuildError, "PRECEDES"):
                build_champion_artifact(
                    source_root=root,
                    snapshot_path=snapshot,
                    registered_at=datetime(2026, 7, 1, tzinfo=UTC),
                    output=output,
                )
            self.assertFalse(output.exists())

    def test_source_identity_change_before_publish_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, snapshot, commit = self._repo(base)
            output = base / f"rule-core-phillip-commodity-champion-{commit[:8]}.zip"
            original = builder.build_archive_bytes

            def drift_after_build(**kwargs: object):
                result = original(**kwargs)  # type: ignore[arg-type]
                path = root / RULE_CORE_MODEL_SOURCE_PATHS[0]
                path.write_bytes(path.read_bytes() + b"late drift\n")
                return result

            with patch.object(
                builder,
                "build_archive_bytes",
                side_effect=drift_after_build,
            ):
                with self.assertRaisesRegex(RuleCoreChampionBuildError, "dirty"):
                    self._build(root, snapshot, output)
            self.assertFalse(output.exists())

    @unittest.skipIf(not hasattr(Path, "symlink_to"), "symlinks unavailable")
    def test_snapshot_and_output_parent_indirection_are_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, snapshot, commit = self._repo(base)
            snapshot_link_root = base / "snapshot-link"
            snapshot_link_root.mkdir()
            snapshot_link = snapshot_link_root / "xauusd.csv"
            snapshot_link.symlink_to(snapshot)
            output = base / f"rule-core-phillip-commodity-champion-{commit[:8]}.zip"
            with self.assertRaisesRegex(RuleCoreChampionBuildError, "non-reparse"):
                self._build(root, snapshot_link, output)
            output_parent_link = base / "output-link"
            real_output = base / "real-output"
            real_output.mkdir()
            output_parent_link.symlink_to(real_output, target_is_directory=True)
            linked_output = output_parent_link / output.name
            with self.assertRaisesRegex(RuleCoreChampionBuildError, "real directory"):
                self._build(root, snapshot, linked_output)
            self.assertFalse((real_output / output.name).exists())


if __name__ == "__main__":
    unittest.main()
