from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from windows_operator import verify_phillip_commodity_window_02_contract as verifier


class PhillipCommodityWindow02ContractVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir()
        self.lock = self.runtime / "pylock.windows-cp312.toml"
        self.lock.write_text("lock\n", encoding="utf-8")
        self.artifacts = self.root / "artifacts"
        self.contract_root = (
            self.artifacts
            / "forward"
            / verifier.EXPECTED_CONTRACT_ID
        )
        self.contract_root.mkdir(parents=True)
        (self.contract_root / ".contract-write.lock").write_bytes(b"\0")
        self.contract = {
            "contract_id": verifier.EXPECTED_CONTRACT_ID,
            "snapshot_id": verifier.EXPECTED_SNAPSHOT_ID,
            "registered_at_utc": verifier.EXPECTED_REGISTERED_AT_UTC,
            "observation_start_at_utc": (
                verifier.EXPECTED_OBSERVATION_START_UTC
            ),
            "blind_until_utc": verifier.EXPECTED_BLIND_UNTIL_UTC,
            "validation_profile": "DIAGNOSTIC",
            "promotion_profile_eligible": False,
            "contract_payload_sha256": (
                verifier.EXPECTED_CONTRACT_PAYLOAD_SHA256
            ),
            "build_identity_sha256": (
                verifier.EXPECTED_BUILD_IDENTITY_SHA256
            ),
            "signing_key_id": verifier.EXPECTED_SIGNING_KEY_ID,
            "symbols": ["XAUUSD"],
            "ruleset": {
                "git_commit_sha": verifier.EXPECTED_WORKER_COMMIT,
                "git_tree_sha": verifier.EXPECTED_WORKER_TREE,
            },
        }
        self._write_contract()
        for relative in (
            "anchors/raw_ticks/XAUUSD/000000.json",
            "anchors/segments/XAUUSD/000000.json",
            "calendar_amendments/000000.json",
            "heads/calendar_amendments.json",
            "heads/raw_ticks/XAUUSD.json",
            "heads/segments/XAUUSD.json",
            "seal.json",
        ):
            path = self.contract_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"path": relative}) + "\n", encoding="utf-8")
        self.args = argparse.Namespace(
            runtime_repo=self.runtime,
            artifact_root=self.artifacts,
            lock=self.lock,
        )

    def _write_contract(self) -> None:
        (self.contract_root / "contract.json").write_text(
            json.dumps(self.contract, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _inventory(self) -> dict[str, tuple[int, str]]:
        result: dict[str, tuple[int, str]] = {}
        for path in self.contract_root.rglob("*"):
            if path.is_file():
                relative = path.relative_to(self.contract_root).as_posix()
                if relative in verifier.OPTIONAL_OPERATIONAL_FENCE_FILES:
                    continue
                value = path.read_bytes()
                result[relative] = (
                    len(value),
                    hashlib.sha256(value).hexdigest(),
                )
        return result

    def _authority(self) -> dict[str, object]:
        profile = SimpleNamespace(
            key_name=verifier.EXPECTED_KEY_NAME,
            snapshot_id=verifier.EXPECTED_SNAPSHOT_ID,
            contract_id=verifier.EXPECTED_CONTRACT_ID,
            template_path=(
                "config/phillip_commodity_calendar_window_02.template.json"
            ),
        )
        return {
            "profile": profile,
            "dependency_receipt": {
                "lock_sha256": verifier.EXPECTED_DEPENDENCY_LOCK_SHA256
            },
            "signing_key_id": verifier.EXPECTED_SIGNING_KEY_ID,
            "forward": {
                "valid": True,
                "failures": [],
                "contract_payload_sha256": (
                    verifier.EXPECTED_CONTRACT_PAYLOAD_SHA256
                ),
                "contract_hmac_sha256": "3" * 64,
                "chain_heads": {
                    "segments": {"XAUUSD": {}},
                    "raw_ticks": {"XAUUSD": {}},
                    "paired_commits": {},
                },
                "coverage": {
                    "XAUUSD": {
                        "validation_profile": "DIAGNOSTIC",
                        "bar_window_observed": False,
                        "raw_window_observed": False,
                        "observed_data_complete": False,
                        "data_complete": False,
                        "complete": False,
                        "paired_commit_verified": True,
                        "session_calendar_verified": True,
                        "calendar_completeness_satisfied": False,
                    }
                },
                "observed_data_coverage_complete": False,
                "data_coverage_complete": False,
                "coverage_complete": False,
                "validation_profile": "DIAGNOSTIC",
                "sealed": False,
                "calendar_completeness_required": True,
                "calendar_completeness_attested": False,
                "calendar_completeness_satisfied": False,
                "calendar_amendment_chain_verified": True,
                "calendar_amendment_head": {},
                "session_calendar_verified": True,
                "paired_commit_verified": True,
                "segment_counts": {"XAUUSD": 0},
                "raw_tick_partition_counts": {"XAUUSD": 0},
                "evidence_root_sha256": "2" * 64,
                "local_anchor_model": "SIGNED_HEAD_AND_APPEND_HISTORY_V1",
                "off_host_object_lock_verified": False,
                "external_key_custody_verified": False,
                "external_tick_sequence_authenticity_verified": False,
            },
        }

    def _verify(self, authority: dict[str, object] | None = None):
        return verifier.verify(
            self.args,
            expected_inventory=self._inventory(),
            git_identity_provider=lambda _root: (
                verifier.EXPECTED_WORKER_COMMIT,
                verifier.EXPECTED_WORKER_TREE,
            ),
            authority_provider=lambda _runtime, _artifacts, _lock: (
                self._authority() if authority is None else authority
            ),
        )

    def test_exact_external_contract_identity_is_frozen(self) -> None:
        self.assertEqual(
            "cbfd753b0aed2d66af56446adc734ce8d62666e309e91bf74d24b4cc56b613a2",
            verifier.EXPECTED_CONTRACT_PAYLOAD_SHA256,
        )
        self.assertEqual(
            "ad4fd8853563976483fbffbd3bd97847f7e05c8a4194afd10fa95832e2fe485b",
            verifier.EXPECTED_CONTRACT_FILE_SHA256,
        )
        self.assertEqual(9, len(verifier.EXPECTED_INVENTORY))
        self.assertEqual(8, len(verifier.EXPECTED_GENESIS_INVENTORY))
        self.assertEqual(
            (
                1,
                "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            ),
            verifier.EXPECTED_INVENTORY[".contract-write.lock"],
        )
        self.assertEqual(
            (19601, verifier.EXPECTED_CONTRACT_FILE_SHA256),
            verifier.EXPECTED_INVENTORY["contract.json"],
        )

    def test_production_path_promotes_genesis_to_operational_inventory(self) -> None:
        (self.contract_root / ".contract-write.lock").unlink()
        genesis = self._inventory()
        operational = {
            ".contract-write.lock": (
                1,
                "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            ),
            **genesis,
        }

        def authority(*_args):
            (self.contract_root / ".contract-write.lock").write_bytes(b"\0")
            return self._authority()

        with (
            mock.patch.object(verifier, "EXPECTED_GENESIS_INVENTORY", genesis),
            mock.patch.object(verifier, "EXPECTED_INVENTORY", operational),
        ):
            result = verifier.verify(
                self.args,
                git_identity_provider=lambda _root: (
                    verifier.EXPECTED_WORKER_COMMIT,
                    verifier.EXPECTED_WORKER_TREE,
                ),
                authority_provider=authority,
            )
        self.assertEqual(9, result["artifact_files_verified"])
        self.assertEqual(b"\0", (self.contract_root / ".contract-write.lock").read_bytes())

    def test_production_path_requires_operational_lock_after_authority(self) -> None:
        (self.contract_root / ".contract-write.lock").unlink()
        genesis = self._inventory()
        operational = {
            ".contract-write.lock": (
                1,
                "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            ),
            **genesis,
        }
        with (
            mock.patch.object(verifier, "EXPECTED_GENESIS_INVENTORY", genesis),
            mock.patch.object(verifier, "EXPECTED_INVENTORY", operational),
            self.assertRaisesRegex(
                verifier.Window02ContractVerificationError,
                r"missing=\['\.contract-write\.lock'\]",
            ),
        ):
            verifier.verify(
                self.args,
                git_identity_provider=lambda _root: (
                    verifier.EXPECTED_WORKER_COMMIT,
                    verifier.EXPECTED_WORKER_TREE,
                ),
                authority_provider=lambda *_args: self._authority(),
            )

    def test_authenticates_valid_empty_window_02_projection(self) -> None:
        result = self._verify()
        self.assertEqual(
            "PHILLIP_COMMODITY_WINDOW_02_CONTRACT_AUTHENTICATED",
            result["status"],
        )
        self.assertEqual(verifier.EXPECTED_CONTRACT_ID, result["contract_id"])
        self.assertEqual(9, result["artifact_files_verified"])
        self.assertEqual(0, result["initial_segment_count"])
        self.assertEqual(0, result["initial_raw_tick_partition_count"])
        self.assertEqual("DISABLED", result["order_capability"])
        self.assertFalse(result["live_allowed"])

    def test_accepts_operational_shadow_fences_without_reading_them(self) -> None:
        for relative in verifier.OPTIONAL_OPERATIONAL_FENCE_FILES:
            (self.contract_root / relative).write_bytes(b"\0")

        original = verifier._read_stable_bytes

        def read_contract_artifact(path: Path, label: str) -> bytes:
            relative = path.relative_to(self.contract_root.resolve()).as_posix()
            self.assertNotIn(
                relative,
                verifier.OPTIONAL_OPERATIONAL_FENCE_FILES,
            )
            return original(path, label)

        with mock.patch.object(
            verifier,
            "_read_stable_bytes",
            side_effect=read_contract_artifact,
        ):
            result = self._verify()
        self.assertEqual(9, result["artifact_files_verified"])

    def test_rejects_malformed_operational_shadow_fences(self) -> None:
        for relative in verifier.OPTIONAL_OPERATIONAL_FENCE_FILES:
            with self.subTest(relative=relative):
                path = self.contract_root / relative
                path.write_bytes(b"")
                with self.assertRaisesRegex(
                    verifier.Window02ContractVerificationError,
                    "stable one-byte regular non-reparse file",
                ):
                    self._verify()
                path.unlink()

    def test_rejects_symlinked_operational_shadow_fence(self) -> None:
        target = self.root / "shadow-worker-lock-target"
        target.write_bytes(b"\0")
        path = self.contract_root / ".shadow-worker.lock"
        try:
            path.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable")
        with self.assertRaisesRegex(
            verifier.Window02ContractVerificationError,
            "regular non-reparse file",
        ):
            self._verify()

    def test_rejects_physical_artifact_drift(self) -> None:
        inventory = self._inventory()
        path = self.contract_root / "seal.json"
        path.write_bytes(path.read_bytes() + b"drift")
        with self.assertRaisesRegex(
            verifier.Window02ContractVerificationError,
            "artifact drift",
        ):
            verifier.verify(
                self.args,
                expected_inventory=inventory,
                git_identity_provider=lambda _root: (
                    verifier.EXPECTED_WORKER_COMMIT,
                    verifier.EXPECTED_WORKER_TREE,
                ),
                authority_provider=lambda *_args: self._authority(),
            )

    def test_rejects_unexpected_empty_directory(self) -> None:
        (self.contract_root / "unexpected-empty-directory").mkdir()
        with self.assertRaisesRegex(
            verifier.Window02ContractVerificationError,
            "directory inventory mismatch",
        ):
            self._verify()

    def test_rejects_missing_persistent_contract_lock_with_path_diff(self) -> None:
        (self.contract_root / ".contract-write.lock").unlink()
        inventory = self._inventory()
        inventory[".contract-write.lock"] = (
            1,
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        )
        with self.assertRaisesRegex(
            verifier.Window02ContractVerificationError,
            r"missing=\['\.contract-write\.lock'\]",
        ):
            verifier.verify(
                self.args,
                expected_inventory=inventory,
                git_identity_provider=lambda _root: (
                    verifier.EXPECTED_WORKER_COMMIT,
                    verifier.EXPECTED_WORKER_TREE,
                ),
                authority_provider=lambda *_args: self._authority(),
            )

    def test_rejects_unexpected_artifact_with_path_diff(self) -> None:
        (self.contract_root / "unexpected.json").write_text(
            "{}\n",
            encoding="utf-8",
        )
        inventory = self._inventory()
        del inventory["unexpected.json"]
        with self.assertRaisesRegex(
            verifier.Window02ContractVerificationError,
            r"unexpected=\['unexpected\.json'\]",
        ):
            verifier.verify(
                self.args,
                expected_inventory=inventory,
                git_identity_provider=lambda _root: (
                    verifier.EXPECTED_WORKER_COMMIT,
                    verifier.EXPECTED_WORKER_TREE,
                ),
                authority_provider=lambda *_args: self._authority(),
            )

    def test_rejects_contract_identity_even_when_physical_hash_is_rebound(self) -> None:
        self.contract["contract_id"] = "phillip-commodity-window-02-diagnostic-v2"
        self._write_contract()
        with self.assertRaisesRegex(
            verifier.Window02ContractVerificationError,
            "identity or safety mismatch",
        ):
            self._verify()

    def test_rejects_authoritative_profile_drift(self) -> None:
        authority = self._authority()
        authority["forward"]["validation_profile"] = "LIVE_GRADE"  # type: ignore[index]
        with self.assertRaisesRegex(
            verifier.Window02ContractVerificationError,
            "projection mismatch",
        ):
            self._verify(authority)

    def test_rejects_cli_projection_in_place_of_frozen_library_shape(self) -> None:
        authority = self._authority()
        forward = authority["forward"]  # type: ignore[assignment]
        del forward["observed_data_coverage_complete"]
        forward["status"] = "FORWARD_CONTRACT_VALID"
        forward["order_capability"] = "DISABLED"
        forward["live_allowed"] = False
        with self.assertRaisesRegex(
            verifier.Window02ContractVerificationError,
            "projection mismatch",
        ):
            self._verify(authority)

    def test_rejects_malformed_authoritative_failures(self) -> None:
        authority = self._authority()
        authority["forward"]["failures"] = None  # type: ignore[index]
        with self.assertRaisesRegex(
            verifier.Window02ContractVerificationError,
            "projection mismatch",
        ):
            self._verify(authority)

    def test_rejects_dependency_lock_receipt_drift(self) -> None:
        authority = self._authority()
        authority["dependency_receipt"]["lock_sha256"] = "0" * 64  # type: ignore[index]
        with self.assertRaisesRegex(
            verifier.Window02ContractVerificationError,
            "frozen lock",
        ):
            self._verify(authority)

    def test_rejects_dependency_lock_outside_frozen_runtime(self) -> None:
        outside = self.root / "pylock.windows-cp312.toml"
        outside.write_text("lock\n", encoding="utf-8")
        args = argparse.Namespace(
            runtime_repo=self.runtime,
            artifact_root=self.artifacts,
            lock=outside,
        )
        with self.assertRaisesRegex(
            verifier.Window02ContractVerificationError,
            "not the frozen runtime lock",
        ):
            verifier.verify(
                args,
                expected_inventory=self._inventory(),
                git_identity_provider=lambda _root: (
                    verifier.EXPECTED_WORKER_COMMIT,
                    verifier.EXPECTED_WORKER_TREE,
                ),
                authority_provider=lambda *_args: self._authority(),
            )

    def test_rejects_wrong_worker_source_identity_before_authority(self) -> None:
        called = False

        def authority(*_args):
            nonlocal called
            called = True
            return self._authority()

        with self.assertRaisesRegex(
            verifier.Window02ContractVerificationError,
            "source identity mismatch",
        ):
            verifier.verify(
                self.args,
                expected_inventory=self._inventory(),
                git_identity_provider=lambda _root: ("0" * 40, "1" * 40),
                authority_provider=authority,
            )
        self.assertFalse(called)

    def test_rejects_duplicate_contract_json_key(self) -> None:
        duplicate = b'{"contract_id":"one","contract_id":"two"}\n'
        (self.contract_root / "contract.json").write_bytes(duplicate)
        with self.assertRaisesRegex(
            verifier.Window02ContractVerificationError,
            "invalid JSON",
        ):
            self._verify()


if __name__ == "__main__":
    unittest.main()
