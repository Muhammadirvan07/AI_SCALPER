from __future__ import annotations

from dataclasses import fields
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
import subprocess

from build_windows_release import (
    READ_ONLY_SERVICE_ALLOWLIST_SCHEMA,
    READ_ONLY_SERVICE_USAGE_POLICY,
    ReleaseBuildError,
    build_release,
    load_allowlist,
    _read_release_sources,
)
from live_runtime.release_reproducibility import (
    ReproducibilityError,
    ReproducibilityObservation,
    WindowsReproducibilityReceipt,
    issue_reproducibility_receipt,
    verify_reproducibility_receipt,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
KEY = b"r" * 32


def observation(build_id: str, **overrides):
    payload = {
        "build_id": build_id,
        "host_alias_sha256": ("1" if build_id == "build-a" else "2") * 64,
        "os_name": "WINDOWS",
        "python_version": "3.12.10",
        "clean_checkout": True,
        "git_commit": "a" * 40,
        "git_tree": "b" * 40,
        "archive_sha256": "c" * 64,
        "manifest_sha256": "d" * 64,
        "release_identity_sha256": "e" * 64,
        "observed_at_utc": NOW if build_id == "build-a" else NOW + timedelta(minutes=1),
    }
    payload.update(overrides)
    return ReproducibilityObservation(**payload)


class ReleaseReproducibilityTests(unittest.TestCase):
    def test_ac9_project_service_allowlist_is_strict_read_only(self):
        root = Path(__file__).resolve().parent
        payload = load_allowlist(root / "config/windows_shadow_service_allowlist.v1.json")
        self.assertEqual(payload["schema_version"], READ_ONLY_SERVICE_ALLOWLIST_SCHEMA)
        self.assertEqual(payload["usage_policy"], READ_ONLY_SERVICE_USAGE_POLICY)
        self.assertEqual(payload["safety"]["order_capability"], "DISABLED")
        self.assertNotIn("live_runtime/executor.py", payload["files"])
        self.assertNotIn("setup_broker_evidence_key.py", payload["files"])
        self.assertIn(
            "live_runtime/mt5_decision_feed_publisher.py",
            payload["files"],
        )
        self.assertIn("live_runtime/decision_feed.py", payload["files"])
        self.assertIn(
            "live_runtime/brokerless_decision_producer.py",
            payload["files"],
        )
        sources = _read_release_sources(root, payload["files"], set(payload["files"]))
        self.assertEqual(set(sources), set(payload["files"]))

    def test_ac9_service_archive_is_byte_reproducible(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "repo"
            (root / "config").mkdir(parents=True)
            (root / "service.py").write_text("print('read-only')\n", encoding="utf-8")
            allowlist_path = root / "config" / "windows_shadow_service_allowlist.v1.json"
            allowlist_path.write_text(json.dumps({
                "schema_version": READ_ONLY_SERVICE_ALLOWLIST_SCHEMA,
                "release_profile": "WINDOWS_READ_ONLY_SHADOW_SERVICE_V1",
                "safety": {
                    "live_allowed": False,
                    "safe_to_demo_auto_order": False,
                    "max_lot": 0.01,
                    "order_capability": "DISABLED",
                },
                "usage_policy": READ_ONLY_SERVICE_USAGE_POLICY,
                "files": [
                    "service.py",
                    "config/windows_shadow_service_allowlist.v1.json",
                ],
            }, indent=2) + "\n", encoding="utf-8")
            subprocess.run(("git", "init", "-q"), cwd=root, check=True)
            subprocess.run(("git", "config", "user.email", "test@example.invalid"), cwd=root, check=True)
            subprocess.run(("git", "config", "user.name", "Test"), cwd=root, check=True)
            subprocess.run(("git", "add", "."), cwd=root, check=True)
            subprocess.run(("git", "commit", "-qm", "fixture"), cwd=root, check=True)
            first = build_release(root, allowlist_path, base / "first.zip")
            second = build_release(root, allowlist_path, base / "second.zip")
            self.assertEqual(first["archive_sha256"], second["archive_sha256"])
            self.assertEqual(first["bundle_class"], "READ_ONLY_SHADOW_SERVICE")

    def test_ac10_service_profile_rejects_policy_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "allowlist.json"
            path.write_text(json.dumps({
                "schema_version": READ_ONLY_SERVICE_ALLOWLIST_SCHEMA,
                "release_profile": "WINDOWS_READ_ONLY_SHADOW_SERVICE_V1",
                "safety": {
                    "live_allowed": False,
                    "safe_to_demo_auto_order": False,
                    "max_lot": 0.01,
                    "order_capability": "ENABLED",
                },
                "usage_policy": READ_ONLY_SERVICE_USAGE_POLICY,
                "files": ["run_realtime_diagnostic_shadow.py"],
            }))
            with self.assertRaises(ReleaseBuildError):
                load_allowlist(path)

    def test_ac11_signed_reproducibility_receipt_verifies(self):
        receipt = issue_reproducibility_receipt(
            observation("build-a"),
            observation("build-b"),
            issued_at=NOW + timedelta(minutes=2),
            signer_key_id="release-review-key",
            secret=KEY,
        )
        self.assertTrue(
            verify_reproducibility_receipt(
                receipt,
                key_provider=lambda key_id: KEY,
                checked_at=NOW + timedelta(minutes=3),
            )
        )
        self.assertFalse(receipt.live_allowed)
        self.assertFalse(receipt.safe_to_demo_auto_order)
        self.assertFalse(receipt.promotion_eligible)

    def test_receipt_subclass_cannot_override_release_verification(self):
        class ForgedReceipt(WindowsReproducibilityReceipt):
            def verify(self, secret):  # type: ignore[no-untyped-def]
                return True

        signed = issue_reproducibility_receipt(
            observation("build-a"),
            observation("build-b"),
            issued_at=NOW + timedelta(minutes=2),
            signer_key_id="release-review-key",
            secret=KEY,
        )
        forged = ForgedReceipt(
            **{
                field.name: getattr(signed, field.name)
                for field in fields(WindowsReproducibilityReceipt)
            }
        )
        with self.assertRaisesRegex(
            TypeError,
            "exact WindowsReproducibilityReceipt",
        ):
            verify_reproducibility_receipt(
                forged,
                key_provider=lambda key_id: KEY,
                checked_at=NOW + timedelta(minutes=3),
            )

    def test_ac12_mismatch_and_replay_are_rejected(self):
        with self.assertRaisesRegex(ReproducibilityError, "FULL_HASH_REQUIRED"):
            observation("short-hash", git_commit="a" * 39)
        with self.assertRaisesRegex(ReproducibilityError, "BUILD_ID_REPLAY"):
            issue_reproducibility_receipt(
                observation("same"), observation("same"),
                issued_at=NOW + timedelta(minutes=2), signer_key_id="k", secret=KEY,
            )
        with self.assertRaisesRegex(ReproducibilityError, "ARCHIVE_SHA256_MISMATCH"):
            issue_reproducibility_receipt(
                observation("build-a"),
                observation("build-b", archive_sha256="f" * 64),
                issued_at=NOW + timedelta(minutes=2), signer_key_id="k", secret=KEY,
            )


if __name__ == "__main__":
    unittest.main()
