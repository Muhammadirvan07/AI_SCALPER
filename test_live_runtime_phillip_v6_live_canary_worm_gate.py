from __future__ import annotations

import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile

from live_runtime.phillip_v6_live_canary_worm_gate import (
    PHILLIP_V6_WORM_GATE_MANIFEST,
    PHILLIP_V6_WORM_GATE_PATHS,
    PhillipV6LiveCanaryWormGateError,
    build_phillip_v6_live_canary_worm_gate_evidence,
    verify_phillip_v6_live_canary_worm_gate_evidence,
)
import test_windows_phillip_commodity_v6_postrun_acceptance as v6_fixture
from windows_operator import phillip_commodity_v6_postrun_acceptance as v6


UTC = timezone.utc
VERIFIED_AT = datetime(2026, 7, 29, 22, 2, tzinfo=UTC)
REQUIRED_UNTIL = datetime(2027, 9, 30, 0, 0, tzinfo=UTC)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class PhillipV6LiveCanaryWormGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

        fixture = v6_fixture.PhillipCommodityV6PostRunAcceptanceTests(
            "test_signed_custody_receipt_writes_deny_only_assessment"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        (
            _acceptance_archive,
            self.request,
            _acceptance_result,
            request_result,
        ) = fixture._prepare_custody("bridge-custody-request.zip")
        self.policy, self.receipt, _receipt = fixture._custody_documents(
            self.request,
            request_result,
        )
        self.request_sha256 = _sha256(self.request.read_bytes())
        self.policy_sha256 = _sha256(self.policy.read_bytes())
        self.assessment = fixture.root / "bridge-custody-assessment.json"
        v6.verify_custody_receipt(
            custody_request_archive=self.request,
            expected_custody_request_archive_sha256=self.request_sha256,
            expected_toolkit_source_commit=fixture.source_commit,
            expected_toolkit_source_tree=fixture.source_tree,
            policy_path=self.policy,
            expected_policy_sha256=self.policy_sha256,
            receipt_path=self.receipt,
            verified_at_utc="2026-07-29T22:02:00.000000Z",
            assessment_output=self.assessment,
        )

    def _build(self, name: str = "worm-gate.zip") -> tuple[Path, dict[str, object]]:
        output = self.root / name
        result = build_phillip_v6_live_canary_worm_gate_evidence(
            custody_request_archive=self.request,
            expected_custody_request_archive_sha256=self.request_sha256,
            expected_toolkit_source_commit=self.fixture.source_commit,
            expected_toolkit_source_tree=self.fixture.source_tree,
            policy_path=self.policy,
            expected_policy_sha256=self.policy_sha256,
            receipt_path=self.receipt,
            assessment_path=self.assessment,
            output=output,
        )
        return output, result

    def test_ac1_deterministic_bridge_round_trips(self) -> None:
        first, first_result = self._build("first.zip")
        second, second_result = self._build("second.zip")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(
            first_result["archive_sha256"], second_result["archive_sha256"]
        )
        with zipfile.ZipFile(first) as package:
            self.assertEqual(PHILLIP_V6_WORM_GATE_PATHS, tuple(package.namelist()))
            manifest = json.loads(package.read(PHILLIP_V6_WORM_GATE_MANIFEST))
        self.assertEqual(
            "phillip-v6-live-canary-worm-gate-evidence-v1",
            manifest["schema_version"],
        )
        self.assertEqual("DISABLED", manifest["safety"]["order_capability"])
        self.assertFalse(manifest["safety"]["live_allowed"])

        verified = verify_phillip_v6_live_canary_worm_gate_evidence(
            first,
            expected_policy_sha256=self.policy_sha256,
            observed_at=VERIFIED_AT,
            required_until=REQUIRED_UNTIL,
        )
        self.assertEqual(first_result["archive_sha256"], verified["archive_sha256"])
        self.assertEqual("DISABLED", verified["order_capability"])
        self.assertFalse(verified["live_allowed"])

    def test_ac2_assessment_must_reconstruct_byte_identically(self) -> None:
        payload = json.loads(self.assessment.read_bytes())
        payload["verified_at_utc"] = "2026-07-29T22:02:00.000001Z"
        self.assessment.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            PhillipV6LiveCanaryWormGateError,
            "ASSESSMENT",
        ):
            self._build("assessment-drift.zip")
        self.assertFalse((self.root / "assessment-drift.zip").exists())

    def test_ac3_external_policy_pin_is_mandatory_and_exact(self) -> None:
        bridge, _result = self._build()
        for invalid in ("", "0" * 64, "F" * 64, "f" * 64):
            with self.subTest(pin=invalid), self.assertRaises(
                PhillipV6LiveCanaryWormGateError
            ):
                verify_phillip_v6_live_canary_worm_gate_evidence(
                    bridge,
                    expected_policy_sha256=invalid,
                    observed_at=VERIFIED_AT,
                    required_until=REQUIRED_UNTIL,
                )

    def test_ac4_retention_and_future_evidence_fail_closed(self) -> None:
        bridge, _result = self._build()
        with self.assertRaisesRegex(
            PhillipV6LiveCanaryWormGateError,
            "RETENTION",
        ):
            verify_phillip_v6_live_canary_worm_gate_evidence(
                bridge,
                expected_policy_sha256=self.policy_sha256,
                observed_at=VERIFIED_AT,
                required_until=datetime(2027, 10, 1, 0, 0, 0, 1, tzinfo=UTC),
            )
        with self.assertRaisesRegex(
            PhillipV6LiveCanaryWormGateError,
            "TIME",
        ):
            verify_phillip_v6_live_canary_worm_gate_evidence(
                bridge,
                expected_policy_sha256=self.policy_sha256,
                observed_at=datetime(2026, 7, 29, 22, 1, 59, 999999, tzinfo=UTC),
                required_until=REQUIRED_UNTIL,
            )

    def test_ac8_archive_ambiguity_and_trailing_bytes_are_rejected(self) -> None:
        bridge, _result = self._build()
        appended = self.root / "appended.zip"
        appended.write_bytes(bridge.read_bytes() + b"trailing")
        with self.assertRaises(PhillipV6LiveCanaryWormGateError):
            verify_phillip_v6_live_canary_worm_gate_evidence(
                appended,
                expected_policy_sha256=self.policy_sha256,
                observed_at=VERIFIED_AT,
                required_until=REQUIRED_UNTIL,
            )

        duplicate = self.root / "duplicate.zip"
        with zipfile.ZipFile(bridge) as source, zipfile.ZipFile(duplicate, "x") as out:
            for info in source.infolist():
                out.writestr(info, source.read(info.filename))
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                out.writestr("custody-policy.json", self.policy.read_bytes())
        with self.assertRaises(PhillipV6LiveCanaryWormGateError):
            verify_phillip_v6_live_canary_worm_gate_evidence(
                duplicate,
                expected_policy_sha256=self.policy_sha256,
                observed_at=VERIFIED_AT,
                required_until=REQUIRED_UNTIL,
            )

    def test_ac8_existing_destination_is_preserved(self) -> None:
        output = self.root / "existing.zip"
        output.write_bytes(b"preserve-existing")
        with self.assertRaises(FileExistsError):
            build_phillip_v6_live_canary_worm_gate_evidence(
                custody_request_archive=self.request,
                expected_custody_request_archive_sha256=self.request_sha256,
                expected_toolkit_source_commit=self.fixture.source_commit,
                expected_toolkit_source_tree=self.fixture.source_tree,
                policy_path=self.policy,
                expected_policy_sha256=self.policy_sha256,
                receipt_path=self.receipt,
                assessment_path=self.assessment,
                output=output,
            )
        self.assertEqual(b"preserve-existing", output.read_bytes())

    def test_ac7_effect_and_release_isolation_are_exact(self) -> None:
        repo = Path(__file__).resolve().parent
        source_paths = (
            repo / "live_runtime/phillip_v6_live_canary_worm_gate.py",
            repo / "prepare_phillip_v6_live_canary_worm_gate_evidence.py",
            repo / "verify_phillip_v6_live_canary_worm_gate_evidence.py",
            repo / "windows_operator/phillip_commodity_v6_postrun_acceptance.py",
        )
        forbidden_modules = {"MetaTrader5", "requests", "socket", "subprocess"}
        forbidden_calls = {"initialize", "order_check", "order_send", "Popen", "system"}
        for path in source_paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            imported = {
                alias.name.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            }
            imported.update(
                node.module.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module
            )
            called = {
                node.func.attr
                for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            }
            with self.subTest(path=path.name):
                self.assertFalse(imported & forbidden_modules)
                self.assertFalse(called & forbidden_calls)

        required = {path.relative_to(repo).as_posix() for path in source_paths}
        allowlists = sorted((repo / "config").glob("*allowlist*.json"))
        for path in allowlists:
            payload = json.loads(path.read_text(encoding="utf-8"))
            files = set(payload.get("files", ()))
            if path.name == "windows_release_allowlist.v1.json":
                self.assertTrue(required <= files)
            else:
                self.assertFalse(required & files, path.name)

    def test_ac9_optimized_round_trip(self) -> None:
        if sys.flags.optimize:
            self.skipTest("already running under optimized mode")
        completed = subprocess.run(
            [
                sys.executable,
                "-O",
                "-B",
                "-m",
                "unittest",
                (
                    "test_live_runtime_phillip_v6_live_canary_worm_gate."
                    "PhillipV6LiveCanaryWormGateTests."
                    "test_ac1_deterministic_bridge_round_trips"
                ),
            ],
            cwd=Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
