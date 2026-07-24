from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from live_runtime.manual_demo_activation_kit import (
    ManualDemoActivationKitError,
    build_manual_demo_activation_kit,
)
from live_runtime.manual_demo_readiness import load_current_manual_demo_readiness
from live_runtime.windows_service_factory_template import provider_contracts
from validate_windows_gated_execution_service import validate_gated_execution_ports


ROOT = Path(__file__).resolve().parent
NOW = datetime(2026, 7, 23, 0, 0, tzinfo=timezone.utc)


class ManualDemoActivationKitTests(unittest.TestCase):
    def readiness(self):
        return load_current_manual_demo_readiness(
            candidate_id="phillip-fx",
            project_root=ROOT,
            clock_provider=lambda: NOW,
        )

    def test_kit_is_blocked_complete_and_content_addressed(self) -> None:
        kit = build_manual_demo_activation_kit(
            readiness=self.readiness(),
            windows_validation=validate_gated_execution_ports(),
            provider_contracts=provider_contracts(),
            prepared_at_utc=NOW,
        )
        payload = kit.to_canonical_dict()
        self.assertEqual("BLOCKED_EXTERNAL_INPUT_REQUIRED", payload["status"])
        self.assertFalse(payload["ready"])
        self.assertFalse(payload["broker_mutation_performed"])
        self.assertEqual(10, payload["target_controlled_orders"])
        self.assertEqual("DISABLED", payload["safety"]["order_capability"])
        self.assertFalse(payload["safety"]["live_allowed"])
        self.assertFalse(payload["safety"]["safe_to_demo_auto_order"])
        self.assertIn("MANUAL_DEMO_POLICY_LOCKED", payload["readiness_blocker_codes"])
        self.assertGreater(len(payload["required_external_providers"]), 10)
        self.assertEqual(64, len(kit.content_sha256))

    def test_kit_rejects_nonpassing_windows_validation(self) -> None:
        with self.assertRaisesRegex(
            ManualDemoActivationKitError,
            "did not pass",
        ):
            build_manual_demo_activation_kit(
                readiness=self.readiness(),
                windows_validation={
                    "port_validation": "FAIL",
                    "production_execution_ready": False,
                },
                provider_contracts=provider_contracts(),
                prepared_at_utc=NOW,
            )

    def test_cli_creates_once_and_never_claims_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "kit.json"
            command = [
                sys.executable,
                "-B",
                str(ROOT / "prepare_manual_demo_activation_kit.py"),
                "--candidate",
                "phillip-fx",
                "--output",
                str(output),
            ]
            completed = subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                "BLOCKED_EXTERNAL_INPUT_REQUIRED",
                payload["status"],
            )
            self.assertFalse(payload["ready"])
            self.assertFalse(payload["broker_mutation_performed"])
            repeated = subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(2, repeated.returncode)
            self.assertIn("REJECTED", repeated.stderr)

    def test_source_has_no_broker_or_order_surface(self) -> None:
        source = (
            (ROOT / "live_runtime" / "manual_demo_activation_kit.py").read_text()
            + (ROOT / "prepare_manual_demo_activation_kit.py").read_text()
        )
        for forbidden in (
            "MetaTrader5",
            "order_send",
            "order_check",
            "MT5Adapter",
            "CredentialManager",
            "execute_prepared_manual_demo",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
