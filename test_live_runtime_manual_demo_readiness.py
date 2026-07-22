from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from live_runtime.manual_demo_readiness import (
    ManualDemoReadinessError,
    evaluate_manual_demo_readiness,
    load_json_object_strict,
)


ROOT = Path(__file__).resolve().parent
NOW = datetime(2026, 7, 22, 2, 0, 0, tzinfo=timezone.utc)


def _candidate_plan():
    return {
        "schema_version": "broker-candidate-plan-v1",
        "status": "PHILLIP_JAPAN_DUAL_SHADOW_ACTIVE",
        "execution_enabled": False,
        "credentials_allowed": False,
        "operational_priority": {},
        "required_symbols": ["XAUUSD", "EURUSD", "USDJPY", "AUDUSD"],
        "minimum_sessions_per_candidate": 20,
        "candidates": [
            {
                "candidate_id": "phillip-fx",
                "server": "PhillipSecuritiesJP-PROD",
                "environment": "DEMO",
                "account_currency": "JPY",
                "binding_status": "READ_ONLY_DISCOVERY_V3_APPROVED",
                "instrument_specification_status": "API_CAPTURE_PENDING",
                "server_time_model": {
                    "calendar_hash_status": "PENDING_EXACT_SYMBOL_SESSIONS_AND_HOLIDAYS"
                },
                "regulatory_observation": {
                    "legal_eligible": True,
                },
            }
        ],
        "notes": [],
    }


def _evidence_profiles():
    return {
        "schema_version": "broker-evidence-profiles-v1",
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "max_lot": 0.01,
        "profiles": [
            {
                "candidate_id": "phillip-fx",
                "registration_enabled": False,
                "status": "BLOCKED_PENDING_SIGNED_REGULATORY_CALENDAR_AND_REGISTRATION_REVIEW",
            }
        ],
    }


def _readiness_policy():
    return {
        "schema_version": "manual-demo-readiness-policy-v1",
        "status": "LOCKED_PENDING_EXTERNAL_GATES",
        "manual_demo_enabled": False,
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "order_capability": "DISABLED",
        "max_lot": 0.01,
        "global_gates": {
            "CLEAN_RELEASE_ATTESTATION_REQUIRED": False,
            "FAILURE_DRILLS_REQUIRED": False,
            "INDEPENDENT_APPROVER_REQUIRED": False,
            "PRODUCTION_NEWS_PROVIDER_REQUIRED": False,
        },
        "candidate_gates": {
            "phillip-fx": {
                "BROKER_FORWARD_SAMPLE_REQUIRED": False,
                "BROKER_SESSIONS_20_REQUIRED": False,
                "TERMINAL_FENCE_ATTESTATION_REQUIRED": False,
                "USD_RISK_CAP_CONVERSION_RUNTIME_ATTESTATION_REQUIRED": False,
            }
        },
    }


class ManualDemoReadinessTests(unittest.TestCase):
    def test_current_locked_state_reports_sorted_blockers(self) -> None:
        report = evaluate_manual_demo_readiness(
            candidate_id="phillip-fx",
            candidate_plan=_candidate_plan(),
            evidence_profiles=_evidence_profiles(),
            readiness_policy=_readiness_policy(),
            evaluated_at_utc=NOW,
        )
        self.assertFalse(report.ready)
        self.assertEqual("BLOCKED", report.status)
        self.assertEqual("phillip-fx", report.candidate_id)
        self.assertEqual("PhillipSecuritiesJP-PROD", report.candidate_server)
        self.assertEqual("JPY", report.account_currency)
        self.assertEqual(tuple(sorted(report.blocker_codes)), report.blocker_codes)
        self.assertIn("MANUAL_DEMO_POLICY_LOCKED", report.blocker_codes)
        self.assertIn("EVIDENCE_REGISTRATION_DISABLED", report.blocker_codes)
        self.assertIn("INSTRUMENT_SPECIFICATION_PENDING", report.blocker_codes)
        self.assertIn("SESSION_CALENDAR_PENDING", report.blocker_codes)
        self.assertIn(
            "USD_RISK_CAP_CONVERSION_RUNTIME_ATTESTATION_REQUIRED",
            report.blocker_codes,
        )
        self.assertEqual("DISABLED", report.safety["order_capability"])
        self.assertFalse(report.safety["execution_enabled"])
        self.assertFalse(report.safety["live_allowed"])
        self.assertFalse(report.safety["safe_to_demo_auto_order"])
        self.assertEqual(0.01, report.safety["max_lot"])
        self.assertEqual(64, len(report.content_sha256))

    def test_unknown_candidate_and_missing_candidate_gate_are_rejected(self) -> None:
        with self.assertRaisesRegex(ManualDemoReadinessError, "unknown candidate"):
            evaluate_manual_demo_readiness(
                candidate_id="missing",
                candidate_plan=_candidate_plan(),
                evidence_profiles=_evidence_profiles(),
                readiness_policy=_readiness_policy(),
                evaluated_at_utc=NOW,
            )

        policy = _readiness_policy()
        policy["candidate_gates"] = {}
        with self.assertRaisesRegex(ManualDemoReadinessError, "candidate gates"):
            evaluate_manual_demo_readiness(
                candidate_id="phillip-fx",
                candidate_plan=_candidate_plan(),
                evidence_profiles=_evidence_profiles(),
                readiness_policy=policy,
                evaluated_at_utc=NOW,
            )

    def test_binding_status_requires_an_exact_approved_enum(self) -> None:
        plan = _candidate_plan()
        plan["candidates"][0]["binding_status"] = "NOT_APPROVED"

        report = evaluate_manual_demo_readiness(
            candidate_id="phillip-fx",
            candidate_plan=plan,
            evidence_profiles=_evidence_profiles(),
            readiness_policy=_readiness_policy(),
            evaluated_at_utc=NOW,
        )

        self.assertIn("BROKER_BINDING_NOT_APPROVED", report.blocker_codes)

    def test_calendar_status_missing_or_unknown_is_blocked(self) -> None:
        for status in (None, "UNKNOWN"):
            with self.subTest(status=status):
                plan = _candidate_plan()
                time_model = plan["candidates"][0]["server_time_model"]
                if status is None:
                    del time_model["calendar_hash_status"]
                else:
                    time_model["calendar_hash_status"] = status

                report = evaluate_manual_demo_readiness(
                    candidate_id="phillip-fx",
                    candidate_plan=plan,
                    evidence_profiles=_evidence_profiles(),
                    readiness_policy=_readiness_policy(),
                    evaluated_at_utc=NOW,
                )

                self.assertIn("SESSION_CALENDAR_PENDING", report.blocker_codes)

    def test_exact_verified_calendar_status_clears_calendar_blocker(self) -> None:
        plan = _candidate_plan()
        plan["candidates"][0]["server_time_model"]["calendar_hash_status"] = (
            "VERIFIED_EXACT_SYMBOL_SESSIONS_AND_HOLIDAYS"
        )

        report = evaluate_manual_demo_readiness(
            candidate_id="phillip-fx",
            candidate_plan=plan,
            evidence_profiles=_evidence_profiles(),
            readiness_policy=_readiness_policy(),
            evaluated_at_utc=NOW,
        )

        self.assertNotIn("SESSION_CALENDAR_PENDING", report.blocker_codes)

    def test_any_policy_lock_weakening_is_rejected(self) -> None:
        mutations = {
            "manual_demo_enabled": True,
            "execution_enabled": True,
            "live_allowed": True,
            "safe_to_demo_auto_order": True,
            "order_capability": "ENABLED",
            "max_lot": 0.02,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                policy = deepcopy(_readiness_policy())
                policy[field] = value
                with self.assertRaises(ManualDemoReadinessError):
                    evaluate_manual_demo_readiness(
                        candidate_id="phillip-fx",
                        candidate_plan=_candidate_plan(),
                        evidence_profiles=_evidence_profiles(),
                        readiness_policy=policy,
                        evaluated_at_utc=NOW,
                    )

    def test_unknown_policy_field_and_duplicate_json_keys_are_rejected(self) -> None:
        policy = _readiness_policy()
        policy["unexpected"] = True
        with self.assertRaisesRegex(ManualDemoReadinessError, "unknown readiness policy"):
            evaluate_manual_demo_readiness(
                candidate_id="phillip-fx",
                candidate_plan=_candidate_plan(),
                evidence_profiles=_evidence_profiles(),
                readiness_policy=policy,
                evaluated_at_utc=NOW,
            )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema_version":"one","schema_version":"two"}')
            with self.assertRaisesRegex(ManualDemoReadinessError, "duplicate JSON"):
                load_json_object_strict(path)

    def test_tracked_policy_and_allowlists_preserve_all_locks(self) -> None:
        policy = load_json_object_strict(
            ROOT / "config" / "manual_demo_readiness.v1.json"
        )
        self.assertFalse(policy["manual_demo_enabled"])
        self.assertFalse(policy["execution_enabled"])
        self.assertFalse(policy["live_allowed"])
        self.assertFalse(policy["safe_to_demo_auto_order"])
        self.assertEqual("DISABLED", policy["order_capability"])
        self.assertEqual(0.01, policy["max_lot"])

        release = load_json_object_strict(
            ROOT / "config" / "windows_release_allowlist.v1.json"
        )
        shadow = load_json_object_strict(
            ROOT / "config" / "windows_shadow_service_allowlist.v1.json"
        )
        self.assertIn("run_manual_demo_readiness.py", release["files"])
        self.assertIn("live_runtime/manual_demo_readiness.py", release["files"])
        self.assertNotIn("run_manual_demo_readiness.py", shadow["files"])
        self.assertNotIn("live_runtime/manual_demo_readiness.py", shadow["files"])

    def test_readiness_source_has_no_execution_surface(self) -> None:
        source = (ROOT / "live_runtime" / "manual_demo_readiness.py").read_text()
        cli_source = (ROOT / "run_manual_demo_readiness.py").read_text()
        combined = source + cli_source
        for forbidden in (
            "MetaTrader5",
            "mt5_adapter",
            "executor",
            "order_check",
            "order_send",
            "PromotionPermit",
            "ManualDemoApproval",
            "Credential",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, combined)

    def test_cli_reports_blocked_and_optional_output_is_create_only(self) -> None:
        command = [
            sys.executable,
            "-B",
            str(ROOT / "run_manual_demo_readiness.py"),
            "--candidate",
            "phillip-fx",
        ]
        result = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["ready"])
        self.assertEqual("DISABLED", payload["safety"]["order_capability"])

        forbidden = subprocess.run(
            [*command, "--password", "not-a-real-password"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(0, forbidden.returncode)
        self.assertIn("unrecognized arguments", forbidden.stderr)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "readiness.json"
            first = subprocess.run(
                [*command, "--output", str(output)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, first.returncode, first.stderr)
            self.assertTrue(output.is_file())
            second = subprocess.run(
                [*command, "--output", str(output)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, second.returncode)
            self.assertIn("already exists", second.stderr)


if __name__ == "__main__":
    unittest.main()
