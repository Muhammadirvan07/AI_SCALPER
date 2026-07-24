from __future__ import annotations

from datetime import timedelta
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from live_runtime.demo_soak_three_service_operations import (
    EXTERNAL_READINESS_BLOCKERS,
)
from live_runtime.three_service_external_acceptance import (
    OBSERVATIONS_SCHEMA_VERSION,
    ThreeServiceAcceptanceError,
)
from live_runtime.windows_manual_demo_entry_review import (
    MANUAL_DEMO_RESULT_GATE,
    PRE_MANUAL_GATE_INVENTORY,
    REQUIRED_PER_INTENT_CONTROLS,
    WindowsManualDemoEntryReviewError,
    assess_windows_manual_demo_entry_review,
)
from test_windows_three_service_external_acceptance import (
    CHECKED_AT,
    all_observations,
    json_ready,
    policy_for,
    review_bundle,
    signed_observation,
)


ROOT = Path(__file__).resolve().parent
CLI = ROOT / "verify_windows_manual_demo_entry_review.py"


def pre_manual_observations(bundle, policy):
    return tuple(
        signed_observation(bundle, policy, gate)
        for gate in PRE_MANUAL_GATE_INVENTORY
    )


def assess(bundle, policy, observations):
    return assess_windows_manual_demo_entry_review(
        review_bundle=bundle,
        trust_policy=policy,
        observations=observations,
        expected_policy_sha256=policy.content_sha256,
        clock_provider=lambda: CHECKED_AT,
    )


def write_documents(
    root: Path,
    *,
    observations=None,
):
    bundle = review_bundle()
    policy = policy_for(bundle)
    selected = (
        pre_manual_observations(bundle, policy)
        if observations is None
        else observations
    )
    (root / "review.json").write_text(
        json.dumps(json_ready(bundle), indent=2) + "\n",
        encoding="utf-8",
    )
    (root / "policy.json").write_text(
        json.dumps(
            json_ready(policy.to_canonical_dict()),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "observations.json").write_text(
        json.dumps(
            {
                "schema_version": OBSERVATIONS_SCHEMA_VERSION,
                "observations": [
                    json_ready(item.to_canonical_dict())
                    for item in selected
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return bundle, policy


class WindowsManualDemoEntryReviewTests(unittest.TestCase):
    def test_exact_pre_manual_dossier_requests_review_without_authority(
        self,
    ) -> None:
        bundle = review_bundle()
        policy = policy_for(bundle)
        result = assess(
            bundle,
            policy,
            pre_manual_observations(bundle, policy),
        )
        canonical_plan = bundle["plan"]
        self.assertIsInstance(canonical_plan, dict)
        self.assertEqual(
            "PRE_MANUAL_DEMO_EXTERNAL_PRECONDITIONS_COMPLETE_"
            "ACTIVATION_REVIEW_REQUIRED",
            result.status,
        )
        self.assertTrue(result.external_preconditions_complete)
        self.assertTrue(result.manual_demo_activation_review_required)
        self.assertEqual(
            tuple(sorted(PRE_MANUAL_GATE_INVENTORY)),
            result.accepted_pre_manual_gates,
        )
        self.assertEqual((), result.pending_pre_manual_gates)
        self.assertEqual({}, dict(result.pending_reasons))
        self.assertEqual(MANUAL_DEMO_RESULT_GATE, result.manual_demo_result_gate)
        self.assertEqual(10, result.target_controlled_lifecycles)
        self.assertEqual(
            REQUIRED_PER_INTENT_CONTROLS,
            result.required_per_intent_controls,
        )
        self.assertFalse(result.full_external_acceptance_complete)
        self.assertFalse(result.manual_demo_authorized)
        self.assertFalse(result.activation_authorized)
        self.assertFalse(result.execution_enabled)
        self.assertFalse(result.ready_for_demo_auto_soak)
        self.assertFalse(result.safe_to_demo_auto_order)
        self.assertFalse(result.live_allowed)
        self.assertFalse(result.promotion_eligible)
        self.assertEqual("DISABLED", result.order_capability)
        self.assertEqual(0.01, result.max_lot)
        self.assertEqual("XAUUSD", result.canonical_symbol)
        self.assertEqual(
            canonical_plan["decision"]["configured_release_identity_sha256"],
            result.decision_release_identity_sha256,
        )
        self.assertEqual(
            canonical_plan["execution"]["configured_release_identity_sha256"],
            result.execution_release_identity_sha256,
        )
        self.assertEqual(
            canonical_plan["status_monitor"][
                "configured_release_identity_sha256"
            ],
            result.status_monitor_release_identity_sha256,
        )
        self.assertEqual(
            bundle["failure_drill_manifest_sha256"],
            result.failure_drill_manifest_sha256,
        )
        self.assertEqual(64, len(result.content_sha256))

    def test_missing_failed_and_stale_pre_manual_evidence_remains_blocked(
        self,
    ) -> None:
        bundle = review_bundle()
        policy = policy_for(bundle)
        gates = tuple(PRE_MANUAL_GATE_INVENTORY)
        selected = tuple(
            signed_observation(
                bundle,
                policy,
                gate,
                **(
                    {"outcome": "FAILED"}
                    if gate == gates[0]
                    else (
                        {
                            "observed_at_utc": CHECKED_AT
                            - timedelta(minutes=5),
                            "not_before_utc": CHECKED_AT
                            - timedelta(minutes=4),
                            "expires_at_utc": CHECKED_AT,
                        }
                        if gate == gates[1]
                        else {}
                    )
                ),
            )
            for gate in gates[:-1]
        )
        result = assess(bundle, policy, selected)
        self.assertEqual(
            "BLOCKED_PRE_MANUAL_DEMO_EXTERNAL_PRECONDITIONS",
            result.status,
        )
        self.assertFalse(result.external_preconditions_complete)
        self.assertFalse(result.manual_demo_activation_review_required)
        self.assertEqual(
            tuple(sorted((gates[0], gates[1], gates[-1]))),
            result.pending_pre_manual_gates,
        )
        self.assertEqual(
            "SIGNED_OUTCOME_FAILED",
            result.pending_reasons[gates[0]],
        )
        self.assertEqual("EXPIRED", result.pending_reasons[gates[1]])
        self.assertEqual("MISSING", result.pending_reasons[gates[-1]])
        self.assertFalse(result.manual_demo_authorized)
        self.assertEqual("DISABLED", result.order_capability)

    def test_manual_demo_result_observation_is_never_pre_run_evidence(
        self,
    ) -> None:
        bundle = review_bundle()
        policy = policy_for(bundle)
        with self.assertRaisesRegex(
            WindowsManualDemoEntryReviewError,
            "MANUAL_DEMO_RESULT_ALREADY_PRESENT",
        ):
            assess(bundle, policy, all_observations(bundle, policy))
        failed_result = signed_observation(
            bundle,
            policy,
            MANUAL_DEMO_RESULT_GATE,
            outcome="FAILED",
        )
        with self.assertRaisesRegex(
            WindowsManualDemoEntryReviewError,
            "MANUAL_DEMO_RESULT_OBSERVATION_NOT_ALLOWED",
        ):
            assess(
                bundle,
                policy,
                (
                    *pre_manual_observations(bundle, policy),
                    failed_result,
                ),
            )

    def test_policy_pin_signature_and_bundle_drift_fail_closed(self) -> None:
        bundle = review_bundle()
        policy = policy_for(bundle)
        with self.assertRaisesRegex(
            ThreeServiceAcceptanceError,
            "ACCEPTANCE_POLICY_PIN_MISMATCH",
        ):
            assess_windows_manual_demo_entry_review(
                review_bundle=bundle,
                trust_policy=policy,
                observations=pre_manual_observations(bundle, policy),
                expected_policy_sha256="f" * 64,
                clock_provider=lambda: CHECKED_AT,
            )
        changed = dict(bundle)
        changed["content_sha256"] = "f" * 64
        with self.assertRaises(ThreeServiceAcceptanceError):
            assess_windows_manual_demo_entry_review(
                review_bundle=changed,
                trust_policy=policy,
                observations=pre_manual_observations(bundle, policy),
                expected_policy_sha256=policy.content_sha256,
                clock_provider=lambda: CHECKED_AT,
            )

    def test_review_is_deterministic_and_within_bound(self) -> None:
        bundle = review_bundle()
        policy = policy_for(bundle)
        observations = pre_manual_observations(bundle, policy)
        started = time.perf_counter()
        first = assess(bundle, policy, observations)
        elapsed = time.perf_counter() - started
        second = assess(bundle, policy, observations)
        self.assertEqual(first, second)
        self.assertEqual(first.content_sha256, second.content_sha256)
        self.assertLess(elapsed, 2.0)


class WindowsManualDemoEntryReviewArtifactTests(unittest.TestCase):
    def test_cli_is_create_exclusive_and_deny_only(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _, policy = write_documents(root)
            output = root / "manual-demo-entry-review.json"
            command = [
                sys.executable,
                "-B",
                str(CLI),
                "--review-bundle",
                str(root / "review.json"),
                "--trust-policy",
                str(root / "policy.json"),
                "--observations",
                str(root / "observations.json"),
                "--expected-policy-sha256",
                policy.content_sha256,
                "--checked-at-utc",
                CHECKED_AT.isoformat(timespec="microseconds").replace(
                    "+00:00",
                    "Z",
                ),
                "--output",
                str(output),
            ]
            first = subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            original = output.read_bytes() if output.exists() else b""
            second = subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            help_result = subprocess.run(
                [sys.executable, str(CLI), "--help"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(original, output.read_bytes())
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(2, second.returncode)
        self.assertEqual(0, help_result.returncode)
        self.assertTrue(payload["manual_demo_activation_review_required"])
        self.assertFalse(payload["manual_demo_authorized"])
        self.assertFalse(payload["execution_enabled"])
        self.assertEqual("DISABLED", payload["order_capability"])
        help_text = help_result.stdout.casefold()
        for forbidden in (
            "private-key",
            "password",
            "credential",
            "terminal-path",
            "volume",
            "permit",
            "arm",
            "install-task",
            "provider-module",
        ):
            self.assertNotIn(forbidden, help_text)

    def test_cli_inherits_strict_public_document_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _, policy = write_documents(root)
            (root / "policy.json").write_text(
                '{"schema_version":"x","schema_version":"y"}',
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(CLI),
                    "--review-bundle",
                    str(root / "review.json"),
                    "--trust-policy",
                    str(root / "policy.json"),
                    "--observations",
                    str(root / "observations.json"),
                    "--expected-policy-sha256",
                    policy.content_sha256,
                    "--checked-at-utc",
                    CHECKED_AT.isoformat(timespec="microseconds").replace(
                        "+00:00",
                        "Z",
                    ),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(2, result.returncode)
        self.assertIn("DUPLICATE_JSON_KEY", result.stderr)

    def test_operator_only_packaging_boundary(self) -> None:
        module = "live_runtime/windows_manual_demo_entry_review.py"
        cli = "verify_windows_manual_demo_entry_review.py"
        operator = json.loads(
            (ROOT / "config/windows_release_allowlist.v1.json").read_text()
        )["files"]
        self.assertIn(module, operator)
        self.assertIn(cli, operator)
        for name in (
            "windows_decision_service_allowlist.v1.json",
            "windows_execution_service_allowlist.v1.json",
            "windows_status_monitor_allowlist.v1.json",
            "windows_shadow_service_allowlist.v1.json",
        ):
            files = json.loads((ROOT / "config" / name).read_text())["files"]
            self.assertNotIn(module, files)
            self.assertNotIn(cli, files)

    def test_sources_have_no_issuer_mutation_or_broker_surface(self) -> None:
        sources = "\n".join(
            (
                (
                    ROOT
                    / "live_runtime/windows_manual_demo_entry_review.py"
                ).read_text(encoding="utf-8"),
                CLI.read_text(encoding="utf-8"),
            )
        ).casefold()
        for forbidden in (
            "metatrader5",
            "order_send",
            "order_check",
            "win32cred",
            "credentialmanager",
            "register-scheduledtask",
            "start-scheduledtask",
            "private_key",
            "private exponent",
            "execution_policy.safe_to_demo_auto_order",
            "issue_stage_readiness_authorization",
            "sign(",
        ):
            self.assertNotIn(forbidden, sources)

    def test_gate_partition_is_exact(self) -> None:
        self.assertEqual(
            set(EXTERNAL_READINESS_BLOCKERS) - {MANUAL_DEMO_RESULT_GATE},
            set(PRE_MANUAL_GATE_INVENTORY),
        )
        self.assertEqual(
            len(EXTERNAL_READINESS_BLOCKERS) - 1,
            len(PRE_MANUAL_GATE_INVENTORY),
        )


if __name__ == "__main__":
    unittest.main()
