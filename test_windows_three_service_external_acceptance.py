from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from live_runtime.asymmetric_release_trust import (
    rsa_public_key_fingerprint_sha256,
)
from live_runtime.contracts import canonical_json
from live_runtime.demo_soak_three_service_operations import (
    EXTERNAL_READINESS_BLOCKERS,
)
from live_runtime.demo_soak_three_service_operations_artifacts import (
    build_windows_three_service_demo_soak_review_bundle,
)
from live_runtime.three_service_external_acceptance import (
    ACCEPTANCE_OBSERVATION_DOMAIN,
    ASSESSMENT_SCHEMA_VERSION,
    GATE_OWNER_ROLES,
    OBSERVATION_SCHEMA_VERSION,
    OBSERVATIONS_SCHEMA_VERSION,
    POLICY_SCHEMA_VERSION,
    SIGNATURE_ALGORITHM,
    ThreeServiceAcceptanceError,
    ThreeServiceAcceptanceObservation,
    ThreeServiceAcceptanceTrustPolicy,
    assess_three_service_external_acceptance,
    derive_acceptance_observation_id,
    load_three_service_acceptance_observations,
    load_three_service_acceptance_policy,
    load_three_service_review_bundle,
)
from test_live_runtime_asymmetric_release_trust import (
    TEST_RSA_N_HEX,
    _test_rsa_sign,
)
from test_windows_three_service_demo_soak_operations import (
    ISSUED_AT,
    plan,
)


UTC = timezone.utc
CHECKED_AT = datetime(2026, 7, 24, 13, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parent
CLI = ROOT / "verify_windows_three_service_external_acceptance.py"


def review_bundle() -> dict[str, object]:
    return build_windows_three_service_demo_soak_review_bundle(
        plan(),
        issued_at_utc=ISSUED_AT,
    )


def policy_for(bundle: dict[str, object]) -> ThreeServiceAcceptanceTrustPolicy:
    return ThreeServiceAcceptanceTrustPolicy(
        policy_id="three-service-acceptance-policy-v1",
        plan_sha256=str(bundle["plan_sha256"]),
        review_bundle_sha256=str(bundle["content_sha256"]),
        authority_id="offline-operations-acceptance-authority",
        authority_key_id="operations-acceptance-rsa-v1",
        rsa_modulus_hex=TEST_RSA_N_HEX,
        rsa_exponent=65537,
        public_key_fingerprint_sha256=rsa_public_key_fingerprint_sha256(
            TEST_RSA_N_HEX,
            65537,
        ),
        gate_owner_roles=GATE_OWNER_ROLES,
        maximum_observation_ttl_seconds=86_400,
    )


def signed_observation(
    bundle: dict[str, object],
    policy: ThreeServiceAcceptanceTrustPolicy,
    gate_code: str,
    *,
    outcome: str = "PASSED",
    observed_at_utc: datetime = CHECKED_AT - timedelta(minutes=2),
    not_before_utc: datetime = CHECKED_AT - timedelta(minutes=1),
    expires_at_utc: datetime = CHECKED_AT + timedelta(minutes=10),
    **changes: object,
) -> ThreeServiceAcceptanceObservation:
    canonical_plan = bundle["plan"]
    assert isinstance(canonical_plan, dict)
    values: dict[str, object] = {
        "trust_policy_sha256": policy.content_sha256,
        "plan_sha256": bundle["plan_sha256"],
        "review_bundle_sha256": bundle["content_sha256"],
        "decision_release_identity_sha256": canonical_plan["decision"][
            "configured_release_identity_sha256"
        ],
        "execution_release_identity_sha256": canonical_plan["execution"][
            "configured_release_identity_sha256"
        ],
        "status_monitor_release_identity_sha256": canonical_plan[
            "status_monitor"
        ]["configured_release_identity_sha256"],
        "gate_code": gate_code,
        "owner_role": GATE_OWNER_ROLES[gate_code],
        "source_evidence_sha256": hashlib.sha256(
            f"source:{gate_code}".encode("utf-8")
        ).hexdigest(),
        "validation_receipt_sha256": hashlib.sha256(
            f"validation:{gate_code}".encode("utf-8")
        ).hexdigest(),
        "outcome": outcome,
        "observed_at_utc": observed_at_utc,
        "not_before_utc": not_before_utc,
        "expires_at_utc": expires_at_utc,
        "authority_id": policy.authority_id,
        "authority_key_id": policy.authority_key_id,
        "public_key_fingerprint_sha256": (
            policy.public_key_fingerprint_sha256
        ),
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "activation_authorized": False,
        "execution_enabled": False,
        "promotion_eligible": False,
        "order_capability": "DISABLED",
        "max_lot": 0.01,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "schema_version": OBSERVATION_SCHEMA_VERSION,
    }
    values.update(changes)
    observation_id = derive_acceptance_observation_id(values)
    unsigned = ThreeServiceAcceptanceObservation(
        observation_id=observation_id,
        signature_rsa_pkcs1v15_sha256_hex="00" * 384,
        **values,
    )
    signature = _test_rsa_sign(
        ACCEPTANCE_OBSERVATION_DOMAIN
        + canonical_json(unsigned.signing_dict).encode("utf-8")
    )
    return replace(
        unsigned,
        signature_rsa_pkcs1v15_sha256_hex=signature,
    )


def all_observations(
    bundle: dict[str, object],
    policy: ThreeServiceAcceptanceTrustPolicy,
) -> tuple[ThreeServiceAcceptanceObservation, ...]:
    return tuple(
        signed_observation(bundle, policy, gate)
        for gate in EXTERNAL_READINESS_BLOCKERS
    )


def json_ready(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, dict):
        return {key: json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_ready(item) for item in value]
    return value


class ThreeServiceExternalAcceptanceTests(unittest.TestCase):
    def test_complete_signed_dossier_is_activation_review_only(self) -> None:
        bundle = review_bundle()
        policy = policy_for(bundle)
        result = assess_three_service_external_acceptance(
            review_bundle=bundle,
            trust_policy=policy,
            observations=all_observations(bundle, policy),
            expected_policy_sha256=policy.content_sha256,
            clock_provider=lambda: CHECKED_AT,
        )
        self.assertEqual(ASSESSMENT_SCHEMA_VERSION, result.schema_version)
        self.assertEqual(
            "EXTERNAL_ACCEPTANCE_COMPLETE_ACTIVATION_REVIEW_REQUIRED",
            result.status,
        )
        self.assertTrue(result.external_acceptance_complete)
        self.assertEqual(
            tuple(sorted(EXTERNAL_READINESS_BLOCKERS)),
            result.accepted_gates,
        )
        self.assertEqual((), result.pending_gates)
        self.assertEqual({}, dict(result.pending_reasons))
        self.assertTrue(result.activation_review_required)
        self.assertFalse(result.activation_authorized)
        self.assertFalse(result.ready_for_demo_auto_soak)
        self.assertFalse(result.execution_enabled)
        self.assertFalse(result.safe_to_demo_auto_order)
        self.assertFalse(result.live_allowed)
        self.assertFalse(result.promotion_eligible)
        self.assertEqual("DISABLED", result.order_capability)
        self.assertEqual(0.01, result.max_lot)

    def test_partial_failed_future_and_expired_evidence_remain_pending(
        self,
    ) -> None:
        bundle = review_bundle()
        policy = policy_for(bundle)
        gates = tuple(EXTERNAL_READINESS_BLOCKERS)
        values = (
            signed_observation(
                bundle,
                policy,
                gates[0],
                outcome="FAILED",
            ),
            signed_observation(
                bundle,
                policy,
                gates[1],
                observed_at_utc=CHECKED_AT,
                not_before_utc=CHECKED_AT + timedelta(seconds=1),
                expires_at_utc=CHECKED_AT + timedelta(minutes=2),
            ),
            signed_observation(
                bundle,
                policy,
                gates[2],
                observed_at_utc=CHECKED_AT - timedelta(minutes=5),
                not_before_utc=CHECKED_AT - timedelta(minutes=4),
                expires_at_utc=CHECKED_AT,
            ),
        )
        result = assess_three_service_external_acceptance(
            review_bundle=bundle,
            trust_policy=policy,
            observations=values,
            expected_policy_sha256=policy.content_sha256,
            clock_provider=lambda: CHECKED_AT,
        )
        self.assertEqual("BLOCKED_EXTERNAL_ACCEPTANCE", result.status)
        self.assertFalse(result.external_acceptance_complete)
        self.assertEqual((), result.accepted_gates)
        self.assertEqual(
            tuple(sorted(EXTERNAL_READINESS_BLOCKERS)),
            result.pending_gates,
        )
        self.assertEqual("SIGNED_OUTCOME_FAILED", result.pending_reasons[gates[0]])
        self.assertEqual("NOT_YET_VALID", result.pending_reasons[gates[1]])
        self.assertEqual("EXPIRED", result.pending_reasons[gates[2]])
        for gate in gates[3:]:
            self.assertEqual("MISSING", result.pending_reasons[gate])

    def test_external_policy_pin_and_review_bundle_are_mandatory(self) -> None:
        bundle = review_bundle()
        policy = policy_for(bundle)
        with self.assertRaisesRegex(
            ThreeServiceAcceptanceError,
            "ACCEPTANCE_POLICY_PIN_MISMATCH",
        ):
            assess_three_service_external_acceptance(
                review_bundle=bundle,
                trust_policy=policy,
                observations=(),
                expected_policy_sha256="f" * 64,
                clock_provider=lambda: CHECKED_AT,
            )
        tampered = deepcopy(bundle)
        tampered["plan"]["decision"]["service_id"] = "tampered"
        tampered["content_sha256"] = hashlib.sha256(
            canonical_json(
                {key: value for key, value in tampered.items() if key != "content_sha256"}
            ).encode("utf-8")
        ).hexdigest()
        with self.assertRaises(ThreeServiceAcceptanceError):
            assess_three_service_external_acceptance(
                review_bundle=tampered,
                trust_policy=policy,
                observations=(),
                expected_policy_sha256=policy.content_sha256,
                clock_provider=lambda: CHECKED_AT,
            )

    def test_signature_binding_owner_and_duplicate_tamper_fail_closed(
        self,
    ) -> None:
        bundle = review_bundle()
        policy = policy_for(bundle)
        valid = signed_observation(
            bundle,
            policy,
            EXTERNAL_READINESS_BLOCKERS[0],
        )
        cases = (
            replace(valid, signature_rsa_pkcs1v15_sha256_hex="00" * 384),
            replace(valid, plan_sha256="f" * 64),
            replace(valid, owner_role="WRONG_OWNER"),
            replace(valid, authority_id="wrong-authority"),
        )
        for item in cases:
            with self.subTest(item=item), self.assertRaises(
                ThreeServiceAcceptanceError
            ):
                assess_three_service_external_acceptance(
                    review_bundle=bundle,
                    trust_policy=policy,
                    observations=(item,),
                    expected_policy_sha256=policy.content_sha256,
                    clock_provider=lambda: CHECKED_AT,
                )
        with self.assertRaisesRegex(
            ThreeServiceAcceptanceError,
            "DUPLICATE_ACCEPTANCE_GATE",
        ):
            assess_three_service_external_acceptance(
                review_bundle=bundle,
                trust_policy=policy,
                observations=(valid, valid),
                expected_policy_sha256=policy.content_sha256,
                clock_provider=lambda: CHECKED_AT,
            )

    def test_policy_inventory_key_and_observation_constraints(self) -> None:
        bundle = review_bundle()
        policy = policy_for(bundle)
        with self.assertRaises(ValueError):
            replace(
                policy,
                gate_owner_roles={
                    **dict(GATE_OWNER_ROLES),
                    "UNKNOWN_GATE": "WINDOWS_SECURITY_AUTHORITY",
                },
            )
        with self.assertRaises(ValueError):
            replace(policy, rsa_exponent=3)
        with self.assertRaises(ValueError):
            replace(policy, public_key_fingerprint_sha256="f" * 64)
        gate = EXTERNAL_READINESS_BLOCKERS[0]
        source = hashlib.sha256(f"source:{gate}".encode()).hexdigest()
        with self.assertRaises(ValueError):
            signed_observation(
                bundle,
                policy,
                gate,
                validation_receipt_sha256=source,
            )

    def test_clock_regression_or_expiry_during_verification_fails_closed(
        self,
    ) -> None:
        bundle = review_bundle()
        policy = policy_for(bundle)
        item = signed_observation(
            bundle,
            policy,
            EXTERNAL_READINESS_BLOCKERS[0],
            expires_at_utc=CHECKED_AT + timedelta(seconds=1),
        )
        moments = iter(
            (
                CHECKED_AT,
                CHECKED_AT + timedelta(seconds=2),
            )
        )
        result = assess_three_service_external_acceptance(
            review_bundle=bundle,
            trust_policy=policy,
            observations=(item,),
            expected_policy_sha256=policy.content_sha256,
            clock_provider=lambda: next(moments),
        )
        self.assertEqual(
            "EXPIRED_DURING_VERIFICATION",
            result.pending_reasons[item.gate_code],
        )
        moments = iter((CHECKED_AT, CHECKED_AT - timedelta(seconds=1)))
        with self.assertRaisesRegex(
            ThreeServiceAcceptanceError,
            "TRUSTED_CLOCK_REGRESSION",
        ):
            assess_three_service_external_acceptance(
                review_bundle=bundle,
                trust_policy=policy,
                observations=(item,),
                expected_policy_sha256=policy.content_sha256,
                clock_provider=lambda: next(moments),
            )

    def test_deterministic_assessment_for_identical_inputs(self) -> None:
        bundle = review_bundle()
        policy = policy_for(bundle)
        observations = all_observations(bundle, policy)
        kwargs = {
            "review_bundle": bundle,
            "trust_policy": policy,
            "observations": observations,
            "expected_policy_sha256": policy.content_sha256,
            "clock_provider": lambda: CHECKED_AT,
        }
        first = assess_three_service_external_acceptance(**kwargs)
        second = assess_three_service_external_acceptance(**kwargs)
        self.assertEqual(first, second)
        self.assertEqual(first.content_sha256, second.content_sha256)


class ThreeServiceExternalAcceptanceArtifactTests(unittest.TestCase):
    def _write_documents(
        self,
        root: Path,
        *,
        observations: tuple[ThreeServiceAcceptanceObservation, ...] | None = None,
    ) -> tuple[dict[str, object], ThreeServiceAcceptanceTrustPolicy]:
        bundle = review_bundle()
        policy = policy_for(bundle)
        observed = (
            all_observations(bundle, policy)
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
                        json_ready(value.to_canonical_dict())
                        for value in observed
                    ],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return bundle, policy

    def test_strict_loaders_round_trip_public_documents(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            bundle, policy = self._write_documents(root)
            loaded_bundle = load_three_service_review_bundle(
                root / "review.json"
            )
            loaded_policy = load_three_service_acceptance_policy(
                root / "policy.json"
            )
            loaded_observations = load_three_service_acceptance_observations(
                root / "observations.json"
            )
        self.assertEqual(bundle, loaded_bundle)
        self.assertEqual(policy, loaded_policy)
        self.assertEqual(
            tuple(sorted(EXTERNAL_READINESS_BLOCKERS)),
            tuple(sorted(value.gate_code for value in loaded_observations)),
        )

    def test_strict_loaders_reject_symlink_empty_oversize_duplicate_and_nan(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            valid = root / "valid.json"
            valid.write_text("{}\n", encoding="utf-8")
            cases = {
                "empty.json": "",
                "duplicate.json": '{"schema_version":"a","schema_version":"b"}',
                "nan.json": '{"value":NaN}',
                "oversize.json": " " * 1_048_577,
            }
            for name, text in cases.items():
                path = root / name
                path.write_text(text, encoding="utf-8")
                with self.subTest(name=name), self.assertRaises(
                    ThreeServiceAcceptanceError
                ):
                    load_three_service_acceptance_policy(path)
            link = root / "link.json"
            link.symlink_to(valid)
            with self.assertRaises(ThreeServiceAcceptanceError):
                load_three_service_acceptance_policy(link)

    def test_secret_material_and_schema_drift_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _, policy = self._write_documents(root)
            payload = policy.to_canonical_dict()
            payload["private_key"] = "forbidden"
            (root / "secret.json").write_text(
                json.dumps(payload),
                encoding="utf-8",
            )
            with self.assertRaises(ThreeServiceAcceptanceError):
                load_three_service_acceptance_policy(root / "secret.json")

    def test_cli_is_report_only_and_create_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _, policy = self._write_documents(root)
            output = root / "assessment.json"
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
            second = subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            help_result = subprocess.run(
                [sys.executable, str(CLI), "--help"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(2, second.returncode)
        self.assertEqual(
            "EXTERNAL_ACCEPTANCE_COMPLETE_ACTIVATION_REVIEW_REQUIRED",
            payload["status"],
        )
        self.assertFalse(payload["ready_for_demo_auto_soak"])
        self.assertEqual(0, help_result.returncode)
        help_text = help_result.stdout.casefold()
        for forbidden in (
            "private-key",
            "password",
            "credential",
            "terminal-path",
            "volume",
            "order",
            "permit",
            "arm",
            "install",
            "start-task",
        ):
            self.assertNotIn(forbidden, help_text)

    def test_operator_only_packaging_boundary(self) -> None:
        module = "live_runtime/three_service_external_acceptance.py"
        cli = "verify_windows_three_service_external_acceptance.py"
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

    def test_sources_have_no_mutation_or_private_key_surface(self) -> None:
        sources = "\n".join(
            (
                (ROOT / "live_runtime/three_service_external_acceptance.py")
                .read_text(encoding="utf-8"),
                CLI.read_text(encoding="utf-8"),
            )
        ).casefold()
        for forbidden in (
            "metatrader5",
            "order_send",
            "order_check",
            "subprocess",
            "win32cred",
            "credentialmanager",
            "register-scheduledtask",
            "start-scheduledtask",
            "private_key",
            "private exponent",
            "execution_policy.safe_to_demo_auto_order",
        ):
            self.assertNotIn(forbidden, sources)


if __name__ == "__main__":
    unittest.main()
