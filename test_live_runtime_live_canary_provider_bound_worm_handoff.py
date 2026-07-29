from __future__ import annotations

import ast
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

import execution_policy
from live_runtime.live_canary_portable_launch_custody import (
    decode_live_canary_portable_custody_policy,
)
from live_runtime.live_canary_provider_bound_worm_handoff import (
    ADMISSION_MEMBER,
    CUSTODY_POLICY_MEMBER,
    LiveCanaryProviderBoundWormHandoffError,
    PROVIDER_POLICY_MEMBER,
    REQUEST_MANIFEST_MEMBER,
    REQUEST_MEMBER_ORDER,
    prepare_live_canary_provider_bound_worm_request,
    verify_live_canary_provider_bound_worm_receipt,
    verify_live_canary_provider_bound_worm_request_path,
)

custody_fixture_module = importlib.import_module(
    "test_live_runtime_live_canary_provider_bound_portable_custody"
)
handoff_module = importlib.import_module(
    "live_runtime.live_canary_provider_bound_worm_handoff"
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


class LiveCanaryProviderBoundWormHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        fixture_type = getattr(
            custody_fixture_module,
            "LiveCanaryProviderBoundPortableCustodyTests",
        )
        fixture_type.setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        fixture_type = getattr(
            custody_fixture_module,
            "LiveCanaryProviderBoundPortableCustodyTests",
        )
        fixture_type.tearDownClass()
        super().tearDownClass()

    def setUp(self) -> None:
        fixture_type = getattr(
            custody_fixture_module,
            "LiveCanaryProviderBoundPortableCustodyTests",
        )
        fixture = fixture_type(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.admission_data = fixture.admission.canonical_json().encode("utf-8")
        self.custody_data = fixture.policy.canonical_json().encode("utf-8")
        self.provider_data = (
            fixture.fixture.provider.policy.canonical_json().encode("utf-8")
        )
        self.receipt_data = fixture.receipt.canonical_json().encode("utf-8")
        self.admission_path = self.root / "provider-bound-admission.json"
        self.custody_path = self.root / "portable-custody-policy.json"
        self.provider_path = self.root / "provider-acceptance-policy.json"
        self.receipt_path = self.root / "provider-bound-receipt.json"
        self.readback_path = self.root / "provider-bound-readback.json"
        self.admission_path.write_bytes(self.admission_data)
        self.custody_path.write_bytes(self.custody_data)
        self.provider_path.write_bytes(self.provider_data)
        self.receipt_path.write_bytes(self.receipt_data)
        self.readback_path.write_bytes(self.admission_data)
        self.requested_at = fixture.now
        self.retain_until = fixture.now + timedelta(days=366)

    def _pins(self, **changes: str) -> dict[str, str]:
        values = {
            "expected_provider_bound_admission_sha256": _sha256(
                self.admission_data
            ),
            "expected_custody_policy_sha256": _sha256(self.custody_data),
            "expected_provider_policy_sha256": _sha256(self.provider_data),
            "expected_target_host_identity_sha256": (
                self.fixture.admission.target_host_identity_sha256
            ),
            "expected_installed_environment_sha256": (
                self.fixture.admission.installed_environment_sha256
            ),
            "expected_live_execution_release_identity_sha256": (
                self.fixture.admission.live_execution_release_identity_sha256
            ),
            "expected_live_execution_task_definition_sha256": (
                self.fixture.admission.live_execution_task_definition_sha256
            ),
            "expected_launcher_trust_policy_sha256": (
                self.fixture.policy.launcher_trust_policy_sha256
            ),
        }
        values.update(changes)
        return values

    def _prepare(self, name: str = "xm-v1") -> tuple[Path, dict[str, object]]:
        output = self.root / (
            f"live-canary-provider-bound-worm-request-{name}.zip"
        )
        result = prepare_live_canary_provider_bound_worm_request(
            admission_path=self.admission_path,
            custody_policy_path=self.custody_path,
            provider_policy_path=self.provider_path,
            request_id="xm-provider-bound-worm-request-v1",
            requested_at_utc=_utc(self.requested_at),
            minimum_retain_until_utc=_utc(self.retain_until),
            output=output,
            **self._pins(),
        )
        return output, result

    def _verify_receipt(
        self,
        request: Path,
        *,
        receipt_path: Path | None = None,
        readback_path: Path | None = None,
        readback_sha256: str | None = None,
        verified_at: datetime | None = None,
        suffix: str = "xm-v1",
    ) -> dict[str, object]:
        assessment = self.root / (
            f"live-canary-provider-bound-worm-assessment-{suffix}.json"
        )
        return verify_live_canary_provider_bound_worm_receipt(
            request_archive=request,
            expected_request_archive_sha256=_sha256(request.read_bytes()),
            receipt_path=receipt_path or self.receipt_path,
            readback_path=readback_path or self.readback_path,
            expected_readback_sha256=(
                readback_sha256 or _sha256(self.admission_data)
            ),
            verified_at_utc=_utc(
                verified_at or self.fixture.now + timedelta(seconds=1)
            ),
            assessment_output=assessment,
            **self._pins(),
        )

    def _cli_pin_arguments(self) -> list[str]:
        pins = self._pins()
        return [
            "--expected-provider-bound-admission-sha256",
            pins["expected_provider_bound_admission_sha256"],
            "--expected-custody-policy-sha256",
            pins["expected_custody_policy_sha256"],
            "--expected-provider-policy-sha256",
            pins["expected_provider_policy_sha256"],
            "--expected-target-host-identity-sha256",
            pins["expected_target_host_identity_sha256"],
            "--expected-installed-environment-sha256",
            pins["expected_installed_environment_sha256"],
            "--expected-live-execution-release-identity-sha256",
            pins["expected_live_execution_release_identity_sha256"],
            "--expected-live-execution-task-definition-sha256",
            pins["expected_live_execution_task_definition_sha256"],
            "--expected-launcher-trust-policy-sha256",
            pins["expected_launcher_trust_policy_sha256"],
        ]

    def test_ac1_deterministic_exact_four_member_request(self) -> None:
        first, first_result = self._prepare("first")
        second, second_result = self._prepare("second")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(
            first_result["request_identity_sha256"],
            second_result["request_identity_sha256"],
        )
        verified = verify_live_canary_provider_bound_worm_request_path(
            first,
            expected_request_archive_sha256=_sha256(first.read_bytes()),
            **self._pins(),
        )
        self.assertEqual(
            "LIVE_CANARY_PROVIDER_BOUND_WORM_REQUEST_VERIFIED",
            verified["status"],
        )
        with zipfile.ZipFile(first) as archive:
            self.assertEqual(REQUEST_MEMBER_ORDER, tuple(archive.namelist()))
            for info in archive.infolist():
                self.assertEqual((1980, 1, 1, 0, 0, 0), info.date_time)
                self.assertEqual(zipfile.ZIP_STORED, info.compress_type)
                self.assertEqual(b"", info.extra)
                self.assertEqual(b"", info.comment)
            self.assertEqual(self.admission_data, archive.read(ADMISSION_MEMBER))
            self.assertEqual(self.custody_data, archive.read(CUSTODY_POLICY_MEMBER))
            self.assertEqual(self.provider_data, archive.read(PROVIDER_POLICY_MEMBER))
            self.assertTrue(archive.read(REQUEST_MANIFEST_MEMBER))
        decoded = decode_live_canary_portable_custody_policy(self.custody_data)
        self.assertEqual(self.fixture.policy, decoded)
        self.assertFalse(first_result["runtime_admission_seal"])
        self.assertFalse(first_result["runtime_custody_seal"])
        self.assertFalse(first_result["live_allowed"])
        self.assertEqual("DISABLED", first_result["order_capability"])

    def test_ac2_external_pins_and_authority_separation_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundWormHandoffError,
            "HANDOFF_EXTERNAL_PIN_MISMATCH",
        ):
            prepare_live_canary_provider_bound_worm_request(
                admission_path=self.admission_path,
                custody_policy_path=self.custody_path,
                provider_policy_path=self.provider_path,
                request_id="xm-provider-bound-worm-request-v1",
                requested_at_utc=_utc(self.requested_at),
                minimum_retain_until_utc=_utc(self.retain_until),
                output=self.root
                / "live-canary-provider-bound-worm-request-wrong-pin.zip",
                **self._pins(
                    expected_installed_environment_sha256="a" * 64
                ),
            )
        reused = self.fixture._policy(
            custody_key_id=(
                self.fixture.fixture.provider.policy.owner_authority_key_id
            )
        )
        reused_path = self.root / "reused-custody-policy.json"
        reused_data = reused.canonical_json().encode("utf-8")
        reused_path.write_bytes(reused_data)
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundWormHandoffError,
            "CUSTODY_PROVIDER_AUTHORITY_REUSE",
        ):
            prepare_live_canary_provider_bound_worm_request(
                admission_path=self.admission_path,
                custody_policy_path=reused_path,
                provider_policy_path=self.provider_path,
                request_id="xm-provider-bound-worm-request-v1",
                requested_at_utc=_utc(self.requested_at),
                minimum_retain_until_utc=_utc(self.retain_until),
                output=self.root
                / "live-canary-provider-bound-worm-request-reused.zip",
                **self._pins(
                    expected_custody_policy_sha256=_sha256(reused_data)
                ),
            )

    def test_ac3_archive_collision_tamper_and_lock_reject(self) -> None:
        request, _ = self._prepare()
        with self.assertRaises(LiveCanaryProviderBoundWormHandoffError):
            self._prepare()
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundWormHandoffError,
            "REQUEST_ARCHIVE_EXTERNAL_PIN_MISMATCH",
        ):
            verify_live_canary_provider_bound_worm_request_path(
                request,
                expected_request_archive_sha256="a" * 64,
                **self._pins(),
            )
        tampered = self.root / "tampered.zip"
        tampered.write_bytes(request.read_bytes() + b"trailing-data")
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundWormHandoffError,
            "REQUEST_ARCHIVE_INVALID",
        ):
            verify_live_canary_provider_bound_worm_request_path(
                tampered,
                expected_request_archive_sha256=_sha256(tampered.read_bytes()),
                **self._pins(),
            )
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            with self.assertRaisesRegex(
                LiveCanaryProviderBoundWormHandoffError,
                "CENTRAL_LIVE_LOCK_NOT_FALSE",
            ):
                verify_live_canary_provider_bound_worm_request_path(
                    request,
                    expected_request_archive_sha256=_sha256(
                        request.read_bytes()
                    ),
                    **self._pins(),
                )
        final_guard_output = self.root / (
            "live-canary-provider-bound-worm-request-final-guard.zip"
        )
        guard_error = LiveCanaryProviderBoundWormHandoffError(
            "CENTRAL_LIVE_LOCK_NOT_FALSE"
        )
        with mock.patch.object(
            handoff_module,
            "_require_central_lock",
            side_effect=(None, None, None, guard_error),
        ):
            with self.assertRaisesRegex(
                LiveCanaryProviderBoundWormHandoffError,
                "CENTRAL_LIVE_LOCK_NOT_FALSE",
            ):
                prepare_live_canary_provider_bound_worm_request(
                    admission_path=self.admission_path,
                    custody_policy_path=self.custody_path,
                    provider_policy_path=self.provider_path,
                    request_id="xm-provider-bound-worm-request-v1",
                    requested_at_utc=_utc(self.requested_at),
                    minimum_retain_until_utc=_utc(self.retain_until),
                    output=final_guard_output,
                    **self._pins(),
                )
        self.assertFalse(final_guard_output.exists())

    def test_ac5_strict_input_time_and_symlink_guards(self) -> None:
        noncanonical = self.root / "noncanonical-admission.json"
        noncanonical_data = self.admission_data + b"\n"
        noncanonical.write_bytes(noncanonical_data)
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundWormHandoffError,
            "PROVIDER_BOUND_ADMISSION_JSON_NOT_CANONICAL",
        ):
            prepare_live_canary_provider_bound_worm_request(
                admission_path=noncanonical,
                custody_policy_path=self.custody_path,
                provider_policy_path=self.provider_path,
                request_id="xm-provider-bound-worm-request-v1",
                requested_at_utc=_utc(self.requested_at),
                minimum_retain_until_utc=_utc(self.retain_until),
                output=self.root
                / "live-canary-provider-bound-worm-request-noncanonical.zip",
                **self._pins(
                    expected_provider_bound_admission_sha256=_sha256(
                        noncanonical_data
                    )
                ),
            )
        for requested, retained in (
            (
                self.requested_at - timedelta(microseconds=1),
                self.retain_until,
            ),
            (self.requested_at, self.requested_at + timedelta(days=1)),
        ):
            with self.subTest(requested=requested, retained=retained):
                with self.assertRaises(LiveCanaryProviderBoundWormHandoffError):
                    prepare_live_canary_provider_bound_worm_request(
                        admission_path=self.admission_path,
                        custody_policy_path=self.custody_path,
                        provider_policy_path=self.provider_path,
                        request_id="xm-provider-bound-worm-request-v1",
                        requested_at_utc=_utc(requested),
                        minimum_retain_until_utc=_utc(retained),
                        output=self.root
                        / (
                            "live-canary-provider-bound-worm-request-time-"
                            f"{requested.microsecond}.zip"
                        ),
                        **self._pins(),
                    )
        symlink_output = self.root / (
            "live-canary-provider-bound-worm-request-symlink.zip"
        )
        try:
            symlink_output.symlink_to(self.root / "missing-target")
        except OSError:
            return
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundWormHandoffError,
            "REQUEST_DESTINATION_INVALID",
        ):
            prepare_live_canary_provider_bound_worm_request(
                admission_path=self.admission_path,
                custody_policy_path=self.custody_path,
                provider_policy_path=self.provider_path,
                request_id="xm-provider-bound-worm-request-v1",
                requested_at_utc=_utc(self.requested_at),
                minimum_retain_until_utc=_utc(self.retain_until),
                output=symlink_output,
                **self._pins(),
            )

    def test_ac6_valid_receipt_and_readback_publish_deny_only_assessment(self) -> None:
        request, _ = self._prepare()
        result = self._verify_receipt(request)
        self.assertEqual(
            "LIVE_CANARY_PROVIDER_BOUND_WORM_RECEIPT_VERIFIED",
            result["status"],
        )
        self.assertTrue(result["signed_receipt_accepted"])
        self.assertTrue(result["byte_identical_exported_readback_accepted"])
        for field in (
            "direct_storage_api_inspection_performed",
            "runtime_admission_seal",
            "runtime_custody_seal",
            "runtime_sealed_custody_emitted",
            "cas_reservation_performed",
            "nonce_consumed",
            "central_unlock_performed",
            "process_launch_performed",
            "bootstrap_authorized",
            "process_launch_authorized",
            "execution_authorized",
            "activation_authorized",
            "broker_mutation_authorized",
            "promotion_eligible",
            "safe_to_demo_auto_order",
            "live_allowed",
        ):
            self.assertFalse(result[field], field)
        self.assertEqual("DISABLED", result["order_capability"])
        self.assertTrue(Path(str(result["assessment"])).is_file())

    def test_ac7_signature_readback_and_chronology_reject(self) -> None:
        request, _ = self._prepare()
        bad_receipt = replace(
            self.fixture.receipt,
            signature_rsa_pkcs1v15_sha256_hex=(
                "0"
                * len(
                    self.fixture.receipt.signature_rsa_pkcs1v15_sha256_hex
                )
            ),
        )
        bad_receipt_path = self.root / "bad-receipt.json"
        bad_receipt_path.write_bytes(
            bad_receipt.canonical_json().encode("utf-8")
        )
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundWormHandoffError,
            "CUSTODY_RECEIPT_SIGNATURE_INVALID",
        ):
            self._verify_receipt(
                request,
                receipt_path=bad_receipt_path,
                suffix="bad-signature",
            )
        cross_unsigned = replace(
            self.fixture.receipt,
            candidate_sha256="a" * 64,
            signature_rsa_pkcs1v15_sha256_hex="",
        )
        signing_message = (
            custody_fixture_module.provider_bound_admission_custody_signing_message(
                cross_unsigned
            )
        )
        cross_signed = replace(
            cross_unsigned,
            signature_rsa_pkcs1v15_sha256_hex=(
                custody_fixture_module.custody_support.custody_signature(
                    signing_message
                )
            ),
        )
        cross_path = self.root / "cross-bound-receipt.json"
        cross_path.write_bytes(cross_signed.canonical_json().encode("utf-8"))
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundWormHandoffError,
            "CUSTODY_RECEIPT_BINDING_MISMATCH",
        ):
            self._verify_receipt(
                request,
                receipt_path=cross_path,
                suffix="cross-bound",
            )
        drift_path = self.root / "drift-readback.json"
        drift_path.write_bytes(b"{}")
        with self.assertRaises(LiveCanaryProviderBoundWormHandoffError):
            self._verify_receipt(
                request,
                readback_path=drift_path,
                readback_sha256=_sha256(b"{}"),
                suffix="drift-readback",
            )
        with self.assertRaisesRegex(
            LiveCanaryProviderBoundWormHandoffError,
            "CUSTODY_RECEIPT_TIME_OR_RETENTION_INVALID",
        ):
            self._verify_receipt(
                request,
                verified_at=self.fixture.now + timedelta(seconds=301),
                suffix="stale",
            )

    def test_ac11_cli_runs_in_isolated_normal_and_optimized_modes(self) -> None:
        script = Path(
            "manage_live_canary_provider_bound_worm_handoff.py"
        ).resolve()
        for optimized in (False, True):
            prefix = [sys.executable, "-I", "-S"]
            if optimized:
                prefix.append("-O")
            prefix.extend(("-B", str(script)))
            request = self.root / (
                "live-canary-provider-bound-worm-request-cli-"
                f"{int(optimized)}.zip"
            )
            prepare = subprocess.run(
                [
                    *prefix,
                    "prepare-request",
                    "--admission",
                    str(self.admission_path),
                    "--custody-policy",
                    str(self.custody_path),
                    "--provider-policy",
                    str(self.provider_path),
                    *self._cli_pin_arguments(),
                    "--request-id",
                    "xm-provider-bound-worm-request-cli-v1",
                    "--requested-at-utc",
                    _utc(self.requested_at),
                    "--minimum-retain-until-utc",
                    _utc(self.retain_until),
                    "--output",
                    str(request),
                ],
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(0, prepare.returncode, prepare.stderr)
            self.assertIn(
                "LIVE_CANARY_PROVIDER_BOUND_WORM_REQUEST_READY",
                prepare.stdout,
            )
            verify = subprocess.run(
                [
                    *prefix,
                    "verify-request",
                    "--request-archive",
                    str(request),
                    "--expected-request-archive-sha256",
                    _sha256(request.read_bytes()),
                    *self._cli_pin_arguments(),
                ],
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(0, verify.returncode, verify.stderr)
            self.assertIn(
                "LIVE_CANARY_PROVIDER_BOUND_WORM_REQUEST_VERIFIED",
                verify.stdout,
            )
            assessment = self.root / (
                "live-canary-provider-bound-worm-assessment-cli-"
                f"{int(optimized)}.json"
            )
            receipt = subprocess.run(
                [
                    *prefix,
                    "verify-receipt",
                    "--request-archive",
                    str(request),
                    "--expected-request-archive-sha256",
                    _sha256(request.read_bytes()),
                    *self._cli_pin_arguments(),
                    "--receipt",
                    str(self.receipt_path),
                    "--readback",
                    str(self.readback_path),
                    "--expected-readback-sha256",
                    _sha256(self.admission_data),
                    "--verified-at-utc",
                    _utc(self.fixture.now + timedelta(seconds=1)),
                    "--assessment-output",
                    str(assessment),
                ],
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(0, receipt.returncode, receipt.stderr)
            self.assertIn(
                "LIVE_CANARY_PROVIDER_BOUND_WORM_RECEIPT_VERIFIED",
                receipt.stdout,
            )

    def test_ac10_static_surface_contains_no_effect_import(self) -> None:
        source = Path(
            "live_runtime/live_canary_provider_bound_worm_handoff.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".", 1)[0])
        self.assertTrue(
            imports.isdisjoint(
                {
                    "MetaTrader5",
                    "ctypes",
                    "keyring",
                    "requests",
                    "socket",
                    "sqlite3",
                    "subprocess",
                    "urllib",
                    "win32cred",
                }
            )
        )
        self.assertIs(False, execution_policy.LIVE_ALLOWED)


if __name__ == "__main__":
    unittest.main()
