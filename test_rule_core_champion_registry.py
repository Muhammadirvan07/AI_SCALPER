from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from live_runtime.model_governance import RULE_CORE_MODEL_SOURCE_PATHS
from live_runtime.rule_core_model_artifact import build_archive_bytes
from live_runtime.rule_core_champion_registry import (
    RECEIPT_SIGNATURE_DOMAIN,
    REGISTRY_SAFETY,
    REQUEST_ARTIFACT_MEMBER,
    REQUEST_MANIFEST_MEMBER,
    SIGNATURE_ALGORITHM,
    RuleCoreChampionRegistryError,
    canonical_registry_json,
    prepare_registry_request,
    public_key_fingerprint_sha256,
    verify_registry_receipt,
    verify_registry_request_path,
)


TEST_RSA_N_HEX = (
    "b255752ab2bd742a42f53ff66a77489fc8c1ab65f50b18849f24b88777f8e6a"
    "33d0b66e9adfd494aefee1566f62774f701407dbebae74ed091d4c409ce6476b0"
    "16b5d8015112f9c9944c1608d5ec5d4b06954b318111953c76a6c854f5a8ffc9"
    "de6e71731ce8d1ad0212a78b36ec2806c60a817532d442a4f6aa14624afd945b0"
    "97733acd802d7d729d9f6f68eacf0718514d19dba0e0523052cb5e8e8ecaa6dc"
    "9120b4e225a240d24894fb75fd75b039b91a87b4b7afcea0fbe7b86a91bf6879"
    "a97e88ec86107b48da4586273e3dc7969145375b42850d4586ecacf50bb6621476"
    "6bfae75f9b5208eb8e4bd0ef7ee390130f5d3d01c44982713e51ee383dc50a120"
    "625c1c7ab903b7494309e8960499e3a0f9e7a5ae5cc167bd59e71f95cfb05954c"
    "0b2dc00747a33d877ea6362156f78854d4feb3f26529e4cea5a1e9ccecd8efcfe"
    "fb06b1f14e9c40e7a0ff213c61367a8135b710bba9be88c75e0b40cb80a859499"
    "50a8a14e9bdd3560bc3200fe84ac9fa758d751fe124fa93bac2594e55"
)
TEST_RSA_D_HEX = (
    "0c297ad7a21ffc8ba34c6183d727f26a7f410204ee8cc6abc8c4b2d6fe4e19c0"
    "9939ad5793779a2783ac6b863d945c4c3a28214b4028e53da12c6f003234b4c9"
    "768b0943b1b94712c1cbdc96d6ac0b82c1dcada79f234957b9c9cf10c83e31cf"
    "9d1d501c6724d3a3e667ca485ac30949c8f8cf72643888a102777ff36224e018c"
    "350ff53b2d9a2c9b83f76b1c2f23565b08b466e68d16af543f5942461ba3e374"
    "586b701a9a3172154540efd350a9558ee23a5675f32f08bafee30337356065e84c"
    "80699f974f6bc7e641c808f45d24d892e10c82e9740acf4df9502e9d7f7831fa"
    "f61223a3f0efadd5d8e2ef1937dc6e2624af137350084f49a5a664999889b87c6"
    "97add9172b606f1cc3f3646d6d4c42ae6e5a0e4e37f306683f2d6865310163188"
    "18288df54fad9c6a22e37daa5150eec82143dd950d240c1270da495bd9acd01a17"
    "4a49877528a243044aed804430fef404055367bfe2b2fb9553b723a174e75588ea"
    "f328a702fe62d32222ef756f00c23f4e4f04e1f107e759a169f9983"
)
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


def _rsa_sign(message: bytes) -> str:
    modulus = int(TEST_RSA_N_HEX, 16)
    private_exponent = int(TEST_RSA_D_HEX, 16)
    length = (modulus.bit_length() + 7) // 8
    digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
    padding = b"\xff" * (length - len(digest_info) - 3)
    encoded = b"\x00\x01" + padding + b"\x00" + digest_info
    return pow(
        int.from_bytes(encoded, "big"), private_exponent, modulus
    ).to_bytes(length, "big").hex()


class RuleCoreChampionRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # macOS exposes /var through the /private/var symlink.  Resolve the
        # fixture root so these tests exercise the intended direct-path rule
        # instead of failing on that operating-system alias.
        self.root = Path(self.temp.name).resolve(strict=True)
        self.commit = "a" * 40
        self.tree = "b" * 40
        source = {
            path: f"# fixture {path}\n".encode("utf-8")
            for path in RULE_CORE_MODEL_SOURCE_PATHS
        }
        config = {
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
        }
        start = datetime(2026, 7, 27, tzinfo=timezone.utc)
        rows = ["Datetime,Close,High,Low,Open,Volume"]
        for index in range(96):
            stamp = start + timedelta(minutes=15 * index)
            rows.append(
                f"{stamp.isoformat()},100.1,100.5,99.5,100.0,{index + 1}"
            )
        archive, artifact = build_archive_bytes(
            source_members=source,
            config_bytes=(json.dumps(config, sort_keys=True) + "\n").encode(),
            snapshot_bytes=("\n".join(rows) + "\n").encode(),
            branch="agent/live-grade-phase3",
            commit=self.commit,
            tree=self.tree,
            registered_at=datetime(2026, 7, 29, tzinfo=timezone.utc),
        )
        self.artifact_path = self.root / "champion.zip"
        self.artifact_path.write_bytes(archive)
        self.artifact = artifact
        self.pins = {
            "expected_archive_sha256": artifact["archive_sha256"],
            "expected_model_artifact_sha256": artifact[
                "model_artifact_sha256"
            ],
            "expected_training_snapshot_sha256": artifact[
                "training_snapshot_sha256"
            ],
            "expected_config_sha256": artifact["config_sha256"],
            "expected_git_commit": self.commit,
            "expected_git_tree": self.tree,
        }
        self.requested_at = "2026-07-29T01:00:00.000000Z"
        self.retain_until = "2027-07-30T01:00:00.000000Z"

    def _cli_pins(self) -> list[str]:
        return [
            "--expected-archive-sha256",
            str(self.pins["expected_archive_sha256"]),
            "--expected-model-artifact-sha256",
            str(self.pins["expected_model_artifact_sha256"]),
            "--expected-training-snapshot-sha256",
            str(self.pins["expected_training_snapshot_sha256"]),
            "--expected-config-sha256",
            str(self.pins["expected_config_sha256"]),
            "--expected-git-commit",
            self.commit,
            "--expected-git-tree",
            self.tree,
        ]

    def _run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        script = Path(__file__).resolve().parent / (
            "manage_rule_core_champion_registry.py"
        )
        return subprocess.run(
            (sys.executable, "-I", "-S", "-B", str(script), *arguments),
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def _prepare(self, name: str = "rule-core-champion-registry-request-aaaaaaaa.zip"):
        return prepare_registry_request(
            artifact_path=self.artifact_path,
            registry_id="model-registry-jp-01",
            destination_id="champion-immutable-prod-01",
            requested_at_utc=self.requested_at,
            minimum_retain_until_utc=self.retain_until,
            output=self.root / name,
            **self.pins,
        )

    def _policy(self) -> dict[str, object]:
        return {
            "schema_version": "rule-core-champion-registry-rsa-policy-v1",
            "policy_id": "registry-policy-01",
            "registry_id": "model-registry-jp-01",
            "custodian_id": "independent-custodian-01",
            "custodian_key_id": "registry-rsa-key-01",
            "storage_provider_id": "immutable-provider-01",
            "destination_id": "champion-immutable-prod-01",
            "minimum_retain_until_utc": self.retain_until,
            "rsa_modulus_hex": TEST_RSA_N_HEX,
            "rsa_exponent": 65537,
            "public_key_fingerprint_sha256": public_key_fingerprint_sha256(
                TEST_RSA_N_HEX, 65537
            ),
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "safety": REGISTRY_SAFETY,
        }

    def _receipt(
        self,
        request: dict[str, object],
        policy: dict[str, object],
        **overrides: object,
    ) -> dict[str, object]:
        unsigned: dict[str, object] = {
            "schema_version": "rule-core-champion-registry-receipt-v1",
            "receipt_id": "registry-receipt-01",
            "request_identity_sha256": request["request_identity_sha256"],
            "request_archive_sha256": request["archive_sha256"],
            "artifact_archive_sha256": self.artifact["archive_sha256"],
            "registry_id": "model-registry-jp-01",
            "custodian_id": "independent-custodian-01",
            "custodian_key_id": "registry-rsa-key-01",
            "public_key_fingerprint_sha256": policy[
                "public_key_fingerprint_sha256"
            ],
            "trust_policy_sha256": hashlib.sha256(
                canonical_registry_json(policy)
            ).hexdigest(),
            "acknowledged_at_utc": "2026-07-29T01:05:00.000000Z",
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "remote_object": {
                "storage_provider_id": "immutable-provider-01",
                "destination_id": "champion-immutable-prod-01",
                "object_key_sha256": "1" * 64,
                "object_version_id_sha256": "2" * 64,
                "content_sha256": self.artifact["archive_sha256"],
                "size_bytes": self.artifact["archive_size_bytes"],
                "retain_until_utc": self.retain_until,
                "versioning_enabled": True,
                "immutable_retention_enabled": True,
                "content_hash_verified": True,
            },
            "external_registry": {
                "custodian_attests_registration_performed": True,
                "custodian_attests_exact_bytes_verified": True,
                "custodian_attests_immutable_retention_enabled": True,
            },
            "safety": REGISTRY_SAFETY,
        }
        unsigned.update(overrides)
        return {
            **unsigned,
            "signature_rsa_pkcs1v15_sha256_hex": _rsa_sign(
                RECEIPT_SIGNATURE_DOMAIN + canonical_registry_json(unsigned)
            ),
        }

    def _verify_receipt(
        self,
        request_path: Path,
        request: dict[str, object],
        policy: dict[str, object],
        receipt: dict[str, object],
        *,
        assessment_name: str = "rule-core-champion-registry-assessment-fixture.json",
    ) -> dict[str, object]:
        policy_path = self.root / "policy.json"
        receipt_path = self.root / "receipt.json"
        policy_bytes = canonical_registry_json(policy)
        policy_path.write_bytes(policy_bytes)
        receipt_path.write_bytes(canonical_registry_json(receipt))
        return verify_registry_receipt(
            request_archive=request_path,
            expected_request_archive_sha256=request["archive_sha256"],
            policy_path=policy_path,
            expected_policy_sha256=hashlib.sha256(policy_bytes).hexdigest(),
            receipt_path=receipt_path,
            verified_at_utc="2026-07-29T01:10:00.000000Z",
            assessment_output=self.root / assessment_name,
            **self.pins,
        )

    def test_ac1_deterministic_request_and_deny_only_safety(self):
        first = self._prepare()
        second = self._prepare(
            "rule-core-champion-registry-request-aaaaaaaa-copy.zip"
        )
        first_path = Path(first["archive"])
        second_path = Path(second["archive"])
        self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
        self.assertEqual(first["archive_sha256"], second["archive_sha256"])
        self.assertEqual("DISABLED", first["order_capability"])
        self.assertFalse(first["quality_approved"])
        self.assertFalse(first["promotion_eligible"])
        self.assertFalse(first["safe_to_demo_auto_order"])
        self.assertFalse(first["live_allowed"])
        with zipfile.ZipFile(first_path) as archive:
            self.assertEqual(
                [REQUEST_ARTIFACT_MEMBER, REQUEST_MANIFEST_MEMBER],
                archive.namelist(),
            )
            self.assertEqual(
                self.artifact_path.read_bytes(),
                archive.read(REQUEST_ARTIFACT_MEMBER),
            )

    def test_ac2_wrong_artifact_pin_creates_no_output(self):
        output = self.root / "rule-core-champion-registry-request-aaaaaaaa.zip"
        pins = dict(self.pins)
        pins["expected_model_artifact_sha256"] = "f" * 64
        with self.assertRaisesRegex(
            RuleCoreChampionRegistryError, "ARTIFACT_EXTERNAL_PIN_MISMATCH"
        ):
            prepare_registry_request(
                artifact_path=self.artifact_path,
                registry_id="model-registry-jp-01",
                destination_id="champion-immutable-prod-01",
                requested_at_utc=self.requested_at,
                minimum_retain_until_utc=self.retain_until,
                output=output,
                **pins,
            )
        self.assertFalse(output.exists())

    def test_ac3_request_rejects_extra_member(self):
        request = self._prepare()
        original = Path(request["archive"])
        tampered = self.root / "tampered.zip"
        with zipfile.ZipFile(original) as source, zipfile.ZipFile(
            tampered, "w", compression=zipfile.ZIP_STORED
        ) as target:
            for name in source.namelist():
                target.writestr(name, source.read(name))
            target.writestr("extra.txt", b"forbidden")
        with self.assertRaisesRegex(
            RuleCoreChampionRegistryError, "REQUEST_ARCHIVE_INVALID"
        ):
            verify_registry_request_path(
                tampered,
                expected_request_archive_sha256=hashlib.sha256(
                    tampered.read_bytes()
                ).hexdigest(),
                **self.pins,
            )

    def test_request_outer_pin_and_zip_metadata_drift_are_rejected(self):
        request = self._prepare()
        request_path = Path(request["archive"])
        with self.assertRaisesRegex(
            RuleCoreChampionRegistryError, "REQUEST_EXTERNAL_PIN_MISMATCH"
        ):
            verify_registry_request_path(
                request_path,
                expected_request_archive_sha256="f" * 64,
                **self.pins,
            )

        metadata_drift = self.root / "metadata-drift.zip"
        with zipfile.ZipFile(request_path) as source, zipfile.ZipFile(
            metadata_drift, "w", compression=zipfile.ZIP_STORED
        ) as target:
            for name in source.namelist():
                target.writestr(name, source.read(name))
        with self.assertRaisesRegex(
            RuleCoreChampionRegistryError, "REQUEST_ARCHIVE_INVALID"
        ):
            verify_registry_request_path(
                metadata_drift,
                expected_request_archive_sha256=hashlib.sha256(
                    metadata_drift.read_bytes()
                ).hexdigest(),
                **self.pins,
            )

    def test_ac4_time_and_retention_boundaries(self):
        for requested, retained, reason in (
            (
                "2026-07-28T23:59:59.000000Z",
                self.retain_until,
                "REQUEST_PRECEDES_ARTIFACT_REGISTRATION",
            ),
            (
                self.requested_at,
                "2027-07-28T01:00:00.000000Z",
                "REQUEST_RETENTION_REJECTED",
            ),
        ):
            output = self.root / (
                "rule-core-champion-registry-request-aaaaaaaa-"
                + reason.lower()
                + ".zip"
            )
            with self.assertRaisesRegex(RuleCoreChampionRegistryError, reason):
                prepare_registry_request(
                    artifact_path=self.artifact_path,
                    registry_id="model-registry-jp-01",
                    destination_id="champion-immutable-prod-01",
                    requested_at_utc=requested,
                    minimum_retain_until_utc=retained,
                    output=output,
                    **self.pins,
                )
            self.assertFalse(output.exists())

    def test_ac5_output_collision_is_preserved(self):
        output = self.root / "rule-core-champion-registry-request-aaaaaaaa.zip"
        output.write_bytes(b"preserve")
        with self.assertRaisesRegex(
            RuleCoreChampionRegistryError, "REQUEST_DESTINATION_INVALID"
        ):
            self._prepare()
        self.assertEqual(b"preserve", output.read_bytes())

    def test_directory_and_symlink_output_collisions_are_preserved(self):
        directory = self.root / (
            "rule-core-champion-registry-request-aaaaaaaa-directory.zip"
        )
        directory.mkdir()
        with self.assertRaisesRegex(
            RuleCoreChampionRegistryError, "REQUEST_DESTINATION_INVALID"
        ):
            self._prepare(directory.name)
        self.assertTrue(directory.is_dir())

        link = self.root / (
            "rule-core-champion-registry-request-aaaaaaaa-link.zip"
        )
        target = self.root / "collision-target"
        target.write_bytes(b"preserve")
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            return
        with self.assertRaisesRegex(
            RuleCoreChampionRegistryError, "REQUEST_DESTINATION_INVALID"
        ):
            self._prepare(link.name)
        self.assertTrue(link.is_symlink())
        self.assertEqual(b"preserve", target.read_bytes())

    def test_ac7_valid_signed_receipt_publishes_deny_only_assessment(self):
        request = self._prepare()
        policy = self._policy()
        receipt = self._receipt(request, policy)
        result = self._verify_receipt(Path(request["archive"]), request, policy, receipt)
        assessment = json.loads(Path(result["assessment"]).read_bytes())
        self.assertEqual(
            "RULE_CORE_CHAMPION_REGISTRY_ATTESTATION_VERIFIED_DENY_ONLY",
            result["status"],
        )
        self.assertTrue(result["signed_registry_attestation_accepted"])
        self.assertFalse(result["direct_storage_api_inspection_performed"])
        self.assertEqual(REGISTRY_SAFETY, assessment["safety"])
        self.assertFalse(result["quality_approved"])
        self.assertFalse(result["promotion_eligible"])
        self.assertFalse(result["live_allowed"])

    def test_ac6_policy_pin_and_key_are_enforced(self):
        request = self._prepare()
        policy = self._policy()
        receipt = self._receipt(request, policy)
        policy_path = self.root / "policy.json"
        receipt_path = self.root / "receipt.json"
        policy_path.write_bytes(canonical_registry_json(policy))
        receipt_path.write_bytes(canonical_registry_json(receipt))
        with self.assertRaisesRegex(
            RuleCoreChampionRegistryError, "REGISTRY_POLICY_PIN_MISMATCH"
        ):
            verify_registry_receipt(
                request_archive=Path(request["archive"]),
                expected_request_archive_sha256=request["archive_sha256"],
                policy_path=policy_path,
                expected_policy_sha256="f" * 64,
                receipt_path=receipt_path,
                verified_at_utc="2026-07-29T01:10:00.000000Z",
                assessment_output=self.root / "assessment.json",
                **self.pins,
            )
        policy["rsa_exponent"] = 3
        policy_path.write_bytes(canonical_registry_json(policy))
        with self.assertRaisesRegex(
            RuleCoreChampionRegistryError, "REGISTRY_POLICY_SCHEMA_REJECTED"
        ):
            verify_registry_receipt(
                request_archive=Path(request["archive"]),
                expected_request_archive_sha256=request["archive_sha256"],
                policy_path=policy_path,
                expected_policy_sha256=hashlib.sha256(
                    policy_path.read_bytes()
                ).hexdigest(),
                receipt_path=receipt_path,
                verified_at_utc="2026-07-29T01:10:00.000000Z",
                assessment_output=self.root / "assessment-2.json",
                **self.pins,
            )

    def test_ac8_resigned_binding_drift_is_rejected(self):
        request = self._prepare()
        policy = self._policy()
        receipt = self._receipt(
            request, policy, artifact_archive_sha256="f" * 64
        )
        with self.assertRaisesRegex(
            RuleCoreChampionRegistryError, "REGISTRY_RECEIPT_BINDING_REJECTED"
        ):
            self._verify_receipt(Path(request["archive"]), request, policy, receipt)

    def test_ac9_tampered_signature_creates_no_assessment(self):
        request = self._prepare()
        policy = self._policy()
        receipt = self._receipt(request, policy)
        receipt["signature_rsa_pkcs1v15_sha256_hex"] = (
            "00" + str(receipt["signature_rsa_pkcs1v15_sha256_hex"])[2:]
        )
        assessment = self.root / "rule-core-champion-registry-assessment-fixture.json"
        with self.assertRaisesRegex(
            RuleCoreChampionRegistryError, "REGISTRY_RECEIPT_SIGNATURE_REJECTED"
        ):
            self._verify_receipt(
                Path(request["archive"]), request, policy, receipt
            )
        self.assertFalse(assessment.exists())

    def test_ac10_receipt_chronology_is_enforced(self):
        request = self._prepare()
        policy = self._policy()
        receipt = self._receipt(
            request,
            policy,
            acknowledged_at_utc="2026-07-29T01:11:00.000000Z",
        )
        with self.assertRaisesRegex(
            RuleCoreChampionRegistryError, "REGISTRY_RECEIPT_TIME_REJECTED"
        ):
            self._verify_receipt(Path(request["archive"]), request, policy, receipt)

    def test_ac11_successful_outputs_are_deny_only(self):
        request = self._prepare()
        policy = self._policy()
        receipt = self._receipt(request, policy)
        assessment = self._verify_receipt(
            Path(request["archive"]), request, policy, receipt
        )
        for result in (request, assessment):
            self.assertEqual("DISABLED", result["order_capability"])
            self.assertFalse(result["quality_approved"])
            self.assertFalse(result["oos_gate_passed"])
            self.assertFalse(result["promotion_eligible"])
            self.assertFalse(result["safe_to_demo_auto_order"])
            self.assertFalse(result["live_allowed"])
            self.assertEqual("NOT_PERFORMED", result["broker_mutation"])

    def test_ac12_isolated_cli_help_request_and_receipt_workflows(self):
        for command, flag in (
            ("prepare-request", "--minimum-retain-until-utc"),
            ("verify-request", "--expected-request-archive-sha256"),
            ("verify-receipt", "--expected-policy-sha256"),
        ):
            with self.subTest(command=command):
                help_result = self._run_cli(command, "--help")
                self.assertEqual(0, help_result.returncode, help_result.stderr)
                self.assertIn(flag, help_result.stdout)

        request_path = self.root / (
            "rule-core-champion-registry-request-aaaaaaaa-cli.zip"
        )
        prepare_result = self._run_cli(
            "prepare-request",
            "--artifact",
            str(self.artifact_path),
            *self._cli_pins(),
            "--registry-id",
            "model-registry-jp-01",
            "--destination-id",
            "champion-immutable-prod-01",
            "--requested-at-utc",
            self.requested_at,
            "--minimum-retain-until-utc",
            self.retain_until,
            "--output",
            str(request_path),
        )
        self.assertEqual(0, prepare_result.returncode, prepare_result.stderr)
        self.assertIn(
            "RULE_CORE_CHAMPION_REGISTRY_REQUEST_READY",
            prepare_result.stdout,
        )
        request_sha = hashlib.sha256(request_path.read_bytes()).hexdigest()
        verify_result = self._run_cli(
            "verify-request",
            "--request-archive",
            str(request_path),
            "--expected-request-archive-sha256",
            request_sha,
            *self._cli_pins(),
        )
        self.assertEqual(0, verify_result.returncode, verify_result.stderr)
        self.assertIn(
            "RULE_CORE_CHAMPION_REGISTRY_REQUEST_VERIFIED",
            verify_result.stdout,
        )
        request = verify_registry_request_path(
            request_path,
            expected_request_archive_sha256=request_sha,
            **self.pins,
        )
        policy = self._policy()
        receipt = self._receipt(request, policy)
        policy_path = self.root / "cli-policy.json"
        receipt_path = self.root / "cli-receipt.json"
        policy_data = canonical_registry_json(policy)
        policy_path.write_bytes(policy_data)
        receipt_path.write_bytes(canonical_registry_json(receipt))
        assessment_path = self.root / (
            "rule-core-champion-registry-assessment-cli.json"
        )
        receipt_result = self._run_cli(
            "verify-receipt",
            "--request-archive",
            str(request_path),
            "--expected-request-archive-sha256",
            request_sha,
            *self._cli_pins(),
            "--policy",
            str(policy_path),
            "--expected-policy-sha256",
            hashlib.sha256(policy_data).hexdigest(),
            "--receipt",
            str(receipt_path),
            "--verified-at-utc",
            "2026-07-29T01:10:00.000000Z",
            "--assessment-output",
            str(assessment_path),
        )
        self.assertEqual(0, receipt_result.returncode, receipt_result.stderr)
        self.assertIn(
            "RULE_CORE_CHAMPION_REGISTRY_ATTESTATION_VERIFIED_DENY_ONLY",
            receipt_result.stdout,
        )
        self.assertTrue(assessment_path.is_file())

    def test_ac13_noncanonical_policy_is_rejected(self):
        request = self._prepare()
        policy = self._policy()
        receipt = self._receipt(request, policy)
        policy_path = self.root / "policy.json"
        receipt_path = self.root / "receipt.json"
        policy_path.write_text(json.dumps(policy, indent=2), encoding="utf-8")
        receipt_path.write_bytes(canonical_registry_json(receipt))
        with self.assertRaisesRegex(
            RuleCoreChampionRegistryError, "REGISTRY_POLICY_JSON_NOT_CANONICAL"
        ):
            verify_registry_receipt(
                request_archive=Path(request["archive"]),
                expected_request_archive_sha256=request["archive_sha256"],
                policy_path=policy_path,
                expected_policy_sha256=hashlib.sha256(
                    policy_path.read_bytes()
                ).hexdigest(),
                receipt_path=receipt_path,
                verified_at_utc="2026-07-29T01:10:00.000000Z",
                assessment_output=self.root / "assessment.json",
                **self.pins,
            )

    def test_duplicate_and_extra_receipt_fields_are_rejected(self):
        request = self._prepare()
        policy = self._policy()
        receipt = self._receipt(request, policy)
        policy_path = self.root / "policy.json"
        receipt_path = self.root / "receipt.json"
        policy_data = canonical_registry_json(policy)
        policy_path.write_bytes(policy_data)

        canonical = canonical_registry_json(receipt)
        receipt_path.write_bytes(
            b'{"schema_version":"duplicate",' + canonical[1:]
        )
        with self.assertRaisesRegex(
            RuleCoreChampionRegistryError,
            "REGISTRY_RECEIPT_JSON_DUPLICATE_KEY",
        ):
            verify_registry_receipt(
                request_archive=Path(request["archive"]),
                expected_request_archive_sha256=request["archive_sha256"],
                policy_path=policy_path,
                expected_policy_sha256=hashlib.sha256(policy_data).hexdigest(),
                receipt_path=receipt_path,
                verified_at_utc="2026-07-29T01:10:00.000000Z",
                assessment_output=self.root / "assessment-duplicate.json",
                **self.pins,
            )

        receipt["unexpected"] = False
        receipt_path.write_bytes(canonical_registry_json(receipt))
        with self.assertRaisesRegex(
            RuleCoreChampionRegistryError,
            "REGISTRY_RECEIPT_SCHEMA_REJECTED",
        ):
            verify_registry_receipt(
                request_archive=Path(request["archive"]),
                expected_request_archive_sha256=request["archive_sha256"],
                policy_path=policy_path,
                expected_policy_sha256=hashlib.sha256(policy_data).hexdigest(),
                receipt_path=receipt_path,
                verified_at_utc="2026-07-29T01:10:00.000000Z",
                assessment_output=self.root / "assessment-extra.json",
                **self.pins,
            )

    def test_ac14_symlink_artifact_is_rejected(self):
        link = self.root / "artifact-link.zip"
        try:
            link.symlink_to(self.artifact_path)
        except (OSError, NotImplementedError):
            self.skipTest("symlink unavailable")
        output = self.root / "rule-core-champion-registry-request-aaaaaaaa.zip"
        with self.assertRaisesRegex(
            RuleCoreChampionRegistryError, "ARTIFACT_ARCHIVE_FILE_INVALID"
        ):
            prepare_registry_request(
                artifact_path=link,
                registry_id="model-registry-jp-01",
                destination_id="champion-immutable-prod-01",
                requested_at_utc=self.requested_at,
                minimum_retain_until_utc=self.retain_until,
                output=output,
                **self.pins,
            )
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
