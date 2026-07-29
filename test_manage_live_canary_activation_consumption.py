from __future__ import annotations

import ast
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import manage_live_canary_activation_consumption as consumption_cli
from live_runtime.live_canary_activation import (
    LIVE_CANARY_APPROVAL_ROLES,
    LIVE_CANARY_GATE_DOMAINS,
    LiveCanaryReplayRegistry,
)
from live_runtime.live_canary_activation_artifacts import (
    assemble_live_canary_activation_authorization_artifact,
    assemble_live_canary_activation_request_artifact,
    issue_live_canary_human_approval_artifact,
)
from live_runtime.live_canary_activation_consumption import (
    LiveCanaryReplayRegistryProfile,
    load_live_canary_replay_registry_profile,
)
from live_runtime.live_canary_gate_receipt_artifacts import (
    assemble_live_canary_gate_receipt_set,
    issue_live_canary_gate_receipt_artifact,
    write_live_canary_gate_artifact_exclusive,
)
import test_live_runtime_demo_auto_soak_cohort as soak_fixture_module
import test_live_runtime_live_canary_activation as activation_fixture
import test_live_runtime_phillip_v6_live_canary_worm_gate as worm_fixture


NOW = datetime(2026, 7, 30, 0, 0, tzinfo=timezone.utc)


class _ShiftedSoakFixture(soak_fixture_module.Fixture):
    def __init__(self) -> None:
        super().__init__(assessed_at=NOW)

    def aggregate(self, **overrides):
        overrides.setdefault("now", NOW)
        return super().aggregate(**overrides)


def _write_json(path: Path, payload: object) -> Path:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


class _Store:
    def __init__(self, provider) -> None:
        self.load = provider


class LiveCanaryActivationConsumptionCliTests(unittest.TestCase):
    def setUp(self) -> None:
        context = tempfile.TemporaryDirectory()
        self.addCleanup(context.cleanup)
        self.root = Path(context.name)
        now_patch = mock.patch.object(activation_fixture, "NOW", NOW)
        soak_patch = mock.patch.object(
            activation_fixture,
            "SoakFixture",
            _ShiftedSoakFixture,
        )
        now_patch.start()
        soak_patch.start()
        self.addCleanup(now_patch.stop)
        self.addCleanup(soak_patch.stop)
        self.fixture = activation_fixture.LiveCanaryActivationTests(
            "test_ac1_exact_eligible_request_is_canonical_and_deny_only"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.registry_path = self.root / "live-canary-replay.sqlite3"
        self.registry_key_id = "phillip-live-canary-replay-key-v1"
        self.store = _Store(self._key)

        self.binding = _write_json(
            self.root / "binding.json", self.fixture.binding.to_canonical_dict()
        )
        self.policy = _write_json(
            self.root / "policy.json", self.fixture.policy.to_canonical_dict()
        )
        self.soak_binding = _write_json(
            self.root / "soak-binding.json",
            self.fixture.soak.binding.to_canonical_dict(),
        )
        self.soak_receipt = _write_json(
            self.root / "soak-receipt.json",
            self.fixture.soak_receipt.to_canonical_dict(),
        )
        self.promotion = _write_json(
            self.root / "promotion.json", self.fixture.promotion.to_canonical_dict()
        )
        self.gate_evidence: dict[str, Path] = {}
        for domain in sorted(LIVE_CANARY_GATE_DOMAINS - {"LEGAL_COMPLIANCE"}):
            if domain == "WORM_CUSTODY":
                fixture = worm_fixture.PhillipV6LiveCanaryWormGateTests(
                    "test_ac1_deterministic_bridge_round_trips"
                )
                fixture.setUp()
                self.addCleanup(fixture.doCleanups)
                path, _result = fixture._build("consumption-gate-source.zip")
                self.worm_policy_sha256 = fixture.policy_sha256
                self.gate_evidence[domain] = path
                continue
            evidence = self.root / f"{domain.lower()}-evidence.bin"
            evidence.write_bytes(f"external-gate:{domain}".encode("utf-8"))
            self.gate_evidence[domain] = evidence
        receipts = tuple(
            issue_live_canary_gate_receipt_artifact(
                self.fixture.binding,
                self.fixture.policy,
                domain="WORM_CUSTODY",
                evidence_path=self.gate_evidence["WORM_CUSTODY"],
                eligibility_evidence=None,
                issued_at=NOW,
                expires_at=NOW + timedelta(minutes=4),
                issuer_id="issuer:worm-custody",
                key_provider=self.fixture._gate_key,
                clock_provider=lambda: NOW,
                worm_custody_policy_sha256=self.worm_policy_sha256,
            )
            if receipt.domain == "WORM_CUSTODY"
            else receipt
            for receipt in self.fixture.gate_receipts
        )
        gate_set = assemble_live_canary_gate_receipt_set(
            self.fixture.binding,
            self.fixture.policy,
            receipts=receipts,
            evidence_paths_by_domain=self.gate_evidence,
            eligibility_evidence=self.fixture.eligibility,
            key_provider=self.fixture._gate_key,
            assembled_at=NOW,
            required_until=NOW + timedelta(minutes=3),
            clock_provider=lambda: NOW,
            worm_custody_policy_sha256=self.worm_policy_sha256,
        )
        self.gate_set = self.root / "gate-set.json"
        write_live_canary_gate_artifact_exclusive(self.gate_set, gate_set)
        request = assemble_live_canary_activation_request_artifact(
            binding=self.fixture.binding,
            trust_policy=self.fixture.policy,
            soak_binding=self.fixture.soak.binding,
            soak_receipt=self.fixture.soak_receipt,
            soak_key_provider=self.fixture.soak.aggregator_key,
            promotion_evidence=self.fixture.promotion,
            promotion_key_provider=lambda _key_id: self.fixture.promotion_secret,
            live_account_alias="phillip-live-account-alias",
            broker_eligibility_evidence=self.fixture.eligibility,
            gate_receipt_set_path=self.gate_set,
            gate_evidence_paths_by_domain=self.gate_evidence,
            gate_key_provider=self.fixture._gate_key,
            worm_custody_policy_sha256=self.worm_policy_sha256,
            expires_at=NOW + timedelta(minutes=3),
            nonce="consumption-cli-request-nonce-v1",
            clock_provider=lambda: NOW,
        )
        approvals = tuple(
            issue_live_canary_human_approval_artifact(
                request,
                trust_policy=self.fixture.policy,
                role=role,
                approver_identity=self.fixture.approver_identities[role],
                key_provider=self.fixture._approval_key,
                clock_provider=lambda: NOW,
            )
            for role in sorted(LIVE_CANARY_APPROVAL_ROLES)
        )
        authorization = assemble_live_canary_activation_authorization_artifact(
            request,
            approvals=approvals,
            trust_policy=self.fixture.policy,
            approval_key_provider=self.fixture._approval_key,
            deployment_key_provider=lambda _key_id: self.fixture.deployment_secret,
            clock_provider=lambda: NOW,
        )
        self.authorization = _write_json(
            self.root / "authorization.json",
            authorization.to_canonical_dict(),
        )

    def _key(self, key_id: str) -> bytes:
        for provider in (
            self.fixture._gate_key,
            self.fixture.soak.aggregator_key,
            self.fixture._approval_key,
        ):
            try:
                return provider(key_id)
            except KeyError:
                pass
        if key_id == self.fixture.policy.promotion_key_id:
            return self.fixture.promotion_secret
        if key_id == self.fixture.policy.deployment_key_id:
            return self.fixture.deployment_secret
        if key_id == self.fixture.policy.replay_checkpoint_key_id:
            return self.fixture.checkpoint_secret
        if key_id == self.registry_key_id:
            return self.fixture.replay_secret
        raise KeyError(key_id)

    def _patch(self, now=NOW):
        patches = (
            mock.patch.object(
                consumption_cli, "WindowsEvidenceKeyStore", return_value=self.store
            ),
            mock.patch.object(consumption_cli, "_utc_now", return_value=now),
            mock.patch(
                "live_runtime.live_canary_activation_cli_support."
                "load_verified_eligibility_evidence",
                return_value=self.fixture.eligibility,
            ),
        )
        for patcher in patches:
            patcher.start()
        self.addCleanup(lambda: [item.stop() for item in reversed(patches)])
        return patches

    def _run(self, argv: list[str], *, now=NOW) -> tuple[int, str]:
        patches = self._patch(now)
        rendered = io.StringIO()
        with redirect_stdout(rendered):
            status = consumption_cli.main(argv)
        for patcher in reversed(patches):
            patcher.stop()
        return status, rendered.getvalue()

    def _profile_args(self, output: Path) -> list[str]:
        return [
            "prepare-profile",
            "--binding",
            str(self.binding),
            "--trust-policy",
            str(self.policy),
            "--registry-path",
            str(self.registry_path),
            "--profile-id",
            "phillip-live-canary-replay-profile-v1",
            "--registry-id",
            "phillip-live-canary-replay-v1",
            "--registry-key-id",
            self.registry_key_id,
            "--registry-key-fingerprint-sha256",
            hashlib.sha256(self.fixture.replay_secret).hexdigest(),
            "--output",
            str(output),
        ]

    def _initialize_args(
        self, profile_path: Path, profile: LiveCanaryReplayRegistryProfile, output: Path
    ) -> list[str]:
        return [
            "initialize",
            "--binding",
            str(self.binding),
            "--trust-policy",
            str(self.policy),
            "--profile",
            str(profile_path),
            "--expected-profile-sha256",
            profile.content_sha256,
            "--registry-path",
            str(self.registry_path),
            "--output",
            str(output),
        ]

    def _evidence_args(self) -> list[str]:
        result = [
            "--binding",
            str(self.binding),
            "--trust-policy",
            str(self.policy),
            "--soak-binding",
            str(self.soak_binding),
            "--soak-receipt",
            str(self.soak_receipt),
            "--promotion-receipt",
            str(self.promotion),
            "--live-account-alias",
            "phillip-live-account-alias",
            "--candidate",
            "phillip-commodity",
            "--eligibility-review",
            str(self.root / "eligibility-review.json"),
            "--regulatory-observation",
            str(self.root / "regulatory-observation.json"),
            "--gate-receipt-set",
            str(self.gate_set),
            "--worm-custody-policy-sha256",
            self.worm_policy_sha256,
        ]
        for domain, path in sorted(self.gate_evidence.items()):
            result.extend(("--gate-evidence", f"{domain}={path}"))
        return result

    def _consumption_args(
        self,
        command: str,
        profile_path: Path,
        profile: LiveCanaryReplayRegistryProfile,
        predecessor: Path,
        *,
        receipt: Path | None = None,
        output: Path | None = None,
    ) -> list[str]:
        result = [
            command,
            "--profile",
            str(profile_path),
            "--expected-profile-sha256",
            profile.content_sha256,
            "--registry-path",
            str(self.registry_path),
            "--predecessor-receipt",
            str(predecessor),
            "--authorization",
            str(self.authorization),
            *self._evidence_args(),
        ]
        if receipt is not None:
            result.extend(("--receipt", str(receipt)))
        if output is not None:
            result.extend(("--output", str(output)))
        return result

    def _prepare_and_initialize(self) -> tuple[Path, LiveCanaryReplayRegistryProfile, Path]:
        profile_path = self.root / "profile.json"
        status, output = self._run(self._profile_args(profile_path))
        self.assertEqual(0, status, output)
        profile = load_live_canary_replay_registry_profile(profile_path)
        initialization = self.root / "initialization.json"
        status, output = self._run(
            self._initialize_args(profile_path, profile, initialization)
        )
        self.assertEqual(0, status, output)
        return profile_path, profile, initialization

    def test_prepare_initialize_consume_and_verify_end_to_end(self) -> None:
        profile_path, profile, initialization = self._prepare_and_initialize()
        receipt = self.root / "consumption.json"
        status, output = self._run(
            self._consumption_args(
                "consume",
                profile_path,
                profile,
                initialization,
                output=receipt,
            )
        )
        self.assertEqual(0, status, output)
        self.assertIn("LIVE_CANARY_ACTIVATION_CONSUMED_ONCE", output)
        self.assertIn("Activation authorized: false", output)
        self.assertTrue(receipt.is_file())

        status, output = self._run(
            self._consumption_args(
                "verify",
                profile_path,
                profile,
                initialization,
                receipt=receipt,
            ),
            now=NOW + timedelta(hours=1),
        )
        self.assertEqual(0, status, output)
        self.assertIn("LIVE_CANARY_ACTIVATION_CONSUMPTION_VERIFIED", output)
        self.assertIn("Broker mutation: NOT_PERFORMED", output)

    def test_consume_rejects_wrong_worm_policy_pin_before_registry_event(self) -> None:
        profile_path, profile, initialization = self._prepare_and_initialize()
        receipt = self.root / "must-not-exist.json"
        argv = self._consumption_args(
            "consume",
            profile_path,
            profile,
            initialization,
            output=receipt,
        )
        pin_index = argv.index("--worm-custody-policy-sha256") + 1
        argv[pin_index] = "f" * 64
        status, output = self._run(argv)
        self.assertEqual(2, status, output)
        self.assertFalse(receipt.exists())
        self.assertIn("Activation authorized: false", output)
        self.assertIn("Broker mutation: NOT_PERFORMED", output)

        registry = LiveCanaryReplayRegistry(
            self.registry_path,
            binding=self.fixture.binding,
            trust_policy=self.fixture.policy,
            registry_id=profile.registry_id,
            key_id=profile.registry_key_id,
            key_fingerprint_sha256=profile.registry_key_fingerprint_sha256,
            key_provider=self._key,
        )
        self.assertEqual(0, registry.event_count)

    def test_publication_failure_recovers_without_second_event(self) -> None:
        profile_path, profile, initialization = self._prepare_and_initialize()
        failed_output = self.root / "failed-consumption.json"
        argv = self._consumption_args(
            "consume",
            profile_path,
            profile,
            initialization,
            output=failed_output,
        )
        patches = self._patch()
        rendered = io.StringIO()

        def raced_write(path: Path, _payload: object) -> None:
            Path(path).write_bytes(b"racing-owner-evidence")
            raise FileExistsError("simulated output race")

        with (
            mock.patch.object(
                consumption_cli,
                "write_live_canary_activation_consumption_artifact_exclusive",
                side_effect=raced_write,
            ),
            redirect_stdout(rendered),
        ):
            status = consumption_cli.main(argv)
        for patcher in reversed(patches):
            patcher.stop()
        self.assertEqual(2, status)
        self.assertEqual(b"racing-owner-evidence", failed_output.read_bytes())

        registry = LiveCanaryReplayRegistry(
            self.registry_path,
            binding=self.fixture.binding,
            trust_policy=self.fixture.policy,
            registry_id=profile.registry_id,
            key_id=profile.registry_key_id,
            key_fingerprint_sha256=profile.registry_key_fingerprint_sha256,
            key_provider=self._key,
        )
        self.assertEqual(1, registry.event_count)

        recovered = self.root / "recovered-consumption.json"
        status, output = self._run(
            self._consumption_args(
                "recover",
                profile_path,
                profile,
                initialization,
                output=recovered,
            ),
            now=NOW + timedelta(hours=1),
        )
        self.assertEqual(0, status, output)
        self.assertIn("LIVE_CANARY_ACTIVATION_CONSUMPTION_RECOVERED", output)
        self.assertTrue(recovered.is_file())
        self.assertEqual(1, registry.event_count)

    def test_existing_output_precedes_credential_or_registry_access(self) -> None:
        destination = self.root / "existing.json"
        destination.write_bytes(b"owner-evidence")
        store = mock.Mock(side_effect=AssertionError("credential store accessed"))
        rendered = io.StringIO()
        with mock.patch.object(
            consumption_cli, "WindowsEvidenceKeyStore", store
        ), redirect_stdout(rendered):
            status = consumption_cli.main(self._profile_args(destination))
        self.assertEqual(2, status)
        self.assertEqual(b"owner-evidence", destination.read_bytes())
        store.assert_not_called()
        self.assertFalse(self.registry_path.exists())

    def test_malformed_arguments_do_not_reflect_caller_values(self) -> None:
        secret = "forbidden-caller-secret"
        status, output = self._run(["consume", "--secret", secret])
        self.assertEqual(2, status)
        self.assertNotIn(secret, output)
        self.assertIn("Activation authorized: false", output)
        self.assertIn("Order capability: DISABLED", output)

    def test_help_needs_no_credential_access(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            consumption_cli.main(["--help"])
        self.assertEqual(0, raised.exception.code)
        self.assertIn("prepare-profile", output.getvalue())

    def test_operator_has_no_runtime_or_broker_effect_surface(self) -> None:
        paths = (
            Path(consumption_cli.__file__),
            Path(__file__).parent
            / "live_runtime/live_canary_activation_consumption.py",
        )
        forbidden_modules = {
            "MetaTrader5",
            "requests",
            "socket",
            "subprocess",
        }
        forbidden_calls = {
            "initialize",
            "order_send",
            "Popen",
            "run",
            "system",
        }
        for path in paths:
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


if __name__ == "__main__":
    unittest.main()
