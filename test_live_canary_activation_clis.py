from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from datetime import timedelta
import ast
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import assemble_live_canary_activation_authorization as authorization_cli
import assemble_live_canary_activation_request as request_cli
import sign_live_canary_human_approval as approval_cli
import verify_live_canary_activation_authorization as verify_authorization_cli
import verify_live_canary_activation_request as verify_request_cli
import verify_live_canary_human_approval as verify_approval_cli
from live_runtime.live_canary_activation import LIVE_CANARY_APPROVAL_ROLES
from live_runtime.live_canary_gate_contracts import LIVE_CANARY_GATE_DOMAINS
from live_runtime.live_canary_gate_receipt_artifacts import (
    assemble_live_canary_gate_receipt_set,
    write_live_canary_gate_artifact_exclusive,
)
from test_live_runtime_demo_auto_soak_cohort import NOW
import test_live_runtime_live_canary_activation as activation_fixture


def _write_json(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _utc_text(value) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


class _Store:
    def __init__(self, key_provider) -> None:
        self.load = key_provider


class LiveCanaryActivationCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root_context = tempfile.TemporaryDirectory()
        self.addCleanup(self.root_context.cleanup)
        self.root = Path(self.root_context.name)
        self.fixture = activation_fixture.LiveCanaryActivationTests(
            "test_ac1_exact_eligible_request_is_canonical_and_deny_only"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.store = _Store(self._key)

        self.binding = self._artifact(
            "binding.json", self.fixture.binding.to_canonical_dict()
        )
        self.policy = self._artifact(
            "policy.json", self.fixture.policy.to_canonical_dict()
        )
        self.soak_binding = self._artifact(
            "soak-binding.json", self.fixture.soak.binding.to_canonical_dict()
        )
        self.soak_receipt = self._artifact(
            "soak-receipt.json", self.fixture.soak_receipt.to_canonical_dict()
        )
        self.promotion = self._artifact(
            "promotion.json", self.fixture.promotion.to_canonical_dict()
        )
        self.gate_evidence = {}
        for domain in sorted(LIVE_CANARY_GATE_DOMAINS - {"LEGAL_COMPLIANCE"}):
            path = self.root / f"{domain.lower()}-evidence.bin"
            path.write_bytes(f"external-gate:{domain}".encode("utf-8"))
            self.gate_evidence[domain] = path
        gate_set = assemble_live_canary_gate_receipt_set(
            self.fixture.binding,
            self.fixture.policy,
            receipts=self.fixture.gate_receipts,
            evidence_paths_by_domain=self.gate_evidence,
            eligibility_evidence=self.fixture.eligibility,
            key_provider=self.fixture._gate_key,
            assembled_at=NOW,
            required_until=NOW + timedelta(minutes=3),
            clock_provider=lambda: NOW,
        )
        self.gate_set = self.root / "gate-set.json"
        write_live_canary_gate_artifact_exclusive(self.gate_set, gate_set)

    def _artifact(self, name: str, payload: object) -> Path:
        path = self.root / name
        _write_json(path, payload)
        return path

    def _key(self, key_id: str) -> bytes:
        providers = (
            self.fixture._gate_key,
            self.fixture.soak.aggregator_key,
            self.fixture._approval_key,
        )
        for provider in providers:
            try:
                return provider(key_id)
            except KeyError:
                pass
        if key_id == self.fixture.policy.promotion_key_id:
            return self.fixture.promotion_secret
        if key_id == self.fixture.policy.deployment_key_id:
            return self.fixture.deployment_secret
        raise KeyError(key_id)

    def _request_args(self, output: Path | None = None) -> list[str]:
        result = [
            "--binding", str(self.binding),
            "--trust-policy", str(self.policy),
            "--soak-binding", str(self.soak_binding),
            "--soak-receipt", str(self.soak_receipt),
            "--promotion-receipt", str(self.promotion),
            "--live-account-alias", "phillip-live-account-alias",
            "--candidate", "phillip-commodity",
            "--eligibility-review", str(self.root / "eligibility-review.json"),
            "--regulatory-observation", str(self.root / "observation.json"),
            "--gate-receipt-set", str(self.gate_set),
        ]
        for domain, path in self.gate_evidence.items():
            result.extend(("--gate-evidence", f"{domain}={path}"))
        if output is not None:
            result.extend(
                (
                    "--expires-at-utc",
                    _utc_text(NOW + timedelta(minutes=3)),
                    "--nonce",
                    "activation-cli-request-nonce-v1",
                    "--output",
                    str(output),
                )
            )
        return result

    def _patch(self, module):
        patches = (
            mock.patch.object(module, "WindowsEvidenceKeyStore", return_value=self.store),
            mock.patch.object(module, "_utc_now", return_value=NOW),
            mock.patch(
                "live_runtime.live_canary_activation_cli_support.load_verified_eligibility_evidence",
                return_value=self.fixture.eligibility,
            ),
        )
        for patcher in patches:
            patcher.start()
        self.addCleanup(lambda: [patcher.stop() for patcher in reversed(patches)])
        return patches

    def _run(self, module, argv):
        patches = self._patch(module)
        output = io.StringIO()
        with redirect_stdout(output):
            status = module.main(argv)
        for patcher in reversed(patches):
            patcher.stop()
        return status, output.getvalue()

    def test_request_assemble_and_verify_clis(self) -> None:
        request = self.root / "request.json"
        status, output = self._run(request_cli, self._request_args(request))
        self.assertEqual(0, status, output)
        self.assertIn("LIVE_CANARY_ACTIVATION_REQUEST_ASSEMBLED", output)
        self.assertIn("Order capability: DISABLED", output)

        status, output = self._run(
            verify_request_cli,
            ["--request", str(request), *self._request_args()],
        )
        self.assertEqual(0, status, output)
        self.assertIn("LIVE_CANARY_ACTIVATION_REQUEST_VERIFIED", output)

    def test_three_approval_and_authorization_clis(self) -> None:
        request = self.root / "request.json"
        status, output = self._run(request_cli, self._request_args(request))
        self.assertEqual(0, status, output)
        approvals = {}
        for role in sorted(LIVE_CANARY_APPROVAL_ROLES):
            path = self.root / f"{role.lower()}-approval.json"
            status, output = self._run(
                approval_cli,
                [
                    "--request", str(request),
                    "--trust-policy", str(self.policy),
                    "--role", role,
                    "--approver-id", self.fixture.approver_identities[role],
                    "--output", str(path),
                ],
            )
            self.assertEqual(0, status, output)
            approvals[role] = path
            status, output = self._run(
                verify_approval_cli,
                [
                    "--request", str(request),
                    "--trust-policy", str(self.policy),
                    "--approval", str(path),
                    "--role", role,
                ],
            )
            self.assertEqual(0, status, output)

        authorization = self.root / "authorization.json"
        common = [
            "--request", str(request),
            "--trust-policy", str(self.policy),
        ]
        for role, path in approvals.items():
            common.extend(("--approval", f"{role}={path}"))
        status, output = self._run(
            authorization_cli,
            [*common, "--output", str(authorization)],
        )
        self.assertEqual(0, status, output)
        self.assertIn("LIVE_CANARY_ACTIVATION_AUTHORIZATION_ASSEMBLED", output)
        status, output = self._run(
            verify_authorization_cli,
            ["--authorization", str(authorization), *common],
        )
        self.assertEqual(0, status, output)
        self.assertIn("LIVE_CANARY_ACTIVATION_AUTHORIZATION_VERIFIED", output)
        self.assertIn("Broker mutation: NOT_PERFORMED", output)

    def test_existing_output_and_missing_key_fail_deny_only(self) -> None:
        destination = self.root / "existing.json"
        destination.write_bytes(b"preserve")
        status, output = self._run(
            request_cli, self._request_args(destination)
        )
        self.assertEqual(2, status)
        self.assertEqual(b"preserve", destination.read_bytes())
        self.assertIn("Live allowed: false", output)
        self.assertIn("Order capability: DISABLED", output)
        self.assertIn("Broker mutation: NOT_PERFORMED", output)

        request = self.root / "request-for-missing-key.json"
        status, output = self._run(request_cli, self._request_args(request))
        self.assertEqual(0, status, output)
        missing_output = self.root / "missing-key-approval.json"
        missing_rendered = io.StringIO()
        with (
            mock.patch.object(
                approval_cli,
                "WindowsEvidenceKeyStore",
                return_value=_Store(lambda _key_id: (_ for _ in ()).throw(KeyError())),
            ),
            mock.patch.object(approval_cli, "_utc_now", return_value=NOW),
            redirect_stdout(missing_rendered),
        ):
            status = approval_cli.main(
                [
                    "--request", str(request),
                    "--trust-policy", str(self.policy),
                    "--role", "RISK_OWNER",
                    "--approver-id", self.fixture.approver_identities["RISK_OWNER"],
                    "--output", str(missing_output),
                ]
            )
        self.assertEqual(2, status)
        self.assertFalse(missing_output.exists())
        self.assertIn("Live allowed: false", missing_rendered.getvalue())
        self.assertIn("Broker mutation: NOT_PERFORMED", missing_rendered.getvalue())

    def test_malformed_source_fails_before_eligibility_verification(self) -> None:
        payload = self.fixture.binding.to_canonical_dict()
        payload["unexpected"] = "field"
        malformed = self._artifact("malformed-binding.json", payload)
        output_path = self.root / "must-not-exist.json"
        argv = self._request_args(output_path)
        argv[argv.index("--binding") + 1] = str(malformed)
        eligibility = mock.Mock(
            side_effect=AssertionError("eligibility credential access occurred")
        )
        rendered = io.StringIO()
        with (
            mock.patch.object(
                request_cli, "WindowsEvidenceKeyStore", return_value=self.store
            ),
            mock.patch.object(request_cli, "_utc_now", return_value=NOW),
            mock.patch(
                "live_runtime.live_canary_activation_cli_support.load_verified_eligibility_evidence",
                eligibility,
            ),
            redirect_stdout(rendered),
        ):
            status = request_cli.main(argv)
        self.assertEqual(2, status)
        eligibility.assert_not_called()
        self.assertFalse(output_path.exists())
        self.assertIn("Broker mutation: NOT_PERFORMED", rendered.getvalue())

    def test_raw_secret_arguments_are_absent_from_all_clis(self) -> None:
        for module in (
            request_cli,
            verify_request_cli,
            approval_cli,
            verify_approval_cli,
            authorization_cli,
            verify_authorization_cli,
        ):
            with self.subTest(module=module.__name__):
                status, output = self._run(module, ["--secret", "forbidden"])
                self.assertEqual(2, status)
                self.assertNotIn("forbidden", output)
                self.assertIn("Live allowed: false", output)
                self.assertIn("Order capability: DISABLED", output)
                self.assertIn("Broker mutation: NOT_PERFORMED", output)

    def test_help_is_available_without_credentials(self) -> None:
        for module in (
            request_cli,
            verify_request_cli,
            approval_cli,
            verify_approval_cli,
            authorization_cli,
            verify_authorization_cli,
        ):
            output = io.StringIO()
            with self.subTest(module=module.__name__), redirect_stdout(output), self.assertRaises(SystemExit) as raised:
                module.main(["--help"])
            self.assertEqual(0, raised.exception.code)
            self.assertIn("usage:", output.getvalue())

    def test_operator_modules_have_no_forbidden_effect_imports_or_calls(self) -> None:
        paths = (
            Path(request_cli.__file__),
            Path(verify_request_cli.__file__),
            Path(approval_cli.__file__),
            Path(verify_approval_cli.__file__),
            Path(authorization_cli.__file__),
            Path(verify_authorization_cli.__file__),
            Path(__file__).parent / "live_runtime/live_canary_activation_artifacts.py",
            Path(__file__).parent / "live_runtime/live_canary_activation_cli_support.py",
        )
        forbidden_modules = {"subprocess", "socket", "requests", "MetaTrader5"}
        forbidden_calls = {"order_send", "initialize", "Popen", "run", "system"}
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
