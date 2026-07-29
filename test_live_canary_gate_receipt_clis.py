from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from datetime import timedelta
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import assemble_live_canary_gate_receipt_set as assemble_cli
import sign_live_canary_gate_receipt as sign_cli
import verify_live_canary_gate_receipt as verify_cli
import verify_live_canary_gate_receipt_set as verify_set_cli
from live_runtime.live_canary_gate_contracts import LIVE_CANARY_GATE_DOMAINS
from live_runtime.live_canary_gate_cli_support import parse_cli_utc
from live_runtime.live_canary_gate_receipt_artifacts import (
    issue_live_canary_gate_receipt_artifact,
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


class LiveCanaryGateReceiptCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root_context = tempfile.TemporaryDirectory()
        self.addCleanup(self.root_context.cleanup)
        self.root = Path(self.root_context.name)
        fixture = activation_fixture.LiveCanaryActivationTests(
            "test_ac1_exact_eligible_request_is_canonical_and_deny_only"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.binding = fixture.binding
        self.policy = fixture.policy
        self.eligibility = fixture.eligibility
        self.gate_key_ids = fixture.gate_key_ids
        self.gate_secrets = fixture.gate_secrets
        self.store = _Store(self._key)
        self.binding_path = self.root / "binding.json"
        self.policy_path = self.root / "policy.json"
        _write_json(self.binding_path, self.binding.to_canonical_dict())
        _write_json(self.policy_path, self.policy.to_canonical_dict())

    def _key(self, key_id: str) -> bytes:
        for domain, expected in self.gate_key_ids.items():
            if key_id == expected:
                return self.gate_secrets[domain]
        raise KeyError(key_id)

    def _evidence(self, domain: str) -> Path:
        path = self.root / f"{domain.lower()}-evidence.json"
        _write_json(path, {"domain": domain, "review": "APPROVED"})
        return path

    def _patches(self, module, *, eligibility: bool = False):
        patches = [
            mock.patch.object(module, "WindowsEvidenceKeyStore", return_value=self.store),
            mock.patch.object(module, "_utc_now", return_value=NOW),
        ]
        if eligibility:
            patches.append(
                mock.patch.object(
                    module,
                    "load_verified_eligibility_evidence",
                    return_value=self.eligibility,
                )
            )
        return patches

    def _run_patched(self, module, argv, *, eligibility: bool = False):
        patches = self._patches(module, eligibility=eligibility)
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        output = io.StringIO()
        with redirect_stdout(output):
            status = module.main(argv)
        for patcher in reversed(patches):
            patcher.stop()
        return status, output.getvalue()

    def test_generic_sign_and_verify_cli(self):
        evidence = self._evidence("SECURITY")
        receipt = self.root / "security-receipt.json"
        status, output = self._run_patched(
            sign_cli,
            [
                "--domain",
                "SECURITY",
                "--binding",
                str(self.binding_path),
                "--trust-policy",
                str(self.policy_path),
                "--issuer-id",
                "issuer:security",
                "--expires-at-utc",
                _utc_text(NOW + timedelta(days=1)),
                "--evidence",
                str(evidence),
                "--output",
                str(receipt),
            ],
        )
        self.assertEqual(0, status, output)
        self.assertIn("LIVE_CANARY_GATE_RECEIPT_SIGNED", output)
        self.assertNotIn("secret-material-padding", output)

        status, output = self._run_patched(
            verify_cli,
            [
                "--domain",
                "SECURITY",
                "--binding",
                str(self.binding_path),
                "--trust-policy",
                str(self.policy_path),
                "--receipt",
                str(receipt),
                "--required-until-utc",
                _utc_text(NOW + timedelta(hours=1)),
                "--evidence",
                str(evidence),
            ],
        )
        self.assertEqual(0, status, output)
        self.assertIn("LIVE_CANARY_GATE_RECEIPT_VERIFIED", output)

    def test_legal_sign_cli_uses_verified_eligibility(self):
        receipt = self.root / "legal-receipt.json"
        status, output = self._run_patched(
            sign_cli,
            [
                "--domain",
                "LEGAL_COMPLIANCE",
                "--binding",
                str(self.binding_path),
                "--trust-policy",
                str(self.policy_path),
                "--issuer-id",
                "issuer:legal-compliance",
                "--expires-at-utc",
                _utc_text(NOW + timedelta(days=1)),
                "--candidate",
                "phillip-commodity",
                "--eligibility-review",
                str(self.root / "eligibility-review.json"),
                "--regulatory-observation",
                str(self.root / "observation.json"),
                "--output",
                str(receipt),
            ],
            eligibility=True,
        )
        self.assertEqual(0, status, output)
        persisted = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            self.eligibility.content_sha256, persisted["evidence_sha256"]
        )

    def test_complete_set_assemble_and_verify_clis(self):
        receipts: dict[str, Path] = {}
        evidence: dict[str, Path] = {}
        for domain in sorted(LIVE_CANARY_GATE_DOMAINS):
            source = None
            eligibility = None
            if domain == "LEGAL_COMPLIANCE":
                eligibility = self.eligibility
            else:
                source = self._evidence(domain)
                evidence[domain] = source
            item = issue_live_canary_gate_receipt_artifact(
                self.binding,
                self.policy,
                domain=domain,
                evidence_path=source,
                eligibility_evidence=eligibility,
                issued_at=NOW,
                expires_at=NOW + timedelta(days=1),
                issuer_id=f"issuer:{domain.lower()}",
                key_provider=self._key,
                clock_provider=lambda: NOW,
            )
            path = self.root / f"{domain.lower()}-receipt.json"
            write_live_canary_gate_artifact_exclusive(
                path, item.to_canonical_dict()
            )
            receipts[domain] = path

        output_path = self.root / "receipt-set.json"
        argv = [
            "--binding",
            str(self.binding_path),
            "--trust-policy",
            str(self.policy_path),
            "--candidate",
            "phillip-commodity",
            "--eligibility-review",
            str(self.root / "eligibility-review.json"),
            "--regulatory-observation",
            str(self.root / "observation.json"),
            "--required-until-utc",
            _utc_text(NOW + timedelta(hours=1)),
            "--output",
            str(output_path),
        ]
        for domain, path in receipts.items():
            argv.extend(("--receipt", f"{domain}={path}"))
        for domain, path in evidence.items():
            argv.extend(("--evidence", f"{domain}={path}"))
        status, output = self._run_patched(
            assemble_cli, argv, eligibility=True
        )
        self.assertEqual(0, status, output)
        self.assertIn("Receipts verified: 9", output)

        verify_argv = [
            "--binding",
            str(self.binding_path),
            "--trust-policy",
            str(self.policy_path),
            "--receipt-set",
            str(output_path),
            "--candidate",
            "phillip-commodity",
            "--eligibility-review",
            str(self.root / "eligibility-review.json"),
            "--regulatory-observation",
            str(self.root / "observation.json"),
            "--required-until-utc",
            _utc_text(NOW + timedelta(hours=1)),
        ]
        for domain, path in evidence.items():
            verify_argv.extend(("--evidence", f"{domain}={path}"))
        status, output = self._run_patched(
            verify_set_cli, verify_argv, eligibility=True
        )
        self.assertEqual(0, status, output)
        self.assertIn("LIVE_CANARY_GATE_RECEIPT_SET_VERIFIED", output)

    def test_failures_are_deny_only_and_never_overwrite(self):
        evidence = self._evidence("SECURITY")
        output_path = self.root / "existing.json"
        output_path.write_bytes(b"preserve-me")
        status, output = self._run_patched(
            sign_cli,
            [
                "--domain",
                "SECURITY",
                "--binding",
                str(self.binding_path),
                "--trust-policy",
                str(self.policy_path),
                "--issuer-id",
                "issuer:security",
                "--expires-at-utc",
                _utc_text(NOW + timedelta(days=1)),
                "--evidence",
                str(evidence),
                "--output",
                str(output_path),
            ],
        )
        self.assertEqual(2, status)
        self.assertEqual(b"preserve-me", output_path.read_bytes())
        self.assertIn("Live allowed: false", output)
        self.assertIn("Order capability: DISABLED", output)
        self.assertIn("Broker mutation: NOT_PERFORMED", output)

    def test_raw_secret_arguments_do_not_exist(self):
        diagnostics = io.StringIO()
        with redirect_stderr(diagnostics), self.assertRaises(SystemExit):
            sign_cli.main(["--secret", "forbidden"])
        self.assertNotIn("forbidden", diagnostics.getvalue())

    def test_cli_timestamps_require_exact_canonical_utc(self):
        expected = _utc_text(NOW)
        self.assertEqual(NOW, parse_cli_utc(expected, label="test time"))
        for invalid in (
            expected.replace(".000000", ""),
            expected.replace("Z", "+00:00"),
            "2026-7-29T00:00:00.000000Z",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse_cli_utc(invalid, label="test time")


if __name__ == "__main__":
    unittest.main()
