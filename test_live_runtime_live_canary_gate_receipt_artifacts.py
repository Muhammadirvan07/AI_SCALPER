from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from live_runtime.live_canary_gate_contracts import LIVE_CANARY_GATE_DOMAINS
from live_runtime.live_canary_gate_contracts import (
    LiveCanaryBinding as MinimalLiveCanaryBinding,
    LiveCanaryGateReceipt as MinimalLiveCanaryGateReceipt,
    LiveCanaryTrustPolicy as MinimalLiveCanaryTrustPolicy,
)
from live_runtime.live_canary_gate_receipt_artifacts import (
    LiveCanaryGateReceiptArtifactError,
    assemble_live_canary_gate_receipt_set,
    issue_live_canary_gate_receipt_artifact,
    load_live_canary_binding,
    load_live_canary_gate_receipt,
    load_live_canary_trust_policy,
    verify_live_canary_gate_receipt_artifact,
    verify_live_canary_gate_receipt_set,
    write_live_canary_gate_artifact_exclusive,
)
from test_live_runtime_demo_auto_soak_cohort import NOW
import test_live_runtime_live_canary_activation as activation_fixture
import live_runtime.live_canary_activation as activation_core


class _BindingSubclass:  # sentinel for duck-type rejection
    pass


def _write_json(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


class LiveCanaryGateReceiptArtifactTests(unittest.TestCase):
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
        self.gate_secrets = fixture.gate_secrets
        self.gate_key_ids = fixture.gate_key_ids

        self.binding_path = self.root / "binding.json"
        self.policy_path = self.root / "policy.json"
        _write_json(self.binding_path, self.binding.to_canonical_dict())
        _write_json(self.policy_path, self.policy.to_canonical_dict())

    def _key(self, key_id: str) -> bytes:
        for domain, expected in self.gate_key_ids.items():
            if key_id == expected:
                return self.gate_secrets[domain]
        raise KeyError(key_id)

    def _evidence(self, domain: str, *, label: str | None = None) -> Path:
        path = self.root / f"{domain.lower()}-{label or 'evidence'}.json"
        _write_json(
            path,
            {
                "domain": domain,
                "review_id": label or f"review-{domain.lower()}",
                "result": "APPROVED_FOR_GATE_REVIEW_ONLY",
            },
        )
        return path

    def _issue(
        self,
        domain: str,
        *,
        evidence_path: Path | None = None,
        eligibility=None,
        expires_at=NOW + timedelta(days=1),
    ):
        return issue_live_canary_gate_receipt_artifact(
            self.binding,
            self.policy,
            domain=domain,
            evidence_path=evidence_path,
            eligibility_evidence=eligibility,
            issued_at=NOW,
            expires_at=expires_at,
            issuer_id=f"issuer:{domain.lower()}",
            key_provider=self._key,
            clock_provider=lambda: NOW,
        )

    def _all_receipts(self):
        receipts = []
        sources: dict[str, Path] = {}
        for domain in sorted(LIVE_CANARY_GATE_DOMAINS):
            if domain == "LEGAL_COMPLIANCE":
                receipts.append(self._issue(domain, eligibility=self.eligibility))
                continue
            source = self._evidence(domain)
            sources[domain] = source
            receipts.append(self._issue(domain, evidence_path=source))
        return tuple(receipts), sources

    def test_ac1_strict_binding_and_policy_loaders_round_trip(self):
        self.assertIs(
            activation_core.LiveCanaryBinding, MinimalLiveCanaryBinding
        )
        self.assertIs(
            activation_core.LiveCanaryTrustPolicy,
            MinimalLiveCanaryTrustPolicy,
        )
        self.assertIs(
            activation_core.LiveCanaryGateReceipt,
            MinimalLiveCanaryGateReceipt,
        )
        loaded_binding = load_live_canary_binding(self.binding_path)
        loaded_policy = load_live_canary_trust_policy(self.policy_path)
        self.assertIs(type(loaded_binding), type(self.binding))
        self.assertIs(type(loaded_policy), type(self.policy))
        self.assertEqual(self.binding.binding_sha256, loaded_binding.binding_sha256)
        self.assertEqual(self.policy.policy_sha256, loaded_policy.policy_sha256)

        extra = self.binding.to_canonical_dict()
        extra["unexpected"] = True
        extra_path = self.root / "binding-extra.json"
        _write_json(extra_path, extra)
        with self.assertRaises(LiveCanaryGateReceiptArtifactError):
            load_live_canary_binding(extra_path)

        duplicate_path = self.root / "binding-duplicate.json"
        duplicate_path.write_text('{"schema_version":"x","schema_version":"y"}\n')
        with self.assertRaises(LiveCanaryGateReceiptArtifactError):
            load_live_canary_binding(duplicate_path)

        noncanonical_path = self.root / "binding-noncanonical.json"
        noncanonical_path.write_bytes(self.binding_path.read_bytes() + b"\n")
        with self.assertRaises(LiveCanaryGateReceiptArtifactError):
            load_live_canary_binding(noncanonical_path)

        link = self.root / "binding-link.json"
        link.symlink_to(self.binding_path)
        with self.assertRaises(LiveCanaryGateReceiptArtifactError):
            load_live_canary_binding(link)

    def test_ac2_generic_gate_binds_exact_evidence_bytes(self):
        domain = "SECURITY"
        evidence = self._evidence(domain)
        receipt = self._issue(domain, evidence_path=evidence)
        verified = verify_live_canary_gate_receipt_artifact(
            receipt,
            self.binding,
            self.policy,
            evidence_path=evidence,
            eligibility_evidence=None,
            key_provider=self._key,
            now=NOW,
            required_until=NOW + timedelta(hours=1),
            clock_provider=lambda: NOW,
        )
        self.assertIs(verified, receipt)
        self.assertFalse(receipt.live_allowed)
        self.assertFalse(receipt.execution_authorized)
        self.assertEqual("DISABLED", receipt.order_capability)

        evidence.write_bytes(evidence.read_bytes() + b" ")
        with self.assertRaises(LiveCanaryGateReceiptArtifactError):
            verify_live_canary_gate_receipt_artifact(
                receipt,
                self.binding,
                self.policy,
                evidence_path=evidence,
                eligibility_evidence=None,
                key_provider=self._key,
                now=NOW,
                required_until=NOW + timedelta(hours=1),
                clock_provider=lambda: NOW,
            )

    def test_ac3_legal_gate_requires_exact_fresh_eligibility(self):
        receipt = self._issue(
            "LEGAL_COMPLIANCE", eligibility=self.eligibility
        )
        self.assertEqual(self.eligibility.content_sha256, receipt.evidence_sha256)
        self.assertIs(
            receipt,
            verify_live_canary_gate_receipt_artifact(
                receipt,
                self.binding,
                self.policy,
                evidence_path=None,
                eligibility_evidence=self.eligibility,
                key_provider=self._key,
                now=NOW,
                required_until=NOW + timedelta(hours=1),
                clock_provider=lambda: NOW,
            ),
        )
        with self.assertRaises(LiveCanaryGateReceiptArtifactError):
            self._issue(
                "LEGAL_COMPLIANCE",
                evidence_path=self._evidence("LEGAL_COMPLIANCE"),
            )
        with self.assertRaises(LiveCanaryGateReceiptArtifactError):
            self._issue(
                "LEGAL_COMPLIANCE",
                eligibility=replace(
                    self.eligibility,
                    live_server="Another-LIVE-Server",
                ),
            )
        with self.assertRaises(LiveCanaryGateReceiptArtifactError):
            self._issue(
                "LEGAL_COMPLIANCE",
                eligibility=replace(
                    self.eligibility,
                    expires_at=NOW + timedelta(hours=12),
                ),
            )

    def test_ac4_receipt_persistence_is_strict_and_exclusive(self):
        evidence = self._evidence("WINDOWS_HOST")
        receipt = self._issue("WINDOWS_HOST", evidence_path=evidence)
        path = self.root / "receipt.json"
        write_live_canary_gate_artifact_exclusive(
            path, receipt.to_canonical_dict()
        )
        loaded = load_live_canary_gate_receipt(path)
        self.assertEqual(receipt.content_sha256, loaded.content_sha256)
        before = path.read_bytes()
        with self.assertRaises(FileExistsError):
            write_live_canary_gate_artifact_exclusive(
                path, receipt.to_canonical_dict()
            )
        self.assertEqual(before, path.read_bytes())

    def test_ac5_complete_receipt_set_round_trips_and_verifies(self):
        receipts, sources = self._all_receipts()
        payload = assemble_live_canary_gate_receipt_set(
            self.binding,
            self.policy,
            receipts=receipts,
            evidence_paths_by_domain=sources,
            eligibility_evidence=self.eligibility,
            key_provider=self._key,
            assembled_at=NOW,
            required_until=NOW + timedelta(hours=1),
            clock_provider=lambda: NOW,
        )
        self.assertEqual("live-canary-gate-receipt-set-v1", payload["schema_version"])
        self.assertEqual(9, len(payload["receipts"]))
        self.assertEqual(
            self.eligibility.content_sha256,
            payload["legal_eligibility_evidence_sha256"],
        )
        self.assertFalse(payload["live_allowed"])
        self.assertEqual("DISABLED", payload["order_capability"])

        path = self.root / "receipt-set.json"
        write_live_canary_gate_artifact_exclusive(path, payload)
        verified = verify_live_canary_gate_receipt_set(
            path,
            self.binding,
            self.policy,
            evidence_paths_by_domain=sources,
            eligibility_evidence=self.eligibility,
            key_provider=self._key,
            now=NOW,
            required_until=NOW + timedelta(hours=1),
            clock_provider=lambda: NOW,
        )
        self.assertEqual(
            tuple(sorted(LIVE_CANARY_GATE_DOMAINS)),
            tuple(receipt.domain for receipt in verified),
        )

    def test_ac5_duplicate_evidence_or_incomplete_set_fails(self):
        receipts, sources = self._all_receipts()
        with self.assertRaises(LiveCanaryGateReceiptArtifactError):
            assemble_live_canary_gate_receipt_set(
                self.binding,
                self.policy,
                receipts=receipts[:-1],
                evidence_paths_by_domain=sources,
                eligibility_evidence=self.eligibility,
                key_provider=self._key,
                assembled_at=NOW,
                required_until=NOW + timedelta(hours=1),
                clock_provider=lambda: NOW,
            )

        domain_a, domain_b = sorted(sources)[:2]
        sources[domain_b] = sources[domain_a]
        with self.assertRaises(LiveCanaryGateReceiptArtifactError):
            assemble_live_canary_gate_receipt_set(
                self.binding,
                self.policy,
                receipts=receipts,
                evidence_paths_by_domain=sources,
                eligibility_evidence=self.eligibility,
                key_provider=self._key,
                assembled_at=NOW,
                required_until=NOW + timedelta(hours=1),
                clock_provider=lambda: NOW,
            )

    def test_ac6_set_mutation_and_expiry_fail_closed(self):
        receipts, sources = self._all_receipts()
        payload = assemble_live_canary_gate_receipt_set(
            self.binding,
            self.policy,
            receipts=receipts,
            evidence_paths_by_domain=sources,
            eligibility_evidence=self.eligibility,
            key_provider=self._key,
            assembled_at=NOW,
            required_until=NOW + timedelta(hours=1),
            clock_provider=lambda: NOW,
        )
        payload["binding_sha256"] = "f" * 64
        path = self.root / "mutated-set.json"
        _write_json(path, payload)
        with self.assertRaises(LiveCanaryGateReceiptArtifactError):
            verify_live_canary_gate_receipt_set(
                path,
                self.binding,
                self.policy,
                evidence_paths_by_domain=sources,
                eligibility_evidence=self.eligibility,
                key_provider=self._key,
                now=NOW,
                required_until=NOW + timedelta(hours=1),
                clock_provider=lambda: NOW,
            )

    def test_ac7_exact_types_and_clock_are_enforced(self):
        evidence = self._evidence("SECURITY")
        with self.assertRaises(TypeError):
            issue_live_canary_gate_receipt_artifact(
                _BindingSubclass(),  # type: ignore[arg-type]
                self.policy,
                domain="SECURITY",
                evidence_path=evidence,
                eligibility_evidence=None,
                issued_at=NOW,
                expires_at=NOW + timedelta(days=1),
                issuer_id="issuer:security",
                key_provider=self._key,
                clock_provider=lambda: NOW,
            )
        with self.assertRaises(LiveCanaryGateReceiptArtifactError):
            issue_live_canary_gate_receipt_artifact(
                self.binding,
                self.policy,
                domain="SECURITY",
                evidence_path=evidence,
                eligibility_evidence=None,
                issued_at=NOW,
                expires_at=NOW + timedelta(days=1),
                issuer_id="issuer:security",
                key_provider=self._key,
                clock_provider=lambda: NOW + timedelta(milliseconds=51),
            )

    def test_ac8_static_surface_has_no_forbidden_effects(self):
        source = "\n".join(
            Path(path).read_text(encoding="utf-8")
            for path in (
                "live_runtime/live_canary_gate_contracts.py",
                "live_runtime/live_canary_gate_receipt_artifacts.py",
                "live_runtime/live_canary_gate_cli_support.py",
            )
        )
        for token in (
            "MetaTrader5",
            "order_send",
            "mt5_adapter",
            "subprocess",
            "socket",
            "requests",
            "urllib",
        ):
            with self.subTest(token=token):
                self.assertNotIn(token, source)

    def test_ac9_bounded_and_optimized(self):
        evidence = self._evidence("SECURITY")
        started = time.perf_counter()
        for _index in range(20):
            receipt = self._issue("SECURITY", evidence_path=evidence)
            verify_live_canary_gate_receipt_artifact(
                receipt,
                self.binding,
                self.policy,
                evidence_path=evidence,
                eligibility_evidence=None,
                key_provider=self._key,
                now=NOW,
                required_until=NOW + timedelta(hours=1),
                clock_provider=lambda: NOW,
            )
        self.assertLess((time.perf_counter() - started) / 20, 0.1)

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
                    "test_live_runtime_live_canary_gate_receipt_artifacts."
                    "LiveCanaryGateReceiptArtifactTests."
                    "test_ac2_generic_gate_binds_exact_evidence_bytes"
                ),
            ],
            cwd=Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
