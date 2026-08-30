from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from live_runtime.contracts import canonical_json
from live_runtime.windows_ed25519_trusted_clock import (
    ENVELOPE_SCHEMA,
    Ed25519AttestedTrustedUTCProvider,
    SSHSIG_NAMESPACE,
    WindowsEd25519ClockBinding,
    WindowsEd25519TrustedUTCAttestation,
    WindowsEd25519TrustedUTCContinuity,
    WindowsEd25519TrustedUTCError,
    ed25519_public_key_sha256,
)


UTC = timezone.utc
NOW = datetime(2026, 8, 30, 2, 0, tzinfo=UTC)
HASH_A = "a" * 64
HASH_B = "b" * 64
OPENSSH = shutil.which("ssh-keygen")


class Ed25519TrustedUTCProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        cls.private_key = Path(cls.directory.name) / "clock"
        if OPENSSH:
            subprocess.run(
                [str(OPENSSH), "-q", "-t", "ed25519", "-N", "", "-f", str(cls.private_key)],
                check=True,
                capture_output=True,
            )
            cls.public_key = subprocess.run(
                [str(OPENSSH), "-y", "-f", str(cls.private_key)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            cls.ssh_keygen = Path(str(OPENSSH)).resolve()
            cls.ssh_keygen_sha256 = __import__("hashlib").sha256(
                cls.ssh_keygen.read_bytes()
            ).hexdigest()
        else:
            algorithm = b"ssh-ed25519"
            key = b"k" * 32
            blob = (
                len(algorithm).to_bytes(4, "big")
                + algorithm
                + len(key).to_bytes(4, "big")
                + key
            )
            cls.public_key = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii")
            cls.ssh_keygen = Path(r"C:\Windows\System32\OpenSSH\ssh-keygen.exe")
            cls.ssh_keygen_sha256 = "e" * 64

    @classmethod
    def tearDownClass(cls) -> None:
        cls.directory.cleanup()

    def setUp(self) -> None:
        self.signature_patcher = mock.patch(
            "live_runtime.windows_ed25519_trusted_clock._verify_signature",
            return_value=None,
        )
        self.signature_patcher.start()
        self.binding = WindowsEd25519ClockBinding(
            provider_id="finex-offhost-clock-v1",
            source_host_identity_sha256=HASH_A,
            consumer_host_identity_sha256=HASH_B,
            authority_issuer_id="putra-trusted-utc-v1",
            signer_identity="putra-finex-trusted-utc-v1",
            authority_public_key=self.public_key,
            authority_public_key_sha256=ed25519_public_key_sha256(self.public_key),
            ssh_keygen_path=str(self.ssh_keygen),
            ssh_keygen_sha256=self.ssh_keygen_sha256,
            maximum_attestation_age_ms=10_000,
            maximum_delivery_delay_ms=3_000,
            maximum_bootstrap_drift_ms=1_000,
        )
        self.local_now = NOW
        self.monotonic = 100.0
        self.cursor = None

    def tearDown(self) -> None:
        self.signature_patcher.stop()

    def envelope(self, *, sequence=1, previous="0" * 64, **changes) -> bytes:
        values = dict(
            binding_sha256=self.binding.content_sha256,
            source_host_identity_sha256=HASH_A,
            consumer_host_identity_sha256=HASH_B,
            authority_issuer_id="putra-trusted-utc-v1",
            signer_identity="putra-finex-trusted-utc-v1",
            authority_public_key_sha256=self.binding.authority_public_key_sha256,
            sequence=sequence,
            previous_attestation_sha256=previous,
            authority_utc=NOW,
            issued_at_utc=NOW - timedelta(milliseconds=100),
            expires_at_utc=NOW + timedelta(seconds=5),
        )
        values.update(changes)
        attestation = WindowsEd25519TrustedUTCAttestation(**values)
        payload = attestation.signing_payload
        if OPENSSH:
            source = Path(self.directory.name) / "payload.json"
            signature = Path(str(source) + ".sig")
            source.write_bytes(payload)
            signature.unlink(missing_ok=True)
            subprocess.run(
                [str(OPENSSH), "-Y", "sign", "-f", str(self.private_key), "-n", SSHSIG_NAMESPACE, str(source)],
                check=True,
                capture_output=True,
            )
            signature_bytes = signature.read_bytes()
        else:
            signature_bytes = b"offline-unit-signature"
        return (canonical_json({
            "payload_base64": base64.b64encode(payload).decode("ascii"),
            "schema_version": ENVELOPE_SCHEMA,
            "signature_base64": base64.b64encode(signature_bytes).decode("ascii"),
        }) + "\n").encode("utf-8")

    def provider(self, envelope: bytes):
        def cas(expected, replacement):
            current_hash = "0" * 64 if self.cursor is None else self.cursor.content_sha256
            if expected != current_hash:
                return False
            self.cursor = replacement
            return True

        return Ed25519AttestedTrustedUTCProvider(
            binding=self.binding,
            envelope_provider=lambda: envelope,
            continuity_provider=lambda: self.cursor,
            continuity_compare_and_swap=cas,
            system_clock=lambda: self.local_now,
            monotonic_clock=lambda: self.monotonic,
        )

    def test_valid_signature_bootstraps_cursor_and_advances_from_monotonic(self):
        provider = self.provider(self.envelope())
        self.assertEqual(NOW, provider())
        self.monotonic += 0.25
        self.local_now += timedelta(milliseconds=250)
        self.assertEqual(NOW + timedelta(milliseconds=250), provider())
        self.assertEqual(1, self.cursor.sequence)

    def test_next_attestation_requires_exact_sequence_and_predecessor(self):
        first = self.envelope()
        provider = self.provider(first)
        provider()
        predecessor = self.cursor.attestation_sha256
        self.local_now += timedelta(milliseconds=200)
        second = self.envelope(
            sequence=2,
            previous=predecessor,
            authority_utc=self.local_now,
            issued_at_utc=self.local_now - timedelta(milliseconds=50),
            expires_at_utc=self.local_now + timedelta(seconds=5),
        )
        provider = self.provider(second)
        self.assertEqual(self.local_now, provider())
        self.assertEqual(2, self.cursor.sequence)
        with self.assertRaises(WindowsEd25519TrustedUTCError) as raised:
            self.provider(first)()
        self.assertEqual("TRUSTED_UTC_CONTINUITY_INVALID", raised.exception.reason_code)

    def test_signed_successor_cannot_move_time_backward(self):
        provider = self.provider(self.envelope())
        provider()
        predecessor = self.cursor.attestation_sha256
        self.local_now += timedelta(milliseconds=200)
        rollback = self.envelope(
            sequence=2,
            previous=predecessor,
            authority_utc=NOW - timedelta(milliseconds=100),
            issued_at_utc=NOW - timedelta(milliseconds=200),
            expires_at_utc=NOW + timedelta(seconds=4),
        )
        with self.assertRaises(WindowsEd25519TrustedUTCError) as raised:
            self.provider(rollback)()
        self.assertEqual("TRUSTED_UTC_AUTHORITY_REGRESSION", raised.exception.reason_code)
        self.assertEqual(1, self.cursor.sequence)

    def test_restart_rejects_same_attestation_after_trusted_time_advanced(self):
        envelope = self.envelope()
        provider = self.provider(envelope)
        provider()
        self.local_now += timedelta(milliseconds=250)
        self.monotonic += 0.25
        provider()
        with self.assertRaises(WindowsEd25519TrustedUTCError) as raised:
            self.provider(envelope)()
        self.assertEqual("TRUSTED_UTC_REGRESSION", raised.exception.reason_code)

    def test_binding_tamper_and_wrong_scope_are_rejected(self):
        with self.assertRaises(WindowsEd25519TrustedUTCError) as raised:
            self.provider(self.envelope(consumer_host_identity_sha256=HASH_A))()
        self.assertEqual("TRUSTED_UTC_BINDING_MISMATCH", raised.exception.reason_code)
        valid = self.envelope()
        envelope = __import__("json").loads(valid)
        payload = base64.b64decode(envelope["payload_base64"])
        envelope["payload_base64"] = base64.b64encode(
            payload.replace(b"TRUSTED_UTC_ONLY", b"CONNECTIVITY_ONLY")
        ).decode("ascii")
        with self.assertRaises(WindowsEd25519TrustedUTCError):
            self.provider((canonical_json(envelope) + "\n").encode())()

    def test_stale_future_and_excessive_validity_are_rejected(self):
        cases = (
            dict(issued_at_utc=NOW - timedelta(seconds=4), authority_utc=NOW - timedelta(seconds=4), expires_at_utc=NOW + timedelta(seconds=1)),
            dict(issued_at_utc=NOW + timedelta(seconds=2), authority_utc=NOW + timedelta(seconds=2), expires_at_utc=NOW + timedelta(seconds=4)),
            dict(issued_at_utc=NOW - timedelta(seconds=1), expires_at_utc=NOW + timedelta(seconds=20)),
        )
        for values in cases:
            with self.subTest(values=values):
                with self.assertRaises(WindowsEd25519TrustedUTCError) as raised:
                    self.provider(self.envelope(**values))()
                self.assertEqual("TRUSTED_UTC_FRESHNESS_INVALID", raised.exception.reason_code)

    def test_bad_signature_duplicate_fields_and_health_payload_fail_closed(self):
        envelope = self.envelope()
        duplicate = b'{"schema_version":"x","schema_version":"y"}'
        with self.assertRaises(WindowsEd25519TrustedUTCError):
            self.provider(duplicate)()
        health = (canonical_json({"schema_version": "finex-runtime-health-evidence-v1"}) + "\n").encode()
        with self.assertRaises(WindowsEd25519TrustedUTCError):
            self.provider(health)()

        noncanonical = b" " + envelope
        with self.assertRaises(WindowsEd25519TrustedUTCError):
            self.provider(noncanonical)()

    def test_clock_regressions_and_cas_failure_fail_closed(self):
        provider = self.provider(self.envelope())
        provider()
        self.local_now -= timedelta(milliseconds=1)
        with self.assertRaises(WindowsEd25519TrustedUTCError) as raised:
            provider()
        self.assertEqual("TRUSTED_UTC_SYSTEM_CLOCK_REGRESSION", raised.exception.reason_code)

        self.cursor = None
        failing = Ed25519AttestedTrustedUTCProvider(
            binding=self.binding,
            envelope_provider=lambda: self.envelope(),
            continuity_provider=lambda: None,
            continuity_compare_and_swap=lambda *_: False,
            system_clock=lambda: NOW,
            monotonic_clock=lambda: 1.0,
        )
        with self.assertRaises(WindowsEd25519TrustedUTCError) as raised:
            failing()
        self.assertEqual("TRUSTED_UTC_CONTINUITY_CAS_FAILED", raised.exception.reason_code)

    def test_cross_binding_cursor_and_non_boolean_cas_fail_closed(self):
        envelope = self.envelope()
        self.cursor = WindowsEd25519TrustedUTCContinuity(
            binding_sha256="c" * 64,
            source_host_identity_sha256=HASH_A,
            consumer_host_identity_sha256=HASH_B,
            sequence=1,
            attestation_sha256="d" * 64,
            last_authority_utc=NOW,
            last_trusted_utc=NOW,
        )
        with self.assertRaises(WindowsEd25519TrustedUTCError):
            self.provider(envelope)()

        self.cursor = None
        provider = Ed25519AttestedTrustedUTCProvider(
            binding=self.binding,
            envelope_provider=lambda: envelope,
            continuity_provider=lambda: None,
            continuity_compare_and_swap=lambda *_: 1,
            system_clock=lambda: NOW,
            monotonic_clock=lambda: 1.0,
        )
        with self.assertRaises(WindowsEd25519TrustedUTCError) as raised:
            provider()
        self.assertEqual("TRUSTED_UTC_CONTINUITY_CAS_FAILED", raised.exception.reason_code)

    def test_callback_errors_are_classified(self):
        envelope = self.envelope()
        cases = (
            ("TRUSTED_UTC_SYSTEM_CLOCK_FAILED", dict(system_clock=lambda: (_ for _ in ()).throw(OSError()))),
            ("TRUSTED_UTC_MONOTONIC_INVALID", dict(monotonic_clock=lambda: float("nan"))),
            ("TRUSTED_UTC_ENVELOPE_READ_FAILED", dict(envelope_provider=lambda: (_ for _ in ()).throw(OSError()))),
            ("TRUSTED_UTC_CONTINUITY_READ_FAILED", dict(continuity_provider=lambda: (_ for _ in ()).throw(OSError()))),
        )
        defaults = dict(
            binding=self.binding,
            envelope_provider=lambda: envelope,
            continuity_provider=lambda: None,
            continuity_compare_and_swap=lambda *_: True,
            system_clock=lambda: NOW,
            monotonic_clock=lambda: 1.0,
        )
        for reason, changes in cases:
            with self.subTest(reason=reason):
                configured = dict(defaults)
                configured.update(changes)
                with self.assertRaises(WindowsEd25519TrustedUTCError) as raised:
                    Ed25519AttestedTrustedUTCProvider(**configured)()
                self.assertEqual(reason, raised.exception.reason_code)

    @unittest.skipUnless(OPENSSH, "OpenSSH integration is unavailable")
    def test_pinned_executable_identity_rejects_hash_mismatch(self):
        drifted = replace(self.binding, ssh_keygen_sha256="f" * 64)
        original = self.binding
        self.binding = drifted
        envelope = self.envelope()
        self.binding = original
        provider = Ed25519AttestedTrustedUTCProvider(
            binding=drifted,
            envelope_provider=lambda: envelope,
            continuity_provider=lambda: None,
            continuity_compare_and_swap=lambda *_: True,
            system_clock=lambda: NOW,
            monotonic_clock=lambda: 1.0,
        )
        self.signature_patcher.stop()
        try:
            with self.assertRaises(WindowsEd25519TrustedUTCError) as raised:
                provider()
            self.assertEqual("TRUSTED_UTC_SSH_KEYGEN_IDENTITY_MISMATCH", raised.exception.reason_code)
        finally:
            self.signature_patcher.start()

    @unittest.skipUnless(OPENSSH, "OpenSSH integration is unavailable")
    def test_real_sshsig_verification_with_pinned_executable(self):
        provider = self.provider(self.envelope())
        self.signature_patcher.stop()
        try:
            self.assertEqual(NOW, provider())
        finally:
            self.signature_patcher.start()

    @unittest.skipUnless(OPENSSH, "OpenSSH integration is unavailable")
    def test_real_sshsig_rejects_tampered_signature(self):
        envelope = __import__("json").loads(self.envelope())
        signature = bytearray(base64.b64decode(envelope["signature_base64"]))
        signature[len(signature) // 2] ^= 1
        envelope["signature_base64"] = base64.b64encode(signature).decode("ascii")
        tampered = (canonical_json(envelope) + "\n").encode("utf-8")
        provider = self.provider(tampered)
        self.signature_patcher.stop()
        try:
            with self.assertRaises(WindowsEd25519TrustedUTCError) as raised:
                provider()
            self.assertEqual("TRUSTED_UTC_SIGNATURE_INVALID", raised.exception.reason_code)
        finally:
            self.signature_patcher.start()

    def test_expiry_before_cas_does_not_advance_cursor(self):
        envelope = self.envelope()
        cas_calls = 0

        def cas(expected, replacement):
            nonlocal cas_calls
            cas_calls += 1
            current_hash = "0" * 64 if self.cursor is None else self.cursor.content_sha256
            if expected != current_hash:
                return False
            self.cursor = replacement
            return True

        provider = Ed25519AttestedTrustedUTCProvider(
            binding=self.binding,
            envelope_provider=lambda: envelope,
            continuity_provider=lambda: self.cursor,
            continuity_compare_and_swap=cas,
            system_clock=lambda: self.local_now,
            monotonic_clock=lambda: self.monotonic,
        )
        provider()
        original = self.cursor
        original_calls = cas_calls
        self.local_now = NOW + timedelta(milliseconds=900)
        self.monotonic += 5.0
        with self.assertRaises(WindowsEd25519TrustedUTCError) as raised:
            provider()
        self.assertEqual("TRUSTED_UTC_EXPIRED", raised.exception.reason_code)
        self.assertEqual(original, self.cursor)
        self.assertEqual(original_calls, cas_calls)

    def test_two_instances_share_one_cas_transition(self):
        envelope = self.envelope()
        cursor = None
        cursor_lock = threading.Lock()
        barrier = threading.Barrier(2)
        outcomes = []

        def current():
            observed = cursor
            barrier.wait(timeout=2)
            return observed

        def cas(expected, replacement):
            nonlocal cursor
            with cursor_lock:
                observed = "0" * 64 if cursor is None else cursor.content_sha256
                if expected != observed:
                    return False
                cursor = replacement
                return True

        def run():
            provider = Ed25519AttestedTrustedUTCProvider(
                binding=self.binding,
                envelope_provider=lambda: envelope,
                continuity_provider=current,
                continuity_compare_and_swap=cas,
                system_clock=lambda: NOW,
                monotonic_clock=lambda: 1.0,
            )
            try:
                outcomes.append(("ok", provider()))
            except WindowsEd25519TrustedUTCError as exc:
                outcomes.append(("error", exc.reason_code))

        with mock.patch(
            "live_runtime.windows_ed25519_trusted_clock._verify_signature",
            return_value=None,
        ):
            threads = [threading.Thread(target=run) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=3)
        self.assertEqual(1, sum(item[0] == "ok" for item in outcomes))
        self.assertEqual(
            ["TRUSTED_UTC_CONTINUITY_CAS_FAILED"],
            [item[1] for item in outcomes if item[0] == "error"],
        )


class TrustedUTCDeterministicTests(unittest.TestCase):
    """Core parser checks that run even when OpenSSH is not installed."""

    def test_exact_public_key_parser_rejects_trailing_blob_data(self):
        algorithm = b"ssh-ed25519"
        key = b"k" * 32
        blob = (
            len(algorithm).to_bytes(4, "big")
            + algorithm
            + len(key).to_bytes(4, "big")
            + key
            + b"trailing"
        )
        from live_runtime.windows_ed25519_trusted_clock import normalize_ed25519_public_key

        with self.assertRaises(ValueError):
            normalize_ed25519_public_key(
                "ssh-ed25519 " + base64.b64encode(blob).decode("ascii")
            )


if __name__ == "__main__":
    unittest.main()
