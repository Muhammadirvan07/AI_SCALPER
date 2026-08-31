from __future__ import annotations

import base64
import ast
from datetime import datetime, timedelta, timezone
from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import threading
import unittest
import json
import shutil
import subprocess
import sqlite3
import sys
import types
from argparse import Namespace
from unittest import mock

from live_runtime.contracts import canonical_json
from live_runtime.windows_decision_provider_pack import ExternalCASRequest, WindowsTrustedUTCContinuityCASBinding
from live_runtime.windows_ed25519_trusted_clock import WindowsEd25519TrustedUTCContinuity
from live_runtime.windows_trusted_utc_continuity_acceptance import (
    ACCEPTANCE_SSHSIG_NAMESPACE, TrustedUTCContinuityAcceptanceError, parse_acceptance_envelope,
    make_acceptance_envelope, normalize_openssh_ed25519_public_key,
    acceptance_public_key_sha256, OpenSSHEd25519AcceptanceSigner,
    verify_acceptance_envelope, validate_restricted_path_acl,
)
from live_runtime.windows_trusted_utc_continuity_acceptance_verifier import (
    verify_acceptance_envelope as verify_client_acceptance_envelope,
)
from live_runtime.windows_trusted_utc_continuity_cas_responder import (
    TrustedUTCContinuityCASResponderError, WindowsTrustedUTCContinuityCASResponder, ZERO_SHA256,
    stable_secret_read, validate_restricted_acl,
)

H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64


class FakeSigner:
    public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeResponderOnlyPublicKey finex"
    public_key_sha256 = hashlib.sha256(public_key.encode()).hexdigest()
    fail = False
    def sign(self, payload: bytes) -> bytes:
        if self.fail:
            raise RuntimeError("secret detail")
        return b"SSHSIG:" + ACCEPTANCE_SSHSIG_NAMESPACE.encode() + b":" + hashlib.sha256(payload).digest()
    def verify_envelope(self, data: bytes):
        _, receipt, payload, signature = parse_acceptance_envelope(data)
        expected = b"SSHSIG:" + ACCEPTANCE_SSHSIG_NAMESPACE.encode() + b":" + hashlib.sha256(payload).digest()
        if signature != expected or receipt.custody_public_key_sha256 != self.public_key_sha256:
            raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_VERIFY_FAILED")
        return receipt


class ResponderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.req = self.root / "requests"; self.req.mkdir()
        self.res = self.root / "responses"; self.res.mkdir()
        self.dbdir = self.root / "database"; self.dbdir.mkdir()
        self.now = datetime(2026, 8, 31, 1, 2, 3, 4000, tzinfo=timezone.utc)
        self.key = b"hmac-custody-material-not-ed25519"
        self.binding = WindowsTrustedUTCContinuityCASBinding(
            provider_id="trusted-utc-continuity-cas-v1", clock_binding_sha256=H1,
            custody_issuer_id="hmac-issuer", custody_key_id="hmac-key",
            custody_key_fingerprint_sha256=hashlib.sha256(self.key).hexdigest())
        self.signer = FakeSigner()
        self.responder = self.make_responder()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_responder(self):
        return WindowsTrustedUTCContinuityCASResponder(
            binding=self.binding, source_host_identity_sha256=H2, consumer_host_identity_sha256=H3,
            request_directory=self.req, response_directory=self.res, database_path=self.dbdir / "authority.sqlite3",
            custody_key_provider=lambda _: self.key, acceptance_signer=self.signer,
            acceptance_custody_issuer_id="ed-issuer", acceptance_custody_key_id="ed-key",
            clock=lambda: self.now, acl_validator=lambda _: None)

    def request(self, *, expected=ZERO_SHA256, sequence=1, attestation="4" * 64,
                issued=None, expires=None, source=H2, consumer=H3) -> bytes:
        continuity = WindowsEd25519TrustedUTCContinuity(
            binding_sha256=H1, source_host_identity_sha256=source, consumer_host_identity_sha256=consumer,
            sequence=sequence, attestation_sha256=attestation, last_authority_utc=self.now,
            last_trusted_utc=self.now)
        issued = issued or self.now - timedelta(milliseconds=50)
        expires = expires or self.now + timedelta(seconds=1)
        seed = {"provider_id": self.binding.provider_id, "state_domain": "TRUSTED_UTC_CONTINUITY",
                "identity_sha256": H1, "expected_previous_sha256": expected,
                "proposed_sha256": continuity.content_sha256}
        rid = hashlib.sha256(canonical_json(seed).encode()).hexdigest()
        request = ExternalCASRequest(
            request_id=rid, provider_id=self.binding.provider_id, state_domain="TRUSTED_UTC_CONTINUITY",
            identity_sha256=H1, expected_previous_sha256=expected, proposed_object=continuity.to_canonical_dict(),
            proposed_sha256=continuity.content_sha256, issued_at_utc=issued, expires_at_utc=expires)
        return canonical_json(request).encode()

    def test_commit_receipt_replay_and_restart_rematerialization(self):
        payload = self.request()
        first = self.responder.process_request_bytes(payload)
        _, receipt, signing_payload, signature = parse_acceptance_envelope(first.acceptance_bytes)
        self.assertEqual(receipt.cas_request_id, first.request_id)
        self.assertEqual(receipt.predecessor_attestation_sha256, ZERO_SHA256)
        self.assertIn(ACCEPTANCE_SSHSIG_NAMESPACE.encode(), signature)
        self.assertEqual(signing_payload, receipt.signing_payload)
        replay = self.responder.process_request_bytes(payload)
        self.assertTrue(replay.replayed)
        self.assertEqual(first.response_bytes, replay.response_bytes)
        evidence = self.responder.build_committed_success_evidence(first, payload)
        self.assertEqual(first.request_id, evidence["request_id"])
        self.assertEqual(hashlib.sha256(payload).hexdigest(), evidence["request_sha256"])
        self.assertEqual(hashlib.sha256(first.acceptance_bytes).hexdigest(), evidence["acceptance_receipt_sha256"])
        self.assertEqual(1, evidence["database_commit_revision"])
        replay_evidence = self.responder.build_committed_success_evidence(replay, payload)
        self.assertTrue(replay_evidence["replayed"])
        self.assertEqual(evidence["committed_continuity_sha256"], replay_evidence["committed_continuity_sha256"])
        for path in self.res.iterdir(): path.unlink()
        self.make_responder()
        self.assertTrue((self.res / f"{first.request_id}.response.json").is_file())
        self.assertTrue((self.res / "current.acceptance.json").is_file())

    def test_signing_failure_rolls_back(self):
        self.signer.fail = True
        with self.assertRaisesRegex(TrustedUTCContinuityCASResponderError, "CONTINUITY_CAS_COMMIT_FAILED"):
            self.responder.process_request_bytes(self.request())

    def test_success_evidence_rejects_publication_tamper_and_uncommitted_result(self):
        payload=self.request();result=self.responder.process_request_bytes(payload)
        acceptance=self.res/f"{result.request_id}.acceptance.json"
        acceptance.write_bytes(b"tampered")
        with self.assertRaisesRegex(TrustedUTCContinuityCASResponderError,"PUBLICATION_INVALID"):
            self.responder.build_committed_success_evidence(result,payload)
        forged=type(result)("f"*64,result.response_bytes,result.acceptance_bytes,False)
        with self.assertRaisesRegex(TrustedUTCContinuityCASResponderError,"EVIDENCE_INVALID"):
            self.responder.build_committed_success_evidence(forged,payload)
        self.signer.fail = False
        self.responder.process_request_bytes(self.request())

    def test_historical_replay_does_not_roll_back_current_publication(self):
        first_payload = self.request(attestation="4" * 64)
        first = self.responder.process_request_bytes(first_payload)
        first_evidence = self.responder.build_committed_success_evidence(first, first_payload)
        second_payload = self.request(expected=first_evidence["committed_continuity_sha256"],
                                      sequence=2, attestation="5" * 64)
        second = self.responder.process_request_bytes(second_payload)
        self.assertEqual({"head_sha256": self.responder.build_committed_success_evidence(second, second_payload)["committed_continuity_sha256"],
                          "revision": 2}, self.responder.authoritative_head_snapshot())
        self.assertEqual(second.response_bytes, (self.res / "current.response.json").read_bytes())
        replay = self.responder.process_request_bytes(first_payload)
        replay_evidence = self.responder.build_committed_success_evidence(replay, first_payload)
        self.assertTrue(replay.replayed)
        self.assertEqual(second.response_bytes, (self.res / "current.response.json").read_bytes())
        self.assertEqual(second.acceptance_bytes, (self.res / "current.acceptance.json").read_bytes())
        self.assertEqual(self.responder.build_committed_success_evidence(second, second_payload)["committed_continuity_sha256"],
                         replay_evidence["new_authoritative_head_sha256"])

    def test_readiness_and_acceptance_custody_must_be_distinct(self):
        import run_windows_trusted_utc_continuity_cas_responder as entry
        entry._require_separate_custody("a" * 64, "b" * 64)
        with self.assertRaisesRegex(RuntimeError, "READINESS_ACCEPTANCE_CUSTODY_NOT_SEPARATE"):
            entry._require_separate_custody("a" * 64, "a" * 64)

    def test_stale_future_and_cross_binding_fail_closed(self):
        cases = [
            self.request(issued=self.now - timedelta(seconds=2), expires=self.now - timedelta(seconds=1)),
            self.request(issued=self.now + timedelta(milliseconds=1), expires=self.now + timedelta(seconds=1)),
            self.request(source="5" * 64), self.request(consumer="6" * 64),
        ]
        for payload in cases:
            with self.subTest(payload=payload[:30]), self.assertRaises(TrustedUTCContinuityCASResponderError):
                self.responder.process_request_bytes(payload)

    def test_noncanonical_duplicate_and_partial_packet_rejected(self):
        payload = self.request()
        self.assertRaises(TrustedUTCContinuityCASResponderError, self.responder.process_request_bytes, payload + b"\n")
        duplicate = payload.replace(b'{"expected_previous_sha256"', b'{"provider_id":"x","expected_previous_sha256"', 1)
        self.assertRaises(TrustedUTCContinuityCASResponderError, self.responder.process_request_bytes, duplicate)
        self.assertRaises(TrustedUTCContinuityCASResponderError, self.responder.process_request_bytes, payload[:30])

    def test_concurrent_same_head_exactly_one(self):
        left = self.request(attestation="7" * 64)
        right = self.request(attestation="8" * 64)
        barrier = threading.Barrier(2)
        results = []
        def work(value):
            barrier.wait()
            try: results.append(self.responder.process_request_bytes(value))
            except TrustedUTCContinuityCASResponderError as exc: results.append(str(exc))
        threads = [threading.Thread(target=work, args=(item,)) for item in (left, right)]
        for item in threads: item.start()
        for item in threads: item.join()
        self.assertEqual(sum(not isinstance(item, str) for item in results), 1)
        self.assertIn("CONTINUITY_CAS_CONFLICT", [item for item in results if isinstance(item, str)])

    def test_commit_survives_publication_failure(self):
        payload = self.request()
        original = self.responder._publish
        self.responder._publish = lambda _: (_ for _ in ()).throw(TrustedUTCContinuityCASResponderError("SIMULATED_CRASH"))
        with self.assertRaisesRegex(TrustedUTCContinuityCASResponderError, "SIMULATED_CRASH"):
            self.responder.process_request_bytes(payload)
        self.responder._publish = original
        replay = self.responder.process_request_bytes(payload)
        self.assertTrue(replay.replayed)

    def test_response_replacement_is_overwritten_from_authority(self):
        committed = self.responder.process_request_bytes(self.request())
        target = self.res / f"{committed.request_id}.response.json"
        target.write_bytes(b"injected")
        replay = self.responder.process_request_bytes(self.request())
        self.assertEqual(target.read_bytes(), replay.response_bytes)

    def test_database_and_root_replacement_fail_closed(self):
        database = self.dbdir / "authority.sqlite3"
        displaced = self.dbdir / "displaced.sqlite3"
        database.replace(displaced)
        database.write_bytes(displaced.read_bytes())
        with self.assertRaisesRegex(TrustedUTCContinuityCASResponderError, "DATABASE_REPLACED"):
            self.responder.process_request_bytes(self.request())
        database.unlink(); displaced.replace(database)
        original = self.req.with_name("requests-original")
        self.req.replace(original); self.req.mkdir()
        with self.assertRaisesRegex(TrustedUTCContinuityCASResponderError, "ROOT_REPLACED"):
            self.responder.process_request_bytes(self.request())

    def test_acceptance_exact_schema_time_namespace_and_key(self):
        committed = self.responder.process_request_bytes(self.request())
        envelope = json.loads(committed.acceptance_bytes)
        payload = json.loads(base64.b64decode(envelope["payload_base64"]))
        mutations = []
        extra = dict(payload); extra["unexpected"] = True; mutations.append(extra)
        wrong_time = dict(payload); wrong_time["accepted_at_utc"] = wrong_time["accepted_at_utc"].replace("Z", "+00:00"); mutations.append(wrong_time)
        wrong_namespace = dict(payload); wrong_namespace["sshsig_namespace"] = "ai-scalper-finex-trusted-utc-v1"; mutations.append(wrong_namespace)
        for mutation in mutations:
            candidate = dict(envelope)
            candidate["payload_base64"] = base64.b64encode((canonical_json(mutation) + "\n").encode()).decode()
            encoded = (canonical_json(candidate) + "\n").encode()
            with self.assertRaises(TrustedUTCContinuityAcceptanceError):
                parse_acceptance_envelope(encoded)
        _, acceptance, _, _ = parse_acceptance_envelope(committed.acceptance_bytes)
        alien = FakeSigner(); alien.public_key_sha256 = "9" * 64
        with self.assertRaisesRegex(TrustedUTCContinuityAcceptanceError, "KEY_MISMATCH"):
            make_acceptance_envelope(acceptance, alien)

    def test_zero_microsecond_is_exact_six_digit_utc(self):
        self.now = self.now.replace(microsecond=0)
        committed = self.responder.process_request_bytes(self.request())
        envelope = json.loads(committed.acceptance_bytes)
        payload = base64.b64decode(envelope["payload_base64"])
        self.assertIn(b'"accepted_at_utc":"2026-08-31T01:02:03.000000Z"', payload)
        self.assertIn(b'"responded_at_utc":"2026-08-31T01:02:03.000000Z"', committed.response_bytes)

    def test_stored_response_and_acceptance_corruption_fail_replay(self):
        payload = self.request()
        committed = self.responder.process_request_bytes(payload)
        database = self.dbdir / "authority.sqlite3"
        db = sqlite3.connect(database)
        try:
            db.execute("UPDATE committed_response SET response_bytes=? WHERE request_id=?", (b"{}", committed.request_id))
            db.commit()
        finally:
            db.close()
        with self.assertRaisesRegex(TrustedUTCContinuityCASResponderError, "DATABASE_INVALID"):
            self.responder.process_request_bytes(payload)

    def test_stored_hmac_and_request_corruption_fail_closed(self):
        payload = self.request()
        committed = self.responder.process_request_bytes(payload)
        response = json.loads(committed.response_bytes)
        response["acknowledgement"]["hmac_sha256"] = "f" * 64
        db = sqlite3.connect(self.dbdir / "authority.sqlite3")
        try:
            db.execute("UPDATE committed_response SET response_bytes=? WHERE request_id=?",
                       (canonical_json(response).encode(), committed.request_id))
            db.commit()
        finally:
            db.close()
        with self.assertRaisesRegex(TrustedUTCContinuityCASResponderError, "DATABASE_INVALID"):
            self.responder.process_request_bytes(payload)

    def test_stored_request_bytes_corruption_fails_closed(self):
        payload = self.request()
        committed = self.responder.process_request_bytes(payload)
        db = sqlite3.connect(self.dbdir / "authority.sqlite3")
        try:
            db.execute("UPDATE committed_response SET request_bytes=? WHERE request_id=?",
                       (payload[:-1], committed.request_id))
            db.commit()
        finally:
            db.close()
        with self.assertRaisesRegex(TrustedUTCContinuityCASResponderError, "DATABASE_INVALID"):
            self.responder.process_request_bytes(payload)

    def test_stored_ed_signature_corruption_fails_closed(self):
        payload = self.request()
        committed = self.responder.process_request_bytes(payload)
        envelope = json.loads(committed.acceptance_bytes)
        envelope["signature_base64"] = base64.b64encode(b"forged-signature").decode()
        db = sqlite3.connect(self.dbdir / "authority.sqlite3")
        try:
            db.execute("UPDATE committed_response SET acceptance_bytes=? WHERE request_id=?",
                       ((canonical_json(envelope) + "\n").encode(), committed.request_id))
            db.commit()
        finally:
            db.close()
        with self.assertRaisesRegex(TrustedUTCContinuityCASResponderError, "DATABASE_INVALID"):
            self.responder.process_request_bytes(payload)

    def test_stored_acceptance_corruption_fails_restart_rematerialization(self):
        committed = self.responder.process_request_bytes(self.request())
        db = sqlite3.connect(self.dbdir / "authority.sqlite3")
        try:
            db.execute("UPDATE committed_response SET acceptance_bytes=? WHERE request_id=?", (b"{}", committed.request_id))
            db.commit()
        finally:
            db.close()
        with self.assertRaisesRegex(TrustedUTCContinuityCASResponderError, "DATABASE_INVALID"):
            self.make_responder()

    def test_head_corruption_fails_restart_rematerialization(self):
        self.responder.process_request_bytes(self.request())
        db = sqlite3.connect(self.dbdir / "authority.sqlite3")
        try:
            db.execute("UPDATE head SET continuity_sha256=?", ("f" * 64,))
            db.commit()
        finally:
            db.close()
        with self.assertRaisesRegex(TrustedUTCContinuityCASResponderError, "DATABASE_INVALID"):
            self.make_responder()

    def test_unexpected_trigger_and_schema_fail_closed(self):
        db = sqlite3.connect(self.dbdir / "authority.sqlite3")
        try:
            db.execute("CREATE TRIGGER injected AFTER INSERT ON head BEGIN SELECT 1; END")
            db.commit()
        finally:
            db.close()
        with self.assertRaisesRegex(TrustedUTCContinuityCASResponderError, "SCHEMA_INVALID"):
            self.responder.process_request_bytes(self.request())

    def test_sidecar_identity_drift_fails_transaction(self):
        original = self.responder._database_file_snapshot
        calls = 0
        def drift():
            nonlocal calls
            calls += 1
            observed = original()
            if calls >= 2:
                observed = dict(observed); observed["injected-wal"] = (9, 9)
            return observed
        self.responder._database_file_snapshot = drift
        with self.assertRaisesRegex(TrustedUTCContinuityCASResponderError, "DATABASE_FILE_REPLACED"):
            self.responder.process_request_bytes(self.request())

    def test_root_and_temp_identity_races_fail_publication(self):
        import live_runtime.windows_trusted_utc_continuity_cas_responder as responder_module
        blocked = []
        def replace_root(_source, _target):
            displaced = self.res.with_name("responses-displaced")
            try:
                self.res.replace(displaced)
            except OSError:
                blocked.append(True)
        with mock.patch.object(responder_module, "_ATOMIC_BEFORE_HANDLE_RENAME_HOOK", replace_root):
            self.responder._atomic_write(self.res / "race.response.json", b"payload")
        self.assertEqual([True], blocked)
        self.assertEqual(b"payload", (self.res / "race.response.json").read_bytes())

        fresh = self.responder
        real_lstat = Path.lstat
        def unstable(path):
            item = real_lstat(path)
            if path.name.startswith(".continuity-cas-"):
                values = list(item); values[1] = int(item.st_ino) + 1
                return __import__("os").stat_result(values)
            return item
        with mock.patch.object(Path, "lstat", unstable), self.assertRaisesRegex(TrustedUTCContinuityCASResponderError, "PUBLICATION_FAILED"):
            fresh._atomic_write(self.res / "temp-race.response.json", b"payload")

    @unittest.skipUnless(__import__("os").name == "nt", "Windows handle-sharing test")
    def test_final_window_child_replacement_is_blocked_without_transient_target(self):
        import live_runtime.windows_trusted_utc_continuity_cas_responder as responder_module
        target = self.res / "held-child.response.json"
        attacker = self.res / "attacker-child.tmp"
        attacker.write_bytes(b"attacker")
        observations = []

        def replace_child(source, final):
            self.assertFalse(final.exists())
            blocked_replace = blocked_write = False
            try:
                attacker.replace(source)
            except OSError:
                blocked_replace = True
            try:
                source.write_bytes(b"attacker")
            except OSError:
                blocked_write = True
            observations.append((blocked_replace, blocked_write, final.exists()))

        with mock.patch.object(responder_module, "_ATOMIC_BEFORE_HANDLE_RENAME_HOOK", replace_child):
            self.responder._atomic_write(target, b"authority")
        self.assertEqual([(True, True, False)], observations)
        self.assertEqual(b"authority", target.read_bytes())
        self.assertNotEqual(b"attacker", target.read_bytes())

    def test_pinned_core_import_graph_is_stdlib_only(self):
        repository = Path(__file__).resolve().parent
        cores = (
            repository / "live_runtime" / "windows_trusted_utc_continuity_acceptance.py",
            repository / "live_runtime" / "windows_trusted_utc_continuity_cas_responder.py",
        )
        allowed = set(sys.stdlib_module_names) | {"__future__"}
        for core in cores:
            tree = ast.parse(core.read_text(encoding="utf-8"), filename=str(core))
            imported = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.extend(alias.name.split(".", 1)[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    self.assertEqual(0, node.level, f"relative import in pinned core: {core.name}")
                    imported.append((node.module or "").split(".", 1)[0])
            self.assertEqual([], sorted(set(imported) - allowed), core.name)

    def test_non_windows_rejected_before_state_or_secret_access(self):
        import live_runtime.windows_trusted_utc_continuity_cas_responder as responder_module
        untouched = self.root / "must-not-exist"
        with mock.patch.object(responder_module.os, "name", "posix"):
            with self.assertRaisesRegex(TrustedUTCContinuityCASResponderError, "PLATFORM_UNSUPPORTED"):
                WindowsTrustedUTCContinuityCASResponder(
                    binding=self.binding, source_host_identity_sha256=H2,
                    consumer_host_identity_sha256=H3,
                    request_directory=untouched / "requests",
                    response_directory=untouched / "responses",
                    database_path=untouched / "database" / "authority.sqlite3",
                    custody_key_provider=lambda _: self.key, acceptance_signer=self.signer,
                    acceptance_custody_issuer_id="ed-issuer", acceptance_custody_key_id="ed-key",
                    clock=lambda: self.now, acl_validator=lambda _: None)
            with self.assertRaisesRegex(TrustedUTCContinuityCASResponderError, "PLATFORM_UNSUPPORTED"):
                stable_secret_read(untouched / "secret", acl_validator=lambda _: None)
        self.assertFalse(untouched.exists())

    def test_secret_symlink_is_rejected_no_follow(self):
        target = self.root / "secret.bin"; target.write_bytes(b"secret")
        alias = self.root / "secret-link.bin"
        try:
            alias.symlink_to(target)
        except OSError:
            self.skipTest("symlink privilege unavailable")
        with self.assertRaises(TrustedUTCContinuityCASResponderError):
            stable_secret_read(alias, acl_validator=lambda _: None)

    def test_secret_descriptor_double_read(self):
        target = self.root / "stable-secret.bin"
        target.write_bytes(b"responder-only-secret")
        self.assertEqual(b"responder-only-secret", stable_secret_read(target, acl_validator=lambda _: None))

    def test_exact_schema_and_authority_corruption_fail_closed(self):
        database = self.dbdir / "authority.sqlite3"
        db = sqlite3.connect(database)
        try:
            db.execute("ALTER TABLE authority ADD COLUMN injected TEXT")
            db.commit()
        finally:
            db.close()
        with self.assertRaisesRegex(TrustedUTCContinuityCASResponderError, "SCHEMA_INVALID"):
            self.responder.process_request_bytes(self.request())

    def test_authority_binding_corruption_fail_closed(self):
        database = self.dbdir / "authority.sqlite3"
        db = sqlite3.connect(database)
        try:
            db.execute("UPDATE authority SET provider_id='forged-provider'")
            db.commit()
        finally:
            db.close()
        with self.assertRaisesRegex(TrustedUTCContinuityCASResponderError, "AUTHORITY_MISMATCH"):
            self.responder.process_request_bytes(self.request())

    def test_entrypoint_preimport_and_main_reachability(self):
        completed = subprocess.run(
            [sys.executable, "-c", "import sys; import run_windows_trusted_utc_continuity_cas_responder; assert 'live_runtime.windows_trusted_utc_continuity_cas_responder' not in sys.modules; assert 'live_runtime.windows_trusted_utc_continuity_acceptance' not in sys.modules"],
            cwd=Path(__file__).resolve().parent, capture_output=True, timeout=15, check=False)
        self.assertEqual(0, completed.returncode, completed.stderr.decode(errors="replace"))

        import run_windows_trusted_utc_continuity_cas_responder as entry
        public_wire = (11).to_bytes(4, "big") + b"ssh-ed25519" + (32).to_bytes(4, "big") + b"p" * 32
        public = "ssh-ed25519 " + base64.b64encode(public_wire).decode()
        public_hash = hashlib.sha256(public.encode()).hexdigest()
        config = {
            "provider_id":"p", "clock_binding_sha256":H1, "custody_issuer_id":"i", "custody_key_id":"k",
            "custody_key_fingerprint_sha256":H2, "source_host_identity_sha256":H2, "consumer_host_identity_sha256":H3,
            "request_directory":str(self.req), "response_directory":str(self.res), "database_path":str(self.dbdir / "entry.sqlite3"),
            "hmac_key_path":str(self.root / "hmac"), "acceptance_custody_issuer_id":"ei", "acceptance_custody_key_id":"ek",
            "acceptance_private_key_path":str(self.root / "private"), "acceptance_public_key_path":str(self.root / "public"),
            "acceptance_public_key_file_sha256":H1, "acceptance_public_key_sha256":public_hash,
            "ssh_keygen_path":str(self.root / "ssh-keygen"), "ssh_keygen_sha256":H3, "poll_interval_ms":5,
            "schema_version":"windows-trusted-utc-continuity-cas-responder-v1",
        }
        config_bytes = (json.dumps(config, sort_keys=True, separators=(",", ":")) + "\n").encode()
        request_file = self.req / ("activation-"+"b"*64+".request.json")
        request_file.write_bytes(b'{"issued_at_utc":"2026-08-31T01:02:03.004000Z"}')
        challenge = {
            "baseline_head_sha256":"0"*64,"baseline_revision":0,
            "deadline_utc":"2099-01-01T00:00:00.000000Z", "generation_id":"a"*32,
            "issued_at_utc":"2026-08-31T01:02:03.004000Z",
            "nonce":"b"*64, "pointer_sha256":"c"*64, "role":"cas_responder",
            "schema_version":"finex-role-readiness-challenge-v3", "task_name":"cas-task",
        }
        challenge_bytes=(json.dumps(challenge,sort_keys=True,separators=(",",":"))+"\n").encode()
        challenge_path=self.root/"challenge.json";challenge_path.write_bytes(challenge_bytes)
        fake_pack = types.ModuleType("live_runtime.windows_decision_provider_pack")
        fake_pack.WindowsTrustedUTCContinuityCASBinding = lambda **kwargs: types.SimpleNamespace(**kwargs)
        fake_acceptance = types.ModuleType("live_runtime.windows_trusted_utc_continuity_acceptance")
        fake_acceptance.OpenSSHEd25519AcceptanceSigner = lambda **kwargs: types.SimpleNamespace(public_key_sha256=public_hash)
        fake_acceptance.acceptance_public_key_sha256 = lambda _: public_hash
        fake_acceptance.validate_restricted_path_acl = lambda _: None
        fake_responder = types.ModuleType("live_runtime.windows_trusted_utc_continuity_cas_responder")
        fake_responder.WindowsTrustedUTCContinuityCASBinding = fake_pack.WindowsTrustedUTCContinuityCASBinding
        fake_result=types.SimpleNamespace(request_id="d"*64,response_bytes=b"response",acceptance_bytes=b"acceptance",replayed=False)
        fake_instance=types.SimpleNamespace(
            process_request_bytes=lambda _:fake_result,
            authoritative_head_snapshot=lambda:{"head_sha256":"0"*64,"revision":0},
            build_committed_success_evidence=lambda _result,_request:{
                "committed_continuity_sha256":"f"*64,"database_commit_revision":1,
                "expected_previous_continuity_sha256":"0"*64,
                "new_authoritative_head_sha256":"f"*64,
                "schema_version":"windows-trusted-utc-continuity-cas-success-evidence-v1"},
            _atomic_write=lambda path,payload:path.write_bytes(payload),
        )
        fake_responder.WindowsTrustedUTCContinuityCASResponder = lambda **kwargs: fake_instance
        fake_responder.stable_secret_read = lambda _: b"secret"
        fake_responder.validate_restricted_acl = lambda _: None
        modules = {fake_pack.__name__:fake_pack, fake_acceptance.__name__:fake_acceptance, fake_responder.__name__:fake_responder}
        def pinned(_path, _hash, label, maximum=0):
            if label == "CONFIG": return config_bytes
            if label == "READINESS_CHALLENGE": return challenge_bytes
            if label == "ACCEPTANCE_PUBLIC_KEY": return public.encode()
            return b"pinned"
        with mock.patch.object(entry, "_arguments", return_value=Namespace(config=str(self.root / "config"), config_sha256=H1, python_sha256=H1, responder_core_sha256=H1, acceptance_core_sha256=H1, entrypoint_sha256=H1, activation_challenge_path=str(challenge_path), success_evidence_path=str(self.res/"success-evidence.json"), success_evidence_stdout=False, readiness_role="cas_responder", readiness_task_name="cas-task", readiness_generation_id="a"*32, readiness_pointer_sequence=1, readiness_pointer_sha256="c"*64, readiness_public_key_sha256="e"*64, once=True, durable=False)), \
             mock.patch.object(entry, "_stable_pinned", side_effect=pinned), mock.patch.object(entry, "_preflight_acl"), \
             mock.patch.object(entry, "_execute_pinned_module", side_effect=[fake_acceptance, fake_responder]), \
             mock.patch.dict(sys.modules, modules), mock.patch.dict(__import__("os").environ,{"AI_SCALPER_FINEX_READINESS_CHALLENGE_SHA256":hashlib.sha256(challenge_bytes).hexdigest()}):
            self.assertEqual(0, entry.main())

    def test_pinned_bytes_are_executed_and_replacement_rejected_subprocess(self):
        probe = self.root / "pinned_probe.py"
        script = self.root / "run_pinned_probe.py"
        script.write_text(
            "import builtins,hashlib,pathlib,sys\n"
            "import run_windows_trusted_utc_continuity_cas_responder as e\n"
            "e._preflight_acl=lambda _p: None\n"
            "p=pathlib.Path(sys.argv[1]).resolve()\n"
            "a=b\"import builtins;builtins._pinned_execution_probe='PINNED'\\n\"\n"
            "b=b\"import builtins;builtins._pinned_execution_probe='MUTATE'\\n\"\n"
            "assert len(a)==len(b)\n"
            "p.write_bytes(a)\n"
            "data=e._stable_pinned(p,hashlib.sha256(a).hexdigest(),'PROBE_CORE')\n"
            "p.write_bytes(b)\n"
            "try:e._execute_pinned_module('probe.pinned',p,data,'PROBE_CORE')\n"
            "except RuntimeError:pass\n"
            "else:raise AssertionError('replacement accepted')\n"
            "assert builtins._pinned_execution_probe=='PINNED'\n"
            "assert not (p.parent/'__pycache__').exists()\n",
            encoding="ascii")
        repository = Path(__file__).resolve().parent
        environment = dict(__import__("os").environ)
        environment["PYTHONPATH"] = str(repository)
        completed = subprocess.run([sys.executable, str(script), str(probe)], cwd=Path(__file__).resolve().parent,
                                   env=environment, capture_output=True, timeout=15, check=False)
        self.assertEqual(0, completed.returncode, completed.stderr.decode(errors="replace"))

    def test_exclusive_database_creation_rejects_injected_file_without_mutation(self):
        import live_runtime.windows_trusted_utc_continuity_cas_responder as responder_module
        request_dir = self.root / "inject-requests"; request_dir.mkdir()
        response_dir = self.root / "inject-responses"; response_dir.mkdir()
        database_dir = self.root / "inject-database"; database_dir.mkdir()
        database = database_dir / "authority.sqlite3"
        injected = b"attacker-owned-file"
        def inject(path):
            path.write_bytes(injected)
        with mock.patch.object(responder_module, "_DATABASE_BEFORE_EXCLUSIVE_CREATE_HOOK", inject), \
             self.assertRaisesRegex(TrustedUTCContinuityCASResponderError, "DATABASE_CREATE_RACE"):
            WindowsTrustedUTCContinuityCASResponder(
                binding=self.binding, source_host_identity_sha256=H2, consumer_host_identity_sha256=H3,
                request_directory=request_dir, response_directory=response_dir, database_path=database,
                custody_key_provider=lambda _: self.key, acceptance_signer=self.signer,
                acceptance_custody_issuer_id="ed-issuer", acceptance_custody_key_id="ed-key",
                clock=lambda: self.now, acl_validator=lambda _: None)
        self.assertEqual(injected, database.read_bytes())

    def test_same_size_secret_replacement_is_blocked_or_detected(self):
        import live_runtime.windows_trusted_utc_continuity_cas_responder as responder_module
        target = self.root / "held-secret.bin"; target.write_bytes(b"original-secret")
        replacement = self.root / "replacement-secret.bin"; replacement.write_bytes(b"forged---secret")
        blocked = []
        def replace(_path):
            try:
                replacement.replace(target)
            except OSError:
                blocked.append(True)
        with mock.patch.object(responder_module, "_SECRET_AFTER_FIRST_READ_HOOK", replace):
            if __import__("os").name == "nt":
                self.assertEqual(b"original-secret", stable_secret_read(target, acl_validator=lambda _: None))
                self.assertEqual([True], blocked)
            else:
                with self.assertRaises(TrustedUTCContinuityCASResponderError):
                    stable_secret_read(target, acl_validator=lambda _: None)

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symlink unsupported")
    def test_wal_reparse_is_rejected_before_sqlite_open(self):
        wal = Path(str(self.dbdir / "authority.sqlite3") + "-wal")
        wal.unlink(missing_ok=True)
        target = self.root / "injected-wal"; target.write_bytes(b"not-a-wal")
        try:
            wal.symlink_to(target)
        except OSError:
            self.skipTest("symlink privilege unavailable")
        with self.assertRaises(TrustedUTCContinuityCASResponderError):
            self.make_responder()
        self.assertTrue(wal.is_symlink())
        self.assertEqual(b"not-a-wal", target.read_bytes())

    def test_public_key_normalization_ignores_comment(self):
        wire = (11).to_bytes(4, "big") + b"ssh-ed25519" + (32).to_bytes(4, "big") + b"k" * 32
        plain = "ssh-ed25519 " + base64.b64encode(wire).decode()
        commented = plain + " responder-only@example"
        self.assertEqual(plain, normalize_openssh_ed25519_public_key(commented))
        self.assertEqual(acceptance_public_key_sha256(plain), acceptance_public_key_sha256(commented))
        with self.assertRaises(ValueError):
            normalize_openssh_ed25519_public_key("ssh-rsa " + base64.b64encode(wire).decode())

    @unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH ssh-keygen unavailable")
    def test_real_openssh_sign_verify_and_private_public_comparison(self):
        executable = Path(shutil.which("ssh-keygen")).resolve()
        key = self.root / "ephemeral-ed25519"
        generated = subprocess.run([str(executable), "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                                   capture_output=True, timeout=15, check=False)
        if generated.returncode:
            self.skipTest("OpenSSH key generation unavailable")
        public = key.with_suffix(".pub").read_text(encoding="ascii").strip() + " ignored-comment"
        signer = OpenSSHEd25519AcceptanceSigner(
            executable_path=executable, executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            private_key_path=key, public_key=public, acl_validator=lambda _: None)
        committed = self.responder.process_request_bytes(self.request())
        _, receipt, _, _ = parse_acceptance_envelope(committed.acceptance_bytes)
        receipt = replace(receipt, custody_public_key_sha256=signer.public_key_sha256)
        signed = make_acceptance_envelope(receipt, signer)
        verified = verify_acceptance_envelope(
            signed, public_key=public, executable_path=executable,
            executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(), acl_validator=lambda _: None)
        self.assertEqual(receipt, verified)
        client_verified = verify_client_acceptance_envelope(
            signed, public_key=public, executable_path=executable,
            executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            acl_validator=lambda _: None,
        )
        self.assertEqual(receipt.to_canonical_dict(), client_verified.to_canonical_dict())

    @unittest.skipUnless(__import__("os").name == "nt", "Windows ACL test")
    def test_windows_acl_rejects_unexpected_write_trustee(self):
        target = self.root / "acl-negative.txt"
        target.write_text("public fixture", encoding="ascii")
        with self.assertRaises(TrustedUTCContinuityAcceptanceError):
            validate_restricted_path_acl(target)
        with self.assertRaises(TrustedUTCContinuityCASResponderError):
            validate_restricted_acl(target)

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symlink unsupported")
    def test_reparse_request_root_rejected(self):
        alias = self.root / "alias"
        try: alias.symlink_to(self.req, target_is_directory=True)
        except OSError: self.skipTest("symlink privilege unavailable")
        with self.assertRaises(TrustedUTCContinuityCASResponderError):
            WindowsTrustedUTCContinuityCASResponder(
                binding=self.binding, source_host_identity_sha256=H2, consumer_host_identity_sha256=H3,
                request_directory=alias, response_directory=self.res, database_path=self.dbdir / "other.sqlite3",
                custody_key_provider=lambda _: self.key, acceptance_signer=self.signer,
                acceptance_custody_issuer_id="ed-issuer", acceptance_custody_key_id="ed-key",
                clock=lambda: self.now, acl_validator=lambda _: None)


if __name__ == "__main__":
    unittest.main()
