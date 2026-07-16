from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
import inspect
import os
import unittest
from unittest.mock import patch

from live_runtime.controls import (
    DEFAULT_ENVIRONMENT_ARM_VARIABLE,
    ENVIRONMENT_ARM_TTL,
    EnvironmentArmDecision,
    MANUAL_DEMO_APPROVAL_MAX_TTL,
    ManualDemoApproval,
    ManualDemoApprovalValidation,
    canonical_environment_arm_token,
    environment_arm_binding_sha256,
    manual_demo_account_sha256,
    read_environment_arm,
    validate_manual_demo_approval,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 16, 1, 0, tzinfo=UTC)
ACCOUNT = "demo-account-alias"
SERVER = "Broker-Demo-01"
MODE = "DEMO"
INTENT_ID = "intent-manual-demo-0001"
APPROVER_ID = "operator-01"
KEY_ID = "manual-demo-key-v1"
SECRET = b"manual-demo-approval-secret-32-bytes-minimum"
JOURNAL_SHA256 = "f" * 64


def unsigned_approval(**changes: object) -> ManualDemoApproval:
    values: dict[str, object] = {
        "intent_id": INTENT_ID,
        "account_id_sha256": manual_demo_account_sha256(ACCOUNT),
        "server": SERVER,
        "approver_id": APPROVER_ID,
        "key_id": KEY_ID,
        "issued_at_utc": NOW,
        "expires_at_utc": NOW + timedelta(minutes=5),
        "nonce": "manual-review-0001",
        "journal_sha256": JOURNAL_SHA256,
    }
    values.update(changes)
    return ManualDemoApproval(**values)  # type: ignore[arg-type]


def validate(
    approval: ManualDemoApproval,
    *,
    trusted_now: datetime = NOW + timedelta(seconds=1),
    **changes: object,
) -> ManualDemoApprovalValidation:
    values: dict[str, object] = {
        "expected_intent_id": INTENT_ID,
        "expected_account_id": ACCOUNT,
        "expected_server": SERVER,
        "expected_approver_id": APPROVER_ID,
        "expected_key_id": KEY_ID,
        "expected_journal_sha256": JOURNAL_SHA256,
        "key_provider": lambda key_id: SECRET if key_id == KEY_ID else None,
        "clock_provider": lambda: trusted_now,
    }
    values.update(changes)
    return validate_manual_demo_approval(approval, **values)  # type: ignore[arg-type]


class EnvironmentArmControlTests(unittest.TestCase):
    def test_valid_exact_process_environment_arm_is_sealed_and_short_lived(self) -> None:
        token = canonical_environment_arm_token(
            ACCOUNT, SERVER, MODE, JOURNAL_SHA256
        )
        with patch.dict(
            os.environ,
            {DEFAULT_ENVIRONMENT_ARM_VARIABLE: token},
            clear=False,
        ):
            decision = read_environment_arm(
                ACCOUNT, SERVER, MODE, NOW, JOURNAL_SHA256
            )

        self.assertTrue(decision.armed, decision.reason_codes)
        self.assertEqual((), decision.reason_codes)
        self.assertEqual(
            environment_arm_binding_sha256(
                ACCOUNT, SERVER, MODE, JOURNAL_SHA256
            ),
            decision.binding_sha256,
        )
        self.assertEqual(ENVIRONMENT_ARM_TTL, decision.valid_until_utc - NOW)
        self.assertTrue(decision.is_fresh(NOW))
        self.assertTrue(decision.is_fresh(NOW + timedelta(microseconds=999_999)))
        self.assertFalse(decision.is_fresh(NOW + timedelta(seconds=1)))
        self.assertNotIn(ACCOUNT, decision.canonical_json())
        self.assertNotIn(token, decision.canonical_json())
        with self.assertRaises(FrozenInstanceError):
            decision.armed = False  # type: ignore[misc]

    def test_direct_environment_decision_construction_is_denied(self) -> None:
        with self.assertRaisesRegex(TypeError, "read_environment_arm"):
            EnvironmentArmDecision(
                armed=True,
                reason_codes=(),
                checked_at_utc=NOW,
                valid_until_utc=NOW + timedelta(seconds=1),
                env_var_name=DEFAULT_ENVIRONMENT_ARM_VARIABLE,
                binding_sha256="a" * 64,
                journal_sha256=JOURNAL_SHA256,
                observed_value_sha256="b" * 64,
            )

    def test_missing_and_wrong_values_fail_closed_without_leaking_raw_value(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            missing = read_environment_arm(
                ACCOUNT, SERVER, MODE, NOW, JOURNAL_SHA256
            )
        self.assertFalse(missing.armed)
        self.assertEqual(("ENVIRONMENT_ARM_MISSING",), missing.reason_codes)
        self.assertIsNone(missing.observed_value_sha256)

        raw_wrong_value = "not-the-canonical-token"
        with patch.dict(
            os.environ,
            {DEFAULT_ENVIRONMENT_ARM_VARIABLE: raw_wrong_value},
            clear=True,
        ):
            wrong = read_environment_arm(
                ACCOUNT, SERVER, MODE, NOW, JOURNAL_SHA256
            )
        self.assertFalse(wrong.armed)
        self.assertEqual(("ENVIRONMENT_ARM_MISMATCH",), wrong.reason_codes)
        self.assertNotIn(raw_wrong_value, wrong.canonical_json())

    def test_token_is_bound_to_exact_account_server_and_mode(self) -> None:
        token = canonical_environment_arm_token(
            ACCOUNT, SERVER, MODE, JOURNAL_SHA256
        )
        cases = (
            ("other-account", SERVER, MODE),
            (ACCOUNT, "Other-Demo-Server", MODE),
            (ACCOUNT, SERVER, "LIVE"),
        )
        with patch.dict(
            os.environ,
            {DEFAULT_ENVIRONMENT_ARM_VARIABLE: token},
            clear=True,
        ):
            for account_id, server, mode in cases:
                with self.subTest(account=account_id, server=server, mode=mode):
                    decision = read_environment_arm(
                        account_id,
                        server,
                        mode,
                        NOW,
                        JOURNAL_SHA256,
                    )
                    self.assertFalse(decision.armed)
                    self.assertIn(
                        "ENVIRONMENT_ARM_MISMATCH",
                        decision.reason_codes,
                    )

    def test_value_must_match_byte_for_byte_and_custom_key_reads_real_environ(self) -> None:
        custom_name = "AI_SCALPER_TEST_EXECUTION_ARM"
        token = canonical_environment_arm_token(
            ACCOUNT, SERVER, MODE, JOURNAL_SHA256
        )
        with patch.dict(os.environ, {custom_name: f"{token} "}, clear=True):
            mismatch = read_environment_arm(
                ACCOUNT,
                SERVER,
                MODE,
                NOW,
                JOURNAL_SHA256,
                env_var_name=custom_name,
            )
        self.assertFalse(mismatch.armed)

        with patch.dict(os.environ, {custom_name: token}, clear=True):
            armed = read_environment_arm(
                ACCOUNT,
                SERVER,
                MODE,
                NOW,
                JOURNAL_SHA256,
                env_var_name=custom_name,
            )
        self.assertTrue(armed.armed)
        self.assertEqual(custom_name, armed.env_var_name)
        self.assertNotIn("environ", inspect.signature(read_environment_arm).parameters)
        with self.assertRaises(TypeError):
            read_environment_arm(
                ACCOUNT,
                SERVER,
                MODE,
                NOW,
                JOURNAL_SHA256,
                environ={custom_name: token},  # type: ignore[call-arg]
            )

    def test_utc_and_mode_inputs_are_strict(self) -> None:
        with self.assertRaisesRegex(ValueError, "timezone-aware UTC"):
            read_environment_arm(
                ACCOUNT,
                SERVER,
                MODE,
                NOW.replace(tzinfo=None),
                JOURNAL_SHA256,
            )
        with self.assertRaisesRegex(ValueError, "non-zero offset"):
            read_environment_arm(
                ACCOUNT,
                SERVER,
                MODE,
                NOW.astimezone(timezone(timedelta(hours=9))),
                JOURNAL_SHA256,
            )
        with self.assertRaisesRegex(ValueError, "unsupported execution mode"):
            canonical_environment_arm_token(
                ACCOUNT, SERVER, "MANUAL", JOURNAL_SHA256
            )


class ManualDemoApprovalTests(unittest.TestCase):
    def test_valid_signed_approval_binds_exact_intent_identity_and_key(self) -> None:
        unsigned = unsigned_approval()
        signed = unsigned.sign(SECRET)
        result = validate(signed)

        self.assertTrue(result.valid, result.reason_codes)
        self.assertTrue(result.signature_valid)
        self.assertTrue(result.binding_valid)
        self.assertTrue(result.time_valid)
        self.assertEqual((), result.reason_codes)
        self.assertEqual(signed.approval_id, result.approval_id)
        self.assertEqual(signed.binding_sha256, result.binding_sha256)
        self.assertEqual(unsigned.approval_id, signed.approval_id)
        self.assertTrue(result.is_fresh(NOW + timedelta(seconds=2)))
        self.assertNotIn(ACCOUNT, signed.canonical_json())
        with self.assertRaises(FrozenInstanceError):
            signed.intent_id = "forged"  # type: ignore[misc]

    def test_validation_cannot_be_constructed_directly(self) -> None:
        with self.assertRaisesRegex(TypeError, "validate_manual_demo_approval"):
            ManualDemoApprovalValidation(
                valid=True,
                reason_codes=(),
                signature_valid=True,
                binding_valid=True,
                time_valid=True,
                checked_at_utc=NOW,
                issued_at_utc=NOW - timedelta(seconds=1),
                valid_until_utc=NOW + timedelta(seconds=1),
                approval_id="forged",
                binding_sha256="a" * 64,
                intent_id=INTENT_ID,
                account_id_sha256="b" * 64,
                server=SERVER,
                approver_id=APPROVER_ID,
                key_id=KEY_ID,
                journal_sha256=JOURNAL_SHA256,
                mode="DEMO",
                schema_version="manual-demo-approval-v1",
            )

    def test_each_expected_binding_is_checked(self) -> None:
        signed = unsigned_approval().sign(SECRET)
        cases = (
            ({"expected_intent_id": "other-intent"}, "INTENT_BINDING_MISMATCH"),
            ({"expected_account_id": "other-account"}, "ACCOUNT_BINDING_MISMATCH"),
            ({"expected_server": "other-server"}, "SERVER_BINDING_MISMATCH"),
            ({"expected_approver_id": "other-operator"}, "APPROVER_BINDING_MISMATCH"),
            ({"expected_key_id": "other-key"}, "KEY_BINDING_MISMATCH"),
            (
                {"expected_journal_sha256": "e" * 64},
                "JOURNAL_BINDING_MISMATCH",
            ),
        )
        for changes, reason in cases:
            with self.subTest(reason=reason):
                result = validate(signed, **changes)
                self.assertFalse(result.valid)
                self.assertTrue(result.signature_valid)
                self.assertFalse(result.binding_valid)
                self.assertIn(reason, result.reason_codes)

    def test_tampered_and_unsigned_approvals_fail_signature_validation(self) -> None:
        signed = unsigned_approval().sign(SECRET)
        tampered = replace(signed, server="tampered-server")
        result = validate(tampered, expected_server="tampered-server")
        self.assertFalse(result.valid)
        self.assertFalse(result.signature_valid)
        self.assertIn("INVALID_SIGNATURE", result.reason_codes)

        unsigned_result = validate(unsigned_approval())
        self.assertFalse(unsigned_result.valid)
        self.assertIn("INVALID_SIGNATURE", unsigned_result.reason_codes)

    def test_expired_and_not_yet_valid_approvals_fail_with_trusted_time(self) -> None:
        signed = unsigned_approval().sign(SECRET)
        expired = validate(signed, trusted_now=signed.expires_at_utc)
        self.assertFalse(expired.valid)
        self.assertFalse(expired.time_valid)
        self.assertIn("APPROVAL_EXPIRED", expired.reason_codes)

        future = validate(signed, trusted_now=NOW - timedelta(microseconds=1))
        self.assertFalse(future.valid)
        self.assertFalse(future.time_valid)
        self.assertIn("APPROVAL_NOT_YET_VALID", future.reason_codes)

    def test_key_provider_failure_wrong_key_and_short_secrets_fail_closed(self) -> None:
        signed = unsigned_approval().sign(SECRET)
        unavailable = validate(
            signed,
            key_provider=lambda key_id: (_ for _ in ()).throw(KeyError(key_id)),
        )
        self.assertFalse(unavailable.valid)
        self.assertIn("APPROVAL_KEY_UNAVAILABLE", unavailable.reason_codes)
        self.assertIn("INVALID_SIGNATURE", unavailable.reason_codes)

        wrong = validate(signed, key_provider=lambda key_id: b"x" * 32)
        self.assertFalse(wrong.valid)
        self.assertFalse(wrong.signature_valid)
        self.assertIn("INVALID_SIGNATURE", wrong.reason_codes)

        short = validate(signed, key_provider=lambda key_id: b"short")
        self.assertFalse(short.valid)
        self.assertIn("APPROVAL_KEY_UNAVAILABLE", short.reason_codes)
        with self.assertRaisesRegex(ValueError, "at least 32 bytes"):
            unsigned_approval().sign(b"short")

    def test_five_minute_ttl_is_hard_maximum_and_all_times_require_utc(self) -> None:
        exact = unsigned_approval(
            expires_at_utc=NOW + MANUAL_DEMO_APPROVAL_MAX_TTL
        )
        self.assertEqual(MANUAL_DEMO_APPROVAL_MAX_TTL, exact.expires_at_utc - NOW)
        with self.assertRaisesRegex(ValueError, "cannot exceed five minutes"):
            unsigned_approval(
                expires_at_utc=NOW
                + MANUAL_DEMO_APPROVAL_MAX_TTL
                + timedelta(microseconds=1)
            )
        with self.assertRaisesRegex(ValueError, "timezone-aware UTC"):
            unsigned_approval(issued_at_utc=NOW.replace(tzinfo=None))
        with self.assertRaisesRegex(ValueError, "timezone-aware UTC"):
            validate(
                exact.sign(SECRET),
                trusted_now=NOW.replace(tzinfo=None),
            )

    def test_unknown_schema_is_invalid_even_when_correctly_signed(self) -> None:
        signed = unsigned_approval(schema_version="manual-demo-approval-v2").sign(
            SECRET
        )
        result = validate(signed)
        self.assertTrue(result.signature_valid)
        self.assertFalse(result.valid)
        self.assertFalse(result.binding_valid)
        self.assertIn("SCHEMA_VERSION_MISMATCH", result.reason_codes)


if __name__ == "__main__":
    unittest.main()
