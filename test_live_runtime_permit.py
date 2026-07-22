from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import unittest

from live_runtime.permit import (
    KillSwitchResetPermit,
    LIVE_ALLOWED,
    PROMOTION_PERMIT_MAX_TTL,
    PermitValidation,
    SAFE_TO_DEMO_AUTO_ORDER,
    PromotionPermit,
    account_alias_sha256,
    authorize_kill_switch_reset,
    reset_reason_sha256,
    validate_permit,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 15, 3, 0, tzinfo=UTC)
SECRET = "correct-horse-battery-staple-extra-secret"
COMMIT = "a" * 40
CONFIG = "b" * 64
MODEL_ARTIFACT = "c" * 64
RESET_SECRET_A = "permit-reset-approver-a-secret-at-least-32-bytes"
RESET_SECRET_B = "permit-reset-approver-b-secret-at-least-32-bytes"
RESET_KEY_ID_A = "risk-reset-key-v1"
RESET_KEY_ID_B = "operations-reset-key-v1"


def unsigned_permit(**changes: object) -> PromotionPermit:
    values: dict[str, object] = {
        "mode": "PAPER",
        "account_alias_sha256": account_alias_sha256("acct-01"),
        "server": "broker-demo",
        "symbols": ("XAUUSD", "EURUSD"),
        "commit_sha": COMMIT,
        "config_sha256": CONFIG,
        "model_artifact_sha256": MODEL_ARTIFACT,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=4),
        "nonce": "review-0001",
    }
    values.update(changes)
    return PromotionPermit(**values)  # type: ignore[arg-type]


def validate(permit: PromotionPermit, **changes: object):
    values: dict[str, object] = {
        "now": NOW + timedelta(minutes=1),
        "expected_mode": "PAPER",
        "expected_account_alias": "acct-01",
        "expected_server": "broker-demo",
        "expected_symbols": ("EURUSD", "XAUUSD"),
        "expected_commit_sha": COMMIT,
        "expected_config_sha256": CONFIG,
        "expected_model_artifact_sha256": MODEL_ARTIFACT,
    }
    values.update(changes)
    return validate_permit(permit, SECRET, **values)  # type: ignore[arg-type]


def unsigned_reset_permit(**changes: object) -> KillSwitchResetPermit:
    values: dict[str, object] = {
        "journal_sha256": "f" * 64,
        "latched_at_utc": NOW,
        "reset_reason_sha256": reset_reason_sha256("reviewed reset"),
        "approver_ids": ("risk-officer", "operations-officer"),
        "approver_key_ids": (
            ("risk-officer", RESET_KEY_ID_A),
            ("operations-officer", RESET_KEY_ID_B),
        ),
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
        "nonce": "reset-review-0001",
    }
    values.update(changes)
    return KillSwitchResetPermit(**values)  # type: ignore[arg-type]


def signed_reset_permit() -> KillSwitchResetPermit:
    return unsigned_reset_permit().sign(
        "risk-officer",
        RESET_KEY_ID_A,
        RESET_SECRET_A,
    ).sign(
        "operations-officer",
        RESET_KEY_ID_B,
        RESET_SECRET_B,
    )


class PromotionPermitTests(unittest.TestCase):
    def test_valid_hmac_binds_all_deployment_fields_but_unlocks_nothing(self) -> None:
        permit = unsigned_permit().sign(SECRET)
        result = validate(permit)
        self.assertTrue(result.valid, result.reason_codes)
        self.assertTrue(result.signature_valid)
        self.assertTrue(result.binding_valid)
        self.assertTrue(result.time_valid)
        self.assertEqual("PAPER", result.mode)
        self.assertEqual(permit.expires_at, result.expires_at)
        self.assertEqual(permit.account_alias_sha256, result.account_alias_sha256)
        self.assertEqual(MODEL_ARTIFACT, result.model_artifact_sha256)
        self.assertFalse(result.execution_authorized)
        self.assertFalse(result.can_unlock)
        self.assertFalse(result.live_allowed)
        self.assertFalse(result.safe_to_demo_auto_order)
        self.assertFalse(LIVE_ALLOWED)
        self.assertFalse(SAFE_TO_DEMO_AUTO_ORDER)
        self.assertNotIn("acct-01", permit.canonical_json())

    def test_validation_result_cannot_be_forged_without_hmac_boundary(self) -> None:
        with self.assertRaises(TypeError):
            PermitValidation(
                valid=True,
                reason_codes=(),
                checked_at=NOW,
                permit_id="forged",
                signature_valid=True,
                binding_valid=True,
                time_valid=True,
                mode="LIVE",
                account_alias_sha256="a" * 64,
                server="broker-live",
                symbols=("EURUSD",),
                commit_sha="b" * 40,
                config_sha256="c" * 64,
                model_artifact_sha256="d" * 64,
                schema_version="1.0",
                issued_at=NOW - timedelta(seconds=1),
                expires_at=NOW + timedelta(minutes=1),
            )

    def test_permit_subclass_cannot_override_signature_verification(self) -> None:
        class ForgedPermit(PromotionPermit):
            def verify_signature(self, secret: str | bytes) -> bool:
                return True

        source = unsigned_permit()
        forged = ForgedPermit(
            **{
                field.name: getattr(source, field.name)
                for field in fields(PromotionPermit)
            }
        )
        with self.assertRaisesRegex(TypeError, "exact PromotionPermit"):
            validate(forged)

    def test_permit_is_frozen_and_id_is_stable_before_and_after_signing(self) -> None:
        unsigned = unsigned_permit()
        signed = unsigned.sign(SECRET)
        self.assertEqual(unsigned.permit_id, signed.permit_id)
        with self.assertRaises(FrozenInstanceError):
            signed.server = "other"  # type: ignore[misc]

    def test_maximum_ttl_boundary_is_valid(self) -> None:
        permit = unsigned_permit(
            expires_at=NOW + PROMOTION_PERMIT_MAX_TTL,
        ).sign(SECRET)
        result = validate(permit)
        self.assertTrue(result.valid, result.reason_codes)
        self.assertTrue(result.time_valid)

    def test_oversized_ttl_is_rejected_at_construction(self) -> None:
        with self.assertRaisesRegex(ValueError, "maximum lifetime"):
            unsigned_permit(
                expires_at=(
                    NOW
                    + PROMOTION_PERMIT_MAX_TTL
                    + timedelta(microseconds=1)
                )
            )

    def test_oversized_ttl_is_rejected_again_at_sign_and_validation_boundaries(
        self,
    ) -> None:
        unsigned = unsigned_permit()
        object.__setattr__(
            unsigned,
            "expires_at",
            NOW + PROMOTION_PERMIT_MAX_TTL + timedelta(seconds=1),
        )
        with self.assertRaisesRegex(ValueError, "maximum lifetime"):
            unsigned.sign(SECRET)

        # Simulate a legacy/externally deserialized artifact whose HMAC is valid
        # but whose lifetime predates this policy boundary.  Validation must
        # reject the TTL independently of signature verification.
        signed = unsigned_permit()
        object.__setattr__(
            signed,
            "expires_at",
            NOW + PROMOTION_PERMIT_MAX_TTL + timedelta(seconds=1),
        )
        object.__setattr__(
            signed,
            "signature",
            hmac.new(
                SECRET.encode("utf-8"),
                signed.signing_payload,
                hashlib.sha256,
            ).hexdigest(),
        )
        result = validate(signed)
        self.assertFalse(result.valid)
        self.assertTrue(result.signature_valid)
        self.assertFalse(result.time_valid)
        self.assertIn("PERMIT_TTL_EXCEEDED", result.reason_codes)

    def test_tampering_invalidates_hmac_and_binding(self) -> None:
        signed = unsigned_permit().sign(SECRET)
        tampered = replace(signed, account_alias_sha256="f" * 64)
        result = validate(tampered)
        self.assertFalse(result.valid)
        self.assertFalse(result.signature_valid)
        self.assertFalse(result.binding_valid)
        self.assertIn("INVALID_SIGNATURE", result.reason_codes)
        self.assertIn("ACCOUNT_BINDING_MISMATCH", result.reason_codes)

    def test_expired_and_not_yet_valid_permits_fail_closed(self) -> None:
        signed = unsigned_permit().sign(SECRET)
        expired = validate(signed, now=NOW + timedelta(minutes=30))
        self.assertFalse(expired.valid)
        self.assertIn("PERMIT_EXPIRED", expired.reason_codes)
        future = validate(signed, now=NOW - timedelta(microseconds=1))
        self.assertFalse(future.valid)
        self.assertIn("PERMIT_NOT_YET_VALID", future.reason_codes)

    def test_each_expected_binding_is_checked(self) -> None:
        signed = unsigned_permit().sign(SECRET)
        cases = (
            ({"expected_mode": "DRY_RUN"}, "MODE_BINDING_MISMATCH"),
            ({"expected_account_alias": "other"}, "ACCOUNT_BINDING_MISMATCH"),
            ({"expected_server": "other"}, "SERVER_BINDING_MISMATCH"),
            ({"expected_symbols": ("EURUSD",)}, "SYMBOL_BINDING_MISMATCH"),
            ({"expected_commit_sha": "c" * 40}, "COMMIT_BINDING_MISMATCH"),
            ({"expected_config_sha256": "d" * 64}, "CONFIG_BINDING_MISMATCH"),
            (
                {"expected_model_artifact_sha256": "e" * 64},
                "MODEL_ARTIFACT_BINDING_MISMATCH",
            ),
        )
        for changes, reason in cases:
            with self.subTest(reason=reason):
                result = validate(signed, **changes)
                self.assertFalse(result.valid)
                self.assertIn(reason, result.reason_codes)

    def test_unknown_signed_schema_is_rejected_even_with_a_valid_hmac(self) -> None:
        permit = unsigned_permit(schema_version="2.0").sign(SECRET)
        result = validate(permit)
        self.assertTrue(result.signature_valid)
        self.assertFalse(result.binding_valid)
        self.assertIn("SCHEMA_VERSION_MISMATCH", result.reason_codes)

    def test_invalid_time_signature_flags_and_short_secrets_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            unsigned_permit(issued_at=NOW.replace(tzinfo=None))
        with self.assertRaises(ValueError):
            unsigned_permit(live_allowed=True)
        with self.assertRaises(ValueError):
            unsigned_permit(safe_to_demo_auto_order=True)
        with self.assertRaises(ValueError):
                unsigned_permit().sign("short")


class KillSwitchResetPermitTests(unittest.TestCase):
    def test_reset_approval_requires_distinct_key_ids_and_secrets(self) -> None:
        with self.assertRaisesRegex(ValueError, "distinct key_id"):
            unsigned_reset_permit(
                approver_key_ids=(
                    ("risk-officer", "shared-reset-key"),
                    ("operations-officer", "shared-reset-key"),
                )
            )
        with self.assertRaisesRegex(ValueError, "independent HMAC secrets"):
            unsigned_reset_permit().sign(
                "risk-officer",
                RESET_KEY_ID_A,
                RESET_SECRET_A,
            ).sign(
                "operations-officer",
                RESET_KEY_ID_B,
                RESET_SECRET_A,
            )

        permit = signed_reset_permit()
        with self.assertRaisesRegex(PermissionError, "invalid"):
            authorize_kill_switch_reset(
                permit,
                {
                    "risk-officer": (RESET_KEY_ID_A, RESET_SECRET_A),
                    "operations-officer": (RESET_KEY_ID_A, RESET_SECRET_B),
                },
                now=NOW,
                expected_journal_sha256=permit.journal_sha256,
                expected_latched_at_utc=permit.latched_at_utc,
                expected_reason="reviewed reset",
                clock_provider=lambda: NOW,
            )

    def test_reset_authorizer_uses_trusted_clock_not_caller_assertion(self) -> None:
        permit = signed_reset_permit()
        approver_keys = {
            "risk-officer": (RESET_KEY_ID_A, RESET_SECRET_A),
            "operations-officer": (RESET_KEY_ID_B, RESET_SECRET_B),
        }
        trusted = NOW + timedelta(milliseconds=1)
        authorization = authorize_kill_switch_reset(
            permit,
            approver_keys,
            now=NOW,
            expected_journal_sha256=permit.journal_sha256,
            expected_latched_at_utc=permit.latched_at_utc,
            expected_reason="reviewed reset",
            clock_provider=lambda: trusted,
        )
        self.assertEqual(trusted, authorization.checked_at_utc)
        self.assertEqual(permit.approver_key_ids, authorization.approver_key_ids)

        with self.assertRaisesRegex(ValueError, "trusted clock"):
            authorize_kill_switch_reset(
                permit,
                approver_keys,
                now=NOW,
                expected_journal_sha256=permit.journal_sha256,
                expected_latched_at_utc=permit.latched_at_utc,
                expected_reason="reviewed reset",
                clock_provider=lambda: NOW + timedelta(milliseconds=51),
            )
        with self.assertRaisesRegex(PermissionError, "stale"):
            authorize_kill_switch_reset(
                permit,
                approver_keys,
                expected_journal_sha256=permit.journal_sha256,
                expected_latched_at_utc=permit.latched_at_utc,
                expected_reason="reviewed reset",
                clock_provider=lambda: permit.expires_at,
            )


if __name__ == "__main__":
    unittest.main()
