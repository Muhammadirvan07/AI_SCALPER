from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import unittest

from live_runtime.contracts import DecisionSnapshot, _mint_decision_snapshot
from live_runtime.model_governance import (
    ModelArtifactManifest,
    ModelBindingDecision,
    verify_decision_model,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 15, 4, 0, 1, tzinfo=UTC)


def artifact(role="CHAMPION"):
    return ModelArtifactManifest(
        role=role,
        model_version="champion-1",
        artifact_sha256="a" * 64,
        training_snapshot_sha256="b" * 64,
        commit_sha="c" * 40,
        config_sha256="d" * 64,
        training_cutoff_at=NOW - timedelta(days=2),
        registered_at=NOW - timedelta(days=1),
    )


def decision():
    return _mint_decision_snapshot(
        decision_run_id="run-1",
        symbol="XAUUSD",
        side="BUY",
        strategy="MOMENTUM_PULLBACK",
        score=3,
        score_components={"trend": 2, "pullback": 1},
        entry_reference=3300.0,
        stop_loss=3299.0,
        take_profit=3302.0,
        model_version="champion-1",
        model_artifact_sha256="a" * 64,
        commit_sha="c" * 40,
        config_sha256="d" * 64,
        data_sha256="e" * 64,
        source_name="broker",
        source_aligned=True,
        data_fresh=True,
        bar_closed_at=NOW - timedelta(seconds=1),
        created_at=NOW,
    )


class ModelGovernanceTests(unittest.TestCase):
    def test_exact_champion_binding_never_authorizes_execution(self):
        result = verify_decision_model(decision(), artifact(), checked_at=NOW)
        self.assertTrue(result.bound)
        self.assertFalse(result.execution_authorized)

    def test_challenger_is_always_shadow_only(self):
        result = verify_decision_model(decision(), artifact("CHALLENGER"), checked_at=NOW)
        self.assertFalse(result.bound)
        self.assertIn("CHALLENGER_SHADOW_ONLY", result.reason_codes)

    def test_model_drift_is_reported(self):
        values = asdict(decision())
        values.update(
            model_version="other",
            model_artifact_sha256="f" * 64,
            config_sha256="f" * 64,
        )
        changed = _mint_decision_snapshot(**values)
        result = verify_decision_model(changed, artifact(), checked_at=NOW)
        self.assertIn("MODEL_VERSION_MISMATCH", result.reason_codes)
        self.assertIn("MODEL_ARTIFACT_MISMATCH", result.reason_codes)
        self.assertIn("MODEL_CONFIG_MISMATCH", result.reason_codes)

    def test_model_binding_cannot_be_minted_by_a_caller(self):
        with self.assertRaises(ValueError):
            ModelBindingDecision(
                bound=True,
                role="CHAMPION",
                model_version="champion-1",
                model_artifact_sha256="a" * 64,
                decision_snapshot_id=decision().snapshot_id,
                reason_codes=(),
                checked_at=NOW,
                valid_until=NOW + timedelta(seconds=1),
            )

    def test_online_learning_credentials_and_self_promotion_are_forbidden(self):
        for field in ("online_learning_enabled", "credential_access", "self_promotion_allowed"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    replace(artifact(), **{field: True})


if __name__ == "__main__":
    unittest.main()
