import unittest

from live_runtime.live_readiness import LiveReadinessEvidence, assess_live_readiness


def complete_evidence(**overrides):
    values = {
        "operating_jurisdiction": "ID",
        "broker_id": "FINEX",
        "ai_mode": "AI_VETO_CONFIRM",
        "demo_clean_days": 30,
        "demo_closed_fills_by_symbol": {
            "EURUSD": 25,
            "USDJPY": 25,
            "AUDUSD": 25,
            "XAUUSD": 25,
        },
        "demo_account_attested": True,
        "live_broker_eligibility_verified": True,
        "broker_evidence_unexpired": True,
        "instrument_specs_verified": True,
        "conversion_quotes_fresh": True,
        "strategy_runtime_parity_verified": True,
        "future_holdout_available": True,
        "point_in_time_calendar_available": True,
        "economic_calendar_fresh": True,
        "risk_controls_verified": True,
        "human_approval_pipeline_verified": True,
        "kill_switch_verified": True,
        "reconciliation_verified": True,
        "release_identity_verified": True,
        "terminal_monitor_verified": True,
    }
    values.update(overrides)
    return LiveReadinessEvidence(**values)


class LiveReadinessTests(unittest.TestCase):
    def test_complete_evidence_is_review_ready_but_never_authorizes(self):
        result = assess_live_readiness(complete_evidence())
        self.assertTrue(result.demo_auto_ready_for_activation_review)
        self.assertTrue(result.live_canary_ready_for_activation_review)
        self.assertFalse(result.authorization_granted)
        self.assertEqual(result.order_capability, "DISABLED")

    def test_missing_each_symbol_threshold_blocks_live(self):
        result = assess_live_readiness(
            complete_evidence(
                demo_closed_fills_by_symbol={
                    "EURUSD": 19,
                    "USDJPY": 27,
                    "AUDUSD": 27,
                    "XAUUSD": 27,
                }
            )
        )
        self.assertIn("DEMO_EURUSD_CLOSED_FILLS_20_REQUIRED", result.blocker_codes)
        self.assertFalse(result.demo_auto_ready_for_activation_review)
        self.assertFalse(result.live_canary_ready_for_activation_review)

    def test_deterministic_fallback_requires_fresh_calendar(self):
        result = assess_live_readiness(
            complete_evidence(ai_mode="FALLBACK_DETERMINISTIC", economic_calendar_fresh=False)
        )
        self.assertIn("FRESH_ECONOMIC_CALENDAR_REQUIRED", result.blocker_codes)
        self.assertFalse(result.demo_auto_ready_for_activation_review)

    def test_indonesia_live_eligibility_is_live_only_external_gate(self):
        result = assess_live_readiness(
            complete_evidence(
                live_broker_eligibility_verified=False,
            )
        )
        self.assertTrue(result.demo_auto_ready_for_activation_review)
        self.assertFalse(result.live_canary_ready_for_activation_review)

    def test_broker_freshness_and_human_approval_block_demo_auto(self):
        result = assess_live_readiness(
            complete_evidence(
                broker_evidence_unexpired=False,
                human_approval_pipeline_verified=False,
            )
        )
        self.assertIn(
            "BROKER_ELIGIBILITY_EVIDENCE_FRESHNESS_REQUIRED",
            result.blocker_codes,
        )
        self.assertIn("HUMAN_APPROVAL_PIPELINE_REQUIRED", result.blocker_codes)
        self.assertFalse(result.demo_auto_ready_for_activation_review)

    def test_incident_demotes_both_stages(self):
        result = assess_live_readiness(complete_evidence(critical_incident_count=1))
        self.assertFalse(result.demo_auto_ready_for_activation_review)
        self.assertFalse(result.live_canary_ready_for_activation_review)
        self.assertIn("CRITICAL_INCIDENT_DEMOTION_LATCHED", result.blocker_codes)

    def test_realtime_terminal_monitor_is_required(self):
        result = assess_live_readiness(complete_evidence(terminal_monitor_verified=False))
        self.assertIn("REALTIME_TERMINAL_MONITOR_REQUIRED", result.blocker_codes)
        self.assertFalse(result.demo_auto_ready_for_activation_review)

    def test_unknown_symbol_is_rejected(self):
        with self.assertRaises(ValueError):
            assess_live_readiness(
                complete_evidence(demo_closed_fills_by_symbol={"EURUSD": 100, "BTCUSD": 20})
            )


if __name__ == "__main__":
    unittest.main()
