import json
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError

from openai_decision_advisor import AdvisorSettings, OpenAIDecisionAdvisor, apply_openai_advisory


def ready_decision():
    return {
        "status": "READY_TO_TRADE", "symbol": "EURUSD", "action": "BUY", "lot_size": 0.01,
        "entry_price": 1.1, "stop_loss": 1.09, "take_profit": 1.12,
        "market_status": "NORMAL", "volatility_percent": 0.08,
        "selected_strategy": "BREAKOUT", "strategy_score": 5,
    }


class StubAdvisor:
    def __init__(self, result):
        self.result = result

    def advise(self, decision):
        return dict(self.result)


class OpenAIDecisionAdvisorTests(unittest.TestCase):
    def settings(self, directory, **changes):
        values = dict(
            api_key="test", enabled=True, model="gpt-5.4-mini", minimum_confidence=0.7,
            require_news=True, news_api_base_url="http://localhost", timeout_seconds=1,
            audit_file=Path(directory) / "audit.jsonl",
        )
        values.update(changes)
        return AdvisorSettings(**values)

    def successful_transport(self, request, timeout):
        if request.get_method() == "GET":
            return {
                "data": {"items": [{
                    "title": "Fresh factual test", "summary": "Synthetic test only",
                    "published_at": datetime.now(UTC).isoformat(), "source": "TEST",
                    "sentiment_score": 0.0, "impact_score": 0.0,
                }]},
                "meta": {"stale": False, "fallback_applied": False, "effective_freshness": "live"},
            }
        advisory = {
            "recommendation": "BUY", "confidence": 0.9, "news_sentiment": 0.0,
            "news_sentiment_label": "NEUTRAL", "risk_flags": [], "rationale": ["Synthetic test."],
        }
        return {"id": "response-test", "output": [{"type": "message", "content": [
            {"type": "output_text", "text": json.dumps(advisory)}
        ]}]}

    def test_api_key_does_not_enable_advisor_without_explicit_opt_in(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}, clear=True), patch(
            "openai_decision_advisor.LOCAL_ENV_FILE", Path("missing-test-env")
        ):
            self.assertFalse(AdvisorSettings.from_environment().enabled)

    def test_disabled_advisor_is_a_noop_for_paper_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            advisor = OpenAIDecisionAdvisor(settings=self.settings(directory, enabled=False))
            result = apply_openai_advisory([ready_decision()], advisor)[0]
            self.assertEqual("READY_TO_TRADE", result["status"])
            self.assertEqual("SKIPPED_DISABLED", result["openai_advisory"]["status"])
            self.assertEqual("PAPER_ONLY", result["execution_scope"])

    def test_legacy_live_path_requires_enabled_advisor(self):
        with tempfile.TemporaryDirectory() as directory:
            advisor = OpenAIDecisionAdvisor(settings=self.settings(directory, enabled=False))
            result = apply_openai_advisory([ready_decision()], advisor, require_enabled=True)[0]
            self.assertEqual("WAIT", result["status"])
            self.assertEqual("VETOED_ERROR", result["openai_advisory"]["status"])

    def test_ai_can_confirm_without_mutating_risk_parameters(self):
        decision = ready_decision()
        original = dict(decision)
        result = apply_openai_advisory(
            [decision], StubAdvisor({"status": "APPROVED", "recommendation": "BUY", "confidence": 0.9})
        )[0]
        self.assertEqual(result["status"], "READY_TO_TRADE")
        for field in ("lot_size", "entry_price", "stop_loss", "take_profit"):
            self.assertEqual(result[field], original[field])
        self.assertEqual(result["execution_scope"], "PAPER_ONLY")

    def test_ai_veto_is_fail_closed_wait(self):
        result = apply_openai_advisory(
            [ready_decision()], StubAdvisor({"status": "VETOED", "recommendation": "SELL", "confidence": 0.9})
        )[0]
        self.assertEqual(result["status"], "WAIT")
        self.assertEqual(result["action"], "WAIT")
        self.assertEqual(result["original_action"], "BUY")

    def test_reasoning_effort_scales_to_xhigh_for_complex_context(self):
        with tempfile.TemporaryDirectory() as directory:
            advisor = OpenAIDecisionAdvisor(settings=AdvisorSettings(
                api_key="test", enabled=True, model="gpt-5.4-mini", minimum_confidence=0.7,
                require_news=True, news_api_base_url="http://localhost", timeout_seconds=1,
                audit_file=Path(directory) / "audit.jsonl",
            ))
            news = [{"deterministic_sentiment": -0.8}, {"deterministic_sentiment": 0.8}, {}, {}, {}, {}, {}, {}]
            decision = ready_decision()
            decision["market_status"] = "EXTREME"
            self.assertEqual(advisor._reasoning_effort(decision, news), "xhigh")

    def test_fresh_live_news_and_strict_output_can_approve(self):
        with tempfile.TemporaryDirectory() as directory:
            advisor = OpenAIDecisionAdvisor(
                settings=self.settings(directory), transport=self.successful_transport
            )
            result = advisor.advise(ready_decision())
            self.assertEqual("APPROVED", result["status"])
            self.assertEqual("WRITTEN", result["audit_status"])

    def test_optional_signed_receipt_issuer_is_bound_to_advisory_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            captured = []
            advisor = OpenAIDecisionAdvisor(
                settings=self.settings(directory),
                transport=self.successful_transport,
                receipt_issuer=lambda evidence: captured.append(evidence) or {
                    "schema_version": "synthetic-signed-receipt"
                },
            )
            result = advisor.advise(ready_decision())
            self.assertEqual("WRITTEN", result["advisory_receipt_status"])
            self.assertEqual("PAPER_ONLY", captured[0]["execution_scope"])
            self.assertEqual("BUY", captured[0]["deterministic_action"])

    def test_receipt_issuer_failure_vetoes_advisory(self):
        with tempfile.TemporaryDirectory() as directory:
            def fail(_):
                raise OSError("synthetic signer failure")

            advisor = OpenAIDecisionAdvisor(
                settings=self.settings(directory),
                transport=self.successful_transport,
                receipt_issuer=fail,
            )
            result = advisor.advise(ready_decision())
            self.assertEqual("VETOED_ERROR", result["status"])
            self.assertEqual("FAILED", result["advisory_receipt_status"])
            self.assertEqual(["ADVISORY_RECEIPT_WRITE_FAILED"], result["risk_flags"])

    def test_stale_missing_or_naive_news_fails_closed(self):
        for published_at in (
            (datetime.now(UTC) - timedelta(hours=2)).isoformat(), None, datetime.now().isoformat()
        ):
            with self.subTest(published_at=published_at), tempfile.TemporaryDirectory() as directory:
                def transport(request, timeout):
                    if request.get_method() == "GET":
                        return {
                            "data": {"items": [{"title": "test", "published_at": published_at}]},
                            "meta": {"stale": False, "fallback_applied": False, "effective_freshness": "live"},
                        }
                    return self.successful_transport(request, timeout)
                result = OpenAIDecisionAdvisor(
                    settings=self.settings(directory), transport=transport
                ).advise(ready_decision())
                self.assertEqual("VETOED_ERROR", result["status"])

    def test_malformed_structured_output_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            def transport(request, timeout):
                if request.get_method() == "GET":
                    return self.successful_transport(request, timeout)
                malformed = {
                    "recommendation": "BUY", "confidence": 0.9, "news_sentiment": 0.0,
                    "news_sentiment_label": "NEUTRAL", "risk_flags": "", "rationale": ["test"],
                }
                return {"output": [{"type": "message", "content": [
                    {"type": "output_text", "text": json.dumps(malformed)}
                ]}]}
            result = OpenAIDecisionAdvisor(
                settings=self.settings(directory), transport=transport
            ).advise(ready_decision())
            self.assertEqual("VETOED_ERROR", result["status"])
            self.assertIn("OPENAI_TEXT_FIELD_INVALID", result["risk_flags"])

    def test_audit_failure_vetoes_without_crashing(self):
        with tempfile.TemporaryDirectory() as directory:
            advisor = OpenAIDecisionAdvisor(
                settings=self.settings(directory, audit_file=Path(directory)),
                transport=self.successful_transport,
            )
            result = advisor.advise(ready_decision())
            self.assertEqual("VETOED_ERROR", result["status"])
            self.assertEqual("FAILED", result["audit_status"])
            self.assertEqual(["AUDIT_WRITE_FAILED"], result["risk_flags"])

    def test_cycle_budget_vetoes_excess_ready_decisions(self):
        advisor = StubAdvisor({"status": "APPROVED", "recommendation": "BUY", "confidence": 0.9})
        advisor.settings = SimpleNamespace(enabled=True, max_advisories_per_cycle=1, cycle_timeout_seconds=60)
        result = apply_openai_advisory([ready_decision(), ready_decision()], advisor)
        self.assertEqual("READY_TO_TRADE", result[0]["status"])
        self.assertEqual("WAIT", result[1]["status"])
        self.assertIn("ADVISORY_CYCLE_BUDGET_EXHAUSTED", result[1]["openai_advisory"]["risk_flags"])

    def test_operational_openai_failure_can_fallback_only_to_unchanged_paper_decision(self):
        with tempfile.TemporaryDirectory() as directory:
            def transport(request, timeout):
                if request.get_method() == "GET":
                    return self.successful_transport(request, timeout)
                raise HTTPError(request.full_url, 429, "rate limited", {}, None)

            decision = ready_decision()
            decision["economic_calendar_guard"] = {
                "status": "PASS",
                "stale": False,
                "source_available": True,
            }
            original = dict(decision)
            advisor = OpenAIDecisionAdvisor(
                settings=self.settings(directory), transport=transport
            )
            result = apply_openai_advisory([decision], advisor)[0]
            self.assertEqual("READY_TO_TRADE", result["status"])
            self.assertEqual("BUY", result["action"])
            self.assertEqual(
                "FALLBACK_DETERMINISTIC",
                result["openai_advisory"]["advisory_mode"],
            )
            self.assertEqual("PAPER_ONLY", result["execution_scope"])
            for field in ("lot_size", "entry_price", "stop_loss", "take_profit"):
                self.assertEqual(original[field], result[field])

    def test_operational_failure_without_fresh_calendar_evidence_remains_wait(self):
        with tempfile.TemporaryDirectory() as directory:
            def transport(request, timeout):
                if request.get_method() == "GET":
                    return self.successful_transport(request, timeout)
                raise HTTPError(request.full_url, 503, "unavailable", {}, None)

            result = apply_openai_advisory(
                [ready_decision()],
                OpenAIDecisionAdvisor(
                    settings=self.settings(directory), transport=transport
                ),
            )[0]
            self.assertEqual("WAIT", result["status"])
            self.assertEqual("BLOCKED", result["openai_advisory"]["advisory_mode"])


if __name__ == "__main__":
    unittest.main()
