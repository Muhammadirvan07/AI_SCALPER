from __future__ import annotations

from datetime import timedelta
from pathlib import Path
import tempfile
import unittest

from live_runtime.ai_advisory_receipt import (
    ai_advisory_receipt_from_mapping,
    verify_ai_advisory_receipt,
)
from live_runtime.finex_ai_advisory_evidence import (
    FinexAIAdvisoryEvidenceError,
    FinexAIAdvisoryReceiptIssuer,
)
from test_finex_ai_news_receipt_persistence import (
    ACCOUNT, AI_KEY, NEWS_KEY, NOW, SERVER, _news,
)


STAGES = {
    symbol: f"{index + 10:064x}"
    for index, symbol in enumerate(("AUDUSD", "EURUSD", "USDJPY", "XAUUSD"))
}


def _evidence(**changes):
    values = {
        "symbol": "EURUSD",
        "model": "gpt-5.4-mini",
        "reasoning_effort": "high",
        "execution_scope": "DEMO_AUTO_VETO_ONLY",
        "decision_snapshot_sha256": "6" * 64,
        "news_payload_sha256": "7" * 64,
        "advisory_output_sha256": "8" * 64,
        "policy_sha256": "9" * 64,
        "deterministic_action": "BUY",
        "recommendation": "BUY",
        "status": "APPROVED",
        "confidence": 0.9,
        "generated_at_utc": (NOW + timedelta(seconds=1)).isoformat(),
    }
    values.update(changes)
    return values


class FinexAIAdvisoryEvidenceTests(unittest.TestCase):
    def _issuer(self, directory):
        keys = {"finex-news-key-v1": NEWS_KEY, "finex-ai-advisory-v1": AI_KEY}
        return FinexAIAdvisoryReceiptIssuer(
            news_guard_receipt=_news(),
            expected_news_provider_id="finex-news-runtime-v1",
            expected_news_key_id="finex-news-key-v1",
            account_id_sha256=ACCOUNT,
            server=SERVER,
            news_config_sha256="5" * 64,
            stage_binding_sha256_by_symbol=STAGES,
            model="gpt-5.4-mini",
            policy_sha256="9" * 64,
            issuer_id="decision-runtime",
            key_id="finex-ai-advisory-v1",
            key_provider=keys.__getitem__,
            output_directory=directory,
            now_provider=lambda: NOW + timedelta(seconds=2),
        )

    def test_issuer_persists_exact_bound_demo_auto_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            mapping = self._issuer(directory)(_evidence())
            self.assertEqual(
                1, len(list(Path(directory).glob("finex_ai_advisory_*.json")))
            )
            receipt = ai_advisory_receipt_from_mapping(mapping)
            verified = verify_ai_advisory_receipt(
                receipt,
                expected_account_id_sha256=ACCOUNT,
                expected_server=SERVER,
                expected_environment="DEMO",
                expected_execution_scope="DEMO_AUTO_VETO_ONLY",
                expected_policy_sha256="9" * 64,
                expected_news_guard_receipt_sha256=_news().content_sha256,
                expected_stage_binding_sha256=STAGES["EURUSD"],
                key_provider=lambda _: AI_KEY,
                now=NOW + timedelta(seconds=2),
            )
            self.assertFalse(verified.safe_to_demo_auto_order)
            self.assertEqual("DISABLED", verified.order_capability)

    def test_fallback_error_and_wrong_policy_cannot_mint_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            issuer = self._issuer(directory)
            for evidence in (
                _evidence(status="FALLBACK_DETERMINISTIC"),
                _evidence(status="VETOED_ERROR"),
                _evidence(policy_sha256="f" * 64),
            ):
                with self.assertRaisesRegex(
                    FinexAIAdvisoryEvidenceError, "AI_RECEIPT_CONTEXT_INVALID"
                ):
                    issuer(evidence)
            self.assertEqual([], list(Path(directory).iterdir()))


if __name__ == "__main__":
    unittest.main()
