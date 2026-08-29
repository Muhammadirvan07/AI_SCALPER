"""Signed FINEX demo-auto veto-only evidence issuer for the OpenAI advisor."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
from typing import Callable, Mapping

from .ai_advisory_receipt import issue_ai_advisory_receipt
from .contracts import require_hash, require_text, require_utc
from .runtime_supervisor import RuntimeNewsGuardReceipt, verify_runtime_news_guard_receipt
from .secure_files import write_json_exclusive


REQUIRED_SYMBOLS = ("AUDUSD", "EURUSD", "USDJPY", "XAUUSD")
RECEIPT_TTL = timedelta(seconds=30)
_SAFE_COMPONENT = re.compile(r"^[A-Z0-9]{6,12}$")


class FinexAIAdvisoryEvidenceError(RuntimeError):
    pass


class FinexAIAdvisoryReceiptIssuer:
    """Verify context and persist one short-lived receipt per advisory result."""

    execution_scope = "DEMO_AUTO_VETO_ONLY"
    _FIELDS = {
        "symbol", "model", "reasoning_effort", "execution_scope",
        "decision_snapshot_sha256", "news_payload_sha256",
        "advisory_output_sha256", "policy_sha256", "deterministic_action",
        "recommendation", "status", "confidence", "generated_at_utc",
    }

    def __init__(
        self,
        *,
        news_guard_receipt: RuntimeNewsGuardReceipt,
        expected_news_provider_id: str,
        expected_news_key_id: str,
        account_id_sha256: str,
        server: str,
        news_config_sha256: str,
        stage_binding_sha256_by_symbol: Mapping[str, str],
        model: str,
        policy_sha256: str,
        issuer_id: str,
        key_id: str,
        key_provider: Callable[[str], str | bytes],
        output_directory: str | Path,
        now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if type(news_guard_receipt) is not RuntimeNewsGuardReceipt:
            raise TypeError("exact signed news guard receipt is required")
        if not callable(key_provider) or not callable(now_provider):
            raise TypeError("key and clock providers must be callable")
        stages = {
            str(symbol).upper(): require_hash("stage_binding_sha256", value)
            for symbol, value in stage_binding_sha256_by_symbol.items()
        }
        if tuple(stages) != REQUIRED_SYMBOLS:
            raise FinexAIAdvisoryEvidenceError("AI_STAGE_BINDING_SET_INVALID")
        directory = Path(output_directory)
        if directory.is_symlink() or not directory.is_dir():
            raise FinexAIAdvisoryEvidenceError("AI_RECEIPT_OUTPUT_DIRECTORY_UNSAFE")
        self.output_directory = directory.resolve(strict=True)
        self.news_guard_receipt = news_guard_receipt
        self.expected_news_provider_id = require_text(
            "expected_news_provider_id", expected_news_provider_id
        )
        self.expected_news_key_id = require_text(
            "expected_news_key_id", expected_news_key_id
        )
        self.account_id_sha256 = require_hash("account_id_sha256", account_id_sha256)
        self.server = require_text("server", server)
        self.news_config_sha256 = require_hash(
            "news_config_sha256", news_config_sha256
        )
        self.stage_bindings = stages
        self.model = require_text("model", model)
        self.policy_sha256 = require_hash("policy_sha256", policy_sha256)
        self.issuer_id = require_text("issuer_id", issuer_id)
        self.key_id = require_text("key_id", key_id)
        if self.key_id == self.expected_news_key_id:
            raise FinexAIAdvisoryEvidenceError("AI_AND_NEWS_KEY_CUSTODY_NOT_DISTINCT")
        self.key_provider = key_provider
        self.now_provider = now_provider
        self._verify_news_guard()

    def _now(self) -> datetime:
        try:
            return require_utc("AI receipt clock", self.now_provider())
        except Exception as exc:
            raise FinexAIAdvisoryEvidenceError("AI_RECEIPT_CLOCK_INVALID") from exc

    def _verify_news_guard(self) -> RuntimeNewsGuardReceipt:
        try:
            return verify_runtime_news_guard_receipt(
                self.news_guard_receipt,
                expected_provider_id=self.expected_news_provider_id,
                expected_key_id=self.expected_news_key_id,
                expected_account_id_sha256=self.account_id_sha256,
                expected_server=self.server,
                expected_environment="DEMO",
                expected_config_sha256=self.news_config_sha256,
                key_provider=self.key_provider,
                now=self._now(),
            )
        except Exception as exc:
            raise FinexAIAdvisoryEvidenceError(
                "SIGNED_NEWS_GUARD_INVALID_OR_STALE"
            ) from exc

    @staticmethod
    def _generated_at(value: object) -> datetime:
        if not isinstance(value, str):
            raise FinexAIAdvisoryEvidenceError("AI_GENERATED_AT_INVALID")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise FinexAIAdvisoryEvidenceError("AI_GENERATED_AT_INVALID") from exc
        if parsed.tzinfo is None:
            raise FinexAIAdvisoryEvidenceError("AI_GENERATED_AT_NAIVE")
        return parsed.astimezone(timezone.utc)

    def __call__(self, evidence: Mapping[str, object]) -> dict[str, object]:
        if not isinstance(evidence, Mapping) or set(evidence) != self._FIELDS:
            raise FinexAIAdvisoryEvidenceError("AI_RECEIPT_EVIDENCE_SHAPE_INVALID")
        news = self._verify_news_guard()
        symbol = str(evidence["symbol"]).upper()
        if symbol not in self.stage_bindings or _SAFE_COMPONENT.fullmatch(symbol) is None:
            raise FinexAIAdvisoryEvidenceError("AI_RECEIPT_SYMBOL_INVALID")
        if (
            evidence["model"] != self.model
            or evidence["policy_sha256"] != self.policy_sha256
            or evidence["execution_scope"] != self.execution_scope
            or evidence["status"] not in {"APPROVED", "VETOED"}
        ):
            raise FinexAIAdvisoryEvidenceError("AI_RECEIPT_CONTEXT_INVALID")
        generated_at = self._generated_at(evidence["generated_at_utc"])
        now = self._now()
        if generated_at > now + timedelta(seconds=2) or now - generated_at > RECEIPT_TTL:
            raise FinexAIAdvisoryEvidenceError("AI_RECEIPT_GENERATION_TIME_INVALID")
        valid_until = min(generated_at + RECEIPT_TTL, news.valid_until_utc)
        if valid_until <= now:
            raise FinexAIAdvisoryEvidenceError("AI_RECEIPT_ALREADY_EXPIRED")
        try:
            receipt = issue_ai_advisory_receipt(
                issuer_id=self.issuer_id,
                key_id=self.key_id,
                key=self.key_provider(self.key_id),
                account_id_sha256=self.account_id_sha256,
                server=self.server,
                environment="DEMO",
                symbol=symbol,
                model=self.model,
                reasoning_effort=str(evidence["reasoning_effort"]),
                execution_scope=self.execution_scope,
                decision_snapshot_sha256=str(evidence["decision_snapshot_sha256"]),
                news_payload_sha256=str(evidence["news_payload_sha256"]),
                advisory_output_sha256=str(evidence["advisory_output_sha256"]),
                policy_sha256=self.policy_sha256,
                deterministic_action=str(evidence["deterministic_action"]),
                recommendation=str(evidence["recommendation"]),
                status=str(evidence["status"]),
                confidence=evidence["confidence"],
                generated_at_utc=generated_at,
                valid_until_utc=valid_until,
                news_guard_receipt_sha256=news.content_sha256,
                stage_binding_sha256=self.stage_bindings[symbol],
            )
            stamp = generated_at.strftime("%Y%m%dT%H%M%S%fZ")
            filename = (
                f"finex_ai_advisory_{symbol}_{stamp}_"
                f"{receipt.content_sha256[:12]}.json"
            )
            write_json_exclusive(
                self.output_directory / filename, receipt.to_canonical_dict()
            )
            return receipt.to_canonical_dict()
        except FinexAIAdvisoryEvidenceError:
            raise
        except Exception as exc:
            raise FinexAIAdvisoryEvidenceError("AI_RECEIPT_ISSUANCE_FAILED") from exc


__all__ = ["FinexAIAdvisoryEvidenceError", "FinexAIAdvisoryReceiptIssuer"]
