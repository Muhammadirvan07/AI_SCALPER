from __future__ import annotations

import logging

from app.core.config import Settings
from app.schemas.news import SentimentResult

logger = logging.getLogger(__name__)


class FinBERTSentimentAdapter:
    """Optional lazy FinBERT adapter; importing transformers is never required at startup."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.available = False
        self._pipeline = None
        self.last_error: str | None = None

    def load(self) -> bool:
        if not self.settings.news_finbert_enabled:
            return False
        if self._pipeline is not None:
            return True
        try:
            from transformers import pipeline  # type: ignore[import-not-found]

            device = -1 if self.settings.news_finbert_device in {"auto", "cpu"} else 0
            self._pipeline = pipeline("text-classification", model=self.settings.news_finbert_model, device=device)
            self.available = True
            return True
        except (ImportError, OSError, RuntimeError) as exc:
            self.last_error = f"FinBERT unavailable: {type(exc).__name__}"
            logger.warning(
                "FinBERT unavailable; using deterministic baseline",
                extra={"event": "news.finbert_fallback", "error_type": type(exc).__name__},
            )
            return False

    def analyze(self, text: str) -> SentimentResult | None:
        if not self.load() or self._pipeline is None:
            return None
        result = self._pipeline(text[:2000], truncation=True)[0]
        label = str(result.get("label", "neutral")).lower()
        confidence = float(result.get("score", 0))
        signed = confidence if label == "positive" else -confidence if label == "negative" else 0.0
        from app.services.sentiment_service import label_for_score

        return SentimentResult(
            label=label_for_score(signed),
            score=signed,
            confidence=confidence,
            analyzer="finbert",
            positive_probability=confidence if label == "positive" else 0.0,
            neutral_probability=confidence if label == "neutral" else 0.0,
            negative_probability=confidence if label == "negative" else 0.0,
        )
