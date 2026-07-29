from __future__ import annotations

import re

from app.adapters.sentiment_adapter import FinBERTSentimentAdapter
from app.core.config import Settings
from app.schemas.news import ProviderSentiment, SentimentLabel, SentimentResult

POSITIVE = {
    "beat": 1.0,
    "beats": 1.0,
    "growth": 0.6,
    "gain": 0.7,
    "gains": 0.7,
    "rally": 0.9,
    "surge": 1.0,
    "strong": 0.6,
    "upgrade": 0.8,
    "optimistic": 0.8,
    "recovery": 0.7,
    "bullish": 1.0,
    "outperform": 0.9,
    "record high": 1.0,
    "rate cut": 0.35,
    "cooling inflation": 0.7,
}
NEGATIVE = {
    "miss": -1.0,
    "misses": -1.0,
    "decline": -0.7,
    "drop": -0.7,
    "falls": -0.7,
    "plunge": -1.0,
    "weak": -0.6,
    "downgrade": -0.8,
    "recession": -1.0,
    "default": -1.0,
    "crisis": -1.0,
    "bearish": -1.0,
    "selloff": -1.0,
    "war": -0.9,
    "sanction": -0.7,
    "rate hike": -0.35,
    "hot inflation": -0.7,
    "unemployment rises": -0.8,
}
NEGATIONS = {"not", "no", "never", "without", "hardly", "isn't", "wasn't", "won't", "doesn't"}
INTENSIFIERS = {"very": 1.35, "sharply": 1.4, "significantly": 1.3, "slightly": 0.65, "marginally": 0.7}
TOKEN_RE = re.compile(r"[a-z]+(?:'[a-z]+)?")


def label_for_score(score: float) -> SentimentLabel:
    if score <= -0.60:
        return SentimentLabel.VERY_BEARISH
    if score <= -0.20:
        return SentimentLabel.BEARISH
    if score < 0.20:
        return SentimentLabel.NEUTRAL
    if score < 0.60:
        return SentimentLabel.BULLISH
    return SentimentLabel.VERY_BULLISH


class BaselineSentimentAnalyzer:
    name = "baseline"

    @staticmethod
    def _score_text(text: str) -> tuple[float, list[str]]:
        lower = text.lower()
        tokens = TOKEN_RE.findall(lower)
        score = 0.0
        matches: list[str] = []
        lexicon = {**POSITIVE, **NEGATIVE}
        for term, weight in lexicon.items():
            positions = [index for index in range(len(tokens)) if tokens[index] == term]
            if " " in term:
                phrase_tokens = term.split()
                positions = [
                    index
                    for index in range(len(tokens) - len(phrase_tokens) + 1)
                    if tokens[index : index + len(phrase_tokens)] == phrase_tokens
                ]
            for index in positions:
                local = weight
                preceding = tokens[max(0, index - 3) : index]
                if any(token in NEGATIONS for token in preceding):
                    local *= -0.8
                for token in preceding[-2:]:
                    local *= INTENSIFIERS.get(token, 1.0)
                score += local
                matches.append(term)
        return score, sorted(set(matches))

    def analyze(self, title: str, summary: str | None) -> SentimentResult:
        headline_score, headline_terms = self._score_text(title)
        summary_score, summary_terms = self._score_text(summary or "")
        raw = headline_score * 0.7 + summary_score * 0.3
        matched = sorted({*headline_terms, *summary_terms})
        score = max(-1.0, min(1.0, raw / max(1.0, len(matched) * 0.8))) if matched else 0.0
        confidence = min(0.95, 0.25 + len(matched) * 0.12) if matched else 0.2
        positive = max(0.0, score)
        negative = max(0.0, -score)
        neutral = max(0.0, 1.0 - abs(score))
        total = positive + negative + neutral or 1.0
        return SentimentResult(
            label=label_for_score(score),
            score=round(score, 4),
            confidence=round(confidence, 4),
            analyzer=self.name,
            positive_probability=round(positive / total, 4),
            neutral_probability=round(neutral / total, 4),
            negative_probability=round(negative / total, 4),
            matched_terms=matched,
        )


class SentimentService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.baseline = BaselineSentimentAnalyzer()
        self.finbert = FinBERTSentimentAdapter(settings)

    @property
    def analyzer_name(self) -> str:
        return "finbert" if self.finbert.available else "baseline"

    def analyze(
        self, title: str, summary: str | None, provider_sentiment: ProviderSentiment | None = None
    ) -> SentimentResult:
        if not self.settings.news_sentiment_enabled:
            return SentimentResult(label=SentimentLabel.UNKNOWN, analyzer="disabled")
        baseline = self.baseline.analyze(title, summary)
        if self.settings.news_finbert_enabled:
            finbert = self.finbert.analyze(f"{title}. {summary or ''}")
            if finbert is not None and finbert.score is not None:
                evidence = provider_sentiment.normalized_score if provider_sentiment else None
                provider_confidence = (
                    provider_sentiment.normalized_confidence if provider_sentiment is not None else None
                )
                weights = (0.65, 0.35, 0.0) if evidence is None else (0.60, 0.25, 0.15)
                score = finbert.score * weights[0] + (baseline.score or 0.0) * weights[1]
                if evidence is not None:
                    score += evidence * weights[2]
                confidence_inputs = [
                    (finbert.confidence or 0.0, weights[0]),
                    (baseline.confidence or 0.0, weights[1]),
                ]
                if evidence is not None:
                    confidence_inputs.append((provider_confidence or 0.5, weights[2]))
                confidence = sum(value * weight for value, weight in confidence_inputs)
                score = max(-1.0, min(1.0, score))
                positive = max(0.0, score)
                negative = max(0.0, -score)
                neutral = max(0.0, 1.0 - abs(score))
                total = positive + negative + neutral or 1.0
                return SentimentResult(
                    label=label_for_score(score),
                    score=round(score, 4),
                    confidence=round(min(1.0, confidence), 4),
                    analyzer="ensemble",
                    positive_probability=round(positive / total, 4),
                    neutral_probability=round(neutral / total, 4),
                    negative_probability=round(negative / total, 4),
                    matched_terms=baseline.matched_terms,
                )
        return baseline
