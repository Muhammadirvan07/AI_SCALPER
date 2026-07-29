from __future__ import annotations

import hashlib
import re
from datetime import datetime
from difflib import SequenceMatcher

from app.schemas.news import NewsArticle

_NON_WORD = re.compile(r"[^a-z0-9 ]+")
_SPACE = re.compile(r"\s+")


def normalized_title(title: str) -> str:
    return _SPACE.sub(" ", _NON_WORD.sub(" ", title.lower())).strip()


class NewsDeduplicator:
    @staticmethod
    def _close_in_time(left: datetime | None, right: datetime | None) -> bool:
        if left is None or right is None:
            return True
        return abs((left - right).total_seconds()) <= 6 * 3600

    @staticmethod
    def _same_story(left: NewsArticle, right: NewsArticle) -> bool:
        left_title = normalized_title(left.title)
        right_title = normalized_title(right.title)
        same_url = str(left.url).rstrip("/") == str(right.url).rstrip("/")
        same_provider_id = bool(
            left.raw_provider_id
            and right.raw_provider_id
            and left.provider == right.provider
            and left.raw_provider_id == right.raw_provider_id
        )
        same_title = left_title == right_title
        similar_story = (
            len(left_title) >= 24
            and SequenceMatcher(None, left_title, right_title).ratio() >= 0.92
            and NewsDeduplicator._close_in_time(left.published_at, right.published_at)
        )
        return same_url or same_provider_id or same_title or similar_story

    @staticmethod
    def _canonical_quality(article: NewsArticle) -> tuple[int, int, int, int, float]:
        published = article.published_at or article.fetched_at
        return (
            int(str(article.url).startswith("https://")),
            int(article.published_at is not None),
            int(article.category.value != "GENERAL"),
            len(article.summary or ""),
            published.timestamp(),
        )

    def mark(self, articles: list[NewsArticle]) -> list[NewsArticle]:
        ordered = sorted(articles, key=lambda item: item.published_at or item.fetched_at, reverse=True)
        groups: list[list[NewsArticle]] = []
        for article in ordered:
            group = next((items for items in groups if any(self._same_story(article, item) for item in items)), None)
            if group is None:
                groups.append([article])
            else:
                group.append(article)

        output: list[NewsArticle] = []
        for items in groups:
            canonical = max(items, key=self._canonical_quality)
            if len(items) == 1:
                output.append(canonical)
                continue
            seed = normalized_title(canonical.title) or str(canonical.url)
            group_id = hashlib.sha256(seed.encode()).hexdigest()[:20]
            output.append(
                canonical.model_copy(
                    update={"is_duplicate": False, "duplicate_group_id": group_id, "canonical_article_id": None}
                )
            )
            output.extend(
                item.model_copy(
                    update={
                        "is_duplicate": True,
                        "duplicate_group_id": group_id,
                        "canonical_article_id": canonical.id,
                    }
                )
                for item in items
                if item is not canonical
            )
        return sorted(output, key=lambda item: item.published_at or item.fetched_at, reverse=True)
