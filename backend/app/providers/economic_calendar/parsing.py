from __future__ import annotations

import html
import re
from html.parser import HTMLParser


def normalize_space(value: str) -> str:
    return " ".join(value.split()).strip()


def normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


class PlainTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript"}:
            self._ignored_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth and (text := normalize_space(data)):
            self.parts.append(text)

    def text(self) -> str:
        return "\n".join(self.parts)


def html_to_text(value: str) -> str:
    parser = PlainTextParser()
    parser.feed(value)
    return html.unescape(parser.text())


def slug(value: str, *, maximum: int = 72) -> str:
    candidate = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return candidate[:maximum].rstrip("-") or "event"


def token_similarity(left: str, right: str) -> float:
    left_tokens = set(normalized_key(left).split())
    right_tokens = set(normalized_key(right).split())
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)
