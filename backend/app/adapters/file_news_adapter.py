from __future__ import annotations


class FileNewsAdapter:
    def normalize(self, raw: dict, *, known_symbols: list[str]) -> dict:
        del known_symbols
        return dict(raw)


class FileEconomicCalendarAdapter:
    def normalize(self, raw: dict, *, known_symbols: list[str]) -> dict:
        del known_symbols
        return dict(raw)
