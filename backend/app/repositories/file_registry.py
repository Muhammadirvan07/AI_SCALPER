from __future__ import annotations

from pathlib import Path

from app.core.config import Settings
from app.core.constants import SOURCE_FILES
from app.core.security import validate_symbol


class FileRegistry:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.root = settings.ai_scalper_root.resolve()
        self.data = (settings.data_directory or self.root / "data").resolve()

    def json_path(self, key: str) -> Path | None:
        if key == "news_archive":
            return self.settings.news_archive_path
        if key == "economic_calendar":
            return self.settings.economic_calendar_path
        candidates = SOURCE_FILES.get(key)
        if candidates is None:
            return None
        for name in candidates:
            path = (self.root / name).resolve()
            if self._inside(path, self.root) and path.is_file():
                return path
        return (self.root / candidates[0]).resolve()

    def csv_path(self, symbol: str) -> Path:
        normalized = validate_symbol(symbol)
        path = (self.data / f"{normalized.lower()}.csv").resolve()
        if not self._inside(path, self.data):
            raise ValueError("Market path outside data directory")
        return path

    def symbols(self) -> list[str]:
        if not self.data.is_dir():
            return []
        return sorted({path.stem.upper() for path in self.data.glob("*.csv") if path.is_file()})

    def watched_paths(self) -> dict[str, Path]:
        paths = {key: path for key in SOURCE_FILES if (path := self.json_path(key)) is not None}
        for key in ("news_archive", "economic_calendar"):
            if not self.settings.file_news_watch_enabled:
                continue
            if path := self.json_path(key):
                paths[key] = path
        paths.update({f"market:{symbol}": self.csv_path(symbol) for symbol in self.symbols()})
        return paths

    @staticmethod
    def _inside(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False
