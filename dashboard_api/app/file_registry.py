from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

from .config import SOURCE_FILE_NAMES, Settings

logger = logging.getLogger(__name__)

EXCLUDED_PARTS = {
    ".git",
    ".venv",
    ".venv-dashboard",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "dashboard_api",
}


@dataclass(frozen=True, slots=True)
class RegisteredSource:
    key: str
    path: Path | None
    kind: str


class FileRegistry:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.sources: dict[str, RegisteredSource] = {}
        self.csv_sources: dict[str, RegisteredSource] = {}

    @staticmethod
    def _allowed(path: Path) -> bool:
        return not any(part in EXCLUDED_PARTS for part in path.parts)

    def _build_name_index(self) -> dict[str, list[Path]]:
        wanted = {
            name
            for names in SOURCE_FILE_NAMES.values()
            for name in names
        }
        index: dict[str, list[Path]] = {name: [] for name in wanted}
        for directory, child_directories, filenames in os.walk(self.settings.root):
            child_directories[:] = [
                name for name in child_directories if name not in EXCLUDED_PARTS
            ]
            base = Path(directory)
            for filename in filenames:
                if filename in index:
                    index[filename].append(base / filename)
        return index

    def _find_named_file(
        self,
        names: tuple[str, ...],
        index: dict[str, list[Path]],
    ) -> Path | None:
        candidates: list[Path] = []
        for name in names:
            direct = self.settings.root / name
            if direct.is_file():
                candidates.append(direct)
            candidates.extend(
                path
                for path in index.get(name, [])
                if path.is_file() and self._allowed(path.relative_to(self.settings.root))
            )
        if not candidates:
            return None
        return min(
            set(candidates),
            key=lambda path: (len(path.relative_to(self.settings.root).parts), str(path)),
        )

    def refresh(self) -> bool:
        previous = {
            key: source.path
            for key, source in {**self.sources, **self.csv_sources}.items()
        }
        discovered: dict[str, RegisteredSource] = {}
        name_index = self._build_name_index()
        for key, names in SOURCE_FILE_NAMES.items():
            path = self._find_named_file(names, name_index)
            discovered[key] = RegisteredSource(key=key, path=path, kind="json")
            if path and previous.get(key) != path:
                logger.info("Sumber ditemukan: %s -> %s", key, path)

        csv_sources: dict[str, RegisteredSource] = {}
        if self.settings.data_dir.is_dir():
            for path in sorted(self.settings.data_dir.glob("*.csv")):
                symbol = path.stem.upper()
                key = f"market:{symbol}"
                csv_sources[key] = RegisteredSource(key=key, path=path, kind="csv")
                if previous.get(key) != path:
                    logger.info("Sumber pasar ditemukan: %s -> %s", key, path)

        self.sources = discovered
        self.csv_sources = csv_sources
        current = {
            key: source.path
            for key, source in {**self.sources, **self.csv_sources}.items()
        }
        return current != previous

    def all_sources(self) -> dict[str, RegisteredSource]:
        return {**self.sources, **self.csv_sources}

    def json_sources(self) -> dict[str, RegisteredSource]:
        return dict(self.sources)

    def market_sources(self) -> dict[str, RegisteredSource]:
        return dict(self.csv_sources)
