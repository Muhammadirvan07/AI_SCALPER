from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

from dashboard_api.app.safe_json_reader import SafeJsonReader


def reader(stale_after: float = 180) -> SafeJsonReader:
    return SafeJsonReader(
        stale_after_seconds=stale_after,
        max_bytes=1024,
        retries=2,
        retry_delay_seconds=0,
    )


def test_reads_valid_json(tmp_path: Path) -> None:
    path = tmp_path / "valid.json"
    path.write_text(json.dumps({"live_allowed": False}), encoding="utf-8")
    result = asyncio.run(reader().read("valid", path))
    assert result.value == {"live_allowed": False}
    assert result.meta.status == "fresh"
    assert result.meta.from_last_known_good is False


def test_missing_file_is_unavailable(tmp_path: Path) -> None:
    result = asyncio.run(reader().read("missing", tmp_path / "missing.json"))
    assert result.value is None
    assert result.meta.status == "unavailable"


def test_temporary_invalid_json_uses_last_known_good(tmp_path: Path) -> None:
    path = tmp_path / "changing.json"
    path.write_text('{"value": 1}', encoding="utf-8")
    safe_reader = reader()
    first = asyncio.run(safe_reader.read("changing", path))
    path.write_text('{"value":', encoding="utf-8")
    second = asyncio.run(safe_reader.read("changing", path))
    assert first.value == {"value": 1}
    assert second.value == {"value": 1}
    assert second.meta.status == "partial"
    assert second.meta.from_last_known_good is True


def test_stale_calculation_uses_file_mtime(tmp_path: Path) -> None:
    path = tmp_path / "old.json"
    path.write_text('{"value": 1}', encoding="utf-8")
    old = time.time() - 20
    os.utime(path, (old, old))
    result = asyncio.run(reader(stale_after=10).read("old", path))
    assert result.meta.status == "stale"
    assert result.meta.stale is True
    assert result.meta.age_seconds is not None
    assert result.meta.age_seconds >= 19
