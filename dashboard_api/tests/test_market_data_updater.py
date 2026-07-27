from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from market_data_updater import (
    CollectorRunner,
    MarketDataUpdater,
    SingleInstanceLock,
    UpdaterSettings,
)


def _settings(tmp_path: Path) -> UpdaterSettings:
    collector = tmp_path / "data_collector.py"
    collector.write_text(
        "import json, pathlib, sys\n"
        "pathlib.Path('collector-call.json').write_text(json.dumps(sys.argv[1:]))\n",
        encoding="utf-8",
    )
    return UpdaterSettings(
        root=tmp_path,
        python_executable=Path(sys.executable),
        collector_script=collector,
        lock_file=tmp_path / "updater.lock",
        fast_interval_seconds=15,
        full_interval_seconds=60,
        timeout_seconds=5,
        max_backoff_seconds=120,
        run_full_on_start=False,
    )


def test_collector_runner_only_invokes_fixed_safe_collector(tmp_path: Path) -> None:
    settings = _settings(tmp_path)

    result = asyncio.run(CollectorRunner(settings).run("fast"))

    assert result.successful is True
    call = json.loads((tmp_path / "collector-call.json").read_text(encoding="utf-8"))
    assert call == ["--mode", "fast", "--quiet"]


def test_collector_runner_rejects_unknown_mode(tmp_path: Path) -> None:
    settings = _settings(tmp_path)

    with pytest.raises(ValueError, match="tidak diizinkan"):
        asyncio.run(CollectorRunner(settings).run("live"))


def test_single_instance_lock_prevents_duplicate_process(tmp_path: Path) -> None:
    first = SingleInstanceLock(tmp_path / "updater.lock")
    second = SingleInstanceLock(tmp_path / "updater.lock")

    assert first.acquire() is True
    try:
        assert second.acquire() is False
    finally:
        first.release()


def test_failure_backoff_is_bounded_and_resets(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    updater = MarketDataUpdater(settings)

    assert updater._delay_after("fast", False) == 15
    assert updater._delay_after("fast", False) == 30
    assert updater._delay_after("fast", False) == 60
    assert updater._delay_after("fast", False) == 120
    assert updater._delay_after("fast", False) == 120
    assert updater._delay_after("fast", True) == 15


def test_settings_reject_unsafe_polling_rate(tmp_path: Path) -> None:
    settings = replace(_settings(tmp_path), fast_interval_seconds=1)

    with pytest.raises(ValueError, match="minimal 15 detik"):
        settings.validate()


def test_environment_keeps_virtualenv_python_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    venv_bin = tmp_path / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    python_link = venv_bin / "python"
    python_link.symlink_to(Path(sys.executable))
    (tmp_path / "data_collector.py").write_text("pass\n", encoding="utf-8")
    monkeypatch.setenv("AI_SCALPER_ROOT", str(tmp_path))
    monkeypatch.delenv("AI_SCALPER_COLLECTOR_PYTHON", raising=False)

    settings = UpdaterSettings.from_environment()

    assert settings.python_executable == python_link
    assert settings.python_executable.is_symlink()
