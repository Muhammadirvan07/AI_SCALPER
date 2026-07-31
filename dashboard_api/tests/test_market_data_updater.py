from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from market_data_updater import (
    CollectorRunner,
    LockSecurityError,
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


def test_single_instance_lock_rejects_symbolic_link(tmp_path: Path) -> None:
    target = tmp_path / "target.lock"
    target.touch(mode=0o600)
    link = tmp_path / "updater.lock"
    link.symlink_to(target)

    with pytest.raises(LockSecurityError, match="aman|link"):
        SingleInstanceLock(link).acquire()


def test_single_instance_lock_rejects_unsafe_file_permission(tmp_path: Path) -> None:
    lock_path = tmp_path / "updater.lock"
    lock_path.touch(mode=0o600)
    lock_path.chmod(0o644)

    with pytest.raises(LockSecurityError, match="0600"):
        SingleInstanceLock(lock_path).acquire()


def test_single_instance_lock_rejects_unsafe_runtime_directory(tmp_path: Path) -> None:
    runtime = tmp_path / "shared"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o755)

    with pytest.raises(LockSecurityError, match="0700"):
        SingleInstanceLock(runtime / "updater.lock").acquire()


def test_single_instance_lock_rejects_owner_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    actual_uid = os.getuid()
    observed = iter((actual_uid, actual_uid + 1))
    monkeypatch.setattr("market_data_updater._current_uid", lambda: next(observed))

    with pytest.raises(LockSecurityError, match="current user"):
        SingleInstanceLock(tmp_path / "updater.lock").acquire()


def test_single_instance_lock_fallback_still_rejects_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target.lock"
    target.touch(mode=0o600)
    link = tmp_path / "updater.lock"
    link.symlink_to(target)
    monkeypatch.setattr("market_data_updater._O_NOFOLLOW", 0)

    with pytest.raises(LockSecurityError, match="Symbolic link"):
        SingleInstanceLock(link).acquire()


def test_single_instance_lock_fails_closed_without_platform_locking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("market_data_updater.fcntl", None)

    with pytest.raises(RuntimeError, match="belum mendukung"):
        SingleInstanceLock(tmp_path / "updater.lock").acquire()

    assert not (tmp_path / "updater.lock").exists()


def test_single_instance_lock_closes_descriptor_after_flock_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    closed: list[int] = []
    real_close = os.close

    def record_close(descriptor: int) -> None:
        closed.append(descriptor)
        real_close(descriptor)

    def fail_flock(_descriptor: int, _operation: int) -> None:
        raise OSError("simulated flock failure")

    monkeypatch.setattr("market_data_updater.os.close", record_close)
    monkeypatch.setattr("market_data_updater.fcntl.flock", fail_flock)
    lock = SingleInstanceLock(tmp_path / "updater.lock")

    with pytest.raises(OSError, match="simulated"):
        lock.acquire()

    assert lock._handle is None
    assert len(closed) == 1


def test_single_instance_lock_release_closes_handle_and_allows_reacquire(tmp_path: Path) -> None:
    path = tmp_path / "updater.lock"
    first = SingleInstanceLock(path)
    assert first.acquire() is True
    handle = first._handle
    assert handle is not None
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

    first.release()

    assert handle.closed is True
    assert first._handle is None
    second = SingleInstanceLock(path)
    assert second.acquire() is True
    second.release()


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
    assert settings.lock_file != Path("/tmp/ai_scalper_market_data_updater.lock")


def test_environment_uses_private_xdg_runtime_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    venv_bin = root / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").symlink_to(Path(sys.executable))
    (root / "data_collector.py").write_text("pass\n", encoding="utf-8")
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    monkeypatch.setenv("AI_SCALPER_ROOT", str(root))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    monkeypatch.delenv("AI_SCALPER_MARKET_UPDATER_LOCK_FILE", raising=False)

    settings = UpdaterSettings.from_environment()

    assert settings.lock_file == runtime / "ai_scalper" / "market-data-updater.lock"
