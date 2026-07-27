"""Scheduler aman untuk memperbarui data pasar dashboard AI_SCALPER.

Proses ini sengaja berdiri terpisah dari dashboard API read-only dan engine
trading. Satu-satunya program anak yang dapat dijalankan adalah data_collector.py
dalam mode FAST atau FULL.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final

try:
    import fcntl
except ImportError:  # pragma: no cover - target operasional saat ini adalah macOS.
    fcntl = None


LOGGER = logging.getLogger("ai_scalper.market_data_updater")

DEFAULT_FAST_INTERVAL_SECONDS: Final[float] = 60.0
DEFAULT_FULL_INTERVAL_SECONDS: Final[float] = 900.0
DEFAULT_TIMEOUT_SECONDS: Final[float] = 240.0
DEFAULT_MAX_BACKOFF_SECONDS: Final[float] = 300.0
MIN_FAST_INTERVAL_SECONDS: Final[float] = 15.0
MIN_FULL_INTERVAL_SECONDS: Final[float] = 60.0


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as error:
        raise ValueError(f"{name} harus berupa angka, menerima {raw!r}") from error


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} harus true/false, menerima {raw!r}")


def _absolute_path_without_resolving_symlinks(path: Path, base: Path) -> Path:
    """Buat path absolut tanpa melepas konteks virtualenv dari symlink python."""

    expanded = path.expanduser()
    if expanded.is_absolute():
        return expanded
    return base / expanded


@dataclass(frozen=True)
class UpdaterSettings:
    root: Path
    python_executable: Path
    collector_script: Path
    lock_file: Path
    fast_interval_seconds: float = DEFAULT_FAST_INTERVAL_SECONDS
    full_interval_seconds: float = DEFAULT_FULL_INTERVAL_SECONDS
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_backoff_seconds: float = DEFAULT_MAX_BACKOFF_SECONDS
    run_full_on_start: bool = True

    @classmethod
    def from_environment(cls) -> "UpdaterSettings":
        default_root = Path(__file__).resolve().parent
        root = Path(os.getenv("AI_SCALPER_ROOT", str(default_root))).expanduser().resolve()
        default_python = root / ".venv" / "bin" / "python"
        python_executable = _absolute_path_without_resolving_symlinks(
            Path(os.getenv("AI_SCALPER_COLLECTOR_PYTHON", str(default_python))),
            root,
        )
        lock_file = Path(
            os.getenv(
                "AI_SCALPER_MARKET_UPDATER_LOCK_FILE",
                "/tmp/ai_scalper_market_data_updater.lock",
            )
        ).expanduser()
        settings = cls(
            root=root,
            python_executable=python_executable,
            collector_script=root / "data_collector.py",
            lock_file=lock_file,
            fast_interval_seconds=_env_float(
                "AI_SCALPER_MARKET_FAST_INTERVAL_SECONDS",
                DEFAULT_FAST_INTERVAL_SECONDS,
            ),
            full_interval_seconds=_env_float(
                "AI_SCALPER_MARKET_FULL_INTERVAL_SECONDS",
                DEFAULT_FULL_INTERVAL_SECONDS,
            ),
            timeout_seconds=_env_float(
                "AI_SCALPER_MARKET_COLLECTOR_TIMEOUT_SECONDS",
                DEFAULT_TIMEOUT_SECONDS,
            ),
            max_backoff_seconds=_env_float(
                "AI_SCALPER_MARKET_FAILURE_BACKOFF_MAX_SECONDS",
                DEFAULT_MAX_BACKOFF_SECONDS,
            ),
            run_full_on_start=_env_bool(
                "AI_SCALPER_MARKET_FULL_ON_START",
                True,
            ),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if not self.root.is_dir():
            raise ValueError(f"AI_SCALPER_ROOT tidak valid: {self.root}")
        if not self.python_executable.is_file():
            raise ValueError(
                "Python collector tidak ditemukan: "
                f"{self.python_executable}. Siapkan .venv atau atur "
                "AI_SCALPER_COLLECTOR_PYTHON."
            )
        if not self.collector_script.is_file():
            raise ValueError(f"Collector tidak ditemukan: {self.collector_script}")
        if self.fast_interval_seconds < MIN_FAST_INTERVAL_SECONDS:
            raise ValueError(
                "AI_SCALPER_MARKET_FAST_INTERVAL_SECONDS minimal "
                f"{MIN_FAST_INTERVAL_SECONDS:.0f} detik"
            )
        if self.full_interval_seconds < MIN_FULL_INTERVAL_SECONDS:
            raise ValueError(
                "AI_SCALPER_MARKET_FULL_INTERVAL_SECONDS minimal "
                f"{MIN_FULL_INTERVAL_SECONDS:.0f} detik"
            )
        if self.timeout_seconds <= 0:
            raise ValueError("Timeout collector harus lebih besar dari 0")
        if self.max_backoff_seconds < self.fast_interval_seconds:
            raise ValueError(
                "Backoff maksimum tidak boleh lebih kecil dari interval FAST"
            )


@dataclass(frozen=True)
class CollectionResult:
    mode: str
    return_code: int
    duration_seconds: float
    output: str

    @property
    def successful(self) -> bool:
        return self.return_code == 0


class SingleInstanceLock:
    """Advisory lock yang otomatis dilepas OS saat proses berhenti."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle: object | None = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+", encoding="utf-8")
        if fcntl is None:
            handle.close()
            raise RuntimeError("Platform ini belum mendukung advisory lock updater")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            handle.close()
            return False
        handle.seek(0)
        handle.truncate()
        handle.write(f"{os.getpid()}\n")
        handle.flush()
        self._handle = handle
        return True

    def release(self) -> None:
        handle = self._handle
        if handle is None:
            return
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()
        self._handle = None

    def __enter__(self) -> "SingleInstanceLock":
        if not self.acquire():
            raise RuntimeError(
                "Updater data pasar lain sudah aktif; proses kedua dibatalkan."
            )
        return self

    def __exit__(self, *_args: object) -> None:
        self.release()


class CollectorRunner:
    """Menjalankan satu-satunya writer yang diizinkan: data_collector.py."""

    def __init__(self, settings: UpdaterSettings) -> None:
        self.settings = settings
        self._process: asyncio.subprocess.Process | None = None

    async def run(self, mode: str) -> CollectionResult:
        if mode not in {"fast", "full"}:
            raise ValueError(f"Mode collector tidak diizinkan: {mode}")

        started = time.monotonic()
        command = (
            str(self.settings.python_executable),
            str(self.settings.collector_script),
            "--mode",
            mode,
            "--quiet",
        )
        self._process = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(self.settings.root),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                self._process.communicate(),
                timeout=self.settings.timeout_seconds,
            )
            return_code = int(self._process.returncode or 0)
        except asyncio.TimeoutError:
            self._process.terminate()
            try:
                stdout, _ = await asyncio.wait_for(
                    self._process.communicate(), timeout=5
                )
            except asyncio.TimeoutError:
                self._process.kill()
                stdout, _ = await self._process.communicate()
            return_code = 124
        finally:
            self._process = None

        output = stdout.decode("utf-8", errors="replace").strip()
        return CollectionResult(
            mode=mode,
            return_code=return_code,
            duration_seconds=time.monotonic() - started,
            output=output,
        )

    async def stop(self) -> None:
        process = self._process
        if process is None or process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()


class MarketDataUpdater:
    def __init__(self, settings: UpdaterSettings, runner: CollectorRunner | None = None) -> None:
        self.settings = settings
        self.runner = runner or CollectorRunner(settings)
        self.stop_event = asyncio.Event()
        self._failure_streaks = {"fast": 0, "full": 0}

    def request_stop(self) -> None:
        self.stop_event.set()

    def _delay_after(self, mode: str, successful: bool) -> float:
        base = (
            self.settings.fast_interval_seconds
            if mode == "fast"
            else self.settings.full_interval_seconds
        )
        if successful:
            self._failure_streaks[mode] = 0
            return base
        self._failure_streaks[mode] += 1
        multiplier = 2 ** min(self._failure_streaks[mode] - 1, 8)
        return min(base * multiplier, self.settings.max_backoff_seconds)

    async def collect_once(self, mode: str) -> CollectionResult:
        LOGGER.info("Memulai refresh %s", mode.upper())
        result = await self.runner.run(mode)
        if result.successful:
            LOGGER.info(
                "Refresh %s selesai dalam %.2f detik",
                mode.upper(),
                result.duration_seconds,
            )
        else:
            output_tail = "\n".join(result.output.splitlines()[-12:])
            LOGGER.warning(
                "Refresh %s gagal (kode=%s, durasi=%.2fs). Output akhir:\n%s",
                mode.upper(),
                result.return_code,
                result.duration_seconds,
                output_tail or "(tidak ada output)",
            )
        return result

    async def run_forever(self) -> None:
        next_fast = time.monotonic()
        next_full = (
            time.monotonic()
            if self.settings.run_full_on_start
            else time.monotonic() + self.settings.full_interval_seconds
        )

        LOGGER.info(
            "Updater aktif: FAST %.0fs, FULL %.0fs, sumber M15 finalized",
            self.settings.fast_interval_seconds,
            self.settings.full_interval_seconds,
        )
        while not self.stop_event.is_set():
            now = time.monotonic()
            if now >= next_fast:
                result = await self.collect_once("fast")
                next_fast = time.monotonic() + self._delay_after(
                    "fast", result.successful
                )

            now = time.monotonic()
            if self.stop_event.is_set():
                break
            if now >= next_full:
                result = await self.collect_once("full")
                next_full = time.monotonic() + self._delay_after(
                    "full", result.successful
                )

            delay = max(0.05, min(next_fast, next_full) - time.monotonic())
            try:
                await asyncio.wait_for(self.stop_event.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass

        await self.runner.stop()
        LOGGER.info("Updater data pasar berhenti dengan bersih")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Auto-updater data pasar read-only input dashboard AI_SCALPER"
    )
    parser.add_argument(
        "--once",
        choices=["fast", "full"],
        help="Jalankan satu refresh lalu keluar",
    )
    parser.add_argument("--fast-interval", type=float)
    parser.add_argument("--full-interval", type=float)
    parser.add_argument("--timeout", type=float)
    parser.add_argument(
        "--no-full-on-start",
        action="store_true",
        help="Tunda refresh FULL sampai interval pertama",
    )
    return parser


async def _async_main(args: argparse.Namespace) -> int:
    settings = UpdaterSettings.from_environment()
    if args.fast_interval is not None:
        settings = replace(settings, fast_interval_seconds=args.fast_interval)
    if args.full_interval is not None:
        settings = replace(settings, full_interval_seconds=args.full_interval)
    if args.timeout is not None:
        settings = replace(settings, timeout_seconds=args.timeout)
    if args.no_full_on_start:
        settings = replace(settings, run_full_on_start=False)
    settings.validate()

    updater = MarketDataUpdater(settings)
    lock = SingleInstanceLock(settings.lock_file)
    if not lock.acquire():
        LOGGER.error("Updater data pasar sudah berjalan; proses kedua tidak dibuat")
        return 2

    loop = asyncio.get_running_loop()
    installed_signals: list[signal.Signals] = []
    for signal_name in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signal_name, updater.request_stop)
            installed_signals.append(signal_name)
        except NotImplementedError:  # pragma: no cover
            pass

    try:
        if args.once:
            result = await updater.collect_once(args.once)
            return 0 if result.successful else 1
        await updater.run_forever()
        return 0
    finally:
        await updater.runner.stop()
        for signal_name in installed_signals:
            loop.remove_signal_handler(signal_name)
        lock.release()


def main() -> int:
    logging.basicConfig(
        level=os.getenv("AI_SCALPER_MARKET_UPDATER_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )
    try:
        return asyncio.run(_async_main(_build_parser().parse_args()))
    except (ValueError, RuntimeError) as error:
        LOGGER.error("Updater tidak dapat dimulai: %s", error)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
