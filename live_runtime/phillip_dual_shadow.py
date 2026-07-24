"""Fail-closed topology helpers for two isolated Phillip MT5 terminals."""

from __future__ import annotations

import ntpath
from pathlib import Path, PureWindowsPath
from typing import Callable, Sequence


class PhillipDualShadowError(RuntimeError):
    """Raised when a dual-terminal diagnostic topology is unsafe."""


def _terminal_path(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text or "\x00" in text or "\n" in text or "\r" in text:
        raise PhillipDualShadowError(f"{label} terminal path is invalid")
    parsed = PureWindowsPath(text)
    if not parsed.is_absolute() or not parsed.drive:
        raise PhillipDualShadowError(
            f"{label} terminal must use an absolute Windows path"
        )
    if parsed.name.casefold() != "terminal64.exe":
        raise PhillipDualShadowError(f"{label} path must end with terminal64.exe")
    return str(parsed)


def validate_dual_terminal_paths(
    fx_terminal_path: object,
    commodity_terminal_path: object,
    *,
    path_is_file: Callable[[str], bool],
) -> tuple[str, str]:
    """Validate distinct, existing MT5 executables without opening either one."""

    fx = _terminal_path(fx_terminal_path, "FX")
    commodity = _terminal_path(commodity_terminal_path, "commodity")
    fx_directory = ntpath.normcase(ntpath.normpath(ntpath.dirname(fx)))
    commodity_directory = ntpath.normcase(
        ntpath.normpath(ntpath.dirname(commodity))
    )
    if fx_directory == commodity_directory:
        raise PhillipDualShadowError(
            "FX and commodity terminals require different installation directories"
        )
    for label, path in (("FX", fx), ("commodity", commodity)):
        if not path_is_file(path):
            raise PhillipDualShadowError(f"{label} terminal does not exist")
    return fx, commodity


def _poll_text(value: float) -> str:
    if isinstance(value, bool):
        raise PhillipDualShadowError("poll seconds is invalid")
    parsed = float(value)
    if not 1.0 <= parsed <= 300.0:
        raise PhillipDualShadowError("poll seconds must be between 1 and 300")
    return format(parsed, "g")


def build_child_commands(
    *,
    python_executable: str,
    repo_root: Path,
    fx_terminal_path: str,
    commodity_terminal_path: str,
    poll_seconds: float,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Build fixed argument-vector commands for the two read-only children."""

    python = str(python_executable or "").strip()
    if not python:
        raise PhillipDualShadowError("Python executable is unavailable")
    poll = _poll_text(poll_seconds)

    def command(script: str, candidate: str, terminal: str) -> tuple[str, ...]:
        return (
            python,
            "-B",
            str(repo_root / script),
            "--candidate",
            candidate,
            "--terminal-path",
            terminal,
            "--acknowledge-diagnostic-only",
            "--continuous",
            "--poll-seconds",
            poll,
        )

    return (
        command("run_phillip_fx_shadow.py", "phillip-fx", fx_terminal_path),
        command(
            "run_phillip_commodity_shadow.py",
            "phillip-commodity",
            commodity_terminal_path,
        ),
    )


def stop_children(children: Sequence[object]) -> None:
    """Best-effort bounded shutdown for already-created child processes."""

    for child in children:
        poll = getattr(child, "poll", None)
        terminate = getattr(child, "terminate", None)
        if callable(poll) and poll() is None and callable(terminate):
            terminate()
    for child in children:
        wait = getattr(child, "wait", None)
        kill = getattr(child, "kill", None)
        if not callable(wait):
            continue
        try:
            wait(timeout=5)
        except Exception:
            if callable(kill):
                kill()
                try:
                    wait(timeout=5)
                except Exception:
                    pass


def supervise_children(
    children: Sequence[object],
    *,
    sleep: Callable[[float], None],
) -> int:
    """Fail the topology if either continuous child exits."""

    if len(children) != 2:
        raise PhillipDualShadowError("dual-terminal supervisor requires two children")
    try:
        while True:
            for child in children:
                poll = getattr(child, "poll", None)
                if not callable(poll):
                    raise PhillipDualShadowError("child process API is unavailable")
                if poll() is not None:
                    stop_children(children)
                    return 2
            sleep(1.0)
    except KeyboardInterrupt:
        stop_children(children)
        return 130


__all__ = [
    "PhillipDualShadowError",
    "build_child_commands",
    "stop_children",
    "supervise_children",
    "validate_dual_terminal_paths",
]
