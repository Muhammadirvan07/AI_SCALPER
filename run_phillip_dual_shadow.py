"""Windows supervisor for isolated Phillip FX and commodity shadows."""

from __future__ import annotations

import argparse
from pathlib import Path
import platform
import subprocess
import sys
import time
from typing import Callable, Sequence

from live_runtime.phillip_dual_shadow import (
    PhillipDualShadowError,
    build_child_commands,
    stop_children,
    supervise_children,
    validate_dual_terminal_paths,
)


REPO_ROOT = Path(__file__).resolve().parent


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run two isolated Phillip read-only diagnostic shadows"
    )
    parser.add_argument("--fx-terminal-path", required=True)
    parser.add_argument("--commodity-terminal-path", required=True)
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--acknowledge-diagnostic-only", action="store_true")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    platform_name: str | None = None,
    path_is_file: Callable[[str], bool] | None = None,
    process_factory: Callable[..., object] = subprocess.Popen,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    args = _parser().parse_args(argv)
    if not args.acknowledge_diagnostic_only:
        raise PhillipDualShadowError("--acknowledge-diagnostic-only is required")
    if (platform_name or platform.system()) != "Windows":
        raise PhillipDualShadowError("Phillip dual-terminal shadow requires Windows")
    checker = path_is_file or (lambda value: Path(value).is_file())
    fx_terminal, commodity_terminal = validate_dual_terminal_paths(
        args.fx_terminal_path,
        args.commodity_terminal_path,
        path_is_file=checker,
    )
    commands = build_child_commands(
        python_executable=sys.executable,
        repo_root=REPO_ROOT,
        fx_terminal_path=fx_terminal,
        commodity_terminal_path=commodity_terminal,
        poll_seconds=args.poll_seconds,
    )

    print("Profile: PHILLIP_DUAL_TERMINAL_DIAGNOSTIC_ONLY")
    print("FX terminal: VERIFIED_DISTINCT_PATH")
    print("Commodity terminal: VERIFIED_DISTINCT_PATH")
    print("Credentials: DISALLOWED")
    print("Order capability: DISABLED")
    print("Promotion evidence: DISABLED")
    if args.validate_only:
        print("PHILLIP_DUAL_TERMINAL_VALID")
        return 0

    children: list[object] = []
    try:
        for command in commands:
            children.append(
                process_factory(
                    command,
                    cwd=str(REPO_ROOT),
                    shell=False,
                )
            )
    except OSError as exc:
        stop_children(children)
        raise PhillipDualShadowError("failed to start isolated shadow child") from exc
    return supervise_children(children, sleep=sleep)


def cli_entrypoint(argv: Sequence[str] | None = None) -> int:
    try:
        return main(argv)
    except PhillipDualShadowError as exc:
        print(f"PHILLIP_DUAL_SHADOW_REJECTED: {exc}", file=sys.stderr)
        print(
            "Safety lock remains active; no broker order was submitted.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(cli_entrypoint())
