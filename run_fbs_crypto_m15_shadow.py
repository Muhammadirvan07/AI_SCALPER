"""FBS MT5 BTC/ETH M15 broker diagnostic champion."""

from __future__ import annotations

from typing import Sequence

from run_realtime_diagnostic_shadow import (
    FBS_CRYPTO_M15_RUNNER_DOMAIN,
    cli_entrypoint as _shared_cli_entrypoint,
    main as _shared_main,
)


def main(argv: Sequence[str] | None = None, **kwargs) -> int:
    return _shared_main(
        argv,
        runner_domain=FBS_CRYPTO_M15_RUNNER_DOMAIN,
        **kwargs,
    )


def cli_entrypoint(argv: Sequence[str] | None = None) -> int:
    return _shared_cli_entrypoint(
        argv,
        runner_domain=FBS_CRYPTO_M15_RUNNER_DOMAIN,
    )


if __name__ == "__main__":
    raise SystemExit(cli_entrypoint())
