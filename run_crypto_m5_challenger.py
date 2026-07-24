"""Dedicated CLI for the isolated BTC/ETH M5 diagnostic challenger."""

from __future__ import annotations

from typing import Sequence

from live_runtime.crypto_shadow import CryptoPublicMarketClient
from run_crypto_weekend_shadow import (
    M5_RUNNER_PROFILE,
    cli_entrypoint as _shared_cli_entrypoint,
    main as _shared_main,
    utc_now,
)


def main(
    argv: Sequence[str] | None = None,
    *,
    client: CryptoPublicMarketClient | None = None,
    clock_provider=utc_now,
) -> int:
    return _shared_main(
        argv,
        client=client,
        clock_provider=clock_provider,
        runner_profile=M5_RUNNER_PROFILE,
    )


def cli_entrypoint(argv: Sequence[str] | None = None) -> int:
    return _shared_cli_entrypoint(argv, runner_profile=M5_RUNNER_PROFILE)


if __name__ == "__main__":
    raise SystemExit(cli_entrypoint())
