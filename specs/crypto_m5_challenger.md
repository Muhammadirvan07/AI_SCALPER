# Crypto M5 Challenger

## Scope

Add a separate BTCUSD/ETHUSD M5 diagnostic challenger beside the existing M15
crypto champion. The challenger observes the same Binance-primary and
Coinbase-validator public feeds, but it owns a distinct configuration,
identity, journal, summary, performance report, and strategy timeframe.

## Acceptance criteria

1. The existing M15 champion remains the default and retains byte-identical
   decision snapshot hashes for existing golden fixtures.
2. M5 accepts only finalized, unique, contiguous, timezone-aware UTC bars
   aligned to five-minute boundaries; M15 and malformed series are rejected.
3. The shared pure decision evaluator receives an explicit timeframe. M5 uses
   an explicit crypto challenger profile whose maximum holding duration is 72
   bars (six hours), while M15 remains 24 bars (six hours).
4. Every M5 decision snapshot binds `timeframe=M5`. A non-M15 snapshot cannot
   create a `TradeIntent`, even if it contains a BUY or SELL decision.
5. The M5 profile, schema, source-binding hash, SQLite WAL journal, summary,
   decision keys, and performance report are distinct from M15. Opening either
   journal with the other domain must fail closed.
6. The M5 report uses M5 holding-horizon metrics and cannot read an M15 journal.
7. The M5 CLI has a dedicated config and default artifact paths. It requires
   `--acknowledge-diagnostic-only`, uses no credentials, and exposes no order,
   account, wallet, permit, promotion, or broker mutation capability.
8. Cross-feed, clock, spread, staleness, entry-window, append-only hash-chain,
   and all existing safety checks remain mandatory and unchanged.
9. Windows release packaging contains the M5 config, runner, report generator,
   and all shared source files required to reproduce the runtime identity.

## Non-goals

- M5 does not replace or promote over M15 automatically.
- M5 produces no broker-forward or live-promotion evidence.
- No API key, exchange account, wallet, leverage, futures, CFD, or order API is
  introduced.
- M5 thresholds are an offline/shadow challenger baseline, not an assertion of
  superior profitability.
