# AI_SCALPER Project Progress — 2026-07-18

- Active branch: `agent/live-grade-phase3`
- Scope: Python AI_SCALPER only
- Status: broker/crypto diagnostic shadow; `NOT_READY / DO NOT SHIP`

## Added

- Binance public spot primary adapter for `BTCUSDT` and `ETHUSDT`.
- Coinbase public cross-feed validation using `BTC-USD` and `ETH-USD`.
- GET-only host/path allowlist with no credential, account, wallet, or order
  surface.
- Finalized, contiguous UTC M15 validation plus clock, staleness, spread, and
  cross-feed deviation guards.
- Shared pure decision-core integration for canonical `BTCUSD` and `ETHUSD`.
- Explicit crypto strategy profile for ETHUSD matching the locked BTC shadow
  profile.
- Separate append-only SQLite WAL journal, summary, and verified read-only
  performance report.
- Weekend focus scheduler from Friday 21:00 UTC through Sunday 22:00 UTC.
- Runtime journal domain binding so broker and crypto journals cannot be mixed.
- Startup verification of existing journal hash chain and SQL row/envelope
  binding before any append.

## Verification

- Full regression suite: `472/472` passed.
- Public endpoint smoke test succeeded without credentials or orders.
- Live smoke result during an already-open M15 candle:
  `BTCUSD=ENTRY_WINDOW_MISSED, ETHUSD=ENTRY_WINDOW_MISSED`.
- `ENTRY_WINDOW_MISSED` is expected for a one-shot process started more than ten
  seconds after candle close; continuous mode is required to observe the next
  eligible boundary.

## Safety

- `live_allowed=false`
- `safe_to_demo_auto_order=false`
- `promotion_eligible=false`
- `validation_evidence=false`
- Credentials: disallowed
- Order capability: disabled
- BTCUSD and ETHUSD: shadow-only

Crypto spot diagnostics do not prove CFD execution performance, broker parity,
fees, funding, slippage, margin, or legal eligibility. XM XAU/FX journal and
metrics remain separate.
