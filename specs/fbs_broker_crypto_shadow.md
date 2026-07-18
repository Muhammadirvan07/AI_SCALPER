# FBS broker crypto diagnostic shadow

## Scope

BTCUSD and ETHUSD are read from the already-open `FBS-Demo` MT5 terminal as
broker CFD instruments. They must not reuse Binance/Coinbase public-market
journals or the FBS XAU/FX journal.

## Runtime domains

- M15 champion: `FBS_BROKER_CRYPTO_M15_DIAGNOSTIC_ONLY`
- M5 challenger: `FBS_BROKER_CRYPTO_M5_CHALLENGER_DIAGNOSTIC_ONLY`
- Each domain has an independent SQLite journal, summary, hash chain, report,
  decision keys, open positions, and performance metrics.

Both domains use the shared pure decision core with their exact timeframe.
They require finalized broker bars and the first eligible broker tick after
the bar close. BUY uses ask entry/bid exit and SELL uses bid entry/ask exit.

## Safety

- demo account and exact `FBS-Demo` server only;
- investor/read-only account and terminal API attestation required;
- no credentials or account identifier persisted;
- no order, position, deal, or mutation API exposed;
- no promotion evidence and no automatic learning/promotion;
- `live_allowed=false`, `safe_to_demo_auto_order=false`, `max_lot=0.01`.
