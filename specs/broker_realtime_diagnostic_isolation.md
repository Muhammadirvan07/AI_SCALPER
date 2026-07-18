# Broker realtime diagnostic isolation

## Scope

The broker realtime diagnostic is observation and paper simulation only. It
must never submit, modify, or close a broker order and it is never promotion
evidence.

## Candidate isolation

- The default SQLite journal, summary, and performance report are namespaced by
  normalized candidate ID.
- `xm` retains the existing `xm-real-market-*` filenames.
- `finex` uses `finex-real-market-*` filenames.
- `fbs` uses `fbs-real-market-*` filenames and is the current default.
- A journal containing a cycle for a different broker server or account
  identity is rejected before a new cycle is observed.
- Explicit output paths are supported, but do not bypass the broker-cohort
  check.

## Locked safety properties

- `live_allowed=false`
- `safe_to_demo_auto_order=false`
- `promotion_eligible=false`
- `validation_evidence=false`
- `order_capability=DISABLED`
- `max_lot=0.01`
