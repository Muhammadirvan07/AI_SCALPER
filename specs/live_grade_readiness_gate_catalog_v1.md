# Live-Grade Readiness Gate Catalog v1

## Purpose

This catalog prevents repository completeness from being confused with broker
or live readiness. It separates gates into local foundation, external
configuration, temporal evidence, and manual approval. Code may close a local
foundation gap, but it may never self-assert a broker observation, legal fact,
elapsed soak period, statistical result, or operator approval.

## Safety contract

- `LIVE_ALLOWED=false`.
- `SAFE_TO_DEMO_AUTO_ORDER=false`.
- `max_lot=0.01`.
- `order_capability=DISABLED` for this reporting module.
- Every report has `production_execution_ready=false` and
  `promotion_eligible=false`.
- The catalog does not accept caller-claimed pass booleans and does not verify
  or issue promotion evidence.

## Acceptance requirements

1. Gate codes are unique, normalized uppercase text with a non-empty
   description.
2. Unknown, non-text, or non-normalized codes fail closed.
3. Classification is deterministic, sorted, and duplicate-insensitive.
4. Every non-local gate remains pending in the static report.
5. External, temporal, and manual gates are never converted into a pass by
   local source code or unit tests.
6. The report exposes all immutable safety locks.

## Operational interpretation

`LOCAL_FOUNDATION` means Codex can implement and test it in this repository.
`EXTERNAL_CONFIGURATION` requires the exact Windows host, broker terminal,
credential custody, legal review, or independent receipt providers.
`TEMPORAL_EVIDENCE` requires real elapsed observation and closed trades.
`MANUAL_APPROVAL` requires a deliberate human decision after the evidence is
complete. No percentage should merge these categories into a single misleading
"ready" number.

In particular, the roadmap's twenty-XAU fill criterion does not override the
locked per-trade risk cap. The exact broker must first demonstrate through
`order_calc_profit()` that its minimum XAUUSD volume and a valid stop distance
fit that cap. If not, XAUUSD correctly remains `WAIT` and another eligible
account specification is required; software must not reduce the stop merely to
manufacture soak fills.

The first DEMO_AUTO and live canary is restricted to one XAU account. Before
FX and commodity services may execute concurrently across separate broker
accounts, an external portfolio coordinator must atomically reserve the single
global position slot and reconcile exposure across every account. Per-account
SQLite journals or process mutexes cannot satisfy that cross-account gate.
