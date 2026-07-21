# AI_SCALPER Project Progress — 2026-07-21

- Active branch: `agent/live-grade-phase3`
- Scope: Python AI_SCALPER only
- Status: FBS XAU/FX M15 diagnostic shadow; `NOT_READY / DO NOT SHIP`

## Saved Runtime Checkpoint

- Exact broker binding remains `FBS-Demo`.
- Active M15 lanes are XAUUSD, EURUSD, USDJPY, and AUDUSD.
- The shadow processed 24 decisions: six finalized M15 decisions per lane.
- EURUSD opened one paper position and that position remains open.
- XAUUSD, USDJPY, and AUDUSD have not opened a paper position in this sample.
- Closed trades, wins, losses, timeouts, and net R are all zero.
- Win rate and profit factor are intentionally undefined because no paper trade
  has closed.
- The latest reported cycle was `OBSERVED` with no failures; repeated
  `ALREADY_PROCESSED` states are expected polling of the same finalized candle.
- The generated report status is `NO_CLOSED_TRADES` and remains diagnostic-only.

## Locked Safety State

- `live_allowed=false`
- `safe_to_demo_auto_order=false`
- `promotion_eligible=false`
- `validation_evidence=false`
- Broker mutation and order capability remain disabled.

## Next Evidence Step

Continue exactly one FBS XAU/FX M15 shadow instance so the open EURUSD paper
position can close at TP, SL, or its configured timeout. Preserve the existing
SQLite journal and regenerate the FBS performance report after `paper_closed`
increases. Do not run the FBS Crypto M5 shadow concurrently on the same account.

## Architecture Checkpoint

- Broker registration-review tooling is implemented as a fail-closed local
  workflow: exact official source bytes, candidate/template/lane binding, two
  independent domain-separated HMAC approvals, immutable assembly, and
  downstream vault-key verification.
- The tooling does not download documents, decide legal meaning, issue human
  approvals, patch tracked candidate config, or enable registration.
- Both Phillip profiles remain
  `BLOCKED_PENDING_SIGNED_REGULATORY_CALENDAR_AND_REGISTRATION_REVIEW` with
  `registration_enabled=false`; no actual compliance/legal approval is claimed.
- The operator workflow is documented in
  `docs/BROKER_REGISTRATION_REVIEW.md` for a later independent review.
