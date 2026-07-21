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

## Registration Activation Review Checkpoint

- A non-mutating activation-review pack now verifies the exact discovery-v3,
  two independent regulatory approvals, signed pre-window calendar review,
  clean Git commit/tree, and three bounded proposed config images together.
- The static verifier carries both base and proposed content, recomputes every
  canonical hash, enforces lane cross-binding, and rejects a forged base even
  when an attacker recomputes the top-level proposal hash.
- Discovery, compliance, legal, and calendar HMAC keys are loaded once and
  must have four distinct secret fingerprints. Keys remain in Windows
  Credential Manager and are never exported.
- Preparation output must be outside the repository and create-exclusive.
  No apply, patch, commit, activation, credential, or order command exists.
- Validation: spec `100/100`; focused/release suite `38/38`; full regression
  suite `669/669`; safety/reproducibility suite `28/28`; targeted project
  compilation and Windows dependency lock verification pass.
- Both Phillip registrations remain false. Actual independent human approvals,
  review-pack acceptance, a later explicit clean commit, contract registration,
  broker-forward evidence, and every order/live gate remain outstanding.
