---
name: ai-scalper-live-grade-core
description: Implement or review AI_SCALPER live-grade decision, risk, execution, reconciliation, broker-contract, and promotion-gate code while preserving its fail-closed trading boundaries. Use for work in live_runtime or any request that changes progression toward demo or live order capability; do not use for dashboard-only or packaging-only work.
metadata:
  short-description: Preserve AI_SCALPER live-grade invariants
---

# AI_SCALPER live-grade core

Work from the exact lane and trust boundary affected by the request. Before
changing behavior, read the relevant current code and specification plus the
matching sections of `docs/LIVE_GRADE_ARCHITECTURE.md`. Read
`docs/LIVE_GRADE_IMPLEMENTATION_STATUS.md` only to understand recorded gaps;
verify every status claim against current code and fresh evidence.

## Non-negotiable boundaries

- The decision core stays pure and cannot read credentials, policy arms,
  permits, broker APIs, or execution mode.
- Risk, health, market/news/rollover guards, model identity, permit, journal,
  account fence, and broker preflight remain separate fail-closed authorities.
- Intent is immutable and idempotent. An uncertain submission is never retried
  before reconciliation proves its outcome.
- A broker fill is incomplete until reconciliation verifies position and
  server-side protection.
- Development data, green tests, shadow evidence, diagnostic registration, or a
  signed receipt does not independently authorize an order.
- Preserve current safety projections unless a separately scoped and reviewed
  request explicitly changes them. Do not weaken a gate merely to make a test
  or operator command pass.

## Workflow

1. Identify the exact symbol, strategy, environment, contract, build identity,
   journal, and authority boundary in scope.
2. Trace producers and consumers of every changed receipt or sealed object.
   Reject parallel schemas or caller-supplied booleans that bypass an existing
   authority.
3. Implement the smallest change with focused negative tests for drift,
   replay, duplicate input, stale evidence, wrong identity, and forbidden side
   effects where relevant.
4. Run focused tests first. For a cross-cutting runtime change, run the normal
   and optimized suites used by the repository. Treat platform skips as missing
   host evidence, not passes.
5. Report software verification separately from operational gates still
   missing. Never express progress toward live trading as a test-pass
   percentage unless a tracked gate model defines that percentage.

For promotion or execution work, also inspect the current gate definitions in
the relevant `specs/` files and the latest applicable ship-gate document. Do
not treat historical approvals or hashes as current without revalidation.
