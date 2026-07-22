# DEMO_AUTO Account Soak Cohort v1

## Status and purpose

This component aggregates post-activation DEMO_AUTO evidence at the exact
broker-account cohort level. It measures the roadmap soak thresholds of at
least 30 clean days, 50 broker-reconciled closed fills, and 20 XAUUSD closed
fills across allowlisted lanes. It is evidence accounting only and never
grants activation, execution, promotion, permit, or live authority.

Every output remains locked:

- `ready=false`
- `promotion_eligible=false`
- `execution_enabled=false`
- `activation_authorized=false`
- `safe_to_demo_auto_order=false`
- `live_allowed=false`
- `order_capability=DISABLED`

Meeting the cohort counters is not a substitute for the independent
statistical and promotion gates of each symbol/strategy lane.

## Immutable cohort boundary

`DemoAutoSoakCohortBinding` fixes one DEMO account, broker server, journal,
commit, configuration, dependency lock, runtime profile, release manifest,
session calendar, model, clean generation, and complete allowlisted lane set.
Each lane separately binds its canonical and broker symbol, account currency,
broker specification, stage/session/projection identities, tracker identity,
and all assessment, projection-custody, and broker-reconciliation key
fingerprints. The cohort broker-spec-set hash must equal the canonical set of
all member specifications.

Unknown, missing, duplicate, case-drifted, cross-account, cross-server,
cross-release, or cross-generation members fail closed.

## Accepted evidence

For every lane the aggregator requires:

1. a current signed `SoakAssessmentReceipt` with the exact lane binding;
2. a complete externally signed projection checkpoint chain from genesis to
   the declared current head, with contiguous event counts and predecessor
   hashes;
3. canonically ordered `CLOSED_FILL` event proofs included in that chain; and
4. exact signed broker deal receipts bound to their reconciliation envelope,
   closed-intent mapping, account, server, symbol, broker symbol, currency,
   provider sequence, and clean-period timestamps.

A broker deal identity includes provider, account, server, source sequence,
and deal ticket. One identity can have only one lane owner. A provider source
sequence can have only one reconciliation head across the complete cohort.

## Restart, rollback, and incident rules

Each signed cohort receipt contains the complete cumulative deal-owner set and
per-lane assessment/projection heads. A successor must include every prior
deal and may not reduce counts or event heights. Equal-height assessment or
projection head changes are forks and are rejected.

Any critical incident, demotion latch, clean-generation mismatch, or unmatched
incident/review counter resets qualified duration and fills to zero and latches
the cohort receipt as `RESET_REQUIRED`. Restart cannot clear that latch. A new
reviewed cohort binding is required after incident review.

## Threshold semantics

When no reset condition exists:

- clean duration is the minimum clean duration across all cohort members;
- closed-fill count is the number of unique authenticated broker deal
  identities across all members;
- XAUUSD count includes only deals whose exact member and broker evidence are
  both XAUUSD; and
- all three thresholds must be true for status
  `CRITERIA_MET_DENY_ONLY`.

The status is an input to later human-reviewed promotion evaluation only. It
cannot arm the executor or modify `execution_policy.py`.

## Acceptance criteria

1. A complete 30-day, 50-fill, 20-XAU cohort returns a valid signed deny-only
   receipt while all authority fields remain false.
2. A missing/reordered checkpoint, equal-height fork, regressed counter,
   disappearing prior deal, duplicate deal, reconciliation fork, or tampered
   HMAC is rejected.
3. FX deals cannot masquerade as XAUUSD, and broker-symbol/currency/spec drift
   is rejected.
4. Incident or generation drift resets all qualified progress and remains
   latched across restart.
5. The deterministic Windows GATED release includes this module and its static
   validator reports the foundation present without claiming readiness.

## Out of scope

- Enabling DEMO_AUTO or live trading.
- Creating stage authorization, promotion permits, or environment-arm values.
- Reading MT5 directly or sending, changing, cancelling, or retrying orders.
- Replacing per-lane OOS, broker-forward, parity, PF, expectancy, drawdown,
  cost-stress, regulatory, security, failure-drill, or manual approval gates.
