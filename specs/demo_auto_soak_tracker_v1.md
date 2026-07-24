# Spec: HMAC-Anchored Deny-Only Demo-Auto Soak Tracker v1

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-22
**Status:** Implemented; deny-only
**Related specs:** `specs/architecture_foundation_completion_v1.md`, `specs/manual_demo_acceptance_tracker_v1.md`

## Context

The roadmap requires a clean demo-auto observation period of at least 30 days
and 50 closed broker fills, including 20 XAUUSD fills. A local counter or a
plain SHA chain is insufficient: an attacker or operational error can replace
the database with an older valid copy, create a valid-looking fork, or rewrite
both the events and the local head.

This tracker is an evidence component, not an authorization component. It uses
a secret HMAC key obtained by identifier from an injected key provider. It
signs the immutable tracker identity, every append, the materialized head, and
an exportable assessment checkpoint. An assessment checkpoint held outside the
SQLite/WAL files can be supplied on reopen to detect rollback, fork, coherent
rewrite, missing events, lost incident history, or regressed clean-generation
counters.

Production progress cannot be asserted through raw timestamps, symbols, fill
IDs, incident IDs, or reviewer IDs. Every accepted event carries a sealed
source receipt whose signature, freshness, exact broker/account/environment/
journal binding, issuer, and key allowlist are verified at ingestion and again
during database replay. Diagnostic-only raw observations are outside this
tracker and are ineligible to increment its counters.

Every report and signed receipt permanently exposes the following constants:

- `ready=false`
- `promotion_eligible=false`
- `execution_enabled=false`
- `safe_to_demo_auto_order=false`
- `live_allowed=false`
- `order_capability=DISABLED`

The module contains no broker connection, order request, permit, approval,
credential loading, or safety-lock clearing surface.

## Security and Trust Boundary

### Trusted inputs

- exact non-secret binding: broker identifier, `DEMO` environment,
  account-alias SHA-256, broker server, source-journal SHA-256, Git commit,
  configuration SHA-256, broker-specification SHA-256, model-artifact SHA-256,
  and lane identifier;
- an exact `key_id` and a key provider returning at least 32 bytes;
- a separate source-key provider plus exact issuer/key allowlists for
  `DEMO_AUTO_ACTIVATION`, `BROKER_CLOSED_DEAL`, `CRITICAL_INCIDENT`, and
  `DUAL_REVIEW`;
- sealed, domain-signed source receipts with a maximum five-second lifetime,
  maximum 30-second source-observation delay, and timezone-aware UTC times;
- a timezone-aware UTC trusted clock;
- optional prior sealed `SoakAssessmentReceipt` exported to independent,
  append-only or immutable custody.

### Local assurance

- SQLite `WAL`, `synchronous=FULL`, foreign keys, 10-second busy timeout;
- exact table, column, constraint, index, and trigger definitions;
- immutable HMAC identity and key fingerprint;
- immutable `source_trust_sha256` binding the complete issuer/key allowlist and
  every source-key fingerprint;
- domain-separated append HMAC chain;
- HMAC-protected materialized state replayed from genesis;
- update/delete triggers on identity/events and a required-head delete trigger.

### External-anchor assurance

Without a prior receipt, a coherent replacement of every local SQLite/WAL file
with an older internally valid copy cannot be distinguished from valid state.
When a prior signed receipt is supplied, the tracker requires the exact prefix
event HMAC and timestamp to remain in the local chain, and requires all event,
generation, incident, demotion, and current-generation counters to be at least
as advanced. Production operations therefore must export each accepted receipt
off-host and provide the latest accepted receipt on every reopen.

## Cryptographic Domains

All HMACs are HMAC-SHA-256 over canonical JSON and use independent domains:

```text
AI_SCALPER_DEMO_AUTO_SOAK_IDENTITY_V1\0
AI_SCALPER_DEMO_AUTO_SOAK_EVENT_V1\0
AI_SCALPER_DEMO_AUTO_SOAK_STATE_V1\0
AI_SCALPER_DEMO_AUTO_SOAK_ASSESSMENT_V1\0
AI_SCALPER_SOAK_DEMO_AUTO_ACTIVATION_V1\0
AI_SCALPER_SOAK_BROKER_CLOSED_DEAL_V1\0
AI_SCALPER_SOAK_CRITICAL_INCIDENT_V1\0
AI_SCALPER_SOAK_DUAL_REVIEW_V1\0
```

Secrets are never stored. SQLite stores the ledger `key_id`, its SHA-256
fingerprint, and a hash of the complete source trust configuration. Ledger and
source key IDs and secret material must be distinct. The two review signatures
must also use distinct reviewer identities, key IDs, and cryptographic secret
material.

## Functional Requirements

- **FR-1 Exact identity.** One database is immutably bound to one tracker UUID,
  broker ID, the literal `DEMO` environment, account alias hash, server,
  journal hash, commit, configuration hash, broker-specification hash,
  model-artifact hash, lane, and key identifier. Any mismatch fails before
  append or assessment. A non-demo binding is rejected before storage opens.
- **FR-2 Strong key.** The key provider is mandatory and must return `str` or
  `bytes` containing at least 32 encoded bytes. Missing, short, changed, or
  wrong-key material fails closed.
- **FR-3 HMAC identity.** The complete identity is signed under the identity
  domain. Identity update/delete is rejected by SQLite triggers and signature
  verification.
- **FR-4 Append chain.** Start, reviewed-restart, closed-fill, and
  critical-incident observations form a contiguous, domain-separated HMAC
  chain. Every HMAC binds exact row fields, canonical payload, predecessor,
  binding, tracker, key, sequence, generation, and UTC timestamp.
- **FR-4a Authenticated sources.** `SOAK_STARTED` accepts only an exact signed
  `DEMO_AUTO_ACTIVATION` receipt whose details are exactly
  `mode=DEMO_AUTO`. `CLOSED_FILL` accepts only a signed reconciled broker-deal
  receipt binding account alias, server, `DEMO`, journal, intent, deal, ticket,
  closed volume, symbol, broker occurrence timestamp, and upstream receipt
  hash. `CRITICAL_INCIDENT` accepts only a signed incident-controller receipt.
  All receipts are sealed by their verifier and reverified during replay.
- **FR-5 Uniqueness.** Event IDs, activation IDs, broker deal IDs, incident
  IDs, and review receipt IDs are immutable and unique. A new signed wrapper
  around an already-counted broker deal remains a duplicate. Duplicate sources
  or observation timestamps fail atomically without advancing state.
- **FR-6 Time.** Observations and assessments must be timezone-aware UTC.
  Observations may not predate tracker creation, may not be in the future, and
  must be strictly later than the last event. Assessments may not predate the
  latest event or be in the future.
- **FR-7 Genesis.** The first and only start event creates clean generation 1.
  Fills and incidents before genesis are rejected.
- **FR-8 Incident generation.** Every critical incident advances the clean
  generation by exactly one, resets only the current-generation start and fill
  counters, increments the permanent incident count, and latches demotion.
  Earlier events remain in the HMAC chain.
- **FR-8a Reviewed restart.** A latched soak may restart only through an
  explicit `SOAK_RESTARTED_AFTER_REVIEW` event carrying two valid independent
  signatures from the trusted review allowlist. The receipt must name the exact
  currently latched incident and bind its immutable review-evidence hash. The
  event advances the clean
  generation, increments the permanent reviewed-restart count, clears only the
  *current* demotion latch, resets the current counters, and begins a completely
  new 30-day period at the restart timestamp. It never removes an incident or
  historical event. A restart without an active latch is rejected.
- **FR-9 Latest generation.** Duration, total fills, and XAUUSD fills are
  computed only from the latest clean generation. Historical pre-incident fills
  can never satisfy current criteria.
- **FR-10 Numerical criteria.** The tracker independently reports 30 clean
  days, 50 closed fills, 20 XAUUSD fills, and their conjunction.
- **FR-11 Deny-only outcome.** Satisfying all numerical criteria never changes
  any readiness, promotion, execution, demo-auto, live, or order-capability
  field.
- **FR-12 Signed checkpoint.** `assessment_receipt()` returns a sealed
  HMAC-signed receipt bound to exact identity, event count/head, clean
  generation/start, latest event, 30/50/20 counters, permanent incident and
  reviewed-restart counts, current demotion state, assessment time, blockers,
  and all deny constants.
- **FR-13 Sealing.** A receipt cannot be directly constructed or replaced by
  ordinary caller code. Signature verification is also available as a pure
  fail-closed function.
- **FR-14 External rollback check.** Reopening with an expected receipt rejects
  invalid signature, wrong binding/tracker/key, future receipt, missing or
  regressed event count, changed prefix HMAC/time, regressed generation,
  removed incident/restart history, an unexplained demotion-latch transition,
  or regressed same-generation counters.
- **FR-15 Valid progress.** A local chain may extend a prior receipt prefix. A
  later generation is valid only when permanent incident or reviewed-restart
  evidence also advances. A `true` to `false` demotion transition additionally
  requires the reviewed-restart count to advance.
- **FR-16 Replay.** Startup, append, listing, assessment, and receipt issuance
  replay all events from genesis and compare the exact materialized state and
  its HMAC before returning data.
- **FR-17 No mutation capability.** The module must not import or call MT5,
  broker APIs, an executor, a permit issuer, an approval signer, or a secret
  store directly.
- **FR-18 No raw production helper.** No public production method can append a
  raw start, fill, incident, or restart. Legacy raw keyword calls are rejected;
  diagnostic raw accounting must use a separate ineligible component.

## Non-Functional Requirements

- **NFR-1 Durability.** Every connection verifies SQLite WAL,
  `synchronous=FULL`, foreign keys, and a 10-second busy timeout.
- **NFR-2 Atomicity.** Append and head update occur inside one `BEGIN IMMEDIATE`
  transaction. Duplicate or invalid observations persist neither operation.
- **NFR-3 Canonical data.** Payload JSON is canonical, rejects duplicate keys,
  uses canonical microsecond UTC text, and contains no NaN or infinity.
- **NFR-4 Strict schema.** Table SQL, columns, constraints, trigger SQL, and the
  absence of unapproved user indexes are verified exactly.
- **NFR-5 Secret minimization.** No raw login, name, balance, equity, order,
  credential, or secret is persisted. Account identity is represented only by
  its approved alias hash.
- **NFR-6 Determinism.** The same verified event chain and assessment timestamp
  produce the same unsigned assessment. The signed receipt is deterministic
  for the same key and inputs.
- **NFR-7 Fail closed.** Malformed storage raises a typed error and never
  returns partial progress.

## API Contract

```python
tracker = DemoAutoSoakTracker(
    path,
    binding=SoakBinding(...),
    key_id="demo-soak-window-01",
    key_provider=key_provider,       # Callable[[str], str | bytes], >=32 bytes
    source_key_provider=source_key_provider,
    trusted_source_issuer_keys={
        "DEMO_AUTO_ACTIVATION": {"activation-controller": (...)},
        "BROKER_CLOSED_DEAL": {"broker-reconciler": (...)},
        "CRITICAL_INCIDENT": {"incident-controller": (...)},
        "DUAL_REVIEW": {"review-board": (review_key_1, review_key_2)},
    },
    clock_provider=trusted_utc_now,
    expected_receipt=last_offhost_receipt,  # optional but required operationally
)

activation = verify_soak_source_receipt(...)
closed_deal = verify_soak_source_receipt(...)
incident = verify_soak_source_receipt(...)
dual_review = verify_dual_review_receipt(...)

tracker.start_soak(event_id=..., activation_receipt=activation)
tracker.record_closed_fill(event_id=..., closed_deal_receipt=closed_deal)
tracker.record_critical_incident(event_id=..., incident_receipt=incident)
tracker.restart_after_review(event_id=..., review_receipt=dual_review)

assessment = tracker.assessment(as_of_utc=...)
receipt = tracker.assessment_receipt(as_of_utc=...)
verify_soak_assessment_receipt(receipt, key_provider)
tracker.verify_integrity(expected_receipt=last_offhost_receipt)
```

### `SoakAssessmentReceipt`

The sealed receipt contains:

| Group | Fields |
|---|---|
| identity | `tracker_id`, broker ID, `DEMO` environment, account alias hash, server, journal hash, commit, config hash, broker-spec hash, model-artifact hash, lane, binding hash, `key_id` |
| chain | `event_count`, `head_hmac_sha256`, `latest_event_at_utc` |
| clean generation | generation, start, duration seconds/days, closed fills, XAUUSD fills |
| criteria | 30-day, 50-fill, 20-XAU, conjunction, blocker codes |
| incident state | permanent critical-incident count, permanent reviewed-restart count, and current demotion latch |
| checkpoint | `assessed_at_utc`, schema version, receipt HMAC |
| safety | six constant deny-only fields |

## Acceptance Criteria

1. **Identity and key binding:** Same binding/key reopens; changing any binding
   field, key ID, or secret fails closed.
2. **Durable storage:** WAL/FULL/foreign-keys/timeout and exact schema/triggers
   are proven; append and head update are atomic.
3. **Complete numerical generation:** 30 days, 50 fills, and 20 XAU fills set
   numerical booleans true while assessment and signed receipt remain denied.
4. **Independent blockers:** Each unmet numerical criterion is represented by a
   distinct blocker.
5. **Permanent incident evidence and reviewed recovery:** Incident advances
   generation, resets current counters, persists historical events/count, and
   latches demotion across process restart. Only a reviewed-restart event may
   clear the current latch; it preserves permanent incident history, advances
   generation/restart history, and begins a full fresh soak from zero.
6. **Duplicate/time rejection:** Repeated event/fill/incident identifiers,
   equal timestamps, backdated observations, pre-creation observations, future
   observations, naive/non-UTC time, and future assessments fail atomically.
7. **Tamper rejection:** Payload, identity, event HMAC, head, state HMAC,
   schema, trigger, index, sequence, predecessor, generation, or canonical JSON
   mutation fails before progress is returned.
8. **Tail-loss detection:** A deleted tail with unchanged head projection fails
   local verification.
9. **Rollback anchor:** An older valid database cannot reopen against a newer
   external receipt.
10. **Fork/rewrite anchor:** A divergent locally valid chain with the same event
    count cannot reopen against the original receipt prefix.
11. **Valid prefix extension:** Later events and a properly evidenced later
    incident or reviewed-restart generation remain compatible with an older
    valid receipt.
12. **Receipt protection:** Direct construction/replacement, signature tamper,
    wrong key, wrong tracker/binding, and future receipt fail closed.
13. **No execution surface:** Public API contains no approve, arm, permit,
    promote, order, or unlock operation. The reviewed restart only resets
    evidence accounting; it never enables execution and every safety field
    stays denied.
14. **Authenticated ingestion:** Raw public calls and unsealed source objects
    fail. Forged, stale, future, untrusted-key, wrong-domain, or cross-bound
    activation/deal/incident receipts fail before append.
15. **Exact broker deal replay:** Reusing a broker deal ID under a different
    signed receipt ID, event ID, intent, or ticket is rejected as a duplicate.
16. **Independent review:** Same reviewer identity, same key ID, duplicated key
    material, one forged signature, wrong incident, stale review, and replayed
    review all fail closed.
17. **Trust immutability:** Adding/removing an issuer or key, changing source
    secret material, or reusing the ledger key prevents database reopen.

## Error Types

- `SoakTrackerError`: invalid caller observation or state-independent request;
- `SoakTrackerDuplicateError`: duplicate immutable observation;
- `SoakTrackerBindingError`: exact database/receipt identity mismatch;
- `SoakTrackerIntegrityError`: schema, semantic, HMAC, key, or storage failure;
- `SoakTrackerRollbackError`: external receipt proves rollback, fork, rewrite,
  missing history, or regression.
- `SoakTrackerSourceError`: source receipt is unsealed, forged, stale, future,
  untrusted, wrong-domain, structurally invalid, or violates review
  independence.

## Operational Requirements

1. Generate the HMAC key in an approved secret manager; never commit it or put
   it in command history.
2. Use one key ID and one database for one exact binding only.
3. After every accepted observation window, generate an assessment receipt and
   export it off-host to append-only/immutable custody.
4. On every process start, fetch the latest externally accepted receipt and
   pass it as `expected_receipt`. Missing external custody is a promotion
   blocker even if local verification passes.
5. A critical incident starts a new clean generation and also triggers the
   roadmap-defined operational demotion/reset outside this component.
6. To resume evidence collection, an independent review workflow must issue an
   immutable review artifact. Record its SHA-256 and reviewer key ID through
   `restart_after_review()`, export the resulting assessment receipt, and run a
   full new 30-day/50-fill/20-XAU soak. The tracker does not validate or issue
   that external review authorization and therefore cannot authorize trading.

## Out of Scope

- enabling manual-demo, demo-auto, canary, or live orders;
- issuing a promotion permit, clearing a risk kill switch, or validating the
  external review authorization referenced by a reviewed-restart event;
- proving OOS profitability, runtime parity, legal eligibility, security
  approval, broker-forward quality, or the 30-day operational calendar by
  itself;
- implementing the off-host/WORM transport or secret manager;
- recovering a lost key, mutating history, migrating/rebinding an existing
  tracker, or accepting unsigned legacy SHA-chain databases;
- executor or runtime entrypoint integration, which requires a separate
  reviewed composition and remains fail-closed.
