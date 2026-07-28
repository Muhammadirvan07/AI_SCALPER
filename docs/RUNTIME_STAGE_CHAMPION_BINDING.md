# Runtime Stage Champion Binding v1

Status: **IMPLEMENTED LOCALLY / DENY-ONLY / NOT AN ACTIVATION**

## Outcome

The runtime stage no longer identifies a reviewed champion only by Git commit,
configuration, and model digest. `StageBinding` now also carries the exact:

- champion archive SHA-256;
- champion package identity SHA-256;
- training snapshot SHA-256;
- 40-character Git tree; and
- runtime-binding SHA-256.

All five values are required, canonical lower-case hexadecimal, and non-zero.
They become part of the canonical stage hash and therefore transitively bind
stage authorization, acceptance receipts, session identity, session lease,
IPC, and supervisor state. Because the canonical shape changed, the stage
authorization schema is `stage-readiness-authorization-v3`; old v2 artifacts
fail closed and must not be rewritten as v3.

## Verification path

For DEMO_AUTO, the signed promotion receipt must match every exact champion
field in the independently selected stage binding. The comparison occurs:

1. before stage authorization can be issued or consumed;
2. when the promotion receipt is independently validated;
3. when the runtime supervisor verifies sealed dispatch controls; and
4. at the executor's initial, reservation-refresh, final-reservation, and
   immediate pre-send checks.

The executor derives expectations only from the exact sealed DEMO_AUTO IPC
stage. It never uses a receipt to choose the expected identity. Missing or
malformed expectations fail with stable field-specific reason codes:

```text
PROMOTION_CHAMPION_ARCHIVE_MISMATCH
PROMOTION_CHAMPION_PACKAGE_MISMATCH
PROMOTION_CHAMPION_SNAPSHOT_MISMATCH
PROMOTION_CHAMPION_TREE_MISMATCH
PROMOTION_CHAMPION_RUNTIME_BINDING_MISMATCH
```

Quality-corpus and bootstrap identity remain covered by the exact signed
promotion-receipt content hash already referenced by the stage request and
permit. They are deliberately not duplicated as caller-controlled execution
inputs.

The Windows composition boundary now also exposes the same five champion pins
as direct required fields of `ProductionRuntimeConfig`. Bootstrap schema v2
compares those independent configuration pins with the exact stage before any
provider or runtime effect while retaining the aggregate stage-hash check.
See `docs/WINDOWS_RUNTIME_STAGE_CHAMPION_CONFIGURATION.md`.

## Validation evidence

- focused runtime/stage cluster: 206 tests pass in normal mode;
- the same 206 tests pass under optimized Python;
- full project regression: 1,775 tests pass with 3 platform skips in each
  normal and optimized mode;
- cross-champion, absent expectation, malformed hash, supervisor substitution,
  session round-trip, and pre-adapter rejection cases are covered.

This is local software evidence only. It is not broker-forward evidence,
Windows provider acceptance, manual-demo acceptance, DEMO_AUTO soak evidence,
or live approval.

## Safety boundary

```text
order_capability = DISABLED
live_allowed = false
safe_to_demo_auto_order = false
promotion_eligible = false
```

No implementation path introduced by this increment initializes MT5, reads a
credential/private key, changes Task Scheduler, accesses a broker, or submits,
modifies, or cancels an order. LIVE validation without a separately configured
exact champion stage fails closed.
