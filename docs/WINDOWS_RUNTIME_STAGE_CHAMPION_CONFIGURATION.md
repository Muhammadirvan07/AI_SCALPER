# Windows Runtime Stage Champion Configuration

Status: **IMPLEMENTED LOCALLY / DENY-ONLY / NOT AN ACTIVATION**

## Outcome

The Windows production bootstrap now requires the five exact champion
identities already carried by `StageBinding` v3:

- champion archive SHA-256;
- champion package identity SHA-256;
- champion training-snapshot SHA-256;
- champion Git tree; and
- champion runtime-binding SHA-256.

These are direct scalar fields of `ProductionRuntimeConfig`, are included in
its reviewed configuration payload, and therefore change
`safe_binding_sha256`. The production-bootstrap schema is now
`windows-production-bootstrap-v2`; v1 configuration objects are not silently
upgraded.

## Fail-closed boundary

Static bootstrap validation compares all five configuration pins with the
separately supplied exact `ProductionRuntimePorts.stage_binding`, in addition
to the existing aggregate `stage_binding_sha256` check. Missing, zero,
malformed, or mismatched values fail before any external provider, SQLite
database, credential, MT5 module, network sender, or execution adapter is
used.

The implementation deliberately keeps both layers:

1. the aggregate stage hash protects the complete canonical stage; and
2. the explicit champion pins make the reviewed Windows configuration's
   expected lineage independently visible and auditable.

No receipt is allowed to choose these expected values.

## Validation evidence

- specification validator: 100/100, Grade A, no warnings;
- production-bootstrap and Windows Execution integration cluster: 49 tests in
  normal mode and 49 under optimized Python;
- invalid, zero, upper-case, cross-champion, and aggregate-stage mismatch
  behavior is covered before effects.

Complete-regression counts are recorded in the project progress and ship-gate
audit after the exact increment is finalized.

## Safety state

```text
order_capability = DISABLED
live_allowed = false
safe_to_demo_auto_order = false
promotion_eligible = false
```

This increment does not implement or accept external Windows provider hooks,
does not approve a champion, and does not provision credentials, launcher
trust, Task Scheduler, MT5, manual-demo orders, DEMO_AUTO soak, or LIVE
trading.
