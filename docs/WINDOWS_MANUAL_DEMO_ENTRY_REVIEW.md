# Windows Manual-Demo Entry Review

This review closes the phase-ordering gap between Windows external acceptance
and the ten controlled manual-demo lifecycles.

The complete three-service dossier has ten gates. Nine are prerequisites for
the controlled run. The tenth,
`MANUAL_DEMO_10_CONTROLLED_ORDERS_REQUIRED`, is evidence produced by that run
and therefore cannot exist beforehand.

`verify_windows_manual_demo_entry_review.py` verifies the same v3 operations
bundle, pinned public RSA policy, and signed observations as the full external
acceptance verifier. It requests a separate human activation review only when:

- every one of the nine pre-manual gates is accepted;
- the manual-demo result observation is completely absent; and
- the full external dossier truthfully remains incomplete.

It never authorizes manual-demo. Its complete pre-run result still contains:

```text
manual_demo_authorized = false
activation_authorized = false
execution_enabled = false
ready_for_demo_auto_soak = false
safe_to_demo_auto_order = false
live_allowed = false
promotion_eligible = false
order_capability = "DISABLED"
max_lot = 0.01
```

## Required pre-manual gates

The inventory is fixed in source as all canonical external blockers except the
manual-demo result gate:

1. decision/execution IPC custody;
2. decision provider configuration;
3. execution provider configuration;
4. launcher attestations;
5. monitor off-host delivery acceptance;
6. configured status-monitor release acceptance;
7. three Windows task/ACL attestation;
8. Windows hardening and failure drills; and
9. XAUUSD minimum-lot risk feasibility.

The caller cannot add, omit, or rename a gate.

## Verification command

Use the same immutable artifacts as the full dossier, but supply only signed
observations for the nine pre-manual gates:

```powershell
python -B .\verify_windows_manual_demo_entry_review.py `
  --review-bundle C:\AI_SCALPER_PRIVATE\operations\three-service-review-v3.json `
  --trust-policy C:\AI_SCALPER_PRIVATE\operations\external-acceptance-policy.json `
  --observations C:\AI_SCALPER_PRIVATE\operations\pre-manual-observations.json `
  --expected-policy-sha256 <INDEPENDENTLY_PINNED_POLICY_SHA256> `
  --checked-at-utc <TRUSTED_CANONICAL_UTC> `
  --output C:\AI_SCALPER_PRIVATE\operations\manual-demo-entry-review.json
```

The only phase-complete status is:

```text
PRE_MANUAL_DEMO_EXTERNAL_PRECONDITIONS_COMPLETE_ACTIVATION_REVIEW_REQUIRED
```

This means an independent human may review whether to issue the separate,
short-lived MANUAL_DEMO stage evidence. It is not itself a stage
authorization, per-intent approval, permit, environment arm, task install
permission, or broker capability.

If any pre-manual evidence is missing, failed, future, expired, or expires
during verification, the status remains:

```text
BLOCKED_PRE_MANUAL_DEMO_EXTERNAL_PRECONDITIONS
```

Any observation for the manual-demo result gate is rejected at this boundary,
including failed or expired observations. After the ten lifecycles have run,
use the full external-acceptance verifier instead.

## Controlled-run requirements

Every one of the ten lifecycles still requires:

- startup-only stage-readiness authorization;
- separate signed human approval for the exact intent;
- the one-second process environment arm;
- signed news and rollover guard;
- broker-native risk and margin calculation;
- account-wide position fence;
- journal idempotency;
- broker preflight;
- confirmed server-side SL/TP; and
- reconciliation plus external monitor acknowledgement.

The signed manual-demo tracker, not this review, records lifecycle outcomes.
After ten clean completed lifecycles, the manual-demo acceptance authority may
produce the tenth external observation. The full dossier must then be verified
before any DEMO_AUTO activation release is reviewed.
