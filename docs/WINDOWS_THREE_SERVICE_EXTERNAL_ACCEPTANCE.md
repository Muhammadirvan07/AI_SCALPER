# Windows Three-Service External Acceptance

This workflow verifies the external evidence that closes the ten blockers in
the Windows three-service operations review. It is a report-only boundary.
Even a complete dossier returns:

```text
EXTERNAL_ACCEPTANCE_COMPLETE_ACTIVATION_REVIEW_REQUIRED
activation_authorized = false
ready_for_demo_auto_soak = false
execution_enabled = false
live_allowed = false
safe_to_demo_auto_order = false
order_capability = DISABLED
max_lot = 0.01
```

A complete result is therefore an input to a separate human activation-release
review. It is not permission to start DEMO_AUTO, access a broker, install a
task, or submit a trade.

## Required public artifacts

Keep all four inputs outside the repository:

1. the exact `windows-three-service-demo-soak-operations-review-bundle-v3`;
2. a public RSA trust policy bound to the plan and review-bundle SHA-256;
3. a signed observations collection containing no more than one observation
   per required gate; and
4. the expected policy SHA-256 obtained through an independent trusted
   channel, not copied from the observations.

The verifier accepts only RSA keys with a 3072–8192-bit odd modulus, exponent
65537, and `RSASSA-PKCS1-v1_5-SHA256`. It has no issuer or signing function.
Secret material remains in the offline acceptance authority and must never
enter the repository, public policy, observation collection, CLI arguments,
or report.

## Canonical gate ownership

| Gate | Required owner role |
|---|---|
| `EXTERNAL_DECISION_EXECUTION_IPC_CUSTODY_REQUIRED` | `IPC_CUSTODY_AUTHORITY` |
| `EXTERNAL_DECISION_FACTORY_PROVIDER_CONFIGURATION_REQUIRED` | `DECISION_SERVICE_OWNER` |
| `EXTERNAL_EXECUTION_FACTORY_PROVIDER_CONFIGURATION_REQUIRED` | `EXECUTION_SERVICE_OWNER` |
| `EXTERNAL_LAUNCHER_ATTESTATIONS_REQUIRED` | `RELEASE_SECURITY_AUTHORITY` |
| `EXTERNAL_MONITOR_OFFHOST_DELIVERY_ACCEPTANCE_REQUIRED` | `MONITOR_OPERATIONS_OWNER` |
| `EXTERNAL_STATUS_MONITOR_CONFIGURED_RELEASE_ACCEPTANCE_REQUIRED` | `STATUS_MONITOR_SERVICE_OWNER` |
| `EXTERNAL_THREE_SERVICE_TASK_INSTALLATION_AND_ACL_ATTESTATION_REQUIRED` | `WINDOWS_SECURITY_AUTHORITY` |
| `MANUAL_DEMO_10_CONTROLLED_ORDERS_REQUIRED` | `MANUAL_DEMO_ACCEPTANCE_AUTHORITY` |
| `WINDOWS_VPS_HARDENING_AND_FAILURE_DRILLS_REQUIRED` | `WINDOWS_OPERATIONS_AUTHORITY` |
| `XAUUSD_MINIMUM_LOT_RISK_FEASIBILITY_REQUIRED` | `RISK_GOVERNOR_OWNER` |

Each observation binds the exact policy, plan, review bundle, three configured
release identities, gate, owner, source-evidence hash, independent
validation-receipt hash, validity interval, authority, public-key fingerprint,
and fixed safety locks. Source evidence and its validation receipt must be
different immutable objects.

This ownership map authenticates who accepted the evidence reference. It does
not replace the independent stage-authorization acceptance domains, two-human
approval, manual-demo checkpoint, promotion receipt, permit, or environment
arm required later by the runtime.

## Pre-manual phase boundary

The full dossier cannot be complete before controlled manual-demo because one
of its gates is the result of those ten lifecycles. Do not fabricate or
pre-approve that result.

`verify_windows_manual_demo_entry_review.py` derives a separate deny-only
pre-run review from the same signed dossier. It requires all nine other gates
to pass and requires the manual-demo result observation to be absent. Its
phase-complete status is
`PRE_MANUAL_DEMO_EXTERNAL_PRECONDITIONS_COMPLETE_ACTIVATION_REVIEW_REQUIRED`;
all execution and activation fields remain false.

See `docs/WINDOWS_MANUAL_DEMO_ENTRY_REVIEW.md`. After ten clean controlled
lifecycles exist, the pre-run verifier must no longer be used; add the
independently accepted result observation and verify the full ten-gate dossier.

## Verification command

Use an independently trusted UTC value with six fractional digits and `Z`:

```powershell
python -B .\verify_windows_three_service_external_acceptance.py `
  --review-bundle C:\AI_SCALPER_PRIVATE\operations\three-service-review-v3.json `
  --trust-policy C:\AI_SCALPER_PRIVATE\operations\external-acceptance-policy.json `
  --observations C:\AI_SCALPER_PRIVATE\operations\external-acceptance-observations.json `
  --expected-policy-sha256 <INDEPENDENTLY_PINNED_POLICY_SHA256> `
  --checked-at-utc 2026-07-24T13:00:00.000000Z `
  --output C:\AI_SCALPER_PRIVATE\operations\external-acceptance-assessment.json
```

The output path is create-only. An existing file, symlink/reparse point,
directory, empty/oversized/unstable input, duplicate JSON key, non-finite
number, schema drift, secret-like field, hash drift, owner drift, duplicate
gate, invalid signature, or clock regression fails closed with exit code `2`.

Exit code `0` means the dossier was assessed successfully; it does not mean
the system is activated. Interpret the `status` field:

- `BLOCKED_EXTERNAL_ACCEPTANCE`: at least one gate is missing, failed,
  future-dated, expired, or expired during verification;
- `EXTERNAL_ACCEPTANCE_COMPLETE_ACTIVATION_REVIEW_REQUIRED`: all ten exact
  observations are current and authenticated, but a separate activation
  review is still mandatory.

## Packaging boundary

The verifier module and CLI are included only in the release-operator tooling
allowlist. They are excluded from decision, execution, external-status-monitor,
and read-only-shadow service releases. The CLI performs no network access,
provider import, broker initialization, service launch, task installation, or
credential lookup.
