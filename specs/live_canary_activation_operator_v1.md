# Spec: LIVE Canary Activation Operator V1

**Author:** Codex with AI_SCALPER project owner

**Date:** 2026-07-30

**Status:** Approved for implementation

**Reviewers:** project owner, security boundary, risk, operations, compliance,
ship-gate

**Related specs:** `live_canary_activation_evidence_v1.md`,
`live_canary_gate_receipt_operator_v1.md`,
`live_canary_broker_eligibility_review_v1.md`

## Context

The activation core already verifies an exact demo-auto soak cohort, LIVE
promotion receipt, broker eligibility evidence, nine external gate receipts,
three distinct human approvals, and a separate deployment authority. Today,
those request, approval, and authorization objects can only be assembled in
memory through Python APIs and tests. A Windows operator cannot reconstruct the
sealed source artifacts, re-verify all evidence, create canonical files, or
independently verify the complete approval chain.

This feature adds that missing offline operator bridge. It does not consume an
authorization, create a replay registry, change the checked-in central lock,
initialize MT5, materialize a production factory, or submit an order. Request,
approval, and authorization artifacts remain deny-only inputs to the existing
one-use runtime verifier.

## Functional Requirements

- FR-1: Strict loaders MUST reconstruct exact `DemoAutoSoakCohortBinding`,
  sealed `DemoAutoSoakCohortReceipt`, `PromotionEvidenceReceipt`,
  `LiveCanaryActivationRequest`, `LiveCanaryHumanApproval`, and
  `LiveCanaryActivationAuthorization` objects from canonical JSON.
- FR-2: Loaders MUST reject extra, missing, duplicate, non-finite,
  non-canonical, wrong-typed, malformed nested, BOM-prefixed, or non-object
  JSON before credential access.
- FR-3: Every input MUST be a bounded regular non-symlink/non-reparse file and
  MUST remain the same inode/file identity, size, and bytes throughout the
  read.
- FR-4: Request assembly MUST use the existing activation-core request builder
  and MUST re-verify the exact signed cohort receipt against its binding and
  policy-pinned aggregator key.
- FR-5: Request assembly MUST re-verify the exact signed LIVE promotion
  receipt, signer key ID/fingerprint, LIVE account alias hash, broker server,
  lane, release, model, and champion lineage.
- FR-6: Request assembly MUST re-verify the exact broker-eligibility review
  from its regulatory observation and distinct diagnostic/LIVE reviewer keys.
- FR-7: Request assembly MUST independently verify one canonical nine-domain
  gate-receipt set against the eight original non-legal source files and exact
  eligibility evidence.
- FR-8: `LEGAL_COMPLIANCE` gate evidence MUST equal the exact re-verified
  broker-eligibility content hash. No caller-supplied replacement hash is
  accepted.
- FR-9: Every child receipt and eligibility window MUST cover the complete
  request window. The request MUST be current and no longer than five minutes.
- FR-10: Request assembly MUST derive issuance time from an injected trusted
  clock and accept only a caller-pinned expiry and nonce. A caller-supplied
  issuance time is forbidden in the CLI.
- FR-11: Independent request verification MUST re-run all source validation,
  rebuild the request with its persisted issuance, expiry, and nonce, and
  compare the complete canonical object and content hash.
- FR-12: Human approval signing MUST require exactly one policy role from
  `RISK_OWNER`, `OPERATIONS_OWNER`, or `COMPLIANCE_OWNER`, the real approver
  identity, and the exact policy-pinned key.
- FR-13: Approval key ID and fingerprint MUST be derived from the trust policy;
  the CLI MUST NOT accept caller-selected authority identity or raw secret
  material.
- FR-14: Approval signing MUST hash the normalized approver identity, require
  the exact policy identity hash, bind the exact request hash, and use a
  trusted approval time inside the request window.
- FR-15: Independent approval verification MUST compare the exact request,
  role, policy identity/key/fingerprint, time, and HMAC using constant-time
  comparison.
- FR-16: Authorization assembly MUST require exactly three canonical approval
  files, one per role, with three different identities, key IDs, fingerprints,
  and observed secrets.
- FR-17: Authorization assembly MUST independently verify all three approvals,
  derive the deployment key from the trust policy, and sign only after the
  latest approval using the trusted clock inside the request window.
- FR-18: The deployment authority MUST be distinct from promotion, all nine
  gate, all three approval, and replay-checkpoint authorities as already
  enforced by the trust-policy contract.
- FR-19: Independent authorization verification MUST reconstruct the embedded
  request and approvals, compare them byte-semantically with the supplied
  source files, re-verify all approval signatures, and verify the deployment
  HMAC and trusted time window.
- FR-20: Request, approval, and authorization writes MUST use create-exclusive,
  fsync-backed publication and MUST never overwrite or remove a pre-existing
  path.
- FR-21: Signing keys MUST come only from an injected provider in library code
  and Windows Credential Manager in CLIs. Secret bytes MUST never be accepted
  as an argument, environment variable, JSON field, file input, or output.
- FR-22: Every successful and failed CLI invocation MUST report
  `Live allowed: false`, `Order capability: DISABLED`, and
  `Broker mutation: NOT_PERFORMED`.
- FR-23: CLI failure MUST return exit code 2 with a deterministic operation
  prefix and MUST leave no partial destination.
- FR-24: The feature MUST NOT consume/replay an authorization, create a
  capability, set `LIVE_ALLOWED`, change central policy, access network, launch
  a service/process, install a task, initialize MT5, or call a broker API.
- FR-25: Operator modules and CLIs MUST be packaged only in
  `WINDOWS_SHADOW_DEPLOYMENT_TOOLING_V1`; they MUST be absent from Decision,
  Execution, Status Monitor, read-only shadow, and configured-service releases.
- FR-26: Existing activation schemas, canonical hashes, HMAC domains, runtime
  verifier behavior, and service-release bytes outside the explicit operator
  allowlist change MUST remain compatible.

## Non-Functional Requirements

- NFR-S1: HMAC, hash, fingerprint, and canonical-object identity comparisons
  MUST use constant-time comparison where secret-dependent or attacker
  controlled.
- NFR-S2: Every authority key MUST contain at least 256 bits and match its
  policy-pinned SHA-256 fingerprint.
- NFR-S3: Exact base-class checks MUST reject subclasses and duck types at
  trust boundaries.
- NFR-S4: All output capability flags MUST remain false and `max_lot` MUST
  remain `0.01` with one-position scope.
- NFR-R1: A failed read, validation, key access, or write MUST be fail-closed
  and leave source files unchanged.
- NFR-R2: Re-running against an existing output MUST fail instead of replacing
  historical evidence.
- NFR-P1: A bounded in-memory approval or authorization issue/verify operation
  MUST average below 100 ms in focused tests.
- NFR-C1: The implementation MUST support Python 3.12 normal and `-O` modes,
  use existing project dependencies only, and preserve deterministic Windows
  release construction.
- NFR-O1: Output MUST name the artifact hash, request/authorization identity,
  role or signer key ID as applicable, while explicitly reporting that secret
  material was not exported.

## Acceptance Criteria

### AC-1: Strict source reconstruction (FR-1, FR-2, FR-3)

Given canonical cohort binding/receipt, promotion receipt, request, approvals,
and authorization files
When each loader reads the artifact
Then it reconstructs the exact sealed/base contract and identical canonical
hash
And any field, encoding, nesting, link, replacement, or canonical-byte drift
fails before credential access.

### AC-2: Complete request assembly (FR-4, FR-5, FR-6, FR-7, FR-8, FR-9, FR-10)

Given an authentic current qualifying cohort, LIVE promotion, verified broker
eligibility, exact binding/policy, nine gate receipts, and all original sources
When the Windows operator assembles a request
Then every source and signature is re-verified through existing core APIs
And one current canonical request is written with no execution capability.

### AC-3: Independent request verification (FR-7, FR-8, FR-9, FR-11)

Given a persisted request and all original source artifacts
When a separate verifier runs at a trusted time
Then it rebuilds the same complete request and verifies an identical content
hash
And any source, receipt, key, identity, policy, time, or nested hash mutation
fails closed.

### AC-4: Role-bound human approval (FR-12, FR-13, FR-14, FR-15)

Given a verified current request, trust policy, one exact role, actual approver
identity, and its policy-pinned Credential Manager key
When the role signer runs
Then it emits one canonical HMAC approval bound to that request
And a wrong role, identity, key, time, request, or signature is rejected.

### AC-5: Three-person separation (FR-16, FR-18)

Given three role approval files
When authorization assembly verifies them
Then the roles, identities, key IDs, fingerprints, and observed keys are all
exact and distinct
And omission, duplication, reuse, substitution, subclassing, or extra approval
fails before deployment-key access.

### AC-6: Deployment authorization (FR-17, FR-19)

Given one current request, three verified approvals, and the separate
policy-pinned deployment key
When authorization assembly and independent verification run
Then the embedded request/approvals and deployment HMAC verify exactly
And the result remains deny-only and cannot itself authorize an order.

### AC-7: Exclusive persistence and safe CLI behavior (FR-20, FR-21, FR-22, FR-23)

Given an existing output, malformed input, unavailable credential, wrong key,
or injected write failure
When any CLI runs
Then it exits 2, preserves every existing byte, leaves no partial artifact,
prints no secret, and reports the locked safety state.

### AC-8: No runtime effect or release leakage (FR-24, FR-25, FR-26)

Given static import inspection, CLI help/success/failure runs, and every Windows
release build
When the feature is audited
Then no forbidden effect occurs, only the operator bundle contains the tooling,
service bundles remain free of the operator surface, and repeated operator
builds are byte-identical.

### AC-9: Performance and optimized regression (NFR-P1, NFR-C1)

Given bounded valid fixtures
When approval/authorization issue and verification are measured and the focused
suite runs normally and under `-O`
Then the latency target is met and all normal/optimized tests pass.

## Edge Cases and Error Scenarios

- EC-1: A cohort receipt with a valid-looking HMAC but without the module seal,
  an incomplete member snapshot, inconsistent fill totals, or stale five-minute
  window is rejected.
- EC-2: A promotion receipt for DEMO_AUTO, another account/server/lane/build,
  a stale window, or a non-policy key is rejected.
- EC-3: Eligibility or any gate expires one microsecond before request expiry;
  request assembly fails.
- EC-4: The gate set is structurally valid but one original evidence file has
  changed; request assembly fails.
- EC-5: Caller expiry is equal to issuance, beyond five minutes, already past,
  or too close for child validity; request assembly fails.
- EC-6: Trusted clock and asserted operation time differ by more than the core
  tolerance; the operation fails.
- EC-7: Approval identity differs by whitespace/case, role is lowercase, key is
  absent, or approval occurs exactly at request expiry; approval fails.
- EC-8: Two approvals reuse an identity, key ID, fingerprint, or actual secret;
  authorization assembly fails.
- EC-9: Deployment signing occurs before the latest approval, at expiry, with
  an approval key, or with a key whose bytes differ from the pinned
  fingerprint; authorization fails.
- EC-10: Embedded authorization request or approval differs from the supplied
  source file while retaining valid standalone structure; independent
  verification fails.
- EC-11: Duplicate JSON keys, NaN/Infinity, invalid UTF-8, BOM, extra newline,
  offset timestamp, uppercase hash, boolean-as-integer, or unknown schema fails.
- EC-12: Existing destination, symlink/reparse destination, or concurrent
  creator wins; the operation preserves the winning bytes and fails closed.

## API Contracts

```python
load_demo_auto_soak_cohort_binding_artifact(path) -> DemoAutoSoakCohortBinding
load_demo_auto_soak_cohort_receipt_artifact(path) -> DemoAutoSoakCohortReceipt
load_promotion_evidence_receipt_artifact(path) -> PromotionEvidenceReceipt
load_live_canary_activation_request_artifact(path) -> LiveCanaryActivationRequest
load_live_canary_human_approval_artifact(path) -> LiveCanaryHumanApproval
load_live_canary_activation_authorization_artifact(path) -> LiveCanaryActivationAuthorization
assemble_live_canary_activation_request_artifact(...) -> LiveCanaryActivationRequest
verify_live_canary_activation_request_artifact(...) -> LiveCanaryActivationRequest
issue_live_canary_human_approval_artifact(...) -> LiveCanaryHumanApproval
verify_live_canary_human_approval_artifact(...) -> LiveCanaryHumanApproval
assemble_live_canary_activation_authorization_artifact(...) -> LiveCanaryActivationAuthorization
verify_live_canary_activation_authorization_artifact(...) -> LiveCanaryActivationAuthorization
write_live_canary_activation_artifact_exclusive(path, payload) -> Path
```

```typescript
interface LiveCanaryActivationOperatorResultV1 {
  schemaVersion:
    | "live-canary-activation-request-v2"
    | "live-canary-human-approval-v1"
    | "live-canary-authorization-v1";
  contentSha256: Sha256;
  liveAllowed: false;
  executionAuthorized?: false;
  activationAuthorized?: false;
  orderCapability?: "DISABLED";
}
```

The TypeScript interface documents displayed operator state only. `POST
/internal/live-canary/activation` is a reserved negative sentinel and MUST NOT
be registered. No HTTP, WebSocket, dashboard mutation, order, or activation
endpoint is added.

## Data Models

### Request source set

| Source | Required verification | Bound request claim |
|---|---|---|
| cohort binding + sealed receipt | exact binding, HMAC, freshness, 30 days, 50 fills, 20 XAU fills | cohort receipt hash |
| LIVE promotion receipt | policy key, account/server/lane/build/champion, freshness | receipt and stable validation hashes |
| eligibility review + regulatory observation | diagnostic and new LIVE legal/compliance signatures, broker/server/XAU scope | eligibility content hash |
| nine-domain gate set + eight source files | policy keys, source bytes, legal eligibility, full request window | sorted domain-to-receipt hashes |
| activation binding + trust policy | exact canonical identities and policy hash | embedded binding |

### Human approval

| Field | Type | Constraint |
|---|---|---|
| request hash | SHA-256 | exact current activation request |
| role | enum | one of three policy roles |
| approver identity hash | SHA-256 | exact policy-pinned real identity |
| key ID/fingerprint | canonical ID/SHA-256 | exact role key, distinct globally |
| approved time | UTC | inside request window |
| signature | HMAC-SHA256 | domain-separated existing core signature |

### Deployment authorization

| Field | Type | Constraint |
|---|---|---|
| request | canonical object | exact verified request |
| approvals | three canonical objects | sorted exact roles and separated authorities |
| deployment key | ID/fingerprint | exact separate policy authority |
| issued time | UTC | after all approvals and inside request window |
| signature | HMAC-SHA256 | existing deployment domain |
| capability state | constants | live/execution/activation false; order disabled; lot 0.01; one position |

## Dependencies

- Existing canonical contracts and activation-core verification functions.
- Existing gate-receipt set verifier and broker-eligibility verifier.
- Windows Credential Manager through `WindowsEvidenceKeyStore`.
- Existing create-exclusive secure JSON writer.
- No new package, network provider, database, MT5, scheduler, or service
  dependency.

## Observability

- Success output identifies artifact kind, content hash, request or
  authorization ID, role/key identity when applicable, and destination.
- Failure output uses operation-specific blocked codes and repeats the locked
  capability state.
- Every invocation states `Secret material: NOT_EXPORTED` when a key was read.
- No log or exception includes secret bytes, account credentials, or an
  unredacted broker login.

## Migration and Rollback

- The change is additive. Existing in-memory APIs and activation schemas remain
  authoritative and unchanged.
- Rollback removes the new operator CLIs/modules from the operator allowlist;
  existing artifacts remain historical evidence but are not consumed.
- No database migration, task mutation, service restart, policy change, or
  broker action is part of deployment.
- A partially completed approval ceremony is abandoned by retaining its files
  and issuing a new request/approval set; files are never overwritten.

## Out of Scope

- OS-1: Creating, guessing, or approving the LIVE account/server, trust policy,
  authority identities, evidence sources, or reviewer decisions.
- OS-2: Provisioning authority keys whose fingerprints are not already pinned
  by an independently reviewed policy.
- OS-3: Running or shortening the real 30-day/50-fill/20-XAU demo-auto soak.
- OS-4: Issuing the independent LIVE promotion or nine external gate evidence
  decisions.
- OS-5: Consuming the authorization, creating/updating the replay registry or
  off-host checkpoint, changing central unlock, materializing a factory,
  starting a service, initializing MT5, or sending an order.
- OS-6: Treating a locally successful ceremony, fixture, screenshot, log, or
  canonical file as independent external acceptance or live-trading approval.

## Definition of Done

- All nine acceptance criteria pass normally and under `-O`.
- Strict spec validation scores 100/100 with no errors or warnings.
- Focused loaders, artifact functions, CLIs, tamper/failure tests, release
  isolation tests, and full Python regression pass.
- Two clean operator release builds are byte-identical and independently
  verify while all service releases exclude the new operator surface.
- Documentation states that real evidence and central unlock remain required;
  no source or output claims that LIVE trading is ready.
