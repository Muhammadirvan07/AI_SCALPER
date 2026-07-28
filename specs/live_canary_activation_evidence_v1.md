# Live Canary Activation Evidence Boundary v1

**Author:** Codex with the AI_SCALPER project owner
**Date:** 2026-07-29
**Status:** Approved for implementation
**Approval basis:** the project owner's standing instruction to continue the
live-grade implementation without repeated approval prompts; this approval is
limited to the deny-only source boundary defined here and grants no broker
authority.
**Review domains:** architecture, execution safety, security, ship gate
**Related specifications:**
`live_grade_readiness_gate_catalog_v1.md`,
`mode_aware_execution_symbol_policy_v1.md`,
`demo_auto_soak_cohort_v1.md`,
`runtime_stage_champion_binding_v1.md`, and
`production_runtime_supervisor_v1.md`.

## Context

The current source has a real MT5 execution coordinator and a dormant XAUUSD
`LIVE` symbol scope, but the Windows production composition explicitly rejects
`LIVE`. This is correct while the demo-auto soak and external approvals are
missing, but it also means there is no cryptographic handoff that a future
reviewed live release can consume after those gates are complete.

The existing demo-auto cohort receipt proves the minimum 30 clean days, 50
broker-reconciled closed fills, and 20 XAUUSD closed fills without granting
promotion. The existing LIVE promotion receipt binds model quality and champion
lineage. Neither object alone proves that the exact live account, Windows host,
failure drills, custody, rollback, compliance, and human owners were reviewed.

This feature supplies that missing handoff as a short-lived, replay-protected,
deny-only evidence boundary. It is broker-neutral at the source level so the
first reviewed candidate can be XM, but every request binds one exact broker,
demo account, live account, server pair, XAUUSD lane, release, model, and
journal. It does not enable `LIVE_ALLOWED`, initialize MT5, or submit an order.

## Functional Requirements

- FR-1: The system MUST represent one immutable `LiveCanaryBinding` that
  binds the exact broker identity, demo account/server/journal/build, live
  account/server/journal/build, XAUUSD lane, dependency lock, broker
  specification, session calendar, runtime/release identities, model, and all
  five champion lineage pins.
- FR-2: The binding MUST restrict the first live canary to `XAUUSD`, one
  live account, one concurrent position, and exactly `0.01` lot.
- FR-3: A request MUST be constructible only from an exact, HMAC-verified,
  fresh `DemoAutoSoakCohortReceipt` whose binding matches the declared demo
  side and whose 30-day, 50-fill, 20-XAU, non-reset criteria are all met.
- FR-4: A request MUST be constructible only from an exact, independently
  verified `PromotionEvidenceValidation` for mode `LIVE` whose live account,
  server, journal, lane, build, model, and champion lineage match the binding.
- FR-5: The request MUST include one independently signed gate receipt for
  each exact domain: `LIVE_BROKER_ACCOUNT`, `WINDOWS_HOST`, `SECURITY`,
  `FAILURE_DRILL`, `WORM_CUSTODY`, `BACKUP_RESTORE`, `LEGAL_COMPLIANCE`,
  `OPERATIONAL_ROLLBACK`, and `SINGLE_ACCOUNT_SCOPE`.
- FR-6: A `LiveCanaryTrustPolicy` MUST bind the exact allowed key ID and
  SHA-256 key fingerprint for every gate domain, the LIVE promotion signer,
  each role-bound human approver, the deployment signer, and the off-host
  replay-checkpoint signer. Key IDs and key material MUST NOT be reused across
  any of these authorities.
- FR-7: Every gate receipt MUST bind the request binding, one evidence
  object hash, a validity window, issuer/key identity, and immutable deny-only
  safety fields. A missing, stale, future, malformed, untrusted, mismatched, or
  incorrectly signed receipt MUST fail closed.
- FR-8: An authorization MUST contain exactly three policy-pinned signed human
  approvals with roles `RISK_OWNER`, `OPERATIONS_OWNER`, and
  `COMPLIANCE_OWNER`. Approver identity hashes, key IDs, and key material MUST
  all be distinct and MUST match their exact role entries in the trust policy.
- FR-9: A separate deployment authority MUST sign the complete request and
  approval set. Its key ID and key material MUST be distinct from every gate
  and human approval key.
- FR-10: Request, approval, authorization, and validation windows MUST use
  canonical UTC and MUST NOT exceed five minutes. Validation MUST use an
  injected trusted clock and MUST reject caller time drift above 50 ms.
- FR-11: A valid authorization MUST be consumed exactly once through a
  durable, HMAC-authenticated SQLite replay registry bound to one registry ID,
  key ID, key fingerprint, trust policy, and live-canary binding. The registry
  MUST produce and verify a separately signed off-host high-water checkpoint.
- FR-12: Replay-registry exact DDL, identity, event ordering, predecessor
  HMAC, row HMAC, SQLite integrity, immutable trigger definitions, and any
  supplied off-host checkpoint prefix MUST be verified before consumption.
  Replay, rollback below a checkpoint, forked checkpoint prefix, schema drift,
  same-name trigger substitution, or storage failure MUST fail closed.
- FR-13: Every public artifact and validation result MUST retain
  `live_allowed=false`, `safe_to_demo_auto_order=false`,
  `execution_authorized=false`, `activation_authorized=false`,
  `order_capability=DISABLED`, `max_lot=0.01`, and
  `max_concurrent_positions=1`.
- FR-14: The module MUST have no MT5 import, credential lookup, network
  access, task/service mutation, process launch, environment-arm minting,
  permit issuance, or broker order call.
- FR-15: Canonical JSON and SHA-256 identities MUST make any field,
  inventory, approval, evidence, policy, or signature substitution observable.
- FR-16: This validation MAY become an input to a later, separately
  reviewed LIVE composition; it MUST NOT be interpreted as execution authority
  without the central release lock and every runtime control.

## Non-Functional Requirements

- NFR-S1: Verification MUST fail closed on every exception from a key,
  clock, evidence, or replay provider.
- NFR-S2: Raw account logins, passwords, human names, emails, secret key
  material, or environment-arm tokens MUST NOT appear in canonical artifacts,
  exceptions, or logs.
- NFR-S3: HMAC keys MUST contain at least 32 bytes and MUST match their
  independently pinned SHA-256 fingerprints.
- NFR-R1: Replay consumption MUST be atomic under `BEGIN IMMEDIATE`; two
  concurrent consumers of one authorization MUST produce exactly one success.
- NFR-R2: SQLite MUST use WAL, `synchronous=FULL`, and an exact DDL inventory;
  append rows and identity state MUST be protected from update and delete.
- NFR-P1: In-memory validation excluding SQLite lock wait MUST complete in
  under 100 ms in the focused unit benchmark on the development host.
- NFR-C1: The implementation MUST support CPython 3.12 and MUST pass under
  normal and `-O` optimized execution.
- NFR-T1: Every acceptance criterion and edge case MUST have automated
  regression coverage.

## Acceptance Criteria

### AC-1: Exact eligible request (FR-1, FR-2, FR-3, FR-4, FR-5, FR-6, FR-7, FR-13)

Given an exact XAUUSD binding, a fresh authenticated cohort receipt meeting all
three soak thresholds, a valid LIVE promotion validation, and nine trusted gate
receipts
When the request builder validates the evidence
Then it returns one canonical request bound to every exact evidence hash
And every trading capability field remains disabled.

### AC-2: Soak evidence rejection (FR-3, NFR-S1)

Given a cohort receipt that is stale, signed by the wrong key, bound to another
account/build, reset-required, below 30 days, below 50 fills, or below 20 XAU
fills
When request construction runs
Then construction fails with a deterministic soak-evidence error
And no request or replay event is created.

### AC-3: LIVE promotion binding (FR-4, NFR-S1)

Given promotion evidence that is invalid, expired, mode `DEMO_AUTO`, or differs
in any live account/server/journal/lane/build/model/champion field
When request construction runs
Then construction fails closed
And no request is returned.

### AC-4: External gate policy (FR-5, FR-6, FR-7, NFR-S3)

Given nine gate receipts
When one domain is absent, duplicated, stale, future-dated, mismatched,
untrusted, signed by a reused key, or has modified evidence bytes
Then request construction fails closed.

### AC-5: Human and deployment approvals (FR-8, FR-9, FR-10, NFR-S3)

Given one valid request
When exactly three distinct role-bound approvals and a distinct deployment
authority sign within the request window
Then one canonical deny-only authorization is produced
And any missing role, duplicate human/key material, bad signature, or time
mismatch is rejected.

### AC-6: One-use validation (FR-10, FR-11, FR-12, FR-13, NFR-R1, NFR-R2)

Given one valid authorization and an intact empty replay registry
When validation is attempted twice or concurrently
Then exactly one attempt returns `valid=true` and `consumed_once=true`
And every later attempt returns `LIVE_CANARY_AUTHORIZATION_REPLAYED` without
broker or process effects.

### AC-7: Tamper and storage failure (FR-12, FR-15, NFR-S1, NFR-R2)

Given a valid authorization and a retained signed high-water checkpoint
When its request, approval, policy, signature, replay identity, event chain,
schema, trigger definition, checkpoint prefix, or SQLite integrity is altered,
or storage raises an error
Then validation raises or returns a deterministic fail-closed result
And never reports execution or activation authority.

### AC-8: Static side-effect boundary (FR-13, FR-14, FR-16)

Given module import, request construction, authorization issuance, validation,
and optimized test execution
When all code paths are inspected and exercised
Then no MT5, credential, network, task, process, permit, environment-arm, or
broker mutation primitive is imported or called
And the checked-in `execution_policy.LIVE_ALLOWED` remains exactly false.

### AC-9: Performance and compatibility (NFR-P1, NFR-C1, NFR-T1)

Given valid in-memory evidence
When validation is measured and the focused suite runs normally and with `-O`

Then in-memory validation completes within 100 ms
And all focused tests pass in both modes.

## Edge Cases and Error Scenarios

- EC-1: Non-text/empty identifiers, uppercase/lowercase hash drift, zero
  hashes, malformed commit/tree hashes, non-UTC timestamps, NaN lot values, or
  boolean-as-integer values are rejected during construction.
- EC-2: A policy with extra/missing domains, duplicate keys, duplicate
  fingerprints, or a policy hash that differs from the binding is rejected.
- EC-3: A gate key provider that raises, returns the wrong type, returns
  fewer than 32 bytes, or returns material with the wrong fingerprint fails
  closed.
- EC-4: The trusted clock provider raising, returning non-UTC, moving
  backwards, or disagreeing with an asserted time by more than 50 ms fails
  closed.
- EC-5: A request issued before its evidence or expiring after any child
  receipt is rejected.
- EC-6: Approval roles with the same person, key ID, fingerprint, or key
  bytes are rejected even when all individual signatures are valid.
- EC-7: A deployment signer reusing any gate or approval key is rejected.
- EC-8: A symlink, non-regular replay database, unexpected parent, locked
  database, corrupt page, missing trigger, schema drift, or replacement store
  fails closed and is never deleted by the verifier.
- EC-9: Two processes racing to consume the same authorization yield one
  durable event and no duplicate success.
- EC-10: A registry below an independently signed checkpoint count or with a
  rewritten checkpoint prefix is rejected as rollback/fork evidence.
- EC-11: Evidence for EURUSD, multiple accounts, lot above/below 0.01, or
  more than one concurrent position is rejected.

## API Contracts

```typescript
interface LiveCanaryBinding {
  brokerId: string;
  demoAccountAliasSha256: Sha256;
  demoServer: string;
  demoJournalSha256: Sha256;
  demoCommitSha: GitCommit;
  demoConfigSha256: Sha256;
  demoDependencyLockSha256: Sha256;
  demoRuntimeProfileSha256: Sha256;
  demoReleaseManifestSha256: Sha256;
  demoSessionCalendarSha256: Sha256;
  demoBrokerSpecSetSha256: Sha256;
  soakCohortBindingSha256: Sha256;
  liveAccountAliasSha256: Sha256;
  liveServer: string;
  liveJournalSha256: Sha256;
  liveCommitSha: GitCommit;
  liveConfigSha256: Sha256;
  liveDependencyLockSha256: Sha256;
  liveBrokerSpecSha256: Sha256;
  liveSessionCalendarSha256: Sha256;
  liveRuntimeProfileSha256: Sha256;
  liveReleaseManifestSha256: Sha256;
  modelArtifactSha256: Sha256;
  championArchiveSha256: Sha256;
  championPackageIdentitySha256: Sha256;
  championTrainingSnapshotSha256: Sha256;
  championGitTree: GitTree;
  championRuntimeBindingSha256: Sha256;
  acceptancePolicySha256: Sha256;
  environment: "LIVE";
  symbol: "XAUUSD";
  maxLot: 0.01;
  maxConcurrentPositions: 1;
}

interface LiveCanaryGateReceipt {
  domain: LiveCanaryGateDomain;
  bindingSha256: Sha256;
  evidenceSha256: Sha256;
  issuedAt: UtcDateTime;
  expiresAt: UtcDateTime;
  issuerId: string;
  keyId: string;
  keyFingerprintSha256: Sha256;
  signatureHmacSha256: Sha256;
  liveAllowed: false;
  orderCapability: "DISABLED";
}

interface LiveCanaryTrustPolicy {
  domainKeyAllowlist: ReadonlyArray<[LiveCanaryGateDomain, string, Sha256]>;
  promotionKeyId: string;
  promotionKeyFingerprintSha256: Sha256;
  approvalKeyAllowlist: ReadonlyArray<
    [ApprovalRole, Sha256, string, Sha256]
  >;
  deploymentKeyId: string;
  deploymentKeyFingerprintSha256: Sha256;
  replayCheckpointKeyId: string;
  replayCheckpointKeyFingerprintSha256: Sha256;
}

interface LiveCanaryActivationRequest {
  binding: LiveCanaryBinding;
  soakCohortReceiptSha256: Sha256;
  livePromotionValidationSha256: Sha256;
  gateReceiptSha256ByDomain: ReadonlyArray<[LiveCanaryGateDomain, Sha256]>;
  issuedAt: UtcDateTime;
  expiresAt: UtcDateTime;
  nonce: string;
}

interface LiveCanaryActivationAuthorization {
  request: LiveCanaryActivationRequest;
  approvals: readonly [RiskApproval, OperationsApproval, ComplianceApproval];
  deploymentSignerKeyId: string;
  deploymentSignerKeyFingerprintSha256: Sha256;
  signatureHmacSha256: Sha256;
  liveAllowed: false;
  executionAuthorized: false;
  orderCapability: "DISABLED";
}

interface LiveCanaryActivationValidation {
  valid: boolean;
  reasonCodes: readonly string[];
  authorizationSha256: Sha256;
  bindingSha256: Sha256;
  consumedOnce: boolean;
  liveAllowed: false;
  executionAuthorized: false;
  activationAuthorized: false;
  orderCapability: "DISABLED";
}
```

Python entry points:

```python
build_live_canary_activation_request(...) -> LiveCanaryActivationRequest
issue_live_canary_activation_authorization(...) -> LiveCanaryActivationAuthorization
validate_and_consume_live_canary_activation(...) -> LiveCanaryActivationValidation
LiveCanaryReplayRegistry(
    path, binding, trust_policy, registry_id, key_id, key_provider,
    expected_checkpoint=None, checkpoint_key_provider=None,
)
LiveCanaryReplayRegistry.create_checkpoint(...) -> LiveCanaryReplayCheckpoint
LiveCanaryReplayRegistry.verify_checkpoint(...) -> LiveCanaryReplayCheckpoint
```

All failures use `LiveCanaryActivationError` or its integrity/binding/replay
subclasses. No function returns or accepts raw secrets in a serializable model.
HTTP method/path: N/A — this is a local Python verification API and exposes no
HTTP route. Reserved, non-implemented mapping for a future reviewed adapter:
`POST /internal/live-canary/activation`; v1 does not register that route.

## Data Models

### LiveCanaryReplayIdentity

| Field | Type | Constraints |
|---|---|---|
| singleton | integer | Primary key, exact value 1 |
| schema_version | text | Exact v1 schema |
| registry_id | text | Non-empty canonical identifier |
| binding_sha256 | text | Exact non-zero SHA-256 |
| key_id | text | Exact reviewed key ID |
| key_fingerprint_sha256 | text | Exact independent pin |
| identity_hmac_sha256 | text | HMAC over every preceding field |

### LiveCanaryReplayEvent

| Field | Type | Constraints |
|---|---|---|
| sequence | integer | Primary key, contiguous from 1 |
| authorization_id | text | Unique |
| authorization_sha256 | text | Unique exact SHA-256 |
| request_sha256 | text | Unique exact SHA-256 |
| nonce_sha256 | text | Unique exact SHA-256 |
| consumed_at_utc | text | Canonical UTC |
| previous_event_hmac_sha256 | text | Zero hash at genesis, prior head thereafter |
| event_hmac_sha256 | text | Unique HMAC of the complete row projection |

The database is local NTFS/POSIX storage, not a network share. This module
creates and verifies a signed high-water checkpoint. Production integration is
responsible for placing that checkpoint in independent off-host/WORM custody
and presenting it on restart; the module does not perform that I/O itself.

## Out of Scope

- OS-1: Setting `execution_policy.LIVE_ALLOWED=true` or changing any
  checked-in trading lock; that requires a separate reviewed release after real
  evidence exists.
- OS-2: Integrating the validation into `ProductionRuntimeConfig`,
  `RuntimeSupervisor`, or `ExecutionCoordinator`; that is the next source
  milestone after this evidence boundary passes.
- OS-3: Creating or fabricating soak, promotion, gate, approval, custody,
  broker, Windows, legal, or operational evidence.
- OS-4: Accessing XM/MT5 credentials, opening a broker connection, sending
  demo/live orders, or mutating Windows Task Scheduler/services.
- OS-5: Pair expansion beyond XAUUSD, multiple live accounts, portfolio
  concurrency, lot/risk scaling, or automatic kill-switch reset.
- OS-6: Treating 50 future live closed trades as a prerequisite for the
  first canary order; those trades are post-canary evidence required before
  pair expansion or scaling.
