# Spec: LIVE Canary Broker Eligibility Review V1

**Author:** Codex with AI_SCALPER project owner

**Date:** 2026-07-29

**Status:** Approved

**Reviewers:** project owner, security boundary, ship-gate

**Related specs:** `broker_registration_review_gate.md`,
`live_canary_activation_evidence_v1.md`

## Context

Commit `1464c68` makes an exact `LiveCanaryBrokerEligibilityEvidence` mandatory
for activation-request construction. Repository inspection shows that this
type is currently constructed only in tests; no Windows operator CLI can
produce or verify it from reviewed broker evidence. Therefore a real operator
would still have to hand-construct an object, which is unacceptable at an
authorization boundary.

The existing Phillip regulatory observation is deliberately scoped to
`DIAGNOSTIC_EVIDENCE_REGISTRATION_REVIEW_ONLY`. Its compliance and legal
approvals must not be reinterpreted as LIVE-canary approval. This feature adds
a second, explicit, short-lived review whose two new authorities sign the exact
broker legal entity, registration record, LIVE server, and XAUUSD scope. It
only produces deny-only evidence for the later activation gate; it never
enables execution by itself.

## Functional Requirements

- FR-1: The preparer MUST accept exactly candidate `phillip-commodity`, broker
  ID `phillip-jp`, canonical symbol `XAUUSD`, one explicit LIVE server, one
  explicit registration authority, and one explicit registration identifier.
- FR-2: The preparer MUST re-verify the complete signed regulatory observation
  against the checked-in candidate configuration and calendar template using
  the existing candidate-scoped `COMPLIANCE_REVIEW` and `LEGAL_REVIEW` keys.
- FR-3: The source observation MUST remain diagnostic-only, deny-only, legally
  eligible for JP residents, bound to the exact Phillip legal entity, DEMO
  server, XAUUSD broker symbol, and one matching independent registry source.
- FR-4: The LIVE server MUST be canonical, MUST differ from the DEMO server,
  and MUST be signed explicitly by both new LIVE-canary reviewers.
- FR-5: The preparer MUST emit a canonical review body with status
  `PENDING_INDEPENDENT_LIVE_CANARY_APPROVALS`, decision
  `LIVE_CANARY_ELIGIBILITY_REVIEW_REQUIRED`, and all trading capabilities
  disabled.
- FR-6: The review window MUST start at a trusted UTC time, MUST be no longer
  than 30 days, and MUST NOT extend beyond 30 days after the underlying
  regulatory observation was verified.
- FR-7: Dedicated key names MUST be candidate-and-role scoped to exactly
  `LIVE_CANARY_COMPLIANCE_REVIEW` and `LIVE_CANARY_LEGAL_REVIEW`; they MUST NOT
  reuse diagnostic registration-review key names.
- FR-8: Each approval MUST bind the exact review-body hash, candidate, broker,
  legal entity, jurisdiction, registration authority and identifier, LIVE
  server, canonical and broker symbols, validity window, reviewer ID, role,
  key ID, key fingerprint, and explicit decision
  `APPROVE_FIRST_XAUUSD_LIVE_CANARY_ELIGIBILITY`.
- FR-9: The two LIVE-canary approvals MUST have different reviewer IDs, key
  IDs, key bytes, and key fingerprints. Both keys MUST also be distinct from
  the two diagnostic regulatory-review keys.
- FR-10: Assembly MUST verify both LIVE-canary approval signatures and MUST
  re-verify the underlying diagnostic regulatory observation at the trusted
  time before producing a result.
- FR-11: A successful assembly MUST create an exact
  `LiveCanaryBrokerEligibilityEvidence` whose regulatory hash is the canonical
  hash of the fully signed observation and whose compliance/legal hashes are
  the canonical hashes of the corresponding LIVE-canary approval objects.
- FR-12: The assembled review MUST contain the exact eligibility evidence,
  both approvals, source hashes, assembly timestamp, and its own canonical
  content hash; it MUST remain deny-only and MUST require the separate
  `LEGAL_COMPLIANCE` activation gate.
- FR-13: Independent verification of a persisted review MUST re-verify every
  source, signature, hash, time window, role, reviewer, and key-independence
  invariant before returning the exact eligibility evidence object.
- FR-14: JSON loaders MUST accept only regular non-symlink UTF-8 files, reject
  duplicate keys and non-finite values, require exact field sets, and never
  accept subclasses or duck-typed contracts.
- FR-15: CLI outputs MUST use exclusive creation and MUST never overwrite an
  existing evidence, approval, or review file.
- FR-16: Windows key setup and signing CLIs MUST use Windows Credential Manager;
  secret key material MUST NOT be accepted on the command line, written to an
  artifact, or printed.
- FR-17: Every CLI failure MUST return exit code 2 with a deterministic blocked
  prefix and MUST preserve order capability `DISABLED`.
- FR-18: The feature MUST NOT import MT5, initialize a terminal, access broker
  credentials, launch a service, install a task, perform network I/O, mutate
  broker state, or submit an order.
- FR-19: The Windows shadow deployment-tooling bundle, whose existing reviewed
  scope already includes Credential Manager evidence tooling, MUST include the
  review module and its prepare/setup/sign/assemble/verify CLIs without adding
  them to any service or configured-release bundle or weakening safety policy.

## Non-Functional Requirements

- NFR-S1: All HMAC comparisons MUST use constant-time comparison.
- NFR-S2: Keys MUST be at least 256 bits and all four diagnostic/LIVE review
  keys MUST be cryptographically distinct.
- NFR-S3: Every persisted object MUST be content-addressed with SHA-256 and
  canonical JSON.
- NFR-S4: Evidence construction and verification MUST fail closed on type,
  case, timestamp, field, hash, signature, identity, or scope ambiguity.
- NFR-R1: No failure path may leave a partial destination file.
- NFR-P1: In-memory preparation, signing, assembly, and verification MUST each
  complete in less than 100 ms for the bounded V1 payload in unit tests.
- NFR-C1: The implementation MUST use the Python 3.12 standard library plus
  existing AI_SCALPER modules; no new runtime dependency is permitted.

## Acceptance Criteria

### AC-1: Prepare exact pending review body (FR-1, FR-2, FR-3, FR-4, FR-5, FR-6)

Given a fresh, correctly signed Phillip Commodity regulatory observation and
the exact checked-in candidate and template
When the preparer receives the exact Phillip LIVE target and registry record
Then it returns one canonical pending review body bound to all source hashes
And every execution capability remains disabled.

### AC-2: Diagnostic approval cannot become LIVE approval (FR-7, FR-8, FR-9)

Given the two existing diagnostic regulatory approvals
When either is supplied in place of a LIVE-canary approval
Then assembly fails with a deterministic role/key/schema error
And no eligibility evidence is produced.

### AC-3: Two explicit independent LIVE approvals (FR-7, FR-8, FR-9, NFR-S1, NFR-S2)

Given one exact pending review body and two dedicated distinct keys
When different compliance and legal reviewers approve it
Then both signatures verify against their exact roles and key fingerprints
And neither approval grants execution.

### AC-4: Assemble activation-compatible evidence (FR-10, FR-11, FR-12)

Given a still-fresh source observation and two valid LIVE-canary approvals
When assembly runs at a trusted UTC time
Then it returns a review containing one exact
`LiveCanaryBrokerEligibilityEvidence`
And the three evidence hashes equal the signed source and approval hashes
And the review still requires the separate activation gate.

### AC-5: Persisted review verifies independently (FR-13, FR-14, NFR-S3, NFR-S4)

Given a persisted assembled review and its original signed source observation
When a new verifier with the four required keys validates it
Then it reconstructs the same eligibility-evidence content hash
And any byte, hash, signature, field, or key substitution fails closed.

### AC-6: Identity and scope substitutions fail (FR-1, FR-3, FR-4, FR-8, NFR-S4)

Given otherwise valid inputs
When candidate, broker, legal entity, jurisdiction, registry record, DEMO
server, LIVE server, canonical symbol, or broker symbol differs
Then preparation, signing, assembly, or verification fails deterministically.

### AC-7: Time boundaries fail closed (FR-6, FR-10, FR-13, NFR-S4)

Given future-dated, expired, over-30-day, or underlying-source-outliving input
When any review operation runs
Then it fails without producing a result or partial destination.

### AC-8: Strict file and CLI behavior (FR-14, FR-15, FR-16, FR-17, NFR-R1)

Given duplicate-key, NaN, symlink, missing, malformed, or pre-existing-output
files
When the relevant CLI runs
Then it exits 2, never overwrites output, never prints a secret, and reports
order capability disabled.

### AC-9: No forbidden effects (FR-18, NFR-C1)

Given CLI help, static import/call inspection, success, and failure execution
When the feature is tested
Then no MT5, broker, credential export, network, process, service, or scheduler
effect occurs.

### AC-10: Tooling packaging remains deny-only (FR-19)

Given a clean Git commit containing the feature
When Windows shadow deployment tooling is built twice
Then both archives are byte-identical and include exactly the new allowlisted
closure
And their manifest still reports `live_allowed=false`,
`production_execution_ready=false`, and `order_capability=DISABLED`.

### AC-11: Performance and regression (NFR-P1)

Given valid bounded fixtures
When each in-memory operation is measured and all repository tests run
Then each operation averages below 100 ms
And the focused tests pass normally and under Python `-O`.

## Edge Cases and Error Scenarios

- EC-1: Lowercase or padded canonical identifiers/constants are rejected.
- EC-2: LIVE server equal to the DEMO server is rejected.
- EC-3: Registry authority/identifier not found exactly once is rejected.
- EC-4: Regulatory observation with missing, duplicate, stale, or invalid
  diagnostic approvals is rejected.
- EC-5: LIVE reviewer IDs, key IDs, fingerprints, or key bytes reused across
  roles are rejected.
- EC-6: Any LIVE review key reused from either diagnostic review role is
  rejected.
- EC-7: An approval for another body, broker, server, symbol, or window is
  rejected.
- EC-8: Approval timestamp outside the body window is rejected.
- EC-9: Review expiry equal to trusted `now` is expired and rejected.
- EC-10: Zero, uppercase, short, or malformed hashes/signatures are rejected.
- EC-11: A subclass, mapping proxy, extra field, missing field, duplicate JSON
  key, NaN, or symlink input is rejected.
- EC-12: Existing destination or mid-write failure leaves original bytes
  unchanged and produces no partial artifact.
- EC-13: Unknown candidate, broker ID, role, decision, status, symbol, or schema
  is rejected.
- EC-14: CLI invocation with raw secret material is impossible because no such
  argument exists.

## API Contracts

```typescript
type Sha256 = string; // exact 64-character lowercase non-zero hex
type UtcDateTime = string; // canonical UTC with trailing Z

interface LiveCanaryBrokerEligibilityReviewBodyV1 {
  schemaVersion: "live-canary-broker-eligibility-review-body-v1";
  candidateId: "phillip-commodity";
  brokerId: "phillip-jp";
  brokerLegalName: "Phillip Securities Japan, Ltd.";
  operatingJurisdiction: "JP";
  registrationAuthority: string;
  registrationIdentifier: string;
  demoServer: string;
  liveServer: string;
  symbol: "XAUUSD";
  brokerSymbol: string;
  regulatoryObservationSha256: Sha256;
  regulatoryEvidenceBundleSha256: Sha256;
  diagnosticComplianceApprovalSha256: Sha256;
  diagnosticLegalApprovalSha256: Sha256;
  reviewedAt: UtcDateTime;
  expiresAt: UtcDateTime;
  status: "PENDING_INDEPENDENT_LIVE_CANARY_APPROVALS";
  decision: "LIVE_CANARY_ELIGIBILITY_REVIEW_REQUIRED";
  liveAllowed: false;
  executionAuthorized: false;
  orderCapability: "DISABLED";
  contentSha256: Sha256;
}

interface LiveCanaryBrokerEligibilityApprovalV1 {
  schemaVersion: "live-canary-broker-eligibility-approval-v1";
  reviewBodySha256: Sha256;
  candidateId: "phillip-commodity";
  brokerId: "phillip-jp";
  brokerLegalName: string;
  operatingJurisdiction: "JP";
  registrationAuthority: string;
  registrationIdentifier: string;
  liveServer: string;
  symbol: "XAUUSD";
  brokerSymbol: string;
  reviewedAt: UtcDateTime;
  expiresAt: UtcDateTime;
  approverId: string;
  approverRole:
    | "LIVE_CANARY_COMPLIANCE_REVIEW"
    | "LIVE_CANARY_LEGAL_REVIEW";
  decision: "APPROVE_FIRST_XAUUSD_LIVE_CANARY_ELIGIBILITY";
  keyId: string;
  keyFingerprintSha256: Sha256;
  signedAt: UtcDateTime;
  liveAllowed: false;
  executionAuthorized: false;
  orderCapability: "DISABLED";
  signatureHmacSha256: Sha256;
}

interface LiveCanaryBrokerEligibilityReviewV1 {
  schemaVersion: "live-canary-broker-eligibility-review-v1";
  reviewBody: LiveCanaryBrokerEligibilityReviewBodyV1;
  approvals: readonly [
    LiveCanaryBrokerEligibilityApprovalV1,
    LiveCanaryBrokerEligibilityApprovalV1,
  ];
  eligibilityEvidence: LiveCanaryBrokerEligibilityEvidence;
  assembledAt: UtcDateTime;
  legalComplianceActivationGateRequired: true;
  liveAllowed: false;
  executionAuthorized: false;
  orderCapability: "DISABLED";
  contentSha256: Sha256;
}

interface EligibilityReviewCliFailure {
  exitCode: 2;
  errorPrefix: string;
  orderCapability: "DISABLED";
  brokerMutation: "NOT_PERFORMED";
}
```

The V1 interface is an offline Python/JSON contract. The HTTP surface
`POST /api/v1/live-canary/broker-eligibility` is explicitly forbidden and is
listed only as a negative security sentinel; no HTTP endpoint is added.

## Data Models

### Review body

| Field group | Type | Constraints |
|---|---|---|
| candidate/broker | canonical text | Exact `phillip-commodity` / `phillip-jp` |
| legal/registration identity | canonical text | Exact JP source record and legal entity |
| demo/live servers | canonical text | Non-empty and distinct |
| symbol mapping | canonical text | Exact `XAUUSD` and reviewed broker symbol |
| source hashes | SHA-256 | Fully signed observation, evidence bundle, two diagnostic approvals; all non-zero |
| review window | UTC timestamps | Future-free, positive, at most 30 days, source-bounded |
| safety fields | constants | Pending and deny-only |

### LIVE-canary approval

| Field group | Type | Constraints |
|---|---|---|
| body and scope binding | immutable values | Exact copy/hash of the review body scope |
| reviewer identity | canonical text | Distinct real reviewer per role |
| key identity | canonical text/SHA-256 | Dedicated candidate-role key and exact fingerprint |
| decision | enum | Explicit first-XAUUSD-canary eligibility approval only |
| signature | HMAC-SHA256 | Domain-separated, exact lowercase hex, constant-time verified |

### Assembled review

| Field | Type | Constraints |
|---|---|---|
| review_body | object | Exact verified pending body |
| approvals | tuple | Exactly compliance then legal, independently verified |
| eligibility_evidence | object | Exact activation-compatible deny-only evidence |
| assembled_at | UTC datetime | Within body window |
| content_sha256 | SHA-256 | Canonical hash excluding itself |
| capability fields | constants | Separate gate required; execution disabled |

## Out of Scope

- OS-1: Deciding whether Phillip is legally eligible. Human compliance and
  legal reviewers remain accountable for the explicit LIVE decision.
- OS-2: Reusing diagnostic approvals as LIVE approval. Their scope is narrower
  and intentionally remains unchanged.
- OS-3: Online registry lookup or hard-coded claims about current regulatory
  status. The preparer only verifies captured signed local evidence.
- OS-4: Creating the later `LEGAL_COMPLIANCE` gate receipt, human activation
  approvals, deployment authorization, or central unlock.
- OS-5: Loading MT5 credentials, connecting to a broker, sending demo/live
  orders, or changing any runtime/service/task state.
- OS-6: General broker/pair expansion beyond the first Phillip JP XAUUSD LIVE
  canary. That requires a versioned follow-up specification.
