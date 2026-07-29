# Spec: LIVE Canary Gate Receipt Operator V1

**Author:** Codex with AI_SCALPER project owner

**Date:** 2026-07-29

**Status:** Approved

**Reviewers:** project owner, security boundary, ship-gate

**Related specs:** `live_canary_activation_evidence_v1.md`,
`live_canary_broker_eligibility_review_v1.md`

## Context

The activation core already requires nine distinct authenticated
`LiveCanaryGateReceipt` objects. The only current construction path is an
in-memory Python API used by tests. A Windows operator cannot load an exact
binding/policy, hash the reviewed source artifact, issue a receipt from a
policy-pinned Credential Manager key, independently verify it, or assemble the
nine receipts into one portable set. The special `LEGAL_COMPLIANCE` receipt
must bind the canonical `LiveCanaryBrokerEligibilityEvidence` hash rather than
an arbitrary file hash.

This feature adds that offline operator bridge. It does not build an activation
request, change the central policy, load MT5, access a broker account, or grant
execution. Every result remains deny-only.

## Functional Requirements

- FR-1: Strict loaders MUST reconstruct exact `LiveCanaryBinding`,
  `LiveCanaryTrustPolicy`, and `LiveCanaryGateReceipt` instances from persisted
  JSON and reject extra, missing, duplicate, non-finite, non-canonical, or
  wrong-typed fields.
- FR-2: Input files MUST be regular non-symlink/non-reparse files with bounded
  size. Missing, directory, link, replacement, or unreadable inputs MUST fail
  closed.
- FR-3: Binding and policy MUST be exact base classes. The binding
  `acceptance_policy_sha256` MUST equal the reconstructed policy hash.
- FR-4: Non-`LEGAL_COMPLIANCE` domains MUST bind the SHA-256 of the exact
  reviewed evidence-file bytes supplied to the issuer.
- FR-5: `LEGAL_COMPLIANCE` MUST reject an arbitrary evidence file. It MUST bind
  an exact `LiveCanaryBrokerEligibilityEvidence` whose broker, LIVE server, and
  symbol equal the binding and whose eligibility window covers the receipt.
- FR-6: Issuance MUST use the existing activation-core
  `issue_live_canary_gate_receipt` API so policy key ID/fingerprint and binding
  checks cannot diverge from request construction.
- FR-7: Signing secret material MUST come from an injected key provider in the
  module and from Windows Credential Manager in the CLI. No raw secret CLI
  argument is permitted.
- FR-8: A persisted receipt MUST include the exact domain, binding hash,
  evidence hash, issuer, validity window, policy-pinned key identity and HMAC,
  while all capability fields remain disabled.
- FR-9: Independent receipt verification MUST re-hash/re-validate the exact
  source, re-check binding/policy/key/time scope, and verify HMAC in constant
  time.
- FR-10: A receipt-set assembler MUST require exactly one receipt for each of
  the nine `LIVE_CANARY_GATE_DOMAINS`, with no duplicate receipt, evidence
  hash, key ID, key fingerprint, or source path.
- FR-11: Receipt-set assembly MUST independently verify each source/receipt and
  require every receipt to cover a caller-pinned `required_until` instant.
- FR-12: Receipt-set assembly MUST require the exact verified broker
  eligibility evidence for `LEGAL_COMPLIANCE` and record its content hash.
- FR-13: The resulting canonical receipt set MUST bind the binding hash,
  trust-policy hash, every receipt hash, every evidence hash, assembly time,
  minimum expiry, and its own content hash.
- FR-14: Receipt-set loading/verification MUST reconstruct the same exact nine
  receipt objects and reject any member, ordering, field, hash, source, or time
  substitution.
- FR-15: All writes MUST use create-exclusive, fsync-backed publication and
  MUST never overwrite or remove a pre-existing path.
- FR-16: CLI failures MUST exit 2 with a deterministic blocked prefix and state
  `Live allowed: false`, `Order capability: DISABLED`, and
  `Broker mutation: NOT_PERFORMED`.
- FR-17: The tooling MUST NOT import MT5, initialize a terminal, read broker
  credentials, access network, launch a process/service, install a task,
  change policy, mint a permit, or submit an order.
- FR-18: The sign, verify, and assemble CLIs and module MUST be included only
  in the Windows shadow deployment-tooling allowlist, never in Decision,
  Execution, Status Monitor, read-only service, or configured service releases.
- FR-19: Existing activation-core canonical classes and schemas MUST remain
  byte-compatible.

## Non-Functional Requirements

- NFR-S1: HMAC/fingerprint comparisons MUST use constant-time comparison.
- NFR-S2: Keys MUST be at least 256 bits and policy-pinned.
- NFR-S3: All canonical hashes MUST be lowercase non-zero SHA-256 values.
- NFR-S4: Validation MUST reject subclasses and duck-typed objects.
- NFR-R1: No failure path may leave a partial destination.
- NFR-P1: In-memory issue and verify operations MUST average below 100 ms for
  the bounded V1 payload in focused tests.
- NFR-C1: The implementation MUST use Python 3.12 standard library and existing
  AI_SCALPER modules only and pass with normal and `-O` execution.

## Acceptance Criteria

### AC-1: Strict binding/policy reconstruction (FR-1, FR-2, FR-3)

Given canonical persisted binding and trust-policy JSON
When the operator loader reads both
Then it reconstructs the exact activation-core classes and hashes
And any duplicate, extra, missing, wrong-typed, linked, or noncanonical input
fails before key access or output creation.

### AC-2: Generic gate issuance (FR-4, FR-6, FR-7, FR-8)

Given a non-legal gate, exact binding/policy, reviewed evidence bytes, and the
policy-pinned Credential Manager key
When issuance runs
Then the receipt evidence hash equals the exact source bytes
And the signature verifies while every execution field remains disabled.

### AC-3: Eligibility-bound legal gate (FR-5, FR-6, FR-12)

Given exact verified broker eligibility evidence covering the requested window
When `LEGAL_COMPLIANCE` issuance runs
Then the receipt evidence hash equals the canonical eligibility content hash
And an arbitrary file, mismatched broker/server/symbol, or stale eligibility is
rejected.

### AC-4: Independent receipt verification (FR-2, FR-9, NFR-S1, NFR-S2)

Given one persisted receipt and its exact source
When another process verifies it with the policy-pinned key
Then source, policy, binding, key, signature, and time scope all verify
And any mutation fails closed.

### AC-5: Exact nine-domain receipt set (FR-10, FR-11, FR-12, FR-13)

Given nine valid receipts and sources
When the assembler verifies them at one pinned UTC instant
Then it emits one canonical deny-only set in sorted domain order
And missing/extra/duplicate domains, sources, evidence, keys, or fingerprints
are rejected.

### AC-6: Persisted set verifies independently (FR-13, FR-14)

Given a persisted set plus its original sources
When a new verifier loads and validates it
Then it reconstructs the exact nine receipts and the same set content hash
And any content, ordering, source, or expiry drift fails.

### AC-7: Exclusive output and CLI safety (FR-15, FR-16)

Given an existing destination, link, malformed source, missing credential, or
invalid key
When a CLI runs
Then it exits 2 without overwriting/removing any byte or printing a secret
And reports that all trading capabilities remain disabled.

### AC-8: No forbidden effects or release leakage (FR-17, FR-18, FR-19)

Given static inspection, help, success, failure, and release builds
When the feature is tested
Then it performs no forbidden effect, exists only in operator tooling, leaves
the activation core unchanged, and both operator builds are byte-identical.

### AC-9: Performance and optimized regression (NFR-P1, NFR-C1)

Given bounded valid fixtures
When issue/verify are measured and focused tests run normally and under `-O`
Then both operations average below 100 ms and all tests pass.

## Edge Cases and Error Scenarios

- EC-1: Boolean-as-integer, lowercase domain drift, padded identifiers, zero or
  uppercase hashes, offset timestamps, and over-30-day windows fail closed.
- EC-2: Binding referencing another policy, policy missing one domain, or
  policy reusing any authority ID/fingerprint fails before signing.
- EC-3: Empty evidence, oversized evidence, symlink/reparse evidence, and a
  source replaced between inspection and read are rejected.
- EC-4: `LEGAL_COMPLIANCE` supplied through the generic file route or another
  domain supplied through the eligibility route is rejected.
- EC-5: Eligibility expiry equal to receipt expiry is valid; expiry earlier
  than receipt expiry is invalid.
- EC-6: Receipt issued in the future, expired at `now`, or expiring before
  `required_until` is rejected.
- EC-7: Same evidence bytes, key, fingerprint, receipt, or source path reused
  for two domains makes the complete set invalid.
- EC-8: Subclassed binding/policy/receipt/eligibility objects are rejected.
- EC-9: Duplicate JSON keys, NaN/Infinity, invalid UTF-8, BOM, extra newline
  ambiguity, or non-object top level is rejected.
- EC-10: Existing destination and injected mid-write failure preserve the
  original path and leave no partial artifact.

## API Contracts

```python
load_live_canary_binding(path) -> LiveCanaryBinding
load_live_canary_trust_policy(path) -> LiveCanaryTrustPolicy
load_live_canary_gate_receipt(path) -> LiveCanaryGateReceipt
issue_live_canary_gate_receipt_artifact(...) -> LiveCanaryGateReceipt
verify_live_canary_gate_receipt_artifact(...) -> LiveCanaryGateReceipt
assemble_live_canary_gate_receipt_set(...) -> dict[str, object]
verify_live_canary_gate_receipt_set(...) -> tuple[LiveCanaryGateReceipt, ...]
write_live_canary_gate_artifact_exclusive(path, payload) -> Path
```

```typescript
interface LiveCanaryGateReceiptSetV1 {
  schemaVersion: "live-canary-gate-receipt-set-v1";
  bindingSha256: Sha256;
  trustPolicySha256: Sha256;
  receiptSha256ByDomain: readonly [string, Sha256][];
  evidenceSha256ByDomain: readonly [string, Sha256][];
  receipts: readonly LiveCanaryGateReceipt[];
  legalEligibilityEvidenceSha256: Sha256;
  assembledAt: UtcDateTime;
  validUntil: UtcDateTime;
  liveAllowed: false;
  executionAuthorized: false;
  activationAuthorized: false;
  orderCapability: "DISABLED";
  contentSha256: Sha256;
}
```

The V1 interface is a local file contract. `POST
/internal/live-canary/gate-receipts` is a reserved negative sentinel and MUST
NOT be registered by this feature; no HTTP endpoint is added.

## Data Models

### Exact activation inputs

| Model | Source | Required invariants |
|---|---|---|
| `LiveCanaryBinding` | persisted canonical JSON | exact activation-core base class; policy hash, broker, LIVE server, XAUUSD scope, release and champion lineage pinned |
| `LiveCanaryTrustPolicy` | persisted canonical JSON | exactly nine gate authorities plus promotion, three human, deployment, and checkpoint authorities; all IDs/fingerprints distinct |
| `LiveCanaryBrokerEligibilityEvidence` | independently verified eligibility review | exact broker/LIVE server/XAUUSD scope; registered, eligible, fresh, deny-only |

### Gate source and receipt

| Field group | Type | Constraints |
|---|---|---|
| evidence source | regular file bytes or exact eligibility object | non-empty, bounded, no symlink/reparse; legal domain only accepts eligibility object |
| receipt domain | enum | exactly one member of `LIVE_CANARY_GATE_DOMAINS` |
| binding/evidence identity | SHA-256 | exact non-zero hashes; legal evidence equals eligibility content hash |
| issuer/key identity | canonical text/SHA-256 | exact trust-policy entry and Credential Manager key material |
| window | UTC timestamps | positive, at most 30 days, fresh, covers required request time |
| signature | HMAC-SHA256 | activation-core domain-separated signature |
| capability fields | constants | live/execution/activation false; order disabled |

### Receipt set

| Field | Type | Constraints |
|---|---|---|
| binding/policy hashes | SHA-256 | exact reconstructed input identities |
| receipt/evidence maps | nine sorted pairs each | all domains exact and unique; all hashes distinct |
| receipts | nine canonical objects | sorted by domain; each independently verified |
| legal eligibility hash | SHA-256 | equals `LEGAL_COMPLIANCE` evidence hash |
| assembled/valid-until | UTC timestamps | assembly is fresh; valid-until is minimum child expiry |
| content hash | SHA-256 | canonical object hash excluding itself |
| capability fields | constants | deny-only and non-executable |

## Out of Scope

- OS-1: Creating or approving the underlying legal, security, host, custody,
  backup, rollback, account, or drill evidence.
- OS-2: Preparing the trust policy or live binding from raw deployment facts.
- OS-3: Building the five-minute activation request, collecting three human
  approvals, signing deployment authorization, or consuming the replay nonce.
- OS-4: Setting `LIVE_ALLOWED=true`, changing central policy, starting a
  runtime, accessing MT5, or sending an order.
