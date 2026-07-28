# Rule-Core Champion Registry Custody v1

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-28
**Status:** Approved
**Reviewers:** project owner, security, ship-gate
**Related specs:** `rule_core_champion_artifact_v1.md`,
`create_exclusive_output_custody_v1.md`

## Context

The deterministic Phillip Commodity rule-core champion artifact closes local
source, configuration, snapshot, and runtime-binding lineage. An exact-HEAD
artifact has been independently rebuilt and verified against six external
pins, but the repository has no portable contract for requesting immutable
external registration or for verifying a registry/custodian acknowledgement.
An archive hash alone does not prove that any independent system retained the
exact bytes.

This feature adds a deterministic, offline handoff request and a policy-pinned
RSA acknowledgement verifier. It lets an external registry attest that it
stored the exact artifact bytes under an immutable, versioned object. The
local assessment explicitly distinguishes a verified signed attestation from
direct storage-API inspection and never turns registry custody into model
quality, promotion, demo-order, or live authority.

The implementation is additive. It must remain usable with Python 3.12 under
`-I -S -B`, use only the standard library, preserve all existing trading
safety locks, and perform no network, credential, MT5, Task Scheduler, or
broker action.

## Functional Requirements

- FR-1: The system MUST verify the exact champion artifact against
  independently supplied archive, model, training-snapshot, configuration,
  Git commit, and Git tree SHA-256 pins before creating a registry request.
- FR-2: The system MUST create a deterministic ZIP containing exactly the
  original champion artifact bytes and one canonical request manifest.
- FR-3: The request manifest MUST bind the six supplied pins, artifact
  package identity, runtime-binding identity, size, candidate, model version,
  training cutoff, registry destination, request time, and minimum retention.
- FR-4: The request time MUST be canonical UTC, MUST NOT precede the
  artifact registration time, and the minimum retention time MUST be at least
  365 days after the request time.
- FR-5: Registry, policy, custodian, key, receipt, provider, and object
  identifiers MUST use the reviewed identifier grammar
  `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`.
- FR-6: Request publication MUST be create-exclusive, MUST reject
  file/directory/symlink/reparse collisions, and MUST preserve any object whose
  identity is not proven to have been created by the current invocation.
- FR-7: An independent request verifier MUST reconstruct the full request,
  verify the embedded artifact with the six external pins, and reject any ZIP
  metadata, inventory, path, canonical-JSON, hash, size, identity, timestamp,
  retention, or safety drift.
- FR-8: A trust policy MUST be canonical JSON externally pinned by exact
  SHA-256 and MUST bind one registry, custodian, storage provider, destination,
  minimum retention time, RSA public key, and signature algorithm.
- FR-9: The RSA key MUST be 3072 through 8192 bits, odd, use exponent 65537,
  and match its canonical public-key fingerprint.
- FR-10: A registry receipt MUST be canonical JSON and MUST bind the exact
  request archive, request identity, embedded artifact hash and size, policy
  hash, registry/custodian/key identities, and immutable remote object version.
- FR-11: Receipt acceptance MUST require a domain-separated
  `RSASSA-PKCS1-v1_5-SHA256` signature, exact content-hash verification,
  versioning, immutability, and a retain-until time satisfying both request and
  policy floors.
- FR-12: Receipt acknowledgement MUST occur no earlier than the request and
  no later than the explicit trusted verification time; retention MUST extend
  beyond the verification time.
- FR-13: A successful receipt verification MUST publish one separate
  canonical assessment with create-exclusive semantics.
- FR-14: The assessment MUST report signed registry attestation accepted,
  exact artifact bytes attested, and immutable retention attested, while
  reporting direct storage API inspection as not performed.
- FR-15: Request, receipt, and assessment results MUST retain
  `quality_approved=false`, `oos_gate_passed=false`,
  `promotion_eligible=false`, `order_capability=DISABLED`,
  `safe_to_demo_auto_order=false`, and `live_allowed=false`.
- FR-16: The tools MUST NOT generate or read a private key, contact a
  registry, read credentials, import MetaTrader5, mutate Task Scheduler,
  submit an order, or mutate a broker.
- FR-17: Request creation MUST be byte-deterministic for identical artifact
  bytes, pins, destination, request time, and retention time.
- FR-18: All input files MUST be stable regular non-reparse files and all
  JSON MUST reject duplicate keys, non-finite values, invalid UTF-8, extra
  fields, and non-canonical encoding.
- FR-19: Public CLI commands MUST support prepare-request, verify-request,
  and verify-receipt workflows without importing project code before the
  intended isolated bootstrap path is established.
- FR-20: The request builder and all verifiers MUST produce stable
  machine-readable reason codes on failure and MUST NOT leave a partial output.

## Non-Functional Requirements

- **NFR-1 (Compatibility):** All public workflows MUST run on CPython 3.12 on
  macOS, Linux, and Windows using only the standard library.
- **NFR-2 (Isolation):** Request and receipt verification MUST pass under
  `python -I -S -B` from an extracted configured-release tooling package.
- **NFR-3 (Bounds):** Champion artifacts MUST be at most 16 MiB, registry
  requests at most 32 MiB, and policy/receipt/assessment documents at most
  1 MiB.
- **NFR-4 (Determinism):** Two builds with identical inputs MUST have identical
  outer SHA-256 values and exact member bytes.
- **NFR-5 (Reliability):** Publication MUST fsync the new regular file before
  returning and MUST revalidate parent and file identity after publication.
- **NFR-6 (Security):** RSA verification MUST implement the exact SHA-256
  DigestInfo prefix and reject malformed padding, wrong length, out-of-range
  signature integers, and wrong domain separation.
- **NFR-7 (Safety):** No successful or failed workflow may change existing
  central safety configuration or claim trading readiness.

## Acceptance Criteria

### AC-1: Deterministic request (FR-1, FR-2, FR-3, FR-17, NFR-4)

Given a valid exact champion artifact, identical six external pins, registry
destination, canonical request time, and retention time
When two independent request builds run to different new destinations
Then both archives verify successfully
And both archives have identical bytes and SHA-256 values.

### AC-2: Exact artifact pin enforcement (FR-1, FR-7)

Given a valid champion artifact
When any one of the six independently supplied pins is wrong
Then request creation and request verification fail before publication
And no output is created.

### AC-3: Exact two-member request (FR-2, FR-7, FR-18)

Given a valid request archive
When its inventory, member path, ZIP mode, timestamp, ordering, compression,
trailer, or embedded member bytes are changed
Then independent request verification rejects it.

### AC-4: Time and retention boundaries (FR-4, FR-12)

Given an artifact registration time and a canonical request time
When the request precedes registration or retention is less than 365 days
Then request preparation fails with a stable time or retention reason.

### AC-5: Create-exclusive request custody (FR-6, FR-20, NFR-5)

Given a destination already occupied by a file, directory, valid symlink,
dangling symlink, or a race replacement
When request publication runs
Then it fails closed without overwriting or deleting the existing object
And removes only an unchanged partial regular file created by that invocation.

### AC-6: Externally pinned policy (FR-8, FR-9, FR-18)

Given a canonical registry trust policy
When its observed SHA-256 differs from the independently supplied pin, its RSA
key is outside 3072–8192 bits, its exponent is not 65537, or its fingerprint
does not match
Then receipt verification fails before signature acceptance.

### AC-7: Valid signed registry receipt (FR-10, FR-11, FR-12, FR-13, FR-14)

Given a verified request, exact pinned policy, and correctly signed canonical
receipt binding one immutable versioned remote object
When receipt verification runs at a canonical trusted UTC time
Then a separate assessment is published
And it reports signed attestation accepted but direct API inspection not
performed.

### AC-8: Receipt binding drift (FR-10, FR-11)

Given a correctly signed receipt for a different request, artifact, registry,
destination, provider, object content, object size, key, or policy
When it is checked against the current request and policy
Then verification fails even though the RSA signature is mathematically valid.

### AC-9: Receipt signature rejection (FR-11, NFR-6)

Given a receipt with a missing, malformed, wrong-domain, or tampered RSA
signature
When receipt verification runs
Then no assessment is published.

### AC-10: Receipt chronology and retention (FR-12)

Given a signed receipt
When acknowledgement precedes request, follows verification, retention misses
either floor, or retention is not later than verification
Then receipt verification fails closed.

### AC-11: Deny-only semantics (FR-14, FR-15, FR-16, NFR-7)

Given any successful request or assessment workflow
When its output is inspected
Then every trading safety field remains disabled or false
And network, credential, Task Scheduler, MT5, private-key, and broker effects
remain not performed.

### AC-12: Isolated configured-tooling execution (FR-19, NFR-1, NFR-2)

Given an extracted configured-release tooling archive
When all public help paths and request verification execute under
`python -I -S -B`
Then imports and verification succeed without site-packages.

### AC-13: Strict JSON (FR-18)

Given policy, receipt, or request JSON containing duplicate keys, a non-finite
number, invalid UTF-8, an extra field, or non-canonical bytes
When the corresponding verifier runs
Then it rejects the document with a stable schema or canonicalization reason.

### AC-14: Stable regular inputs (FR-18, FR-20)

Given an input path that is missing, a directory, a symlink/reparse point, too
large, or changes during reading
When any workflow consumes it
Then the workflow fails closed and creates no assessment or request output.

## Edge Cases and Error Scenarios

- EC-1: Champion artifact disappears or changes during read → reject as
  unstable; do not create a request.
- EC-2: Output parent is missing, indirect, or a reparse point → reject;
  do not create parent directories implicitly.
- EC-3: ZIP contains duplicate, case-colliding, absolute, traversal, NUL,
  encrypted, data-descriptor, ZIP64, directory, or unsupported members →
  reject the full archive.
- EC-4: Request identifiers are empty or outside the reviewed grammar →
  reject before publication.
- EC-5: Request time equals artifact registration time → allowed if
  retention is at least 365 days later.
- EC-6: Policy/receipt is valid JSON but has a trailing newline or pretty
  formatting → reject as non-canonical.
- EC-7: RSA modulus has a leading zero, even value, or signature length
  mismatch → reject the key or signature.
- EC-8: Receipt remote object has no unique version, has disabled
  versioning/immutability/hash verification, or carries zero size → reject.
- EC-9: Assessment destination collides or is replaced during publication
  → preserve the unknown object and fail closed.
- EC-10: Filesystem becomes unwritable or fsync fails → remove only the
  invocation-owned unchanged partial regular file and return a stable error.

## API Contracts

This feature exposes local CLIs, not network endpoints. A hypothetical
`POST /rule-core/champion/registry` endpoint is explicitly prohibited and MUST
NOT be implemented by this increment; upload and registry API access remain an
external-authority boundary.

```typescript
interface PrepareRequestCommand {
  command: "prepare-request";
  artifact: AbsolutePath;
  expectedArchiveSha256: LowerHex64;
  expectedModelArtifactSha256: LowerHex64;
  expectedTrainingSnapshotSha256: LowerHex64;
  expectedConfigSha256: LowerHex64;
  expectedGitCommit: LowerHex40;
  expectedGitTree: LowerHex40;
  registryId: Identifier;
  destinationId: Identifier;
  requestedAtUtc: CanonicalUtc;
  minimumRetainUntilUtc: CanonicalUtc;
  output: AbsolutePath;
}

interface VerifyRequestCommand extends Omit<PrepareRequestCommand,
  "command" | "artifact" | "registryId" | "requestedAtUtc" |
  "minimumRetainUntilUtc" | "output"> {
  command: "verify-request";
  requestArchive: AbsolutePath;
  expectedRequestArchiveSha256: LowerHex64;
}

interface VerifyReceiptCommand extends VerifyRequestCommand {
  command: "verify-receipt";
  policy: AbsolutePath;
  expectedPolicySha256: LowerHex64;
  receipt: AbsolutePath;
  verifiedAtUtc: CanonicalUtc;
  assessmentOutput: AbsolutePath;
}

interface RegistryWorkflowResult {
  schema_version: string;
  status: string;
  archive_sha256?: LowerHex64;
  request_identity_sha256?: LowerHex64;
  assessment_sha256?: LowerHex64;
  signed_registry_attestation_accepted: boolean;
  direct_storage_api_inspection_performed: false;
  quality_approved: false;
  promotion_eligible: false;
  order_capability: "DISABLED";
  safe_to_demo_auto_order: false;
  live_allowed: false;
}
```

Errors are emitted as
`RULE_CORE_REGISTRY_REJECTED: <STABLE_REASON_CODE>` with exit code `2`.
Successful commands return exit code `0` and print only non-secret identities
and deny-only safety state.

## Data Models

### Registry Request Manifest

| Field | Type | Constraints |
|---|---|---|
| schema_version | string | Exact request schema |
| candidate_id | string | Exact `phillip-commodity` |
| requested_at_utc | CanonicalUtc | Not before artifact registration |
| registry_id | Identifier | Exact external registry |
| destination_id | Identifier | Exact immutable destination within registry |
| artifact | object | Six pins, package/runtime identities, size, model metadata |
| retention | object | 365-day minimum, immutable/versioned/hash verification required |
| external_registry | object | `performed=false`, `receipt_present=false` |
| safety | object | Exact deny-only constants |
| request_identity_sha256 | LowerHex64 | SHA-256 of canonical body without this field |

### Registry Trust Policy

| Field | Type | Constraints |
|---|---|---|
| schema_version | string | Exact policy schema |
| policy_id | Identifier | Immutable policy identity |
| registry_id | Identifier | Must equal request registry |
| custodian_id | Identifier | Independent custodian |
| custodian_key_id | Identifier | Public verification key identity |
| storage_provider_id | Identifier | Exact provider identity |
| destination_id | Identifier | Exact immutable destination |
| minimum_retain_until_utc | CanonicalUtc | External retention floor |
| rsa_modulus_hex | lower hex | 3072–8192-bit odd modulus, no leading zero |
| rsa_exponent | integer | Exact 65537 |
| public_key_fingerprint_sha256 | LowerHex64 | Canonical public-key fingerprint |
| signature_algorithm | string | Exact reviewed RSA algorithm |
| safety | object | Exact deny-only constants |

### Registry Receipt

| Field | Type | Constraints |
|---|---|---|
| schema_version | string | Exact receipt schema |
| receipt_id | Identifier | Immutable external receipt identity |
| request_identity_sha256 | LowerHex64 | Must match request |
| request_archive_sha256 | LowerHex64 | Must match pinned request archive |
| artifact_archive_sha256 | LowerHex64 | Must match embedded exact artifact |
| registry_id | Identifier | Must match request and policy |
| custodian_id | Identifier | Must match policy |
| custodian_key_id | Identifier | Must match policy |
| trust_policy_sha256 | LowerHex64 | Exact external policy pin |
| acknowledged_at_utc | CanonicalUtc | Request ≤ acknowledgement ≤ verification |
| remote_object | object | Provider, destination, object hashes/version/content/size/retention flags |
| external_registry | object | Three exact positive external attestations |
| safety | object | Exact deny-only constants |
| signature_rsa_pkcs1v15_sha256_hex | lower hex | Domain-separated RSA signature |

### Registry Assessment

| Field | Type | Constraints |
|---|---|---|
| schema_version | string | Exact assessment schema |
| status | string | Verified-attestation deny-only status |
| verified_at_utc | CanonicalUtc | Explicit trusted verification time |
| request | object | Exact request archive and identity |
| artifact | object | Exact artifact and model lineage identities |
| registry | object | Exact policy, receipt, registry, custodian, key identities |
| remote_object | object | Exact accepted immutable object claims |
| external_registry | object | Attestation true; direct API inspection false |
| safety | object | Exact deny-only constants |
| assessment_identity_sha256 | LowerHex64 | Canonical body identity |

No database schema is changed. All artifacts are immutable files and are
never updated or deleted by the workflow.

## Out of Scope

- OS-1: Uploading to a registry or WORM provider — external authority and
  credentials must remain outside this repository and process.
- OS-2: Generating or storing RSA private keys — signer custody must remain
  independent of the VPS and development checkout.
- OS-3: Direct registry/storage API inspection — a separate integration and
  authority review is required; this version verifies signed attestation only.
- OS-4: Model quality, champion/challenger selection, OOS validation,
  statistical promotion, or performance approval — separate evidence gates.
- OS-5: Manual-demo, DEMO_AUTO, live policy unlock, order submission, or
  broker mutation — registry custody is never execution authority.
- OS-6: Replacing the existing champion artifact schema or six-pin verifier
  — the request consumes that contract unchanged.
- OS-7: Legal retention determination — 365 days is an engineering floor,
  not legal advice; an external policy may require a later date.
