# Live Canary External CAS Handoff v1

**Author:** OpenAI Codex with AI_SCALPER project owner
**Date:** 2026-07-29
**Status:** Approved for implementation
**Reviewers:** senior architecture, security, and ship-gate

## Context

The provider-bound LIVE canary chain now has a deterministic operator handoff
for the exact provider-bound admission, public custody policy, external
provider policy, signed WORM receipt, and exported byte-identical readback.
That handoff deliberately stops before the existing one-use launch reservation
protocol. The runtime protocol still requires one fresh launcher nonce to be
atomically committed in an independently controlled off-host compare-and-swap
(CAS) ledger before it may emit a verifier-sealed launch prerequisite.

The existing runtime verifier already implements the authoritative callback
flow: read and authenticate the current head, confirm the nonce is unseen,
submit one canonical proposal through atomic CAS, authenticate a separately
signed checkpoint and acknowledgement, read the exact head back, and confirm
the nonce is now seen. What is missing is a deterministic, provider-neutral
operator format for handing the exact public proposal and policy to an
external custodian and independently reviewing its exported response.

This feature closes only that transport and evidence-review gap. It does not
replace the synchronous runtime callbacks, recreate any module-owned seal, or
turn exported evidence into launch authority. Actual provider choice,
credentials, atomic storage semantics, and runtime callback integration remain
external deployment work.

## Functional Requirements

- FR-1: The handoff MUST accept one exact canonical
  `live-canary-launch-reservation-proposal-v1` and one exact canonical
  `live-canary-portable-custody-policy-v1` using only public data.
- FR-2: Request construction MUST require independent SHA-256 pins for the
  proposal, custody policy, predecessor, launcher nonce, candidate, admission,
  custody verification, authorization, validation, launcher policy, launcher
  attestation, release, host, service account, and task definition.
- FR-3: The proposal MUST bind the custody policy and every independently
  supplied pin. Sequence one MUST use the all-zero predecessor; every later
  sequence MUST use a non-zero predecessor. The request time MUST equal the
  proposal request time and remain before its expiry.
- FR-4: The custody policy MUST pin one RSA authority with modulus size
  3072-8192 bits, exponent 65537, exact public-key fingerprint, exact host,
  service-account, task, and launcher-policy hashes, and a launch TTL of at
  most 60 seconds.
- FR-5: The request archive MUST contain exactly, in order,
  `launch-proposal.json`, `portable-custody-policy.json`, and
  `LIVE_CANARY_EXTERNAL_CAS_REQUEST.json`. It MUST use deterministic stored ZIP
  members, fixed metadata, no directories/extras/comments, exact member
  hashes/sizes, an outer SHA-256 pin, and exact byte reconstruction.
- FR-6: Request and response documents MUST be canonical UTF-8 JSON with exact
  field inventories, no duplicate/unknown keys, no non-finite numbers,
  canonical microsecond UTC text, bounded size, and stable regular-file reads.
- FR-7: The external response MUST include one canonical signed launch
  checkpoint, one separately domain-signed canonical CAS acknowledgement, one
  byte-identical exported head readback, and one canonical signed nonce
  readback attestation using a third signature domain.
- FR-8: The checkpoint MUST contain the exact request proposal and bind its
  hash, policy, authority, commit time, and safety fields. Its RSA signature
  MUST validate under the exact custody public key.
- FR-9: The acknowledgement MUST bind the exact predecessor, committed
  checkpoint hash, proposal hash, launcher nonce, sequence, authority, and
  acknowledgement time. Its RSA signature MUST validate under the exact
  custody public key and its signature domain MUST differ from the checkpoint
  domain.
- FR-10: The nonce readback attestation MUST bind the exact request,
  predecessor, proposal, checkpoint, acknowledgement, observed head, launcher
  nonce, sequence, `nonce_seen=true`, authority, and observation time. Its RSA
  signature domain MUST differ from both existing CAS signature domains.
- FR-11: The exported head readback MUST equal the signed checkpoint bytes
  byte-for-byte and its independently supplied SHA-256 pin MUST match. All
  response times MUST be monotonic and strictly inside the proposal window.
- FR-12: Successful response review MUST create one canonical create-exclusive
  assessment with a content identity, exact request/response hashes, accepted
  signature/readback claims, and all runtime/effect authority false.
- FR-13: The assessment MUST explicitly state that no runtime CAS callback was
  executed, no runtime nonce was consumed by this tool, no runtime capability
  or seal was emitted, and no central unlock, process, MT5, credential, or
  broker effect occurred.
- FR-14: The tooling MUST enforce the checked-in central LIVE lock before and
  after parsing, archive reconstruction, response verification, and output
  publication. It MUST reject if `LIVE_ALLOWED` or the locked policy decision
  changes.
- FR-15: Request and assessment publication MUST use create-exclusive regular
  files, reject symlink/reparse/path substitution, verify the written bytes,
  never overwrite evidence, and remove only a partially created file owned by
  the failed operation.
- FR-16: Public failures MUST expose stable uppercase reason codes without
  private material, provider exception text, raw account identifiers, or
  filesystem contents.
- FR-17: The module and CLI MUST contain no private-key operation, provider or
  cloud SDK, network client, credential access, subprocess, Task Scheduler,
  MT5 import, SQLite, process launch, central-policy mutation, permit issuance,
  or broker order surface.
- FR-18: The CLI MUST run from extracted configured operator tooling under
  `python -I -S -B`, admit only exact regular dependency files, and expose
  `prepare-request`, `verify-request`, and `verify-response` commands.
- FR-19: An offline assessment MUST NOT be accepted anywhere as
  `LiveCanaryOneUseLaunchCapability`; the authoritative runtime MUST still
  execute the existing fresh synchronous callback path and module-owned seal.

## Non-Functional Requirements

- NFR-1: Implementation MUST use Python 3.12 standard-library primitives and
  existing public RSA verification/canonical-JSON helpers only.
- NFR-2: Identical inputs MUST produce byte-identical request archives,
  manifests, hashes, and assessments.
- NFR-3: Documents MUST be at most 1 MiB each and request archives at most
  4 MiB; exact three-member request parsing MUST complete in under two seconds
  on the development host, excluding filesystem latency.
- NFR-4: Validation MUST use no `assert` and behave identically under normal
  Python and `PYTHONOPTIMIZE=2`.
- NFR-5: Focused tests MUST require no Windows, network, credentials, external
  provider, Task Scheduler, MT5, broker account, or production private key.
- NFR-6: Focused, related, and full repository tests MUST remain green in
  normal and optimized modes.
- NFR-7: The configured tooling release MUST include the CLI and its complete
  import closure while retaining `production_execution_ready=false`,
  `live_allowed=false`, and `order_capability=DISABLED`.

## Acceptance Criteria

### AC-1: Request is exact and deterministic (FR-1, FR-2, FR-3, FR-4, FR-5, FR-6; NFR-1, NFR-2, NFR-3, NFR-4)

Given one valid canonical proposal, public custody policy, and all independent
pins
When two requests are prepared with identical arguments
Then both archive byte streams and identities are identical
And independent verification reconstructs the exact three-member archive.

### AC-2: Substitution and archive ambiguity fail closed (FR-2, FR-3, FR-4, FR-5, FR-6, FR-14, FR-15, FR-16)

Given a replaced proposal or policy, mismatched independent pin, wrong
predecessor rule, malformed JSON, duplicate key, symlink, colliding output, or
non-canonical ZIP
When request preparation or verification runs
Then no accepted request or overwritten evidence is produced
And one stable public reason code is returned.

### AC-3: Signed CAS result is bound end to end (FR-7, FR-8, FR-9, FR-10, FR-11)

Given an exact request and custody-authority-signed checkpoint,
acknowledgement, and nonce readback attestation
When the exported head is byte-identical and all times and bindings match
Then all four external response claims are independently accepted.

### AC-4: Forgery, rollback, replay, and ambiguous readback fail closed (FR-7, FR-8, FR-9, FR-10, FR-11, FR-14, FR-16)

Given a forged signature, wrong authority, substituted proposal, stale or
future time, wrong predecessor or sequence, mismatched head readback,
`nonce_seen=false`, wrong nonce, or cross-request response
When response verification runs
Then no assessment is published and no runtime authority is emitted.

### AC-5: Assessment remains evidence-only (FR-12, FR-13, FR-19)

Given every offline response check passes
When the assessment is published
Then it records the accepted signed external claims and exact hashes
But all runtime seals, runtime CAS execution, local nonce consumption, central
unlock, launch, execution, and broker authority remain false.

### AC-6: CLI and configured release are portable (FR-17, FR-18; NFR-5 through NFR-7)

Given an extracted configured operator tooling release
When CLI help and request/response verification run with isolated optimized
Python
Then imports resolve only from exact regular release files
And release safety metadata remains deny-only.

### AC-7: Static and regression gates remain clean (FR-14, FR-17, FR-19; NFR-4 through NFR-7)

Given the completed implementation
When static scans, focused tests, dependency lock verification, complete normal
tests, complete optimized tests, and ship-gate checks run
Then no forbidden effect surface is introduced
And external/manual blockers remain reported rather than fabricated.

## Edge Cases

- EC-1: Empty, oversized, non-UTF-8, non-object, non-canonical, duplicate-key,
  unknown-field, boolean-integer, zero-required-hash, or malformed UTC input is
  rejected.
- EC-2: Proposal sequence one with non-zero predecessor, or later sequence with
  zero predecessor, is rejected.
- EC-3: Proposal policy, host, service, task, release, launcher, admission,
  authorization, validation, nonce, or external pin substitution is rejected.
- EC-4: RSA modulus below 3072 bits, exponent other than 65537, even modulus,
  malformed modulus/signature, or fingerprint mismatch is rejected.
- EC-5: ZIP64, compression, data descriptors, reordered/duplicate members,
  path traversal, directories, comments, extras, trailing bytes, or metadata
  drift is rejected.
- EC-6: Checkpoint embeds a different proposal, commits before request or at
  expiry, uses the wrong policy/authority, or has an invalid signature.
- EC-7: Acknowledgement names the wrong predecessor, checkpoint, proposal,
  nonce, sequence, authority, or time, or reuses an invalid signature.
- EC-8: Head readback differs by one byte, its external hash pin differs, or a
  file changes while read is in progress.
- EC-9: Nonce readback names a different request/proposal/checkpoint/ack/head,
  reports false, regresses in time, reaches expiry, or has an invalid signature.
- EC-10: A response from a different request, lane, release, host, or nonce is
  rejected even if every individual signature is cryptographically valid.
- EC-11: Existing output, symlinked parent/file, reparse point, replaced inode,
  parent swap, short write, or post-write byte drift fails without overwriting
  pre-existing evidence.
- EC-12: Central LIVE policy drift at any boundary fails closed.
- EC-13: Importing or invoking the CLI MUST NOT contact a provider, open a
  credential store, consume a nonce, create a runtime seal, launch a process,
  initialize MT5, or mutate a broker.

## API Contracts

HTTP API: N/A. No endpoint or provider client is introduced. The validator
marker `GET /not-applicable` documents that no route may be implemented.

```typescript
interface ExternalCasHandoffPins {
  expectedProposalSha256: string;
  expectedCustodyPolicySha256: string;
  expectedPredecessorCheckpointSha256: string;
  expectedLauncherNonceSha256: string;
  expectedCandidateSha256: string;
  expectedAdmissionSha256: string;
  expectedCustodyVerificationSha256: string;
  expectedAuthorizationSha256: string;
  expectedValidationSha256: string;
  expectedLauncherTrustPolicySha256: string;
  expectedLauncherAttestationSha256: string;
  expectedReleaseIdentitySha256: string;
  expectedDeploymentHostAliasSha256: string;
  expectedServiceAccountAliasSha256: string;
  expectedTaskDefinitionSha256: string;
}

interface ExternalCasNonceReadbackV1 {
  schema_version: "live-canary-external-cas-nonce-readback-v1";
  request_identity_sha256: string;
  proposal_sha256: string;
  checkpoint_sha256: string;
  acknowledgement_sha256: string;
  expected_predecessor_checkpoint_sha256: string;
  observed_head_sha256: string;
  launcher_nonce_sha256: string;
  sequence: number;
  nonce_seen: true;
  observed_at_utc: string;
  custody_issuer_id: string;
  custody_key_id: string;
  public_key_fingerprint_sha256: string;
  signature_algorithm: "RSASSA-PKCS1-v1_5-SHA256";
  signature_rsa_pkcs1v15_sha256_hex: string;
  live_allowed: false;
  execution_authorized: false;
  bootstrap_authorized: false;
  process_launch_authorized: false;
  order_capability: "DISABLED";
}
```

```python
def prepare_live_canary_external_cas_request(
    *,
    proposal_path: str | Path,
    custody_policy_path: str | Path,
    request_id: str,
    output: str | Path,
    **pins: str,
) -> dict[str, object]: ...

def verify_live_canary_external_cas_request_path(
    request_archive: str | Path,
    *,
    expected_request_archive_sha256: str,
    **pins: str,
) -> dict[str, object]: ...

def verify_live_canary_external_cas_response(
    *,
    request_archive: str | Path,
    checkpoint_path: str | Path,
    acknowledgement_path: str | Path,
    head_readback_path: str | Path,
    nonce_readback_path: str | Path,
    expected_head_readback_sha256: str,
    verified_at_utc: str,
    assessment_output: str | Path,
    **pins: str,
) -> dict[str, object]: ...
```

Errors use `LiveCanaryExternalCasHandoffError.reason_code` and CLI exit code
2. No response contract contains a runtime capability or execution grant.

## Data Models

| Entity | Field group | Type | Constraints |
| --- | --- | --- | --- |
| CAS request archive | members | three stored ZIP files | exact order, fixed metadata, exact reconstruction |
| CAS request manifest | identity and pins | canonical JSON/hash | exact proposal/policy/member/pin closure |
| Launch proposal | reservation | canonical JSON | existing v1 exact field inventory and safety lock |
| Custody policy | public authority | canonical JSON/RSA | exact existing v1 public policy and deployment pins |
| Launch checkpoint | committed head | canonical JSON/RSA signature | exact proposal, policy authority, bounded commit time |
| CAS acknowledgement | atomic result | canonical JSON/RSA signature | exact predecessor/head/proposal/nonce/sequence |
| Nonce readback | exported observation | canonical JSON/RSA signature | exact request/head/nonce, `nonce_seen=true`, unique domain |
| Assessment | evidence review | canonical JSON/hash | accepted claims plus all runtime/effect authority false |

## Out of Scope

- OS-1: Choosing, provisioning, configuring, or paying for an external CAS or
  WORM provider.
- OS-2: Provider credentials, private keys, network calls, cloud SDKs, HTTP
  endpoints, queues, or polling agents.
- OS-3: Replacing the existing synchronous runtime callback protocol or
  creating a capability from an offline assessment.
- OS-4: Changing `execution_policy.LIVE_ALLOWED`, performing the central unlock
  ceremony, starting a service/process/task, or accessing broker credentials.
- OS-5: MT5 initialization, reconciliation, permit issuance, order submission,
  modification, cancellation, lot expansion, or symbol expansion.
- OS-6: Claiming external CAS atomicity, nonce consumption, provider custody,
  selected-broker readiness, or live-trading readiness without real signed
  provider artifacts and the subsequent fresh runtime verification.
