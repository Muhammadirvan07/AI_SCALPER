# Live Canary Provider-Bound WORM Handoff v1

**Author:** OpenAI Codex with AI_SCALPER project owner
**Date:** 2026-07-29
**Status:** Approved for implementation
**Reviewers:** senior architecture, security, and ship-gate
**Related specs:** `live_canary_provider_bound_portable_custody_v2.md`,
`windows_live_provider_conformance_acceptance_v1.md`,
`create_exclusive_output_custody_v1.md`

## Context

The provider-bound prebootstrap verifier can produce one sealed, deny-only
admission that binds the accepted Windows provider environment to the exact
DEMO and LIVE source lineages. The portable custody verifier can consume an
RSA-signed receipt and a byte-identical WORM readback for that admission.
There is currently no deterministic operator handoff between those two
boundaries. An operator can name individual files and hashes, but an external
custodian has no exact archive contract describing which admission bytes,
custody policy, provider policy, host, task, release, retention floor, and
independent pins belong to one request.

This feature adds a deterministic, offline WORM request and receipt-assessment
tool. It transports only public, canonical, deny-only evidence. It does not
contact storage, reconstruct a verifier seal from JSON, issue a launch
capability, consume a CAS nonce, open the central policy, or authorize an
order. A later launch process must freshly recreate the sealed provider-bound
admission from its raw upstream evidence and pass the existing runtime custody
verifier against the externally retained bytes.

## Goals

- Package the exact provider-bound admission, portable custody policy, and
  provider acceptance policy into one deterministic request.
- Require independent pins for the archive inputs and the target-host LIVE
  closure before publication.
- Verify the custodian's existing provider-bound receipt schema, RSA
  signature, retention, and exported byte-identical WORM readback.
- Publish a canonical deny-only assessment that explicitly distinguishes an
  offline signed/readback assessment from runtime-sealed custody.
- Keep the checked-in central LIVE lock false and perform no external effect.

## Functional Requirements

- FR-1: Request preparation MUST require exact canonical UTF-8 JSON for one
  provider-bound prebootstrap admission, one portable custody policy, and one
  Windows LIVE provider acceptance policy.
- FR-2: The admission document MUST have the exact v1 provider-bound admission
  field inventory and every safety/authority field MUST retain its reviewed
  deny-only value. The tooling MUST NOT claim to restore its module seal.
- FR-3: The custody policy MUST be decoded into the exact reviewed contract,
  match an independently supplied content-SHA-256 pin, bind the admission host
  and LIVE Execution task, and use a custody key ID and fingerprint distinct
  from both provider authorities.
- FR-4: The provider acceptance policy MUST be decoded into the exact reviewed
  contract, match an independently supplied content-SHA-256 pin, and equal the
  admission's provider-policy binding.
- FR-5: Request preparation MUST require independent SHA-256 pins for the
  provider-bound admission, custody policy, provider policy, target-host
  identity, installed environment, LIVE Execution release identity, LIVE task
  definition, and launcher trust policy.
- FR-6: The request time MUST be canonical aware UTC, MUST NOT precede the
  admission check, and MUST be strictly earlier than the admission's limiting
  provider-acceptance expiry.
- FR-7: The requested minimum retain-until time MUST be canonical aware UTC and
  MUST be at least the custody policy's minimum retention interval after the
  request time.
- FR-8: The request archive MUST contain exactly four members in fixed order:
  `provider-bound-admission.json`, `portable-custody-policy.json`,
  `provider-acceptance-policy.json`, and
  `LIVE_CANARY_PROVIDER_BOUND_WORM_REQUEST.json`.
- FR-9: The request manifest MUST bind the exact member hashes and sizes, all
  independent pins, every provider/host/environment/release/task/activation
  lineage field required by the v2 custody receipt, the request identity,
  request time, retention floor, and all deny-only claims.
- FR-10: Identical inputs and metadata MUST produce byte-identical request ZIP
  bytes with fixed member timestamps, permissions, compression, order, and no
  extra fields, comments, directories, encryption, or trailing data.
- FR-11: Request and assessment publication MUST be create-exclusive, reject
  file/directory/symlink/reparse collisions, and remove only an unchanged
  partial regular file proven to be owned by the current invocation.
- FR-12: Independent request verification MUST require an independently
  supplied outer archive SHA-256 plus all FR-5 pins and MUST reconstruct every
  manifest, member, policy, chronology, authority-separation, ZIP, and safety
  invariant.
- FR-13: Receipt assessment MUST first independently verify the request, then
  decode the existing canonical provider-bound WORM receipt v2 without
  accepting an alternative schema.
- FR-14: The receipt MUST bind every corresponding admission and policy field,
  the exact admission content hash and size, a non-zero object key and version,
  the custody authority, and the exact provider-acceptance expiry.
- FR-15: Receipt assessment MUST verify the existing domain-separated
  `RSASSA-PKCS1-v1_5-SHA256` signature against the embedded, independently
  pinned custody policy public key.
- FR-16: The exported WORM readback MUST be a stable regular file whose bytes
  are exactly the embedded admission bytes. Its independent SHA-256 pin MUST
  match both the file and the receipt's stored-content binding.
- FR-17: Receipt upload MUST be no earlier than the admission check or request,
  no later than the trusted assessment time, and no older than the custody
  policy's maximum receipt age. Retention MUST satisfy the request and policy
  floors and extend beyond assessment time. Provider acceptance MUST still be
  current.
- FR-18: A successful assessment MUST bind the request archive, request
  identity, receipt, readback, policies, admission, remote object identity,
  retention, provider expiry, assessment time, and all independent pins.
- FR-19: A successful assessment MUST report signed receipt accepted and
  exported byte-identical readback accepted, while reporting direct storage
  API inspection, runtime-sealed custody, CAS reservation, nonce consumption,
  central unlock, process launch, execution, and broker mutation as false or
  not performed.
- FR-20: Request and assessment results MUST retain `live_allowed=false`,
  `execution_authorized=false`, `broker_mutation_authorized=false`,
  `promotion_eligible=false`, `safe_to_demo_auto_order=false`, and
  `order_capability=DISABLED`.
- FR-21: All input files MUST reject missing, empty, oversized, changing,
  directory, symlink, and reparse-point inputs. JSON MUST reject invalid UTF-8,
  duplicate keys, non-finite numbers, extra fields, and non-canonical bytes.
- FR-22: The public CLI MUST expose `prepare-request`, `verify-request`, and
  `verify-receipt` workflows under `python -I -S -B` from the configured
  operator-tooling release.
- FR-23: Failure paths MUST emit stable uppercase reason codes, must not expose
  raw evidence, paths, credentials, keys, or callback details, and must not
  leave partial output.
- FR-24: The implementation MUST NOT access a private key, credential store,
  network, WORM service, provider runtime, Task Scheduler, subprocess, SQLite,
  MT5, broker, permit issuer, or order primitive.

## Non-Functional Requirements

- NFR-1: The implementation MUST support CPython 3.12 on Windows, macOS, and
  Linux using the standard library and existing public verification modules.
- NFR-2: All workflows MUST behave identically under normal Python and
  optimized `python -O` / `PYTHONOPTIMIZE=2` execution.
- NFR-3: Public JSON documents MUST be at most 1 MiB and request archives MUST
  be at most 4 MiB.
- NFR-4: Request preparation and verification, excluding filesystem latency,
  MUST complete within two seconds on the development host.
- NFR-5: File reads and create-exclusive writes MUST recheck object and parent
  identity before and after I/O and MUST fsync a newly published regular file.
- NFR-6: Tests MUST use only synthetic public keys, signatures, admissions,
  policies, receipts, and readback bytes. No test artifact is external custody.
- NFR-7: Existing provider-bound custody, launch-session, configured-tooling,
  normal, and optimized regressions MUST remain green.

## Acceptance Criteria

### AC-1: Deterministic exact request (FR-1 through FR-10)

Given exact canonical admission and policy files plus identical independent
pins and timestamps
When two requests are prepared at distinct new output paths
Then both requests independently verify
And their bytes, outer SHA-256, manifest, and request identity are identical.

### AC-2: Independent closure pins (FR-3 through FR-5, FR-12)

Given an otherwise valid request
When any admission, policy, host, environment, release, task, or launcher pin
is changed
Then preparation and independent verification reject before publication.

### AC-3: Authority separation (FR-3, FR-4)

Given exact provider and custody policies
When custody reuses either provider authority key ID or public-key fingerprint
Then request preparation and verification reject without an output.

### AC-4: Exact four-member archive (FR-8, FR-9, FR-10, FR-11, FR-12)

Given a valid request
When member inventory, order, metadata, compression, bytes, manifest, comment,
or trailing data changes
Then independent request verification rejects.

### AC-5: Create-exclusive safety (FR-11, FR-23, NFR-5)

Given an occupied output path or an output race
When request or assessment publication runs
Then it overwrites or removes no pre-existing object
And removes only an unchanged partial regular file owned by that invocation.

### AC-6: Valid receipt and readback assessment (FR-13 through FR-18)

Given a verified request, correctly signed canonical v2 receipt, exact exported
readback, independent readback hash, and trusted assessment time
When receipt assessment runs
Then a canonical assessment is published with every exact binding.

### AC-7: Receipt signature and binding rejection (FR-13, FR-14, FR-15, FR-16)

Given a receipt that is unsigned, malformed, wrong-domain, incorrectly signed,
or validly signed for another admission, policy, provider, host, release, task,
object, expiry, hash, or size
When assessment runs
Then it rejects and publishes no assessment.

### AC-8: Chronology and retention (FR-6, FR-7, FR-17)

Given otherwise valid evidence
When request, upload, assessment, retention, or provider-expiry chronology is
invalid or stale
Then request preparation or receipt assessment fails closed.

### AC-9: Readback drift (FR-16, FR-21)

Given a signed receipt
When the exported readback is missing, unstable, non-regular, unpinned, or
byte-different from the embedded admission
Then assessment rejects even if its RSA signature is valid.

### AC-10: Deny-only truthfulness (FR-2, FR-19, FR-20, FR-24)

Given successful request and assessment workflows
When every output and source import is inspected
Then all trading authority remains disabled
And no runtime seal, storage API inspection, CAS, nonce, process, credential,
MT5, broker, or order effect is claimed or performed.

### AC-11: Isolated operator tooling (FR-22, NFR-1, NFR-2)

Given an extracted configured-release tooling ZIP
When CLI help, request verification, and receipt assessment run under normal
and optimized `python -I -S -B`
Then imports and results are identical without site-packages.

### AC-12: Strict inputs and stable failures (FR-21, FR-23)

Given malformed JSON, duplicate keys, non-finite values, extra fields,
oversized/changing inputs, symlinks, reparses, or invalid CLI arguments
When any workflow consumes them
Then it emits only the stable public reason code and leaves no partial output.

## Edge Cases

- EC-1: A canonical admission JSON has the right hash but a safety flag is
  true: reject before request creation.
- EC-2: A policy file permits a valid trailing newline but its independent pin
  is over different bytes: reject exact content-pin drift.
- EC-3: Request retention is sufficient under policy but provider acceptance
  expires before request time: reject the request as stale.
- EC-4: The receipt is fresh but its retention misses the request's later floor:
  reject despite a valid signature.
- EC-5: Readback contains the same JSON value with different whitespace or a
  trailing newline: reject because custody is byte-exact.
- EC-6: Receipt object key or version is all zero: reject before assessment.
- EC-7: Assessment time equals provider expiry or retain-until: reject because
  validity intervals are half-open.
- EC-8: A request/assessment output is replaced after exclusive creation:
  reject final identity verification and do not remove the replacement.
- EC-9: A request created from saved canonical admission bytes is valid as a
  transport artifact but MUST still report `runtime_admission_seal=false`.
- EC-10: A passing assessment is supplied directly to runtime launch code:
  it MUST remain an unsealed offline assessment and cannot satisfy custody or
  launch authority predicates.

## API Contracts

HTTP API: N/A. The marker `POST /not-applicable` is documentation-only and
MUST NOT be implemented or exposed.

```python
def prepare_live_canary_provider_bound_worm_request(
    *,
    admission_path: str | Path,
    custody_policy_path: str | Path,
    provider_policy_path: str | Path,
    expected_provider_bound_admission_sha256: str,
    expected_custody_policy_sha256: str,
    expected_provider_policy_sha256: str,
    expected_target_host_identity_sha256: str,
    expected_installed_environment_sha256: str,
    expected_live_execution_release_identity_sha256: str,
    expected_live_execution_task_definition_sha256: str,
    expected_launcher_trust_policy_sha256: str,
    request_id: str,
    requested_at_utc: str,
    minimum_retain_until_utc: str,
    output: str | Path,
) -> dict[str, object]:
    """Create one deterministic deny-only four-member WORM request."""

def verify_live_canary_provider_bound_worm_request_path(
    request_archive: str | Path,
    *,
    expected_request_archive_sha256: str,
    **independent_pins: str,
) -> dict[str, object]:
    """Independently reconstruct one request without restoring a seal."""

def verify_live_canary_provider_bound_worm_receipt(
    *,
    request_archive: str | Path,
    expected_request_archive_sha256: str,
    receipt_path: str | Path,
    readback_path: str | Path,
    expected_readback_sha256: str,
    verified_at_utc: str,
    assessment_output: str | Path,
    **independent_pins: str,
) -> dict[str, object]:
    """Verify public evidence and publish an unsealed deny-only assessment."""
```

## Data Models

| Field | Type | Constraints |
|---|---|---|
| `request_identity_sha256` | string | Canonical non-zero lowercase SHA-256 of the request manifest without this field |
| `provider_bound_admission_sha256` | string | Exact independently pinned admission content hash |
| `custody_policy_sha256` | string | Exact independently pinned portable custody policy hash |
| `provider_acceptance_policy_sha256` | string | Exact independently pinned provider acceptance policy hash |
| `requested_at_utc` | string | Canonical aware UTC with six fractional digits |
| `minimum_retain_until_utc` | string | Canonical aware UTC satisfying the policy retention floor |
| `members` | array | Three exact source-member records in normative order |
| `signed_receipt_accepted` | boolean | `true` only after exact RSA and binding verification |
| `runtime_sealed_custody_emitted` | boolean | Always `false` for this offline assessment |
| `order_capability` | string | Always `DISABLED` |

### Request manifest

```json
{
  "schema_version": "live-canary-provider-bound-worm-request-v1",
  "request_id": "xm-live-provider-bound-worm-request-0001",
  "requested_at_utc": "2026-07-29T00:00:00.000000Z",
  "minimum_retain_until_utc": "2027-07-29T00:00:00.000000Z",
  "provider_bound_admission_sha256": "<sha256>",
  "custody_policy_sha256": "<sha256>",
  "provider_acceptance_policy_sha256": "<sha256>",
  "members": [
    {"path": "provider-bound-admission.json", "sha256": "<sha256>", "size_bytes": 1},
    {"path": "portable-custody-policy.json", "sha256": "<sha256>", "size_bytes": 1},
    {"path": "provider-acceptance-policy.json", "sha256": "<sha256>", "size_bytes": 1}
  ],
  "runtime_admission_seal": false,
  "runtime_custody_seal": false,
  "live_allowed": false,
  "order_capability": "DISABLED"
}
```

The normative implementation adds every FR-5 and FR-9 binding to this compact
illustrative shape and computes `request_identity_sha256` over the manifest
with that identity field omitted.

### Receipt assessment

```json
{
  "schema_version": "live-canary-provider-bound-worm-assessment-v1",
  "request_archive_sha256": "<sha256>",
  "request_identity_sha256": "<sha256>",
  "receipt_sha256": "<sha256>",
  "readback_sha256": "<sha256>",
  "signed_receipt_accepted": true,
  "byte_identical_exported_readback_accepted": true,
  "direct_storage_api_inspection_performed": false,
  "runtime_sealed_custody_emitted": false,
  "cas_reservation_performed": false,
  "live_allowed": false,
  "order_capability": "DISABLED"
}
```

## Out of Scope

- OS-1: Provisioning or calling an external Object Lock/WORM API.
- OS-2: Generating, loading, or exporting any private key or credential.
- OS-3: Recreating a sealed provider-bound admission from saved JSON.
- OS-4: Producing `VerifiedLiveCanaryProviderBoundAdmissionCustody`.
- OS-5: Atomic checkpoint CAS, nonce observation/consumption, launch capability, or
  provider-bound runtime session creation.
- OS-6: Changing the central LIVE policy or running a Windows service/task.
- OS-7: MT5 initialization, order checks, order submission, reconciliation, or any
  broker mutation.
