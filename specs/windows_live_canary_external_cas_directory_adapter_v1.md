# Windows LIVE Canary External CAS Directory Adapter v1

**Author:** Codex with AI_SCALPER project owner
**Date:** 2026-07-29
**Status:** Approved for implementation
**Reviewers:** senior architecture, security, ship-gate
**Target:** Windows XM LIVE-canary launch reservation boundary

## Context

The LIVE-canary custody core already defines the authoritative synchronous
callback contract for reading the current checkpoint, atomically committing a
successor, and observing nonce state. The core verifies RSA-signed checkpoint
and acknowledgement documents and mints the only valid in-memory
`LiveCanaryOneUseLaunchCapability`. The offline external-CAS handoff packages
and reviews public evidence, but it intentionally cannot invoke those callbacks
inside the proposal's at-most-60-second window or mint the module-owned seal.

The Windows Decision service already proves a bounded directory request/response
pattern for an independently controlled CAS service. This feature applies a
separate, LIVE-specific protocol to the launch-reservation callbacks. A Windows
service writes canonical requests to one externally serviced mount and reads
signed responses from another. The external service remains the atomic state
owner; a local directory, test fixture, or adapter instance is never called an
external CAS provider or WORM custody evidence by itself.

The adapter runs only while the checked-in central LIVE lock remains false. It
does not perform the later central-unlock ceremony, activate a runtime launch
session, build an Execution service, initialize MT5, or submit an order. It is
an additive client-side bridge that allows a separately provisioned and
reviewed external provider to satisfy the exact existing callbacks without
changing their canonical protocol.

## Functional Requirements

- FR-1: The implementation MUST add a separate LIVE-canary directory adapter
  module and MUST NOT change the canonical fields, hashes, signatures, seals,
  or behavior of existing custody, launch-session, provider-bound, or Windows
  materialization contracts.
- FR-2: The adapter MUST expose exactly three public callback methods compatible
  with `external_checkpoint_provider()`,
  `external_checkpoint_cas(expected_predecessor, proposal_bytes)`, and
  `external_nonce_seen_provider(nonce_sha256)`.
- FR-3: Construction MUST require the exact canonical public custody-policy
  bytes, their independently supplied exact SHA-256 pin, a provider ID,
  existing absolute request and response directories, a trusted UTC callback,
  and a bounded response timeout. It MUST NOT require or retain a producer-side
  `LiveCanaryPortableCustodyPolicy` instance.
- FR-4: Construction MUST independently decode and validate the public policy
  schema, canonical bytes, policy pin, RSA public-key fingerprint, locked
  safety fields, provider identity, and that request and response directories
  are distinct real directories before retaining only an immutable public
  policy projection.
- FR-5: Directory validation MUST reject missing, relative, identical,
  symlinked, reparse-point, non-directory, or path-indirected roots. Every
  accessed file MUST be an immediate child with a protocol-derived filename.
- FR-6: Every public callback MUST verify that `execution_policy.LIVE_ALLOWED`
  is exact `false` and that the central LIVE policy decision is exactly
  `false/(LIVE_MODE_LOCKED)` before and after every filesystem, clock, sleep,
  entropy, or external-response effect.
- FR-7: The checkpoint callback MUST perform one stable bounded read of
  `current.checkpoint.json`; absence MAY mean genesis, while an empty,
  oversized, unstable, indirect, noncanonical, unsigned, wrong-authority, or
  invalid checkpoint MUST fail closed.
- FR-8: A valid current checkpoint MUST be independently decoded with the
  byte-identical canonical schema and signature domain used by the custody
  protocol, verified against the exact public custody authority and RSA
  signature, and returned as the byte-identical payload read from the external
  mount. The adapter MUST NOT import a producer-side custody decoder.
- FR-9: The nonce callback MUST first obtain and pin a freshly verified current
  head, then create one canonical create-exclusive nonce-query request using a
  fresh 256-bit public query nonce and a lifetime no longer than two seconds.
- FR-10: A nonce response MUST be canonical, signed under a new domain-separated
  RSA message, and exactly bind request ID/hash, provider, custody policy,
  repository, query nonce, launcher nonce, expected and observed head,
  observation time, expiry, authority, and boolean `nonce_seen`.
- FR-11: The nonce callback MUST return only the exact boolean from a current,
  correctly signed response; missing, late, replayed, cross-request,
  cross-head, or cross-nonce responses MUST fail closed.
- FR-12: The CAS callback MUST independently decode the exact proposal bytes
  with the byte-identical canonical custody schema and MUST bind its
  custody-policy hash and predecessor to the adapter policy, the caller
  argument, and the most recently verified external head before publishing a
  request.
- FR-13: The CAS request MUST be canonical, create-exclusive, deterministic for
  the same proposal, bounded to the proposal expiry, and bind the exact raw
  proposal hash plus every identity needed to prevent cross-provider,
  cross-policy, cross-repository, or cross-lane substitution.
- FR-14: The CAS callback MUST publish at most one request and MUST NOT retry or
  create a second request after timeout, interruption, ambiguous publication,
  missing response, or response-verification failure.
- FR-15: A CAS response MUST exactly bind the request and contain one canonical
  checkpoint plus one canonical acknowledgement. Both embedded documents MUST
  be independently decoded without producer imports, authority-checked,
  RSA-verified with the existing byte-identical public signature domains,
  proposal-bound, predecessor-bound, sequence-bound, nonce-bound, and
  time-bound before their exact canonical bytes are returned.
- FR-16: After an accepted CAS response, the adapter MUST NOT claim durable
  success, mutate an in-memory head, or mark a nonce locally. The existing
  custody core MUST still perform independent head and nonce readback before it
  can mint a launch capability.
- FR-17: Public callback calls MUST be serialized per adapter instance. A
  concurrent or re-entrant call MUST fail without publishing another request or
  returning cached authority.
- FR-18: All adapter failures MUST expose a stable uppercase non-secret reason
  code and MUST NOT include path contents, proposal contents, credentials,
  account logins, tokens, private keys, signatures, or broker payloads.
- FR-19: The adapter MUST use only Python standard-library plus the existing
  consumer-safe `execution_policy`, asymmetric public-verification, and
  canonical-JSON primitives. It MUST NOT import producer-side custody,
  admission, acceptance, handoff, or launch-session modules, MUST contain no
  private-key operation, and MUST contain no MT5 import, task/service mutation,
  process launch, socket/HTTP client, SQLite, permit, policy mutation, or
  broker-order primitive.
- FR-20: The Windows Execution release MUST include the exact adapter and its
  required existing consumer closure while retaining
  `production_execution_ready=false`, checked-in `live_allowed=false`, and all
  existing order gates.
- FR-21: Project status, runbook, and ship-gate documentation MUST state that
  the adapter is only a client primitive and that an independently operated
  atomic service, mount/ACL evidence, actual signed responses, provider-bound
  evidence, central unlock, and first reconciled broker canary remain required.

## Non-Functional Requirements

- NFR-1: Construction and one immediate checkpoint read MUST complete within
  250 ms on the project test host, excluding externally configured polling.
- NFR-2: The response timeout MUST be a finite exact number in `(0, 2]` seconds;
  polling MUST use a fixed interval no greater than 10 ms and MUST stop on both
  trusted-UTC expiry and monotonic deadline.
- NFR-3: Every protocol file MUST be at most 1 MiB and every JSON object MUST
  reject duplicate keys, non-finite values, unknown fields, non-UTF-8 data, and
  noncanonical encoding before field-level processing continues.
- NFR-4: File reads MUST compare pre-read and post-read identity, type, size,
  timestamps, and reparse state. Request publication MUST use exclusive create,
  flush, file sync, directory sync where supported, and exact readback.
- NFR-5: No security decision MAY rely on `assert`, process-local cache,
  filename ordering, wall-clock-only timeout, environment variables, current
  working directory, or mutable default arguments.
- NFR-6: Security behavior MUST be identical under normal Python and
  `PYTHONOPTIMIZE=2`.
- NFR-7: Tests MUST cover every acceptance criterion and edge case with
  deterministic RSA fixtures, fake monotonic time, and effect traces. Tests
  MUST prove zero broker, MT5, task, process, network, credential, and policy
  mutation.
- NFR-8: Focused normal and optimized tests, full normal and optimized
  regression suites, compile checks, dependency-lock verification, JSON and
  whitespace checks, release-builder tests, and the ship gate MUST run before
  handoff.
- NFR-9: Identical valid input MUST yield byte-identical request payloads; only
  a fresh nonce query is intentionally unique because it represents a new
  observation.
- NFR-10: The adapter MUST remain usable from an isolated extracted Windows
  Execution release without importing operator-only producer, acceptance,
  WORM-handoff, or private-key tooling.

## Acceptance Criteria

### AC-1: Additive callback surface (FR-1, FR-2, FR-19)

Given the existing LIVE custody and provider-bound consumer modules
When the new adapter is imported and inspected
Then all existing public contracts and hashes remain unchanged
And the adapter exposes the exact three required callback signatures
And its static source contains no forbidden effect primitive.

### AC-2: Exact construction and path safety (FR-3 through FR-5, NFR-1)

Given exact canonical public policy bytes/pin and two distinct real absolute
directories
When the adapter is constructed
Then construction completes within 250 ms without reading or writing a file
And a wrong pin, unsafe policy, missing root, same root, relative root,
symlink, reparse point, or producer policy object is rejected with a stable
reason.

### AC-3: Genesis and signed head read (FR-6, FR-7, FR-8, NFR-3, NFR-4)

Given a locked central policy and an independently controlled response root
When no current head exists
Then the checkpoint callback returns `None`
And when one exact signed checkpoint exists it returns byte-identical bytes
And malformed, changed, oversized, indirect, forged, or wrong-authority heads
are rejected.

### AC-4: Signed nonce observations (FR-9 through FR-11, NFR-2, NFR-9)

Given locked policy, a current signed head, and an external responder
When the nonce callback queries an unseen and then a seen nonce
Then each invocation publishes one distinct canonical query
And accepts only the exact current signed response
And returns `false` followed by `true` without any local nonce mutation.

### AC-5: Exact CAS success (FR-12 through FR-16)

Given a current signed predecessor, exact proposal bytes, and a responder that
atomically accepts the predecessor
When the CAS callback runs
Then exactly one canonical request is published
And the exact independently signed checkpoint and acknowledgement bytes are
returned
And no local head or nonce claim is created.

### AC-6: CAS ambiguity is terminal (FR-13, FR-14, FR-18, NFR-2)

Given a missing, late, interrupted, conflicting, rejected, or malformed CAS
response
When the CAS callback reaches its deadline or verification fails
Then it returns no bytes, emits a stable non-secret reason, and publishes no
second request.

### AC-7: Cryptographic and binding rejection (FR-4, FR-8, FR-10, FR-15)

Given a response with a wrong provider, policy, repository, request, proposal,
predecessor, sequence, nonce, head, timestamp, authority, public-key
fingerprint, signature, or safety field
When any callback validates it
Then validation fails before returning a callback result.

### AC-8: Central-lock race closure (FR-6, FR-16, FR-19)

Given a central lock that changes before or after any clock, entropy, write,
read, or sleep effect
When a callback executes
Then it fails with the central-lock reason before the next effect
And it never returns authority or mutates the policy.

### AC-9: Serialized instance behavior (FR-17, NFR-5)

Given one adapter instance with an in-flight callback
When another thread or a re-entrant callback invokes it
Then the second call fails immediately and no duplicate request is published.

### AC-10: Authoritative-core compatibility (FR-2, FR-8, FR-11, FR-15,
FR-16)

Given the three bound adapter methods and a deterministic external responder
When `consume_live_canary_launch_reservation(...)` invokes them in its exact
order
Then the existing core performs pre-read, CAS, post-read, and nonce readback
And only that core can return a sealed `LiveCanaryOneUseLaunchCapability`.

### AC-11: Release closure and isolated import (FR-20, NFR-10)

Given a clean committed source tree
When the Windows Execution release is built and extracted
Then the adapter and exact import closure are present and import successfully
in normal and optimized isolated modes
And no producer-side custody, admission, acceptance, WORM-handoff, or
launch-session module is present or imported by the adapter
And release safety remains not production-ready and centrally locked.

### AC-12: Regression and honest status (FR-21, NFR-6 through NFR-8)

Given the completed implementation
When focused, full, optimized, compile, dependency, release, and ship-gate
checks run
Then automated checks pass without enabling LIVE
And the status remains `DO_NOT_SHIP LIVE TRADING` until external evidence and
the bounded unlock/canary ceremony exist.

## Edge Cases

- EC-1: The expected custody-policy hash is uppercase, zero, malformed, or
  does not equal the SHA-256 of the exact canonical policy bytes -> reject at
  construction.
- EC-1A: The custody policy input is an object, mutable mapping, string,
  noncanonical JSON, contains an unknown/duplicate field, or requires a
  producer-only decoder -> reject at construction.
- EC-2: Request and response paths are lexically different but resolve to the
  same directory, or either becomes a symlink/reparse point -> reject.
- EC-3: `current.checkpoint.json` disappears, changes identity, changes size,
  or is replaced during read -> reject as unstable, not genesis.
- EC-4: A zero-byte or greater-than-1-MiB head/query/CAS response -> reject.
- EC-5: Duplicate JSON fields, trailing newline, alternate whitespace,
  non-finite numbers, arrays, or unknown fields -> reject as noncanonical.
- EC-6: Entropy returns the wrong type/length, a reused query nonce, or raises
  -> reject before publishing the nonce query.
- EC-7: Trusted UTC is naive, non-UTC, regresses, raises, reaches request
  expiry, or conflicts with monotonic deadline -> reject.
- EC-8: A nonce response is validly signed but for the prior query or prior
  head -> reject.
- EC-9: Proposal bytes are noncanonical, use a different custody policy, name
  a different predecessor, or are already expired -> reject before write.
- EC-10: An identical CAS request file already exists with identical bytes ->
  resume bounded response observation without writing again; different bytes
  at the same derived path -> reject conflict.
- EC-11: CAS response exists but current head is not yet published -> return the
  signed CAS pair only; the authoritative core's mandatory subsequent head
  readback must still fail until the external service publishes it.
- EC-12: A callback times out after the request may have been accepted -> emit
  an ambiguity reason and never retry automatically; the nonce is treated as
  potentially consumed.
- EC-13: A signed response uses the correct key but any readiness/authority
  safety boolean is true or order capability is not `DISABLED` -> reject.
- EC-14: Callback invocations overlap across threads or recurse through an
  injected effect -> reject the later invocation without blocking.
- EC-15: Central policy is already true, has inconsistent decision reasons, or
  changes during a callback -> reject; this adapter is intentionally unusable
  after the unlock ceremony.
- EC-16: Direct local fixture directories pass syntax checks but lack external
  custody evidence -> tests MAY execute, but project documentation and reports
  MUST NOT classify them as production CAS acceptance.

## API Contracts

N/A for HTTP — the client uses an independently controlled directory mount;
it adds no web endpoint. In particular, `POST /api/live-canary/cas` is not
defined or implemented by this feature. The canonical file protocol is defined
below.

```typescript
type Sha256 = string;
type CanonicalUtc = string;

interface LiveCanaryDirectoryCasRequest {
  readonly schema_version: "windows-live-canary-directory-cas-request-v1";
  readonly request_id: Sha256;
  readonly provider_id: string;
  readonly custody_policy_sha256: Sha256;
  readonly worm_repository_alias_sha256: Sha256;
  readonly expected_predecessor_checkpoint_sha256: Sha256;
  readonly proposal_sha256: Sha256;
  readonly proposal: LiveCanaryLaunchReservationProposal;
  readonly issued_at_utc: CanonicalUtc;
  readonly expires_at_utc: CanonicalUtc;
  readonly live_allowed: false;
  readonly execution_authorized: false;
  readonly bootstrap_authorized: false;
  readonly process_launch_authorized: false;
  readonly order_capability: "DISABLED";
}

interface LiveCanaryDirectoryCasResponse {
  readonly schema_version: "windows-live-canary-directory-cas-response-v1";
  readonly request_id: Sha256;
  readonly request_sha256: Sha256;
  readonly provider_id: string;
  readonly custody_policy_sha256: Sha256;
  readonly worm_repository_alias_sha256: Sha256;
  readonly checkpoint: LiveCanaryLaunchReservationCheckpoint;
  readonly acknowledgement: LiveCanaryLaunchReservationAcknowledgement;
  readonly responded_at_utc: CanonicalUtc;
}

interface LiveCanaryNonceQueryRequest {
  readonly schema_version: "windows-live-canary-nonce-query-request-v1";
  readonly request_id: Sha256;
  readonly provider_id: string;
  readonly custody_policy_sha256: Sha256;
  readonly worm_repository_alias_sha256: Sha256;
  readonly launcher_nonce_sha256: Sha256;
  readonly expected_head_sha256: Sha256;
  readonly query_nonce_sha256: Sha256;
  readonly issued_at_utc: CanonicalUtc;
  readonly expires_at_utc: CanonicalUtc;
  readonly live_allowed: false;
  readonly execution_authorized: false;
  readonly bootstrap_authorized: false;
  readonly process_launch_authorized: false;
  readonly order_capability: "DISABLED";
}

interface LiveCanaryNonceQueryResponse {
  readonly schema_version: "windows-live-canary-nonce-query-response-v1";
  readonly request_id: Sha256;
  readonly request_sha256: Sha256;
  readonly provider_id: string;
  readonly custody_policy_sha256: Sha256;
  readonly worm_repository_alias_sha256: Sha256;
  readonly launcher_nonce_sha256: Sha256;
  readonly expected_head_sha256: Sha256;
  readonly observed_head_sha256: Sha256;
  readonly query_nonce_sha256: Sha256;
  readonly nonce_seen: boolean;
  readonly observed_at_utc: CanonicalUtc;
  readonly expires_at_utc: CanonicalUtc;
  readonly custody_issuer_id: string;
  readonly custody_key_id: string;
  readonly public_key_fingerprint_sha256: Sha256;
  readonly signature_algorithm: "RSASSA-PKCS1-v1_5-SHA256";
  readonly signature_rsa_pkcs1v15_sha256_hex: string;
  readonly live_allowed: false;
  readonly execution_authorized: false;
  readonly bootstrap_authorized: false;
  readonly process_launch_authorized: false;
  readonly order_capability: "DISABLED";
}
```

```text
WindowsLiveCanaryExternalCasDirectoryAdapter(
    *,
    provider_id: str,
    custody_policy_payload: bytes,
    expected_custody_policy_sha256: str,
    request_directory: str | Path,
    response_directory: str | Path,
    clock_provider: Callable[[], datetime],
    timeout_seconds: float,
    entropy_provider: Callable[[int], bytes] = os.urandom,
    sleeper: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
)

checkpoint_provider() -> bytes | None

checkpoint_cas(
    expected_predecessor_checkpoint_sha256: str,
    proposal_payload: bytes,
) -> tuple[bytes, bytes]

nonce_seen_provider(launcher_nonce_sha256: str) -> bool

live_canary_nonce_query_response_signing_message(
    response: Mapping[str, object],
) -> bytes
```

Every failure raises
`WindowsLiveCanaryExternalCasDirectoryAdapterError(reason_code)`; no error
response contains external document content or secret material.

## Data Models

| Model | Field | Type | Constraints |
|---|---|---|---|
| Adapter | `provider_id` | identifier | exact, non-empty, bounded |
| Adapter | `custody_policy_payload` | exact canonical public JSON bytes | independently parsed, pinned SHA-256 and locked safety; producer object rejected |
| Adapter | `request_directory` | absolute directory | existing, real, distinct, immediate-child writes only |
| Adapter | `response_directory` | absolute directory | existing, real, distinct, immediate-child reads only |
| Adapter | timing providers | callables | trusted UTC plus monotonic deadline, at most two seconds |
| CAS request | proposal closure | canonical object | exact predecessor/policy/repository/proposal hash |
| CAS response | checkpoint and acknowledgement | canonical signed objects | exact request/proposal/predecessor/sequence/nonce/authority |
| Nonce query | query identity | canonical object | fresh 256-bit query nonce and current-head pin |
| Nonce response | observation | canonical signed object | exact query/head/nonce and boolean state |
| Error | `reason_code` | uppercase identifier | stable, non-secret, no raw provider exception |

No database table, local durable nonce record, credential record, broker
record, or executable authority model is introduced.

## Out of Scope

- OS-1: Implementing or selecting the independently operated CAS server,
  cloud vendor, WORM repository, SMB/VPN transport, mount provisioning, ACL,
  backup, disaster recovery, uptime monitoring, or billing.
- OS-2: Generating or accessing the custody RSA private key, broker credential,
  Windows Credential Manager secret, TLS secret, account login, permit,
  promotion key, or approval key.
- OS-3: Treating local directories, synthetic RSA fixtures, an offline handoff
  assessment, or passing unit tests as actual external CAS/WORM evidence.
- OS-4: Verifying provider acceptance, issuing provider-bound admission/WORM
  custody, changing `execution_policy.LIVE_ALLOWED`, performing the central
  unlock ceremony, or activating the provider-bound runtime launch session.
- OS-5: Building concrete Windows runtime providers other than these three CAS
  callbacks, starting a task/service/process, importing or initializing MT5,
  reading a broker account, minting per-order authority, or submitting an
  order.
- OS-6: Relaxing the 0.01-lot XAUUSD canary scope, statistical XM demo-soak
  requirements, three-person approval, nine gate receipts, reconciliation,
  rollback, or any existing safety boundary.
- OS-7: Claiming LIVE readiness or 100% completion. Until actual target-host
  artifacts and independently retained external evidence exist, the verdict
  remains `DO_NOT_SHIP LIVE TRADING`.
