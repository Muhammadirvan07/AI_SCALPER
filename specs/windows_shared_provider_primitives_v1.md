# Spec: Windows Shared Provider Primitives v1

**Author:** Codex with AI_SCALPER project owner  
**Date:** 2026-07-25  
**Status:** Approved  
**Reviewers:** AI_SCALPER project owner under the standing authorization to
continue the live-grade roadmap while preserving every execution and live
lock  
**Related specs:**
`specs/windows_decision_provider_pack_v1.md`,
`specs/windows_external_status_monitor_v1.md`,
`specs/windows_three_service_provider_conformance_v2.md`,
`specs/windows_atomic_base_release_suite_v1.md`

## Context

The reviewed Windows Decision provider foundation contains two security
primitives that are not decision-domain operations: exact read-only lookup of
allowlisted HMAC keys from Windows Credential Manager and a monotonic trusted
UTC provider backed by a fresh externally signed clock attestation. The
Status Monitor and future Execution provider foundations require the same
capabilities. Importing `windows_decision_provider_pack` from either service
would also import decision-feed, decision-IPC, cursor, and producer modules,
violating the three-service release boundary.

Copying the credential and clock implementation would be equally unsafe.
Separate copies could drift in credential decoding, fingerprint verification,
clock freshness, HMAC verification, or regression detection. The correct
architecture is one standard-library-only primitive module beneath all three
service adapters. Decision must retain its existing public import surface and
exact v1 cryptographic behavior so already reviewed tests, manifests, and
provider inputs continue to mean the same thing.

This feature extracts only the generic credential and clock capabilities. It
does not materialize a Status Monitor provider pack, access a credential
during release construction, open mutable provider state, install a task,
initialize MT5, or grant execution authority.

## Functional Requirements

- FR-1: The repository MUST provide
  `live_runtime.windows_provider_primitives` as the single implementation
  module for `CredentialReference`,
  `WindowsCredentialManagerKeyProvider`, `WindowsClockBinding`,
  `WindowsClockAttestation`, `AttestedTrustedUTCProvider`,
  `issue_windows_clock_attestation`, and key-material validation used by
  Windows service provider adapters.
- FR-2: The shared module MUST import only Python standard-library modules
  and `live_runtime.contracts`. It MUST NOT import Decision, Execution,
  Status Monitor, broker, MT5, risk, intent, permit, task, subprocess,
  networking, or dynamic-loader modules.
- FR-3: The Windows Credential Manager provider MUST remain read-only and
  accept exactly one reviewed target prefix plus a closed, case-exact,
  duplicate-free mapping of key ID, target name, and full SHA-256
  fingerprint.
- FR-4: Credential lookup MUST read only the exact allowlisted generic
  credential target and MUST reject non-Windows platforms, unknown key IDs,
  missing credentials, malformed encoding, key material shorter than 32
  bytes, key material longer than 4,096 bytes, fingerprint mismatch, and
  native-backend failure.
- FR-5: The credential provider MUST NOT enumerate, create, update, delete,
  serialize, log, persist, or cache credential values and MUST NOT expose its
  native backend through the public object surface.
- FR-6: The trusted-clock provider MUST require an exact
  `WindowsClockBinding`, an exact `WindowsClockAttestation`, an allowlisted
  verification key, aware UTC from the system clock, and an exact SHA-256 key
  fingerprint.
- FR-7: Trusted UTC MUST reject a forged, stale, expired, future-issued,
  binding-mismatched, excessive-drift, naive, or regressing observation before
  returning a timestamp.
- FR-8: Extraction MUST preserve the existing v1 schemas, canonical
  payload fields, HMAC domain bytes, derived `content_sha256` values, stable
  reason codes, exact key-decoding behavior, freshness limits, and monotonic
  behavior byte-for-byte, except that credential identifiers and targets
  differing only by case MUST now be rejected as ambiguous under EC-1.
- FR-9: `live_runtime.windows_decision_provider_pack` MUST re-export the
  extracted public types and functions under their existing names, including
  `WindowsDecisionProviderError`, without defining a second implementation.
- FR-10: Existing imports from
  `live_runtime.windows_decision_provider_pack` MUST remain source-compatible,
  and values constructed through the old and new import paths MUST have exact
  type identity rather than merely equivalent fields.
- FR-11: The Decision base-release allowlist MUST include the shared
  primitive module because the Decision provider foundation imports it.
- FR-12: The Status Monitor base-release allowlist MUST include the shared
  primitive module as a reviewed provider foundation dependency for the next
  Status Monitor provider-pack slice, while the module itself remains
  non-materializing.
- FR-13: Release builders MUST include the shared module only in
  `DECISION` and `STATUS_MONITOR`; it MUST remain absent from read-only shadow,
  configured operator tooling, and unrelated release profiles unless an
  approved later spec adds a direct consumer.
- FR-14: Every exported primitive MUST preserve
  `order_capability=DISABLED`, `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `promotion_eligible=false`,
  `production_execution_ready=false`, and `max_lot=0.01` as module-level
  safety declarations.
- FR-15: Importing or validating the shared module MUST perform no
  credential access, filesystem write, process launch, network access, task
  installation, provider materialization, MT5 initialization, or broker
  mutation.
- FR-16: The source change MUST update exact release allowlists,
  deterministic builder tests, project status, ship-gate evidence, and
  operator documentation without adding any dashboard source.
- FR-17: Every generated Decision provider `implementation_sha256` MUST bind
  the exact bytes and paths of both
  `live_runtime/windows_decision_provider_pack.py` and
  `live_runtime/windows_provider_primitives.py` from the verified Decision
  base release. A missing, empty, oversized, duplicate, or unreadable member
  MUST fail before any provider-pack output is created.

## Non-Functional Requirements

- NFR-1: Security — No secret bytes, credential values, private keys,
  account logins, permits, arms, or activation flags may be accepted through
  release configuration or emitted through errors, representations, logs, or
  serialized objects.
- NFR-2: Compatibility — All existing Decision provider-pack tests MUST
  pass without changing their import statements or expected reason codes.
- NFR-3: Isolation — Static import analysis of the shared module MUST show
  no import outside the standard library and `live_runtime.contracts`.
- NFR-4: Determinism — Identical inputs MUST produce identical canonical
  contract dictionaries, hashes, clock-attestation payloads, and signatures.
- NFR-5: Performance — A successful injected-backend credential lookup
  MUST complete in under 250 ms and a trusted-clock verification MUST complete
  in under 100 ms on the normal development host.
- NFR-6: Concurrency — Concurrent calls to one trusted-clock provider MUST
  serialize monotonic-state updates and MUST reject any timestamp lower than
  the greatest previously returned timestamp.
- NFR-7: Portability — Import, construction, canonicalization, and tests
  MUST run on macOS and Windows. Native credential access MUST reject
  non-Windows platforms before invoking a backend.
- NFR-8: Regression — Focused tests and the full tracked-project suite MUST
  pass with normal Python and `PYTHONOPTIMIZE=2`; compilation, dependency lock,
  SBOM, release-boundary, and safety scans MUST remain green.

## Acceptance Criteria

### AC-1: Shared type identity (FR-1, FR-9, FR-10; NFR-2)

Given imports of each public credential and clock symbol from both the shared
module and the Decision compatibility module  
When their identities are compared  
Then every corresponding class and function is the exact same Python object  
And Decision contains no duplicate implementation.

### AC-2: Exact read-only credential lookup (FR-3, FR-4, FR-5; NFR-1)

Given an injected Windows backend containing one exact allowlisted hex-encoded
256-bit key  
When the provider resolves its exact key ID twice  
Then it returns the exact key both times  
And the backend records only two reads of the exact target  
And no cache, enumeration, or mutation surface is exposed.

### AC-3: Credential failures are stable and secret-free (FR-4; NFR-1)

Given a non-Windows platform, unknown key, missing record, malformed encoding,
short key, oversized key, native failure, or fingerprint mismatch  
When lookup occurs  
Then a stable provider error is raised  
And neither the raw credential nor its hexadecimal representation appears in
the exception.

### AC-4: Trusted UTC preserves v1 cryptography (FR-6, FR-7, FR-8; NFR-4)

Given the same binding, timestamps, and key used by the pre-extraction
Decision implementation  
When a clock attestation is issued through either import path  
Then its canonical dictionary, `content_sha256`, and HMAC are identical  
And a fresh valid attestation returns exact aware UTC.

### AC-5: Clock failures remain fail-closed (FR-7, FR-8; NFR-1)

Given forged, stale, expired, future, drifted, binding-mismatched, naive, or
regressing time evidence  
When trusted UTC is requested  
Then the exact previously reviewed reason code is raised  
And no timestamp is returned.

### AC-6: Concurrent monotonicity (FR-7; NFR-6)

Given multiple concurrent callers and a sequence containing a regressing
system timestamp  
When all callers invoke one provider  
Then no regressing timestamp is returned  
And at least the regressing call fails closed with
`TRUSTED_CLOCK_REGRESSION`.

### AC-7: Shared module is service-neutral (FR-2, FR-15; NFR-3)

Given the AST and import closure of the shared module  
When it is audited  
Then imports are limited to the standard library and
`live_runtime.contracts`  
And no broker, order, MT5, network, subprocess, dynamic import, task, or
credential mutation token is executable.

### AC-8: Exact release partition (FR-11, FR-12, FR-13, FR-16)

Given all fixed Windows release allowlists  
When their source sets are inspected and deterministic releases are built  
Then the shared module is present in Decision and Status Monitor only  
And remains absent from Execution, read-only shadow, and configured tooling.

### AC-9: Import has zero effects (FR-15; NFR-1, NFR-7)

Given instrumented credential, filesystem, process, network, MT5, and broker
surfaces  
When the shared module is imported and its static contracts are constructed  
Then none of those effectful surfaces is called.

### AC-10: Full regression and safety state (FR-14, FR-16; NFR-8)

Given the completed extraction and allowlist updates  
When focused, full, optimized, compilation, dependency, SBOM, release, and
safety checks run  
Then all checks pass  
And every activation lock remains false with `max_lot=0.01`.

### AC-11: Transitive provider implementation binding (FR-11, FR-17; NFR-4)

Given a verified Decision base release containing the Decision foundation and
the shared primitive module  
When provider implementation hashes are generated  
Then each hash binds a canonical, path-sorted list containing the SHA-256 of
both exact source members  
And changing either member changes every affected implementation hash  
And omitting either member fails closed before creating an output directory.

## Edge Cases

- EC-1: Duplicate key IDs differing only by case MUST be rejected.
- EC-2: A credential target outside the exact prefix or containing path
  ambiguity MUST be rejected before backend access.
- EC-3: UTF-16LE `hex:` credential blobs MUST remain supported exactly as
  before extraction.
- EC-4: Odd-length hex, non-hex characters, embedded NUL, empty blobs, and
  undecodable bytes MUST fail without including the blob in errors.
- EC-5: An authority key provider that throws an exception containing key
  material MUST be converted to a stable secret-free reason code.
- EC-6: An attestation with an aware non-UTC offset that canonicalizes to
  the same instant MUST follow existing `require_utc` behavior without a new
  implicit conversion.
- EC-7: Equality at exact maximum age and exact maximum drift MUST preserve
  existing boundary semantics.
- EC-8: Two simultaneous equal timestamps MAY both succeed; a lower value
  after either success MUST fail.
- EC-9: Direct construction with invalid schemas, zero hashes, non-finite
  limits, or non-exact booleans MUST preserve existing validation failures.
- EC-10: `PYTHONOPTIMIZE=2` MUST NOT bypass any validation currently
  implemented through explicit checks.
- EC-11: A release allowlist containing the shared module in an
  unauthorized role MUST fail its exact allowlist test.
- EC-12: Dashboard directories and virtual environments MUST remain
  untracked and outside all release source sets.
- EC-13: A Decision archive containing duplicate ZIP members for either
  bound implementation path MUST be rejected rather than accepting the first
  or last member.

## API Contracts

```typescript
interface CredentialReference {
  key_id: string;
  target_name: string;
  fingerprint_sha256: Hex64;
}

interface WindowsCredentialManagerKeyProvider {
  readonly target_prefix: string;
  call(key_id: string): bytes;
}

interface WindowsClockBinding {
  provider_id: string;
  host_identity_sha256: Hex64;
  authority_issuer_id: string;
  authority_key_id: string;
  authority_key_fingerprint_sha256: Hex64;
  maximum_attestation_age_ms: integer;
  maximum_absolute_drift_ms: integer;
  schema_version: "windows-clock-binding-v1";
}

interface WindowsClockAttestation {
  provider_id: string;
  binding_sha256: Hex64;
  host_identity_sha256: Hex64;
  authority_issuer_id: string;
  authority_key_id: string;
  authority_key_fingerprint_sha256: Hex64;
  authority_utc: UTCDateTime;
  observed_system_utc: UTCDateTime;
  issued_at_utc: UTCDateTime;
  expires_at_utc: UTCDateTime;
  hmac_sha256: Hex64;
  schema_version: "windows-clock-attestation-v1";
}

interface AttestedTrustedUTCProvider {
  call(): UTCDateTime;
}

type PrimitiveFailure = {
  reason_code: UppercaseReasonCode;
  secret_material: never;
};
```

No HTTP, RPC, broker, order, task-installation, or credential-mutation API is
introduced.

## Data Models

| Model | Field | Type | Constraints |
|---|---|---|---|
| CredentialReference | `key_id` | string | Opaque, case-exact, non-empty |
| CredentialReference | `target_name` | string | Exact prefix-bound target |
| CredentialReference | `fingerprint_sha256` | string | Lowercase full SHA-256 |
| WindowsClockBinding | `provider_id` | string | Opaque reviewed ID |
| WindowsClockBinding | `host_identity_sha256` | string | Non-zero SHA-256 |
| WindowsClockBinding | `authority_issuer_id` | string | Opaque issuer ID |
| WindowsClockBinding | `authority_key_id` | string | Exact credential key ID |
| WindowsClockBinding | `authority_key_fingerprint_sha256` | string | Exact SHA-256 |
| WindowsClockBinding | `maximum_attestation_age_ms` | integer | Existing v1 bound |
| WindowsClockBinding | `maximum_absolute_drift_ms` | integer | At most 1,000 |
| WindowsClockAttestation | UTC fields | aware datetime | Exact UTC required |
| WindowsClockAttestation | `hmac_sha256` | string | Exact v1 domain HMAC |
| Provider state | greatest returned UTC | datetime | Memory-only, monotonic |

No database table, credential record, registry key, environment variable, or
network resource is created by this feature.

## Out of Scope

- OS-1: Building the complete Status Monitor provider pack, configured
  candidate, task definition, or external custody service. Those follow in a
  separate approved spec after this prerequisite is green.
- OS-2: Refactoring Decision IPC or producer external CAS adapters. Their
  domain-specific behavior remains in the Decision provider foundation.
- OS-3: Changing the v1 clock schema or HMAC domain. Compatibility is more
  important than renaming the historical domain in this slice.
- OS-4: Reading or provisioning real Windows credentials during build or
  validation.
- OS-5: Implementing network time synchronization, NTP, certificate
  validation, remote APIs, or automatic failover.
- OS-6: Enabling manual-demo, demo-auto, live trading, order submission,
  permits, arm flags, or promotion.
- OS-7: Integrating `dashboard_api/`, `frontend-dashboard/`, or
  `.venv-dashboard/`.
