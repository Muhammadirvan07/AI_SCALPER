# Windows Three-Service Provider Conformance Review v1

## Title and Metadata

- **Title:** Windows Three-Service Provider Conformance Review v1
- **Author:** Codex / AI_SCALPER maintainers
- **Date:** 2026-07-24
- **Status:** Approved
- **Reviewers:** AI_SCALPER owner under the standing Live-Grade v1 roadmap
  authorization; independent Windows service owners remain required for the
  external acceptance signatures

## Context

AI_SCALPER already has deterministic decision, execution, and external-status
monitor releases; strict configured-overlay packaging; exact factory-template
contracts; and a public-key external-acceptance verifier. The current local
tooling can prove which provider source and configuration hashes are packaged,
but it does not produce one canonical, provider-level review packet that
enumerates every required role or port and binds it to externally produced
conformance evidence.

This gap matters because a gate-level statement such as “factory providers
accepted” is too coarse to audit. A reviewer needs to know which exact
configured release, factory template, provider binding, implementation,
configuration, test suite, and evidence artifact was reviewed. The decision,
execution, and status-monitor services also use different template schemas and
role vocabularies, which makes manual reconciliation error-prone.

This feature adds an offline, deny-only verifier. It validates one strict JSON
input, reconstructs all three existing factory templates through their
authoritative validators, requires exactly one conformance evidence record per
provider binding, and emits a canonical create-exclusive review packet. The
packet is suitable as the `details_sha256` target of the existing independent
RSA acceptance-observation process. It is not provider acceptance, does not
verify the external evidence bytes, and cannot activate or execute anything.

## Functional Requirements

- FR-1: The system MUST accept exactly one strict JSON input using schema
  `windows-three-service-provider-conformance-input-v1` and MUST reject
  duplicate keys, non-finite numbers, unknown fields, non-canonical UTC text,
  oversized input, symlink/reparse input, and unstable file reads.
- FR-2: The input MUST bind a non-zero operations-plan SHA-256, operations
  review-bundle SHA-256, configured-release admission SHA-256, and exactly
  three distinct configured release identities.
- FR-3: The input MUST contain exactly one service entry for each role:
  `DECISION`, `EXECUTION`, and `STATUS_MONITOR`.
- FR-4: The `DECISION` entry MUST be reconstructed with
  `validate_windows_decision_service_factory_template`; its release profile
  and configured release identity MUST match the service entry.
- FR-5: The `EXECUTION` entry MUST be reconstructed with
  `validate_windows_service_factory_template`; its release profile, runtime
  mode `DEMO_AUTO`, and expected configured release identity MUST match the
  service entry.
- FR-6: The `STATUS_MONITOR` entry MUST be reconstructed with
  `validate_windows_external_status_monitor_factory_template`; its release
  profile and configured release identity MUST match the service entry.
- FR-7: Each service MUST contain exactly one evidence record for every
  provider role or port present in its validated factory template, and MUST
  reject missing, duplicate, extra, or cross-service records.
- FR-8: Every evidence record MUST exactly match the template’s provider
  role or port name, contract SHA-256, implementation SHA-256, configuration
  SHA-256, and provider binding SHA-256. For decision and status-monitor
  providers, custody mode MUST match. For execution providers, provider kind
  and credential reference ID MUST match.
- FR-9: Every evidence record MUST bind a non-zero conformance suite
  SHA-256 and evidence artifact SHA-256, a canonical reviewer ID, an aware UTC
  observation time, and the exact result `PASS`.
- FR-10: Every evidence record MUST assert all six bounded probe outcomes
  as exact `true`: interface contract, fail-closed behavior, secret
  non-export, restart recovery, custody boundary, and deterministic replay.
  These are reviewer claims for later independent signature, not facts
  manufactured by this verifier.
- FR-11: Evidence observations MUST be no more than 24 hours old and MUST
  not be in the future relative to an injected trusted UTC clock.
- FR-12: The system MUST produce canonical JSON using schema
  `windows-three-service-provider-conformance-review-v1`, including exact
  normalized service/provider inventories, per-service evidence-set hashes,
  an overall evidence-set hash, all topology hashes, readiness blockers, and
  a content SHA-256 computed over every field except itself.
- FR-13: A successful packet MUST report
  `PROVIDER_CONFORMANCE_PACKET_READY_EXTERNAL_SIGNATURE_REQUIRED`,
  `external_signature_required=true`, and fixed deny-only claims:
  `provider_accepted=false`, `activation_allowed=false`,
  `execution_enabled=false`, `task_install_allowed=false`,
  `credential_access_performed=false`, `provider_imported=false`,
  `provider_materialized=false`, `broker_mutation_performed=false`,
  `live_allowed=false`, `safe_to_demo_auto_order=false`,
  `promotion_eligible=false`, `order_capability=DISABLED`, and
  `max_lot=0.01`.
- FR-14: The CLI MUST stable-read the input exactly once, write the output
  create-exclusively, print the packet SHA-256 and explicit deny-only status,
  and MUST return a non-zero exit code without output on validation failure.
- FR-15: A public verifier MUST reconstruct the complete packet and reject
  any changed topology, template, provider inventory, evidence claim,
  blocker, safety claim, or content SHA-256.
- FR-16: Existing factory template, configured-release, admission, runtime,
  and external-acceptance APIs MUST remain unchanged.
- FR-17: The CLI, verifier module, and exact local contract dependencies MUST
  be included in the deterministic configured-release operator tooling
  allowlist and archive; the tooling security scan and import-closure
  validation MUST continue to prove that provider import, credential access,
  network access, task installation, runtime materialization, and broker
  mutation capabilities are absent.

## Non-Functional Requirements

- NFR-1 Security: The implementation MUST NOT import a configured provider,
  resolve a credential or key, inspect environment secrets, initialize MT5,
  call broker APIs, install/start tasks, spawn a subprocess, or access the
  network.
- NFR-2 Determinism: Identical semantic input and trusted clock MUST produce
  byte-identical canonical packet output on supported Python 3.12 hosts.
- NFR-3 Reliability: Validation MUST fail closed with stable, uppercase
  reason codes and MUST leave no partial output file.
- NFR-4 Performance: A maximum-size valid input MUST be validated and
  rendered in less than 2 seconds on the project’s normal test environment.
- NFR-5 Resource bounds: Input and packet JSON MUST each be at most
  4,194,304 bytes; service count MUST be exactly three; provider count MUST be
  bounded by the authoritative factory templates.
- NFR-6 Compatibility: The module and CLI MUST use the Python standard
  library plus existing repository modules only and MUST pass under normal
  execution and `PYTHONOPTIMIZE=2`.
- NFR-7 Auditability: Every normalized collection MUST be sorted
  deterministically, and every external evidence reference MUST be represented
  only by non-secret identifiers, hashes, UTC time, and bounded boolean claims.

## Acceptance Criteria

### AC-1: Complete deterministic packet (FR-2, FR-3, FR-4, FR-5, FR-6, FR-7, FR-8, FR-9, FR-10, FR-11, FR-12, FR-13)

**References:** FR-2 through FR-13, NFR-2.

Given valid decision, `DEMO_AUTO`
  execution, and status-monitor factory templates with one fresh passing
  evidence record per provider, when the review is prepared twice with the
  same trusted time, then both canonical packets and all hashes are identical,
  all inventories are complete, and all authority flags remain denied.

### AC-2: Service and provider binding rejection (FR-3, FR-4, FR-5, FR-6, FR-7, FR-8)

**References:** FR-3 through FR-8.

Given a missing service, duplicated service,
  wrong release identity/profile/runtime mode, missing/extra provider,
  mismatched provider hash, custody mode, provider kind, credential reference,
  or binding hash, when validation runs, then it fails closed with a stable
  reason code.

### AC-3: Evidence rejection (FR-9, FR-10, FR-11)

**References:** FR-9 through FR-11.

Given failed, stale, future, malformed, or
  partially false conformance evidence, when validation runs, then no packet
  is accepted.

### AC-4: Strict file boundary (FR-1, FR-14)

**References:** FR-1, FR-14, NFR-3, NFR-5.

Given duplicate-key, unknown-field,
  non-finite, oversized, symlink, unstable, or existing-output input, when the
  CLI runs, then it returns non-zero and does not create or overwrite output.

### AC-5: Full reconstruction (FR-12, FR-15)

**References:** FR-12, FR-15.

Given a valid packet with any nested field or hash
  changed and its outer SHA-256 recomputed, when the public verifier runs, then
  it rejects because reconstruction no longer matches the authoritative
  contracts.

### AC-6: No external authority (FR-13)

**References:** FR-13, NFR-1.

Given sentinels for import, credential, network,
  subprocess, MT5, task, and broker mutation boundaries, when preparation and
  verification run, then every sentinel remains untouched.

### AC-7: Canonical CLI output (FR-14)

**References:** FR-14, NFR-2, NFR-7.

Given valid canonical input, when the CLI
  succeeds, then it writes one newline-terminated canonical JSON file
  create-exclusively and prints the exact output path, packet SHA-256,
  `Provider acceptance: false`, and `Order capability: DISABLED`.

### AC-8: Compatibility (FR-16)

**References:** FR-16, NFR-6.

Given the full existing test suite, when the feature
  is added, then all prior tests plus the new tests pass in normal and
  optimized modes.

### AC-9: Bounded performance (FR-12)

**References:** NFR-4.

Given the complete authoritative provider inventory, when
  a valid packet is prepared and verified in a unit benchmark, then each
  operation completes in less than 2 seconds.

### AC-10: Deterministic operator tooling integration (FR-17)

**References:** FR-17, NFR-1, NFR-2, NFR-6.

Given a clean tracked Git commit, when configured-release operator tooling is
built twice, then both archives are byte-identical, contain the exact provider
review CLI/import closure, pass the existing static security scan, and retain
all deny-only usage-policy claims.

## Edge Cases

- EC-1: Input contains duplicate JSON keys at any depth.
- EC-2: Input contains `NaN`, positive infinity, or negative infinity.
- EC-3: One configured release identity is reused by two service roles.
- EC-4: A service role is missing, unknown, duplicated, or case-drifted.
- EC-5: The execution template uses `DEMO` instead of `DEMO_AUTO`.
- EC-6: A factory template is structurally valid but bound to a different
  configured release identity or release profile.
- EC-7: Evidence contains a provider not present in the template, omits a
  template provider, or duplicates one using case variation.
- EC-8: A provider record matches source hashes but not contract,
  configuration, custody, kind, credential reference, or binding hash.
- EC-9: Observation result is not exactly `PASS`, a probe flag is not exact
  boolean `true`, or a hash is zero/malformed.
- EC-10: Observation time is future, stale by more than 24 hours, naive,
  offset-formatted instead of canonical `Z`, or has non-canonical precision.
- EC-11: Trusted clock raises, returns a naive value, or moves backwards
  between start and completion.
- EC-12: Input changes between stable-read checks, is a symlink/reparse
  point, is not a regular file, exceeds the size limit, or contains invalid
  UTF-8.
- EC-13: Output exists, is inside an untrusted indirection, or cannot be
  created exclusively.
- EC-14: Packet content hash is valid for tampered outer content but one
  normalized nested object differs from authoritative reconstruction.
- EC-15: Provider implementation or reviewer identifiers contain secrets,
  whitespace drift, control characters, or unsupported punctuation.
- EC-16: Operator tooling omits a local import, includes an unapproved source,
  includes a forbidden import/call, or drifts from its exact allowlist.

## API Contracts

```typescript
type ServiceRole = "DECISION" | "EXECUTION" | "STATUS_MONITOR";

interface ProviderConformanceEvidenceInput {
  provider_role: string;
  provider_contract_sha256: Hex64;
  implementation_sha256: Hex64;
  configuration_sha256: Hex64;
  provider_binding_sha256: Hex64;
  custody_mode: string | null;
  provider_kind: "CALLABLE" | "COMPONENT" | null;
  credential_reference_id: string | null;
  conformance_suite_sha256: Hex64;
  evidence_artifact_sha256: Hex64;
  reviewer_id: CanonicalId;
  observed_at_utc: CanonicalUtcZ;
  result: "PASS";
  interface_contract_probe_passed: true;
  fail_closed_probe_passed: true;
  secret_non_export_probe_passed: true;
  restart_recovery_probe_passed: true;
  custody_boundary_probe_passed: true;
  deterministic_replay_probe_passed: true;
}

interface ServiceProviderConformanceInput {
  service_role: ServiceRole;
  configured_release_identity_sha256: Hex64;
  factory_template: object;
  provider_evidence: ProviderConformanceEvidenceInput[];
}

interface ThreeServiceProviderConformanceInput {
  schema_version: "windows-three-service-provider-conformance-input-v1";
  review_id: CanonicalId;
  operations_plan_sha256: Hex64;
  operations_review_bundle_sha256: Hex64;
  configured_release_admission_sha256: Hex64;
  services: ServiceProviderConformanceInput[];
}

interface ThreeServiceProviderConformanceReview {
  schema_version: "windows-three-service-provider-conformance-review-v1";
  review_id: CanonicalId;
  operations_plan_sha256: Hex64;
  operations_review_bundle_sha256: Hex64;
  configured_release_admission_sha256: Hex64;
  services: NormalizedServiceReview[];
  configured_release_set_sha256: Hex64;
  provider_evidence_set_sha256: Hex64;
  provider_count: number;
  checked_at_utc: CanonicalUtcZ;
  status: "PROVIDER_CONFORMANCE_PACKET_READY_EXTERNAL_SIGNATURE_REQUIRED";
  readiness_blockers: [
    "EXTERNAL_PROVIDER_OWNER_SIGNATURE_REQUIRED",
    "EXTERNAL_PROVIDER_RUNTIME_ATTESTATION_REQUIRED"
  ];
  external_signature_required: true;
  provider_accepted: false;
  activation_allowed: false;
  execution_enabled: false;
  task_install_allowed: false;
  credential_access_performed: false;
  provider_imported: false;
  provider_materialized: false;
  broker_mutation_performed: false;
  live_allowed: false;
  safe_to_demo_auto_order: false;
  promotion_eligible: false;
  order_capability: "DISABLED";
  max_lot: 0.01;
  content_sha256: Hex64;
}

prepare_windows_three_service_provider_conformance_review(
  payload: Mapping,
  *,
  clock_provider: () => AwareUtcDatetime
): ThreeServiceProviderConformanceReview;

verify_windows_three_service_provider_conformance_review(
  payload: Mapping,
  *,
  clock_provider: () => AwareUtcDatetime
): ThreeServiceProviderConformanceReview;

prepare_windows_three_service_provider_conformance_review_file(
  input_path: Path,
  output_path: Path,
  *,
  clock_provider: () => AwareUtcDatetime
): ThreeServiceProviderConformanceReview;
```

Errors use:

```typescript
class WindowsProviderConformanceError extends RuntimeError {
  reason_code: UppercaseReasonCode;
}
```

## Data Models

| Entity | Field | Type | Constraints |
|---|---|---|---|
| Input | `schema_version` | string | Exact input schema |
| Input | `review_id` | string | Canonical ID, 1–128 chars |
| Input | topology hashes | SHA-256 | Lowercase, non-zero |
| Input | `services` | array | Exactly three unique roles |
| Service | `service_role` | enum | Decision, execution, status monitor |
| Service | `configured_release_identity_sha256` | SHA-256 | Unique, non-zero, template-bound |
| Service | `factory_template` | object | Existing authoritative template schema |
| Service | `provider_evidence` | array | Exact one-to-one template coverage |
| Evidence | provider identity fields | strings/hashes/null | Exact template match |
| Evidence | evidence hashes | SHA-256 | Non-zero |
| Evidence | `reviewer_id` | string | Canonical non-secret ID |
| Evidence | `observed_at_utc` | UTC text | Canonical microsecond `Z`, fresh <=24h |
| Evidence | `result` | enum | Exact `PASS` |
| Evidence | probe outcomes | booleans | All exact `true` |
| Review | normalized services | array | Sorted by service role |
| Review | set hashes | SHA-256 | Canonical inventories |
| Review | deny-only claims | booleans/enums | Fixed values from FR-13 |
| Review | `content_sha256` | SHA-256 | Hash of all preceding fields |

## Out of Scope

- OS-1: Importing, executing, or materializing any provider or factory.
- OS-2: Reading Credential Manager, private keys, environment secrets, or MT5 login
  material.
- OS-3: Verifying the bytes behind an external evidence-artifact hash.
- OS-4: Issuing or verifying the independent RSA provider-owner observation; the
  existing external-acceptance workflow performs that step.
- OS-5: Installing Task Scheduler tasks, changing ACLs, launching services, opening
  network connections, initializing MT5, calling `order_check`/`order_send`,
  or creating broker orders.
- OS-6: Declaring provider acceptance, configured-release acceptance, activation,
  demo-auto readiness, promotion eligibility, or live readiness.
- OS-7: Changing any existing runtime, factory, release, risk, permit, stage, or
  execution contract.
