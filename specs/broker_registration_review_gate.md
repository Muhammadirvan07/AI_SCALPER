# Spec: Signed Broker Evidence Registration Review Gate

**Author:** AI_SCALPER Engineering

**Date:** 2026-07-21

**Status:** Approved

**Reviewer:** Project owner through explicit approval on 2026-07-21; independent regulatory/calendar reviewers still issue runtime approvals
**Related specs:** `phillip_lane_evidence_contract.md`,
`prospective_calendar_amendment_chain.md`, `architecture_foundation_completion_v1.md`

## Context

AI_SCALPER already verifies two independently signed regulatory approvals in
the broker calendar-plan core. However, the operator CLIs do not yet provide a
safe way to capture official source files, create the evidence body, provision
review keys, produce the two approval artifacts, assemble the final
observation, or load those reviewer keys during plan and contract verification.
The tracked Phillip observations therefore remain descriptive placeholders and
both evidence profiles correctly retain `registration_enabled=false`.

As of 2026-07-21, the official Japan FSA registry lists Phillip Securities
Japan, Ltd. as Kanto Finance Bureau (Kinsho) No. 127. Phillip's official pages
publish the legal entity, FX hours, 2026 daylight-saving transition, and XAU
hours. These facts support preparation of a review package, but neither this
software nor its operator may convert them into legal advice or silently
approve evidence registration.

This feature closes only the local tooling gap. It creates a reproducible,
immutable, signed review package whose final application still requires an
explicit human-reviewed clean commit. It MUST NOT enable order submission,
demo-auto, promotion, or live trading.

## Functional Requirements

- FR-1: The system MUST prepare one immutable regulatory evidence body for exactly one broker candidate and operating jurisdiction from tracked candidate facts, a reviewed broker-calendar template, and operator-supplied official source files.
- FR-2: Each source MUST use an allowlisted HTTPS authority URL and MUST bind authority, entity, registry/result identifier, observed-at UTC, byte length, and a SHA-256 computed from the supplied regular file; caller-supplied content hashes MUST NOT be trusted.
- FR-3: The evidence body MUST bind the exact candidate ID, legal entity, broker server, environment, binding scope, canonical/broker symbol map, operating jurisdiction, template SHA-256, official source inventory, verification UTC, and safety state.
- FR-4: The system MUST create exactly two separate approval artifacts with roles `COMPLIANCE_REVIEW` and `LEGAL_REVIEW`; each MUST bind the same evidence-body SHA-256, candidate, legal entity, jurisdiction, approver ID, key ID, and signing UTC.
- FR-5: The two approvals MUST have different approver IDs, key IDs, and secret fingerprints, and both signatures MUST verify with HMAC-SHA256 domain `AI_SCALPER/REGULATORY_APPROVAL/V1`.
- FR-6: Reviewer keys MUST be generated and loaded only through Windows Credential Manager; secret bytes MUST NOT be accepted by CLI, printed, written to repository files, or exported in any artifact.
- FR-7: Evidence preparation, each approval, and final assembly MUST use create-exclusive canonical JSON writes and MUST reject overwrite, symlink, duplicate-key JSON, non-finite numbers, naive timestamps, and unknown fields.
- FR-8: Final assembly MUST re-read and re-hash the evidence and both approvals, enforce the existing maximum 30-day evidence age, require approvals at or after source verification, and output one candidate regulatory observation compatible with the existing legal-binding verifier.
- FR-9: Final assembly MUST NOT modify `config/broker_candidates.phase3.json` or `config/broker_evidence_profiles.v1.json`; it MUST output a review artifact for an explicit human-reviewed repository patch.
- FR-10: Broker plan preparation and forward-contract registration MUST load reviewer keys through a deny-by-default provider and MUST fail closed if a required key is absent, invalid, duplicated, or has the same fingerprint as the other reviewer key.
- FR-11: A disabled profile MUST remain blocked even when a valid signed review artifact exists; enabling `registration_enabled` MUST require a separate explicit clean commit reviewed by the project owner.
- FR-12: The final tracked candidate observation, calendar template, discovery receipt, plan, calendar bundle, and profile candidate ID MUST match exactly before a forward contract can be registered.
- FR-13: All artifacts and CLI output MUST retain `execution_enabled=false`, `live_allowed=false`, `safe_to_demo_auto_order=false`, `promotion_eligible=false`, and `max_lot=0.01` where those fields apply.
- FR-14: The feature MUST support the isolated Phillip FX and Phillip commodity candidates without merging their sources, templates, symbol sets, reviewer artifacts, or evidence contracts.
- FR-15: Existing disabled FBS/XM profiles and legacy four-symbol fixtures MUST remain fail-closed and backward compatible.

## Non-Functional Requirements

- NFR-S1: No CLI introduced or changed by this feature may accept password, login, order, lot, live, private-key, raw-secret, or exported-key arguments.
- NFR-S2: Source paths MUST be absolute or repository-resolved regular files, MUST reject symlinks and directories, and MUST be read without modification.
- NFR-S3: Official-source URLs MUST use HTTPS, contain no userinfo or custom port, and match the existing jurisdiction authority allowlist.
- NFR-S4: Reviewer keys MUST contain at least 32 bytes and remain distinct by full SHA-256 fingerprint, not only by key name.
- NFR-R1: Every immutable artifact write MUST either complete durably or leave no target file; an existing target MUST never be replaced.
- NFR-R2: Verification MUST be deterministic for identical bytes and trusted UTC input; canonical payload hashes and signatures MUST be stable across supported Windows CPython 3.12 hosts.
- NFR-C1: The current full unit/integration suite MUST pass with zero regressions, and every acceptance criterion plus edge case in this spec MUST have an automated test.
- NFR-A1: Operator output MUST display candidate, artifact hash/key fingerprint as appropriate, and `Order capability: DISABLED`, but MUST never display source-document contents or secret material.
- NFR-G1: Source verification and signatures older than 30 days MUST be rejected, requiring a fresh review before a new observation window.

## Acceptance Criteria

### AC-1: Official source body is derived from bytes (FR-1, FR-2, FR-3, NFR-S2, NFR-S3)

Given a Phillip candidate, matching calendar template, and reviewed local
copies of allowlisted official source documents
When the regulatory evidence preparation command runs
Then it computes each source byte length and SHA-256 itself
And emits one immutable canonical evidence body bound to the exact lane
And reports order capability disabled.

### AC-2: Source substitution fails closed (FR-2, FR-7, NFR-S2, NFR-S3)

Given a source with a non-HTTPS URL, non-allowlisted host, wrong entity,
symlink, directory, changed bytes, unknown field, or duplicate JSON key
When evidence preparation or verification runs
Then it rejects the input and writes no final artifact.

### AC-3: Independent approval creation (FR-4, FR-5, FR-6, NFR-S4)

Given one verified evidence body and two separately provisioned Windows
Credential Manager keys
When the compliance and legal reviewers sign in separate invocations
Then each immutable approval binds the same evidence hash and its exact role
And neither output contains raw secret material.

### AC-4: Independence is mandatory (FR-5, FR-8, FR-10)

Given two approvals with the same approver, key ID, secret fingerprint, role,
or a forged/tampered signature
When final assembly or a downstream gate verifies them
Then verification fails closed and no registration state changes.

### AC-5: Freshness and ordering (FR-8, NFR-G1)

Given source verification or approval timestamps that are future, naive, older
than 30 days, or approvals that predate source verification
When final assembly runs
Then it rejects the package without creating a regulatory observation.

### AC-6: Review artifact does not activate registration (FR-9, FR-11, FR-13)

Given a completely valid final regulatory observation while the tracked profile
is disabled
When plan preparation or contract registration is attempted
Then the profile gate remains blocked
And no tracked config, broker order, demo-auto, promotion, or live flag changes.

### AC-7: Explicit clean-commit activation remains necessary (FR-10, FR-11, FR-12)

Given the project owner later approves a tracked candidate observation and
separately enables the matching profile in a reviewed clean commit
When plan preparation and contract registration run on Windows
Then both commands load the two required reviewer keys from Credential Manager
And reverify candidate, template, discovery, plan, calendar, observation, and
profile bindings before creating the diagnostic contract.

### AC-8: Lane isolation (FR-12, FR-14)

Given valid but different Phillip FX and commodity review packages
When either package is supplied to the other lane
Then candidate, template, server/scope, or symbol bindings reject it before
plan or contract creation.

### AC-9: Legacy candidates remain safe (FR-13, FR-15)

Given existing disabled FBS/XM profiles and four-symbol test fixtures
When the new feature is installed
Then prior diagnostic behavior remains compatible
And no profile or execution safety lock is opened.

### AC-10: CLI attack surface remains read-only (FR-6, FR-7, FR-13, NFR-S1, NFR-A1)

Given every new or modified operator CLI
When help and forbidden-argument tests run
Then no credential/order/live arguments are available
And all success and failure paths state that order capability remains disabled.

## Edge Cases and Error Scenarios

- EC-1: Candidate does not exist exactly once in tracked config → reject.
- EC-2: Candidate legal entity, jurisdiction, server, scope, or symbol map differs from the template → reject.
- EC-3: Source manifest is empty, has duplicate authorities/records, unknown fields, duplicate JSON keys, or non-finite values → reject.
- EC-4: Source path is missing, relative escape, symlink, directory, device, or changes between first and second read → reject.
- EC-5: Source URL contains HTTP, userinfo, a custom port, an unallowlisted host, fragment, or missing path → reject.
- EC-6: Source entity/result/registry identifier is missing or not eligible for the operating jurisdiction → reject.
- EC-7: Evidence or approval destination already exists or is a symlink → reject without overwrite.
- EC-8: Credential Manager is unavailable, wrong backend is active, key is missing, or key is shorter than 32 bytes → reject.
- EC-9: Approval role is unknown, duplicated, or does not match its command input → reject.
- EC-10: Approver IDs, key IDs, or full key fingerprints are not pairwise distinct → reject.
- EC-11: Evidence body, source hash, template hash, candidate binding, or approval signature changes after signing → reject.
- EC-12: Verified-at or signed-at is naive, future, stale, non-monotonic, or outside the allowed evidence lifetime → reject.
- EC-13: A valid observation is inserted into the wrong candidate or lane → reject.
- EC-14: Profile remains disabled → reject before reading mutable runtime artifacts.
- EC-15: Profile is enabled but signed observation/key provider is missing → reject before plan or contract creation.
- EC-16: Caller supplies password/login/order/lot/live/private-key/secret flags → argument parser rejects them.
- EC-17: One lane succeeds while the other remains incomplete → only the incomplete lane stays blocked; no cross-lane promotion is allowed.

## API Contracts

No network listener is introduced. For contract notation only, the local
application port is equivalent to
`POST /local-evidence/broker-registration-review`; implemented adapters are
Python functions and command-line programs. Official documents are supplied as
reviewed local files; the tools do not scrape or download them automatically.

```typescript
interface RegulatorySourceInput {
  authority: "Japan Financial Services Agency" | "Bappebti";
  url: HTTPSURL;
  entity: string;
  result: string;
  registry_record_id: string;
  observed_at_utc: UTCInstant;
  source_file: LocalRegularFile;
}

interface RegulatoryEvidenceBody {
  schema_version: "regulatory-evidence-v1";
  candidate_id: string;
  broker_legal_name: string;
  broker_server: string;
  environment: "DEMO";
  binding_scope: "FX" | "COMMODITY" | "ALL";
  operating_jurisdiction: "JP" | "ID";
  broker_symbols: Record<CanonicalSymbol, BrokerSymbol>;
  calendar_template_sha256: SHA256;
  verified_at_utc: UTCInstant;
  independent_registry_sources: RegulatorySourceEvidence[];
  execution_enabled: false;
  live_allowed: false;
  safe_to_demo_auto_order: false;
  max_lot: 0.01;
  evidence_bundle_sha256: SHA256;
}

interface RegulatoryApproval {
  schema_version: "regulatory-approval-v1";
  candidate_id: string;
  broker_legal_name: string;
  operating_jurisdiction: "JP" | "ID";
  evidence_bundle_sha256: SHA256;
  approver_id: string;
  approver_role: "COMPLIANCE_REVIEW" | "LEGAL_REVIEW";
  key_id: string;
  signed_at_utc: UTCInstant;
  signature_hmac_sha256: HMACSHA256;
}

interface FinalRegulatoryObservation extends RegulatoryEvidenceBody {
  regulatory_approvals: [RegulatoryApproval, RegulatoryApproval];
}

interface RegistrationGateResult {
  candidate_id: string;
  regulatory_observation_sha256: SHA256;
  registration_enabled: false;
  order_capability: "DISABLED";
  review_required: true;
}
```

## Data Models

### Regulatory source evidence

| Field | Type | Constraints |
|---|---|---|
| authority | string | Existing jurisdiction allowlist; exact canonical authority |
| url | string | HTTPS, allowlisted host, no credentials/custom port/fragment |
| entity | string | Exact tracked broker legal entity |
| result | enum | Existing eligible result for jurisdiction |
| registry_record_id | string | Non-empty stable official record/license identifier |
| observed_at_utc | UTC instant | Aware, not future, no older than 30 days |
| captured_content_sha256 | lowercase hex | Computed from regular source-file bytes |
| captured_content_bytes | integer | Positive, exact byte length |

### Reviewer approval

| Field | Type | Constraints |
|---|---|---|
| approver_id | string | Non-empty; distinct across both approvals |
| approver_role | enum | Exactly one compliance and one legal reviewer |
| key_id | string | Windows Credential Manager name; distinct |
| key fingerprint | SHA-256 | Verification-only; distinct; raw key never stored |
| signed_at_utc | UTC instant | At/after verification, not future/stale |
| signature_hmac_sha256 | lowercase hex | Domain-separated signature over all other approval fields |

### Final review package

| Field | Type | Constraints |
|---|---|---|
| candidate/lane binding | object | Exact candidate, server, scope, jurisdiction, symbols, template hash |
| sources | array | Non-empty, unique official record inventory |
| evidence_bundle_sha256 | SHA-256 | Canonical body excluding approvals and hash field as defined by verifier |
| regulatory_approvals | tuple | Exactly two valid independent approval artifacts |
| safety fields | constants | Execution/demo-auto/promotion/live false; max lot 0.01 |

## Out of Scope

- OS-1: The software does not provide legal advice, certify the user's personal eligibility, or issue either human approval.
- OS-2: This feature does not set `registration_enabled=true`, modify tracked candidate/profile configs automatically, or register a forward contract without a separate reviewed commit.
- OS-3: This feature does not enable manual-demo orders, demo-auto, live trading, promotion permits, or increased lot/risk caps.
- OS-4: The tools do not download, scrape, OCR, translate, or decide the meaning of official documents; reviewers supply and interpret exact source files.
- OS-5: Windows Credential Manager provides local demo-evidence custody only; HSM, external legal-signature services, and organizationally independent production key custody remain external ship gates.
- OS-6: Holiday and exceptional-closure completeness after contract registration remains governed by the prospective calendar amendment chain and final completeness attestation.
- OS-7: FBS Japan eligibility, XM reactivation, FINEX eligibility after relocation, and stock/index account support are not changed by this feature.
