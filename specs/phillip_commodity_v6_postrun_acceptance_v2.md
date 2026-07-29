# Spec: Phillip Commodity V6 Post-Run Acceptance v2

**Author:** AI_SCALPER engineering
**Date:** 2026-07-30
**Status:** Approved
**Reviewers:** senior architecture, security, ship-gate
**Supersedes:** `phillip_commodity_v6_postrun_acceptance_v1.md` for new builds
**Authority:** none; read-only evidence packaging only

## Context

The installed Phillip Commodity V6.3 task is intended to start from its
registered Windows Task Scheduler time trigger. A timestamp after the boundary
does not prove that the registered trigger, rather than a manual start, created
the run. Local Task Scheduler Operational events strengthen that provenance,
but they remain local-host evidence and are not an independent attestation.

This contract binds the exact scheduled-trigger event chain, authenticated
worker evidence, installation receipt, installed task, and health result into
one deterministic acceptance archive. It also defines a separate custody
request and signed-receipt verification boundary. Independent off-host WORM
custody remains mandatory for later gates; this feature grants no trading or
promotion authority.

## Functional Requirements

- FR-1: The toolkit MUST contain exactly the seven reviewed members listed in
  the Toolkit Inventory subsection and MUST bind their byte sizes and SHA-256
  values to one source commit and tree.
- FR-2: Toolkit verification MUST require externally supplied archive SHA-256,
  source commit, and source tree pins before any evidence collection.
- FR-3: Trigger readiness MUST be read-only and MUST require `Tokyo Standard
  Time`, an enabled Task Scheduler Operational log, one exact root-path V6.3
  task, one exact root-path V4 task, one exact root-path V5 task, and the
  reviewed task states.
- FR-4: Trigger collection MUST query event IDs 100, 102, 107, and 110 from the
  exact Task Scheduler Operational channel and MUST bind each retained raw XML
  value, SHA-256, UTC time, provider, channel, task name, and record ID.
- FR-5: Acceptance MUST require one event 107 with the same normalized task
  instance as event 100 and a lower EventRecordID, and MUST reject event 110
  for that instance or matching launch window.
- FR-6: A completed task in `Ready` state MUST have exactly one correlated
  event 102 whose EventRecordID follows event 100 and whose timestamp does not
  exceed the health observation.
- FR-7: The acceptance ZIP MUST contain exactly the eight reviewed members and
  MUST bind their hashes, the correlated scheduler projection, the advanced
  authenticated checkpoint, and every deny-only safety claim.
- FR-8: Every JSON evidence, manifest, checkpoint, toolkit, archive, and
  custody input MUST reject duplicate object keys before field projection.
- FR-9: Every file input MUST be read through one regular-file handle whose
  identity, size, and modification time agree with no-follow path inspection
  before and after the read.
- FR-10: Every output MUST be create-exclusive. Cleanup after a failed write or
  post-write verification MUST remove only the exact file identity created by
  the current invocation and MUST preserve any replacement identity.
- FR-11: The toolkit MUST deterministically create and independently verify a
  custody-request ZIP for the exact acceptance bytes.
- FR-12: Custody verification MUST require a canonical policy-pinned RSA
  receipt that binds byte-identical acceptance content, Object Lock
  `COMPLIANCE`, versioning, WORM retention, and the required retain-until time.
- FR-13: The toolkit MUST NOT start, register, update, disable, or delete a
  scheduled task; import MT5; access credentials directly; contact a broker;
  or submit an order.
- FR-14: Local scheduler events MUST NOT be described as independent evidence,
  and custody MUST remain unperformed until a valid external signed receipt is
  verified.
- FR-15: Every success result MUST retain `order_capability=DISABLED`,
  `live_allowed=false`, `promotion_eligible=false`, scheduler mutation false,
  and broker mutation false.

### Toolkit Inventory

The deterministic toolkit contains exactly:

1. `Invoke-PhillipCommodityV6PostRunAcceptance.ps1`;
2. `New-PhillipCommodityV6CustodyRequest.ps1`;
3. `Test-PhillipCommodityV6CustodyReceipt.ps1`;
4. `Test-PhillipCommodityV6TriggerAuditReadiness.ps1`;
5. `PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE.md`;
6. `phillip_commodity_v6_postrun_acceptance.py`;
7. `PHILLIP_COMMODITY_V6_POSTRUN_TOOLKIT.json`.

The toolkit manifest schema is
`phillip-commodity-v6-postrun-toolkit-v2`.

### Acceptance Inventory

The acceptance archive contains exactly:

1. `audit-export.json`;
2. `audit-manifest.json`;
3. `evidence-checkpoint.json`;
4. `health-transcript.txt`;
5. `installation-receipt.json`;
6. `installed-task.xml`;
7. `task-scheduler-events.json`;
8. `PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE.json`.

The acceptance schema is
`phillip-commodity-v6-postrun-acceptance-bundle-v2`.

## Non-Functional Requirements

- NFR-1: Archive generation MUST be byte-deterministic for the same exact
  inputs by using fixed ZIP metadata, sorted inventories, and canonical hashes.
- NFR-2: A single evidence member MUST NOT exceed 64 MiB, a scheduler event XML
  value MUST NOT exceed 512 KiB, and retained scheduler events MUST NOT exceed
  4,096 records.
- NFR-3: Collection and independent verification MUST fail closed on malformed,
  oversized, missing, ambiguous, substituted, or mutated input.
- NFR-4: All security and correctness guards MUST behave identically in normal
  Python and optimized `-O` execution.
- NFR-5: The focused tests, full serial regression, deterministic package test,
  Python compilation, scoped lint, whitespace check, and forbidden-effect scan
  MUST pass before release packaging.

## Acceptance Criteria

### AC-1: Exact toolkit verification (FR-1, FR-2, NFR-1)
Given a toolkit archive with externally pinned SHA-256, source commit, and tree
When the independent toolkit verifier reads and reconstructs its inventory
Then it accepts exactly the seven reviewed members
And it rejects any missing, extra, reordered, hash-drifted, or source-drifted member

### AC-2: Read-only readiness projection (FR-3, FR-13, FR-15)
Given the exact V6.3, V4, and V5 task names on a Tokyo-time Windows host
When the readiness checker inspects Task Scheduler before the first boundary
Then each name resolves exactly once at root task path `\`
And V6.3 is `Ready` or `Running` while V4 and V5 remain `Disabled`
And no scheduler or broker mutation occurs

### AC-3: Correlated scheduled start (FR-4, FR-5, FR-7)
Given valid event 107 and event 100 XML for one task instance
When the acceptance collector correlates the automatic run
Then event 107 has a lower EventRecordID than event 100
And the acceptance manifest binds both record IDs, timestamps, raw XML hashes,
and `provenance_scope=LOCAL_HOST_EVENT_LOG`

### AC-4: Manual or reordered trigger rejection (FR-5, FR-14)
Given a matching event 110 or an event 107 whose record ID does not precede
event 100
When trigger provenance is validated
Then collection fails with a stable Task Scheduler provenance rejection
And no acceptance archive remains published

### AC-5: Completed run correlation (FR-6)
Given a V6.3 health result whose task state is `Ready`
When trigger provenance is validated
Then exactly one event 102 follows the correlated start record
And a missing, preceding, duplicate, or post-observation completion is rejected

### AC-6: Unambiguous stable input reads (FR-8, FR-9, NFR-2, NFR-3)
Given an evidence JSON with duplicate keys or a file path substituted during
the read
When the generic evidence loader reads the input
Then it rejects the input before projection
And it never validates bytes from a different file identity

### AC-7: Identity-safe publication cleanup (FR-10)
Given post-write verification fails after an output archive is published
When cleanup runs
Then the exact output identity created by that invocation is removed
And a replacement file published by another process is preserved unchanged

### AC-8: Deterministic acceptance archive (FR-7, NFR-1)
Given identical valid health, checkpoint, audit, task, receipt, and scheduler
inputs
When two independent acceptance builds run
Then the ZIP bytes and archive SHA-256 values are identical
And independent archive verification reconstructs the same bundle identity

### AC-9: External custody boundary (FR-11, FR-12, FR-14)
Given an exact acceptance archive and an independent canonical custody policy
When a custody request is built and a signed receipt is verified
Then the request binds the exact acceptance bytes
And only a valid policy-pinned RSA receipt with compliant WORM retention creates
a deny-only custody assessment
And local evidence alone never marks custody performed

### AC-10: Safety and optimized execution (FR-13, FR-15, NFR-4, NFR-5)
Given the completed implementation and its release inventory
When focused, full, normal, optimized, lint, compile, and forbidden-effect
gates run
Then every gate passes
And no credential, MT5, scheduler-mutation, broker, order, promotion, or live
capability is introduced

## Edge Cases

- EC-1: The Operational log is missing or disabled → readiness and collection
  fail without enabling the log.
- EC-2: A same-name task exists in another scheduler folder → exact task lookup
  is ambiguous and fails before evidence collection.
- EC-3: Event XML has a localized message but valid structured data → message
  text is ignored and structured XML fields remain authoritative.
- EC-4: Event 107 follows event 100 in EventRecordID order → provenance fails
  even if its timestamp appears earlier.
- EC-5: A JSON object repeats a safety or identity key → parsing fails before
  last-key-wins projection.
- EC-6: A file is swapped for same-size content and restored during read →
  handle/path identity disagreement fails closed.
- EC-7: Another process replaces an output after publication failure → cleanup
  preserves the replacement identity and returns failure.
- EC-8: The custody service is unavailable or returns an unsigned receipt → the
  request remains valid but custody and promotion remain false.

## API Contracts

This is a local CLI contract; it exposes no HTTP service. In particular,
`POST /api/live/order` MUST NOT be implemented by this toolkit.

Commands and successful result contracts:

- `verify-toolkit` → one JSON object with verified archive/source identities
  and deny-only safety fields.
- `collect` → one JSON object naming the exact acceptance ZIP, SHA-256, bundle
  identity, scheduler instance, and deny-only safety fields.
- `verify` → one JSON object reconstructed independently from the archive.
- `prepare-custody` and `verify-custody-request` → deterministic request
  identities without a custody success claim.
- `verify-custody-receipt` → a deny-only assessment only after RSA and retention
  verification.

```typescript
interface PostRunCliResult {
  status: string;
  archive_sha256?: string;
  bundle_identity_sha256?: string;
  order_capability: "DISABLED";
  live_allowed: false;
  promotion_eligible: false;
}
```

All contract violations return a non-zero process code and one stable public
reason code; they never return a partial success projection.

## Data Models

### Task Scheduler Evidence

| Field | Type | Constraints |
|---|---|---|
| schema_version | string | Exact `phillip-commodity-v6-task-scheduler-trigger-evidence-v1` |
| captured_at_utc | UTC string | Canonical, bounded after the run |
| task_name | string | Exact root-qualified V6.3 task name |
| events | array | Maximum 4,096, unique monotonically ordered record IDs |
| events[].raw_xml | string | Maximum 512 KiB and SHA-256 bound |
| collection | object | `Get-WinEvent`, messages unused, no mutation |

### Acceptance Manifest

| Field | Type | Constraints |
|---|---|---|
| schema_version | string | Exact v2 bundle schema |
| toolkit | object | Exact source commit, tree, and toolkit manifest hash |
| scheduler_observation | object | Correlated 107/100 and optional 102 projection |
| authenticated_evidence | object | Advanced checkpoint and source-chain facts |
| members | array | Exact seven evidence members with size and SHA-256 |
| external_custody | object | Required but false before independent receipt |
| safety | object | Exact deny-only projection |
| bundle_identity_sha256 | lower hex | Canonical non-zero SHA-256 |

### Custody Receipt

| Field | Type | Constraints |
|---|---|---|
| receipt_id | identifier | Unique custodian receipt identifier |
| request_identity_sha256 | lower hex | Exact custody request binding |
| acceptance_archive_sha256 | lower hex | Exact acceptance bytes |
| remote_object | object | Compliance lock, versioning, retention, content hash |
| signature_rsa_pkcs1v15_sha256_hex | lower hex | Policy-pinned 3,072–8,192-bit RSA signature |

## Out of Scope

- OS-1: Starting or repairing the scheduled task — operator installation and
  remediation use separate reviewed packages.
- OS-2: Enabling Task Scheduler Operational history — this is an explicit
  administrator action outside the read-only toolkit.
- OS-3: Uploading to or configuring an off-host WORM provider — the toolkit
  only prepares and verifies the handoff contract.
- OS-4: Provisioning or exporting a custodian private key — key custody belongs
  to an independent external authority.
- OS-5: Demo-auto activation, promotion, central unlock, MT5 initialization,
  or broker order submission — all require later independent gates.
- OS-6: Treating local Task Scheduler logs as independent attestation — only a
  separately signed external custody receipt may close that boundary.
