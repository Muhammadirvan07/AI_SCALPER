# Spec: Signed Pre-Window Broker Calendar Review

**Author:** AI_SCALPER Engineering

**Date:** 2026-07-21

**Status:** Approved

**Reviewer:** Project owner through the explicit autonomous implementation request; the runtime calendar reviewer approval remains unissued

**Related specs:** `broker_registration_review_gate.md`,
`phillip_lane_evidence_contract.md`,
`prospective_calendar_amendment_chain.md`

## Context

The Phillip FX and commodity templates contain conservative, regular DST
schedules derived from official Phillip sources. Their
`special_hours_review.attested` values correctly remain false because an
eight-week future window cannot truthfully claim that every exceptional
holiday or shortened session is already known. Future official notices are
handled by the existing closure-only prospective amendment chain, and the
post-window completeness attestation remains the final calendar-completeness
gate.

The remaining software gap is different: there is no immutable workflow for a
human calendar reviewer to bind exact official source bytes to the base weekly
schedule, the candidate lane, and the planned observation window. A code
comment or URL in the tracked template is not a signed review. Conversely,
setting `special_hours_review.attested=true` would overstate what the pre-window
sources prove.

This feature creates a byte-derived pre-window evidence body, one separately
signed calendar-review approval, and an assembled review artifact. A later
human-reviewed clean commit may embed that assembled artifact into a new
versioned broker-calendar template. Plan preparation, calendar generation, and
contract registration then reverify its signature through Windows Credential
Manager. The current tracked templates and profiles remain disabled throughout
this implementation.

Architecture decision: the pre-window review is a separate bounded context
from regulatory eligibility and from post-window calendar completeness. It
attests only that the regular base schedule and all exceptional closures known
as of the stated review cutoff match the captured official sources. It does
not attest that future notices do not exist.

## Functional Requirements

- FR-1: The system MUST prepare one immutable pre-window calendar evidence body for exactly one broker candidate from a tracked template and operator-supplied official source files.
- FR-2: Every source MUST bind a unique source ID, review role, official HTTPS URL, publication date when known, observed-at UTC, byte length, and SHA-256 calculated from the supplied regular file; caller-supplied hashes MUST NOT be trusted.
- FR-3: Phillip FX evidence MUST include regular FX session and DST-transition sources; Phillip commodity evidence MUST include the commodity XAU session source. Additional official special-hours sources MAY be included.
- FR-4: The evidence body MUST bind candidate, broker legal name/server, jurisdiction, exact canonical-to-broker symbol map, server timezone, calendar version, observation window, amendment policy, weekly M15 sessions, the still-unattested special-hours claim, and a deterministic schedule-claim SHA-256.
- FR-5: Evidence preparation MUST reject a template that already claims `special_hours_review.attested=true`, because this workflow does not issue post-window completeness.
- FR-6: A calendar reviewer MUST create one role-scoped HMAC-SHA256 approval with role `CALENDAR_REVIEW`; it MUST bind the exact evidence hash, candidate, schedule claim, reviewer ID, key ID, and signed-at UTC.
- FR-7: The calendar-review key MUST be generated and loaded only through Windows Credential Manager; raw secret bytes MUST NOT be accepted by a CLI, printed, exported, or persisted in review artifacts.
- FR-8: Final assembly MUST re-read and verify the evidence and approval, require approval at or after evidence verification, enforce a maximum 30-day review age, and output one immutable `prewindow-calendar-review-v1` artifact.
- FR-9: The assembled artifact MUST retain `special_hours_review.attested=false`, MUST state `future_exception_completeness=false`, and MUST state that the prospective amendment chain and post-window completeness attestation remain required.
- FR-10: Assembly MUST NOT patch a template, candidate configuration, evidence profile, or registration flag. Embedding the artifact and changing a template schema MUST require a later explicit human-reviewed clean commit.
- FR-11: Broker calendar template schema v3 MUST support exactly one embedded assembled pre-window review and MUST bind it to the exact base schedule without changing the existing special-hours semantics.
- FR-12: Plan preparation for schema v3 MUST require a deny-by-default calendar-review key provider, verify the embedded approval, and fail closed for missing, stale, mismatched, or forged review artifacts.
- FR-13: Calendar building and broker contract registration for schema/plan v3 MUST reverify the embedded review through the same key provider before producing or accepting evidence.
- FR-14: Existing v1/v2 templates, plans, XM/FBS fixtures, amendment-enabled base calendars, and diagnostic shadow behavior MUST remain backward compatible.
- FR-15: All artifacts and CLI output MUST preserve `execution_enabled=false`, `live_allowed=false`, `safe_to_demo_auto_order=false`, `promotion_eligible=false`, `registration_enabled=false`, and `max_lot=0.01` where applicable.
- FR-16: FX and commodity review artifacts, keys, source sets, template hashes, symbols, and schedule claims MUST remain lane-isolated.

## Non-Functional Requirements

- NFR-S1: Source and artifact readers MUST reject symlinks, directories, path traversal, duplicate JSON keys, non-finite values, unknown fields, empty files, unstable reads, and files larger than 64 MiB.
- NFR-S2: Official URLs MUST use HTTPS without userinfo, fragments, or custom ports and MUST resolve to `phillip.co.jp` or a direct subdomain for Phillip candidates.
- NFR-S3: Timestamps MUST be timezone-aware UTC. Publication dates MUST be valid ISO calendar dates and MUST NOT be after the evidence review date.
- NFR-S4: The review key MUST contain at least 32 bytes. Signatures MUST use canonical JSON, HMAC-SHA256, constant-time comparison, and domain `AI_SCALPER/PREWINDOW_CALENDAR_REVIEW/V1`.
- NFR-S5: Schedule hashes MUST cover exact normalized JSON values, including list order, and MUST exclude only the embedded pre-window artifact to avoid a circular hash.
- NFR-R1: Every output MUST use create-exclusive durable JSON writes. An existing or symlink destination MUST never be replaced.
- NFR-R2: Preparation, signing, assembly, and verification MUST be deterministic for identical input bytes and trusted UTC providers on supported CPython 3.12 hosts.
- NFR-G1: A review older than 30 days, signed after observation start, or verified after the planned observation start MUST be rejected for plan preparation.
- NFR-A1: Failures MUST expose stable non-secret messages and MUST never include source contents, account identifiers, balances, credentials, or key material.
- NFR-A2: No introduced CLI may accept login, password, account, order, volume, lot-change, live-enable, private-key, raw-secret, or key-export arguments.
- NFR-C1: Every acceptance criterion and edge case MUST have automated coverage, and the full project suite plus safety scans MUST pass.

## Acceptance Criteria

### AC-1: Byte-derived FX review evidence (FR-1, FR-2, FR-3, FR-4)

Given the Phillip FX template and reviewed local copies of the official FX
session and 2026 DST sources
When the preparation command runs
Then it computes exact source byte hashes and lengths
And writes one lane-bound evidence body whose schedule hash covers the weekly
sessions, window, symbols, amendment policy, and false special-hours claim.

### AC-2: Byte-derived commodity review evidence (FR-1, FR-2, FR-3, FR-16)

Given the Phillip commodity template and reviewed local copy of the official
XAU schedule document
When preparation runs
Then it writes a commodity-only evidence body
And no FX symbol, source requirement, or review artifact is silently imported.

### AC-3: Source and manifest attacks fail closed (FR-2, NFR-S1, NFR-S2)

Given a wrong host, HTTP URL, source-role gap, duplicate ID, unknown field,
path escape, symlink, directory, changed/empty/oversized file, duplicate JSON
key, or non-finite value
When preparation runs
Then it rejects before writing the evidence artifact.

### AC-4: Pre-window scope cannot claim completeness (FR-5, FR-9)

Given a template with `special_hours_review.attested=true` or a manifest that
claims future exception completeness
When preparation or assembly runs
Then it rejects the claim
And no post-window completeness artifact is created.

### AC-5: Credential-backed calendar approval (FR-6, FR-7, NFR-S4)

Given a verified evidence body and a separately controlled Windows Credential
Manager key
When a named calendar reviewer signs it
Then the immutable approval verifies against the exact evidence and schedule
hash
And neither CLI output nor artifact contains the secret.

### AC-6: Approval tampering and freshness (FR-8, NFR-G1)

Given an approval with a wrong role, candidate, key ID, evidence hash, schedule
hash, signature, future/stale time, time before evidence verification, or time
at/after observation start
When assembly or downstream verification runs
Then it fails closed without producing a final review or calendar plan.

### AC-7: Safe assembled artifact (FR-8, FR-9, FR-10, FR-15)

Given authentic evidence and approval
When assembly succeeds
Then the output is one content-addressed `prewindow-calendar-review-v1`
artifact with false future completeness and all trading locks false
And repository configuration remains unchanged.

### AC-8: Schema-v3 template binding (FR-11, FR-12, NFR-S5)

Given a later human-reviewed schema-v3 template containing the assembled
artifact
When plan preparation runs with the matching review key provider
Then it verifies the exact schedule claim and signature before creating a plan
And any template field or embedded artifact drift is rejected.

### AC-9: Key absence remains blocked (FR-12, FR-13)

Given a schema-v3 template and authentic-looking embedded review but no key,
the wrong key, or a key shorter than 32 bytes
When plan preparation, calendar building, or contract registration runs
Then each entry point fails closed and no output is created.

### AC-10: End-to-end downstream re-verification (FR-13)

Given an authentic schema-v3 plan and calendar bundle
When calendar build and diagnostic contract registration re-read them
Then both reverify the embedded review and exact template/plan/calendar binding
before accepting the evidence.

### AC-11: Legacy behavior remains compatible (FR-14)

Given existing schema-v1/v2 templates, XM/FBS fixtures, and amendment-enabled
false special-hours base calendars
When existing preparation, calendar, shadow, and test workflows run
Then behavior and hashes are unchanged unless the new schema is explicitly
selected.

### AC-12: CLI attack surface and locks (FR-10, FR-15, NFR-A2)

Given every new or modified command
When help/forbidden-argument and success/failure-output tests run
Then no broker/order/secret mutation option exists
And registration, promotion, and order capability remain disabled.

## Edge Cases and Error Scenarios

- EC-1: Candidate/template lane, legal name, server, jurisdiction, symbol set, timezone, calendar version, or window differs → Reject.
- EC-2: Source ID or role is invalid/duplicated, a mandatory role is absent, or an unsupported role is supplied → Reject.
- EC-3: Source URL has a custom port, credentials, fragment, non-Phillip host, or empty path → Reject.
- EC-4: Source publication date is invalid or after observed/review time → Reject.
- EC-5: Source changes between metadata reads, cannot be opened without following a symlink, is empty, or exceeds the size cap → Reject.
- EC-6: Weekly sessions, amendment policy, registered closures, or special-hours fields drift after evidence preparation → Schedule hash mismatch; reject.
- EC-7: Approval key is missing/short, reviewer ID is invalid, or key ID is not candidate-scoped → Reject.
- EC-8: Evidence/approval destination already exists or is a symlink → Reject without overwrite.
- EC-9: Review evidence or approval is stale, future, non-monotonic, or reaches observation start → Reject.
- EC-10: Assembled review says future completeness true or special-hours attested true → Reject.
- EC-11: Schema-v3 template omits the assembled review, adds unknown fields, or embeds another lane's artifact → Reject.
- EC-12: A v3 plan is verified without a key provider → Reject; no implicit trust in the template hash.
- EC-13: A v1/v2 plan is passed with a review key provider → Continue with its legacy rules without requiring a new artifact.
- EC-14: Review tooling succeeds for one Phillip lane only → The other lane remains independently blocked.
- EC-15: Profile remains disabled after valid review → Plan/contract registration remains blocked by the existing explicit profile gate.

## API Contracts

No network listener or downloader is introduced. Operator-reviewed files are
local inputs. For notation only, the application port resembles
`POST /local-evidence/prewindow-calendar-review`.

```typescript
interface CalendarSourceInput {
  sourceId: string;
  sourceRole:
    | "REGULAR_FX_SESSION_SCHEDULE"
    | "DST_TRANSITION_NOTICE"
    | "COMMODITY_XAU_SESSION_SCHEDULE"
    | "KNOWN_SPECIAL_HOURS_NOTICE";
  url: HTTPSURL;
  publishedOn: ISODate | null;
  observedAtUtc: UTCInstant;
  sourceFile: LocalRegularFile;
}

interface PrewindowCalendarEvidence {
  schemaVersion: "prewindow-calendar-evidence-v1";
  candidateId: string;
  brokerLegalName: string;
  brokerServer: string;
  operatingJurisdiction: "JP";
  brokerSymbols: Record<string, string>;
  serverTimezone: string;
  calendarVersion: string;
  observationStartAtUtc: UTCInstant;
  blindUntilUtc: UTCInstant;
  scheduleClaimSha256: SHA256;
  officialSources: CalendarSourceEvidence[];
  verifiedAtUtc: UTCInstant;
  specialHoursAttested: false;
  futureExceptionCompleteness: false;
  executionEnabled: false;
  liveAllowed: false;
  safeToDemoAutoOrder: false;
  promotionEligible: false;
  maxLot: 0.01;
  evidenceBundleSha256: SHA256;
}

interface CalendarReviewApproval {
  schemaVersion: "prewindow-calendar-approval-v1";
  candidateId: string;
  evidenceBundleSha256: SHA256;
  scheduleClaimSha256: SHA256;
  reviewerId: string;
  reviewerRole: "CALENDAR_REVIEW";
  keyId: string;
  signedAtUtc: UTCInstant;
  signatureHmacSha256: HMACSHA256;
}

interface PrewindowCalendarReview extends PrewindowCalendarEvidence {
  schemaVersion: "prewindow-calendar-review-v1";
  calendarReviewApproval: CalendarReviewApproval;
  reviewArtifactSha256: SHA256;
  amendmentChainRequired: true;
  postWindowCompletenessRequired: true;
}
```

## Data Models

### Schedule claim

The schedule claim is canonical SHA-256 over candidate/server/jurisdiction,
broker symbols, timezone, calendar version, observation window,
`weekly_m15_sessions`, `calendar_amendment_policy`, and the exact
`special_hours_review` object. It excludes schema version and the embedded
pre-window review so a v3 template can bind the artifact without a circular
hash.

### Official source evidence

| Field | Type | Constraints |
|---|---|---|
| source ID / role | strings | Unique; mandatory lane roles present |
| URL | HTTPS URL | Phillip official host, no credentials/port/fragment |
| published date | ISO date or null | Not after observed/review time |
| observed at | UTC instant | Fresh and before observation start |
| captured hash / bytes | SHA-256 / integer | Derived from stable regular-file bytes |

### Calendar review approval

| Field | Type | Constraints |
|---|---|---|
| reviewer ID / role | strings | Valid ID; exact role `CALENDAR_REVIEW` |
| key ID | string | Derived candidate-scoped Credential Manager key name |
| signed at | UTC instant | At/after evidence, fresh, before observation start |
| signature | HMAC-SHA256 | Domain-separated over all other approval fields |

## Out of Scope

- OS-1: Automatically downloading, scraping, translating, or interpreting broker documents.
- OS-2: Claiming that no unpublished future holiday or special-hours notice exists.
- OS-3: Issuing the human calendar-review approval from Codex.
- OS-4: Setting `special_hours_review.attested=true` before post-window completeness.
- OS-5: Patching or enabling a broker evidence profile without a later explicit human-reviewed clean commit.
- OS-6: Order submission, demo-auto, promotion, live activation, risk-limit changes, or lot changes.
