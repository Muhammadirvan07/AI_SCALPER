# Signed Pre-Window Calendar Review

Status: **TOOLING IMPLEMENTED / HUMAN CALENDAR APPROVAL NOT ISSUED /
TEMPLATES NOT ACTIVATED / REGISTRATION DISABLED**

This workflow binds reviewed official broker-document bytes to one exact base
calendar. It does not claim that future exceptional hours are complete, patch
a tracked template, enable a broker evidence profile, create promotion
evidence, or submit an order.

The distinction is important:

- the pre-window review confirms the regular schedule and notices known at its
  review cutoff;
- future official closures are appended only prospectively through the signed
  amendment chain; and
- final special-hours completeness is attested only after the blind window.

The current Phillip templates intentionally remain schema v2 with
`special_hours_review.attested=false`. The tools below prepare a review package
for a separate human reviewer. Codex does not issue that approval.

## Official source basis

For the Phillip FX lane, review exact local captures of:

- `https://www.phillip.co.jp/fx/servicelist.php` as
  `REGULAR_FX_SESSION_SCHEDULE`; and
- `https://www.phillip.co.jp/information/info/10999` as
  `DST_TRANSITION_NOTICE`.

For the Phillip commodity lane, review an exact local capture of:

- `https://www.phillip.co.jp/fx/pdf/C-CFD_important_notes.pdf` as
  `COMMODITY_XAU_SESSION_SCHEDULE`.

The FX service page publishes the Japan-time DST span and daily maintenance
interval. The 5 March 2026 notice identifies the 2026 US DST transition. The
commodity document is marked June 2026 and publishes the XAU DST session and
daily maintenance interval. None of those documents proves that no later
holiday notice will be published.

Download and inspect the documents manually. Keep them outside the repository,
for example:

```text
C:\AI_SCALPER_PRIVATE\phillip-fx-calendar-review\
  fx-service-hours.html
  dst-2026.html
  source-manifest.json
```

## Source manifest

Example FX manifest:

```json
{
  "schema_version": "prewindow-calendar-source-manifest-v1",
  "candidate_id": "phillip-fx",
  "future_exception_completeness": false,
  "sources": [
    {
      "source_id": "fx-service-hours",
      "source_role": "REGULAR_FX_SESSION_SCHEDULE",
      "url": "https://www.phillip.co.jp/fx/servicelist.php",
      "published_on": null,
      "observed_at_utc": "2026-07-21T12:00:00Z",
      "source_file": "fx-service-hours.html"
    },
    {
      "source_id": "dst-2026",
      "source_role": "DST_TRANSITION_NOTICE",
      "url": "https://www.phillip.co.jp/information/info/10999",
      "published_on": "2026-03-05",
      "observed_at_utc": "2026-07-21T12:00:00Z",
      "source_file": "dst-2026.html"
    }
  ]
}
```

Example commodity manifest:

```json
{
  "schema_version": "prewindow-calendar-source-manifest-v1",
  "candidate_id": "phillip-commodity",
  "future_exception_completeness": false,
  "sources": [
    {
      "source_id": "xau-important-notes-2026-06",
      "source_role": "COMMODITY_XAU_SESSION_SCHEDULE",
      "url": "https://www.phillip.co.jp/fx/pdf/C-CFD_important_notes.pdf",
      "published_on": "2026-06-01",
      "observed_at_utc": "2026-07-21T12:00:00Z",
      "source_file": "C-CFD_important_notes.pdf"
    }
  ]
}
```

Use the actual UTC capture time. Review evidence and approvals expire after 30
days and must be completed before the observation window starts. Files are
hashed by the tool; a manifest cannot supply its own digest.
Each `source_file` must be a relative path below `--source-root`; absolute
paths, traversal components, and symlinked descendants are rejected.

## Prepare and sign

On the reviewed Windows evidence host:

```powershell
cd C:\AI_SCALPER
.\.venv\Scripts\Activate.ps1

python -B .\setup_calendar_review_key.py `
  --candidate phillip-fx

$reviewRoot = "C:\AI_SCALPER_PRIVATE\phillip-fx-calendar-review"

python -B .\prepare_prewindow_calendar_review.py `
  --candidate phillip-fx `
  --source-manifest "$reviewRoot\source-manifest.json" `
  --source-root $reviewRoot `
  --output "$reviewRoot\calendar-evidence.json"
```

The named calendar reviewer inspects the exact evidence and source hashes,
then runs:

```powershell
python -B .\sign_prewindow_calendar_review.py `
  --candidate phillip-fx `
  --reviewer-id calendar-reviewer `
  --evidence "$reviewRoot\calendar-evidence.json" `
  --output "$reviewRoot\calendar-approval.json"

python -B .\assemble_prewindow_calendar_review.py `
  --candidate phillip-fx `
  --evidence "$reviewRoot\calendar-evidence.json" `
  --approval "$reviewRoot\calendar-approval.json" `
  --output "$reviewRoot\prewindow-calendar-review.json"
```

Repeat in a separate private directory and with a separate candidate-scoped
key for `phillip-commodity`. Do not reuse an FX artifact in the commodity lane.

All destinations are create-exclusive. Source paths, duplicate JSON keys,
unknown fields, non-official hosts, missing source roles, changed bytes, stale
timestamps, wrong keys, lane drift, and schedule drift fail closed.

## Activation remains a separate human gate

Assembly prints `Template patched: false` and
`Registration enabled: false`. A later human-reviewed clean commit must:

1. verify the exact assembled artifact and reviewer identity;
2. upgrade only the matching template to
   `broker-calendar-plan-template-v3`;
3. embed the artifact as `prewindow_calendar_review` without changing the
   schedule it signed;
4. insert the separately assembled regulatory observation into the matching
   candidate;
5. explicitly enable only the matching evidence profile; and
6. retain all order, demo-auto, promotion, live, and `max_lot=0.01` locks.

Schema-v3 plan preparation, calendar building, and contract registration all
reload the calendar-review key from Windows Credential Manager and reverify
the embedded artifact. A valid pre-window review still leaves
`special_hours_review.attested=false`; the amendment and post-window
completeness gates remain mandatory.
