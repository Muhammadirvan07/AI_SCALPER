# Prospective Calendar Amendment Operations

Status: **ARCHITECTURE READY / REGISTRATION GATED / ORDERS DISABLED**

AI_SCALPER stores the reviewed regular broker schedule in an immutable
`forward-contract-v4`. Later official holiday or special-hours notices are
recorded as signed, append-only closures. An amendment can remove only future
M15 buckets that are still open. It cannot add a session, alter an observed
bucket, repair missing evidence, change a strategy, or enable an order.

The Phillip regular-session basis is conservative:

- FX DST schedule: Monday 07:00 JST through Saturday 05:50 JST, with the
  published daily 05:50–06:00 maintenance break. Only complete M15 buckets are
  eligible, so the final bucket ends at 05:45 and the next begins at 06:00.
- XAUUSD DST schedule: Monday 07:00 JST, then ordinary daily sessions ending
  at 05:50 JST. Only complete M15 buckets are eligible, so the final bucket
  ends at 05:45 and the next begins at 07:00.

Primary reviewed sources are the
[Phillip FX service-hours page](https://www.phillip.co.jp/fx/servicelist.php),
the [Phillip 2026 daylight-saving notice](https://www.phillip.co.jp/information/info/10999),
and the
[Phillip commodity-CFD important notes](https://www.phillip.co.jp/fx/pdf/C-CFD_important_notes.pdf).
An operator must still review and hash every later official notice that changes
the registered window.

## Preconditions

Do not run the commands below until all of these are true:

1. the matching candidate profile has been reviewed and intentionally enabled
   in a clean release commit;
2. the `forward-contract-v4` already exists for that exact candidate lane;
3. the current build identity matches the contract;
4. the matching Windows Credential Manager evidence key is available;
5. the closure begins at least the contract's lead time—currently 900
   seconds—after command execution;
6. no evidence has already been observed for the affected time; and
7. the contract is not sealed and the blind boundary has not begun.

Phillip profile registration is currently false, so this runbook documents the
future governed operation; it does not authorize registration today.

## Prepare a reviewed amendment request

Download the official notice without modifying it, then compute its exact byte
hash:

```powershell
(Get-FileHash .\official-notice.pdf -Algorithm SHA256).Hash.ToLower()
```

Read the authenticated current head from the candidate contract. Never copy a
head from another lane:

```powershell
$contract = "phillip-fx-window-01-diagnostic-v1"
$headPath = ".\validation_artifacts\forward\$contract\heads\calendar_amendments.json"
$head = Get-Content $headPath -Raw | ConvertFrom-Json
$head.amendment_hmac_sha256
```

Create a JSON regular file such as `phillip-fx-amendment-001.json`:

```json
{
  "schema_version": "calendar-amendment-request-v1",
  "candidate_id": "phillip-fx",
  "contract_id": "phillip-fx-window-01-diagnostic-v1",
  "amendment_id": "phillip-fx-special-hours-001",
  "expected_previous_head_hmac_sha256": "LOWERCASE_64_CHARACTER_HEAD_HMAC",
  "source": {
    "title": "Exact title of the official Phillip notice",
    "url": "https://www.phillip.co.jp/official-notice-url",
    "document_sha256": "LOWERCASE_64_CHARACTER_DOCUMENT_SHA256",
    "published_at_utc": "2026-07-21T00:00:00Z",
    "captured_at_utc": "2026-07-21T00:05:00Z"
  },
  "closures": {
    "EURUSD": [
      {
        "start_at_utc": "2026-07-22T01:00:00Z",
        "end_at_utc": "2026-07-22T02:00:00Z",
        "reason_code": "HOLIDAY",
        "label": "Exact reviewed special-hours closure"
      }
    ]
  }
}
```

All times are timezone-aware UTC and M15-aligned. Convert the official JST
schedule deliberately; do not label a JST timestamp with `Z`. The request
schema rejects unknown fields, including credentials, login, order, live, and
lot controls.

Register it:

```powershell
python -B .\register_calendar_amendment.py `
  --candidate phillip-fx `
  --input .\phillip-fx-amendment-001.json `
  --artifact-root .\validation_artifacts
```

The command stamps trusted current UTC itself, loads the signing key from
Windows Credential Manager, creates the next immutable record exclusively,
then atomically advances the signed head. A stale head, duplicate ID, late
notice, observed bucket, non-HTTPS source, bad hash, or chain defect is rejected
before a valid head advancement.

## Attest final calendar completeness

After `blind_until_utc` but before the contract is sealed, review the regular
schedule sources and every special-hours notice for the entire window. Create
`phillip-fx-calendar-completeness.json` with the final authenticated head and a
complete source inventory:

```json
{
  "schema_version": "calendar-completeness-request-v1",
  "candidate_id": "phillip-fx",
  "contract_id": "phillip-fx-window-01-diagnostic-v1",
  "attestation_id": "phillip-fx-calendar-review-001",
  "expected_final_head_hmac_sha256": "LOWERCASE_64_CHARACTER_FINAL_HEAD_HMAC",
  "reviewed_sources": [
    {
      "title": "Reviewed official source",
      "url": "https://www.phillip.co.jp/official-source",
      "document_sha256": "LOWERCASE_64_CHARACTER_DOCUMENT_SHA256",
      "published_at_utc": "2026-07-21T00:00:00Z",
      "captured_at_utc": "2026-07-21T00:05:00Z"
    }
  ]
}
```

Then run:

```powershell
python -B .\attest_calendar_completeness.py `
  --candidate phillip-fx `
  --input .\phillip-fx-calendar-completeness.json `
  --artifact-root .\validation_artifacts
```

Completeness is independent from mechanical chain validity. Without this final
attestation, the chain can be authentic while complete coverage remains false.
After completeness, no further amendment is accepted. Both commands always
report execution, demo-auto, promotion, and live capability as disabled with
`max_lot=0.01`.

## Fail-closed incident handling

- History beyond the current head indicates an interrupted commit. Do not
  delete or rename evidence; preserve the directory for review.
- A missing sequence, modified record, HMAC mismatch, stale head, or source
  mismatch invalidates verification and blocks append, receipt, and sealing.
- Never "repair" an already observed interval with an amendment. Record an
  incident and restart the evidence window under a newly reviewed contract.
- Keep request files free of account IDs, passwords, balances, and key
  material. The evidence key is never accepted as a command-line argument.
