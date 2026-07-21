# Broker Registration Review Gate

Status: **TOOLING IMPLEMENTED / HUMAN APPROVALS NOT ISSUED / REGISTRATION DISABLED**

This workflow prepares a signed review package for one broker lane. It does
not decide legal eligibility, modify tracked broker configuration, enable an
evidence profile, submit an order, or create promotion evidence. The project
owner must not treat a locally generated signature as legal advice.

The four tools are intentionally local and read-only:

1. `setup_regulatory_review_key.py` provisions a lane-and-role-scoped 256-bit
   key in Windows Credential Manager.
2. `prepare_broker_registration_review.py` hashes exact operator-supplied
   official source-file bytes and binds them to one candidate and calendar
   template.
3. `sign_broker_registration_review.py` produces one compliance or legal
   approval without accepting or exporting raw key material.
4. `assemble_broker_registration_review.py` requires two independently
   controlled approvals and re-runs the existing legal-binding verifier.

## Required independent review

The two roles are `COMPLIANCE_REVIEW` and `LEGAL_REVIEW`. They must use
different approver IDs, different key names, and different secret material.
The software detects those cryptographic differences, but cannot prove that
the people are organizationally independent or professionally qualified.
That remains an external governance gate.

For Phillip, prepare FX and commodity as separate packages. Never reuse one
lane's evidence, approvals, or output as the other lane's artifact.

## Prepare reviewed source files

Manually obtain an exact official registry document and review its meaning.
Do not commit the document or the manifest to Git. Keep them in a private
operator directory, for example:

```text
C:\AI_SCALPER_PRIVATE\phillip-fx-review-20260721\
  fsa-registry.pdf
  source-manifest.json
```

The Japan FSA registry currently used by the review package is:

```text
https://www.fsa.go.jp/menkyo/menkyoj/kinyushohin.pdf
```

Example `source-manifest.json` for the FX lane follows. Set
`observed_at_utc` to the actual timezone-aware UTC review time; do not copy a
stale timestamp.

```json
{
  "schema_version": "regulatory-source-manifest-v1",
  "candidate_id": "phillip-fx",
  "operating_jurisdiction": "JP",
  "sources": [
    {
      "authority": "Japan Financial Services Agency",
      "url": "https://www.fsa.go.jp/menkyo/menkyoj/kinyushohin.pdf",
      "entity": "Phillip Securities Japan, Ltd.",
      "result": "ENTITY_REGISTERED_FOR_JAPAN_RESIDENTS",
      "registry_record_id": "KANTO-KINSHO-127",
      "observed_at_utc": "2026-07-21T10:00:00Z",
      "source_file": "fsa-registry.pdf"
    }
  ]
}
```

For the commodity lane, use a separate private directory and change only the
reviewed lane identity to `phillip-commodity`. Source files must be non-empty
regular files. Symlinks, path traversal, duplicate JSON keys, unknown fields,
non-HTTPS authorities, changed files, future claims, and evidence older than
30 days are rejected.

## Provision distinct review keys

Run on the reviewed Windows evidence host:

```powershell
cd C:\AI_SCALPER
.\.venv\Scripts\Activate.ps1

python -B .\setup_regulatory_review_key.py `
  --candidate phillip-fx `
  --role COMPLIANCE_REVIEW

python -B .\setup_regulatory_review_key.py `
  --candidate phillip-fx `
  --role LEGAL_REVIEW
```

The resulting names are
`phillip-fx-compliance-review-v1` and
`phillip-fx-legal-review-v1`. Repeat separately for
`phillip-commodity`. Secret bytes are never printed or accepted on the command
line.

## Prepare, approve, and assemble

```powershell
$reviewRoot = "C:\AI_SCALPER_PRIVATE\phillip-fx-review-20260721"

python -B .\prepare_broker_registration_review.py `
  --candidate phillip-fx `
  --source-manifest "$reviewRoot\source-manifest.json" `
  --source-root $reviewRoot `
  --output "$reviewRoot\regulatory-evidence.json"
```

Each reviewer runs a separate approval invocation only after inspecting the
exact evidence hash and official document hash:

```powershell
python -B .\sign_broker_registration_review.py `
  --candidate phillip-fx `
  --role COMPLIANCE_REVIEW `
  --approver-id compliance-reviewer `
  --evidence "$reviewRoot\regulatory-evidence.json" `
  --output "$reviewRoot\compliance-approval.json"

python -B .\sign_broker_registration_review.py `
  --candidate phillip-fx `
  --role LEGAL_REVIEW `
  --approver-id legal-reviewer `
  --evidence "$reviewRoot\regulatory-evidence.json" `
  --output "$reviewRoot\legal-approval.json"
```

Assemble only after both approvals exist:

```powershell
python -B .\assemble_broker_registration_review.py `
  --candidate phillip-fx `
  --evidence "$reviewRoot\regulatory-evidence.json" `
  --compliance-approval "$reviewRoot\compliance-approval.json" `
  --legal-approval "$reviewRoot\legal-approval.json" `
  --output "$reviewRoot\regulatory-observation.json"
```

Every destination is create-exclusive. Use a new reviewed directory instead
of overwriting an earlier artifact.

## What remains blocked

Assembly leaves `registration_enabled=false`. It does not patch
`config/broker_candidates.phase3.json` and does not attest special hours. A
later change requires all of the following in one explicit human-reviewed
clean commit:

- the exact assembled observation inserted into the matching candidate only;
- the exact official-calendar/special-hours review completed;
- the matching evidence profile deliberately enabled;
- the source, template, discovery, reviewer keys, and candidate bindings
  reverified; and
- no change to `live_allowed=false`, `safe_to_demo_auto_order=false`, or
  `max_lot=0.01`.

Only after that separate review can plan preparation and diagnostic contract
registration load the reviewer keys from Windows Credential Manager. Even a
valid contract remains diagnostic evidence and cannot place an order.
