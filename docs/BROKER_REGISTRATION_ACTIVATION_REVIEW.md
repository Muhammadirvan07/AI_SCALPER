# Broker Registration Activation Review Pack

Status: **NON-MUTATING REVIEW TOOLING / REGISTRATION DISABLED**

This workflow is the last software-only checkpoint before a human-reviewed
registration commit. It verifies one exact Phillip lane against all of the
following at the same time:

- one clean Git commit and tree;
- the lane-specific signed MT5 discovery-v3 receipt;
- one byte-derived regulatory observation with two independent approvals;
- one byte-derived pre-window calendar review with its separate approval; and
- the currently disabled candidate, profile, and schema-v2 calendar template.

The result contains complete base and proposed images for exactly three files,
plus canonical before/after hashes. It does not modify those files. There is
no apply command and the pack is not an approval.

## Safety properties

Every valid pack says:

```text
configuration_mutated = false
registration_enabled = false
manual_activation_required = true
apply_capability = DISABLED
order_capability = DISABLED
execution_enabled = false
live_allowed = false
safe_to_demo_auto_order = false
promotion_eligible = false
max_lot = 0.01
```

The command rejects a dirty worktree, a changing commit, an existing output,
an output inside the repository, a cross-lane artifact, an invalid signature,
an already-enabled profile, or any proposed change outside the three fields
explicitly reviewed by the specification.

## Prerequisites

Run from a clean Windows checkout after pulling the reviewed branch. Keep all
human-review inputs and outputs outside `C:\AI_SCALPER`.

```powershell
cd C:\AI_SCALPER
git pull origin agent/live-grade-phase3
git status --short
.\.venv\Scripts\Activate.ps1
```

`git status --short` must print nothing. Runtime artifacts should remain in
ignored runtime directories; do not stage or delete them merely to satisfy the
gate.

For the selected lane, these immutable artifacts must already exist:

1. discovery-v3 signed with the lane evidence key;
2. regulatory evidence prepared from exact official source bytes;
3. one `COMPLIANCE_REVIEW` and one `LEGAL_REVIEW` approval from different
   reviewers and different Credential Manager keys;
4. the assembled regulatory observation;
5. pre-window calendar evidence and a calendar-review approval; and
6. the assembled pre-window calendar review.

Never invent reviewer identities. The two regulatory approvals are external
human gates; one person entering two labels does not satisfy independence.

## Prepare the review pack

Example for the commodity lane:

```powershell
$reviewRoot = "C:\AI_SCALPER_PRIVATE\phillip-commodity-review"

python -B .\prepare_broker_registration_activation_review.py `
  --candidate phillip-commodity `
  --discovery .\runtime_state\broker_discovery\phillip-commodity-window-01-v3.json `
  --regulatory-observation "$reviewRoot\regulatory-observation.json" `
  --calendar-review "$reviewRoot\prewindow-calendar-review.json" `
  --output "$reviewRoot\registration-activation-review.json"
```

For FX, use `phillip-fx` and the matching FX-only artifacts. Commodity and FX
receipts are intentionally not interchangeable.

The command loads all four required secrets from Windows Credential Manager:
the discovery key, compliance key, legal key, and calendar-review key. Raw key
bytes are never accepted as arguments, exported, or printed.

## Human inspection

An independent reviewer should verify:

- `source_git_commit` and `source_git_tree` identify the reviewed clean
  checkout;
- the three `before_sha256` values match each embedded `base_content`;
- the three `after_sha256` values match each embedded `proposed_content`;
- candidate config changes only the selected `regulatory_observation`;
- calendar template changes only v2 to v3 and embeds the exact calendar
  review; and
- evidence profile changes only the selected lane's registration flag and
  reviewed diagnostic status.

The static verifier repeats these checks without secret access. A modified
pack, including one whose top-level hash was recomputed, is rejected if its
bounded diff or safety fields drift.

Run it on any review workstation that has the clean project tooling; no
Credential Manager key is required:

```powershell
python -B .\verify_broker_registration_activation_review.py `
  --input "$reviewRoot\registration-activation-review.json"
```

## What happens next

Nothing is applied automatically. After qualified reviewers accept the exact
pack, the project owner must authorize a separate clean-commit change. That
future action remains outside this tool and must rerun tests and safety gates.
Even a later diagnostic registration does not authorize an order, demo-auto,
promotion, or live trading. Broker-forward collection, 20 sessions, eight
weeks, statistical gates, and subsequent roadmap approvals remain required.
