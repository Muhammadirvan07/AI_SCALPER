# AI_SCALPER agent instructions

## Skill routing

- Before taking task actions, compare the request with the available skill
  descriptions.
- Use the smallest set of skills that fully covers the task. Prefer one focused
  skill over a broad bundle, aggregator, persona, or generic mode.
- Automatically invoke a skill only when its description has a direct,
  substantive match to the requested outcome. Do not invoke a skill for an
  incidental keyword match.
- If the user explicitly names a skill, use it for that turn.
- Read each selected `SKILL.md` completely before acting, and load only the
  linked references needed for the task.
- Do not carry a skill into later turns unless the new request still matches it
  or the user names it again.

## Project skills

- `ai-scalper-live-grade-core`: changes or reviews involving `live_runtime/`,
  decision, risk, permits, execution, reconciliation, broker contracts, or
  progression toward demo/live operation.
- `ai-scalper-windows-evidence-ops`: Windows/MT5 operator packages, Task
  Scheduler, broker shadow collection, dependency-lock verification, transfer
  ZIPs, receipts, ACLs, and automatic-run acceptance.
- `ai-scalper-dashboard-runtime`: canonical backend and React dashboard work,
  including REST/WebSocket contracts, realtime data, loopback deployment, and
  dashboard verification.

Use existing generic skills only when the requested outcome directly matches
them. In particular, `spec-driven-workflow` is appropriate for an approved new
feature with a specification; `focused-fix` is appropriate for systematic
cross-file repair; `dependency-auditor` is appropriate for dependency audits;
and `ship-gate` is appropriate for an explicit release-readiness audit. These
generic skills do not replace the project-specific invariants above.

## Context and evidence

- Load the current code, current specification, and the narrowest relevant
  runbook. Historical progress and audit documents are evidence from their own
  dates, not current truth.
- Separate source/test completion from Windows-host evidence, broker-forward
  evidence, external custody, human approval, and actual trading permission.
- Never infer a live/demo authorization, broker mutation, task mutation, or
  external upload from an unrelated approval.
- Preserve unrelated worktree changes and stage explicit paths only.
