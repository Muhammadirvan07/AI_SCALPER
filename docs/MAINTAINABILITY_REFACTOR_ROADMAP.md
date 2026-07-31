# Maintainability Refactor Roadmap

## Measurement baseline

Measured on 2026-07-31 from the working tree based on commit `ccc71bfbccdeef9ff6eabf1b9e961e8c5e2ea3f3`, after the local production-readiness fixes. The measurement used Radon 6.0.1 and did not execute trading code.

- 684 tracked Python files and 339,943 tracked Python lines.
- 467 non-test/source files in the complexity scan.
- Radon cyclomatic complexity: 6,740 unique blocks, average 6.85; grades A/B/C/D/E/F = 4,365/1,111/822/255/88/99.
- Radon maintainability index across 684 tracked Python files: average 36.81; ranks A/B/C = 534/50/100. Radon reports MI 0.00 (C) for the five primary hotspots below.
- The previous claim of “141 grade F” used a different, undocumented metric and is not treated as comparable evidence. The reproducible Radon result is the baseline here.

| Hotspot | Lines | Largest measured block | Complexity | Function length |
|---|---:|---|---:|---:|
| `decision_engine.py` | 16,547 | `build_phase5z_all_pair_replay_validation_recovery_checker` / `print_guard_block` | 83 | `build_trade_decision`: 860 lines |
| `validation_evidence/secure_core.py` | 5,928 | `_verify_paired_commits_for_symbol` | 64 | 239 lines |
| `live_runtime/runtime_supervisor.py` | 5,137 | `__init__` | 87 | 477 lines |
| `live_runtime/executor.py` | 2,232 | `ExecutionCoordinator.execute_once` | 278 | 1,715 lines |
| `live_runtime/runtime_service.py` | 1,226 | `LiveRuntimeService.execute_once` | 115 | 553 lines |

Coupling proxy from static local-import edges identifies high fan-in boundaries: `live_runtime.evidence_credentials` (35), `execution_policy` (30), `live_runtime.secure_files` (21), `live_runtime.broker_evidence_profile` (21), and `live_runtime.contracts` (15). These are security-sensitive seams; extraction must preserve their fail-closed contracts.

## Non-negotiable refactor rules

1. No strategy, scoring, pair rotation, risk, SL/TP, entry, exit, or AI-model behavior changes.
2. Characterization tests must be committed before moving logic.
3. Normal and `python -O` safety suites must pass after every slice.
4. Every extraction is mechanical: same inputs, serialized outputs, error codes, hashes, and ordering.
5. No live broker, MT5 order, or manual scheduler acceptance is used as a test oracle.

## Phased roadmap

### Phase 1 — Characterize executor orchestration (highest risk)

- Target: `ExecutionCoordinator.execute_once` in `live_runtime/executor.py`.
- Boundary: snapshot input context, each fail-closed rejection code, audit payload, dispatch fence, and final `ExecutionOutcome`.
- Prerequisite: table-driven characterization fixtures for every early return and dispatch-abort path; mutation/order adapter remains mocked.
- Extraction order: pure precondition collection, rejection-reason assembly, audit serialization, then dispatch-settlement formatting.
- Risk: high because the function is 1,715 lines and complexity 278.
- Acceptance: byte-equivalent audit/output fixtures, zero broker calls, existing executor/safety tests normal and `-O` pass.

### Phase 2 — Split runtime cycle preparation from execution

- Target: `LiveRuntimeService.execute_once` and `runtime_supervisor` validation helpers.
- Boundary: immutable cycle context, preparation result, supervisor validation receipt, and reconciliation result.
- Prerequisite: characterization coverage for IDLE/HOLD/FAILED paths, stale heartbeat, dependency failure, and duplicate cycle.
- Extraction: pure context builder first; then diagnostic serialization; no executor ownership changes.
- Risk: high.
- Acceptance: identical cycle IDs/status/error codes and journal records; safety verifier unchanged.

### Phase 3 — Isolate configuration and report serialization

- Target: parsing/normalization and report writers in `decision_engine.py`.
- Boundary: typed input dictionaries to deterministic output dictionaries; no market-data or executor side effects.
- Prerequisite: golden JSON fixtures and stable key/order/hash checks.
- Initial candidates: report serialization, guard diagnostics formatting, and configuration parsing—not `build_trade_decision` itself.
- Risk: medium.
- Acceptance: byte-for-byte report fixtures and unchanged decision characterization suite.

### Phase 4 — Decompose evidence validation by schema

- Target: `validation_evidence/secure_core.py`.
- Boundary: schema parsing, canonicalization, digest verification, and semantic validation as separate pure modules.
- Prerequisite: valid/tampered/missing/extra-field fixtures for every supported schema.
- Risk: medium-high because evidence integrity and release admission depend on it.
- Acceptance: exact existing rejection codes and canonical hashes; release reproducibility gate passes twice.

### Phase 5 — Reduce coupling at shared security seams

- Target: the five high fan-in modules listed above.
- Boundary: narrow protocol/dataclass interfaces; callers retain ownership of policy decisions.
- Prerequisite: import-contract tests and static cycle detection.
- Risk: medium-high; do only after Phases 1–4 stabilize public contracts.
- Acceptance: fan-in is intentional/documented, no new circular imports, and all service/package builders remain deterministic.

## Incremental quality targets

- No new grade F block.
- Reduce `ExecutionCoordinator.execute_once` below complexity 200 in the first slice, then below 100 through later mechanical slices.
- Keep each new helper below 80 lines and complexity 15 unless an explicit architecture review records why not.
- Raise characterization branch coverage around the extracted boundary before each move; never lower the backend 90% gate.
- Re-run and record Radon with the exact commands below after each phase:

```bash
python -m radon cc -s -a live_runtime/executor.py live_runtime/runtime_service.py decision_engine.py live_runtime/runtime_supervisor.py validation_evidence/secure_core.py
python -m radon mi -s decision_engine.py live_runtime/runtime_supervisor.py validation_evidence/secure_core.py live_runtime/executor.py live_runtime/runtime_service.py
```

This roadmap deliberately defers a broad rewrite. P2 maintainability debt does not justify changing trading behavior or opening live execution.
