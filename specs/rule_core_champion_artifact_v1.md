# Rule-Core Champion Artifact v1

**Status:** Approved for implementation
**Scope:** Phillip Commodity diagnostic-to-manual-demo preparation
**Safety:** deny-only; no execution or promotion authority

## Purpose

The live-grade contracts bind every decision, permit, configured provider,
manual-demo record, and soak record to a model artifact hash. Before this
contract, the diagnostic runner computed that hash from eight source files,
but there was no portable artifact that also bound the exact Git source,
candidate configuration, calibration snapshot, and post-snapshot registration
time.

This contract defines one deterministic archive for the current
`phillip-commodity` rule-core champion. It closes only the model-lineage gap.
It does not prove model quality, broker parity, profitability, statistical
significance, promotion eligibility, or execution readiness.

## Fixed identity

- Candidate: `phillip-commodity`
- Role: `CHAMPION`
- Model version: `rule-core-phillip-commodity-locked-v1`
- Timeframe: `M15`
- Canonical symbol: `XAUUSD`
- Snapshot member: `training-snapshot/xauusd.csv`
- Candidate config: `config/broker_candidates.phase3.json`
- Schema: `rule-core-champion-artifact-v1`

The model artifact SHA-256 is the existing runtime digest over the exact
ordered source-path and byte sequence. The source list has one implementation
shared by the diagnostic runner, builder, and verifier.

## Required source members

1. `agents/market_status.py`
2. `agents/supervisor_agent.py`
3. `live_runtime/decision_core.py`
4. `market_data_quality.py`
5. `market_regime_filter.py`
6. `strategy/strategy_profiles.py`
7. `strategy/strategy_selector.py`
8. `strategy/trend_analyzer.py`

Every source and the candidate config MUST be tracked at exact `HEAD`, MUST
equal `git show HEAD:<path>`, and the tracked working tree MUST be clean.

## Snapshot contract

The calibration snapshot MUST be one stable, regular, non-reparse CSV file no
larger than 64 MiB with exact columns:

```text
Datetime,Close,High,Low,Open,Volume
```

The snapshot MUST contain at least 96 and at most 2,000,000 data rows. Rows
MUST have strictly increasing UTC M15 open timestamps, finite positive
OHLC values, valid candle extrema, and finite nonnegative volume. The training
cutoff is exactly fifteen minutes after the final bar open. Registration MUST
be explicit UTC and MUST NOT precede that cutoff.

The archive contains the exact snapshot bytes; a hash-only reference is not a
frozen snapshot.

## Archive contract

The deterministic ZIP contains exactly:

- the eight source members below `model-source/`;
- the exact candidate config;
- the exact snapshot; and
- `RULE_CORE_CHAMPION_MANIFEST.json`.

All member paths, order, timestamps, Unix modes, compression, sizes, and hashes
are canonical. Duplicate members, traversal, links, extra fields, duplicate
JSON keys, noncanonical ZIP metadata, source drift, config drift, snapshot
drift, and output collisions fail closed.

The manifest binds:

- full 40-hex Git commit and tree;
- model artifact SHA-256 and ordered source inventory;
- config SHA-256;
- snapshot SHA-256, size, row count, first/final timestamps, and cutoff;
- a canonical `ModelArtifactManifest` projection;
- explicit quality non-claims; and
- immutable safety locks.

## Safety invariants

Every successful build and verification MUST report:

```text
execution_enabled=false
manual_demo_enabled=false
safe_to_demo_auto_order=false
live_allowed=false
promotion_eligible=false
order_capability=DISABLED
max_lot=0.01
credential_access=NOT_PERFORMED
network_access=NOT_PERFORMED
mt5_initialization=NOT_PERFORMED
broker_mutation=NOT_PERFORMED
```

`offline_validation_performed`, `broker_forward_validation_performed`,
`oos_gate_passed`, and `quality_approved` MUST all remain `false`. No metric or
caller option may relax these fields.

## Acceptance criteria

1. Two builds with identical inputs are byte-identical.
2. Builder and independent verifier recompute the runtime model digest.
3. Exact archive/model/snapshot/config/commit/tree pins are mandatory for
   independent verification.
4. Dirty tracked source, source drift, malformed config, wrong candidate,
   malformed snapshot, early registration, archive drift, or output collision
   is rejected without overwriting pre-existing bytes.
5. The read-only shadow runner uses the same source inventory and digest
   implementation as the package.
6. The Windows configured-release operator tooling carries the independent
   verifier but not the artifact builder or any training data.
7. Focused and complete tests pass in normal and optimized modes.

## Remaining external gates

This archive cannot close:

- offline champion/challenger evaluation;
- 100 closed OOS trades per lane;
- eight-week and 50-trade broker-forward evidence;
- broker-native XAUUSD minimum-lot risk feasibility;
- manual-demo lifecycle review;
- demo-auto soak; or
- live-canary approval.
