# Rule-Core Champion Artifact

## Outcome and boundary

`build_rule_core_champion_artifact.py` freezes the exact Phillip Commodity
rule-core sources, tracked candidate configuration, and one XAUUSD M15
calibration snapshot into a deterministic ZIP. The archive is a model-lineage
input only. It never enables execution, manual demo, demo-auto, promotion, or
live trading.

The independent verifier is shipped in the configured-release operator
tooling. The builder and training snapshot are deliberately excluded from that
Windows tooling bundle.

## Build from a clean source commit

Create the destination directory outside the repository first. The snapshot
must be a stable regular file named `xauusd.csv`, contain at least 96 rows, and
end before the explicit registration time.

```bash
cd /Users/muhammadirvan/Documents/AI_SCALPER

commit="$(git rev-parse HEAD)"
registered_at="$(date -u '+%Y-%m-%dT%H:%M:%S.000000Z')"
output_root="/private/tmp/ai-scalper-rule-core-${commit:0:8}"
mkdir "$output_root"

python3 -B build_rule_core_champion_artifact.py \
  --snapshot data/xauusd.csv \
  --registered-at-utc "$registered_at" \
  --output "$output_root/rule-core-phillip-commodity-champion-${commit:0:8}.zip"
```

Record the six independently transported pins printed by the builder:

- archive SHA-256;
- model-artifact SHA-256;
- training-snapshot SHA-256;
- candidate-config SHA-256;
- full Git commit; and
- full Git tree.

Two builds using the same source, snapshot bytes, and registration timestamp
must be byte-identical. Never overwrite an earlier artifact; use a new empty
destination.

## Verify independently

Extract the configured-release operator tooling and invoke its verifier under
isolated stdlib mode. Replace every placeholder with the six values received
through the independent review channel.

```powershell
& $python -I -S -B `
  .\verify_rule_core_champion_artifact.py `
  --archive C:\AI_SCALPER_PRIVATE\rule-core-phillip-commodity-champion-<commit>.zip `
  --expected-archive-sha256 <archive-sha256> `
  --expected-model-artifact-sha256 <model-sha256> `
  --expected-training-snapshot-sha256 <snapshot-sha256> `
  --expected-config-sha256 <config-sha256> `
  --expected-git-commit <full-commit> `
  --expected-git-tree <full-tree>
```

A successful result still reports:

```text
quality_approved: false
promotion_eligible: false
order_capability: DISABLED
live_allowed: false
broker_mutation: NOT_PERFORMED
```

## Remaining gates

This artifact does not replace offline champion/challenger evaluation, OOS
evidence, broker-forward evidence, minimum-lot risk feasibility, manual-demo
lifecycle review, demo-auto soak, production registry custody, or live-canary
approval.
