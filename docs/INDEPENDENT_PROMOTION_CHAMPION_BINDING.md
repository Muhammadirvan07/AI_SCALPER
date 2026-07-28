# Independent Promotion Champion Binding

Status: **IMPLEMENTED LOCALLY / SYNTHETIC TESTS PASS / REAL QUALITY EVIDENCE PENDING**

The independent promotion issuer now binds every raw quality observation to
one exact, externally pinned rule-core champion ZIP. This closes an identity
gap in which a caller could previously calculate a complete corpus and provide
an unrelated `model_artifact_sha256` only at signing time.

## Trust chain

1. `champion_artifact_from_archive(...)` receives the exact ZIP bytes and six
   pins obtained independently: archive, model, training snapshot,
   configuration, Git commit, and Git tree.
2. The existing champion verifier reconstructs and validates the whole ZIP.
   Only a successful direct verification can create
   `ChampionArtifactObservation`.
3. Every OOS trade, broker-forward trade, rolling fold, and parity report
   carries the same symbol, strategy, configuration, and model hashes.
4. `PromotionCorpus` rejects a different champion, lane, model, duplicate ID,
   non-canonical ordering, or overlapping OOS/forward time ranges.
5. `quality_corpus_sha256` covers the complete raw corpus, validation receipt
   observation, and exact champion observation.
6. `issue_independent_promotion_evidence_receipt(...)` derives commit and model
   identities from the verified champion. They are no longer public caller
   arguments.
7. Signed `promotion-evidence-v2` also binds the champion archive, package,
   training snapshot, Git tree, runtime binding, raw corpus, and bootstrap
   receipt identities.

## What this proves

- a quality calculation and signed receipt identify one exact champion ZIP;
- raw trade/fold/parity substitution is visible in the corpus hash or rejected;
- receipt tampering invalidates its HMAC signature;
- synthetic complete-corpus fixtures satisfy deterministic calculator tests;
- all safety locks remain false or disabled.

## What this does not prove

- that Phillip Commodity has enough real OOS or broker-forward trades;
- that its eight-week blinded observation window has completed;
- that a production validation receipt, quality signer key, or human ship-gate
  approval exists;
- that the champion is profitable, approved, safe for demo-auto, or safe for
  live trading;
- that any order may be sent.

The current real diagnostic sample is still far below the promotion threshold.
The first Phillip V6.3 automatic scheduled proof and the full observation
window remain external, time-dependent gates.

## Safety state

```text
live_allowed = false
safe_to_demo_auto_order = false
promotion_eligible = false
max_lot = 0.01
order_capability = DISABLED
manual_ship_gate_required = true
```

No network, credential, private-key store, MT5, Task Scheduler, registry, or
broker effect is performed by the champion/corpus verification functions.

Canonical requirements and acceptance tests are defined in
`specs/independent_promotion_champion_binding_v1.md`.
