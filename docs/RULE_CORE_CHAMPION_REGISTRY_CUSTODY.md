# Rule-Core Champion Registry Custody

## Outcome and boundary

`manage_rule_core_champion_registry.py` provides a portable, standard-library-
only boundary for handing one exact Phillip Commodity rule-core champion to an
independent immutable model registry. It can:

1. create a deterministic two-member custody-request ZIP;
2. verify that request against seven independently transported pins; and
3. verify a canonical, policy-pinned RSA custodian receipt and publish a
   deny-only assessment.

It does not upload, access a registry API, read credentials or private keys,
inspect remote storage directly, initialize MT5, mutate Task Scheduler, touch a
broker, approve model quality, or authorize any order. A successful local
request means only that the exact bytes are ready for external custody.

## Required independent pins

Keep these values outside the request ZIP and transfer them through a reviewed
independent channel:

- champion archive SHA-256;
- model-artifact SHA-256;
- training-snapshot SHA-256;
- candidate-config SHA-256;
- full Git commit;
- full Git tree; and
- after preparation, registry-request archive SHA-256.

The external receipt verifier additionally requires the exact canonical
registry-policy SHA-256. Do not accept a policy hash delivered only beside the
policy through the same untrusted transfer.

## Prepare a custody request on Windows

Run the CLI from the extracted configured-release operator tooling with the
isolated release Python. The output directory must already exist, must be a
direct regular directory, and the output name must contain the first 8–12
characters of the pinned commit. Never overwrite an existing path.

```powershell
$tooling = "C:\AI_SCALPER_PRIVATE\configured-release-tooling-v1"
$python = "C:\AI_SCALPER\.venv\Scripts\python.exe"
$artifact = "C:\AI_SCALPER_PRIVATE\rule-core-phillip-commodity-champion-<commit8>.zip"
$request = "C:\AI_SCALPER_PRIVATE\rule-core-champion-registry-request-<commit8>.zip"

& $python -I -S -B `
  "$tooling\manage_rule_core_champion_registry.py" `
  prepare-request `
  --artifact $artifact `
  --expected-archive-sha256 <champion-archive-sha256> `
  --expected-model-artifact-sha256 <model-artifact-sha256> `
  --expected-training-snapshot-sha256 <snapshot-sha256> `
  --expected-config-sha256 <config-sha256> `
  --expected-git-commit <full-git-commit> `
  --expected-git-tree <full-git-tree> `
  --registry-id <reviewed-registry-id> `
  --destination-id <reviewed-immutable-destination-id> `
  --requested-at-utc <canonical-utc-with-six-fractional-digits> `
  --minimum-retain-until-utc <at-least-365-days-after-request> `
  --output $request
```

The request time must not precede the champion registration time. The ZIP
contains exactly `rule-core-champion-artifact.zip` and
`RULE_CORE_REGISTRY_REQUEST.json`, uses deterministic metadata, and records
`external_registry.performed=false`.

## Verify before external transfer

```powershell
& $python -I -S -B `
  "$tooling\manage_rule_core_champion_registry.py" `
  verify-request `
  --request-archive $request `
  --expected-request-archive-sha256 <request-archive-sha256> `
  --expected-archive-sha256 <champion-archive-sha256> `
  --expected-model-artifact-sha256 <model-artifact-sha256> `
  --expected-training-snapshot-sha256 <snapshot-sha256> `
  --expected-config-sha256 <config-sha256> `
  --expected-git-commit <full-git-commit> `
  --expected-git-tree <full-git-tree>
```

Transfer the verified request to the independent custodian. Upload, WORM
retention, object versioning, content-hash comparison, alerting, restore proof,
and policy approval are external actions and must not be inferred from this
local command.

## Verify an independent custodian receipt

The trust policy and receipt must be canonical JSON with no newline, duplicate
key, extra field, non-finite number, or encoding drift. The policy pins one
registry, custodian, RSA key, storage provider, destination, and retention
floor. The supported signature is RSA PKCS#1 v1.5 with SHA-256, exponent 65537,
and a 3072–8192-bit public modulus. Private key material must remain with the
independent custodian.

The receipt must bind the exact request identity and archive hash, exact
champion content hash and size, immutable destination, unique remote object
version, retention date, and three positive custodian attestations. The signed
message is the ASCII domain
`AI_SCALPER_RULE_CORE_CHAMPION_REGISTRY_RECEIPT_V1` followed by one NUL byte and
the canonical JSON bytes of the receipt with the signature field removed.

```powershell
$policy = "C:\AI_SCALPER_PRIVATE\registry-policy.json"
$receipt = "C:\AI_SCALPER_PRIVATE\registry-receipt.json"
$assessment = "C:\AI_SCALPER_PRIVATE\rule-core-champion-registry-assessment-<receipt-id>.json"

& $python -I -S -B `
  "$tooling\manage_rule_core_champion_registry.py" `
  verify-receipt `
  --request-archive $request `
  --expected-request-archive-sha256 <request-archive-sha256> `
  --expected-archive-sha256 <champion-archive-sha256> `
  --expected-model-artifact-sha256 <model-artifact-sha256> `
  --expected-training-snapshot-sha256 <snapshot-sha256> `
  --expected-config-sha256 <config-sha256> `
  --expected-git-commit <full-git-commit> `
  --expected-git-tree <full-git-tree> `
  --policy $policy `
  --expected-policy-sha256 <independently-reviewed-policy-sha256> `
  --receipt $receipt `
  --verified-at-utc <canonical-verification-utc> `
  --assessment-output $assessment
```

A successful assessment means a policy-pinned signed attestation was accepted;
it still states `direct_storage_api_inspection_performed=false` and is not
model-quality or trading evidence.

## Immutable safety result

Every successful request and assessment retains:

```text
quality_approved: false
oos_gate_passed: false
promotion_eligible: false
order_capability: DISABLED
safe_to_demo_auto_order: false
live_allowed: false
broker_mutation: NOT_PERFORMED
```

Registry custody closes neither champion/challenger validation nor OOS,
broker-forward, minimum-lot risk, manual-demo, demo-auto soak, legal, or live
canary gates.
