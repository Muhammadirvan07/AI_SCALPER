# Windows Base Release Reproducibility — 2026-07-24

Status: **PASS / CONFIGURED PROVIDERS STILL ABSENT**

Supersession note: this remains the exact reproducibility receipt for
`d153361`. A later working tree adds the signed finalized-M15 decision-feed
handoff to the decision allowlist, so these four archives are a historical
baseline rather than the current configured-release candidate. Rebuild all
roles from the same next clean commit before provider/configured-release
admission.

## Scope

This receipt records the deterministic-build comparison for Git commit
`d153361827c0ba2542c3df2b381582ac64fa8122` and Git tree
`bdd5cf4a7469f0ab35fda0333713893f46c10007`.

The first build was performed on the reviewed Windows Python 3.12 workspace.
An independent clean checkout on macOS rebuilt the same four deterministic
archives. All archive SHA-256 values and release identities matched exactly.

This receipt covers base-release provenance only. It does not accept a
configured provider, credential, Windows service identity, Task Scheduler
definition, launcher attestation, manual-demo order, demo-auto activation, or
live trading.

## Exact results

| Role | Archive SHA-256 | Release identity SHA-256 | Files | Capability |
|---|---|---|---:|---|
| Decision | `811e118f980228816b8af1ddc0e66ceda7ade4eacf24a68b4483b83d08626405` | `32b77dd44093c1cb6196889b01c56381c0ce2f9aaa292506a81756cb7f92f91a` | 22 | `DISABLED` |
| Execution | `948e28556123e359b21a651949890113b4f6b9cbbd99a03e8e5a5981487d9109` | `d0070af075e7a1472955e35222373d68e71e9b509f47afb440aaf6f65f056563` | 46 | `GATED_PRESENT` |
| Status monitor | `dbd3a8aa8d163edb0d1afe091fefac0acf4fa466e898d37bf987d37518aa6eef` | `7a1dda8a4fceb0e076f19975522b2c7955d2bd236998dac71a210500db154564` | 11 | `DISABLED` |
| Configured-release operator tooling | `ef53de419df266f187090171d2092edbceaf8cdd2f284c4df2ec490af0348a01` | `5d376cf26ee622b82efbace383108881fc2a0d20398239187f14b82e2b2b3a80` | 14 | `DISABLED` |

All four manifests bind the same reviewed Git commit and tree. All reported:

```text
production_execution_ready = false
live_allowed = false
safe_to_demo_auto_order = false
max_lot = 0.01
```

The execution archive's `GATED_PRESENT` value is expected: it contains the
dormant, fail-closed execution boundary but grants no runtime authority.

## Gate decision

The deterministic base-release and configured-tooling build gate is closed.
The next gate is to supply and independently test three secret-free, exact-hash
provider overlays, then build and admit three configured releases. Until that
work and the later manual-demo acceptance sequence are complete, the system
remains `NOT_READY`.
