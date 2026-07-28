# Create-Exclusive Output Custody v1

Status: **Implemented and regression verified**

## Purpose

This contract prevents a failed publisher from deleting or overwriting a path
that it did not create. It applies to release archives, release sidecars,
configured overlays, evidence packets, provider packs, vulnerability reports,
atomic-suite publication locks, and generated candidate trees.

It does not grant execution, broker, demo-auto, promotion, or live authority.

## Required behavior

1. A leaf output is created with `O_CREAT | O_EXCL`. `O_NOFOLLOW`,
   `O_CLOEXEC`, and `O_BINARY` are added where the platform exposes them.
2. The publisher captures the opened object's identity from the descriptor
   immediately after creation. At minimum this binds device, inode, object
   type, and the platform file-attribute value used to identify reparse
   points.
3. A failure before identity capture has no deletion authority. The output
   path is preserved.
4. Failure cleanup may unlink only a regular file whose current no-follow
   identity is exactly the identity created by that invocation.
5. A symlink, dangling symlink, reparse point, directory, missing path, or
   identity mismatch is preserved and the operation fails closed.
6. A multi-output transaction retains one identity token per successfully
   created member. Outer cleanup must use those exact tokens; a boolean such
   as `created = true` is insufficient deletion authority.
7. A generated directory tree may be cleaned only while the root remains the
   exact non-link directory created by that invocation. Replacement roots are
   preserved.
8. Directory synchronization failure is handled by the same identity-bound
   rule. It must not broaden cleanup authority.
9. Destination validation preserves the requested leaf path. Resolving a
   dangling output symlink into its target before exclusive creation is
   forbidden.
10. An immutable evidence directory is published with an atomic native
    no-replace move. A preceding `exists()` check followed by ordinary
    directory `rename` is insufficient because POSIX may replace a raced empty
    target directory.
11. The evidence publisher pins the parent and staging-directory identities
    before publication. Staging cleanup is authorized only while the current
    no-follow directory identity remains exactly equal to the root created by
    that invocation; symlink, junction/reparse, identity drift, or an unknown
    platform without atomic no-replace support fails closed.

## Failure cases

The implementation must preserve a competing or pre-existing path when:

- exclusive open loses a race;
- a dangling output symlink is present;
- the created path is swapped during file `fsync` or directory `fsync`;
- a release sidecar replaces a previously created archive or manifest;
- a staging root or publication lock is replaced before exception cleanup;
- an empty destination directory appears between pre-check and publication;
- an internal configured-candidate or provider-pack root is replaced before
  cleanup begins.

Preservation is the fail-closed result. A leftover partial object created by
the same invocation is preferable to deleting an object whose ownership can
no longer be proven.

## Verification

Regression tests inject output swaps at write, file-sync, directory-sync,
second-member publication, publication-lock, and staging-root boundaries.
They assert that replacement bytes, links, and roots survive unchanged while
the publisher reports failure. Frozen-snapshot and forward-contract tests also
inject an empty target at the exact directory-publication boundary, verify the
native Windows write-through/no-replace path, and replace the staging root
before cleanup.

The contract is verified in normal and optimized Python modes so production
behavior does not depend on `assert` statements.

## Trading safety invariants

```text
order_capability = DISABLED
live_allowed = false
safe_to_demo_auto_order = false
promotion_eligible = false
```

No implementation or test covered by this contract imports MT5, submits an
order, starts a Windows task, imports a provider, or grants a release
activation decision.
