# Execution Journal Checkpoint v1

This deny-only component supplements SQLite `integrity_check` with a semantic,
HMAC-signed snapshot of the execution journal. It binds the exact journal
incarnation, account alias hash, server, environment, commit, configuration,
schema, all execution tables, and the append-only transition/receipt/kill-event
prefixes.

A previous signed checkpoint must be exported off-host. `DEMO`, `DEMO_AUTO`, and
`LIVE` creation/verification reject a missing external predecessor; a checkpoint
created only from the local database cannot prove execution continuity. Each new
v2 checkpoint signs the exact predecessor checkpoint content SHA-256. On the next
checkpoint, each append-only prefix is recomputed through the previous row count.
A shorter table, different prefix, forged predecessor, or restored old database is
a rollback/fork and fails closed. The current checkpoint is valid for at most one
second and verification requires the live database to match it exactly. `SHADOW`
may explicitly bootstrap the first zero-predecessor checkpoint, but that bootstrap
does not grant order capability.

The verifier also reconstructs every intent state from its ordered transitions,
checks canonical JSON and UTC timestamps, and requires each durable authorization
consumption to have a matching final-submission-guard receipt. This module does
not create an intent, permit, risk decision, or order capability.
