# MT5 Candidate Read-Only Preflight

Status: preparation-only; no discovery evidence and no broker mutation.

## Acceptance criteria

1. Preflight accepts only the operator-selected demo candidate while its full
   discovery gate remains disabled.
2. The MT5 facade must expose only read APIs and runtime attestation must prove
   account trading, terminal trading, and external Python API trading are
   disabled. The account Expert flag is recorded but is not itself a gate
   because investor authorization may report it as enabled while account
   trading remains unavailable.
3. Exact server, demo mode, account currency, leverage, and all four canonical
   broker symbols must match the reviewed candidate configuration.
4. Any missing, malformed, enabled, or drifting fact fails closed.
5. The result contains no login, account name, balance, or credential and can
   never be treated as discovery or promotion evidence.
6. The Windows CLI accepts no credential or order argument and prints only a
   sanitized pass/fail summary.
