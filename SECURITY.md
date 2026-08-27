# Security Policy

## Supported code

Security fixes apply to the current maintained default branch. Historical
handoffs, evidence archives, generated release bundles, and expired observation
windows are immutable records rather than supported deployment releases.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository when available.
Otherwise contact the repository owner privately through the account contact
method. Do not open a public issue containing exploit details or sensitive data.

Include:

- affected commit and file paths
- reproduction steps using paper/read-only mode
- observed and expected behavior
- potential impact
- a minimal remediation proposal, if known

Never include API keys, passwords, MT5 logins, account identifiers, balances,
private evidence, or unredacted runtime artifacts.

## Safe research boundary

- Do not enable live or demo-auto order capability.
- Do not invoke broker mutation or order APIs while reproducing an issue.
- Do not weaken read-only account, terminal, Python API, or maximum-lot locks.
- Do not alter Task Scheduler jobs, evidence custody, or immutable archives
  without separate explicit authorization.
- Use synthetic fixtures and isolated test environments whenever possible.

If a finding appears to require an actual order, broker-account mutation, or
secret disclosure to reproduce, stop and report the limitation privately. A
security test result never grants trading permission.
