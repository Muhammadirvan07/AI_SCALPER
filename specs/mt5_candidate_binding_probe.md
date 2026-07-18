# MT5 candidate binding probe

The binding probe is a preparation-only tool for an already-open MT5 demo
terminal. It discovers the exact server, account currency, leverage, margin
mode, and possible broker symbol aliases needed before a candidate can be
selected in configuration.

It must:

- require the MT5 demo account and terminal to be read-only;
- expose no order or position mutation API;
- accept no login, password, or credential argument;
- never serialize account login, name, balance, equity, or credentials;
- report ambiguous/missing symbol aliases without guessing;
- keep execution, discovery evidence, promotion evidence, and live gates off.
