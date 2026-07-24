# Manual Demo Activation Kit v1

`prepare_manual_demo_activation_kit.py` joins the tracked candidate readiness
report with the reviewed Windows service provider contracts.

The output is an operator checklist, not an authorization:

- status is always `BLOCKED_EXTERNAL_INPUT_REQUIRED`;
- `ready`, `live_allowed`, `safe_to_demo_auto_order`, and execution flags remain
  false;
- order capability remains `DISABLED` and maximum lot remains `0.01`;
- exactly ten controlled manual-demo order lifecycles are the next acceptance
  target;
- every required external provider contract is listed by name, type, call
  contract, credential purpose, and content hash;
- the tool never imports MetaTrader, reads credentials, creates permits, or
  performs broker mutation;
- optional output is create-only and refuses to overwrite an existing file.

The kit may be used to configure and review a Windows host. It cannot be used
as evidence that manual demo, demo-auto, or live execution is approved.
