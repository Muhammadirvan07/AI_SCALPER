# AI_SCALPER

AI_SCALPER is a safety-gated research platform for deterministic market analysis,
news diagnostics, paper-trading evaluation, and read-only broker observation.
The repository is not authorized or ready for live trading.

## Safety boundary

- `live_allowed=false`
- `safe_to_demo_auto_order=false`
- `AI_SCALPER_ORDER_CAPABILITY=DISABLED`
- maximum lot remains capped at `0.01`
- OpenAI is advisory-only and may confirm or veto a deterministic paper setup
- broker and MT5 observation must remain read-only unless a separate reviewed
  authorization explicitly changes that boundary

No test, report, AI response, broker connection, or successful CI run grants
permission to place an order.

## Main components

- `decision_engine.py`: deterministic strategy and risk decision pipeline
- `openai_decision_advisor.py`: fail-closed paper-trade advisory layer
- `backend/`: canonical read-only FastAPI service and news intelligence
- `frontend-dashboard/`: React dashboard for REST/WebSocket diagnostics
- `strategy/`: replay, walk-forward, and performance validation
- `live_runtime/`: safety-gated broker/runtime components
- `scripts/verify_repository.py`: canonical repository quality entrypoint

## Development checks

Use Python 3.12 and Node.js 24. Install test dependencies in an isolated
environment, then run the relevant focused gate:

```bash
python -m pip install --no-input -r requirements-test.txt
python scripts/verify_repository.py repository-validation
python scripts/verify_repository.py root-tests
python scripts/verify_repository.py backend-quality
python scripts/verify_repository.py dashboard-api
python scripts/verify_repository.py frontend
```

The weekly one-year workflow is a deterministic, Yahoo Finance based paper
backtest. It does not evaluate historical OpenAI/news performance because the
repository does not yet contain a complete point-in-time news archive.

## Local dashboard

Start the canonical backend on loopback port 8000 and the Vite frontend on
loopback port 5173. The dashboard intentionally rejects non-loopback API and
WebSocket origins.

See `backend/README.md`, `frontend-dashboard/README.md`, and
`docs/CORE_SAFETY_RUNBOOK.md` for component-specific instructions.

## Security and licensing

Report vulnerabilities according to `SECURITY.md`. Do not include credentials,
account identifiers, or private broker evidence in public reports.

This repository does not currently declare a project license. Third-party
attribution in `THIRD_PARTY_NOTICES.md` does not grant a license to this project.
