# Reproducible Development Environment

## Purpose and safety boundary

All acceptance work must start from a newly created environment. Existing repository-local environments are convenience caches only and must never be used as release evidence. Every command below remains read-only/paper: `LIVE_ALLOWED=false`, `live_allowed=false`, `AI_SCALPER_ORDER_CAPABILITY=DISABLED`, and maximum lot `0.01`.

The repository currently contains three ignored, untracked environments:

| Directory | Observed size on 2026-07-31 | Status |
|---|---:|---|
| `.venv/` | 561 MiB | stale/non-acceptance |
| `.venv-dashboard/` | 305 MiB | stale/non-acceptance; previously contained undeclared `orjson` |
| `venv/` | 224 MiB | stale/non-acceptance |

They are intentionally preserved. Remove them only through a separate, explicit owner-approved cleanup after the commands below reproduce the required environment.

## Toolchain

- CPython 3.12 is the canonical Python version.
- Node.js 24 is the CI version. Node.js 26.4.0 was also exercised locally on 2026-07-31.
- npm must use the committed `frontend-dashboard/package-lock.json` through `npm ci`.
- Set `PYTHONNOUSERSITE=1`; never inherit global/user site packages.
- Create acceptance environments outside the repository, or use one of the ignored environment names.

## Root test environment

`requirements-test.txt` is the root test entrypoint. It installs the root runtime requirements, the backend as editable with its exact dev dependencies, and the dashboard API requirements.

```bash
python3.12 -m venv /tmp/ai_scalper_root_clean
PYTHONNOUSERSITE=1 /tmp/ai_scalper_root_clean/bin/python -m pip install --no-input -r requirements-test.txt
PYTHONNOUSERSITE=1 /tmp/ai_scalper_root_clean/bin/python -m pip check
PYTHONNOUSERSITE=1 /tmp/ai_scalper_root_clean/bin/python scripts/verify_repository.py root-tests
```

The root gate intentionally excludes `backend/tests` and `dashboard_api/tests`; those suites have independent pytest configuration and dedicated gates. This also prevents duplicate test module basenames from colliding in one interpreter.

## Backend environment

`backend/pyproject.toml` is authoritative. `backend/requirements.txt` is an exact mirror of its runtime and `dev` groups, enforced by `repository-validation`.

```bash
python3.12 -m venv /tmp/ai_scalper_backend_clean
PYTHONNOUSERSITE=1 /tmp/ai_scalper_backend_clean/bin/python -m pip install --no-input -e './backend[dev]'
PYTHONNOUSERSITE=1 /tmp/ai_scalper_backend_clean/bin/python -m pip check
PYTHONNOUSERSITE=1 /tmp/ai_scalper_backend_clean/bin/python scripts/verify_repository.py backend-quality
```

## Dashboard API environment

```bash
python3.12 -m venv /tmp/ai_scalper_dashboard_clean
PYTHONNOUSERSITE=1 /tmp/ai_scalper_dashboard_clean/bin/python -m pip install --no-input -r dashboard_api/requirements.txt
PYTHONNOUSERSITE=1 /tmp/ai_scalper_dashboard_clean/bin/python -m pip check
PYTHONNOUSERSITE=1 /tmp/ai_scalper_dashboard_clean/bin/python scripts/verify_repository.py dashboard-api
```

`orjson` is not declared and must not appear in this clean environment. Its presence indicates environment drift.

## Frontend environment

```bash
cd frontend-dashboard
npm ci
cd ..
python3 scripts/verify_repository.py frontend
```

The canonical frontend gate runs unit tests, lint, typecheck, build, bundle budget, Playwright E2E, and `npm audit --audit-level=high`.

## Dependency and attribution audit

Use an isolated audit environment so audit tooling does not contaminate an acceptance environment:

```bash
python3.12 -m venv /tmp/ai_scalper_audit
/tmp/ai_scalper_audit/bin/python -m pip install --no-input pip-audit==2.10.1
/tmp/ai_scalper_audit/bin/python -m pip_audit --strict -r requirements.txt
/tmp/ai_scalper_audit/bin/python -m pip_audit --strict -r backend/requirements.txt
/tmp/ai_scalper_audit/bin/python -m pip_audit --strict -r dashboard_api/requirements.txt
cd frontend-dashboard && npm audit --audit-level=high && cd ..
python3 scripts/generate_third_party_notices.py --python /tmp/ai_scalper_root_clean/bin/python
python3 scripts/generate_third_party_notices.py --python /tmp/ai_scalper_root_clean/bin/python --check
```

`THIRD_PARTY_NOTICES.md` copies upstream metadata; it is not a license opinion. The repository still has no project `LICENSE`, which remains an explicit owner decision.

## Canonical gates

```bash
python3 scripts/verify_repository.py repository-validation
python3 scripts/verify_repository.py root-tests
python3 scripts/verify_repository.py backend-quality
python3 scripts/verify_repository.py dashboard-api
python3 scripts/verify_repository.py frontend
python3 scripts/verify_repository.py security-regressions
python3 scripts/verify_repository.py release
```

The release gate requires a clean, committed Git tree. A dirty working tree is not valid release evidence.
