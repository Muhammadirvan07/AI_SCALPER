from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import subprocess
import sys

import pytest

from dashboard_api.app.config import DashboardNetworkBoundaryError
from dashboard_api import run_dashboard_api


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_runner_can_be_invoked_as_a_direct_script_from_a_foreign_cwd(
    tmp_path: Path,
) -> None:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["AI_SCALPER_API_HOST"] = "0.0.0.0"

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            str(PROJECT_ROOT / "dashboard_api" / "run_dashboard_api.py"),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "ModuleNotFoundError" not in result.stderr
    assert "dashboard API host must remain loopback-only" in result.stderr


def test_runner_validates_boundary_before_uvicorn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        run_dashboard_api,
        "settings",
        replace(run_dashboard_api.settings, host="0.0.0.0"),
    )

    def forbidden_run(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("uvicorn.run must not be reached")

    monkeypatch.setattr(run_dashboard_api.uvicorn, "run", forbidden_run)
    with pytest.raises(DashboardNetworkBoundaryError):
        run_dashboard_api.main()


def test_runner_passes_validated_loopback_settings_to_uvicorn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        run_dashboard_api,
        "settings",
        replace(
            run_dashboard_api.settings,
            host="127.0.0.1",
            port=8000,
            cors_origins=("http://localhost:5173",),
        ),
    )

    def record_run(app: str, **kwargs: object) -> None:
        observed["app"] = app
        observed.update(kwargs)

    monkeypatch.setattr(run_dashboard_api.uvicorn, "run", record_run)
    run_dashboard_api.main()
    assert observed == {
        "app": "dashboard_api.app.main:app",
        "host": "127.0.0.1",
        "port": 8000,
        "reload": False,
    }
