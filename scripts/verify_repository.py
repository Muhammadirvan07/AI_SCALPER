#!/usr/bin/env python3
"""Canonical local/CI entrypoint for AI_SCALPER quality gates."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend-dashboard"


class VerificationError(RuntimeError):
    """A canonical repository gate failed."""


def run(*command: str, cwd: Path = ROOT, python_optimized: bool = False) -> None:
    argv = list(command)
    if python_optimized:
        argv = [sys.executable, "-O", *argv]
    print(f"+ ({cwd}) {' '.join(argv)}", flush=True)
    completed = subprocess.run(argv, cwd=cwd, check=False)
    if completed.returncode != 0:
        raise VerificationError(
            f"command failed with exit code {completed.returncode}: {' '.join(argv)}"
        )


def capture(*command: str, cwd: Path = ROOT) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise VerificationError(
            f"command failed with exit code {completed.returncode}: {' '.join(command)}"
        )
    return completed.stdout.strip()


def tracked_files() -> list[Path]:
    raw = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    return sorted({ROOT / item.decode("utf-8") for item in raw.split(b"\0") if item})


def _manifest_groups() -> tuple[set[str], set[str]]:
    payload = tomllib.loads((BACKEND / "pyproject.toml").read_text(encoding="utf-8"))
    project = payload["project"]
    runtime = set(project["dependencies"])
    development = set(project["optional-dependencies"]["dev"])
    return runtime, development


def verify_backend_manifest_sync() -> None:
    runtime, development = _manifest_groups()
    requirements = {
        line.strip()
        for line in (BACKEND / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    expected = runtime | development
    if requirements != expected:
        missing = sorted(expected - requirements)
        extra = sorted(requirements - expected)
        raise VerificationError(
            f"backend manifests differ; missing={missing!r}, extra={extra!r}"
        )


def repository_validation() -> None:
    counts = {"python": 0, "json": 0, "toml": 0}
    for path in tracked_files():
        if path.suffix == ".py":
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            counts["python"] += 1
        elif path.suffix == ".json":
            json.loads(path.read_text(encoding="utf-8"))
            counts["json"] += 1
        elif path.suffix == ".toml":
            tomllib.loads(path.read_text(encoding="utf-8"))
            counts["toml"] += 1
    verify_backend_manifest_sync()
    providers = (
        BACKEND / "app/providers/news/investing_rss.py",
        BACKEND / "app/providers/news/official_rss.py",
        BACKEND / "app/providers/news/rss_provider.py",
    )
    for provider in providers:
        source = provider.read_text(encoding="utf-8")
        if "parse_untrusted_xml" not in source or "ElementTree.fromstring" in source:
            raise VerificationError(f"unsafe external XML parser boundary: {provider}")
    updater = (ROOT / "market_data_updater.py").read_text(encoding="utf-8")
    if "/tmp/ai_scalper_market_data_updater.lock" in updater or '.open("a+"' in updater:
        raise VerificationError("unsafe market updater lock pattern reintroduced")
    run("git", "diff", "--check")
    run(sys.executable, "scripts/verify_safety_contract.py")
    run("scripts/verify_safety_contract.py", python_optimized=True)
    print(f"REPOSITORY_VALIDATION_PASS {json.dumps(counts, sort_keys=True)}")


def root_tests() -> None:
    # Backend and dashboard suites have independent pytest configuration and
    # quality jobs.  Keeping them out of this process also avoids duplicate
    # test-module basenames being imported into the same interpreter.
    root_pytest = (
        "-m",
        "pytest",
        "-q",
        "--ignore=backend/tests",
        "--ignore=dashboard_api/tests",
    )
    run(sys.executable, *root_pytest)
    run(*root_pytest, python_optimized=True)


def backend_quality() -> None:
    run(sys.executable, "-m", "pip", "check", cwd=BACKEND)
    run(sys.executable, "-m", "ruff", "check", ".", cwd=BACKEND)
    run(sys.executable, "-m", "ruff", "format", "--check", ".", cwd=BACKEND)
    run(sys.executable, "-m", "mypy", "app", cwd=BACKEND)
    run(
        sys.executable,
        "-m",
        "pytest",
        "--cov=app",
        "--cov-report=term-missing",
        "--cov-fail-under=90",
        cwd=BACKEND,
    )


def dashboard_api_tests() -> None:
    run(sys.executable, "-m", "pip", "check")
    run(sys.executable, "-m", "pytest", "-q", "dashboard_api/tests")


def frontend_quality() -> None:
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    if npm is None:
        raise VerificationError("npm is required for the frontend gate")
    commands = [
        (npm, "run", "test:unit"),
        (npm, "run", "lint"),
        (npm, "run", "typecheck"),
        (npm, "run", "build"),
        (npm, "run", "check:bundle"),
        (npm, "run", "test:e2e"),
        (npm, "audit", "--audit-level=high"),
    ]
    if os.environ.get("AI_SCALPER_FRONTEND_DEPS_PREINSTALLED") != "1":
        commands.insert(0, (npm, "ci"))
    for command in commands:
        run(*command, cwd=FRONTEND)


def _digest_tree(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def release_verifier() -> None:
    head = capture("git", "rev-parse", "HEAD")
    tree = capture("git", "rev-parse", "HEAD^{tree}")
    with tempfile.TemporaryDirectory(prefix="ai-scalper-release-gate-") as temporary:
        # macOS exposes its temporary directory through /var -> /private/var.
        # The release builder deliberately rejects non-canonical parents, so
        # normalize the trusted directory before constructing destinations.
        parent = Path(temporary).resolve(strict=True)
        first = parent / "suite-a"
        second = parent / "suite-b"
        run(sys.executable, "-B", "build_windows_base_release_suite.py", "--output-root", str(first))
        run(sys.executable, "-B", "build_windows_base_release_suite.py", "--output-root", str(second))
        first_digests = _digest_tree(first)
        second_digests = _digest_tree(second)
        if first_digests != second_digests:
            raise VerificationError("base release suite is not byte-for-byte reproducible")
        manifest = json.loads((first / "BASE_RELEASE_SUITE.json").read_text(encoding="utf-8"))
        identity = str(manifest["suite_identity_sha256"])
        for suite in (first, second):
            run(
                sys.executable,
                "-B",
                "verify_windows_base_release_suite.py",
                "--suite-root",
                str(suite),
                "--expected-suite-identity-sha256",
                identity,
                "--expected-git-commit",
                head,
                "--expected-git-tree",
                tree,
            )
        print(f"RELEASE_REPRODUCIBILITY_PASS suite_identity_sha256={identity}")


def security_regressions() -> None:
    run(
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "tests/unit/test_safe_xml.py",
        "tests/unit/test_investing_rss.py",
        cwd=BACKEND,
    )
    run(
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "dashboard_api/tests/test_market_data_updater.py",
        cwd=ROOT,
    )
    run(sys.executable, "scripts/verify_safety_contract.py")
    run("scripts/verify_safety_contract.py", python_optimized=True)


GATES = {
    "repository-validation": repository_validation,
    "root-tests": root_tests,
    "backend-quality": backend_quality,
    "dashboard-api": dashboard_api_tests,
    "frontend": frontend_quality,
    "release": release_verifier,
    "security-regressions": security_regressions,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gate", choices=sorted(GATES))
    args = parser.parse_args()
    GATES[args.gate]()
    print(f"QUALITY_GATE_PASS: {args.gate}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, VerificationError, subprocess.SubprocessError) as exc:
        print(f"QUALITY_GATE_FAIL: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
