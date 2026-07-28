from __future__ import annotations

from importlib.metadata import version
from pathlib import Path


REQUIREMENTS = Path(__file__).resolve().parents[1] / "requirements.txt"
EXPECTED_PINS = {
    "fastapi": "0.140.7",
    "starlette": "1.3.1",
    "httpx": "0.28.1",
    "httpx2": "2.9.1",
    "pydantic": "2.11.7",
    "pytest": "9.0.3",
    "python-dotenv": "1.2.2",
    "uvicorn": "0.35.0",
    "websockets": "15.0.1",
}


def _pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw_line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        assert line.count("==") == 1, f"dependency is not exact-pinned: {line}"
        name, pinned_version = line.split("==", 1)
        normalized = name.strip().casefold()
        assert normalized and normalized not in pins
        assert pinned_version.strip()
        pins[normalized] = pinned_version.strip()
    return pins


def test_dashboard_dependency_manifest_is_the_reviewed_exact_set() -> None:
    assert _pins() == EXPECTED_PINS


def test_dashboard_test_environment_matches_every_direct_pin() -> None:
    for distribution, expected in EXPECTED_PINS.items():
        assert version(distribution) == expected
