"""Fail-closed validation for the Windows CPython 3.12 dependency lock."""

from __future__ import annotations

import base64
import csv
import hashlib
from importlib import metadata
import io
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform
import re
import stat
import struct
import sys
import tomllib
from typing import Any, Mapping
import unicodedata
from urllib.parse import quote, urlparse


LOCK_FILE_NAME = "pylock.windows-cp312.toml"
TA_VENDOR_WHEEL = "vendor/wheels/ta-0.11.0-py3-none-any.whl"
PIP_VENDOR_WHEEL = "vendor/wheels/pip-26.1.2-py3-none-any.whl"
INSTALL_MANIFEST = "vendor/windows-cp312-install-manifest.json"
DEPENDENCY_SBOM = "vendor/windows-cp312-dependency-sbom.cdx.json"
BOOTSTRAP_REQUIREMENTS_FILE = "requirements-windows-bootstrap.lock.txt"
RUNTIME_REQUIREMENTS_FILE = "requirements-windows-cp312.lock.txt"
INSTALL_MANIFEST_SCHEMA_VERSION = "windows-wheel-tree-v1"
DEPENDENCY_SBOM_SPEC_VERSION = "1.6"
TA_VENDOR_WHEEL_SHA256 = (
    "acd933756f0badbe6b1cc28d5db42dc0d9b0ac5877956f5cf8f304ece3f50b0d"
)
PIP_VENDOR_WHEEL_SHA256 = (
    "382ff9f685ee3bc25864f820aa50505825f10f5458ffff07e30a6d96e5715cab"
)
LOCK_VERSION = "1.0"
TARGET_PYTHON = "3.12"
TARGET_IMPLEMENTATION = "CPython"
TARGET_PLATFORM = "win_amd64"
TARGET_ARCHITECTURE = "x86_64"
LIVE_REQUIREMENTS_FILE = "requirements-live-windows.txt"
SOURCE_MANIFESTS = (LIVE_REQUIREMENTS_FILE,)
DIRECT_REQUIREMENTS = {
    "keyring": "25.7.0",
    "metatrader5": "5.0.5735",
    "numpy": "2.5.1",
    "pandas": "2.3.3",
    "ta": "0.11.0",
}
EXPECTED_LOCKED_PACKAGES = frozenset(
    {
        "jaraco-classes",
        "jaraco-context",
        "jaraco-functools",
        "keyring",
        "metatrader5",
        "more-itertools",
        "numpy",
        "pandas",
        "python-dateutil",
        "pytz",
        "pywin32-ctypes",
        "six",
        "ta",
        "tzdata",
    }
)
BOOTSTRAP_REQUIREMENTS = {
    "pip": "26.1.2",
}
MT5_WHEEL_URL = (
    "https://files.pythonhosted.org/packages/d9/db/"
    "42dc3437c7371492262b0642c64c7b5f67c396bbcb8101ccf182981b67b3/"
    "metatrader5-5.0.5735-cp312-cp312-win_amd64.whl"
)
MT5_WHEEL_SHA256 = "f6e8584e48f2c3f5de818f17ee65f0f5adfa1e4af29cd5f4bf3f72b91ff06e10"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_NORMALIZE_NAME_RE = re.compile(r"[-_.]+")
_ALLOWED_GENERATED_METADATA = frozenset({"INSTALLER", "REQUESTED"})
_FORBIDDEN_DIST_INFO_METADATA = frozenset(
    {
        "direct_url.json",
        "origin.json",
        "RECORD.jws",
        "RECORD.p7s",
    }
)
_FORBIDDEN_SITE_NAMES = frozenset({"sitecustomize.py", "usercustomize.py"})
_FORBIDDEN_SITE_SUFFIXES = frozenset({".pyc", ".pyo", ".pth"})
_MANIFEST_TARGET = {
    "python": TARGET_PYTHON,
    "implementation": TARGET_IMPLEMENTATION,
    "platform": TARGET_PLATFORM,
    "architecture": TARGET_ARCHITECTURE,
}


class DependencyLockError(RuntimeError):
    """Raised when the release lock or target runtime does not match policy."""


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError as exc:
        raise DependencyLockError(f"filesystem entry is unavailable: {path.name}") from exc
    return path.is_symlink() or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _normalized_name(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DependencyLockError("dependency package name is missing")
    return _NORMALIZE_NAME_RE.sub("-", value.strip().lower())


def _read_lock(path: Path) -> tuple[dict[str, object], bytes]:
    if not path.is_file() or path.is_symlink():
        raise DependencyLockError(f"dependency lock is unavailable: {path}")
    try:
        raw = path.read_bytes()
        payload = tomllib.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise DependencyLockError(f"dependency lock is invalid TOML: {path}") from exc
    if not isinstance(payload, dict):
        raise DependencyLockError("dependency lock root must be a TOML table")
    return payload, raw


def _intent_table(payload: Mapping[str, object]) -> Mapping[str, object]:
    tool = payload.get("tool")
    if not isinstance(tool, Mapping):
        raise DependencyLockError("dependency lock target metadata is missing")
    intent = tool.get("ai_scalper")
    if not isinstance(intent, Mapping):
        raise DependencyLockError("AI_SCALPER dependency target metadata is missing")
    return intent


def _require_target_intent(payload: Mapping[str, object]) -> None:
    if payload.get("lock-version") != LOCK_VERSION:
        raise DependencyLockError("unsupported dependency lock version")
    if payload.get("requires-python") != ">=3.12":
        raise DependencyLockError("dependency lock Python range drift")
    intent = _intent_table(payload)
    expected = {
        "target-python": TARGET_PYTHON,
        "target-implementation": TARGET_IMPLEMENTATION,
        "target-platform": TARGET_PLATFORM,
        "target-architecture": TARGET_ARCHITECTURE,
    }
    for field, value in expected.items():
        if intent.get(field) != value:
            raise DependencyLockError(f"dependency lock target drift: {field}")
    manifests = intent.get("source-manifests")
    if not isinstance(manifests, list) or tuple(manifests) != SOURCE_MANIFESTS:
        raise DependencyLockError("dependency lock source manifest drift")


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DependencyLockError(f"install manifest duplicate field: {key}")
        result[key] = value
    return result


def _strict_sbom_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DependencyLockError(f"dependency SBOM duplicate field: {key}")
        result[key] = value
    return result


def _content_addressed_local_file(
    entry: object,
    *,
    lock_directory: Path,
    expected_path: str,
    label: str,
) -> tuple[Path, bytes, str]:
    if not isinstance(entry, Mapping) or set(entry) != {"path", "size", "hashes"}:
        raise DependencyLockError(f"{label} binding is invalid")
    relative = entry.get("path")
    if relative != expected_path:
        raise DependencyLockError(f"{label} path drift")
    path_value = Path(str(relative))
    if path_value.is_absolute() or ".." in path_value.parts:
        raise DependencyLockError(f"{label} path is invalid")
    path = lock_directory / path_value
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(lock_directory.resolve(strict=True))
    except (OSError, RuntimeError, ValueError) as exc:
        raise DependencyLockError(f"{label} is unavailable") from exc
    if path.is_symlink() or not resolved.is_file():
        raise DependencyLockError(f"{label} is unavailable")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise DependencyLockError(f"{label} is unreadable") from exc
    size = entry.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise DependencyLockError(f"{label} size is invalid")
    if len(raw) != size:
        raise DependencyLockError(f"{label} size drift")
    hashes = entry.get("hashes")
    sha256 = hashes.get("sha256") if isinstance(hashes, Mapping) else None
    if not isinstance(sha256, str) or not _SHA256_RE.fullmatch(sha256):
        raise DependencyLockError(f"{label} SHA-256 is invalid")
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != sha256:
        raise DependencyLockError(f"{label} SHA-256 drift")
    return resolved, raw, actual_sha256


def _validate_artifact(
    package_name: str,
    artifact: object,
    *,
    lock_directory: Path,
) -> None:
    if not isinstance(artifact, Mapping):
        raise DependencyLockError(f"invalid artifact entry: {package_name}")
    url = artifact.get("url")
    relative_path = artifact.get("path")
    if (url is None) == (relative_path is None):
        raise DependencyLockError(
            f"artifact must bind exactly one URL or local path: {package_name}"
        )
    local_file: Path | None = None
    if url is not None:
        if not isinstance(url, str):
            raise DependencyLockError(f"artifact URL is invalid: {package_name}")
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname != "files.pythonhosted.org":
            raise DependencyLockError(f"unapproved artifact origin: {package_name}")
    else:
        approved_local_artifacts = {
            "ta": TA_VENDOR_WHEEL,
            "pip": PIP_VENDOR_WHEEL,
        }
        if relative_path != approved_local_artifacts.get(package_name):
            raise DependencyLockError(f"unapproved local artifact: {package_name}")
        local_file = lock_directory / str(relative_path)
        if (
            local_file.is_symlink()
            or not local_file.is_file()
            or ".." in Path(str(relative_path)).parts
            or Path(str(relative_path)).is_absolute()
        ):
            raise DependencyLockError(f"local artifact is unavailable: {package_name}")
        try:
            local_file.resolve().relative_to(lock_directory.resolve())
        except ValueError as exc:
            raise DependencyLockError(
                f"local artifact escaped lock directory: {package_name}"
            ) from exc
    hashes = artifact.get("hashes")
    if not isinstance(hashes, Mapping):
        raise DependencyLockError(f"artifact hashes are missing: {package_name}")
    sha256 = hashes.get("sha256")
    if not isinstance(sha256, str) or not _SHA256_RE.fullmatch(sha256):
        raise DependencyLockError(f"artifact SHA-256 is invalid: {package_name}")
    size = artifact.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise DependencyLockError(f"artifact size is invalid: {package_name}")
    if local_file is not None:
        raw = local_file.read_bytes()
        if len(raw) != size:
            raise DependencyLockError(f"local artifact size drift: {package_name}")
        if hashlib.sha256(raw).hexdigest() != hashes["sha256"]:
            raise DependencyLockError(f"local artifact SHA-256 drift: {package_name}")


def _package_map(
    payload: Mapping[str, object],
    *,
    lock_directory: Path,
) -> dict[str, Mapping[str, object]]:
    packages = payload.get("packages")
    if not isinstance(packages, list) or not packages:
        raise DependencyLockError("dependency lock package set is empty")
    result: dict[str, Mapping[str, object]] = {}
    for package in packages:
        if not isinstance(package, Mapping):
            raise DependencyLockError("dependency package entry is invalid")
        name = _normalized_name(package.get("name"))
        if name in result:
            raise DependencyLockError(f"duplicate dependency package: {name}")
        version = package.get("version")
        if not isinstance(version, str) or not version:
            raise DependencyLockError(f"dependency version is missing: {name}")
        artifacts: list[object] = []
        if "sdist" in package:
            artifacts.append(package["sdist"])
        wheels = package.get("wheels", [])
        if not isinstance(wheels, list):
            raise DependencyLockError(f"dependency wheel list is invalid: {name}")
        if not wheels:
            raise DependencyLockError(
                f"release dependency has no locked wheel: {name}"
            )
        artifacts.extend(wheels)
        for artifact in artifacts:
            _validate_artifact(
                name,
                artifact,
                lock_directory=lock_directory,
            )
        result[name] = package
    return result


def _bootstrap_package_map(
    payload: Mapping[str, object],
    *,
    lock_directory: Path,
) -> dict[str, Mapping[str, object]]:
    bootstrap = _intent_table(payload).get("bootstrap-wheels")
    if not isinstance(bootstrap, list) or not bootstrap:
        raise DependencyLockError("dependency bootstrap wheel set is missing")
    result: dict[str, Mapping[str, object]] = {}
    for entry in bootstrap:
        if not isinstance(entry, Mapping):
            raise DependencyLockError("dependency bootstrap wheel entry is invalid")
        name = _normalized_name(entry.get("name"))
        if name in result:
            raise DependencyLockError(f"duplicate bootstrap dependency: {name}")
        version = entry.get("version")
        if not isinstance(version, str) or not version:
            raise DependencyLockError(
                f"bootstrap dependency version is missing: {name}"
            )
        _validate_artifact(name, entry, lock_directory=lock_directory)
        result[name] = entry
    actual = {
        name: str(entry["version"])
        for name, entry in result.items()
    }
    if actual != BOOTSTRAP_REQUIREMENTS:
        raise DependencyLockError("dependency bootstrap pin drift")
    pip_entry = result["pip"]
    pip_hashes = pip_entry.get("hashes")
    if (
        pip_entry.get("path") != PIP_VENDOR_WHEEL
        or not isinstance(pip_hashes, Mapping)
        or pip_hashes.get("sha256") != PIP_VENDOR_WHEEL_SHA256
    ):
        raise DependencyLockError("pip bootstrap wheel drift")
    return result


def _artifact_filename(artifact: Mapping[str, object]) -> str:
    location = artifact.get("url", artifact.get("path"))
    if not isinstance(location, str):
        raise DependencyLockError("locked wheel location is invalid")
    filename = PurePosixPath(urlparse(location).path).name
    if not filename.endswith(".whl"):
        raise DependencyLockError("locked artifact is not a wheel")
    return filename


def _artifact_binding(artifact: Mapping[str, object]) -> tuple[str, int, str]:
    size = artifact.get("size")
    hashes = artifact.get("hashes")
    sha256 = hashes.get("sha256") if isinstance(hashes, Mapping) else None
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or not isinstance(sha256, str)
    ):
        raise DependencyLockError("locked wheel binding is invalid")
    return _artifact_filename(artifact), size, sha256


def _target_wheel_priority(filename: str) -> tuple[int, str]:
    """Return the deterministic compatibility order for the release target."""

    lower = filename.casefold()
    if lower.endswith("-cp312-cp312-win_amd64.whl"):
        return (0, lower)
    if "-abi3-win_amd64.whl" in lower:
        return (1, lower)
    if lower.endswith(("-py3-none-any.whl", "-py2.py3-none-any.whl")):
        return (2, lower)
    return (100, lower)


def _select_target_wheel(
    package_name: str,
    wheels: object,
) -> Mapping[str, object]:
    if not isinstance(wheels, list) or not wheels:
        raise DependencyLockError(
            f"release dependency has no locked wheel: {package_name}"
        )
    candidates = [
        wheel
        for wheel in wheels
        if isinstance(wheel, Mapping)
        and _target_wheel_priority(_artifact_filename(wheel))[0] < 100
    ]
    if not candidates:
        raise DependencyLockError(
            f"release dependency has no compatible target wheel: {package_name}"
        )
    return min(
        candidates,
        key=lambda wheel: _target_wheel_priority(_artifact_filename(wheel)),
    )


def _safe_manifest_site_path(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise DependencyLockError(f"install manifest path is invalid: {field}")
    path = PurePosixPath(value)
    if (
        not value
        or "\x00" in value
        or "\\" in value
        or ":" in value
        or value.endswith("/")
        or value.startswith("./")
        or "/./" in value
        or "//" in value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise DependencyLockError(f"install manifest path is invalid: {field}")
    for part in path.parts:
        if part.endswith((" ", ".")):
            raise DependencyLockError(f"install manifest path is invalid: {field}")
        stem = part.split(".", 1)[0].upper()
        if stem in {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            *(f"COM{index}" for index in range(1, 10)),
            *(f"LPT{index}" for index in range(1, 10)),
        }:
            raise DependencyLockError(f"install manifest path is invalid: {field}")
    return path.as_posix()


def _validate_manifest_package_entry(
    name: str,
    entry: object,
    *,
    expected_version: str,
    expected_artifact: Mapping[str, object],
) -> Mapping[str, object]:
    expected_fields = {
        "name",
        "version",
        "wheel_filename",
        "wheel_size",
        "wheel_sha256",
        "record_path",
        "wheel_record_sha256",
        "site_packages_file_count",
        "site_packages_tree_sha256",
        "console_scripts",
    }
    if not isinstance(entry, Mapping) or set(entry) != expected_fields:
        raise DependencyLockError(f"install manifest package entry is invalid: {name}")
    if entry.get("name") != name or entry.get("version") != expected_version:
        raise DependencyLockError(f"install manifest package identity drift: {name}")
    binding = (
        entry.get("wheel_filename"),
        entry.get("wheel_size"),
        entry.get("wheel_sha256"),
    )
    if binding != _artifact_binding(expected_artifact):
        raise DependencyLockError(f"install manifest wheel binding drift: {name}")
    for field in ("wheel_sha256", "wheel_record_sha256", "site_packages_tree_sha256"):
        value = entry.get(field)
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise DependencyLockError(
                f"install manifest digest is invalid: {name}:{field}"
            )
    count = entry.get("site_packages_file_count")
    if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
        raise DependencyLockError(
            f"install manifest file count is invalid: {name}"
        )
    record_path = _safe_manifest_site_path(
        entry.get("record_path"),
        field=f"{name}:record_path",
    )
    record = PurePosixPath(record_path)
    if record.name != "RECORD" or not record.parent.name.endswith(".dist-info"):
        raise DependencyLockError(f"install manifest RECORD path is invalid: {name}")
    scripts = entry.get("console_scripts")
    if not isinstance(scripts, list) or scripts != sorted(set(scripts)):
        raise DependencyLockError(f"install manifest console scripts are invalid: {name}")
    for script in scripts:
        if (
            not isinstance(script, str)
            or not script
            or script.endswith((" ", "."))
            or any(character in script for character in "/\\:\x00")
        ):
            raise DependencyLockError(
                f"install manifest console script is invalid: {name}"
            )
    return entry


def _load_install_manifest(
    lock_path: Path,
    payload: Mapping[str, object],
    packages: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    manifest_path, raw, manifest_sha256 = _content_addressed_local_file(
        _intent_table(payload).get("install-manifest"),
        lock_directory=lock_path.parent,
        expected_path=INSTALL_MANIFEST,
        label="install manifest",
    )
    try:
        manifest = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DependencyLockError("install manifest JSON is invalid") from exc
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version",
        "target",
        "packages",
        "payload_sha256",
    }:
        raise DependencyLockError("install manifest root is invalid")
    if manifest.get("schema_version") != INSTALL_MANIFEST_SCHEMA_VERSION:
        raise DependencyLockError("install manifest schema drift")
    if manifest.get("target") != _MANIFEST_TARGET:
        raise DependencyLockError("install manifest target drift")
    body = {
        key: value
        for key, value in manifest.items()
        if key != "payload_sha256"
    }
    if manifest.get("payload_sha256") != _canonical_sha256(body):
        raise DependencyLockError("install manifest payload SHA-256 mismatch")

    bootstrap = _bootstrap_package_map(
        payload,
        lock_directory=lock_path.parent,
    )
    manifest_packages = manifest.get("packages")
    if not isinstance(manifest_packages, dict):
        raise DependencyLockError("install manifest package set is invalid")
    expected_names = set(packages) | set(bootstrap)
    if set(manifest_packages) != expected_names:
        raise DependencyLockError("install manifest package set drift")
    validated: dict[str, Mapping[str, object]] = {}
    for name in sorted(expected_names):
        if name in packages:
            package = packages[name]
            expected_artifact = _select_target_wheel(
                name,
                package.get("wheels"),
            )
            version = str(package["version"])
        else:
            expected_artifact = bootstrap[name]
            version = str(bootstrap[name]["version"])
        validated[name] = _validate_manifest_package_entry(
            name,
            manifest_packages[name],
            expected_version=version,
            expected_artifact=expected_artifact,
        )
    return {
        **manifest,
        "packages": validated,
        "manifest_file": str(manifest_path),
        "manifest_sha256": manifest_sha256,
    }


def _dependency_purl(name: str, version: str) -> str:
    return (
        "pkg:pypi/"
        + quote(name, safe="-._~")
        + "@"
        + quote(version, safe="-._~")
    )


def _expected_dependency_sbom(
    manifest: Mapping[str, object],
) -> dict[str, object]:
    packages = manifest.get("packages")
    if not isinstance(packages, Mapping) or "pip" not in packages:
        raise DependencyLockError("install manifest package set is invalid")
    components: list[dict[str, object]] = []
    for name in sorted(packages):
        entry = packages[name]
        if not isinstance(name, str) or not isinstance(entry, Mapping):
            raise DependencyLockError("install manifest package set is invalid")
        version = entry.get("version")
        filename = entry.get("wheel_filename")
        wheel_size = entry.get("wheel_size")
        wheel_sha256 = entry.get("wheel_sha256")
        if (
            not isinstance(version, str)
            or not isinstance(filename, str)
            or not isinstance(wheel_size, int)
            or isinstance(wheel_size, bool)
            or not isinstance(wheel_sha256, str)
            or not _SHA256_RE.fullmatch(wheel_sha256)
        ):
            raise DependencyLockError(
                f"install manifest wheel binding is invalid: {name}"
            )
        purl = _dependency_purl(name, version)
        components.append(
            {
                "bom-ref": purl,
                "hashes": [{"alg": "SHA-256", "content": wheel_sha256}],
                "name": name,
                "properties": [
                    {
                        "name": "ai_scalper:dependency-role",
                        "value": "bootstrap" if name == "pip" else "runtime",
                    },
                    {
                        "name": "ai_scalper:wheel-filename",
                        "value": filename,
                    },
                    {
                        "name": "ai_scalper:wheel-size",
                        "value": str(wheel_size),
                    },
                ],
                "purl": purl,
                "scope": "required",
                "type": "library",
                "version": version,
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "components": components,
        "metadata": {
            "properties": [
                {
                    "name": "ai_scalper:bootstrap-package-count",
                    "value": str(len(BOOTSTRAP_REQUIREMENTS)),
                },
                {
                    "name": "ai_scalper:runtime-package-count",
                    "value": str(len(EXPECTED_LOCKED_PACKAGES)),
                },
                {
                    "name": "ai_scalper:target-architecture",
                    "value": TARGET_ARCHITECTURE,
                },
                {
                    "name": "ai_scalper:target-implementation",
                    "value": TARGET_IMPLEMENTATION,
                },
                {
                    "name": "ai_scalper:target-platform",
                    "value": TARGET_PLATFORM,
                },
                {
                    "name": "ai_scalper:target-python",
                    "value": TARGET_PYTHON,
                },
            ]
        },
        "specVersion": DEPENDENCY_SBOM_SPEC_VERSION,
        "version": 1,
    }


def _canonical_document_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _load_dependency_sbom(
    lock_path: Path,
    payload: Mapping[str, object],
    manifest: Mapping[str, object],
) -> dict[str, object]:
    sbom_path, raw, sbom_sha256 = _content_addressed_local_file(
        _intent_table(payload).get("dependency-sbom"),
        lock_directory=lock_path.parent,
        expected_path=DEPENDENCY_SBOM,
        label="dependency SBOM",
    )
    try:
        sbom = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_sbom_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DependencyLockError("dependency SBOM JSON is invalid") from exc
    expected = _expected_dependency_sbom(manifest)
    if sbom != expected:
        raise DependencyLockError("dependency SBOM semantic drift")
    if raw != _canonical_document_bytes(expected):
        raise DependencyLockError("dependency SBOM canonical encoding drift")
    components = expected["components"]
    if not isinstance(components, list):
        raise DependencyLockError("dependency SBOM component set is invalid")
    return {
        "sbom_file": str(sbom_path),
        "sbom_sha256": sbom_sha256,
        "component_count": len(components),
        "components_sha256": _canonical_sha256(components),
    }


def _expected_hashed_requirements(
    packages: Mapping[str, Mapping[str, object]],
) -> bytes:
    lines = [
        "# Generated from vendor/windows-cp312-install-manifest.json.",
        "# Install only with --no-index, --find-links, --require-hashes, and --no-deps.",
    ]
    for name, entry in sorted(packages.items()):
        lines.append(
            f"{name}=={entry['version']} "
            f"--hash=sha256:{entry['wheel_sha256']}"
        )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _validate_hashed_requirements_files(
    lock_path: Path,
    manifest: Mapping[str, object],
) -> dict[str, str]:
    packages = manifest.get("packages")
    if not isinstance(packages, Mapping) or "pip" not in packages:
        raise DependencyLockError("install manifest package set is invalid")
    groups = {
        BOOTSTRAP_REQUIREMENTS_FILE: {"pip": packages["pip"]},
        RUNTIME_REQUIREMENTS_FILE: {
            name: entry
            for name, entry in packages.items()
            if name != "pip"
        },
    }
    digests: dict[str, str] = {}
    for relative, selected in groups.items():
        path = lock_path.parent / relative
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(lock_path.parent.resolve(strict=True))
        except (OSError, RuntimeError, ValueError) as exc:
            raise DependencyLockError(
                f"hashed requirements file is unavailable: {relative}"
            ) from exc
        if _is_reparse_or_symlink(path) or not resolved.is_file():
            raise DependencyLockError(
                f"hashed requirements file is unavailable: {relative}"
            )
        try:
            raw = resolved.read_bytes()
        except OSError as exc:
            raise DependencyLockError(
                f"hashed requirements file is unreadable: {relative}"
            ) from exc
        if raw != _expected_hashed_requirements(selected):
            raise DependencyLockError(
                f"hashed requirements file drift: {relative}"
            )
        digests[relative] = hashlib.sha256(raw).hexdigest()
    return digests


def _require_direct_versions(packages: Mapping[str, Mapping[str, object]]) -> None:
    for name, version in DIRECT_REQUIREMENTS.items():
        package = packages.get(name)
        if package is None or package.get("version") != version:
            raise DependencyLockError(f"direct dependency pin drift: {name}")


def _require_exact_locked_package_set(
    packages: Mapping[str, Mapping[str, object]],
) -> None:
    actual = frozenset(packages)
    if actual != EXPECTED_LOCKED_PACKAGES:
        missing = sorted(EXPECTED_LOCKED_PACKAGES - actual)
        unexpected = sorted(actual - EXPECTED_LOCKED_PACKAGES)
        raise DependencyLockError(
            "locked dependency set drift: "
            f"missing={missing}, unexpected={unexpected}"
        )


def _require_direct_manifest(lock_directory: Path) -> str:
    path = lock_directory / LIVE_REQUIREMENTS_FILE
    if not path.is_file() or path.is_symlink():
        raise DependencyLockError(
            "live dependency source manifest is unavailable"
        )
    try:
        resolved_root = lock_directory.resolve(strict=True)
        resolved = path.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise DependencyLockError(
            "live dependency source manifest is unavailable"
        ) from exc
    try:
        raw = resolved.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DependencyLockError(
            "live dependency source manifest is invalid"
        ) from exc

    parsed: dict[str, str] = {}
    requirement_re = re.compile(
        r"^([A-Za-z0-9][A-Za-z0-9_.-]*)"
        r"==([A-Za-z0-9][A-Za-z0-9_.+!-]*)$"
    )
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = requirement_re.fullmatch(line)
        if match is None:
            raise DependencyLockError(
                "live dependency source manifest contains a non-exact "
                f"requirement at line {line_number}"
            )
        name = _normalized_name(match.group(1))
        if name in parsed:
            raise DependencyLockError(
                f"live dependency source manifest duplicates package: {name}"
            )
        parsed[name] = match.group(2)
    if parsed != DIRECT_REQUIREMENTS:
        missing = sorted(set(DIRECT_REQUIREMENTS) - set(parsed))
        unexpected = sorted(set(parsed) - set(DIRECT_REQUIREMENTS))
        raise DependencyLockError(
            "live dependency source manifest drift: "
            f"missing={missing}, unexpected={unexpected}"
        )
    return hashlib.sha256(raw).hexdigest()


def _require_mt5_windows_artifact(packages: Mapping[str, Mapping[str, object]]) -> None:
    package = packages["metatrader5"]
    if "sdist" in package:
        raise DependencyLockError("MetaTrader5 must not resolve from source")
    wheels = package.get("wheels")
    if not isinstance(wheels, list) or len(wheels) != 1:
        raise DependencyLockError("MetaTrader5 must bind exactly one Windows wheel")
    wheel = wheels[0]
    if not isinstance(wheel, Mapping):
        raise DependencyLockError("MetaTrader5 wheel entry is invalid")
    if wheel.get("url") != MT5_WHEEL_URL:
        raise DependencyLockError("MetaTrader5 CPython 3.12 win_amd64 wheel drift")
    hashes = wheel.get("hashes")
    if not isinstance(hashes, Mapping) or hashes.get("sha256") != MT5_WHEEL_SHA256:
        raise DependencyLockError("MetaTrader5 wheel SHA-256 drift")


def _require_reproducible_ta_wheel(
    packages: Mapping[str, Mapping[str, object]],
) -> None:
    package = packages["ta"]
    if "sdist" in package:
        raise DependencyLockError("ta must not be built from source on the release host")
    wheels = package.get("wheels")
    if not isinstance(wheels, list) or len(wheels) != 1:
        raise DependencyLockError("ta must bind exactly one reproducible wheel")
    wheel = wheels[0]
    if (
        not isinstance(wheel, Mapping)
        or wheel.get("path") != TA_VENDOR_WHEEL
        or wheel.get("hashes", {}).get("sha256") != TA_VENDOR_WHEEL_SHA256
    ):
        raise DependencyLockError("ta reproducible wheel drift")


def validate_windows_dependency_lock(path: str | Path) -> dict[str, object]:
    """Validate target intent, exact direct pins, and every artifact hash."""

    lock_path = Path(path)
    payload, raw = _read_lock(lock_path)
    _require_target_intent(payload)
    packages = _package_map(payload, lock_directory=lock_path.parent)
    _require_exact_locked_package_set(packages)
    _require_direct_versions(packages)
    source_manifest_sha256 = _require_direct_manifest(lock_path.parent)
    _require_mt5_windows_artifact(packages)
    _require_reproducible_ta_wheel(packages)
    manifest = _load_install_manifest(lock_path, payload, packages)
    dependency_sbom = _load_dependency_sbom(
        lock_path,
        payload,
        manifest,
    )
    requirements_sha256 = _validate_hashed_requirements_files(
        lock_path,
        manifest,
    )
    return {
        "lock_file": lock_path.name,
        "lock_sha256": hashlib.sha256(raw).hexdigest(),
        "package_count": len(packages),
        "target_python": TARGET_PYTHON,
        "target_platform": TARGET_PLATFORM,
        "metatrader5_version": DIRECT_REQUIREMENTS["metatrader5"],
        "metatrader5_wheel_sha256": MT5_WHEEL_SHA256,
        "ta_wheel_sha256": TA_VENDOR_WHEEL_SHA256,
        "pip_wheel_sha256": PIP_VENDOR_WHEEL_SHA256,
        "source_manifest_sha256": source_manifest_sha256,
        "install_manifest_sha256": manifest["manifest_sha256"],
        "dependency_sbom_file": DEPENDENCY_SBOM,
        "dependency_sbom_sha256": dependency_sbom["sbom_sha256"],
        "dependency_sbom_package_count": dependency_sbom["component_count"],
        "dependency_sbom_components_sha256": dependency_sbom[
            "components_sha256"
        ],
        "hashed_requirements_sha256": requirements_sha256,
    }


def validate_release_wheelhouse(
    path: str | Path,
    wheelhouse: str | Path,
) -> dict[str, object]:
    """Verify a flat offline wheelhouse against the selected manifest wheels."""

    lock_path = Path(path)
    lock_receipt = validate_windows_dependency_lock(lock_path)
    payload, _ = _read_lock(lock_path)
    packages = _package_map(payload, lock_directory=lock_path.parent)
    manifest = _load_install_manifest(lock_path, payload, packages)
    manifest_packages = manifest.get("packages")
    if not isinstance(manifest_packages, Mapping):
        raise DependencyLockError("install manifest package set is invalid")

    root = Path(wheelhouse)
    try:
        if not root.is_dir() or _is_reparse_or_symlink(root):
            raise DependencyLockError("release wheelhouse is unavailable")
        resolved_root = root.resolve(strict=True)
    except DependencyLockError:
        raise
    except (OSError, RuntimeError) as exc:
        raise DependencyLockError("release wheelhouse is unavailable") from exc

    expected_by_key: dict[str, tuple[str, Mapping[str, object]]] = {}
    for name, entry in sorted(manifest_packages.items()):
        if not isinstance(entry, Mapping):
            raise DependencyLockError(
                f"install manifest package entry is invalid: {name}"
            )
        filename = entry.get("wheel_filename")
        if not isinstance(filename, str):
            raise DependencyLockError(
                f"install manifest wheel filename is invalid: {name}"
            )
        safe_filename = _safe_manifest_site_path(
            filename,
            field=f"{name}:wheel_filename",
        )
        if "/" in safe_filename or not safe_filename.casefold().endswith(".whl"):
            raise DependencyLockError(
                f"install manifest wheel filename is invalid: {name}"
            )
        key = _windows_path_key(safe_filename)
        if key in expected_by_key:
            previous = expected_by_key[key][0]
            raise DependencyLockError(
                "install manifest wheel filenames collide: "
                f"{previous},{name}"
            )
        expected_by_key[key] = (safe_filename, entry)

    try:
        children = sorted(
            resolved_root.iterdir(),
            key=lambda item: _windows_path_key(item.name),
        )
    except OSError as exc:
        raise DependencyLockError("release wheelhouse is unreadable") from exc
    actual_keys: set[str] = set()
    receipts: list[dict[str, object]] = []
    for child in children:
        key = _windows_path_key(child.name)
        if key in actual_keys:
            raise DependencyLockError(
                "release wheelhouse contains a case-insensitive collision"
            )
        actual_keys.add(key)
        if _is_reparse_or_symlink(child) or not child.is_file():
            raise DependencyLockError(
                f"release wheelhouse contains an unsupported entry: {child.name}"
            )
        expected = expected_by_key.get(key)
        if expected is None or child.name != expected[0]:
            raise DependencyLockError(
                f"release wheelhouse contains an unexpected file: {child.name}"
            )
        entry = expected[1]
        try:
            resolved_child = child.resolve(strict=True)
            resolved_child.relative_to(resolved_root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise DependencyLockError(
                f"release wheel escaped wheelhouse: {child.name}"
            ) from exc
        size, digest = _hash_file(resolved_child)
        if size != entry.get("wheel_size"):
            raise DependencyLockError(
                f"release wheel size mismatch: {child.name}"
            )
        if digest.hex() != entry.get("wheel_sha256"):
            raise DependencyLockError(
                f"release wheel SHA-256 mismatch: {child.name}"
            )
        receipts.append(
            {
                "filename": child.name,
                "size": size,
                "sha256": digest.hex(),
            }
        )
    if actual_keys != set(expected_by_key):
        missing = sorted(
            filename
            for key, (filename, _) in expected_by_key.items()
            if key not in actual_keys
        )
        raise DependencyLockError(
            "release wheelhouse is incomplete: " + ",".join(missing)
        )

    pip_entry = manifest_packages.get("pip")
    if not isinstance(pip_entry, Mapping):
        raise DependencyLockError("pip install manifest entry is missing")
    pip_filename = pip_entry.get("wheel_filename")
    if not isinstance(pip_filename, str):
        raise DependencyLockError("pip install manifest filename is invalid")
    receipts.sort(key=lambda entry: _windows_path_key(str(entry["filename"])))
    canonical = json.dumps(
        receipts,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return {
        "lock_sha256": lock_receipt["lock_sha256"],
        "install_manifest_sha256": manifest["manifest_sha256"],
        "wheelhouse": str(resolved_root),
        "wheel_count": len(receipts),
        "wheelhouse_sha256": hashlib.sha256(canonical).hexdigest(),
        "pip_wheel": str(resolved_root / pip_filename),
    }


def require_current_windows_runtime(
    *,
    platform_name: str | None = None,
    machine: str | None = None,
    python_version: tuple[int, int] | None = None,
    python_implementation: str | None = None,
    pointer_bits: int | None = None,
) -> None:
    """Reject installation outside 64-bit Windows CPython 3.12."""

    current_platform = sys.platform if platform_name is None else platform_name
    current_machine = platform.machine() if machine is None else machine
    current_version = sys.version_info[:2] if python_version is None else python_version
    current_implementation = (
        platform.python_implementation()
        if python_implementation is None
        else python_implementation
    )
    current_bits = struct.calcsize("P") * 8 if pointer_bits is None else pointer_bits
    if current_platform != "win32":
        raise DependencyLockError("Windows dependency lock requires sys.platform=win32")
    if current_machine.lower() not in {"amd64", "x86_64"} or current_bits != 64:
        raise DependencyLockError("Windows dependency lock requires x86-64")
    if tuple(current_version) != (3, 12):
        raise DependencyLockError("Windows dependency lock requires Python 3.12")
    if current_implementation != TARGET_IMPLEMENTATION:
        raise DependencyLockError("Windows dependency lock requires CPython")


def require_safe_dependency_verification_runtime(
    *,
    isolated: bool | None = None,
    no_site: bool | None = None,
    dont_write_bytecode: bool | None = None,
) -> None:
    """Require startup flags that prevent pre-verification path execution."""

    current_isolated = bool(sys.flags.isolated) if isolated is None else isolated
    current_no_site = bool(sys.flags.no_site) if no_site is None else no_site
    current_no_bytecode = (
        bool(sys.dont_write_bytecode)
        if dont_write_bytecode is None
        else dont_write_bytecode
    )
    if not current_isolated:
        raise DependencyLockError(
            "dependency verification must start with python -I"
        )
    if not current_no_site:
        raise DependencyLockError(
            "dependency verification must start with python -S"
        )
    if not current_no_bytecode:
        raise DependencyLockError(
            "dependency verification must start with python -B"
        )


def _active_environment_paths() -> tuple[Path, Path]:
    candidates: list[Path] = []
    for candidate in (
        Path(sys.prefix),
        Path(sys.executable).parent.parent,
    ):
        try:
            absolute = candidate.absolute()
        except OSError:
            continue
        if absolute not in candidates:
            candidates.append(absolute)

    environment_root: Path | None = None
    for candidate in candidates:
        configuration = candidate / "pyvenv.cfg"
        try:
            if (
                candidate.is_dir()
                and not _is_reparse_or_symlink(candidate)
                and configuration.is_file()
                and not _is_reparse_or_symlink(configuration)
            ):
                environment_root = candidate.resolve(strict=True)
                break
        except (DependencyLockError, OSError, RuntimeError):
            continue
    if environment_root is None:
        raise DependencyLockError("active Windows venv root is unavailable")

    site_packages = environment_root / "Lib" / "site-packages"
    try:
        if (
            not site_packages.is_dir()
            or _is_reparse_or_symlink(site_packages)
        ):
            raise DependencyLockError(
                "active Windows site-packages is unavailable"
            )
        resolved_site_packages = site_packages.resolve(strict=True)
        resolved_site_packages.relative_to(environment_root)
    except DependencyLockError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise DependencyLockError(
            "active Windows site-packages is unavailable"
        ) from exc
    return environment_root, resolved_site_packages


def prepare_isolated_venv_install() -> str:
    """Restore the active venv prefix without importing ``site``."""

    require_safe_dependency_verification_runtime()
    environment_root, _ = _active_environment_paths()
    sys.prefix = str(environment_root)
    sys.exec_prefix = str(environment_root)
    return str(environment_root)


def _distribution_name(distribution: Any) -> str:
    try:
        value = distribution.metadata.get("Name")
    except Exception as exc:
        raise DependencyLockError("installed distribution metadata is unreadable") from exc
    try:
        return _normalized_name(value)
    except DependencyLockError as exc:
        raise DependencyLockError("installed distribution name is invalid") from exc


def _distribution_version(distribution: Any, package_name: str) -> str:
    try:
        value = distribution.version
    except Exception as exc:
        raise DependencyLockError(
            f"installed distribution version is unreadable: {package_name}"
        ) from exc
    if not isinstance(value, str) or not value.strip():
        raise DependencyLockError(
            f"installed distribution version is invalid: {package_name}"
        )
    return value.strip()


def _record_path(
    distribution: Any,
    package_name: str,
    recorded_path: str,
    *,
    environment_root: Path,
) -> Path:
    pure_path = PurePosixPath(recorded_path)
    parts = pure_path.parts
    non_parent_seen = False
    parent_order_valid = True
    for part in parts:
        if part == "..":
            if non_parent_seen:
                parent_order_valid = False
        else:
            non_parent_seen = True
    if (
        not recorded_path
        or "\x00" in recorded_path
        or "\\" in recorded_path
        or recorded_path.endswith("/")
        or recorded_path.startswith("./")
        or "/./" in recorded_path
        or "//" in recorded_path
        or pure_path.is_absolute()
        or not parent_order_valid
    ):
        raise DependencyLockError(f"installed RECORD path is invalid: {package_name}")
    try:
        located = Path(distribution.locate_file(recorded_path))
        if _is_reparse_or_symlink(located):
            raise DependencyLockError(
                f"installed RECORD file is a reparse point: "
                f"{package_name}:{recorded_path}"
            )
        resolved = located.resolve(strict=True)
    except DependencyLockError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise DependencyLockError(
            f"installed RECORD file is missing: {package_name}:{recorded_path}"
        ) from exc
    try:
        resolved.relative_to(environment_root)
    except ValueError as exc:
        raise DependencyLockError(
            f"installed RECORD file escaped environment: {package_name}:{recorded_path}"
        ) from exc
    if not resolved.is_file():
        raise DependencyLockError(
            f"installed RECORD entry is not a file: {package_name}:{recorded_path}"
        )
    return resolved


def _decode_record_sha256(
    value: str,
    *,
    package_name: str,
    recorded_path: str,
) -> bytes:
    if not value.startswith("sha256="):
        raise DependencyLockError(
            f"installed RECORD hash algorithm is invalid: "
            f"{package_name}:{recorded_path}"
        )
    encoded = value.removeprefix("sha256=")
    if not encoded or "=" in encoded:
        raise DependencyLockError(
            f"installed RECORD SHA-256 is malformed: {package_name}:{recorded_path}"
        )
    padded = encoded + ("=" * ((4 - len(encoded) % 4) % 4))
    try:
        decoded = base64.b64decode(
            padded.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, ValueError) as exc:
        raise DependencyLockError(
            f"installed RECORD SHA-256 is malformed: {package_name}:{recorded_path}"
        ) from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if len(decoded) != hashlib.sha256().digest_size or canonical != encoded:
        raise DependencyLockError(
            f"installed RECORD SHA-256 is malformed: {package_name}:{recorded_path}"
        )
    return decoded


def _hash_file(path: Path) -> tuple[int, bytes]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
    except OSError as exc:
        raise DependencyLockError(
            f"installed distribution file is unreadable: {path.name}"
        ) from exc
    return size, digest.digest()


def _windows_path_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _forbidden_site_file(relative_path: str) -> str | None:
    path = PurePosixPath(relative_path)
    name = path.name.casefold()
    suffix = path.suffix.casefold()
    if suffix in {".pyc", ".pyo"}:
        return "installed bytecode is forbidden"
    if suffix == ".pth" or name in _FORBIDDEN_SITE_NAMES:
        return "forbidden site-packages file"
    return None


def _verify_recorded_file(
    installed_path: Path,
    *,
    package_name: str,
    recorded_path: str,
    hash_value: str,
    size_value: str,
) -> tuple[int, str]:
    if not hash_value or not size_value:
        if hash_value or size_value:
            raise DependencyLockError(
                f"installed RECORD hash/size pair is incomplete: "
                f"{package_name}:{recorded_path}"
            )
        raise DependencyLockError(
            f"installed RECORD entry is unexpectedly unhashed: "
            f"{package_name}:{recorded_path}"
        )
    if not size_value.isdecimal():
        raise DependencyLockError(
            f"installed RECORD size is malformed: {package_name}:{recorded_path}"
        )
    expected_size = int(size_value)
    expected_digest = _decode_record_sha256(
        hash_value,
        package_name=package_name,
        recorded_path=recorded_path,
    )
    actual_size, actual_digest = _hash_file(installed_path)
    if actual_size != expected_size:
        raise DependencyLockError(
            f"installed RECORD size mismatch: {package_name}:{recorded_path}"
        )
    if actual_digest != expected_digest:
        raise DependencyLockError(
            f"installed RECORD hash mismatch: {package_name}:{recorded_path}"
        )
    return actual_size, actual_digest.hex()


def _claim_owned_file(
    ownership: dict[str, tuple[Path, str]],
    *,
    environment_root: Path,
    path: Path,
    package_name: str,
) -> None:
    try:
        relative = path.relative_to(environment_root).as_posix()
    except ValueError as exc:
        raise DependencyLockError(
            f"installed owned file escaped environment: {package_name}"
        ) from exc
    key = _windows_path_key(relative)
    previous = ownership.get(key)
    if previous is not None:
        raise DependencyLockError(
            f"installed file ownership overlaps: "
            f"{previous[1]},{package_name}:{relative}"
        )
    ownership[key] = (path, package_name)


def _allowed_script_filenames(
    package_name: str,
    scripts: object,
) -> set[str]:
    if not isinstance(scripts, list):
        raise DependencyLockError(
            f"install manifest console scripts are invalid: {package_name}"
        )
    allowed: set[str] = set()
    for script in scripts:
        if not isinstance(script, str):
            raise DependencyLockError(
                f"install manifest console script is invalid: {package_name}"
            )
        allowed.update(
            {
                script,
                f"{script}.exe",
                f"{script}-script.py",
                f"{script}.exe.manifest",
            }
        )
    return {_windows_path_key(value) for value in allowed}


def _verify_distribution_record(
    distribution: Any,
    package_name: str,
    *,
    environment_root: Path,
    site_packages: Path,
    manifest_entry: Mapping[str, object],
    ownership: dict[str, tuple[Path, str]],
    allow_console_scripts: bool = False,
) -> dict[str, object]:
    try:
        record_text = distribution.read_text("RECORD")
    except Exception as exc:
        raise DependencyLockError(
            f"installed wheel RECORD is unreadable: {package_name}"
        ) from exc
    if not isinstance(record_text, str) or not record_text:
        raise DependencyLockError(f"installed wheel RECORD is missing: {package_name}")

    try:
        rows = list(csv.reader(io.StringIO(record_text), strict=True))
    except csv.Error as exc:
        raise DependencyLockError(
            f"installed wheel RECORD is malformed: {package_name}"
        ) from exc
    if not rows:
        raise DependencyLockError(f"installed wheel RECORD is empty: {package_name}")

    seen: set[str] = set()
    seen_files: set[Path] = set()
    record_file: Path | None = None
    expected_record_path = str(manifest_entry["record_path"])
    expected_record_parent = PurePosixPath(expected_record_path).parent
    expected_generated_metadata = {
        "INSTALLER": b"pip\n",
        "REQUESTED": b"",
    }
    seen_generated_metadata: set[str] = set()
    original_site_files: list[dict[str, object]] = []
    hashed_files = 0
    generated_files = 0
    allowed_script_files = _allowed_script_filenames(
        package_name,
        manifest_entry.get("console_scripts"),
    )
    for row in rows:
        if len(row) != 3 or not row[0] or row[0] in seen:
            raise DependencyLockError(
                f"installed wheel RECORD is malformed: {package_name}"
            )
        recorded_path, hash_value, size_value = row
        seen.add(recorded_path)
        installed_path = _record_path(
            distribution,
            package_name,
            recorded_path,
            environment_root=environment_root,
        )
        if installed_path in seen_files:
            raise DependencyLockError(
                f"installed wheel RECORD aliases a file: {package_name}"
            )
        seen_files.add(installed_path)

        try:
            relative_site = installed_path.relative_to(site_packages).as_posix()
        except ValueError:
            relative_site = None
        if relative_site is not None:
            relative_site = _safe_manifest_site_path(
                relative_site,
                field=f"{package_name}:installed",
            )
            forbidden_reason = _forbidden_site_file(relative_site)
            if forbidden_reason is not None:
                raise DependencyLockError(
                    f"{forbidden_reason}: {package_name}:{relative_site}"
                )

            if relative_site == expected_record_path:
                if record_file is not None or hash_value or size_value:
                    raise DependencyLockError(
                        f"installed wheel RECORD self-entry is malformed: "
                        f"{package_name}"
                    )
                record_file = installed_path
                _claim_owned_file(
                    ownership,
                    environment_root=environment_root,
                    path=installed_path,
                    package_name=package_name,
                )
                continue
            path = PurePosixPath(relative_site)
            if path.name == "RECORD" and path.parent.name.endswith(".dist-info"):
                raise DependencyLockError(
                    f"installed wheel RECORD path drift: {package_name}"
                )

            if (
                path.parent == expected_record_parent
                and path.name in _FORBIDDEN_DIST_INFO_METADATA
            ):
                raise DependencyLockError(
                    f"installed generated metadata is forbidden: "
                    f"{package_name}:{relative_site}"
                )

            if (
                path.parent == expected_record_parent
                and path.name in _ALLOWED_GENERATED_METADATA
            ):
                if path.name not in expected_generated_metadata:
                    raise DependencyLockError(
                        f"installed generated metadata is forbidden: "
                        f"{package_name}:{relative_site}"
                    )
                if path.name in seen_generated_metadata:
                    raise DependencyLockError(
                        f"installed generated metadata is duplicated: "
                        f"{package_name}:{relative_site}"
                    )
                actual_size, actual_sha256 = _verify_recorded_file(
                    installed_path,
                    package_name=package_name,
                    recorded_path=recorded_path,
                    hash_value=hash_value,
                    size_value=size_value,
                )
                try:
                    content = installed_path.read_bytes()
                except OSError as exc:
                    raise DependencyLockError(
                        f"installed generated metadata is unreadable: "
                        f"{package_name}:{relative_site}"
                    ) from exc
                if content != expected_generated_metadata[path.name]:
                    raise DependencyLockError(
                        f"installed generated metadata content mismatch: "
                        f"{package_name}:{relative_site}"
                    )
                seen_generated_metadata.add(path.name)
                _claim_owned_file(
                    ownership,
                    environment_root=environment_root,
                    path=installed_path,
                    package_name=package_name,
                )
                hashed_files += 1
                generated_files += 1
                continue

            actual_size, actual_sha256 = _verify_recorded_file(
                installed_path,
                package_name=package_name,
                recorded_path=recorded_path,
                hash_value=hash_value,
                size_value=size_value,
            )
            original_site_files.append(
                {
                    "path": relative_site,
                    "sha256": actual_sha256,
                    "size": actual_size,
                }
            )
            _claim_owned_file(
                ownership,
                environment_root=environment_root,
                path=installed_path,
                package_name=package_name,
            )
            hashed_files += 1
            continue

        try:
            relative_environment = installed_path.relative_to(
                environment_root
            ).as_posix()
        except ValueError as exc:
            raise DependencyLockError(
                f"installed RECORD file escaped environment: "
                f"{package_name}:{recorded_path}"
            ) from exc
        relative_parts = PurePosixPath(relative_environment).parts
        if (
            len(relative_parts) != 2
            or relative_parts[0].casefold() != "scripts"
            or _windows_path_key(relative_parts[1]) not in allowed_script_files
        ):
            raise DependencyLockError(
                f"installed RECORD non-library path is forbidden: "
                f"{package_name}:{recorded_path}"
            )
        if not allow_console_scripts:
            raise DependencyLockError(
                f"installed console scripts are not sealed: "
                f"{package_name}:{recorded_path}"
            )
        if relative_parts[1].casefold().endswith(".deleteme"):
            raise DependencyLockError(
                f"installed script upgrade debris is forbidden: "
                f"{package_name}:{recorded_path}"
            )
        _verify_recorded_file(
            installed_path,
            package_name=package_name,
            recorded_path=recorded_path,
            hash_value=hash_value,
            size_value=size_value,
        )
        _claim_owned_file(
            ownership,
            environment_root=environment_root,
            path=installed_path,
            package_name=package_name,
        )
        hashed_files += 1
        generated_files += 1

    if record_file is None:
        raise DependencyLockError(
            f"installed wheel RECORD self-entry is missing: {package_name}"
        )
    if seen_generated_metadata != set(expected_generated_metadata):
        missing = sorted(set(expected_generated_metadata) - seen_generated_metadata)
        raise DependencyLockError(
            f"installed generated metadata is missing: "
            f"{package_name}:{','.join(missing)}"
        )
    original_site_files.sort(key=lambda entry: str(entry["path"]))
    if (
        len(original_site_files)
        != manifest_entry.get("site_packages_file_count")
        or _canonical_sha256(original_site_files)
        != manifest_entry.get("site_packages_tree_sha256")
    ):
        raise DependencyLockError(
            f"installed wheel-tree manifest mismatch: {package_name}"
        )
    if hashed_files == 0:
        raise DependencyLockError(
            f"installed wheel RECORD has no hashed files: {package_name}"
        )
    record_size, record_digest = _hash_file(record_file)
    return {
        "name": package_name,
        "version": _distribution_version(distribution, package_name),
        "wheel_sha256": manifest_entry["wheel_sha256"],
        "site_packages_tree_sha256": manifest_entry[
            "site_packages_tree_sha256"
        ],
        "record_sha256": record_digest.hex(),
        "record_size": record_size,
        "hashed_file_count": hashed_files,
        "generated_file_count": generated_files,
    }


def _iter_tree_files(root: Path, *, label: str) -> list[Path]:
    if not root.is_dir() or _is_reparse_or_symlink(root):
        raise DependencyLockError(f"{label} directory is unavailable")
    files: list[Path] = []
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            children = sorted(
                directory.iterdir(),
                key=lambda path: _windows_path_key(path.name),
            )
        except OSError as exc:
            raise DependencyLockError(f"{label} directory is unreadable") from exc
        seen_names: set[str] = set()
        for child in children:
            key = _windows_path_key(child.name)
            if key in seen_names:
                raise DependencyLockError(
                    f"{label} contains a case-insensitive path collision"
                )
            seen_names.add(key)
            if _is_reparse_or_symlink(child):
                raise DependencyLockError(
                    f"{label} contains a reparse point: {child.name}"
                )
            if child.is_dir():
                stack.append(child)
            elif child.is_file():
                files.append(child.resolve(strict=True))
            else:
                raise DependencyLockError(
                    f"{label} contains an unsupported filesystem entry: "
                    f"{child.name}"
                )
    return files


def _scan_site_packages(
    site_packages: Path,
    *,
    environment_root: Path,
    ownership: Mapping[str, tuple[Path, str]],
) -> int:
    files = _iter_tree_files(site_packages, label="site-packages")
    seen: set[str] = set()
    for path in files:
        relative_site = path.relative_to(site_packages).as_posix()
        relative_site = _safe_manifest_site_path(
            relative_site,
            field="installed ownership scan",
        )
        forbidden_reason = _forbidden_site_file(relative_site)
        if forbidden_reason is not None:
            raise DependencyLockError(
                f"{forbidden_reason}: {relative_site}"
            )
        relative_environment = path.relative_to(environment_root).as_posix()
        key = _windows_path_key(relative_environment)
        if key not in ownership:
            raise DependencyLockError(
                f"unowned site-packages file: {relative_site}"
            )
        seen.add(key)
    expected = {
        key
        for key, (path, _) in ownership.items()
        if path.is_relative_to(site_packages)
    }
    if seen != expected:
        raise DependencyLockError("site-packages ownership inventory mismatch")
    return len(files)


def _scan_scripts_directory(
    environment_root: Path,
    *,
    ownership: Mapping[str, tuple[Path, str]],
) -> list[dict[str, object]]:
    scripts = environment_root / "Scripts"
    files = _iter_tree_files(scripts, label="venv Scripts")
    required_venv_files = {
        "activate",
        "activate.bat",
        "activate.ps1",
        "deactivate.bat",
        "python.exe",
        "pythonw.exe",
    }
    required_keys = {
        _windows_path_key(filename) for filename in required_venv_files
    }
    seen_core_keys: set[str] = set()
    receipt: list[dict[str, object]] = []
    for path in files:
        relative = path.relative_to(environment_root).as_posix()
        filename = path.name.casefold()
        if filename.endswith(".deleteme"):
            raise DependencyLockError(
                f"venv Scripts upgrade debris is forbidden: {path.name}"
            )
        key = _windows_path_key(relative)
        if key not in ownership and filename not in required_venv_files:
            raise DependencyLockError(f"unowned venv Scripts file: {path.name}")
        if filename in required_venv_files:
            seen_core_keys.add(_windows_path_key(path.name))
        size, digest = _hash_file(path)
        receipt.append(
            {
                "path": relative,
                "size": size,
                "sha256": digest.hex(),
            }
        )
    receipt.sort(key=lambda entry: _windows_path_key(str(entry["path"])))
    if seen_core_keys != required_keys:
        missing = sorted(required_keys - seen_core_keys)
        raise DependencyLockError(
            "venv Scripts core file set is incomplete: " + ",".join(missing)
        )
    return receipt


def _verify_pyvenv_configuration(environment_root: Path) -> dict[str, object]:
    path = environment_root / "pyvenv.cfg"
    try:
        if not path.is_file() or _is_reparse_or_symlink(path):
            raise DependencyLockError("pyvenv.cfg is unavailable")
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except DependencyLockError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise DependencyLockError("pyvenv.cfg is unreadable") from exc

    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        normalized_key = key.strip().casefold()
        normalized_value = value.strip()
        if (
            not separator
            or not normalized_key
            or not normalized_value
            or normalized_key in fields
        ):
            raise DependencyLockError("pyvenv.cfg is malformed")
        fields[normalized_key] = normalized_value
    required = {
        "home",
        "include-system-site-packages",
        "version",
        "executable",
        "command",
    }
    allowed = required | {"prompt"}
    if not required.issubset(fields) or not set(fields).issubset(allowed):
        raise DependencyLockError("pyvenv.cfg field set is invalid")
    if fields["include-system-site-packages"].casefold() != "false":
        raise DependencyLockError(
            "pyvenv.cfg must disable system site-packages"
        )
    version_parts = fields["version"].split(".")
    if len(version_parts) < 3 or version_parts[:2] != ["3", "12"]:
        raise DependencyLockError("pyvenv.cfg Python version drift")
    for field in ("home", "executable"):
        value = fields[field]
        windows_path = PureWindowsPath(value)
        if (
            not windows_path.is_absolute()
            or value.startswith(("\\\\", "//"))
        ):
            raise DependencyLockError(
                f"pyvenv.cfg {field} path is invalid"
            )
    executable = PureWindowsPath(fields["executable"])
    if executable.name.casefold() not in {"python.exe", "python3.12.exe"}:
        raise DependencyLockError("pyvenv.cfg executable is invalid")
    command = fields["command"].casefold()
    if "-m venv" not in command or "--without-pip" not in command:
        raise DependencyLockError(
            "pyvenv.cfg does not attest --without-pip creation"
        )
    return {
        "path": "pyvenv.cfg",
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "python_version": fields["version"],
        "system_site_packages": False,
        "created_without_pip": True,
    }


def _scan_environment_tree(
    environment_root: Path,
    *,
    ownership: Mapping[str, tuple[Path, str]],
    script_receipts: list[dict[str, object]],
) -> int:
    allowed_keys = set(ownership)
    for receipt in script_receipts:
        relative = receipt.get("path")
        if not isinstance(relative, str):
            raise DependencyLockError("venv Scripts receipt is invalid")
        allowed_keys.add(_windows_path_key(relative))
    allowed_keys.add(_windows_path_key("pyvenv.cfg"))

    files = _iter_tree_files(environment_root, label="venv")
    actual_keys = {
        _windows_path_key(path.relative_to(environment_root).as_posix())
        for path in files
    }
    if actual_keys != allowed_keys:
        unexpected = sorted(actual_keys - allowed_keys)
        missing = sorted(allowed_keys - actual_keys)
        detail = []
        if unexpected:
            detail.append("unexpected=" + ",".join(unexpected))
        if missing:
            detail.append("missing=" + ",".join(missing))
        raise DependencyLockError(
            "venv file inventory mismatch: " + ";".join(detail)
        )
    return len(files)


def _installed_distribution_inventory(
    site_packages: Path,
    expected_versions: Mapping[str, str],
) -> dict[str, Any]:
    installed: dict[str, Any] = {}
    try:
        distributions = tuple(metadata.distributions(path=[str(site_packages)]))
    except Exception as exc:
        raise DependencyLockError(
            "installed distribution inventory is unavailable"
        ) from exc
    for distribution in distributions:
        name = _distribution_name(distribution)
        if name in installed:
            raise DependencyLockError(f"duplicate installed distribution: {name}")
        installed[name] = distribution

    failures: list[str] = []
    for name, expected in sorted(expected_versions.items()):
        distribution = installed.get(name)
        if distribution is None:
            failures.append(f"{name}=MISSING")
            continue
        actual = _distribution_version(distribution, name)
        if actual != expected:
            failures.append(f"{name}={actual} (expected {expected})")
    unexpected = sorted(set(installed).difference(expected_versions))
    if unexpected:
        failures.append("unexpected=" + ",".join(unexpected))
    if failures:
        raise DependencyLockError(
            "installed dependency set does not match lock: " + ", ".join(failures)
        )
    return installed


def verify_installed_lock(path: str | Path) -> dict[str, object]:
    """Verify the exact installed set against the immutable wheel-tree manifest."""

    require_safe_dependency_verification_runtime()
    lock_path = Path(path)
    lock_receipt = validate_windows_dependency_lock(lock_path)
    payload, _ = _read_lock(lock_path)
    packages = _package_map(payload, lock_directory=lock_path.parent)
    manifest = _load_install_manifest(lock_path, payload, packages)
    expected_versions = {
        name: str(package["version"]) for name, package in packages.items()
    } | BOOTSTRAP_REQUIREMENTS

    environment_root, site_packages = _active_environment_paths()
    installed = _installed_distribution_inventory(
        site_packages,
        expected_versions,
    )

    manifest_packages = manifest["packages"]
    if not isinstance(manifest_packages, Mapping):
        raise DependencyLockError("install manifest package set is invalid")
    ownership: dict[str, tuple[Path, str]] = {}
    distribution_receipts = [
        _verify_distribution_record(
            installed[name],
            name,
            environment_root=environment_root,
            site_packages=site_packages,
            manifest_entry=manifest_packages[name],
            ownership=ownership,
        )
        for name in sorted(expected_versions)
    ]
    site_file_count = _scan_site_packages(
        site_packages,
        environment_root=environment_root,
        ownership=ownership,
    )
    script_receipts = _scan_scripts_directory(
        environment_root,
        ownership=ownership,
    )
    pyvenv_receipt = _verify_pyvenv_configuration(environment_root)
    environment_file_count = _scan_environment_tree(
        environment_root,
        ownership=ownership,
        script_receipts=script_receipts,
    )
    canonical_receipt = json.dumps(
        {
            "distributions": distribution_receipts,
            "pyvenv": pyvenv_receipt,
            "scripts": script_receipts,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return {
        "lock_file": lock_receipt["lock_file"],
        "lock_sha256": lock_receipt["lock_sha256"],
        "install_manifest_sha256": manifest["manifest_sha256"],
        "locked_package_count": len(packages),
        "bootstrap_packages": dict(BOOTSTRAP_REQUIREMENTS),
        "installed_distribution_count": len(distribution_receipts),
        "hashed_file_count": sum(
            int(receipt["hashed_file_count"]) for receipt in distribution_receipts
        ),
        "generated_file_count": sum(
            int(receipt["generated_file_count"]) for receipt in distribution_receipts
        ),
        "site_packages_file_count": site_file_count,
        "scripts_file_count": len(script_receipts),
        "environment_file_count": environment_file_count,
        "pyvenv_sha256": pyvenv_receipt["sha256"],
        "site_packages": str(site_packages),
        "installed_environment_sha256": hashlib.sha256(canonical_receipt).hexdigest(),
    }


def activate_verified_site_packages(receipt: Mapping[str, object]) -> str:
    """Append only the site-packages directory authenticated by the receipt."""

    require_safe_dependency_verification_runtime()
    environment_root, expected_site_packages = _active_environment_paths()
    receipt_path = receipt.get("site_packages")
    if receipt_path != str(expected_site_packages):
        raise DependencyLockError(
            "verified site-packages receipt does not match the active venv"
        )
    for entry in sys.path:
        if not entry:
            continue
        try:
            candidate = Path(entry).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if candidate == expected_site_packages:
            raise DependencyLockError(
                "site-packages was active before dependency verification"
            )
    sys.prefix = str(environment_root)
    sys.exec_prefix = str(environment_root)
    sys.path.append(str(expected_site_packages))
    return str(expected_site_packages)


def _atomic_write_record(record_file: Path, rows: list[list[str]]) -> None:
    stream = io.StringIO()
    csv.writer(stream, lineterminator="\n").writerows(rows)
    encoded = stream.getvalue().encode("utf-8")
    temporary = record_file.with_name(record_file.name + ".sealing.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, record_file)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise DependencyLockError(
            f"installed wheel RECORD sealing failed: {record_file.parent.name}"
        ) from exc


def seal_dependency_console_scripts(path: str | Path) -> dict[str, object]:
    """Remove dependency-generated console wrappers and their mutable RECORD rows."""

    require_safe_dependency_verification_runtime()
    lock_path = Path(path)
    validate_windows_dependency_lock(lock_path)
    payload, _ = _read_lock(lock_path)
    packages = _package_map(payload, lock_directory=lock_path.parent)
    manifest = _load_install_manifest(lock_path, payload, packages)
    expected_versions = {
        name: str(package["version"]) for name, package in packages.items()
    } | BOOTSTRAP_REQUIREMENTS
    environment_root, site_packages = _active_environment_paths()
    installed = _installed_distribution_inventory(
        site_packages,
        expected_versions,
    )
    manifest_packages = manifest["packages"]
    if not isinstance(manifest_packages, Mapping):
        raise DependencyLockError("install manifest package set is invalid")

    ownership: dict[str, tuple[Path, str]] = {}
    for name in sorted(expected_versions):
        _verify_distribution_record(
            installed[name],
            name,
            environment_root=environment_root,
            site_packages=site_packages,
            manifest_entry=manifest_packages[name],
            ownership=ownership,
            allow_console_scripts=True,
        )
    _scan_site_packages(
        site_packages,
        environment_root=environment_root,
        ownership=ownership,
    )

    rewritten_records = 0
    removed_record_rows = 0
    for name in sorted(expected_versions):
        distribution = installed[name]
        try:
            record_text = distribution.read_text("RECORD")
        except Exception as exc:
            raise DependencyLockError(
                f"installed wheel RECORD is unreadable: {name}"
            ) from exc
        if not isinstance(record_text, str) or not record_text:
            raise DependencyLockError(f"installed wheel RECORD is missing: {name}")
        try:
            rows = list(csv.reader(io.StringIO(record_text), strict=True))
        except csv.Error as exc:
            raise DependencyLockError(
                f"installed wheel RECORD is malformed: {name}"
            ) from exc
        kept: list[list[str]] = []
        record_file: Path | None = None
        removed_for_distribution = 0
        for row in rows:
            if len(row) != 3:
                raise DependencyLockError(
                    f"installed wheel RECORD is malformed: {name}"
                )
            installed_path = _record_path(
                distribution,
                name,
                row[0],
                environment_root=environment_root,
            )
            try:
                installed_path.relative_to(site_packages)
            except ValueError:
                removed_for_distribution += 1
                continue
            kept.append(row)
            if row[0] == manifest_packages[name]["record_path"]:
                record_file = installed_path
        if removed_for_distribution:
            if record_file is None:
                raise DependencyLockError(
                    f"installed wheel RECORD self-entry is missing: {name}"
                )
            _atomic_write_record(record_file, kept)
            rewritten_records += 1
            removed_record_rows += removed_for_distribution

    expected_wrapper_names: set[str] = set()
    for name in sorted(expected_versions):
        expected_wrapper_names.update(
            _allowed_script_filenames(
                name,
                manifest_packages[name].get("console_scripts"),
            )
        )
    scripts_directory = environment_root / "Scripts"
    removed_files: list[str] = []
    for script_path in _iter_tree_files(
        scripts_directory,
        label="venv Scripts",
    ):
        if _windows_path_key(script_path.name) not in expected_wrapper_names:
            continue
        try:
            script_path.unlink()
        except OSError as exc:
            raise DependencyLockError(
                f"dependency console script removal failed: {script_path.name}"
            ) from exc
        removed_files.append(script_path.name)

    post_scripts = _scan_scripts_directory(
        environment_root,
        ownership={},
    )
    return {
        "lock_file": lock_path.name,
        "install_manifest_sha256": manifest["manifest_sha256"],
        "rewritten_record_count": rewritten_records,
        "removed_record_row_count": removed_record_rows,
        "removed_console_script_count": len(removed_files),
        "removed_console_scripts": sorted(
            removed_files,
            key=_windows_path_key,
        ),
        "remaining_core_script_count": len(post_scripts),
        "site_packages": str(site_packages),
    }
