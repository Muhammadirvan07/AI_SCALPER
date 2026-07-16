"""Build the deterministic CycloneDX inventory for the Windows release lock.

This generator intentionally uses only the Python standard library so it can
run before any release dependency is installed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tomllib
from typing import Mapping
from urllib.parse import quote, urlparse


SBOM_PATH = "vendor/windows-cp312-dependency-sbom.cdx.json"
INSTALL_MANIFEST_PATH = "vendor/windows-cp312-install-manifest.json"
INSTALL_MANIFEST_SCHEMA_VERSION = "windows-wheel-tree-v1"
SBOM_SPEC_VERSION = "1.6"
REPO_ROOT = Path(__file__).resolve().parent
_NORMALIZE_NAME_RE = re.compile(r"[-_.]+")
_TARGET = {
    "architecture": "x86_64",
    "implementation": "CPython",
    "platform": "win_amd64",
    "python": "3.12",
}


class SbomBuildError(RuntimeError):
    """Raised when the lock cannot produce a trustworthy deterministic SBOM."""


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SbomBuildError(f"install manifest duplicate field: {key}")
        result[key] = value
    return result


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _normalized_name(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SbomBuildError("package name is missing")
    return _NORMALIZE_NAME_RE.sub("-", value.strip().lower())


def _artifact_filename(artifact: Mapping[str, object]) -> str:
    location = artifact.get("url", artifact.get("path"))
    if not isinstance(location, str):
        raise SbomBuildError("locked wheel location is invalid")
    filename = PurePosixPath(urlparse(location).path).name
    if not filename.endswith(".whl"):
        raise SbomBuildError("locked artifact is not a wheel")
    return filename


def _target_wheel_priority(filename: str) -> tuple[int, str]:
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
        raise SbomBuildError(f"locked wheel is missing: {package_name}")
    candidates = [
        wheel
        for wheel in wheels
        if isinstance(wheel, Mapping)
        and _target_wheel_priority(_artifact_filename(wheel))[0] < 100
    ]
    if not candidates:
        raise SbomBuildError(f"compatible locked wheel is missing: {package_name}")
    return min(
        candidates,
        key=lambda wheel: _target_wheel_priority(_artifact_filename(wheel)),
    )


def _wheel_binding(
    package_name: str,
    artifact: Mapping[str, object],
) -> tuple[str, int, str]:
    filename = _artifact_filename(artifact)
    size = artifact.get("size")
    hashes = artifact.get("hashes")
    sha256 = hashes.get("sha256") if isinstance(hashes, Mapping) else None
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or not isinstance(sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", sha256)
    ):
        raise SbomBuildError(f"locked wheel binding is invalid: {package_name}")
    return filename, size, sha256


def _purl(name: str, version: str) -> str:
    return (
        "pkg:pypi/"
        + quote(name, safe="-._~")
        + "@"
        + quote(version, safe="-._~")
    )


def _component(
    *,
    name: str,
    version: str,
    artifact: Mapping[str, object],
    role: str,
) -> dict[str, object]:
    filename, size, sha256 = _wheel_binding(name, artifact)
    purl = _purl(name, version)
    return {
        "bom-ref": purl,
        "hashes": [{"alg": "SHA-256", "content": sha256}],
        "name": name,
        "properties": [
            {"name": "ai_scalper:dependency-role", "value": role},
            {"name": "ai_scalper:wheel-filename", "value": filename},
            {"name": "ai_scalper:wheel-size", "value": str(size)},
        ],
        "purl": purl,
        "scope": "required",
        "type": "library",
        "version": version,
    }


def build_dependency_sbom(
    lock_path: str | Path,
) -> dict[str, object]:
    """Build a timestamp-free CycloneDX document from exact selected wheels."""

    path = Path(lock_path)
    if path.is_symlink() or not path.is_file():
        raise SbomBuildError("dependency lock is unavailable or invalid")
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SbomBuildError("dependency lock is unavailable or invalid") from exc
    if not isinstance(payload, dict):
        raise SbomBuildError("dependency lock root is invalid")
    tool = payload.get("tool")
    intent = tool.get("ai_scalper") if isinstance(tool, Mapping) else None
    if not isinstance(intent, Mapping):
        raise SbomBuildError("dependency target metadata is missing")
    for field, expected in (
        ("target-python", _TARGET["python"]),
        ("target-implementation", _TARGET["implementation"]),
        ("target-platform", _TARGET["platform"]),
        ("target-architecture", _TARGET["architecture"]),
    ):
        if intent.get(field) != expected:
            raise SbomBuildError(f"dependency target drift: {field}")

    manifest_binding = intent.get("install-manifest")
    if (
        not isinstance(manifest_binding, Mapping)
        or set(manifest_binding) != {"path", "size", "hashes"}
        or manifest_binding.get("path") != INSTALL_MANIFEST_PATH
    ):
        raise SbomBuildError("install manifest binding is invalid")
    relative_manifest = manifest_binding.get("path")
    manifest_path = path.parent / str(relative_manifest)
    try:
        root = path.parent.resolve(strict=True)
        resolved_manifest = manifest_path.resolve(strict=True)
        resolved_manifest.relative_to(root)
        if manifest_path.is_symlink() or not resolved_manifest.is_file():
            raise SbomBuildError("install manifest is unavailable or invalid")
        raw_manifest = resolved_manifest.read_bytes()
        size = manifest_binding.get("size")
        hashes = manifest_binding.get("hashes")
        sha256 = hashes.get("sha256") if isinstance(hashes, Mapping) else None
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or len(raw_manifest) != size
            or not isinstance(sha256, str)
            or hashlib.sha256(raw_manifest).hexdigest() != sha256
        ):
            raise SbomBuildError("install manifest binding drift")
        manifest = json.loads(
            raw_manifest.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except (OSError, RuntimeError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        if isinstance(exc, SbomBuildError):
            raise
        raise SbomBuildError("install manifest is unavailable or invalid") from exc
    if not isinstance(manifest, Mapping) or set(manifest) != {
        "schema_version",
        "target",
        "packages",
        "payload_sha256",
    }:
        raise SbomBuildError("install manifest root is invalid")
    if manifest.get("schema_version") != INSTALL_MANIFEST_SCHEMA_VERSION:
        raise SbomBuildError("install manifest schema drift")
    if manifest.get("target") != _TARGET:
        raise SbomBuildError("install manifest target drift")
    manifest_body = {
        key: value
        for key, value in manifest.items()
        if key != "payload_sha256"
    }
    if manifest.get("payload_sha256") != _canonical_sha256(manifest_body):
        raise SbomBuildError("install manifest payload SHA-256 mismatch")
    manifest_packages = (
        manifest.get("packages") if isinstance(manifest, Mapping) else None
    )
    if not isinstance(manifest_packages, Mapping):
        raise SbomBuildError("install manifest package set is invalid")

    package_entries = payload.get("packages")
    if not isinstance(package_entries, list) or not package_entries:
        raise SbomBuildError("runtime package set is missing")
    components: list[dict[str, object]] = []
    seen: set[str] = set()
    for package in package_entries:
        if not isinstance(package, Mapping):
            raise SbomBuildError("runtime package entry is invalid")
        name = _normalized_name(package.get("name"))
        if name in seen:
            raise SbomBuildError(f"duplicate package: {name}")
        seen.add(name)
        version = package.get("version")
        if not isinstance(version, str) or not version:
            raise SbomBuildError(f"package version is missing: {name}")
        artifact = _select_target_wheel(name, package.get("wheels"))
        component = _component(
            name=name,
            version=version,
            artifact=artifact,
            role="runtime",
        )
        manifest_entry = manifest_packages.get(name)
        if not isinstance(manifest_entry, Mapping):
            raise SbomBuildError(f"install manifest package is missing: {name}")
        filename, size, sha256 = _wheel_binding(name, artifact)
        if (
            manifest_entry.get("version") != version
            or manifest_entry.get("wheel_filename") != filename
            or manifest_entry.get("wheel_size") != size
            or manifest_entry.get("wheel_sha256") != sha256
        ):
            raise SbomBuildError(f"install manifest wheel binding drift: {name}")
        components.append(component)

    bootstrap = intent.get("bootstrap-wheels")
    if not isinstance(bootstrap, list) or not bootstrap:
        raise SbomBuildError("bootstrap package set is missing")
    for package in bootstrap:
        if not isinstance(package, Mapping):
            raise SbomBuildError("bootstrap package entry is invalid")
        name = _normalized_name(package.get("name"))
        if name in seen:
            raise SbomBuildError(f"duplicate package: {name}")
        seen.add(name)
        version = package.get("version")
        if not isinstance(version, str) or not version:
            raise SbomBuildError(f"package version is missing: {name}")
        component = _component(
            name=name,
            version=version,
            artifact=package,
            role="bootstrap",
        )
        manifest_entry = manifest_packages.get(name)
        filename, size, sha256 = _wheel_binding(name, package)
        if (
            not isinstance(manifest_entry, Mapping)
            or manifest_entry.get("version") != version
            or manifest_entry.get("wheel_filename") != filename
            or manifest_entry.get("wheel_size") != size
            or manifest_entry.get("wheel_sha256") != sha256
        ):
            raise SbomBuildError(f"install manifest wheel binding drift: {name}")
        components.append(component)

    components.sort(key=lambda item: str(item["name"]))
    if set(manifest_packages) != seen:
        raise SbomBuildError("install manifest package set drift")
    return {
        "bomFormat": "CycloneDX",
        "components": components,
        "metadata": {
            "properties": [
                {
                    "name": "ai_scalper:bootstrap-package-count",
                    "value": str(len(bootstrap)),
                },
                {
                    "name": "ai_scalper:runtime-package-count",
                    "value": str(len(package_entries)),
                },
                {
                    "name": "ai_scalper:target-architecture",
                    "value": _TARGET["architecture"],
                },
                {
                    "name": "ai_scalper:target-implementation",
                    "value": _TARGET["implementation"],
                },
                {
                    "name": "ai_scalper:target-platform",
                    "value": _TARGET["platform"],
                },
                {
                    "name": "ai_scalper:target-python",
                    "value": _TARGET["python"],
                },
            ]
        },
        "specVersion": SBOM_SPEC_VERSION,
        "version": 1,
    }


def canonical_sbom_bytes(payload: Mapping[str, object]) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _canonical_components_sha256(payload: Mapping[str, object]) -> str:
    components = payload.get("components")
    raw = json.dumps(
        components,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--lock",
        default=str(REPO_ROOT / "pylock.windows-cp312.toml"),
    )
    parser.add_argument("--output", default=str(REPO_ROOT / SBOM_PATH))
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        payload = build_dependency_sbom(args.lock)
        raw = canonical_sbom_bytes(payload)
        output = Path(args.output)
        if args.check:
            if not output.is_file() or output.read_bytes() != raw:
                raise SbomBuildError("committed dependency SBOM drift")
        else:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(raw)
    except (OSError, SbomBuildError) as exc:
        print(f"DEPENDENCY_SBOM_REJECTED: {exc}", file=sys.stderr)
        return 2
    print(f"Dependency SBOM valid: {output}")
    print(f"Components: {len(payload['components'])}")
    print(f"SHA-256: {hashlib.sha256(raw).hexdigest()}")
    print(f"Components SHA-256: {_canonical_components_sha256(payload)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
