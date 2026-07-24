"""Build the immutable Windows wheel-tree manifest from exact locked wheels."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import tomllib
from typing import Mapping
import unicodedata
from urllib.parse import urlparse
from urllib.request import urlopen
import zipfile


SCHEMA_VERSION = "windows-wheel-tree-v1"
TARGET = {
    "python": "3.12",
    "implementation": "CPython",
    "platform": "win_amd64",
    "architecture": "x86_64",
}
FORBIDDEN_SITE_NAMES = {"sitecustomize.py", "usercustomize.py"}
FORBIDDEN_SITE_SUFFIXES = {".pyc", ".pyo", ".pth"}
FORBIDDEN_GENERATED_METADATA = {
    "INSTALLER",
    "REQUESTED",
    "direct_url.json",
    "origin.json",
    "RECORD.jws",
    "RECORD.p7s",
}
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


class ManifestBuildError(RuntimeError):
    pass


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _normalized_name(value: object) -> str:
    text = str(value).strip().lower().replace("_", "-").replace(".", "-")
    while "--" in text:
        text = text.replace("--", "-")
    if not text:
        raise ManifestBuildError("package name is missing")
    return text


def _safe_archive_path(value: str) -> PurePosixPath:
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
        raise ManifestBuildError(f"wheel path is invalid: {value!r}")
    for part in path.parts:
        if part.endswith((" ", ".")):
            raise ManifestBuildError(f"wheel path is invalid: {value!r}")
        if part.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES:
            raise ManifestBuildError(f"wheel path is invalid: {value!r}")
    return path


def _windows_path_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _decode_record_sha256(value: str, path: str) -> str:
    if not value.startswith("sha256="):
        raise ManifestBuildError(f"wheel RECORD hash algorithm is invalid: {path}")
    encoded = value.removeprefix("sha256=")
    if not encoded or "=" in encoded:
        raise ManifestBuildError(f"wheel RECORD SHA-256 is malformed: {path}")
    padded = encoded + ("=" * ((4 - len(encoded) % 4) % 4))
    try:
        decoded = base64.b64decode(
            padded.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, ValueError) as exc:
        raise ManifestBuildError(
            f"wheel RECORD SHA-256 is malformed: {path}"
        ) from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if len(decoded) != hashlib.sha256().digest_size or canonical != encoded:
        raise ManifestBuildError(f"wheel RECORD SHA-256 is malformed: {path}")
    return decoded.hex()


def _artifact_sha256(artifact: Mapping[str, object]) -> str:
    hashes = artifact.get("hashes")
    if not isinstance(hashes, Mapping):
        raise ManifestBuildError("locked wheel hash is missing")
    value = hashes.get("sha256")
    if not isinstance(value, str) or len(value) != 64:
        raise ManifestBuildError("locked wheel SHA-256 is invalid")
    return value


def _artifact_filename(artifact: Mapping[str, object]) -> str:
    value = artifact.get("url", artifact.get("path"))
    if not isinstance(value, str):
        raise ManifestBuildError("locked wheel location is invalid")
    filename = PurePosixPath(urlparse(value).path).name
    if not filename.endswith(".whl"):
        raise ManifestBuildError("locked artifact is not a wheel")
    return filename


def _wheel_priority(filename: str) -> tuple[int, str]:
    lower = filename.lower()
    if lower.endswith("-cp312-cp312-win_amd64.whl"):
        return (0, lower)
    if "-abi3-win_amd64.whl" in lower:
        return (1, lower)
    if lower.endswith(("-py3-none-any.whl", "-py2.py3-none-any.whl")):
        return (2, lower)
    return (100, lower)


def _select_wheel(package: Mapping[str, object]) -> Mapping[str, object]:
    wheels = package.get("wheels")
    if not isinstance(wheels, list) or not wheels:
        raise ManifestBuildError(f"package has no wheels: {package.get('name')}")
    candidates = [
        wheel
        for wheel in wheels
        if isinstance(wheel, Mapping)
        and _wheel_priority(_artifact_filename(wheel))[0] < 100
    ]
    if not candidates:
        raise ManifestBuildError(
            f"package has no compatible Windows wheel: {package.get('name')}"
        )
    return min(candidates, key=lambda wheel: _wheel_priority(_artifact_filename(wheel)))


def _locked_wheels(lock: Mapping[str, object]) -> dict[str, dict[str, object]]:
    packages = lock.get("packages")
    if not isinstance(packages, list):
        raise ManifestBuildError("dependency package set is missing")
    selected: dict[str, dict[str, object]] = {}
    for package in packages:
        if not isinstance(package, Mapping):
            raise ManifestBuildError("dependency package entry is invalid")
        name = _normalized_name(package.get("name"))
        wheel = _select_wheel(package)
        selected[name] = {
            "name": name,
            "version": str(package.get("version")),
            "artifact": wheel,
        }

    tool = lock.get("tool")
    intent = tool.get("ai_scalper") if isinstance(tool, Mapping) else None
    bootstrap = intent.get("bootstrap-wheels") if isinstance(intent, Mapping) else None
    if not isinstance(bootstrap, list):
        raise ManifestBuildError("bootstrap wheel set is missing")
    for entry in bootstrap:
        if not isinstance(entry, Mapping):
            raise ManifestBuildError("bootstrap wheel entry is invalid")
        name = _normalized_name(entry.get("name"))
        if name in selected:
            raise ManifestBuildError(f"duplicate locked package: {name}")
        selected[name] = {
            "name": name,
            "version": str(entry.get("version")),
            "artifact": entry,
        }
    return selected


def _materialize_wheel(
    artifact: Mapping[str, object],
    *,
    lock_directory: Path,
    wheel_directory: Path,
    download: bool,
) -> Path:
    filename = _artifact_filename(artifact)
    destination = wheel_directory / filename
    relative = artifact.get("path")
    if relative is not None:
        source = lock_directory / str(relative)
        if not source.is_file() or source.is_symlink():
            raise ManifestBuildError(f"vendored wheel is unavailable: {relative}")
        if not destination.exists():
            shutil.copy2(source, destination)
    elif not destination.exists():
        if not download:
            raise ManifestBuildError(f"locked wheel is missing: {filename}")
        url = artifact.get("url")
        if not isinstance(url, str):
            raise ManifestBuildError(f"wheel URL is invalid: {filename}")
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname != "files.pythonhosted.org":
            raise ManifestBuildError(f"wheel origin is unapproved: {filename}")
        temporary = destination.with_suffix(destination.suffix + ".partial")
        with urlopen(url, timeout=60) as response, temporary.open("xb") as output:
            shutil.copyfileobj(response, output)
        temporary.replace(destination)

    raw = destination.read_bytes()
    expected_size = artifact.get("size")
    if not isinstance(expected_size, int) or len(raw) != expected_size:
        raise ManifestBuildError(f"locked wheel size mismatch: {filename}")
    expected_sha256 = _artifact_sha256(artifact)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ManifestBuildError(f"locked wheel SHA-256 mismatch: {filename}")
    return destination


def _site_path(recorded_path: str, data_prefix: str | None) -> str | None:
    path = _safe_archive_path(recorded_path)
    if data_prefix is None or path.parts[0] != data_prefix:
        return path.as_posix()
    if len(path.parts) < 3:
        raise ManifestBuildError(f"wheel .data path is invalid: {recorded_path}")
    scheme = path.parts[1]
    if scheme == "scripts":
        return None
    if scheme not in {"purelib", "platlib"}:
        raise ManifestBuildError(
            f"unsupported wheel install scheme: {recorded_path}"
        )
    site_path = PurePosixPath(*path.parts[2:])
    if not site_path.parts:
        raise ManifestBuildError(f"wheel library path is empty: {recorded_path}")
    return site_path.as_posix()


def _console_scripts(archive: zipfile.ZipFile, dist_info: str) -> list[str]:
    entry_points_path = f"{dist_info}/entry_points.txt"
    try:
        text = archive.read(entry_points_path).decode("utf-8")
    except KeyError:
        return []
    except UnicodeDecodeError as exc:
        raise ManifestBuildError("wheel entry_points.txt is not UTF-8") from exc
    section = ""
    scripts: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if section == "console_scripts":
            name, separator, _ = line.partition("=")
            candidate = name.strip()
            if not separator or not candidate or any(
                character in candidate for character in "/\\\x00"
            ):
                raise ManifestBuildError("wheel console script name is invalid")
            scripts.append(candidate)
    return sorted(set(scripts))


def _wheel_manifest_entry(
    *,
    name: str,
    version: str,
    artifact: Mapping[str, object],
    wheel_path: Path,
) -> tuple[dict[str, object], dict[str, str]]:
    raw_wheel = wheel_path.read_bytes()
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw_wheel))
    except zipfile.BadZipFile as exc:
        raise ManifestBuildError(f"wheel ZIP is invalid: {wheel_path.name}") from exc
    with archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        if len(names) != len(set(names)):
            raise ManifestBuildError(f"wheel has duplicate paths: {wheel_path.name}")
        casefolded_names = [_windows_path_key(name) for name in names]
        if len(casefolded_names) != len(set(casefolded_names)):
            raise ManifestBuildError(
                f"wheel has Windows path collisions: {wheel_path.name}"
            )
        for item in archive.infolist():
            if item.is_dir():
                continue
            _safe_archive_path(item.filename)
            if (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise ManifestBuildError(f"wheel contains a symlink: {item.filename}")

        record_candidates = [
            candidate
            for candidate in names
            if candidate.endswith(".dist-info/RECORD")
            and len(PurePosixPath(candidate).parts) == 2
        ]
        if len(record_candidates) != 1:
            raise ManifestBuildError(f"wheel RECORD is ambiguous: {wheel_path.name}")
        record_path = record_candidates[0]
        dist_info = PurePosixPath(record_path).parent.as_posix()
        data_prefix = dist_info.removesuffix(".dist-info") + ".data"
        record_bytes = archive.read(record_path)
        try:
            rows = list(
                csv.reader(
                    io.StringIO(record_bytes.decode("utf-8")),
                    strict=True,
                )
            )
        except (UnicodeDecodeError, csv.Error) as exc:
            raise ManifestBuildError(
                f"wheel RECORD is invalid: {wheel_path.name}"
            ) from exc

        seen: set[str] = set()
        site_files: list[dict[str, object]] = []
        site_path_owners: dict[str, str] = {}
        wheel_scripts: set[str] = set()
        record_seen = False
        for row in rows:
            if len(row) != 3 or not row[0] or row[0] in seen:
                raise ManifestBuildError(
                    f"wheel RECORD row is invalid: {wheel_path.name}"
                )
            recorded_path, hash_value, size_value = row
            seen.add(recorded_path)
            _safe_archive_path(recorded_path)
            if recorded_path == record_path:
                if record_seen or hash_value or size_value:
                    raise ManifestBuildError(
                        f"wheel RECORD self-row is invalid: {wheel_path.name}"
                    )
                record_seen = True
                continue
            if not hash_value or not size_value or not size_value.isdecimal():
                raise ManifestBuildError(
                    f"wheel RECORD entry is unhashed: {recorded_path}"
                )
            try:
                content = archive.read(recorded_path)
            except KeyError as exc:
                raise ManifestBuildError(
                    f"wheel RECORD file is missing: {recorded_path}"
                ) from exc
            expected_sha256 = _decode_record_sha256(hash_value, recorded_path)
            if len(content) != int(size_value):
                raise ManifestBuildError(
                    f"wheel RECORD size mismatch: {recorded_path}"
                )
            if hashlib.sha256(content).hexdigest() != expected_sha256:
                raise ManifestBuildError(
                    f"wheel RECORD hash mismatch: {recorded_path}"
                )
            installed_path = _site_path(recorded_path, data_prefix)
            if installed_path is None:
                path = PurePosixPath(recorded_path)
                if (
                    path.parts[0] != data_prefix
                    or len(path.parts) < 3
                    or path.parts[1] != "scripts"
                ):
                    raise ManifestBuildError(
                        f"wheel non-library path is unsupported: {recorded_path}"
                    )
                script_name = path.name
                if any(character in script_name for character in "/\\:\x00"):
                    raise ManifestBuildError(
                        f"wheel script name is invalid: {recorded_path}"
                    )
                wheel_scripts.add(script_name)
                continue
            installed = PurePosixPath(installed_path)
            if (
                installed.name.lower() in FORBIDDEN_SITE_NAMES
                or installed.suffix.lower() in FORBIDDEN_SITE_SUFFIXES
                or (
                    installed.parent.as_posix() == dist_info
                    and installed.name in FORBIDDEN_GENERATED_METADATA
                )
            ):
                raise ManifestBuildError(
                    f"wheel contains forbidden startup file: {installed_path}"
                )
            installed_key = _windows_path_key(installed_path)
            if installed_key in site_path_owners:
                raise ManifestBuildError(
                    f"wheel site-packages paths collide: {installed_path}"
                )
            site_path_owners[installed_key] = installed_path
            site_files.append(
                {
                    "path": installed_path,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size": int(size_value),
                }
            )
        if not record_seen:
            raise ManifestBuildError(
                f"wheel RECORD self-row is missing: {wheel_path.name}"
            )
        if seen != set(names):
            extra = sorted(set(names) - seen)
            raise ManifestBuildError(
                f"wheel contains files outside RECORD: "
                f"{wheel_path.name}:{','.join(extra[:3])}"
            )
        if len(site_files) != len({entry["path"] for entry in site_files}):
            raise ManifestBuildError(
                f"wheel site-packages paths overlap: {wheel_path.name}"
            )
        site_files.sort(key=lambda entry: str(entry["path"]))
        scripts = set(_console_scripts(archive, dist_info)) | wheel_scripts
        if name == "pip":
            scripts.add("pip3.12")
        entry = {
            "name": name,
            "version": version,
            "wheel_filename": wheel_path.name,
            "wheel_size": len(raw_wheel),
            "wheel_sha256": hashlib.sha256(raw_wheel).hexdigest(),
            "record_path": record_path,
            "wheel_record_sha256": hashlib.sha256(record_bytes).hexdigest(),
            "site_packages_file_count": len(site_files),
            "site_packages_tree_sha256": _canonical_sha256(site_files),
            "console_scripts": sorted(scripts),
        }
        return entry, site_path_owners


def build_manifest(
    lock_path: Path,
    wheel_directory: Path,
    *,
    download: bool,
) -> dict[str, object]:
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    wheel_directory.mkdir(parents=True, exist_ok=True)
    package_entries: dict[str, dict[str, object]] = {}
    global_site_paths: dict[str, tuple[str, str]] = {}
    for name, locked in sorted(_locked_wheels(lock).items()):
        artifact = locked["artifact"]
        if not isinstance(artifact, Mapping):
            raise ManifestBuildError(f"wheel artifact is invalid: {name}")
        wheel_path = _materialize_wheel(
            artifact,
            lock_directory=lock_path.parent,
            wheel_directory=wheel_directory,
            download=download,
        )
        entry, site_paths = _wheel_manifest_entry(
            name=name,
            version=str(locked["version"]),
            artifact=artifact,
            wheel_path=wheel_path,
        )
        package_entries[name] = entry
        for path_key, original_path in site_paths.items():
            previous = global_site_paths.get(path_key)
            if previous is not None:
                raise ManifestBuildError(
                    f"cross-package wheel ownership overlap: "
                    f"{previous[0]},{name}:{original_path}"
                )
            global_site_paths[path_key] = (name, original_path)
    body = {
        "schema_version": SCHEMA_VERSION,
        "target": TARGET,
        "packages": package_entries,
    }
    return {**body, "payload_sha256": _canonical_sha256(body)}


def _write_json_create_or_replace(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(
            payload,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    path.write_text(encoded, encoding="utf-8")


def _write_hashed_requirements(
    path: Path,
    packages: Mapping[str, Mapping[str, object]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Generated from vendor/windows-cp312-install-manifest.json.",
        "# Install only with --no-index, --find-links, --require-hashes, and --no-deps.",
    ]
    for name, entry in sorted(packages.items()):
        lines.append(
            f"{name}=={entry['version']} "
            f"--hash=sha256:{entry['wheel_sha256']}"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=Path("pylock.windows-cp312.toml"))
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("vendor/windows-cp312-install-manifest.json"),
    )
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--bootstrap-requirements-output", type=Path)
    parser.add_argument("--runtime-requirements-output", type=Path)
    args = parser.parse_args()
    manifest = build_manifest(
        args.lock.resolve(),
        args.wheel_dir.resolve(),
        download=args.download,
    )
    _write_json_create_or_replace(args.output, manifest)
    packages = manifest["packages"]
    if not isinstance(packages, Mapping):
        raise ManifestBuildError("manifest package set is invalid")
    if args.bootstrap_requirements_output is not None:
        _write_hashed_requirements(
            args.bootstrap_requirements_output,
            {"pip": packages["pip"]},
        )
    if args.runtime_requirements_output is not None:
        _write_hashed_requirements(
            args.runtime_requirements_output,
            {
                name: entry
                for name, entry in packages.items()
                if name != "pip"
            },
        )
    raw = args.output.read_bytes()
    print(f"Manifest written: {args.output}")
    print(f"SHA-256: {hashlib.sha256(raw).hexdigest()}")
    print(f"Size: {len(raw)}")
    print(f"Packages: {len(manifest['packages'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
