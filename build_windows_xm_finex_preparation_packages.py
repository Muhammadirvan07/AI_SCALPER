"""Build deterministic, source-bound XM and FINEX preparation packages.

The XM artifact is a Japan legal-hold verifier and never initializes MT5. The
FINEX artifact may invoke only the existing sanitized read-only preflight.
Neither artifact contains discovery, credential, task-installation, execution,
or broker-mutation capability.
"""

from __future__ import annotations

import argparse
import base64
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import Any, Mapping
import zipfile


REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_PROFILE_PATH = (
    REPO_ROOT / "config/windows_broker_preparation_profiles.v1.json"
)
PROFILE_SCHEMA = "ai-scalper-windows-broker-preparation-profiles-v1"
MANIFEST_SCHEMA = "ai-scalper-windows-broker-preparation-manifest-v1"
ARCHIVE_MANIFEST_SCHEMA = "ai-scalper-windows-broker-preparation-archive-v1"
INTERNAL_MANIFEST_NAME = "BROKER_PREPARATION_MANIFEST.json"
INTERNAL_PROFILE_NAME = "BROKER_PREPARATION_PROFILE.json"
INTERNAL_README_NAME = "README.md"
REQUIRED_SAFETY = {
    "live_allowed": False,
    "safe_to_demo_auto_order": False,
    "promotion_eligible": False,
    "max_lot": 0.01,
    "order_capability": "DISABLED",
}
EXPECTED_CANDIDATES = frozenset({"xm", "finex"})
LOWER_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
LOWER_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_FILES = 20
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
FORBIDDEN_OPERATOR_TOKENS = (
    "order_send",
    "order_check",
    "Register-ScheduledTask",
    "Start-ScheduledTask",
    "CredRead",
    "CredWrite",
)
TEMPLATE_TOKENS = (
    "__EXPECTED_COMMIT__",
    "__EXPECTED_TREE__",
    "__OFFICIAL_BRANCH__",
    "__REQUIRED_FILES_JSON_BASE64__",
)


class PackageBuildError(RuntimeError):
    """Raised when preparation packaging cannot preserve its safety contract."""


FileIdentity = tuple[int, int, int, int, int, int]
CreatedFileIdentity = FileIdentity
DirectoryIdentity = tuple[int, int, int, int]


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)


def _file_identity(metadata: os.stat_result) -> FileIdentity:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _created_file_identity(metadata: os.stat_result) -> CreatedFileIdentity:
    return _file_identity(metadata)


def _directory_identity(metadata: os.stat_result) -> DirectoryIdentity:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _sync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_created_file(
    path: Path,
    identity: CreatedFileIdentity | None,
) -> None:
    if identity is None:
        return
    try:
        observed = path.lstat()
    except OSError:
        return
    if (
        not stat.S_ISREG(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or _is_reparse(observed)
        or _created_file_identity(observed) != identity
    ):
        return
    try:
        path.unlink()
    except OSError:
        pass


def _remove_if_same(path: Path, identity: FileIdentity) -> None:
    try:
        observed = path.lstat()
    except OSError:
        return
    if (
        not stat.S_ISREG(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or _is_reparse(observed)
        or _file_identity(observed) != identity
    ):
        return
    try:
        path.unlink()
    except OSError:
        pass


def _cleanup_created_root(
    root: Path,
    root_identity: DirectoryIdentity,
    files: list[tuple[Path, FileIdentity]],
) -> None:
    try:
        observed_root = root.lstat()
    except OSError:
        return
    if (
        not stat.S_ISDIR(observed_root.st_mode)
        or stat.S_ISLNK(observed_root.st_mode)
        or _is_reparse(observed_root)
        or _directory_identity(observed_root) != root_identity
    ):
        return
    for path, identity in reversed(files):
        try:
            current_root = root.lstat()
        except OSError:
            return
        if _directory_identity(current_root) != root_identity:
            return
        _remove_if_same(path, identity)
    try:
        current_root = root.lstat()
        if _directory_identity(current_root) == root_identity:
            root.rmdir()
    except OSError:
        pass


def _create_output_root(path: Path) -> tuple[Path, DirectoryIdentity]:
    candidate = path.expanduser().absolute()
    if candidate.name in {"", ".", ".."}:
        raise PackageBuildError("output root is invalid")
    try:
        candidate.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise PackageBuildError("output root is unavailable") from exc
    else:
        raise PackageBuildError("output root already exists")

    parent = candidate.parent
    try:
        parent_metadata = parent.lstat()
        resolved_parent = parent.resolve(strict=True)
    except OSError as exc:
        raise PackageBuildError("output parent must already exist") from exc
    parent_identity = _directory_identity(parent_metadata)
    if (
        parent != resolved_parent
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or stat.S_ISLNK(parent_metadata.st_mode)
        or _is_reparse(parent_metadata)
    ):
        raise PackageBuildError("output parent must be a real directory")

    try:
        os.mkdir(candidate, 0o700)
    except FileExistsError as exc:
        raise PackageBuildError("output root already exists") from exc
    except OSError as exc:
        raise PackageBuildError("output root creation failed") from exc

    try:
        root_metadata = candidate.lstat()
        current_parent = parent.lstat()
    except OSError as exc:
        raise PackageBuildError("output root identity is unstable") from exc
    root_identity = _directory_identity(root_metadata)
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_ISLNK(root_metadata.st_mode)
        or _is_reparse(root_metadata)
        or _directory_identity(current_parent) != parent_identity
    ):
        raise PackageBuildError("output root identity is unstable")
    try:
        _sync_directory(parent)
    except OSError as exc:
        _cleanup_created_root(candidate, root_identity, [])
        raise PackageBuildError("output root synchronization failed") from exc
    return candidate, root_identity


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git(repo_root: Path, *args: str) -> bytes:
    try:
        completed = subprocess.run(
            ("git", *args),
            cwd=repo_root,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PackageBuildError(
            "Git source identity inspection failed"
        ) from exc
    return completed.stdout


def _git_text(repo_root: Path, *args: str) -> str:
    try:
        return _git(repo_root, *args).decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise PackageBuildError("Git source identity is not UTF-8") from exc


def _normalize_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise PackageBuildError("profile path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise PackageBuildError("profile path is invalid")
    normalized = path.as_posix()
    if normalized != value:
        raise PackageBuildError("profile path is not canonical")
    return normalized


def _required_bool_map(value: object, expected: Mapping[str, bool]) -> dict[str, bool]:
    if not isinstance(value, dict) or set(value) != set(expected):
        raise PackageBuildError("profile capability or eligibility fields drift")
    result = {str(key): item for key, item in value.items()}
    for key, item in expected.items():
        if result[key] is not item:
            raise PackageBuildError("profile capability or eligibility safety drift")
    return result


def load_profiles(path: Path) -> dict[str, dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageBuildError("broker preparation profiles are invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "official_branch",
        "safety",
        "profiles",
    }:
        raise PackageBuildError("broker preparation profile fields drift")
    if payload["schema_version"] != PROFILE_SCHEMA:
        raise PackageBuildError("broker preparation profile schema drift")
    if payload["official_branch"] != "agent/live-grade-phase3":
        raise PackageBuildError("official branch policy drift")
    if payload["safety"] != REQUIRED_SAFETY:
        raise PackageBuildError("broker preparation safety policy drift")
    raw_profiles = payload["profiles"]
    if not isinstance(raw_profiles, list) or len(raw_profiles) != 2:
        raise PackageBuildError("exactly two preparation profiles are required")
    profiles: dict[str, dict[str, Any]] = {}
    expected_fields = {
        "candidate_id",
        "release_profile",
        "archive_name",
        "helper_name",
        "operator_template_path",
        "operator_entry_point",
        "default_extraction_root",
        "eligibility",
        "capabilities",
        "instrument_claims",
        "required_repo_files",
    }
    for raw in raw_profiles:
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise PackageBuildError("candidate preparation profile fields drift")
        candidate = raw.get("candidate_id")
        if candidate not in EXPECTED_CANDIDATES or candidate in profiles:
            raise PackageBuildError("candidate preparation profile is invalid")
        profile = dict(raw)
        for name in (
            "archive_name",
            "helper_name",
            "operator_template_path",
            "operator_entry_point",
        ):
            profile[name] = _normalize_relative_path(profile[name])
        if "/" in profile["archive_name"] or not profile["archive_name"].endswith(".zip"):
            raise PackageBuildError("archive name is invalid")
        if "/" in profile["helper_name"] or not profile["helper_name"].endswith(".ps1"):
            raise PackageBuildError("helper name is invalid")
        if "/" in profile["operator_entry_point"]:
            raise PackageBuildError("operator entry point must be a flat member")
        root = profile.get("default_extraction_root")
        if not isinstance(root, str) or not root.startswith("C:\\AI_SCALPER_PRIVATE\\"):
            raise PackageBuildError("default extraction root is invalid")
        expected_eligibility = {
            "operating_jurisdiction": "JP",
            "status": (
                "LEGAL_BLOCKED_CURRENT_JAPAN"
                if candidate == "xm"
                else "PREPARATION_ONLY_ELIGIBILITY_PENDING"
            ),
            "discovery_allowed": False,
            "contract_registration_allowed": False,
            "task_installation_allowed": False,
        }
        if profile.get("eligibility") != expected_eligibility:
            raise PackageBuildError("candidate eligibility policy drift")
        expected_capabilities = {
            "read_only_preflight_allowed": candidate == "finex",
            "mt5_initialization_allowed": candidate == "finex",
            "credential_access_allowed": False,
            "evidence_creation_allowed": False,
        }
        _required_bool_map(profile.get("capabilities"), expected_capabilities)
        claims = profile.get("instrument_claims")
        if not isinstance(claims, dict) or set(claims) != {
            "reviewed_categories",
            "crypto_status",
            "broker_symbol_map_added",
            "official_sources",
        }:
            raise PackageBuildError("instrument claim fields drift")
        expected_crypto = (
            "ACCOUNT_ENTITY_DISCOVERY_REQUIRED"
            if candidate == "xm"
            else "NOT_LISTED_IN_REVIEWED_OFFICIAL_INVENTORY"
        )
        if (
            claims.get("crypto_status") != expected_crypto
            or claims.get("broker_symbol_map_added") is not False
            or not isinstance(claims.get("reviewed_categories"), list)
            or not isinstance(claims.get("official_sources"), list)
        ):
            raise PackageBuildError("instrument claim policy drift")
        claims_text = json.dumps(claims, ensure_ascii=False)
        if "BTCUSD" in claims_text or "ETHUSD" in claims_text:
            raise PackageBuildError("unverified crypto symbol binding is forbidden")
        raw_required = profile.get("required_repo_files")
        if not isinstance(raw_required, list) or not raw_required:
            raise PackageBuildError("required repository inventory is missing")
        required = [_normalize_relative_path(item) for item in raw_required]
        if (
            len(required) != len(set(required))
            or len({item.casefold() for item in required}) != len(required)
        ):
            raise PackageBuildError("required repository inventory collides")
        profile["required_repo_files"] = required
        profiles[candidate] = profile
    if set(profiles) != EXPECTED_CANDIDATES:
        raise PackageBuildError("XM and FINEX profiles must both be present")
    if len({item["archive_name"].casefold() for item in profiles.values()}) != 2:
        raise PackageBuildError("candidate archives must be isolated")
    if len({item["default_extraction_root"].casefold() for item in profiles.values()}) != 2:
        raise PackageBuildError("candidate extraction roots must be isolated")
    return profiles


def _git_blob(repo_root: Path, relative: str) -> bytes:
    return _git(repo_root, "show", f"HEAD:{relative}")


def _verified_git_blob(repo_root: Path, relative: str) -> bytes:
    blob = _git_blob(repo_root, relative)
    path = repo_root / relative
    try:
        working = path.read_bytes()
    except OSError as exc:
        raise PackageBuildError(f"required source is unavailable: {relative}") from exc
    if working != blob:
        raise PackageBuildError(f"required source differs from Git: {relative}")
    return blob


def _records(repo_root: Path, paths: list[str]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for relative in sorted(paths):
        value = _verified_git_blob(repo_root, relative)
        if not value:
            raise PackageBuildError(f"required source is empty: {relative}")
        records.append(
            {
                "path": relative,
                "sha256": _sha256(value),
                "size_bytes": len(value),
            }
        )
    return records


def _render_operator(
    template: bytes,
    *,
    commit: str,
    tree: str,
    branch: str,
    required_records: list[dict[str, object]],
) -> bytes:
    try:
        text = template.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PackageBuildError("operator template must be UTF-8") from exc
    replacements = {
        "__EXPECTED_COMMIT__": commit,
        "__EXPECTED_TREE__": tree,
        "__OFFICIAL_BRANCH__": branch,
        "__REQUIRED_FILES_JSON_BASE64__": base64.b64encode(
            _canonical_json(required_records)
        ).decode("ascii"),
    }
    for token in TEMPLATE_TOKENS:
        if text.count(token) != 1:
            raise PackageBuildError(f"operator template token drift: {token}")
        text = text.replace(token, replacements[token])
    for token in FORBIDDEN_OPERATOR_TOKENS:
        if token.casefold() in text.casefold():
            raise PackageBuildError(f"forbidden operator capability: {token}")
    return text.encode("utf-8")


def _readme(profile: Mapping[str, Any], commit: str, tree: str) -> bytes:
    candidate = str(profile["candidate_id"]).upper()
    status = str(profile["eligibility"]["status"])
    entry = str(profile["operator_entry_point"])
    text = (
        f"# {candidate} Windows Preparation V1\n\n"
        f"Eligibility: `{status}`\n\n"
        f"Source commit: `{commit}`\n\n"
        f"Source tree: `{tree}`\n\n"
        f"Run `{entry}` only after extracting with the companion helper. "
        "This package is preparation-only. Discovery, contract registration, "
        "task installation, promotion, and every order capability remain disabled.\n"
    )
    return text.encode("utf-8")


def _zip_bytes(files: Mapping[str, bytes]) -> bytes:
    if not files or len(files) > MAX_ARCHIVE_FILES:
        raise PackageBuildError("archive file count is invalid")
    if len({name.casefold() for name in files}) != len(files):
        raise PackageBuildError("archive member path collision")
    output = BytesIO()
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for name in sorted(files):
            normalized = _normalize_relative_path(name)
            if "/" in normalized:
                raise PackageBuildError("archive members must be flat")
            info = zipfile.ZipInfo(normalized, FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            info.create_system = 3
            archive.writestr(info, files[name], compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    value = output.getvalue()
    if len(value) > MAX_ARCHIVE_BYTES:
        raise PackageBuildError("archive exceeds the size limit")
    return value


def _member_records(files: Mapping[str, bytes]) -> list[dict[str, object]]:
    return [
        {
            "path": name,
            "sha256": _sha256(files[name]),
            "size_bytes": len(files[name]),
        }
        for name in sorted(files)
    ]


def _write_exclusive(path: Path, value: bytes) -> FileIdentity:
    descriptor: int | None = None
    created_identity: CreatedFileIdentity | None = None
    completed_identity: FileIdentity | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= int(getattr(os, "O_BINARY", 0))
        flags |= int(getattr(os, "O_CLOEXEC", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            created = os.fstat(stream.fileno())
            if not stat.S_ISREG(created.st_mode) or _is_reparse(created):
                raise PackageBuildError("output must be a regular file")
            created_identity = _created_file_identity(created)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
            completed_identity = _file_identity(os.fstat(stream.fileno()))
            created_identity = completed_identity
        _sync_directory(path.parent)
    except PackageBuildError:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        _remove_created_file(path, created_identity)
        raise
    except OSError as exc:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        _remove_created_file(path, created_identity)
        raise PackageBuildError(f"output write failed: {path}") from exc
    if completed_identity is None:
        raise PackageBuildError(f"output write failed: {path}")
    return completed_identity


def _powershell_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _render_helper(
    *,
    archive_name: str,
    archive_sha256: str,
    companion_sha256: str,
    release_identity: str,
    commit: str,
    tree: str,
    default_destination: str,
    candidate: str,
) -> bytes:
    values = {
        "archive_name": _powershell_literal(archive_name),
        "archive_sha256": _powershell_literal(archive_sha256),
        "companion_sha256": _powershell_literal(companion_sha256),
        "release_identity": _powershell_literal(release_identity),
        "commit": _powershell_literal(commit),
        "tree": _powershell_literal(tree),
        "destination": _powershell_literal(default_destination),
        "candidate": _powershell_literal(candidate),
    }
    text = r'''[CmdletBinding()]
param(
  [Parameter()]
  [string]$ArchivePath = (Join-Path $PSScriptRoot __ARCHIVE_NAME__),

  [Parameter()]
  [string]$ManifestPath = (Join-Path $PSScriptRoot (__ARCHIVE_NAME__ + ".manifest.json")),

  [Parameter()]
  [string]$Destination = __DESTINATION__
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$expectedArchiveSHA256 = __ARCHIVE_SHA256__
$expectedManifestSHA256 = __COMPANION_SHA256__
$expectedReleaseIdentity = __RELEASE_IDENTITY__
$expectedCommit = __COMMIT__
$expectedTree = __TREE__
$expectedCandidate = __CANDIDATE__

function Assert-ExactExtractedInventory {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Root,

    [Parameter(Mandatory = $true)]
    [object[]]$ExpectedFiles
  )
  $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
  if (
    -not $rootItem.PSIsContainer -or
    (($rootItem.Attributes -band
      [System.IO.FileAttributes]::ReparsePoint) -ne 0)
  ) {
    throw "EXTRACTED_ROOT_TYPE_INVALID"
  }
  $observed = @(Get-ChildItem -LiteralPath $Root -Force)
  if ($observed.Count -ne $ExpectedFiles.Count) {
    throw "EXTRACTED_MEMBER_INVENTORY_MISMATCH"
  }
  foreach ($item in $observed) {
    if (
      $item.PSIsContainer -or
      (($item.Attributes -band
        [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    ) {
      throw "EXTRACTED_MEMBER_TYPE_INVALID"
    }
    $expected = @(
      $ExpectedFiles | Where-Object { $_.path -ceq $item.Name }
    )
    if ($expected.Count -ne 1) {
      throw "EXTRACTED_MEMBER_INVENTORY_MISMATCH"
    }
    $digest = (
      Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if (
      $item.Length -ne [long]$expected[0].size_bytes -or
      $digest -ne [string]$expected[0].sha256
    ) {
      throw "EXTRACTED_MEMBER_HASH_MISMATCH"
    }
  }
}

foreach ($path in @($ArchivePath, $ManifestPath)) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "TRANSFER_FILE_MISSING: $path"
  }
}
if (-not [System.IO.Path]::IsPathFullyQualified($Destination)) {
  throw "DESTINATION_PATH_INVALID"
}
$destinationFull = [System.IO.Path]::GetFullPath($Destination)
$destinationParentPath = [System.IO.Path]::GetDirectoryName($destinationFull)
$destinationLeaf = [System.IO.Path]::GetFileName($destinationFull)
if (
  [string]::IsNullOrWhiteSpace($destinationParentPath) -or
  [string]::IsNullOrWhiteSpace($destinationLeaf)
) {
  throw "DESTINATION_PATH_INVALID"
}
$destinationParent = Get-Item `
  -LiteralPath $destinationParentPath `
  -Force `
  -ErrorAction Stop
if (
  -not $destinationParent.PSIsContainer -or
  (($destinationParent.Attributes -band
    [System.IO.FileAttributes]::ReparsePoint) -ne 0)
) {
  throw "DESTINATION_PARENT_INVALID"
}
if (Test-Path -LiteralPath $Destination) {
  throw "DESTINATION_ALREADY_EXISTS"
}

$archiveHash = (
  Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256
).Hash.ToLowerInvariant()
$manifestHash = (
  Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($archiveHash -ne $expectedArchiveSHA256) {
  throw "ARCHIVE_HASH_MISMATCH"
}
if ($manifestHash -ne $expectedManifestSHA256) {
  throw "COMPANION_MANIFEST_HASH_MISMATCH"
}

$companion = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
if (
  $companion.archive_name -ne [System.IO.Path]::GetFileName($ArchivePath) -or
  $companion.archive_sha256 -ne $expectedArchiveSHA256 -or
  $companion.release_identity_sha256 -ne $expectedReleaseIdentity -or
  $companion.git_commit -ne $expectedCommit -or
  $companion.git_tree -ne $expectedTree
) {
  throw "COMPANION_MANIFEST_IDENTITY_MISMATCH"
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
try {
  $entries = @($zip.Entries)
  $expectedFiles = @($companion.files)
  $actualNames = @($entries | ForEach-Object { $_.FullName } | Sort-Object)
  $expectedNames = @($expectedFiles | ForEach-Object { $_.path } | Sort-Object)
  if (($actualNames -join "|") -ne ($expectedNames -join "|")) {
    throw "ARCHIVE_MEMBER_INVENTORY_MISMATCH"
  }
  foreach ($entry in $entries) {
    if (
      [string]::IsNullOrWhiteSpace($entry.Name) -or
      $entry.FullName -ne $entry.Name -or
      $entry.FullName.Contains("..") -or
      (($entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000
    ) {
      throw "ARCHIVE_MEMBER_PATH_INVALID"
    }
    $expected = @(
      $expectedFiles | Where-Object { $_.path -eq $entry.FullName }
    )
    if ($expected.Count -ne 1 -or $entry.Length -ne [long]$expected[0].size_bytes) {
      throw "ARCHIVE_MEMBER_SIZE_MISMATCH"
    }
    $stream = $entry.Open()
    try {
      $sha = [System.Security.Cryptography.SHA256]::Create()
      try {
        $hashBytes = $sha.ComputeHash($stream)
      }
      finally {
        $sha.Dispose()
      }
    }
    finally {
      $stream.Dispose()
    }
    $hash = ([System.BitConverter]::ToString($hashBytes)).Replace("-", "").ToLowerInvariant()
    if ($hash -ne [string]$expected[0].sha256) {
      throw "ARCHIVE_MEMBER_HASH_MISMATCH"
    }
  }

  $manifestEntry = @(
    $entries | Where-Object { $_.FullName -eq "BROKER_PREPARATION_MANIFEST.json" }
  )
  if ($manifestEntry.Count -ne 1) {
    throw "INTERNAL_MANIFEST_MISSING"
  }
  $reader = [System.IO.StreamReader]::new(
    $manifestEntry[0].Open(),
    [System.Text.UTF8Encoding]::new($false),
    $true
  )
  try {
    $internal = $reader.ReadToEnd() | ConvertFrom-Json
  }
  finally {
    $reader.Dispose()
  }
  if (
    $internal.release_identity_sha256 -ne $expectedReleaseIdentity -or
    $internal.git_commit -ne $expectedCommit -or
    $internal.git_tree -ne $expectedTree -or
    $internal.candidate_id -ne $expectedCandidate
  ) {
    throw "INTERNAL_MANIFEST_IDENTITY_MISMATCH"
  }

  $stagingPath = Join-Path $destinationParent.FullName (
    "." + $destinationLeaf + ".staging-" +
    [System.Guid]::NewGuid().ToString("N")
  )
  if (Test-Path -LiteralPath $stagingPath) {
    throw "EXTRACTION_STAGING_COLLISION"
  }
  try {
    [System.IO.Directory]::CreateDirectory($stagingPath) | Out-Null
    $stagingItem = Get-Item `
      -LiteralPath $stagingPath `
      -Force `
      -ErrorAction Stop
    if (
      -not $stagingItem.PSIsContainer -or
      (($stagingItem.Attributes -band
        [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    ) {
      throw "EXTRACTION_STAGING_INVALID"
    }

    foreach ($entry in $entries) {
      $target = Join-Path $stagingPath $entry.FullName
      $sourceStream = $entry.Open()
      try {
        $targetStream = [System.IO.File]::Open(
          $target,
          [System.IO.FileMode]::CreateNew,
          [System.IO.FileAccess]::Write,
          [System.IO.FileShare]::None
        )
        try {
          $sourceStream.CopyTo($targetStream)
          $targetStream.Flush($true)
        }
        finally {
          $targetStream.Dispose()
        }
      }
      finally {
        $sourceStream.Dispose()
      }
    }

    Assert-ExactExtractedInventory `
      -Root $stagingPath `
      -ExpectedFiles $expectedFiles
    [System.IO.Directory]::Move($stagingPath, $destinationFull)
    $stagingPath = $null
    Assert-ExactExtractedInventory `
      -Root $destinationFull `
      -ExpectedFiles $expectedFiles
  }
  catch {
    throw (
      "PACKAGE_EXTRACTION_FAILED_PRESERVE_STAGING: " +
      [string]$stagingPath + ". " + $_.Exception.Message
    )
  }
}
finally {
  $zip.Dispose()
}

[PSCustomObject]@{
  Status = "BROKER_PREPARATION_PACKAGE_EXTRACTED_VERIFIED"
  Candidate = $expectedCandidate
  Destination = $destinationFull
  ArchiveSHA256 = $expectedArchiveSHA256
  ReleaseIdentitySHA256 = $expectedReleaseIdentity
  SourceCommit = $expectedCommit
  SourceTree = $expectedTree
  OrderCapability = "DISABLED"
  BrokerMutation = "NOT_PERFORMED"
} | Format-List
'''
    replacements = {
        "__ARCHIVE_NAME__": values["archive_name"],
        "__ARCHIVE_SHA256__": values["archive_sha256"],
        "__COMPANION_SHA256__": values["companion_sha256"],
        "__RELEASE_IDENTITY__": values["release_identity"],
        "__COMMIT__": values["commit"],
        "__TREE__": values["tree"],
        "__DESTINATION__": values["destination"],
        "__CANDIDATE__": values["candidate"],
    }
    for token, value in replacements.items():
        text = text.replace(token, value)
    return text.encode("utf-8")


def _build_one(
    repo_root: Path,
    output_root: Path,
    profile: dict[str, Any],
    created_outputs: list[tuple[Path, FileIdentity]],
    *,
    commit: str,
    tree: str,
    official_branch: str,
) -> dict[str, object]:
    required_records = _records(repo_root, profile["required_repo_files"])
    template = _verified_git_blob(repo_root, profile["operator_template_path"])
    operator = _render_operator(
        template,
        commit=commit,
        tree=tree,
        branch=official_branch,
        required_records=required_records,
    )
    profile_member = _canonical_json(profile) + b"\n"
    readme = _readme(profile, commit, tree)
    source_members = {
        profile["operator_entry_point"]: operator,
        INTERNAL_PROFILE_NAME: profile_member,
        INTERNAL_README_NAME: readme,
    }
    manifest_body: dict[str, object] = {
        "schema_version": MANIFEST_SCHEMA,
        "release_profile": profile["release_profile"],
        "candidate_id": profile["candidate_id"],
        "git_commit": commit,
        "git_tree": tree,
        "official_branch": official_branch,
        "source_files": _member_records(source_members),
        "required_repo_files": required_records,
        "safety": REQUIRED_SAFETY,
        "eligibility": profile["eligibility"],
        "capabilities": profile["capabilities"],
        "instrument_claims": profile["instrument_claims"],
        "operator_entry_point": profile["operator_entry_point"],
        "default_extraction_root": profile["default_extraction_root"],
        "effects_during_build": {
            "credential_access": "NOT_PERFORMED",
            "discovery": "NOT_PERFORMED",
            "contract_registration": "NOT_PERFORMED",
            "task_installation": "NOT_PERFORMED",
            "broker_mutation": "NOT_PERFORMED",
        },
        "production_execution_ready": False,
    }
    release_identity = _sha256(_canonical_json(manifest_body))
    manifest = dict(manifest_body)
    manifest["release_identity_sha256"] = release_identity
    files = dict(source_members)
    files[INTERNAL_MANIFEST_NAME] = _canonical_json(manifest) + b"\n"
    archive = _zip_bytes(files)
    archive_sha256 = _sha256(archive)
    archive_name = profile["archive_name"]
    archive_path = output_root / archive_name
    created_outputs.append(
        (archive_path, _write_exclusive(archive_path, archive))
    )

    companion: dict[str, object] = {
        "schema_version": ARCHIVE_MANIFEST_SCHEMA,
        "archive_name": archive_name,
        "archive_sha256": archive_sha256,
        "archive_size_bytes": len(archive),
        "release_identity_sha256": release_identity,
        "git_commit": commit,
        "git_tree": tree,
        "candidate_id": profile["candidate_id"],
        "files": _member_records(files),
    }
    companion_bytes = _canonical_json(companion) + b"\n"
    companion_name = archive_name + ".manifest.json"
    companion_path = output_root / companion_name
    created_outputs.append(
        (
            companion_path,
            _write_exclusive(companion_path, companion_bytes),
        )
    )
    companion_sha256 = _sha256(companion_bytes)
    helper = _render_helper(
        archive_name=archive_name,
        archive_sha256=archive_sha256,
        companion_sha256=companion_sha256,
        release_identity=release_identity,
        commit=commit,
        tree=tree,
        default_destination=profile["default_extraction_root"],
        candidate=profile["candidate_id"],
    )
    helper_name = profile["helper_name"]
    helper_path = output_root / helper_name
    created_outputs.append(
        (helper_path, _write_exclusive(helper_path, helper))
    )
    return {
        "candidate_id": profile["candidate_id"],
        "archive_name": archive_name,
        "archive_sha256": archive_sha256,
        "archive_size_bytes": len(archive),
        "companion_manifest_name": companion_name,
        "companion_manifest_sha256": companion_sha256,
        "helper_name": helper_name,
        "helper_sha256": _sha256(helper),
        "release_identity_sha256": release_identity,
        "git_commit": commit,
        "git_tree": tree,
        "order_capability": "DISABLED",
        "production_execution_ready": False,
    }


def build_packages(
    repo_root: Path,
    profile_path: Path,
    output_root: Path,
    *,
    official_branch: str,
) -> dict[str, dict[str, object]]:
    repo_root = repo_root.resolve()
    profile_path = profile_path.resolve()
    if not output_root.is_absolute():
        raise PackageBuildError("output root must be absolute")
    try:
        profile_relative = profile_path.relative_to(repo_root).as_posix()
    except ValueError as exc:
        raise PackageBuildError("profile must be inside the source repository") from exc
    profile_blob = _git_blob(repo_root, profile_relative)
    try:
        working_profile = profile_path.read_bytes()
    except OSError as exc:
        raise PackageBuildError("profile source is unavailable") from exc
    if working_profile != profile_blob:
        raise PackageBuildError("profile source differs from Git")
    commit = _git_text(repo_root, "rev-parse", "HEAD")
    tree = _git_text(repo_root, "rev-parse", "HEAD^{tree}")
    branch = _git_text(repo_root, "symbolic-ref", "--short", "HEAD")
    if not LOWER_HEX_40.fullmatch(commit) or not LOWER_HEX_40.fullmatch(tree):
        raise PackageBuildError("Git source identity is invalid")
    if branch != official_branch:
        raise PackageBuildError("source branch does not match the official branch")
    profiles = load_profiles(profile_path)
    if official_branch != "agent/live-grade-phase3":
        raise PackageBuildError("unsupported official branch")
    if _git_text(
        repo_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    ):
        raise PackageBuildError("source checkout must be clean")
    output_root, root_identity = _create_output_root(output_root)
    created_outputs: list[tuple[Path, FileIdentity]] = []
    try:
        results = {
            candidate: _build_one(
                repo_root,
                output_root,
                profiles[candidate],
                created_outputs,
                commit=commit,
                tree=tree,
                official_branch=official_branch,
            )
            for candidate in sorted(profiles)
        }
    except BaseException:
        _cleanup_created_root(
            output_root,
            root_identity,
            created_outputs,
        )
        raise
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build source-bound XM legal-hold and FINEX read-only preparation packages"
    )
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--profiles",
        type=Path,
        default=DEFAULT_PROFILE_PATH,
    )
    parser.add_argument(
        "--branch",
        default="agent/live-grade-phase3",
    )
    args = parser.parse_args(argv)
    try:
        results = build_packages(
            REPO_ROOT,
            args.profiles if args.profiles.is_absolute() else REPO_ROOT / args.profiles,
            args.output_root,
            official_branch=args.branch,
        )
    except PackageBuildError as exc:
        print(f"BROKER_PREPARATION_PACKAGES_REJECTED: {exc}")
        return 2
    print("WINDOWS_XM_FINEX_PREPARATION_PACKAGES_READY")
    print(f"Output root: {args.output_root.resolve()}")
    for candidate in ("xm", "finex"):
        result = results[candidate]
        print(
            f"{candidate.upper()}: {result['archive_sha256']} "
            f"({result['archive_name']})"
        )
        print(
            f"{candidate.upper()} helper SHA-256: {result['helper_sha256']}"
        )
    print("Order capability: DISABLED")
    print("Production execution ready: false")
    print("Credential access: NOT_PERFORMED")
    print("Discovery: NOT_PERFORMED")
    print("Contract registration: NOT_PERFORMED")
    print("Task installation: NOT_PERFORMED")
    print("Broker mutation: NOT_PERFORMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
