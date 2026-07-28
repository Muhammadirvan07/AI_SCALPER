#!/usr/bin/env python3
"""Build one deterministic, self-verifying base-suite transfer ZIP."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import BinaryIO
import zipfile

from live_runtime.windows_base_release_suite import (
    BaseReleaseSuiteVerificationError,
    ROLE_POLICIES,
    SUITE_MANIFEST_NAME,
    SUITE_PROFILE,
    SUITE_SCHEMA,
    verify_base_release_suite,
)
from live_runtime.windows_base_release_suite_transfer import (
    BaseReleaseSuiteTransferVerificationError,
    FIXED_ZIP_MODE,
    FIXED_ZIP_TIMESTAMP,
    MAX_TRANSFER_ARCHIVE_BYTES,
    MAX_TRANSFER_MEMBER_BYTES,
    TRANSFER_EFFECTS,
    TRANSFER_HELPER_NAME,
    TRANSFER_MANIFEST_NAME,
    TRANSFER_PROFILE,
    TRANSFER_SAFETY,
    TRANSFER_SCHEMA,
    TRANSFER_SUITE_ROOT,
    TRANSFER_VERIFICATION,
    canonical_transfer_file,
    expected_transfer_payload_paths,
    transfer_identity,
    verify_base_release_suite_transfer,
)


_HEX_40 = re.compile(r"[0-9a-f]{40}")
_HEX_64 = re.compile(r"[0-9a-f]{64}")
_OUTPUT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.zip")


class BaseReleaseSuiteTransferBuildError(RuntimeError):
    """One transfer build failed closed with a stable reason code."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _reject(reason_code: str) -> None:
    raise BaseReleaseSuiteTransferBuildError(reason_code)


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        getattr(left, name, None) == getattr(right, name, None)
        for name in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
    )


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        getattr(left, name, None) == getattr(right, name, None)
        for name in ("st_dev", "st_ino", "st_mode")
    )


def _pin(value: object, pattern: re.Pattern[str], reason: str) -> str:
    normalized = str(value or "").strip()
    if pattern.fullmatch(normalized) is None:
        _reject(reason)
    return normalized


def _validate_output(suite_root: Path, output: Path) -> tuple[Path, os.stat_result]:
    candidate = output.expanduser().absolute()
    if _OUTPUT_NAME.fullmatch(candidate.name) is None:
        _reject("TRANSFER_DESTINATION_INVALID")
    parent = candidate.parent
    try:
        parent_metadata = parent.lstat()
        resolved_parent = parent.resolve(strict=True)
    except OSError as exc:
        raise BaseReleaseSuiteTransferBuildError(
            "TRANSFER_DESTINATION_INVALID"
        ) from exc
    if (
        parent != resolved_parent
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or stat.S_ISLNK(parent_metadata.st_mode)
        or _is_reparse(parent_metadata)
        or candidate.is_relative_to(suite_root)
        or os.path.lexists(candidate)
    ):
        _reject("TRANSFER_DESTINATION_INVALID")
    return candidate, parent_metadata


def _open_regular(
    path: Path,
    *,
    maximum_bytes: int,
) -> tuple[BinaryIO, os.stat_result]:
    candidate = path.expanduser().absolute()
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise BaseReleaseSuiteTransferBuildError(
            "TRANSFER_SOURCE_UNSTABLE"
        ) from exc
    if (
        candidate != resolved
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or metadata.st_size <= 0
        or metadata.st_size > maximum_bytes
    ):
        _reject("TRANSFER_SOURCE_UNSTABLE")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(candidate, flags)
        handle = os.fdopen(descriptor, "rb")
        opened = os.fstat(handle.fileno())
    except OSError as exc:
        raise BaseReleaseSuiteTransferBuildError(
            "TRANSFER_SOURCE_UNSTABLE"
        ) from exc
    if not _same_stat(metadata, opened):
        handle.close()
        _reject("TRANSFER_SOURCE_UNSTABLE")
    return handle, opened


def _source_facts(
    path: Path,
    *,
    maximum_bytes: int = MAX_TRANSFER_MEMBER_BYTES,
) -> dict[str, object]:
    handle, opened = _open_regular(
        path,
        maximum_bytes=maximum_bytes,
    )
    digest = hashlib.sha256()
    observed = 0
    try:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            digest.update(chunk)
        after = os.fstat(handle.fileno())
        current = path.lstat()
    except OSError as exc:
        raise BaseReleaseSuiteTransferBuildError(
            "TRANSFER_SOURCE_UNSTABLE"
        ) from exc
    finally:
        handle.close()
    if observed != opened.st_size or not _same_stat(opened, after) or not _same_stat(
        opened, current
    ):
        _reject("TRANSFER_SOURCE_UNSTABLE")
    return {
        "size_bytes": observed,
        "sha256": digest.hexdigest(),
    }


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, FIXED_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = FIXED_ZIP_MODE << 16
    return info


def _write_bytes_member(
    archive: zipfile.ZipFile,
    path: str,
    data: bytes,
) -> None:
    archive.writestr(_zip_info(path), data, compress_type=zipfile.ZIP_DEFLATED)


def _write_source_member(
    archive: zipfile.ZipFile,
    archive_path: str,
    source_path: Path,
    expected: dict[str, object],
) -> None:
    handle, opened = _open_regular(
        source_path,
        maximum_bytes=MAX_TRANSFER_MEMBER_BYTES,
    )
    digest = hashlib.sha256()
    observed = 0
    try:
        with archive.open(_zip_info(archive_path), "w") as destination:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                observed += len(chunk)
                digest.update(chunk)
                destination.write(chunk)
        after = os.fstat(handle.fileno())
        current = source_path.lstat()
    except OSError as exc:
        raise BaseReleaseSuiteTransferBuildError(
            "TRANSFER_SOURCE_UNSTABLE"
        ) from exc
    finally:
        handle.close()
    if (
        observed != expected["size_bytes"]
        or digest.hexdigest() != expected["sha256"]
        or observed != opened.st_size
        or not _same_stat(opened, after)
        or not _same_stat(opened, current)
    ):
        _reject("TRANSFER_SOURCE_UNSTABLE")


def _powershell_helper() -> bytes:
    source = r'''#requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$ArchivePath,

  [Parameter(Mandatory = $true)]
  [string]$BundleRoot,

  [Parameter(Mandatory = $true)]
  [string]$PythonPath,

  [Parameter(Mandatory = $true)]
  [string]$ExpectedArchiveSHA256,

  [Parameter(Mandatory = $true)]
  [string]$ExpectedSuiteIdentitySHA256,

  [Parameter(Mandatory = $true)]
  [string]$ExpectedGitCommit,

  [Parameter(Mandatory = $true)]
  [string]$ExpectedGitTree
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ExactLeaf {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Label
  )
  $full = [System.IO.Path]::GetFullPath($Path)
  $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
  if (
    $item.PSIsContainer -or
    (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
  ) {
    throw "$Label must be one regular non-reparse file."
  }
  return $item
}

function Get-ExactDirectory {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Label
  )
  $full = [System.IO.Path]::GetFullPath($Path).TrimEnd(
    [char[]]@('\', '/')
  )
  $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
  if (
    -not $item.PSIsContainer -or
    (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
  ) {
    throw "$Label must be one regular non-reparse directory."
  }
  return $item
}

function Assert-LowerHex {
  param(
    [Parameter(Mandatory = $true)][string]$Value,
    [Parameter(Mandatory = $true)][int]$Length,
    [Parameter(Mandatory = $true)][string]$Label
  )
  if ($Value -cnotmatch "^[0-9a-f]{$Length}$") {
    throw "$Label is not one lowercase externally pinned identity."
  }
}

$ExpectedArchiveSHA256 = $ExpectedArchiveSHA256.Trim()
$ExpectedSuiteIdentitySHA256 = $ExpectedSuiteIdentitySHA256.Trim()
$ExpectedGitCommit = $ExpectedGitCommit.Trim()
$ExpectedGitTree = $ExpectedGitTree.Trim()
Assert-LowerHex $ExpectedArchiveSHA256 64 "Archive SHA-256"
Assert-LowerHex $ExpectedSuiteIdentitySHA256 64 "Suite identity"
Assert-LowerHex $ExpectedGitCommit 40 "Git commit"
Assert-LowerHex $ExpectedGitTree 40 "Git tree"

$archive = Get-ExactLeaf $ArchivePath "Transfer archive"
$python = Get-ExactLeaf $PythonPath "Python executable"
$bundle = Get-ExactDirectory $BundleRoot "Extracted bundle root"
$bundlePath = $bundle.FullName.TrimEnd([char[]]@('\', '/'))
$archiveHash = (
  Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($archiveHash -ne $ExpectedArchiveSHA256) {
  throw "Externally pinned transfer archive SHA-256 mismatch."
}

$manifestPath = Join-Path $bundlePath "BASE_RELEASE_SUITE_TRANSFER.json"
$manifestFile = Get-ExactLeaf $manifestPath "Transfer manifest"
$manifest = Get-Content -LiteralPath $manifestFile.FullName -Raw |
  ConvertFrom-Json
if (
  $manifest.schema_version -ne
    "ai-scalper-windows-base-release-suite-transfer-v1" -or
  $manifest.transfer_profile -ne
    "WINDOWS_ATOMIC_BASE_RELEASE_SUITE_TRANSFER_V1" -or
  $manifest.suite.root -ne "base-release-suite-v1" -or
  $manifest.suite.schema_version -ne
    "ai-scalper-windows-base-release-suite-v1" -or
  $manifest.suite.release_profile -ne
    "WINDOWS_ATOMIC_BASE_RELEASE_SUITE_V1" -or
  $manifest.suite.suite_identity_sha256 -ne
    $ExpectedSuiteIdentitySHA256 -or
  $manifest.suite.git_commit -ne $ExpectedGitCommit -or
  $manifest.suite.git_tree -ne $ExpectedGitTree -or
  [int]$manifest.suite.role_count -ne 5 -or
  [int]$manifest.suite.file_count -ne 11 -or
  $manifest.safety.order_capability -ne
    "DISABLED_AT_TRANSFER_BOUNDARY" -or
  $manifest.safety.live_allowed -ne $false -or
  $manifest.safety.safe_to_demo_auto_order -ne $false -or
  $manifest.safety.promotion_eligible -ne $false -or
  [double]$manifest.safety.max_lot -ne 0.01
) {
  throw "Transfer manifest identity or safety mismatch."
}

$rows = @(
  $manifest.payload_members |
    ForEach-Object { $_ }
)
$expectedFiles = @{}
$expectedFiles.Add("BASE_RELEASE_SUITE_TRANSFER.json", $null)
foreach ($row in $rows) {
  $relative = [string]$row.path
  $parts = @($relative.Split('/'))
  if (
    [string]::IsNullOrWhiteSpace($relative) -or
    $relative.Contains('\') -or
    $relative.Contains(':') -or
    $relative.StartsWith('/') -or
    $parts.Count -lt 1 -or
    @($parts | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' }).Count -gt 0 -or
    $expectedFiles.ContainsKey($relative) -or
    [int64]$row.size_bytes -le 0 -or
    [string]$row.sha256 -cnotmatch '^[0-9a-f]{64}$'
  ) {
    throw "Transfer payload inventory is invalid or duplicated."
  }
  $expectedFiles.Add($relative, $row)
}
if ($rows.Count -ne 12 -or $expectedFiles.Count -ne 13) {
  throw "Transfer payload inventory count mismatch."
}

$observed = @(
  Get-ChildItem -LiteralPath $bundlePath -Force -Recurse -ErrorAction Stop
)
$observedFiles = @($observed | Where-Object { -not $_.PSIsContainer })
$observedDirectories = @($observed | Where-Object { $_.PSIsContainer })
if ($observedFiles.Count -ne $expectedFiles.Count) {
  throw "Extracted transfer file count mismatch."
}
if ($observedDirectories.Count -ne 1) {
  throw "Extracted transfer directory count mismatch."
}
$directoryRelative = $observedDirectories[0].FullName.Substring(
  $bundlePath.Length + 1
).Replace('\', '/')
if ($directoryRelative -cne "base-release-suite-v1") {
  throw "Extracted transfer directory identity mismatch."
}

foreach ($item in $observed) {
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Extracted transfer contains a reparse point."
  }
}
foreach ($item in $observedFiles) {
  $relative = $item.FullName.Substring(
    $bundlePath.Length + 1
  ).Replace('\', '/')
  if (-not $expectedFiles.ContainsKey($relative)) {
    throw "Extracted transfer contains an unexpected file."
  }
  $row = $expectedFiles[$relative]
  if ($null -ne $row) {
    $digest = (
      Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if (
      $relative -cne [string]$row.path -or
      $item.Length -ne [int64]$row.size_bytes -or
      $digest -ne [string]$row.sha256
    ) {
      throw "Extracted transfer member mismatch: $relative"
    }
  }
}

$suiteRoot = Join-Path $bundlePath "base-release-suite-v1"
$toolingZip = Get-ExactLeaf (
  Join-Path $suiteRoot "configured-release-tooling-v1.zip"
) "Configured tooling archive"
$toolingRoot = Join-Path (
  [System.IO.Path]::GetTempPath()
) ("AI_SCALPER-base-suite-transfer-" + [Guid]::NewGuid().ToString("N"))
if (Test-Path -LiteralPath $toolingRoot) {
  throw "Private tooling verification root already exists."
}
try {
  Expand-Archive -LiteralPath $toolingZip.FullName -DestinationPath $toolingRoot
  $verifier = Get-ExactLeaf (
    Join-Path $toolingRoot "verify_windows_base_release_suite_transfer.py"
  ) "Configured tooling transfer verifier"
  & $python.FullName -I -S -B $verifier.FullName `
    --archive $archive.FullName `
    --expected-archive-sha256 $ExpectedArchiveSHA256 `
    --expected-suite-identity-sha256 $ExpectedSuiteIdentitySHA256 `
    --expected-git-commit $ExpectedGitCommit `
    --expected-git-tree $ExpectedGitTree
  if ($LASTEXITCODE -ne 0) {
    throw "Configured tooling transfer verification failed."
  }
}
finally {
  if (Test-Path -LiteralPath $toolingRoot) {
    Remove-Item -LiteralPath $toolingRoot -Recurse -Force
  }
}

$archiveHashAfter = (
  Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($archiveHashAfter -ne $ExpectedArchiveSHA256) {
  throw "Transfer archive changed during verification."
}
$observedAfter = @(
  Get-ChildItem -LiteralPath $bundlePath -Force -Recurse -ErrorAction Stop
)
$filesAfter = @($observedAfter | Where-Object { -not $_.PSIsContainer })
$directoriesAfter = @($observedAfter | Where-Object { $_.PSIsContainer })
if (
  $filesAfter.Count -ne $expectedFiles.Count -or
  $directoriesAfter.Count -ne 1 -or
  @(
    $observedAfter |
      Where-Object {
        ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
      }
  ).Count -ne 0
) {
  throw "Extracted transfer changed during verification."
}
foreach ($item in $filesAfter) {
  $relative = $item.FullName.Substring(
    $bundlePath.Length + 1
  ).Replace('\', '/')
  if (-not $expectedFiles.ContainsKey($relative)) {
    throw "Extracted transfer changed during verification."
  }
  $row = $expectedFiles[$relative]
  if ($null -ne $row) {
    $digest = (
      Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if (
      $relative -cne [string]$row.path -or
      $item.Length -ne [int64]$row.size_bytes -or
      $digest -ne [string]$row.sha256
    ) {
      throw "Extracted transfer changed during verification."
    }
  }
}

[PSCustomObject]@{
  Status = "WINDOWS_BASE_RELEASE_SUITE_TRANSFER_VERIFIED"
  ArchiveSHA256 = $archiveHash
  SuiteRoot = $suiteRoot
  SuiteIdentitySHA256 = $ExpectedSuiteIdentitySHA256
  GitCommit = $ExpectedGitCommit
  GitTree = $ExpectedGitTree
  RolesVerified = 5
  OrderCapability = "DISABLED_AT_TRANSFER_BOUNDARY"
  ProductionExecutionReady = $false
  LiveAllowed = $false
  SafeToDemoAutoOrder = $false
  ProviderImport = "NOT_PERFORMED"
  CredentialAccess = "NOT_PERFORMED"
  TaskInstallation = "NOT_PERFORMED"
  MT5Initialization = "NOT_PERFORMED"
  BrokerMutation = "NOT_PERFORMED"
} | Format-List
'''
    return source.encode("utf-8")


def _publish_no_replace(staging: Path, output: Path) -> None:
    try:
        if os.name == "nt":
            os.rename(staging, output)
        else:
            os.link(staging, output)
            try:
                staging.unlink()
            except OSError:
                pass
    except OSError as exc:
        raise BaseReleaseSuiteTransferBuildError(
            "TRANSFER_PUBLICATION_FAILED"
        ) from exc


def build_base_release_suite_transfer(
    suite_root: Path,
    output: Path,
    *,
    expected_suite_identity_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
) -> dict[str, object]:
    """Build and self-verify one exact deterministic transfer archive."""

    expected_suite = _pin(
        expected_suite_identity_sha256,
        _HEX_64,
        "EXPECTED_SUITE_IDENTITY_INVALID",
    )
    expected_commit = _pin(
        expected_git_commit,
        _HEX_40,
        "EXPECTED_GIT_COMMIT_INVALID",
    )
    expected_tree = _pin(
        expected_git_tree,
        _HEX_40,
        "EXPECTED_GIT_TREE_INVALID",
    )
    try:
        suite = verify_base_release_suite(suite_root)
    except BaseReleaseSuiteVerificationError as exc:
        raise BaseReleaseSuiteTransferBuildError(
            "TRANSFER_BASE_SUITE_INVALID"
        ) from exc
    if (
        suite.suite_identity_sha256 != expected_suite
        or suite.git_commit != expected_commit
        or suite.git_tree != expected_tree
    ):
        _reject("TRANSFER_BASE_SUITE_PIN_MISMATCH")
    destination, parent_state = _validate_output(suite.root, output)

    sources: dict[str, Path] = {
        f"{TRANSFER_SUITE_ROOT}/{SUITE_MANIFEST_NAME}": suite.manifest_path,
    }
    expected_facts: dict[str, dict[str, object]] = {
        f"{TRANSFER_SUITE_ROOT}/{SUITE_MANIFEST_NAME}": {
            "size_bytes": suite.manifest_path.stat().st_size,
            "sha256": suite.manifest_sha256,
        }
    }
    for role in suite.roles:
        archive_member = f"{TRANSFER_SUITE_ROOT}/{role.archive_path.name}"
        sidecar_member = f"{TRANSFER_SUITE_ROOT}/{role.sidecar_path.name}"
        sources[archive_member] = role.archive_path
        sources[sidecar_member] = role.sidecar_path
        expected_facts[archive_member] = {
            "size_bytes": role.archive_size_bytes,
            "sha256": role.archive_sha256,
        }
        expected_facts[sidecar_member] = {
            "size_bytes": role.sidecar_size_bytes,
            "sha256": role.sidecar_sha256,
        }
    for member_path, source_path in sources.items():
        if _source_facts(source_path) != expected_facts[member_path]:
            _reject("TRANSFER_SOURCE_MISMATCH")

    helper = _powershell_helper()
    payload_rows: list[dict[str, object]] = []
    for path in expected_transfer_payload_paths():
        if path == TRANSFER_HELPER_NAME:
            facts = {
                "size_bytes": len(helper),
                "sha256": hashlib.sha256(helper).hexdigest(),
            }
        else:
            facts = expected_facts[path]
        payload_rows.append({"path": path, **facts})
    unsigned_manifest: dict[str, object] = {
        "schema_version": TRANSFER_SCHEMA,
        "transfer_profile": TRANSFER_PROFILE,
        "suite": {
            "root": TRANSFER_SUITE_ROOT,
            "schema_version": SUITE_SCHEMA,
            "release_profile": SUITE_PROFILE,
            "suite_identity_sha256": suite.suite_identity_sha256,
            "manifest_sha256": suite.manifest_sha256,
            "git_commit": suite.git_commit,
            "git_tree": suite.git_tree,
            "role_count": len(suite.roles),
            "file_count": 1 + (2 * len(suite.roles)),
        },
        "allowed_directories": [TRANSFER_SUITE_ROOT],
        "payload_members": payload_rows,
        "verification": TRANSFER_VERIFICATION,
        "effects": TRANSFER_EFFECTS,
        "safety": TRANSFER_SAFETY,
    }
    manifest = {
        **unsigned_manifest,
        "transfer_identity_sha256": transfer_identity(unsigned_manifest),
    }
    manifest_bytes = canonical_transfer_file(manifest)

    descriptor: int | None = None
    staging: Path | None = None
    try:
        try:
            descriptor, raw_staging = tempfile.mkstemp(
                prefix=f".{destination.name}.staging-",
                dir=destination.parent,
            )
            staging = Path(raw_staging).resolve(strict=True)
            handle = os.fdopen(descriptor, "w+b")
            descriptor = None
            with handle:
                with zipfile.ZipFile(
                    handle,
                    mode="w",
                    compression=zipfile.ZIP_DEFLATED,
                    compresslevel=9,
                    strict_timestamps=True,
                ) as archive:
                    for member_path in sorted(
                        {
                            TRANSFER_MANIFEST_NAME,
                            *expected_transfer_payload_paths(),
                        }
                    ):
                        if member_path == TRANSFER_MANIFEST_NAME:
                            _write_bytes_member(
                                archive, member_path, manifest_bytes
                            )
                        elif member_path == TRANSFER_HELPER_NAME:
                            _write_bytes_member(archive, member_path, helper)
                        else:
                            _write_source_member(
                                archive,
                                member_path,
                                sources[member_path],
                                expected_facts[member_path],
                            )
                handle.flush()
                os.fsync(handle.fileno())
        except BaseReleaseSuiteTransferBuildError:
            raise
        except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
            raise BaseReleaseSuiteTransferBuildError(
                "TRANSFER_ARCHIVE_BUILD_FAILED"
            ) from exc

        archive_facts = _source_facts(
            staging,
            maximum_bytes=MAX_TRANSFER_ARCHIVE_BYTES,
        )
        try:
            report = verify_base_release_suite_transfer(
                staging,
                expected_archive_sha256=str(archive_facts["sha256"]),
                expected_suite_identity_sha256=expected_suite,
                expected_git_commit=expected_commit,
                expected_git_tree=expected_tree,
            )
        except BaseReleaseSuiteTransferVerificationError as exc:
            raise BaseReleaseSuiteTransferBuildError(
                "TRANSFER_SELF_VERIFICATION_FAILED"
            ) from exc
        if (
            report.transfer_identity_sha256
            != manifest["transfer_identity_sha256"]
            or report.payload_member_count != len(payload_rows)
        ):
            _reject("TRANSFER_SELF_VERIFICATION_FAILED")
        try:
            current_parent = destination.parent.stat(follow_symlinks=False)
        except OSError as exc:
            raise BaseReleaseSuiteTransferBuildError(
                "TRANSFER_PUBLICATION_FAILED"
            ) from exc
        if (
            not _same_identity(parent_state, current_parent)
            or destination.parent.is_symlink()
            or _is_reparse(current_parent)
            or os.path.lexists(destination)
        ):
            _reject("TRANSFER_PUBLICATION_FAILED")
        _publish_no_replace(staging, destination)
        staging = None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if staging is not None:
            try:
                staging.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass

    return {
        "archive": str(destination),
        "archive_sha256": archive_facts["sha256"],
        "archive_size_bytes": archive_facts["size_bytes"],
        "transfer_identity_sha256": manifest["transfer_identity_sha256"],
        "suite_identity_sha256": suite.suite_identity_sha256,
        "suite_manifest_sha256": suite.manifest_sha256,
        "git_commit": suite.git_commit,
        "git_tree": suite.git_tree,
        "role_count": len(suite.roles),
        "payload_member_count": len(payload_rows),
    }


class _StableArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise BaseReleaseSuiteTransferBuildError("ARGUMENTS_INVALID")


def _parser() -> argparse.ArgumentParser:
    parser = _StableArgumentParser(
        description=(
            "Build one deterministic transfer ZIP around an already verified "
            "atomic Windows base-release suite. No provider, credential, "
            "task, service, MT5, activation, or broker effect is performed."
        )
    )
    parser.add_argument("--suite-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-suite-identity-sha256", required=True)
    parser.add_argument("--expected-git-commit", required=True)
    parser.add_argument("--expected-git-tree", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
        result = build_base_release_suite_transfer(
            args.suite_root,
            args.output,
            expected_suite_identity_sha256=(
                args.expected_suite_identity_sha256
            ),
            expected_git_commit=args.expected_git_commit,
            expected_git_tree=args.expected_git_tree,
        )
    except BaseReleaseSuiteTransferBuildError as exc:
        print(
            f"BASE_RELEASE_SUITE_TRANSFER_REJECTED: {exc.reason_code}",
            file=sys.stderr,
        )
        return 2
    except (OSError, RuntimeError, TypeError, ValueError):
        print(
            "BASE_RELEASE_SUITE_TRANSFER_REJECTED: TRANSFER_BUILDER_ERROR",
            file=sys.stderr,
        )
        return 2
    print("WINDOWS_BASE_RELEASE_SUITE_TRANSFER_READY")
    print(f"Archive: {result['archive']}")
    print(f"Archive SHA-256: {result['archive_sha256']}")
    print(f"Archive size bytes: {result['archive_size_bytes']}")
    print(
        "Transfer identity SHA-256: "
        f"{result['transfer_identity_sha256']}"
    )
    print(f"Suite identity SHA-256: {result['suite_identity_sha256']}")
    print(f"Suite manifest SHA-256: {result['suite_manifest_sha256']}")
    print(f"Git commit: {result['git_commit']}")
    print(f"Git tree: {result['git_tree']}")
    print(f"Roles: {result['role_count']}")
    print(f"Payload members: {result['payload_member_count']}")
    print("Order capability: DISABLED_AT_TRANSFER_BOUNDARY")
    print("Production execution ready: false")
    print("Live allowed: false")
    print("Safe to demo auto order: false")
    print("Provider import: NOT_PERFORMED")
    print("Credential access: NOT_PERFORMED")
    print("Task installation: NOT_PERFORMED")
    print("Runtime/service process launch: NOT_PERFORMED")
    print("MT5 initialization: NOT_PERFORMED")
    print("Broker mutation: NOT_PERFORMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
