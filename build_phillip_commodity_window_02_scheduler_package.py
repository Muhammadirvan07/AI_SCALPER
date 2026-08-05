from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


BRANCH = "agent/live-grade-phase3"
WORKER_COMMIT = "da3190013d86426533019d6927a58181c624b1f8"
WORKER_TREE = "9e84a0d7c9a5b3d4213c6abf0fdf1c8770361d10"
CONTRACT_ID = "phillip-commodity-window-02-diagnostic-v1"
SNAPSHOT_ID = "phillip-commodity-dev-pre-window-02-v1"
CONTRACT_PAYLOAD_SHA256 = (
    "cbfd753b0aed2d66af56446adc734ce8"
    "d62666e309e91bf74d24b4cc56b613a2"
)
CONTRACT_FILE_SHA256 = (
    "ad4fd8853563976483fbffbd3bd97847"
    "f7e05c8a4194afd10fa95832e2fe485b"
)
BUILD_IDENTITY_SHA256 = (
    "9d64b8c9be0b42bdc991b767a7452587"
    "74a57f80613e2fd322791d6d18cc6287"
)
SIGNING_KEY_ID = "105e393cd619804e"
DEPENDENCY_LOCK_SHA256 = (
    "34087f736724e7d92591f7886f565b15"
    "436c59de0d4e80a59e42b04f2851d862"
)
REGISTERED_AT_UTC = "2026-08-05T07:16:19.157743Z"
OBSERVATION_START_UTC = "2026-08-16T16:00:00Z"
BLIND_UNTIL_UTC = "2026-10-12T15:00:00Z"
FIRST_SCHEDULED_START_UTC = "2026-08-16T21:45:00Z"
FIRST_SCHEDULED_START_LOCAL = "2026-08-17T06:45:00+09:00"
FIRST_NEXT_RUN_LOCAL = "2026-08-17T06:45:00"
SCHEDULE_END_LOCAL = "2026-10-13T00:16:00+09:00"
TASK_NAME = "AI_SCALPER-PhillipCommodityWindow02-ReadOnlyShadow"
TRANSPORT_REVISION = "WINDOW02.V4"
EXTRACTION_INVENTORY_MODE = "WINDOWS_POWERSHELL_5_1_FLAT_EXACT_V1"
TEMPLATE_PATHS = (
    "windows_operator/PhillipCommodityTaskContract.ps1",
    "windows_operator/Install-PhillipCommodityWindow02ReadOnlyTask.ps1",
    "windows_operator/Test-PhillipCommodityWindow02TaskHealth.ps1",
    "windows_operator/verify_phillip_commodity_window_02_contract.py",
    "docs/PHILLIP_COMMODITY_WINDOW_02_SCHEDULER.md",
)
ARCHIVE_TIMESTAMP = (2026, 8, 5, 12, 0, 0)


class PackageBuildError(RuntimeError):
    pass


@dataclass(frozen=True)
class Member:
    path: str
    data: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def size_bytes(self) -> int:
        return len(self.data)

    def manifest_row(self) -> dict[str, object]:
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise PackageBuildError(
            f"git {' '.join(arguments)} failed: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def _source_identity(root: Path) -> tuple[str, str]:
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise PackageBuildError("source worktree must be clean")
    commit = _git(root, "rev-parse", "HEAD^{commit}")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(
        r"[0-9a-f]{40}", tree
    ):
        raise PackageBuildError("invalid Git source identity")
    return commit, tree


def _tracked_source(root: Path, relative: str) -> bytes:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise PackageBuildError(f"source is not a regular file: {relative}")
    expected = subprocess.run(
        ["git", "-C", str(root), "show", f"HEAD:{relative}"],
        check=False,
        capture_output=True,
    )
    if expected.returncode != 0:
        raise PackageBuildError(f"source is not tracked at HEAD: {relative}")
    observed = path.read_bytes()
    if observed != expected.stdout:
        raise PackageBuildError(f"tracked source drift: {relative}")
    return observed


def _render(
    source: bytes,
    *,
    commit: str,
    tree: str,
    task_contract_sha256: str,
    contract_verifier_sha256: str,
    health_checker_sha256: str,
    package_name: str,
    operator_root_name: str,
) -> bytes:
    text = source.decode("utf-8")
    replacements = {
        "__PACKAGE_SOURCE_COMMIT__": commit,
        "__PACKAGE_SOURCE_TREE__": tree,
        "__TASK_CONTRACT_SHA256__": task_contract_sha256,
        "__CONTRACT_VERIFIER_SHA256__": contract_verifier_sha256,
        "__HEALTH_CHECKER_SHA256__": health_checker_sha256,
        "__PACKAGE_NAME__": package_name,
        "__OPERATOR_ROOT_NAME__": operator_root_name,
    }
    for placeholder, value in replacements.items():
        text = text.replace(placeholder, value)
    unresolved = [key for key in replacements if key in text]
    if unresolved:
        raise PackageBuildError(
            "unresolved package placeholders: " + ", ".join(unresolved)
        )
    return text.encode("utf-8")


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _write_zip(path: Path, members: Iterable[Member]) -> None:
    with zipfile.ZipFile(
        path,
        mode="x",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for member in sorted(members, key=lambda item: item.path):
            info = zipfile.ZipInfo(member.path, date_time=ARCHIVE_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            info.create_system = 3
            archive.writestr(info, member.data, compress_type=zipfile.ZIP_DEFLATED)


def _expand_helper(
    *,
    archive_name: str,
    archive_size: int,
    archive_sha256: str,
    manifest_name: str,
    manifest_sha256: str,
    commit: str,
    tree: str,
    members: list[Member],
) -> bytes:
    inventory = base64.b64encode(
        _json_bytes([member.manifest_row() for member in members])
    ).decode("ascii")
    operator_root_name = (
        "phillip-commodity-window-02-scheduler-operator-" + commit[:8]
    )
    source = f'''[CmdletBinding()]
param(
  [Parameter()]
  [string]$ArchivePath = (Join-Path $PSScriptRoot "{archive_name}"),

  [Parameter()]
  [string]$ManifestPath = (Join-Path $PSScriptRoot "{manifest_name}"),

  [Parameter()]
  [string]$OperatorRoot = (
    "C:\\AI_SCALPER_PRIVATE\\{operator_root_name}"
  )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$expectedArchiveName = "{archive_name}"
$expectedArchiveSize = [int64]{archive_size}
$expectedArchiveSha256 = "{archive_sha256}"
$expectedManifestSha256 = "{manifest_sha256}"
$expectedCommit = "{commit}"
$expectedTree = "{tree}"
$expectedOperatorRoot = "C:\\AI_SCALPER_PRIVATE\\{operator_root_name}"
$memberInventoryBase64 = "{inventory}"

function Get-ExactLeaf {{
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $true)]
    [string]$Label
  )
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if ($item.PSIsContainer) {{
    throw "$Label must be a regular file."
  }}
  if (
    ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
  ) {{
    throw "$Label must not be a reparse point."
  }}
  return $item
}}

$archive = Get-ExactLeaf -Path $ArchivePath -Label "Window 02 archive"
$manifestFile = Get-ExactLeaf `
  -Path $ManifestPath `
  -Label "Window 02 transfer manifest"
if (
  $archive.Name -ne $expectedArchiveName -or
  $archive.Length -ne $expectedArchiveSize
) {{
  throw "Window 02 archive name or size mismatch."
}}
$archiveHash = (
  Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256
).Hash.ToLowerInvariant()
$manifestHash = (
  Get-FileHash -LiteralPath $manifestFile.FullName -Algorithm SHA256
).Hash.ToLowerInvariant()
if (
  $archiveHash -ne $expectedArchiveSha256 -or
  $manifestHash -ne $expectedManifestSha256
) {{
  throw "Window 02 transfer artifact hash mismatch."
}}

$manifest = Get-Content -LiteralPath $manifestFile.FullName -Raw |
  ConvertFrom-Json
if (
  $manifest.schema_version -ne
    "phillip-commodity-window-02-scheduler-transfer-v1" -or
  $manifest.transport_revision -ne "{TRANSPORT_REVISION}" -or
  $manifest.archive.path -ne $expectedArchiveName -or
  [int64]$manifest.archive.size_bytes -ne $expectedArchiveSize -or
  $manifest.archive.sha256 -ne $expectedArchiveSha256 -or
  $manifest.source.commit -ne $expectedCommit -or
  $manifest.source.tree -ne $expectedTree -or
  $manifest.operator_root -ne $expectedOperatorRoot -or
  $manifest.worker.source_commit -ne "{WORKER_COMMIT}" -or
  $manifest.worker.source_tree -ne "{WORKER_TREE}" -or
  $manifest.worker.contract_id -ne "{CONTRACT_ID}" -or
  $manifest.worker.snapshot_id -ne "{SNAPSHOT_ID}" -or
  $manifest.worker.contract_payload_sha256 -ne
    "{CONTRACT_PAYLOAD_SHA256}" -or
  $manifest.worker.contract_file_sha256 -ne "{CONTRACT_FILE_SHA256}" -or
  $manifest.worker.build_identity_sha256 -ne "{BUILD_IDENTITY_SHA256}" -or
  $manifest.worker.signing_key_id -ne "{SIGNING_KEY_ID}" -or
  $manifest.worker.dependency_lock_sha256 -ne
    "{DEPENDENCY_LOCK_SHA256}" -or
  $manifest.schedule.first_scheduled_start_utc -ne
    "{FIRST_SCHEDULED_START_UTC}" -or
  $manifest.schedule.start_boundary -ne
    "{FIRST_SCHEDULED_START_LOCAL}" -or
  $manifest.schedule.end_boundary -ne "{SCHEDULE_END_LOCAL}" -or
  $manifest.new_task_name -ne "{TASK_NAME}" -or
  $manifest.extraction_inventory_mode -ne
    "{EXTRACTION_INVENTORY_MODE}" -or
  $manifest.safety.order_capability -ne "DISABLED" -or
  $manifest.safety.live_allowed -ne $false -or
  $manifest.safety.safe_to_demo_auto_order -ne $false -or
  $manifest.safety.task_scheduler_mutation -ne
    "NOT_PERFORMED_DURING_BUILD" -or
  $manifest.safety.broker_mutation -ne "NOT_PERFORMED"
) {{
  throw "Window 02 transfer manifest identity or safety mismatch."
}}

$expectedJson = [System.Text.Encoding]::UTF8.GetString(
  [System.Convert]::FromBase64String($memberInventoryBase64)
)
$expectedMembers = @(($expectedJson | ConvertFrom-Json) | ForEach-Object {{ $_ }})
if (
  $expectedMembers.Count -lt 1 -or
  [int]$manifest.archive.member_count -ne $expectedMembers.Count
) {{
  throw "Embedded Window 02 inventory count mismatch."
}}
$paths = @{{}}
foreach ($expected in $expectedMembers) {{
  $path = [string]$expected.path
  if (
    [string]::IsNullOrWhiteSpace($path) -or
    [System.IO.Path]::GetFileName($path) -ne $path -or
    $paths.ContainsKey($path) -or
    [int64]$expected.size_bytes -lt 0 -or
    [string]$expected.sha256 -notmatch '^[0-9a-f]{{64}}$'
  ) {{
    throw "Embedded Window 02 inventory member is invalid."
  }}
  $paths.Add($path, $true)
}}
if (Test-Path -LiteralPath $OperatorRoot) {{
  throw "Window 02 operator root already exists; preserve it."
}}
New-Item -ItemType Directory -Path $OperatorRoot -ErrorAction Stop |
  Out-Null

try {{
  Expand-Archive `
    -LiteralPath $archive.FullName `
    -DestinationPath $OperatorRoot
  $observed = @(
    Get-ChildItem -LiteralPath $OperatorRoot -Force -Recurse
  )
  $directories = @($observed | Where-Object {{ $_.PSIsContainer }})
  if (
    $observed.Count -ne $expectedMembers.Count -or
    $directories.Count -ne 0
  ) {{
    throw "Extracted Window 02 inventory count or type mismatch."
  }}
  foreach ($expected in $expectedMembers) {{
    $member = Get-ExactLeaf `
      -Path (Join-Path $OperatorRoot ([string]$expected.path)) `
      -Label "Extracted Window 02 member"
    $memberHash = (
      Get-FileHash -LiteralPath $member.FullName -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if (
      $member.Length -ne [int64]$expected.size_bytes -or
      $memberHash -ne [string]$expected.sha256
    ) {{
      throw "Extracted Window 02 member mismatch: $($expected.path)"
    }}
  }}
}}
catch {{
  throw (
    "Window 02 extraction failed. Preserve the operator root and " +
    "transfer artifacts for forensic review. $($_.Exception.Message)"
  )
}}

[PSCustomObject]@{{
  Status = "PHILLIP_COMMODITY_WINDOW_02_SCHEDULER_TRANSFER_VERIFIED"
  TransportRevision = "{TRANSPORT_REVISION}"
  ArchiveSHA256 = $archiveHash
  OperatorRoot = $OperatorRoot
  PackageSourceCommit = $expectedCommit
  PackageSourceTree = $expectedTree
  FrozenWorkerCommit = "{WORKER_COMMIT}"
  Contract = "{CONTRACT_ID}"
  ContractPayloadSHA256 = "{CONTRACT_PAYLOAD_SHA256}"
  TaskName = "{TASK_NAME}"
  FilesVerified = $expectedMembers.Count
  OrderCapability = "DISABLED"
  LiveAllowed = $false
  TaskSchedulerMutation = "NOT_PERFORMED"
  BrokerMutation = "NOT_PERFORMED"
}} | Format-List
'''
    return source.encode("utf-8")


def _worker_binding() -> dict[str, object]:
    return {
        "source_commit": WORKER_COMMIT,
        "source_tree": WORKER_TREE,
        "contract_id": CONTRACT_ID,
        "snapshot_id": SNAPSHOT_ID,
        "registered_at_utc": REGISTERED_AT_UTC,
        "observation_start_at_utc": OBSERVATION_START_UTC,
        "blind_until_utc": BLIND_UNTIL_UTC,
        "contract_payload_sha256": CONTRACT_PAYLOAD_SHA256,
        "contract_file_sha256": CONTRACT_FILE_SHA256,
        "build_identity_sha256": BUILD_IDENTITY_SHA256,
        "signing_key_id": SIGNING_KEY_ID,
        "dependency_lock_sha256": DEPENDENCY_LOCK_SHA256,
        "initial_artifact_file_count": 8,
    }


def _schedule() -> dict[str, object]:
    return {
        "first_scheduled_start_utc": FIRST_SCHEDULED_START_UTC,
        "start_boundary": FIRST_SCHEDULED_START_LOCAL,
        "end_boundary": SCHEDULE_END_LOCAL,
        "weekdays_only": True,
        "worker_duration_seconds": 84300,
    }


def build_package(source_root: Path, output: Path) -> dict[str, object]:
    source_root = source_root.resolve()
    output = output.resolve()
    if not re.fullmatch(
        r"phillip-commodity-window-02-scheduler-[0-9a-f]{8,12}\.zip",
        output.name,
    ):
        raise PackageBuildError(
            "output filename is not the reviewed Window 02 form"
        )
    manifest_path = Path(f"{output}.manifest.json")
    helper_path = output.parent / (
        "Expand-PhillipCommodityWindow02SchedulerPackage.ps1"
    )
    if output.exists() or manifest_path.exists() or helper_path.exists():
        raise PackageBuildError("output artifact already exists")
    output.parent.mkdir(parents=True, exist_ok=True)

    commit, tree = _source_identity(source_root)
    sources = {
        relative: _tracked_source(source_root, relative)
        for relative in TEMPLATE_PATHS
    }
    task_contract = sources[TEMPLATE_PATHS[0]]
    verifier = sources[TEMPLATE_PATHS[3]]
    task_contract_sha256 = hashlib.sha256(task_contract).hexdigest()
    verifier_sha256 = hashlib.sha256(verifier).hexdigest()
    operator_root_name = (
        "phillip-commodity-window-02-scheduler-operator-" + commit[:8]
    )
    provisional_render = dict(
        commit=commit,
        tree=tree,
        task_contract_sha256=task_contract_sha256,
        contract_verifier_sha256=verifier_sha256,
        health_checker_sha256="0" * 64,
        package_name=output.name,
        operator_root_name=operator_root_name,
    )
    rendered_health = _render(sources[TEMPLATE_PATHS[2]], **provisional_render)
    health_checker_sha256 = hashlib.sha256(rendered_health).hexdigest()
    render = {
        **provisional_render,
        "health_checker_sha256": health_checker_sha256,
    }
    members = [
        Member("PhillipCommodityTaskContract.ps1", task_contract),
        Member(
            "Install-PhillipCommodityWindow02ReadOnlyTask.ps1",
            _render(sources[TEMPLATE_PATHS[1]], **render),
        ),
        Member(
            "Test-PhillipCommodityWindow02TaskHealth.ps1",
            rendered_health,
        ),
        Member("verify_phillip_commodity_window_02_contract.py", verifier),
        Member(
            "PHILLIP_COMMODITY_WINDOW_02_SCHEDULER.md",
            _render(sources[TEMPLATE_PATHS[4]], **render),
        ),
    ]
    artifacts = {
        "schema_version": "phillip-commodity-window-02-scheduler-artifacts-v1",
        "transport_revision": TRANSPORT_REVISION,
        "execution_status": "PREPARED_NOT_EXECUTED_ON_WINDOWS",
        "package_source": {"branch": BRANCH, "commit": commit, "tree": tree},
        "worker": _worker_binding(),
        "new_task_name": TASK_NAME,
        "historical_tasks": [
            {
                "task_name": name,
                "required_state_if_present": "Disabled",
                "mutation": "PROHIBITED",
            }
            for name in (
                "AI_SCALPER-PhillipCommodityV4-ReadOnlyShadow",
                "AI_SCALPER-PhillipCommodityV5-ReadOnlyShadow",
                "AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow",
            )
        ],
        "schedule": _schedule(),
        "operator_root": rf"C:\AI_SCALPER_PRIVATE\{operator_root_name}",
        "extraction_inventory_mode": EXTRACTION_INVENTORY_MODE,
        "members": [member.manifest_row() for member in members],
        "safety": {
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "manual_start": "PROHIBITED",
            "task_scheduler_mutation": "NOT_PERFORMED_DURING_BUILD",
            "broker_mutation": "NOT_PERFORMED",
        },
    }
    members.append(
        Member(
            "PHILLIP_COMMODITY_WINDOW_02_OPERATOR_ARTIFACTS.json",
            _json_bytes(artifacts),
        )
    )
    _write_zip(output, members)

    archive_data = output.read_bytes()
    archive_sha256 = hashlib.sha256(archive_data).hexdigest()
    manifest = {
        "schema_version": "phillip-commodity-window-02-scheduler-transfer-v1",
        "transport_revision": TRANSPORT_REVISION,
        "archive": {
            "path": output.name,
            "size_bytes": len(archive_data),
            "sha256": archive_sha256,
            "encrypted": False,
            "member_count": len(members),
        },
        "source": {"branch": BRANCH, "commit": commit, "tree": tree},
        "worker": _worker_binding(),
        "new_task_name": TASK_NAME,
        "schedule": _schedule(),
        "operator_root": rf"C:\AI_SCALPER_PRIVATE\{operator_root_name}",
        "extraction_inventory_mode": EXTRACTION_INVENTORY_MODE,
        "members": [member.manifest_row() for member in members],
        "safety": {
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "manual_start": "PROHIBITED",
            "task_scheduler_mutation": "NOT_PERFORMED_DURING_BUILD",
            "broker_mutation": "NOT_PERFORMED",
        },
    }
    manifest_path.write_bytes(_json_bytes(manifest))
    manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    helper_path.write_bytes(
        _expand_helper(
            archive_name=output.name,
            archive_size=len(archive_data),
            archive_sha256=archive_sha256,
            manifest_name=manifest_path.name,
            manifest_sha256=manifest_sha256,
            commit=commit,
            tree=tree,
            members=members,
        )
    )
    return {
        "archive": str(output),
        "archive_sha256": archive_sha256,
        "manifest": str(manifest_path),
        "manifest_sha256": manifest_sha256,
        "expand_helper": str(helper_path),
        "source_commit": commit,
        "source_tree": tree,
        "worker_commit": WORKER_COMMIT,
        "contract_payload_sha256": CONTRACT_PAYLOAD_SHA256,
        "task_name": TASK_NAME,
        "member_count": len(members),
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the Phillip Commodity Window 02 scheduler package"
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path(__file__).resolve().parent,
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        result = build_package(args.source_root, args.output)
    except (OSError, ValueError, PackageBuildError) as exc:
        print(
            "PHILLIP_COMMODITY_WINDOW_02_PACKAGE_REJECTED: " + str(exc),
            file=sys.stderr,
        )
        return 2
    print("PHILLIP_COMMODITY_WINDOW_02_SCHEDULER_PACKAGE_READY")
    for key, value in result.items():
        print(f"{key}: {value}")
    print("Order capability: DISABLED")
    print("Live allowed: false")
    print("Task Scheduler mutation: NOT_PERFORMED")
    print("Broker mutation: NOT_PERFORMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
