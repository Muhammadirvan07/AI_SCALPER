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
WORKER_COMMIT = "290cc23d9d87f93e914612afdfecfc481d2c232f"
WORKER_TREE = "ef568ae39aa4c51d9afe738badbb86d2c45e9a58"
CONTRACT_ID = "phillip-commodity-window-01-diagnostic-v5"
PROOF_SHA256 = (
    "29e14f81bbd87d460f171484d59a40e9"
    "bdd6ae00611c3453ade4aa6c846b3aec"
)
TEMPLATE_PATHS = (
    "windows_operator/PhillipCommodityTaskContract.ps1",
    "windows_operator/Install-PhillipCommodityV6ReadOnlyTask.ps1",
    "windows_operator/Test-PhillipCommodityV6TaskHealth.ps1",
    "windows_operator/verify_phillip_commodity_v5_scheduler_evidence.py",
    "docs/PHILLIP_COMMODITY_V6_SCHEDULER_REMEDIATION.md",
)
ARCHIVE_TIMESTAMP = (2026, 7, 26, 12, 0, 0)


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


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise PackageBuildError(
            f"git {' '.join(args)} failed: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def _source_identity(root: Path) -> tuple[str, str]:
    commit = _git(root, "rev-parse", "HEAD^{commit}")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    if len(commit) != 40 or len(tree) != 40:
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
    evidence_verifier_sha256: str,
    package_name: str,
) -> bytes:
    text = source.decode("utf-8")
    replacements = {
        "__REMEDIATION_COMMIT__": commit,
        "__REMEDIATION_TREE__": tree,
        "__TASK_CONTRACT_SHA256__": task_contract_sha256,
        "__EVIDENCE_VERIFIER_SHA256__": evidence_verifier_sha256,
        "__PACKAGE_NAME__": package_name,
    }
    for placeholder, value in replacements.items():
        text = text.replace(placeholder, value)
    unresolved = sorted(
        token
        for token in replacements
        if token in text
    )
    if unresolved:
        raise PackageBuildError(
            f"unresolved package placeholders: {', '.join(unresolved)}"
        )
    return text.encode("utf-8")


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
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
    source = f'''[CmdletBinding()]
param(
  [Parameter()]
  [string]$ArchivePath = (Join-Path $PSScriptRoot "{archive_name}"),

  [Parameter()]
  [string]$ManifestPath = (Join-Path $PSScriptRoot "{manifest_name}"),

  [Parameter()]
  [string]$OperatorRoot = (
    "C:\\AI_SCALPER_PRIVATE\\" +
    "phillip-commodity-v6-scheduler-operator"
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

$archive = Get-ExactLeaf -Path $ArchivePath -Label "V6 archive"
$manifestFile = Get-ExactLeaf `
  -Path $ManifestPath `
  -Label "V6 transfer manifest"
if (
  $archive.Name -ne $expectedArchiveName -or
  $archive.Length -ne $expectedArchiveSize
) {{
  throw "V6 archive name or size mismatch."
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
  throw "V6 transfer artifact hash mismatch."
}}

$manifest = Get-Content -LiteralPath $manifestFile.FullName -Raw |
  ConvertFrom-Json
if (
  $manifest.schema_version -ne
    "phillip-commodity-v6-scheduler-transfer-v1" -or
  $manifest.archive.path -ne $expectedArchiveName -or
  [int64]$manifest.archive.size_bytes -ne $expectedArchiveSize -or
  $manifest.archive.sha256 -ne $expectedArchiveSha256 -or
  $manifest.source.commit -ne $expectedCommit -or
  $manifest.source.tree -ne $expectedTree -or
  $manifest.worker.source_commit -ne "{WORKER_COMMIT}" -or
  $manifest.worker.source_tree -ne "{WORKER_TREE}" -or
  $manifest.worker.contract_id -ne "{CONTRACT_ID}" -or
  $manifest.worker.proof_receipt_sha256 -ne "{PROOF_SHA256}" -or
  $manifest.evidence_checkpoint_mode -ne
    "HMAC_SIGNED_INCREMENTAL_WITH_LIVE_JOURNAL_HEAD_V2" -or
  $manifest.historical_archive_audit_mode -ne
    "FULL_EXPLICIT_AND_INSTALL_GATE" -or
  [int]$manifest.historical_archive_quiescence_lead_seconds -ne 3600 -or
  $manifest.health_checkpoint_serialization -ne
    "NAMED_MUTEX_CREATE_EXCLUSIVE_V1" -or
  $manifest.checkpoint_publication -ne
    "FLUSHED_TEMP_ATOMIC_MOVE_V1" -or
  $manifest.safety.order_capability -ne "DISABLED" -or
  $manifest.safety.live_allowed -ne $false -or
  $manifest.safety.safe_to_demo_auto_order -ne $false
) {{
  throw "V6 transfer manifest identity or safety mismatch."
}}

$expectedMembersJson = [System.Text.Encoding]::UTF8.GetString(
  [System.Convert]::FromBase64String($memberInventoryBase64)
)
$expectedMembers = @($expectedMembersJson | ConvertFrom-Json)
if (Test-Path -LiteralPath $OperatorRoot) {{
  throw "V6 operator root already exists; preserve it for review."
}}
New-Item -ItemType Directory -Path $OperatorRoot -ErrorAction Stop |
  Out-Null

try {{
  Expand-Archive `
    -LiteralPath $archive.FullName `
    -DestinationPath $OperatorRoot
  $observed = @(Get-ChildItem -LiteralPath $OperatorRoot -Force)
  if (
    $observed.Count -ne $expectedMembers.Count -or
    @($observed | Where-Object {{ $_.PSIsContainer }}).Count -ne 0
  ) {{
    throw "Extracted V6 inventory count or type mismatch."
  }}
  foreach ($expected in $expectedMembers) {{
    $memberPath = Join-Path $OperatorRoot ([string]$expected.path)
    $member = Get-ExactLeaf `
      -Path $memberPath `
      -Label "Extracted V6 member"
    $memberHash = (
      Get-FileHash -LiteralPath $member.FullName -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if (
      $member.Length -ne [int64]$expected.size_bytes -or
      $memberHash -ne [string]$expected.sha256
    ) {{
      throw "Extracted V6 member mismatch: $($expected.path)"
    }}
  }}
}}
catch {{
  throw (
    "V6 extraction failed. Preserve the operator root and transfer " +
    "artifacts for forensic review. $($_.Exception.Message)"
  )
}}

[PSCustomObject]@{{
  Status = "PHILLIP_COMMODITY_V6_SCHEDULER_TRANSFER_VERIFIED"
  ArchiveSHA256 = $archiveHash
  RemediationSourceCommit = $expectedCommit
  RemediationSourceTree = $expectedTree
  FrozenWorkerCommit = "{WORKER_COMMIT}"
  Contract = "{CONTRACT_ID}"
  FilesVerified = $expectedMembers.Count
  OrderCapability = "DISABLED"
  LiveAllowed = $false
  TaskSchedulerMutation = "NOT_PERFORMED"
  BrokerMutation = "NOT_PERFORMED"
}} | Format-List
'''
    return source.encode("utf-8")


def build_package(source_root: Path, output: Path) -> dict[str, object]:
    source_root = source_root.resolve()
    output = output.resolve()
    if not re.fullmatch(
        r"phillip-commodity-v6-scheduler-[0-9a-f]{8,12}\.zip",
        output.name,
    ):
        raise PackageBuildError("output filename is not the reviewed V6 form")
    if output.exists() or Path(f"{output}.manifest.json").exists():
        raise PackageBuildError("output artifact already exists")
    helper_path = output.parent / "Expand-PhillipCommodityV6SchedulerPackage.ps1"
    if helper_path.exists():
        raise PackageBuildError("expansion helper already exists")
    output.parent.mkdir(parents=True, exist_ok=True)

    commit, tree = _source_identity(source_root)
    source = {
        relative: _tracked_source(source_root, relative)
        for relative in TEMPLATE_PATHS
    }
    contract_data = source[TEMPLATE_PATHS[0]]
    contract_sha256 = hashlib.sha256(contract_data).hexdigest()
    evidence_verifier_data = source[TEMPLATE_PATHS[3]]
    evidence_verifier_sha256 = hashlib.sha256(
        evidence_verifier_data
    ).hexdigest()
    package_name = output.name
    members = [
        Member("PhillipCommodityTaskContract.ps1", contract_data),
        Member(
            "Install-PhillipCommodityV6ReadOnlyTask.ps1",
            _render(
                source[TEMPLATE_PATHS[1]],
                commit=commit,
                tree=tree,
                task_contract_sha256=contract_sha256,
                evidence_verifier_sha256=evidence_verifier_sha256,
                package_name=package_name,
            ),
        ),
        Member(
            "Test-PhillipCommodityV6TaskHealth.ps1",
            _render(
                source[TEMPLATE_PATHS[2]],
                commit=commit,
                tree=tree,
                task_contract_sha256=contract_sha256,
                evidence_verifier_sha256=evidence_verifier_sha256,
                package_name=package_name,
            ),
        ),
        Member(
            "verify_phillip_commodity_v5_scheduler_evidence.py",
            evidence_verifier_data,
        ),
        Member(
            "PHILLIP_COMMODITY_V6_SCHEDULER_REMEDIATION.md",
            _render(
                source[TEMPLATE_PATHS[4]],
                commit=commit,
                tree=tree,
                task_contract_sha256=contract_sha256,
                evidence_verifier_sha256=evidence_verifier_sha256,
                package_name=package_name,
            ),
        ),
    ]
    artifacts = {
        "schema_version": "phillip-commodity-v6-scheduler-artifacts-v1",
        "execution_status": "PREPARED_NOT_EXECUTED_ON_WINDOWS",
        "remediation_source": {"branch": BRANCH, "commit": commit, "tree": tree},
        "worker": {
            "source_commit": WORKER_COMMIT,
            "source_tree": WORKER_TREE,
            "contract_id": CONTRACT_ID,
            "proof_receipt_sha256": PROOF_SHA256,
        },
        "preserved_tasks": [
            {
                "task_name": "AI_SCALPER-PhillipCommodityV4-ReadOnlyShadow",
                "required_state": "Disabled",
                "mutation": "PROHIBITED",
            },
            {
                "task_name": "AI_SCALPER-PhillipCommodityV5-ReadOnlyShadow",
                "required_state": "Disabled",
                "mutation": "PROHIBITED",
            },
        ],
        "new_task_name": "AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow",
        "first_scheduled_start_utc": "2026-07-26T21:45:00Z",
        "evidence_checkpoint_mode": (
            "HMAC_SIGNED_INCREMENTAL_WITH_LIVE_JOURNAL_HEAD_V2"
        ),
        "historical_archive_audit_mode": "FULL_EXPLICIT_AND_INSTALL_GATE",
        "historical_archive_quiescence_lead_seconds": 3600,
        "health_checkpoint_serialization": "NAMED_MUTEX_CREATE_EXCLUSIVE_V1",
        "checkpoint_publication": "FLUSHED_TEMP_ATOMIC_MOVE_V1",
        "audit_publication_commit_marker": "MANIFEST",
        "members": [member.manifest_row() for member in members],
        "safety": {
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "broker_mutation": "NOT_PERFORMED",
        },
    }
    members.append(
        Member("PHILLIP_COMMODITY_V6_OPERATOR_ARTIFACTS.json", _json_bytes(artifacts))
    )
    _write_zip(output, members)

    archive_data = output.read_bytes()
    archive_sha256 = hashlib.sha256(archive_data).hexdigest()
    manifest = {
        "schema_version": "phillip-commodity-v6-scheduler-transfer-v1",
        "archive": {
            "path": output.name,
            "size_bytes": len(archive_data),
            "sha256": archive_sha256,
            "encrypted": False,
            "member_count": len(members),
        },
        "source": {"branch": BRANCH, "commit": commit, "tree": tree},
        "worker": {
            "source_commit": WORKER_COMMIT,
            "source_tree": WORKER_TREE,
            "contract_id": CONTRACT_ID,
            "proof_receipt_sha256": PROOF_SHA256,
        },
        "evidence_checkpoint_mode": (
            "HMAC_SIGNED_INCREMENTAL_WITH_LIVE_JOURNAL_HEAD_V2"
        ),
        "historical_archive_audit_mode": "FULL_EXPLICIT_AND_INSTALL_GATE",
        "historical_archive_quiescence_lead_seconds": 3600,
        "health_checkpoint_serialization": "NAMED_MUTEX_CREATE_EXCLUSIVE_V1",
        "checkpoint_publication": "FLUSHED_TEMP_ATOMIC_MOVE_V1",
        "audit_publication_commit_marker": "MANIFEST",
        "members": [member.manifest_row() for member in members],
        "safety": {
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "task_scheduler_mutation": "NOT_PERFORMED_DURING_BUILD",
            "broker_mutation": "NOT_PERFORMED",
        },
    }
    manifest_path = Path(f"{output}.manifest.json")
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
        "member_count": len(members),
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the Phillip Commodity V6 scheduler remediation package."
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
        print(f"PHILLIP_COMMODITY_V6_PACKAGE_REJECTED: {exc}", file=sys.stderr)
        return 2
    print("PHILLIP_COMMODITY_V6_SCHEDULER_PACKAGE_READY")
    for key, value in result.items():
        print(f"{key}: {value}")
    print("Order capability: DISABLED")
    print("Live allowed: false")
    print("Task Scheduler mutation: NOT_PERFORMED")
    print("Broker mutation: NOT_PERFORMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
