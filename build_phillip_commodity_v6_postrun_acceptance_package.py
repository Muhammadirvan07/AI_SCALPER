"""Build one deterministic, read-only Phillip Commodity V6 post-run toolkit."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import zipfile


BRANCH = "agent/live-grade-phase3"
V63_REMEDIATION_COMMIT = "14762eac7e991fee8818ee20816709066f457f06"
V63_REMEDIATION_TREE = "727f5215b203796c584d7bf321edac2447e92a60"
V63_HEALTH_CHECKER_SHA256 = (
    "29b1cc9958d9f471a6664eea449f272c"
    "a539d750fa5778586303c7272990c1e5"
)
V63_TASK_CONTRACT_SHA256 = (
    "e40b315c5cae30b6708d04e39314fc13"
    "c4dbc9dffb18c2a37c4d2f6f959acbc6"
)
V63_EVIDENCE_VERIFIER_SHA256 = (
    "980712896acb613665e18f46d8cdc62e"
    "ac95bfc90ede222c318c374b0849606c"
)
TASK_NAME = "AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow"
CONTRACT_ID = "phillip-commodity-window-01-diagnostic-v5"
FIRST_SCHEDULED_START_UTC = "2026-07-29T21:45:00Z"
SCHEDULE_END_UTC = "2026-09-21T15:16:00Z"
TOOLKIT_SCHEMA = "phillip-commodity-v6-postrun-toolkit-v1"
TOOLKIT_MANIFEST = "PHILLIP_COMMODITY_V6_POSTRUN_TOOLKIT.json"
FIXED_ZIP_TIMESTAMP = (2026, 7, 30, 6, 45, 0)
FIXED_ZIP_MODE = stat.S_IFREG | 0o644
SOURCE_PATHS = {
    "Invoke-PhillipCommodityV6PostRunAcceptance.ps1": (
        "windows_operator/Invoke-PhillipCommodityV6PostRunAcceptance.ps1"
    ),
    "phillip_commodity_v6_postrun_acceptance.py": (
        "windows_operator/phillip_commodity_v6_postrun_acceptance.py"
    ),
    "PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE.md": (
        "docs/PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE.md"
    ),
}


class PostRunToolkitBuildError(RuntimeError):
    pass


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise PostRunToolkitBuildError(
            f"git {' '.join(args)} failed: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def _source_identity(root: Path) -> tuple[str, str]:
    commit = _git(root, "rev-parse", "HEAD^{commit}")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(
        r"[0-9a-f]{40}", tree
    ):
        raise PostRunToolkitBuildError("invalid Git source identity")
    return commit, tree


def _tracked_source(root: Path, relative: str) -> bytes:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise PostRunToolkitBuildError(f"source is not a regular file: {relative}")
    expected = subprocess.run(
        ["git", "-C", str(root), "show", f"HEAD:{relative}"],
        check=False,
        capture_output=True,
    )
    if expected.returncode != 0:
        raise PostRunToolkitBuildError(f"source is not tracked at HEAD: {relative}")
    observed = path.read_bytes()
    if observed != expected.stdout:
        raise PostRunToolkitBuildError(f"tracked source drift: {relative}")
    return observed


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _member_row(path: str, data: bytes) -> dict[str, object]:
    return {"path": path, "size_bytes": len(data), "sha256": _sha256(data)}


def _render_wrapper(source: bytes, *, commit: str, tree: str, tool_sha256: str) -> bytes:
    text = source.decode("utf-8")
    replacements = {
        "__TOOLKIT_SOURCE_COMMIT__": commit,
        "__TOOLKIT_SOURCE_TREE__": tree,
        "__POSTRUN_TOOL_SHA256__": tool_sha256,
    }
    for token, value in replacements.items():
        if text.count(token) != 1:
            raise PostRunToolkitBuildError(f"wrapper placeholder count invalid: {token}")
        text = text.replace(token, value)
    if any(token in text for token in replacements):
        raise PostRunToolkitBuildError("wrapper has unresolved placeholders")
    return text.encode("utf-8")


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, FIXED_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = FIXED_ZIP_MODE << 16
    info.create_system = 3
    return info


def build_package(source_root: Path, output: Path) -> dict[str, object]:
    source_root = source_root.resolve()
    output = output.absolute()
    if not re.fullmatch(
        r"phillip-commodity-v6-postrun-toolkit-[0-9a-f]{8,12}\.zip",
        output.name,
    ):
        raise PostRunToolkitBuildError("output filename is not the reviewed form")
    if output.exists():
        raise PostRunToolkitBuildError("output artifact already exists")
    if output.parent.exists() and output.parent.is_symlink():
        raise PostRunToolkitBuildError("output parent must not be a symlink")
    output.parent.mkdir(parents=True, exist_ok=True)
    commit, tree = _source_identity(source_root)
    tracked = {
        archive_path: _tracked_source(source_root, source_path)
        for archive_path, source_path in SOURCE_PATHS.items()
    }
    tool_data = tracked["phillip_commodity_v6_postrun_acceptance.py"]
    tracked["Invoke-PhillipCommodityV6PostRunAcceptance.ps1"] = _render_wrapper(
        tracked["Invoke-PhillipCommodityV6PostRunAcceptance.ps1"],
        commit=commit,
        tree=tree,
        tool_sha256=_sha256(tool_data),
    )
    rows = [_member_row(path, tracked[path]) for path in sorted(tracked)]
    manifest = {
        "schema_version": TOOLKIT_SCHEMA,
        "source": {"branch": BRANCH, "commit": commit, "tree": tree},
        "installed_scheduler": {
            "remediation_source_commit": V63_REMEDIATION_COMMIT,
            "remediation_source_tree": V63_REMEDIATION_TREE,
            "health_checker_sha256": V63_HEALTH_CHECKER_SHA256,
            "task_contract_sha256": V63_TASK_CONTRACT_SHA256,
            "evidence_verifier_sha256": V63_EVIDENCE_VERIFIER_SHA256,
            "task_name": TASK_NAME,
            "contract_id": CONTRACT_ID,
            "first_scheduled_start_utc": FIRST_SCHEDULED_START_UTC,
            "schedule_end_utc": SCHEDULE_END_UTC,
        },
        "members": rows,
        "safety": {
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "task_scheduler_mutation": "NOT_PERFORMED",
            "broker_mutation": "NOT_PERFORMED",
            "offhost_custody_performed": False,
        },
    }
    tracked[TOOLKIT_MANIFEST] = _json_bytes(manifest)
    try:
        with output.open("xb") as handle:
            with zipfile.ZipFile(
                handle,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            ) as archive:
                for path in (*sorted(SOURCE_PATHS), TOOLKIT_MANIFEST):
                    archive.writestr(_zip_info(path), tracked[path])
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        output.unlink(missing_ok=True)
        raise
    archive_data = output.read_bytes()
    return {
        "status": "PHILLIP_COMMODITY_V6_POSTRUN_TOOLKIT_READY",
        "archive": str(output),
        "archive_sha256": _sha256(archive_data),
        "archive_size_bytes": len(archive_data),
        "source_commit": commit,
        "source_tree": tree,
        "member_count": len(tracked),
        "order_capability": "DISABLED",
        "live_allowed": False,
        "task_scheduler_mutation": "NOT_PERFORMED",
        "broker_mutation": "NOT_PERFORMED",
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the Phillip Commodity V6 post-run acceptance toolkit."
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
    except (OSError, ValueError, PostRunToolkitBuildError) as exc:
        print(f"PHILLIP_COMMODITY_V6_POSTRUN_TOOLKIT_REJECTED: {exc}", file=sys.stderr)
        return 2
    for key, value in result.items():
        print(f"{key}: {value}")
    print("Off-host custody: NOT_PERFORMED")
    print("Order capability: DISABLED")
    print("Live allowed: false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
