"""Validate an extracted ``WINDOWS_DECISION_SERVICE_V1`` release.

Runtime construction is deliberately external.  This entrypoint supports only
static validation and cannot fetch decision data or publish to IPC.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
from typing import Any

from live_runtime.contracts import require_hash
from validate_windows_decision_service import validate_windows_decision_service


RELEASE_PROFILE = "WINDOWS_DECISION_SERVICE_V1"
MANIFEST_MEMBER = "RELEASE_MANIFEST.json"


class DecisionServiceLaunchError(RuntimeError):
    """The extracted release or external static configuration is invalid."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _regular_file(path: Path, *, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise DecisionServiceLaunchError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise DecisionServiceLaunchError(f"{label} must be a regular file")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise DecisionServiceLaunchError(f"{label} cannot be read") from exc


def validate_extracted_decision_release(
    release_root: Path,
    *,
    expected_release_identity_sha256: str,
) -> dict[str, Any]:
    expected_identity = require_hash(
        "expected_release_identity_sha256",
        expected_release_identity_sha256,
    )
    configured_root = release_root.expanduser()
    try:
        root_metadata = configured_root.lstat()
    except OSError as exc:
        raise DecisionServiceLaunchError("release root is unavailable") from exc
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or int(getattr(root_metadata, "st_file_attributes", 0)) & 0x400
    ):
        raise DecisionServiceLaunchError("release root must be a real directory")
    root = configured_root.resolve(strict=True)
    try:
        manifest = json.loads(
            _regular_file(root / MANIFEST_MEMBER, label="release manifest").decode(
                "utf-8"
            )
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecisionServiceLaunchError("release manifest is invalid") from exc
    if not isinstance(manifest, dict):
        raise DecisionServiceLaunchError("release manifest must be an object")
    if manifest.get("release_profile") != RELEASE_PROFILE:
        raise DecisionServiceLaunchError("decision release profile mismatch")
    if manifest.get("release_identity_sha256") != expected_identity:
        raise DecisionServiceLaunchError("decision release identity mismatch")
    sources = manifest.get("source_files")
    if not isinstance(sources, list) or not sources:
        raise DecisionServiceLaunchError("decision release source inventory missing")
    expected_paths = {MANIFEST_MEMBER}
    for item in sources:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "size_bytes",
            "sha256",
        }:
            raise DecisionServiceLaunchError("decision release source entry invalid")
        raw_path = item["path"]
        if not isinstance(raw_path, str) or raw_path != PurePosixPath(raw_path).as_posix():
            raise DecisionServiceLaunchError("decision release source path invalid")
        source_path = root / Path(raw_path)
        try:
            source_path.resolve(strict=True).relative_to(root)
        except (OSError, ValueError) as exc:
            raise DecisionServiceLaunchError("decision release source escapes root") from exc
        data = _regular_file(source_path, label=f"release source {raw_path}")
        if len(data) != item["size_bytes"] or _sha256(data) != item["sha256"]:
            raise DecisionServiceLaunchError("decision release source hash mismatch")
        expected_paths.add(raw_path)
    observed_paths: set[str] = set()
    for path in root.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or int(
            getattr(metadata, "st_file_attributes", 0)
        ) & 0x400:
            raise DecisionServiceLaunchError("decision release path indirection detected")
        if stat.S_ISREG(metadata.st_mode):
            observed_paths.add(path.relative_to(root).as_posix())
        elif not stat.S_ISDIR(metadata.st_mode):
            raise DecisionServiceLaunchError("decision release special file detected")
    if observed_paths != expected_paths:
        raise DecisionServiceLaunchError("decision release extracted file set drift")
    return manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate the extracted Windows decision-only service"
    )
    parser.add_argument("--factory-manifest", type=Path, required=True)
    parser.add_argument("--release-root", type=Path, default=Path(__file__).parent)
    parser.add_argument(
        "--expected-release-identity-sha256",
        required=True,
    )
    parser.add_argument("--validate-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.validate_only:
        print("DECISION_SERVICE_REJECTED: external runtime factory is required")
        return 2
    try:
        release = validate_extracted_decision_release(
            args.release_root,
            expected_release_identity_sha256=(
                args.expected_release_identity_sha256
            ),
        )
        factory_raw = _regular_file(
            args.factory_manifest.resolve(strict=True),
            label="external factory manifest",
        )
        factory = json.loads(factory_raw.decode("utf-8"))
        if not isinstance(factory, dict):
            raise DecisionServiceLaunchError("factory manifest must be an object")
        report = validate_windows_decision_service(
            factory_payload=factory,
            expected_release_identity_sha256=release[
                "release_identity_sha256"
            ],
        )
    except (
        DecisionServiceLaunchError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"DECISION_SERVICE_REJECTED: {exc}")
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["port_validation"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
