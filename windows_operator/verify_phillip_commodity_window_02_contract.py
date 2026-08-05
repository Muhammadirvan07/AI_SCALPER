"""Authenticate the exact empty Phillip Commodity Window 02 contract.

This verifier is intentionally pre-observation.  It proves the immutable
contract, frozen snapshot, build identity, dependency environment, and
credential-backed HMAC without requiring a historical proof receipt, audit
export, journal, MT5 module, or broker connection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Callable, Mapping


EXPECTED_WORKER_COMMIT = "da3190013d86426533019d6927a58181c624b1f8"
EXPECTED_WORKER_TREE = "9e84a0d7c9a5b3d4213c6abf0fdf1c8770361d10"
EXPECTED_CONTRACT_ID = "phillip-commodity-window-02-diagnostic-v1"
EXPECTED_SNAPSHOT_ID = "phillip-commodity-dev-pre-window-02-v1"
EXPECTED_KEY_NAME = "phillip-commodity-window-01-v1"
EXPECTED_SIGNING_KEY_ID = "105e393cd619804e"
EXPECTED_REGISTERED_AT_UTC = "2026-08-05T07:16:19.157743Z"
EXPECTED_OBSERVATION_START_UTC = "2026-08-16T16:00:00Z"
EXPECTED_BLIND_UNTIL_UTC = "2026-10-12T15:00:00Z"
EXPECTED_CONTRACT_PAYLOAD_SHA256 = (
    "cbfd753b0aed2d66af56446adc734ce8"
    "d62666e309e91bf74d24b4cc56b613a2"
)
EXPECTED_CONTRACT_FILE_SHA256 = (
    "ad4fd8853563976483fbffbd3bd97847"
    "f7e05c8a4194afd10fa95832e2fe485b"
)
EXPECTED_BUILD_IDENTITY_SHA256 = (
    "9d64b8c9be0b42bdc991b767a7452587"
    "74a57f80613e2fd322791d6d18cc6287"
)
EXPECTED_DEPENDENCY_LOCK_SHA256 = (
    "34087f736724e7d92591f7886f565b15"
    "436c59de0d4e80a59e42b04f2851d862"
)
EXPECTED_GENESIS_INVENTORY: Mapping[str, tuple[int, str]] = {
    "anchors/raw_ticks/XAUUSD/000000.json": (
        764,
        "0954b53a613c2b893da65313cb3cc077d3f3b340405a22f7714295a861112e96",
    ),
    "anchors/segments/XAUUSD/000000.json": (
        763,
        "fd9d1bd1c28ae38e4fdf4894cc2a78103346dbf121d8e52532da97a9556090ab",
    ),
    "calendar_amendments/000000.json": (
        697,
        "6f8a7f90c4ba4ea3b05b7d17f731c0c4e47c0187522fb14b89923343b68bc865",
    ),
    "contract.json": (19601, EXPECTED_CONTRACT_FILE_SHA256),
    "heads/calendar_amendments.json": (
        697,
        "6f8a7f90c4ba4ea3b05b7d17f731c0c4e47c0187522fb14b89923343b68bc865",
    ),
    "heads/raw_ticks/XAUUSD.json": (
        764,
        "0954b53a613c2b893da65313cb3cc077d3f3b340405a22f7714295a861112e96",
    ),
    "heads/segments/XAUUSD.json": (
        763,
        "fd9d1bd1c28ae38e4fdf4894cc2a78103346dbf121d8e52532da97a9556090ab",
    ),
    "seal.json": (
        571,
        "7be98a026bd4a702f17efc70ecadf6d34b7696effb800697c7557603d118ad4a",
    ),
}
EXPECTED_INVENTORY: Mapping[str, tuple[int, str]] = {
    ".contract-write.lock": (
        1,
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    ),
    **EXPECTED_GENESIS_INVENTORY,
}
EXPECTED_FORWARD_PROJECTION_KEYS = frozenset(
    {
        "valid",
        "failures",
        "segment_counts",
        "raw_tick_partition_counts",
        "contract_payload_sha256",
        "contract_hmac_sha256",
        "chain_heads",
        "coverage",
        "observed_data_coverage_complete",
        "data_coverage_complete",
        "coverage_complete",
        "validation_profile",
        "session_calendar_verified",
        "calendar_amendment_chain_verified",
        "calendar_amendment_head",
        "calendar_completeness_required",
        "calendar_completeness_attested",
        "calendar_completeness_satisfied",
        "paired_commit_verified",
        "evidence_root_sha256",
        "sealed",
        "local_anchor_model",
        "off_host_object_lock_verified",
        "external_key_custody_verified",
        "external_tick_sequence_authenticity_verified",
    }
)
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class Window02ContractVerificationError(RuntimeError):
    pass


def _has_reparse_attribute(metadata: os.stat_result) -> bool:
    return bool(
        int(getattr(metadata, "st_file_attributes", 0))
        & FILE_ATTRIBUTE_REPARSE_POINT
    )


def _regular(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise Window02ContractVerificationError(
            f"{label} is unavailable"
        ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _has_reparse_attribute(metadata)
    ):
        raise Window02ContractVerificationError(
            f"{label} must be a regular non-reparse file"
        )
    return path.resolve()


def _directory(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise Window02ContractVerificationError(
            f"{label} is unavailable"
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _has_reparse_attribute(metadata)
    ):
        raise Window02ContractVerificationError(
            f"{label} must be a regular non-reparse directory"
        )
    return path.resolve()


def _read_stable_bytes(path: Path, label: str) -> bytes:
    safe = _regular(path, label)
    before = safe.lstat()
    try:
        value = safe.read_bytes()
    except OSError as exc:
        raise Window02ContractVerificationError(f"{label} is unreadable") from exc
    after = safe.lstat()
    for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns"):
        if getattr(before, field) != getattr(after, field):
            raise Window02ContractVerificationError(
                f"{label} changed while being read"
            )
    if len(value) != after.st_size or _has_reparse_attribute(after):
        raise Window02ContractVerificationError(
            f"{label} changed while being read"
        )
    return value


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON constant is prohibited: {value}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _json_bytes(value: bytes, label: str) -> dict[str, object]:
    try:
        parsed = json.loads(
            value.decode("utf-8"),
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise Window02ContractVerificationError(
            f"{label} is invalid JSON"
        ) from exc
    if not isinstance(parsed, dict):
        raise Window02ContractVerificationError(f"{label} must be an object")
    return parsed


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git(runtime_repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(runtime_repo), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise Window02ContractVerificationError(
            f"git {' '.join(arguments)} failed"
        )
    return completed.stdout.strip()


def _runtime_git_identity(runtime_repo: Path) -> tuple[str, str]:
    commit = _git(runtime_repo, "rev-parse", "HEAD^{commit}")
    tree = _git(runtime_repo, "rev-parse", "HEAD^{tree}")
    dirty = _git(
        runtime_repo,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    if dirty:
        raise Window02ContractVerificationError("frozen runtime worktree is dirty")
    return commit, tree


def _verify_inventory(
    contract_root: Path,
    expected_inventory: Mapping[str, tuple[int, str]],
) -> dict[str, bytes]:
    observed: dict[str, bytes] = {}
    observed_directories: set[str] = set()
    for item in contract_root.rglob("*"):
        relative = item.relative_to(contract_root).as_posix()
        if item.is_dir():
            _directory(item, f"contract directory {relative}")
            observed_directories.add(relative)
            continue
        observed[relative] = _read_stable_bytes(
            item, f"contract artifact {relative}"
        )
    expected_directories: set[str] = set()
    for relative in expected_inventory:
        parent = Path(relative).parent
        while parent != Path("."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    if observed_directories != expected_directories:
        missing = sorted(expected_directories - observed_directories)
        unexpected = sorted(observed_directories - expected_directories)
        raise Window02ContractVerificationError(
            "contract directory inventory mismatch; "
            f"missing={missing}; unexpected={unexpected}"
        )
    observed_paths = set(observed)
    expected_paths = set(expected_inventory)
    if observed_paths != expected_paths:
        missing = sorted(expected_paths - observed_paths)
        unexpected = sorted(observed_paths - expected_paths)
        raise Window02ContractVerificationError(
            "contract artifact inventory mismatch; "
            f"missing={missing}; unexpected={unexpected}"
        )
    for relative, (size_bytes, expected_sha256) in expected_inventory.items():
        value = observed[relative]
        if len(value) != size_bytes or _sha256_bytes(value) != expected_sha256:
            raise Window02ContractVerificationError(
                f"contract artifact drift: {relative}"
            )
    return observed


def _validate_contract(contract: Mapping[str, object]) -> None:
    ruleset = contract.get("ruleset")
    if not isinstance(ruleset, Mapping):
        raise Window02ContractVerificationError("contract ruleset is invalid")
    if (
        contract.get("contract_id") != EXPECTED_CONTRACT_ID
        or contract.get("snapshot_id") != EXPECTED_SNAPSHOT_ID
        or contract.get("registered_at_utc") != EXPECTED_REGISTERED_AT_UTC
        or contract.get("observation_start_at_utc")
        != EXPECTED_OBSERVATION_START_UTC
        or contract.get("blind_until_utc") != EXPECTED_BLIND_UNTIL_UTC
        or contract.get("validation_profile") != "DIAGNOSTIC"
        or contract.get("promotion_profile_eligible") is not False
        or contract.get("contract_payload_sha256")
        != EXPECTED_CONTRACT_PAYLOAD_SHA256
        or contract.get("build_identity_sha256")
        != EXPECTED_BUILD_IDENTITY_SHA256
        or contract.get("signing_key_id") != EXPECTED_SIGNING_KEY_ID
        or contract.get("symbols") != ["XAUUSD"]
        or ruleset.get("git_commit_sha") != EXPECTED_WORKER_COMMIT
        or ruleset.get("git_tree_sha") != EXPECTED_WORKER_TREE
    ):
        raise Window02ContractVerificationError(
            "contract identity or safety mismatch"
        )


def _authoritative_projection(
    runtime_repo: Path,
    artifact_root: Path,
    lock_path: Path,
) -> dict[str, object]:
    sys.path.insert(0, str(runtime_repo))
    try:
        import run_xm_shadow_once as runner

        runner_path = Path(runner.__file__).resolve().parent
        if runner_path != runtime_repo:
            raise Window02ContractVerificationError(
                "worker module was not loaded from the frozen runtime"
            )
        _guard, dependency_receipt = (
            runner._verify_and_activate_dependencies_fresh(lock_path)
        )

        from live_runtime.broker_evidence_profile import (
            load_broker_evidence_profile,
        )
        from live_runtime.evidence_bootstrap import build_current_identity
        from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
        from validation_evidence import verify_forward_evidence

        profile_path = (
            runtime_repo / "config" / "broker_evidence_profiles.v1.json"
        )
        profile = load_broker_evidence_profile(
            profile_path,
            "phillip-commodity",
            require_registration_enabled=True,
        )
        if (
            profile.key_name != EXPECTED_KEY_NAME
            or profile.snapshot_id != EXPECTED_SNAPSHOT_ID
            or profile.contract_id != EXPECTED_CONTRACT_ID
            or profile.template_path
            != "config/phillip_commodity_calendar_window_02.template.json"
        ):
            raise Window02ContractVerificationError(
                "active broker profile binding mismatch"
            )
        signing_key = WindowsEvidenceKeyStore().load(profile.key_name)
        signing_key_id = hashlib.sha256(signing_key).hexdigest()[:16]
        if signing_key_id != EXPECTED_SIGNING_KEY_ID:
            raise Window02ContractVerificationError(
                "evidence signing key identity mismatch"
            )
        config_files = (
            "config/broker_candidates.phase3.json",
            "config/broker_evidence_profiles.v1.json",
            profile.template_path,
        )
        forward = verify_forward_evidence(
            artifact_root,
            EXPECTED_CONTRACT_ID,
            signing_key=signing_key,
            build_identity_provider=lambda: build_current_identity(
                runtime_repo,
                config_files=config_files,
            ),
        )
    except Window02ContractVerificationError:
        raise
    except Exception as exc:
        raise Window02ContractVerificationError(
            "authoritative Window 02 verification failed"
        ) from exc
    return {
        "profile": profile,
        "dependency_receipt": dependency_receipt,
        "forward": forward,
        "signing_key_id": signing_key_id,
    }


def _validate_authority(authority: Mapping[str, object]) -> dict[str, object]:
    forward = authority.get("forward")
    receipt = authority.get("dependency_receipt")
    profile = authority.get("profile")
    if not isinstance(forward, Mapping) or not isinstance(receipt, Mapping):
        raise Window02ContractVerificationError(
            "authoritative verification projection is invalid"
        )
    failures = forward.get("failures")
    coverage = forward.get("coverage")
    chain_heads = forward.get("chain_heads")
    xau_coverage = (
        coverage.get("XAUUSD") if isinstance(coverage, Mapping) else None
    )
    contract_hmac = forward.get("contract_hmac_sha256")
    if (
        set(forward) != EXPECTED_FORWARD_PROJECTION_KEYS
        or getattr(profile, "key_name", None) != EXPECTED_KEY_NAME
        or getattr(profile, "snapshot_id", None) != EXPECTED_SNAPSHOT_ID
        or getattr(profile, "contract_id", None) != EXPECTED_CONTRACT_ID
        or getattr(profile, "template_path", None)
        != "config/phillip_commodity_calendar_window_02.template.json"
        or authority.get("signing_key_id") != EXPECTED_SIGNING_KEY_ID
        or forward.get("valid") is not True
        or not isinstance(failures, list)
        or failures != []
        or forward.get("contract_payload_sha256")
        != EXPECTED_CONTRACT_PAYLOAD_SHA256
        or not isinstance(contract_hmac, str)
        or len(contract_hmac) != 64
        or any(
            character not in "0123456789abcdef"
            for character in contract_hmac
        )
        or not isinstance(chain_heads, Mapping)
        or not isinstance(coverage, Mapping)
        or set(coverage) != {"XAUUSD"}
        or not isinstance(xau_coverage, Mapping)
        or forward.get("validation_profile") != "DIAGNOSTIC"
        or forward.get("sealed") is not False
        or forward.get("observed_data_coverage_complete") is not False
        or forward.get("data_coverage_complete") is not False
        or forward.get("coverage_complete") is not False
        or forward.get("calendar_completeness_required") is not True
        or forward.get("calendar_completeness_attested") is not False
        or forward.get("calendar_completeness_satisfied") is not False
        or forward.get("calendar_amendment_chain_verified") is not True
        or forward.get("session_calendar_verified") is not True
        or forward.get("paired_commit_verified") is not True
        or forward.get("segment_counts") != {"XAUUSD": 0}
        or forward.get("raw_tick_partition_counts") != {"XAUUSD": 0}
        or forward.get("local_anchor_model")
        != "SIGNED_HEAD_AND_APPEND_HISTORY_V1"
        or forward.get("off_host_object_lock_verified") is not False
        or forward.get("external_key_custody_verified") is not False
        or forward.get("external_tick_sequence_authenticity_verified")
        is not False
        or xau_coverage.get("validation_profile") != "DIAGNOSTIC"
        or xau_coverage.get("bar_window_observed") is not False
        or xau_coverage.get("raw_window_observed") is not False
        or xau_coverage.get("observed_data_complete") is not False
        or xau_coverage.get("data_complete") is not False
        or xau_coverage.get("complete") is not False
        or xau_coverage.get("paired_commit_verified") is not True
        or xau_coverage.get("session_calendar_verified") is not True
        or xau_coverage.get("calendar_completeness_satisfied") is not False
    ):
        raise Window02ContractVerificationError(
            "authoritative contract projection mismatch"
        )
    lock_sha256 = receipt.get("lock_sha256")
    if lock_sha256 != EXPECTED_DEPENDENCY_LOCK_SHA256:
        raise Window02ContractVerificationError(
            "dependency verification receipt does not match the frozen lock"
        )
    return dict(forward)


def verify(
    args: argparse.Namespace,
    *,
    expected_inventory: Mapping[str, tuple[int, str]] | None = None,
    git_identity_provider: Callable[[Path], tuple[str, str]] | None = None,
    authority_provider: (
        Callable[[Path, Path, Path], dict[str, object]] | None
    ) = None,
) -> dict[str, object]:
    runtime_repo = _directory(args.runtime_repo, "runtime repository")
    artifact_root = _directory(args.artifact_root, "artifact root")
    lock_path = _regular(args.lock, "dependency lock")
    expected_lock_path = runtime_repo / "pylock.windows-cp312.toml"
    if lock_path != expected_lock_path:
        raise Window02ContractVerificationError(
            "dependency lock is not the frozen runtime lock"
        )
    commit, tree = (git_identity_provider or _runtime_git_identity)(runtime_repo)
    if commit != EXPECTED_WORKER_COMMIT or tree != EXPECTED_WORKER_TREE:
        raise Window02ContractVerificationError(
            "frozen runtime source identity mismatch"
        )

    contract_root = _directory(
        artifact_root / "forward" / EXPECTED_CONTRACT_ID,
        "Window 02 contract root",
    )
    inventory = EXPECTED_INVENTORY if expected_inventory is None else expected_inventory
    if expected_inventory is None:
        # The authoritative frozen verifier creates this one-byte kernel-lock
        # carrier on its first successful call and intentionally keeps it.
        # Authenticate either legitimate pre-call state, then require the
        # exact operational state after the authoritative call.  This makes a
        # clean install and an idempotent retry equally valid without allowing
        # any unbound artifact.
        lock_carrier = contract_root / ".contract-write.lock"
        pre_authority_inventory = (
            EXPECTED_INVENTORY
            if lock_carrier.exists()
            else EXPECTED_GENESIS_INVENTORY
        )
    else:
        pre_authority_inventory = inventory
    observed = _verify_inventory(contract_root, pre_authority_inventory)
    contract_bytes = observed.get("contract.json")
    if contract_bytes is None:
        raise Window02ContractVerificationError("contract.json is unavailable")
    contract = _json_bytes(contract_bytes, "contract.json")
    _validate_contract(contract)

    authority = (authority_provider or _authoritative_projection)(
        runtime_repo,
        artifact_root,
        lock_path,
    )
    forward = _validate_authority(authority)
    if expected_inventory is None:
        observed = _verify_inventory(contract_root, EXPECTED_INVENTORY)
        if observed.get("contract.json") != contract_bytes:
            raise Window02ContractVerificationError(
                "contract.json changed during authoritative verification"
            )
    receipt = authority["dependency_receipt"]
    assert isinstance(receipt, Mapping)
    evidence_root = forward.get("evidence_root_sha256")
    if (
        not isinstance(evidence_root, str)
        or len(evidence_root) != 64
        or any(character not in "0123456789abcdef" for character in evidence_root)
    ):
        raise Window02ContractVerificationError(
            "evidence root identity is unavailable"
        )
    return {
        "schema_version": "phillip-commodity-window-02-contract-verification-v1",
        "status": "PHILLIP_COMMODITY_WINDOW_02_CONTRACT_AUTHENTICATED",
        "candidate_id": "phillip-commodity",
        "contract_id": EXPECTED_CONTRACT_ID,
        "snapshot_id": EXPECTED_SNAPSHOT_ID,
        "registered_at_utc": EXPECTED_REGISTERED_AT_UTC,
        "observation_start_at_utc": EXPECTED_OBSERVATION_START_UTC,
        "blind_until_utc": EXPECTED_BLIND_UNTIL_UTC,
        "worker_source_commit": commit,
        "worker_source_tree": tree,
        "contract_payload_sha256": EXPECTED_CONTRACT_PAYLOAD_SHA256,
        "contract_file_sha256": EXPECTED_CONTRACT_FILE_SHA256,
        "build_identity_sha256": EXPECTED_BUILD_IDENTITY_SHA256,
        "signing_key_id": EXPECTED_SIGNING_KEY_ID,
        "evidence_root_sha256": evidence_root,
        "dependency_lock_sha256": receipt["lock_sha256"],
        "artifact_files_verified": len(inventory),
        "initial_segment_count": 0,
        "initial_raw_tick_partition_count": 0,
        "calendar_amendment_chain_verified": True,
        "source_chain_from_genesis": True,
        "order_capability": "DISABLED",
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "broker_mutation": "NOT_PERFORMED",
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify the exact Phillip Commodity Window 02 contract"
    )
    parser.add_argument("--runtime-repo", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        result = verify(args)
    except (OSError, ValueError, Window02ContractVerificationError) as exc:
        print(
            "PHILLIP_COMMODITY_WINDOW_02_CONTRACT_REJECTED: " + str(exc),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
