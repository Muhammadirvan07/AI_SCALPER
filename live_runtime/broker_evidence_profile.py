"""Tracked broker-specific identities for the generic evidence pipeline."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import re
from typing import Mapping


PROFILE_SCHEMA_VERSION = "broker-evidence-profiles-v1"
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")


class BrokerEvidenceProfileError(RuntimeError):
    pass


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BrokerEvidenceProfileError(f"{field} is required")
    return value.strip()


def _relative_path(value: object, field: str) -> str:
    text = _text(value, field).replace("\\", "/")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise BrokerEvidenceProfileError(f"{field} must be a safe repository path")
    return path.as_posix()


@dataclass(frozen=True)
class BrokerEvidenceProfile:
    candidate_id: str
    key_name: str
    snapshot_id: str
    contract_id: str
    template_path: str
    registration_enabled: bool
    status: str

    def __post_init__(self) -> None:
        candidate = _text(self.candidate_id, "candidate_id").lower()
        if _IDENTIFIER.fullmatch(candidate) is None:
            raise BrokerEvidenceProfileError("candidate_id is invalid")
        object.__setattr__(self, "candidate_id", candidate)
        for field in ("key_name", "snapshot_id", "contract_id"):
            normalized = _text(getattr(self, field), field).lower()
            if _IDENTIFIER.fullmatch(normalized) is None:
                raise BrokerEvidenceProfileError(f"{field} is invalid")
            if not normalized.startswith(candidate + "-"):
                raise BrokerEvidenceProfileError(
                    f"{field} must be namespaced to the candidate"
                )
            object.__setattr__(self, field, normalized)
        object.__setattr__(
            self,
            "template_path",
            _relative_path(self.template_path, "template_path"),
        )
        if type(self.registration_enabled) is not bool:
            raise BrokerEvidenceProfileError("registration_enabled must be boolean")
        object.__setattr__(self, "status", _text(self.status, "status").upper())


def load_broker_evidence_profile(
    path: str | Path,
    candidate_id: str,
    *,
    require_registration_enabled: bool = False,
) -> BrokerEvidenceProfile:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise BrokerEvidenceProfileError(
            "broker evidence profile must be a regular file"
        )
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BrokerEvidenceProfileError(
            "broker evidence profile configuration is unavailable"
        ) from exc
    if not isinstance(payload, Mapping) or set(payload) != {
        "schema_version",
        "execution_enabled",
        "live_allowed",
        "safe_to_demo_auto_order",
        "max_lot",
        "profiles",
    }:
        raise BrokerEvidenceProfileError("broker evidence profile root is invalid")
    if (
        payload.get("schema_version") != PROFILE_SCHEMA_VERSION
        or payload.get("execution_enabled") is not False
        or payload.get("live_allowed") is not False
        or payload.get("safe_to_demo_auto_order") is not False
        or payload.get("max_lot") != 0.01
    ):
        raise BrokerEvidenceProfileError("broker evidence profile violates safety locks")
    profiles = payload.get("profiles")
    if not isinstance(profiles, list):
        raise BrokerEvidenceProfileError("broker evidence profile list is invalid")
    requested = _text(candidate_id, "candidate_id").lower()
    matches = [
        item
        for item in profiles
        if isinstance(item, Mapping)
        and str(item.get("candidate_id") or "").lower() == requested
    ]
    if len(matches) != 1 or set(matches[0]) != {
        "candidate_id",
        "key_name",
        "snapshot_id",
        "contract_id",
        "template_path",
        "registration_enabled",
        "status",
    }:
        raise BrokerEvidenceProfileError("candidate evidence profile is invalid")
    profile = BrokerEvidenceProfile(**dict(matches[0]))
    if require_registration_enabled and not profile.registration_enabled:
        raise BrokerEvidenceProfileError(
            "broker evidence registration remains blocked by external gates"
        )
    return profile


__all__ = [
    "BrokerEvidenceProfile",
    "BrokerEvidenceProfileError",
    "PROFILE_SCHEMA_VERSION",
    "load_broker_evidence_profile",
]
