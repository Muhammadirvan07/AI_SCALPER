"""Shared parsing and eligibility verification for gate operator CLIs."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Callable, Iterable

from .broker_evidence_profile import load_broker_evidence_profile
from .broker_window_plan import read_json_object
from .live_canary_broker_eligibility import (
    LiveCanaryBrokerEligibilityEvidence,
)
from .live_canary_broker_eligibility_review import (
    load_live_canary_broker_eligibility_review,
    verify_live_canary_broker_eligibility_review,
)
from .registration_review import load_regulatory_observation


UTC = timezone.utc
_CANONICAL_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
)


def parse_cli_utc(value: str, *, label: str) -> datetime:
    text = str(value or "").strip()
    if _CANONICAL_UTC_RE.fullmatch(text) is None:
        raise ValueError(f"{label} must be canonical UTC ending in Z")
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=UTC
        )
    except ValueError as exc:
        raise ValueError(f"{label} must be canonical UTC ending in Z") from exc
    return parsed


def parse_domain_paths(
    values: Iterable[str],
    *,
    expected_domains: frozenset[str],
    label: str,
) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for raw in values:
        domain, separator, path_text = str(raw or "").partition("=")
        if (
            separator != "="
            or domain not in expected_domains
            or not path_text
            or domain in result
        ):
            raise ValueError(f"{label} must contain each exact DOMAIN=PATH once")
        result[domain] = Path(path_text)
    if frozenset(result) != expected_domains:
        raise ValueError(f"{label} domain inventory is incomplete")
    return result


def load_verified_eligibility_evidence(
    *,
    repo_root: Path,
    candidate: str,
    review_path: Path,
    regulatory_observation_path: Path,
    candidate_config_path: Path,
    profile_config_path: Path,
    key_provider: Callable[[str], bytes | None],
    now: datetime,
) -> LiveCanaryBrokerEligibilityEvidence:
    def rooted(path: Path) -> Path:
        return path if path.is_absolute() else repo_root / path

    profile = load_broker_evidence_profile(
        rooted(profile_config_path), candidate
    )
    candidate_config = read_json_object(rooted(candidate_config_path))
    template = read_json_object(repo_root / profile.template_path)
    review = load_live_canary_broker_eligibility_review(rooted(review_path))
    observation = load_regulatory_observation(
        rooted(regulatory_observation_path)
    )
    return verify_live_canary_broker_eligibility_review(
        review,
        observation,
        candidate_config,
        template,
        diagnostic_key_provider=key_provider,
        live_key_provider=key_provider,
        now_provider=lambda: now,
    )


__all__ = [
    "load_verified_eligibility_evidence",
    "parse_cli_utc",
    "parse_domain_paths",
]
