"""Strict local request adapters for prospective calendar governance."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping


AMENDMENT_REQUEST_SCHEMA_VERSION = "calendar-amendment-request-v1"
COMPLETENESS_REQUEST_SCHEMA_VERSION = "calendar-completeness-request-v1"
_AMENDMENT_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "contract_id",
        "amendment_id",
        "expected_previous_head_hmac_sha256",
        "source",
        "closures",
    }
)
_COMPLETENESS_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "contract_id",
        "attestation_id",
        "expected_final_head_hmac_sha256",
        "reviewed_sources",
    }
)


class CalendarOperatorInputError(ValueError):
    pass


def _reject_constant(value: str) -> None:
    raise CalendarOperatorInputError("non-finite JSON values are not allowed")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CalendarOperatorInputError("duplicate JSON keys are not allowed")
        result[key] = value
    return result


def _read_request(path: str | Path) -> dict[str, object]:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise CalendarOperatorInputError("operator input must be a regular file")
    try:
        value = json.loads(
            source.read_text(encoding="utf-8"),
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CalendarOperatorInputError("operator input is invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise CalendarOperatorInputError("operator input must be a JSON object")
    return dict(value)


def _bind_request(
    path: str | Path,
    *,
    schema_version: str,
    fields: frozenset[str],
    candidate_id: str,
    contract_id: str,
) -> dict[str, object]:
    request = _read_request(path)
    if set(request) != set(fields):
        raise CalendarOperatorInputError("operator input fields are invalid")
    if request.get("schema_version") != schema_version:
        raise CalendarOperatorInputError("operator input schema is invalid")
    if request.get("candidate_id") != candidate_id:
        raise CalendarOperatorInputError("operator candidate binding mismatch")
    if request.get("contract_id") != contract_id:
        raise CalendarOperatorInputError("operator contract binding mismatch")
    return request


def load_amendment_request(
    path: str | Path,
    *,
    candidate_id: str,
    contract_id: str,
) -> dict[str, object]:
    return _bind_request(
        path,
        schema_version=AMENDMENT_REQUEST_SCHEMA_VERSION,
        fields=_AMENDMENT_FIELDS,
        candidate_id=candidate_id,
        contract_id=contract_id,
    )


def load_completeness_request(
    path: str | Path,
    *,
    candidate_id: str,
    contract_id: str,
) -> dict[str, object]:
    return _bind_request(
        path,
        schema_version=COMPLETENESS_REQUEST_SCHEMA_VERSION,
        fields=_COMPLETENESS_FIELDS,
        candidate_id=candidate_id,
        contract_id=contract_id,
    )


__all__ = [
    "AMENDMENT_REQUEST_SCHEMA_VERSION",
    "COMPLETENESS_REQUEST_SCHEMA_VERSION",
    "CalendarOperatorInputError",
    "load_amendment_request",
    "load_completeness_request",
]
