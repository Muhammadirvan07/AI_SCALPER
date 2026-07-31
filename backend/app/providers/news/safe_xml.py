"""Fail-closed XML parsing for untrusted external news feeds.

External RSS and Atom payloads are limited to two MiB even when a caller has
a more permissive HTTP setting.  Downloads must reject oversized responses
before parsing; this module repeats the size check so direct parser calls
cannot bypass that boundary.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from defusedxml import ElementTree as DefusedElementTree
from defusedxml.common import DefusedXmlException

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element


MAX_UNTRUSTED_XML_BYTES: Final[int] = 2 * 1024 * 1024


class UnsafeXmlError(ValueError):
    """Raised when an external XML document violates the safe-feed contract."""


def effective_xml_limit(configured_limit: int) -> int:
    """Return a positive feed limit capped by the global untrusted-XML limit."""

    if type(configured_limit) is not int or configured_limit <= 0:
        raise ValueError("configured XML limit must be a positive integer")
    return min(configured_limit, MAX_UNTRUSTED_XML_BYTES)


def parse_untrusted_xml(payload: bytes, *, max_bytes: int) -> Element:
    """Parse bounded XML while rejecting DTDs, entities, and external access."""

    limit = effective_xml_limit(max_bytes)
    if not payload:
        raise UnsafeXmlError("external XML payload is empty")
    if len(payload) > limit:
        raise UnsafeXmlError("external XML payload exceeds the safe size limit")
    try:
        return DefusedElementTree.fromstring(
            payload,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except DefusedXmlException as exc:
        raise UnsafeXmlError("external XML declarations are not allowed") from exc
    except (DefusedElementTree.ParseError, UnicodeError, ValueError) as exc:
        raise UnsafeXmlError("external XML is malformed") from exc
