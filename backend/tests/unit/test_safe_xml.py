from __future__ import annotations

import pytest

from app.providers.news.safe_xml import (
    MAX_UNTRUSTED_XML_BYTES,
    UnsafeXmlError,
    effective_xml_limit,
    parse_untrusted_xml,
)


def test_valid_rss_and_declared_encoding_are_preserved() -> None:
    utf8 = parse_untrusted_xml(
        b"<rss><channel><title>Safe feed</title></channel></rss>",
        max_bytes=4096,
    )
    latin1 = parse_untrusted_xml(
        '<?xml version="1.0" encoding="iso-8859-1"?><rss><title>Caf\xe9</title></rss>'.encode("latin-1"),
        max_bytes=4096,
    )

    assert utf8.findtext("./channel/title") == "Safe feed"
    assert latin1.findtext("title") == "Caf\xe9"


@pytest.mark.parametrize(
    "payload",
    [
        b"<rss>",
        b"not-xml",
        b"\xff\xfe\x00broken",
    ],
)
def test_malformed_xml_is_rejected_without_echoing_payload(payload: bytes) -> None:
    with pytest.raises(UnsafeXmlError, match="malformed") as caught:
        parse_untrusted_xml(payload, max_bytes=4096)

    assert payload.decode("utf-8", errors="ignore") not in str(caught.value)


@pytest.mark.parametrize(
    "payload",
    [
        b"<!DOCTYPE rss><rss/>",
        b'<!DOCTYPE rss [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><rss>&xxe;</rss>',
        b'<!DOCTYPE rss [<!ENTITY a "1234567890"><!ENTITY b "&a;&a;&a;&a;&a;">]><rss>&b;</rss>',
    ],
)
def test_dtd_external_entity_and_entity_expansion_are_rejected(payload: bytes) -> None:
    with pytest.raises(UnsafeXmlError, match="declarations"):
        parse_untrusted_xml(payload, max_bytes=4096)


def test_empty_and_oversized_payloads_are_rejected_before_parsing() -> None:
    with pytest.raises(UnsafeXmlError, match="empty"):
        parse_untrusted_xml(b"", max_bytes=4096)
    with pytest.raises(UnsafeXmlError, match="size limit"):
        parse_untrusted_xml(b"x" * 4097, max_bytes=4096)


def test_untrusted_xml_limit_is_globally_capped_and_requires_an_integer() -> None:
    assert effective_xml_limit(MAX_UNTRUSTED_XML_BYTES * 2) == MAX_UNTRUSTED_XML_BYTES
    with pytest.raises(ValueError, match="positive integer"):
        effective_xml_limit(0)
    with pytest.raises(ValueError, match="positive integer"):
        effective_xml_limit(True)
