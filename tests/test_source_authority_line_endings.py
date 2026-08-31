from __future__ import annotations

from reprobit.model import Digest
from reprobit.source_authority import _line_ending_drift_hint


def test_line_ending_drift_identifies_crlf_checkout_of_lf_source() -> None:
    expected = Digest.from_bytes(b"first\nsecond\n")

    hint = _line_ending_drift_hint(b"first\r\nsecond\r\n", expected)

    assert hint is not None
    assert "uses CRLF" in hint
    assert ".gitattributes" in hint


def test_line_ending_drift_identifies_lf_checkout_of_crlf_source() -> None:
    expected = Digest.from_bytes(b"first\r\nsecond\r\n")

    hint = _line_ending_drift_hint(b"first\nsecond\n", expected)

    assert hint is not None
    assert "uses LF" in hint
    assert ".gitattributes" in hint


def test_line_ending_drift_does_not_hide_a_content_change() -> None:
    expected = Digest.from_bytes(b"first\nsecond\n")

    assert _line_ending_drift_hint(b"first\r\nchanged\r\n", expected) is None
