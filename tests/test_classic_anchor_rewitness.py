from __future__ import annotations

import pytest

from reprobit.artifacts import digest_bytes
from reprobit.classic.anchor_rewitness import rewitness_operations
from reprobit.classic.overlay_document import render_classic_overlay_proposal
from reprobit.classic.overlay_types import SourceEditError


def _seat_digest(tokens: list[str]) -> str:
    return digest_bytes("\0".join(tokens).encode("ascii"))


def _declaration(source: bytes, ops: list[dict[str, object]]) -> dict[str, object]:
    return {
        "path": "src/unit.cpp",
        "clean": digest_bytes(source),
        "effective": digest_bytes(source),
        "ops": ops,
    }


def _render(source: bytes, ops: list[dict[str, object]]) -> bytes:
    result = render_classic_overlay_proposal(
        [_declaration(source, ops)], {"src/unit.cpp": source}
    )
    return result.outputs["src/unit.cpp"]


_ORIGINAL = b"int alpha;\nint omega;\n"
_SEAM_OPS: list[dict[str, object]] = [
    {
        "op": "insert",
        "anchor": {
            "ctx": _seat_digest(["int", "alpha", ";", "<SEAT>", "int", "omega", ";"]),
            "b": 3,
            "a": 3,
            "line_before": digest_bytes(b"int alpha;"),
            "line_after": digest_bytes(b"int omega;"),
        },
        "gen": {"k": "fwd", "id": "Spare"},
    }
]


def test_strict_render_succeeds_on_unedited_source() -> None:
    rendered = _render(_ORIGINAL, _SEAM_OPS)
    assert b"class Spare;" in rendered


def test_unedited_source_needs_no_rewitness() -> None:
    assert rewitness_operations(_SEAM_OPS, _ORIGINAL) is None


def test_blank_line_at_seat_is_rewitnessed() -> None:
    edited = b"int alpha;\n\nint omega;\n"
    with pytest.raises(SourceEditError):
        _render(edited, _SEAM_OPS)

    rescued = rewitness_operations(_SEAM_OPS, edited)
    assert rescued is not None
    updated_ops, changes = rescued
    anchor = updated_ops[0]["anchor"]
    # The token context still resolves; only the seat pair is re-witnessed,
    # canonical seat directly after the recorded before-line.
    assert anchor["ctx"] == _SEAM_OPS[0]["anchor"]["ctx"]
    assert anchor["line_before"] == digest_bytes(b"int alpha;")
    assert anchor["line_after"] == digest_bytes(b"")
    assert {location for location, _, _ in changes} == {"0 anchor.line_after"}

    rendered = _render(edited, updated_ops)
    assert b"class Spare;" in rendered
    assert rendered.index(b"int alpha;") < rendered.index(b"class Spare;")
    assert rendered.index(b"class Spare;") < rendered.index(b"int omega;")


def test_token_move_is_rewitnessed_via_unique_seat_pair() -> None:
    original = b"int aa;\nint bb;\nint cc;\nint dd;\nint ee;\n"
    ops: list[dict[str, object]] = [
        {
            "op": "insert",
            "anchor": {
                "ctx": _seat_digest(
                    ["int", "aa", ";", "int", "bb", ";", "<SEAT>", "int", "cc", ";", "int", "dd", ";"]
                ),
                "b": 6,
                "a": 6,
                "line_before": digest_bytes(b"int bb;"),
                "line_after": digest_bytes(b"int cc;"),
            },
            "gen": {"k": "fwd", "id": "Spare"},
        }
    ]
    assert b"class Spare;" in _render(original, ops)

    # Move "int dd;" (inside the after-window) to the top of the file: the
    # token context digest no longer matches, but the literal seat pair
    # still identifies the seam uniquely.
    edited = b"int dd;\nint aa;\nint bb;\nint cc;\nint ee;\n"
    with pytest.raises(SourceEditError):
        _render(edited, ops)

    rescued = rewitness_operations(ops, edited)
    assert rescued is not None
    updated_ops, changes = rescued
    anchor = updated_ops[0]["anchor"]
    assert anchor["ctx"] != ops[0]["anchor"]["ctx"]
    assert anchor["line_before"] == digest_bytes(b"int bb;")
    assert anchor["line_after"] == digest_bytes(b"int cc;")
    assert {location for location, _, _ in changes} == {"0 anchor.ctx"}

    rendered = _render(edited, updated_ops)
    assert rendered.index(b"int bb;") < rendered.index(b"class Spare;")
    assert rendered.index(b"class Spare;") < rendered.index(b"int cc;")


def test_ambiguous_seat_pair_is_never_guessed() -> None:
    # Two identical seams: the drifted seat cannot be re-witnessed uniquely.
    original = b"int alpha;\nint omega;\nint alpha;\nint omega;\n"
    ops: list[dict[str, object]] = [
        {
            "op": "insert",
            "anchor": {
                "ctx": _seat_digest(["alpha", ";", "<SEAT>", "int", "omega"]),
                "b": 2,
                "a": 2,
                "line_before": digest_bytes(b"int alpha;"),
                "line_after": digest_bytes(b"int omega;"),
            },
            "gen": {"k": "fwd", "id": "Spare"},
        }
    ]
    edited = b"int alpha;\n\nint omega;\nint alpha;\n\nint omega;\n"
    assert rewitness_operations(ops, edited) is None


def test_unrelated_edit_is_not_rescued() -> None:
    # The seam itself was rewritten: neither the context nor the seat pair
    # resolves, and re-witnessing must refuse.
    edited = b"int alpha;\nint sigma;\n"
    with pytest.raises(SourceEditError):
        _render(edited, _SEAM_OPS)
    assert rewitness_operations(_SEAM_OPS, edited) is None


def test_non_default_boundaries_are_left_alone() -> None:
    ops: list[dict[str, object]] = [
        {
            "op": "insert",
            "anchor": {
                "ctx": _seat_digest(["<SEAT>", "int", "alpha", ";"]),
                "b": 0,
                "a": 3,
                "at": "start",
            },
            "gen": {"k": "fwd", "id": "Spare"},
        }
    ]
    edited = b"\nint alpha;\nint omega;\n"
    assert rewitness_operations(ops, edited) is None
