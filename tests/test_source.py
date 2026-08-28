from __future__ import annotations

import pytest

from reprobit.source import (
    SourceEdit,
    SourceEditError,
    StructuralAnchor,
    apply_source_edits,
    preprocessor_directives,
)


def _span(source: bytes, selected: bytes) -> tuple[int, int]:
    start = source.index(selected)
    return start, start + len(selected)


def test_edit_preserves_every_untouched_byte_and_crlf_directive() -> None:
    source = b"#define SCALE(x) ((x) + 1)\r\n\r\nint f() {\r\n  return SCALE(2);\r\n}\r\n"
    start, end = _span(source, b"SCALE(2)")
    anchor = StructuralAnchor.capture(source, start, end)

    rendered, witness = apply_source_edits(
        source,
        (SourceEdit("replace.call", anchor, b"SCALE(3)"),),
    )

    assert rendered == source[:start] + b"SCALE(3)" + source[end:]
    assert preprocessor_directives(rendered) == (b"#define SCALE(x) ((x) + 1)\r\n",)
    assert witness.edit_ids == ("replace.call",)
    assert not witness.drifted_edit_ids


def test_structural_fallback_handles_horizontal_trivia_but_marks_drift() -> None:
    original = b"int f(int value) {\n  return value + 1;\n}\n"
    selected = b"return value + 1;"
    start, end = _span(original, selected)
    anchor = StructuralAnchor.capture(original, start, end)
    drifted = b"int f(int value) {\n  return   value+1;\n}\n"

    with pytest.raises(SourceEditError, match="drifted"):
        anchor.resolve(drifted)
    rendered, witness = apply_source_edits(
        drifted,
        (SourceEdit("replace.return", anchor, b"return value + 2;", allow_trivia_drift=True),),
    )

    assert rendered == b"int f(int value) {\n  return value + 2;\n}\n"
    assert witness.drifted_edit_ids == ("replace.return",)


def test_preprocessor_change_fails_closed_by_default() -> None:
    source = b"#define VALUE 1\nint x = VALUE;\n"
    selected = b"#define VALUE 1"
    start, end = _span(source, selected)
    edit = SourceEdit(
        "change.directive",
        StructuralAnchor.capture(source, start, end),
        b"#define VALUE 2",
    )

    with pytest.raises(SourceEditError, match="preprocessor"):
        apply_source_edits(source, (edit,))
    rendered, _ = apply_source_edits(source, (edit,), preserve_preprocessor=False)
    assert rendered.startswith(b"#define VALUE 2\n")


def test_overlapping_edits_are_rejected() -> None:
    source = b"int result = first + second;\n"
    first_start, first_end = _span(source, b"result = first")
    second_start, second_end = _span(source, b"first + second")
    edits = (
        SourceEdit(
            "left",
            StructuralAnchor.capture(source, first_start, first_end),
            b"result = left",
        ),
        SourceEdit(
            "right",
            StructuralAnchor.capture(source, second_start, second_end),
            b"right",
        ),
    )

    with pytest.raises(SourceEditError, match="overlap"):
        apply_source_edits(source, edits)


def test_anchor_span_must_stop_on_tokens() -> None:
    source = b"int value;  "
    with pytest.raises(SourceEditError, match="begin and end on tokens"):
        StructuralAnchor.capture(source, 0, len(source))
