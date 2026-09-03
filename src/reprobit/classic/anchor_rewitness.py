"""Fail-closed anchor re-witnessing for mechanical source regeneration.

When an already-reviewed clean source file receives an edit that only moves
whitespace lines or relocates tokens away from an insertion seam, the saved
overlay operations still describe the same reviewed transformation, but their
recorded witnesses no longer resolve:

* an ``after_newline`` seat records the literal adjacent line pair, so a blank
  line inserted at the seam invalidates the pair even though the surrounding
  token context still resolves uniquely;
* a token-context digest records a window of significant tokens, so tokens
  moved out of the window invalidate the context even though the literal seat
  line pair still identifies the seam uniquely;
* a file-boundary seat (``start``/``end``) records the tokens beside the file
  boundary, so an edit among those tokens invalidates the context even though
  the boundary itself still identifies the seam uniquely.

This module re-witnesses such anchors against the current clean bytes.  Every
rescue requires a unique candidate; any ambiguity or unsupported drift leaves
the operation untouched so the caller rejects exactly as before.  Only the
regeneration path may call this: build and verify always resolve the saved
witnesses strictly.
"""

from __future__ import annotations

from bisect import bisect_left
from collections.abc import Mapping
from typing import Any

from reprobit.artifacts import digest_bytes
from reprobit.classic.overlay_tokens import (
    _build_token_index,
    _seat_digest_from_index,
    _seat_lines,
    _TokenIndex,
)

_ANCHOR_KEYS = ("anchor", "from", "to")
_DEFAULT_WINDOW = 32


def _is_blank(line: bytes) -> bool:
    return not line.strip()


def _skipped_pair(data: bytes, offset: int) -> tuple[bytes, bytes]:
    """The nearest non-blank lines before and after an after-newline offset."""

    before_lines = data[:offset].splitlines()
    after_lines = data[offset:].splitlines()
    before = b""
    for line in reversed(before_lines):
        if not _is_blank(line):
            before = line
            break
    after = b""
    for line in after_lines:
        if not _is_blank(line):
            after = line
            break
    return before, after


def _newline_offsets(data: bytes, lower: int, upper: int) -> list[int]:
    return [
        position + 1 for position in range(lower, upper) if data[position : position + 1] == b"\n"
    ]


def _context_candidates(
    index: _TokenIndex, before_count: int, after_count: int, context_digest: str
) -> list[int]:
    upper = index.token_count - after_count
    found: list[int] = []
    for token_boundary in range(before_count, upper + 1):
        if (
            _seat_digest_from_index(index, token_boundary, before_count, after_count)
            == context_digest
        ):
            found.append(token_boundary)
            if len(found) > 1:
                break
    return found


def _rescue_seat(
    data: bytes,
    lower: int,
    upper: int,
    before_line_digest: str,
    after_line_digest: str,
) -> tuple[str, str] | None:
    """Re-witness a seat whose only drift is blank lines at the seam."""

    literal: list[int] = []
    preferred: list[int] = []
    for offset in _newline_offsets(data, lower, upper):
        before_line, after_line = _seat_lines(data, offset)
        if (
            digest_bytes(before_line) == before_line_digest
            and digest_bytes(after_line) == after_line_digest
        ):
            literal.append(offset)
            continue
        skipped_before, skipped_after = _skipped_pair(data, offset)
        if (
            digest_bytes(skipped_before) == before_line_digest
            and digest_bytes(skipped_after) == after_line_digest
            and digest_bytes(before_line) == before_line_digest
        ):
            # The canonical rescue seat directly terminates the recorded
            # before-line; only blank lines follow before the recorded
            # after-line.
            preferred.append(offset)
    if literal:
        return None  # strict resolution should have succeeded; do not touch
    if len(preferred) != 1:
        return None
    before_line, after_line = _seat_lines(data, preferred[0])
    return digest_bytes(before_line), digest_bytes(after_line)


def _rescue_context(
    data: bytes,
    index: _TokenIndex,
    before_count: int,
    after_count: int,
    before_line_digest: str,
    after_line_digest: str,
) -> tuple[str, str, str] | None:
    """Re-witness a token context via the still-unique literal seat pair."""

    matches: list[int] = []
    rescued: list[int] = []
    for offset in _newline_offsets(data, 0, len(data)):
        before_line, after_line = _seat_lines(data, offset)
        if (
            digest_bytes(before_line) == before_line_digest
            and digest_bytes(after_line) == after_line_digest
        ):
            matches.append(offset)
            continue
        skipped_before, skipped_after = _skipped_pair(data, offset)
        if (
            digest_bytes(skipped_before) == before_line_digest
            and digest_bytes(skipped_after) == after_line_digest
            and digest_bytes(before_line) == before_line_digest
        ):
            rescued.append(offset)
    if len(matches) + len(rescued) != 1:
        return None
    offset = matches[0] if matches else rescued[0]
    token_boundary = bisect_left(index.source_starts, offset)
    if token_boundary < before_count or token_boundary > index.token_count - after_count:
        return None
    context_digest = _seat_digest_from_index(index, token_boundary, before_count, after_count)
    if _context_candidates(index, before_count, after_count, context_digest) != [token_boundary]:
        return None
    before_line, after_line = _seat_lines(data, offset)
    return context_digest, digest_bytes(before_line), digest_bytes(after_line)


def _rewitness_boundary_anchor(
    anchor: Mapping[str, Any], index: _TokenIndex
) -> dict[str, Any] | None:
    """Re-witness a file-boundary seat whose token context drifted.

    A ``start`` or ``end`` seat is fixed by the file boundary itself; its
    context digest only witnesses the tokens beside that boundary.  When an
    edit changed those tokens the seam is still unique by construction, so
    the digest is recomputed at the same boundary and nothing else moves.
    """

    context_digest = anchor.get("ctx")
    before_count = anchor.get("b", _DEFAULT_WINDOW)
    after_count = anchor.get("a", _DEFAULT_WINDOW)
    if (
        not isinstance(context_digest, str)
        or not isinstance(before_count, int)
        or not isinstance(after_count, int)
        or "line_before" in anchor
        or "line_after" in anchor
    ):
        return None
    if anchor.get("at") == "start":
        if before_count:
            return None  # nothing precedes the file start; not a boundary seat
        token_boundary = 0
    else:
        if after_count:
            return None  # nothing follows the file end; not a boundary seat
        token_boundary = index.token_count
    if token_boundary < before_count or token_boundary > index.token_count - after_count:
        return None
    fresh = _seat_digest_from_index(index, token_boundary, before_count, after_count)
    if fresh == context_digest:
        return None  # strict resolution succeeds; do not touch
    updated = dict(anchor)
    updated["ctx"] = fresh
    return updated


def _rewitness_anchor(
    anchor: Mapping[str, Any], data: bytes, index: _TokenIndex
) -> dict[str, Any] | None:
    """Return an updated anchor mapping, or None when nothing can change."""

    if not isinstance(anchor, Mapping):
        return None
    boundary_name = anchor.get("at")
    if boundary_name in {"start", "end"}:
        return _rewitness_boundary_anchor(anchor, index)
    if boundary_name is not None:
        return None  # token seats carry no second witness; never guess a seam
    context_digest = anchor.get("ctx")
    before_line_digest = anchor.get("line_before")
    after_line_digest = anchor.get("line_after")
    if (
        not isinstance(context_digest, str)
        or not isinstance(before_line_digest, str)
        or not isinstance(after_line_digest, str)
    ):
        return None
    before_count = anchor.get("b", _DEFAULT_WINDOW)
    after_count = anchor.get("a", _DEFAULT_WINDOW)
    if not isinstance(before_count, int) or not isinstance(after_count, int):
        return None
    candidates = _context_candidates(index, before_count, after_count, context_digest)
    if len(candidates) == 1:
        boundary = candidates[0]
        lower = index.source_ends[boundary - 1] if boundary else 0
        upper = index.source_starts[boundary] if boundary < index.token_count else len(data)
        seat = _rescue_seat(data, lower, upper, before_line_digest, after_line_digest)
        if seat is None:
            return None
        updated = dict(anchor)
        updated["line_before"], updated["line_after"] = seat
        return updated
    if not candidates:
        rescue = _rescue_context(
            data, index, before_count, after_count, before_line_digest, after_line_digest
        )
        if rescue is None:
            return None
        updated = dict(anchor)
        updated["ctx"], updated["line_before"], updated["line_after"] = rescue
        return updated
    return None  # ambiguous context: never guess


def rewitness_operations(
    operations: list[Any], data: bytes
) -> tuple[list[Any], list[tuple[str, str, str]]] | None:
    """Re-witness drifted anchors in raw operation mappings.

    Returns updated operations plus ``(location, old_digest, new_digest)``
    change records, or ``None`` when no anchor could be re-witnessed.  The
    input list is never mutated.
    """

    index = _build_token_index(data)
    changed = False
    changes: list[tuple[str, str, str]] = []
    updated_operations: list[Any] = []
    for position, operation in enumerate(operations):
        if not isinstance(operation, Mapping):
            updated_operations.append(operation)
            continue
        updated_operation = dict(operation)
        label = str(operation.get("id", position))
        for key in _ANCHOR_KEYS:
            anchor = operation.get(key)
            if anchor is None:
                continue
            updated = _rewitness_anchor(anchor, data, index)
            if updated is None or updated == anchor:
                continue
            for field in ("ctx", "line_before", "line_after"):
                if updated.get(field) != anchor.get(field):
                    changes.append(
                        (f"{label} {key}.{field}", str(anchor.get(field)), str(updated.get(field)))
                    )
            updated_operation[key] = updated
            changed = True
        updated_operations.append(updated_operation)
    if not changed:
        return None
    return updated_operations, changes
