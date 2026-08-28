"""Byte-preserving source anchors and edits.

Source code is not normalized in this module.  Anchors may use lexical structure
to relocate after horizontal-trivia drift, but edits are always spliced into the
original byte stream.  In particular, comments, line endings, preprocessor
directives, and untouched whitespace retain their exact representation.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from itertools import pairwise

from reprobit.artifacts import ByteRange, digest_bytes


class SourceEditError(ValueError):
    """Raised when an anchor or a byte-preservation invariant fails."""


@dataclass(frozen=True, slots=True)
class OverlayOutputWitness:
    """Fresh receipt for one declaratively rendered overlay output."""

    path: str
    input_digest: str
    output_digest: str
    operation_count: int


@dataclass(frozen=True, slots=True)
class _Token:
    value: bytes
    start: int
    end: int


# Newlines are structural tokens.  Other horizontal whitespace is deliberately
# omitted, which permits a controlled repin after indentation or spacing edits.
_TOKEN = re.compile(
    rb"(?:"
    rb"//[^\r\n]*|"
    rb"/\*.*?\*/|"
    rb"(?:u8|u|U|L)?\"(?:\\.|[^\"\\])*\"|"
    rb"(?:u8|u|U|L)?'(?:\\.|[^'\\])*'|"
    rb"\r\n|\r|\n|"
    rb"[A-Za-z_][A-Za-z0-9_]*|"
    rb"0[xX][0-9A-Fa-f]+|[0-9]+(?:\.[0-9]*)?|"
    rb"##|<<=|>>=|->\*|\.\*|::|\.\.\.|==|!=|<=|>=|&&|\|\||"
    rb"\+\+|--|->|<<|>>|\+=|-=|\*=|/=|%=|&=|\|=|\^=|"
    rb"[^\s]"
    rb")",
    re.DOTALL,
)


def _tokens(source: bytes) -> tuple[_Token, ...]:
    return tuple(
        _Token(match.group(), match.start(), match.end()) for match in _TOKEN.finditer(source)
    )


def _sequence_digest(values: tuple[bytes, ...]) -> str:
    digest = sha256()
    for value in values:
        digest.update(len(value).to_bytes(4, "little"))
        digest.update(value)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class AnchorResolution:
    """The resolved source span and whether exact bytes drifted."""

    span: ByteRange
    drifted: bool


@dataclass(frozen=True, slots=True)
class StructuralAnchor:
    """An exact anchor with a bounded lexical fallback.

    ``capture`` requires the selected span to begin and end on a non-whitespace
    token.  This prevents an automatic repin from making an arbitrary choice
    about which surrounding indentation belongs to the replacement.
    """

    preimage_digest: str
    preimage_length: int
    exact_before: bytes
    exact_after: bytes
    before_tokens: tuple[bytes, ...]
    body_tokens: tuple[bytes, ...]
    after_tokens: tuple[bytes, ...]
    ordinal: int | None = None

    def __post_init__(self) -> None:
        if self.ordinal is not None and self.ordinal < 0:
            raise SourceEditError("source anchor ordinal cannot be negative")

    @classmethod
    def capture(
        cls,
        source: bytes,
        start: int,
        end: int,
        *,
        context_bytes: int = 64,
        context_tokens: int = 6,
        ordinal: int | None = None,
    ) -> StructuralAnchor:
        if not 0 <= start < end <= len(source):
            raise SourceEditError("anchor span is outside the source")
        if context_bytes < 0 or context_tokens < 1:
            raise SourceEditError("anchor context sizes must be non-negative")
        selected = source[start:end]
        selected_tokens = _tokens(selected)
        if not selected_tokens:
            raise SourceEditError("cannot structurally anchor an all-whitespace span")
        if selected_tokens[0].start != 0 or selected_tokens[-1].end != len(selected):
            raise SourceEditError("structural anchor span must begin and end on tokens")

        all_tokens = _tokens(source)
        first_index = next(
            (index for index, token in enumerate(all_tokens) if token.start == start), None
        )
        if first_index is None:
            raise SourceEditError("anchor start is not a lexical boundary")
        last_index = first_index + len(selected_tokens)
        if last_index > len(all_tokens) or all_tokens[last_index - 1].end != end:
            raise SourceEditError("anchor end is not a lexical boundary")

        before = tuple(
            token.value
            for token in all_tokens[max(0, first_index - context_tokens) : first_index]
        )
        body = tuple(token.value for token in selected_tokens)
        after = tuple(token.value for token in all_tokens[last_index : last_index + context_tokens])
        return cls(
            preimage_digest=digest_bytes(selected),
            preimage_length=len(selected),
            exact_before=source[max(0, start - context_bytes) : start],
            exact_after=source[end : min(len(source), end + context_bytes)],
            before_tokens=before,
            body_tokens=body,
            after_tokens=after,
            ordinal=ordinal,
        )

    @property
    def token_digest(self) -> str:
        return _sequence_digest(self.body_tokens)

    def resolve(self, source: bytes, *, allow_trivia_drift: bool = False) -> AnchorResolution:
        """Resolve the anchor uniquely, or select its explicit ordinal.

        Exact-byte matching is attempted first.  The lexical fallback is used
        only when requested, and its result is labelled ``drifted`` so callers
        cannot mistake token equality for a proof of semantic equivalence.
        """

        exact: list[ByteRange] = []
        search_at = 0
        while True:
            before_at = source.find(self.exact_before, search_at)
            if before_at < 0:
                break
            start = before_at + len(self.exact_before)
            end = start + self.preimage_length
            if (
                end <= len(source)
                and digest_bytes(source[start:end]) == self.preimage_digest
                and source.startswith(self.exact_after, end)
            ):
                exact.append(ByteRange(start, end))
            search_at = before_at + 1
        if exact:
            return AnchorResolution(self._select(exact), drifted=False)
        if not allow_trivia_drift:
            raise SourceEditError("source anchor preimage or context drifted")

        tokens = _tokens(source)
        body_length = len(self.body_tokens)
        candidates: list[ByteRange] = []
        for index in range(0, len(tokens) - body_length + 1):
            body = tuple(token.value for token in tokens[index : index + body_length])
            if body != self.body_tokens:
                continue
            before_start = index - len(self.before_tokens)
            after_end = index + body_length + len(self.after_tokens)
            if before_start < 0 or after_end > len(tokens):
                continue
            before = tuple(token.value for token in tokens[before_start:index])
            after = tuple(token.value for token in tokens[index + body_length : after_end])
            if before == self.before_tokens and after == self.after_tokens:
                candidates.append(
                    ByteRange(tokens[index].start, tokens[index + body_length - 1].end)
                )
        if not candidates:
            raise SourceEditError("source anchor has no structural match")
        return AnchorResolution(self._select(candidates), drifted=True)

    def _select(self, candidates: list[ByteRange]) -> ByteRange:
        if self.ordinal is None:
            if len(candidates) != 1:
                raise SourceEditError(
                    "source anchor is ambiguous; capture it with an explicit ordinal "
                    "or stronger context"
                )
            return candidates[0]
        if self.ordinal >= len(candidates):
            raise SourceEditError(
                f"source anchor ordinal {self.ordinal} does not select one of "
                f"{len(candidates)} matches"
            )
        return candidates[self.ordinal]


@dataclass(frozen=True, slots=True)
class SourceEdit:
    """A replacement addressed by a structural anchor."""

    id: str
    anchor: StructuralAnchor
    replacement: bytes
    allow_trivia_drift: bool = False


@dataclass(frozen=True, slots=True)
class SourceWitness:
    """Receipt for one byte-preserving render."""

    input_digest: str
    output_digest: str
    edit_ids: tuple[str, ...]
    drifted_edit_ids: tuple[str, ...]
    preprocessor_digest: str


def _physical_lines(source: bytes) -> tuple[bytes, ...]:
    return tuple(source.splitlines(keepends=True))


def preprocessor_directives(source: bytes) -> tuple[bytes, ...]:
    """Extract exact logical preprocessor directives, including continuations."""

    directives: list[bytes] = []
    active: list[bytes] = []
    for line in _physical_lines(source):
        body = line.rstrip(b"\r\n")
        if active:
            active.append(line)
        elif body.lstrip(b" \t").startswith(b"#"):
            active = [line]
        else:
            continue
        if not body.rstrip(b" \t").endswith(b"\\"):
            directives.append(b"".join(active))
            active = []
    if active:
        directives.append(b"".join(active))
    return tuple(directives)


def preprocessor_digest(source: bytes) -> str:
    return _sequence_digest(preprocessor_directives(source))


def apply_source_edits(
    source: bytes,
    edits: tuple[SourceEdit, ...],
    *,
    preserve_preprocessor: bool = True,
) -> tuple[bytes, SourceWitness]:
    """Resolve and apply non-overlapping edits without normalizing source bytes."""

    if len({edit.id for edit in edits}) != len(edits):
        raise SourceEditError("source edit ids must be unique")
    resolved: list[tuple[ByteRange, SourceEdit, bool]] = []
    for edit in edits:
        resolution = edit.anchor.resolve(source, allow_trivia_drift=edit.allow_trivia_drift)
        resolved.append((resolution.span, edit, resolution.drifted))
    resolved.sort(key=lambda item: item[0].start)
    for previous, current in pairwise(resolved):
        if previous[0].intersects(current[0]):
            raise SourceEditError(
                f"source edits {previous[1].id!r} and {current[1].id!r} overlap"
            )

    pieces: list[bytes] = []
    cursor = 0
    for span, edit, _ in resolved:
        pieces.append(source[cursor : span.start])
        pieces.append(edit.replacement)
        cursor = span.end
    pieces.append(source[cursor:])
    output = b"".join(pieces)

    before_pp = preprocessor_digest(source)
    after_pp = preprocessor_digest(output)
    if preserve_preprocessor and before_pp != after_pp:
        raise SourceEditError("source edits changed preprocessor directives")
    witness = SourceWitness(
        input_digest=digest_bytes(source),
        output_digest=digest_bytes(output),
        edit_ids=tuple(edit.id for _, edit, _ in resolved),
        drifted_edit_ids=tuple(edit.id for _, edit, drifted in resolved if drifted),
        preprocessor_digest=after_pp,
    )
    return output, witness


def _overlay_identifier(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value)
    ):
        raise SourceEditError(f"overlay {label} is not a C/C++ identifier")
    return value


def _overlay_integer(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise SourceEditError(f"overlay {label} must be an integer >= {minimum}")
    return value


def _render_lean_generator(generator: object) -> bytes:
    """Render the deliberately small, source-only generator subset.

    Unsupported kinds fail closed.  In particular this seam cannot relocate
    byte payloads or install material obtained from an oracle.
    """

    if not isinstance(generator, Mapping):
        raise SourceEditError("overlay generator must be an object")
    kind = generator.get("k")
    if kind == "lines":
        count = _overlay_integer(
            generator.get("n", generator.get("lines")), "line count", minimum=1
        )
        return b"\n" * count
    if kind == "fwd":
        identifier = _overlay_identifier(generator.get("id"), "forward identifier")
        tag = generator.get("tag", "class")
        if tag not in {"class", "struct", "union"}:
            raise SourceEditError("overlay forward tag is outside the closed enum")
        return f"{tag} {identifier};\n".encode("ascii")
    if kind == "include":
        header = generator.get("header")
        style = generator.get("style", "quote")
        if (
            not isinstance(header, str)
            or not header
            or "\0" in header
            or "\n" in header
            or "\r" in header
            or '"' in header
            or ">" in header
        ):
            raise SourceEditError("overlay include header is unsafe")
        if style == "quote":
            return f'#include "{header}"\n'.encode("ascii")
        if style == "angle":
            return f"#include <{header}>\n".encode("ascii")
        raise SourceEditError("overlay include style is outside the closed enum")
    if kind == "size_asserts":
        assertions = generator.get("assertions")
        if not isinstance(assertions, list) or not assertions:
            raise SourceEditError("overlay size assertions must be a non-empty array")
        rendered: list[bytes] = []
        for item in assertions:
            if not isinstance(item, Mapping):
                raise SourceEditError("overlay size assertion must be an object")
            rendered.append(
                (
                f"DECOMP_SIZE_ASSERT("
                f"{_overlay_identifier(item.get('type'), 'asserted type')}, "
                f"0x{_overlay_integer(item.get('size'), 'asserted size', minimum=1):x})\n"
                ).encode("ascii")
            )
        return b"".join(rendered)
    if kind == "seq":
        line_count = _overlay_integer(generator.get("lines"), "sequence lines", minimum=1)
        raw_items = generator.get("items")
        if not isinstance(raw_items, list):
            raise SourceEditError("overlay sequence items must be an array")
        canvas = [b"\n"] * line_count
        for raw in raw_items:
            if not isinstance(raw, Mapping):
                raise SourceEditError("overlay sequence item must be an object")
            first_line = _overlay_integer(raw.get("line"), "sequence line", minimum=1)
            child = _render_lean_generator(raw)
            child_lines = child.splitlines(keepends=True)
            if first_line - 1 + len(child_lines) > line_count:
                raise SourceEditError("overlay sequence child leaves its canvas")
            for index, line in enumerate(child_lines, start=first_line - 1):
                if line.strip() and canvas[index].strip() and canvas[index] != line:
                    raise SourceEditError("overlay sequence children overlap")
                if line.strip():
                    canvas[index] = line
        return b"".join(canvas)
    raise SourceEditError(f"unsupported source-overlay generator kind: {kind!r}")


def _overlay_offset(anchor: object, length: int) -> int:
    if not isinstance(anchor, Mapping) or set(anchor) != {"offset"}:
        raise SourceEditError(
            "unsupported source-overlay anchor; this runtime slice requires exact offsets"
        )
    offset = _overlay_integer(anchor.get("offset"), "anchor offset")
    if offset > length:
        raise SourceEditError("overlay anchor leaves the current source")
    return offset


def render_overlay_output(
    source: bytes,
    declaration: Mapping[str, object],
) -> tuple[bytes, OverlayOutputWitness]:
    """Apply one pinned overlay declaration without normalizing untouched bytes."""

    path = declaration.get("path")
    clean = declaration.get("clean")
    effective = declaration.get("effective")
    operations = declaration.get("ops")
    if not isinstance(path, str) or not path or "\0" in path:
        raise SourceEditError("overlay output path is invalid")
    if not isinstance(clean, str) or digest_bytes(source) != clean:
        raise SourceEditError(f"overlay clean digest differs for {path!r}")
    if not isinstance(effective, str) or not re.fullmatch(r"[0-9a-f]{64}", effective):
        raise SourceEditError(f"overlay effective digest is invalid for {path!r}")
    if not isinstance(operations, list):
        raise SourceEditError(f"overlay operations must be an array for {path!r}")

    output = source
    for raw in operations:
        if not isinstance(raw, Mapping):
            raise SourceEditError("overlay operation must be an object")
        operation = raw.get("op")
        if operation == "append":
            output += _render_lean_generator(raw.get("gen"))
            continue
        if operation == "insert":
            offset = _overlay_offset(raw.get("anchor"), len(output))
            output = output[:offset] + _render_lean_generator(raw.get("gen")) + output[offset:]
            continue
        if operation not in {"replace", "delete"}:
            raise SourceEditError(f"unsupported source-overlay operation: {operation!r}")
        start = _overlay_offset(raw.get("from"), len(output))
        end = _overlay_offset(raw.get("to"), len(output))
        if end < start:
            raise SourceEditError("overlay replacement range is reversed")
        removed = raw.get("removed")
        if not isinstance(removed, Mapping):
            raise SourceEditError("overlay replacement lacks a removed-range pin")
        expected_size = _overlay_integer(removed.get("size"), "removed size")
        expected_digest = removed.get("sha256")
        selected = output[start:end]
        if len(selected) != expected_size or digest_bytes(selected) != expected_digest:
            raise SourceEditError("overlay replacement preimage differs from its pin")
        replacement = b"" if operation == "delete" else _render_lean_generator(raw.get("gen"))
        output = output[:start] + replacement + output[end:]

    declared_size = declaration.get("size")
    if declared_size is not None and _overlay_integer(declared_size, "output size") != len(output):
        raise SourceEditError(f"overlay output size differs for {path!r}")
    output_digest = digest_bytes(output)
    if output_digest != effective:
        raise SourceEditError(f"overlay effective digest differs for {path!r}")
    return output, OverlayOutputWitness(path, clean, output_digest, len(operations))
