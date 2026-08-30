"""Data models shared by the closed classic source-overlay renderer."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


class SourceEditError(ValueError):
    """A declarative source overlay is malformed or cannot resolve exactly."""


@dataclass(frozen=True, slots=True)
class ClassicOverlayAnchorReceipt:
    """Fresh evidence for one contextual anchor resolution."""

    role: str
    context_digest: str
    token_boundary: int
    byte_offset: int


@dataclass(frozen=True, slots=True)
class ClassicOverlayOperationReceipt:
    """Fresh evidence for one typed operation."""

    operation_id: str
    action: str
    fragment_digest: str
    fragment_size: int
    anchors: tuple[ClassicOverlayAnchorReceipt, ...]
    removed_digest: str | None = None
    removed_size: int | None = None


@dataclass(frozen=True, slots=True)
class ClassicOverlayOutputReceipt:
    """Clean-to-effective receipt for one logical source output."""

    path: str
    input_digest: str | None
    input_size: int | None
    output_digest: str
    output_size: int
    operations: tuple[ClassicOverlayOperationReceipt, ...]


@dataclass(frozen=True, slots=True)
class ClassicOverlayRenderResult:
    """Rendered bytes and receipts for one validated overlay document."""

    outputs: Mapping[str, bytes]
    receipts: tuple[ClassicOverlayOutputReceipt, ...]


@dataclass(frozen=True, slots=True)
class ClassicOverlayRenderSessionStats:
    """Compact observability for one bounded overlay-render invocation."""

    token_index_builds: int
    token_index_hits: int
    anchor_batch_builds: int
    anchor_batch_hits: int
    anchor_windows_hashed: int
    retained_token_indexes: int
    retained_index_bytes: int
    retained_anchor_batches: int
    retained_anchor_requests: int


@dataclass(frozen=True, slots=True)
class _Anchor:
    context_digest: str
    before_count: int
    after_count: int
    boundary: str
    before_line_digest: str | None = None
    after_line_digest: str | None = None


@dataclass(frozen=True, slots=True)
class _Layout:
    lines: int | None = None
    positions: tuple[int, ...] | None = None
    indent: tuple[tuple[int, bytes], ...] = ()
    newline: bool | str = True
    blank_indent: tuple[tuple[int, int, bytes], ...] = ()


@dataclass(frozen=True, slots=True)
class _Operation:
    operation_id: str
    action: str
    generator: Mapping[str, object]
    start: _Anchor | None = None
    end: _Anchor | None = None
    removed_digest: str | None = None
    removed_size: int | None = None


@dataclass(frozen=True, slots=True)
class _Output:
    path: str
    clean_digest: str | None
    effective_digest: str
    effective_size: int | None
    operations: tuple[_Operation, ...]


@dataclass(frozen=True, slots=True)
class _ValidatedOverlay:
    outputs: tuple[_Output, ...]
    generated_translation_units: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ResolvedOperation:
    ordinal: int
    operation: _Operation
    start: int
    end: int
    fragment: bytes
    payload: bytes
    anchors: tuple[ClassicOverlayAnchorReceipt, ...]
    removed: bytes | None


__all__ = [
    "ClassicOverlayAnchorReceipt",
    "ClassicOverlayOperationReceipt",
    "ClassicOverlayOutputReceipt",
    "ClassicOverlayRenderResult",
    "ClassicOverlayRenderSessionStats",
    "SourceEditError",
]
