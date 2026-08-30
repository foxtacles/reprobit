"""Authenticated source-range relocation for classic overlays."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from reprobit.artifacts import digest_bytes
from reprobit.classic_overlay_tokens import (
    _ANNOTATION_COMMENT_RE,
    _TOKEN_RE,
    _token_sequence_digest,
    _tokens,
)
from reprobit.classic_overlay_types import _Layout
from reprobit.classic_overlay_validation import (
    _RANGE_DEPENDENCY_RE,
    _digest,
    _fail,
    _integer,
    _keys,
    _object,
    _operation_id,
    _qualified,
    _relative_path,
    _seat_fragment,
)


@dataclass(frozen=True, slots=True)
class _RelocationSpec:
    source_operation_id: str
    range_dependency_id: str
    range_identity: str
    ordinary_owner: str
    byte_destination: str
    baseline_digest: str
    baseline_size: int
    baseline_line_count: int
    baseline_significant_digest: str
    range_render_policy: str


def _relocation_spec(value: Mapping[str, object], context: str) -> _RelocationSpec:
    _keys(
        value,
        {
            "k",
            "range_identity",
            "ordinary_owner",
            "byte_destination",
            "source_range_token_pin",
            "transfer",
            "source_operation_id",
            "range_dependency_id",
            "range_render_policy",
        },
        context,
    )
    if value.get("transfer") != "copy_authenticated_clean_source_range":
        _fail(f"{context}.transfer differs")
    policy = value.get("range_render_policy")
    if policy not in {
        "strip_comments_preserve_physical_lines_v1",
        "strip_prose_preserve_physical_lines_v1",
    }:
        _fail(f"{context}.range_render_policy is outside the closed enum")
    source_operation_id = _operation_id(
        value.get("source_operation_id"), f"{context}.source_operation_id", ""
    )
    dependency = value.get("range_dependency_id")
    if not isinstance(dependency, str) or _RANGE_DEPENDENCY_RE.fullmatch(dependency) is None:
        _fail(f"{context}.range_dependency_id differs")
    ordinary_owner = _relative_path(value.get("ordinary_owner"), f"{context}.ordinary_owner")
    byte_destination = _relative_path(value.get("byte_destination"), f"{context}.byte_destination")
    if ordinary_owner == byte_destination:
        _fail(f"{context} relocation owner and destination must differ")
    pin = _object(value.get("source_range_token_pin"), f"{context}.source_range_token_pin")
    _keys(
        pin,
        {
            "baseline_sha256",
            "baseline_size",
            "baseline_line_count",
            "baseline_significant_token_sha256",
        },
        f"{context}.source_range_token_pin",
    )
    return _RelocationSpec(
        source_operation_id,
        dependency,
        _qualified(value.get("range_identity"), f"{context}.range_identity"),
        ordinary_owner,
        byte_destination,
        _digest(pin.get("baseline_sha256"), f"{context}.source_range_token_pin.baseline_sha256"),
        _integer(
            pin.get("baseline_size"),
            f"{context}.source_range_token_pin.baseline_size",
            minimum=1,
            maximum=64 * 1024 * 1024,
        ),
        _integer(
            pin.get("baseline_line_count"),
            f"{context}.source_range_token_pin.baseline_line_count",
            minimum=0,
            maximum=2_000_000,
        ),
        _digest(
            pin.get("baseline_significant_token_sha256"),
            f"{context}.source_range_token_pin.baseline_significant_token_sha256",
        ),
        policy,
    )


def _significant_digest(data: bytes) -> str:
    return _token_sequence_digest([token for token, _, _ in _tokens(data)])


def _require_relocation_pin(data: bytes, spec: _RelocationSpec, context: str) -> None:
    if (
        digest_bytes(data) != spec.baseline_digest
        or len(data) != spec.baseline_size
        or data.count(b"\n") != spec.baseline_line_count
        or _significant_digest(data) != spec.baseline_significant_digest
    ):
        _fail(f"{context} differs from its authenticated byte/token/line pin")


def _strip_relocation_comments(data: bytes, *, preserve_annotations: bool) -> bytes:
    text = data.decode("latin1")
    result = bytearray(data)
    for match in _TOKEN_RE.finditer(text):
        token = match.group(0)
        if not token.startswith(("//", "/*")):
            continue
        if preserve_annotations and token.startswith("//") and _ANNOTATION_COMMENT_RE.match(token):
            continue
        for index in range(match.start(), match.end()):
            if result[index] not in (10, 13):
                result[index] = 32
    return bytes(result)


def _render_relocation_range(data: bytes, spec: _RelocationSpec) -> bytes:
    _require_relocation_pin(data, spec, "source relocation range")
    rendered = _strip_relocation_comments(
        data,
        preserve_annotations=(spec.range_render_policy == "strip_prose_preserve_physical_lines_v1"),
    )
    return _seat_fragment("reloc", rendered, _Layout())
