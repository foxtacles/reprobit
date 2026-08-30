"""One-way normalization for underspecified legacy source overlays.

Current overlay records are self-contained.  This module exists only so the
schema-v2 migrator can recover the return type that old ``member_probe``
generators left implicit, then write that type into every migrated generator.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy

from reprobit.classic_overlay_cpp import _cpp_type, _render_cpp_type
from reprobit.classic_overlay_document import validate_classic_overlay
from reprobit.classic_overlay_generator_common import _string_array
from reprobit.classic_overlay_tokens import _tokens
from reprobit.classic_overlay_types import SourceEditError
from reprobit.classic_overlay_validation import (
    _array,
    _object,
    _relative_path,
)


def _type_text_from_tokens(tokens: Sequence[str]) -> str:
    rendered = ""
    previous: str | None = None
    for token in tokens:
        if not rendered:
            rendered = token
        elif token in {"::", "<", ">", ">>", "*", "&"}:
            rendered += token
        elif token == ",":
            rendered += ", "
        elif previous in {"::", "<"}:
            rendered += token
        elif previous in {"*", "&"} and token == "const":
            rendered += " const"
        else:
            rendered += " " + token
        previous = token
    return rendered


def _matching_token(
    tokens: Sequence[tuple[str, int, int]],
    opening: int,
    opening_token: str,
    closing_token: str,
) -> int | None:
    depth = 0
    for index in range(opening, len(tokens)):
        token = tokens[index][0]
        if token == opening_token:
            depth += 1
        elif token == closing_token:
            depth -= 1
            if depth == 0:
                return index
    return None


def _parameter_arity(tokens: Sequence[tuple[str, int, int]], opening: int, closing: int) -> int:
    content = [token for token, _, _ in tokens[opening + 1 : closing]]
    if not content or content == ["void"]:
        return 0
    depth = 0
    commas = 0
    for token in content:
        if token in {"(", "[", "<"}:
            depth += 1
        elif token in {")", "]", ">"}:
            depth = max(0, depth - 1)
        elif token == ">>":
            depth = max(0, depth - 2)
        elif token == "," and depth == 0:
            commas += 1
    return commas + 1


def _return_type_before_member(
    tokens: Sequence[tuple[str, int, int]], member_index: int, lower_bound: int
) -> str | None:
    boundary = member_index - 1
    while boundary >= lower_bound and tokens[boundary][0] not in {";", "{", "}", ":"}:
        boundary -= 1
    first = boundary + 1
    candidates: list[tuple[int, str]] = []
    for start in range(first, member_index):
        candidate = _type_text_from_tokens([token for token, _, _ in tokens[start:member_index]])
        try:
            parsed = _cpp_type(candidate, "member-probe inferred return type")
        except SourceEditError:
            continue
        candidates.append((member_index - start, _render_cpp_type(parsed)))
    if not candidates:
        return None
    maximum = max(length for length, _ in candidates)
    longest = {candidate for length, candidate in candidates if length == maximum}
    if len(longest) != 1:
        raise SourceEditError("member-probe return-type token run is ambiguous")
    return next(iter(longest))


def _class_member_return_types(
    data: bytes,
    owner: str,
    member: str,
    argument_count: int,
) -> set[str]:
    tokens = _tokens(data)
    discovered: set[str] = set()
    for class_index, (token, _, _) in enumerate(tokens):
        if token not in {"class", "struct"}:
            continue
        opening: int | None = None
        owner_is_named = False
        for index in range(class_index + 1, min(len(tokens), class_index + 65)):
            header_token = tokens[index][0]
            if header_token == ";":
                break
            if header_token == "{":
                opening = index
                break
            if header_token == owner:
                owner_is_named = True
        if opening is None or not owner_is_named:
            continue
        closing = _matching_token(tokens, opening, "{", "}")
        if closing is None:
            raise SourceEditError(f"class {owner!r} has an unterminated body")
        depth = 1
        index = opening + 1
        while index < closing:
            body_token = tokens[index][0]
            if body_token == "{":
                depth += 1
                index += 1
                continue
            if body_token == "}":
                depth -= 1
                index += 1
                continue
            if (
                depth == 1
                and body_token == member
                and index + 1 < closing
                and tokens[index + 1][0] == "("
            ):
                parameter_end = _matching_token(tokens, index + 1, "(", ")")
                if parameter_end is None or parameter_end > closing:
                    raise SourceEditError(
                        f"member declaration {owner}::{member} has unterminated parameters"
                    )
                if _parameter_arity(tokens, index + 1, parameter_end) == argument_count:
                    return_type = _return_type_before_member(tokens, index, opening + 1)
                    if return_type is not None:
                        discovered.add(return_type)
                index = parameter_end + 1
                continue
            index += 1
    return discovered


def _member_probe_generators(
    document: Mapping[str, object],
) -> list[tuple[dict[str, object], tuple[str, ...], int]]:
    overlay = _object(document, "overlay")
    raw_outputs = _array(overlay.get("outputs"), "overlay.outputs", minimum=1, maximum=2000)
    probes: list[tuple[dict[str, object], tuple[str, ...], int]] = []

    def collect(raw_generator: object, context: str) -> None:
        generator = _object(raw_generator, context)
        kind = generator.get("k")
        if kind == "member_probe":
            if not isinstance(raw_generator, dict):
                raise SourceEditError(f"{context} must be a mutable JSON object")
            qualified = tuple(
                _string_array(
                    generator.get("qualified_member"),
                    f"{context}.qualified_member",
                    minimum=2,
                    maximum=16,
                )
            )
            arguments = _array(
                generator.get("arguments"),
                f"{context}.arguments",
                minimum=1,
                maximum=1,
            )
            probes.append((raw_generator, qualified, len(arguments)))
        elif kind == "seq":
            for item_index, raw_item in enumerate(
                _array(generator.get("items"), f"{context}.items", minimum=1, maximum=100_000)
            ):
                item = _object(raw_item, f"{context}.items[{item_index}]")
                if item.get("k") != "fwd_run":
                    collect(raw_item, f"{context}.items[{item_index}]")

    for output_index, raw_output in enumerate(raw_outputs):
        output = _object(raw_output, f"overlay.outputs[{output_index}]")
        for operation_index, raw_operation in enumerate(
            _array(
                output.get("ops"),
                f"overlay.outputs[{output_index}].ops",
                minimum=1,
                maximum=100_000,
            )
        ):
            operation = _object(
                raw_operation,
                f"overlay.outputs[{output_index}].ops[{operation_index}]",
            )
            collect(
                operation.get("gen"),
                f"overlay.outputs[{output_index}].ops[{operation_index}].gen",
            )
    return probes


def normalize_legacy_member_probe_return_types(
    document: Mapping[str, object],
    clean_sources: Mapping[str, bytes],
) -> dict[str, object]:
    """Embed schema-v2's implicit member-probe type into every generator."""

    normalized = deepcopy(dict(document))
    probes = _member_probe_generators(normalized)
    if not probes:
        validate_classic_overlay(normalized)
        return normalized

    folded: dict[str, str] = {}
    normalized_sources: dict[str, bytes] = {}
    for raw_path, raw_data in clean_sources.items():
        path = _relative_path(raw_path, "clean_sources path")
        prior = folded.get(path.casefold())
        if prior is not None:
            raise SourceEditError(f"clean_sources has a casefold collision: {prior} / {path}")
        if type(raw_data) is not bytes:
            raise SourceEditError(f"clean_sources[{path!r}] must be immutable bytes")
        folded[path.casefold()] = path
        normalized_sources[path] = raw_data

    inferred_types: set[str] = set()
    probe_types: list[str] = []
    for _generator, qualified_member, argument_count in probes:
        owner = qualified_member[-2]
        member = qualified_member[-1]
        matches: set[str] = set()
        for data in normalized_sources.values():
            if owner.encode() not in data or member.encode() not in data:
                continue
            matches.update(_class_member_return_types(data, owner, member, argument_count))
        if not matches:
            raise SourceEditError(
                "member-probe declaration is absent from clean sources: "
                + "::".join(qualified_member)
            )
        if len(matches) != 1:
            raise SourceEditError(
                f"member-probe return type is ambiguous for "
                f"{'::'.join(qualified_member)}: {sorted(matches)}"
            )
        inferred = next(iter(matches))
        inferred_types.add(inferred)
        probe_types.append(inferred)
    if len(inferred_types) > 1:
        raise SourceEditError(
            f"legacy member probes require conflicting return types: {sorted(inferred_types)}"
        )

    for (generator, _qualified, _arity), return_type in zip(probes, probe_types, strict=True):
        raw_explicit = generator.get("return_type")
        if raw_explicit is not None:
            explicit = _render_cpp_type(
                _cpp_type(raw_explicit, "legacy member-probe explicit return type")
            )
            if explicit != return_type:
                raise SourceEditError(
                    "explicit member-probe return type differs from clean-source inference"
                )
        generator["return_type"] = return_type
    validate_classic_overlay(normalized)
    return normalized
